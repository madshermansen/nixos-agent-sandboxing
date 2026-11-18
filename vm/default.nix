# The agent VM: a headless NixOS system that runs the T3 server and Claude Code.
{
  config,
  lib,
  modulesPath,
  pkgs,
  hostPkgs,
  ports,
  ...
}:
let
  t3 = pkgs.callPackage ./t3.nix { };
  t3Port = 3773;

  # Where the VM finds the broker. The address exists only inside the VM:
  # QEMU hands every connection to it over to the broker on the Mac.
  brokerAddress = "10.0.2.100";
  brokerPort = 3128;
  brokerUrl = "http://${brokerAddress}:${toString brokerPort}";

  # Programs find the broker through these variables. Both spellings are set
  # because programs disagree on which one they read.
  proxyVariables = {
    HTTP_PROXY = brokerUrl;
    HTTPS_PROXY = brokerUrl;
    NO_PROXY = "127.0.0.1,localhost";
  };

  # What programs in the VM use in place of a GitHub token. It is public and
  # gives no access by itself: the broker on the Mac puts the real token in
  # its place on the way out. Keep it equal to PLACEHOLDER in broker/swap.py.
  githubPlaceholder = "nixt3-placeholder-not-a-real-token";

  # The certificates this system trusts: the usual ones, and the broker's.
  # The file is put together at boot, see the broker-ca service below. Every
  # program that looks in the usual place finds it, because the usual place
  # (/etc/ssl/certs/ca-certificates.crt) is made to point here.
  trustedCertificates = "/run/broker-ca/ca-certificates.crt";

  # For programs that do not look in the usual place by themselves. Node
  # (and with it Claude Code and the T3 server) brings its own list and only
  # adds to it what NODE_EXTRA_CA_CERTS names. The others are named for
  # programs that bring a list of their own.
  certificateVariables = {
    SSL_CERT_FILE = trustedCertificates;
    NIX_SSL_CERT_FILE = trustedCertificates;
    CURL_CA_BUNDLE = trustedCertificates;
    GIT_SSL_CAINFO = trustedCertificates;
    NODE_EXTRA_CA_CERTS = trustedCertificates;
    REQUESTS_CA_BUNDLE = trustedCertificates;
  };

  # gh and other GitHub tools read the token from these.
  githubVariables = {
    GH_TOKEN = githubPlaceholder;
    GITHUB_TOKEN = githubPlaceholder;
  };

  # Everything a program in the VM needs in its environment to get out
  # through the broker. Login shells and the T3 service both get it.
  sandboxVariables = proxyVariables // certificateVariables // githubVariables;

  # git asks this for a login when GitHub wants one, and gets the placeholder.
  githubCredentialHelper = pkgs.writeShellScript "git-credential-placeholder" ''
    if [ "$1" = get ]; then
      echo username=x-access-token
      echo password=${githubPlaceholder}
    fi
  '';
in
{
  imports = [ (modulesPath + "/virtualisation/qemu-vm.nix") ];

  virtualisation = {
    # QEMU runs on the Mac, with a Linux system inside.
    host.pkgs = hostPkgs;
    graphics = false;
    cores = 4;
    memorySize = 8192;
    diskSize = 40960;

    # Nothing on the Mac is shared with the VM. It gets its own copy of the
    # Nix store instead of a view of the Mac's, and no exchange folders.
    useNixStoreImage = true;
    sharedDirectories = lib.mkForce { };

    # The network is locked. The VM cannot reach the internet, the Mac, or
    # even a name server. Only the three forwards below work, and QEMU
    # enforces this from outside the VM, so nothing inside it can lift the
    # lock.
    #
    # This is the whole of the VM's network, written out as the one option
    # QEMU gets for it, instead of NixOS's `forwardPorts`. The reason is the
    # way out: NixOS would run `nc` for each connection to the broker, and
    # `nc` does not tell the VM when the broker closes a connection. A
    # program in the VM whose request was refused then waited until its own
    # time limit, or forever. `socat` ends when either side closes, and the
    # VM sees that.
    #
    #   restrict=on  drops everything the VM sends, except to the forwards
    #   guestfwd     the one way out: connections to the broker's address in
    #                the VM are handed to a helper on the Mac, which passes
    #                them to the broker on the Mac's localhost. The broker
    #                decides per request.
    #                  -b65536  pass data on in pieces of 64 KiB
    #                  -t1      after one side has closed, wait a second for
    #                           what the other side still sends, then end
    #   hostfwd      two ports on the Mac's localhost that lead into the VM:
    #                SSH and the T3 server
    #
    # No other option is read from the environment of the start command, so
    # a variable left over in a shell cannot add a forward.
    qemu.networkingOptions = lib.mkForce [
      "-net nic,netdev=user.0,model=virtio"
      (
        "-netdev '"
        + lib.concatStringsSep "," [
          "user"
          "id=user.0"
          "restrict=on"
          "guestfwd=tcp:${brokerAddress}:${toString brokerPort}-cmd:${hostPkgs.socat}/bin/socat -b65536 -t1 STDIO TCP:127.0.0.1:${toString ports.broker}"
          "hostfwd=tcp:127.0.0.1:${toString ports.ssh}-:22"
          "hostfwd=tcp:127.0.0.1:${toString ports.t3}-:${toString t3Port}"
        ]
        + "'"
      )
    ];
  };

  networking.hostName = "agent-vm";
  networking.firewall.allowedTCPPorts = [ t3Port ];

  # Send all web traffic to the broker. A program that ignores these settings
  # and connects directly gets no answer, because of the lock above.
  networking.proxy.default = brokerUrl;
  networking.proxy.noProxy = proxyVariables.NO_PROXY;
  environment.sessionVariables = sandboxVariables;

  # The broker opens the traffic to GitHub, to put the real token in. What
  # it sends back is signed by a certificate authority of its own, which
  # lives on the Mac. The Mac hands the authority's public certificate to
  # the VM at start through QEMU's "fw_cfg", a way to give a VM a small file
  # without sharing a folder. Only the certificate comes in; the key that
  # signs stays on the Mac.
  #
  # This service adds that certificate to the ones the system trusts. It
  # runs before anything that goes out, and again at every boot, so a new
  # authority on the Mac is picked up by a restart.
  boot.kernelModules = [ "qemu_fw_cfg" ];
  systemd.services.broker-ca = {
    description = "Trust the broker's certificate authority";
    wantedBy = [ "multi-user.target" ];
    before = [
      "t3.service"
      "sshd.service"
      "getty.target"
    ];
    path = [ pkgs.kmod ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      modprobe qemu_fw_cfg 2>/dev/null || true
      from=/sys/firmware/qemu_fw_cfg/by_name/opt/nixt3/broker-ca/raw

      mkdir -p /run/broker-ca
      new=/run/broker-ca/ca-certificates.crt.new
      cat ${config.security.pki.caBundle} > "$new"

      # Without the broker's certificate the usual ones are still trusted,
      # so destinations that are passed on untouched keep working. GitHub
      # does not, and says so with a certificate error.
      if [ ! -r "$from" ]; then
        echo "The Mac passed no broker certificate. Start the VM with: nix run .#vm" >&2
      elif ! grep -q "BEGIN CERTIFICATE" "$from" || grep -q "PRIVATE KEY" "$from"; then
        echo "What the Mac passed is not a certificate alone. It is not trusted." >&2
      else
        install -m 444 "$from" /run/broker-ca/broker-ca.pem
        { echo; cat "$from"; } >> "$new"
      fi

      chmod 444 "$new"
      mv "$new" ${trustedCertificates}
    '';
  };
  environment.etc = {
    "ssl/certs/ca-certificates.crt".source = lib.mkForce trustedCertificates;
    "ssl/certs/ca-bundle.crt".source = lib.mkForce trustedCertificates;
    "pki/tls/certs/ca-bundle.crt".source = lib.mkForce trustedCertificates;
  };

  # GitHub goes through the broker, which can only read HTTPS. So git is
  # told to use HTTPS for GitHub whatever kind of address it is given, and
  # to log in with the placeholder.
  programs.git = {
    enable = true;
    config = {
      url."https://github.com/".insteadOf = [
        "git@github.com:"
        "ssh://git@github.com/"
        "ssh://github.com/"
        "git://github.com/"
      ];
      credential."https://github.com".helper = "${githubCredentialHelper}";
    };
  };

  # With the network locked the VM cannot ask a time server, and its clock
  # stops while the Mac sleeps. The VM's hardware clock follows the Mac's
  # clock, so the system clock is set from it every minute. A wrong clock
  # makes HTTPS connections and sign-ins fail.
  systemd.services.clock-from-host = {
    description = "Set the clock from the Mac's clock";
    serviceConfig.Type = "oneshot";
    script = "${pkgs.util-linux}/bin/hwclock --hctosys --utc";
  };
  systemd.timers.clock-from-host = {
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnBootSec = "10s";
      OnUnitActiveSec = "1min";
      AccuracySec = "1s";
    };
  };

  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
  ];

  # The agent's account. It has no sudo. Extra tools go in the package list
  # below, because the locked network keeps Nix from downloading them.
  users.users.agent = {
    isNormalUser = true;
    extraGroups = [ "systemd-journal" ];
  };
  services.getty.autologinUser = "agent";

  # SSH from the Mac. The start script generates a key on the Mac and passes
  # its public half on the kernel command line, so no key is kept in this repo.
  services.openssh = {
    enable = true;
    authorizedKeysFiles = [ "/run/host-ssh-key/%u" ];
    settings = {
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
      PermitRootLogin = "no";
    };
  };
  systemd.services.host-ssh-key = {
    description = "Accept the SSH key passed by the Mac at boot";
    wantedBy = [ "multi-user.target" ];
    before = [ "sshd.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      mkdir -p /run/host-ssh-key
      for arg in $(cat /proc/cmdline); do
        case "$arg" in
          agentvm.sshkey=*)
            echo "ssh-ed25519 ''${arg#agentvm.sshkey=}" > /run/host-ssh-key/agent
            ;;
        esac
      done
    '';
  };

  # Tells Claude Code, in every session on this machine, that it is in a
  # sandbox, how the machine is set up, what a refusal from the broker means
  # and how to ask for more: with a pull request in this repo. Without it an
  # agent tends to retry or look for a way around. It is in /etc, which the
  # agent cannot write to, so a program in the VM cannot change this file.
  # It can still change the other files Claude Code reads, in the home
  # folder and in a project.
  environment.etc."claude-code/CLAUDE.md".source = ./agent-instructions.md;

  # T3 and the tools it downloads are prebuilt Linux programs, which NixOS
  # cannot run without this.
  programs.nix-ld.enable = true;

  systemd.services.t3 = {
    description = "T3 Code server";
    wantedBy = [ "multi-user.target" ];
    wants = [ "network-online.target" ];
    after = [
      "network-online.target"
      "broker-ca.service"
    ];
    # Agents started by T3 see the same tools as a login shell.
    path = [
      "/run/wrappers"
      "/run/current-system/sw"
    ];
    environment = {
      HOME = "/home/agent";
      NIX_LD = "/run/current-system/sw/share/nix-ld/lib/ld.so";
      NIX_LD_LIBRARY_PATH = "/run/current-system/sw/share/nix-ld/lib";
    }
    # The agents T3 starts inherit these, so they reach the broker, trust
    # its certificate and log in to GitHub with the placeholder, as a login
    # shell does.
    // config.networking.proxy.envVars
    // sandboxVariables;
    serviceConfig = {
      User = "agent";
      WorkingDirectory = "/home/agent";
      # QEMU hands forwarded connections to the VM's network address, not its
      # loopback, so the server listens on all of the VM's interfaces.
      ExecStart = "${t3}/bin/t3 serve --host 0.0.0.0 --port ${toString t3Port}";
      Restart = "on-failure";
      RestartSec = 5;
    };
  };

  nixpkgs.config.allowUnfreePredicate = pkg: builtins.elem (lib.getName pkg) [ "claude-code" ];

  environment.systemPackages = with pkgs; [
    claude-code
    curl
    gh
    git
    jq
    nodejs
    ripgrep
    t3
  ];

  system.stateVersion = "26.11";
}
