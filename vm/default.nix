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
    # even a name server. Only the forwards below work, and QEMU enforces
    # this from outside the VM, so nothing inside it can lift the lock.
    restrictNetwork = true;

    forwardPorts = [
      {
        # The one way out: the broker on the Mac, which decides per request.
        from = "guest";
        guest.address = brokerAddress;
        guest.port = brokerPort;
        host.address = "127.0.0.1";
        host.port = ports.broker;
      }
      {
        from = "host";
        host.address = "127.0.0.1";
        host.port = ports.ssh;
        guest.port = 22;
      }
      {
        from = "host";
        host.address = "127.0.0.1";
        host.port = ports.t3;
        guest.port = t3Port;
      }
    ];
  };

  networking.hostName = "agent-vm";
  networking.firewall.allowedTCPPorts = [ t3Port ];

  # Send all web traffic to the broker. A program that ignores these settings
  # and connects directly gets no answer, because of the lock above.
  networking.proxy.default = brokerUrl;
  networking.proxy.noProxy = proxyVariables.NO_PROXY;
  environment.sessionVariables = proxyVariables;

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
  # sandbox and what a refusal from the broker means. Without it an agent
  # tends to retry or look for a way around.
  environment.etc."claude-code/CLAUDE.md".source = ./agent-instructions.md;

  # T3 and the tools it downloads are prebuilt Linux programs, which NixOS
  # cannot run without this.
  programs.nix-ld.enable = true;

  systemd.services.t3 = {
    description = "T3 Code server";
    wantedBy = [ "multi-user.target" ];
    wants = [ "network-online.target" ];
    after = [ "network-online.target" ];
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
    # The agents T3 starts inherit these, so they reach the broker too.
    // config.networking.proxy.envVars
    // proxyVariables;
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
