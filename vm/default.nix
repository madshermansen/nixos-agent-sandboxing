# The agent VM: a headless NixOS system that runs the T3 server and Claude Code.
{
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

    forwardPorts = [
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

  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
  ];

  # The agent's account. It has no sudo; `nix shell` covers extra tools.
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
    };
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
