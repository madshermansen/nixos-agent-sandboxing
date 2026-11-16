{
  description = "A NixOS VM for coding agents, and a broker on the Mac that holds their keys";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      hostSystem = "aarch64-darwin";
      hostPkgs = nixpkgs.legacyPackages.${hostSystem};

      # Ports on the Mac, all listening on localhost only. `ssh` and `t3` lead
      # into the VM. `broker` is the proxy that is the VM's only way out.
      ports = {
        ssh = 2222;
        t3 = 3774;
        broker = 8474;
      };

      hostScripts = hostPkgs.callPackage ./darwin/commands.nix {
        inherit ports;
        vm = self.nixosConfigurations.agent-vm.config.system.build.vm;
      };
    in
    {
      nixosConfigurations.agent-vm = nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";
        specialArgs = { inherit hostPkgs ports; };
        modules = [ ./vm ];
      };

      # What the Mac itself needs, for import into a nix-darwin configuration.
      darwinModules.default = ./darwin;

      # `nix run .#vm` starts the VM and `nix run .#stop` shuts it down,
      # `nix run .#ssh` opens a shell in it, and `nix run .#pair` adds it to
      # the T3 app.
      packages.${hostSystem} = {
        inherit (hostScripts)
          vm
          stop
          ssh
          pair
          ;
        default = hostScripts.vm;
      };

      formatter.${hostSystem} = hostPkgs.nixfmt-tree;
    };
}
