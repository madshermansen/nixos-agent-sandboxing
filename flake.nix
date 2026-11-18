{
  description = "nixt3: a locked-down NixOS VM for coding agents on a Mac, and a broker that is its only way out";

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

      # The tests that need no VM, see tests/default.nix and docs/testing.md.
      tests = hostPkgs.callPackage ./tests { inherit self hostScripts; };
    in
    {
      nixosConfigurations.agent-vm = nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";
        specialArgs = { inherit hostPkgs ports; };
        modules = [ ./vm ];
      };

      # What the Mac itself needs, for import into a nix-darwin configuration.
      darwinModules.default = ./darwin;

      # `nix run .#vm` starts the VM and its broker, and `nix run .#stop`
      # shuts both down. `nix run .#ssh` opens a shell in the VM, and
      # `nix run .#pair` adds it to the T3 app. `nix run .#broker` runs the
      # broker alone, in the terminal. `nix run .#logs` follows the broker's
      # log, and `nix run .#check` tests the network lock from inside the VM.
      packages.${hostSystem} = {
        inherit (hostScripts)
          vm
          stop
          ssh
          pair
          broker
          logs
          check
          status
          vm-fresh
          update-t3
          ;
        default = hostScripts.vm;
      };

      formatter.${hostSystem} = hostPkgs.nixfmt-tree;

      # `nix flake check` runs every test that needs neither the VM nor the
      # Linux builder. `nix develop` opens a shell with the tools for working
      # on the repo. `nix run .#test-broker` checks a real broker on the Mac
      # against a stand-in server.
      checks.${hostSystem} = tests.checks;
      devShells.${hostSystem}.default = tests.devShell;
      apps.${hostSystem} = tests.apps;
    };
}
