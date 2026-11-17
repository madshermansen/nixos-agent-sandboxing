# The tests that need no VM, as Nix sees them: what `nix flake check` runs,
# the shell that `nix develop` opens, and `nix run .#test-broker`.
#
# Everything here runs on the Mac alone. The VM is a Linux system, which only
# the Linux builder can build, so nothing here may build any part of it; that
# is what lets the same checks run in CI, on a machine with no Linux builder.
# docs/testing.md says what each layer of tests covers and what is left to
# the check inside the VM.
{
  lib,
  stdenv,
  runCommand,
  linkFarmFromDrvs,
  mkShellNoCC,
  writeShellApplication,
  writeShellScriptBin,
  callPackage,
  python3,
  bash,
  shellcheck,
  ruff,
  curl,
  openssl,
  # The flake itself: its files are the source under test, and its outputs
  # give the VM and the formatter.
  self,
  ports,
}:
let
  formatter = self.formatter.${stdenv.hostPlatform.system};

  # The Python that the broker runs on, with pytest added. Nixpkgs builds the
  # `mitmdump` program from this same `python3Packages.mitmproxy`, so the
  # tests see the mitmproxy version, and the versions of everything under
  # it, that the broker has when it runs. It also has ruamel.yaml, without
  # which a file of tests skips itself.
  testPython = python3.withPackages (packages: [
    packages.mitmproxy
    packages.pytest
  ]);

  # The Mac-side commands, built with a stand-in for the VM. Each command is
  # a shell script that Nix runs shellcheck over when it builds it, so
  # building them is the check. The real `vm` command holds the path of the
  # VM, and asking for it would build the VM; here that path is a script
  # that does nothing.
  commands = callPackage ../darwin/commands.nix {
    inherit ports;
    vm = writeShellScriptBin "run-agent-vm-vm" ''
      echo "This is the stand-in used by the checks, not a VM." >&2
      exit 1
    '';
  };

  # tests/github-broker.sh asks Nix to build the broker, because it is
  # written to be run by hand from a checkout. Under `nix run .#test-broker`
  # the broker is built already, as part of the same build as the test. So
  # the test is given this stand-in for the `nix` command, which answers
  # that one question with the broker at hand. The test then needs no Nix
  # while it runs, and the broker it tests is sure to be the one built from
  # the same files as the test.
  nixStandIn = writeShellScriptBin "nix" ''
    case "$*" in
      "build .#broker "*) echo ${commands.broker} ;;
      *)
        echo "test-broker: the test asked Nix for something else than the broker: nix $*" >&2
        echo "test-broker: teach the stand-in in tests/default.nix about it." >&2
        exit 1
        ;;
    esac
  '';

  # Runs tests/github-broker.sh with the programs it needs. They come from
  # Nix, so the result does not depend on what the machine has installed.
  # The rest of what it uses (ps, shasum and the like) is on every Mac.
  test-broker = writeShellApplication {
    name = "nixt3-test-broker";
    runtimeInputs = [
      nixStandIn
      bash
      python3
      openssl
      curl
    ];
    text = ''
      # The test sends its requests through a broker of its own. Proxy
      # settings of the shell it is started from would send them elsewhere:
      # a `no_proxy` that names localhost makes curl go around the broker.
      unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY
      exec ${self}/tests/github-broker.sh "$@"
    '';
  };
in
{
  checks = {
    # `nix fmt` would change nothing.
    format = runCommand "nixt3-check-format" { nativeBuildInputs = [ formatter ]; } ''
      cp -r ${self} tree
      chmod -R u+w tree
      cd tree
      # --ci: change nothing, and fail if a file would be changed.
      treefmt --ci --tree-root . --walk filesystem
      touch $out
    '';

    # The scripts under tests/ pass shellcheck. Which of its notes are
    # turned off, and why, is in tests/.shellcheckrc.
    shell = runCommand "nixt3-check-shell" { nativeBuildInputs = [ shellcheck ]; } ''
      shellcheck ${self}/tests/*.sh
      touch $out
    '';

    # The Python files compile with the Python the broker runs on, and pass
    # ruff's checks for real mistakes (tests/ruff.toml). Nothing is
    # reformatted or checked for style.
    python =
      runCommand "nixt3-check-python"
        {
          nativeBuildInputs = [
            testPython
            ruff
          ];
        }
        ''
          cd ${self}
          # Compiled files go here instead of beside the sources, which are
          # read-only.
          export PYTHONPYCACHEPREFIX=$TMPDIR/pycache
          # -W error: what Python only warns about, such as a misspelt
          # escape in a text, counts as a mistake too.
          python -W error -m compileall -q broker tests/unit
          ruff check --no-cache --config tests/ruff.toml broker tests/unit
          touch $out
        '';

    # Every test under tests/unit, whoever added it. NIXT3_NO_SKIPS makes a
    # skipped test a failure (tests/unit/conftest.py), so that a missing
    # library cannot quietly shrink the set.
    unit = runCommand "nixt3-check-unit" { nativeBuildInputs = [ testPython ]; } ''
      cd ${self}
      export HOME=$TMPDIR
      export PYTHONDONTWRITEBYTECODE=1
      NIXT3_NO_SKIPS=1 pytest -p no:cacheprovider tests/unit
      touch $out
    '';

    # The Mac-side commands and the broker test build, which runs shellcheck
    # over each of them.
    commands = linkFarmFromDrvs "nixt3-check-commands" (
      lib.filter lib.isDerivation (lib.attrValues commands) ++ [ test-broker ]
    );

    # The VM's configuration still makes sense to Nix: every option in it
    # can be worked out, down to the recipe for building the VM (its
    # "derivation"). Nothing is built. The recipe's path is taken as plain
    # text on purpose: taken as a path, it would make this check depend on
    # the VM and so build it.
    vm-evaluates =
      runCommand "nixt3-check-vm-evaluates"
        {
          recipe = builtins.unsafeDiscardStringContext self.nixosConfigurations.agent-vm.config.system.build.vm.drvPath;
        }
        ''
          echo "$recipe" >$out
        '';
  };

  # `nix develop`: the tools for working on the repo.
  devShell = mkShellNoCC {
    packages = [
      testPython # python, pytest, and mitmproxy with its `mitmdump`
      formatter # treefmt, which is what `nix fmt` runs
      shellcheck
      ruff
      curl
      openssl
    ];
  };

  apps.test-broker = {
    type = "app";
    program = lib.getExe test-broker;
    meta.description = "Check the broker on the Mac against a stand-in server, with no VM and no token";
  };
}
