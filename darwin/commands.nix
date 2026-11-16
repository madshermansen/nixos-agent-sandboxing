# Commands that run on the Mac: start and stop the VM, open a shell in it, and
# pair it with the T3 app.
#
# The VM's disk and the SSH key for reaching it live outside the repo, in
# ~/.local/state/agent-vm (or $AGENT_VM_STATE). While the VM runs, the folder
# also holds QEMU's control socket and process id, which the stop command uses.
{
  writeShellApplication,
  openssh,
  jq,
  socat,
  vm,
  ports,
}:
let
  stateDir = ''"''${AGENT_VM_STATE:-''${XDG_STATE_HOME:-$HOME/.local/state}/agent-vm}"'';

  ssh = writeShellApplication {
    name = "agent-vm-ssh";
    runtimeInputs = [ openssh ];
    text = ''
      state=${stateDir}

      # The VM gets a new host key whenever its disk is recreated, and it is
      # only reachable on localhost, so host keys are not remembered.
      exec ssh \
        -p ${toString ports.ssh} \
        -i "$state/ssh_key" \
        -o IdentitiesOnly=yes \
        -o IdentityAgent=none \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        agent@127.0.0.1 "$@"
    '';
  };
in
{
  inherit ssh;

  vm = writeShellApplication {
    name = "agent-vm";
    runtimeInputs = [ openssh ];
    text = ''
      state=${stateDir}
      mkdir -p "$state"
      chmod 700 "$state"

      if [ -f "$state/qemu.pid" ] && kill -0 "$(cat "$state/qemu.pid")" 2>/dev/null; then
        echo "agent-vm: already running. Stop it with: nix run .#stop" >&2
        exit 1
      fi
      rm -f "$state/qemu.pid" "$state/qmp.sock"

      if [ ! -f "$state/ssh_key" ]; then
        ssh-keygen -q -t ed25519 -N "" -C agent-vm -f "$state/ssh_key"
      fi

      # The VM reads the public key from its kernel command line at boot.
      QEMU_KERNEL_PARAMS="agentvm.sshkey=$(cut -d' ' -f2 "$state/ssh_key.pub")"
      export QEMU_KERNEL_PARAMS
      export NIX_DISK_IMAGE="$state/disk.qcow2"

      echo "agent-vm: SSH on localhost:${toString ports.ssh}, T3 on localhost:${toString ports.t3}, state in $state" >&2
      exec ${vm}/bin/run-agent-vm-vm \
        -qmp "unix:$state/qmp.sock,server=on,wait=off" \
        -pidfile "$state/qemu.pid" \
        "$@"
    '';
  };

  # Presses the VM's power button through QEMU's control socket, so the system
  # shuts down cleanly. If it has not stopped after a minute, QEMU is told to
  # quit, which is like pulling the plug.
  stop = writeShellApplication {
    name = "agent-vm-stop";
    runtimeInputs = [ socat ];
    text = ''
      state=${stateDir}

      if [ ! -S "$state/qmp.sock" ] || [ ! -f "$state/qemu.pid" ] || ! kill -0 "$(cat "$state/qemu.pid")" 2>/dev/null; then
        echo "agent-vm: not running" >&2
        exit 0
      fi
      pid=$(cat "$state/qemu.pid")

      qmp() {
        {
          printf '{"execute":"qmp_capabilities"}\n{"execute":"%s"}\n' "$1"
          sleep 1
        } | socat - "UNIX-CONNECT:$state/qmp.sock" >/dev/null
      }

      echo "agent-vm: shutting down" >&2
      qmp system_powerdown
      for _ in $(seq 60); do
        if ! kill -0 "$pid" 2>/dev/null; then
          rm -f "$state/qemu.pid" "$state/qmp.sock"
          echo "agent-vm: stopped" >&2
          exit 0
        fi
        sleep 1
      done

      echo "agent-vm: still running after a minute, switching it off" >&2
      qmp quit || kill "$pid"
      rm -f "$state/qemu.pid" "$state/qmp.sock"
    '';
  };

  # Asks the VM's T3 server for a one-time pairing code and hands it to the
  # T3 app on the Mac, which then lists the VM as an environment.
  pair = writeShellApplication {
    name = "agent-vm-pair";
    runtimeInputs = [ jq ];
    text = ''
      code=$(${ssh}/bin/agent-vm-ssh t3 auth pairing create --json --ttl 10m --label "'T3 app on the Mac'" | jq -r .credential)
      url="http://127.0.0.1:${toString ports.t3}/pair#token=$code"

      echo "Pairing link, valid for 10 minutes: $url" >&2
      /usr/bin/open "t3code://pair?pairingUrl=$(jq -rn --arg url "$url" '$url | @uri')"
    '';
  };
}
