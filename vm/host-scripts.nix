# Commands that run on the Mac: start the VM, open a shell in it, and pair it
# with the T3 app.
#
# The VM's disk and the SSH key for reaching it live outside the repo, in
# ~/.local/state/agent-vm (or $AGENT_VM_STATE).
{
  writeShellApplication,
  openssh,
  jq,
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

      if [ ! -f "$state/ssh_key" ]; then
        ssh-keygen -q -t ed25519 -N "" -C agent-vm -f "$state/ssh_key"
      fi

      # The VM reads the public key from its kernel command line at boot.
      QEMU_KERNEL_PARAMS="agentvm.sshkey=$(cut -d' ' -f2 "$state/ssh_key.pub")"
      export QEMU_KERNEL_PARAMS
      export NIX_DISK_IMAGE="$state/disk.qcow2"

      echo "agent-vm: SSH on localhost:${toString ports.ssh}, T3 on localhost:${toString ports.t3}, state in $state" >&2
      exec ${vm}/bin/run-agent-vm-vm "$@"
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
