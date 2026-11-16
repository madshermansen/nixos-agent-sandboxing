# Commands that run on the Mac: start the VM, and open a shell in it.
#
# The VM's disk and the SSH key for reaching it live outside the repo, in
# ~/.local/state/agent-vm (or $AGENT_VM_STATE).
{
  writeShellApplication,
  openssh,
  vm,
  ports,
}:
let
  stateDir = ''"''${AGENT_VM_STATE:-''${XDG_STATE_HOME:-$HOME/.local/state}/agent-vm}"'';
in
{
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
}
