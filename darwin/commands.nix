# Commands that run on the Mac: start and stop the VM and its broker, open a
# shell in the VM, and pair it with the T3 app.
#
# The VM's disk and the SSH key for reaching it live outside the repo, in
# ~/.local/state/agent-vm (or $AGENT_VM_STATE). While the VM runs, the folder
# also holds QEMU's control socket and process id, which the stop command uses.
#
# The broker is the proxy that is the VM's only way out, see ../broker. Its
# files are in the same folder:
#
#   broker/      mitmproxy's own files, among them the certificate authority
#                it generates on first start. The broker signs with it when
#                it opens the traffic to a destination, and the VM is given
#                its public certificate at start so that it trusts those
#                signatures. The private key stays in this folder.
#   broker.pid   the process id of the broker that `nix run .#vm` started
#   broker.log   that broker's output, one line per decision
#
# Three more files are described where they are used: `vm.lock`, which keeps
# two VMs from running on one disk; `throwaway.qcow2`, the disk of a run
# started with `nix run .#vm-fresh`; and `broker.log.1` to `.3` and
# `console.log.1` to `.3`, older parts of the two logs.
{
  lib,
  callPackage,
  writeShellApplication,
  coreutils,
  curl,
  flock,
  gnused,
  openssh,
  jq,
  socat,
  mitmproxy,
  python3,
  qemu_kvm,
  vm,
  ports,
}:
let
  stateDir = ''"''${AGENT_VM_STATE:-''${XDG_STATE_HOME:-$HOME/.local/state}/agent-vm}"'';

  # The broker's files are taken as a folder, so that proxy.py finds the
  # files beside it.
  brokerFiles = ../broker;

  # Runs fetch_tokens.py, which needs a YAML reader.
  tokenPython = python3.withPackages (packages: [ packages.ruamel-yaml ]);

  # Shell functions for finding and stopping the broker that runs in the
  # background. They expect `state` to be set.
  brokerFunctions = ''
    # Prints the process id of the background broker and succeeds, or fails
    # when there is none. The pid file can outlive the broker, for example
    # across a reboot, and its number may by then belong to another program.
    # So the process is also checked to be a broker before anyone signals it.
    broker_pid() {
      local pid
      [ -f "$state/broker.pid" ] || return 1
      pid=$(cat "$state/broker.pid")
      case "$(/bin/ps -o command= -p "$pid" 2>/dev/null)" in
        *mitmdump* | *agent-vm-broker-run*) echo "$pid" ;;
        *) return 1 ;;
      esac
    }

    # Stops the background broker if it is running. It is asked to stop
    # first, and ended the hard way if it has not after five seconds.
    stop_broker() {
      local pid
      if pid=$(broker_pid); then
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 50); do
          kill -0 "$pid" 2>/dev/null || break
          sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null; then
          kill -KILL "$pid" 2>/dev/null || true
        fi
        echo "agent-vm: broker stopped" >&2
      fi
      rm -f "$state/broker.pid"
    }

    # Succeeds when a broker started with `nix run .#broker` in a terminal is
    # running. It records its process id like the background one does.
    foreground_broker_running() {
      local pid
      [ -f "$state/broker-foreground.pid" ] || return 1
      pid=$(cat "$state/broker-foreground.pid")
      case "$(/bin/ps -o command= -p "$pid" 2>/dev/null)" in
        *mitmdump* | *agent-vm-broker-run*) return 0 ;;
        *) return 1 ;;
      esac
    }

    # Succeeds when something accepts connections on the broker's port.
    broker_port_open() {
      (exec 3<>/dev/tcp/127.0.0.1/${toString ports.broker}) 2>/dev/null
    }
  '';

  # A shell function that keeps a log file from growing without end. It
  # needs `mv` and `wc` only.
  logFunctions = ''
    # Moves the log file $1 aside when it is larger than 5 MiB: it becomes
    # $1.1, the one that had that name becomes $1.2, and so on. Three old
    # files are kept and the oldest is deleted, so a log takes at most about
    # 20 MiB plus what one run writes.
    #
    # A program that has the file open keeps writing to the same file under
    # its new name; it does not follow the old name. So call this only when
    # no program has the log open, or re-open the log right after.
    rotate_log() {
      local file=$1 keep=3 limit=$((5 * 1024 * 1024)) size number
      # Only a plain file is moved, never a link to something else.
      if [ ! -f "$file" ] || [ -L "$file" ]; then
        return 0
      fi
      size=$(wc -c <"$file") || return 0
      size=''${size//[^0-9]/}
      if [ "$size" -le "$limit" ]; then
        return 0
      fi
      for number in $(seq "$((keep - 1))" -1 1); do
        if [ -f "$file.$number" ]; then
          mv -f "$file.$number" "$file.$((number + 1))"
        fi
      done
      mv -f "$file" "$file.1"
    }
  '';

  # Shell functions that tell whether the VM runs and on which disk. They
  # expect `state` to be set.
  vmFunctions = ''
    # Prints the process id of the running VM and succeeds, or fails when
    # there is none. QEMU writes qemu.pid itself. The file can outlive the
    # VM, and its number may by then belong to another program, so the
    # process is also checked to be QEMU.
    vm_pid() {
      local pid
      [ -f "$state/qemu.pid" ] || return 1
      pid=$(cat "$state/qemu.pid" 2>/dev/null) || return 1
      [[ $pid =~ ^[0-9]+$ ]] || return 1
      case "$(/bin/ps -ww -o command= -p "$pid" 2>/dev/null)" in
        *qemu-system*) echo "$pid" ;;
        *) return 1 ;;
      esac
    }

    # Succeeds when the VM with process id $1 is a throwaway run. QEMU's own
    # command line names the disk it was given, which is the one fact that
    # cannot be out of date.
    vm_is_throwaway() {
      case "$(/bin/ps -ww -o command= -p "$1" 2>/dev/null)" in
        *"/throwaway.qcow2,"*) return 0 ;;
        *) return 1 ;;
      esac
    }
  '';

  # The version of the T3 server that this checkout puts in the VM.
  t3Pinned = (callPackage ../vm/t3.nix { }).version;

  # A shell function that needs `timeout` from coreutils.
  t3AppVersion = ''
    # Prints the version of the T3 app on this Mac, such as 0.1.7, or fails.
    # The app installs a small command, ~/.t3/bin/t3, that runs the server
    # bundled inside the app, so its version is the app's.
    t3_app_version() {
      local cli answer
      cli="$HOME/.t3/bin/t3"
      if [ ! -x "$cli" ]; then
        cli=$(command -v t3) || return 1
      fi
      # It prints "t3 v0.1.7".
      answer=$(timeout 10 "$cli" --version 2>/dev/null </dev/null) || return 1
      answer=''${answer##* }
      answer=''${answer#v}
      [[ $answer =~ ^[0-9]+(\.[0-9]+)+(-[0-9A-Za-z.]+)?$ ]] || return 1
      echo "$answer"
    }
  '';

  # Runs the broker in the foreground. The two commands below start it: one
  # for a terminal, one for the background.
  brokerRun = writeShellApplication {
    name = "agent-vm-broker-run";
    runtimeInputs = [ mitmproxy ];
    text = ''
      state=${stateDir}
      mkdir -p "$state/broker"
      chmod 700 "$state" "$state/broker"

      # The rules are the repo's copy, fixed when this command was built. Set
      # AGENT_BROKER_RULES to another file to try out a change.
      export AGENT_BROKER_RULES="''${AGENT_BROKER_RULES:-${brokerFiles}/rules.yaml}"
      # Write each log line at once, also when the output goes to a file.
      export PYTHONUNBUFFERED=1

      # Fetch the tokens the rules ask for, before the broker starts. The
      # rules name each token only by a short name. Where it is kept is in
      # a file of the user's own, outside the repo; AGENT_BROKER_TOKENS
      # names another file.
      #
      # The fetching program writes the tokens into a pipe, which is opened
      # here as number 3 and inherited by the broker. That is the only place
      # they pass through: not this script, not a file, not an environment
      # variable, not a command line. The broker itself runs no programs, so
      # the fetching has to happen here.
      tokens_file="''${AGENT_BROKER_TOKENS:-''${XDG_CONFIG_HOME:-$HOME/.config}/nixt3/tokens.yaml}"
      exec 3< <(exec ${tokenPython}/bin/python3 ${brokerFiles}/fetch_tokens.py "$AGENT_BROKER_RULES" "$tokens_file")
      # Wait for it to end. It has said why if it failed, and then there is
      # no broker, and so no VM either.
      if ! wait "$!"; then
        exit 1
      fi
      export AGENT_BROKER_TOKENS_FD=3

      # What the options are for:
      #   listen-host          only programs on this Mac can connect
      #   confdir              where mitmproxy keeps its own files
      #   connection_strategy  contact a server only after the broker has
      #                        decided to, never ahead of time
      #   flow_detail          mitmproxy prints nothing about the traffic; the
      #                        broker writes its own line per decision
      #   termlog_verbosity    of mitmproxy's own messages, show only errors
      #   onboarding           no built-in web page that hands out mitmproxy's
      #                        certificate
      #   stream_large_bodies  anything larger than this that the broker
      #                        reads is passed on piece by piece instead of
      #                        held in memory, so the VM cannot fill the
      #                        Mac's memory. The broker's own code already
      #                        sees to that (see proxy.py); this is a second
      #                        safeguard. It replaces a hard size limit,
      #                        which would also stop a large git push or
      #                        clone. Keep it at or above MAX_READ_BODY in
      #                        swap.py.
      #   rawtcp               traffic in a tunnel that is neither TLS nor
      #                        HTTP is dropped instead of passed on
      #   http2                the broker speaks HTTP/1.1 where it opens the
      #                        traffic. There a request says in its first
      #                        lines whether a body follows and how long it
      #                        is, which the broker relies on; in HTTP/2 it
      #                        need not. Traffic passed on untouched is not
      #                        affected and may be HTTP/2.
      exec mitmdump \
        --listen-host 127.0.0.1 \
        --listen-port ${toString ports.broker} \
        --set confdir="$state/broker" \
        --set connection_strategy=lazy \
        --set flow_detail=0 \
        --set termlog_verbosity=error \
        --set onboarding=false \
        --set stream_large_bodies=1m \
        --set rawtcp=false \
        --set http2=false \
        --scripts ${brokerFiles}/proxy.py \
        "$@"
    '';
  };

  # Starts the broker in the background, replacing the one that is there, so
  # that a change to the rules takes effect. The VM start command runs this.
  brokerStart = writeShellApplication {
    name = "agent-vm-broker-start";
    text = ''
      state=${stateDir}
      mkdir -p "$state"
      chmod 700 "$state"

      ${brokerFunctions}
      stop_broker

      if broker_port_open; then
        if foreground_broker_running; then
          echo "agent-vm: using the broker that \`nix run .#broker\` runs in another terminal." >&2
          echo "agent-vm: it has the rules it was started with." >&2
          exit 0
        fi
        # Whatever holds the port would become the VM's way out, with rules
        # nobody chose. So the VM is not started.
        echo "agent-vm: localhost:${toString ports.broker} is taken by a program that is not the broker." >&2
        echo "agent-vm: not starting. Find it with: lsof -nP -iTCP:${toString ports.broker} -sTCP:LISTEN" >&2
        exit 1
      fi

      # Keep the log from growing without end. This is the one safe moment
      # to move it: the old background broker has ended just above and the
      # new one has not opened the file yet. A running broker cannot be told
      # to switch files, so the log is not moved while it runs.
      ${logFunctions}
      rotate_log "$state/broker.log"

      # The broker must outlive this terminal. Job control (`set -m`) puts it
      # in a process group of its own, so Ctrl-C in the terminal does not
      # reach it, and it ignores the hangup signal sent when the terminal
      # closes.
      set -m
      # The background broker always uses the repo's rules. A rules file
      # named in the shell is for \`nix run .#broker\` only, so that one
      # left over from an experiment cannot quietly replace them.
      (
        trap "" HUP
        unset AGENT_BROKER_RULES
        exec ${brokerRun}/bin/agent-vm-broker-run
      ) >>"$state/broker.log" 2>&1 </dev/null &
      pid=$!
      set +m
      echo "$pid" >"$state/broker.pid"

      # Wait until it answers, so the VM never starts without its way out.
      # Fetching a token can mean waiting for the user, so the wait is long;
      # it ends at once when the broker gives up.
      for tick in $(seq 3000); do
        if ! kill -0 "$pid" 2>/dev/null; then
          break
        fi
        if broker_port_open; then
          echo "agent-vm: broker on localhost:${toString ports.broker}, log in $state/broker.log" >&2
          exit 0
        fi
        if [ "$tick" -eq 50 ]; then
          echo "agent-vm: waiting for the broker. It may be asking your password manager for a token." >&2
        fi
        sleep 0.1
      done

      echo "agent-vm: the broker did not start. The end of $state/broker.log:" >&2
      tail -n 20 "$state/broker.log" >&2
      stop_broker
      exit 1
    '';
  };

  ssh = writeShellApplication {
    name = "agent-vm-ssh";
    runtimeInputs = [ openssh ];
    text = ''
      state=${stateDir}

      # The VM gets a new host key whenever its disk is recreated, and it is
      # only reachable on localhost, so host keys are not remembered.
      #
      # `-F none` keeps ssh from reading ~/.ssh/config and the system's
      # configuration. Without it a line there under `Host *`, such as
      # RemoteForward, ForwardAgent or SendEnv, would apply to the VM too
      # and open a way between the VM and the Mac that nobody chose here.
      # The three options after it say the same for the most harmful ones,
      # in case a later ssh changes what it does by itself. An option typed
      # after the command, such as `-L`, still works: it is your own choice.
      exec ssh \
        -F none \
        -o ForwardAgent=no \
        -o ForwardX11=no \
        -o PermitLocalCommand=no \
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
# `self` is this set of commands itself, so that one command can run another.
lib.fix (self: {
  inherit ssh;

  vm = writeShellApplication {
    name = "agent-vm";
    runtimeInputs = [
      openssh
      coreutils
      flock
    ];
    text = ''
      state=${stateDir}
      mkdir -p "$state"
      chmod 700 "$state"

      # `--throwaway` as the first argument asks for a run whose changes are
      # discarded when it stops. \`nix run .#vm-fresh\` passes it; see there.
      throwaway=
      if [ "''${1:-}" = --throwaway ]; then
        throwaway=yes
        shift
      fi

      # The script that starts QEMU adds what these variables hold to QEMU's
      # command line, or boots another kernel. One left over in a shell could
      # give the locked VM a shared folder or a second network card, without
      # anyone asking for it. So they are dropped here, with a note.
      # QEMU_KERNEL_PARAMS is not in the list because it is set further
      # down, which replaces whatever the shell held. The last entry stands
      # for every variable whose name starts with NIXPKGS_QEMU_KERNEL_.
      for name in QEMU_OPTS QEMU_NET_OPTS "''${!NIXPKGS_QEMU_KERNEL_@}"; do
        if [ -n "''${!name+set}" ]; then
          echo "agent-vm: ignoring $name from the environment, so that a value left in a shell cannot change the VM." >&2
          unset "$name"
        fi
      done
      # Options typed after \`nix run .#vm --\` are a choice made just now,
      # so they are passed on, and shown.
      if [ "$#" -gt 0 ]; then
        echo "agent-vm: passing these options to QEMU as typed: $*" >&2
      fi

      if [ -f "$state/qemu.pid" ] && kill -0 "$(cat "$state/qemu.pid")" 2>/dev/null; then
        echo "agent-vm: already running. Stop it with: nix run .#stop" >&2
        exit 1
      fi

      # One VM at a time. Two of them writing to one disk would ruin it, and
      # a throwaway run reads the normal disk the whole time, so it must not
      # change under it either.
      #
      # The check above can be passed by two starts at the same moment. This
      # lock cannot: the system gives it to one program only. It is held on
      # the open file number 9, which QEMU inherits, so it lasts exactly as
      # long as the VM and is given back by the system however the VM ends.
      # Nothing has to be tidied up after a crash.
      exec 9>>"$state/vm.lock"
      if ! flock -n 9; then
        echo "agent-vm: a VM is running or starting on $state. Stop it with: nix run .#stop" >&2
        exit 1
      fi
      rm -f "$state/qemu.pid" "$state/qmp.sock"

      # A throwaway disk can be left behind when its run ended by a crash or
      # a restart of the Mac. It is never used again, because the normal disk
      # may have changed since, and with the lock held no VM is using it.
      rm -f "$state/throwaway.qcow2"
      if [ -n "$throwaway" ] && [ ! -f "$state/disk.qcow2" ]; then
        echo "agent-vm: a throwaway run starts from the normal disk, and there is none yet." >&2
        echo "agent-vm: run \`nix run .#vm\` once first, and sign in to Claude there." >&2
        exit 1
      fi

      # console.log holds the VM's console when the VM was started detached
      # (see CLAUDE.md). Keep it from growing without end. If it is where
      # this script's own output goes, the output is pointed at the new,
      # empty file, so that QEMU does not keep writing to the old one.
      ${logFunctions}
      # Succeeds when this script's output number $2 goes to the file $1.
      # Two names are the same file when their device and file numbers are
      # equal. `stat -` looks at its own standard input, which is made to be
      # the output in question for that one call.
      writes_to() {
        local file output
        file=$(stat -L -c %d:%i "$1" 2>/dev/null) || return 1
        { output=$(stat -L -c %d:%i - <&8 2>/dev/null) || return 1; } 8>&"$2"
        [ "$file" = "$output" ]
      }
      console="$state/console.log"
      console_is_stdout=
      console_is_stderr=
      if writes_to "$console" 1; then console_is_stdout=yes; fi
      if writes_to "$console" 2; then console_is_stderr=yes; fi
      rotate_log "$console"
      if [ ! -e "$console" ]; then
        if [ -n "$console_is_stdout" ]; then exec >>"$console"; fi
        if [ -n "$console_is_stderr" ]; then exec 2>>"$console"; fi
      fi

      # The VM can reach nothing but the broker, so the broker comes first.
      # It is started without the lock (\`9>&-\`): the broker outlives the VM,
      # and would otherwise keep the lock after the VM has ended.
      ${brokerStart}/bin/agent-vm-broker-start 9>&-

      if [ ! -f "$state/ssh_key" ]; then
        ssh-keygen -q -t ed25519 -N "" -C agent-vm -f "$state/ssh_key"
      fi

      # The VM reads the public key from its kernel command line at boot.
      QEMU_KERNEL_PARAMS="agentvm.sshkey=$(cut -d' ' -f2 "$state/ssh_key.pub")"
      export QEMU_KERNEL_PARAMS
      export NIX_DISK_IMAGE="$state/disk.qcow2"

      # The broker opens the traffic to some destinations, and signs what it
      # sends back with a certificate authority of its own. The VM has to
      # trust that authority. Its public certificate is handed over through
      # QEMU's "fw_cfg", a way to give a VM a small file at start without
      # sharing a folder; a certificate is too long for the command line.
      #
      # mitmproxy creates the authority the first time it starts, which is
      # before it opens its port, so the file exists by now. Only the public
      # certificate is passed. The private key is in mitmproxy-ca.pem beside
      # it and must never leave the Mac.
      ca="$state/broker/mitmproxy-ca-cert.pem"
      if [ ! -s "$ca" ]; then
        echo "agent-vm: the broker's certificate is missing: $ca" >&2
        echo "agent-vm: not starting. The broker creates it when it starts; see $state/broker.log" >&2
        exit 1
      fi
      if ! grep -q "BEGIN CERTIFICATE" "$ca" || grep -q "PRIVATE KEY" "$ca"; then
        echo "agent-vm: $ca is not a certificate alone. Not starting, so that no key is handed to the VM." >&2
        exit 1
      fi

      echo "agent-vm: SSH on localhost:${toString ports.ssh}, T3 on localhost:${toString ports.t3}, state in $state" >&2
      # The broker is left running when the VM ends. \`nix run .#stop\` stops
      # it, and the next start replaces it.
      # A comma in a QEMU option is written twice.
      set -- \
        -qmp "unix:$state/qmp.sock,server=on,wait=off" \
        -pidfile "$state/qemu.pid" \
        -fw_cfg "name=opt/nixt3/broker-ca,file=''${ca//,/,,}" \
        "$@"

      if [ -n "$throwaway" ]; then
        # The throwaway disk is an empty layer on top of the normal disk.
        # The VM reads through it to the normal disk, and everything it
        # writes stays in the layer. Deleting the layer undoes the run. The
        # normal disk is opened for reading only and is not changed.
        #
        # The normal disk is named without its folder, which QEMU takes as
        # "beside the layer". A full path would break on a folder name with
        # a colon in it.
        ${qemu_kvm}/bin/qemu-img create -q -f qcow2 -F qcow2 -b disk.qcow2 "$state/throwaway.qcow2"
        export NIX_DISK_IMAGE="$state/throwaway.qcow2"

        # Unlike the normal start, this script stays until QEMU has ended, to
        # delete the layer then. It holds the lock until it is done, so the
        # next start cannot come in between. If this script is killed, the
        # layer is deleted by the next start or \`nix run .#stop\` instead.
        trap 'rm -f "$state/throwaway.qcow2"; echo "agent-vm: the throwaway run has ended. What it wrote is gone." >&2' EXIT
        echo "agent-vm: throwaway run. Everything written in the VM is discarded when it stops." >&2
        ${vm}/bin/run-agent-vm-vm "$@"
        exit
      fi

      exec ${vm}/bin/run-agent-vm-vm "$@"
    '';
  };

  # A throwaway run of the VM: a clean environment for one task, without
  # building anything. It starts from the normal disk as it is now, so Claude
  # is signed in and T3 is paired, and everything written during the run is
  # discarded when the VM stops: cloned repos, T3's threads, changed settings.
  # The normal disk is not changed.
  #
  # It is a command of its own and not a variable such as AGENT_VM_FRESH=1,
  # because a variable can stay behind in a shell. A later `nix run .#vm`
  # would then throw away a day's work without saying so. A command has to be
  # typed each time.
  #
  # It cannot run beside the normal VM: both take the same lock, see above.
  # `nix run .#stop`, `.#ssh`, `.#status` and the rest work as for the
  # normal VM.
  vm-fresh = writeShellApplication {
    name = "agent-vm-fresh";
    text = ''
      exec ${self.vm}/bin/agent-vm --throwaway "$@"
    '';
  };

  # Runs the broker in this terminal, where its log can be read as it is
  # written. If `nix run .#vm` has a broker running in the background, this
  # one takes its place, which is also how a change to the rules is applied
  # while the VM keeps running.
  broker = writeShellApplication {
    name = "agent-vm-broker";
    text = ''
      state=${stateDir}

      ${brokerFunctions}
      if broker_pid >/dev/null; then
        echo "agent-vm: taking over from the broker in the background. When this one" >&2
        echo "agent-vm: ends, the VM has no way out until a broker is started again." >&2
        stop_broker
      fi
      if [ -n "''${AGENT_BROKER_RULES:-}" ]; then
        echo "agent-vm: using the rules in $AGENT_BROKER_RULES, not the repo's." >&2
      fi

      # Recorded so that \`nix run .#vm\` can tell this broker from some
      # other program on the port. \`exec\` keeps the process id.
      mkdir -p "$state"
      echo "$$" >"$state/broker-foreground.pid"
      exec ${brokerRun}/bin/agent-vm-broker-run "$@"
    '';
  };

  # Shuts down the VM, then stops the broker in the background. Either may be
  # running without the other.
  #
  # The VM is stopped by pressing its power button through QEMU's control
  # socket, so the system shuts down cleanly. If it has not stopped after a
  # minute, QEMU is told to quit, which is like pulling the plug.
  #
  # After a throwaway run (`nix run .#vm-fresh`) the run's disk is deleted
  # here too, if the start command has not done so already.
  stop = writeShellApplication {
    name = "agent-vm-stop";
    runtimeInputs = [
      socat
      flock
    ];
    text = ''
      state=${stateDir}

      ${brokerFunctions}
      ${vmFunctions}

      # Deletes the disk of a throwaway run, also one left by a run that
      # ended by a crash. The lock is the one a VM holds for as long as it
      # runs (see the start command). Taking it first means the disk of a VM
      # that is running, for example one started a moment ago, is never
      # deleted. If the lock is taken, the disk is left for its owner.
      remove_throwaway() {
        [ -e "$state/throwaway.qcow2" ] || return 0
        if (exec 9>>"$state/vm.lock" && flock -n 9 && rm -f "$state/throwaway.qcow2") 2>/dev/null; then
          echo "agent-vm: the throwaway run's disk is deleted. What that run wrote is gone." >&2
        fi
      }

      qmp() {
        {
          printf '{"execute":"qmp_capabilities"}\n{"execute":"%s"}\n' "$1"
          sleep 1
        } | socat - "UNIX-CONNECT:$state/qmp.sock" >/dev/null
      }

      stop_vm() {
        local pid
        if [ ! -S "$state/qmp.sock" ] || [ ! -f "$state/qemu.pid" ] || ! kill -0 "$(cat "$state/qemu.pid")" 2>/dev/null; then
          echo "agent-vm: VM not running" >&2
          return
        fi
        pid=$(cat "$state/qemu.pid")

        if vm_is_throwaway "$pid"; then
          echo "agent-vm: this is a throwaway run. What it wrote is discarded." >&2
        fi
        echo "agent-vm: shutting down" >&2
        qmp system_powerdown
        for _ in $(seq 60); do
          if ! kill -0 "$pid" 2>/dev/null; then
            rm -f "$state/qemu.pid" "$state/qmp.sock"
            echo "agent-vm: stopped" >&2
            return
          fi
          sleep 1
        done

        echo "agent-vm: still running after a minute, switching it off" >&2
        qmp quit || kill "$pid"
        rm -f "$state/qemu.pid" "$state/qmp.sock"
      }

      # The broker goes last, and also when stopping the VM went wrong.
      trap stop_broker EXIT
      stop_vm
      remove_throwaway
    '';
  };

  # Runs the checks in ../tests inside the VM. Most of them pass when
  # something fails: they try to get around the network lock.
  check = writeShellApplication {
    name = "agent-vm-check";
    text = ''
      state=${stateDir}

      # One check sends a TLS hello with the wrong site name. Only the
      # broker's log can show that the broker is what stopped it.
      count() { grep -c " tls tls-name-differs" "$state/broker.log" 2>/dev/null || true; }
      before=$(count)

      status=0
      ${ssh}/bin/agent-vm-ssh bash -s <${../tests/network-lock.sh} || status=$?

      echo "On the Mac:"
      if [ "$(count)" -gt "$before" ]; then
        echo "  ok    the broker logged the wrong site name as refused"
      else
        echo "  FAIL  the broker logged the wrong site name as refused"
        echo "        (not checked when the broker runs in a terminal, where it has no log file)"
        status=1
      fi
      exit "$status"
    '';
  };

  # Follows the log of the broker that `nix run .#vm` started: one line for
  # each destination the VM asked for, and whether it was allowed.
  logs = writeShellApplication {
    name = "agent-vm-logs";
    text = ''
      state=${stateDir}

      if [ ! -f "$state/broker.log" ]; then
        echo "agent-vm: no broker log yet. It appears when the VM is first started." >&2
        exit 1
      fi
      # -F follows the name: when a start moves the log aside and begins a
      # new one, this carries on with the new one.
      exec tail -n 40 -F "$state/broker.log"
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

  # Answers "is it working?" on one screen: the VM, the broker, SSH, the T3
  # server and its version, the Claude sign-in, the tokens, who holds the VM,
  # what the broker refused last, and how large the files have grown.
  #
  # It changes nothing: it creates no file, takes no lock and runs no token
  # command. Every question it asks has a time limit, so it answers within
  # seconds also when the VM hangs. It works when nothing runs and when the
  # state folder does not exist yet.
  #
  # It ends with status 0 when the VM and all it needs are up, 1 when
  # something that should be up is down (the lines marked FAIL), and 2 when
  # the VM is simply not running. A line marked `warn` works today but wants
  # attention; it does not change the status.
  #
  # Much of what is shown comes from the VM or was caused by it: log lines,
  # version numbers, the notes of other agents. It is shown with everything
  # but plain letters and signs replaced, so that it cannot move the cursor
  # or recolour the terminal.
  status = writeShellApplication {
    name = "agent-vm-status";
    runtimeInputs = [
      coreutils
      curl
      jq
    ];
    text = ''
      state=${stateDir}

      ${brokerFunctions}
      ${vmFunctions}
      ${t3AppVersion}

      # Treat text as plain bytes everywhere below, so that the clean-up of
      # what is shown works the same whatever language the Mac is set to.
      # It is set once here and not in front of single commands: bash 5.3
      # crashed now and then (about one run in six) with `LC_ALL=C tr ...`
      # inside a function.
      export LC_ALL=C

      problems=0
      row() { printf '  %-5s %-11s %s\n' "$1" "$2" "$3"; }
      more() { row "" "" "$1"; }
      ok() { row ok "$@"; }
      off() { row -- "$@"; }
      note() { row note "$@"; }
      warn() { row warn "$@"; }
      fail() {
        row FAIL "$@"
        problems=$((problems + 1))
      }

      # Replaces everything that is not a plain printable character.
      plain() { tr -c '\n\40-\176' '?'; }

      # Prints how long the process $1 has run, such as "2h 5m". `ps` gives
      # it as [[days-]hours:]minutes:seconds.
      running_for() {
        local time days=0 hours=0 minutes seconds first second third
        time=$(/bin/ps -o etime= -p "$1" 2>/dev/null | tr -d ' ')
        if [[ ! $time =~ ^([0-9]+-)?([0-9]+:)?[0-9]+:[0-9]+$ ]]; then
          echo "an unknown time"
          return 0
        fi
        if [[ $time == *-* ]]; then
          days=''${time%%-*}
          time=''${time#*-}
        fi
        IFS=: read -r first second third <<<"$time"
        if [ -n "$third" ]; then
          hours=$first minutes=$second seconds=$third
        else
          minutes=$first seconds=$second
        fi
        # 10# reads "08" as eight, not as a broken octal number.
        days=$((10#$days)) hours=$((10#$hours)) minutes=$((10#$minutes)) seconds=$((10#$seconds))
        if [ "$days" -gt 0 ]; then
          echo "''${days}d ''${hours}h"
        elif [ "$hours" -gt 0 ]; then
          echo "''${hours}h ''${minutes}m"
        elif [ "$minutes" -gt 0 ]; then
          echo "''${minutes}m"
        else
          echo "''${seconds}s"
        fi
      }

      # Prints the size of the file $1, such as 204MB.
      size_of() { numfmt --to=iec --suffix=B "$(stat -L -c %s "$1" 2>/dev/null || echo 0)"; }

      echo "nixt3 status"
      if [ -d "$state" ]; then
        echo "state folder: $state"
      else
        echo "state folder: $state (not there yet; \`nix run .#vm\` creates it)"
      fi
      echo

      # --- The VM
      vm_up=
      throwaway_up=
      if pid=$(vm_pid); then
        vm_up=yes
        if vm_is_throwaway "$pid"; then
          throwaway_up=yes
          ok VM "running for $(running_for "$pid") as process $pid, as a throwaway run"
          more "what it writes is discarded when it stops; the normal disk is not changed"
        else
          ok VM "running for $(running_for "$pid") as process $pid, on its normal disk"
        fi
      elif [ -e "$state/qemu.pid" ]; then
        off VM "not running. It ended without \`nix run .#stop\`; the next start tidies up"
      else
        off VM "not running"
      fi
      if [ -z "$throwaway_up" ] && [ -e "$state/throwaway.qcow2" ]; then
        warn "" "a throwaway run left its disk behind ($(size_of "$state/throwaway.qcow2")). It is not used again;"
        more "the next start or \`nix run .#stop\` deletes it"
      fi

      # --- The broker
      broker_up=
      address="localhost:${toString ports.broker}"
      if pid=$(broker_pid); then
        if broker_port_open; then
          broker_up=yes
          ok Broker "running for $(running_for "$pid") as process $pid in the background, on $address"
          started=$(grep -a ' started ' "$state/broker.log" 2>/dev/null | tail -n 1 | plain | cut -c1-200) || true
          if [ -n "$started" ]; then
            more "$started"
            # The rules are part of what a command is built from. If the
            # broker's differ from this checkout's, it was started from
            # another checkout or before a change.
            case "$started" in
              *" rules=${brokerFiles}/rules.yaml"*) ;;
              *) more "its rules are not the ones of this checkout; a restart of the broker applies these" ;;
            esac
          fi
        elif [ -n "$vm_up" ]; then
          fail Broker "process $pid was started $(running_for "$pid") ago and does not answer on $address"
          more "it may be waiting for a token; the VM has no way out until it answers. See $state/broker.log"
        else
          warn Broker "process $pid was started $(running_for "$pid") ago and does not answer on $address yet"
          more "it may be waiting for your password manager to hand over a token"
        fi
      elif foreground_broker_running; then
        pid=$(cat "$state/broker-foreground.pid")
        if broker_port_open; then
          broker_up=yes
          ok Broker "running for $(running_for "$pid") as process $pid in a terminal (\`nix run .#broker\`), on $address"
          more "its log is in that terminal, so broker.log below is from an earlier broker"
        elif [ -n "$vm_up" ]; then
          fail Broker "process $pid in a terminal does not answer on $address; the VM has no way out"
        else
          warn Broker "process $pid in a terminal does not answer on $address yet"
        fi
      elif broker_port_open; then
        fail Broker "$address is taken by a program that is not this state folder's broker, so the VM will not start"
        more "find it with: lsof -nP -iTCP:${toString ports.broker} -sTCP:LISTEN"
      elif [ -n "$vm_up" ]; then
        fail Broker "not running, so the VM has no way out"
        more "start one with \`nix run .#broker\`, or restart the VM"
      else
        off Broker "not running"
      fi
      if [ -z "$vm_up" ] && [ -n "$broker_up" ]; then
        more "it runs without the VM and holds the tokens; \`nix run .#stop\` ends a background broker"
      fi

      # --- What runs inside the VM. Asked only when the VM is up, so that
      # nothing here waits for an answer that cannot come.
      ssh_up=
      vm_t3=
      if [ -n "$vm_up" ]; then
        if timeout 10 ${ssh}/bin/agent-vm-ssh -o BatchMode=yes -o ConnectTimeout=5 true </dev/null 2>/dev/null; then
          ssh_up=yes
          ok SSH "answers on localhost:${toString ports.ssh}"
        else
          fail SSH "no answer on localhost:${toString ports.ssh}. A VM needs about a minute after its start"
        fi

        # The T3 server says which version it is at an address made for that.
        answer=$(curl --silent --fail --max-time 5 --noproxy '*' "http://127.0.0.1:${toString ports.t3}/.well-known/t3/environment" 2>/dev/null) || answer=
        vm_t3=$(jq -r '.serverVersion | strings' <<<"$answer" 2>/dev/null | head -n 1 | tr -cd '0-9A-Za-z.+-' | cut -c1-40) || vm_t3=
        if [ -n "$vm_t3" ]; then
          ok "T3 server" "answers on localhost:${toString ports.t3}"
        else
          fail "T3 server" "no answer on localhost:${toString ports.t3}. Its log: nix run .#ssh -- journalctl -u t3 -e"
        fi
      else
        off SSH "not asked, the VM is not running"
        off "T3 server" "not asked, the VM is not running"
      fi

      # --- The T3 server in the VM should be the version of the T3 app.
      app_t3=$(t3_app_version) || app_t3=
      if [ -z "$app_t3" ]; then
        note "T3 version" "''${vm_t3:-${t3Pinned}} in the VM; the T3 app's version on this Mac could not be read"
      elif [ -n "$vm_t3" ] && [ "$vm_t3" != "$app_t3" ]; then
        warn "T3 version" "the VM runs $vm_t3 and the T3 app on the Mac is $app_t3. They should be the same"
        if [ "${t3Pinned}" = "$app_t3" ]; then
          more "this checkout has $app_t3 already; restart the VM to get it"
        else
          more "run \`nix run .#update-t3\`, then restart the VM"
        fi
      elif [ -n "$vm_t3" ]; then
        ok "T3 version" "$vm_t3 in the VM and in the T3 app on the Mac"
        if [ "${t3Pinned}" != "$vm_t3" ]; then
          warn "" "this checkout has ${t3Pinned}, which the VM gets at its next start. Run \`nix run .#update-t3\`"
        fi
      elif [ "${t3Pinned}" != "$app_t3" ]; then
        warn "T3 version" "this checkout puts ${t3Pinned} in the VM and the T3 app on the Mac is $app_t3"
        more "run \`nix run .#update-t3\` before the next start"
      else
        ok "T3 version" "${t3Pinned} in this checkout and in the T3 app on the Mac"
      fi

      # --- Claude's sign-in is on the VM's disk. `claude auth status` prints
      # a few facts about it, of which only "loggedIn" is looked at; the rest
      # names the account and is not shown.
      if [ -n "$ssh_up" ]; then
        answer=$(timeout 15 ${ssh}/bin/agent-vm-ssh -o BatchMode=yes -o ConnectTimeout=5 claude auth status </dev/null 2>/dev/null) || true
        case "$(jq -r '.loggedIn' <<<"$answer" 2>/dev/null)" in
          true) ok Claude "signed in inside the VM" ;;
          false) warn Claude "not signed in inside the VM. Sign in with: nix run .#ssh -- -t claude" ;;
          *) warn Claude "\`claude auth status\` in the VM gave no answer, so the sign-in is unknown" ;;
        esac
      else
        off Claude "not asked, the VM does not answer"
      fi

      # --- The tokens. The rules name each token the broker must hold, and
      # a file of the user's own names the command that prints it. The same
      # code that the broker's start uses reads both here, up to the point
      # where it would run a command. No command is run and no token is read.
      tokens_file="''${AGENT_BROKER_TOKENS:-''${XDG_CONFIG_HOME:-$HOME/.config}/nixt3/tokens.yaml}"
      report=$(
        ${tokenPython}/bin/python3 -B - ${brokerFiles} "$tokens_file" 2>/dev/null <<'PYTHON'
      import sys

      sys.path.insert(0, sys.argv[1])
      import fetch_tokens

      try:
          names = fetch_tokens.needed_tokens(sys.argv[1] + "/rules.yaml")
          print("needs", " ".join(names))
          if names:
              fetch_tokens.load_commands(sys.argv[2], names)
          print("ready")
      except fetch_tokens.FetchError as error:
          print("problem", str(error).splitlines()[0])
      PYTHON
      ) || report="problem the rules and the tokens file could not be read"
      report=$(plain <<<"$report")
      needs=$(sed -n 's/^needs //p' <<<"$report")
      problem=$(sed -n 's/^problem //p' <<<"$report" | cut -c1-300)
      if [ -n "$problem" ]; then
        warn Tokens "the broker will not start: $problem"
      elif [ -z "$needs" ]; then
        off Tokens "the rules ask for no token"
      else
        ok Tokens "the rules need: $needs. $tokens_file names a command for each"
      fi

      # --- Agents that work at the same time take turns with the VM by
      # making this folder, and leave a note in it saying who they are.
      if [ -d "$state/in-use" ]; then
        note "In use" "an agent holds the VM since $(stat -c %y "$state/in-use" 2>/dev/null | cut -c1-16). Do not stop or restart it"
        shown=0
        for file in "$state/in-use"/*; do
          if [ -f "$file" ] && [ "$shown" -lt 3 ]; then
            more "its note: $(head -n 1 "$file" 2>/dev/null | plain | cut -c1-200)"
            shown=$((shown + 1))
          fi
        done
      else
        off "In use" "no agent holds the VM (no \`in-use\` folder)"
      fi

      # --- What the VM asked for and did not get. A host that is unknown
      # here, or one refused again and again, is worth a look.
      echo
      refused=$(grep -aE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+ refused ' "$state/broker.log" 2>/dev/null | tail -n 5 | plain | cut -c1-160 | sed 's/ refused /  /') || true
      if [ ! -f "$state/broker.log" ]; then
        echo "Refused destinations: there is no broker.log yet"
      elif [ -z "$refused" ]; then
        echo "Refused destinations: none in broker.log"
      else
        echo "The last refused destinations in broker.log (time, host, port, how, why):"
        while IFS= read -r line; do
          echo "  $line"
        done <<<"$refused"
      fi

      # --- Sizes. The disk grows as the VM is used. The two logs are moved
      # aside at a start once they pass 5 MiB, not while the VM runs.
      echo
      echo "Sizes:"
      found=
      for name in disk.qcow2 throwaway.qcow2 broker.log console.log; do
        if [ -f "$state/$name" ]; then
          found=yes
          line=$(size_of "$state/$name")
          old=0
          for file in "$state/$name".[0-9]; do
            if [ -f "$file" ]; then old=$((old + 1)); fi
          done
          if [ "$old" -gt 0 ]; then
            line="$line, and $old older part(s) beside it"
          fi
          case "$name" in
            *.log)
              if [ "$(stat -L -c %s "$state/$name" 2>/dev/null || echo 0)" -gt $((5 * 1024 * 1024)) ]; then
                line="$line; it is moved aside at the next start"
              fi
              ;;
          esac
          printf '  %-16s %s\n' "$name" "$line"
        fi
      done
      if [ -z "$found" ]; then
        echo "  nothing there yet"
      fi

      echo
      if [ "$problems" -gt 0 ]; then
        echo "Not working: see the $problems line(s) marked FAIL."
        exit 1
      fi
      if [ -z "$vm_up" ]; then
        echo "The VM is not running. Start it with: nix run .#vm"
        exit 2
      fi
      echo "Everything is up."
    '';
  };

  # Makes the T3 server in the VM the version of the T3 app on this Mac. The
  # two should be the same, and the app updates itself, so the VM falls
  # behind. This rewrites the version and the checksum in vm/t3.nix, in the
  # checkout it is run from. Nothing else is changed and nothing is built:
  # the next start of the VM does that.
  #
  #   nix run .#update-t3            the version of the T3 app
  #   nix run .#update-t3 -- 0.1.8   that version, whatever the app is
  #
  # The checksum comes from the file SHA256SUMS that each release on GitHub
  # carries. AGENT_VM_T3_RELEASES names another place to fetch releases from,
  # which is how this command is tested without GitHub.
  update-t3 = writeShellApplication {
    name = "agent-vm-update-t3";
    runtimeInputs = [
      coreutils
      curl
      gnused
    ];
    text = ''
      ${t3AppVersion}

      fail() {
        echo "update-t3: $1" >&2
        exit 1
      }

      # The file to change is the one in the checkout this is run from, not
      # the copy in the Nix store that this command was built from.
      checkout=$PWD
      while [ ! -f "$checkout/flake.nix" ] || [ ! -f "$checkout/vm/t3.nix" ]; do
        if [ "$checkout" = / ] || [ -z "$checkout" ]; then
          fail "run this inside a checkout of nixt3; no vm/t3.nix was found in $PWD or above it"
        fi
        checkout=$(dirname "$checkout")
      done
      file="$checkout/vm/t3.nix"

      if [ "$#" -gt 1 ]; then
        fail "give one version at most, such as 0.1.8"
      elif [ "$#" -eq 1 ]; then
        version=''${1#v}
      else
        version=$(t3_app_version) || fail "the version of the T3 app could not be read (~/.t3/bin/t3 --version). Open the app once, or give the version: nix run .#update-t3 -- 0.1.8"
      fi
      # The version becomes part of an address and of a file, so it must be
      # a version and nothing else.
      if [[ ! $version =~ ^[0-9]+(\.[0-9]+)+(-[0-9A-Za-z.]+)?$ ]]; then
        fail "\"$version\" does not look like a version such as 0.1.8"
      fi

      # What the file pins now. Each of the two lines must be there exactly
      # once, or this command does not know what it would be changing.
      version_line='^[[:space:]]*version = "[^"]*";$'
      checksum_line='^[[:space:]]*sha256 = "[0-9a-f]{64}";$'
      if [ "$(grep -cE "$version_line" "$file")" != 1 ] || [ "$(grep -cE "$checksum_line" "$file")" != 1 ]; then
        fail "$file does not have exactly one \`version = \"...\";\` line and one \`sha256 = \"...\";\` line, so it is left alone"
      fi
      old_version=$(sed -nE 's/^[[:space:]]*version = "([^"]*)";$/\1/p' "$file")
      old_checksum=$(sed -nE 's/^[[:space:]]*sha256 = "([0-9a-f]{64})";$/\1/p' "$file")

      # The release's list of checksums, one line per file:
      #   <64 hex digits>  t3-0.1.8-linux-arm64.tar.gz
      releases="''${AGENT_VM_T3_RELEASES:-https://github.com/pingdotgg/t3code/releases/download}"
      url="$releases/v$version/SHA256SUMS"
      archive="t3-$version-linux-arm64.tar.gz"
      status=0
      sums=$(curl --fail --silent --show-error --location --max-time 60 "$url") || status=$?
      if [ "$status" -eq 22 ]; then
        fail "there is no $url. Either T3 $version is not released, or the release has no checksum file. vm/t3.nix is unchanged"
      elif [ "$status" -ne 0 ]; then
        fail "could not fetch $url (curl ended with status $status). vm/t3.nix is unchanged"
      fi
      # The name may have a "*" or "./" in front, which checksum tools add.
      checksum=$(awk -v name="$archive" '{ file = $2; sub(/^\*/, "", file); sub(/^\.\//, "", file) } file == name { print tolower($1) }' <<<"$sums")
      if [ -z "$checksum" ]; then
        fail "$url has no line for $archive, the server for the VM. vm/t3.nix is unchanged"
      fi
      if [[ ! $checksum =~ ^[0-9a-f]{64}$ ]]; then
        fail "the line for $archive in $url does not hold one SHA-256 checksum. vm/t3.nix is unchanged"
      fi

      if [ "$version" = "$old_version" ] && [ "$checksum" = "$old_checksum" ]; then
        echo "vm/t3.nix already has T3 $version with the release's checksum. Nothing changed."
        exit 0
      fi

      # Write the new text beside the file, look at it, and only then put it
      # in place, so that a failure half way leaves the file as it was.
      new=$(mktemp "$file.XXXXXX")
      trap 'rm -f "$new"' EXIT
      sed -E \
        -e "s/^([[:space:]]*version = \")[^\"]*(\";)\$/\1$version\2/" \
        -e "s/^([[:space:]]*sha256 = \")[0-9a-f]{64}(\";)\$/\1$checksum\2/" \
        "$file" >"$new"
      if [ "$(sed -nE 's/^[[:space:]]*version = "([^"]*)";$/\1/p' "$new")" != "$version" ] ||
        [ "$(sed -nE 's/^[[:space:]]*sha256 = "([0-9a-f]{64})";$/\1/p' "$new")" != "$checksum" ] ||
        [ "$(wc -l <"$new")" != "$(wc -l <"$file")" ]; then
        fail "rewriting $file did not give the expected result. It is unchanged"
      fi
      # `cat` into the file keeps its permissions, which `mv` would not.
      cat "$new" >"$file"

      echo "Changed $file:"
      if [ "$version" != "$old_version" ]; then
        echo "  version   $old_version -> $version"
      else
        echo "  version   $version (as before)"
      fi
      echo "  checksum  $old_checksum"
      echo "         -> $checksum"
      echo "The VM runs the new server after a restart: nix run .#stop, then nix run .#vm."
      echo "That start builds the VM anew, which takes a few minutes. Commit the change to keep it."
    '';
  };
})
