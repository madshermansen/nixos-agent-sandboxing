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
#   broker/      mitmproxy's own files, among them a certificate authority it
#                generates on first start and does not use yet
#   broker.pid   the process id of the broker that `nix run .#vm` started
#   broker.log   that broker's output, one line per decision
{
  writeShellApplication,
  openssh,
  jq,
  socat,
  mitmproxy,
  vm,
  ports,
}:
let
  stateDir = ''"''${AGENT_VM_STATE:-''${XDG_STATE_HOME:-$HOME/.local/state}/agent-vm}"'';

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
      export AGENT_BROKER_RULES="''${AGENT_BROKER_RULES:-${../broker/rules.yaml}}"
      # Write each log line at once, also when the output goes to a file.
      export PYTHONUNBUFFERED=1

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
      #   body_size_limit      a request the broker reads is cut off at this
      #                        size, so the VM cannot fill the Mac's memory;
      #                        traffic passed on untouched is not affected
      #   rawtcp               traffic in a tunnel that is neither TLS nor
      #                        HTTP is dropped instead of passed on
      exec mitmdump \
        --listen-host 127.0.0.1 \
        --listen-port ${toString ports.broker} \
        --set confdir="$state/broker" \
        --set connection_strategy=lazy \
        --set flow_detail=0 \
        --set termlog_verbosity=error \
        --set onboarding=false \
        --set body_size_limit=1m \
        --set rawtcp=false \
        --scripts ${../broker/proxy.py} \
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
      for _ in $(seq 150); do
        if ! kill -0 "$pid" 2>/dev/null; then
          break
        fi
        if broker_port_open; then
          echo "agent-vm: broker on localhost:${toString ports.broker}, log in $state/broker.log" >&2
          exit 0
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

      # The VM can reach nothing but the broker, so the broker comes first.
      ${brokerStart}/bin/agent-vm-broker-start

      if [ ! -f "$state/ssh_key" ]; then
        ssh-keygen -q -t ed25519 -N "" -C agent-vm -f "$state/ssh_key"
      fi

      # The VM reads the public key from its kernel command line at boot.
      QEMU_KERNEL_PARAMS="agentvm.sshkey=$(cut -d' ' -f2 "$state/ssh_key.pub")"
      export QEMU_KERNEL_PARAMS
      export NIX_DISK_IMAGE="$state/disk.qcow2"

      echo "agent-vm: SSH on localhost:${toString ports.ssh}, T3 on localhost:${toString ports.t3}, state in $state" >&2
      # The broker is left running when the VM ends. \`nix run .#stop\` stops
      # it, and the next start replaces it.
      exec ${vm}/bin/run-agent-vm-vm \
        -qmp "unix:$state/qmp.sock,server=on,wait=off" \
        -pidfile "$state/qemu.pid" \
        "$@"
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
  stop = writeShellApplication {
    name = "agent-vm-stop";
    runtimeInputs = [ socat ];
    text = ''
      state=${stateDir}

      ${brokerFunctions}

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
      exec tail -n 40 -f "$state/broker.log"
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
