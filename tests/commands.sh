#!/usr/bin/env bash
# Checks the commands that run on the Mac (darwin/commands.nix), with no VM.
#
# The real commands are built, but with three things replaced, the same way
# flake.nix hands them the real ones:
#
#   vm       the script that starts QEMU. The stand-in starts a small program
#            that behaves like QEMU as far as the commands can tell: it keeps
#            the lock it inherits, writes its process id where it is told to,
#            and ends when the control socket is told to power down.
#   openssh  `ssh` answers as a VM would, without connecting anywhere.
#   ports    ports of this test's own, so the real VM and broker are not met.
#
# Everything else is real: the lock, the throwaway layer (made by the real
# qemu-img on a tiny disk), the broker (started with a made-up token), the
# log upkeep, `status` and `update-t3`. The last one fetches from a small
# server on this machine instead of GitHub.
#
# Run it from the repo:
#
#   tests/commands.sh
#
# It needs `nix` and takes under a minute once the commands are built. It
# works in a temporary folder of its own, sets HOME to a folder in there for
# the commands it runs, and ends every program it started. The real state
# folder, VM and broker are not touched. Nothing here leaves this machine.

set -u

cd "$(dirname "$0")/.." || exit 1
repo=$PWD

# Ports for this test. They are part of what the commands are built from, so
# they are fixed here; the test stops at once if one of them is in use.
ssh_port=42222
t3_port=43774
broker_port=48474
releases_port=48475

failures=0
pass() { echo "  ok    $1"; }
fail() {
  echo "  FAIL  $1"
  failures=$((failures + 1))
}
# check <description> <command...>: passes when the command succeeds.
check() {
  local what=$1
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}
# check_not <description> <command...>: passes when the command fails.
check_not() {
  local what=$1
  shift
  if "$@" >/dev/null 2>&1; then fail "$what"; else pass "$what"; fi
}
# check_status <description> <wanted status> <command...>
check_status() {
  local what=$1 wanted=$2 got=0
  shift 2
  "$@" >/dev/null 2>&1 || got=$?
  if [ "$got" = "$wanted" ]; then pass "$what"; else fail "$what (status $got, wanted $wanted)"; fi
}
# said <file> <text>: succeeds when the file holds the text.
said() { grep -qF -- "$2" "$1"; }

# The temporary folder. Its real path is used, because the commands compare
# paths with what `ps` shows, and macOS reaches /var through a link.
work=$(cd "$(mktemp -d)" && pwd -P)
state="$work/state folder"
mkdir -p "$work/standins" "$work/home/.t3/bin" "$work/www" "$work/checkout/vm"

# Ends every program whose command line names the temporary folder: the
# stand-in QEMU (its pid file is in there), the broker (its folder is), the
# servers and the start scripts.
end_everything() {
  local pids
  pids=$(pgrep -f "$work" 2>/dev/null | grep -vx "$$" || true)
  # shellcheck disable=SC2086
  [ -n "$pids" ] && kill $pids 2>/dev/null
  sleep 0.3
  pids=$(pgrep -f "$work" 2>/dev/null | grep -vx "$$" || true)
  # shellcheck disable=SC2086
  [ -n "$pids" ] && kill -KILL $pids 2>/dev/null
  return 0
}
cleanup() {
  end_everything
  rm -rf "$work"
}
trap cleanup EXIT

for port in "$ssh_port" "$t3_port" "$broker_port" "$releases_port"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "Port $port on this machine is in use, and this test needs it. Nothing was run."
    exit 1
  fi
done

# --- The stand-ins -----------------------------------------------------------

# In place of the script that NixOS generates. Like that script it takes a
# while before QEMU is there (STANDIN_START_DELAY, in seconds), adds what
# QEMU_OPTS holds to the command line, and then becomes QEMU.
cat >"$work/standins/run-agent-vm-vm" <<'EOF'
#!/bin/bash
if [ -n "${STANDIN_START_DELAY:-}" ]; then sleep "$STANDIN_START_DELAY"; fi
# shellcheck disable=SC2086
exec "$NIXT3_TEST_PYTHON" "$NIXT3_TEST_STANDINS/qemu-system-standin.py" \
  -drive "cache=writeback,file=$NIX_DISK_IMAGE,id=drive1,if=none" ${QEMU_OPTS:-} "$@"
EOF

# In place of QEMU. Its name holds "qemu-system", and its command line holds
# the options the commands look for: -pidfile and the disk.
cat >"$work/standins/qemu-system-standin.py" <<'EOF'
"""Behaves like QEMU as far as the commands on the Mac can tell."""
import os, signal, socket, sys, time

args = sys.argv[1:]
pidfile = args[args.index("-pidfile") + 1]
control = args[args.index("-qmp") + 1].split(",")[0].removeprefix("unix:")

# What it was started with, for the test to read.
with open(os.path.join(os.environ["NIXT3_TEST_WORK"], "qemu.args"), "w") as file:
    file.write("\n".join(args) + "\n")

def end(*_):
    # STANDIN_END_DELAY: seconds it takes to end, as a real VM takes a while.
    time.sleep(float(os.environ.get("STANDIN_END_DELAY", "0")))
    for path in (control,):
        try:
            os.unlink(path)
        except OSError:
            pass
    os._exit(0)

signal.signal(signal.SIGTERM, end)
signal.signal(signal.SIGHUP, end)

listener = socket.socket(socket.AF_UNIX)
listener.bind(control)
listener.listen(5)
with open(pidfile, "w") as file:
    file.write(f"{os.getpid()}\n")

while True:
    connection, _ = listener.accept()
    asked = b""
    connection.settimeout(3)
    try:
        while b"system_powerdown" not in asked and b'"quit"' not in asked:
            piece = connection.recv(4096)
            if not piece:
                break
            asked += piece
    except OSError:
        pass
    connection.close()
    if b"system_powerdown" in asked or b'"quit"' in asked:
        end()
EOF

# In place of ssh. It notes how it was called, and answers the two questions
# `status` asks. The file ssh.down makes it fail like a VM that is not there.
cat >"$work/standins/ssh" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >>"$NIXT3_TEST_WORK/ssh.calls"
if [ -e "$NIXT3_TEST_WORK/ssh.down" ]; then exit 255; fi
case "$*" in
  *"claude auth status") echo '{"loggedIn": true, "email": "someone@example.com"}' ;;
esac
exit 0
EOF
# The start command makes the VM's key with ssh-keygen; the Mac's own will do.
cat >"$work/standins/ssh-keygen" <<'EOF'
#!/bin/bash
exec /usr/bin/ssh-keygen "$@"
EOF
chmod +x "$work/standins/run-agent-vm-vm" "$work/standins/ssh" "$work/standins/ssh-keygen"

# In place of the T3 server in the VM: it says which version it is.
cat >"$work/standins/t3-server.py" <<'EOF'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"serverVersion": sys.argv[2]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        pass

HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
EOF

# In place of GitHub's releases: files from a folder, and a status of the
# test's choosing for an address that starts with /status/<number>/.
cat >"$work/standins/releases.py" <<'EOF'
import os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parts = self.path.split("/")
        if len(parts) > 2 and parts[1] == "status":
            self.send_response(int(parts[2]))
            self.end_headers()
            return
        path = os.path.join(sys.argv[2], self.path.lstrip("/"))
        if ".." in parts or not os.path.isfile(path):
            self.send_response(404)
            self.end_headers()
            return
        with open(path, "rb") as file:
            body = file.read()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        pass

HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
EOF

# --- Build the commands with the stand-ins in place ---------------------------

# The stand-ins handed to commands.nix are two tiny programs in the Nix store
# that pass on to the files above. They never change, so they and the
# commands are built once and then found again on the next run.
cat >"$work/commands.nix" <<EOF
let
  flake = builtins.getFlake "git+file://$repo";
  pkgs = flake.inputs.nixpkgs.legacyPackages.\${builtins.currentSystem};
  standin = name: pkgs.writeShellScriptBin name ''exec "\$NIXT3_TEST_STANDINS/\${name}" "\$@"'';
  commands = pkgs.callPackage (flake.outPath + "/darwin/commands.nix") {
    vm = standin "run-agent-vm-vm";
    openssh = pkgs.symlinkJoin {
      name = "standin-openssh";
      paths = [
        (standin "ssh")
        (standin "ssh-keygen")
      ];
    };
    ports = {
      ssh = $ssh_port;
      t3 = $t3_port;
      broker = $broker_port;
    };
    # See "A stop while the VM is starting" below.
    stopWaitSeconds = 4;
  };
in
pkgs.linkFarm "nixt3-commands-under-test" [
  { name = "vm"; path = "\${commands.vm}/bin/agent-vm"; }
  { name = "vm-fresh"; path = "\${commands.vm-fresh}/bin/agent-vm-fresh"; }
  { name = "stop"; path = "\${commands.stop}/bin/agent-vm-stop"; }
  { name = "status"; path = "\${commands.status}/bin/agent-vm-status"; }
  { name = "ssh"; path = "\${commands.ssh}/bin/agent-vm-ssh"; }
  { name = "update-t3"; path = "\${commands.update-t3}/bin/agent-vm-update-t3"; }
  { name = "python"; path = "\${pkgs.python3}/bin/python3"; }
  { name = "qemu-img"; path = "\${pkgs.qemu_kvm}/bin/qemu-img"; }
  { name = "qemu-io"; path = "\${pkgs.qemu_kvm}/bin/qemu-io"; }
]
EOF
if ! built=$(nix build --impure --no-link --print-out-paths --file "$work/commands.nix" 2>"$work/build.log"); then
  echo "The commands could not be built with the stand-ins:"
  tail -n 30 "$work/build.log"
  exit 1
fi

# Runs a built command, or anything else, the way the test wants the commands
# to see the world: the temporary folder as home and as state folder, a
# tokens file whose command prints a made-up token, and no variable of the
# user's that the commands read.
printf 'tokens:\n  github:\n    command: ["printf", "made-up-token-for-the-commands-test"]\n' >"$work/tokens.yaml"
chmod 600 "$work/tokens.yaml"
world=(
  env -u XDG_STATE_HOME -u XDG_CONFIG_HOME -u AGENT_BROKER_RULES -u AGENT_VM_T3_RELEASES
  HOME="$work/home" AGENT_VM_STATE="$state" AGENT_BROKER_TOKENS="$work/tokens.yaml"
  NIXT3_TEST_WORK="$work" NIXT3_TEST_STANDINS="$work/standins" NIXT3_TEST_PYTHON="$built/python"
)
run() { "${world[@]}" "$@"; }
# start <output file> <command...>: runs a start command detached, as
# CLAUDE.md describes for a tool call. `exec` makes start_pid the process
# id of the start command itself, so that the test can signal it.
start() {
  local out=$1
  shift
  (exec "${world[@]}" "$@") >>"$out" 2>&1 </dev/null &
  start_pid=$!
}

# The process id of the stand-in QEMU, when it is running.
vm_pid() {
  local pid
  pid=$(cat "$state/qemu.pid" 2>/dev/null) || return 1
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && echo "$pid"
}
vm_up() { vm_pid >/dev/null; }
broker_up() { (exec 3<>"/dev/tcp/127.0.0.1/$broker_port") 2>/dev/null; }
# wait_for <command...>: tries for 20 seconds.
wait_for() {
  local tries=0
  until "$@" >/dev/null 2>&1; do
    tries=$((tries + 1))
    [ "$tries" -ge 200 ] && return 1
    sleep 0.1
  done
}
gone() { ! kill -0 "$1" 2>/dev/null; }
nothing_runs() { ! pgrep -f "$state" 2>/dev/null | grep -vx "$$" >/dev/null; }
disk_sum() { shasum -a 256 "$state/disk.qcow2" | cut -d' ' -f1; }
status_of() {
  local got=0
  run "$built/status" >"$work/status.out" 2>&1 || got=$?
  echo "$got"
}

# --- Before anything exists ---------------------------------------------------

echo "With no state folder:"
check_status "status ends with 2 when the VM is not running" 2 run "$built/status"
check_not "status did not create the state folder" test -e "$state"
check_status "ssh refuses to start without the VM's own key" 1 run "$built/ssh" true
check_not "and does not start ssh, which would offer the user's own keys" test -e "$work/ssh.calls"
check_status "stop has nothing to do and says so" 0 run "$built/stop"

mkdir -p "$state"
check_status "a throwaway run without a normal disk is refused" 1 run "$built/vm-fresh"
check_not "and leaves no layer behind" test -e "$state/throwaway.qcow2"
run "$built/stop" >/dev/null 2>&1

# A tiny normal disk with something on it, made by the real qemu-img.
"$built/qemu-img" create -q -f qcow2 "$state/disk.qcow2" 16M
"$built/qemu-io" -f qcow2 -c 'write -P 0x11 0 1M' "$state/disk.qcow2" >/dev/null
disk_before=$(disk_sum)

# --- The normal VM, the lock, and what a shell left over ----------------------

echo "The normal VM:"
QEMU_OPTS="-snapshot" NIXPKGS_QEMU_KERNEL_agent_vm=/nowhere start "$work/start.out" "$built/vm" -name typed-option
check "it starts" wait_for vm_up
check "QEMU_OPTS from the shell is dropped, with a note" said "$work/start.out" "ignoring QEMU_OPTS"
check_not "and does not reach QEMU" grep -qx -- "-snapshot" "$work/qemu.args"
check "a variable that names another kernel is dropped too" said "$work/start.out" "ignoring NIXPKGS_QEMU_KERNEL_agent_vm"
check "an option typed after the command reaches QEMU, with a note" \
  sh -c 'grep -qx "typed-option" "$1/qemu.args" && grep -qF "passing these options to QEMU" "$1/start.out"' sh "$work"
check "QEMU is given the normal disk" said "$work/qemu.args" "file=$state/disk.qcow2,"
check "the broker runs" broker_up
check_not "the broker does not hold the VM's lock" \
  sh -c '/usr/sbin/lsof -t -- "$1/vm.lock" | grep -qx "$(cat "$1/broker.pid")"' sh "$state"

run "$built/vm" >"$work/second.out" 2>&1 </dev/null
check "a second start is refused" said "$work/second.out" "already running"
run "$built/vm-fresh" >"$work/second.out" 2>&1 </dev/null
check "a throwaway start beside it is refused" said "$work/second.out" "already running"
mv "$state/qemu.pid" "$state/qemu.pid.hidden"
run "$built/vm" >"$work/second.out" 2>&1 </dev/null
check "without the pid file, the lock alone refuses a second start" said "$work/second.out" "a VM is running or starting"
check_not "and that refused start created no layer" test -e "$state/throwaway.qcow2"
mv "$state/qemu.pid.hidden" "$state/qemu.pid"

# --- status, with everything up ----------------------------------------------

echo "status:"
pinned=$(sed -nE 's/^[[:space:]]*version = "([^"]*)";$/\1/p' vm/t3.nix)
printf '#!/bin/sh\necho "t3 v%s"\n' "$pinned" >"$work/home/.t3/bin/t3"
chmod +x "$work/home/.t3/bin/t3"
"$built/python" "$work/standins/t3-server.py" "$t3_port" "$pinned" &
t3_server=$!
wait_for sh -c "(exec 3<>/dev/tcp/127.0.0.1/$t3_port)"

check "it ends with 0 when everything is up" test "$(status_of)" = 0
check "it says the VM runs on its normal disk" said "$work/status.out" "on its normal disk"
check "it shows the broker's own start line" grep -qE "^ +[0-9T:+-]+ started destinations=" "$work/status.out"
check "it says Claude is signed in, and not as whom" \
  sh -c 'grep -qF "signed in inside the VM" "$1" && ! grep -qF "someone@example.com" "$1"' sh "$work/status.out"

# What a program in the VM can put in the log: a host named "started", and
# characters that move the cursor or recolour a terminal.
{
  echo "2026-01-31T12:00:00+01:00 refused started 443 connect host-not-listed"
  printf '2026-01-31T12:00:01+01:00 refused evil\033[31m.example 443 connect host-not-listed\n'
  echo "Traceback refused nothing-of-the-broker"
} >>"$state/broker.log"
mkdir "$state/in-use"
printf 'an agent \033]0;title\007 with odd characters\n' >"$state/in-use/owner"
check "it still ends with 0 with such lines in the log" test "$(status_of)" = 0
check "a host named \"started\" is not shown as the broker's start line" \
  sh -c '! grep -qF "refused started" "$1" && ! grep -qF "not the ones of this checkout" "$1"' sh "$work/status.out"
check "a line that is not the broker's is not listed as a refusal" sh -c '! grep -qF "nothing-of-the-broker" "$1"' sh "$work/status.out"
check "the refusals are listed" said "$work/status.out" "evil?[31m.example 443 connect host-not-listed"
check "no escape character reaches the screen" sh -c '! grep -q "$(printf "\033")" "$1" && ! grep -q "$(printf "\007")" "$1"' sh "$work/status.out"
check "it shows who holds the VM" said "$work/status.out" "its note: an agent ?]0;title? with odd characters"
rm -rf "$state/in-use"

touch "$work/ssh.down"
check "it ends with 1 when SSH does not answer" test "$(status_of)" = 1
check "and marks that line" grep -qE "^ +FAIL +SSH" "$work/status.out"
rm "$work/ssh.down"
kill "$t3_server"
wait_for gone "$t3_server"
check "it ends with 1 when the T3 server does not answer" test "$(status_of)" = 1

# --- stop ---------------------------------------------------------------------

echo "stop:"
qemu=$(vm_pid)
check_status "it shuts the VM down" 0 run "$built/stop"
check "the VM has ended" gone "$qemu"
check "the broker has ended" sh -c "! (exec 3<>/dev/tcp/127.0.0.1/$broker_port) 2>/dev/null"
check_not "qemu.pid and qmp.sock are gone" sh -c 'test -e "$1/qemu.pid" || test -e "$1/qmp.sock"' sh "$state"
check "nothing of the test is left running" nothing_runs
check "status ends with 2 again" test "$(status_of)" = 2

# --- A qemu.pid that outlived its VM -----------------------------------------

echo "A qemu.pid left by a VM that ended by a crash:"
# Its number now belongs to another program, and a dead control socket lies
# beside it. Neither may block a start or a stop, and the other program must
# be left alone.
sleep 300 &
bystander=$!
echo "$bystander" >"$state/qemu.pid"
"$built/python" -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$state/qmp.sock"
check "status says they are left over and block nothing" \
  sh -c 'test "$1" = 2 && grep -qF "left qemu.pid or qmp.sock behind" "$2"' sh "$(status_of)" "$work/status.out"
check_status "stop succeeds" 0 run "$built/stop"
check_not "and removes both" sh -c 'test -e "$1/qemu.pid" || test -e "$1/qmp.sock"' sh "$state"
check "and leaves the other program alone" kill -0 "$bystander"

echo "$bystander" >"$state/qemu.pid"
: >"$work/start.out"
start "$work/start.out" "$built/vm"
check "a start is not blocked by it either" wait_for sh -c "test \"\$(cat '$state/qemu.pid')\" != $bystander && kill -0 \"\$(cat '$state/qemu.pid')\""
check "the other program is still alone" kill -0 "$bystander"
run "$built/stop" >/dev/null 2>&1

# A QEMU that is not this folder's, as the Linux builder is. It must not be
# taken for the VM, or stop would end it.
run "$built/python" "$work/standins/qemu-system-standin.py" -pidfile "$work/other.pid" -qmp "unix:$work/other.sock" &
other=$!
wait_for test -s "$work/other.pid"
echo "$other" >"$state/qemu.pid"
check_status "with qemu.pid naming another QEMU, stop still succeeds" 0 run "$built/stop"
check "and that other QEMU keeps running" kill -0 "$other"
kill "$other" "$bystander" 2>/dev/null

# --- A throwaway run ----------------------------------------------------------

echo "A throwaway run:"
: >"$work/start.out"
start "$work/start.out" "$built/vm-fresh"
check "it starts" wait_for vm_up
check "QEMU is given the layer, not the normal disk" said "$work/qemu.args" "file=$state/throwaway.qcow2,"
check "the layer reads through to the normal disk" \
  sh -c '"$1" -c "read -P 0x11 0 1M" "$2/throwaway.qcow2" | grep -q "^read 1048576/1048576"' sh "$built/qemu-io" "$state"
"$built/qemu-io" -c 'write -P 0x22 0 2M' "$state/throwaway.qcow2" >/dev/null
"$built/python" "$work/standins/t3-server.py" "$t3_port" "$pinned" &
wait_for sh -c "(exec 3<>/dev/tcp/127.0.0.1/$t3_port)"
check "status says it is a throwaway run, and ends with 0" \
  sh -c 'test "$1" = 0 && grep -qF "as a throwaway run" "$2"' sh "$(status_of)" "$work/status.out"
run "$built/stop" >"$work/stop.out" 2>&1
check "stop says what kind of run it ends" said "$work/stop.out" "this is a throwaway run"
check "the start command reports the end after QEMU has ended" wait_for said "$work/start.out" "the throwaway run has ended"
check_not "the layer is deleted" test -e "$state/throwaway.qcow2"
check "the normal disk is unchanged, byte for byte" test "$(disk_sum)" = "$disk_before"
check "nothing of the test is left running" wait_for nothing_runs

echo "A throwaway run whose start command is told to end:"
: >"$work/start.out"
STANDIN_END_DELAY=2 start "$work/start.out" "$built/vm-fresh"
wait_for vm_up
qemu=$(vm_pid)
kill -TERM "$start_pid"
sleep 0.7
check "QEMU is still ending, and the run is not reported as ended yet" \
  sh -c 'kill -0 "$1" && ! grep -qF "has ended" "$2"' sh "$qemu" "$work/start.out"
check "the layer is still there while QEMU runs" test -e "$state/throwaway.qcow2"
check "QEMU ends, because the signal was passed on" wait_for gone "$qemu"
check "then the run is reported as ended" wait_for said "$work/start.out" "the throwaway run has ended"
check_not "and the layer is deleted" test -e "$state/throwaway.qcow2"
run "$built/stop" >/dev/null 2>&1

echo "A throwaway run that ends by a crash:"
: >"$work/start.out"
start "$work/start.out" "$built/vm-fresh"
wait_for vm_up
kill -KILL "$start_pid" "$(vm_pid)"
# `wait` here only keeps bash from announcing that the script was killed.
wait "$start_pid" 2>/dev/null
check "its layer is left behind" test -e "$state/throwaway.qcow2"
check "status warns about it" sh -c 'test "$1" = 2 && grep -qF "left its disk behind" "$2"' sh "$(status_of)" "$work/status.out"
run "$built/stop" >"$work/stop.out" 2>&1
check "stop deletes it and says so" sh -c '! test -e "$1/throwaway.qcow2" && grep -qF "disk is deleted" "$2"' sh "$state" "$work/stop.out"
"$built/qemu-img" create -q -f qcow2 -F qcow2 -b disk.qcow2 "$state/throwaway.qcow2"
: >"$work/start.out"
start "$work/start.out" "$built/vm"
wait_for vm_up
check_not "a left-over layer is also deleted by the next normal start" test -e "$state/throwaway.qcow2"
run "$built/stop" >/dev/null 2>&1
check "the normal disk is still unchanged" test "$(disk_sum)" = "$disk_before"

# --- A stop while the VM is starting -----------------------------------------

# A real start takes most of a minute before QEMU is there. The stand-in
# takes as long as STANDIN_START_DELAY says, and the commands under test
# were built to wait 4 seconds for a starting VM, not the real 90.
echo "A stop while the VM is starting:"
: >"$work/start.out"
STANDIN_START_DELAY=2 start "$work/start.out" "$built/vm-fresh"
wait_for said "$work/start.out" "throwaway run."
check "status says the VM is starting, and ends with 2" \
  sh -c 'test "$1" = 2 && grep -qE "^ +-- +VM +starting" "$2"' sh "$(status_of)" "$work/status.out"
check_not "and does not call the layer of that start left over" said "$work/status.out" "left its disk behind"
run "$built/stop" >"$work/stop.out" 2>&1
stopped=$?
check "stop waits for it, shuts it down, and succeeds" \
  sh -c 'test "$1" = 0 && grep -qF "a VM is starting" "$2" && grep -qF "agent-vm: stopped" "$2"' sh "$stopped" "$work/stop.out"
check "nothing of the test is left running" wait_for nothing_runs

: >"$work/start.out"
STANDIN_START_DELAY=8 start "$work/start.out" "$built/vm"
wait_for broker_up
wait_for said "$work/start.out" "SSH on localhost"
run "$built/stop" >"$work/stop.out" 2>&1
stopped=$?
check "when the start takes too long, stop gives up with an error" \
  sh -c 'test "$1" = 1 && grep -qF "still starting after 4 seconds" "$2"' sh "$stopped" "$work/stop.out"
check "and leaves the broker for the VM that is coming" broker_up
check "the VM then comes up" wait_for vm_up
check_status "and a second stop shuts it down" 0 run "$built/stop"
check "nothing of the test is left running" wait_for nothing_runs

# --- The logs -----------------------------------------------------------------

echo "The logs:"
# A log over 5 MiB with three older parts beside it.
big() { head -c $((5 * 1024 * 1024 + 1)) /dev/zero | tr '\0' "$1"; }
for log in broker.log console.log; do
  big a >"$state/$log"
  echo "old part 1" >"$state/$log.1"
  echo "old part 2" >"$state/$log.2"
  echo "old part 3" >"$state/$log.3"
done
# The console log is where the start's own output goes, as in CLAUDE.md.
start "$state/console.log" "$built/vm"
wait_for vm_up
for log in broker.log console.log; do
  check "$log over 5 MiB is moved aside at a start" sh -c 'test "$(head -c 1 "$1.1")" = a && test "$(wc -c <"$1.1")" -gt 5242880' sh "$state/$log"
  check "its older parts move up, and the oldest is dropped" \
    sh -c 'grep -qx "old part 1" "$1.2" && grep -qx "old part 2" "$1.3" && ! test -e "$1.4"' sh "$state/$log"
done
check "the new broker writes its start line to the new broker.log" \
  sh -c 'head -n 1 "$1" | grep -qE "^[0-9T:+-]+ started destinations="' sh "$state/broker.log"
check "the start writes to the new console.log, not the one moved aside" \
  sh -c 'grep -qF "agent-vm: SSH on localhost" "$1" && ! grep -qF "agent-vm:" "$1.1"' sh "$state/console.log"
run "$built/stop" >/dev/null 2>&1
echo "a small log" >"$state/broker.log"
rm -f "$state"/broker.log.?
start "$state/console.log" "$built/vm"
wait_for vm_up
check "a small log is left alone" sh -c 'head -n 1 "$1" | grep -qx "a small log" && ! test -e "$1.1"' sh "$state/broker.log"
run "$built/stop" >/dev/null 2>&1
check "nothing of the test is left running" wait_for nothing_runs

# --- update-t3 ----------------------------------------------------------------

echo "update-t3:"
real_sum=$(sed -nE 's/^[[:space:]]*sha256 = "([0-9a-f]{64})";$/\1/p' vm/t3.nix)
other_sum=$(printf 'B%.0s' $(seq 64))
cp vm/t3.nix "$work/checkout/vm/t3.nix"
touch "$work/checkout/flake.nix"
mkdir -p "$work/www/v$pinned" "$work/www/v9.9.1" "$work/www/v9.9.2" "$work/www/v9.9.3"
printf '%s  t3-%s-linux-x64.tar.gz\n%s  t3-%s-linux-arm64.tar.gz\n' "$other_sum" "$pinned" "$real_sum" "$pinned" >"$work/www/v$pinned/SHA256SUMS"
printf '%s *./t3-9.9.1-linux-arm64.tar.gz\n' "$other_sum" >"$work/www/v9.9.1/SHA256SUMS"
printf '%s  t3-9.9.2-linux-x64.tar.gz\n' "$other_sum" >"$work/www/v9.9.2/SHA256SUMS"
printf 'not-a-checksum  t3-9.9.3-linux-arm64.tar.gz\n' >"$work/www/v9.9.3/SHA256SUMS"
"$built/python" "$work/standins/releases.py" "$releases_port" "$work/www" &
wait_for sh -c "(exec 3<>/dev/tcp/127.0.0.1/$releases_port)"

# update <releases address> [version]: runs the command in the scratch
# checkout and keeps what it said.
update() {
  local from=$1 got=0
  shift
  (cd "$work/checkout" && run env AGENT_VM_T3_RELEASES="$from" "$built/update-t3" "$@") >"$work/update.out" 2>&1 || got=$?
  echo "$got"
}
unchanged() { cmp -s vm/t3.nix "$work/checkout/vm/t3.nix"; }
here="http://127.0.0.1:$releases_port"

check "the app's version, already pinned: nothing changes" \
  sh -c 'test "$1" = 0 && grep -qF "Nothing changed" "$2"' sh "$(update "$here")" "$work/update.out"
check "and the file is as it was" unchanged
check "it says that releases are not fetched from GitHub" said "$work/update.out" "because AGENT_VM_T3_RELEASES is set"
check "a version that is not released fails, naming 404" \
  sh -c 'test "$1" = 1 && grep -qF "answered 404" "$2"' sh "$(update "$here" 9.9.9)" "$work/update.out"
for code in 403 429 500; do
  check "an answer of $code is reported as that, not as \"not released\"" \
    sh -c 'test "$1" = 1 && grep -qF "answered $3" "$2" && ! grep -qF "not released" "$2"' sh "$(update "$here/status/$code" 9.9.9)" "$work/update.out" "$code"
done
check "a release without a line for the VM's server fails" \
  sh -c 'test "$1" = 1 && grep -qF "has no line for" "$2"' sh "$(update "$here" 9.9.2)" "$work/update.out"
check "a line that holds no checksum fails" \
  sh -c 'test "$1" = 1 && grep -qF "does not hold one SHA-256" "$2"' sh "$(update "$here" 9.9.3)" "$work/update.out"
check "a server that is not there fails" test "$(update "http://127.0.0.1:$ssh_port" 9.9.1)" = 1
check "an address that is a file is refused" test "$(update "file://$work/www" 9.9.1)" = 1
check "something that is not a version is refused" test "$(update "$here" "9.9.1/../x")" = 1
check "after all those failures the file is as it was" unchanged

check "a new version is written" test "$(update "$here" 9.9.1)" = 0
check "exactly the version and the checksum changed" \
  sh -c 'test "$(diff "$1" "$2" | grep -c "^[<>]")" = 4 && grep -qF "version = \"9.9.1\";" "$2" && grep -qF "sha256 = \"$3\";" "$2"' \
  sh vm/t3.nix "$work/checkout/vm/t3.nix" "$(echo "$other_sum" | tr 'B' 'b')"
check "going back gives the file of the repo" sh -c 'test "$1" = 0' sh "$(update "$here")"
check "byte for byte" unchanged
check "outside a checkout it fails" sh -c "cd '$work/www' && ! '$built/update-t3' 9.9.1"

# --- Done ---------------------------------------------------------------------

end_everything
check "nothing of the test is left running at the end" nothing_runs

echo
if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) failed."
  exit 1
fi
echo "All checks passed."
