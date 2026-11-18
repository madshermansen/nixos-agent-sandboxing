#!/usr/bin/env bash
# Shows what the broker's sandbox allows and what it refuses, on the Mac,
# with no VM, no token and no broker.
#
# The broker runs inside a sandbox of macOS, described in broker/sandbox.sb.
# This test takes the profile out of the very start command that
# `nix run .#vm` uses, and runs a small probe under it: a Python program
# that tries, one after another, what a broker that was taken over might
# try (read a file in the home folder, write outside its folder, run a
# shell, connect to another program on the Mac) and what a healthy broker
# must be able to do (read its rules, write to its folder, listen on its
# port, look a name up, connect out to port 443).
#
# The probe is run twice, with the same folders and the same steps: once
# with no sandbox, as a control, and once inside it. A forbidden step counts
# only if it worked in the control and was refused in the sandbox, so a step
# that fails for another reason (a file that is not there) cannot pass for a
# refusal. The probe is run by the same Python as mitmdump, because that is
# the only program the sandbox lets start.
#
# It then shows that the sandbox fails closed: a start command whose profile
# is missing or broken starts no broker, and a broker started with no
# sandbox, or in one that allows everything, refuses to run.
#
# Run it from the repo:
#
#   tests/broker-sandbox.sh
#
# It needs `nix` and a Mac. Four steps use the internet: they look up
# github.com and open a connection to it, without sending a request. On a
# machine with no network those four are skipped, and the test says so.
#
# The VM's broker is not touched, and nothing is written outside a
# temporary folder.

set -u

cd "$(dirname "$0")/.." || exit 1
repo=$PWD

failures=0
skipped=0
pass() { echo "  ok    $1"; }
fail() {
  echo "  FAIL  $1"
  failures=$((failures + 1))
}
skip() {
  echo "  skip  $1"
  skipped=$((skipped + 1))
}
# check <description> <command...>: passes when the command succeeds.
check() {
  local what=$1
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}

if [ ! -x /usr/bin/sandbox-exec ]; then
  echo "This test needs a Mac: there is no /usr/bin/sandbox-exec here."
  exit 1
fi

# The sandbox goes by full paths without symbolic links, and the temporary
# folder of a Mac is reached through one (/var is a link to /private/var).
work=$(cd "$(mktemp -d)" && pwd -P)
pids=()
cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do
    kill "$pid" 2>/dev/null
  done
  rm -rf "$work"
}
trap cleanup EXIT

# --- The start command and its profile ---------------------------------------

echo "Building the broker..."
broker=$(nix build .#broker --no-link --print-out-paths 2>/dev/null)/bin/agent-vm-broker
if [ ! -x "$broker" ]; then
  echo "The broker could not be built: nix build .#broker"
  exit 1
fi
# The command that `nix run .#broker` runs ends in a second one, which
# starts mitmdump. Both are scripts, and the paths are read out of them.
run=$(grep -o '/nix/store/[a-z0-9]*-agent-vm-broker-run/bin/agent-vm-broker-run' "$broker" | head -n 1)
profile=$(grep -o '/nix/store/[a-z0-9]*-broker-sandbox.sb' "$run" | head -n 1)
mitmdump=$(grep -o '/nix/store/[^ "]*/bin/mitmdump' "$run" | head -n 1)
proxy_script=$(grep -o '/nix/store/[^ "]*-broker/proxy.py' "$run" | head -n 1)
# The Python that runs mitmdump is the last program the profile lets start.
python=$(grep -o '^(allow process-exec (literal "[^"]*/bin/python[0-9.]*"))$' "$profile" | tail -n 1 | cut -d'"' -f2)
if [ ! -f "$profile" ] || [ ! -x "$mitmdump" ] || [ ! -f "$proxy_script" ] || [ ! -x "$python" ]; then
  echo "The test did not find the profile, mitmdump, the broker's script and Python in the start command:"
  echo "  $run"
  exit 1
fi

echo "The profile that the start command uses:"

check "mitmdump is started through sandbox-exec, with that profile" \
  grep -q "/usr/bin/sandbox-exec \\\\\$" "$run"
# What comes between `sandbox-exec` and mitmdump: the profile and three
# values, and nothing that could add rules.
between=$(sed -n '/\/usr\/bin\/sandbox-exec/,/\/bin\/mitmdump/p' "$run" | sed '1d;$d' | sed 's/^ *//; s/ *\\$//')
expected="-f $profile
-D BROKER_DIR=\"\$broker_dir\"
-D PORT=$(sed -n 's/^ *--listen-port \([0-9]*\) .*/\1/p' "$run")
-D RULES=\"\$rules\""
[ "$between" = "$expected" ] &&
  pass "it is given the profile and three values, and nothing else" ||
  fail "it is given the profile and three values, and nothing else"

# The profile in the Nix store is the repo's file, with rules added below
# it when the commands were built.
size=$(wc -c <broker/sandbox.sb | tr -d ' ')
[ "$(head -c "$size" "$profile" | shasum)" = "$(shasum <broker/sandbox.sb)" ] &&
  pass "it begins with this checkout's broker/sandbox.sb, byte for byte" ||
  fail "it begins with this checkout's broker/sandbox.sb, byte for byte (is a change not yet added to git?)"
added=$(tail -c +"$((size + 1))" "$profile" | grep -v '^;;' | grep -v '^$')
if [ -n "$added" ] && ! grep -qvE '^\(allow (file-read\* \(subpath|process-exec \(literal) "/nix/store/[^"/]+(/[^"]*)?"\)\)$' <<<"$added"; then
  pass "what was added below it only allows reading and starting things in the Nix store"
else
  fail "what was added below it only allows reading and starting things in the Nix store"
fi
[ "$(grep -c '^(allow process-exec ' <<<"$added")" = 4 ] &&
  pass "four files can be started: mitmdump's two scripts, and the shell and the Python that run them" ||
  fail "four files can be started: mitmdump's two scripts, and the shell and the Python that run them"
check "the whole Nix store is not allowed, only packages by their paths" \
  test -z "$(grep -E '\((subpath|literal|regex) "/nix(/store)?/?"\)' "$profile" | grep -v 'file-read-metadata' | grep -v '^  (literal')"

# Everything is refused first, and nothing is allowed without saying what.
[ "$(grep -c '^(deny default)$' "$profile")" = 1 ] && ! grep -q '(allow default' "$profile" &&
  pass "it refuses everything first, and never allows everything" ||
  fail "it refuses everything first, and never allows everything"
# A rule on one line with no filter, such as `(allow file-read*)`, would
# allow that operation everywhere. One such rule is meant: reading facts
# about the machine.
[ "$(grep -E '^\(allow [a-z*-]+( [a-z*-]+)*\)$' "$profile")" = "(allow sysctl-read)" ] &&
  pass "one operation is allowed without limits: reading facts about the machine" ||
  fail "one operation is allowed without limits: reading facts about the machine"
if grep -qE 'process-fork|mach-lookup|\(allow (signal|iokit|ipc|system-socket|file-write\* \(literal|network-outbound \(remote ip "\*:\*")' <<<"$(grep -v '^;' "$profile")"; then
  fail "no rule allows starting a process, the system's services, or every port"
else
  pass "no rule allows starting a process, the system's services, or every port"
fi

# --- The probe ---------------------------------------------------------------

# It gets what to try as JSON, and prints one line per step: the step's
# name, then `done`, `refused` or `failed`, then a detail. `refused` is the
# error macOS gives for something a sandbox forbids ("Operation not
# permitted"). Any other error is `failed`, with its name.
cat >"$work/probe.py" <<'EOF'
import errno, json, os, socket, sys, time

config = json.loads(sys.argv[1])


def attempt(name, action):
    detail = ""
    try:
        detail = action() or ""
        result = "done"
    except OSError as error:
        if error.errno == errno.EPERM:
            result = "refused"
        else:
            result, detail = "failed", errno.errorcode.get(error.errno, type(error).__name__)
    except Exception as error:
        result, detail = "failed", type(error).__name__
    print(f"{name}\t{result}\t{detail}", flush=True)


def open_it(path):
    """Open a file for reading, without reading it."""
    return lambda: open(path, "rb").close()


def list_it(path):
    return lambda: str(len(os.listdir(path))) + " names"


def create(path):
    """Create a file, and remove it again if that worked."""

    def action():
        with open(path, "x") as file:
            file.write("written by the probe\n")
        os.unlink(path)

    return action


def append(path):
    def action():
        with open(path, "a") as file:
            file.write("# added by the probe\n")

    return action


def connect(host, port):
    def action():
        socket.create_connection((host, port), timeout=10).close()

    return action


def listen(host, port, wait):
    def action():
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        if wait:
            # The test asks macOS about this process meanwhile, and then
            # connects.
            print(f"waiting\t{os.getpid()}\t", flush=True)
            server.settimeout(30)
            server.accept()[0].close()
        server.close()

    return action


def use_own_folder():
    path = os.path.join(config["broker_dir"], "made-by-the-probe")
    with open(path, "w") as file:
        file.write("one")
    with open(path, "a") as file:
        file.write(" two")
    with open(path) as file:
        text = file.read()
    os.rename(path, path + ".moved")
    os.unlink(path + ".moved")
    if text != "one two":
        raise RuntimeError
    return "created, changed, read, renamed, deleted"


def encryption():
    import hashlib, ssl

    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    hashlib.sha256(os.urandom(32))


def fork():
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)


def send_udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"\0" * 12, (config["name_server"], 53))


# What the broker must be able to do.
attempt("read the rules file", open_it(config["rules"]))
attempt("read the broker's own script", open_it(config["proxy_script"]))
attempt("read what mitmproxy is made of", open_it(config["mitmdump"]))
attempt("load the encryption and make random numbers", encryption)
attempt("tell the time in the Mac's time zone", lambda: time.strftime("%z %Z"))
attempt("create, change and delete a file in its own folder", use_own_folder)
attempt("look up the address of a host", lambda: socket.getaddrinfo(config["host"], 443) and None)
attempt("connect out to port 443", connect(config["host"], 443))

# What it must not be able to do. Files first.
attempt("list the home folder", list_it(config["home"]))
attempt("read a file in the home folder", open_it(config["home_file"]))
attempt("read a file in the checkout of this repo", open_it(config["repo_file"]))
attempt("list the state folder, around its own folder", list_it(config["state"]))
attempt("read the SSH key that opens the VM", open_it(config["state"] + "/ssh_key"))
attempt("read the VM's disk", open_it(config["state"] + "/disk.qcow2"))
attempt("read the tokens file", open_it(config["tokens"]))
attempt("read a file beside the rules file", open_it(config["beside_rules"]))
attempt("list the Nix store", list_it("/nix/store"))
attempt("read a file in the Nix store that mitmproxy is not made of", open_it(config["other_store_file"]))
attempt("create a file in the state folder", create(config["state"] + "/made-by-the-probe"))
attempt("create a file in the temporary folder", create(config["tmp"] + "/made-by-the-probe"))
attempt("create a file in /private/tmp", create(f"/private/tmp/nixt3-probe-{os.getpid()}"))
attempt("change the rules file", append(config["rules"]))
attempt("change the SSH key that opens the VM", append(config["state"] + "/ssh_key"))
attempt("delete the VM's disk", lambda: os.unlink(config["state"] + "/disk.qcow2"))

# The network.
attempt("connect to another program on this Mac", connect("127.0.0.1", config["local_port"]))
attempt("connect to port 443 on this Mac itself", connect("127.0.0.1", 443))
attempt("connect out to a port other than 443", connect(config["host"], 80))
attempt("ask a name server directly", send_udp)
attempt("listen on another port", listen("127.0.0.1", config["other_port"], False))

# Programs.
attempt("start a second process", fork)

# Its own port, and a connection from outside.
attempt("listen on its port and take a connection", listen("127.0.0.1", config["port"], True))

# Last, because it replaces this program if it works: the shell then prints
# the line.
attempt("run /bin/sh", lambda: os.execv("/bin/sh", ["/bin/sh", "-c", "printf 'run /bin/sh\\tdone\\t\\n'"]))
EOF

free_port() {
  "$python" -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}
port=$(free_port)
other_port=$(free_port)
local_port=$(free_port)

# "Another program on this Mac": something that takes connections on a port
# of its own, as a database or a development server would.
"$python" -I -c '
import socket, sys
server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", int(sys.argv[1])))
server.listen(16)
while True:
    server.accept()[0].close()
' "$local_port" &
pids+=("$!")

# A file in the home folder to try. Its content is never read: the probe
# only opens it. Any file will do, so the first one that is there is taken.
home_file=""
for candidate in "$HOME/.ssh/known_hosts" "$HOME/.gitconfig" "$HOME/.zshrc" "$HOME/.CFUserTextEncoding" "$HOME/.zprofile" "$HOME/.bash_profile"; do
  if [ -f "$candidate" ]; then
    home_file=$candidate
    break
  fi
done
if [ -z "$home_file" ]; then
  echo "The test found no file in the home folder to try."
  exit 1
fi

# make_world <folder>: a state folder as the start command leaves it, with
# made-up files where the real one has the VM's disk and SSH key, a rules
# file outside the Nix store as AGENT_BROKER_RULES may name one, and a
# tokens file.
make_world() {
  rm -rf "$1"
  mkdir -p "$1/state/broker" "$1/rules" "$1/config"
  echo "a made-up key" >"$1/state/ssh_key"
  echo "a made-up disk" >"$1/state/disk.qcow2"
  cp broker/rules.yaml "$1/rules/rules.yaml"
  echo "beside the rules" >"$1/rules/beside"
  printf 'tokens:\n  github:\n    command: ["/usr/bin/printf", "%%s", "made-up-token-for-the-sandbox-test"]\n' >"$1/config/tokens.yaml"
  chmod 600 "$1/config/tokens.yaml"
}

# run_probe <name> <confined: yes or no>: runs the probe in a world of its
# own, $work/<name>, and leaves what it printed in $work/<name>.out. While
# the probe waits for a connection on its port, macOS is asked from the
# outside what that process may do (broker/confinement.py); the answer is
# left in $work/<name>.asked. Then the connection is made.
run_probe() {
  local name=$1 confined=$2 world="$work/$1" config probe_pid waiting
  make_world "$world"
  config=$("$python" -I -c '
import json, sys
names = ["broker_dir", "state", "rules", "beside_rules", "tokens", "tmp", "home", "home_file",
         "repo_file", "proxy_script", "mitmdump", "other_store_file", "host", "name_server"]
config = dict(zip(names, sys.argv[1:]))
config.update(port=int(sys.argv[-3]), other_port=int(sys.argv[-2]), local_port=int(sys.argv[-1]))
print(json.dumps(config))
' "$world/state/broker" "$world/state" "$world/rules/rules.yaml" "$world/rules/beside" "$world/config/tokens.yaml" \
    "$world" "$HOME" "$home_file" "$repo/CLAUDE.md" "$proxy_script" "$mitmdump" "$run" github.com 1.1.1.1 \
    "$port" "$other_port" "$local_port")

  # As the start command does it: in the broker's folder, with an
  # environment of its own, the profile and its three values. `-I` keeps
  # Python from looking for code in the folder it is started in.
  if [ "$confined" = yes ]; then
    (
      cd "$world/state/broker" && exec /usr/bin/env -i PYTHONUNBUFFERED=1 \
        /usr/bin/sandbox-exec -f "$profile" \
        -D BROKER_DIR="$world/state/broker" -D PORT="$port" -D RULES="$world/rules/rules.yaml" \
        "$python" -I -c "$(cat "$work/probe.py")" "$config"
    ) >"$work/$name.out" 2>"$work/$name.err" &
  else
    (
      cd "$world/state/broker" && exec /usr/bin/env -i PYTHONUNBUFFERED=1 \
        "$python" -I -c "$(cat "$work/probe.py")" "$config"
    ) >"$work/$name.out" 2>"$work/$name.err" &
  fi
  probe_pid=$!
  pids+=("$probe_pid")

  waiting=""
  for _ in $(seq 900); do
    waiting=$(awk -F'\t' '$1 == "waiting" { print $2 }' "$work/$name.out" 2>/dev/null)
    if [ -n "$waiting" ] || ! kill -0 "$probe_pid" 2>/dev/null; then break; fi
    sleep 0.1
  done
  if [ -n "$waiting" ]; then
    "$python" -I broker/confinement.py "$waiting" "$world/state/broker" "$HOME" "$repo" >"$work/$name.asked" 2>&1
    echo "status $?" >>"$work/$name.asked"
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null
  fi
  wait "$probe_pid" 2>/dev/null
}

# result <name> <step>: what a run of the probe printed for a step.
result() { awk -F'\t' -v step="$2" '$1 == step { print $2; exit }' "$work/$1.out"; }
detail() { awk -F'\t' -v step="$2" '$1 == step { print $3; exit }' "$work/$1.out"; }

echo "Running the probe without the sandbox, as a control, and then inside it..."
run_probe control no
run_probe confined yes

# needed <step> [internet]: the step must work inside the sandbox. A step
# marked `internet` is skipped when it did not work in the control either.
needed() {
  local step=$1 inside outside
  outside=$(result control "$step")
  inside=$(result confined "$step")
  if [ "$outside" != done ] && [ "${2:-}" = internet ]; then
    skip "$step: it did not work without the sandbox either (no network?)"
  elif [ "$outside" != done ]; then
    fail "$step: it did not work without the sandbox either (${outside:-no answer} $(detail control "$step"))"
  elif [ "$inside" = done ]; then
    pass "$step"
  else
    fail "$step (${inside:-no answer} $(detail confined "$step"))"
  fi
}

# forbidden <step> [internet|any]: the step must work in the control and be
# refused inside the sandbox. With `any`, the control may end any way but
# `refused`: it is a step that fails without a sandbox too, in another way.
forbidden() {
  local step=$1 inside outside
  outside=$(result control "$step")
  inside=$(result confined "$step")
  if [ "${2:-}" = any ] && [ -n "$outside" ] && [ "$outside" != refused ]; then
    outside=done
  fi
  if [ "$outside" != done ] && [ "${2:-}" = internet ]; then
    skip "$step: it did not work without the sandbox either (no network?)"
  elif [ "$outside" != done ]; then
    fail "$step: it did not work without the sandbox, so the test shows nothing (${outside:-no answer} $(detail control "$step"))"
  elif [ "$inside" = refused ]; then
    pass "$step: refused"
  else
    fail "$step: refused (it was not: ${inside:-no answer} $(detail confined "$step"))"
  fi
}

echo "What the broker needs (each must work inside the sandbox):"
needed "read the rules file"
needed "read the broker's own script"
needed "read what mitmproxy is made of"
needed "load the encryption and make random numbers"
needed "tell the time in the Mac's time zone"
[ -n "$(detail confined "tell the time in the Mac's time zone")" ] &&
  [ "$(detail confined "tell the time in the Mac's time zone")" = "$(detail control "tell the time in the Mac's time zone")" ] &&
  pass "the time zone inside the sandbox is the Mac's ($(detail confined "tell the time in the Mac's time zone"))" ||
  fail "the time zone inside the sandbox is the Mac's"
needed "create, change and delete a file in its own folder"
needed "listen on its port and take a connection"
needed "look up the address of a host" internet
needed "connect out to port 443" internet

echo "Files (each must work without the sandbox and be refused inside it):"
forbidden "list the home folder"
forbidden "read a file in the home folder"
forbidden "read a file in the checkout of this repo"
forbidden "list the state folder, around its own folder"
forbidden "read the SSH key that opens the VM"
forbidden "read the VM's disk"
forbidden "read the tokens file"
forbidden "read a file beside the rules file"
forbidden "list the Nix store"
forbidden "read a file in the Nix store that mitmproxy is not made of"
forbidden "create a file in the state folder"
forbidden "create a file in the temporary folder"
forbidden "create a file in /private/tmp"
forbidden "change the rules file"
forbidden "change the SSH key that opens the VM"
forbidden "delete the VM's disk"
world="$work/confined"
[ "$(cat "$world/state/ssh_key")" = "a made-up key" ] && [ -f "$world/state/disk.qcow2" ] &&
  cmp -s broker/rules.yaml "$world/rules/rules.yaml" && [ "$(ls "$world/state")" = "broker
disk.qcow2
ssh_key" ] && [ -z "$(ls "$world/state/broker")" ] &&
  pass "afterwards the files are as they were, and nothing was left behind" ||
  fail "afterwards the files are as they were, and nothing was left behind"

echo "The network:"
forbidden "connect to another program on this Mac"
# Nothing listens on port 443 of a Mac as a rule, so without the sandbox
# this fails as "connection refused". Inside, the sandbox must stop it first.
forbidden "connect to port 443 on this Mac itself" any
forbidden "connect out to a port other than 443" internet
forbidden "ask a name server directly" internet
forbidden "listen on another port"

echo "Programs:"
forbidden "start a second process"
forbidden "run /bin/sh"

echo "Asking macOS about the running probe, from outside (broker/confinement.py):"
[ "$(cat "$work/confined.asked" 2>/dev/null)" = "status 0" ] &&
  pass "inside the sandbox: nothing is reported" ||
  fail "inside the sandbox: nothing is reported ($(head -n 3 "$work/confined.asked" 2>/dev/null | tr '\n' ' '))"
grep -q "is in no sandbox at all" "$work/control.asked" 2>/dev/null && grep -q "^status 1$" "$work/control.asked" &&
  pass "without the sandbox: it says that the process is in no sandbox" ||
  fail "without the sandbox: it says that the process is in no sandbox"

# --- It fails closed ---------------------------------------------------------

# These start the real start command, changed in one place: a copy of the
# script with another profile named in it, or with the sandbox taken out.
# The command itself offers no way to do either, which is the point: no
# variable and no option reaches the sandbox. So the test edits a copy.
make_world "$work/start"
# start_with <description> <words of the message>: runs the copy in
# $work/run-copy, and passes when no broker comes of it, the message holds
# the words, and nothing listens.
start_with() {
  local what=$1 words=$2 pid
  chmod +x "$work/run-copy"
  AGENT_VM_STATE="$work/start/state" AGENT_BROKER_TOKENS="$work/start/config/tokens.yaml" \
    "$work/run-copy" --listen-port "$port" >"$work/start.log" 2>&1 &
  pid=$!
  pids+=("$pid")
  for _ in $(seq 150); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    fail "$what: no broker starts (one did, and was stopped)"
  elif wait "$pid"; then
    fail "$what: no broker starts"
  elif ! grep -q "$words" "$work/start.log"; then
    fail "$what: no broker starts, and the reason is given ($(tail -n 2 "$work/start.log" | tr '\n' ' '))"
  elif (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    fail "$what: nothing listens afterwards"
  else
    pass "$what: no broker starts, and the reason is given"
  fi
}

echo "When the sandbox cannot be put on, or is not the broker's (each must end without a broker):"

sed "s|$profile|$work/no-such-profile.sb|" "$run" >"$work/run-copy"
start_with "the profile is missing" "sandbox-exec: "

{
  cat "$profile"
  echo "(allow file-read* (subpath"
} >"$work/broken.sb"
sed "s|$profile|$work/broken.sb|" "$run" >"$work/run-copy"
start_with "the profile has a mistake in it" "sandbox-exec: "

# The profile asks for three values. Without one of them macOS does not
# accept it.
sed "/^ *-D PORT=/d" "$run" >"$work/run-copy"
start_with "a value the profile needs is not given" "sandbox-exec: "

# From here the broker itself must refuse: it asks macOS what it may do.
sed -e '/\/usr\/bin\/sandbox-exec/d' -e '/^ *-f \/nix\/store\/.*-broker-sandbox.sb/d' -e '/^ *-D [A-Z_]*=/d' "$run" >"$work/run-copy"
if grep -q "sandbox" <<<"$(grep -v '^ *#' "$work/run-copy")"; then
  fail "the test took the sandbox out of a copy of the start command"
else
  start_with "mitmdump is started with no sandbox" "is in no sandbox at all"
fi

echo "(version 1)(allow default)" >"$work/everything.sb"
sed "s|$profile|$work/everything.sb|" "$run" >"$work/run-copy"
start_with "mitmdump is started in a sandbox that allows everything" "it may start further processes"

# A sandbox that is the broker's but for one thing more: reading the state
# folder around the broker's own, where the VM's disk and SSH key are.
{
  cat "$profile"
  echo "(allow file-read* (subpath \"$work/start/state\"))"
} >"$work/state-too.sb"
sed "s|$profile|$work/state-too.sb|" "$run" >"$work/run-copy"
start_with "mitmdump is started in a sandbox that lets it read the state folder" "it may read $work/start/state"

if grep -rq "made-up-token-for-the-sandbox-test" "$work"/*.log "$work"/*.out "$work"/*.err 2>/dev/null; then
  fail "the made-up token is in nothing these starts wrote"
else
  pass "the made-up token is in nothing these starts wrote"
fi

echo
if [ "$skipped" -gt 0 ]; then
  echo "$skipped check(s) were skipped, because this machine could not reach the internet."
fi
if [ "$failures" -eq 0 ]; then
  echo "All checks passed."
else
  echo "$failures check(s) failed."
  exit 1
fi
