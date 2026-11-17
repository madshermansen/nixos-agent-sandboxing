#!/usr/bin/env bash
# Checks how the broker treats GitHub, on the Mac, with no VM, no GitHub and
# no real token.
#
# It starts a stand-in for GitHub on this machine, a small server that
# answers every request by reporting what it received. It then starts a
# broker of its own, on its own port and with its own state folder, with the
# rules of this repo (broker/rules.yaml) and a tokens file whose command
# prints a made-up token. Requests are sent through that broker the way
# programs in the VM send them, and the stand-in's reports show what the
# broker let out.
#
# The requests are addressed to github.com and api.github.com, by those
# names, because the names are what the broker and its policy go by. Only at
# the last step, when the broker opens its connection to the server, a small
# script loaded for this test sends that connection to the stand-in instead,
# the way a name server would if it gave another address for the name. The
# stand-in has a certificate for both names, from an authority made for this
# run. Nothing in the broker or the policy is changed or loosened for the
# test, and that script refuses every connection it does not redirect, so
# nothing here leaves this machine.
#
# Run it from the repo:
#
#   tests/github-broker.sh
#
# It needs `nix`, `python3`, `openssl` and `curl`. A Mac has the last three;
# if not: nix shell nixpkgs#python3 nixpkgs#openssl nixpkgs#curl -c tests/github-broker.sh
#
# The VM's broker is not touched.

set -u

cd "$(dirname "$0")/.."

placeholder="nixt3-placeholder-not-a-real-token"
standin_token="made-up-token-for-the-broker-test"

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

work=$(mktemp -d)
broker_pid=""
second_pid=""
server_pid=""
cleanup() {
  [ -n "$broker_pid" ] && kill "$broker_pid" 2>/dev/null
  [ -n "$second_pid" ] && kill "$second_pid" 2>/dev/null
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null
  rm -rf "$work"
}
trap cleanup EXIT

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}
server_port=$(free_port)
broker_port=$(free_port)
second_port=$(free_port)

# The one repo that broker/rules.yaml lists, and one that it does not.
listed="madshermansen/nixt3"
unlisted="octocat/Hello-World"
git="https://github.com"
api="https://api.github.com"

# --- The stand-in for GitHub -------------------------------------------------

# A certificate authority, and a certificate from it for GitHub's two names,
# made for this run only. The broker is told to trust the authority, as it
# trusts the real ones for the real GitHub.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=stand-in authority" \
  -keyout "$work/ca.key" -out "$work/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=github.com" \
  -keyout "$work/server.key" -out "$work/server.csr" 2>/dev/null
printf 'subjectAltName=DNS:github.com,DNS:api.github.com\n' >"$work/san.cnf"
openssl x509 -req -in "$work/server.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
  -CAcreateserial -days 2 -extfile "$work/san.cnf" -out "$work/server.pem" 2>/dev/null

cat >"$work/server.py" <<'EOF'
"""Answers every request with a report, as JSON, of what arrived."""
import hashlib, json, ssl, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port, cert, key, count_file = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
requests = 0
completed = 0


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def read_body(self):
        """Read the body without keeping it. Returns its size and checksum.

        Its first bytes are kept in self.start.
        """
        size, digest = 0, hashlib.sha256()
        self.start = b""
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            while True:
                length = int(self.rfile.readline().split(b";")[0], 16)
                left = length
                while left:
                    piece = self.rfile.read(min(left, 1 << 16))
                    digest.update(piece)
                    self.start = (self.start + piece)[:300]
                    left -= len(piece)
                size += length
                self.rfile.readline()
                if length == 0:
                    break
        else:
            left = int(self.headers.get("Content-Length", 0))
            while left:
                piece = self.rfile.read(min(left, 1 << 16))
                digest.update(piece)
                self.start = (self.start + piece)[:300]
                left -= len(piece)
                size += len(piece)
        return size, digest.hexdigest()

    def answer(self):
        global requests
        requests += 1
        with open(count_file, "w") as file:
            file.write(str(requests))
        size, digest = self.read_body()
        # Counted apart: a request that was cut off half way got this far
        # only with its first lines.
        global completed
        completed += 1
        with open(count_file + ".completed", "w") as file:
            file.write(str(completed))
        if self.path == "/meta":
            # An answer that does not say how long it is, and ends when the
            # connection is closed. GitHub answers a wrong token this way.
            self.send_response(401)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'{"message": "Bad credentials"}')
            self.close_connection = True
            return
        if self.path.endswith("/git-upload-pack") and self.start.isdigit():
            # A large answer with a declared size, as a clone gets. The
            # body of the request says how many megabytes.
            megabytes = int(self.start)
            self.send_response(200)
            self.send_header("Content-Length", str(megabytes << 20))
            self.end_headers()
            for _ in range(megabytes):
                self.wfile.write(b"\0" * (1 << 20))
            return
        report = json.dumps(
            {
                "method": self.command,
                "target": self.path,
                "authorization": self.headers.get_all("Authorization", []),
                "host": self.headers.get_all("Host", []),
                "cookie": self.headers.get_all("Cookie", []),
                "x_headers": sorted(
                    name.lower()
                    for name in self.headers.keys()
                    if name.lower().startswith(("x-", "forwarded"))
                ),
                "body_size": size,
                "body_sha256": digest,
                "body_start": self.start.decode("latin-1"),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(report)))
        self.end_headers()
        self.wfile.write(report)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_TRACE = answer


server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
EOF
python3 "$work/server.py" "$server_port" "$work/server.pem" "$work/server.key" "$work/count" &
server_pid=$!

# How many requests the stand-in has received so far, and how many of them
# it received whole.
count() { cat "$work/count" 2>/dev/null || echo 0; }
completed() { cat "$work/count.completed" 2>/dev/null || echo 0; }

# The script that sends the broker's connections to the stand-in. It is
# loaded after the broker's own script, so it runs after the broker has made
# every decision about a connection and has set the name the server must
# prove. It changes one thing: the address the connection goes to. A
# connection to anything but GitHub's two names is refused here, so that a
# mistake in this test cannot reach the internet.
cat >"$work/redirect.py" <<'EOF'
import os

STAND_IN = ("127.0.0.1", int(os.environ["BROKER_TEST_STAND_IN"]))
GITHUB = {("github.com", 443), ("api.github.com", 443)}


class Redirect:
    def server_connect(self, data):
        if data.server.error:
            return  # The broker has refused it already.
        if data.server.address in GITHUB:
            data.server.address = STAND_IN
        else:
            data.server.error = "the test lets nothing leave this machine"


addons = [Redirect()]
EOF

# A third mitmproxy script, loaded last, that can make the
# broker's own code fail on demand. It breaks nothing until the file named in
# BROKER_TEST_FAIL holds the name of a hook; then every helper that hook
# calls raises an error. This stands in for a mistake nobody has found yet.
cat >"$work/inject.py" <<'EOF'
import gc, logging, os, sys

CONTROL = os.environ["BROKER_TEST_FAIL"]


def maybe_fail():
    try:
        hook = open(CONTROL).read().strip()
    except OSError:
        return
    if hook == "scrub-probe":
        # Write the token to the log the way mitmproxy or Python would,
        # without the broker's code seeing the line.
        logging.error("a line that mitmproxy wrote: made-up-token-for-the-broker-test")
        os.write(2, b"a line written past Python: made-up-token-for-the-broker-test\n")
        return
    frame = sys._getframe(1)
    while hook and frame:
        if frame.f_code.co_name == hook and frame.f_code.co_filename.endswith("proxy.py"):
            # The message holds what an error message must never leak.
            raise RuntimeError("INJECTED request text, made-up-token-for-the-broker-test")
        frame = frame.f_back


def breakable(function):
    def wrapper(*arguments, **named):
        maybe_fail()
        return function(*arguments, **named)

    return wrapper


class BreakableSet(set):
    def __len__(self):
        maybe_fail()
        return super().__len__()

    def __contains__(self, item):
        maybe_fail()
        return super().__contains__(item)


broker = next(thing for thing in gc.get_objects() if type(thing).__name__ == "Broker")
swap = sys.modules["swap"]
type(broker).refusal = breakable(type(broker).refusal)
sys.modules["github_request"].plan = breakable(sys.modules["github_request"].plan)
swap.names_the_host = breakable(swap.names_the_host)
swap.split_path = breakable(swap.split_path)
broker.opening = BreakableSet()
broker.clients = BreakableSet()

# The broker has put its limits into mitmproxy by now. Doing it again must
# be refused: the functions are no longer the ones limits.py was written
# for, as they would not be after an update of mitmproxy.
limits = sys.modules["limits"]
try:
    limits.install(lambda *arguments: None)
    verdict = "installed over functions it does not know"
except limits.LimitsError:
    verdict = "refused"
with open(CONTROL + ".limits", "w") as file:
    file.write(verdict)
EOF
: >"$work/fail"

# A program that speaks to the broker byte by byte, for requests that curl
# will not send: ones that never end, or that break the rules of HTTP.
cat >"$work/client.py" <<'EOF'
"""client.py KIND BROKER_PORT HOST PORT CA_FILE MEGABYTES

Sends one hostile request and prints what became of it: "closed after N MB"
when the broker hung up, "answered <first line>" when it answered, "took it
all" when it accepted everything without either.
"""
import socket, ssl, sys

kind, broker_port, host, port, ca, megabytes = sys.argv[1:7]
# A push to the listed repo: a request the policy allows, with a body that
# is passed on in pieces.
PUSH = "/madshermansen/nixt3/git-receive-pack"
piece = b"a" * 65536
total = int(megabytes) << 20


def connect():
    return socket.create_connection(("127.0.0.1", int(broker_port)), timeout=30)


def tunnel(encrypted=True):
    plain = connect()
    plain.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    if b" 200 " not in plain.recv(4096):
        print("no tunnel")
        sys.exit(2)
    if not encrypted:
        return plain
    context = ssl.create_default_context(cafile=ca)
    context.set_alpn_protocols(["http/1.1"])
    return context.wrap_socket(plain, server_hostname=host)


def flood(connection, start):
    """Send `start`, then filler up to the total, and report what happened."""
    sent = 0
    try:
        connection.sendall(start)
        while sent < total:
            connection.sendall(piece)
            sent += len(piece)
        connection.settimeout(5)
        answer = connection.recv(200)
    except (OSError, ssl.SSLError):
        print(f"closed after {sent >> 20} MB")
        return
    if answer:
        print("answered", answer.split(b"\r\n")[0].decode("latin-1"))
    elif sent >= total:
        print("took it all")
    else:
        print(f"closed after {sent >> 20} MB")


if kind == "head":  # a header that never ends, inside an opened tunnel
    flood(tunnel(), f"GET /a HTTP/1.1\r\nHost: {host}:{port}\r\nX-Filler: ".encode())
elif kind == "first-line":  # a request line that never ends, inside an opened tunnel
    flood(tunnel(), b"GET /")
elif kind == "connect":  # a CONNECT that never ends, before any tunnel
    flood(connect(), f"CONNECT {host}:{port} HTTP/1.1\r\nX-Filler: ".encode())
elif kind == "plain-first-line":  # a request line that never ends, before any tunnel
    flood(connect(), b"GET http://example.org/")
elif kind == "chunk-size":  # a chunked body whose first size line never ends
    flood(
        tunnel(),
        f"POST {PUSH} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n".encode(),
    )
elif kind == "tls-hello":  # a first TLS message that claims to be 16 MiB long
    flood(tunnel(encrypted=False), b"\x16\x03\x01\x40\x00\x01\xff\xff\xff")
elif kind == "trailers":  # lines after a chunked body, not announced
    connection = tunnel()
    connection.sendall(
        f"POST {PUSH} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n"
        "5\r\nhello\r\n0\r\nX-After: the body\r\n\r\n".encode()
    )
    connection.settimeout(10)
    try:
        answer = connection.recv(200)
    except (OSError, ssl.SSLError):
        answer = b""
    print("answered " + answer.split(b"\r\n")[0].decode("latin-1") if answer else "closed")
elif kind.startswith("hidden-"):
    # A header hidden from the broker inside the value of another one: on a
    # continuation line (a line that starts with a space), or after a lone
    # carriage return. megabytes is not used.
    hidden = {
        "hidden-login-folded": b"\r\n Authorization: token some-other-token",
        "hidden-login-cr": b"\rAuthorization: token some-other-token",
        "hidden-forward-folded": b"\r\n X-Forwarded-Host: elsewhere.example",
    }[kind]
    connection = tunnel()
    connection.sendall(
        f"GET /{kind} HTTP/1.1\r\nHost: {host}:{port}\r\nX-Note: start".encode()
        + hidden
        + b"\r\n\r\n"
    )
    connection.settimeout(10)
    try:
        answer = connection.recv(200)
    except (OSError, ssl.SSLError):
        answer = b""
    print("answered " + answer.split(b"\r\n")[0].decode("latin-1") if answer else "closed")
EOF

# --- The broker --------------------------------------------------------------

# The broker under test uses this repo's own rules, broker/rules.yaml, as
# they are. These are copies with one thing changed each, for the checks
# that need it.
python3 - "$work" <<'EOF'
import sys

work = sys.argv[1]
rules = open("broker/rules.yaml", encoding="utf-8").read()
start = rules.index("\ngithub:\n")


def write(name, text):
    assert text != rules, name
    with open(f"{work}/{name}", "w", encoding="utf-8") as file:
        file.write(text)


# Unlisted repos may be read, without the token.
write("read-public.yaml", rules.replace("other_repos: refuse", "other_repos: read-public"))
# No `github` part at all.
write("no-policy.yaml", rules[:start] + "\n")
# A mistake in the `github` part.
write("bad-policy.yaml", rules.replace("access: write", "access: everything"))
# A host that is opened but is not GitHub.
write(
    "other-host.yaml",
    rules.replace(
        "destinations:\n",
        "destinations:\n  - host: example.org\n    note: Opened by mistake.\n    inspect: true\n",
        1,
    ),
)
EOF

# GraphQL requests, as files, because their quoting does not survive a shell.
mkdir "$work/graphql"
python3 - "$work/graphql" <<'EOF'
import base64, json, sys

folder = sys.argv[1]
LISTED_ID = "R_kgDOVwfBeQ"  # madshermansen/nixt3, as in broker/rules.yaml


def node_id(kind, *numbers):
    """An id made the way GitHub makes them: a kind and packed numbers."""
    packed = bytes([0x90 + len(numbers) + 1, 0x00])
    for number in numbers:
        packed += b"\xce" + number.to_bytes(4, "big")
    return f"{kind}_{base64.urlsafe_b64encode(packed).decode().rstrip('=')}"


# The number of the listed repo, which is packed inside its id.
listed_number = int.from_bytes(base64.urlsafe_b64decode(LISTED_ID[2:] + "==")[3:7], "big")
other_repo = node_id("R", 1296269)

CREATE = "mutation($input: CreatePullRequestInput!) { createPullRequest(input: $input) { pullRequest { id url } } }"
CLOSE = "mutation($input: ClosePullRequestInput!) { closePullRequest(input: $input) { clientMutationId } }"
COMMENT = "mutation($input: AddCommentInput!) { addComment(input: $input) { clientMutationId } }"
pull_request = {"baseRefName": "main", "headRefName": "a-branch", "title": "A title"}

requests = {
    # Reads.
    "read-listed": ('query { repository(owner: "madshermansen", name: "nixt3") { id name } }', {}),
    "read-unlisted": ('query { repository(owner: "octocat", name: "Hello-World") { id } }', {}),
    "who-am-i": ("query { viewer { login } }", {}),
    # Changes.
    "open-pull-request": (CREATE, {"input": {"repositoryId": LISTED_ID, **pull_request}}),
    "open-pull-request-elsewhere": (CREATE, {"input": {"repositoryId": other_repo, **pull_request}}),
    "open-pull-request-from-a-fork": (
        CREATE,
        {"input": {"repositoryId": LISTED_ID, **pull_request, "headRefName": "someone:a-branch"}},
    ),
    # By the id of a pull request. The second id is forged: it claims the
    # listed repo's number in front of the number of a pull request that
    # could be anywhere, which GitHub would go by.
    "close-by-id": (CLOSE, {"input": {"pullRequestId": node_id("PR", listed_number, 12345)}}),
    "comment-by-forged-id": (
        COMMENT,
        {"input": {"subjectId": node_id("PR", listed_number, 999999999), "body": "something to carry out"}},
    ),
    # Reads that start in the listed repo and walk out of it.
    "walk-to-the-owners-repos": (
        'query { repository(owner: "madshermansen", name: "nixt3") '
        "{ owner { ... on User { repositories(first: 5) { nodes { name } } } } } }",
        {},
    ),
    "walk-to-the-parent": (
        'query { repository(owner: "madshermansen", name: "nixt3") { parent { defaultBranchRef '
        "{ target { ... on Commit { history(first: 5) { nodes { message } } } } } } } }",
        {},
    ),
    "my-repos": ("query { viewer { repositories(first: 5) { nodes { name } } } }", {}),
}
for name, (query, variables) in requests.items():
    with open(f"{folder}/{name}.json", "w") as file:
        # Written with spaces, so that it differs from how the policy
        # writes it out again.
        json.dump({"query": query, "variables": variables}, file, indent=1)
EOF

cat >"$work/tokens.yaml" <<EOF
tokens:
  github:
    command: ["/usr/bin/printf", "%s", "$standin_token"]
EOF
chmod 600 "$work/tokens.yaml"

echo "Building the broker..."
broker=$(nix build .#broker --no-link --print-out-paths 2>/dev/null)/bin/agent-vm-broker
if [ ! -x "$broker" ]; then
  echo "The broker could not be built: nix build .#broker"
  exit 1
fi

# start_broker <log file> [variable=value...]: starts the broker in the
# background with this test's state folder and port, and this repo's rules
# unless a variable names other ones. Every broker started here sends its
# connections to the stand-in.
start_broker() {
  local log=$1
  shift
  env -u AGENT_BROKER_RULES AGENT_VM_STATE="$work/state" \
    AGENT_BROKER_TOKENS="$work/tokens.yaml" BROKER_TEST_FAIL="$work/fail" \
    BROKER_TEST_STAND_IN="$server_port" "$@" \
    "$broker" --listen-port "$broker_port" --scripts "$work/redirect.py" --scripts "$work/inject.py" \
    --set ssl_verify_upstream_trusted_ca="$work/ca.pem" >"$log" 2>&1 &
  broker_pid=$!
}
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
wait_for_port() {
  for _ in $(seq 300); do
    kill -0 "$broker_pid" 2>/dev/null || return 1
    if port_open "$1"; then
      # A broker that is about to give up may listen for a moment.
      sleep 1
      kill -0 "$broker_pid" 2>/dev/null
      return
    fi
    sleep 0.1
  done
  return 1
}

echo "Starting without what it needs (each must fail):"

start_broker "$work/no-file.log" AGENT_BROKER_TOKENS="$work/missing.yaml"
if wait "$broker_pid"; then fail "no tokens file: the broker does not start"; else pass "no tokens file: the broker does not start"; fi
check "no tokens file: the message says what to create" grep -q "command:" "$work/no-file.log"

printf 'tokens:\n  github:\n    command: ["/usr/bin/false"]\n' >"$work/failing.yaml"
chmod 600 "$work/failing.yaml"
start_broker "$work/failing.log" AGENT_BROKER_TOKENS="$work/failing.yaml"
if wait "$broker_pid"; then fail "failing command: the broker does not start"; else pass "failing command: the broker does not start"; fi

printf 'tokens:\n  other:\n    command: ["/usr/bin/true"]\n' >"$work/no-entry.yaml"
chmod 600 "$work/no-entry.yaml"
start_broker "$work/no-entry.log" AGENT_BROKER_TOKENS="$work/no-entry.yaml"
if wait "$broker_pid"; then fail "no entry for the token: the broker does not start"; else pass "no entry for the token: the broker does not start"; fi

cp "$work/tokens.yaml" "$work/writable.yaml"
chmod 666 "$work/writable.yaml"
start_broker "$work/writable.log" AGENT_BROKER_TOKENS="$work/writable.yaml"
if wait "$broker_pid"; then fail "tokens file others can write: the broker does not start"; else pass "tokens file others can write: the broker does not start"; fi

# The rules: a GitHub host is opened, so there must be rules for what may be
# sent there.
start_broker "$work/no-policy.log" AGENT_BROKER_RULES="$work/no-policy.yaml"
if wait "$broker_pid"; then fail "rules without a github part: the broker does not start"; else pass "rules without a github part: the broker does not start"; fi
check "rules without a github part: the message says what is missing" grep -q 'no `github:` part' "$work/no-policy.log"

start_broker "$work/bad-policy.log" AGENT_BROKER_RULES="$work/bad-policy.yaml"
if wait "$broker_pid"; then fail "a mistake in the github part: the broker does not start"; else pass "a mistake in the github part: the broker does not start"; fi
check "a mistake in the github part: the message names the repo and the key" \
  grep -q 'madshermansen/nixt3.*`access` must be' "$work/bad-policy.log"

start_broker "$work/other-host.log" AGENT_BROKER_RULES="$work/other-host.yaml"
if wait "$broker_pid"; then fail "an opened host that is not GitHub: the broker does not start"; else pass "an opened host that is not GitHub: the broker does not start"; fi
check "an opened host that is not GitHub: the message says why" grep -q "can open only" "$work/other-host.log"

if port_open "$broker_port"; then fail "nothing listens after a failed start"; else pass "nothing listens after a failed start"; fi

start_broker "$work/broker.log"
if ! wait_for_port "$broker_port"; then
  echo "The broker did not start:"
  cat "$work/broker.log"
  exit 1
fi
ca="$work/state/broker/mitmproxy-ca-cert.pem"

# through <curl arguments...>: a request through the broker, the way a
# program in the VM makes one. Prints the answer.
through() { curl -s --max-time 60 --proxy "http://127.0.0.1:$broker_port" --cacert "$ca" "$@"; }
# field <name>: reads one field of the stand-in's report from standard input.
field() { python3 -c 'import json, sys; print(json.dumps(json.load(sys.stdin)[sys.argv[1]]))' "$1" 2>/dev/null; }

# logged <pattern>: whether the broker's log has a matching line. The log is
# written a moment after the event, so this waits for it briefly.
logged() {
  for _ in $(seq 30); do
    grep -Eq "$1" "$work/broker.log" && return 0
    sleep 0.1
  done
  return 1
}

basic() { printf '%s' "$1" | base64 | tr -d '\n'; }
real_basic="[\"Basic $(basic "x-access-token:$standin_token")\"]"
with_token="[\"token $standin_token\"]"
login=(-H "Authorization: token $placeholder")
json=(-H "Content-Type: application/json")

# Before anything else: it must be the stand-in that answers for GitHub's
# names. If it is not, stop, so that no test request goes to the real GitHub.
if ! through --http1.1 "$api/rate_limit" | grep -q body_sha256; then
  echo "The stand-in does not answer for api.github.com through the broker. Stopping."
  cat "$work/broker.log"
  exit 1
fi

# The path of an address as the broker logs it, with its dots made safe for
# a pattern: "https://github.com/a/b.git/info/refs?x=y" gives "/a/b\.git/info/refs".
logged_path() {
  local path=${1#https://}
  path=/${path#*/}
  path=${path%%\?*}
  printf '%s' "$path" | sed 's/\./\\./g'
}
host_of() {
  local host=${1#https://}
  printf '%s' "${host%%/*}"
}

# arrives <description> <kind> <curl arguments..., the address last>: the
# request, sent with the placeholder, must reach the stand-in with the token
# in its place, and the broker must log it as that kind of request.
arrives() {
  local what=$1 kind=$2 before report address
  shift 2
  address=${!#}
  before=$(count)
  report=$(through --http1.1 "${login[@]}" "$@")
  if [ "$(printf '%s' "$report" | field authorization)" = "$with_token" ] &&
    [ "$(count)" = "$((before + 1))" ] &&
    logged " allowed $(host_of "$address") 443 https [A-Z]+ $(logged_path "$address") 200 $kind\$"; then
    pass "$what"
  else
    fail "$what"
  fi
}

# turned_away <description> <reason> <words of the answer> <curl arguments...,
# the address last>: the request, sent with the placeholder, must be answered
# by the broker with those words, must not reach the stand-in, and must be
# logged with that reason.
turned_away() {
  local what=$1 reason=$2 words=$3 before answer address
  shift 3
  address=${!#}
  before=$(count)
  answer=$(through --http1.1 "${login[@]}" "$@")
  # For the API the refusal is wrapped as JSON, as GitHub's own errors are.
  case "$address" in
    "$api"*) answer=$(printf '%s' "$answer" | field message | sed 's/^"//') ;;
  esac
  case "$answer" in
    "Refused by the sandbox broker: "*"$words"*) ;;
    *)
      fail "$what (the answer was not the refusal expected)"
      return
      ;;
  esac
  if [ "$(count)" = "$before" ] &&
    logged " refused $(host_of "$address") 443 https [A-Z]+ $(logged_path "$address") $reason\$"; then
    pass "$what"
  else
    fail "$what"
  fi
}

# graphql <name>: the curl arguments for one of the GraphQL requests made above.
graphql() { printf '%s\n' "--data-binary" "@$work/graphql/$1.json"; }

echo "The swap:"

# Each check is made twice: by a program that speaks HTTP/1.1, and by one
# that asks for HTTP/2, as git and gh do. The broker answers both in
# HTTP/1.1.
for version in --http1.1 --http2; do
  [ "$(through $version "${login[@]}" "$api/repos/$listed" | field authorization)" = "$with_token" ] &&
    pass "$version: 'token' with the placeholder goes out with the token" ||
    fail "$version: 'token' with the placeholder goes out with the token"

  [ "$(through $version -H "Authorization: Bearer $placeholder" "$api/repos/$listed" | field authorization)" = "[\"Bearer $standin_token\"]" ] &&
    pass "$version: 'Bearer' with the placeholder goes out with the token" ||
    fail "$version: 'Bearer' with the placeholder goes out with the token"

  [ "$(through $version -u "someone:$placeholder" "$git/$listed.git/info/refs?service=git-upload-pack" | field authorization)" = "$real_basic" ] &&
    pass "$version: git's login with the placeholder goes out with the token" ||
    fail "$version: git's login with the placeholder goes out with the token"

  [ "$(through $version "$git/$listed/info/refs?service=git-upload-pack" | field authorization)" = "[]" ] &&
    pass "$version: a request without a login goes out without one" ||
    fail "$version: a request without a login goes out without one"

  before=$(count)
  answer=$(through $version -H "Authorization: token some-other-token" "$api/repos/$listed")
  case "$answer" in
    *"Refused by the sandbox broker"*"not this"*) [ "$(count)" = "$before" ] &&
      pass "$version: another token is refused and never leaves" ||
      fail "$version: another token is refused and never leaves" ;;
    *) fail "$version: another token is refused and never leaves" ;;
  esac

  before=$(count)
  through $version -u "$placeholder:some-password" "$api/repos/$listed" | grep -q "Refused by the sandbox broker" && [ "$(count)" = "$before" ] &&
    pass "$version: a password beside the placeholder is refused" ||
    fail "$version: a password beside the placeholder is refused"

  [ "$(through $version -H "Cookie: user_session=abc" "${login[@]}" "$api/repos/$listed" | field cookie)" = "[]" ] &&
    pass "$version: a cookie is left out" ||
    fail "$version: a cookie is left out"

  before=$(count)
  through $version -H "Host: other.example" "${login[@]}" "$api/repos/$listed" | grep -q "names another site" && [ "$(count)" = "$before" ] &&
    pass "$version: a request that names another site is refused" ||
    fail "$version: a request that names another site is refused"

  before=$(count)
  through $version -H "Host: github.com" "${login[@]}" "$api/repos/$listed" | grep -q "names another site" && [ "$(count)" = "$before" ] &&
    pass "$version: a request to the API that names github.com is refused" ||
    fail "$version: a request to the API that names github.com is refused"

  before=$(count)
  through $version -X TRACE "${login[@]}" "$api/repos/$listed" | grep -q "Refused by the sandbox broker" && [ "$(count)" = "$before" ] &&
    pass "$version: TRACE, which would send the token back, is refused" ||
    fail "$version: TRACE, which would send the token back, is refused"

  # git's bodies are passed on as they come.
  sum=$(printf 'hello broker' | shasum -a 256 | cut -d' ' -f1)
  [ "$(through $version "${login[@]}" --data-binary 'hello broker' "$git/$listed/git-upload-pack" | field body_sha256)" = "\"$sum\"" ] &&
    pass "$version: the body of a git request arrives unchanged" ||
    fail "$version: the body of a git request arrives unchanged"

  # A body for the API is read by the policy, which writes it out again
  # without the spaces. GitHub gets that, so it reads what was judged.
  sum=$(printf '{"body":"hello broker"}' | shasum -a 256 | cut -d' ' -f1)
  [ "$(through $version "${login[@]}" "${json[@]}" --data-binary '{ "body" : "hello broker" }' "$api/repos/$listed/issues/7/comments" | field body_sha256)" = "\"$sum\"" ] &&
    pass "$version: the body of an API request arrives as the policy read it" ||
    fail "$version: the body of an API request arrives as the policy read it"
done

echo "Logins that are not what they should be (none may reach the stand-in):"

# never_arrives <description> <curl arguments...>: the request must not arrive.
# The address is one the policy allows, so only the login can be what stops it.
never_arrives() {
  local what=$1 before answer
  shift
  before=$(count)
  answer=$(through --http1.1 "$@" "$api/repos/$listed" 2>&1)
  case "$answer" in
    *body_sha256*)
      fail "$what"
      return
      ;;
  esac
  [ "$(count)" = "$before" ] && pass "$what" || fail "$what"
}
long=$(head -c 100000 /dev/zero | tr '\0' a)
never_arrives "a login with bytes that are not ASCII, and a cookie" \
  -H $'Authorization: Basic \xc3\xa9' -H "Cookie: user_session=must-not-arrive"
never_arrives "a login with other bytes that are not text" -H $'Authorization: Basic \xff\xfe\x80'
never_arrives "a login that is not base64" -H "Authorization: Basic !!!not-base64!!!"
never_arrives "base64 of bytes that are not text" -H "Authorization: Basic //79/A=="
never_arrives "an empty login" -H "Authorization;"
never_arrives "a login 100000 characters long" -H "Authorization: token $long"
never_arrives "the placeholder followed by 100000 characters" -H "Authorization: token $placeholder$long"
never_arrives "a login with a control character" -H $'Authorization: token a\x01b'
never_arrives "the placeholder with a tab in it" -H $'Authorization: token nixt3-placeholder\t-not-a-real-token'
never_arrives "the placeholder under an unknown scheme" -H "Authorization: Digest $placeholder"
logged " refused api.github.com 443 https GET /repos/$listed other-login\$" &&
  pass "such a login is logged as refused" || fail "such a login is logged as refused"

report=$(through --http1.1 "${login[@]}" -H "X-Forwarded-Host: other.example" -H "Forwarded: host=other.example" \
  -H "X-Real-IP: 192.0.2.1" -H "X-Harmless: stays" "$api/repos/$listed")
case "$report" in
  *'"x_headers": ["x-harmless"]'*) pass "headers that claim another host or sender are left out" ;;
  *) fail "headers that claim another host or sender are left out" ;;
esac

turned_away "a header that asks for another method than the one sent is refused" method-override "asks for another method" \
  -H "X-HTTP-Method-Override: DELETE" "${json[@]}" --data-binary '{"body":"x"}' "$api/repos/$listed/issues/7/comments"

before=$(count)
through --http1.1 "${login[@]}" -H "Connection: Upgrade" -H "Upgrade: websocket" "$api/repos/$listed" |
  grep -q "another protocol" && [ "$(count)" = "$before" ] &&
  pass "a request to switch to another protocol is refused" ||
  fail "a request to switch to another protocol is refused"

# A closed connection is a poor way to tell the VM that an answer is whole,
# so an answer that ends that way is given an end it can see. The stand-in
# answers /meta that way.
through --http1.1 -D - "${login[@]}" "$api/meta" >"$work/unframed" 2>&1
grep -qi "^transfer-encoding: chunked" "$work/unframed" && grep -q "Bad credentials" "$work/unframed" &&
  pass "an answer that ends by closing the connection is given a marked end" ||
  fail "an answer that ends by closing the connection is given a marked end"

echo "Without encryption:"

before=$(count)
through --proxytunnel "${login[@]}" "http://github.com:443/$listed/info/refs?service=git-upload-pack" | grep -q "was not encrypted" && [ "$(count)" = "$before" ] &&
  pass "clear text inside a tunnel is refused" ||
  fail "clear text inside a tunnel is refused"

through "${login[@]}" "http://github.com:443/$listed/info/refs?service=git-upload-pack" | grep -q "must be encrypted" && [ "$(count)" = "$before" ] &&
  pass "clear text sent to the broker directly is refused" ||
  fail "clear text sent to the broker directly is refused"

# The encrypted connection names another site than the tunnel was opened for.
if curl -sk --max-time 15 --proxy "http://127.0.0.1:$broker_port" \
  --connect-to "other.example:443:github.com:443" "https://other.example/$listed" >/dev/null 2>&1; then
  fail "a tunnel cannot be used under another name"
else
  pass "a tunnel cannot be used under another name"
fi

echo "How a refusal is worded for the program that gets it:"

# gh shows the `message` of a JSON error, and only the status line of a
# plain-text one. git shows a plain-text body line by line.
through --http1.1 -D "$work/headers" "${login[@]}" "$api/repos/$unlisted" >"$work/answer"
grep -qi "^content-type: application/json" "$work/headers" &&
  [ "$(field message <"$work/answer" | cut -c1-32)" = '"Refused by the sandbox broker: ' ] &&
  pass "on the API a refusal is JSON with a message, as GitHub's own errors are" ||
  fail "on the API a refusal is JSON with a message, as GitHub's own errors are"

through --http1.1 -D "$work/headers" "${login[@]}" "$git/$unlisted/info/refs?service=git-upload-pack" >"$work/answer"
grep -qi "^content-type: text/plain" "$work/headers" && head -n 1 "$work/answer" | grep -q "^Refused by the sandbox broker: " &&
  pass "for git a refusal is plain text" || fail "for git a refusal is plain text"

echo "What may be sent to GitHub: git"

# The rules list $listed for writing, and nothing else.
arrives "fetch from the listed repo: asking what is there" git-read "$git/$listed.git/info/refs?service=git-upload-pack"
arrives "fetch from the listed repo: the fetch itself" git-read --data-binary pack "$git/$listed.git/git-upload-pack"
arrives "push to the listed repo: asking whether it may" git-write "$git/$listed/info/refs?service=git-receive-pack"
arrives "push to the listed repo: the push itself" git-write --data-binary pack "$git/$listed/git-receive-pack"

turned_away "fetch from a repo that is not listed" repo-not-listed "is not a repo the sandbox may use" \
  "$git/$unlisted.git/info/refs?service=git-upload-pack"
turned_away "fetch from a repo that is not listed: the fetch itself" repo-not-listed "is not a repo the sandbox may use" \
  --data-binary pack "$git/$unlisted/git-upload-pack"
turned_away "push to a repo that is not listed" repo-not-listed "nothing can be sent to it" \
  "$git/$unlisted/info/refs?service=git-receive-pack"
turned_away "push to a repo that is not listed: the push itself" repo-not-listed "nothing can be sent to it" \
  --data-binary pack "$git/$unlisted/git-receive-pack"
turned_away "the wiki of the listed repo, which is a repo of its own" repo-not-listed "is not a repo the sandbox may use" \
  "$git/$listed.wiki.git/info/refs?service=git-upload-pack"
turned_away "a web page of github.com" not-recognised "git only" "$git/$listed"
turned_away "git's large-file storage" git-lfs "" --data-binary '{}' "$git/$listed.git/info/lfs/objects/batch"

# A push to an unlisted repo that sends its upload without asking first: the
# upload is in pieces, so it gets no answer, and the connection is closed.
before=$(count)
if head -c 5000000 /dev/zero | through --http1.1 --max-time 30 "${login[@]}" -X POST \
  -H "Transfer-Encoding: chunked" -T - "$git/$unlisted/git-receive-pack" >/dev/null 2>&1; then
  fail "an upload to a repo that is not listed is cut off"
else
  [ "$(count)" = "$before" ] && pass "an upload to a repo that is not listed is cut off" ||
    fail "an upload to a repo that is not listed is cut off"
fi

echo "What may be sent to GitHub: the REST API"

arrives "read the listed repo's pull requests" api-read "$api/repos/$listed/pulls?state=open&per_page=5"
[ "$(through --http1.1 "${login[@]}" "$api/repos/$listed/pulls?state=open&per_page=5" | field target)" = "\"/repos/$listed/pulls?state=open&per_page=5\"" ] &&
  pass "the address arrives as it was sent, query string and all" ||
  fail "the address arrives as it was sent, query string and all"
arrives "ask who the token belongs to" api-read "$api/user"
arrives "comment on a pull request" api-write "${json[@]}" --data-binary '{"body":"A comment."}' "$api/repos/$listed/issues/7/comments"
arrives "close a pull request" api-write "${json[@]}" -X PATCH --data-binary '{"state":"closed"}' "$api/repos/$listed/pulls/7"
arrives "open a pull request" api-write "${json[@]}" --data-binary '{"title":"t","head":"a-branch","base":"main"}' "$api/repos/$listed/pulls"

turned_away "read a repo that is not listed" repo-not-listed "is not a repo the sandbox may use" "$api/repos/$unlisted"
turned_away "comment in a repo that is not listed" repo-not-listed "nothing can be sent to it" \
  "${json[@]}" --data-binary '{"body":"something to carry out"}' "$api/repos/$unlisted/issues/1/comments"
turned_away "change the listed repo's settings (make it public)" repo-settings "" \
  "${json[@]}" -X PATCH --data-binary '{"private":false}' "$api/repos/$listed"
turned_away "read the listed repo's secrets" secrets "" "$api/repos/$listed/actions/secrets"
turned_away "delete the listed repo" repo-deletion "" -X DELETE "$api/repos/$listed"
turned_away "merge a pull request, which the rules leave off" merge "merging pull requests" \
  -X PUT -H "Content-Length: 0" "$api/repos/$listed/pulls/7/merge"
turned_away "create a repo" repo-creation "" "${json[@]}" --data-binary '{"name":"new"}' "$api/user/repos"
turned_away "a pull request from someone's fork" head-elsewhere "" \
  "${json[@]}" --data-binary '{"title":"t","head":"someone:a-branch","base":"main"}' "$api/repos/$listed/pulls"
turned_away "a change with values in the query string, which the policy does not read" query-odd "query string" \
  "${json[@]}" --data-binary '{"body":"x"}' "$api/repos/$listed/issues/7/comments?body=other"
turned_away "a part of the API nobody listed" not-recognised "" "$api/zen"

# Addresses in an odd spelling. The broker passes on what it was sent, so it
# must not read an address in a way GitHub might not.
turned_away "an address that climbs out of the listed repo with .." path-odd "" \
  --path-as-is "$api/repos/$listed/../../$unlisted"
turned_away "the same with the dots encoded" path-odd "" "$api/repos/$listed/%2e%2e/%2e%2e/$unlisted"
turned_away "a doubled slash" path-odd "" --path-as-is "$api/repos/madshermansen//nixt3"
turned_away "an encoded keyword" not-recognised "" "$api/repos/$listed/%70ulls"

echo "What may be sent to GitHub: GraphQL, which gh uses"

arrives "read the listed repo" graphql-read "${json[@]}" $(graphql read-listed) "$api/graphql"
# The file has spaces and line breaks; what the policy writes out has none.
case "$(through --http1.1 "${login[@]}" "${json[@]}" $(graphql read-listed) "$api/graphql")" in
  *'"body_start": "{\"query\":\"query {'*) pass "the request arrives written out afresh by the policy" ;;
  *) fail "the request arrives written out afresh by the policy" ;;
esac
arrives "ask who the token belongs to" graphql-read "${json[@]}" $(graphql who-am-i) "$api/graphql"
arrives "open a pull request in the listed repo, as gh pr create does" graphql-write \
  "${json[@]}" $(graphql open-pull-request) "$api/graphql"

turned_away "read a repo that is not listed" repo-not-listed "is not a repo the sandbox may use" \
  "${json[@]}" $(graphql read-unlisted) "$api/graphql"
turned_away "open a pull request in a repo that is not listed" graphql-id-not-listed "" \
  "${json[@]}" $(graphql open-pull-request-elsewhere) "$api/graphql"
turned_away "open a pull request from someone's fork" head-elsewhere "" \
  "${json[@]}" $(graphql open-pull-request-from-a-fork) "$api/graphql"
turned_away "close a pull request by its id, as gh pr close does: refused, with the way on" graphql-by-id "gh api" \
  "${json[@]}" $(graphql close-by-id) "$api/graphql"
turned_away "comment by a forged id that claims the listed repo" graphql-by-id "" \
  "${json[@]}" $(graphql comment-by-forged-id) "$api/graphql"
turned_away "a query that walks from the listed repo to its owner's other repos" graphql-not-on-list "" \
  "${json[@]}" $(graphql walk-to-the-owners-repos) "$api/graphql"
turned_away "a query that walks from the listed repo to the repo it was forked from" graphql-not-on-list "" \
  "${json[@]}" $(graphql walk-to-the-parent) "$api/graphql"
turned_away "a query for all the repos the token can see" graphql-not-on-list "" \
  "${json[@]}" $(graphql my-repos) "$api/graphql"

echo "A body the policy needs but cannot read (none may reach the stand-in):"

turned_away "a compressed body" body-odd "compressed" \
  "${json[@]}" -H "Content-Encoding: gzip" --data-binary '{"body":"x"}' "$api/repos/$listed/issues/7/comments"
turned_away "a body that does not say it is JSON" body-odd "application/json" \
  -H "Content-Type: text/plain" --data-binary '{"body":"x"}' "$api/repos/$listed/issues/7/comments"

# A body sent in pieces, or larger than the broker reads: the broker cannot
# hand it to the policy, so the request gets no answer and is cut off.
cut_off() {
  local what=$1 before
  shift
  before=$(count)
  if through --http1.1 --max-time 30 "${login[@]}" "${json[@]}" "$@" >/dev/null 2>&1; then
    fail "$what"
  else
    [ "$(count)" = "$before" ] && pass "$what" || fail "$what"
  fi
}
cut_off "a GraphQL request sent in pieces" -H "Transfer-Encoding: chunked" $(graphql open-pull-request) "$api/graphql"
python3 -c 'import json, sys; json.dump({"body": "x" * 2_000_000}, sys.stdout)' >"$work/large.json"
cut_off "a comment of 2 MB" --data-binary "@$work/large.json" "$api/repos/$listed/issues/7/comments"
cut_off "a read with a body sent in pieces" -X GET -H "Transfer-Encoding: chunked" --data-binary '{"body":"x"}' "$api/repos/$listed"
rm -f "$work/large.json"
logged " refused api.github.com 443 https POST /graphql body-not-read\$" &&
  pass "such a request is logged as refused" || fail "such a request is logged as refused"

echo "With 'other_repos: read-public': repos that are not listed may be read, without the token:"

# A second broker, with rules that differ in that one line.
env -u AGENT_BROKER_RULES AGENT_VM_STATE="$work/state2" AGENT_BROKER_RULES="$work/read-public.yaml" \
  AGENT_BROKER_TOKENS="$work/tokens.yaml" BROKER_TEST_FAIL="$work/fail" BROKER_TEST_STAND_IN="$server_port" \
  "$broker" --listen-port "$second_port" --scripts "$work/redirect.py" \
  --set ssl_verify_upstream_trusted_ca="$work/ca.pem" >"$work/second.log" 2>&1 &
second_pid=$!
main_pid=$broker_pid
broker_pid=$second_pid
if ! wait_for_port "$second_port"; then
  echo "The second broker did not start:"
  cat "$work/second.log"
  exit 1
fi
broker_pid=$main_pid
second() {
  curl -s --max-time 60 --proxy "http://127.0.0.1:$second_port" \
    --cacert "$work/state2/broker/mitmproxy-ca-cert.pem" --http1.1 "$@"
}

# without_token <description> <curl arguments...>: the request must reach
# the stand-in with no login at all.
without_token() {
  local what=$1 before report
  shift
  before=$(count)
  report=$(second "$@")
  if [ "$(printf '%s' "$report" | field authorization)" = "[]" ] && [ "$(count)" = "$((before + 1))" ]; then
    pass "$what"
  else
    fail "$what"
  fi
}
without_token "git reads an unlisted repo: the placeholder is taken out, no token goes in" \
  -u "someone:$placeholder" "$git/$unlisted.git/info/refs?service=git-upload-pack"
without_token "the fetch itself" "${login[@]}" --data-binary pack "$git/$unlisted/git-upload-pack"
without_token "the API reads an unlisted repo the same way" "${login[@]}" "$api/repos/$unlisted/pulls"
without_token "and so does a request that had no login to begin with" "$api/repos/$unlisted"
for _ in $(seq 30); do
  grep -q " allowed github.com 443 https GET /$unlisted.git/info/refs 200 git-read-without-token\$" "$work/second.log" && break
  sleep 0.1
done
check "the log says that it went without the token" \
  grep -q " allowed github.com 443 https GET /$unlisted.git/info/refs 200 git-read-without-token\$" "$work/second.log"

[ "$(second "${login[@]}" "$api/repos/$listed" | field authorization)" = "$with_token" ] &&
  pass "the listed repo still gets the token" || fail "the listed repo still gets the token"

before=$(count)
second "${login[@]}" "$git/$unlisted/info/refs?service=git-receive-pack" | grep -q "nothing can be sent to it" &&
  second "${login[@]}" "${json[@]}" --data-binary '{"body":"x"}' "$api/repos/$unlisted/issues/1/comments" | grep -q "nothing can be sent to it" &&
  [ "$(count)" = "$before" ] &&
  pass "writing to an unlisted repo is still refused" || fail "writing to an unlisted repo is still refused"

before=$(count)
second -H "Authorization: token some-other-token" "$api/repos/$unlisted" | grep -q "not this sandbox's own" && [ "$(count)" = "$before" ] &&
  pass "another token is still refused, not taken out" || fail "another token is still refused, not taken out"

before=$(count)
second "${login[@]}" "${json[@]}" $(graphql read-unlisted) "$api/graphql" | grep -q "Refused by the sandbox broker" && [ "$(count)" = "$before" ] &&
  pass "GraphQL, which needs the token, still refuses an unlisted repo" ||
  fail "GraphQL, which needs the token, still refuses an unlisted repo"

if grep -q "$standin_token" "$work/second.log"; then fail "the token is not in the second broker's log"; else pass "the token is not in the second broker's log"; fi
kill "$second_pid" 2>/dev/null
second_pid=""

memory() { echo $(($(ps -o rss= -p "$mitm_pid") / 1024)); }
# The broker command ends by turning into mitmdump, so the process is the same.
mitm_pid=$broker_pid

echo "When the broker's own code fails (it must refuse, not let through):"

# fails_closed <hook> <yes|no: may the request reach the stand-in>: makes the
# named hook fail, sends a request that is otherwise allowed, and checks that
# the VM got no answer from the stand-in and that the log says why. The
# request is a comment through the API, which passes every hook: its body is
# read first, and the policy is asked from the `request` hook.
fails_closed() {
  local hook=$1 may_arrive=$2 before answer
  before=$(count)
  echo "$hook" >"$work/fail"
  answer=$(through --http1.1 --max-time 10 "${login[@]}" "${json[@]}" --data-binary '{"body":"x"}' "$api/repos/$listed/issues/7/comments" 2>&1)
  : >"$work/fail"
  case "$answer" in
    *body_sha256*) fail "$hook fails: the VM gets no answer" ;;
    *) pass "$hook fails: the VM gets no answer" ;;
  esac
  if [ "$may_arrive" = no ]; then
    [ "$(count)" = "$before" ] && pass "$hook fails: nothing reaches the server" ||
      fail "$hook fails: nothing reaches the server"
  fi
  logged " refused [^ ]+ [0-9]+ $hook broker-error RuntimeError [a-z_.]+:[0-9]+\$" &&
    pass "$hook fails: the log says so" || fail "$hook fails: the log says so"
}
fails_closed client_connected no
fails_closed http_connect no
fails_closed tls_clienthello no
fails_closed tls_start_client no
fails_closed requestheaders no
# This is where the policy is asked about an API request.
fails_closed request no
fails_closed server_connect no
# By the time the answer's first lines arrive, the request has been sent.
fails_closed responseheaders yes

# The same for git, where the policy is asked as soon as the first lines of
# a request have arrived.
before=$(count)
echo requestheaders >"$work/fail"
answer=$(through --http1.1 --max-time 10 "${login[@]}" "$git/$listed/info/refs?service=git-receive-pack" 2>&1)
: >"$work/fail"
case "$answer" in
  *body_sha256*) fail "the policy call fails for a git request: nothing reaches the server" ;;
  *) [ "$(count)" = "$before" ] && pass "the policy call fails for a git request: nothing reaches the server" ||
    fail "the policy call fails for a git request: nothing reaches the server" ;;
esac

answer=$(through --http1.1 "${login[@]}" "$api/repos/$listed" | field authorization)
[ "$answer" = "$with_token" ] &&
  pass "afterwards the broker works as before" || fail "afterwards the broker works as before"
if grep -q "INJECTED" "$work/broker.log"; then
  fail "the error's message, which may hold request text, is not logged"
else
  pass "the error's message, which may hold request text, is not logged"
fi

echo "More than the broker takes in (each sends up to 200 MB; the broker must hang up early):"

start_memory=$(memory)
# hostile <kind> <description> <log pattern>
hostile() {
  local kind=$1 what=$2 pattern=$3 before outcome
  before=$(count)
  outcome=$(python3 "$work/client.py" "$kind" "$broker_port" github.com 443 "$ca" 200 2>&1)
  case "$outcome" in
    "closed after "[0-9]" MB" | "answered HTTP/1.1 4"*) [ "$(count)" = "$before" ] &&
      pass "$what ($outcome)" || fail "$what (it reached the server)" ;;
    *) fail "$what ($outcome)" ;;
  esac
  logged "$pattern" && pass "$what: logged" || fail "$what: logged"
}
hostile head "a header that never ends" " refused github.com 443 limit too-much-unread\$"
hostile first-line "a request line that never ends" " refused github.com 443 limit too-much-unread\$"
hostile connect "a CONNECT that never ends, before any tunnel" " refused - 0 limit too-much-unread\$"
hostile plain-first-line "a request line that never ends, before any tunnel" " refused - 0 limit too-much-unread\$"
hostile tls-hello "a first TLS message that never ends" " refused github.com 443 limit tls-hello-too-long\$"

# In a push to the listed repo, which the policy allows and passes on in
# pieces: the line that gives the size of a piece never ends.
before=$(completed)
outcome=$(python3 "$work/client.py" chunk-size "$broker_port" github.com 443 "$ca" 200 2>&1)
case "$outcome" in
  "closed after "[0-9]" MB") [ "$(completed)" = "$before" ] &&
    pass "a chunk size line that never ends ($outcome)" ||
    fail "a chunk size line that never ends (the request was completed)" ;;
  *) fail "a chunk size line that never ends ($outcome)" ;;
esac

[ "$(cat "$work/fail.limits" 2>/dev/null)" = refused ] &&
  pass "the limits refuse to go into a mitmproxy they were not written for" ||
  fail "the limits refuse to go into a mitmproxy they were not written for"

grown=$(($(memory) - start_memory))
[ "$grown" -lt 30 ] &&
  pass "the broker held none of it in memory (grew ${grown} MB, from ${start_memory} MB)" ||
  fail "the broker held none of it in memory (grew ${grown} MB, from ${start_memory} MB)"

echo "A header hidden inside another header's value (none may reach the stand-in):"

for kind in hidden-login-folded hidden-login-cr hidden-forward-folded; do
  before=$(count)
  outcome=$(python3 "$work/client.py" "$kind" "$broker_port" github.com 443 "$ca" 1 2>&1)
  sleep 0.5
  case "$kind" in
    hidden-login-folded) what="a login on a continuation line" ;;
    hidden-login-cr) what="a login after a lone carriage return" ;;
    *) what="a forwarding header on a continuation line" ;;
  esac
  [ "$(count)" = "$before" ] && pass "$what ($outcome)" || fail "$what ($outcome)"
done
logged " refused github.com 443 https GET /hidden-login-folded odd-header\$" &&
  pass "a split header line is logged as refused" || fail "a split header line is logged as refused"

echo "Lines after a body (trailers), which mitmproxy cannot pass on:"

before=$(count)
through --http1.1 "${login[@]}" -H "Trailer: X-After" --data-binary pack "$git/$listed/git-receive-pack" |
  grep -q "lines after its body" && [ "$(count)" = "$before" ] &&
  pass "a request that announces trailers is refused before anything is sent" ||
  fail "a request that announces trailers is refused before anything is sent"

# Not announced, they show only after the body, when the request's first
# lines and body have gone out. The request must then not be completed.
before=$(completed)
outcome=$(python3 "$work/client.py" trailers "$broker_port" github.com 443 "$ca" 1 2>&1)
sleep 0.5
case "$outcome" in
  closed | "answered HTTP/1.1 4"* | "answered HTTP/1.1 5"*) [ "$(completed)" = "$before" ] &&
    pass "a request that sends trailers unannounced is cut off, not completed ($outcome)" ||
    fail "a request that sends trailers unannounced is cut off (the server completed it)" ;;
  *) fail "a request that sends trailers unannounced is cut off, not completed ($outcome)" ;;
esac
logged " refused github.com 443 limit trailers\$" &&
  pass "trailers are logged as refused" || fail "trailers are logged as refused"

echo "Large bodies (the broker's memory use is measured in megabytes):"
megabytes=300
start_memory=$(memory)

# Git sends a large push in pieces, without saying how long it is.
[ "$(head -c $((megabytes << 20)) /dev/zero | through --http1.1 "${login[@]}" -X POST \
  -H "Transfer-Encoding: chunked" -T - "$git/$listed/git-receive-pack" | field body_size)" = "$((megabytes << 20))" ] &&
  pass "a $megabytes MB push in pieces arrives whole" ||
  fail "a $megabytes MB push in pieces arrives whole"

head -c $((megabytes << 20)) /dev/zero >"$work/large"
[ "$(through --http1.1 "${login[@]}" -X POST -T "$work/large" "$git/$listed/git-receive-pack" | field body_size)" = "$((megabytes << 20))" ] &&
  pass "a $megabytes MB push with a declared size arrives whole" ||
  fail "a $megabytes MB push with a declared size arrives whole"
rm -f "$work/large"

[ "$(through --http2 -w '%{http_version}' -o /dev/null "${login[@]}" "$api/repos/$listed")" = "1.1" ] &&
  pass "a program that asks for HTTP/2 is answered in HTTP/1.1" ||
  fail "a program that asks for HTTP/2 is answered in HTTP/1.1"

# The stand-in answers a fetch whose body is a number with that many megabytes.
[ "$(through "${login[@]}" --data-binary "$megabytes" "$git/$listed/git-upload-pack" | wc -c | tr -d ' ')" = "$((megabytes << 20))" ] &&
  pass "a $megabytes MB fetch arrives whole" ||
  fail "a $megabytes MB fetch arrives whole"

# A refused request with a body that never ends: the broker must hang up
# instead of taking the body in.
before=$(count)
if head -c $((megabytes << 20)) /dev/zero | through --http1.1 --max-time 30 -H "Authorization: token some-other-token" -X POST \
  -H "Transfer-Encoding: chunked" -T - "$git/$listed/git-receive-pack" >/dev/null 2>&1; then
  fail "a refused upload in pieces is cut off"
else
  [ "$(count)" = "$before" ] && pass "a refused upload in pieces is cut off" || fail "a refused upload in pieces is cut off"
fi

# The same from a program that asks for HTTP/2 and hides the body in a GET.
# The broker speaks HTTP/1.1 only, where a body cannot be hidden.
before=$(count)
if head -c $((megabytes << 20)) /dev/zero | through --http2 --max-time 30 -X GET -H "Authorization: token some-other-token" \
  -T - "$git/$listed/git-receive-pack" >/dev/null 2>&1; then
  fail "a refused upload disguised as a GET is cut off"
else
  [ "$(count)" = "$before" ] && pass "a refused upload disguised as a GET is cut off" || fail "a refused upload disguised as a GET is cut off"
fi

end_memory=$(memory)
grown=$((end_memory - start_memory))
[ "$grown" -lt $((megabytes / 3)) ] &&
  pass "the broker held none of it in memory (grew ${grown} MB, from ${start_memory} MB)" ||
  fail "the broker held none of it in memory (grew ${grown} MB, from ${start_memory} MB)"

echo "The log:"

through "${login[@]}" "$api/repos/$listed/commits?sha=a-private-word" >/dev/null
check "a request is logged with its method, path, status and kind" \
  logged " allowed api.github.com 443 https GET /repos/$listed/commits 200 api-read\$"
check "a refusal is logged with its reason" \
  logged " refused api.github.com 443 https GET /repos/$unlisted repo-not-listed\$"

# mitmproxy and Python write to the same log as the broker, without the
# broker's code seeing the line. So everything is checked for tokens on its
# way to the log, whoever wrote it. Here a second script writes the token
# the way mitmproxy would write an error, and once past Python altogether.
echo scrub-probe >"$work/fail"
through --http1.1 "$api/rate_limit" >/dev/null
: >"$work/fail"
logged "a line that mitmproxy wrote: <secret>" &&
  pass "a token in a line that mitmproxy wrote is replaced" ||
  fail "a token in a line that mitmproxy wrote is replaced"
logged "a line written past Python: <secret>" &&
  pass "a token written straight to the output is replaced" ||
  fail "a token written straight to the output is replaced"
if grep -q "a-private-word" "$work/broker.log"; then fail "the query string is not logged"; else pass "the query string is not logged"; fi
# What a refusal tells the agent can repeat part of the request, so it goes
# to the VM and not to the log.
if grep -q "is not a repo the sandbox may use\|something to carry out" "$work/broker.log"; then
  fail "the policy's message to the agent is not logged"
else
  pass "the policy's message to the agent is not logged"
fi
if grep -rq "$standin_token" "$work/broker.log" "$work/state"; then
  fail "the token is in no log and no file of the broker"
else
  pass "the token is in no log and no file of the broker"
fi
if ps eww -o command= -p "$mitm_pid" | grep -q "$standin_token"; then
  fail "the token is not in the broker's command line or environment"
else
  pass "the token is not in the broker's command line or environment"
fi
if grep -q "mitmproxy has crashed\|Traceback" "$work/broker.log"; then
  fail "the broker reported no errors of its own"
  grep -n "mitmproxy has crashed\|Traceback" -A 12 "$work/broker.log" | head -40
else
  pass "the broker reported no errors of its own"
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "All checks passed."
else
  echo "$failures check(s) failed. The broker's log:"
  tail -n 30 "$work/broker.log"
  exit 1
fi
