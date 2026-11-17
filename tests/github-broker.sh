#!/usr/bin/env bash
# Checks how the broker treats a destination that it opens, on the Mac, with
# no VM, no GitHub and no real token.
#
# It starts a stand-in for GitHub on this machine, a small server that
# answers every request by reporting what it received. It then starts a
# broker of its own, on its own port and with its own state folder, with
# rules that open the stand-in and a tokens file whose command prints a made-up
# token. Requests are sent through that broker the way programs in the VM send
# them, and the stand-in's reports show what the broker let out.
#
# Run it from the repo:
#
#   tests/github-broker.sh
#
# It needs `nix`, `python3`, `openssl` and `curl`. A Mac has the last three;
# if not: nix shell nixpkgs#python3 nixpkgs#openssl nixpkgs#curl -c tests/github-broker.sh
#
# The VM's broker is not touched. Nothing here leaves this machine.

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
server_pid=""
cleanup() {
  [ -n "$broker_pid" ] && kill "$broker_pid" 2>/dev/null
  [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null
  rm -rf "$work"
}
trap cleanup EXIT

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}
server_port=$(free_port)
broker_port=$(free_port)

# --- The stand-in for GitHub -------------------------------------------------

# A certificate authority and a certificate for the name "standin.localhost"
# (a Mac reads every name ending in ".localhost" as itself), made
# for this run only. The broker is told to trust the authority, as it trusts
# the real ones for the real GitHub.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=stand-in authority" \
  -keyout "$work/ca.key" -out "$work/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=standin.localhost" \
  -keyout "$work/server.key" -out "$work/server.csr" 2>/dev/null
printf 'subjectAltName=DNS:standin.localhost\n' >"$work/san.cnf"
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
        """Read the body without keeping it. Returns its size and checksum."""
        size, digest = 0, hashlib.sha256()
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            while True:
                length = int(self.rfile.readline().split(b";")[0], 16)
                left = length
                while left:
                    piece = self.rfile.read(min(left, 1 << 16))
                    digest.update(piece)
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
        if self.path.startswith("/unframed"):
            # An answer that does not say how long it is, and ends when the
            # connection is closed. GitHub answers a wrong token this way.
            self.send_response(401)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'{"message": "Bad credentials"}')
            self.close_connection = True
            return
        if self.path.startswith("/big/"):
            # A large answer with a declared size: /big/<megabytes>
            megabytes = int(self.path.split("/")[2].split("?")[0])
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
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(report)))
        self.end_headers()
        self.wfile.write(report)

    do_GET = do_POST = do_PUT = do_TRACE = answer


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

# A second mitmproxy script, loaded after the broker's, that can make the
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
type(broker).policy = breakable(type(broker).policy)
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
        f"POST /a HTTP/1.1\r\nHost: {host}:{port}\r\nTransfer-Encoding: chunked\r\n\r\n".encode(),
    )
elif kind == "tls-hello":  # a first TLS message that claims to be 16 MiB long
    flood(tunnel(encrypted=False), b"\x16\x03\x01\x40\x00\x01\xff\xff\xff")
elif kind == "trailers":  # lines after a chunked body, not announced
    connection = tunnel()
    connection.sendall(
        f"POST /a HTTP/1.1\r\nHost: {host}:{port}\r\nTransfer-Encoding: chunked\r\n\r\n"
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

cat >"$work/rules.yaml" <<EOF
destinations:
  - host: standin.localhost
    note: The stand-in for GitHub.
    ports: [$server_port]
    inspect: true
    token: github
  - host: unopened.localhost
    note: The stand-in under a second name, passed on without being opened.
    ports: [$server_port]
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
# background with this test's state folder, rules and port.
start_broker() {
  local log=$1
  shift
  env AGENT_VM_STATE="$work/state" AGENT_BROKER_RULES="$work/rules.yaml" \
    AGENT_BROKER_TOKENS="$work/tokens.yaml" BROKER_TEST_FAIL="$work/fail" "$@" \
    "$broker" --listen-port "$broker_port" --scripts "$work/inject.py" \
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

# The rules file. A broker that started without rules, or with half of them,
# would let through what nobody chose. fetch_tokens.py reads the file first
# and stops at one that is missing or is not YAML. Every other mistake is
# left to the broker itself, which must then end instead of starting.

# stops_by_itself: whether the broker that was just started ends with an
# error within 20 seconds. One that keeps running is stopped, so that a
# broker which wrongly started cannot make this script wait for ever.
stops_by_itself() {
  for _ in $(seq 200); do
    if ! kill -0 "$broker_pid" 2>/dev/null; then
      ! wait "$broker_pid"
      return
    fi
    sleep 0.1
  done
  kill "$broker_pid" 2>/dev/null
  return 1
}
# bad_rules <description> <text of a rules file>: the broker must not start
# with these rules, and must say that the rules are why.
bad_rules() {
  local what=$1
  printf '%s\n' "$2" >"$work/bad-rules.yaml"
  start_broker "$work/bad-rules.log" AGENT_BROKER_RULES="$work/bad-rules.yaml"
  stops_by_itself && pass "$what: the broker does not start" || fail "$what: the broker does not start"
  check "$what: the message says the rules are why" \
    grep -q "the rules file cannot be used" "$work/bad-rules.log"
}

start_broker "$work/no-rules.log" AGENT_BROKER_RULES="$work/missing-rules.yaml"
stops_by_itself && pass "no rules file: the broker does not start" || fail "no rules file: the broker does not start"

printf 'destinations: [\n' >"$work/not-yaml.yaml"
start_broker "$work/not-yaml.log" AGENT_BROKER_RULES="$work/not-yaml.yaml"
stops_by_itself && pass "a rules file that is not YAML: the broker does not start" ||
  fail "a rules file that is not YAML: the broker does not start"

bad_rules "an empty rules file" ""
bad_rules "a misspelt key in a rule" "destinations:
  - host: standin.localhost
    note: The key below should be 'inspect'.
    inspct: true"
bad_rules "a rule for every host" "destinations:
  - host: '*'
    note: There are no wildcards."
bad_rules "a rule for an address instead of a name" "destinations:
  - host: 127.0.0.1
    note: Only names can be listed."
bad_rules "a rule without a note" "destinations:
  - host: standin.localhost"

if port_open "$broker_port"; then fail "nothing listens after a failed start"; else pass "nothing listens after a failed start"; fi

start_broker "$work/broker.log"
if ! wait_for_port "$broker_port"; then
  echo "The broker did not start:"
  cat "$work/broker.log"
  exit 1
fi
ca="$work/state/broker/mitmproxy-ca-cert.pem"
url="https://standin.localhost:$server_port"

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

echo "The swap:"

# Each check is made twice: by a program that speaks HTTP/1.1, and by one
# that asks for HTTP/2, as git and gh do. The broker answers both in
# HTTP/1.1.
for version in --http1.1 --http2; do
  [ "$(through $version -H "Authorization: token $placeholder" "$url/a" | field authorization)" = "[\"token $standin_token\"]" ] &&
    pass "$version: 'token' with the placeholder goes out with the token" ||
    fail "$version: 'token' with the placeholder goes out with the token"

  [ "$(through $version -H "Authorization: Bearer $placeholder" "$url/a" | field authorization)" = "[\"Bearer $standin_token\"]" ] &&
    pass "$version: 'Bearer' with the placeholder goes out with the token" ||
    fail "$version: 'Bearer' with the placeholder goes out with the token"

  [ "$(through $version -u "someone:$placeholder" "$url/a" | field authorization)" = "$real_basic" ] &&
    pass "$version: git's login with the placeholder goes out with the token" ||
    fail "$version: git's login with the placeholder goes out with the token"

  [ "$(through $version "$url/a" | field authorization)" = "[]" ] &&
    pass "$version: a request without a login goes out without one" ||
    fail "$version: a request without a login goes out without one"

  before=$(count)
  answer=$(through $version -H "Authorization: token some-other-token" "$url/a")
  case "$answer" in
    *"Refused by the sandbox broker"*"not this"*) [ "$(count)" = "$before" ] &&
      pass "$version: another token is refused and never leaves" ||
      fail "$version: another token is refused and never leaves" ;;
    *) fail "$version: another token is refused and never leaves" ;;
  esac

  before=$(count)
  through $version -u "$placeholder:some-password" "$url/a" | grep -q "Refused by the sandbox broker" && [ "$(count)" = "$before" ] &&
    pass "$version: a password beside the placeholder is refused" ||
    fail "$version: a password beside the placeholder is refused"

  [ "$(through $version -H "Cookie: user_session=abc" -H "Authorization: token $placeholder" "$url/a" | field cookie)" = "[]" ] &&
    pass "$version: a cookie is left out" ||
    fail "$version: a cookie is left out"

  before=$(count)
  through $version -H "Host: other.example" -H "Authorization: token $placeholder" "$url/a" | grep -q "names another site" && [ "$(count)" = "$before" ] &&
    pass "$version: a request that names another site is refused" ||
    fail "$version: a request that names another site is refused"

  before=$(count)
  through $version -X TRACE -H "Authorization: token $placeholder" "$url/a" | grep -q "Refused by the sandbox broker" && [ "$(count)" = "$before" ] &&
    pass "$version: TRACE, which would send the token back, is refused" ||
    fail "$version: TRACE, which would send the token back, is refused"

  # A small body is read in full by the broker before it is passed on.
  sum=$(printf 'hello broker' | shasum -a 256 | cut -d' ' -f1)
  [ "$(through $version -H "Authorization: token $placeholder" --data-binary 'hello broker' "$url/a" | field body_sha256)" = "\"$sum\"" ] &&
    pass "$version: a small body arrives unchanged" ||
    fail "$version: a small body arrives unchanged"
done

echo "Logins that are not what they should be (none may reach the stand-in):"

# never_arrives <description> <curl arguments...>: the request must not arrive.
never_arrives() {
  local what=$1 before answer
  shift
  before=$(count)
  answer=$(through --http1.1 "$@" "$url/malformed" 2>&1)
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
logged " refused standin.localhost $server_port https GET /malformed other-login\$" &&
  pass "such a login is logged as refused" || fail "such a login is logged as refused"

report=$(through --http1.1 -H "Authorization: token $placeholder" -H "X-HTTP-Method-Override: DELETE" \
  -H "X-Forwarded-Host: other.example" -H "Forwarded: host=other.example" -H "X-Harmless: stays" "$url/headers")
case "$report" in
  *'"x_headers": ["x-harmless"]'*) pass "headers that claim another method or host are left out" ;;
  *) fail "headers that claim another method or host are left out" ;;
esac

before=$(count)
through --http1.1 -H "Authorization: token $placeholder" -H "Connection: Upgrade" -H "Upgrade: websocket" "$url/a" |
  grep -q "another protocol" && [ "$(count)" = "$before" ] &&
  pass "a request to switch to another protocol is refused" ||
  fail "a request to switch to another protocol is refused"

# The VM does not notice when a connection is closed, so an answer that ends
# that way has to be given an end it can see.
through --http1.1 -D - -H "Authorization: token $placeholder" "$url/unframed" >"$work/unframed" 2>&1
grep -qi "^transfer-encoding: chunked" "$work/unframed" && grep -q "Bad credentials" "$work/unframed" &&
  pass "an answer that ends by closing the connection is given a marked end" ||
  fail "an answer that ends by closing the connection is given a marked end"

echo "Without encryption:"

before=$(count)
through --proxytunnel -H "Authorization: token $placeholder" "http://standin.localhost:$server_port/a" | grep -q "was not encrypted" && [ "$(count)" = "$before" ] &&
  pass "clear text inside a tunnel is refused" ||
  fail "clear text inside a tunnel is refused"

through -H "Authorization: token $placeholder" "http://standin.localhost:$server_port/a" | grep -q "must be encrypted" && [ "$(count)" = "$before" ] &&
  pass "clear text sent to the broker directly is refused" ||
  fail "clear text sent to the broker directly is refused"

# The encrypted connection names another site than the tunnel was opened for.
if curl -sk --max-time 15 --proxy "http://127.0.0.1:$broker_port" \
  --connect-to "other.example:$server_port:standin.localhost:$server_port" "https://other.example:$server_port/a" >/dev/null 2>&1; then
  fail "a tunnel cannot be used under another name"
else
  pass "a tunnel cannot be used under another name"
fi

logged " refused standin.localhost $server_port tls tls-name-differs other.example\$" &&
  pass "the other name is logged as refused" || fail "the other name is logged as refused"

echo "What the rules do not list (each is refused before anything is sent):"

# Names that end in ".example" are set aside for examples: no such host
# exists, and the broker refuses them without looking them up.
[ "$(through -o /dev/null -w '%{http_connect}' "https://unlisted.example/a")" = 403 ] &&
  pass "a tunnel to a host that is not listed is refused" ||
  fail "a tunnel to a host that is not listed is refused"

# The first line of the broker's answer is all most programs show of it.
through -v "https://unlisted.example/a" 2>&1 | grep -q "^< HTTP/1.1 403 Refused by the sandbox broker" &&
  pass "the refusal says who refused it" || fail "the refusal says who refused it"

# Plain HTTP reaches the broker as a request it can answer in full.
answer=$(through -w '%{http_code}' "http://unlisted.example/a")
case "$answer" in
  *"unlisted.example is not an allowed destination"*"broker/rules.yaml"*403)
    pass "plain HTTP to a host that is not listed is refused, and the answer says what to change"
    ;;
  *) fail "plain HTTP to a host that is not listed is refused, and the answer says what to change" ;;
esac

other_port=$(free_port)
before=$(count)
[ "$(through -o /dev/null -w '%{http_connect}' "https://standin.localhost:$other_port/a")" = 403 ] &&
  pass "a tunnel to a listed host on another port is refused" ||
  fail "a tunnel to a listed host on another port is refused"

through "http://standin.localhost:$other_port/a" |
  grep -q "is an allowed destination, but not on port $other_port. Allowed on this host: port $server_port." &&
  pass "the answer names the port that is allowed" || fail "the answer names the port that is allowed"

[ "$(count)" = "$before" ] && pass "none of it reached the stand-in" || fail "none of it reached the stand-in"

logged " refused unlisted.example 443 connect host-not-listed\$" &&
  logged " refused unlisted.example 80 http host-not-listed\$" &&
  logged " refused standin.localhost $other_port connect port-not-listed\$" &&
  pass "each is logged as refused, with the reason" || fail "each is logged as refused, with the reason"

echo "A destination that is listed but not opened (passed on unread):"

# The stand-in under its second name, which the rules do not mark with
# `inspect`. Its certificate is for the first name, so curl is told not to
# check it (-k); what matters here is whose certificate it is.
unopened="https://unopened.localhost:$server_port"
unchecked() { curl -sk --max-time 15 --proxy "http://127.0.0.1:$broker_port" "$@"; }

[ "$(unchecked -H "Authorization: token $placeholder" "$unopened/a" | field authorization)" = "[\"token $placeholder\"]" ] &&
  pass "a request arrives as it was sent: the placeholder is not swapped" ||
  fail "a request arrives as it was sent: the placeholder is not swapped"

unchecked -v "$unopened/a" 2>&1 | grep -q "issuer: CN=stand-in authority" &&
  pass "the program sees the server's own certificate, not the broker's" ||
  fail "the program sees the server's own certificate, not the broker's"

logged " allowed unopened.localhost $server_port connect\$" &&
  pass "the tunnel is logged as allowed" || fail "the tunnel is logged as allowed"
if grep -q " unopened.localhost $server_port https " "$work/broker.log"; then
  fail "nothing from inside the tunnel is logged"
else
  pass "nothing from inside the tunnel is logged"
fi

memory() { echo $(($(ps -o rss= -p "$mitm_pid") / 1024)); }
# The broker command ends by turning into mitmdump, so the process is the same.
mitm_pid=$broker_pid

echo "When the broker's own code fails (it must refuse, not let through):"

# fails_closed <hook> <yes|no: may the request reach the stand-in>: makes the
# named hook fail, sends an ordinary request with a small body, and checks
# that the VM got no answer from the stand-in and that the log says why.
fails_closed() {
  local hook=$1 may_arrive=$2 before answer
  before=$(count)
  echo "$hook" >"$work/fail"
  answer=$(through --http1.1 --max-time 10 -H "Authorization: token $placeholder" --data-binary hello "$url/when-$hook-fails" 2>&1)
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
fails_closed request no
fails_closed server_connect no
# By the time the answer's first lines arrive, the request has been sent.
fails_closed responseheaders yes

answer=$(through --http1.1 -H "Authorization: token $placeholder" "$url/a" | field authorization)
[ "$answer" = "[\"token $standin_token\"]" ] &&
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
  outcome=$(python3 "$work/client.py" "$kind" "$broker_port" standin.localhost "$server_port" "$ca" 200 2>&1)
  case "$outcome" in
    "closed after "[0-9]" MB" | "answered HTTP/1.1 4"*) [ "$(count)" = "$before" ] &&
      pass "$what ($outcome)" || fail "$what (it reached the server)" ;;
    *) fail "$what ($outcome)" ;;
  esac
  logged "$pattern" && pass "$what: logged" || fail "$what: logged"
}
hostile head "a header that never ends" " refused standin.localhost $server_port limit too-much-unread\$"
hostile first-line "a request line that never ends" " refused standin.localhost $server_port limit too-much-unread\$"
hostile connect "a CONNECT that never ends, before any tunnel" " refused - 0 limit too-much-unread\$"
hostile plain-first-line "a request line that never ends, before any tunnel" " refused - 0 limit too-much-unread\$"
hostile tls-hello "a first TLS message that never ends" " refused standin.localhost $server_port limit tls-hello-too-long\$"

before=$(completed)
outcome=$(python3 "$work/client.py" chunk-size "$broker_port" standin.localhost "$server_port" "$ca" 200 2>&1)
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
  outcome=$(python3 "$work/client.py" "$kind" "$broker_port" standin.localhost "$server_port" "$ca" 1 2>&1)
  sleep 0.5
  case "$kind" in
    hidden-login-folded) what="a login on a continuation line" ;;
    hidden-login-cr) what="a login after a lone carriage return" ;;
    *) what="a forwarding header on a continuation line" ;;
  esac
  [ "$(count)" = "$before" ] && pass "$what ($outcome)" || fail "$what ($outcome)"
done
logged " refused standin.localhost $server_port https GET /hidden-login-folded odd-header\$" &&
  pass "a split header line is logged as refused" || fail "a split header line is logged as refused"

echo "Lines after a body (trailers), which mitmproxy cannot pass on:"

before=$(count)
through --http1.1 -H "Authorization: token $placeholder" -H "Trailer: X-After" --data-binary hello "$url/a" |
  grep -q "lines after its body" && [ "$(count)" = "$before" ] &&
  pass "a request that announces trailers is refused before anything is sent" ||
  fail "a request that announces trailers is refused before anything is sent"

# Not announced, they show only after the body, when the request's first
# lines and body have gone out. The request must then not be completed.
before=$(completed)
outcome=$(python3 "$work/client.py" trailers "$broker_port" standin.localhost "$server_port" "$ca" 1 2>&1)
sleep 0.5
case "$outcome" in
  closed | "answered HTTP/1.1 4"* | "answered HTTP/1.1 5"*) [ "$(completed)" = "$before" ] &&
    pass "a request that sends trailers unannounced is cut off, not completed ($outcome)" ||
    fail "a request that sends trailers unannounced is cut off (the server completed it)" ;;
  *) fail "a request that sends trailers unannounced is cut off, not completed ($outcome)" ;;
esac
logged " refused standin.localhost $server_port limit trailers\$" &&
  pass "trailers are logged as refused" || fail "trailers are logged as refused"

echo "Large bodies (the broker's memory use is measured in megabytes):"
megabytes=300
start_memory=$(memory)

# Git sends a large push in pieces, without saying how long it is.
[ "$(head -c $((megabytes << 20)) /dev/zero | through --http1.1 -H "Authorization: token $placeholder" \
  -H "Transfer-Encoding: chunked" -T - "$url/push" | field body_size)" = "$((megabytes << 20))" ] &&
  pass "a $megabytes MB upload in pieces arrives whole" ||
  fail "a $megabytes MB upload in pieces arrives whole"

head -c $((megabytes << 20)) /dev/zero >"$work/large"
[ "$(through --http1.1 -H "Authorization: token $placeholder" -T "$work/large" "$url/push" | field body_size)" = "$((megabytes << 20))" ] &&
  pass "a $megabytes MB upload with a declared size arrives whole" ||
  fail "a $megabytes MB upload with a declared size arrives whole"

[ "$(through --http2 -w '%{http_version}' -o /dev/null "$url/a")" = "1.1" ] &&
  pass "a program that asks for HTTP/2 is answered in HTTP/1.1" ||
  fail "a program that asks for HTTP/2 is answered in HTTP/1.1"
rm -f "$work/large"

[ "$(through "$url/big/$megabytes" | wc -c | tr -d ' ')" = "$((megabytes << 20))" ] &&
  pass "a $megabytes MB download arrives whole" ||
  fail "a $megabytes MB download arrives whole"

# A refused request with a body that never ends: the broker must hang up
# instead of taking the body in.
before=$(count)
if head -c $((megabytes << 20)) /dev/zero | through --http1.1 --max-time 30 -H "Authorization: token some-other-token" \
  -H "Transfer-Encoding: chunked" -T - "$url/push" >/dev/null 2>&1; then
  fail "a refused upload in pieces is cut off"
else
  [ "$(count)" = "$before" ] && pass "a refused upload in pieces is cut off" || fail "a refused upload in pieces is cut off"
fi

# The same from a program that asks for HTTP/2 and hides the body in a GET.
# The broker speaks HTTP/1.1 only, where a body cannot be hidden.
before=$(count)
if head -c $((megabytes << 20)) /dev/zero | through --http2 --max-time 30 -X GET -H "Authorization: token some-other-token" \
  -T - "$url/push" >/dev/null 2>&1; then
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

through -H "Authorization: token $placeholder" "$url/owner/repo?search=a-private-word" >/dev/null
check "a request is logged with its method, path and status" \
  logged " allowed standin.localhost $server_port https GET /owner/repo 200\$"
check "a refusal is logged with its reason" \
  logged " refused standin.localhost $server_port https GET /a other-login\$"

# mitmproxy and Python write to the same log as the broker, without the
# broker's code seeing the line. So everything is checked for tokens on its
# way to the log, whoever wrote it. Here a second script writes the token
# the way mitmproxy would write an error, and once past Python altogether.
echo scrub-probe >"$work/fail"
through --http1.1 "$url/a" >/dev/null
: >"$work/fail"
logged "a line that mitmproxy wrote: <secret>" &&
  pass "a token in a line that mitmproxy wrote is replaced" ||
  fail "a token in a line that mitmproxy wrote is replaced"
logged "a line written past Python: <secret>" &&
  pass "a token written straight to the output is replaced" ||
  fail "a token written straight to the output is replaced"
if grep -q "a-private-word" "$work/broker.log"; then fail "the query string is not logged"; else pass "the query string is not logged"; fi
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
