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

# How many requests the stand-in has received so far.
count() { cat "$work/count" 2>/dev/null || echo 0; }

# --- The broker --------------------------------------------------------------

cat >"$work/rules.yaml" <<EOF
destinations:
  - host: standin.localhost
    note: The stand-in for GitHub.
    ports: [$server_port]
    inspect: true
    token: github
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
    AGENT_BROKER_TOKENS="$work/tokens.yaml" "$@" \
    "$broker" --listen-port "$broker_port" \
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

echo "Large bodies (the broker's memory use is measured in megabytes):"

memory() { echo $(($(ps -o rss= -p "$mitm_pid") / 1024)); }
# The broker command ends by turning into mitmdump, so the process is the same.
mitm_pid=$broker_pid
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
sleep 0.5
check "a request is logged with its method, path and status" \
  grep -Eq " allowed standin.localhost $server_port https GET /owner/repo 200\$" "$work/broker.log"
check "a refusal is logged with its reason" \
  grep -Eq " refused standin.localhost $server_port https GET /a other-login\$" "$work/broker.log"
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
