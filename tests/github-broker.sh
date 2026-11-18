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

cd "$(dirname "$0")/.." || exit 1

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
                    or name.lower() in ("proxy-connection", "keep-alive", "te")
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
#
# Both helper scripts read what they need from files in their own folder.
# They cannot be told through the environment: the broker starts mitmproxy
# with an environment of its own.
cat >"$work/redirect.py" <<'EOF'
import os

HERE = os.path.dirname(os.path.abspath(__file__))
STAND_IN = ("127.0.0.1", int(open(os.path.join(HERE, "stand-in-port")).read()))
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

from mitmproxy import ctx

CONTROL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fail")
changed = False


def maybe_fail():
    try:
        hook = open(CONTROL).read().strip()
    except OSError:
        return
    if hook == "change-a-setting":
        # Turn on, while the broker runs, a setting that rewrites requests:
        # here, one that adds a header to each. Once is enough.
        global changed
        if not changed:
            changed = True
            ctx.options.update(modify_headers=["/~q/X-Added-By-A-Setting/after-the-start"])
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

# "stream-first": before the broker is asked about a request, switch on the
# passing-on of its body in pieces, as mitmproxy itself does for a body
# larger than its `stream_large_bodies`. mitmproxy then sends the request's
# first lines to the server at once, unless the broker switches it off again.
asked = type(broker).requestheaders


def stream_first(self, flow):
    try:
        mode = open(CONTROL).read().strip()
    except OSError:
        mode = ""
    if mode == "stream-first":
        flow.request.stream = True
    return asked(self, flow)


type(broker).requestheaders = stream_first

# "settings-file-at-start": put a settings file into mitmproxy's folder now,
# after the broker's check at start has passed and before mitmproxy is up.
try:
    at_start = open(CONTROL).read().strip()
except OSError:
    at_start = ""
if at_start == "settings-file-at-start":
    with open(os.path.join(os.path.expanduser(ctx.options.confdir), "config.yaml"), "w") as file:
        file.write("# put here by the test\n")
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
    # The message is cut into TLS records of 16 KiB, each with its five
    # bytes in front, as a real message of that length would be. Filler
    # without them is turned down by mitmproxy's own reader, which may
    # happen before the broker's limit is reached; then the limit is not
    # what was tested, and mitmproxy can stumble over the bytes that follow.
    record = b"\x16\x03\x01\x40\x00"
    piece = (record + b"a" * 0x4000) * 4
    flood(tunnel(encrypted=False), record + b"\x01\xff\xff\xff" + b"a" * (0x4000 - 4))
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
elif kind == "requests":
    # Several requests, one after the other on ONE connection, each given as
    # its first line without the version: "GET /path". They are sent exactly
    # as written, so a method in small letters or a "#" in the address
    # arrives at the broker as it stands. curl cannot do either: it opens a
    # connection per call here, and it cuts a "#" off.
    #
    # Prints one line per answer: "arrived with the token", "arrived without
    # a login", or "refused", after the status.
    import json

    placeholder, lines = sys.argv[7], sys.argv[8:]
    connection = tunnel()
    connection.settimeout(15)
    reader = connection.makefile("rb")
    for line in lines:
        try:
            connection.sendall(
                f"{line} HTTP/1.1\r\nHost: {host}\r\nAuthorization: token {placeholder}\r\n\r\n".encode()
            )
            status = reader.readline().split()[1].decode()
            length = 0
            while (header := reader.readline()) not in (b"\r\n", b""):
                name, _, value = header.partition(b":")
                if name.lower() == b"content-length":
                    length = int(value)
            body = reader.read(length)
        except (OSError, ssl.SSLError, IndexError, ValueError):
            print("closed")
            break
        try:
            report = json.loads(body)
        except ValueError:
            report = {}
        if "authorization" not in report:
            print(status, "refused")
        elif report["authorization"]:
            print(status, "arrived with the token")
        else:
            print(status, "arrived without a login")
elif kind == "odd-headers":
    # One request each, with a header that holds a byte outside plain ASCII.
    # megabytes is not used. Prints "refused" or "arrived" for each.
    import json

    placeholder = sys.argv[7]
    cases = [
        b"Content-Type: application/json\xa0",
        b"Content-Encoding: \xa0",
        b"X-Nul: a\x00b",
        b"X-High: \xff\xfe",
        b"X-Accent: caf\xc3\xa9",
        b"X-Unit-Separator: a\x1fb",
    ]
    for case in cases:
        connection = tunnel()
        connection.settimeout(15)
        body = b'{"body":"x"}'
        connection.sendall(
            f"POST /repos/madshermansen/nixt3/issues/7/comments HTTP/1.1\r\nHost: {host}\r\n"
            f"Authorization: token {placeholder}\r\nContent-Length: {len(body)}\r\n".encode()
            + (b"" if case.lower().startswith(b"content-type") else b"Content-Type: application/json\r\n")
            + case
            + b"\r\n\r\n"
            + body
        )
        try:
            answer = connection.recv(4096)
        except (OSError, ssl.SSLError):
            answer = b""
        print("arrived" if b"body_sha256" in answer else "refused")
        connection.close()
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
    # What `gh pr edit` reads before it changes anything: who can be
    # assigned. That is not on the policy's list.
    "read-before-an-edit": (
        'query { repository(owner: "madshermansen", name: "nixt3") '
        "{ pullRequest(number: 5) { assignedActors(first: 5) { nodes { __typename } } } } }",
        {},
    ),
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
# unless a variable names other ones. What is in `extra` is added to
# mitmproxy's arguments. Every broker started here sends its
# connections to the stand-in.
# Every broker in this test is started from a shell that has these set, as
# a developer's shell might. Each changes what mitmproxy, Python or the TLS
# library does, or makes them write somewhere, if it reaches them: the
# first two make mitmproxy write the keys of every encrypted connection to a
# file. The broker's start command must pass none of them on, so the test
# must pass as if they were not there, and the two files must not appear.
hostile_environment=(
  SSLKEYLOGFILE="$work/keys.log"
  MITMPROXY_SSLKEYLOGFILE="$work/keys-too.log"
  HTTPS_PROXY="http://127.0.0.1:9"
  https_proxy="http://127.0.0.1:9"
  ALL_PROXY="http://127.0.0.1:9"
  SSL_CERT_FILE="/dev/null"
  SSL_CERT_DIR="/var/empty"
  NIX_SSL_CERT_FILE="/dev/null"
  OPENSSL_CONF="$work/no-such-openssl.cnf"
  PYTHONWARNINGS="error"
  MITMPROXY_DEBUG_EXIT="1"
)
printf '%s' "$server_port" >"$work/stand-in-port"

extra=()
start_broker() {
  local log=$1
  shift
  env -u AGENT_BROKER_RULES AGENT_VM_STATE="$work/state" \
    AGENT_BROKER_TOKENS="$work/tokens.yaml" "${hostile_environment[@]}" "$@" \
    "$broker" --listen-port "$broker_port" --scripts "$work/redirect.py" --scripts "$work/inject.py" \
    --set ssl_verify_upstream_trusted_ca="$work/ca.pem" ${extra[@]+"${extra[@]}"} >"$log" 2>&1 &
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

# mitmproxy's own settings. Some of them change a request after the broker
# has judged it, and mitmproxy reads a settings file from its folder without
# being asked. The broker must not run with either. See broker/settings.py.
#
# must_not_start <description> <words of the message> [variable=value...]
must_not_start() {
  local what=$1 words=$2 log
  shift 2
  log="$work/setting-$RANDOM.log"
  start_broker "$log" "$@"
  # A broker that does start would keep running. It gets ten seconds to
  # give up by itself, and is then stopped and counted as a failure.
  for _ in $(seq 100); do
    kill -0 "$broker_pid" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$broker_pid" 2>/dev/null; then
    kill "$broker_pid" 2>/dev/null
    wait "$broker_pid" 2>/dev/null
    fail "$what: the broker does not start (it did, and was stopped)"
  elif wait "$broker_pid"; then
    fail "$what: the broker does not start"
  elif grep -q "$words" "$log"; then
    pass "$what: the broker does not start, and says why"
  else
    fail "$what: the broker does not start, and says why"
  fi
}
mkdir -p "$work/state-with-file/broker"
printf 'map_remote:\n  - "|%s/info/refs|%s/info/refs"\n' "$listed" "$unlisted" >"$work/state-with-file/broker/config.yaml"
must_not_start "a settings file in the broker's folder" "config.yaml is a settings file" AGENT_VM_STATE="$work/state-with-file"
mkdir -p "$work/state-with-yml/broker"
: >"$work/state-with-yml/broker/config.yml"
must_not_start "an empty settings file under its other name" "config.yml is a settings file" AGENT_VM_STATE="$work/state-with-yml"

extra=(--set "map_remote=|$listed/info/refs|$unlisted/info/refs")
must_not_start "a setting that sends a request elsewhere after it was judged (map_remote)" '`map_remote` is set'
extra=(--map-remote "|$listed/info/refs|$unlisted/info/refs")
must_not_start "the same setting given as an option of its own" '`map_remote` is set'
extra=(--set "modify_headers=/~q/Authorization/token something-else")
must_not_start "a setting that rewrites headers (modify_headers)" '`modify_headers` is set'
extra=(--set "modify_body=/~q/main/other")
must_not_start "a setting that rewrites bodies (modify_body)" '`modify_body` is set'
extra=(--mode "upstream:http://127.0.0.1:9")
must_not_start "sending everything through another proxy (mode)" '`mode` is set'
extra=(--set "stickyauth=.")
must_not_start "a setting that adds an earlier login to later requests (stickyauth)" '`stickyauth` is set'
extra=(--set "save_stream_file=$work/flows")
must_not_start "a setting that writes the traffic to a file (save_stream_file)" '`save_stream_file` is set'
extra=(--set "ssl_insecure=true")
must_not_start "certificate checks turned off (ssl_insecure)" '`ssl_insecure` is set'
extra=(--listen-host 0.0.0.0)
must_not_start "listening on every address, not only this Mac's own" '`listen_host` must be'
extra=(--flow-detail 2)
must_not_start "mitmproxy printing the traffic into the log (flow_detail)" '`flow_detail` must be'
extra=()
# mitmproxy creates the file when it is given the setting, before the
# broker's check runs. It must stay empty.
if [ -s "$work/flows" ]; then fail "nothing was written to the traffic file"; else pass "nothing was written to the traffic file"; fi

# The environment. The start command gives mitmproxy an environment of its
# own, so a variable in the shell does not reach it (the brokers above and
# below are all started with a hostile one). Here mitmproxy is started by
# hand, the way the start command does, but with the shell's environment:
# the broker itself must then refuse.
run=$(grep -o '/nix/store/[a-z0-9]*-agent-vm-broker-run/bin/agent-vm-broker-run' "$broker" | head -n 1)
mitmdump=$(grep -o '/nix/store/[^ "]*/bin/mitmdump' "$run" | head -n 1)
proxy_script=$(grep -o '/nix/store/[^ "]*-broker/proxy.py' "$run" | head -n 1)
# by_hand <variable=value> [size]: starts mitmproxy with the broker's script
# and that one variable more, and with `stream_large_bodies` set to the size
# if one is given. Prints what it said.
by_hand() {
  /usr/bin/env -i PYTHONUNBUFFERED=1 AGENT_BROKER_RULES="${proxy_script%proxy.py}rules.yaml" "$1" \
    "$mitmdump" --listen-host 127.0.0.1 --listen-port "$broker_port" --set confdir="$work/state-by-hand" \
    --set connection_strategy=lazy --set flow_detail=0 --set termlog_verbosity=error --set onboarding=false \
    --set stream_large_bodies="${2:-1m}" --set rawtcp=false --set http2=false --scripts "$proxy_script" 2>&1 &
  local pid=$!
  for _ in $(seq 100); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null
    echo "IT STARTED"
  fi
  wait "$pid" 2>/dev/null
}
if [ -x "$mitmdump" ] && [ -f "$proxy_script" ]; then
  for variable in SSLKEYLOGFILE MITMPROXY_SSLKEYLOGFILE PYTHONPATH OPENSSL_CONF HTTPS_PROXY SSL_CERT_FILE SOMETHING_ELSE; do
    said=$(by_hand "$variable=$work/from-the-environment")
    case "$said" in
      *"IT STARTED"*) fail "started by hand with $variable set: the broker does not start" ;;
      *"the variable \`$variable\` is set"*) pass "started by hand with $variable set: the broker does not start, and names it" ;;
      *) fail "started by hand with $variable set: the broker does not start, and names it" ;;
    esac
  done
  # Without any such variable the same start gets past this check, and stops
  # at the next thing it lacks, the tokens.
  case "$(by_hand PYTHONUNBUFFERED=1)" in
    *"no tokens were handed over"*) pass "started by hand without one, it gets as far as asking for its tokens" ;;
    *) fail "started by hand without one, it gets as far as asking for its tokens" ;;
  esac
  # The start command sets `stream_large_bodies`, and mitmproxy takes no
  # second value for a setting, so only a start by hand can change it. Below
  # that size mitmproxy would pass a body on before the broker has read it.
  case "$(by_hand PYTHONUNBUFFERED=1 1k)" in
    *'`stream_large_bodies` must be'*) pass "started by hand with stream_large_bodies=1k: the broker does not start, and says why" ;;
    *) fail "started by hand with stream_large_bodies=1k: the broker does not start, and says why" ;;
  esac
else
  fail "the test found mitmdump and the broker's script in the start command"
fi
if [ -e "$work/from-the-environment" ]; then fail "nothing was written where those variables pointed"; else pass "nothing was written where those variables pointed"; fi

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

# graphql_error: reads the message of the first error of a GraphQL answer.
graphql_error() {
  python3 -c 'import json, sys; print(json.dumps(json.load(sys.stdin)["errors"][0]["message"]))' 2>/dev/null
}

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
  # For the API the refusal is wrapped as JSON: the way GraphQL reports an
  # error for a GraphQL request, the way the REST API does for the rest.
  case "$address" in
    "$api/graphql") answer=$(printf '%s' "$answer" | graphql_error | sed 's/^"//') ;;
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

# Headers about the connection to the next server. One of them can name
# other headers for that server to drop.
report=$(through --http1.1 "${login[@]}" -H "Proxy-Connection: Authorization" -H "Keep-Alive: timeout=5" \
  -H "TE: trailers" -H "X-Harmless: stays" "$api/repos/$listed")
case "$report" in
  *'"x_headers": ["x-harmless"]'*) [ "$(printf '%s' "$report" | field authorization)" = "$with_token" ] &&
    pass "Proxy-Connection, Keep-Alive and TE are left out" || fail "Proxy-Connection, Keep-Alive and TE are left out" ;;
  *) fail "Proxy-Connection, Keep-Alive and TE are left out" ;;
esac

# A header with a byte outside plain ASCII. Programs disagree about such
# bytes; the policy, for one, would read `application/json` followed by the
# byte 0xa0 as `application/json`.
before=$(count)
outcome=$(python3 "$work/client.py" odd-headers "$broker_port" api.github.com 443 "$ca" 0 "$placeholder" 2>&1 | tr '\n' ' ')
[ "$outcome" = "refused refused refused refused refused refused " ] && [ "$(count)" = "$before" ] &&
  pass "six headers with a byte outside plain ASCII are refused, and none arrives" ||
  fail "six headers with a byte outside plain ASCII are refused, and none arrives ($outcome)"
logged " refused api.github.com 443 https POST /repos/$listed/issues/7/comments odd-header\$" &&
  pass "such a header is logged as refused" || fail "such a header is logged as refused"

turned_away "a header that asks for another method than the one sent is refused" method-override "asks for another method" \
  -H "X-HTTP-Method-Override: DELETE" "${json[@]}" --data-binary '{"body":"x"}' "$api/repos/$listed/issues/7/comments"

before=$(count)
through --http1.1 "${login[@]}" -H "Upgrade: websocket" "$api/repos/$listed" |
  grep -q "another protocol" && [ "$(count)" = "$before" ] &&
  pass "a request to switch to another protocol is refused" ||
  fail "a request to switch to another protocol is refused"

# A Connection header can name other headers, which tells the next server
# on the way to drop them: after the broker has judged the request with them.
turned_away "a Connection header that names other headers to drop" odd-connection-header "Connection header" \
  -H "Connection: keep-alive, Content-Type, Authorization" "$api/repos/$listed"
turned_away "the same in the form a request to switch protocols has" odd-connection-header "Connection header" \
  -H "Connection: Upgrade" "$api/repos/$listed"
[ "$(through --http1.1 "${login[@]}" -H "Connection: close" "$api/repos/$listed" | field authorization)" = "$with_token" ] &&
  [ "$(through --http1.1 "${login[@]}" -H "Connection: Keep-Alive" "$api/repos/$listed" | field authorization)" = "$with_token" ] &&
  pass "the two usual Connection headers are passed on" || fail "the two usual Connection headers are passed on"

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

# The status of the answer in "$work/headers". The first status line there
# is the broker's answer to the request for a tunnel; the last is the one
# meant.
answer_status() { grep "^HTTP/" "$work/headers" | tail -n 1 | cut -d' ' -f2; }

# gh shows the `message` of a JSON error, and only the status line of a
# plain-text one. git shows a plain-text body line by line.
through --http1.1 -D "$work/headers" "${login[@]}" "$api/repos/$unlisted" >"$work/answer"
[ "$(answer_status)" = 403 ] && grep -qi "^content-type: application/json" "$work/headers" &&
  [ "$(field message <"$work/answer" | cut -c1-32)" = '"Refused by the sandbox broker: ' ] &&
  pass "on the REST API a refusal is a 403 with a JSON message, as GitHub's own errors are" ||
  fail "on the REST API a refusal is a 403 with a JSON message, as GitHub's own errors are"

# The gh commands that change something print the body of a 403 as one line
# with every quote and line break escaped. They show cleanly what GraphQL
# itself sends for a refusal: the status 200 and `errors` in place of data.
through --http1.1 -D "$work/headers" "${login[@]}" "${json[@]}" --data-binary "@$work/graphql/close-by-id.json" "$api/graphql" >"$work/answer"
[ "$(answer_status)" = 200 ] && grep -qi "^content-type: application/json" "$work/headers" &&
  [ "$(graphql_error <"$work/answer" | cut -c1-32)" = '"Refused by the sandbox broker: ' ] &&
  [ "$(field data <"$work/answer")" = null ] &&
  pass "a refused GraphQL request is answered the way GraphQL reports an error" ||
  fail "a refused GraphQL request is answered the way GraphQL reports an error"

# Only the GraphQL address itself is answered that way. A REST address that
# merely has the word in it gets the 403 of the REST API.
for address in "$api/repos/$unlisted/contents/graphql" "$api/repos/$unlisted/graphql" "$api/graphql/extra" "$api/graphqlx"; do
  through --http1.1 -D "$work/headers" "${login[@]}" "$address" >"$work/answer"
  [ "$(answer_status)" = 403 ] && [ "$(field message <"$work/answer" | cut -c1-32)" = '"Refused by the sandbox broker: ' ] &&
    pass "a refusal for ${address#"$api"} is a 403, not the GraphQL answer" ||
    fail "a refusal for ${address#"$api"} is a 403, not the GraphQL answer"
done

through --http1.1 -D "$work/headers" "${login[@]}" "$git/$unlisted/info/refs?service=git-upload-pack" >"$work/answer"
[ "$(answer_status)" = 403 ] && grep -qi "^content-type: text/plain" "$work/headers" && head -n 1 "$work/answer" | grep -q "^Refused by the sandbox broker: " &&
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
turned_away "the same with the dots encoded" path-odd "" --path-as-is "$api/repos/$listed/%2E%2E/%2E%2E/$unlisted"
turned_away "a doubled slash" path-odd "" --path-as-is "$api/repos/madshermansen//nixt3"
turned_away "an encoded keyword" not-recognised "" "$api/repos/$listed/%70ulls"

echo "What may be sent to GitHub: GraphQL, which gh uses"

arrives "read the listed repo" graphql-read "${json[@]}" --data-binary "@$work/graphql/read-listed.json" "$api/graphql"
# The file has spaces and line breaks; what the policy writes out has none.
case "$(through --http1.1 "${login[@]}" "${json[@]}" --data-binary "@$work/graphql/read-listed.json" "$api/graphql")" in
  *'"body_start": "{\"query\":\"query {'*) pass "the request arrives written out afresh by the policy" ;;
  *) fail "the request arrives written out afresh by the policy" ;;
esac
arrives "ask who the token belongs to" graphql-read "${json[@]}" --data-binary "@$work/graphql/who-am-i.json" "$api/graphql"
arrives "open a pull request in the listed repo, as gh pr create does" graphql-write \
  "${json[@]}" --data-binary "@$work/graphql/open-pull-request.json" "$api/graphql"

turned_away "read a repo that is not listed" repo-not-listed "is not a repo the sandbox may use" \
  "${json[@]}" --data-binary "@$work/graphql/read-unlisted.json" "$api/graphql"
turned_away "open a pull request in a repo that is not listed" graphql-id-not-listed "" \
  "${json[@]}" --data-binary "@$work/graphql/open-pull-request-elsewhere.json" "$api/graphql"
turned_away "open a pull request from someone's fork" head-elsewhere "" \
  "${json[@]}" --data-binary "@$work/graphql/open-pull-request-from-a-fork.json" "$api/graphql"
turned_away "close a pull request by its id, as gh pr close does: refused, with the way on" graphql-by-id "gh api" \
  "${json[@]}" --data-binary "@$work/graphql/close-by-id.json" "$api/graphql"
turned_away "comment by a forged id that claims the listed repo" graphql-by-id "" \
  "${json[@]}" --data-binary "@$work/graphql/comment-by-forged-id.json" "$api/graphql"
turned_away "a query that walks from the listed repo to its owner's other repos" graphql-not-on-list "" \
  "${json[@]}" --data-binary "@$work/graphql/walk-to-the-owners-repos.json" "$api/graphql"
turned_away "a query that walks from the listed repo to the repo it was forked from" graphql-not-on-list "" \
  "${json[@]}" --data-binary "@$work/graphql/walk-to-the-parent.json" "$api/graphql"
turned_away "a query for all the repos the token can see" graphql-not-on-list "" \
  "${json[@]}" --data-binary "@$work/graphql/my-repos.json" "$api/graphql"

# `gh pr edit` reads who can be assigned before it changes anything, and is
# refused at that read. The refusal has to name the way to make the change.
turned_away "what gh pr edit reads first is refused, and the refusal names the gh api line for the change" \
  graphql-not-on-list "gh api -X PATCH repos/OWNER/REPO/pulls/NUMBER -f title=" \
  "${json[@]}" --data-binary "@$work/graphql/read-before-an-edit.json" "$api/graphql"

echo "The request as it was sent, not a tidied view of it (none of the refused may reach the stand-in):"

# sent <host> <expected answers, one per line> <first lines of the requests...>:
# sends the requests as written, on one connection, with the placeholder.
sent() {
  local what=$1 host=$2 expected=$3 outcome
  shift 3
  outcome=$(python3 "$work/client.py" requests "$broker_port" "$host" 443 "$ca" 0 "$placeholder" "$@" 2>&1)
  if [ "$outcome" = "$expected" ]; then pass "$what"; else fail "$what ($(printf '%s' "$outcome" | tr '\n' ';'))"; fi
}
yes="200 arrived with the token"
no="403 refused"

# A decision is about one request. A connection that has carried an allowed
# request must not carry a refused one after it.
git_read="/info/refs?service=git-upload-pack"
before=$(count)
sent "git: a listed repo, then an unlisted one, on one connection" github.com "$yes
$no" "GET /$listed$git_read" "GET /$unlisted$git_read"
sent "git: an unlisted repo, then a listed one" github.com "$no
$yes" "GET /$unlisted$git_read" "GET /$listed$git_read"
sent "git: a fetch from the listed repo, then a push to an unlisted one" github.com "$yes
$no" "GET /$listed$git_read" "GET /$unlisted/info/refs?service=git-receive-pack"
sent "the API: a listed repo, then an unlisted one, then the listed one again" api.github.com "$yes
$no
$yes" "GET /repos/$listed" "GET /repos/$unlisted" "GET /repos/$listed"
sent "the API: an unlisted repo, then a listed one" api.github.com "$no
$yes" "GET /repos/$unlisted" "GET /repos/$listed"
sent "the API: a read of the listed repo, then its secrets" api.github.com "$yes
$no" "GET /repos/$listed" "GET /repos/$listed/actions/secrets"
[ "$(count)" = "$((before + 7))" ] &&
  pass "of those fourteen requests, the seven allowed ones reached the stand-in and no other" ||
  fail "of those fourteen requests, the seven allowed ones reached the stand-in and no other (it got $(($(count) - before)))"

# A "#" has no place in a request. The broker must not cut it off for the
# policy and then send it on: a server that reads on after the "#" would
# act on an address the policy never saw.
before=$(count)
sent "a # in the path, followed by a way out of the listed repo" api.github.com "$no" \
  "GET /repos/$listed#/../../$unlisted"
sent "a # in the path of a git request" github.com "$no" "GET /$listed#/../$unlisted$git_read"
sent "a # in the query string" api.github.com "$no" "GET /repos/$listed/pulls?state=open#/../../../$unlisted"
sent "a # at the end of a git request" github.com "$no" "GET /$listed$git_read#"
sent "a # alone" api.github.com "$no" "GET /repos/$listed#"
[ "$(count)" = "$before" ] && pass "none of them reached the stand-in" || fail "none of them reached the stand-in"
logged " refused api.github.com 443 https GET /repos/$listed path-odd\$" &&
  logged " refused api.github.com 443 https GET /repos/$listed/pulls query-odd\$" &&
  pass "they are logged as an odd path and an odd query" || fail "they are logged as an odd path and an odd query"

# A method in small or mixed letters. mitmproxy shows it to a script in
# capitals and sends it on as it came, so the broker has to look at what
# was sent.
before=$(count)
sent "a method in small letters: get" api.github.com "$no" "get /repos/$listed"
sent "delete, on a comment" api.github.com "$no" "delete /repos/$listed/issues/comments/5"
sent "Post, with a capital" api.github.com "$no" "Post /repos/$listed/issues/7/comments"
sent "PoSt, mixed, as a push" github.com "$no" "PoSt /$listed/git-receive-pack"
sent "get, as a fetch" github.com "$no" "get /$listed$git_read"
sent "a refused spelling, then the usual one on the same connection" api.github.com "$no
$yes" "get /repos/$listed" "GET /repos/$listed"
[ "$(count)" = "$((before + 1))" ] && pass "only the one in capitals reached the stand-in" ||
  fail "only the one in capitals reached the stand-in"
logged " refused api.github.com 443 https delete /repos/$listed/issues/comments/5 odd-method\$" &&
  pass "the log has the method as it was sent" || fail "the log has the method as it was sent"
if grep -Eq " allowed [^ ]+ 443 https (get|delete|Post|PoSt) " "$work/broker.log"; then
  fail "no request with such a method was let through"
else
  pass "no request with such a method was let through"
fi

echo "When mitmproxy has chosen to pass a body on unread before the broker is asked:"

# mitmproxy does that by itself for a body larger than one of its settings,
# and then sends the request's first lines to the server at once. The broker
# pins that setting, and does not rely on it: whatever it refuses, or reads
# first, it takes back from mitmproxy. The second script switches the
# passing-on on for every request here, before the broker's code runs.
echo stream-first >"$work/fail"
before=$(count)
answer=$(through --http1.1 "${login[@]}" "${json[@]}" --data-binary '{"body":"something to carry out"}' "$api/repos/$unlisted/issues/1/comments")
case "$answer" in
  *"nothing can be sent to it"*) [ "$(count)" = "$before" ] &&
    pass "a refused change does not reach the server, also then" ||
    fail "a refused change does not reach the server, also then (it arrived)" ;;
  *) fail "a refused change does not reach the server, also then" ;;
esac
before=$(count)
through --http1.1 -H "Authorization: token some-other-token" "${json[@]}" --data-binary '{"body":"x"}' "$api/repos/$listed/issues/7/comments" |
  grep -q "not this sandbox's own" && [ "$(count)" = "$before" ] &&
  pass "nor does a request with another login" || fail "nor does a request with another login"
sum=$(printf '{"body":"hello broker"}' | shasum -a 256 | cut -d' ' -f1)
report=$(through --http1.1 "${login[@]}" "${json[@]}" --data-binary '{ "body" : "hello broker" }' "$api/repos/$listed/issues/7/comments")
[ "$(printf '%s' "$report" | field body_sha256)" = "\"$sum\"" ] && [ "$(printf '%s' "$report" | field authorization)" = "$with_token" ] &&
  pass "an allowed change is still read first: it arrives as the policy wrote it out, with the token" ||
  fail "an allowed change is still read first: it arrives as the policy wrote it out, with the token"
: >"$work/fail"

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
cut_off "a GraphQL request sent in pieces" -H "Transfer-Encoding: chunked" --data-binary "@$work/graphql/open-pull-request.json" "$api/graphql"
python3 -c 'import json, sys; json.dump({"body": "x" * 2_000_000}, sys.stdout)' >"$work/large.json"
cut_off "a comment of 2 MB" --data-binary "@$work/large.json" "$api/repos/$listed/issues/7/comments"
cut_off "a read with a body sent in pieces" -X GET -H "Transfer-Encoding: chunked" --data-binary '{"body":"x"}' "$api/repos/$listed"
rm -f "$work/large.json"
logged " refused api.github.com 443 https POST /graphql body-not-read\$" &&
  pass "such a request is logged as refused" || fail "such a request is logged as refused"

echo "With 'other_repos: read-public': repos that are not listed may be read, without the token:"

# A second broker, with rules that differ in that one line.
env -u AGENT_BROKER_RULES AGENT_VM_STATE="$work/state2" AGENT_BROKER_RULES="$work/read-public.yaml" \
  AGENT_BROKER_TOKENS="$work/tokens.yaml" "${hostile_environment[@]}" \
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
second "${login[@]}" "${json[@]}" --data-binary "@$work/graphql/read-unlisted.json" "$api/graphql" | grep -q "Refused by the sandbox broker" && [ "$(count)" = "$before" ] &&
  pass "GraphQL, which needs the token, still refuses an unlisted repo" ||
  fail "GraphQL, which needs the token, still refuses an unlisted repo"

if grep -q "$standin_token" "$work/second.log"; then fail "the token is not in the second broker's log"; else pass "the token is not in the second broker's log"; fi
kill "$second_pid" 2>/dev/null
second_pid=""

echo "A setting that changes while the broker runs:"

# A third broker, with helper scripts of its own, so that what is done to it
# does not touch the one the other checks use.
mkdir "$work/third"
cp "$work/redirect.py" "$work/inject.py" "$work/stand-in-port" "$work/third/"
third_port=$second_port
# start_third <log file>: starts it; its id is in second_pid, so that it is
# stopped with the test.
start_third() {
  env -u AGENT_BROKER_RULES AGENT_VM_STATE="$work/state3" AGENT_BROKER_TOKENS="$work/tokens.yaml" \
    "${hostile_environment[@]}" \
    "$broker" --listen-port "$third_port" --scripts "$work/third/redirect.py" --scripts "$work/third/inject.py" \
    --set ssl_verify_upstream_trusted_ca="$work/ca.pem" >"$1" 2>&1 &
  second_pid=$!
}
third() {
  curl -s --max-time 20 --proxy "http://127.0.0.1:$third_port" \
    --cacert "$work/state3/broker/mitmproxy-ca-cert.pem" --http1.1 "$@"
}
# gone <pid>: whether the process ends by itself within ten seconds.
gone() {
  for _ in $(seq 100); do
    kill -0 "$1" 2>/dev/null || return 0
    sleep 0.1
  done
  return 1
}

: >"$work/third/fail"
start_third "$work/third.log"
main_pid=$broker_pid
broker_pid=$second_pid
if ! wait_for_port "$third_port"; then
  echo "The third broker did not start:"
  cat "$work/third.log"
  exit 1
fi
broker_pid=$main_pid
[ "$(third "${login[@]}" "$api/repos/$listed" | field authorization)" = "$with_token" ] &&
  pass "before the change, a request goes through as usual" || fail "before the change, a request goes through as usual"

# The second script now turns on a setting that adds a header to every
# request, in the middle of the next request.
echo change-a-setting >"$work/third/fail"
before=$(count)
report=$(third "${login[@]}" -H "X-Harmless: stays" "$api/repos/$listed" 2>&1)
case "$report" in
  *x-added-by-a-setting* | *body_sha256*) fail "the request under way when a setting changed does not leave" ;;
  *) [ "$(count)" = "$before" ] && pass "the request under way when a setting changed does not leave" ||
    fail "the request under way when a setting changed does not leave (it arrived)" ;;
esac
if gone "$second_pid"; then pass "the broker stops by itself"; else fail "the broker stops by itself"; fi
grep -q 'stopping, because mitmproxy runs with settings' "$work/third.log" && grep -q '`modify_headers` is set' "$work/third.log" &&
  pass "and says which setting" || fail "and says which setting"
before=$(count)
third "${login[@]}" "$api/repos/$listed" >/dev/null 2>&1
[ "$(count)" = "$before" ] && pass "nothing goes through it afterwards" || fail "nothing goes through it afterwards"
kill "$second_pid" 2>/dev/null
wait "$second_pid" 2>/dev/null
second_pid=""

# A settings file that appears in mitmproxy's folder after the broker's
# check at start, and before mitmproxy is up. The check made once mitmproxy
# has started has to find it.
echo settings-file-at-start >"$work/third/fail"
rm -f "$work/state3/broker/config.yaml"
start_third "$work/third-file.log"
if gone "$second_pid"; then
  pass "a settings file that appears during the start: the broker stops by itself"
else
  fail "a settings file that appears during the start: the broker stops by itself"
fi
grep -q 'config.yaml is a settings file' "$work/third-file.log" &&
  pass "and names the file" || fail "and names the file"
before=$(count)
third "${login[@]}" "$api/repos/$listed" >/dev/null 2>&1
[ "$(count)" = "$before" ] && pass "nothing went through it" || fail "nothing went through it"
kill "$second_pid" 2>/dev/null
wait "$second_pid" 2>/dev/null
second_pid=""
: >"$work/third/fail"

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
# The shell these brokers were started from named two files for the keys
# of encrypted connections, among them the one that carries the token.
if [ -e "$work/keys.log" ] || [ -e "$work/keys-too.log" ]; then
  fail "the keys of the broker's connections were written nowhere"
else
  pass "the keys of the broker's connections were written nowhere"
fi
if ps eww -o command= -p "$mitm_pid" | grep -Eq "SSLKEYLOGFILE|HTTPS_PROXY|OPENSSL_CONF"; then
  fail "the shell's variables did not reach mitmproxy"
else
  pass "the shell's variables did not reach mitmproxy"
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

# --- The rules themselves ------------------------------------------------------
#
# Everything above is about a destination that the broker opens. This part
# is about the plainer half of the rules, which is all that stands between
# the VM and the rest of the internet: what is not listed is refused, what
# is listed and not opened is passed on unread, and a rules file with a
# mistake in it stops the broker. The check inside the VM
# (tests/network-lock.sh) shows the same from the VM's side.
#
# It is kept apart from the rest on purpose. It uses a broker of its own,
# started after the one above has done its work, with rules written here
# and with nothing of the checks above loaded into it. It needs only the
# stand-in server and the helpers `pass`, `fail`, `check`, `count`, `field`
# and `port_open`.

kill "$broker_pid" 2>/dev/null
wait "$broker_pid" 2>/dev/null

# A mitmproxy script, loaded after the broker's, that sends the one
# connection the rules below allow to the stand-in, the way a name server
# would if it gave this machine's address for the name. It refuses every
# other connection, so nothing here leaves this machine and no name is ever
# looked up.
cat >"$work/to-stand-in.py" <<'EOF'
import os

STAND_IN = ("127.0.0.1", int(os.environ["RULES_TEST_STAND_IN"]))


class ToStandIn:
    def server_connect(self, data):
        if data.server.error:
            return  # The broker has refused it already.
        if data.server.address == ("unopened.example", 443):
            data.server.address = STAND_IN
        else:
            data.server.error = "the test lets nothing leave this machine"


addons = [ToStandIn()]
EOF

# Names that end in ".example" are set aside for examples: no such host
# exists. One of them is listed, without `inspect`.
cat >"$work/plain-rules.yaml" <<EOF
destinations:
  - host: unopened.example
    note: The stand-in, as a destination that is passed on without being opened.
EOF

# start_plain <log file> <rules file>: starts a broker with these rules in
# the background, with a state folder of its own.
start_plain() {
  env AGENT_VM_STATE="$work/plain-state" AGENT_BROKER_RULES="$2" \
    AGENT_BROKER_TOKENS="$work/tokens.yaml" RULES_TEST_STAND_IN="$server_port" \
    "$broker" --listen-port "$broker_port" --scripts "$work/to-stand-in.py" >"$1" 2>&1 &
  broker_pid=$!
}
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
  start_plain "$work/bad-rules.log" "$work/bad-rules.yaml"
  stops_by_itself && pass "$what: the broker does not start" || fail "$what: the broker does not start"
  check "$what: the message says the rules are why" \
    grep -q "the rules file cannot be used" "$work/bad-rules.log"
}

echo "Rules that cannot be used (each must stop the broker):"

# A broker that started without rules, or with half of them, would let
# through what nobody chose. fetch_tokens.py reads the file first and stops
# at one that is missing or is not YAML. Every other mistake is left to the
# broker itself, which must then end instead of starting.
start_plain "$work/no-rules.log" "$work/missing-rules.yaml"
stops_by_itself && pass "no rules file: the broker does not start" || fail "no rules file: the broker does not start"

printf 'destinations: [\n' >"$work/not-yaml.yaml"
start_plain "$work/not-yaml.log" "$work/not-yaml.yaml"
stops_by_itself && pass "a rules file that is not YAML: the broker does not start" ||
  fail "a rules file that is not YAML: the broker does not start"

bad_rules "an empty rules file" ""
bad_rules "a misspelt key in a rule" "destinations:
  - host: unopened.example
    note: The key below should be 'inspect'.
    inspct: true"
bad_rules "a rule for every host" "destinations:
  - host: '*'
    note: There are no wildcards."
bad_rules "a rule for an address instead of a name" "destinations:
  - host: 127.0.0.1
    note: Only names can be listed."
bad_rules "a rule without a note" "destinations:
  - host: unopened.example"

if port_open "$broker_port"; then fail "nothing listens after these failed starts"; else pass "nothing listens after these failed starts"; fi

start_plain "$work/plain.log" "$work/plain-rules.yaml"
plain_started=no
for _ in $(seq 300); do
  kill -0 "$broker_pid" 2>/dev/null || break
  if port_open "$broker_port"; then
    plain_started=yes
    break
  fi
  sleep 0.1
done
if [ "$plain_started" = no ]; then
  fail "a broker with the plain rules starts"
  cat "$work/plain.log"
fi

# plainly <curl arguments...>: a request through this broker. The stand-in's
# certificate is for another name than the one used here, so curl is told
# not to check it (-k); the checks below look at whose certificate it is.
plainly() { curl -sk --max-time 30 --proxy "http://127.0.0.1:$broker_port" "$@"; }
# plain_logged <pattern>: whether this broker's log has a matching line,
# waiting briefly for it.
plain_logged() {
  for _ in $(seq 30); do
    grep -Eq "$1" "$work/plain.log" && return 0
    sleep 0.1
  done
  return 1
}

echo "What the rules do not list (each is refused before anything is sent):"

before=$(count)
[ "$(plainly -o /dev/null -w '%{http_connect}' "https://unlisted.example/a")" = 403 ] &&
  pass "a tunnel to a host that is not listed is refused" ||
  fail "a tunnel to a host that is not listed is refused"

# The first line of the broker's answer is all most programs show of it.
plainly -v "https://unlisted.example/a" 2>&1 | grep -q "^< HTTP/1.1 403 Refused by the sandbox broker" &&
  pass "the refusal says who refused it" || fail "the refusal says who refused it"

# Plain HTTP reaches the broker as a request it can answer in full.
answer=$(plainly -w '%{http_code}' "http://unlisted.example/a")
case "$answer" in
  *"unlisted.example is not an allowed destination"*"broker/rules.yaml"*403)
    pass "plain HTTP to a host that is not listed is refused, and the answer says what to change"
    ;;
  *) fail "plain HTTP to a host that is not listed is refused, and the answer says what to change" ;;
esac

[ "$(plainly -o /dev/null -w '%{http_connect}' "https://unopened.example:8443/a")" = 403 ] &&
  pass "a tunnel to a listed host on another port is refused" ||
  fail "a tunnel to a listed host on another port is refused"

plainly "http://unopened.example:8443/a" |
  grep -q "is an allowed destination, but not on port 8443. Allowed on this host: port 443." &&
  pass "the answer names the port that is allowed" || fail "the answer names the port that is allowed"

# The encrypted connection names another site than the tunnel was opened for.
if plainly --connect-to "other.example:443:unopened.example:443" "https://other.example/a" >/dev/null 2>&1; then
  fail "a tunnel cannot be used under another name"
else
  pass "a tunnel cannot be used under another name"
fi

[ "$(count)" = "$before" ] && pass "none of it reached the stand-in" || fail "none of it reached the stand-in"

plain_logged " refused unlisted.example 443 connect host-not-listed\$" &&
  plain_logged " refused unlisted.example 80 http host-not-listed\$" &&
  plain_logged " refused unopened.example 8443 connect port-not-listed\$" &&
  plain_logged " refused unopened.example 443 tls tls-name-differs other.example\$" &&
  pass "each is logged as refused, with the reason" || fail "each is logged as refused, with the reason"

echo "A destination that is listed but not opened (passed on unread):"

[ "$(plainly -H "Authorization: token $placeholder" "https://unopened.example/a" | field authorization)" = "[\"token $placeholder\"]" ] &&
  pass "a request arrives as it was sent: the placeholder is not swapped" ||
  fail "a request arrives as it was sent: the placeholder is not swapped"

plainly -v "https://unopened.example/a" 2>&1 | grep -q "issuer: CN=stand-in authority" &&
  pass "the program sees the server's own certificate, not the broker's" ||
  fail "the program sees the server's own certificate, not the broker's"

plain_logged " allowed unopened.example 443 connect\$" &&
  pass "the tunnel is logged as allowed" || fail "the tunnel is logged as allowed"
if grep -q " unopened.example 443 https " "$work/plain.log"; then
  fail "nothing from inside the tunnel is logged"
else
  pass "nothing from inside the tunnel is logged"
fi
if grep -q "mitmproxy has crashed\|Traceback" "$work/plain.log"; then
  fail "this broker reported no errors of its own"
  grep -n "mitmproxy has crashed\|Traceback" -A 12 "$work/plain.log" | head -40
else
  pass "this broker reported no errors of its own"
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "All checks passed."
else
  echo "$failures check(s) failed. The broker's log:"
  tail -n 30 "$work/broker.log"
  exit 1
fi
