#!/usr/bin/env bash
# Checks the network lock from inside the VM, and how the VM uses GitHub
# through the broker without holding a token. Run it from the Mac with
# `nix run .#check`.
#
# Most checks here must FAIL to pass: the point of the lock is what the VM
# cannot do. A check that hangs counts as blocked, so each one has a time
# limit.
#
# No check needs a real GitHub token. What they cannot show without one is
# the swap itself: GitHub answers "Bad credentials" to a made-up token and to
# the placeholder alike, so from inside the VM the two look the same. That
# the broker puts the token in place of the placeholder is shown on the Mac,
# by tests/github-broker.sh, where the test can see what the broker sends
# out. tests/github-live.sh is the check that needs a real token.

set -u

failures=0

pass() { echo "  ok    $1"; }
fail() {
  echo "  FAIL  $1"
  failures=$((failures + 1))
}

# must_fail <description> <command...>: passes when the command fails.
must_fail() {
  local what=$1
  shift
  if "$@" >/dev/null 2>&1; then fail "$what"; else pass "$what"; fi
}

# must_work <description> <command...>: passes when the command succeeds.
must_work() {
  local what=$1
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}

# Prints the HTTP status a site answered with, or 000 when there was none.
status_of() { curl -s -o /dev/null --max-time 15 -w '%{http_code}' "$1"; }

# Prints the status the broker gave when asked to open a tunnel to a site.
# For HTTPS this is where a refusal shows; the site itself is never reached.
tunnel_status_of() { curl -s -o /dev/null --max-time 15 -w '%{http_connect}' "$1"; }

echo "Through the broker:"

[ "$(tunnel_status_of https://example.com)" = 403 ] &&
  pass "a destination that is not listed is refused" ||
  fail "a destination that is not listed is refused"

# The broker's status line is all most programs show of a refusal.
curl -sv --max-time 15 https://example.com 2>&1 | grep -q "Refused by the sandbox broker" &&
  pass "the refusal says who refused it" ||
  fail "the refusal says who refused it"

[ "$(status_of http://example.com)" = 403 ] &&
  pass "plain HTTP is refused" ||
  fail "plain HTTP is refused"

[ "$(tunnel_status_of https://github.com:22)" = 403 ] &&
  pass "an allowed host on another port is refused" ||
  fail "an allowed host on another port is refused"

# A tunnel to an allowed host, but the encrypted connection inside names a
# different site. Certificate checking is off, so that only the broker can be
# what stops it. Without the broker's check this would get an answer.
must_fail "a tunnel cannot be used for a different site" \
  curl -sk --max-time 15 --connect-to example.com:443:github.com:443 https://example.com

# The same again, timed. When the broker refuses a connection it closes it,
# and the VM has to notice: a program should fail at once, not wait until
# its own time limit runs out. Status 28 is curl giving up after 15 seconds.
curl -sk --max-time 15 --connect-to example.com:443:github.com:443 https://example.com >/dev/null 2>&1
[ $? -ne 28 ] &&
  pass "a refused connection is closed at once, as seen from the VM" ||
  fail "a refused connection is closed at once, as seen from the VM"

# The broker runs on the Mac, so "localhost" and 127.0.0.1 mean the Mac to
# it. A tunnel to either would reach the Mac's own services, the broker's
# port among them. --noproxy '' is needed because the VM is told not to use
# the broker for such names, which would make this ask the VM itself.
[ "$(curl --noproxy '' -s -o /dev/null --max-time 15 -w '%{http_connect}' https://127.0.0.1:8474)" = 403 ] &&
  pass "a tunnel to the Mac's own address is refused" ||
  fail "a tunnel to the Mac's own address is refused"

[ "$(curl --noproxy '' -s -o /dev/null --max-time 15 -w '%{http_connect}' https://localhost:22)" = 403 ] &&
  pass "a tunnel to the Mac by the name localhost is refused" ||
  fail "a tunnel to the Mac by the name localhost is refused"

# The broker goes by where a request is sent, not by the host it names.
[ "$(curl -s -o /dev/null --max-time 15 -w '%{http_code}' -H 'Host: github.com' http://example.com/)" = 403 ] &&
  pass "plain HTTP to an unlisted host is refused, also when it names a listed one" ||
  fail "plain HTTP to an unlisted host is refused, also when it names a listed one"

# A request whose first line never ends. The broker has to read a request's
# first lines before it can judge it, so it must stop taking them in at some
# point, or a program in the VM could fill the Mac's memory. This sends 2 MB
# and passes when the broker hangs up; it fails when the broker takes it all
# and waits for more.
endless_request() {
  timeout 30 bash -c '
    address=${HTTP_PROXY#http://}
    exec 3<>"/dev/tcp/${address%:*}/${address##*:}" || exit 3
    printf "GET http://example.com/" >&3
    # A failure to send means the other side has closed.
    head -c 2000000 /dev/zero | tr "\0" a >&3 2>/dev/null || exit 0
    # All of it was sent. An end of the connection shows as a failed read
    # at once; a read that waits out its 10 seconds has status above 128.
    read -r -t 10 -n 1 _ <&3
    [ $? -le 128 ]
  '
}
must_work "a request that never ends is cut off by the broker" endless_request

must_work "GitHub's API answers" \
  curl -sf --max-time 15 https://api.github.com/zen

must_work "git can read a public repo" \
  timeout 30 git ls-remote https://github.com/octocat/Hello-World HEAD

# Any answer from Anthropic will do; without a key it is an error status.
case "$(status_of https://api.anthropic.com/v1/models)" in
  000 | 403) fail "Anthropic's API answers" ;;
  *) pass "Anthropic's API answers" ;;
esac

echo "GitHub, which the broker opens to put the token in:"

# What programs in the VM use in place of a token. Keep it equal to
# PLACEHOLDER in broker/swap.py.
placeholder="nixt3-placeholder-not-a-real-token"

# Prints who signed the certificate the VM is shown for a host. curl checks
# the certificate as usual, so an answer also means the VM trusts the signer.
issuer_of() {
  curl -sv -o /dev/null --max-time 15 "https://$1/" 2>&1 | grep -i '^\* *issuer:' | head -n 1
}

for host in github.com api.github.com; do
  case "$(issuer_of "$host")" in
    *mitmproxy*) pass "$host is opened: its certificate is the broker's, and curl trusts it" ;;
    *) fail "$host is opened: its certificate is the broker's, and curl trusts it" ;;
  esac
done

# Claude's traffic must stay unread: the certificate is Anthropic's own.
case "$(issuer_of api.anthropic.com)" in
  "" | *mitmproxy*) fail "Anthropic is passed on untouched: its certificate is its own" ;;
  *) pass "Anthropic is passed on untouched: its certificate is its own" ;;
esac

# Node brings its own list of certificate authorities, so it is checked
# apart from curl. This opens a tunnel and lets Node check the certificate.
must_work "Node trusts the broker's certificate for GitHub" timeout 20 node -e '
  const proxy = new URL(process.env.HTTPS_PROXY);
  const ask = require("http").request({
    host: proxy.hostname, port: proxy.port, method: "CONNECT", path: "api.github.com:443",
  });
  ask.on("connect", (answer, socket) => {
    const secure = require("tls").connect({ socket, servername: "api.github.com" }, () => process.exit(0));
    secure.on("error", () => process.exit(1));
  });
  ask.on("error", () => process.exit(2));
  ask.end();
'

# gh is written in Go, which reads certificates in its own way. Whatever
# GitHub answers, gh must get the answer and not complain about the
# certificate. With a made-up token on the Mac the answer is an error.
answer=$(timeout 30 gh api zen 2>&1)
if [ $? -eq 124 ] || echo "$answer" | grep -qiE "x509|certificate|tls"; then
  fail "gh gets an answer from GitHub and trusts the broker's certificate"
else
  pass "gh gets an answer from GitHub and trusts the broker's certificate"
fi

[ "${GH_TOKEN:-}" = "$placeholder" ] &&
  pass "gh's token in the VM is the placeholder" ||
  fail "gh's token in the VM is the placeholder"

printf 'protocol=https\nhost=github.com\n\n' | timeout 10 git credential fill 2>/dev/null | grep -qx "password=$placeholder" &&
  pass "git's password for GitHub in the VM is the placeholder" ||
  fail "git's password for GitHub in the VM is the placeholder"

# The T3 server starts the agents, so they get its environment.
t3_pid=$(systemctl show --property MainPID --value t3)
tr '\0' '\n' <"/proc/$t3_pid/environ" 2>/dev/null | grep -qx "GH_TOKEN=$placeholder" &&
  pass "the T3 server, and so each agent, has the placeholder too" ||
  fail "the T3 server, and so each agent, has the placeholder too"

curl -s --max-time 15 https://api.github.com/user | grep -q "Requires authentication" &&
  pass "without a login, GitHub asks for one" ||
  fail "without a login, GitHub asks for one"

# A request with the placeholder. If GitHub answers with an account, the
# broker has put a valid token in its place: the swap works end to end.
#
# If GitHub answers "Bad credentials", this check shows less: only that the
# request went out with some login and that the answer came back whole.
# GitHub says the same to the placeholder itself, so it does not show that
# the broker swapped anything. That is the case while the token on the Mac
# is a made-up one; tests/github-broker.sh on the Mac shows the swap then.
#
# GitHub ends that answer by closing the connection instead of stating its
# length. The broker has to mark the end for the VM, or curl gives up after
# its time limit, which counts as a failure here.
answer=$(curl -s --max-time 15 -H "Authorization: token $placeholder" https://api.github.com/user) ||
  answer="curl did not get a whole answer"
case "$answer" in
  *'"login"'*) pass "with the placeholder, GitHub answers as the token's account: the swap works" ;;
  *"Bad credentials"*)
    pass "with the placeholder, GitHub's answer arrives whole"
    echo "  note  GitHub does not accept the token on the Mac (a made-up one?), so this"
    echo "        does not show the swap. tests/github-broker.sh on the Mac does."
    ;;
  *) fail "with the placeholder, GitHub's answer arrives whole" ;;
esac

curl -s --max-time 15 -H "Authorization: token some-other-token" https://api.github.com/zen |
  grep -q "Refused by the sandbox broker" &&
  pass "a request with any other token is refused by the broker" ||
  fail "a request with any other token is refused by the broker"

curl -s --max-time 15 -H "Host: gist.github.com" https://github.com/ | grep -q "names another site" &&
  pass "a request that names another site than its connection is refused" ||
  fail "a request that names another site than its connection is refused"

# A tunnel is for an encrypted connection. Clear text sent through one must
# not be passed on, least of all with a token. --proxytunnel makes curl open
# a tunnel for an http:// address. The first host is opened by the broker,
# the second is passed on untouched.
for host in github.com api.anthropic.com; do
  curl -s --max-time 15 --proxytunnel -H "Authorization: token $placeholder" "http://$host:443/" |
    grep -q "was not encrypted" &&
    pass "clear text inside a tunnel to $host is refused" ||
    fail "clear text inside a tunnel to $host is refused"
done

must_work "git uses HTTPS for a git@github.com: address" \
  timeout 30 git ls-remote git@github.com:octocat/Hello-World.git HEAD

must_work "git uses HTTPS for an ssh://git@github.com/ address" \
  timeout 30 git ls-remote ssh://git@github.com/octocat/Hello-World.git HEAD

# About 10 MB, far more than the broker reads into memory at once.
scratch=$(mktemp -d)
must_work "a large download gets through: a shallow clone of git itself" \
  timeout 180 git clone --quiet --depth 1 --no-checkout https://github.com/git/git "$scratch/git"
rm -rf "$scratch"

echo "Around the broker:"

must_fail "a direct connection by name is blocked" \
  curl -s --noproxy '*' --max-time 6 https://example.com

must_fail "a direct connection by address is blocked" \
  curl -s --noproxy '*' --max-time 6 https://1.1.1.1

must_fail "names cannot be looked up" \
  timeout 6 getent hosts example.com

# The VM is given no name server, so the check above would pass even without
# the lock. These two ask QEMU's built-in name server and a public one
# directly, with a hand-made question for "example.com".
dns_answers() {
  timeout 5 bash -c '
    exec 3<>"/dev/udp/$1/53" || exit 1
    printf "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01" >&3
    read -r -t 3 -n 1 -u 3
  ' _ "$1"
}
must_fail "QEMU's own name server does not answer" dns_answers 10.0.2.3
must_fail "a public name server is out of reach" dns_answers 1.1.1.1

must_fail "QEMU's own name server refuses connections" \
  timeout 6 bash -c 'exec 3<>/dev/tcp/10.0.2.3/53'

must_fail "a direct connection over IPv6 is blocked" \
  curl -s -6 --noproxy '*' --max-time 6 'https://[2606:4700:4700::1111]'

# 10.0.2.2 is the Mac as seen from the VM. The broker listens on the Mac, so
# something always answers on this port there; the VM must still not get to
# it this way, only through the forward.
must_fail "the Mac itself is out of reach" \
  curl -s --noproxy '*' --max-time 6 http://10.0.2.2:8474

# An address is used because the VM cannot look up names. It is one of
# GitHub's; any address would do, since nothing may leave on port 22.
must_fail "SSH to GitHub is blocked" \
  timeout 6 bash -c 'exec 3<>/dev/tcp/140.82.121.4/22'

echo "Inside the VM:"

must_fail "the agent user has no sudo" \
  sudo -n true

# The mount table would list a shared folder as type 9p or virtiofs.
must_fail "no folder is shared with the Mac" \
  grep -Eq ' (9p|virtiofs) ' /proc/mounts

# A real GitHub token starts with one of these. The placeholder does not.
token_shape='(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})'

if cat /proc/[0-9]*/environ 2>/dev/null | tr '\0' '\n' | grep -Eq "$token_shape"; then
  fail "no program in the VM has something that looks like a GitHub token in its environment"
else
  pass "no program in the VM has something that looks like a GitHub token in its environment"
fi

# Everything the agent user can read where a token could have been left:
# its home folder with git's and gh's settings and every clone, and the
# system's settings and scratch folders. Program files are skipped.
found=$(timeout 300 grep -rIlsE "$token_shape" /home/agent /etc /run /tmp /var/tmp 2>/dev/null)
search_status=$?
if [ "$search_status" -eq 124 ]; then
  fail "no file in the VM holds something that looks like a GitHub token (the search took too long)"
elif [ -n "$found" ]; then
  fail "no file in the VM holds something that looks like a GitHub token"
  echo "$found" | head -n 5 | sed 's/^/          /'
else
  pass "no file in the VM holds something that looks like a GitHub token"
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "All checks passed."
else
  echo "$failures check(s) failed."
  exit 1
fi
