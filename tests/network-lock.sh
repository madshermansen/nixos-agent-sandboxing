#!/usr/bin/env bash
# Checks the network lock from inside the VM. Run it from the Mac with
# `nix run .#check`.
#
# Most checks here must FAIL to pass: the point of the lock is what the VM
# cannot do. A check that hangs counts as blocked, so each one has a time
# limit.

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

must_work "GitHub's API answers" \
  curl -sf --max-time 15 https://api.github.com/zen

must_work "git can read a public repo" \
  timeout 30 git ls-remote https://github.com/octocat/Hello-World HEAD

# Any answer from Anthropic will do; without a key it is an error status.
case "$(status_of https://api.anthropic.com/v1/models)" in
  000 | 403) fail "Anthropic's API answers" ;;
  *) pass "Anthropic's API answers" ;;
esac

echo "Around the broker:"

must_fail "a direct connection by name is blocked" \
  curl -s --noproxy '*' --max-time 6 https://example.com

must_fail "a direct connection by address is blocked" \
  curl -s --noproxy '*' --max-time 6 https://1.1.1.1

must_fail "names cannot be looked up" \
  timeout 6 getent hosts example.com

must_fail "the Mac itself is out of reach" \
  curl -s --noproxy '*' --max-time 6 http://10.0.2.2:3773

must_fail "SSH to GitHub is blocked" \
  timeout 6 bash -c 'exec 3<>/dev/tcp/140.82.121.4/22'

echo "Inside the VM:"

must_fail "the agent user has no sudo" \
  sudo -n true

# The mount table would list a shared folder as type 9p or virtiofs.
must_fail "no folder is shared with the Mac" \
  grep -Eq ' (9p|virtiofs) ' /proc/mounts

echo
if [ "$failures" -eq 0 ]; then
  echo "All checks passed."
else
  echo "$failures check(s) failed."
  exit 1
fi
