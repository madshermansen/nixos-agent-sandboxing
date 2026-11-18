#!/usr/bin/env bash
# The final check of phase 4: the agent's whole GitHub round trip, from inside
# the VM, with the real token on the Mac and none in the VM.
#
# It clones a repo over HTTPS, pushes a branch, opens a pull request with gh,
# comments on it, then closes the pull request and deletes the branch again.
# Every step goes through the broker, which puts the real token in place of
# the placeholder, and lets through only what the `github` rules allow. So
# the steps are the ones those rules allow: `gh pr create` works, while
# commenting and closing go through `gh api`, because `gh pr comment` and
# `gh pr close` are refused (docs/github-rules.md says why). The script also
# checks that two things are refused that should be.
#
# This one needs a real token: set up ~/.config/nixt3/tokens.yaml on the Mac
# first (see docs/setup.md), and restart the VM. Then, from the repo on the
# Mac:
#
#   nix run .#ssh -- bash -s < tests/github-live.sh
#
# To use another repo than this project's own, name it:
#
#   nix run .#ssh -- bash -s -- owner/name < tests/github-live.sh
#
# The repo must be listed in broker/rules.yaml with `access: write` and its
# `id`, and the token must be allowed to push to it and to open pull requests
# in it. It leaves nothing behind when it passes. If it stops half way, it says
# what is left to remove by hand.

set -u

repo=${1:-madshermansen/nixt3}
branch="sandbox-check-$(date +%Y%m%d-%H%M%S)-$$"
placeholder="nixt3-placeholder-not-a-real-token"

work=$(mktemp -d)
pushed=no
pr=""

step() { echo "  ...   $1"; }
pass() { echo "  ok    $1"; }
stop() {
  echo "  FAIL  $1"
  [ -n "$pr" ] && echo "        Left behind: pull request $pr. Close it by hand."
  [ "$pushed" = yes ] && echo "        Left behind: the branch $branch in $repo. Delete it by hand."
  rm -rf "$work"
  exit 1
}

echo "GitHub from inside the VM, as $repo:"

[ "${GH_TOKEN:-}" = "$placeholder" ] || stop "GH_TOKEN in the VM is not the placeholder"
pass "the VM holds the placeholder, not a token"

# Who the token on the Mac belongs to, as GitHub sees it.
login=$(gh api user --jq .login 2>"$work/error") ||
  stop "GitHub does not accept the token the broker adds: $(head -n 1 "$work/error")"
pass "the broker's token is accepted; GitHub knows it as $login"

step "cloning https://github.com/$repo"
timeout 300 git clone --quiet "https://github.com/$repo" "$work/clone" 2>"$work/error" ||
  stop "the clone failed: $(tail -n 1 "$work/error")"
cd "$work/clone" || stop "the clone is not there"
pass "cloned over HTTPS"

base=$(git symbolic-ref --short HEAD)
git checkout --quiet -b "$branch"
date >"sandbox-check-$$.txt"
git add "sandbox-check-$$.txt"
git -c user.name="nixt3 check" -c user.email="nixt3-check@users.noreply.github.com" \
  commit --quiet -m "test: ✅ a commit made by tests/github-live.sh" ||
  stop "the commit failed"

step "pushing the branch $branch"
timeout 300 git push --quiet origin "$branch" 2>"$work/error" ||
  stop "the push failed: $(tail -n 1 "$work/error")"
pushed=yes
pass "pushed a branch"

step "opening a pull request"
pr=$(timeout 120 gh pr create --repo "$repo" --base "$base" --head "$branch" \
  --title "test: ✅ check that the sandbox can open a pull request" \
  --body "Opened by tests/github-live.sh from inside the agent VM. It closes this again by itself." \
  2>"$work/error") || {
  pr=""
  stop "opening the pull request failed: $(tail -n 1 "$work/error")"
}
pass "opened $pr"

number=${pr##*/}

# `gh pr close` names the pull request by an id, which the broker cannot tie
# to a repo. It must be refused, and the refusal must name the way on.
if timeout 120 gh pr close "$pr" >"$work/refusal" 2>&1; then
  pr=""
  stop "\`gh pr close\` went through. The broker should have refused it"
fi
if grep -q "gh api" "$work/refusal"; then
  pass "\`gh pr close\` is refused, and the refusal names the gh api line to use"
elif grep -q "Refused by the sandbox broker" "$work/refusal"; then
  pass "\`gh pr close\` is refused by the broker"
  echo "  note  gh did not show the whole refusal, so the agent would not see the way on."
else
  stop "\`gh pr close\` failed, but not with the broker's refusal: $(tail -n 1 "$work/refusal")"
fi

timeout 120 gh api "repos/$repo/issues/$number/comments" -f body="A comment from tests/github-live.sh." \
  >/dev/null 2>"$work/error" ||
  stop "commenting on the pull request failed: $(tail -n 1 "$work/error")"
pass "commented on the pull request with gh api"

timeout 120 gh api -X PATCH "repos/$repo/pulls/$number" -f state=closed >/dev/null 2>"$work/error" ||
  stop "closing the pull request failed: $(tail -n 1 "$work/error")"
pr=""
pass "closed the pull request with gh api"

timeout 120 git push --quiet origin --delete "$branch" 2>"$work/error" ||
  stop "deleting the branch failed: $(tail -n 1 "$work/error")"
pushed=no
pass "deleted the branch"

# A repo that is not listed must be out of reach, token or not.
if timeout 60 git ls-remote https://github.com/octocat/Hello-World HEAD >"$work/refusal" 2>&1; then
  stop "a repo that is not in the rules could be read"
fi
grep -q "is not a repo the sandbox may use" "$work/refusal" ||
  stop "a repo that is not in the rules failed, but not with the broker's refusal"
pass "a repo that is not in the rules is refused"

# The clone's settings are where a token would end up if git had been given
# one, for example in the address of the remote.
if grep -rIqE '(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})' .git/config "$HOME/.gitconfig" "$HOME/.config/gh" 2>/dev/null; then
  stop "something that looks like a token is in git's or gh's settings"
fi
pass "no token ended up in git's or gh's settings"

cd /
rm -rf "$work"
echo
echo "All steps passed."
