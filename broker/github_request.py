"""What the broker does with one request to GitHub.

Two other files each know half of this. github_policy.py decides whether a
request may go out, and whether with the token. swap.py knows how the token
is put in place of the placeholder. This file joins the two for proxy.py, in
plain functions that know nothing of mitmproxy, so that the joining can be
tested by itself (tests/unit/test_github_request.py).

The order matters and is the same for every request:

1. The login the request carries is looked at. A request may carry the
   placeholder or no login. Any other login is refused here, before the
   policy is asked.
2. The policy decides (`github_policy.decide`). It is given the request as it
   arrived: the same method, path, query string, headers and body that
   GitHub will get. If the two could read a request differently, a request
   could be judged as one thing and served as another.
3. Only then is the token put in. Where the policy says "allowed, but
   without the token", the request goes out with no login at all.
"""

import json
from collections.abc import Iterable
from dataclasses import dataclass

import github_policy
import swap

# The hosts the broker can open: the ones the policy has rules for. For any
# other host the policy refuses every request, so opening one would only
# break it.
HOSTS = (github_policy.GIT_HOST, github_policy.API_HOST)


def load_policy(data: dict, opened: Iterable[str]) -> github_policy.Policy | None:
    """Read the `github` part of rules.yaml, and check that it is there.

    `data` is the whole of rules.yaml as the YAML reader returned it, and
    `opened` holds the hosts that the file marks `inspect: true`.

    The broker adds the token to what it lets through to an opened host. So
    an opened host without rules for what may go there must never happen:
    the file is then refused, and the broker does not start. Returns None
    when no host is opened and there is no `github` part, which is a broker
    that only passes traffic on. Any mistake raises github_policy.PolicyError
    with a message that says what to fix.
    """
    opened = sorted(opened)
    for host in opened:
        if host not in HOSTS:
            raise github_policy.PolicyError(
                f"{host} has `inspect: true`, but the broker can open only "
                f"{' and '.join(HOSTS)}. Those are the hosts it has rules "
                "for; with the token it adds, anything else would be let "
                "through unchecked"
            )
    if "github" not in data:
        if opened:
            raise github_policy.PolicyError(
                f"{opened[0]} has `inspect: true`, but the file has no "
                "`github:` part. That part lists the repos the agent may "
                "use, and without it the broker would add the token to any "
                "request. Add it; docs/github-rules.md shows how"
            )
        return None
    return github_policy.load_policy(data["github"])


def refusal_answer(host: str, target: str, text: str) -> tuple[int, bytes, str]:
    """How a refused request is answered: the status, the body, its type.

    The text is for the agent in the VM: it says what was refused and, for
    several refusals, which command to use instead. So it has to be shown,
    and each program shows only what it expects. There are three cases, each
    tried with the real program:

    - **git** shows the body of a 403 as it is, line by line. So for
      github.com the answer is a 403 with the text.
    - **gh, for the REST API,** expects what the API sends for an error: a
      403 with JSON that has a `message`, and shows that message. Given
      plain text it shows only the status line.
    - **gh, for GraphQL,** is two programs in one. Its reading commands show
      the `message` of a 403 like the above. The commands that change
      something (`gh pr close` and the like) do not: they print the whole
      body of a 403 as one line with every quote and line break escaped.
      Both show cleanly what GraphQL itself sends when it refuses: the
      status 200, and a body with `errors` in place of data. So a refused
      GraphQL request is answered that way. It is still a refusal: nothing
      was sent to GitHub, and no program reads such a body as a success.
    """
    if host.lower() != github_policy.API_HOST:
        return 403, text.encode("utf-8"), "text/plain; charset=utf-8"
    if target.partition("?")[0] == "/graphql":
        body = {"data": None, "errors": [{"type": "FORBIDDEN", "message": text}]}
        return 200, json.dumps(body).encode("ascii"), "application/json; charset=utf-8"
    return 403, json.dumps({"message": text}).encode("ascii"), "application/json; charset=utf-8"


# Added to the refusal of a GraphQL query that asks for something not on the
# policy's list. Some `gh` commands that change something first read more
# than the list allows (`gh pr edit` reads who can be assigned), and are
# refused at that read, before their change is ever sent. The policy's text
# for that refusal is about reading. This says what to do when the aim was
# to change something. It is added here and not in github_policy.py, so that
# the policy stays as it was reviewed; what is allowed does not change.
CHANGE_INSTEAD = """
If this came from a `gh` command that changes a pull request or an issue,
such as `gh pr edit`: the command reads more than is allowed before it
changes anything. Make the change with `gh api`, which is allowed in a repo
listed with `access: write`:

    gh api -X PATCH repos/OWNER/REPO/pulls/NUMBER -f title='TITLE' -f body='TEXT'
    gh api repos/OWNER/REPO/issues/NUMBER/comments -f body='TEXT'
    gh api repos/OWNER/REPO/issues/NUMBER/labels -f 'labels[]=LABEL'
    gh api -X PATCH repos/OWNER/REPO/pulls/NUMBER -f state=closed

Put your own values where the words are in capitals.
"""


def when_to_decide(host: str, body_is_small: bool) -> str:
    """At which point a request to an opened host is decided on.

    "now"         as soon as its first lines have arrived. The body is not
                  needed for the decision and is passed on as it comes. This
                  is git: a push can be very large.
    "after-body"  when the whole body has been read, because the decision
                  depends on it. This is the API, where the body says what a
                  request changes.
    "refuse"      never: the decision needs the body, and the body is too
                  large to read or does not say how long it is. Letting it
                  through unread would be a way around every rule about
                  bodies, so it is refused.

    `body_is_small` is what swap.reads_body() said about the request.
    """
    if not github_policy.wants_body(host):
        return "now"
    return "after-body" if body_is_small else "refuse"


@dataclass(frozen=True)
class Plan:
    """What to do with one request.

    allowed        True: pass it on. False: refuse it.
    reason         For a refusal, a short fixed word for the log.
    message        For a refusal by the policy, the text for the agent in
                   the VM. None for a refusal about the login, for which
                   proxy.py has its own texts.
    kind           What the request is, for the log: `git-read`, `api-write`
                   and so on.
    authorization  The Authorization header to send. None: send none, and
                   remove the one that came.
    with_token     Whether the policy allows the token on this request.
                   False for a read of a repo that is not listed.
    body           When not None, send these bytes as the body instead of
                   the ones received (see github_policy._fresh for why).
    """

    allowed: bool
    reason: str = ""
    message: str | None = None
    kind: str = ""
    authorization: str | None = None
    with_token: bool = False
    body: bytes | None = None


def plan(
    policy: github_policy.Policy | None,
    token: swap.Secret | None,
    *,
    method: str,
    host: str,
    target: str,
    headers: list[tuple[str, str]],
    authority: str | None,
    body: bytes | None,
) -> Plan:
    """Decide about one request to an opened host, and what to send for it.

    policy     From load_policy() above.
    token      The real token for this host, or None when it has none.
    method     As sent, in the letters it was sent in.
    host       The host the tunnel was opened for, in lower case.
    target     What followed the method in the request's first line: the
               path, and the query string if there is one, exactly as sent.
    headers    Every header as a (name, value) pair, in order, with a header
               that was sent twice appearing twice.
    authority  The host the request itself names, from its Host header.
    body       The whole body as sent, or None when it was not read.

    "As sent" is meant strictly: proxy.py hands over the bytes that arrived
    and that will be sent on, each byte read as one character, and not the
    tidied form that mitmproxy offers for convenience (its `method` is in
    upper case whatever was sent). The policy accepts plain ASCII only, so a
    request it allows is one whose text and bytes are the same thing.

    The token is in the result only when the request carried the
    placeholder and the policy allows the token. A request without a login
    stays without one: it is the program in the VM that chooses to log in.
    """
    if policy is None:
        # Cannot happen with rules that load_policy() accepted. Refusing is
        # the safe answer if it ever does.
        return Plan(False, reason="no-policy")

    logins = [value for name, value in headers if name.strip().lower() == "authorization"]
    credential = swap.swap_authorization(logins, token)
    if credential.action == "refuse":
        return Plan(False, reason=credential.reason or "other-login")

    # Split at the first "?" and nowhere else, as a server does. A "#" is
    # left in: the policy refuses it, because it has no place in a request.
    path, _, query = target.partition("?")
    decision = github_policy.decide(
        method, host, path, query, body, policy, headers=headers, authority=authority
    )
    if not decision.allowed:
        message = decision.message
        if decision.reason == "graphql-not-on-list":
            message += CHANGE_INSTEAD
        return Plan(False, reason=decision.reason or "policy", message=message)

    authorization = None
    if decision.with_token and credential.action == "swap":
        authorization = credential.value
    return Plan(
        True,
        kind=decision.kind,
        authorization=authorization,
        with_token=decision.with_token,
        body=decision.body,
    )
