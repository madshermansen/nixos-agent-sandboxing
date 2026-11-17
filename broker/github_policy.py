"""Which GitHub requests the broker lets through.

The agent VM holds no GitHub token. The broker on the Mac adds the token to
requests on their way out, so every request that reaches GitHub with the
token is something the broker chose to let through. This module makes that
choice. It is given one request and answers "allowed" or "refused, and here
is why".

The worry is an agent that has been tricked by something it read. It may try
to use the token to do damage (delete a repo, change who has access, read a
secret) or to move data out (push to someone else's repo, post it in a gist
or a comment elsewhere). GitHub limits the token too, but the broker is the
first check and does not count on the second.

How it decides:

- **Default deny.** A request is allowed only when this module recognises it
  as one of the kinds listed in docs/github-rules.md. Everything else is
  refused, including requests that are harmless but unknown.
- **Repos are listed.** The rules name the repos the agent may use, each as
  `read` or `write`. A request to any other repo is refused, unless the rules
  allow reading other repos, and then it goes out without the token, so only
  public repos can be read that way.
- **Some things are refused on every repo,** listed or not: settings,
  deletion, secrets, deploy keys, webhooks, collaborators, branch protection,
  releases, forks, and so on.
- **Odd spellings are refused, not tidied up.** A path with `..`, a doubled
  slash or an encoded keyword is never rewritten into its plain form and
  passed on. If the broker and GitHub could read a request differently, the
  broker refuses it.

This module is pure: it imports nothing from mitmproxy, opens no files and
makes no connections. That keeps it small enough to test fully; the tests
are in tests/unit/test_github_policy.py. proxy.py calls three things here:
`load_policy` once at start, and `wants_body` and `decide` for each request.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from urllib.parse import unquote_to_bytes

__all__ = [
    "Decision",
    "MAX_BODY",
    "Policy",
    "PolicyError",
    "Repo",
    "decide",
    "load_policy",
    "wants_body",
]

# The two hosts this module knows. Git uses the first, the API the second.
# Any other host is refused: see `_refuse_host` for the ones people ask about.
GIT_HOST = "github.com"
API_HOST = "api.github.com"

# The largest API request body that is read. Real ones are a few kilobytes;
# the largest is a pull request text, which GitHub caps at 65536 characters.
MAX_BODY = 1024 * 1024

# Limits that keep a hostile request from keeping the broker busy. The
# GraphQL ones are about ten times what gh sends: its longest query is 3300
# characters long and uses two fragments.
MAX_PATH = 4096
MAX_QUERY = 8192
MAX_GRAPHQL = 32 * 1024
MAX_DEPTH = 50
MAX_TOKENS = 20_000
MAX_ROOT_FIELDS = 100
MAX_OPERATIONS = 8
MAX_FRAGMENTS = 20
# How many fields, fragments and the like are looked at while checking one
# GraphQL request, counting each again every time a fragment is used.
MAX_STEPS = 50_000

METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})
READ_METHODS = frozenset({"GET", "HEAD"})


# ---------------------------------------------------------------------------
# The rules
# ---------------------------------------------------------------------------


class PolicyError(Exception):
    """The `github` part of rules.yaml cannot be used. The message says what
    to fix."""


@dataclass(frozen=True)
class Repo:
    """One listed repo."""

    owner: str
    name: str
    write: bool
    # May pull requests be merged from the sandbox? Only with `write`.
    merge: bool = False
    # GitHub's number for the repo, taken from the `id` in the rules. GraphQL
    # names the repo by its id when a pull request is opened, and this number
    # is how that id is tied back to a listed repo. None when the rules give
    # no `id`.
    number: int | None = None

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


@dataclass(frozen=True)
class Policy:
    """The loaded rules. Make one with `load_policy`."""

    # Keyed by "owner/name" in lower case, because GitHub ignores case there.
    repos: Mapping[str, Repo]
    # True when repos that are not listed may be read without the token.
    read_public: bool = False

    def find(self, owner: str, name: str) -> Repo | None:
        return self.repos.get(f"{owner}/{name}".lower())

    def find_number(self, number: int) -> Repo | None:
        for repo in self.repos.values():
            if repo.number == number:
                return repo
        return None


REPO_KEYS = {"repo", "note", "access", "id", "merge"}
POLICY_KEYS = {"repos", "other_repos"}
OTHER_REPOS = {"refuse": False, "read-public": True}

# GitHub's own limits on names: an owner is letters, digits and single
# hyphens, at most 39 long; a repo name is letters, digits, dot, hyphen and
# underscore, at most 100 long.
OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}")
REPO_NAME = re.compile(r"[A-Za-z0-9._-]{1,100}")


def load_policy(data: object) -> Policy:
    """Check the `github` part of rules.yaml and return it as a Policy.

    `data` is that part as the YAML reader returned it. Nothing is read from
    disk here. Any mistake raises PolicyError; as with the rest of
    rules.yaml, an unknown key is a mistake, so that a typing error cannot
    quietly change what a rule means.

    The format, with every key shown:

        github:
          repos:
            - repo: some-owner/some-repo
              note: Why the agent needs this repo.
              access: write          # or: read
              id: R_kgDOExample      # optional; `gh pr create` needs it
              merge: false           # optional; only with access: write
          other_repos: refuse        # optional; or: read-public
    """
    if not isinstance(data, dict):
        raise PolicyError("`github` must have a `repos:` list")
    unknown = set(data) - POLICY_KEYS
    if unknown:
        raise PolicyError(
            f"`github` has an unknown key `{sorted(map(str, unknown))[0]}`. "
            f"Known keys: {', '.join(sorted(POLICY_KEYS))}"
        )

    entries = data.get("repos")
    if not isinstance(entries, list):
        raise PolicyError("`github: repos` must be a list")

    other = data.get("other_repos", "refuse")
    if not isinstance(other, str) or other not in OTHER_REPOS:
        raise PolicyError(
            "`github: other_repos` must be `refuse` or `read-public`. It says "
            "what happens to repos that are not listed"
        )

    repos: dict[str, Repo] = {}
    numbers: dict[int, str] = {}
    for position, entry in enumerate(entries, start=1):
        where = f"github repo {position}"
        if not isinstance(entry, dict):
            raise PolicyError(f"{where} must have a `repo`, a `note` and an `access`")

        full_name = entry.get("repo")
        if not isinstance(full_name, str) or not full_name:
            raise PolicyError(f"{where} has no `repo`. Write it as owner/name")
        where = f"{where} ({full_name})"

        unknown = set(entry) - REPO_KEYS
        if unknown:
            raise PolicyError(
                f"{where} has an unknown key `{sorted(map(str, unknown))[0]}`. "
                f"Known keys: {', '.join(sorted(REPO_KEYS))}"
            )

        owner, slash, name = full_name.partition("/")
        if (
            not slash
            or not OWNER.fullmatch(owner)
            or not REPO_NAME.fullmatch(name)
            or name in (".", "..")
        ):
            raise PolicyError(
                f"{where}: `repo` must be one exact repo written as owner/name, "
                "such as octocat/hello-world, without https://, a path or a "
                "wildcard"
            )
        if name.lower().endswith(".git"):
            raise PolicyError(f"{where}: write `repo` without the `.git` ending")
        key = full_name.lower()
        if key in repos:
            raise PolicyError(f"{where} is listed twice")

        note = entry.get("note")
        if not isinstance(note, str) or not note.strip():
            raise PolicyError(
                f"{where} has no `note`. Say in a few words why the agent needs it"
            )

        access = entry.get("access")
        if not isinstance(access, str) or access not in ("read", "write"):
            raise PolicyError(
                f"{where}: `access` must be `read` or `write`. `read` allows "
                "clone and fetch and reading pull requests; `write` also "
                "allows push and working on pull requests"
            )
        write = access == "write"

        merge = entry.get("merge", False)
        # `1` and "yes" are not accepted: a switch this important is spelled
        # true or false.
        if type(merge) is not bool:
            raise PolicyError(f"{where}: `merge` must be true or false")
        if merge and not write:
            raise PolicyError(f"{where}: `merge: true` needs `access: write`")

        number = None
        if "id" in entry:
            node_id = entry["id"]
            number = _repo_number(node_id) if isinstance(node_id, str) else None
            if number is None:
                raise PolicyError(
                    f"{where}: `id` is not a repo id from GitHub. Get it with "
                    f"`gh repo view {full_name} --json id --jq .id`"
                )
            if number in numbers:
                raise PolicyError(
                    f"{where} has the same `id` as {numbers[number]}. Each repo "
                    "has its own"
                )
            numbers[number] = full_name

        repos[key] = Repo(owner, name, write, merge, number)
    return Policy(repos, OTHER_REPOS[other])


# ---------------------------------------------------------------------------
# The answer
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    """What to do with one request.

    allowed     True: send it on. False: answer with a 403 and `message`.
    kind        What the request is, for the log: `git-read`, `git-write`,
                `api-read`, `api-write`, `graphql-read` or `graphql-write`.
                Empty for a refusal.
    reason      For a refusal, a short fixed word for the log, such as
                `repo-not-listed`. It never holds anything from the request.
    message     For a refusal, the text for the agent in the VM: what was
                refused and what to ask the user for.
    with_token  True: add the GitHub token. False: send the request without
                any credentials, because it reads a repo that is not listed.
    body        When not None, send these bytes as the body instead of the
                ones received. See `_fresh` for why.
    repo        The listed repo the request is about, as written in the
                rules, or None.
    """

    allowed: bool
    kind: str = ""
    reason: str = ""
    message: str = ""
    with_token: bool = False
    body: bytes | None = None
    repo: str | None = None


class _Refusal(Exception):
    """Raised anywhere below to refuse the request being looked at."""

    def __init__(self, reason: str, what: str, ask: str, *, other_way: bool = False) -> None:
        super().__init__(reason)
        # Most refusals cannot be got around, and the agent is told not to
        # try. A few have another way that is allowed, named in `ask`.
        again = (
            "Sending this request again will\n"
            "not help. There is another way, and it is given below.\n"
            if other_way
            else "Trying again, or sending the same\n"
            "request in another way or with another tool, will not help.\n"
        )
        self.decision = Decision(
            allowed=False,
            reason=reason,
            message=(
                f"Refused by the sandbox broker: {what}\n"
                "\n"
                "This machine is a sandbox. Its requests to GitHub go through a\n"
                "broker on the host. The broker adds the GitHub token, and lets\n"
                "through only what the `github` rules in broker/rules.yaml of the\n"
                f"nixt3 repo on the host allow. {again}"
                "\n"
                f"{ask}\n"
            ),
        )


# What the agent is told to do about a refusal. Which one is used depends on
# whether the user could change the rules to allow the request.
ASK_LIST = (
    "If the task needs this repo, tell the user. They can list it under\n"
    "`github: repos:` in that file and restart the broker."
)
ASK_WRITE = (
    "If the task needs to change this repo, tell the user. They can give it\n"
    "`access: write` in that file and restart the broker."
)
ASK_MERGE = (
    "Leave the merging to the user, or tell them the task needs it. They can\n"
    "set `merge: true` on the repo in that file and restart the broker."
)
ASK_ID = (
    "The broker knows a repo's id only from the `id` in that repo's entry in\n"
    "the rules. If this is a listed repo, tell the user that its entry needs\n"
    "an `id`; the command for it is in docs/github-rules.md of the nixt3\n"
    "repo. If it is another repo, tell the user the task needs that repo\n"
    "listed."
)
WHY_NOT_BY_ID = (
    "GitHub finds a pull request, issue, comment or review by its id\n"
    "whatever repo the id claims to be in, so the broker cannot keep such a\n"
    "request to the allowed repos."
)
ASK_REST = (
    WHY_NOT_BY_ID + " The REST API does the same job with the\n"
    "repo in the address, and that is allowed in a repo listed with\n"
    "`access: write`:\n"
    "\n"
    "    {call}\n"
    "\n"
    "Put your own values where the words are in capitals.{note}"
)
ASK_NO_REST = (
    WHY_NOT_BY_ID + " GitHub has no other request for this job,\n"
    "so it cannot be done from the sandbox. Tell the user what is needed and\n"
    "let them do it."
)
ASK_READ_BY_NAME = (
    WHY_NOT_BY_ID + " Read it by repo and number instead:\n"
    "\n"
    "    gh pr view NUMBER --repo OWNER/REPO --json statusCheckRollup,reviews,comments\n"
    "    gh api repos/OWNER/REPO/pulls/NUMBER\n"
    "    gh api repos/OWNER/REPO/commits/SHA/check-runs\n"
    "\n"
    "`gh pr checks` reads by id and does not work here. The first line above\n"
    "gives the same checks."
)
ASK_NEVER = (
    "No rule allows this from the sandbox, on purpose. If the task needs it,\n"
    "tell the user what is needed and why, and let them do it themselves."
)
ASK_UNKNOWN = (
    "The broker lets through the kinds of request it knows: clone, fetch and\n"
    "push with git, and reading and working on pull requests with gh. The\n"
    "full list is in docs/github-rules.md of the nixt3 repo. If the task\n"
    "needs this request, tell the user what you were trying to do."
)
ASK_FIX = (
    "The request is written in a way the broker does not accept, whatever it\n"
    "is for. Send it the plain way git and gh do. The accepted forms are in\n"
    "docs/github-rules.md of the nixt3 repo."
)

# Things that are refused on every repo. The key is the reason in the log.
NEVER = {
    "repo-settings": (
        "changing a repo's settings is not allowed from the sandbox. That "
        "covers its name, visibility, default branch, topics, pages and the "
        "like."
    ),
    "repo-deletion": "deleting a repo is not allowed from the sandbox.",
    "repo-transfer": "moving a repo to another owner is not allowed from the sandbox.",
    "repo-creation": "creating a repo is not allowed from the sandbox.",
    "repo-by-id": (
        "repos must be named as /repos/OWNER/NAME. Naming one by its number "
        "would get around the list of allowed repos."
    ),
    "forks": "forking a repo is not allowed from the sandbox.",
    "secrets": (
        "secrets and variables are out of reach of the sandbox: those of "
        "Actions, Dependabot, Codespaces and environments, and secret "
        "scanning results. That goes for reading them too."
    ),
    "deploy-keys": "deploy keys are out of reach of the sandbox.",
    "webhooks": "webhooks are out of reach of the sandbox.",
    "collaborators": (
        "who has access to a repo is out of reach of the sandbox: "
        "collaborators, invitations, teams, and the list of who an issue "
        "can be assigned to."
    ),
    "branch-protection": (
        "branches' protection and rules are out of reach of the sandbox, and "
        "so is renaming a branch. Reading protection shows who may push."
    ),
    "releases": "creating or changing releases is not allowed from the sandbox.",
    "actions": (
        "starting, stopping or changing Actions runs and workflows is not "
        "allowed from the sandbox. Reading runs, jobs and logs is."
    ),
    "checks": (
        "setting commit statuses or checks is not allowed from the sandbox. "
        "They are how tests report on a commit; the agent may read them."
    ),
    "git-data": (
        "changing files, commits or branches through the API is not allowed "
        "from the sandbox. Use git instead: commit and push."
    ),
    "merge-api": (
        "merging branches through the API is not allowed from the sandbox. "
        "That includes bringing a pull request's branch up to date: the "
        "branch may be in another repo, which the broker cannot see. Use git "
        "instead: merge and push."
    ),
    "assignees": (
        "assigning issues and pull requests is not allowed from the sandbox. "
        "Assigning one to a coding agent starts a second agent, outside the "
        "sandbox, with a token of its own."
    ),
    "issues": (
        "creating, editing and closing issues is not allowed from the "
        "sandbox. Reading issues and commenting on them is."
    ),
    "gists": (
        "gists are not allowed from the sandbox. A gist is a place to put "
        "data outside the allowed repos."
    ),
    "account": (
        "the account behind the token is out of reach of the sandbox, apart "
        "from `GET /user`, which says who it is."
    ),
    "organizations": "organizations are out of reach of the sandbox.",
    "search": (
        "the search API is not tied to one repo, so the broker cannot keep "
        "it to the allowed ones. `gh pr list --search` and `gh issue list "
        "--search` work, because they name the repo."
    ),
    "git-lfs": (
        "Git LFS is not supported in the sandbox. It stores files on other "
        "hosts than github.com, which the broker does not pass on."
    ),
}


def _never(reason: str) -> _Refusal:
    return _Refusal(reason, NEVER[reason], ASK_NEVER)


def _unknown(what: str) -> _Refusal:
    return _Refusal("not-recognised", what, ASK_UNKNOWN)


def _fix(reason: str, what: str) -> _Refusal:
    return _Refusal(reason, what, ASK_FIX)


def _show(text: object, limit: int = 80) -> str:
    """Make part of a request safe to repeat in a message to the VM."""
    shown = re.sub(r"[^\x21-\x7e]", "?", str(text))
    return shown if len(shown) <= limit else shown[:limit] + "..."


# ---------------------------------------------------------------------------
# The entry points
# ---------------------------------------------------------------------------


def wants_body(host: str) -> bool:
    """Must the whole body be read before `decide` is called?

    True for the API, where the decision depends on the body. Read at most
    MAX_BODY bytes and refuse a longer one. False for github.com: git's
    uploads can be very large, the decision does not look at them, and they
    should be passed on as they arrive. False for every other host as well,
    because `decide` refuses those whatever they send.
    """
    return isinstance(host, str) and host.lower() == API_HOST


def decide(
    method: str,
    host: str,
    path: str,
    query: str,
    body: bytes | None,
    policy: Policy,
    *,
    headers: Mapping[str, str] | Iterable[tuple[str, str]],
    authority: str | None,
) -> Decision:
    """Decide about one request to GitHub.

    method     As sent, for example "GET". Upper and lower case differ.
    host       The host the broker will connect to: the one the tunnel was
               opened for, not anything the request says about itself.
    path       The path as sent, undecoded, without the query: "/repos/a/b".
    query      What followed the "?" as sent, undecoded, or "" for none.
    body       The body as sent, undecoded. May be None or empty for
               github.com (see `wants_body`); for the API it must be the
               whole body.
    policy     From `load_policy`.
    headers    The request's headers: a mapping, or pairs when a name occurs
               more than once.
    authority  The host the request itself names: the `Host` header, or
               `:authority` in HTTP/2. GitHub goes by this name, so it has to
               be the same as `host`.

    It never raises. Anything unexpected is a refusal, because a check that
    stops with an error must not let the request through.
    """
    try:
        return _decide(method, host, path, query, body, policy, headers, authority)
    except _Refusal as refusal:
        return refusal.decision
    except Exception:  # noqa: BLE001 - see the docstring
        return _Refusal(
            "policy-error",
            "the broker could not make sense of this request.",
            ASK_FIX,
        ).decision


def _decide(
    method: object,
    host: object,
    path: object,
    query: object,
    body: object,
    policy: Policy,
    headers: object,
    authority: object,
) -> Decision:
    if not isinstance(policy, Policy):
        raise TypeError("policy must come from load_policy")
    if not isinstance(host, str):
        raise TypeError("host must be text")
    host = host.lower()
    if host not in (GIT_HOST, API_HOST):
        raise _refuse_host(host)

    # GitHub answers for many names on the same servers, and picks by the
    # name inside the request. A request that connects to one host and names
    # another would be judged here as the first and served there as the
    # second.
    if not isinstance(authority, str) or authority.lower() not in (host, f"{host}:443"):
        raise _fix(
            "host-differs",
            f"the request was sent to {host} but names another host in its "
            "Host header.",
        )

    if method == "OPTIONS":
        raise _unknown(
            "OPTIONS requests are not passed on. Programs do not need them; "
            "browsers do."
        )
    if not isinstance(method, str) or method not in METHODS:
        raise _unknown(f"the method {_show(method, 20)} is not one the broker passes on.")

    header_values = _headers(headers)
    # GitHub does not document these, but web frameworks often honour them,
    # and they would turn an allowed POST into a DELETE after the check.
    for name in ("x-http-method-override", "x-http-method", "x-method-override"):
        if name in header_values:
            raise _fix(
                "method-override",
                f"the header {name} asks for another method than the one sent.",
            )
    for name in ("host", "content-type", "content-encoding"):
        if len(header_values.get(name, ())) > 1:
            raise _fix("header-repeated", f"the header {name} is sent more than once.")
    for named in header_values.get("host", ()):
        if named.lower() not in (host, f"{host}:443"):
            raise _fix(
                "host-differs",
                f"the request was sent to {host} but names another host in "
                "its Host header.",
            )

    segments = _segments(path)
    pairs = _query(query)
    if any(key.lower() == "_method" for key, _ in pairs):
        raise _fix(
            "method-override",
            "the query asks for another method than the one sent (`_method`).",
        )

    if host == GIT_HOST:
        return _git(method, segments, query, policy)
    return _api(method, segments, pairs, header_values, body, policy)


def _refuse_host(host: str) -> _Refusal:
    if host == "gist.github.com":
        return _never("gists")
    if host == "uploads.github.com":
        return _Refusal(
            "releases",
            "uploads.github.com takes files for releases, and " + NEVER["releases"],
            ASK_NEVER,
        )
    return _Refusal(
        "github-host-not-covered",
        f"{_show(host)} is not a GitHub host the broker has rules for. It "
        "knows github.com, for git, and api.github.com, for the API.",
        ASK_UNKNOWN,
    )


def _headers(headers: object) -> dict[str, list[str]]:
    """Group header values by name in lower case."""
    if isinstance(headers, Mapping):
        items = list(headers.items())
    elif headers is None:
        raise TypeError("headers are needed")
    else:
        items = list(headers)  # type: ignore[call-overload]
    values: dict[str, list[str]] = {}
    for name, value in items:
        if isinstance(name, bytes):
            name = name.decode("latin-1")
        if isinstance(value, bytes):
            value = value.decode("latin-1")
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError("header names and values must be text")
        values.setdefault(name.strip().lower(), []).append(value.strip())
    return values


# ---------------------------------------------------------------------------
# Paths and queries
# ---------------------------------------------------------------------------

# Printable ASCII without "#", "?" and "\". A path holds nothing else.
PATH_CHARS = re.compile(r"[\x21\x22\x24-\x3e\x40-\x5b\x5d-\x7e]+")
QUERY_CHARS = re.compile(r"[\x21\x22\x24-\x7e]*")
BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _decode(text: str) -> str | None:
    """Undo percent-encoding once. None when it is not valid."""
    if BAD_ESCAPE.search(text):
        return None
    try:
        return unquote_to_bytes(text).decode("utf-8")
    except UnicodeDecodeError:
        return None


def _segments(path: object) -> list[str]:
    """Split a path into its parts, refusing every spelling that is not plain.

    The parts are returned as they were sent, still encoded. Every later
    check compares these raw parts with plain words, so an encoded keyword
    such as "%70ulls" matches nothing and is refused. The decoded form is
    used only here, to catch what the encoding may hide.

    The path is never repaired and passed on in a better form. The broker
    sends on exactly the path it was given, so the only safe paths are the
    ones GitHub cannot read differently from how they were read here.
    """
    bad = _fix
    if not isinstance(path, str) or not path.startswith("/"):
        raise bad("path-odd", "the path does not start with a slash.")
    if len(path) > MAX_PATH:
        raise bad("path-odd", "the path is too long.")
    if not PATH_CHARS.fullmatch(path):
        raise bad(
            "path-odd",
            "the path holds a character that does not belong in one, such as "
            "a space, `?`, `#`, a backslash or a letter outside plain ASCII.",
        )
    if path == "/":
        return []
    parts = path[1:].split("/")
    for part in parts:
        if not part:
            raise bad("path-odd", "the path has a doubled slash or ends with a slash.")
        decoded = _decode(part)
        if decoded is None:
            raise bad("path-odd", "the path has a `%` that is not a valid encoding.")
        if decoded in (".", ".."):
            raise bad("path-odd", "the path has a `.` or `..` part.")
        if any(char in "/\\%" or ord(char) < 0x20 or ord(char) == 0x7F for char in decoded):
            raise bad(
                "path-odd",
                "the path has an encoded slash, backslash, `%` or control "
                "character. Write a slash as a slash.",
            )
    return parts


def _query(query: object) -> list[tuple[str, str]]:
    """Split a query into decoded names and values."""
    if not isinstance(query, str):
        raise TypeError("query must be text")
    if len(query) > MAX_QUERY or not QUERY_CHARS.fullmatch(query):
        raise _fix("query-odd", "the query is too long or holds an odd character.")
    pairs = []
    for part in query.split("&") if query else []:
        name, _, value = part.partition("=")
        decoded = (_decode(name.replace("+", " ")), _decode(value.replace("+", " ")))
        if decoded[0] is None or decoded[1] is None:
            raise _fix("query-odd", "the query has a `%` that is not a valid encoding.")
        pairs.append((decoded[0], decoded[1]))
    return pairs


def _owner_and_name(owner: str, name: str) -> None:
    """Refuse an owner or repo name that GitHub could not have issued."""
    if not OWNER.fullmatch(owner) or not REPO_NAME.fullmatch(name):
        raise _fix(
            "path-odd",
            "the owner or repo name in the path is not written the plain way: "
            "letters, digits, `-`, `_` and `.` only.",
        )


def _access(
    policy: Policy, owner: str, name: str, want: str, kind: str
) -> Decision:
    """Allow or refuse `want` ("read", "write" or "merge") on one repo."""
    repo = policy.find(owner, name)
    shown = f"{owner}/{name}"
    if repo is None:
        if want == "read" and policy.read_public:
            # No token: GitHub then answers only for public repos. With the
            # token this would read everything its owner can read.
            return Decision(allowed=True, kind=kind, with_token=False)
        if want == "read":
            raise _Refusal(
                "repo-not-listed",
                f"{shown} is not a repo the sandbox may use.",
                ASK_LIST,
            )
        raise _Refusal(
            "repo-not-listed",
            f"{shown} is not a repo the sandbox may use, so nothing can be "
            "sent to it.",
            ASK_LIST,
        )
    if want != "read" and not repo.write:
        raise _Refusal(
            "repo-read-only",
            f"{repo.full_name} is listed for reading only.",
            ASK_WRITE,
        )
    if want == "merge" and not repo.merge:
        raise _Refusal(
            "merge",
            f"merging pull requests in {repo.full_name} is not allowed from "
            "the sandbox.",
            ASK_MERGE,
        )
    return Decision(allowed=True, kind=kind, with_token=True, repo=repo.full_name)


# ---------------------------------------------------------------------------
# github.com: git over HTTPS
# ---------------------------------------------------------------------------


def _git(method: str, segments: list[str], query: str, policy: Policy) -> Decision:
    """Git talks to three addresses per repo, and nothing else is allowed.

        GET  /OWNER/NAME/info/refs?service=git-upload-pack    what is there?
        POST /OWNER/NAME/git-upload-pack                      fetch, clone
        GET  /OWNER/NAME/info/refs?service=git-receive-pack   may I push?
        POST /OWNER/NAME/git-receive-pack                     push

    "upload-pack" is the server uploading to you, so it is the reading one.
    NAME may end in ".git". The rest of github.com is the website, which the
    agent has no use for with a token.

    A push is allowed or refused as a whole. Which branch it changes is
    inside the upload and is not looked at; protect branches on GitHub.
    """
    if len(segments) < 3:
        raise _unknown("on github.com the broker passes on git only: clone, fetch and push.")
    owner, name, rest = segments[0], segments[1], segments[2:]

    if rest[:2] == ["info", "lfs"]:
        raise _never("git-lfs")

    if rest == ["info", "refs"] and method == "GET":
        if query == "service=git-upload-pack":
            want = "read"
        elif query == "service=git-receive-pack":
            want = "write"
        else:
            raise _unknown(
                "this git request does not say whether it is a fetch or a "
                "push in the usual way."
            )
    elif rest == ["git-upload-pack"] and method == "POST":
        want = "read"
    elif rest == ["git-receive-pack"] and method == "POST":
        want = "write"
    else:
        raise _unknown("on github.com the broker passes on git only: clone, fetch and push.")
    if rest != ["info", "refs"] and query:
        raise _unknown("a git fetch or push does not have a query.")

    _owner_and_name(owner, name)
    # GitHub takes the name with or without ".git". One ending is removed and
    # no more: "name.git.git" is then a repo called "name.git", which cannot
    # be listed, and "name.wiki.git" is the repo's wiki, a separate place to
    # push to, which is not listed either.
    if name.endswith(".git"):
        name = name[: -len(".git")]
    if not name or name in (".", ".."):
        raise _fix("path-odd", "the repo name in the path is empty.")
    return _access(policy, owner, name, want, f"git-{want}")


# ---------------------------------------------------------------------------
# api.github.com: the REST API
# ---------------------------------------------------------------------------

# Parts of a repo that may be read: the first word after /repos/OWNER/NAME.
# `actions` is handled apart, because only some of it is readable.
READABLE = frozenset(
    {
        "branches",
        "check-runs",
        "check-suites",
        "comments",
        "commits",
        "compare",
        "contents",
        "contributors",
        "deployments",
        "events",
        "forks",
        "git",
        "issues",
        "labels",
        "languages",
        "license",
        "milestones",
        "pulls",
        "readme",
        "releases",
        "statuses",
        "tags",
        "tarball",
        "topics",
        "zipball",
    }
)
READABLE_ACTIONS = frozenset({"artifacts", "jobs", "runs", "workflows"})

# The changes that are allowed in a `write` repo. "#" stands for a number and
# "*" for any one part. Everything not here is refused.
#
# The `issues` lines are here for pull requests. In this API a pull request
# is also an issue with the same number, and its comments, labels and
# reactions are reached under /issues. The broker cannot tell from a number
# whether it is a pull request, so these work on issues as well. Creating,
# editing and closing an issue have requests of their own, and are refused.
WRITABLE = {
    "POST": (
        ("pulls",),
        ("pulls", "#", "comments"),
        ("pulls", "#", "comments", "#", "replies"),
        ("pulls", "#", "reviews"),
        ("pulls", "#", "reviews", "#", "events"),
        ("pulls", "#", "requested_reviewers"),
        ("pulls", "comments", "#", "reactions"),
        ("issues", "#", "comments"),
        ("issues", "#", "labels"),
        ("issues", "#", "reactions"),
        ("issues", "comments", "#", "reactions"),
    ),
    "PATCH": (
        ("pulls", "#"),
        ("pulls", "comments", "#"),
        ("issues", "comments", "#"),
    ),
    "PUT": (
        ("pulls", "#", "reviews", "#"),
        ("issues", "#", "labels"),
    ),
    "DELETE": (
        ("pulls", "comments", "#"),
        ("pulls", "comments", "#", "reactions", "#"),
        ("pulls", "#", "reviews", "#"),
        ("pulls", "#", "requested_reviewers"),
        ("issues", "comments", "#"),
        ("issues", "comments", "#", "reactions", "#"),
        ("issues", "#", "labels"),
        ("issues", "#", "labels", "*"),
        ("issues", "#", "reactions", "#"),
    ),
}

# Parts of a repo where a change is refused with a reason of its own, so the
# agent is told what the matter is instead of "not recognised".
CLOSED_FOR_CHANGES = {
    "actions": "actions",
    "automated-security-fixes": "repo-settings",
    "autolinks": "repo-settings",
    "branches": "branch-protection",
    "check-runs": "checks",
    "check-suites": "checks",
    "code-scanning": "repo-settings",
    "codespaces": "repo-settings",
    "contents": "git-data",
    "dependabot": "repo-settings",
    "dispatches": "actions",
    "environments": "repo-settings",
    "forks": "forks",
    "generate": "repo-creation",
    "git": "git-data",
    "immutable-releases": "releases",
    "import": "repo-settings",
    "interaction-limits": "repo-settings",
    "merge-upstream": "merge-api",
    "merges": "merge-api",
    "pages": "repo-settings",
    "private-vulnerability-reporting": "repo-settings",
    "properties": "repo-settings",
    "releases": "releases",
    "rulesets": "branch-protection",
    "statuses": "checks",
    "topics": "repo-settings",
    "transfer": "repo-transfer",
    "vulnerability-alerts": "repo-settings",
}

NUMBER = re.compile(r"[1-9][0-9]{0,18}")


def _matches(rest: list[str], patterns: Iterable[tuple[str, ...]]) -> bool:
    for pattern in patterns:
        if len(pattern) == len(rest) and all(
            (want == "#" and NUMBER.fullmatch(got))
            or want == "*"
            or (want == got and want != "#")
            for want, got in zip(pattern, rest)
        ):
            return True
    return False


def _closed_area(rest: list[str]) -> str | None:
    """The parts of a repo that are refused for reading as well."""
    first = rest[0] if rest else ""
    second = rest[1] if len(rest) > 1 else ""
    if first == "actions" and second in (
        "secrets",
        "variables",
        "organization-secrets",
        "organization-variables",
    ):
        return "secrets"
    if first in ("dependabot", "codespaces") and second == "secrets":
        return "secrets"
    if first == "environments" and ("secrets" in rest or "variables" in rest):
        return "secrets"
    if first == "secret-scanning":
        return "secrets"
    if first == "keys":
        return "deploy-keys"
    if first == "hooks":
        return "webhooks"
    if first in ("collaborators", "invitations", "teams", "assignees"):
        return "collaborators"
    # A branch's protection names the people and teams who may push to it.
    if first == "branches" and "protection" in rest[2:]:
        return "branch-protection"
    return None


def _repo_request(method: str, rest: list[str]) -> str:
    """Sort a request under /repos/OWNER/NAME into read, write or merge."""
    closed = _closed_area(rest)
    if closed:
        raise _never(closed)

    if method in READ_METHODS:
        first = rest[0] if rest else ""
        if not rest or first in READABLE:
            return "read"
        if first == "actions" and len(rest) > 1 and rest[1] in READABLE_ACTIONS:
            return "read"
        raise _unknown("this part of a repo is not one the broker lets the sandbox read.")

    if _matches(rest, WRITABLE[method]):
        return "write"
    # Deleting a branch, which `gh pr close --delete-branch` does. A push can
    # delete a branch as well, so this gives nothing new.
    if method == "DELETE" and len(rest) > 3 and rest[:3] == ["git", "refs", "heads"]:
        return "write"
    if method == "PUT" and _matches(rest, [("pulls", "#", "merge")]):
        return "merge"

    if not rest:
        if method == "DELETE":
            raise _never("repo-deletion")
        raise _never("repo-settings")
    if _matches(rest, [("pulls", "#", "merge-async"), ("pulls", "#", "update-branch")]):
        raise _never("merge-api")
    if _matches(rest, [("issues", "#", "assignees")]):
        raise _never("assignees")
    if _matches(rest, [("issues",), ("issues", "#")]):
        raise _never("issues")
    reason = CLOSED_FOR_CHANGES.get(rest[0])
    if reason:
        raise _never(reason)
    raise _unknown("this change to a repo is not one the broker lets through.")


def _api(
    method: str,
    segments: list[str],
    pairs: list[tuple[str, str]],
    headers: dict[str, list[str]],
    body: object,
    policy: Policy,
) -> Decision:
    # A packed body would have to be unpacked to be read, and the unpacked
    # size is not known beforehand. No client of the API packs its requests.
    encoding = headers.get("content-encoding", [""])[0].lower()
    if encoding not in ("", "identity"):
        raise _fix("body-odd", "the body is compressed, so the broker cannot read it.")

    if body is None:
        body = b""
        if method not in READ_METHODS:
            # proxy.py must hand over the body for these. Without it nothing
            # can be said about the request.
            raise _fix("body-odd", "the broker was not given the body of this request.")
    if not isinstance(body, bytes | bytearray):
        raise TypeError("body must be bytes")
    body = bytes(body)
    if len(body) > MAX_BODY:
        raise _fix("body-odd", "the body is larger than the broker reads.")
    if method in READ_METHODS and body:
        raise _fix("body-odd", f"a {method} request must not have a body.")
    if method not in READ_METHODS and pairs:
        # GitHub takes values from the query string on a change as well, and
        # fills in from it what the body leaves out. The checks here read the
        # body, so anything in the query string would go out unread.
        raise _fix(
            "query-odd",
            "a request that changes something must not have a query string. "
            "Put its values in the body.",
        )

    first = segments[0] if segments else ""

    if first == "graphql" and len(segments) == 1:
        if method != "POST":
            raise _unknown("GraphQL requests are sent with POST.")
        return _graphql(headers, body, policy)

    if first == "repos":
        if len(segments) < 3:
            raise _unknown("a repo is named as /repos/OWNER/NAME.")
        owner, name, rest = segments[1], segments[2], segments[3:]
        _owner_and_name(owner, name)
        want = _repo_request(method, rest)
        decision = _access(
            policy, owner, name, want, "api-read" if want == "read" else "api-write"
        )
        if want != "read" and body:
            # The allowed changes take a JSON object or nothing. Most of
            # what is in it is GitHub's business: a title, a comment's text.
            # Assigning is the one thing that is looked for, in case a
            # request that creates or edits something takes assignees on
            # the side.
            data = _json_object(headers, body)
            if any(data.get(key) for key in ("assignees", "assignee", "agent_assignment")):
                raise _never("assignees")
            if rest == ["pulls"] or _matches(rest, [("pulls", "#")]):
                _pull_request_body(data, owner, policy)
            decision = replace(decision, body=_fresh(data))
        return decision

    # What is left is not tied to a repo. Only these few are allowed; they
    # say who the token belongs to and how the API is doing.
    if method in READ_METHODS and segments in (
        [],
        ["user"],
        ["rate_limit"],
        ["meta"],
        ["versions"],
    ):
        return Decision(allowed=True, kind="api-read", with_token=True)

    if first == "user":
        if segments == ["user", "repos"] and method == "POST":
            raise _never("repo-creation")
        raise _never("account")
    if first in ("orgs", "organizations"):
        if len(segments) == 3 and segments[2] == "repos" and method == "POST":
            raise _never("repo-creation")
        raise _never("organizations")
    if first == "gists":
        raise _never("gists")
    if first == "search":
        raise _never("search")
    if first == "repositories":
        raise _never("repo-by-id")
    raise _unknown("this part of the GitHub API is not one the broker lets through.")


# ---------------------------------------------------------------------------
# JSON bodies
# ---------------------------------------------------------------------------


def _reject_constant(name: str) -> object:
    raise ValueError(f"{name} is not JSON")


def _reject_repeats(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("a name is used twice")
        result[name] = value
    return result


def _fresh(data: dict[str, object]) -> bytes:
    """Write a JSON object out again, to be sent on instead of the original.

    GitHub then reads exactly what was judged here, and not a second meaning
    that the original bytes might have had for a reader that differs from
    this one. The result is plain ASCII, which leaves nothing to differ on.
    """
    try:
        text = json.dumps(data, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    except ValueError:
        # A number too large to be one, such as 1e999.
        raise _fix("body-odd", "the body holds a number that is not valid JSON.") from None
    return text.encode("ascii")


def _json_object(headers: dict[str, list[str]], body: bytes) -> dict[str, object]:
    """Read a body as one JSON object, strictly.

    Strictly, because two programs can read a sloppy document in two ways.
    The cases refused here are the ones where readers are known to differ: a
    name used twice (the first or the last value?), a byte order mark, text
    that is not UTF-8, and NaN and Infinity, which are not JSON.

    The body must also say that it is JSON. A server that picked the reader
    from the Content-Type could otherwise be handed a body that is harmless
    as JSON and something else as a web form.
    """
    media_type, *extras = (
        part.strip().lower() for part in headers.get("content-type", [""])[0].split(";")
    )
    # The body is read here as UTF-8. If it claimed another character set, a
    # server that believed the claim would read other text than was judged.
    if media_type != "application/json" or any(
        extra.replace('"', "") != "charset=utf-8" for extra in extras
    ):
        raise _fix(
            "body-odd",
            "a request with a body must say `Content-Type: application/json`, "
            "with no character set other than UTF-8.",
        )
    try:
        data = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_reject_repeats,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError):
        raise _fix(
            "body-odd",
            "the body is not plain JSON: one object, in UTF-8, with no name "
            "used twice.",
        ) from None
    if not isinstance(data, dict):
        raise _fix(
            "body-odd",
            "the body must be one JSON object. Several requests in one body "
            "are not accepted.",
        )
    _refuse_odd_text(data)
    return data


# Added when the policy was wired into the broker, after a review; the one
# change made to this module then. It refuses more and allows nothing new.
def _refuse_odd_text(data: object) -> None:
    """Refuse a body with a name or a text that readers may shorten.

    Two things can be written in JSON that are not text a program can rely
    on: the character U+0000, and half of a pair of "surrogates" without its
    other half (written `\\ud800` in JSON). Programs treat them differently.
    Some drop the half pair, some replace it, and some cut a text off at
    U+0000. A name such as `assignees` followed by such a half is not
    `assignees` to the checks in this module, which would let it through;
    if GitHub's reader dropped the odd character, it would be `assignees`
    there, which is refused. Whether GitHub does is not known, so such a
    body is refused.

    A pair of surrogates that is whole is fine: the JSON reader has already
    turned it into the one character it stands for.
    """
    todo = [data]
    while todo:
        item = todo.pop()
        if isinstance(item, dict):
            todo.extend(item)
            todo.extend(item.values())
        elif isinstance(item, list):
            todo.extend(item)
        elif isinstance(item, str) and any(
            ord(char) == 0 or 0xD800 <= ord(char) <= 0xDFFF for char in item
        ):
            raise _fix(
                "body-odd",
                "the body has a name or a text with the character U+0000 or "
                "half of a surrogate pair in it, which not every program "
                "reads the same way.",
            )


# ---------------------------------------------------------------------------
# Ids
# ---------------------------------------------------------------------------

# GraphQL names a thing by an id such as "PR_kwDOAbCdEf8AAAABPlDjjg" instead
# of by repo and number. An id is a few letters for the kind of thing, an
# underscore, and a short list of numbers packed with MessagePack and
# base64. For a repo the list is [0, the repo's number]. For a thing inside
# a repo, such as a pull request, an issue, a comment or a review, it is
# [0, the repo's number, the thing's own number].
#
# Only a repo's id says which repo it means. For everything else, GitHub
# finds the thing by its own number, the last one, and does not look at the
# repo's number in front of it. An id made of a listed repo's number and the
# number of a pull request in some other repo is answered with that other
# pull request. This was seen on GitHub, not read in its documentation: the
# id of a real pull request with the repo's number replaced by 1 still gave
# the same pull request.
#
# So an id of that kind proves nothing about the repo, and nothing else in
# such a request does either. The only way to know would be to ask GitHub,
# and this module asks nobody. A request that names its target only by such
# an id is therefore refused, and the refusal names the REST request that
# does the same job with the repo in its address (`BY_ID` below).
#
# A repo's own id is trusted: its one number is the repo, and there is no
# second number for GitHub to go by instead. Repos from before 2021 have an
# id of an older make-up, which holds the same number in plain text.
NEW_ID = re.compile(r"([A-Z]{1,8})_([A-Za-z0-9_-]{4,64})")
OLD_REPO_ID = re.compile(rb"010:Repository([1-9][0-9]{0,18})")
OLD_ID_TEXT = re.compile(r"[A-Za-z0-9+/]{8,128}={0,2}")

# The letter a repo's id starts with.
REPO = "R"


def _unpack(packed: bytes) -> tuple[int, int] | None:
    """Read a MessagePack list of exactly two whole numbers, and only that."""
    if not packed or packed[0] != 0x92:
        return None
    numbers = []
    at = 1
    for _ in range(2):
        if at >= len(packed):
            return None
        first = packed[at]
        at += 1
        if first < 0x80:
            numbers.append(first)
            continue
        size = {0xCC: 1, 0xCD: 2, 0xCE: 4, 0xCF: 8}.get(first)
        if size is None or at + size > len(packed):
            return None
        numbers.append(int.from_bytes(packed[at : at + size], "big"))
        at += size
    if at != len(packed):
        return None
    return numbers[0], numbers[1]


def _repo_number(node_id: object) -> int | None:
    """The repo's number from a repo's id, or None for anything else.

    "Anything else" includes the id of a thing inside a repo. That id holds
    a repo's number too, but not one that can be believed.
    """
    if not isinstance(node_id, str):
        return None
    match = NEW_ID.fullmatch(node_id)
    if match:
        text = match.group(2)
        try:
            packed = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        except (binascii.Error, ValueError):
            return None
        numbers = _unpack(packed)
        if match.group(1) != REPO or numbers is None or numbers[0] != 0:
            return None
        return numbers[1]
    if OLD_ID_TEXT.fullmatch(node_id):
        try:
            old = OLD_REPO_ID.fullmatch(base64.b64decode(node_id, validate=True))
        except (binascii.Error, ValueError):
            return None
        if old:
            return int(old.group(1))
    return None


def _listed_repo(node_id: object, policy: Policy) -> Repo:
    """The listed repo with this id, or a refusal."""
    number = _repo_number(node_id)
    repo = policy.find_number(number) if number is not None else None
    if repo is None:
        raise _Refusal(
            "graphql-id-not-listed",
            "the request names a repo by an id, and it is not the id of a "
            "repo the broker has in its rules.",
            ASK_ID,
        )
    return repo


# ---------------------------------------------------------------------------
# GraphQL: reading the document
# ---------------------------------------------------------------------------
#
# A GraphQL request is a small program in the body of a POST to /graphql. To
# know what it does, the broker has to read it the way GitHub will, so below
# is a reader for the part of the language a request can use. It follows the
# GraphQL specification and accepts nothing beyond it. Where it could not be
# sure to agree with GitHub, it refuses.


class _Syntax(Exception):
    """The GraphQL document cannot be read."""


class _Field:
    __slots__ = ("name", "arguments", "selections")

    def __init__(self, name: str, arguments: dict[str, object], selections: list) -> None:
        self.name = name
        self.arguments = arguments
        self.selections = selections


class _Spread:
    """`...name`: the fields of a named fragment, used here."""

    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name


class _Inline:
    """`... on Type { fields }`: fields that apply to one type of thing.

    `on` is the type's name, or None when the request gives none.
    """

    __slots__ = ("on", "selections")

    def __init__(self, on: str | None, selections: list) -> None:
        self.on = on
        self.selections = selections


class _Fragment:
    """`fragment name on Type { fields }`: fields under a name, used with
    `...name` wherever they are wanted."""

    __slots__ = ("on", "selections")

    def __init__(self, on: str, selections: list) -> None:
        self.on = on
        self.selections = selections


class _Operation:
    __slots__ = ("kind", "name", "variables", "selections")

    def __init__(
        self, kind: str, name: str | None, variables: dict[str, object], selections: list
    ) -> None:
        self.kind = kind
        self.name = name
        # Each variable's default value, or _NO_DEFAULT.
        self.variables = variables
        self.selections = selections


class _Variable:
    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name


class _Enum(str):
    """A bare word used as a value, such as ISSUE. Not the same as "ISSUE"."""


class _Unknown:
    """A value this reader does not work out. It equals nothing, so a check
    that needs the value fails."""


_NO_DEFAULT = _Unknown()
_UNKNOWN = _Unknown()

TOKEN = re.compile(
    r"""
      (?P<skip>   [\ufeff\t\n\r ,]+ | \#[^\n\r]* )
    | (?P<punct>  \.\.\. | [!$&()\[\]{}:=@|] )
    | (?P<name>   [_A-Za-z][_0-9A-Za-z]* )
    | (?P<number> -?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?(?![_A-Za-z0-9.]) )
    | (?P<block>  \"\"\"(?:\\\"\"\"|[^"]|"(?!""))*\"\"\" )
    | (?P<string> "(?:[^"\\\n\r]|\\.)*" )
    """,
    re.VERBOSE,
)

ESCAPE = re.compile(r'\\(?:u\{([0-9A-Fa-f]{1,6})\}|u([0-9A-Fa-f]{4})|(["\\/bfnrt])|(.))', re.S)
SIMPLE_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def _unescape(match: re.Match[str]) -> str:
    braced, four, simple, other = match.groups()
    if other is not None:
        raise _Syntax("unknown escape in a string")
    if simple is not None:
        return SIMPLE_ESCAPES[simple]
    code = int(braced or four, 16)
    if code > 0x10FFFF:
        raise _Syntax("escape out of range")
    return chr(code)


def _string(text: str) -> str:
    inner = text[1:-1]
    if any(ord(char) < 0x20 and char != "\t" for char in inner):
        raise _Syntax("control character in a string")
    return ESCAPE.sub(_unescape, inner)


def _tokens(text: str) -> list[tuple[str, str]]:
    tokens = []
    at = 0
    while at < len(text):
        match = TOKEN.match(text, at)
        if not match:
            raise _Syntax("unreadable text")
        at = match.end()
        kind = match.lastgroup
        if kind != "skip":
            tokens.append((kind, match.group()))
            if len(tokens) > MAX_TOKENS:
                raise _Syntax("too long")
    return tokens


class _Reader:
    """Turns the text of a GraphQL document into operations and fragments."""

    def __init__(self, text: str) -> None:
        self.tokens = _tokens(text)
        self.at = 0

    def peek(self) -> tuple[str, str]:
        return self.tokens[self.at] if self.at < len(self.tokens) else ("end", "")

    def take(self) -> tuple[str, str]:
        token = self.peek()
        self.at += 1
        return token

    def has(self, punct: str) -> bool:
        if self.peek() == ("punct", punct):
            self.at += 1
            return True
        return False

    def need(self, punct: str) -> None:
        if not self.has(punct):
            raise _Syntax(f"expected {punct}")

    def name(self) -> str:
        kind, text = self.take()
        if kind != "name":
            raise _Syntax("expected a name")
        return text

    def document(self) -> tuple[list[_Operation], dict[str, _Fragment]]:
        operations: list[_Operation] = []
        fragments: dict[str, _Fragment] = {}
        while self.peek()[0] != "end":
            kind, text = self.peek()
            if (kind, text) == ("punct", "{"):
                operations.append(_Operation("query", None, {}, self.selection_set(1)))
            elif kind == "name" and text in ("query", "mutation", "subscription"):
                self.take()
                name = self.name() if self.peek()[0] == "name" else None
                variables = self.variable_definitions() if self.peek() == ("punct", "(") else {}
                self.directives()
                operations.append(_Operation(text, name, variables, self.selection_set(1)))
            elif kind == "name" and text == "fragment":
                self.take()
                name = self.name()
                if name == "on" or self.name() != "on":
                    raise _Syntax("badly formed fragment")
                on = self.name()
                self.directives()
                if name in fragments:
                    raise _Syntax("two fragments with one name")
                fragments[name] = _Fragment(on, self.selection_set(1))
                if len(fragments) > MAX_FRAGMENTS:
                    raise _Syntax("too many fragments")
            else:
                # Anything else that can start a definition describes a
                # schema. A request has no business sending that.
                raise _Syntax("not an operation or a fragment")
        names = [operation.name for operation in operations]
        if len(operations) > MAX_OPERATIONS:
            raise _Syntax("too many operations")
        if not operations or len(set(names)) != len(names):
            raise _Syntax("no operation, or two with one name")
        if len(operations) > 1 and None in names:
            raise _Syntax("an unnamed operation next to others")
        return operations, fragments

    def variable_definitions(self) -> dict[str, object]:
        variables: dict[str, object] = {}
        self.need("(")
        while not self.has(")"):
            self.need("$")
            name = self.name()
            self.need(":")
            self.type()
            default = self.value(1, constant=True) if self.has("=") else _NO_DEFAULT
            self.directives()
            if name in variables:
                raise _Syntax("a variable is declared twice")
            variables[name] = default
        if not variables:
            raise _Syntax("empty variable list")
        return variables

    def type(self) -> None:
        if self.has("["):
            self.type()
            self.need("]")
        else:
            self.name()
        self.has("!")

    def directives(self) -> None:
        """`@name(arguments)`, as in `@include(if: $x)`. Read and dropped:
        every field is checked whether or not a directive would leave it
        out."""
        while self.has("@"):
            self.name()
            if self.peek() == ("punct", "("):
                self.arguments()

    def selection_set(self, depth: int) -> list:
        if depth > MAX_DEPTH:
            raise _Syntax("nested too deep")
        self.need("{")
        selections: list = []
        while not self.has("}"):
            if self.has("..."):
                kind, text = self.peek()
                if kind == "name" and text != "on":
                    selections.append(_Spread(self.name()))
                    self.directives()
                    continue
                on = None
                if self.peek() == ("name", "on"):
                    self.take()
                    on = self.name()
                self.directives()
                selections.append(_Inline(on, self.selection_set(depth + 1)))
                continue
            name = self.name()
            if self.has(":"):
                # What came first was an alias, a name for the result. The
                # field asked for is the name after the colon.
                name = self.name()
            arguments = self.arguments() if self.peek() == ("punct", "(") else {}
            self.directives()
            inner = self.selection_set(depth + 1) if self.peek() == ("punct", "{") else []
            selections.append(_Field(name, arguments, inner))
        if not selections:
            raise _Syntax("empty selection")
        return selections

    def arguments(self) -> dict[str, object]:
        arguments: dict[str, object] = {}
        self.need("(")
        while not self.has(")"):
            name = self.name()
            self.need(":")
            if name in arguments:
                raise _Syntax("an argument is given twice")
            arguments[name] = self.value(1)
        if not arguments:
            raise _Syntax("empty argument list")
        return arguments

    def value(self, depth: int, constant: bool = False) -> object:
        if depth > MAX_DEPTH:
            raise _Syntax("nested too deep")
        kind, text = self.take()
        if (kind, text) == ("punct", "$"):
            if constant:
                raise _Syntax("a variable where a fixed value is needed")
            return _Variable(self.name())
        if kind == "number":
            # No check depends on a number, so its value is not worked out.
            return _UNKNOWN
        if kind == "string":
            return _string(text)
        if kind == "block":
            # A """block""" string has rules about indentation that decide
            # its value. No tool writes a repo name or an id that way, so it
            # is treated as a value that matches nothing.
            return _UNKNOWN
        if kind == "name":
            if text == "true":
                return True
            if text == "false":
                return False
            if text == "null":
                return None
            return _Enum(text)
        if (kind, text) == ("punct", "["):
            items = []
            while not self.has("]"):
                items.append(self.value(depth + 1, constant))
            return items
        if (kind, text) == ("punct", "{"):
            fields: dict[str, object] = {}
            while not self.has("}"):
                name = self.name()
                self.need(":")
                if name in fields:
                    raise _Syntax("a name is used twice in one value")
                fields[name] = self.value(depth + 1, constant)
            return fields
        raise _Syntax("expected a value")


class _Document:
    """A GraphQL document, read: its operations and its named fragments."""

    def __init__(self, text: str) -> None:
        self.operations, self.fragments = _Reader(text).document()


def _resolve(value: object, operation: _Operation, variables: dict[str, object]) -> object:
    """Work out what an argument's value will be when GitHub runs the request.

    A variable takes its value from the request's `variables`; when it is
    not given there, from the default in its declaration.
    """
    if isinstance(value, _Variable):
        if value.name not in operation.variables:
            return _UNKNOWN
        if value.name in variables:
            return variables[value.name]
        default = operation.variables[value.name]
        return None if default is _NO_DEFAULT else default
    if isinstance(value, list):
        return [_resolve(item, operation, variables) for item in value]
    if isinstance(value, dict):
        return {name: _resolve(item, operation, variables) for name, item in value.items()}
    return value


# ---------------------------------------------------------------------------
# GraphQL: deciding
# ---------------------------------------------------------------------------

# Where a query may start. Each is checked below.
#
#   repository  one repo, by owner and name, which must be listed
#   node        one listed repo, by the repo's own id; nothing else by id
#   search      issues and pull requests, kept to listed repos
#   viewer      the account behind the token: its name and id only
#   user        another account: its name and id only (to request a review)
#   rateLimit, __type, __schema, __typename   about the API itself
QUERY_STARTS = frozenset(
    {"repository", "node", "search", "viewer", "user", "rateLimit", "__type", "__schema", "__typename"}
)

SEARCH_TYPES = frozenset({"ISSUE", "ISSUE_ADVANCED"})

# What a query may ask for after its start.
#
# A query is a tree. `repository { pullRequest { author { login } } }` starts
# at a repo, steps to one of its pull requests, steps on to the author, and
# reads the author's `login`. A step is a field with braces after it; a plain
# field has none and ends the branch.
#
# Checking the start is not enough, because steps lead on: from a listed repo
# to its owner, from the owner to all the owner's repos, and from any of
# those to its files. So every step has to be on the list below. The list
# says, for each place a query can be, which steps may be taken from there
# and where each one leads. A step that is not listed is refused.
#
# The places are named after GitHub's types, and the list is the part of
# GitHub's data model that gh's own read commands use: it was made by
# recording those commands and following their queries through GitHub's
# published schema. It was then checked against that schema, step by step,
# to lead only where it says. The script for that is not in the repo; what it
# checked is in docs/github-rules.md.
#
# Six places are not one of GitHub's types but a stand-in for several, used
# wherever a step leaves the listed repo or may leave it:
#
#   Account          a user, an organization, a bot, or a list of them
#   Reviewer         who a review was asked of: an account or a team
#   OtherRepository  any repo reached by a step: a pull request's own repo,
#                    the repo its branch is in, a fork's parent
#   OtherRef         a branch of such a repo
#   Reference        an issue or pull request that another one points to,
#                    which may be in another repo
#   Project          a project board and what is on it; boards belong to an
#                    account, not to the repo
#
# In those places only a few plain fields may be read (`ONLY` below), and
# the steps on from them lead only to more of the same. That is what keeps a
# query from walking through an account or a fork into another repo.
#
# In every other place any plain field may be read. They are all things
# inside the listed repo, and a plain field cannot lead anywhere.
INSIDE: dict[str, dict[str, str]] = {
    "Account": {
        "edges": "Account",
        "node": "Account",
        "nodes": "Account",
        "pageInfo": "PageInfo",
    },
    "AutoMergeRequest": {
        "enabledBy": "Account",
    },
    "BranchProtectionRule": {},
    "CheckRun": {
        "checkSuite": "CheckSuite",
    },
    "CheckRunStateCount": {},
    "CheckSuite": {
        "workflowRun": "WorkflowRun",
    },
    "CodeOfConduct": {},
    "Commit": {
        "authors": "GitActorConnection",
        "statusCheckRollup": "StatusCheckRollup",
    },
    "CreatePullRequestPayload": {
        "pullRequest": "PullRequest",
    },
    "FundingLink": {},
    "GitActor": {
        "user": "Account",
    },
    "GitActorConnection": {
        "nodes": "GitActor",
    },
    "Issue": {
        "assignees": "Account",
        "author": "Account",
        "blockedBy": "Reference",
        "blocking": "Reference",
        "closedByPullRequestsReferences": "Reference",
        "comments": "IssueCommentConnection",
        "issueType": "IssueType",
        "labels": "LabelConnection",
        "milestone": "Milestone",
        "parent": "Reference",
        "projectCards": "Project",
        "projectItems": "Project",
        "reactionGroups": "ReactionGroup",
        "repository": "OtherRepository",
        "subIssues": "Reference",
        "subIssuesSummary": "SubIssuesSummary",
    },
    "IssueComment": {
        "author": "Account",
        "reactionGroups": "ReactionGroup",
    },
    "IssueCommentConnection": {
        "nodes": "IssueComment",
        "pageInfo": "PageInfo",
    },
    "IssueConnection": {
        "nodes": "Issue",
        "pageInfo": "PageInfo",
    },
    "IssueOrPullRequest": {},
    "IssueTemplate": {},
    "IssueType": {},
    "Label": {},
    "LabelConnection": {
        "nodes": "Label",
        "pageInfo": "PageInfo",
    },
    "Language": {},
    "LanguageConnection": {
        "edges": "LanguageEdge",
    },
    "LanguageEdge": {
        "node": "Language",
    },
    "License": {},
    "Milestone": {},
    "MilestoneConnection": {
        "nodes": "Milestone",
    },
    "OtherRef": {},
    "OtherRepository": {
        "defaultBranchRef": "OtherRef",
        "owner": "Account",
    },
    "PageInfo": {},
    "Project": {
        "column": "Project",
        "edges": "Project",
        "fieldValueByName": "Project",
        "node": "Project",
        "nodes": "Project",
        "pageInfo": "PageInfo",
        "project": "Project",
    },
    "PullRequest": {
        "assignees": "Account",
        "author": "Account",
        "autoMergeRequest": "AutoMergeRequest",
        "baseRef": "Ref",
        "closingIssuesReferences": "Reference",
        "comments": "IssueCommentConnection",
        "commits": "PullRequestCommitConnection",
        "files": "PullRequestChangedFileConnection",
        "headRepository": "OtherRepository",
        "headRepositoryOwner": "Account",
        "labels": "LabelConnection",
        "latestReviews": "PullRequestReviewConnection",
        "mergeCommit": "Commit",
        "mergedBy": "Account",
        "milestone": "Milestone",
        "potentialMergeCommit": "Commit",
        "projectCards": "Project",
        "projectItems": "Project",
        "reactionGroups": "ReactionGroup",
        "repository": "OtherRepository",
        "reviewRequests": "ReviewRequestConnection",
        "reviews": "PullRequestReviewConnection",
    },
    "PullRequestChangedFile": {},
    "PullRequestChangedFileConnection": {
        "nodes": "PullRequestChangedFile",
    },
    "PullRequestCommit": {
        "commit": "Commit",
    },
    "PullRequestCommitConnection": {
        "nodes": "PullRequestCommit",
    },
    "PullRequestConnection": {
        "edges": "PullRequestEdge",
        "nodes": "PullRequest",
        "pageInfo": "PageInfo",
    },
    "PullRequestEdge": {
        "node": "PullRequest",
    },
    "PullRequestReview": {
        "author": "Account",
        "commit": "Commit",
        "reactionGroups": "ReactionGroup",
    },
    "PullRequestReviewConnection": {
        "nodes": "PullRequestReview",
        "pageInfo": "PageInfo",
    },
    "PullRequestTemplate": {},
    "RateLimit": {},
    "ReactionGroup": {
        "users": "Account",
    },
    "Ref": {
        "branchProtectionRule": "BranchProtectionRule",
    },
    "Reference": {
        "edges": "Reference",
        "node": "Reference",
        "nodes": "Reference",
        "pageInfo": "PageInfo",
        "repository": "OtherRepository",
    },
    "Release": {},
    "ReleaseConnection": {
        "nodes": "Release",
        "pageInfo": "PageInfo",
    },
    "Repository": {
        "codeOfConduct": "CodeOfConduct",
        "contactLinks": "RepositoryContactLink",
        "defaultBranchRef": "Ref",
        "fundingLinks": "FundingLink",
        "issue": "Issue",
        "issueOrPullRequest": "IssueOrPullRequest",
        "issueTemplates": "IssueTemplate",
        "issues": "IssueConnection",
        "labels": "LabelConnection",
        "languages": "LanguageConnection",
        "latestRelease": "Release",
        "licenseInfo": "License",
        "milestones": "MilestoneConnection",
        "owner": "Account",
        "parent": "OtherRepository",
        "primaryLanguage": "Language",
        "projects": "Project",
        "pullRequest": "PullRequest",
        "pullRequestTemplates": "PullRequestTemplate",
        "pullRequests": "PullRequestConnection",
        "releases": "ReleaseConnection",
        "repositoryTopics": "RepositoryTopicConnection",
        "templateRepository": "OtherRepository",
        "watchers": "Account",
    },
    "RepositoryContactLink": {},
    "RepositoryTopic": {
        "topic": "Topic",
    },
    "RepositoryTopicConnection": {
        "nodes": "RepositoryTopic",
    },
    "ReviewRequest": {
        "requestedReviewer": "Reviewer",
    },
    "ReviewRequestConnection": {
        "nodes": "ReviewRequest",
    },
    "Reviewer": {
        "organization": "Account",
    },
    "SearchResultItem": {},
    "SearchResultItemConnection": {
        "edges": "SearchResultItemEdge",
        "nodes": "SearchResultItem",
        "pageInfo": "PageInfo",
    },
    "SearchResultItemEdge": {
        "node": "SearchResultItem",
    },
    "StatusCheckRollup": {
        "contexts": "StatusCheckRollupContextConnection",
    },
    "StatusCheckRollupContext": {},
    "StatusCheckRollupContextConnection": {
        "checkRunCountsByState": "CheckRunStateCount",
        "nodes": "StatusCheckRollupContext",
        "pageInfo": "PageInfo",
        "statusContextCountsByState": "StatusContextStateCount",
    },
    "StatusContext": {},
    "StatusContextStateCount": {},
    "SubIssuesSummary": {},
    "Topic": {},
    "Workflow": {},
    "WorkflowRun": {
        "workflow": "Workflow",
    },
}

# Introspection (`__schema`, `__type`) asks about the API, not about data.
# Everything may be asked there.
ANYTHING = "Anything"

# The plain fields that may be read in the places that stand for something
# outside the listed repo. In a place that is not here, all may be read.
ACCOUNT_FIELDS = frozenset({"login", "id", "databaseId", "name", "url", "totalCount", "__typename"})
ONLY: dict[str, frozenset[str]] = {
    "Account": ACCOUNT_FIELDS,
    "Reviewer": ACCOUNT_FIELDS | {"slug"},
    "OtherRepository": frozenset(
        {
            "id",
            "databaseId",
            "name",
            "nameWithOwner",
            "url",
            "sshUrl",
            "description",
            "isPrivate",
            "isFork",
            "isArchived",
            "hasIssuesEnabled",
            "hasWikiEnabled",
            "viewerPermission",
            "__typename",
        }
    ),
    "OtherRef": frozenset({"id", "name", "prefix", "__typename"}),
    "Reference": frozenset({"id", "number", "title", "url", "state", "totalCount", "__typename"}),
    "Project": frozenset(
        {"id", "title", "name", "number", "body", "resourcePath", "optionId", "totalCount", "__typename"}
    ),
    # These three can be one of several types, and have no fields of their
    # own. What is asked of them is asked under `... on Type`, see ONE_OF.
    "IssueOrPullRequest": frozenset({"__typename"}),
    "SearchResultItem": frozenset({"__typename"}),
    "StatusCheckRollupContext": frozenset({"__typename"}),
}

# Places that can be one of several types. `... on PullRequest { }` says
# which one the fields inside are for, and moves the query to that place.
ONE_OF: dict[str, dict[str, str]] = {
    "IssueOrPullRequest": {"Issue": "Issue", "PullRequest": "PullRequest"},
    "SearchResultItem": {"Issue": "Issue", "PullRequest": "PullRequest"},
    "StatusCheckRollupContext": {"CheckRun": "CheckRun", "StatusContext": "StatusContext"},
}

# Steps that are closed in the REST API too, under the names GraphQL has for
# them. They get the same reason as there. (They would be refused anyway,
# for not being on the list.)
CLOSED_FIELDS = {
    "assignableUsers": "collaborators",
    "collaborators": "collaborators",
    "deployKeys": "deploy-keys",
    "mentionableUsers": "collaborators",
}

ASK_NOT_ON_LIST = (
    "Through GraphQL the sandbox may read what gh's own commands read about a\n"
    "listed repo: its pull requests, issues, comments, reviews, checks,\n"
    "labels and releases. Of other repos and of accounts it may read a name\n"
    "and an id, and nothing beyond them. The list is `INSIDE` in\n"
    "broker/github_policy.py of the nixt3 repo.\n"
    "\n"
    "The REST API reads more of a listed repo, such as files and commits:\n"
    "\n"
    "    gh api repos/OWNER/REPO/contents/PATH\n"
    "    gh api repos/OWNER/REPO/commits/SHA\n"
    "\n"
    "If the task needs something else, tell the user what you were trying to\n"
    "read."
)


def _not_on_list(name: str, parent: str, place: str) -> _Refusal:
    if name in CLOSED_FIELDS:
        return _never(CLOSED_FIELDS[name])
    only = ONLY.get(place)
    what = f"the query asks for `{_show(name, 40)}` inside `{_show(parent, 40)}`"
    if only is not None and place not in ONE_OF:
        fields = ", ".join(f"`{field}`" for field in sorted(only - {"__typename", "totalCount"}))
        what += f". There, only these may be read: {fields}."
    else:
        what += ", which is not on the list of what may be read through GraphQL."
    return _Refusal("graphql-not-on-list", what, ASK_NOT_ON_LIST)


class _Check:
    """Goes through a GraphQL document and refuses what is not allowed.

    Each operation is followed from its start, through every fragment it
    uses, with the place it has reached kept track of. A fragment is looked
    at once for each place it is used in, and nothing about it is stored
    beyond that it was looked at, so a document cannot be made expensive by
    nesting fragments.
    """

    def __init__(self, document: _Document, variables: dict[str, object], policy: Policy) -> None:
        self.document = document
        self.variables = variables
        self.policy = policy
        self.steps = 0
        self.used: set[str] = set()
        self.repos: set[str] = set()

    def run(self) -> set[str]:
        """Check every operation. Returns the listed repos they are about."""
        for operation in self.document.operations:
            if operation.kind == "subscription":
                raise _unknown("GraphQL subscriptions are not passed on.")
            self.operation = operation
            self.starts = 0
            self.done: set[tuple[str, str]] = set()
            self.open: list[str] = []
            self.start(operation.selections, 1)
        if set(self.document.fragments) - self.used:
            # GitHub refuses these as well. Refusing them here means that
            # nothing in a request goes unread.
            raise _Syntax("a fragment is defined and not used")
        return self.repos

    def step(self, depth: int) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS or depth > MAX_DEPTH:
            raise _Syntax("too much to check")

    def fragment(self, name: str) -> _Fragment:
        fragment = self.document.fragments.get(name)
        if fragment is None:
            raise _Syntax("a fragment is used but not defined")
        if name in self.open:
            raise _Syntax("a fragment uses itself")
        self.used.add(name)
        return fragment

    def start(self, selections: list, depth: int) -> None:
        """The fields an operation starts at, with fragments opened up.

        `{ a ...F ... on Query { b } }` starts at `a`, at the fields of F and
        at `b`. Looking only at fields written out in place would be walked
        around by putting one in a fragment.
        """
        for selection in selections:
            self.step(depth)
            if isinstance(selection, _Field):
                self.starts += 1
                if self.starts > MAX_ROOT_FIELDS:
                    raise _Syntax("too many starts")
                if self.operation.kind == "mutation":
                    repo, place = _mutation(selection, self.operation, self.variables, self.policy)
                else:
                    repo, place = _query_start(selection, self.operation, self.variables, self.policy)
                if repo is not None:
                    self.repos.add(repo.full_name)
                self.inside(selection.selections, place, selection.name, depth + 1)
            elif isinstance(selection, _Inline):
                self.start(selection.selections, depth + 1)
            else:
                fragment = self.fragment(selection.name)
                if (selection.name, "") not in self.done:
                    self.done.add((selection.name, ""))
                    self.open.append(selection.name)
                    self.start(fragment.selections, depth + 1)
                    self.open.pop()

    def inside(self, selections: list, place: str, parent: str, depth: int) -> None:
        """Everything asked for at one place, and at the places it leads to."""
        for selection in selections:
            self.step(depth)
            if isinstance(selection, _Field):
                if selection.selections:
                    self.inside(
                        selection.selections,
                        self.step_to(place, selection.name, parent),
                        selection.name,
                        depth + 1,
                    )
                elif place != ANYTHING and selection.name != "__typename":
                    only = ONLY.get(place)
                    if only is not None and selection.name not in only:
                        raise _not_on_list(selection.name, parent, place)
            elif isinstance(selection, _Inline):
                self.inside(selection.selections, self.narrow(place, selection.on, parent), parent, depth + 1)
            else:
                fragment = self.fragment(selection.name)
                there = self.narrow(place, fragment.on, parent)
                if (selection.name, there) not in self.done:
                    self.done.add((selection.name, there))
                    self.open.append(selection.name)
                    self.inside(fragment.selections, there, parent, depth + 1)
                    self.open.pop()

    @staticmethod
    def step_to(place: str, name: str, parent: str) -> str:
        """Where the step `name` leads from `place`, or a refusal."""
        if place == ANYTHING:
            return ANYTHING
        there = INSIDE.get(place, {}).get(name)
        if there is None:
            raise _not_on_list(name, parent, place)
        return there

    @staticmethod
    def narrow(place: str, on: str | None, parent: str) -> str:
        """The place after `... on Type`.

        Only a place that can be one of several types moves. Anywhere else
        the fields are judged by the place they are in, whatever type the
        request claims for them, so a claim cannot unlock anything.
        """
        options = ONE_OF.get(place)
        if on is None or options is None:
            return place
        if on not in options:
            raise _not_on_list(f"... on {on}", parent, place)
        return options[on]


# The one change ("mutation") that is allowed, with the names in its input
# that hold the id of a repo. The first must be there, and each one that is
# there must be the id of a listed `write` repo. This is how `gh pr create`
# opens a pull request. It can be allowed because a repo's id can be trusted
# (see "Ids" above).
MUTATIONS: dict[str, tuple[str, ...]] = {
    "createPullRequest": ("repositoryId", "headRepositoryId"),
}

# Changes that name their target only by the id of a pull request, an issue,
# a comment, a review or a review thread. That id does not prove a repo (see
# "Ids" above), so each of these is refused, whatever id it is given.
#
# For each: the gh commands that send it, and the REST request that does the
# same job with the repo in its address, as a line the agent can run. None
# where GitHub has no such request.
BY_ID: dict[str, tuple[str, str | None]] = {
    # Comments, on pull requests and issues alike.
    "addComment": (
        "`gh pr comment` and `gh issue comment` send it",
        "gh api repos/OWNER/REPO/issues/NUMBER/comments -f body='TEXT'",
    ),
    "updateIssueComment": (
        "`gh pr comment --edit-last` sends it",
        "gh api -X PATCH repos/OWNER/REPO/issues/comments/COMMENT_ID -f body='TEXT'",
    ),
    "deleteIssueComment": (
        "`gh pr comment --delete-last` sends it",
        "gh api -X DELETE repos/OWNER/REPO/issues/comments/COMMENT_ID",
    ),
    # Pull requests.
    "updatePullRequest": (
        "`gh pr edit` sends it",
        "gh api -X PATCH repos/OWNER/REPO/pulls/NUMBER -f title='TITLE'",
    ),
    "closePullRequest": (
        "`gh pr close` sends it",
        "gh api -X PATCH repos/OWNER/REPO/pulls/NUMBER -f state=closed",
    ),
    "reopenPullRequest": (
        "`gh pr reopen` sends it",
        "gh api -X PATCH repos/OWNER/REPO/pulls/NUMBER -f state=open",
    ),
    "updatePullRequestBranch": ("`gh pr update-branch` sends it", None),
    "requestReviews": (
        "`gh pr edit --add-reviewer` and `gh pr create --reviewer` send it",
        "gh api repos/OWNER/REPO/pulls/NUMBER/requested_reviewers -f 'reviewers[]=LOGIN'",
    ),
    "requestReviewsByLogin": (
        "`gh pr edit --add-reviewer` and `gh pr create --reviewer` send it",
        "gh api repos/OWNER/REPO/pulls/NUMBER/requested_reviewers -f 'reviewers[]=LOGIN'",
    ),
    "markPullRequestReadyForReview": ("`gh pr ready` sends it", None),
    "convertPullRequestToDraft": ("`gh pr ready --undo` sends it", None),
    # Reviews.
    "addPullRequestReview": (
        "`gh pr review` sends it",
        "gh api repos/OWNER/REPO/pulls/NUMBER/reviews -f event=COMMENT -f body='TEXT'",
    ),
    "submitPullRequestReview": (
        "",
        "gh api repos/OWNER/REPO/pulls/NUMBER/reviews/REVIEW_ID/events -f event=COMMENT",
    ),
    "updatePullRequestReview": (
        "",
        "gh api -X PUT repos/OWNER/REPO/pulls/NUMBER/reviews/REVIEW_ID -f body='TEXT'",
    ),
    "deletePullRequestReview": (
        "",
        "gh api -X DELETE repos/OWNER/REPO/pulls/NUMBER/reviews/REVIEW_ID",
    ),
    "addPullRequestReviewThread": (
        "",
        "gh api repos/OWNER/REPO/pulls/NUMBER/comments -f body='TEXT' -f commit_id=SHA -f path=FILE -F line=LINE",
    ),
    "addPullRequestReviewThreadReply": (
        "",
        "gh api repos/OWNER/REPO/pulls/NUMBER/comments/COMMENT_ID/replies -f body='TEXT'",
    ),
    "updatePullRequestReviewComment": (
        "",
        "gh api -X PATCH repos/OWNER/REPO/pulls/comments/COMMENT_ID -f body='TEXT'",
    ),
    "deletePullRequestReviewComment": (
        "",
        "gh api -X DELETE repos/OWNER/REPO/pulls/comments/COMMENT_ID",
    ),
    "resolveReviewThread": ("", None),
    "unresolveReviewThread": ("", None),
    # Labels and reactions.
    "addLabelsToLabelable": (
        "`gh pr edit --add-label` sends it",
        "gh api repos/OWNER/REPO/issues/NUMBER/labels -f 'labels[]=LABEL'",
    ),
    "removeLabelsFromLabelable": (
        "`gh pr edit --remove-label` sends it",
        "gh api -X DELETE repos/OWNER/REPO/issues/NUMBER/labels/LABEL",
    ),
    "addReaction": (
        "",
        "gh api repos/OWNER/REPO/issues/NUMBER/reactions -f content=+1",
    ),
    "removeReaction": (
        "",
        "gh api -X DELETE repos/OWNER/REPO/issues/NUMBER/reactions/REACTION_ID",
    ),
    # Merging.
    "mergePullRequest": (
        "`gh pr merge` sends it",
        "gh api -X PUT repos/OWNER/REPO/pulls/NUMBER/merge",
    ),
    "enablePullRequestAutoMerge": ("`gh pr merge --auto` sends it", None),
    "disablePullRequestAutoMerge": ("`gh pr merge --disable-auto` sends it", None),
    "enqueuePullRequest": ("", None),
}
# More to say about some of them, after the line to run.
BY_ID_NOTES = {
    "updatePullRequest": (
        " To change the\ntext, use `-f body='TEXT'`, with the title or without it. What is left\n"
        "out stays as it is."
    ),
    "addReaction": (
        " That line is for\na pull request or an issue. For a comment on one:\n"
        "\n"
        "    gh api repos/OWNER/REPO/issues/comments/COMMENT_ID/reactions -f content=+1\n"
        "\n"
        "A comment on a line of code has its own address,\n"
        "`pulls/comments/COMMENT_ID/reactions`."
    ),
    "mergePullRequest": " This one also needs\n`merge: true` on the repo in the rules.",
}
# What to do where there is no REST request but there is another way.
BY_ID_INSTEAD = {
    "updatePullRequestBranch": (
        "Do it with git instead: fetch, merge the base branch into the pull\n"
        "request's branch, and push."
    ),
}

# Mutations that only assign, and the names under which other mutations can
# assign on the side. `agentAssignment` also holds the id of a repo for the
# agent to work in, which nothing here would check.
ASSIGNING = frozenset(
    {"addAssigneesToAssignable", "removeAssigneesFromAssignable", "replaceActorsForAssignable"}
)
ASSIGNING_INPUTS = ("assigneeIds", "assignees", "agentAssignment")

# Issues may be read and commented on, not created, edited or closed.
ISSUE_MUTATIONS = frozenset({"createIssue", "updateIssue", "closeIssue", "reopenIssue"})


def _by_id(name: str) -> _Refusal:
    """The refusal for a change that names its target only by an id."""
    sent_by, call = BY_ID[name]
    what = (
        f"the GraphQL mutation `{name}` names what it changes only by an id, "
        "and an id does not prove which repo that is in."
    )
    if sent_by:
        what += f" ({sent_by}.)"
    if name in BY_ID_INSTEAD:
        ask = f"{WHY_NOT_BY_ID} {BY_ID_INSTEAD[name]}"
        return _Refusal("graphql-by-id", what, ask, other_way=True)
    if call is None:
        return _Refusal("graphql-by-id", what, ASK_NO_REST)
    ask = ASK_REST.format(call=call, note=BY_ID_NOTES.get(name, ""))
    return _Refusal("graphql-by-id", what, ask, other_way=True)


def _malformed(what: str) -> _Refusal:
    return _fix("graphql-malformed", what)


def _graphql(headers: dict[str, list[str]], body: bytes, policy: Policy) -> Decision:
    """Decide about a GraphQL request.

    The body is `{"query": "...", "variables": {...}, "operationName": "..."}`.
    The `query` text may define several operations, of which GitHub runs the
    one named by `operationName`. Here every operation in the text has to
    pass, whichever one is picked, so there is nothing to gain from hiding a
    refused operation next to an allowed one.

    An allowed request is sent on with its body written out afresh from what
    was read here (`Decision.body`); see `_fresh` for why.
    """
    data = _json_object(headers, body)
    extra = set(data) - {"query", "variables", "operationName"}
    if extra:
        raise _malformed(
            f"the body has a part the broker does not know: `{_show(sorted(extra)[0], 40)}`. "
            "It takes `query`, `variables` and `operationName`."
        )
    text = data.get("query")
    if not isinstance(text, str) or not text.strip():
        raise _malformed("the body has no `query` text.")
    if len(text) > MAX_GRAPHQL:
        raise _malformed("the `query` text is longer than the broker reads.")
    variables = data.get("variables")
    if variables is None:
        variables = {}
    if not isinstance(variables, dict):
        raise _malformed("`variables` must be an object.")
    picked_name = data.get("operationName")
    if picked_name is not None and not isinstance(picked_name, str):
        raise _malformed("`operationName` must be text.")

    try:
        document = _Document(text)
        picked = _pick(document, picked_name)
        repo_names = _Check(document, variables, policy).run()
    except _Syntax:
        raise _malformed(
            "the `query` text is not a GraphQL request the broker can read, "
            "or it is far larger than the ones gh sends."
        ) from None

    clean: dict[str, object] = {"query": text}
    if data.get("variables") is not None:
        clean["variables"] = variables
    if picked_name is not None:
        clean["operationName"] = picked_name
    return Decision(
        allowed=True,
        kind="graphql-write" if picked.kind == "mutation" else "graphql-read",
        with_token=True,
        body=_fresh(clean),
        repo=next(iter(repo_names)) if len(repo_names) == 1 else None,
    )


def _pick(document: _Document, name: str | None) -> _Operation:
    """The operation GitHub will run."""
    if name is None:
        if len(document.operations) != 1:
            raise _Syntax("several operations and no operationName")
        return document.operations[0]
    for operation in document.operations:
        if operation.name == name:
            return operation
    raise _Syntax("operationName names no operation")


def _text_argument(
    field: _Field, name: str, operation: _Operation, variables: dict[str, object]
) -> str | None:
    """An argument's value when it is plain text, else None."""
    value = _resolve(field.arguments.get(name, _UNKNOWN), operation, variables)
    # `type(...) is str` leaves out bare words, which are not text.
    return value if type(value) is str else None


def _query_start(
    field: _Field,
    operation: _Operation,
    variables: dict[str, object],
    policy: Policy,
) -> tuple[Repo | None, str]:
    """Check where a query starts. Returns the listed repo it is about, if
    any, and the place in `INSIDE` that its fields are judged at."""
    name = field.name
    if name not in QUERY_STARTS:
        raise _Refusal(
            "graphql-query-not-allowed",
            f"a GraphQL query may not start at `{_show(name, 40)}`. It may "
            "start at `repository` with a listed repo, at `node`, `search`, "
            "`viewer` or `user`.",
            ASK_UNKNOWN,
        )

    if name == "repository":
        owner = _text_argument(field, "owner", operation, variables)
        repo_name = _text_argument(field, "name", operation, variables)
        if owner is None or repo_name is None:
            raise _malformed(
                "`repository` must be given its `owner` and `name` as plain "
                "text, written out or in `variables`."
            )
        repo = policy.find(owner, repo_name)
        if repo is None:
            # Other repos cannot be read here even with `read-public`:
            # GraphQL does not answer without a token, and with the token
            # this would read everything its owner can read.
            raise _Refusal(
                "repo-not-listed",
                f"{_show(owner, 40)}/{_show(repo_name, 100)} is not a repo "
                "the sandbox may use through GraphQL, which is what most gh "
                "commands use.",
                ASK_LIST,
            )
        return repo, "Repository"

    if name == "node":
        node_id = _resolve(field.arguments.get("id", _UNKNOWN), operation, variables)
        if _repo_number(node_id) is None:
            # Not a repo's id, so most likely the id of a pull request or a
            # comment, which proves nothing about the repo.
            raise _Refusal(
                "graphql-by-id",
                "the query asks for something by its id, and an id does not "
                "prove which repo that is in. Only a listed repo can be "
                "asked for by id.",
                ASK_READ_BY_NAME,
                other_way=True,
            )
        return _listed_repo(node_id, policy), "Repository"

    if name == "search":
        kind = _resolve(field.arguments.get("type", _UNKNOWN), operation, variables)
        if not isinstance(kind, str) or str(kind) not in SEARCH_TYPES:
            raise _Refusal(
                "graphql-search",
                "a GraphQL search may look for issues and pull requests only "
                "(type ISSUE).",
                ASK_UNKNOWN,
            )
        _search(_text_argument(field, "query", operation, variables), policy)
        return None, "SearchResultItemConnection"

    if name in ("viewer", "user"):
        return None, "Account"
    if name == "rateLimit":
        return None, "RateLimit"
    return None, ANYTHING


def _search(text: str | None, policy: Policy) -> None:
    """Keep a search for issues and pull requests to listed repos.

    A search names its repos in the search text: `repo:owner/name is:open`.
    The text must name at least one listed repo and no other, and must not
    use the parts of the search language that could widen it again: `OR`,
    `NOT`, a leading `-`, quotes (which turn `repo:` into words to look
    for), and `user:`, `org:` or `owner:`, which add all repos of an
    account.

    This follows GitHub's search language as it is documented. It is the
    weakest check in this module, and it is about reading only.
    """

    def refuse(what: str) -> _Refusal:
        return _Refusal("graphql-search", what, ASK_UNKNOWN)

    if text is None or len(text) > 1024:
        raise refuse("a search must be given its text as plain text of normal length.")
    if '"' in text or "'" in text or "|" in text or "-(" in text:
        raise refuse(
            "a search from the sandbox may not use quotes, `|` or a `-` "
            "before a bracket."
        )
    words = text.replace("(", " ( ").replace(")", " ) ").split()
    listed = 0
    for word in words:
        lower = word.lower()
        if lower in ("or", "and", "not", "-"):
            raise refuse(
                "a search from the sandbox may not use the words OR, AND or "
                "NOT, in capitals or not."
            )
        # "Holds", not "starts with": a word such as `+user:x` might still
        # be read as `user:x` by GitHub.
        if any(scope in lower for scope in ("user:", "org:", "owner:", "enterprise:")):
            raise refuse(
                "a search from the sandbox may not use `user:`, `org:` or "
                "`owner:`. Name the repo with `repo:owner/name`."
            )
        if "repo:" in lower:
            owner, _, name = lower[len("repo:") :].partition("/")
            if not lower.startswith("repo:") or policy.find(owner, name) is None:
                raise _Refusal(
                    "repo-not-listed",
                    "the search names a repo that the sandbox may not use, or "
                    "leaves one out with `-repo:`.",
                    ASK_LIST,
                )
            listed += 1
    if not listed:
        raise refuse(
            "a search must name a listed repo with `repo:owner/name`. "
            "`gh pr list --search` and `gh issue list --search` do that."
        )


def _mutation(
    field: _Field, operation: _Operation, variables: dict[str, object], policy: Policy
) -> tuple[Repo, str]:
    """Check a change. Returns the listed repo it is about, and the place
    in `INSIDE` that the fields of its answer are judged at."""
    name = field.name
    if name in ASSIGNING:
        raise _never("assignees")
    if name in ISSUE_MUTATIONS:
        raise _never("issues")
    if name in BY_ID:
        raise _by_id(name)
    keys = MUTATIONS.get(name)
    if keys is None:
        raise _Refusal(
            "graphql-mutation-not-allowed",
            f"the GraphQL mutation `{_show(name, 60)}` is not one the broker "
            "lets through. The one it lets through is `createPullRequest`, "
            "which `gh pr create` sends.",
            ASK_UNKNOWN,
        )
    given = _resolve(field.arguments.get("input", _UNKNOWN), operation, variables)
    if set(field.arguments) != {"input"} or not isinstance(given, dict):
        raise _malformed(f"`{name}` must be given one `input` object.")

    if any(given.get(key) for key in ASSIGNING_INPUTS):
        raise _never("assignees")

    if given.get(keys[0]) is None:
        raise _malformed(
            f"`{name}` does not say which repo it is about: its input has no "
            f"`{keys[0]}`."
        )
    repos = []
    for key in keys:
        if given.get(key) is None:
            continue
        found = _listed_repo(given[key], policy)
        if not found.write:
            raise _Refusal(
                "repo-read-only",
                f"{found.full_name} is listed for reading only.",
                ASK_WRITE,
            )
        repos.append(found)
    # The repo is proven. The branches must be plain names, or the pull
    # request could still take its branch from a repo that is not listed.
    _own_branch(given.get("headRefName"), "`headRefName`")
    _own_branch(given.get("baseRefName"), "`baseRefName`")
    return repos[0], "CreatePullRequestPayload"


ASK_OWN_BRANCH = (
    "A pull request from the sandbox takes its branch from the repo it is\n"
    "opened in, or from another repo listed with `access: write`. Push the\n"
    "branch to a listed repo, then open the pull request with the plain name\n"
    "of the branch."
)


def _own_branch(value: object, where: str) -> None:
    """Refuse a branch name that reaches into another repo.

    GitHub reads `someone:branch` as the branch in that account's fork. A
    pull request opened that way pulls a branch of an unlisted repo into a
    listed one, and by default gives the listed repo's maintainers the right
    to push to that branch. Which fork it would be cannot be told from the
    name, so the form is refused. Git does not allow a colon in a branch
    name, so no real branch is turned away.
    """
    if value is None:
        return
    if type(value) is not str or ":" in value:
        raise _Refusal(
            "head-elsewhere",
            f"{where} must be the plain name of a branch. The form "
            "`owner:branch` names a branch in another repo, which the broker "
            "cannot check.",
            ASK_OWN_BRANCH,
        )


def _pull_request_body(data: dict[str, object], owner: str, policy: Policy) -> None:
    """The same, for a pull request created or edited through the REST API."""
    _own_branch(data.get("head"), "`head`")
    _own_branch(data.get("base"), "`base`")
    other = data.get("head_repo")
    if other is not None:
        # The repo the branch is in, as `name` (same owner) or `owner/name`.
        there, slash, name = other.partition("/") if type(other) is str else ("", "", "")
        repo = policy.find(there, name) if slash else policy.find(owner, there)
        if type(other) is not str or repo is None or not repo.write:
            raise _Refusal(
                "head-elsewhere",
                "`head_repo` names a repo that is not listed with "
                "`access: write`, as the place the pull request's branch is "
                "in.",
                ASK_OWN_BRANCH,
            )
    if data.get("issue") is not None:
        # Turns an existing issue into the pull request.
        raise _never("issues")
