"""Tests for broker/github_policy.py: which GitHub requests are let through.

Run with `pytest tests/unit`. Nothing here touches the network or the VM.

The repos in these tests are made up. Four are listed in the rules:

    octo-org/app        write, with an id
    octo-org/library    read only, with an id
    octo-org/shipping   write and merge, with an id
    octo-org/no-id      write, but the rules hold no id for it

Everything else, such as other-org/secret, is a repo that is not listed.

About ids. GraphQL names things by ids, which hold numbers. A repo's id
holds the repo's number, and GitHub goes by it. The id of a thing inside a
repo (a pull request, an issue, a comment, a review) holds a repo's number
too, but GitHub ignores that number and finds the thing by its own. So such
an id only CLAIMS a repo. `claims()` below builds one, and no test may expect
anything to be allowed on the strength of it.
"""

import base64
import json
import re
import shlex
import sys
import time
import tracemalloc
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "broker"))

import github_policy as policy_module  # noqa: E402
from github_policy import PolicyError, decide, load_policy, wants_body  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

APP, LIBRARY, SHIPPING, OTHER = 1001, 1002, 1003, 9999


def node_id(kind: str, *numbers: int) -> str:
    """Build an id the way GitHub does: kind, underscore, packed numbers."""
    packed = bytes([0x90 + len(numbers) + 1, 0x00])
    for number in numbers:
        packed += b"\xce" + number.to_bytes(4, "big")
    return f"{kind}_{base64.urlsafe_b64encode(packed).decode().rstrip('=')}"


def old_repo_id(number: int) -> str:
    """A repo id of the older make-up, as repos from before 2021 have."""
    return base64.b64encode(f"010:Repository{number}".encode()).decode()


def rules(other_repos: str | None = None) -> dict:
    data: dict = {
        "repos": [
            {"repo": "octo-org/app", "note": "The app.", "access": "write", "id": node_id("R", APP)},
            {
                "repo": "octo-org/library",
                "note": "Read for reference.",
                "access": "read",
                "id": node_id("R", LIBRARY),
            },
            {
                "repo": "octo-org/shipping",
                "note": "The agent merges here.",
                "access": "write",
                "merge": True,
                "id": node_id("R", SHIPPING),
            },
            {"repo": "octo-org/no-id", "note": "No id given.", "access": "write"},
        ]
    }
    if other_repos is not None:
        data["other_repos"] = other_repos
    return data


POLICY = load_policy(rules())
PUBLIC = load_policy(rules("read-public"))

JSON = {"Content-Type": "application/json; charset=utf-8"}


def ask(method, url, body=None, *, policy=POLICY, headers=None, authority=None):
    """Ask about one request, written as a URL without the https://."""
    host, _, rest = url.partition("/")
    path, _, query = ("/" + rest).partition("?")
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
    elif isinstance(body, str):
        body = body.encode()
    return decide(
        method,
        host,
        path,
        query,
        body,
        policy,
        headers=JSON if headers is None else headers,
        authority=host if authority is None else authority,
    )


def gql(query, variables=None, operation=None, **options):
    """Ask about one GraphQL request."""
    body: dict = {"query": query}
    if variables is not None:
        body["variables"] = variables
    if operation is not None:
        body["operationName"] = operation
    return ask("POST", "api.github.com/graphql", body, **options)


def allowed(decision, kind=None, repo=None):
    assert decision.allowed, f"refused: {decision.reason}\n{decision.message}"
    assert decision.reason == "" and decision.message == ""
    if kind is not None:
        assert decision.kind == kind
    if repo is not None:
        assert decision.repo == repo
    return decision


def refused(decision, reason=None):
    assert not decision.allowed, f"allowed as {decision.kind}"
    assert decision.kind == "" and decision.body is None
    assert not decision.with_token
    assert decision.message.startswith("Refused by the sandbox broker: ")
    assert "broker/rules.yaml" in decision.message
    if reason is not None:
        assert decision.reason == reason, decision.message
    return decision


# ---------------------------------------------------------------------------
# The rules file
# ---------------------------------------------------------------------------


def test_rules_load():
    app = POLICY.find("octo-org", "app")
    assert app.write and not app.merge and app.number == APP
    assert not POLICY.find("octo-org", "library").write
    assert POLICY.find("octo-org", "shipping").merge
    assert POLICY.find("octo-org", "no-id").number is None
    assert POLICY.find("other-org", "secret") is None
    assert not POLICY.read_public and PUBLIC.read_public


def test_rules_ignore_case_in_names():
    assert POLICY.find("OCTO-org", "App").full_name == "octo-org/app"


def test_rules_accept_an_old_style_repo_id():
    loaded = load_policy(
        {"repos": [{"repo": "a/b", "note": "n", "access": "read", "id": old_repo_id(42)}]}
    )
    assert loaded.find("a", "b").number == 42


def test_rules_may_list_no_repos():
    assert load_policy({"repos": []}).repos == {}


def entry(**changes):
    base = {"repo": "a/b", "note": "n", "access": "read"}
    base.update(changes)
    return {key: value for key, value in base.items() if value is not ...}


@pytest.mark.parametrize(
    ("data", "says"),
    [
        (None, "must have a `repos:` list"),
        ([], "must have a `repos:` list"),
        ({}, "must be a list"),
        ({"repos": {}}, "must be a list"),
        ({"repos": [], "repo": []}, "unknown key `repo`"),
        ({"repos": [], "other_repos": "allow"}, "`refuse` or `read-public`"),
        ({"repos": [], "other_repos": True}, "`refuse` or `read-public`"),
        ({"repos": ["a/b"]}, "must have a `repo`"),
        ({"repos": [entry(repo=...)]}, "has no `repo`"),
        ({"repos": [entry(repo=5)]}, "has no `repo`"),
        ({"repos": [entry(acess="read")]}, "unknown key `acess`"),
        ({"repos": [entry(repo="just-a-name")]}, "owner/name"),
        ({"repos": [entry(repo="a/b/c")]}, "owner/name"),
        ({"repos": [entry(repo="a/*")]}, "wildcard"),
        ({"repos": [entry(repo="*/b")]}, "wildcard"),
        ({"repos": [entry(repo="https://github.com/a/b")]}, "owner/name"),
        ({"repos": [entry(repo="a/..")]}, "owner/name"),
        ({"repos": [entry(repo="-a/b")]}, "owner/name"),
        ({"repos": [entry(repo="a b/c")]}, "owner/name"),
        ({"repos": [entry(repo="a/b.git")]}, "without the `.git`"),
        ({"repos": [entry(), entry(repo="A/B")]}, "listed twice"),
        ({"repos": [entry(note=...)]}, "has no `note`"),
        ({"repos": [entry(note="  ")]}, "has no `note`"),
        ({"repos": [entry(access=...)]}, "`read` or `write`"),
        ({"repos": [entry(access="admin")]}, "`read` or `write`"),
        ({"repos": [entry(access=True)]}, "`read` or `write`"),
        ({"repos": [entry(access="write", merge="yes")]}, "true or false"),
        ({"repos": [entry(access="write", merge=1)]}, "true or false"),
        ({"repos": [entry(merge=True)]}, "needs `access: write`"),
        ({"repos": [entry(id=12345)]}, "not a repo id"),
        ({"repos": [entry(id="R_notanid")]}, "not a repo id"),
        ({"repos": [entry(id=node_id("PR", 1, 2))]}, "not a repo id"),
        ({"repos": [entry(id=node_id("U", 7))]}, "not a repo id"),
        (
            {"repos": [entry(id=node_id("R", 7)), entry(repo="c/d", id=old_repo_id(7))]},
            "same `id`",
        ),
    ],
)
def test_rules_with_a_mistake_are_rejected(data, says):
    with pytest.raises(PolicyError) as error:
        load_policy(data)
    assert says in str(error.value)


def test_rules_error_names_the_entry_and_how_to_fix_it():
    with pytest.raises(PolicyError) as error:
        load_policy({"repos": [entry(), entry(repo="c/d", id="nope")]})
    assert "github repo 2 (c/d)" in str(error.value)
    assert "gh repo view c/d --json id" in str(error.value)


# ---------------------------------------------------------------------------
# git over HTTPS
# ---------------------------------------------------------------------------

FETCH = [
    ("GET", "github.com/octo-org/app/info/refs?service=git-upload-pack"),
    ("POST", "github.com/octo-org/app/git-upload-pack"),
]
PUSH = [
    ("GET", "github.com/octo-org/app/info/refs?service=git-receive-pack"),
    ("POST", "github.com/octo-org/app/git-receive-pack"),
]


@pytest.mark.parametrize(("method", "url"), FETCH)
def test_git_fetch_from_a_listed_repo(method, url):
    decision = allowed(ask(method, url), "git-read", "octo-org/app")
    assert decision.with_token and decision.body is None


@pytest.mark.parametrize(("method", "url"), PUSH)
def test_git_push_to_a_write_repo(method, url):
    assert allowed(ask(method, url), "git-write", "octo-org/app").with_token


@pytest.mark.parametrize(("method", "url"), FETCH)
def test_git_fetch_from_a_read_repo(method, url):
    allowed(ask(method, url.replace("/app/", "/library/")), "git-read", "octo-org/library")


@pytest.mark.parametrize(("method", "url"), PUSH)
def test_git_push_to_a_read_repo_is_refused(method, url):
    refused(ask(method, url.replace("/app/", "/library/")), "repo-read-only")


@pytest.mark.parametrize(("method", "url"), FETCH + PUSH)
def test_git_to_an_unlisted_repo_is_refused(method, url):
    decision = refused(ask(method, url.replace("octo-org/app", "other-org/secret")), "repo-not-listed")
    assert "other-org/secret" in decision.message
    assert "tell the user" in decision.message


@pytest.mark.parametrize(("method", "url"), FETCH)
def test_git_fetch_from_an_unlisted_repo_goes_without_the_token(method, url):
    decision = allowed(
        ask(method, url.replace("octo-org/app", "other-org/public"), policy=PUBLIC), "git-read"
    )
    assert not decision.with_token and decision.repo is None


@pytest.mark.parametrize(("method", "url"), PUSH)
def test_git_push_to_an_unlisted_repo_is_refused_even_when_reading_is_allowed(method, url):
    refused(ask(method, url.replace("octo-org/app", "other-org/public"), policy=PUBLIC), "repo-not-listed")


def test_git_body_is_not_needed():
    # A push can be gigabytes. The decision is made without it.
    assert not wants_body("github.com")
    allowed(ask("POST", "github.com/octo-org/app/git-receive-pack", None, headers={}), "git-write")
    allowed(
        ask(
            "POST",
            "github.com/octo-org/app/git-upload-pack",
            b"\x1f\x8b not json",
            headers={
                "Content-Type": "application/x-git-upload-pack-request",
                "Content-Encoding": "gzip",
            },
        ),
        "git-read",
    )


@pytest.mark.parametrize(
    "name",
    ["app.git", "APP", "App.git"],
)
def test_git_repo_name_spellings_that_mean_the_same_repo(name):
    allowed(ask("POST", f"github.com/OCTO-ORG/{name}/git-receive-pack"), "git-write", "octo-org/app")


@pytest.mark.parametrize(
    "name",
    [
        "app.wiki.git",  # the repo's wiki: another place to push to
        "app.wiki",
        "app.git.git",
        "app.GIT",
        "app.",
        "app-2",
        ".git",
    ],
)
def test_git_repo_names_that_are_not_the_listed_repo(name):
    decision = ask("POST", f"github.com/octo-org/{name}/git-receive-pack")
    assert not decision.allowed
    assert decision.reason in ("repo-not-listed", "path-odd")


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("GET", "github.com/octo-org/app/info/refs"),  # the old "dumb" protocol
        ("GET", "github.com/octo-org/app/info/refs?service=git-upload-archive"),
        ("GET", "github.com/octo-org/app/info/refs?service=git-upload-pack&service=git-receive-pack"),
        ("GET", "github.com/octo-org/app/info/refs?service=git-receive-pack&x=1"),
        ("GET", "github.com/octo-org/app/info/refs?SERVICE=git-upload-pack"),
        ("GET", "github.com/octo-org/app/info/refs?service=git%2Dupload%2Dpack"),
        ("HEAD", "github.com/octo-org/app/info/refs?service=git-upload-pack"),
        ("POST", "github.com/octo-org/app/info/refs?service=git-upload-pack"),
        ("GET", "github.com/octo-org/app/git-upload-pack"),
        ("PUT", "github.com/octo-org/app/git-receive-pack"),
        ("POST", "github.com/octo-org/app/git-upload-pack?service=git-receive-pack"),
        ("POST", "github.com/octo-org/app/git-upload-archive"),
        ("GET", "github.com/octo-org/app/HEAD"),
        ("GET", "github.com/octo-org/app/objects/info/packs"),
        ("GET", "github.com/octo-org/app"),  # the website
        ("GET", "github.com/octo-org/app/pull/1"),
        ("GET", "github.com/octo-org/app/archive/refs/heads/main.tar.gz"),
        ("GET", "github.com/octo-org/app/releases/download/v1/tool"),
        ("POST", "github.com/login/oauth/access_token"),
        ("POST", "github.com/login/device/code"),
        ("GET", "github.com/"),
        ("POST", "github.com/git-receive-pack"),
        ("POST", "github.com/octo-org/git-receive-pack"),
        ("POST", "github.com/octo-org/app/extra/git-receive-pack"),
        ("POST", "github.com/graphql"),
        ("GET", "github.com/repos/octo-org/app"),
    ],
)
def test_github_com_passes_on_git_and_nothing_else(method, url):
    refused(ask(method, url), "not-recognised")


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("POST", "github.com/octo-org/app.git/info/lfs/objects/batch"),
        ("POST", "github.com/octo-org/app/info/lfs/locks"),
        ("GET", "github.com/octo-org/app.git/info/lfs/locks"),
    ],
)
def test_git_lfs_is_refused_with_its_own_reason(method, url):
    assert "LFS" in refused(ask(method, url, {}), "git-lfs").message


# ---------------------------------------------------------------------------
# The REST API: reading
# ---------------------------------------------------------------------------

READS = [
    "",
    "/pulls",
    "/pulls?state=open&per_page=100",
    "/pulls/1",
    "/pulls/1/files",
    "/pulls/1/commits",
    "/pulls/1/comments",
    "/pulls/1/reviews",
    "/pulls/comments/5",
    "/issues",
    "/issues/7",
    "/issues/7/comments",
    "/issues/7/timeline",
    "/commits",
    "/commits/main",
    "/commits/main/status",
    "/commits/main/check-runs",
    "/commits/0123abc/check-suites",
    "/check-runs/9",
    "/check-suites/9/check-runs",
    "/statuses/0123abc",
    "/branches",
    "/branches/main",
    "/branches/feature/with/slashes",
    "/git/ref/heads/main",
    "/git/trees/main?recursive=1",
    "/contents/README.md",
    "/contents/docs/my%20notes.md?ref=main",
    "/compare/main...feature",
    "/readme",
    "/tags",
    "/releases",
    "/releases/latest",
    "/labels",
    "/milestones",
    "/languages",
    "/tarball/main",
    "/actions/runs",
    "/actions/runs?exclude_pull_requests=true&per_page=1",
    "/actions/runs/3/jobs",
    "/actions/runs/3/logs",
    "/actions/jobs/4/logs",
    "/actions/workflows",
    "/actions/artifacts",
]


@pytest.mark.parametrize("rest", READS)
@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_reading_a_listed_repo(method, rest):
    decision = allowed(ask(method, f"api.github.com/repos/octo-org/app{rest}"), "api-read", "octo-org/app")
    assert decision.with_token and decision.body is None
    allowed(ask(method, f"api.github.com/repos/octo-org/library{rest}"), "api-read", "octo-org/library")


@pytest.mark.parametrize("rest", READS)
def test_reading_an_unlisted_repo_is_refused(rest):
    refused(ask("GET", f"api.github.com/repos/other-org/secret{rest}"), "repo-not-listed")


@pytest.mark.parametrize("rest", READS)
def test_reading_an_unlisted_repo_goes_without_the_token(rest):
    decision = allowed(ask("GET", f"api.github.com/repos/other-org/public{rest}", policy=PUBLIC), "api-read")
    assert not decision.with_token and decision.repo is None


def test_reading_a_listed_repo_keeps_the_token_when_others_are_public_only():
    assert allowed(ask("GET", "api.github.com/repos/octo-org/library", policy=PUBLIC)).with_token


@pytest.mark.parametrize(
    ("rest", "reason"),
    [
        ("/actions/secrets", "secrets"),
        ("/actions/secrets/public-key", "secrets"),
        ("/actions/secrets/DEPLOY_KEY", "secrets"),
        ("/actions/variables", "secrets"),
        ("/actions/variables/REGION", "secrets"),
        ("/actions/organization-secrets", "secrets"),
        ("/actions/organization-variables", "secrets"),
        ("/dependabot/secrets", "secrets"),
        ("/codespaces/secrets", "secrets"),
        ("/environments/production/secrets", "secrets"),
        ("/environments/production/variables/REGION", "secrets"),
        ("/secret-scanning/alerts", "secrets"),
        ("/keys", "deploy-keys"),
        ("/keys/1", "deploy-keys"),
        ("/hooks", "webhooks"),
        ("/hooks/1/deliveries", "webhooks"),
        ("/collaborators", "collaborators"),
        ("/collaborators/someone/permission", "collaborators"),
        ("/invitations", "collaborators"),
        ("/teams", "collaborators"),
        # Who an issue can be assigned to is the list of who can push.
        ("/assignees", "collaborators"),
        ("/assignees/someone", "collaborators"),
        # A branch's protection names the people and teams who may push.
        ("/branches/main/protection", "branch-protection"),
        ("/branches/main/protection/restrictions", "branch-protection"),
        ("/branches/main/protection/restrictions/users", "branch-protection"),
        ("/branches/main/protection/restrictions/teams", "branch-protection"),
        ("/branches/main/protection/required_pull_request_reviews", "branch-protection"),
        ("/branches/release/1.x/protection/restrictions/users", "branch-protection"),
    ],
)
@pytest.mark.parametrize("method", ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("used", [POLICY, PUBLIC])
def test_parts_of_a_repo_that_are_closed_even_for_reading(method, rest, reason, used):
    body = None if method in ("GET", "HEAD") else {}
    for repo in ("octo-org/app", "other-org/public"):
        decision = refused(ask(method, f"api.github.com/repos/{repo}{rest}", body, policy=used), reason)
        assert "No rule allows this" in decision.message


@pytest.mark.parametrize(
    "rest",
    [
        "/actions/runners",
        "/actions/permissions",
        "/actions/caches",
        "/actions/oidc/customization/sub",
        "/actions",
        "/traffic/clones",
        "/dependabot/alerts",
        "/code-scanning/alerts",
        "/security-advisories",
        "/environments",
        "/pages",
        "/rulesets",
        "/stats/contributors",
        "/something-new",
    ],
)
def test_parts_of_a_repo_that_are_not_on_the_reading_list(rest):
    refused(ask("GET", f"api.github.com/repos/octo-org/app{rest}"), "not-recognised")


# ---------------------------------------------------------------------------
# The REST API: changing
# ---------------------------------------------------------------------------

WRITES = [
    ("POST", "/pulls"),
    ("PATCH", "/pulls/1"),
    ("POST", "/pulls/1/comments"),
    ("POST", "/pulls/1/comments/5/replies"),
    ("PATCH", "/pulls/comments/5"),
    ("DELETE", "/pulls/comments/5"),
    ("POST", "/pulls/1/reviews"),
    ("PUT", "/pulls/1/reviews/8"),
    ("DELETE", "/pulls/1/reviews/8"),
    ("POST", "/pulls/1/reviews/8/events"),
    ("POST", "/pulls/1/requested_reviewers"),
    ("DELETE", "/pulls/1/requested_reviewers"),
    ("POST", "/issues/7/comments"),
    ("PATCH", "/issues/comments/5"),
    ("DELETE", "/issues/comments/5"),
    ("POST", "/issues/7/labels"),
    ("PUT", "/issues/7/labels"),
    ("DELETE", "/issues/7/labels"),
    ("DELETE", "/issues/7/labels/bug"),
    ("POST", "/issues/7/reactions"),
    ("DELETE", "/issues/7/reactions/3"),
    ("POST", "/issues/comments/5/reactions"),
    ("POST", "/pulls/comments/5/reactions"),
    ("DELETE", "/git/refs/heads/my-branch"),
    ("DELETE", "/git/refs/heads/feature/with/slashes"),
]


@pytest.mark.parametrize(("method", "rest"), WRITES)
def test_changes_allowed_in_a_write_repo(method, rest):
    for body in ({"title": "x"}, b""):
        decision = allowed(ask(method, f"api.github.com/repos/octo-org/app{rest}", body), "api-write", "octo-org/app")
        assert decision.with_token


@pytest.mark.parametrize(("method", "rest"), WRITES)
def test_changes_are_refused_in_a_read_repo(method, rest):
    decision = refused(ask(method, f"api.github.com/repos/octo-org/library{rest}", {}), "repo-read-only")
    assert "access: write" in decision.message


@pytest.mark.parametrize(("method", "rest"), WRITES)
@pytest.mark.parametrize("used", [POLICY, PUBLIC])
def test_changes_are_refused_in_an_unlisted_repo(method, rest, used):
    refused(ask(method, f"api.github.com/repos/other-org/public{rest}", {}, policy=used), "repo-not-listed")


def test_merging_needs_the_merge_switch():
    url = "api.github.com/repos/octo-org/{}/pulls/1/merge"
    allowed(ask("PUT", url.format("shipping"), {}), "api-write", "octo-org/shipping")
    assert "merge: true" in refused(ask("PUT", url.format("app"), {}), "merge").message
    refused(ask("PUT", url.format("library"), {}), "repo-read-only")
    refused(ask("PUT", url.format("elsewhere"), {}), "repo-not-listed")
    # The other ways to merge through the API stay closed.
    refused(ask("PUT", url.format("shipping") + "-async", {}), "merge-api")
    refused(ask("POST", "api.github.com/repos/octo-org/shipping/merges", {}), "merge-api")
    refused(ask("POST", "api.github.com/repos/octo-org/shipping/merge-upstream", {}), "merge-api")


@pytest.mark.parametrize(
    ("method", "rest", "reason"),
    [
        # Named in the plan: settings, secrets, deletion.
        ("PATCH", "", "repo-settings"),  # also how visibility is changed
        ("PUT", "", "repo-settings"),
        ("POST", "", "repo-settings"),
        ("DELETE", "", "repo-deletion"),
        ("PUT", "/actions/secrets/DEPLOY_KEY", "secrets"),
        ("POST", "/actions/variables", "secrets"),
        # What the threat adds.
        ("POST", "/transfer", "repo-transfer"),
        ("POST", "/forks", "forks"),
        ("POST", "/generate", "repo-creation"),
        ("POST", "/keys", "deploy-keys"),
        ("POST", "/hooks", "webhooks"),
        ("PATCH", "/hooks/1", "webhooks"),
        ("PUT", "/collaborators/someone", "collaborators"),
        ("DELETE", "/invitations/1", "collaborators"),
        ("PUT", "/branches/main/protection", "branch-protection"),
        ("DELETE", "/branches/main/protection", "branch-protection"),
        ("POST", "/branches/main/rename", "branch-protection"),
        ("POST", "/rulesets", "branch-protection"),
        ("DELETE", "/rulesets/1", "branch-protection"),
        ("POST", "/releases", "releases"),
        ("PATCH", "/releases/1", "releases"),
        ("DELETE", "/releases/assets/1", "releases"),
        ("POST", "/actions/workflows/ci.yml/dispatches", "actions"),
        ("POST", "/actions/runs/3/rerun", "actions"),
        ("POST", "/actions/runs/3/cancel", "actions"),
        ("DELETE", "/actions/runs/3/logs", "actions"),
        ("PUT", "/actions/permissions", "actions"),
        ("POST", "/actions/runners/registration-token", "actions"),
        ("POST", "/dispatches", "actions"),
        ("POST", "/statuses/0123abc", "checks"),  # would fake a green test run
        ("POST", "/check-runs", "checks"),
        ("PUT", "/contents/README.md", "git-data"),
        ("DELETE", "/contents/README.md", "git-data"),
        ("POST", "/git/refs", "git-data"),
        ("PATCH", "/git/refs/heads/main", "git-data"),
        ("DELETE", "/git/refs/tags/v1", "git-data"),
        ("DELETE", "/git/refs/heads", "git-data"),
        ("POST", "/git/blobs", "git-data"),
        ("POST", "/git/commits", "git-data"),
        ("PUT", "/topics", "repo-settings"),
        ("POST", "/pages", "repo-settings"),
        ("PUT", "/environments/production", "repo-settings"),
        # The branch it would write to may be in another repo.
        ("PUT", "/pulls/1/update-branch", "merge-api"),
        ("POST", "/issues/7/assignees", "assignees"),
        ("DELETE", "/issues/7/assignees", "assignees"),
        # Issues are for reading and commenting.
        ("POST", "/issues", "issues"),
        ("PATCH", "/issues/7", "issues"),
        ("DELETE", "/issues/7", "issues"),
        ("PUT", "/vulnerability-alerts", "repo-settings"),
        ("PUT", "/interaction-limits", "repo-settings"),
        ("PATCH", "/properties/values", "repo-settings"),
        # Not known, so refused.
        ("PUT", "/issues/7/lock", "not-recognised"),
        ("PUT", "/pulls/1/reviews/8/dismissals", "not-recognised"),
        ("POST", "/pulls/1/codespaces", "not-recognised"),
        ("DELETE", "/pulls/1", "not-recognised"),
        ("POST", "/labels", "not-recognised"),
        ("DELETE", "/labels/bug", "not-recognised"),
        ("POST", "/commits/0123abc/comments", "not-recognised"),
        ("POST", "/deployments", "not-recognised"),
        ("PUT", "/subscription", "not-recognised"),
        ("POST", "/something-new", "not-recognised"),
        ("POST", "/pulls/x", "not-recognised"),
        ("PATCH", "/pulls/0", "not-recognised"),
        ("PATCH", "/pulls/1/", "path-odd"),
        ("PATCH", "/pulls/-1", "not-recognised"),
        ("PATCH", "/pulls/1e3", "not-recognised"),
    ],
)
@pytest.mark.parametrize("repo", ["octo-org/app", "octo-org/shipping", "other-org/public"])
def test_changes_refused_on_every_repo(method, rest, reason, repo):
    refused(ask(method, f"api.github.com/repos/{repo}{rest}", {}, policy=PUBLIC), reason)


# ---------------------------------------------------------------------------
# The REST API: what is not tied to a repo
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["", "user", "rate_limit", "meta", "versions"])
@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_the_few_requests_about_the_api_itself(method, path):
    assert allowed(ask(method, f"api.github.com/{path}"), "api-read").with_token


@pytest.mark.parametrize(
    ("method", "path", "reason"),
    [
        ("POST", "user/repos", "repo-creation"),
        ("POST", "orgs/octo-org/repos", "repo-creation"),
        ("GET", "user/repos", "account"),
        ("PATCH", "user", "account"),
        ("GET", "user/emails", "account"),
        ("POST", "user/keys", "account"),
        ("POST", "user/gpg_keys", "account"),
        ("GET", "user/installations", "account"),
        ("PUT", "user/starred/other-org/public", "account"),
        ("GET", "user/1", "account"),
        ("GET", "gists", "gists"),
        ("POST", "gists", "gists"),
        ("PATCH", "gists/abc123", "gists"),
        ("GET", "gists/public", "gists"),
        ("GET", "orgs/octo-org", "organizations"),
        ("GET", "orgs/octo-org/repos", "organizations"),
        ("PUT", "orgs/octo-org/actions/secrets/X", "organizations"),
        ("GET", "organizations", "organizations"),
        ("GET", "search/issues?q=repo%3Aocto-org%2Fapp+is%3Apr", "search"),
        ("GET", "search/code?q=password", "search"),
        ("GET", "search/repositories?q=x", "search"),
        # The same repo under its number instead of its name.
        ("GET", "repositories/1001", "repo-by-id"),
        ("DELETE", "repositories/1001", "repo-by-id"),
        ("GET", "repositories/1001/pulls", "repo-by-id"),
        ("GET", "repositories", "repo-by-id"),
        ("GET", "users/someone", "not-recognised"),
        ("GET", "notifications", "not-recognised"),
        ("POST", "markdown", "not-recognised"),
        ("GET", "repos", "not-recognised"),
        ("GET", "repos/octo-org", "not-recognised"),
        ("GET", "app/installations", "not-recognised"),
        ("GET", "enterprises/x/teams", "not-recognised"),
        ("DELETE", "", "not-recognised"),
        ("POST", "rate_limit", "not-recognised"),
        ("GET", "graphql", "not-recognised"),
        ("PUT", "graphql", "not-recognised"),
        ("POST", "graphql/extra", "not-recognised"),
    ],
)
@pytest.mark.parametrize("used", [POLICY, PUBLIC])
def test_requests_not_tied_to_a_repo_are_refused(method, path, reason, used):
    body = None if method == "GET" else {}
    refused(ask(method, f"api.github.com/{path}", body, policy=used), reason)


# ---------------------------------------------------------------------------
# What attackers try: paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/repos/OCTO-ORG/APP/pulls/1",
        "/repos/Octo-Org/App",
    ],
)
def test_upper_and_lower_case_name_the_same_repo(path):
    allowed(ask("GET", "api.github.com" + path), "api-read", "octo-org/app")


def test_upper_and_lower_case_do_not_hide_an_unlisted_repo():
    refused(ask("GET", "api.github.com/repos/OTHER-ORG/SECRET"), "repo-not-listed")
    refused(ask("POST", "github.com/Other-Org/Secret.git/git-receive-pack"), "repo-not-listed")


@pytest.mark.parametrize(
    "path",
    [
        # Doubled and trailing slashes.
        "//repos/octo-org/app",
        "/repos//octo-org/app",
        "/repos/octo-org//app",
        "/repos/octo-org/app/",
        "/repos/octo-org/app//pulls",
        "/repos/octo-org/app/pulls/",
        # Dot parts, plain and encoded.
        "/repos/octo-org/app/../../other-org/secret",
        "/repos/octo-org/app/./pulls",
        "/repos/octo-org/app/contents/../actions/secrets",
        "/repos/octo-org/app/contents/%2e%2e/actions/secrets",
        "/repos/octo-org/app/contents/%2E%2E/%2E%2E/hooks",
        "/repos/octo-org/app/contents/.%2e/hooks",
        "/repos/octo-org/app/contents/%2e",
        "/repos/other-org/secret/../../octo-org/app",
        "/repos/octo-org/..",
        # Encoded slashes and backslashes, which some servers decode late.
        "/repos/octo-org/app/contents/..%2f..%2fhooks",
        "/repos/octo-org/app/contents/a%2Fb",
        "/repos/octo-org/app/contents/a%5cb",
        "/repos/octo-org/app\\pulls",
        "/repos/octo-org%2Fapp",
        "/repos%2Focto-org%2Fapp",
        # Encoded twice.
        "/repos/octo-org/app/contents/%252e%252e/hooks",
        "/repos/octo-org/app/contents/%25",
        # Broken encodings and control characters.
        "/repos/octo-org/app/contents/%",
        "/repos/octo-org/app/contents/%zz",
        "/repos/octo-org/app/contents/%2",
        "/repos/octo-org/app/contents/%00",
        "/repos/octo-org/app/contents/a%0d%0ab",
        "/repos/octo-org/app/contents/%ff",
        "/repos/octo-org/app/contents/a b",
        "/repos/octo-org/app/contents/a\tb",
        "/repos/octo-org/app/contents/café",
        "/repos/octo-org/app\x00",
        "/repos/octo-org/app\n",
        # Things that are not a path.
        "repos/octo-org/app",
        "",
        "https://api.github.com/repos/octo-org/app",
        "/repos/octo-org/app#x",
        "/repos/octo-org/app?x",
        "/" + "a" * 5000,
        # Owner and repo names GitHub could not have issued.
        "/repos/octo-org/app%00",
        "/repos/octo_org/app",
        "/repos/-octo-org/app",
        "/repos/octo-org/app;x",
        "/repos/octo-org/app,other",
        "/repos/octo-org/a:b",
        "/repos/" + "a" * 40 + "/app",
        "/repos/octo-org/" + "a" * 101,
    ],
)
@pytest.mark.parametrize("host", ["api.github.com", "github.com"])
def test_paths_in_an_odd_spelling_are_refused(host, path):
    for method in ("GET", "DELETE"):
        decision = decide(
            method, host, path, "", None if method == "GET" else b"", POLICY, headers=JSON, authority=host
        )
        assert not decision.allowed
        # Never because the odd spelling was read as a listed repo.
        assert decision.reason in ("path-odd", "not-recognised", "repo-not-listed"), decision.reason


@pytest.mark.parametrize(
    "path",
    [
        # Keywords with a letter encoded: "pulls", "repos", "octo-org", "app".
        "/repos/octo-org/app/%70ulls",
        "/%72epos/octo-org/app",
        "/repos/%6fcto-org/app",
        "/repos/octo-org/%61pp",
        "/repos/octo-org/app/actions/%73ecrets",
        "/REPOS/octo-org/app",
        "/Repos/octo-org/app",
        "/repos/octo-org/app/PULLS",
        "/repos/octo-org/app.git",
        "/repos/octo-org/app.git/pulls",
    ],
)
def test_encoded_or_respelled_keywords_match_nothing(path):
    assert not ask("GET", "api.github.com" + path).allowed
    assert not ask("PATCH", "api.github.com" + path, {}).allowed
    # With reading of other repos allowed, a respelled name is at most one
    # more unlisted repo: read without the token, and never written to.
    public = ask("GET", "api.github.com" + path, policy=PUBLIC)
    assert not (public.allowed and public.with_token)
    assert not ask("PATCH", "api.github.com" + path, {}, policy=PUBLIC).allowed


def test_an_encoded_secrets_path_is_not_readable_as_something_else():
    for path in ("/repos/octo-org/app/actions/%73ecrets", "/repos/octo-org/app/%61ctions/secrets"):
        assert not ask("GET", "api.github.com" + path, policy=PUBLIC).allowed


@pytest.mark.parametrize(
    ("owner", "name"),
    [
        ("repos", "repos"),
        ("user", "gists"),
        ("graphql", "graphql"),
        ("search", "issues"),
        ("octo-org", "pulls"),
        ("octo-org", "info"),
        ("info", "refs"),
        ("octo-org", "git-receive-pack"),
        ("login", "oauth"),
    ],
)
def test_a_repo_named_like_an_api_word_is_still_just_a_repo(owner, name):
    refused(ask("GET", f"api.github.com/repos/{owner}/{name}"), "repo-not-listed")
    refused(ask("DELETE", f"api.github.com/repos/{owner}/{name}", b""), "repo-deletion")
    refused(ask("POST", f"github.com/{owner}/{name}/git-receive-pack"), "repo-not-listed")
    refused(ask("POST", f"github.com/{owner}/{name}.git/git-receive-pack"), "repo-not-listed")

    listed = load_policy({"repos": [{"repo": f"{owner}/{name}", "note": "n", "access": "write"}]})
    allowed(ask("GET", f"api.github.com/repos/{owner}/{name}/pulls", policy=listed), "api-read")
    allowed(ask("POST", f"github.com/{owner}/{name}/git-receive-pack", policy=listed), "git-write")
    # Listing it opens that repo and nothing that shares its words.
    refused(ask("GET", f"api.github.com/{owner}/{name}", policy=listed))
    refused(ask("POST", "api.github.com/user/repos", {}, policy=listed), "repo-creation")
    refused(ask("POST", "api.github.com/gists", {}, policy=listed), "gists")


def test_a_repo_path_that_only_looks_like_a_git_request():
    # The owner is "octo-org", the repo is "info", and "refs" is not git.
    refused(ask("GET", "github.com/octo-org/info/refs?service=git-upload-pack"), "not-recognised")
    # A listed repo's name as the owner of another.
    refused(ask("POST", "github.com/app/octo-org/git-receive-pack"), "repo-not-listed")
    refused(ask("POST", "github.com/other-org/app/git-receive-pack"), "repo-not-listed")
    refused(ask("POST", "github.com/octo-org/app/octo-org/app/git-receive-pack"), "not-recognised")


@pytest.mark.parametrize(
    "query",
    [
        "_method=DELETE",
        "x=1&_method=delete",
        "_METHOD=PUT",
        "%5Fmethod=DELETE",
        "_method",
    ],
)
def test_a_method_override_in_the_query_is_refused(query):
    refused(ask("GET", f"api.github.com/repos/octo-org/app?{query}"), "method-override")
    refused(ask("POST", f"api.github.com/repos/octo-org/app/pulls?{query}", {}), "method-override")


@pytest.mark.parametrize("query", ["x=%", "x=%zz", "a b", "x=é", "x=1#frag", "x=" + "a" * 9000])
def test_an_odd_query_is_refused(query):
    decision = decide(
        "GET", "api.github.com", "/repos/octo-org/app/pulls", query, None, POLICY,
        headers=JSON, authority="api.github.com",
    )
    refused(decision, "query-odd")


# ---------------------------------------------------------------------------
# What attackers try: methods, hosts and headers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method",
    ["OPTIONS", "TRACE", "CONNECT", "PROPFIND", "get", "Get", "delete", "GET ", " GET", "", "GET\r\nX: y", None, 5],
)
@pytest.mark.parametrize(
    "url",
    [
        "api.github.com/repos/octo-org/app",
        "api.github.com/user",
        "github.com/octo-org/app/info/refs?service=git-upload-pack",
    ],
)
def test_methods_outside_the_known_six_are_refused(method, url):
    refused(ask(method, url), "not-recognised")


@pytest.mark.parametrize(
    "name",
    ["X-HTTP-Method-Override", "x-http-method-override", "X-Http-Method", "X-Method-Override"],
)
def test_a_method_override_header_is_refused(name):
    headers = {**JSON, name: "DELETE"}
    refused(ask("POST", "api.github.com/repos/octo-org/app/pulls", {}, headers=headers), "method-override")
    refused(ask("GET", "api.github.com/repos/octo-org/app", headers=headers), "method-override")
    refused(ask("POST", "github.com/octo-org/app/git-upload-pack", headers=headers), "method-override")
    # Also when the headers arrive as pairs, as bytes.
    pairs = [(b"content-type", b"application/json"), (name.encode(), b"DELETE")]
    refused(ask("POST", "api.github.com/repos/octo-org/app/pulls", {}, headers=pairs), "method-override")


@pytest.mark.parametrize(
    "host",
    [
        "uploads.github.com",
        "gist.github.com",
        "raw.githubusercontent.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "lfs.github.com",
        "github.com.",
        "api.github.com.evil.example",
        "evilgithub.com",
        "example.com",
        "140.82.112.3",
        "",
    ],
)
def test_other_hosts_are_refused_whatever_they_are_sent(host):
    for method, path, body in [
        ("GET", "/repos/octo-org/app", None),
        ("GET", "/octo-org/app/info/refs", None),
        ("POST", "/graphql", b'{"query":"{viewer{login}}"}'),
        ("POST", "/repos/octo-org/app/releases/1/assets", b"data"),
        ("POST", "/octo-org/app/git-receive-pack", None),
    ]:
        decision = decide(method, host, path, "", body, POLICY, headers=JSON, authority=host)
        assert not decision.allowed
        assert decision.reason in ("github-host-not-covered", "gists", "releases")
        assert not wants_body(host)


def test_the_api_is_not_served_on_the_git_host_and_the_other_way_round():
    refused(ask("GET", "github.com/repos/octo-org/app/pulls"), "not-recognised")
    refused(ask("POST", "github.com/graphql", {"query": "{viewer{login}}"}), "not-recognised")
    refused(ask("POST", "api.github.com/octo-org/app/git-receive-pack", {}), "not-recognised")
    refused(ask("GET", "api.github.com/octo-org/app/info/refs?service=git-receive-pack"), "not-recognised")


def test_host_names_ignore_case():
    allowed(ask("GET", "API.GitHub.com/repos/octo-org/app"), "api-read")
    allowed(ask("POST", "GitHub.COM/octo-org/app/git-receive-pack"), "git-write")
    assert wants_body("API.github.com")


@pytest.mark.parametrize(
    "named",
    ["uploads.github.com", "gist.github.com", "github.com", "evil.example", "api.github.com:8443", "", None],
)
def test_a_request_that_names_another_host_than_it_is_sent_to(named):
    # Sent to api.github.com, but GitHub would route it by the name inside.
    decision = decide(
        "GET", "api.github.com", "/repos/octo-org/app", "", None, POLICY, headers=JSON, authority=named
    )
    refused(decision, "host-differs")


def test_a_host_header_that_differs_is_refused_too():
    headers = {**JSON, "Host": "gist.github.com"}
    refused(ask("GET", "api.github.com/repos/octo-org/app", headers=headers), "host-differs")
    twice = [("Host", "api.github.com"), ("Host", "gist.github.com")]
    refused(ask("GET", "api.github.com/repos/octo-org/app", headers=twice), "header-repeated")
    allowed(ask("GET", "api.github.com/repos/octo-org/app", headers={"Host": "api.github.com:443"}))
    allowed(ask("GET", "api.github.com/repos/octo-org/app", authority="API.github.com:443"))


# ---------------------------------------------------------------------------
# What attackers try: bodies
# ---------------------------------------------------------------------------


def test_the_api_needs_the_body():
    assert wants_body("api.github.com")
    refused(ask("POST", "api.github.com/repos/octo-org/app/pulls", None), "body-odd")
    refused(ask("POST", "api.github.com/graphql", None), "body-odd")
    # Reading has no body to hand over.
    allowed(ask("GET", "api.github.com/repos/octo-org/app/pulls", None))
    allowed(ask("GET", "api.github.com/repos/octo-org/app/pulls", b""))


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_a_body_on_a_reading_request_is_refused(method):
    refused(ask(method, "api.github.com/repos/octo-org/app", {"x": 1}), "body-odd")
    refused(ask(method, "api.github.com/user", b"x"), "body-odd")


BAD_JSON = [
    b"not json",
    b"{",
    b'{"title": "x"',
    b'{"title": "x"} trailing',
    b'{"title": "x"}{"title": "y"}',
    b'[{"title": "x"}]',
    b'"text"',
    b"5",
    b"null",
    b'{"title": "x", "title": "y"}',  # which one counts?
    b'{"a": {"b": 1, "b": 2}}',
    b'\xef\xbb\xbf{"title": "x"}',  # byte order mark
    b'{"title": "\xff"}',  # not UTF-8
    '{"title": "x"}'.encode("utf-16"),
    b'{"n": NaN}',
    b'{"n": Infinity}',
    b"title=x&_method=DELETE",
    b"[" * 100_000,
    b'{"a":' * 100_000,
]


@pytest.mark.parametrize("body", BAD_JSON)
def test_a_body_that_is_not_plain_json_is_refused(body):
    refused(ask("POST", "api.github.com/repos/octo-org/app/pulls", body), "body-odd")
    refused(ask("POST", "api.github.com/graphql", body), "body-odd")


def test_an_empty_body():
    # Fine where the request needs none, such as deleting a comment.
    allowed(ask("DELETE", "api.github.com/repos/octo-org/app/issues/comments/5", b""))
    allowed(ask("DELETE", "api.github.com/repos/octo-org/app/issues/comments/5", b"", headers={}))
    # Not for GraphQL, where the body is the request.
    refused(ask("POST", "api.github.com/graphql", b""), "body-odd")
    refused(ask("POST", "api.github.com/graphql", {}), "graphql-malformed")


def test_a_huge_body_is_refused():
    huge = b'{"body": "' + b"a" * policy_module.MAX_BODY + b'"}'
    refused(ask("POST", "api.github.com/repos/octo-org/app/issues/7/comments", huge), "body-odd")
    refused(ask("POST", "api.github.com/graphql", huge), "body-odd")
    almost = b'{"body": "' + b"a" * (policy_module.MAX_BODY - 100) + b'"}'
    allowed(ask("POST", "api.github.com/repos/octo-org/app/issues/7/comments", almost))


@pytest.mark.parametrize(
    "content_type",
    [
        None,
        "",
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=x",
        "text/plain",
        "application/jsonx",
        "application/json, application/x-www-form-urlencoded",
        "application/vnd.github+json",
        "application/json; charset=utf-16",
        "application/json; charset=utf-8; charset=utf-16",
        "application/json; boundary=x",
    ],
)
def test_a_body_must_say_it_is_json(content_type):
    headers = {} if content_type is None else {"Content-Type": content_type}
    refused(ask("POST", "api.github.com/repos/octo-org/app/pulls", {"title": "x"}, headers=headers), "body-odd")
    refused(ask("POST", "api.github.com/graphql", {"query": "{viewer{login}}"}, headers=headers), "body-odd")


def test_a_body_that_is_json_and_also_a_web_form():
    # Read as JSON this is a harmless query. Read as a web form, the part
    # after the "&" would be a second `query`. It must go out as JSON only.
    body = b'{"query":"{viewer{login}}","x":"&query=mutation{deleteRepository}"}'
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    refused(ask("POST", "api.github.com/graphql", body, headers=form), "body-odd")
    refused(ask("POST", "api.github.com/graphql", body), "graphql-malformed")


@pytest.mark.parametrize(
    "content_type",
    ["application/json", "Application/JSON", "application/json; charset=utf-8", 'application/json;charset="UTF-8"'],
)
def test_the_ways_to_say_a_body_is_json(content_type):
    headers = {"Content-Type": content_type}
    allowed(ask("POST", "api.github.com/repos/octo-org/app/pulls", {"title": "x"}, headers=headers))
    allowed(ask("POST", "api.github.com/graphql", {"query": "{viewer{login}}"}, headers=headers))


def test_content_type_sent_twice_is_refused():
    twice = [("Content-Type", "application/json"), ("content-type", "text/plain")]
    refused(ask("POST", "api.github.com/repos/octo-org/app/pulls", {}, headers=twice), "header-repeated")


@pytest.mark.parametrize("encoding", ["gzip", "deflate", "br", "zstd", "identity, gzip", "x"])
def test_a_compressed_api_body_is_refused(encoding):
    headers = {**JSON, "Content-Encoding": encoding}
    refused(ask("POST", "api.github.com/graphql", {"query": "{viewer{login}}"}, headers=headers), "body-odd")
    refused(ask("POST", "api.github.com/repos/octo-org/app/pulls", {}, headers=headers), "body-odd")
    refused(ask("GET", "api.github.com/repos/octo-org/app", headers=headers), "body-odd")


def test_an_uncompressed_body_may_say_so():
    headers = {**JSON, "Content-Encoding": "identity"}
    allowed(ask("POST", "api.github.com/repos/octo-org/app/pulls", {}, headers=headers))


# ---------------------------------------------------------------------------
# GraphQL: the requests gh really sends
# ---------------------------------------------------------------------------
#
# These are shapes recorded from gh 2.102 with GH_DEBUG=api, with the repo
# names swapped for the made-up ones. The long field lists are shortened.

# The kinds of thing that live inside a repo, by the letters their ids start
# with: pull request, issue, issue comment, review, review comment and review
# thread.
INSIDE_KINDS = ["PR", "I", "IC", "PRR", "PRRC", "PRRT"]


def claims(kind: str, repo_number: int, own: int = 5) -> str:
    """The id of a thing that claims to be inside the repo with this number.

    GitHub does not check the claim. It finds the thing by `own`, its own
    number, in whatever repo that is. The same bytes are both "pull request 5
    of this repo" and "a forged id for pull request 5 of another repo", and
    nothing in the id tells which.
    """
    return node_id(kind, repo_number, own)


# Says it is a pull request in octo-org/app. Nothing may be allowed for that.
PR_ID = claims("PR", APP)

# The id of octo-org/app itself, which can be trusted.
APP_ID = node_id("R", APP)

ADD_COMMENT = "mutation($input: AddCommentInput!) { addComment(input: $input) { clientMutationId } }"
CREATE_PR = "mutation($input: CreatePullRequestInput!) { createPullRequest(input: $input) { clientMutationId } }"
REPO_VARS = {"owner": "octo-org", "repo": "app"}

GH_QUERIES = [
    # gh pr list
    (
        """
        fragment pr on PullRequest{number,title,state,url,headRefName,
          headRepositoryOwner{id,login,...on User{name}},isCrossRepository,isDraft,createdAt}
        query PullRequestList(
          $owner: String!, $repo: String!, $limit: Int!, $endCursor: String,
          $baseBranch: String, $headBranch: String, $state: [PullRequestState!] = OPEN
        ) {
          repository(owner: $owner, name: $repo) {
            pullRequests(states: $state, baseRefName: $baseBranch, headRefName: $headBranch,
              first: $limit, after: $endCursor, orderBy: {field: CREATED_AT, direction: DESC}) {
              totalCount
              nodes { ...pr }
              pageInfo { hasNextPage endCursor }
            }
          }
        }""",
        {"limit": 30, "owner": "octo-org", "repo": "app", "state": ["OPEN"]},
    ),
    # gh pr view 1
    (
        """query PullRequestByNumber($owner: String!, $repo: String!, $pr_number: Int!) {
          repository(owner: $owner, name: $repo) {
            pullRequest(number: $pr_number) {url,number,title,state,body,
              author{login,...on User{id,name}},
              headRepositoryOwner{id,login,...on User{name}},headRepository{id,name,nameWithOwner},
              reviewRequests(first: 100) {nodes {requestedReviewer {__typename,...on User{login,name},
                ...on Team{organization{login}name,slug}}}},
              comments(first: 100) {nodes {id,author{login},body,createdAt,url,viewerDidAuthor},
                pageInfo{hasNextPage,endCursor},totalCount},
              statusCheckRollup: commits(last: 1) {nodes {commit {statusCheckRollup {
                contexts(first:100) {nodes {__typename...on StatusContext {context,state,targetUrl},
                ...on CheckRun {name,checkSuite{workflowRun{workflow{name}}},status,conclusion}}}}}}},
              id}
          }
        }""",
        {"owner": "octo-org", "pr_number": 1, "repo": "app"},
    ),
    # gh pr view BRANCH
    (
        """query PullRequestForBranch($owner: String!, $repo: String!, $headRefName: String!,
            $states: [PullRequestState!]) {
          repository(owner: $owner, name: $repo) {
            pullRequests(headRefName: $headRefName, states: $states, first: 30,
              orderBy: { field: CREATED_AT, direction: DESC }) {
              nodes {number,headRefName,isCrossRepository,headRepositoryOwner{id,login}}
            }
            defaultBranchRef { name }
          }
        }""",
        {"headRefName": "my-branch", "owner": "octo-org", "repo": "app", "states": None},
    ),
    # gh asks what the API knows before some commands
    (
        'query PullRequest_fields{PullRequest: __type(name: "PullRequest"){fields(includeDeprecated: true){name}},'
        'StatusCheckRollupContextConnection: __type(name: "StatusCheckRollupContextConnection")'
        "{fields(includeDeprecated: true){name}}}",
        None,
    ),
    ('query SearchType_enumValues{SearchType: __type(name: "SearchType"){enumValues(includeDeprecated: true){name}}}', None),
    # gh pr status
    (
        """query PullRequestStatus($owner: String!, $repo: String!, $headRefName: String!,
            $viewerQuery: String!, $reviewerQuery: String!, $per_page: Int = 10) {
          repository(owner: $owner, name: $repo) {
            defaultBranchRef { name }
            pullRequests(headRefName: $headRefName, first: $per_page) { totalCount edges { node { number } } }
          }
          viewerCreated: search(query: $viewerQuery, type: ISSUE, first: $per_page) {
            totalCount: issueCount edges { node { ...on PullRequest { number title } } }
          }
          reviewRequested: search(query: $reviewerQuery, type: ISSUE, first: $per_page) {
            totalCount: issueCount edges { node { ...on PullRequest { number title } } }
          }
        }""",
        {
            "headRefName": "",
            "owner": "octo-org",
            "repo": "app",
            "reviewerQuery": "repo:octo-org/app state:open review-requested:@me",
            "viewerQuery": "repo:octo-org/app state:open is:pr author:@me",
        },
    ),
    # gh pr list --search "lock network"
    (
        """fragment pr on PullRequest{number,title,state}
        query PullRequestSearch($q: String!, $type: SearchType!, $limit: Int!, $endCursor: String) {
          search(query: $q, type: $type, first: $limit, after: $endCursor) {
            issueCount nodes { ...pr } pageInfo { hasNextPage endCursor }
          }
        }""",
        {"limit": 30, "q": "( lock network ) repo:octo-org/app state:open type:pr", "type": "ISSUE_ADVANCED"},
    ),
    # gh issue list, gh issue view 1
    (
        """query IssueList($owner: String!, $repo: String!, $limit: Int, $endCursor: String,
            $states: [IssueState!] = OPEN, $assignee: String, $author: String, $mention: String) {
          repository(owner: $owner, name: $repo) {
            hasIssuesEnabled
            issues(first: $limit, after: $endCursor, states: $states,
              filterBy: {assignee: $assignee, createdBy: $author, mentioned: $mention}) {
              totalCount nodes { number title } pageInfo { hasNextPage endCursor }
            }
          }
        }""",
        {"limit": 30, "owner": "octo-org", "repo": "app", "states": ["OPEN"]},
    ),
    (
        "query IssueProjectItems($endCursor:String$name:String!$number:Int!$owner:String!)"
        "{repository(owner: $owner, name: $name){issue(number: $number){projectItems(first: 100, after: $endCursor)"
        '{totalCount,nodes{id,project{id,title},status:fieldValueByName(name: "Status")'
        "{... on ProjectV2ItemFieldSingleSelectValue{optionId,name}}},pageInfo{hasNextPage,endCursor}}}}}",
        {"endCursor": None, "name": "app", "number": 1, "owner": "octo-org"},
    ),
    # gh repo view
    (
        "query RepositoryInfo($owner: String!, $name: String!) {"
        " repository(owner: $owner, name: $name) {name,owner{id,login},description} }",
        {"name": "app", "owner": "octo-org"},
    ),
    # gh pr create looks at the repo and its parent first, with the names
    # written into the query under made-up names (aliases).
    (
        """fragment repo on Repository { id name owner { login } viewerPermission
             defaultBranchRef { name } isPrivate }
        query RepositoryNetwork {
          viewer { login }
          repo_000: repository(owner: "octo-org", name: "app") { ...repo parent { ...repo } }
        }""",
        None,
    ),
    ("query UserCurrent{viewer{login}}", None),
    # gh pr create --reviewer someone
    ('query RepositoryResolveMetadataIDs { u000: user(login: "someone") { id } }', None),
]


@pytest.mark.parametrize(("query", "variables"), GH_QUERIES)
def test_queries_gh_sends_are_allowed(query, variables):
    decision = allowed(gql(query, variables), "graphql-read")
    assert decision.with_token
    # The same queries about a read-only repo...
    if variables and "owner" in variables:
        swapped = json.loads(json.dumps(variables).replace('"app"', '"library"'))
        allowed(gql(query, swapped), "graphql-read", "octo-org/library")
        # ...and about one that is not listed.
        elsewhere = json.loads(json.dumps(variables).replace("octo-org", "other-org"))
        for used in (POLICY, PUBLIC):
            refused(gql(query, elsewhere, policy=used), "repo-not-listed")


REPOSITORY_INFO = (
    "query RepositoryInfo($owner: String!, $name: String!) {"
    " repository(owner: $owner, name: $name) {name,owner{id,login},description} }"
)

# gh pr checks asks for the pull request by its id.
PR_CHECKS = """query PullRequestStatusChecks($id: ID!, $endCursor: String) {
  node(id: $id) {
    ...on PullRequest {
      statusCheckRollup: commits(last: 1) {nodes {commit {statusCheckRollup {
        contexts(first:100,after:$endCursor) {nodes {__typename
          ...on StatusContext {context,state,isRequired(pullRequestId: $id)},
          ...on CheckRun {name,status,conclusion,isRequired(pullRequestId: $id)}},
          pageInfo{hasNextPage,endCursor}}}}}}
    }
  }
}"""


def test_gh_pr_checks_reads_by_id_and_is_refused():
    for number in (APP, LIBRARY, OTHER):
        decision = refused(gql(PR_CHECKS, {"id": claims("PR", number)}), "graphql-by-id")
    # The message gives the agent a way on, and that way is allowed: it is
    # the PullRequestByNumber query in the list above.
    assert "gh pr view NUMBER --repo OWNER/REPO --json statusCheckRollup" in decision.message
    assert "`gh pr checks` reads by id and does not work here" in decision.message
    assert "There is another way" in decision.message
    allowed(ask("GET", "api.github.com/repos/octo-org/app/pulls/7"), "api-read")
    allowed(ask("GET", "api.github.com/repos/octo-org/app/commits/0123abc/check-runs"), "api-read")


# gh pr create, as recorded when the pull request for this module was opened.
CREATE_PR_AS_GH = (
    "mutation PullRequestCreate($input: CreatePullRequestInput!) {"
    " createPullRequest(input: $input) { pullRequest { id url } } }"
)


def pr_input(repo_number: int) -> dict:
    return {
        "repositoryId": node_id("R", repo_number),
        "baseRefName": "main",
        "headRefName": "my-branch",
        "title": "t",
        "body": "b",
        "draft": False,
        "maintainerCanModify": True,
    }


def test_opening_a_pull_request_as_gh_does():
    decision = allowed(gql(CREATE_PR_AS_GH, {"input": pr_input(APP)}), "graphql-write", "octo-org/app")
    assert decision.with_token
    allowed(gql(CREATE_PR_AS_GH, {"input": pr_input(SHIPPING)}), "graphql-write", "octo-org/shipping")
    refused(gql(CREATE_PR_AS_GH, {"input": pr_input(LIBRARY)}), "repo-read-only")
    for used in (POLICY, PUBLIC):
        decision = refused(gql(CREATE_PR_AS_GH, {"input": pr_input(OTHER)}, policy=used), "graphql-id-not-listed")
        assert "`id`" in decision.message


def test_a_write_repo_without_an_id_cannot_open_a_pull_request_with_gh():
    # The rules hold no id for octo-org/no-id, so no id means that repo.
    assert POLICY.find("octo-org", "no-id").write
    refused(gql(CREATE_PR_AS_GH, {"input": pr_input(4242)}), "graphql-id-not-listed")
    # git, the REST API and queries by name still work for it. That
    # includes opening a pull request through the REST API.
    allowed(ask("POST", "github.com/octo-org/no-id/git-receive-pack"), "git-write")
    allowed(ask("POST", "api.github.com/repos/octo-org/no-id/pulls", {"title": "t"}), "api-write")
    allowed(gql(REPOSITORY_INFO, {"owner": "octo-org", "name": "no-id"}), "graphql-read")


def test_one_change_is_allowed_through_graphql_and_it_names_a_repo():
    # Adding a mutation here needs an argument that proves the repo. The id
    # of a pull request, an issue, a comment or a review does not.
    assert policy_module.MUTATIONS == {"createPullRequest": ("repositoryId", "headRepositoryId")}


# ---------------------------------------------------------------------------
# GraphQL: changes named only by an id
# ---------------------------------------------------------------------------
#
# Each of these names what it changes by the id of a pull request, an issue,
# a comment, a review or a review thread, and by nothing else. GitHub applies
# it to whatever has that id, in any repo the token reaches, so none of them
# can be allowed.

ONCE_ALLOWED_BY_ID = {
    "addComment", "updateIssueComment", "deleteIssueComment", "addReaction", "removeReaction",
    "updatePullRequest", "closePullRequest", "reopenPullRequest", "markPullRequestReadyForReview",
    "convertPullRequestToDraft", "updatePullRequestBranch", "requestReviews", "requestReviewsByLogin",
    "addPullRequestReview", "submitPullRequestReview", "updatePullRequestReview", "deletePullRequestReview",
    "addPullRequestReviewThread", "addPullRequestReviewThreadReply", "updatePullRequestReviewComment",
    "deletePullRequestReviewComment", "resolveReviewThread", "unresolveReviewThread",
    "addLabelsToLabelable", "removeLabelsFromLabelable",
    "mergePullRequest", "enablePullRequestAutoMerge", "disablePullRequestAutoMerge", "enqueuePullRequest",
}

# Every name an input uses for an id.
ID_KEYS = [
    "id", "subjectId", "pullRequestId", "issueId", "labelableId", "assignableId", "pullRequestReviewId",
    "pullRequestReviewThreadId", "pullRequestReviewCommentId", "threadId", "repositoryId", "headRepositoryId",
]


def mutation(name: str) -> str:
    return f"mutation($input: X!) {{ {name}(input: $input) {{ clientMutationId }} }}"


def test_every_change_once_allowed_by_such_an_id_is_now_refused_by_name():
    assert ONCE_ALLOWED_BY_ID <= set(policy_module.BY_ID)
    assert not ONCE_ALLOWED_BY_ID & set(policy_module.MUTATIONS)


def test_the_forged_id_from_the_review_is_refused():
    # octo-org/app's number in front, and the number of some pull request
    # elsewhere behind it. GitHub would comment on that other pull request.
    forged = node_id("PR", APP, 999999)
    decision = refused(gql(ADD_COMMENT, {"input": {"subjectId": forged, "body": "x"}}), "graphql-by-id")
    assert "does not prove which repo" in decision.message
    for name, key in [
        ("updateIssueComment", "id"),
        ("deleteIssueComment", "id"),
        ("closePullRequest", "pullRequestId"),
    ]:
        kind = "IC" if key == "id" else "PR"
        refused(gql(mutation(name), {"input": {key: node_id(kind, APP, 999999)}}), "graphql-by-id")
    read = "query($id: ID!) { node(id: $id) { ... on PullRequest { title body } } }"
    refused(gql(read, {"id": forged}), "graphql-by-id")


@pytest.mark.parametrize("name", sorted(policy_module.BY_ID))
@pytest.mark.parametrize("kind", [*INSIDE_KINDS, "R"])
def test_a_change_named_only_by_an_id_is_refused_whatever_the_id_claims(name, kind):
    for number in (APP, SHIPPING, LIBRARY, OTHER):
        for own in (5, 999999):
            # The same id under every name, so that no name is the lucky one.
            the_id = node_id("R", number) if kind == "R" else claims(kind, number, own)
            given = dict.fromkeys(ID_KEYS, the_id)
            for used in (POLICY, PUBLIC):
                decision = refused(gql(mutation(name), {"input": given}, policy=used), "graphql-by-id")
                assert f"`{name}`" in decision.message


@pytest.mark.parametrize(
    ("query", "given"),
    [
        # gh pr comment, as recorded
        (
            "mutation CommentCreate($input: AddCommentInput!) {"
            " addComment(input: $input) { commentEdge { node { url } } } }",
            {"subjectId": claims("PR", APP), "body": "hello"},
        ),
        # gh pr comment --edit-last, as recorded
        (
            "mutation CommentUpdate($input: UpdateIssueCommentInput!) {"
            " updateIssueComment(input: $input) { issueComment { url } } }",
            {"id": claims("IC", APP), "body": "edited"},
        ),
        # gh pr edit, gh pr close, gh pr ready, gh pr review, gh pr merge
        (
            "mutation PullRequestUpdate($input: UpdatePullRequestInput!) {"
            " updatePullRequest(input: $input) { __typename } }",
            {"pullRequestId": claims("PR", APP), "title": "new", "body": "new"},
        ),
        (
            "mutation PullRequestClose($input: ClosePullRequestInput!) {"
            " closePullRequest(input: $input) { pullRequest { id } } }",
            {"pullRequestId": claims("PR", APP)},
        ),
        (
            "mutation PullRequestReadyForReview($input: MarkPullRequestReadyForReviewInput!) {"
            " markPullRequestReadyForReview(input: $input) { pullRequest { id } } }",
            {"pullRequestId": claims("PR", APP)},
        ),
        (
            "mutation PullRequestReviewAdd($input: AddPullRequestReviewInput!) {"
            " addPullRequestReview(input: $input) { clientMutationId } }",
            {"pullRequestId": claims("PR", APP), "event": "COMMENT", "body": "looks fine"},
        ),
        (
            "mutation PullRequestMerge($input: MergePullRequestInput!) {"
            " mergePullRequest(input: $input) { clientMutationId } }",
            {"pullRequestId": claims("PR", SHIPPING), "mergeMethod": "SQUASH"},
        ),
    ],
)
def test_the_changes_gh_sends_by_id_are_refused(query, given):
    refused(gql(query, {"input": given}), "graphql-by-id")


def rest_call(line: str, repo: str):
    """Turn a `gh api ...` line from a refusal into a request to ask about."""
    words = shlex.split(line)
    assert words[:2] == ["gh", "api"]
    words = words[2:]
    method, path, fields = None, None, {}
    while words:
        word = words.pop(0)
        if word == "-X":
            method = words.pop(0)
        elif word in ("-f", "-F"):
            key, _, value = words.pop(0).partition("=")
            if key.endswith("[]"):
                fields.setdefault(key[:-2], []).append(value)
            else:
                fields[key] = value
        else:
            assert path is None, line
            path = word
    # gh sends POST when there are fields and no method is given.
    method = method or ("POST" if fields else "GET")
    assert path.startswith("repos/OWNER/REPO/"), line
    fill = {"OWNER/REPO": repo, "NUMBER": "7", "COMMENT_ID": "5", "REVIEW_ID": "8", "REACTION_ID": "3", "LABEL": "bug"}
    for word, value in fill.items():
        path = path.replace(word, value)
    assert not any(part.isupper() and len(part) > 2 for part in path.split("/")), path
    return method, f"api.github.com/{path}", fields or b""


WITH_REST = sorted(name for name, (_, call) in policy_module.BY_ID.items() if call)
WITHOUT_REST = sorted(name for name, (_, call) in policy_module.BY_ID.items() if not call)


@pytest.mark.parametrize("name", WITH_REST)
def test_the_rest_request_a_refusal_names_is_allowed_in_a_write_repo(name):
    call = policy_module.BY_ID[name][1]
    message = refused(gql(mutation(name), {"input": dict.fromkeys(ID_KEYS, PR_ID)}), "graphql-by-id").message
    # The agent is shown this very line, and told that it is a way on.
    assert f"\n    {call}\n" in message
    assert "There is another way" in message and "in another way or with another tool" not in message
    assert "access: write" in message

    assert rest_call(call, "x/y")[0] != "GET"
    allowed(ask(*rest_call(call, "octo-org/shipping")), "api-write", "octo-org/shipping")
    if name == "mergePullRequest":
        assert "merge: true" in message
        refused(ask(*rest_call(call, "octo-org/app")), "merge")
    else:
        allowed(ask(*rest_call(call, "octo-org/app")), "api-write", "octo-org/app")
    refused(ask(*rest_call(call, "octo-org/library")), "repo-read-only")
    for used in (POLICY, PUBLIC):
        refused(ask(*rest_call(call, "other-org/public"), policy=used), "repo-not-listed")


@pytest.mark.parametrize("name", WITHOUT_REST)
def test_a_change_with_no_rest_request_says_so(name):
    message = refused(gql(mutation(name), {"input": dict.fromkeys(ID_KEYS, PR_ID)}), "graphql-by-id").message
    assert "gh api" not in message
    if name == "updatePullRequestBranch":
        # No REST request, but git does the same.
        assert "Do it with git instead" in message and "There is another way" in message
    else:
        assert "cannot be done from the sandbox" in message and "There is another way" not in message


def test_the_changes_a_refusal_can_point_to():
    # Enough to open a pull request with gh and do the rest through REST.
    assert set(WITH_REST) >= {
        "addComment", "updateIssueComment", "deleteIssueComment", "updatePullRequest", "closePullRequest",
        "reopenPullRequest", "addPullRequestReview", "submitPullRequestReview", "addPullRequestReviewThread",
        "addPullRequestReviewThreadReply", "addLabelsToLabelable", "removeLabelsFromLabelable",
        "addReaction", "removeReaction", "mergePullRequest",
    }
    # GitHub has no REST request for these, or the one it has is refused.
    assert set(WITHOUT_REST) == {
        "markPullRequestReadyForReview", "convertPullRequestToDraft", "resolveReviewThread",
        "unresolveReviewThread", "enablePullRequestAutoMerge", "disablePullRequestAutoMerge",
        "enqueuePullRequest", "updatePullRequestBranch",
    }


def test_every_gh_api_line_in_a_refusal_is_allowed():
    # Some refusals say more than one line: a second request, or a note.
    lines = set()
    for name in policy_module.BY_ID:
        message = refused(gql(mutation(name), {"input": dict.fromkeys(ID_KEYS, PR_ID)}), "graphql-by-id").message
        lines.update(re.findall(r"^    (gh api .+)$", message, re.MULTILINE))
    assert len(lines) > len(WITH_REST) - 3  # two share a line, and one adds a line
    for line in lines:
        allowed(ask(*rest_call(line, "octo-org/shipping")), "api-write", "octo-org/shipping")
        refused(ask(*rest_call(line, "octo-org/library")), "repo-read-only")
        refused(ask(*rest_call(line, "other-org/public"), policy=PUBLIC), "repo-not-listed")


def test_editing_a_pull_request_does_not_have_to_overwrite_its_text():
    message = refused(gql(mutation("updatePullRequest"), {"input": {"pullRequestId": PR_ID}}), "graphql-by-id").message
    # The line to run changes the title only, and the note says how to change the text.
    assert "\n    gh api -X PATCH repos/OWNER/REPO/pulls/NUMBER -f title='TITLE'\n" in message
    assert "-f body='TEXT'" in message and "What is left\nout stays as it is." in message
    allowed(ask("PATCH", "api.github.com/repos/octo-org/app/pulls/7", {"title": "new"}), "api-write")
    allowed(ask("PATCH", "api.github.com/repos/octo-org/app/pulls/7", {"body": "new"}), "api-write")


def test_a_reaction_on_a_comment_has_its_own_line():
    message = refused(gql(mutation("addReaction"), {"input": {"subjectId": claims("IC", APP)}}), "graphql-by-id").message
    assert "\n    gh api repos/OWNER/REPO/issues/NUMBER/reactions -f content=+1\n" in message
    assert "\n    gh api repos/OWNER/REPO/issues/comments/COMMENT_ID/reactions -f content=+1\n" in message
    assert "pulls/comments/COMMENT_ID/reactions" in message
    allowed(ask("POST", "api.github.com/repos/octo-org/app/pulls/comments/5/reactions", {"content": "+1"}), "api-write")


# ---------------------------------------------------------------------------
# Pull requests: where the branch comes from
# ---------------------------------------------------------------------------
#
# A pull request may name its branch as `someone:branch`, the branch in that
# account's fork. Opened that way it pulls a branch of an unlisted repo into
# a listed one, and by default lets the listed repo's maintainers push to it.

PULLS = "api.github.com/repos/octo-org/app/pulls"


def test_opening_a_pull_request_with_a_plain_branch_name():
    base = {"repositoryId": APP_ID, "baseRefName": "main", "title": "t"}
    for branch in ("my-branch", "feature/with/slashes", "v1.2", "dependabot/npm_and_yarn/x-1.0", "refs/heads/x"):
        allowed(gql(CREATE_PR, {"input": {**base, "headRefName": branch}}), "graphql-write", "octo-org/app")
        allowed(ask("POST", PULLS, {"title": "t", "head": branch, "base": "main"}), "api-write", "octo-org/app")


@pytest.mark.parametrize(
    "head",
    [
        "attacker:exfil",
        "octo-org:my-branch",  # the same owner, written the cross-repo way
        "attacker:feature/x",
        ":exfil",
        "attacker:",
        ":",
        "a:b:c",
        ["attacker:exfil"],
        {"ref": "exfil"},
        5,
        True,
    ],
)
def test_a_pull_request_may_not_take_its_branch_from_someones_fork(head):
    for extra in ({}, {"maintainerCanModify": True}, {"maintainerCanModify": False}, {"draft": True}):
        given = {"repositoryId": APP_ID, "baseRefName": "main", "headRefName": head, "title": "t", **extra}
        decision = refused(gql(CREATE_PR, {"input": given}), "head-elsewhere")
        assert "Push the\nbranch to a listed repo" in decision.message
    # Also when the repo of the branch is named as well, and is a listed one.
    given = {"repositoryId": APP_ID, "headRepositoryId": node_id("R", SHIPPING), "headRefName": head, "title": "t"}
    refused(gql(CREATE_PR, {"input": given}), "head-elsewhere")
    # The same through the REST API.
    for extra in ({}, {"maintainer_can_modify": True}, {"draft": True}):
        refused(ask("POST", PULLS, {"title": "t", "head": head, "base": "main", **extra}), "head-elsewhere")


def test_the_branch_a_pull_request_goes_into_is_a_plain_name_too():
    refused(gql(CREATE_PR, {"input": {"repositoryId": APP_ID, "baseRefName": "other:main", "headRefName": "x"}}), "head-elsewhere")
    refused(ask("POST", PULLS, {"title": "t", "head": "x", "base": "other:main"}), "head-elsewhere")
    refused(ask("POST", PULLS, {"title": "t", "head": "x", "base": ["main"]}), "head-elsewhere")
    # Changing it afterwards.
    allowed(ask("PATCH", PULLS + "/7", {"base": "release"}), "api-write")
    refused(ask("PATCH", PULLS + "/7", {"base": "other:main"}), "head-elsewhere")


def test_a_branch_name_written_into_the_query_is_checked_too():
    inline = 'mutation { createPullRequest(input: {repositoryId: "%s", baseRefName: "main", headRefName: "%s", title: "t"}) { clientMutationId } }'
    allowed(gql(inline % (APP_ID, "my-branch")), "graphql-write")
    refused(gql(inline % (APP_ID, "attacker:exfil")), "head-elsewhere")
    refused(gql(inline % (APP_ID, "attacker\\u003aexfil")), "head-elsewhere")  # the colon as an escape
    by_default = 'mutation($repo: ID!, $head: String = "attacker:exfil") { createPullRequest(input: {repositoryId: $repo, headRefName: $head}) { clientMutationId } }'
    refused(gql(by_default, {"repo": APP_ID}), "head-elsewhere")
    allowed(gql(by_default, {"repo": APP_ID, "head": "my-branch"}), "graphql-write")


@pytest.mark.parametrize(
    ("head_repo", "ok"),
    [
        ("shipping", True),  # another listed write repo of the same owner
        ("octo-org/shipping", True),
        ("OCTO-ORG/Shipping", True),
        ("app", True),
        ("library", False),  # listed, but for reading
        ("octo-org/library", False),
        ("attacker/other", False),
        ("other", False),
        ("other-org/app", False),
        ("octo-org/shipping/x", False),
        ("", False),
        ("/", False),
        (["octo-org/shipping"], False),
        ({"name": "shipping"}, False),
        (5, False),
        (True, False),
    ],
)
def test_the_repo_a_pull_requests_branch_is_in_must_be_a_listed_write_repo(head_repo, ok):
    decision = ask("POST", PULLS, {"title": "t", "head": "exfil", "head_repo": head_repo, "base": "main"})
    if ok:
        allowed(decision, "api-write", "octo-org/app")
    else:
        refused(decision, "head-elsewhere")
    allowed(ask("POST", PULLS, {"title": "t", "head": "x", "head_repo": None, "base": "main"}), "api-write")


def test_an_issue_is_not_turned_into_a_pull_request():
    refused(ask("POST", PULLS, {"issue": 7, "head": "my-branch", "base": "main"}), "issues")
    allowed(ask("POST", PULLS, {"issue": None, "title": "t", "head": "my-branch", "base": "main"}), "api-write")


def test_a_pull_requests_branch_is_brought_up_to_date_with_git():
    # The branch may be in a fork, where this would write a commit, and
    # nothing in the request says so.
    for repo in ("app", "shipping"):
        decision = refused(ask("PUT", f"api.github.com/repos/octo-org/{repo}/pulls/7/update-branch", b""), "merge-api")
        assert "Use git instead" in decision.message
    message = refused(gql(mutation("updatePullRequestBranch"), {"input": {"pullRequestId": PR_ID}}), "graphql-by-id").message
    assert "merge the base branch into the pull\nrequest's branch, and push" in message


# ---------------------------------------------------------------------------
# A query string on a change
# ---------------------------------------------------------------------------
#
# GitHub reads values from the address on a change as well as from the body.
# The checks read the body, so anything in the query string would go out
# unread.


@pytest.mark.parametrize(
    ("method", "url", "body"),
    [
        ("PATCH", "api.github.com/repos/octo-org/app/pulls/1?assignees[]=evil", {"title": "t"}),
        ("PATCH", "api.github.com/repos/octo-org/app/pulls/1?base=other:main", {"title": "t"}),
        ("POST", "api.github.com/repos/octo-org/app/pulls?head=attacker:exfil&base=main&title=t", b""),
        ("POST", "api.github.com/repos/octo-org/app/pulls?head_repo=attacker/other", {"title": "t", "head": "x"}),
        ("POST", "api.github.com/repos/octo-org/app/issues/1/comments?body=hello", b""),
        ("PUT", "api.github.com/repos/octo-org/shipping/pulls/1/merge?merge_method=squash", b""),
        ("DELETE", "api.github.com/repos/octo-org/app/issues/comments/5?x=1", b""),
        ("DELETE", "api.github.com/repos/octo-org/app/git/refs/heads/my-branch?x", b""),
        ("POST", "api.github.com/repos/octo-org/app/pulls?", {"title": "t"}),
        ("POST", "api.github.com/graphql?x=1", {"query": "{ viewer { login } }"}),
    ],
)
def test_a_change_must_not_have_a_query_string(method, url, body):
    if url.endswith("?"):
        # An empty query string holds nothing to read.
        allowed(ask(method, url, body), "api-write")
        return
    decision = refused(ask(method, url, body), "query-odd")
    assert "Put its values in the body" in decision.message
    # Without it, each of these is a request that is allowed.
    allowed(ask(method, url.split("?")[0], body or ({"query": "{ viewer { login } }"} if "graphql" in url else b"")))


def test_reading_may_have_a_query_string():
    allowed(ask("GET", "api.github.com/repos/octo-org/app/pulls?state=all&per_page=100&head=octo-org:x"), "api-read")
    allowed(ask("HEAD", "api.github.com/repos/octo-org/app/issues?labels=bug"), "api-read")


# ---------------------------------------------------------------------------
# GraphQL: changes that are never allowed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "deleteRepository",
        "createRepository",
        "updateRepository",
        "archiveRepository",
        "cloneTemplateRepository",
        "transferIssue",
        "createBranchProtectionRule",
        "updateBranchProtectionRule",
        "deleteBranchProtectionRule",
        "createRepositoryRuleset",
        "deleteRepositoryRuleset",
        "createRef",
        "updateRef",
        "updateRefs",
        "deleteRef",
        "createCommitOnBranch",
        "mergeBranch",
        "revertPullRequest",
        "dismissPullRequestReview",
        "createCheckRun",
        "createDeployment",
        "createEnvironment",
        "removeOutsideCollaborator",
        "addStar",
        "followUser",
        "changeUserStatus",
        "createLabel",
        "deleteIssue",
        "lockLockable",
        "minimizeComment",
        "addDiscussionComment",
        "createProjectV2",
        "createSponsorship",
        "setRepositoryInteractionLimit",
        "aMutationGitHubAddsNextYear",
    ],
)
def test_other_changes_are_refused_through_graphql(name):
    given = dict.fromkeys(ID_KEYS, node_id("R", APP))
    decision = refused(gql(mutation(name), {"input": given}), "graphql-mutation-not-allowed")
    assert name not in policy_module.MUTATIONS and name not in policy_module.BY_ID
    assert name in decision.message


# ---------------------------------------------------------------------------
# Assigning, which can start a second agent outside the sandbox
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name", ["addAssigneesToAssignable", "removeAssigneesFromAssignable", "replaceActorsForAssignable"]
)
def test_assigning_is_refused_through_graphql(name):
    query = f"mutation($input: X!) {{ {name}(input: $input) {{ clientMutationId }} }}"
    decision = refused(gql(query, {"input": {"assignableId": claims("I", APP), "actorIds": ["BOT_x"]}}), "assignees")
    assert "second agent" in decision.message


@pytest.mark.parametrize(
    ("name", "given"),
    [
        ("createPullRequest", {"repositoryId": node_id("R", APP), "title": "t"}),
    ],
)
@pytest.mark.parametrize(
    "extra",
    [
        {"assigneeIds": ["BOT_x"]},
        {"assignees": [{"id": "BOT_x"}]},
        # This one also names a repo for the agent to work in.
        {"agentAssignment": {"targetRepositoryId": node_id("R", OTHER), "customInstructions": "x"}},
    ],
)
def test_assigning_on_the_side_of_another_change_is_refused(name, given, extra):
    query = f"mutation($input: X!) {{ {name}(input: $input) {{ clientMutationId }} }}"
    allowed(gql(query, {"input": given}), "graphql-write")
    refused(gql(query, {"input": {**given, **extra}}), "assignees")
    # Clearing the field is not assigning.
    allowed(gql(query, {"input": {**given, **{key: None for key in extra}}}), "graphql-write")


@pytest.mark.parametrize(("method", "rest"), [("POST", "/pulls"), ("PATCH", "/pulls/1")])
@pytest.mark.parametrize(
    "extra",
    [
        {"assignees": ["copilot-swe-agent[bot]"]},
        {"assignee": "someone"},
        {"agent_assignment": {"target_repo": "other-org/secret"}},
    ],
)
def test_assigning_on_the_side_is_refused_through_the_rest_api(method, rest, extra):
    url = f"api.github.com/repos/octo-org/app{rest}"
    refused(ask(method, url, {"title": "t", **extra}), "assignees")
    allowed(ask(method, url, {"title": "t", "assignees": []}), "api-write")
    allowed(ask(method, url, {"title": "t", "assignee": None}), "api-write")


def test_a_name_spelled_with_an_escape_is_still_that_name():
    # On the wire the name is written with "\u0061" for its first letter.
    raw = rb'{"title": "t", "\u0061ssignees": ["someone"]}'
    assert b"assignees" not in raw
    refused(ask("POST", "api.github.com/repos/octo-org/app/pulls", raw), "assignees")


def test_reading_who_can_be_assigned_is_refused_like_collaborators():
    refused(ask("GET", "api.github.com/repos/octo-org/app/assignees"), "collaborators")
    refused(gql('{ repository(owner: "octo-org", name: "app") { assignableUsers(first: 100) { nodes { login } } } }'), "collaborators")
    refused(gql('{ repository(owner: "octo-org", name: "app") { mentionableUsers(first: 100) { nodes { login } } } }'), "collaborators")


def test_a_branch_is_readable_and_its_protection_is_not():
    allowed(ask("GET", "api.github.com/repos/octo-org/app/branches/main"), "api-read")
    # A branch that happens to be called "protection".
    allowed(ask("GET", "api.github.com/repos/octo-org/app/branches/protection"), "api-read")
    refused(ask("GET", "api.github.com/repos/octo-org/app/branches/main/protection"), "branch-protection")


# ---------------------------------------------------------------------------
# Issues: read and comment, nothing more
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "given"),
    [
        ("createIssue", {"repositoryId": "R", "title": "t", "body": "b"}),
        ("updateIssue", {"id": "I", "title": "new"}),
        ("closeIssue", {"issueId": "I"}),
        ("reopenIssue", {"issueId": "I"}),
    ],
)
def test_issues_are_not_created_edited_or_closed_through_graphql(name, given):
    for number in (APP, SHIPPING, OTHER):
        ids = {"R": node_id("R", number), "I": claims("I", number)}
        filled = {key: ids.get(value, value) for key, value in given.items()}
        decision = refused(gql(mutation(name), {"input": filled}), "issues")
        assert "commenting on them is" in decision.message


def test_issues_can_be_read_and_commented_on():
    allowed(ask("GET", "api.github.com/repos/octo-org/app/issues/7"), "api-read")
    allowed(ask("POST", "api.github.com/repos/octo-org/app/issues/7/comments", {"body": "x"}), "api-write")
    # Through the REST API, that is. `gh issue comment` names the issue by id.
    refused(gql(ADD_COMMENT, {"input": {"subjectId": claims("I", APP), "body": "x"}}), "graphql-by-id")
    refused(ask("POST", "api.github.com/repos/octo-org/app/issues", {"title": "t"}), "issues")
    refused(ask("PATCH", "api.github.com/repos/octo-org/app/issues/7", {"state": "closed"}), "issues")


def test_subscriptions_are_refused():
    refused(gql("subscription { viewer { login } }"), "not-recognised")


# ---------------------------------------------------------------------------
# GraphQL: the id of a repo
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "repo_id",
    [
        node_id("R", OTHER),
        # Ids of things inside octo-org/app are not the id of octo-org/app.
        *[claims(kind, APP) for kind in INSIDE_KINDS],
        node_id("R", APP, 5),  # a repo's letter on an id with one number too many
        node_id("R"),  # and with one too few
        node_id("U", APP),  # the user numbered like the repo
        node_id("O", APP),  # the organization numbered like the repo
        node_id("T", APP, 7),  # a team of that organization
        node_id("D", APP, 7),  # a discussion
        "R_" + base64.urlsafe_b64encode(b"\x92\x01\xce\x00\x00\x03\xe9").decode().rstrip("="),  # not 0 first
        "R_" + base64.urlsafe_b64encode(b"\x92\x00\xa4\x31\x30\x30\x31").decode().rstrip("="),  # text, not a number
        "R_" + base64.urlsafe_b64encode(b"\x92\x00\xce\x00\x00\x03").decode().rstrip("="),  # cut short
        "R_" + base64.urlsafe_b64encode(b"\x92\x00\xce\x00\x00\x03\xe9\x05").decode().rstrip("="),  # too long
        "R_" + base64.urlsafe_b64encode(b"\x92\x00\xd2\x00\x00\x03\xe9").decode().rstrip("="),  # a signed number
        "R_" + base64.urlsafe_b64encode(b"\x93\x00\xcd\x03\xe9\x00").decode().rstrip("="),  # three numbers
        "R_" + base64.urlsafe_b64encode(b"\x93\x00\xcd\x03\xe9").decode().rstrip("="),  # says three, holds two
        base64.b64encode(b"011:PullRequest1001").decode(),  # the older make-up, of a pull request
        base64.b64encode(b"010:Repository1001x").decode(),
        base64.b64encode(b"010:Repository01001").decode(),
        base64.b64encode(b"04:User1001").decode(),
        old_repo_id(OTHER),
        APP_ID.lower(),
        APP_ID + "=",
        " " + APP_ID,
        APP_ID + "\n",
        "r_" + APP_ID[2:],
        "R_",
        "R_!!!!",
        "",
        "octo-org/app",
        "1001",
        5,
        1001,
        True,
        [APP_ID],
        {"id": APP_ID},
    ],
)
def test_only_the_id_of_a_listed_repo_opens_a_pull_request(repo_id):
    for used in (POLICY, PUBLIC):
        refused(gql(CREATE_PR, {"input": {"repositoryId": repo_id, "title": "t"}}, policy=used), "graphql-id-not-listed")
        # Nor as the repo the branch comes from.
        both = {"repositoryId": APP_ID, "headRepositoryId": repo_id, "title": "t"}
        refused(gql(CREATE_PR, {"input": both}, policy=used), "graphql-id-not-listed")


def test_the_same_repo_number_packed_in_other_ways_is_the_same_repo():
    # MessagePack can write 1001 in two, four or eight bytes. GitHub reads
    # the same number from each, and so does the broker.
    for packed in (b"\x92\x00\xcd\x03\xe9", b"\x92\x00\xce\x00\x00\x03\xe9", b"\x92\x00\xcf" + (1001).to_bytes(8, "big")):
        repo_id = "R_" + base64.urlsafe_b64encode(packed).decode().rstrip("=")
        allowed(gql(CREATE_PR, {"input": {"repositoryId": repo_id}}), "graphql-write", "octo-org/app")


def test_a_repo_id_of_the_older_make_up_is_understood():
    old = load_policy({"repos": [{"repo": "a/b", "note": "n", "access": "write", "id": old_repo_id(77)}]})
    # The repo is old, so gh sends its old id.
    allowed(gql(CREATE_PR, {"input": {"repositoryId": old_repo_id(77)}}, policy=old), "graphql-write", "a/b")
    allowed(gql(CREATE_PR, {"input": {"repositoryId": node_id("R", 77)}}, policy=old), "graphql-write")
    refused(gql(CREATE_PR, {"input": {"repositoryId": old_repo_id(78)}}, policy=old), "graphql-id-not-listed")
    refused(gql(CREATE_PR, {"input": {"repositoryId": old_repo_id(770)}}, policy=old), "graphql-id-not-listed")
    # A thing inside the old repo is still only named by an id.
    refused(gql(ADD_COMMENT, {"input": {"subjectId": claims("PR", 77)}}, policy=old), "graphql-by-id")


def test_a_pull_request_from_another_repo_must_come_from_a_listed_one():
    base = {"repositoryId": node_id("R", APP), "baseRefName": "main", "headRefName": "x", "title": "t"}
    allowed(gql(CREATE_PR, {"input": {**base, "headRepositoryId": node_id("R", SHIPPING)}}))
    allowed(gql(CREATE_PR, {"input": {**base, "headRepositoryId": None}}))
    refused(gql(CREATE_PR, {"input": {**base, "headRepositoryId": node_id("R", OTHER)}}), "graphql-id-not-listed")
    refused(gql(CREATE_PR, {"input": {**base, "headRepositoryId": node_id("R", LIBRARY)}}), "repo-read-only")
    # The other way round: into an unlisted repo from a listed one.
    swapped = {**base, "repositoryId": node_id("R", OTHER), "headRepositoryId": node_id("R", APP)}
    refused(gql(CREATE_PR, {"input": swapped}), "graphql-id-not-listed")
    # The repo the pull request goes into must be named; the other alone
    # will not do.
    refused(gql(CREATE_PR, {"input": {"headRepositoryId": node_id("R", APP), "title": "t"}}), "graphql-malformed")


@pytest.mark.parametrize(
    "variables",
    [
        None,
        {},
        {"input": None},
        {"input": "text"},
        {"input": [{"repositoryId": APP_ID}]},
        {"input": {}},
        {"input": {"title": "x"}},
        {"input": {"repositoryId": None, "title": "x"}},
        {"Input": {"repositoryId": APP_ID}},
    ],
)
def test_a_change_without_a_usable_input_is_refused(variables):
    refused(gql(CREATE_PR, variables), "graphql-malformed")


READ_BY_ID = "query($id: ID!) { node(id: $id) { ... on Repository { name } ... on PullRequest { title } } }"


def test_a_listed_repo_can_be_read_by_its_own_id():
    allowed(gql(READ_BY_ID, {"id": node_id("R", APP)}), "graphql-read", "octo-org/app")
    allowed(gql(READ_BY_ID, {"id": node_id("R", LIBRARY)}), "graphql-read", "octo-org/library")
    old = load_policy({"repos": [{"repo": "a/b", "note": "n", "access": "read", "id": old_repo_id(77)}]})
    allowed(gql(READ_BY_ID, {"id": old_repo_id(77)}, policy=old), "graphql-read", "a/b")
    for used in (POLICY, PUBLIC):
        refused(gql(READ_BY_ID, {"id": node_id("R", OTHER)}, policy=used), "graphql-id-not-listed")
        refused(gql(READ_BY_ID, {"id": node_id("R", 4242)}, policy=used), "graphql-id-not-listed")


@pytest.mark.parametrize("kind", [*INSIDE_KINDS, "U", "T", "D", "LA", "C", "REF"])
def test_nothing_inside_a_repo_can_be_read_by_its_id(kind):
    for number in (APP, LIBRARY, SHIPPING, OTHER):
        for own in (5, 999999):
            for used in (POLICY, PUBLIC):
                decision = refused(gql(READ_BY_ID, {"id": claims(kind, number, own)}, policy=used), "graphql-by-id")
    assert "Read it by repo and number instead" in decision.message


def test_other_ways_to_ask_by_id_are_refused():
    refused(gql(READ_BY_ID, {}), "graphql-by-id")
    refused(gql(READ_BY_ID, {"id": None}), "graphql-by-id")
    refused(gql(READ_BY_ID, {"id": 1001}), "graphql-by-id")
    refused(gql("{ node { id } }"), "graphql-by-id")
    refused(gql('{ nodes(ids: ["%s"]) { id } }' % APP_ID), "graphql-query-not-allowed")
    refused(gql('{ nodes(ids: ["%s"]) { id } }' % PR_ID), "graphql-query-not-allowed")
    # An alias, a fragment and a second operation do not hide it.
    refused(gql('{ repository: node(id: "%s") { id } }' % PR_ID), "graphql-by-id")
    refused(gql('query { ...f } fragment f on Query { node(id: "%s") { id } }' % PR_ID), "graphql-by-id")
    both = 'query Good { viewer { login } } query Bad { node(id: "%s") { id } }' % PR_ID
    refused(gql(both, operation="Good"), "graphql-by-id")


# ---------------------------------------------------------------------------
# GraphQL: where a query may start
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        '{ repositoryOwner(login: "octo-org") { repositories(first: 100) { nodes { name } } } }',
        '{ organization(login: "octo-org") { repositories(first: 100) { nodes { name } } } }',
        '{ resource(url: "https://github.com/other-org/secret") { ... on Repository { name } } }',
        '{ relay { repository(owner: "other-org", name: "secret") { name } } }',
        '{ relay { viewer { repositories(first: 1) { nodes { name } } } } }',
        '{ nodes(ids: ["x"]) { id } }',
        '{ enterprise(slug: "x") { name } }',
        "{ securityAdvisories(first: 1) { nodes { summary } } }",
        '{ topic(name: "x") { repositories(first: 1) { nodes { name } } } }',
        "{ meta { hookIpAddresses } }",
        '{ marketplaceListing(slug: "x") { name } }',
        '{ sponsorables(first: 1) { nodes { __typename } } }',
        "{ somethingNew { id } }",
    ],
)
def test_a_query_may_not_start_just_anywhere(query):
    decision = refused(gql(query), "graphql-query-not-allowed")
    assert "may not start at" in decision.message


@pytest.mark.parametrize(
    "query",
    [
        "{ viewer { login } }",
        "{ viewer { login id databaseId name url __typename } }",
        "{ viewer { ... on User { login } } }",
        "{ viewer { ...who } } fragment who on User { login id }",
        '{ user(login: "someone") { id login name } }',
        "{ rateLimit { limit remaining resetAt } }",
        "{ __typename }",
        '{ __schema { queryType { name } } }',
        "query { viewer { login } rateLimit { cost } }",
    ],
)
def test_queries_about_the_account_and_the_api(query):
    allowed(gql(query), "graphql-read")


@pytest.mark.parametrize(
    "query",
    [
        "{ viewer { repositories(first: 100) { nodes { nameWithOwner isPrivate } } } }",
        "{ viewer { gists(first: 100) { nodes { files { text } } } } }",
        "{ viewer { email } }",
        "{ viewer { organizations(first: 10) { nodes { login } } } }",
        '{ viewer { repository(name: "secret") { name } } }',
        "{ viewer { publicKeys(first: 10) { nodes { key } } } }",
        "{ viewer { ... on User { email } } }",
        "{ viewer { ...who } } fragment who on User { login ...more } fragment more on User { email }",
        "{ viewer { login: email } }",  # an alias that reads like an allowed field
        '{ user(login: "someone") { repositories(first: 1) { nodes { name } } } }',
        '{ user(login: "someone") { repository(name: "secret") { object(expression: "HEAD:x") { id } } } }',
        '{ me: viewer { r: repositories(first: 1) { nodes { name } } } }',
    ],
)
def test_only_the_name_and_id_of_an_account_may_be_asked_for(query):
    refused(gql(query), "graphql-not-on-list")


def test_a_repository_must_be_named_in_plain_text():
    q = "query($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { name } }"
    allowed(gql(q, REPO_VARS), "graphql-read", "octo-org/app")
    allowed(gql(q, {"owner": "OCTO-ORG", "repo": "APP"}), "graphql-read", "octo-org/app")
    allowed(gql('{ repository(owner: "octo-org", name: "app") { name } }'))
    allowed(gql('{ repository(name: "app", owner: "octo-org", followRenames: false) { name } }'))
    for variables in (
        None,
        {},
        {"owner": "octo-org"},
        {"owner": "octo-org", "repo": None},
        {"owner": "octo-org", "repo": 5},
        {"owner": ["octo-org"], "repo": "app"},
        {"owner": {"x": "octo-org"}, "repo": "app"},
    ):
        refused(gql(q, variables), "graphql-malformed")
    for query in (
        "{ repository { name } }",
        '{ repository(owner: "octo-org") { name } }',
        '{ repository(owner: octo, name: app) { name } }',  # bare words, not text
        '{ repository(owner: """octo-org""", name: "app") { name } }',
        '{ repository(owner: ["octo-org"], name: "app") { name } }',
        "{ repository(owner: $nowhere, name: $nowhere) { name } }",
    ):
        refused(gql(query), "graphql-malformed")


@pytest.mark.parametrize(
    ("owner", "name"),
    [
        ("other-org", "secret"),
        ("octo-org", "app.git"),
        ("octo-org", "app "),
        ("octo-org", "app/"),
        ("octo-org", "app\u0000"),
        ("octo-org/app", ""),
        ("", "octo-org/app"),
        ("octo-org", "../app"),
        ("octo-org", "aрp"),  # a Cyrillic letter that looks like "p"
    ],
)
def test_a_repository_that_is_not_listed_is_refused_through_graphql(owner, name):
    q = "query($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { name } }"
    for used in (POLICY, PUBLIC):
        refused(gql(q, {"owner": owner, "repo": name}, policy=used), "repo-not-listed")


def test_text_escapes_in_a_query_are_read_as_github_reads_them():
    # "app" is "app"; so is "\u{61}pp".
    allowed(gql('{ repository(owner: "octo-org", name: "\\u0061pp") { name } }'), repo="octo-org/app")
    allowed(gql('{ repository(owner: "octo-org", name: "\\u{61}pp") { name } }'), repo="octo-org/app")
    # And an escape cannot make an unlisted name pass.
    refused(gql('{ repository(owner: "other-org", name: "\\u0073ecret") { name } }'), "repo-not-listed")
    refused(gql('{ repository(owner: "octo-org", name: "app\\q") { name } }'), "graphql-malformed")


# ---------------------------------------------------------------------------
# GraphQL: several operations, aliases, fragments, variables
# ---------------------------------------------------------------------------

GOOD = 'query Good { repository(owner: "octo-org", name: "app") { name } }'
BAD_QUERY = 'query Bad { repository(owner: "other-org", name: "secret") { name } }'
BAD_MUTATION = "mutation Bad { deleteRepository(input: {repositoryId: \"x\"}) { clientMutationId } }"


@pytest.mark.parametrize("bad", [BAD_QUERY, BAD_MUTATION])
@pytest.mark.parametrize("picked", ["Good", "Bad"])
@pytest.mark.parametrize("order", ["good-first", "bad-first"])
def test_every_operation_in_a_request_must_pass_whichever_is_picked(bad, picked, order):
    text = f"{GOOD} {bad}" if order == "good-first" else f"{bad} {GOOD}"
    assert not gql(text, operation=picked).allowed


def test_several_operations_need_a_pick():
    other = 'query Other { viewer { login } }'
    allowed(gql(f"{GOOD} {other}", operation="Good"), "graphql-read")
    allowed(gql(f"{GOOD} {other}", operation="Other"), "graphql-read")
    refused(gql(f"{GOOD} {other}"), "graphql-malformed")
    refused(gql(f"{GOOD} {other}", operation="Missing"), "graphql-malformed")
    refused(gql(f"{GOOD} {other}", operation=""), "graphql-malformed")
    refused(gql(f"{GOOD} {GOOD}", operation="Good"), "graphql-malformed")  # one name twice
    refused(gql(f"{GOOD} {{ viewer {{ login }} }}", operation="Good"), "graphql-malformed")
    refused(gql(GOOD, operation="good"), "graphql-malformed")
    refused(ask("POST", "api.github.com/graphql", {"query": GOOD, "operationName": 5}), "graphql-malformed")
    refused(ask("POST", "api.github.com/graphql", {"query": GOOD, "operationName": ["Good"]}), "graphql-malformed")


def test_the_kind_follows_the_picked_operation():
    change = "mutation Change($input: X!) { createPullRequest(input: $input) { clientMutationId } }"
    variables = {"input": {"repositoryId": APP_ID, "title": "x"}}
    assert allowed(gql(f"{GOOD} {change}", variables, "Change")).kind == "graphql-write"
    assert allowed(gql(f"{GOOD} {change}", variables, "Good")).kind == "graphql-read"


@pytest.mark.parametrize(
    "query",
    [
        "variables=%7B%22owner%22%3A%22other-org%22%2C%22repo%22%3A%22secret%22%7D",
        "variables[owner]=other-org&variables[repo]=secret",
        "operationName=Bad",
        "query=mutation%7BdeleteRepository%7D",
        "x",
    ],
)
def test_a_graphql_request_has_no_query_string(query):
    # With defaults in the text and no `variables` in the body, a server
    # that also reads the query string would take its variables from there.
    text = 'query($owner: String = "octo-org", $repo: String = "app") { repository(owner: $owner, name: $repo) { name } }'
    allowed(ask("POST", "api.github.com/graphql", {"query": text}), "graphql-read")
    refused(ask("POST", f"api.github.com/graphql?{query}", {"query": text}), "query-odd")


def test_a_batch_of_requests_is_refused():
    batch = [{"query": GOOD}, {"query": BAD_MUTATION}]
    refused(ask("POST", "api.github.com/graphql", batch), "body-odd")


def test_an_alias_does_not_hide_what_is_asked_for():
    # The name before the colon is only a label for the answer.
    refused(gql('{ viewer: repository(owner: "other-org", name: "secret") { name } }'), "repo-not-listed")
    refused(gql('{ repository: repositoryOwner(login: "x") { id } }'), "graphql-query-not-allowed")
    refused(gql('mutation { addComment: deleteRepository(input: {repositoryId: "x"}) { clientMutationId } }'), "graphql-mutation-not-allowed")
    refused(
        gql(
            'mutation($a: X!, $b: X!) { one: createPullRequest(input: $a) { clientMutationId }'
            " two: createPullRequest(input: $b) { clientMutationId } }",
            {"a": {"repositoryId": APP_ID}, "b": {"repositoryId": node_id("R", OTHER)}},
        ),
        "graphql-id-not-listed",
    )
    # An allowed name as the label of a refused change.
    refused(
        gql('mutation($a: X!) { createPullRequest: addComment(input: $a) { clientMutationId } }', {"a": {"subjectId": PR_ID}}),
        "graphql-by-id",
    )
    refused(
        gql(
            'mutation($a: X!, $b: X!) { one: createPullRequest(input: $a) { clientMutationId }'
            " two: closePullRequest(input: $b) { clientMutationId } }",
            {"a": {"repositoryId": APP_ID}, "b": {"pullRequestId": PR_ID}},
        ),
        "graphql-by-id",
    )
    # Many aliases of allowed things are fine.
    allowed(
        gql(
            '{ a: repository(owner: "octo-org", name: "app") { name }'
            ' b: repository(owner: "octo-org", name: "library") { name } }'
        ),
        "graphql-read",
    )


def test_a_fragment_does_not_hide_what_is_asked_for():
    for query in (
        'query { ...f } fragment f on Query { repository(owner: "other-org", name: "secret") { name } }',
        'query { ...a } fragment a on Query { ...b } fragment b on Query { ...c }'
        ' fragment c on Query { repository(owner: "other-org", name: "secret") { name } }',
        'query { ... on Query { repository(owner: "other-org", name: "secret") { name } } }',
        'query { ... { ... { repository(owner: "other-org", name: "secret") { name } } } }',
        'query { ... @include(if: true) { repository(owner: "other-org", name: "secret") { name } } }',
    ):
        refused(gql(query), "repo-not-listed")
    for query in (
        "mutation { ...m } fragment m on Mutation { deleteRepository(input: {repositoryId: \"x\"}) { clientMutationId } }",
        "mutation { ... on Mutation { deleteRepository(input: {repositoryId: \"x\"}) { clientMutationId } } }",
    ):
        refused(gql(query), "graphql-mutation-not-allowed")
    refused(gql("query { ...f } fragment f on Query { relay { viewer { login } } }"), "graphql-query-not-allowed")


def test_a_variable_inside_a_fragment_is_followed():
    query = (
        "query($owner: String!, $repo: String!) { ...f }"
        " fragment f on Query { repository(owner: $owner, name: $repo) { name } }"
    )
    allowed(gql(query, REPO_VARS), "graphql-read", "octo-org/app")
    refused(gql(query, {"owner": "other-org", "repo": "secret"}), "repo-not-listed")


@pytest.mark.parametrize(
    "query",
    [
        "query { ...missing }",
        "query { ...f } fragment f on Query { ...f }",
        "query { ...a } fragment a on Query { ...b } fragment b on Query { ...a }",
        "query { viewer { login } } fragment f on Query { ...missing }",
        "query { viewer { login } } fragment f on Query { __typename } fragment f on Query { __typename }",
        "query { viewer { login } } fragment on on Query { __typename }",
    ],
)
def test_broken_fragments_are_refused(query):
    refused(gql(query), "graphql-malformed")


def bounded(decision_maker, seconds=1.0, megabytes=16):
    """Run one check and make sure it stays quick and small.

    It is run twice: once against the clock, and once with Python counting
    the memory it takes, which slows it down too much to time.
    """
    started = time.perf_counter()
    decision = decision_maker()
    took = time.perf_counter() - started
    assert took < seconds, f"took {took:.2f} s"
    tracemalloc.start()
    try:
        decision_maker()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < megabytes * 1024 * 1024, f"used {peak / 1024 / 1024:.0f} MB"
    return decision


def test_fragments_that_use_each_other_twice_are_cheap():
    # Each fragment uses the one before it twice. Opened up naively that is
    # two to the power of nineteen fields.
    parts = ["fragment f0 on Query { __typename }"]
    for number in range(1, policy_module.MAX_FRAGMENTS):
        parts.append(f"fragment f{number} on Query {{ ...f{number - 1} ...f{number - 1} }}")
    last = policy_module.MAX_FRAGMENTS - 1
    allowed(bounded(lambda: gql(f"query {{ ...f{last} }} " + " ".join(parts))), "graphql-read")
    # One fragment more than the limit.
    parts.append(f"fragment f{last + 1} on Query {{ ...f{last} }}")
    refused(bounded(lambda: gql(f"query {{ ...f{last + 1} }} " + " ".join(parts))), "graphql-malformed")


def test_fragments_inside_a_repo_that_use_each_other_twice_are_cheap():
    # The same, below the start: each use is in the same place, so each
    # fragment is looked at once.
    parts = ["fragment f0 on PullRequest { title }"]
    for number in range(1, policy_module.MAX_FRAGMENTS):
        parts.append(f"fragment f{number} on PullRequest {{ ...f{number - 1} number ...f{number - 1} }}")
    last = policy_module.MAX_FRAGMENTS - 1
    text = (IN_APP % f"pullRequest(number: 1) {{ ...f{last} }}") + " " + " ".join(parts)
    allowed(bounded(lambda: gql(text)), "graphql-read", "octo-org/app")
    # One refused field at the bottom is still found.
    bad = text.replace("fragment f0 on PullRequest { title }", "fragment f0 on PullRequest { headRepository { diskUsage } }")
    refused(bounded(lambda: gql(bad)), "graphql-not-on-list")


def test_a_request_may_start_at_a_hundred_things_and_no_more():
    def starts(count):
        return "{ " + " ".join(f"a{n}: viewer {{ login }}" for n in range(count)) + " }"

    assert len(starts(policy_module.MAX_ROOT_FIELDS + 1)) < policy_module.MAX_GRAPHQL
    allowed(gql(starts(policy_module.MAX_ROOT_FIELDS)), "graphql-read")
    refused(gql(starts(policy_module.MAX_ROOT_FIELDS + 1)), "graphql-malformed")


def test_the_request_from_the_review_that_took_a_second_and_400_megabytes():
    # 9000 fragments, each holding one field and the fragment before it.
    parts = ["fragment f0 on Q{a}"] + [f"fragment f{n} on Q{{a...f{n - 1}}}" for n in range(1, 9000)]
    text = "".join(parts) + '{repository(owner:"octo-org",name:"app"){...f8999}}'
    assert len(text) > 250_000
    refused(bounded(lambda: gql(text), seconds=0.5), "graphql-malformed")
    # The same shape cut down to just under the size limit is stopped by the
    # limit on fragments.
    count = 800
    text = "".join(parts[:count]) + '{repository(owner:"octo-org",name:"app"){...f%d}}' % (count - 1)
    assert len(text) < policy_module.MAX_GRAPHQL
    refused(bounded(lambda: gql(text), seconds=0.5), "graphql-malformed")


def test_a_request_that_makes_the_check_repeat_itself_is_cut_off():
    # Long fragments of plain fields, each used in many places. Every use
    # has to be looked at, so the work is counted and capped.
    names = " ".join(f"x{n}" for n in range(200))
    count = policy_module.MAX_FRAGMENTS
    fragments = " ".join(f"fragment f{n} on Node {{ {names} }}" for n in range(count))
    spreads = " ".join(f"...f{n}" for n in range(count))
    places = (
        "%s pullRequest(number: 1) { %s comments(first: 1) { %s nodes { %s } } reviews(first: 1) { %s nodes { %s } }"
        " commits(first: 1) { %s nodes { %s commit { %s statusCheckRollup { %s contexts(first: 1) { %s } } } } }"
        " labels(first: 1) { %s nodes { %s } } milestone { %s } files(first: 1) { %s nodes { %s } } }"
        " issue(number: 1) { %s comments(first: 1) { %s nodes { %s } } labels(first: 1) { %s } milestone { %s } }"
        " releases(first: 1) { %s nodes { %s } } labels(first: 1) { %s nodes { %s } }"
    )
    text = (IN_APP % (places % ((spreads,) * places.count("%s")))) + " " + fragments
    assert len(text) < policy_module.MAX_GRAPHQL
    refused(bounded(lambda: gql(text)), "graphql-malformed")
    # A tenth of it is fine, and quick.
    small = (IN_APP % f"{spreads} pullRequest(number: 1) {{ {spreads} }}") + " " + fragments
    allowed(bounded(lambda: gql(small)), "graphql-read")


def test_too_many_operations_in_one_request():
    some = " ".join(f"query Q{n} {{ viewer {{ login }} }}" for n in range(policy_module.MAX_OPERATIONS))
    allowed(gql(some, operation="Q0"), "graphql-read")
    refused(gql(some + " query Extra { viewer { login } }", operation="Q0"), "graphql-malformed")


def test_a_fragment_nobody_uses_is_refused():
    # GitHub refuses it too. Here it means nothing in a request goes unread.
    refused(gql("{ viewer { login } } fragment unused on User { email }"), "graphql-malformed")
    refused(
        gql('{ viewer { login } } fragment unused on Query { repository(owner: "other-org", name: "secret") { name } }'),
        "graphql-malformed",
    )


def test_every_hostile_request_in_this_file_is_checked_quickly():
    deep = "{ " * 49 + "x" + " }" * 49
    wide = "{ " + " ".join(f"a{n}: viewer {{ login }}" for n in range(2000)) + " }"
    strings = '{ repository(owner: "%s", name: "app") { name } }' % ("o" * 30_000)
    escapes = '{ repository(owner: "%s", name: "app") { name } }' % ("\\u006f" * 4_000)
    comments = "#" + "x" * 30_000 + "\n{ viewer { login } }"
    for text in (deep, wide, strings, escapes, comments, "{" * 30_000, "(" * 30_000, '"' * 30_001, "." * 30_000, "$a" * 15_000):
        decision = bounded(lambda: gql(text), seconds=0.5)
        assert decision.allowed or decision.reason in ("graphql-malformed", "repo-not-listed", "graphql-query-not-allowed")
    variables = {"a": [[[["x"] * 10] * 10] * 10] * 10}
    allowed(bounded(lambda: gql("{ viewer { login } }", variables)), "graphql-read")


def test_a_default_value_is_used_only_when_no_value_is_sent():
    query = 'query($owner: String = "octo-org", $repo: String = "app") { repository(owner: $owner, name: $repo) { name } }'
    allowed(gql(query), "graphql-read", "octo-org/app")
    allowed(gql(query, {}), "graphql-read", "octo-org/app")
    # A value that is sent wins over the default...
    refused(gql(query, {"owner": "other-org", "repo": "secret"}), "repo-not-listed")
    # ...and so does an explicit null.
    refused(gql(query, {"repo": None}), "graphql-malformed")
    bad_default = 'query($repo: String = "secret") { repository(owner: "other-org", name: $repo) { name } }'
    refused(gql(bad_default), "repo-not-listed")
    allowed(gql(bad_default.replace("other-org", "octo-org"), {"repo": "app"}))


def test_a_change_written_into_the_query_instead_of_variables():
    inline = 'mutation { createPullRequest(input: {repositoryId: "%s", title: "x"}) { clientMutationId } }'
    allowed(gql(inline % APP_ID), "graphql-write", "octo-org/app")
    refused(gql(inline % node_id("R", OTHER)), "graphql-id-not-listed")
    # Partly from a variable.
    mixed = 'mutation($id: ID!) { createPullRequest(input: {repositoryId: $id, title: "x"}) { clientMutationId } }'
    allowed(gql(mixed, {"id": APP_ID}), "graphql-write")
    refused(gql(mixed, {"id": node_id("R", OTHER)}), "graphql-id-not-listed")
    refused(gql(mixed, {}), "graphql-malformed")
    # The same name twice in one input, or the input given twice.
    twice = 'mutation { createPullRequest(input: {repositoryId: "%s", repositoryId: "%s"}) { clientMutationId } }'
    refused(gql(twice % (APP_ID, node_id("R", OTHER))), "graphql-malformed")
    refused(gql('mutation { createPullRequest(input: {repositoryId: "%s"}, input: {}) { clientMutationId } }' % APP_ID), "graphql-malformed")
    refused(gql('mutation { createPullRequest(input: {repositoryId: "%s"}, other: 1) { clientMutationId } }' % APP_ID), "graphql-malformed")
    refused(gql("mutation { createPullRequest { clientMutationId } }"), "graphql-malformed")


@pytest.mark.parametrize(
    "bad",
    [
        (
            "mutation Bad($input: X!) { closePullRequest(input: $input) { clientMutationId } }",
            {"input": {"pullRequestId": PR_ID}},
        ),
        ('query Bad($id: ID!) { node(id: $id) { id } }', {"id": PR_ID}),
    ],
)
def test_a_change_by_id_is_not_hidden_next_to_an_allowed_operation(bad):
    text, variables = bad
    for picked in ("Good", "Bad"):
        refused(gql(f"{GOOD} {text}", variables, picked), "graphql-by-id")
        refused(gql(f"{text} {GOOD}", variables, picked), "graphql-by-id")


def test_directives_do_not_switch_a_check_off():
    refused(
        gql('query($no: Boolean = false) { repository(owner: "other-org", name: "secret") @include(if: $no) { name } }'),
        "repo-not-listed",
    )
    refused(
        gql("mutation { deleteRepository(input: {repositoryId: \"x\"}) @skip(if: true) { clientMutationId } }"),
        "graphql-mutation-not-allowed",
    )


# ---------------------------------------------------------------------------
# GraphQL: walking on from an allowed start
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "inner",
    [
        "owner { repositories(first: 100) { nodes { name } } }",
        "owner { ... on User { repositories(first: 100) { nodes { name } } } }",
        "owner { ...walk }",
        'owner { repository(name: "secret") { object(expression: "HEAD:.env") { ... on Blob { text } } } }',
        "owner { ... on User { gists(first: 10) { nodes { files { text } } } } }",
        'owner { ... on User { gist(name: "abc") { files { text } } } }',
        "owner { ... on User { starredRepositories(first: 1) { nodes { name } } } }",
        "owner { ... on User { watching(first: 1) { nodes { name } } } }",
        "owner { ... on User { repositoriesContributedTo(first: 1) { nodes { name } } } }",
        "owner { ... on User { topRepositories(first: 1) { nodes { name } } } }",
        "owner { ... on User { organizations(first: 1) { nodes { login } } } }",
        "owner { ... on User { pinnedItems(first: 1) { nodes { __typename } } } }",
        "pullRequest(number: 1) { author { ... on User { repositories(first: 1) { nodes { name } } } } }",
        "sneaky: owner { hidden: repositories(first: 1) { nodes { name } } }",
    ],
)
def test_a_query_may_not_walk_from_a_listed_repo_to_lists_of_others(inner):
    query = (
        '{ repository(owner: "octo-org", name: "app") { %s } }'
        " fragment walk on RepositoryOwner { repositories(first: 100) { nodes { name } } }" % inner
    )
    if "...walk" not in inner:
        query = query.split(" fragment walk")[0]
    refused(gql(query), "graphql-not-on-list")


@pytest.mark.parametrize(
    ("inner", "reason"),
    [
        ("collaborators(first: 100) { nodes { login } }", "collaborators"),
        ("deployKeys(first: 10) { nodes { key } }", "deploy-keys"),
        ("pullRequest(number: 1) { repository { collaborators(first: 1) { totalCount } } }", "collaborators"),
        ("...closed", "deploy-keys"),
    ],
)
def test_what_is_closed_in_the_rest_api_is_closed_in_graphql(inner, reason):
    query = (
        '{ repository(owner: "octo-org", name: "app") { %s } }'
        " fragment closed on Repository { deployKeys(first: 1) { totalCount } }" % inner
    )
    if "...closed" not in inner:
        query = query.split(" fragment closed")[0]
    refused(gql(query), reason)


def test_a_change_may_not_walk_away_in_what_it_asks_back():
    query = (
        "mutation($input: X!) { createPullRequest(input: $input) {"
        " pullRequest { repository { owner { repositories(first: 100) { nodes { name } } } } } } }"
    )
    refused(gql(query, {"input": {"repositoryId": APP_ID}}), "graphql-not-on-list")


IN_APP = 'query { repository(owner: "octo-org", name: "app") { %s } }'
FILE = 'object(expression: "HEAD:README.md") { ... on Blob { text } }'

# Each of these starts at a listed repo and walks out of it. They came from
# the review of this module, which found them all allowed.
WALKS_OUT = [
    "owner { ... on User { pullRequests(first: 100) { nodes { repository { nameWithOwner isPrivate %s } } } } }" % FILE,
    "owner { ... on User { issues(first: 100) { nodes { body repository { nameWithOwner } } } } }",
    "owner { ... on User { contributionsCollection { commitContributionsByRepository { repository { nameWithOwner isPrivate } } } } }",
    'owner { ... on User { organization(login: "x") { teams(first: 10) { nodes { members { nodes { login email } } } } } } }',
    "owner { ... on Organization { membersWithRole(first: 100) { nodes { login email } } } }",
    "owner { repositories(first: 100) { nodes { name } } }",
    'owner { repository(name: "secret") { name } }',
    "forks(first: 100) { nodes { nameWithOwner %s } }" % FILE,
    "forks(first: 100) { nodes { nameWithOwner } }",
    "parent { %s }" % FILE,
    "parent { forks(first: 10) { nodes { name } } }",
    "parent { pullRequests(first: 10) { nodes { body } } }",
    "parent { owner { repositories(first: 10) { nodes { name } } } }",
    "parent { parent { name } }",
    "templateRepository { %s }" % FILE,
    "pullRequest(number: 1) { headRepository { %s } }" % FILE,
    "pullRequest(number: 1) { headRepository { defaultBranchRef { target { ... on Commit { history(first: 10) { nodes { message } } } } } } }",
    "pullRequest(number: 1) { baseRepository { %s } }" % FILE,
    "pullRequest(number: 1) { repository { %s } }" % FILE,
    "pullRequest(number: 1) { repository { pullRequests(first: 10) { nodes { body } } } }",
    "pullRequest(number: 1) { headRef { repository { %s } } }" % FILE,
    "pullRequest(number: 1) { author { ... on User { repositories(first: 10) { nodes { name } } } } }",
    "pullRequest(number: 1) { author { ... on User { email } } }",
    "pullRequest(number: 1) { closingIssuesReferences(first: 10) { nodes { body } } }",
    "pullRequest(number: 1) { closingIssuesReferences(first: 10) { nodes { comments(first: 10) { nodes { body } } } } }",
    "pullRequest(number: 1) { closingIssuesReferences(first: 10) { nodes { repository { %s } } } }" % FILE,
    "pullRequest(number: 1) { timelineItems(first: 10) { nodes { ... on CrossReferencedEvent { source { ... on Issue { body } } } } } }",
    "pullRequest(number: 1) { commits(first: 1) { nodes { commit { associatedPullRequests(first: 10) { nodes { repository { name } } } } } } }",
    "pullRequest(number: 1) { projectItems(first: 10) { nodes { project { repositories(first: 10) { nodes { name } } } } } }",
    "pullRequest(number: 1) { projectItems(first: 10) { nodes { project { items(first: 10) { nodes { content { ... on Issue { body } } } } } } } }",
    "pullRequest(number: 1) { reviewRequests(first: 10) { nodes { requestedReviewer { ... on Team { members { nodes { email } } } } } } }",
    "pullRequest(number: 1) { reviewRequests(first: 10) { nodes { requestedReviewer { ... on Team { repositories(first: 10) { nodes { name } } } } } } }",
    "issue(number: 1) { parent { body } }",
    "issue(number: 1) { subIssues(first: 10) { nodes { body comments(first: 10) { nodes { body } } } } }",
    "issue(number: 1) { blockedBy(first: 10) { nodes { repository { %s } } } }" % FILE,
    "issue(number: 1) { closedByPullRequestsReferences(first: 10) { nodes { body } } }",
    "issue(number: 1) { repository { %s } }" % FILE,
    "issue(number: 1) { assignees(first: 10) { nodes { repositories(first: 10) { nodes { name } } } } }",
    "issue(number: 1) { assignees(first: 10) { nodes { email } } }",
    "issue(number: 1) { reactionGroups { users(first: 10) { nodes { email } } } }",
    "issue(number: 1) { comments(first: 10) { nodes { author { ... on User { gists(first: 10) { nodes { name } } } } } } }",
    "watchers(first: 10) { nodes { repositories(first: 10) { nodes { name } } } }",
    "stargazers(first: 10) { nodes { repositories(first: 10) { nodes { name } } } }",
    "repositoryTopics(first: 10) { nodes { topic { repositories(first: 10) { nodes { name } } } } }",
    # Things of the listed repo itself that gh does not read through GraphQL.
    FILE,
    "defaultBranchRef { target { ... on Commit { history(first: 10) { nodes { message } } } } }",
    "collaborators(first: 10) { nodes { login } }",
    "branchProtectionRules(first: 10) { nodes { pushAllowances(first: 10) { nodes { actor { ... on User { login } } } } } }",
    "defaultBranchRef { branchProtectionRule { pushAllowances(first: 10) { nodes { actor { ... on User { login } } } } } }",
    "discussions(first: 10) { nodes { body } }",
    "environments(first: 10) { nodes { name } }",
    "vulnerabilityAlerts(first: 10) { nodes { id } }",
    "somethingNew { id }",
]


OUTSIDE = ("Account", "Reviewer", "OtherRepository", "OtherRef", "Reference", "Project")


def test_the_steps_that_lead_out_of_the_listed_repo_are_exactly_these():
    # Written out, so that adding one is a decision somebody makes and reads,
    # and not a line that slips into a long table. Each leads to a place
    # where only a few named plain fields may be read.
    table = policy_module.INSIDE
    leaving = sorted(
        (place, step, there)
        for place, steps in table.items()
        if place not in OUTSIDE
        for step, there in steps.items()
        if there in OUTSIDE
    )
    assert leaving == [
        ("AutoMergeRequest", "enabledBy", "Account"),
        ("GitActor", "user", "Account"),
        ("Issue", "assignees", "Account"),
        ("Issue", "author", "Account"),
        ("Issue", "blockedBy", "Reference"),
        ("Issue", "blocking", "Reference"),
        ("Issue", "closedByPullRequestsReferences", "Reference"),
        ("Issue", "parent", "Reference"),
        ("Issue", "projectCards", "Project"),
        ("Issue", "projectItems", "Project"),
        ("Issue", "repository", "OtherRepository"),
        ("Issue", "subIssues", "Reference"),
        ("IssueComment", "author", "Account"),
        ("PullRequest", "assignees", "Account"),
        ("PullRequest", "author", "Account"),
        ("PullRequest", "closingIssuesReferences", "Reference"),
        ("PullRequest", "headRepository", "OtherRepository"),
        ("PullRequest", "headRepositoryOwner", "Account"),
        ("PullRequest", "mergedBy", "Account"),
        ("PullRequest", "projectCards", "Project"),
        ("PullRequest", "projectItems", "Project"),
        ("PullRequest", "repository", "OtherRepository"),
        ("PullRequestReview", "author", "Account"),
        ("ReactionGroup", "users", "Account"),
        ("Repository", "owner", "Account"),
        ("Repository", "parent", "OtherRepository"),
        ("Repository", "projects", "Project"),
        ("Repository", "templateRepository", "OtherRepository"),
        ("Repository", "watchers", "Account"),
        ("ReviewRequest", "requestedReviewer", "Reviewer"),
    ]
    # And from those places, the only steps on.
    onward = sorted((place, step, there) for place in OUTSIDE for step, there in table[place].items())
    assert onward == [
        ("Account", "edges", "Account"),
        ("Account", "node", "Account"),
        ("Account", "nodes", "Account"),
        ("Account", "pageInfo", "PageInfo"),
        ("OtherRepository", "defaultBranchRef", "OtherRef"),
        ("OtherRepository", "owner", "Account"),
        ("Project", "column", "Project"),
        ("Project", "edges", "Project"),
        ("Project", "fieldValueByName", "Project"),
        ("Project", "node", "Project"),
        ("Project", "nodes", "Project"),
        ("Project", "pageInfo", "PageInfo"),
        ("Project", "project", "Project"),
        ("Reference", "edges", "Reference"),
        ("Reference", "node", "Reference"),
        ("Reference", "nodes", "Reference"),
        ("Reference", "pageInfo", "PageInfo"),
        ("Reference", "repository", "OtherRepository"),
        ("Reviewer", "organization", "Account"),
    ]


def test_the_list_has_the_size_it_had_when_it_was_checked_against_githubs_schema():
    # A change to the list should come with a new check against the schema,
    # as described in docs/github-rules.md.
    table = policy_module.INSIDE
    assert (len(table), sum(len(steps) for steps in table.values())) == (66, 130)


@pytest.mark.parametrize("inner", WALKS_OUT)
def test_a_query_may_not_walk_out_of_the_listed_repo(inner):
    for used in (POLICY, PUBLIC):
        decision = gql(IN_APP % inner, policy=used)
        assert not decision.allowed
        assert decision.reason in ("graphql-not-on-list", "collaborators"), decision.reason
    # The same walk from a repo asked for by its id.
    by_id = 'query { node(id: "%s") { ... on Repository { %s } } }' % (APP_ID, inner)
    assert gql(by_id).reason in ("graphql-not-on-list", "collaborators")
    # ...in a fragment, so that it is not written out in place.
    in_fragment = 'query { repository(owner: "octo-org", name: "app") { ...f } } fragment f on Repository { %s }' % inner
    assert gql(in_fragment).reason in ("graphql-not-on-list", "collaborators")


@pytest.mark.parametrize(
    "inner",
    [
        "repository { owner { repositories(first: 100) { nodes { name } } } }",
        "repository { %s }" % FILE,
        "headRepository { %s }" % FILE,
        "author { ... on User { repositories(first: 10) { nodes { name } } } }",
        "closingIssuesReferences(first: 10) { nodes { body } }",
        "commits(first: 1) { nodes { commit { tree { entries { name object { ... on Blob { text } } } } } } }",
    ],
)
def test_the_answer_to_a_change_may_not_walk_out_either(inner):
    query = "mutation($input: X!) { createPullRequest(input: $input) { pullRequest { %s } } }" % inner
    refused(gql(query, {"input": {"repositoryId": APP_ID, "title": "t"}}), "graphql-not-on-list")
    # What gh asks back is fine.
    asked_back = "mutation($input: X!) { createPullRequest(input: $input) { clientMutationId pullRequest { id url number } } }"
    allowed(gql(asked_back, {"input": {"repositoryId": APP_ID, "title": "t"}}), "graphql-write")


def test_a_search_result_may_not_walk_out_either():
    walk = "{ search(query: \"repo:octo-org/app is:pr\", type: ISSUE, first: 10) { nodes { ... on PullRequest { %s } } } }"
    allowed(gql(walk % "number title headRepository { nameWithOwner } author { login }"), "graphql-read")
    refused(gql(walk % ("headRepository { %s }" % FILE)), "graphql-not-on-list")
    refused(gql(walk % "author { ... on User { repositories(first: 1) { nodes { name } } } }"), "graphql-not-on-list")
    refused(gql("{ search(query: \"repo:octo-org/app\", type: ISSUE, first: 10) { nodes { ... on Repository { name } } } }"), "graphql-not-on-list")
    refused(gql("{ search(query: \"repo:octo-org/app\", type: ISSUE, first: 10) { nodes { ... on User { email } } } }"), "graphql-not-on-list")


def test_the_few_things_readable_of_an_account_or_another_repo():
    # What gh's own queries read there, and no more.
    allowed(
        gql(
            IN_APP
            % (
                "owner { id login ... on User { name } }"
                " parent { id databaseId name nameWithOwner sshUrl description viewerPermission"
                "   owner { login } defaultBranchRef { name } }"
                " templateRepository { id name owner { id login } }"
                " pullRequest(number: 1) {"
                "   repository { id name nameWithOwner owner { id login } }"
                "   headRepository { id name nameWithOwner } headRepositoryOwner { id login ... on User { name } }"
                "   author { login ... on User { id name } } mergedBy { login }"
                "   assignees(first: 100) { nodes { id login name databaseId } totalCount }"
                "   reviewRequests(first: 100) { nodes { requestedReviewer { __typename ... on User { login name }"
                "     ... on Bot { login } ... on Team { organization { login } name slug } } } }"
                "   closingIssuesReferences(first: 100) { nodes { id number url repository { id name owner { id login } } }"
                "     pageInfo { hasNextPage endCursor } }"
                "   projectItems(first: 100) { totalCount nodes { id project { id title } } }"
                "   reactionGroups { content users { totalCount } }"
                " }"
                " issue(number: 1) { parent { id number title url state repository { nameWithOwner } }"
                "   subIssues(first: 100) { nodes { id number title url state repository { nameWithOwner } } totalCount } }"
                " forkCount"
            )
        ),
        "graphql-read",
        "octo-org/app",
    )


@pytest.mark.parametrize(
    "inner",
    [
        "owner { email }",
        "owner { ... on User { email bio company } }",
        "owner { ... on Organization { description } }",
        "parent { diskUsage }",
        "parent { homepageUrl }",
        "parent { defaultBranchRef { target { oid } } }",
        "parent { defaultBranchRef { associatedPullRequests(first: 1) { nodes { title } } } }",
        "pullRequest(number: 1) { headRepository { pushedAt } }",
        "pullRequest(number: 1) { closingIssuesReferences(first: 1) { nodes { bodyText } } }",
        "pullRequest(number: 1) { projectItems(first: 1) { nodes { project { readme } } } }",
        "pullRequest(number: 1) { reviewRequests(first: 1) { nodes { requestedReviewer { ... on Team { description } } } } }",
        # An alias that reads like an allowed field.
        "owner { login: email }",
        "parent { name: diskUsage }",
    ],
)
def test_plain_fields_outside_the_listed_repo_are_named_one_by_one(inner):
    decision = refused(gql(IN_APP % inner), "graphql-not-on-list")
    assert "only these may be read" in decision.message


def test_a_type_claimed_for_fields_does_not_unlock_them():
    # Inside an account, saying "these are a pull request's fields" changes
    # nothing: they are judged as an account's.
    refused(gql(IN_APP % "owner { ... on PullRequest { body } }"), "graphql-not-on-list")
    refused(gql(IN_APP % "owner { ... on Repository { %s } }" % FILE), "graphql-not-on-list")
    in_fragment = 'query { repository(owner: "octo-org", name: "app") { owner { ...f } } } fragment f on Repository { diskUsage }'
    refused(gql(in_fragment), "graphql-not-on-list")
    refused(gql(IN_APP % "parent { ... on Issue { body } }"), "graphql-not-on-list")
    # Where one of several types is possible, only those may be named.
    refused(gql(IN_APP % "issueOrPullRequest(number: 1) { ... on Repository { name } }"), "graphql-not-on-list")
    refused(gql(IN_APP % "issueOrPullRequest(number: 1) { title }"), "graphql-not-on-list")
    allowed(gql(IN_APP % "issueOrPullRequest(number: 1) { __typename ... on Issue { title } ... on PullRequest { title } }"))


def test_what_may_be_read_is_a_list_and_anything_else_is_refused():
    table = policy_module.INSIDE
    # Every place a step leads to is itself on the list.
    for place, steps in table.items():
        for step, there in steps.items():
            assert there in table, (place, step, there)
    # A step into the place where a whole repo is readable exists only at the start.
    assert not [(place, step) for place, steps in table.items() for step, there in steps.items() if there == "Repository"]
    # The places that stand for something outside the listed repo allow named plain fields only.
    for place in ("Account", "Reviewer", "OtherRepository", "OtherRef", "Reference", "Project"):
        assert place in policy_module.ONLY
        assert policy_module.ONLY[place] <= {
            "login", "id", "databaseId", "name", "url", "totalCount", "__typename", "slug", "nameWithOwner", "sshUrl",
            "description", "isPrivate", "isFork", "isArchived", "hasIssuesEnabled", "hasWikiEnabled",
            "viewerPermission", "prefix", "number", "title", "state", "body", "resourcePath", "optionId",
        }
    # ...and lead only to more places of that kind.
    outside = {"Account", "Reviewer", "OtherRepository", "OtherRef", "Reference", "Project", "PageInfo"}
    for place in outside - {"PageInfo"}:
        assert set(table[place].values()) <= outside, place
    # Nobody reaches an account, another repo or a reference by a step that leads to a full one.
    for place, steps in table.items():
        for step in ("owner", "author", "mergedBy", "enabledBy", "headRepositoryOwner", "user", "users", "assignees", "watchers"):
            assert steps.get(step, "Account") == "Account", (place, step)
        for step in ("parent", "headRepository", "baseRepository", "templateRepository", "forks"):
            if place == "Issue" and step == "parent":
                assert steps[step] == "Reference"
            else:
                assert steps.get(step, "OtherRepository") == "OtherRepository", (place, step)
        if place != "Repository":
            assert "repository" not in steps or steps["repository"] == "OtherRepository"


# ---------------------------------------------------------------------------
# GraphQL: every query gh was recorded sending
# ---------------------------------------------------------------------------
#
# Recorded with GH_DEBUG=api from gh 2.102, whole, by running each command
# against one repo. Only the repo's name is changed. `--json (every field)`
# stands for the full list of fields the command offers.
#
# This is the other half of the list of what may be read: the list keeps
# queries from walking out of the repo, and these keep it from being so short
# that gh stops working.

RECORDED = [
    (
        'gh pr view 2 --json (every field)',
        {'owner': 'octo-org', 'pr_number': 2, 'repo': 'app'},
        r"""query PullRequestByNumber($owner: String!, $repo: String!, $pr_number: Int!) {
    repository(owner: $owner, name: $repo) {
      pullRequest(number: $pr_number) {additions,assignees(first:100){nodes{id,login,name,databaseId},totalCount},author{login,...on User{id,name}},autoMergeRequest {authorEmail,commitBody,commitHeadline,mergeMethod,enabledAt,enabledBy{login,...on User{id,name}}},baseRefName,baseRefOid,body,changedFiles,closed,closedAt,closingIssuesReferences(first: 100) {nodes {id,number,url,repository {id,name,owner {id,login}}}pageInfo{hasNextPage,endCursor}},comments(first: 100) {nodes {id,author{login,...on User{id,name}},authorAssociation,body,createdAt,includesCreatedEdit,isMinimized,minimizedReason,reactionGroups{content,users{totalCount}},url,viewerDidAuthor},pageInfo{hasNextPage,endCursor},totalCount},commits(first: 100) {nodes {commit {authors(first:100) {nodes {name,email,user{id,login}}},messageHeadline,messageBody,oid,committedDate,authoredDate}}},createdAt,deletions,files(first: 100) {nodes {additions,deletions,path,changeType}},fullDatabaseId,headRefName,headRefOid,headRepository{id,name,nameWithOwner},headRepositoryOwner{id,login,...on User{name}},id,isCrossRepository,isDraft,labels(first:100){nodes{id,name,description,color},totalCount},latestReviews(first: 100) {nodes {author{login},authorAssociation,submittedAt,body,state}},maintainerCanModify,mergeCommit{oid},mergeStateStatus,mergeable,mergedAt,mergedBy{login,...on User{id,name}},milestone{number,title,description,dueOn},number,potentialMergeCommit{oid},reactionGroups{content,users{totalCount}},reviewDecision,reviewRequests(first: 100) {nodes {requestedReviewer {__typename,...on User{login,name},...on Bot{login},...on Team{organization{login}name,slug}}}},reviews(first: 100) {nodes {id,author{login},authorAssociation,submittedAt,body,state,commit{oid},reactionGroups{content,users{totalCount}}}pageInfo{hasNextPage,endCursor}totalCount},state,statusCheckRollup: commits(last: 1) {nodes {commit {statusCheckRollup {contexts(first:100) {nodes {__typename...on StatusContext {context,state,targetUrl,createdAt,description},...on CheckRun {name,checkSuite{workflowRun{workflow{name}}},status,conclusion,startedAt,completedAt,detailsUrl}},pageInfo{hasNextPage,endCursor}}}}}},title,updatedAt,url}
    }
  }""",
    ),
    (
        'gh pr view 2 --json (every field)',
        {'endCursor': None, 'name': 'app', 'number': 2, 'owner': 'octo-org'},
        r"""query PullRequestProjectItems($endCursor:String$name:String!$number:Int!$owner:String!){repository(owner: $owner, name: $name){pullRequest(number: $number){projectItems(first: 100, after: $endCursor){totalCount,nodes{id,project{id,title},status:fieldValueByName(name: "Status"){... on ProjectV2ItemFieldSingleSelectValue{optionId,name}}},pageInfo{hasNextPage,endCursor}}}}}""",
    ),
    (
        'gh pr view 2',
        {'owner': 'octo-org', 'pr_number': 2, 'repo': 'app'},
        r"""query PullRequestByNumber($owner: String!, $repo: String!, $pr_number: Int!) {
    repository(owner: $owner, name: $repo) {
      pullRequest(number: $pr_number) {url,number,title,state,body,author{login,...on User{id,name}},autoMergeRequest {authorEmail,commitBody,commitHeadline,mergeMethod,enabledAt,enabledBy{login,...on User{id,name}}},isDraft,maintainerCanModify,mergeable,additions,deletions,commits{totalCount},baseRefName,headRefName,headRepositoryOwner{id,login,...on User{name}},headRepository{id,name,nameWithOwner},isCrossRepository,reviewRequests(first: 100) {nodes {requestedReviewer {__typename,...on User{login,name},...on Bot{login},...on Team{organization{login}name,slug}}}},reviews(first: 100) {nodes {id,author{login},authorAssociation,submittedAt,body,state,commit{oid},reactionGroups{content,users{totalCount}}}pageInfo{hasNextPage,endCursor}totalCount},assignees(first:100){nodes{id,login,name,databaseId},totalCount},labels(first:100){nodes{id,name,description,color},totalCount},milestone{number,title,description,dueOn},comments(first: 100) {nodes {id,author{login,...on User{id,name}},authorAssociation,body,createdAt,includesCreatedEdit,isMinimized,minimizedReason,reactionGroups{content,users{totalCount}},url,viewerDidAuthor},pageInfo{hasNextPage,endCursor},totalCount},reactionGroups{content,users{totalCount}},createdAt,statusCheckRollup: commits(last: 1) {nodes {commit {statusCheckRollup {contexts(first:100) {nodes {__typename...on StatusContext {context,state,targetUrl,createdAt,description},...on CheckRun {name,checkSuite{workflowRun{workflow{name}}},status,conclusion,startedAt,completedAt,detailsUrl}},pageInfo{hasNextPage,endCursor}}}}}},id}
    }
  }""",
    ),
    (
        'gh pr view phase-5-github-policy',
        {'headRefName': 'phase-5-github-policy', 'owner': 'octo-org', 'repo': 'app', 'states': None},
        r"""query PullRequestForBranch($owner: String!, $repo: String!, $headRefName: String!, $states: [PullRequestState!]) {
    repository(owner: $owner, name: $repo) {
      pullRequests(headRefName: $headRefName, states: $states, first: 30, orderBy: { field: CREATED_AT, direction: DESC }) {
        nodes {url,number,title,state,body,author{login,...on User{id,name}},autoMergeRequest {authorEmail,commitBody,commitHeadline,mergeMethod,enabledAt,enabledBy{login,...on User{id,name}}},isDraft,maintainerCanModify,mergeable,additions,deletions,commits{totalCount},baseRefName,headRefName,headRepositoryOwner{id,login,...on User{name}},headRepository{id,name,nameWithOwner},isCrossRepository,reviewRequests(first: 100) {nodes {requestedReviewer {__typename,...on User{login,name},...on Bot{login},...on Team{organization{login}name,slug}}}},reviews(first: 100) {nodes {id,author{login},authorAssociation,submittedAt,body,state,commit{oid},reactionGroups{content,users{totalCount}}}pageInfo{hasNextPage,endCursor}totalCount},assignees(first:100){nodes{id,login,name,databaseId},totalCount},labels(first:100){nodes{id,name,description,color},totalCount},milestone{number,title,description,dueOn},comments(first: 100) {nodes {id,author{login,...on User{id,name}},authorAssociation,body,createdAt,includesCreatedEdit,isMinimized,minimizedReason,reactionGroups{content,users{totalCount}},url,viewerDidAuthor},pageInfo{hasNextPage,endCursor},totalCount},reactionGroups{content,users{totalCount}},createdAt,statusCheckRollup: commits(last: 1) {nodes {commit {statusCheckRollup {contexts(first:100) {nodes {__typename...on StatusContext {context,state,targetUrl,createdAt,description},...on CheckRun {name,checkSuite{workflowRun{workflow{name}}},status,conclusion,startedAt,completedAt,detailsUrl}},pageInfo{hasNextPage,endCursor}}}}}},id}
      }
      defaultBranchRef { name }
    }
  }""",
    ),
    (
        'gh pr list --state all --json (every field)',
        {'limit': 30, 'owner': 'octo-org', 'repo': 'app', 'state': ['OPEN', 'CLOSED', 'MERGED']},
        r"""fragment pr on PullRequest{additions,assignees(first:100){nodes{id,login,name,databaseId},totalCount},author{login,...on User{id,name}},autoMergeRequest {authorEmail,commitBody,commitHeadline,mergeMethod,enabledAt,enabledBy{login,...on User{id,name}}},baseRefName,baseRefOid,body,changedFiles,closed,closedAt,closingIssuesReferences(first: 100) {nodes {id,number,url,repository {id,name,owner {id,login}}}pageInfo{hasNextPage,endCursor}},comments(first: 100) {nodes {id,author{login,...on User{id,name}},authorAssociation,body,createdAt,includesCreatedEdit,isMinimized,minimizedReason,reactionGroups{content,users{totalCount}},url,viewerDidAuthor},pageInfo{hasNextPage,endCursor},totalCount},commits(first: 100) {nodes {commit {authors(first:100) {nodes {name,email,user{id,login}}},messageHeadline,messageBody,oid,committedDate,authoredDate}}},createdAt,deletions,files(first: 100) {nodes {additions,deletions,path,changeType}},fullDatabaseId,headRefName,headRefOid,headRepository{id,name,nameWithOwner},headRepositoryOwner{id,login,...on User{name}},id,isCrossRepository,isDraft,labels(first:100){nodes{id,name,description,color},totalCount},latestReviews(first: 100) {nodes {author{login},authorAssociation,submittedAt,body,state}},maintainerCanModify,mergeCommit{oid},mergeStateStatus,mergeable,mergedAt,mergedBy{login,...on User{id,name}},milestone{number,title,description,dueOn},number,potentialMergeCommit{oid},projectCards(first:100){nodes{project{name}column{name}},totalCount},projectItems(first:100){nodes{id, project{id,title}, status:fieldValueByName(name: "Status") { ... on ProjectV2ItemFieldSingleSelectValue{optionId,name}}},totalCount},reactionGroups{content,users{totalCount}},reviewDecision,reviewRequests(first: 100) {nodes {requestedReviewer {__typename,...on User{login,name},...on Bot{login},...on Team{organization{login}name,slug}}}},reviews(first: 100) {nodes {id,author{login},authorAssociation,submittedAt,body,state,commit{oid},reactionGroups{content,users{totalCount}}}pageInfo{hasNextPage,endCursor}totalCount},state,statusCheckRollup: commits(last: 1) {nodes {commit {statusCheckRollup {contexts(first:100) {nodes {__typename...on StatusContext {context,state,targetUrl,createdAt,description},...on CheckRun {name,checkSuite{workflowRun{workflow{name}}},status,conclusion,startedAt,completedAt,detailsUrl}},pageInfo{hasNextPage,endCursor}}}}}},title,updatedAt,url}
    query PullRequestList(
      $owner: String!,
      $repo: String!,
      $limit: Int!,
      $endCursor: String,
      $baseBranch: String,
      $headBranch: String,
      $state: [PullRequestState!] = OPEN
    ) {
      repository(owner: $owner, name: $repo) {
        pullRequests(
          states: $state,
          baseRefName: $baseBranch,
          headRefName: $headBranch,
          first: $limit,
          after: $endCursor,
          orderBy: {field: CREATED_AT, direction: DESC}
        ) {
          totalCount
          nodes {
            ...pr
          }
          pageInfo {
            hasNextPage
            endCursor
          }
        }
      }
    }""",
    ),
    (
        'gh pr list',
        {'limit': 30, 'owner': 'octo-org', 'repo': 'app', 'state': ['OPEN']},
        r"""fragment pr on PullRequest{number,title,state,url,headRefName,headRepositoryOwner{id,login,...on User{name}},isCrossRepository,isDraft,createdAt}
    query PullRequestList(
      $owner: String!,
      $repo: String!,
      $limit: Int!,
      $endCursor: String,
      $baseBranch: String,
      $headBranch: String,
      $state: [PullRequestState!] = OPEN
    ) {
      repository(owner: $owner, name: $repo) {
        pullRequests(
          states: $state,
          baseRefName: $baseBranch,
          headRefName: $headBranch,
          first: $limit,
          after: $endCursor,
          orderBy: {field: CREATED_AT, direction: DESC}
        ) {
          totalCount
          nodes {
            ...pr
          }
          pageInfo {
            hasNextPage
            endCursor
          }
        }
      }
    }""",
    ),
    (
        'gh pr list --search lock --state all',
        None,
        r"""query SearchType_enumValues{SearchType: __type(name: "SearchType"){enumValues(includeDeprecated: true){name}}}""",
    ),
    (
        'gh pr list --search lock --state all',
        {'limit': 30, 'q': '( lock ) repo:octo-org/app type:pr', 'type': 'ISSUE_ADVANCED'},
        r"""fragment pr on PullRequest{number,title,state,url,headRefName,headRepositoryOwner{id,login,...on User{name}},isCrossRepository,isDraft,createdAt}
    query PullRequestSearch(
      $q: String!,
      $type: SearchType!,
      $limit: Int!,
      $endCursor: String,
    ) {
      search(query: $q, type: $type, first: $limit, after: $endCursor) {
        issueCount
        nodes {
          ...pr
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }""",
    ),
    (
        'gh pr status',
        {'headRefName': '', 'number': 0, 'owner': 'octo-org', 'repo': 'app', 'reviewerQuery': 'repo:octo-org/app state:open review-requested:@me', 'viewerQuery': 'repo:octo-org/app state:open is:pr author:@me'},
        r"""fragment pr on PullRequest {number,title,state,url,isDraft,isCrossRepository,headRefName,headRepositoryOwner{id,login,...on User{name}},mergeStateStatus,baseRef{branchProtectionRule{requiresStrictStatusChecks}},autoMergeRequest {authorEmail,commitBody,commitHeadline,mergeMethod,enabledAt,enabledBy{login,...on User{id,name}}},statusCheckRollup: commits(last: 1) {nodes {commit {statusCheckRollup {contexts {checkRunCount,checkRunCountsByState {state,count},statusContextCount,statusContextCountsByState {state,count}}}}}}}
  fragment prWithReviews on PullRequest {...pr,reviewDecision,latestReviews(first: 100) {nodes {author{login},authorAssociation,submittedAt,body,state}}}

  query PullRequestStatus($owner: String!, $repo: String!, $headRefName: String!, $viewerQuery: String!, $reviewerQuery: String!, $per_page: Int = 10) {
    repository(owner: $owner, name: $repo) {
      defaultBranchRef {
        name
      }
      pullRequests(headRefName: $headRefName, first: $per_page, orderBy: { field: CREATED_AT, direction: DESC }) {
        totalCount
        edges {
          node {
            ...prWithReviews
          }
        }
      }
    }

      viewerCreated: search(query: $viewerQuery, type: ISSUE, first: $per_page) {
        totalCount: issueCount
        edges {
          node {
          ...prWithReviews
          }
        }
      }
      reviewRequested: search(query: $reviewerQuery, type: ISSUE, first: $per_page) {
        totalCount: issueCount
        edges {
          node {
          ...pr
          }
        }
      }
    }""",
    ),
    (
        'gh pr status --json (every field)',
        None,
        r"""query PullRequest_fields{PullRequest: __type(name: "PullRequest"){fields(includeDeprecated: true){name}},StatusCheckRollupContextConnection: __type(name: "StatusCheckRollupContextConnection"){fields(includeDeprecated: true){name}}}""",
    ),
    (
        'gh pr status --json (every field)',
        {'headRefName': '', 'number': 0, 'owner': 'octo-org', 'repo': 'app', 'reviewerQuery': 'repo:octo-org/app state:open review-requested:@me', 'viewerQuery': 'repo:octo-org/app state:open is:pr author:@me'},
        r"""fragment pr on PullRequest{additions,assignees(first:100){nodes{id,login,name,databaseId},totalCount},author{login,...on User{id,name}},autoMergeRequest {authorEmail,commitBody,commitHeadline,mergeMethod,enabledAt,enabledBy{login,...on User{id,name}}},baseRefName,baseRefOid,body,changedFiles,closed,closedAt,closingIssuesReferences(first: 100) {nodes {id,number,url,repository {id,name,owner {id,login}}}pageInfo{hasNextPage,endCursor}},comments(first: 100) {nodes {id,author{login,...on User{id,name}},authorAssociation,body,createdAt,includesCreatedEdit,isMinimized,minimizedReason,reactionGroups{content,users{totalCount}},url,viewerDidAuthor},pageInfo{hasNextPage,endCursor},totalCount},commits(first: 100) {nodes {commit {authors(first:100) {nodes {name,email,user{id,login}}},messageHeadline,messageBody,oid,committedDate,authoredDate}}},createdAt,deletions,files(first: 100) {nodes {additions,deletions,path,changeType}},fullDatabaseId,headRefName,headRefOid,headRepository{id,name,nameWithOwner},headRepositoryOwner{id,login,...on User{name}},id,isCrossRepository,isDraft,labels(first:100){nodes{id,name,description,color},totalCount},latestReviews(first: 100) {nodes {author{login},authorAssociation,submittedAt,body,state}},maintainerCanModify,mergeCommit{oid},mergeStateStatus,mergeable,mergedAt,mergedBy{login,...on User{id,name}},milestone{number,title,description,dueOn},number,potentialMergeCommit{oid},projectCards(first:100){nodes{project{name}column{name}},totalCount},projectItems(first:100){nodes{id, project{id,title}, status:fieldValueByName(name: "Status") { ... on ProjectV2ItemFieldSingleSelectValue{optionId,name}}},totalCount},reactionGroups{content,users{totalCount}},reviewDecision,reviewRequests(first: 100) {nodes {requestedReviewer {__typename,...on User{login,name},...on Bot{login},...on Team{organization{login}name,slug}}}},reviews(first: 100) {nodes {id,author{login},authorAssociation,submittedAt,body,state,commit{oid},reactionGroups{content,users{totalCount}}}pageInfo{hasNextPage,endCursor}totalCount},state,statusCheckRollup: commits(last: 1) {nodes {commit {statusCheckRollup {contexts(first:100) {nodes {__typename...on StatusContext {context,state,targetUrl,createdAt,description},...on CheckRun {name,checkSuite{workflowRun{workflow{name}}},status,conclusion,startedAt,completedAt,detailsUrl}},pageInfo{hasNextPage,endCursor}}}}}},title,updatedAt,url}fragment prWithReviews on PullRequest{...pr}
  query PullRequestStatus($owner: String!, $repo: String!, $headRefName: String!, $viewerQuery: String!, $reviewerQuery: String!, $per_page: Int = 10) {
    repository(owner: $owner, name: $repo) {
      defaultBranchRef {
        name
      }
      pullRequests(headRefName: $headRefName, first: $per_page, orderBy: { field: CREATED_AT, direction: DESC }) {
        totalCount
        edges {
          node {
            ...prWithReviews
          }
        }
      }
    }

      viewerCreated: search(query: $viewerQuery, type: ISSUE, first: $per_page) {
        totalCount: issueCount
        edges {
          node {
          ...prWithReviews
          }
        }
      }
      reviewRequested: search(query: $reviewerQuery, type: ISSUE, first: $per_page) {
        totalCount: issueCount
        edges {
          node {
          ...pr
          }
        }
      }
    }""",
    ),
    (
        'gh pr checks 2',
        {'owner': 'octo-org', 'pr_number': 2, 'repo': 'app'},
        r"""query PullRequestByNumber($owner: String!, $repo: String!, $pr_number: Int!) {
    repository(owner: $owner, name: $repo) {
      pullRequest(number: $pr_number) {number,headRefName,id}
    }
  }""",
    ),
    (
        'gh pr checks 2',
        {'id': 'PR_AN_ID'},
        r"""query PullRequestStatusChecks($id: ID!, $endCursor: String) {
    node(id: $id) {
      ...on PullRequest {
        statusCheckRollup: commits(last: 1) {nodes {commit {statusCheckRollup {contexts(first:100,after:$endCursor) {nodes {__typename...on StatusContext {context,state,targetUrl,createdAt,description,isRequired(pullRequestId: $id)},...on CheckRun {name,checkSuite{workflowRun{event,workflow{name}}},status,conclusion,startedAt,completedAt,detailsUrl,isRequired(pullRequestId: $id)}},pageInfo{hasNextPage,endCursor}}}}}}
      }
    }
  }""",
    ),
    (
        'gh pr diff 2',
        {'owner': 'octo-org', 'pr_number': 2, 'repo': 'app'},
        r"""query PullRequestByNumber($owner: String!, $repo: String!, $pr_number: Int!) {
    repository(owner: $owner, name: $repo) {
      pullRequest(number: $pr_number) {number,id}
    }
  }""",
    ),
    (
        'gh issue list --state all --json (every field)',
        {'limit': 30, 'owner': 'octo-org', 'repo': 'app', 'states': ['OPEN', 'CLOSED']},
        r"""fragment issue on Issue {assignees(first:100){nodes{id,login,name,databaseId},totalCount},author{login,...on User{id,name}},blockedBy(first:50){nodes{id,number,title,url,state,repository{nameWithOwner}},totalCount},blocking(first:50){nodes{id,number,title,url,state,repository{nameWithOwner}},totalCount},body,closed,closedAt,closedByPullRequestsReferences(first: 100) {nodes {id,number,url,repository {id,name,owner {id,login}}}pageInfo{hasNextPage,endCursor}},comments(first: 100) {nodes {id,author{login,...on User{id,name}},authorAssociation,body,createdAt,includesCreatedEdit,isMinimized,minimizedReason,reactionGroups{content,users{totalCount}},url,viewerDidAuthor},pageInfo{hasNextPage,endCursor},totalCount},createdAt,id,isPinned,issueType{id,name,description,color},labels(first:100){nodes{id,name,description,color},totalCount},milestone{number,title,description,dueOn},number,parent{id,number,title,url,state,repository{nameWithOwner}},projectCards(first:100){nodes{project{name}column{name}},totalCount},projectItems(first:100){nodes{id, project{id,title}, status:fieldValueByName(name: "Status") { ... on ProjectV2ItemFieldSingleSelectValue{optionId,name}}},totalCount},reactionGroups{content,users{totalCount}},state,stateReason,subIssues(first:100){nodes{id,number,title,url,state,repository{nameWithOwner}},totalCount},subIssuesSummary{total,completed,percentCompleted},title,updatedAt,url}
  query IssueList($owner: String!, $repo: String!, $limit: Int, $endCursor: String, $states: [IssueState!] = OPEN, $assignee: String, $author: String, $mention: String) {
    repository(owner: $owner, name: $repo) {
      hasIssuesEnabled
      issues(first: $limit, after: $endCursor, orderBy: {field: CREATED_AT, direction: DESC}, states: $states, filterBy: {assignee: $assignee, createdBy: $author, mentioned: $mention}) {
        totalCount
        nodes {
          ...issue
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
  }""",
    ),
    (
        'gh issue list',
        {'limit': 30, 'owner': 'octo-org', 'repo': 'app', 'states': ['OPEN']},
        r"""fragment issue on Issue {number,title,url,state,updatedAt,labels(first:100){nodes{id,name,description,color},totalCount},stateReason}
  query IssueList($owner: String!, $repo: String!, $limit: Int, $endCursor: String, $states: [IssueState!] = OPEN, $assignee: String, $author: String, $mention: String) {
    repository(owner: $owner, name: $repo) {
      hasIssuesEnabled
      issues(first: $limit, after: $endCursor, orderBy: {field: CREATED_AT, direction: DESC}, states: $states, filterBy: {assignee: $assignee, createdBy: $author, mentioned: $mention}) {
        totalCount
        nodes {
          ...issue
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
  }""",
    ),
    (
        'gh issue list --search x',
        {'limit': 30, 'owner': 'octo-org', 'query': '( x ) repo:octo-org/app state:open type:issue', 'repo': 'app', 'type': 'ISSUE_ADVANCED'},
        r"""fragment issue on Issue {number,title,url,state,updatedAt,labels(first:100){nodes{id,name,description,color},totalCount},stateReason}query IssueSearch($repo: String!, $owner: String!, $type: SearchType!, $limit: Int, $after: String, $query: String!) {
      repository(name: $repo, owner: $owner) {
        hasIssuesEnabled
      }
      search(type: $type, last: $limit, after: $after, query: $query) {
        issueCount
        nodes { ...issue }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }""",
    ),
    (
        'gh issue view 1 --json (every field)',
        {'number': 1, 'owner': 'octo-org', 'repo': 'app'},
        r"""query IssueByNumber($owner: String!, $repo: String!, $number: Int!) {
    repository(owner: $owner, name: $repo) {
      hasIssuesEnabled
      issue: issueOrPullRequest(number: $number) {
        __typename
        ...on Issue{assignees(first:100){nodes{id,login,name,databaseId},totalCount},author{login,...on User{id,name}},blockedBy(first:50){nodes{id,number,title,url,state,repository{nameWithOwner}},totalCount},blocking(first:50){nodes{id,number,title,url,state,repository{nameWithOwner}},totalCount},body,closed,closedAt,closedByPullRequestsReferences(first: 100) {nodes {id,number,url,repository {id,name,owner {id,login}}}pageInfo{hasNextPage,endCursor}},comments(first: 100) {nodes {id,author{login,...on User{id,name}},authorAssociation,body,createdAt,includesCreatedEdit,isMinimized,minimizedReason,reactionGroups{content,users{totalCount}},url,viewerDidAuthor},pageInfo{hasNextPage,endCursor},totalCount},createdAt,id,isPinned,issueType{id,name,description,color},labels(first:100){nodes{id,name,description,color},totalCount},milestone{number,title,description,dueOn},number,parent{id,number,title,url,state,repository{nameWithOwner}},projectCards(first:100){nodes{project{name}column{name}},totalCount},reactionGroups{content,users{totalCount}},state,stateReason,subIssues(first:100){nodes{id,number,title,url,state,repository{nameWithOwner}},totalCount},subIssuesSummary{total,completed,percentCompleted},title,updatedAt,url}
        ...on PullRequest{assignees(first:100){nodes{id,login,name,databaseId},totalCount},author{login,...on User{id,name}},body,closed,closedAt,comments(first: 100) {nodes {id,author{login,...on User{id,name}},authorAssociation,body,createdAt,includesCreatedEdit,isMinimized,minimizedReason,reactionGroups{content,users{totalCount}},url,viewerDidAuthor},pageInfo{hasNextPage,endCursor},totalCount},createdAt,id,labels(first:100){nodes{id,name,description,color},totalCount},milestone{number,title,description,dueOn},number,projectCards(first:100){nodes{project{name}column{name}},totalCount},reactionGroups{content,users{totalCount}},state,title,updatedAt,url}
      }
    }
  }""",
    ),
    (
        'gh issue view 1 --comments',
        {'number': 1, 'owner': 'octo-org', 'repo': 'app'},
        r"""query IssueByNumber($owner: String!, $repo: String!, $number: Int!) {
    repository(owner: $owner, name: $repo) {
      hasIssuesEnabled
      issue: issueOrPullRequest(number: $number) {
        __typename
        ...on Issue{number,url,state,createdAt,title,body,author{login,...on User{id,name}},milestone{number,title,description,dueOn},assignees(first:100){nodes{id,login,name,databaseId},totalCount},labels(first:100){nodes{id,name,description,color},totalCount},reactionGroups{content,users{totalCount}},stateReason,issueType{id,name,description,color},parent{id,number,title,url,state,repository{nameWithOwner}},subIssues(first:100){nodes{id,number,title,url,state,repository{nameWithOwner}},totalCount},subIssuesSummary{total,completed,percentCompleted},comments(first: 100) {nodes {id,author{login,...on User{id,name}},authorAssociation,body,createdAt,includesCreatedEdit,isMinimized,minimizedReason,reactionGroups{content,users{totalCount}},url,viewerDidAuthor},pageInfo{hasNextPage,endCursor},totalCount},blockedBy(first:50){nodes{id,number,title,url,state,repository{nameWithOwner}},totalCount},blocking(first:50){nodes{id,number,title,url,state,repository{nameWithOwner}},totalCount},id}
        ...on PullRequest{number,url,state,createdAt,title,body,author{login,...on User{id,name}},milestone{number,title,description,dueOn},assignees(first:100){nodes{id,login,name,databaseId},totalCount},labels(first:100){nodes{id,name,description,color},totalCount},reactionGroups{content,users{totalCount}},comments(first: 100) {nodes {id,author{login,...on User{id,name}},authorAssociation,body,createdAt,includesCreatedEdit,isMinimized,minimizedReason,reactionGroups{content,users{totalCount}},url,viewerDidAuthor},pageInfo{hasNextPage,endCursor},totalCount},id}
      }
    }
  }""",
    ),
    (
        'gh issue view 1 --comments',
        {'endCursor': None, 'name': 'app', 'number': 1, 'owner': 'octo-org'},
        r"""query IssueProjectItems($endCursor:String$name:String!$number:Int!$owner:String!){repository(owner: $owner, name: $name){issue(number: $number){projectItems(first: 100, after: $endCursor){totalCount,nodes{id,project{id,title},status:fieldValueByName(name: "Status"){... on ProjectV2ItemFieldSingleSelectValue{optionId,name}}},pageInfo{hasNextPage,endCursor}}}}}""",
    ),
    (
        'gh repo view OWNER/REPO --json (every field)',
        {'name': 'app', 'owner': 'octo-org'},
        r"""query RepositoryInfo($owner: String!, $name: String!) {
    repository(owner: $owner, name: $name) {archivedAt,assignableUsers(first:100){nodes{id,login,name}},codeOfConduct{key,name,url},contactLinks{about,name,url},createdAt,defaultBranchRef{name},deleteBranchOnMerge,description,diskUsage,forkCount,fundingLinks{platform,url},hasDiscussionsEnabled,hasIssuesEnabled,hasProjectsEnabled,hasWikiEnabled,homepageUrl,id,isArchived,isBlankIssuesEnabled,isEmpty,isFork,isInOrganization,isMirror,isPrivate,isSecurityPolicyEnabled,isTemplate,isUserConfigurationRepository,issueTemplates{name,title,body,about},issues(states:OPEN){totalCount},labels(first:100){nodes{id,color,name,description}},languages(first:100){edges{size,node{name}}},latestRelease{publishedAt,tagName,name,url},licenseInfo{key,name,nickname},mentionableUsers(first:100){nodes{id,login,name}},mergeCommitAllowed,milestones(first:100,states:OPEN){nodes{number,title,description,dueOn}},mirrorUrl,name,nameWithOwner,openGraphImageUrl,owner{id,login},parent{id,name,owner{id,login}},primaryLanguage{name},projects(first:100,states:OPEN){nodes{id,name,number,body,resourcePath}},pullRequestTemplates{body,filename},pullRequests(states:OPEN){totalCount},pushedAt,rebaseMergeAllowed,repositoryTopics(first:100){nodes{topic{name}}},securityPolicyUrl,squashMergeAllowed,sshUrl,stargazerCount,templateRepository{id,name,owner{id,login}},updatedAt,url,usesCustomOpenGraphImage,viewerCanAdminister,viewerDefaultCommitEmail,viewerDefaultMergeMethod,viewerHasStarred,viewerPermission,viewerPossibleCommitEmails,viewerSubscription,visibility,watchers{totalCount}}
  }""",
    ),
    (
        'gh repo view OWNER/REPO',
        {'name': 'app', 'owner': 'octo-org'},
        r"""query RepositoryInfo($owner: String!, $name: String!) {
    repository(owner: $owner, name: $name) {name,owner{id,login},description}
  }""",
    ),
    (
        'gh release list --json (every field)',
        None,
        r"""query Release_fields{Release: __type(name: "Release"){fields{name}}}""",
    ),
    (
        'gh release list --json (every field)',
        {'direction': 'DESC', 'endCursor': None, 'name': 'app', 'owner': 'octo-org', 'perPage': 30},
        r"""query RepositoryReleaseList($direction:OrderDirection!$endCursor:String$name:String!$owner:String!$perPage:Int!){repository(owner: $owner, name: $name){releases(first: $perPage, orderBy: {field: CREATED_AT, direction: $direction}, after: $endCursor){nodes{name,tagName,isDraft,immutable,isLatest,isPrerelease,createdAt,publishedAt},pageInfo{hasNextPage,endCursor}}}}""",
    ),
    (
        'gh label list --json (every field)',
        {'limit': 30, 'orderBy': {'direction': 'ASC', 'field': 'CREATED_AT'}, 'owner': 'octo-org', 'query': '', 'repo': 'app'},
        r"""fragment label on Label{color,createdAt,description,id,isDefault,name,updatedAt,url}
  query LabelList($owner: String!, $repo: String!, $limit: Int!, $endCursor: String, $query: String, $orderBy: LabelOrder) {
    repository(owner: $owner, name: $repo) {
      labels(first: $limit, after: $endCursor, query: $query, orderBy: $orderBy) {
        totalCount,
        nodes {
          ...label
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
  }""",
    ),
    (
        'gh label list',
        {'limit': 30, 'orderBy': {'direction': 'ASC', 'field': 'CREATED_AT'}, 'owner': 'octo-org', 'query': '', 'repo': 'app'},
        r"""fragment label on Label{color,description,name}
  query LabelList($owner: String!, $repo: String!, $limit: Int!, $endCursor: String, $query: String, $orderBy: LabelOrder) {
    repository(owner: $owner, name: $repo) {
      labels(first: $limit, after: $endCursor, query: $query, orderBy: $orderBy) {
        totalCount,
        nodes {
          ...label
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
  }""",
    ),
    (
        'gh pr status',
        None,
        r"""query PullRequest_fields2{WorkflowRun: __type(name: "WorkflowRun"){fields(includeDeprecated: true){name}}}""",
    ),
    (
        'gh pr create --dry-run --title x --body y --base main',
        {'name': 'app', 'owner': 'octo-org'},
        r"""fragment repo on Repository {
    id
    databaseId
    name
    owner { login }
    sshUrl
    hasIssuesEnabled
    description
    hasWikiEnabled
    viewerPermission
    defaultBranchRef {
      name
    }
  }

  query RepositoryInfo($owner: String!, $name: String!) {
    repository(owner: $owner, name: $name) {
      ...repo
      parent {
        ...repo
      }
      mergeCommitAllowed
      rebaseMergeAllowed
      squashMergeAllowed
    }
  }""",
    ),
    (
        'gh pr create --dry-run --title x --body y --base main',
        {'headRefName': 'phase-5-github-policy', 'owner': 'octo-org', 'repo': 'app', 'states': ['OPEN']},
        r"""query PullRequestForBranch($owner: String!, $repo: String!, $headRefName: String!, $states: [PullRequestState!]) {
    repository(owner: $owner, name: $repo) {
      pullRequests(headRefName: $headRefName, states: $states, first: 30, orderBy: { field: CREATED_AT, direction: DESC }) {
        nodes {url,id,number,state,baseRefName,headRefName,isCrossRepository,headRepositoryOwner{id,login,...on User{name}}}
      }
      defaultBranchRef { name }
    }
  }""",
    ),
]

# The two that are refused, and why.
RECORDED_REFUSALS = {
    "gh pr checks 2": {"PullRequestStatusChecks": "graphql-by-id"},
    # Among every field of a repo are the two lists of who has access.
    "gh repo view OWNER/REPO --json (every field)": {"RepositoryInfo": "collaborators"},
}


@pytest.mark.parametrize(("command", "variables", "query"), RECORDED, ids=[f"{n}-{c}" for n, (c, _, _) in enumerate(RECORDED)])
def test_the_queries_gh_was_recorded_sending(command, variables, query):
    operation = re.search(r"\bquery\s+(\w+)", query).group(1)
    reason = RECORDED_REFUSALS.get(command, {}).get(operation)
    if reason:
        refused(gql(query, variables), reason)
        return
    decision = allowed(gql(query, variables), "graphql-read")
    assert decision.with_token
    text = json.dumps(variables)
    if "octo-org" in text:
        if "owner" in variables:
            assert decision.repo == "octo-org/app"
        # The same query about a repo listed for reading...
        swapped = json.loads(text.replace('"app"', '"library"').replace("octo-org/app", "octo-org/library"))
        # A search names its repo in the search text, which is checked but
        # not handed back as the repo the request is about.
        allowed(gql(query, swapped), "graphql-read", "octo-org/library" if "owner" in variables else None)
        # ...and about one that is not listed.
        elsewhere = json.loads(text.replace("octo-org", "other-org"))
        for used in (POLICY, PUBLIC):
            refused(gql(query, elsewhere, policy=used), "repo-not-listed")


def test_the_recorded_queries_cover_the_commands_the_docs_say_work():
    commands = " | ".join(command for command, _, _ in RECORDED)
    for command in ("pr view", "pr list", "pr status", "pr diff", "pr create --dry-run", "issue list", "issue view",
                    "repo view", "release list", "label list"):
        assert f"gh {command}" in commands, command
    assert len(RECORDED) == 29
    # Far below the limits, so the limits do not get in gh's way.
    assert max(len(query) for _, _, query in RECORDED) * 8 < policy_module.MAX_GRAPHQL
    assert max(query.count("fragment ") for _, _, query in RECORDED) * 8 < policy_module.MAX_FRAGMENTS


def test_every_field_of_a_repo_but_the_two_lists_of_who_has_access():
    command, variables, query = next(r for r in RECORDED if r[0] == "gh repo view OWNER/REPO --json (every field)")
    assert "assignableUsers(first:100){nodes{id,login,name}}," in query
    assert "mentionableUsers(first:100){nodes{id,login,name}}," in query
    without = query.replace("assignableUsers(first:100){nodes{id,login,name}},", "")
    without = without.replace("mentionableUsers(first:100){nodes{id,login,name}},", "")
    allowed(gql(without, variables), "graphql-read", "octo-org/app")


# ---------------------------------------------------------------------------
# GraphQL: search
# ---------------------------------------------------------------------------

SEARCH = "query($q: String!, $type: SearchType!) { search(query: $q, type: $type, first: 10) { issueCount } }"


@pytest.mark.parametrize(
    "text",
    [
        "repo:octo-org/app is:pr",
        "repo:octo-org/app state:open is:pr author:@me",
        "( lock network ) repo:octo-org/app state:open type:pr",
        "fix the build repo:Octo-Org/App",
        "REPO:octo-org/app label:bug -label:wontfix",
        "repo:octo-org/app repo:octo-org/library is:issue",
        "repo:octo-org/library in:title crash",
    ],
)
def test_a_search_kept_to_listed_repos_is_allowed(text):
    for kind in ("ISSUE", "ISSUE_ADVANCED"):
        allowed(gql(SEARCH, {"q": text, "type": kind}), "graphql-read")


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("password", "graphql-search"),
        ("", "graphql-search"),
        ("is:pr author:@me", "graphql-search"),
        ("repo:other-org/secret is:pr", "repo-not-listed"),
        ("repo:octo-org/app repo:other-org/secret", "repo-not-listed"),
        ("repo:octo-org/app -repo:octo-org/library", "repo-not-listed"),
        ("-repo:other-org/secret", "repo-not-listed"),
        ("repo:octo-org/app,other-org/secret", "repo-not-listed"),
        ("repo:octo-org/app/extra", "repo-not-listed"),
        ("repo:octo-org", "repo-not-listed"),
        ("repo:", "repo-not-listed"),
        ("+repo:other-org/secret repo:octo-org/app", "repo-not-listed"),
        ("x:repo:octo-org/app", "repo-not-listed"),
        ("repo:octo-org/app user:other-org", "graphql-search"),
        ("repo:octo-org/app org:other-org", "graphql-search"),
        ("repo:octo-org/app owner:other-org", "graphql-search"),
        ("repo:octo-org/app -user:x", "graphql-search"),
        ("repo:octo-org/app +ORG:other-org", "graphql-search"),
        ("repo:octo-org/app OR password", "graphql-search"),
        ("password OR repo:octo-org/app", "graphql-search"),
        ("repo:octo-org/app or password", "graphql-search"),
        ("NOT repo:octo-org/app", "graphql-search"),
        ("( x ) OR ( y ) repo:octo-org/app", "graphql-search"),
        ("(x)OR(y) repo:octo-org/app", "graphql-search"),
        ("repo:octo-org/app AND x", "graphql-search"),
        ("-(repo:octo-org/app) password", "graphql-search"),
        ("- ( repo:octo-org/app ) password", "graphql-search"),
        ('"repo:octo-org/app" password', "graphql-search"),
        ("'repo:octo-org/app' password", "graphql-search"),
        ('repo:"octo-org/app"', "graphql-search"),
        ("repo:octo-org/app | password", "graphql-search"),
        ("repo:octo-org/app " + "x" * 2000, "graphql-search"),
    ],
)
def test_a_search_that_could_reach_other_repos_is_refused(text, reason):
    refused(gql(SEARCH, {"q": text, "type": "ISSUE"}), reason)


@pytest.mark.parametrize("kind", ["REPOSITORY", "USER", "DISCUSSION", "issue", "", None, 5])
def test_a_search_for_anything_but_issues_is_refused(kind):
    refused(gql(SEARCH, {"q": "repo:octo-org/app", "type": kind}), "graphql-search")


def test_a_search_written_into_the_query():
    allowed(gql('{ search(query: "repo:octo-org/app is:pr", type: ISSUE, first: 1) { issueCount } }'))
    refused(gql('{ search(query: "is:pr", type: ISSUE, first: 1) { issueCount } }'), "graphql-search")
    refused(gql('{ search(query: "repo:octo-org/app", type: REPOSITORY, first: 1) { repositoryCount } }'), "graphql-search")
    refused(gql('{ search(query: "repo:octo-org/app", first: 1) { issueCount } }'), "graphql-search")
    refused(gql("{ search(type: ISSUE, first: 1) { issueCount } }"), "graphql-search")
    refused(gql('{ search(query: ["repo:octo-org/app"], type: ISSUE) { issueCount } }'), "graphql-search")


# ---------------------------------------------------------------------------
# GraphQL: text that cannot be read
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        "",
        "   ",
        "{",
        "}",
        "{ }",
        "query",
        "query {",
        "{ viewer { login }",
        "{ viewer { login } } }",
        "{ viewer { } }",
        "{ viewer(",
        "{ viewer() { login } }",
        "{ viewer { login } } garbage",
        "query Q() { viewer { login } }",
        "query Q($a) { viewer { login } }",
        "query Q($a: String, $a: String) { viewer { login } }",
        '{ repository(owner: "octo-org", name: "app", name: "x") { name } }',
        '{ repository(owner: "octo-org" name: "app\nx") { name } }',
        '{ repository(owner: "octo-org", name: "app) { name } }',
        "{ viewer { login } } \x00",
        "{ viewer { login } }",
        "{ viewer { 1login } }",
        "{ viewer { login(a: 0x10) } }",
        "{ viewer { login(a: 1.) } }",
        "{ viewer { login(a: 01) } }",
        "{ viewer { login(a: $) } }",
        "query Q($a: String = $b) { viewer { login } }",
        "type Query { viewer: User }",
        "schema { query: Query }",
        "extend type Query { x: Int }",
        "scalar Date",
        "directive @x on FIELD",
        'query { viewer { login } } """docs""" type X { y: Int }',
        "{ viewer { login } } { viewer { login } }",
        "query A { viewer { login } } { viewer { login } }",
        "{ " * 60 + "x" + " }" * 60,
        "{ viewer { login(a: " + "[" * 60 + "]" * 60 + ") } }",
        "{ " + "a " * 200_000 + "}",
    ],
)
def test_graphql_text_that_cannot_be_read_is_refused(query):
    refused(gql(query), "graphql-malformed")


@pytest.mark.parametrize(
    "body",
    [
        {"variables": {}},
        {"query": None},
        {"query": 5},
        {"query": ["{ viewer { login } }"]},
        {"query": {"text": "{ viewer { login } }"}},
        {"query": "{ viewer { login } }", "variables": []},
        {"query": "{ viewer { login } }", "variables": "x"},
        {"query": "{ viewer { login } }", "variables": 5},
        {"query": "{ viewer { login } }", "extensions": {"persistedQuery": {"sha256Hash": "x"}}},
        {"query": "{ viewer { login } }", "id": "x"},
        {"query": "{ viewer { login } }", "operation_name": "x"},
        {"Query": "{ viewer { login } }"},
        {"query": "{ viewer { login } }" + " " * policy_module.MAX_GRAPHQL},
    ],
)
def test_a_graphql_body_with_the_wrong_parts_is_refused(body):
    refused(ask("POST", "api.github.com/graphql", body), "graphql-malformed")


def test_comments_commas_and_spacing_do_not_change_what_is_read():
    allowed(
        gql(
            '# a comment with } and " in it\n'
            'query,,,Q { repository ( owner : "octo-org" , name : "app" ) { name # trailing\n } }'
        ),
        "graphql-read",
        "octo-org/app",
    )
    refused(
        gql('query Q { repository(owner: "other-org", # name: "app"\n name: "secret") { name } }'),
        "repo-not-listed",
    )
    # A "#" inside text is text, not the start of a comment.
    refused(gql('{ repository(owner: "octo-org", name: "app#") { name } }'), "repo-not-listed")
    # A block of text in triple quotes may hold anything, and ends where it ends.
    refused(
        gql('{ repository(owner: "other-org", name: "secret") { issues(filterBy: {x: """ } } """}) { totalCount } } }'),
        "repo-not-listed",
    )


# ---------------------------------------------------------------------------
# GraphQL: the body that is sent on
# ---------------------------------------------------------------------------


def test_an_allowed_graphql_request_is_sent_on_freshly_written():
    variables = {"owner": "octo-org", "repo": "app", "text": "café \U0001f512"}
    query = "query Q($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { name } }"
    raw = json.dumps({"operationName": "Q", "variables": variables, "query": query}, indent=4).encode()
    decision = allowed(ask("POST", "api.github.com/graphql", raw), "graphql-read")
    assert decision.body is not None and decision.body != raw
    # Plain ASCII, so there is nothing for two readers to disagree about.
    decision.body.decode("ascii")
    assert json.loads(decision.body) == {"query": query, "variables": variables, "operationName": "Q"}


def test_the_fresh_body_holds_only_what_was_sent():
    assert json.loads(allowed(gql("{ viewer { login } }")).body) == {"query": "{ viewer { login } }"}
    with_null = ask("POST", "api.github.com/graphql", {"query": "{ viewer { login } }", "variables": None, "operationName": None})
    assert json.loads(allowed(with_null).body) == {"query": "{ viewer { login } }"}


def test_a_number_too_large_to_be_json_is_refused():
    raw = b'{"query": "{ viewer { login } }", "variables": {"n": 1e999}}'
    refused(ask("POST", "api.github.com/graphql", raw), "body-odd")


def test_a_change_through_the_rest_api_is_sent_on_freshly_written_too():
    raw = b'{ "title" : "caf\xc3\xa9", "draft" : false }'
    decision = allowed(ask("POST", "api.github.com/repos/octo-org/app/pulls", raw), "api-write")
    assert decision.body == b'{"title":"caf\\u00e9","draft":false}'
    refused(ask("POST", "api.github.com/repos/octo-org/app/pulls", b'{"n": 1e999}'), "body-odd")


def test_requests_without_a_body_to_judge_are_sent_on_as_they_came():
    assert allowed(ask("GET", "api.github.com/user")).body is None
    assert allowed(ask("DELETE", "api.github.com/repos/octo-org/app/issues/comments/5", b"")).body is None
    assert allowed(ask("POST", "github.com/octo-org/app/git-receive-pack", b"PACK...")).body is None


# ---------------------------------------------------------------------------
# The answer itself
# ---------------------------------------------------------------------------

HOSTILE = "evil\r\nX-Injected: yes \x00\x1b[31m" + "A" * 500


def all_refusals():
    """A refusal of every sort, each with hostile text somewhere in it."""
    yield decide("GET", HOSTILE, "/", "", None, POLICY, headers={}, authority=HOSTILE)
    yield decide(HOSTILE, "api.github.com", "/", "", None, POLICY, headers={}, authority="api.github.com")
    yield decide("GET", "api.github.com", "/" + HOSTILE, "", None, POLICY, headers={}, authority="api.github.com")
    yield decide("GET", "api.github.com", "/user", HOSTILE, None, POLICY, headers={}, authority="api.github.com")
    yield decide("GET", "api.github.com", "/user", "", None, POLICY, headers={}, authority=HOSTILE)
    yield decide("GET", "api.github.com", "/user", "", None, POLICY, headers={HOSTILE: HOSTILE, "Host": HOSTILE}, authority="api.github.com")
    yield ask("GET", "api.github.com/repos/other-org/secret")
    yield ask("DELETE", "api.github.com/repos/octo-org/app", b"")
    yield ask("POST", "api.github.com/graphql", HOSTILE)
    yield gql(HOSTILE)
    yield gql("{ %s { id } }" % ("x" * 500))
    yield gql("mutation { %s(input: {}) { id } }" % ("y" * 500))
    yield gql("{ viewer { %s } }" % ("z" * 500))
    yield gql("{ viewer { login } }", operation=HOSTILE)
    yield ask("POST", "api.github.com/graphql", {"query": "{ viewer { login } }", HOSTILE: 1})
    yield gql("query($o: String!, $n: String!) { repository(owner: $o, name: $n) { id } }", {"o": HOSTILE, "n": HOSTILE})
    yield gql(SEARCH, {"q": HOSTILE, "type": "ISSUE"})
    yield gql(ADD_COMMENT, {"input": {"subjectId": HOSTILE}})
    yield gql(CREATE_PR, {"input": {"repositoryId": HOSTILE}})
    yield gql("query($id: ID!) { node(id: $id) { id } }", {"id": HOSTILE})
    yield gql(CREATE_PR, {"input": {"repositoryId": APP_ID, "headRefName": HOSTILE + ":x"}})
    yield ask("POST", "api.github.com/repos/octo-org/app/pulls", {"head": "x", "head_repo": HOSTILE})
    yield gql(IN_APP % ("%s { id }" % ("w" * 500)))
    yield gql(IN_APP % ("owner { %s }" % ("v" * 500)))
    yield gql(IN_APP % ("issueOrPullRequest(number: 1) { ... on %s { id } }" % ("U" * 500)))
    yield ask("POST", "api.github.com/repos/octo-org/app/pulls?" + "q=" + "x" * 500, {"title": "t"})


def test_a_refusal_explains_itself_and_carries_nothing_hostile():
    known_reasons = set(policy_module.NEVER) | {
        "repo-not-listed", "repo-read-only", "merge", "not-recognised", "github-host-not-covered",
        "host-differs", "header-repeated", "method-override", "path-odd", "query-odd", "body-odd",
        "graphql-malformed", "graphql-query-not-allowed", "graphql-mutation-not-allowed",
        "graphql-id-not-listed", "graphql-by-id", "graphql-not-on-list", "graphql-search", "head-elsewhere",
        "policy-error",
    }
    count = 0
    for decision in all_refusals():
        count += 1
        refused(decision)
        # The reason goes into the log: one fixed word, nothing from the request.
        assert decision.reason in known_reasons, decision.reason
        # The message goes back to the VM: printable, and not a flood.
        assert all(char == "\n" or " " <= char <= "~" for char in decision.message), decision.message
        assert len(decision.message) < 2000
        assert "A" * 100 not in decision.message
        # It ends by saying what to do next.
        assert decision.message.endswith(".\n")
    assert count == 26


def test_messages_say_what_to_ask_the_user_for():
    assert "list it under" in refused(ask("GET", "api.github.com/repos/other-org/secret")).message
    assert "access: write" in refused(ask("POST", "github.com/octo-org/library/git-receive-pack")).message
    assert "No rule allows this" in refused(ask("POST", "api.github.com/gists", {})).message
    assert "docs/github-rules.md" in refused(ask("GET", "api.github.com/users/someone")).message
    assert "plain way" in refused(ask("GET", "api.github.com/repos/octo-org/app/")).message
    assert "Use git instead" in refused(ask("PUT", "api.github.com/repos/octo-org/app/contents/x", {})).message
    by_id = refused(gql(ADD_COMMENT, {"input": {"subjectId": PR_ID, "body": "x"}})).message
    assert "`gh pr comment` and `gh issue comment` send it" in by_id
    assert "gh api repos/OWNER/REPO/issues/NUMBER/comments -f body='TEXT'" in by_id
    no_id = refused(gql(CREATE_PR, {"input": {"repositoryId": node_id("R", OTHER)}})).message
    assert "its entry needs" in no_id and "an `id`" in no_id


@pytest.mark.parametrize(
    "arguments",
    [
        dict(method=None, host=None, path=None, query=None, body=None, headers=None, authority=None),
        dict(method="GET", host=5, path="/", query="", body=None, headers={}, authority="api.github.com"),
        dict(method="GET", host="api.github.com", path=b"/user", query="", body=None, headers={}, authority="api.github.com"),
        dict(method="GET", host="api.github.com", path="/user", query=None, body=None, headers={}, authority="api.github.com"),
        dict(method="GET", host="api.github.com", path="/user", query="", body=None, headers=None, authority="api.github.com"),
        dict(method="GET", host="api.github.com", path="/user", query="", body=None, headers=5, authority="api.github.com"),
        dict(method="GET", host="api.github.com", path="/user", query="", body=None, headers=[("a",)], authority="api.github.com"),
        dict(method="GET", host="api.github.com", path="/user", query="", body=None, headers={5: 5}, authority="api.github.com"),
        dict(method="POST", host="api.github.com", path="/graphql", query="", body="text, not bytes", headers=JSON, authority="api.github.com"),
        dict(method="POST", host="api.github.com", path="/graphql", query="", body=object(), headers=JSON, authority="api.github.com"),
    ],
)
def test_decide_refuses_instead_of_failing(arguments):
    # An error in the check must never turn into a request that goes out.
    decision = decide(policy=POLICY, **arguments)
    assert not decision.allowed and decision.message


def test_decide_refuses_without_real_rules():
    for not_rules in (None, {}, rules()):
        decision = decide(
            "GET", "api.github.com", "/user", "", None, not_rules, headers={}, authority="api.github.com"
        )
        refused(decision, "policy-error")


def test_no_rules_means_no_repo_is_reachable():
    empty = load_policy({"repos": []})
    refused(ask("GET", "github.com/octo-org/app/info/refs?service=git-upload-pack", policy=empty), "repo-not-listed")
    refused(ask("GET", "api.github.com/repos/octo-org/app", policy=empty), "repo-not-listed")
    refused(gql(GOOD, policy=empty), "repo-not-listed")
    refused(gql(CREATE_PR, {"input": {"repositoryId": APP_ID}}, policy=empty), "graphql-id-not-listed")
    refused(gql(ADD_COMMENT, {"input": {"subjectId": PR_ID}}, policy=empty), "graphql-by-id")


def test_bytes_and_bytearray_bodies_are_both_read():
    body = bytearray(json.dumps({"query": "{ viewer { login } }"}).encode())
    allowed(ask("POST", "api.github.com/graphql", body), "graphql-read")
