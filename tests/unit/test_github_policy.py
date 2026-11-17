"""Tests for broker/github_policy.py: which GitHub requests are let through.

Run with `pytest tests/unit`. Nothing here touches the network or the VM.

The repos in these tests are made up. Four are listed in the rules:

    octo-org/app        write, with an id
    octo-org/library    read only, with an id
    octo-org/shipping   write and merge, with an id
    octo-org/no-id      write, but the rules hold no id for it

Everything else, such as other-org/secret, is a repo that is not listed.
"""

import base64
import json
import sys
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
    "/assignees",
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
    ("PUT", "/pulls/1/update-branch"),
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

PR_ID = node_id("PR", APP, 5)
ISSUE_ID = node_id("I", APP, 6)
COMMENT_ID = node_id("IC", APP, 7)
REVIEW_ID = node_id("PRR", APP, 8)
REVIEW_COMMENT_ID = node_id("PRRC", APP, 9)
THREAD_ID = node_id("PRRT", APP, 10)
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
    # gh pr checks 1: the pull request by its id
    (
        """query PullRequestStatusChecks($id: ID!, $endCursor: String) {
          node(id: $id) {
            ...on PullRequest {
              statusCheckRollup: commits(last: 1) {nodes {commit {statusCheckRollup {
                contexts(first:100,after:$endCursor) {nodes {__typename
                  ...on StatusContext {context,state,isRequired(pullRequestId: $id)},
                  ...on CheckRun {name,status,conclusion,isRequired(pullRequestId: $id)}},
                  pageInfo{hasNextPage,endCursor}}}}}}
            }
          }
        }""",
        {"id": PR_ID},
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


GH_MUTATIONS = [
    # gh pr create
    (
        "mutation PullRequestCreate($input: CreatePullRequestInput!) {"
        " createPullRequest(input: $input) { pullRequest { id url } } }",
        {"repositoryId": "REPO", "baseRefName": "main", "headRefName": "x", "title": "t", "body": "b", "draft": False},
    ),
    # gh pr edit
    (
        "mutation PullRequestUpdate($input: UpdatePullRequestInput!) {"
        " updatePullRequest(input: $input) { __typename } }",
        {"pullRequestId": "PR", "title": "new", "body": "new"},
    ),
    # gh pr comment, gh issue comment
    (
        "mutation CommentCreate($input: AddCommentInput!) {"
        " addComment(input: $input) { commentEdge { node { url } } } }",
        {"subjectId": "PR", "body": "hello"},
    ),
    (
        "mutation CommentCreate($input: AddCommentInput!) {"
        " addComment(input: $input) { commentEdge { node { url } } } }",
        {"subjectId": "ISSUE", "body": "hello"},
    ),
    (
        "mutation CommentUpdate($input: UpdateIssueCommentInput!) {"
        " updateIssueComment(input: $input) { issueComment { url } } }",
        {"id": "COMMENT", "body": "edited"},
    ),
    ("mutation($input: DeleteIssueCommentInput!) { deleteIssueComment(input: $input) { clientMutationId } }", {"id": "COMMENT"}),
    # gh pr close, reopen, ready
    (
        "mutation PullRequestClose($input: ClosePullRequestInput!) {"
        " closePullRequest(input: $input) { pullRequest { id } } }",
        {"pullRequestId": "PR"},
    ),
    (
        "mutation PullRequestReopen($input: ReopenPullRequestInput!) {"
        " reopenPullRequest(input: $input) { pullRequest { id } } }",
        {"pullRequestId": "PR"},
    ),
    (
        "mutation PullRequestReadyForReview($input: MarkPullRequestReadyForReviewInput!) {"
        " markPullRequestReadyForReview(input: $input) { pullRequest { id } } }",
        {"pullRequestId": "PR"},
    ),
    ("mutation($input: ConvertPullRequestToDraftInput!) { convertPullRequestToDraft(input: $input) { pullRequest { id } } }", {"pullRequestId": "PR"}),
    ("mutation($input: UpdatePullRequestBranchInput!) { updatePullRequestBranch(input: $input) { pullRequest { id } } }", {"pullRequestId": "PR"}),
    # gh pr review
    (
        "mutation PullRequestReviewAdd($input: AddPullRequestReviewInput!) {"
        " addPullRequestReview(input: $input) { clientMutationId } }",
        {"pullRequestId": "PR", "event": "COMMENT", "body": "looks fine"},
    ),
    ("mutation($input: SubmitPullRequestReviewInput!) { submitPullRequestReview(input: $input) { clientMutationId } }", {"pullRequestReviewId": "REVIEW", "event": "COMMENT"}),
    ("mutation($input: AddPullRequestReviewThreadReplyInput!) { addPullRequestReviewThreadReply(input: $input) { clientMutationId } }", {"pullRequestReviewThreadId": "THREAD", "body": "done"}),
    ("mutation($input: ResolveReviewThreadInput!) { resolveReviewThread(input: $input) { thread { id } } }", {"threadId": "THREAD"}),
    ("mutation($input: UpdatePullRequestReviewCommentInput!) { updatePullRequestReviewComment(input: $input) { clientMutationId } }", {"pullRequestReviewCommentId": "REVIEW_COMMENT", "body": "x"}),
    ("mutation($input: RequestReviewsInput!) { requestReviews(input: $input) { clientMutationId } }", {"pullRequestId": "PR", "userIds": ["U_x"], "union": True}),
    ("mutation($input: RequestReviewsByLoginInput!) { requestReviewsByLogin(input: $input) { clientMutationId } }", {"pullRequestId": "PR", "userLogins": ["someone"]}),
    # labels, reactions
    ("mutation($input: AddLabelsToLabelableInput!) { addLabelsToLabelable(input: $input) { __typename } }", {"labelableId": "PR", "labelIds": ["LA_x"]}),
    ("mutation($input: AddReactionInput!) { addReaction(input: $input) { reaction { content } } }", {"subjectId": "COMMENT", "content": "THUMBS_UP"}),
]

KINDS = {
    "REPO": ("R",),
    "PR": ("PR", 5),
    "ISSUE": ("I", 6),
    "COMMENT": ("IC", 7),
    "REVIEW": ("PRR", 8),
    "REVIEW_COMMENT": ("PRRC", 9),
    "THREAD": ("PRRT", 10),
}


def fill(given: dict, repo_number: int) -> dict:
    """Put real-looking ids of things in the given repo into an input."""
    filled = {}
    for key, value in given.items():
        if isinstance(value, str) and value in KINDS:
            kind, *own = KINDS[value]
            value = node_id(kind, repo_number, *own)
        filled[key] = value
    return filled


@pytest.mark.parametrize(("query", "given"), GH_MUTATIONS)
def test_changes_gh_makes_are_allowed_in_a_write_repo(query, given):
    decision = allowed(gql(query, {"input": fill(given, APP)}), "graphql-write", "octo-org/app")
    assert decision.with_token
    allowed(gql(query, {"input": fill(given, SHIPPING)}), "graphql-write", "octo-org/shipping")


@pytest.mark.parametrize(("query", "given"), GH_MUTATIONS)
def test_changes_are_refused_in_a_read_repo_through_graphql(query, given):
    refused(gql(query, {"input": fill(given, LIBRARY)}), "repo-read-only")


@pytest.mark.parametrize(("query", "given"), GH_MUTATIONS)
@pytest.mark.parametrize("used", [POLICY, PUBLIC])
def test_changes_are_refused_elsewhere_through_graphql(query, given, used):
    decision = refused(gql(query, {"input": fill(given, OTHER)}, policy=used), "graphql-id-not-listed")
    assert "`id`" in decision.message


def test_a_write_repo_without_an_id_cannot_be_changed_through_graphql():
    # Nothing ties an id to octo-org/no-id, so its ids are unknown ids.
    assert POLICY.find("octo-org", "no-id").write
    query, given = GH_MUTATIONS[0]
    refused(gql(query, {"input": fill(given, 4242)}), "graphql-id-not-listed")
    # git, REST and queries by name still work for it.
    allowed(ask("POST", "github.com/octo-org/no-id/git-receive-pack"), "git-write")
    allowed(ask("POST", "api.github.com/repos/octo-org/no-id/pulls", {}), "api-write")
    allowed(gql(GH_QUERIES[10][0], {"owner": "octo-org", "name": "no-id"}), "graphql-read")


def test_merging_through_graphql_needs_the_merge_switch():
    for name in ("mergePullRequest", "enablePullRequestAutoMerge", "disablePullRequestAutoMerge", "enqueuePullRequest"):
        query = f"mutation($input: X!) {{ {name}(input: $input) {{ clientMutationId }} }}"
        allowed(gql(query, {"input": {"pullRequestId": node_id("PR", SHIPPING, 5)}}), "graphql-write")
        refused(gql(query, {"input": {"pullRequestId": node_id("PR", APP, 5)}}), "merge")
        refused(gql(query, {"input": {"pullRequestId": node_id("PR", LIBRARY, 5)}}), "repo-read-only")
        refused(gql(query, {"input": {"pullRequestId": node_id("PR", OTHER, 5)}}), "graphql-id-not-listed")


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
    given = {"repositoryId": node_id("R", APP), "pullRequestId": PR_ID, "subjectId": PR_ID, "id": ISSUE_ID}
    query = f"mutation($input: X!) {{ {name}(input: $input) {{ clientMutationId }} }}"
    decision = refused(gql(query, {"input": given}), "graphql-mutation-not-allowed")
    assert name not in policy_module.MUTATIONS and name not in policy_module.MERGE_MUTATIONS
    assert name in decision.message


# ---------------------------------------------------------------------------
# Assigning, which can start a second agent outside the sandbox
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name", ["addAssigneesToAssignable", "removeAssigneesFromAssignable", "replaceActorsForAssignable"]
)
def test_assigning_is_refused_through_graphql(name):
    query = f"mutation($input: X!) {{ {name}(input: $input) {{ clientMutationId }} }}"
    decision = refused(gql(query, {"input": {"assignableId": ISSUE_ID, "actorIds": ["BOT_x"]}}), "assignees")
    assert "second agent" in decision.message


@pytest.mark.parametrize(
    ("name", "given"),
    [
        ("updatePullRequest", {"pullRequestId": PR_ID}),
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


def test_reading_who_can_be_assigned_is_allowed():
    allowed(ask("GET", "api.github.com/repos/octo-org/app/assignees"), "api-read")


# ---------------------------------------------------------------------------
# Issues: read and comment, nothing more
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "given"),
    [
        ("createIssue", {"repositoryId": "REPO", "title": "t", "body": "b"}),
        ("updateIssue", {"id": "ISSUE", "title": "new"}),
        ("closeIssue", {"issueId": "ISSUE"}),
        ("reopenIssue", {"issueId": "ISSUE"}),
    ],
)
def test_issues_are_not_created_edited_or_closed_through_graphql(name, given):
    query = f"mutation($input: X!) {{ {name}(input: $input) {{ clientMutationId }} }}"
    for number in (APP, SHIPPING, OTHER):
        decision = refused(gql(query, {"input": fill(given, number)}), "issues")
        assert "commenting on them is" in decision.message


def test_issues_can_be_read_and_commented_on():
    allowed(ask("GET", "api.github.com/repos/octo-org/app/issues/7"), "api-read")
    allowed(ask("POST", "api.github.com/repos/octo-org/app/issues/7/comments", {"body": "x"}), "api-write")
    allowed(gql(ADD_COMMENT, {"input": {"subjectId": ISSUE_ID, "body": "x"}}), "graphql-write")
    refused(ask("POST", "api.github.com/repos/octo-org/app/issues", {"title": "t"}), "issues")
    refused(ask("PATCH", "api.github.com/repos/octo-org/app/issues/7", {"state": "closed"}), "issues")


def test_subscriptions_are_refused():
    refused(gql("subscription { viewer { login } }"), "not-recognised")


# ---------------------------------------------------------------------------
# GraphQL: ids
# ---------------------------------------------------------------------------

ADD_COMMENT = "mutation($input: AddCommentInput!) { addComment(input: $input) { clientMutationId } }"
CREATE_PR = "mutation($input: CreatePullRequestInput!) { createPullRequest(input: $input) { clientMutationId } }"


@pytest.mark.parametrize(
    "subject",
    [
        node_id("PR", OTHER, 5),
        node_id("I", OTHER, 6),
        node_id("R", APP),  # a repo is not something to comment on
        node_id("IC", APP, 7),  # nor a comment
        node_id("D", APP, 7),  # a discussion
        node_id("T", APP, 7),  # a team of the organization numbered like the repo
        node_id("U", APP),  # the user numbered like the repo
        node_id("PR", APP),  # too few numbers
        node_id("PR", APP, 5, 6),  # too many
        "PR_" + base64.urlsafe_b64encode(b"\x93\x01\xce\x00\x00\x03\xe9\x05").decode().rstrip("="),  # not 0 first
        "PR_" + base64.urlsafe_b64encode(b"\x93\x00\xa4\x31\x30\x30\x31\x05").decode().rstrip("="),  # text, not a number
        "PR_" + base64.urlsafe_b64encode(b"\x93\x00\xce\x00\x00\x03\xe9").decode().rstrip("="),  # cut short
        "PR_" + base64.urlsafe_b64encode(b"\x93\x00\xce\x00\x00\x03\xe9\x05\x05").decode().rstrip("="),  # too long
        base64.b64encode(b"011:PullRequest5").decode(),  # the older make-up: no repo inside
        old_repo_id(APP),
        PR_ID.lower(),
        PR_ID + "=",
        " " + PR_ID,
        PR_ID + "\n",
        "pr_" + PR_ID[3:],
        "PR_",
        "PR_!!!!",
        "",
        "octo-org/app#5",
        5,
        1001,
        True,
        None,
        [PR_ID],
        {"id": PR_ID},
    ],
)
def test_an_id_that_is_not_plainly_a_thing_in_a_write_repo_is_refused(subject):
    decision = gql(ADD_COMMENT, {"input": {"subjectId": subject, "body": "x"}})
    assert not decision.allowed
    assert decision.reason in ("graphql-id-not-listed", "graphql-malformed")


def test_a_repo_id_of_the_older_make_up_is_understood():
    old = load_policy({"repos": [{"repo": "a/b", "note": "n", "access": "write", "id": old_repo_id(77)}]})
    # The repo is old, so gh sends its old id; new things in it have new ids.
    allowed(gql(CREATE_PR, {"input": {"repositoryId": old_repo_id(77)}}, policy=old), "graphql-write", "a/b")
    allowed(gql(CREATE_PR, {"input": {"repositoryId": node_id("R", 77)}}, policy=old), "graphql-write")
    allowed(gql(ADD_COMMENT, {"input": {"subjectId": node_id("PR", 77, 1)}}, policy=old), "graphql-write")
    refused(gql(CREATE_PR, {"input": {"repositoryId": old_repo_id(78)}}, policy=old), "graphql-id-not-listed")
    refused(gql(CREATE_PR, {"input": {"repositoryId": old_repo_id(770)}}, policy=old), "graphql-id-not-listed")


def test_a_pull_request_from_another_repo_must_come_from_a_listed_one():
    base = {"repositoryId": node_id("R", APP), "baseRefName": "main", "headRefName": "x", "title": "t"}
    allowed(gql(CREATE_PR, {"input": {**base, "headRepositoryId": node_id("R", SHIPPING)}}))
    allowed(gql(CREATE_PR, {"input": {**base, "headRepositoryId": None}}))
    refused(gql(CREATE_PR, {"input": {**base, "headRepositoryId": node_id("R", OTHER)}}), "graphql-id-not-listed")
    refused(gql(CREATE_PR, {"input": {**base, "headRepositoryId": node_id("R", LIBRARY)}}), "repo-read-only")
    # The other way round: into an unlisted repo from a listed one.
    swapped = {**base, "repositoryId": node_id("R", OTHER), "headRepositoryId": node_id("R", APP)}
    refused(gql(CREATE_PR, {"input": swapped}), "graphql-id-not-listed")


def test_every_id_in_a_change_must_check_out():
    submit = "mutation($input: X!) { submitPullRequestReview(input: $input) { clientMutationId } }"
    allowed(gql(submit, {"input": {"pullRequestId": PR_ID, "event": "COMMENT"}}))
    allowed(gql(submit, {"input": {"pullRequestId": PR_ID, "pullRequestReviewId": REVIEW_ID}}))
    mixed = {"pullRequestId": PR_ID, "pullRequestReviewId": node_id("PRR", OTHER, 8)}
    refused(gql(submit, {"input": mixed}), "graphql-id-not-listed")
    refused(gql(submit, {"input": {"event": "COMMENT"}}), "graphql-malformed")


@pytest.mark.parametrize(
    "variables",
    [
        None,
        {},
        {"input": None},
        {"input": "text"},
        {"input": [{"subjectId": PR_ID}]},
        {"input": {}},
        {"input": {"body": "x"}},
        {"input": {"subjectId": None, "body": "x"}},
        {"Input": {"subjectId": PR_ID}},
    ],
)
def test_a_change_without_a_usable_input_is_refused(variables):
    refused(gql(ADD_COMMENT, variables), "graphql-malformed")


def test_reading_one_thing_by_its_id():
    query = "query($id: ID!) { node(id: $id) { ... on PullRequest { title } } }"
    for thing in (PR_ID, ISSUE_ID, COMMENT_ID, REVIEW_ID, REVIEW_COMMENT_ID, THREAD_ID, node_id("R", APP)):
        allowed(gql(query, {"id": thing}), "graphql-read", "octo-org/app")
    allowed(gql(query, {"id": node_id("PR", LIBRARY, 1)}), "graphql-read", "octo-org/library")
    for used in (POLICY, PUBLIC):
        refused(gql(query, {"id": node_id("PR", OTHER, 1)}, policy=used), "graphql-id-not-listed")
        refused(gql(query, {"id": node_id("U", APP)}, policy=used), "graphql-id-not-listed")
        refused(gql(query, {"id": node_id("T", APP, 1)}, policy=used), "graphql-id-not-listed")
        refused(gql(query, {}, policy=used), "graphql-id-not-listed")
    refused(gql("{ node { id } }"), "graphql-id-not-listed")
    refused(gql('{ nodes(ids: ["%s"]) { id } }' % PR_ID), "graphql-query-not-allowed")


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
    refused(gql(query), "graphql-account")


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
    change = "mutation Change($input: X!) { addComment(input: $input) { clientMutationId } }"
    variables = {"input": {"subjectId": PR_ID, "body": "x"}}
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
            'mutation($a: X!, $b: X!) { one: addComment(input: $a) { clientMutationId }'
            " two: addComment(input: $b) { clientMutationId } }",
            {"a": {"subjectId": PR_ID}, "b": {"subjectId": node_id("PR", OTHER, 1)}},
        ),
        "graphql-id-not-listed",
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


def test_many_fragments_that_use_each_other_do_not_take_long():
    # Each fragment uses the one before it twice. Opened up naively that is
    # two to the power of sixty fields.
    parts = ["fragment f0 on Query { __typename }"]
    for number in range(1, 60):
        parts.append(f"fragment f{number} on Query {{ ...f{number - 1} ...f{number - 1} }}")
    allowed(gql("query { ...f59 } " + " ".join(parts)), "graphql-read")


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
    inline = 'mutation { addComment(input: {subjectId: "%s", body: "x"}) { clientMutationId } }'
    allowed(gql(inline % PR_ID), "graphql-write", "octo-org/app")
    refused(gql(inline % node_id("PR", OTHER, 1)), "graphql-id-not-listed")
    # Partly from a variable.
    mixed = 'mutation($id: ID!) { addComment(input: {subjectId: $id, body: "x"}) { clientMutationId } }'
    allowed(gql(mixed, {"id": PR_ID}), "graphql-write")
    refused(gql(mixed, {"id": node_id("PR", OTHER, 1)}), "graphql-id-not-listed")
    refused(gql(mixed, {}), "graphql-malformed")
    # The same name twice in one input, or the input given twice.
    twice = 'mutation { addComment(input: {subjectId: "%s", subjectId: "%s"}) { clientMutationId } }'
    refused(gql(twice % (PR_ID, node_id("PR", OTHER, 1))), "graphql-malformed")
    refused(gql('mutation { addComment(input: {subjectId: "%s"}, input: {}) { clientMutationId } }' % PR_ID), "graphql-malformed")
    refused(gql('mutation { addComment(input: {subjectId: "%s"}, other: 1) { clientMutationId } }' % PR_ID), "graphql-malformed")
    refused(gql("mutation { addComment { clientMutationId } }"), "graphql-malformed")


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
    refused(gql(query), "graphql-walks-away")


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
        "mutation($input: X!) { addComment(input: $input) {"
        " subject { ... on PullRequest { repository { owner { repositories(first: 100) { nodes { name } } } } } } } }"
    )
    refused(gql(query, {"input": {"subjectId": PR_ID}}), "graphql-walks-away")


def test_walks_that_gh_itself_makes_are_left_alone():
    # gh asks for a repo's parent and for a pull request's own repo.
    allowed(
        gql(
            '{ repository(owner: "octo-org", name: "app") { parent { name owner { login } }'
            " pullRequest(number: 1) { repository { name } headRepository { nameWithOwner }"
            " baseRepository { nameWithOwner } } forkCount } }"
        ),
        "graphql-read",
    )


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


def test_a_refusal_explains_itself_and_carries_nothing_hostile():
    known_reasons = set(policy_module.NEVER) | {
        "repo-not-listed", "repo-read-only", "merge", "not-recognised", "github-host-not-covered",
        "host-differs", "header-repeated", "method-override", "path-odd", "query-odd", "body-odd",
        "graphql-malformed", "graphql-query-not-allowed", "graphql-mutation-not-allowed",
        "graphql-id-not-listed", "graphql-account", "graphql-search", "graphql-walks-away", "policy-error",
    }
    count = 0
    for decision in all_refusals():
        count += 1
        refused(decision)
        # The reason goes into the log: one fixed word, nothing from the request.
        assert decision.reason in known_reasons, decision.reason
        # The message goes back to the VM: printable, and not a flood.
        assert all(char == "\n" or " " <= char <= "~" for char in decision.message), decision.message
        assert len(decision.message) < 1500
        assert "A" * 100 not in decision.message
        # It ends by saying what to do next.
        assert decision.message.endswith(".\n")
    assert count == 18


def test_messages_say_what_to_ask_the_user_for():
    assert "list it under" in refused(ask("GET", "api.github.com/repos/other-org/secret")).message
    assert "access: write" in refused(ask("POST", "github.com/octo-org/library/git-receive-pack")).message
    assert "No rule allows this" in refused(ask("POST", "api.github.com/gists", {})).message
    assert "docs/github-rules.md" in refused(ask("GET", "api.github.com/users/someone")).message
    assert "plain way" in refused(ask("GET", "api.github.com/repos/octo-org/app/")).message
    assert "Use git instead" in refused(ask("PUT", "api.github.com/repos/octo-org/app/contents/x", {})).message


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
    refused(gql(ADD_COMMENT, {"input": {"subjectId": PR_ID}}, policy=empty), "graphql-id-not-listed")


def test_bytes_and_bytearray_bodies_are_both_read():
    body = bytearray(json.dumps({"query": "{ viewer { login } }"}).encode())
    allowed(ask("POST", "api.github.com/graphql", body), "graphql-read")
