"""Tests for broker/github_request.py: how the policy and the token swap are
joined for one request.

What the policy itself allows is tested in test_github_policy.py, and the
swap in test_swap.py. These tests are about the joining: the order of the
two, what is handed to the policy, and what comes out for each answer it
gives. They need no network and no mitmproxy.
"""

import base64
import json
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "broker"))

import github_policy  # noqa: E402
import github_request  # noqa: E402
import swap  # noqa: E402

TOKEN = swap.Secret("made-up-token-for-tests")
PLACEHOLDER = swap.PLACEHOLDER
GIT, API = "github.com", "api.github.com"

RULES = {
    "repos": [
        {"repo": "some-owner/listed", "note": "Worked on.", "access": "write", "id": "R_kgDOAbCdEf"},
        {"repo": "some-owner/reference", "note": "Read only.", "access": "read"},
    ]
}
POLICY = github_policy.load_policy(RULES)
POLICY_READ_PUBLIC = github_policy.load_policy({**RULES, "other_repos": "read-public"})


def basic(text: str) -> str:
    return "Basic " + base64.b64encode(text.encode()).decode()


def plan(
    method: str,
    host: str,
    target: str,
    *,
    login: str | None = f"token {PLACEHOLDER}",
    body: bytes | None = None,
    policy=POLICY,
    token=TOKEN,
    extra: tuple[tuple[str, str], ...] = (),
    authority: str | None = None,
):
    """Ask for a plan the way proxy.py does, with the usual headers filled in."""
    headers = [("Host", host), ("User-Agent", "test")]
    if login is not None:
        headers.append(("Authorization", login))
    if body is not None:
        headers.append(("Content-Type", "application/json"))
        headers.append(("Content-Length", str(len(body))))
    headers.extend(extra)
    return github_request.plan(
        policy,
        token,
        method=method,
        host=host,
        target=target,
        headers=headers,
        authority=host if authority is None else authority,
        body=body,
    )


# --- The rules file ----------------------------------------------------------


def test_the_github_part_is_loaded_when_a_github_host_is_opened():
    policy = github_request.load_policy({"github": RULES}, [GIT, API])
    assert sorted(policy.repos) == ["some-owner/listed", "some-owner/reference"]


def test_an_opened_host_without_a_github_part_is_an_error():
    """Without rules, the token would be added to any request at all."""
    for opened in ([GIT], [API], [GIT, API]):
        with pytest.raises(github_policy.PolicyError) as caught:
            github_request.load_policy({"destinations": []}, opened)
        assert "`github:`" in str(caught.value)


@pytest.mark.parametrize("part", [None, {}, [], "write", {"repos": "all"}, {"repo": []}])
def test_a_github_part_that_is_not_one_is_an_error(part):
    with pytest.raises(github_policy.PolicyError):
        github_request.load_policy({"github": part}, [GIT, API])


def test_a_github_part_without_repos_refuses_every_repo_but_loads():
    policy = github_request.load_policy({"github": {"repos": []}}, [GIT, API])
    assert not plan("GET", GIT, "/some-owner/listed/info/refs?service=git-upload-pack", policy=policy).allowed


@pytest.mark.parametrize(
    "host", ["gist.github.com", "uploads.github.com", "example.org", "github.com.example.org", "codeload.github.com"]
)
def test_only_the_hosts_the_policy_knows_can_be_opened(host):
    with pytest.raises(github_policy.PolicyError) as caught:
        github_request.load_policy({"github": RULES}, [GIT, host])
    assert host in str(caught.value)


def test_a_file_that_opens_nothing_needs_no_github_part():
    assert github_request.load_policy({"destinations": []}, []) is None


def test_a_github_part_is_checked_even_when_nothing_is_opened():
    assert github_request.load_policy({"github": RULES}, []) is not None
    with pytest.raises(github_policy.PolicyError):
        github_request.load_policy({"github": {"repos": [{"repo": "no-slash"}]}}, [])


def test_the_repos_rules_file_loads_and_lists_this_project():
    yaml = pytest.importorskip("ruamel.yaml")
    with open(REPO / "broker/rules.yaml", encoding="utf-8") as file:
        data = yaml.YAML(typ="safe").load(file)
    opened = [entry["host"] for entry in data["destinations"] if entry.get("inspect")]
    assert sorted(opened) == sorted(github_request.HOSTS)
    policy = github_request.load_policy(data, opened)
    repo = policy.find("madshermansen", "nixt3")
    assert repo is not None and repo.write and not repo.merge and repo.number is not None
    assert not policy.read_public
    assert len(policy.repos) == 1


def test_the_agent_and_the_checks_are_told_about_the_listed_repos():
    """The repos are named in the rules, in what the agent in the VM is
    told, and in the checks that run in the VM. They have to agree."""
    yaml = pytest.importorskip("ruamel.yaml")
    with open(REPO / "broker/rules.yaml", encoding="utf-8") as file:
        data = yaml.YAML(typ="safe").load(file)
    listed = [entry["repo"] for entry in data["github"]["repos"]]
    told = (REPO / "vm/agent-instructions.md").read_text()
    for repo in listed:
        assert f"`{repo}`" in told, repo
    assert f'listed="{listed[0]}"' in (REPO / "tests/network-lock.sh").read_text()
    assert f'listed="{listed[0]}"' in (REPO / "tests/github-broker.sh").read_text()
    assert f"repo=${{1:-{listed[0]}}}" in (REPO / "tests/github-live.sh").read_text()


def test_the_files_the_agent_is_told_to_change_exist():
    """To ask for more access, the agent in the VM is told which file of
    this repo to change. A file that was moved would send it looking."""
    told = (REPO / "vm/agent-instructions.md").read_text()
    for path in ("broker/rules.yaml", "vm/default.nix", "vm/agent-instructions.md", "CLAUDE.md"):
        assert f"`{path}`" in told, path
        assert (REPO / path).is_file(), path
    assert "environment.systemPackages" in told
    assert "environment.systemPackages" in (REPO / "vm/default.nix").read_text()


# --- How a refusal is worded for the program that gets it ----------------------

REFUSAL = "Refused by the sandbox broker: no.\n\nUse:\n\n    gh api -X PATCH repos/a/b/pulls/1 -f state=closed\n"


def test_a_refusal_for_git_is_a_403_in_plain_text_which_git_shows_line_by_line():
    text = "Refused by the sandbox broker: no.\n\nMore, with an \u00e9.\n"
    status, body, content_type = github_request.refusal_answer(GIT, "/a/b/info/refs?service=git-upload-pack", text)
    assert status == 403 and content_type.startswith("text/plain")
    assert body.decode("utf-8") == text


def test_a_refusal_on_the_rest_api_is_a_403_with_a_json_message_as_githubs_own_errors_are():
    """`gh` shows the `message` of a JSON error, and only the status line of
    a plain-text one. The message is where the agent is told the way on."""
    for host in (API, "API.GitHub.com"):
        status, body, content_type = github_request.refusal_answer(host, "/repos/a/b/pulls/1", REFUSAL)
        assert status == 403 and content_type.startswith("application/json")
        assert json.loads(body) == {"message": REFUSAL}
        body.decode("ascii")


@pytest.mark.parametrize("target", ["/graphql", "/graphql?x=y"])
def test_a_refused_graphql_request_is_answered_the_way_graphql_refuses(target):
    """The `gh` commands that change something print the body of a 403 as
    one escaped line. They show a GraphQL error cleanly, and so do the
    commands that read. Seen with gh 2.102."""
    status, body, content_type = github_request.refusal_answer(API, target, REFUSAL)
    assert status == 200 and content_type.startswith("application/json")
    answer = json.loads(body)
    assert answer["data"] is None
    assert answer["errors"] == [{"type": "FORBIDDEN", "message": REFUSAL}]
    body.decode("ascii")


@pytest.mark.parametrize("target", ["/graphql/x", "/graphqlx", "/repos/a/graphql", "/"])
def test_only_the_graphql_address_is_answered_that_way(target):
    status, body, _ = github_request.refusal_answer(API, target, REFUSAL)
    assert status == 403 and json.loads(body) == {"message": REFUSAL}


def test_a_graphql_answer_for_github_dot_com_is_still_plain_text():
    status, _, content_type = github_request.refusal_answer(GIT, "/graphql", REFUSAL)
    assert status == 403 and content_type.startswith("text/plain")


def test_every_refusal_of_the_policy_fits_in_a_json_message():
    result = plan("GET", API, "/repos/someone-else/repo")
    _, body, _ = github_request.refusal_answer(API, "/repos/someone-else/repo", result.message)
    assert json.loads(body)["message"] == result.message


def test_a_read_that_is_not_on_the_list_also_names_the_way_to_make_a_change():
    """`gh pr edit` reads who can be assigned before it changes anything,
    and is refused at that read. The policy's text is about reading; the
    agent wanted to change a title."""
    body = graphql(
        'query { repository(owner: "some-owner", name: "listed") '
        "{ pullRequest(number: 5) { assignedActors(first: 5) { nodes { __typename } } } } }"
    )
    result = plan("POST", API, "/graphql", body=body)
    assert (result.allowed, result.reason) == (False, "graphql-not-on-list")
    assert result.message.startswith("Refused by the sandbox broker: ")
    assert "gh api -X PATCH repos/OWNER/REPO/pulls/NUMBER -f title='TITLE'" in result.message
    assert "`gh pr edit`" in result.message


def test_other_refusals_are_the_policys_text_unchanged():
    decision = github_policy.decide(
        "GET", API, "/repos/someone-else/repo", "", None, POLICY,
        headers=[("Host", API)], authority=API,
    )
    result = plan("GET", API, "/repos/someone-else/repo")
    assert result.message == decision.message
    assert github_request.CHANGE_INSTEAD not in result.message


def test_each_line_named_for_a_change_is_itself_allowed_in_a_write_repo():
    """The hint must not send the agent to something that is refused."""
    requests = [
        ("PATCH", "/repos/some-owner/listed/pulls/5", b'{"title":"T","body":"B"}'),
        ("POST", "/repos/some-owner/listed/issues/5/comments", b'{"body":"B"}'),
        ("POST", "/repos/some-owner/listed/issues/5/labels", b'{"labels":["L"]}'),
        ("PATCH", "/repos/some-owner/listed/pulls/5", b'{"state":"closed"}'),
    ]
    assert github_request.CHANGE_INSTEAD.count("gh api") == len(requests) + 1
    for method, target, body in requests:
        assert plan(method, API, target, body=body).allowed, target


# --- When a request is decided on ---------------------------------------------


def test_git_is_decided_at_once_whatever_its_body():
    assert github_request.when_to_decide(GIT, True) == "now"
    assert github_request.when_to_decide(GIT, False) == "now"


def test_the_api_is_decided_after_its_body_has_been_read():
    assert github_request.when_to_decide(API, True) == "after-body"


def test_an_api_request_whose_body_cannot_be_read_is_refused():
    assert github_request.when_to_decide(API, False) == "refuse"
    assert github_request.when_to_decide("API.GitHub.com", False) == "refuse"


def test_the_two_limits_on_a_body_agree():
    """A body the broker reads in full is one the policy accepts by size."""
    assert swap.MAX_READ_BODY <= github_policy.MAX_BODY


# --- The login comes first -----------------------------------------------------


@pytest.mark.parametrize("login", ["token some-other-token", "Bearer x", basic("a:b"), f"Digest {PLACEHOLDER}", ""])
def test_another_login_is_refused_before_the_policy_is_asked(login, monkeypatch):
    def never(*arguments, **named):
        raise AssertionError("the policy was asked")

    monkeypatch.setattr(github_policy, "decide", never)
    result = plan("GET", API, "/repos/some-owner/listed", login=login)
    assert (result.allowed, result.reason, result.message) == (False, "other-login", None)


def test_two_logins_are_refused():
    result = plan("GET", API, "/repos/some-owner/listed", extra=(("authorization", f"token {PLACEHOLDER}"),))
    assert (result.allowed, result.reason) == (False, "several-logins")


def test_the_placeholder_is_refused_where_the_host_has_no_token():
    result = plan("GET", API, "/repos/some-owner/listed", token=None)
    assert (result.allowed, result.reason) == (False, "no-token-for-host")


def test_without_a_policy_everything_is_refused():
    result = plan("GET", API, "/repos/some-owner/listed", policy=None)
    assert (result.allowed, result.reason) == (False, "no-policy")


# --- What the policy allows -----------------------------------------------------


def test_an_allowed_request_with_the_placeholder_gets_the_token():
    result = plan("GET", API, "/repos/some-owner/listed/pulls?state=open")
    assert result.allowed and result.with_token and result.kind == "api-read"
    assert result.authorization == f"token {TOKEN.reveal()}"
    assert result.body is None


def test_gits_login_gets_the_token_too():
    result = plan(
        "GET", GIT, "/some-owner/listed.git/info/refs?service=git-receive-pack", login=basic(f"x:{PLACEHOLDER}")
    )
    assert result.allowed and result.kind == "git-write"
    assert result.authorization == basic(f"x-access-token:{TOKEN.reveal()}")


def test_an_allowed_request_without_a_login_stays_without_one():
    """The program in the VM chooses to log in; the broker does not for it."""
    result = plan("GET", GIT, "/some-owner/listed/info/refs?service=git-upload-pack", login=None)
    assert result.allowed and result.with_token
    assert result.authorization is None


def test_an_allowed_change_is_sent_with_the_body_the_policy_wrote_out():
    sent = b'{ "body" : "a comment" }'
    result = plan("POST", API, "/repos/some-owner/listed/issues/7/comments", body=sent)
    assert result.allowed and result.kind == "api-write"
    assert result.body == b'{"body":"a comment"}'
    assert result.authorization == f"token {TOKEN.reveal()}"


# --- What the policy refuses -----------------------------------------------------


@pytest.mark.parametrize(
    "method, host, target, body, reason",
    [
        ("GET", GIT, "/someone-else/repo/info/refs?service=git-upload-pack", None, "repo-not-listed"),
        ("POST", GIT, "/someone-else/repo/git-receive-pack", None, "repo-not-listed"),
        ("GET", GIT, "/some-owner/reference/info/refs?service=git-receive-pack", None, "repo-read-only"),
        ("GET", API, "/repos/someone-else/repo", None, "repo-not-listed"),
        ("PATCH", API, "/repos/some-owner/listed", b'{"private":false}', "repo-settings"),
        ("GET", API, "/repos/some-owner/listed/actions/secrets", None, "secrets"),
        ("PUT", API, "/repos/some-owner/listed/pulls/7/merge", b"", "merge"),
    ],
)
def test_a_refusal_carries_the_policys_reason_and_message_and_no_token(method, host, target, body, reason):
    result = plan(method, host, target, body=body)
    assert (result.allowed, result.reason) == (False, reason)
    assert result.message.startswith("Refused by the sandbox broker: ")
    assert result.authorization is None and result.body is None
    assert TOKEN.reveal() not in repr(result)


def test_an_api_change_whose_body_was_not_read_is_refused():
    """proxy.py hands over None when it did not read the body."""
    result = plan("POST", API, "/repos/some-owner/listed/issues/7/comments", body=None)
    assert (result.allowed, result.reason) == (False, "body-odd")
    result = plan("POST", API, "/graphql", body=None)
    assert (result.allowed, result.reason) == (False, "body-odd")


def test_a_compressed_body_is_refused_by_its_header():
    result = plan(
        "POST",
        API,
        "/repos/some-owner/listed/issues/7/comments",
        body=b'{"body":"x"}',
        extra=(("Content-Encoding", "gzip"),),
    )
    assert (result.allowed, result.reason) == (False, "body-odd")


# --- The policy sees the request as it was sent -------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "/repos/some-owner/listed#/../../someone-else/repo",
        "/repos/some-owner/listed/../../someone-else/repo",
        "/repos/some-owner//listed",
        "/repos/some-owner/listed/",
        "/repos/some-owner/listed/%70ulls",
        "/repos/some-owner/listed%2f..%2f..%2fsomeone-else/repo",
        "/repos/some-owner/listed/pulls?state=open#fragment",
        "/repos/some-owner/listed/pulls\\..\\secrets",
        "repos/some-owner/listed",
        "*",
        "https://api.github.com/repos/some-owner/listed",
        "/repos/some-owner/listed/pullsé",
        "/repos/some-owner/listed/pulls\udcc3\udca9",
        "/repos/some-owner/listed/pulls ",
    ],
)
def test_an_odd_target_is_refused_not_tidied(target):
    assert not plan("GET", API, target).allowed


def test_the_target_is_split_at_the_first_question_mark_only():
    """What follows the first `?` is the query, further `?` included."""
    seen = {}

    def spy(method, host, path, query, body, policy, **named):
        seen.update(path=path, query=query, named=named)
        return github_policy.Decision(allowed=True, kind="api-read", with_token=True)

    original = github_policy.decide
    github_policy.decide = spy
    try:
        plan("GET", API, "/repos/a/b/pulls?state=open&q=a?b#c")
        assert (seen["path"], seen["query"]) == ("/repos/a/b/pulls", "state=open&q=a?b#c")
        plan("GET", API, "/repos/a/b")
        assert (seen["path"], seen["query"]) == ("/repos/a/b", "")
        plan("GET", API, "/repos/a/b?")
        assert (seen["path"], seen["query"]) == ("/repos/a/b", "")
    finally:
        github_policy.decide = original


@pytest.mark.parametrize("method", ["get", "Get", "gET", "delete", "Post", "PoSt", "patch", "GET ", " GET", "GE T", ""])
def test_a_method_in_another_spelling_is_refused_not_read_as_the_usual_one(method):
    """The policy is given the method as it was sent. `delete` is not DELETE:
    the broker passes on what it was sent, and must not judge something else."""
    result = plan(method, API, "/repos/some-owner/listed/issues/comments/5", body=b"")
    assert not result.allowed
    result = plan(method, GIT, "/some-owner/listed/info/refs?service=git-upload-pack")
    assert not result.allowed


@pytest.mark.parametrize(
    "extra",
    [
        ("Content-Type", "application/json\xa0"),
        ("Content-Encoding", "\xa0"),
        ("X-Nul", "a\x00b"),
        ("X-High", "\xff\xfe"),
        ("X-N\xe4me", "x"),
    ],
)
def test_a_header_with_a_byte_outside_plain_ascii_is_refused_before_the_policy_is_asked(extra, monkeypatch):
    """The policy removes more than HTTP's white space around a value before
    it reads it, so `application/json` plus the byte 0xa0 would be judged
    as `application/json` and sent on with the byte."""

    def never(*arguments, **named):
        raise AssertionError("the policy was asked")

    monkeypatch.setattr(github_policy, "decide", never)
    headers = [("Host", API), ("Authorization", f"token {PLACEHOLDER}"), extra]
    result = github_request.plan(
        POLICY, TOKEN, method="GET", host=API, target="/repos/some-owner/listed",
        headers=headers, authority=API, body=None,
    )
    assert (result.allowed, result.reason, result.message) == (False, "odd-header", None)


def test_every_header_reaches_the_policy_also_one_sent_twice():
    """A header that asks for another method is refused by the policy."""
    result = plan("POST", API, "/repos/some-owner/listed/issues/7/comments", body=b'{"body":"x"}',
                  extra=(("X-HTTP-Method-Override", "DELETE"),))
    assert (result.allowed, result.reason) == (False, "method-override")
    result = plan("POST", API, "/repos/some-owner/listed/issues/7/comments", body=b'{"body":"x"}',
                  extra=(("Content-Type", "application/x-www-form-urlencoded"),))
    assert (result.allowed, result.reason) == (False, "header-repeated")


@pytest.mark.parametrize("authority", ["gist.github.com", "github.com", "api.github.com:8443", "", "api.github.com."])
def test_a_request_that_names_another_host_than_its_tunnel_is_refused(authority):
    result = github_request.plan(
        POLICY, TOKEN, method="GET", host=API, target="/repos/some-owner/listed",
        headers=[("Host", authority), ("Authorization", f"token {PLACEHOLDER}")],
        authority=authority, body=None,
    )
    assert (result.allowed, result.reason) == (False, "host-differs")


def test_a_request_that_names_no_host_is_refused():
    result = github_request.plan(
        POLICY, TOKEN, method="GET", host=API, target="/repos/some-owner/listed",
        headers=[("Authorization", f"token {PLACEHOLDER}")], authority=None, body=None,
    )
    assert (result.allowed, result.reason) == (False, "host-differs")


def test_the_broker_hands_over_the_bytes_and_not_mitmproxys_view_of_them():
    """proxy.py cannot be loaded here, so this reads it.

    The part that asks the policy must take the method, the address and the
    headers from the bytes mitmproxy holds (`request.data`, and the header
    `fields`), not from the accessors mitmproxy offers for convenience:
    `request.method` is in upper case whatever was sent, and the header
    accessors decode. A request that passes is the same either way since
    headers outside plain ASCII are refused, so no request can show the
    difference; this keeps the next change from bringing it back.
    """
    source = (REPO / "broker/proxy.py").read_text()
    start = source.index("    def pass_on(")
    asks = source[start : source.index("\n    def ", start + 1)]
    assert "request.headers.fields" in asks and "as_sent(request)" in asks
    for convenient in ("request.method", "request.path", "host_header", "= request.authority",
                       ".items(", "get_all(", "request.url", "pretty_"):  # fmt: skip
        assert convenient not in asks, convenient


# --- Repos that are not listed, when reading them is allowed --------------------------


def test_reading_an_unlisted_repo_goes_out_without_any_login():
    for login in (f"token {PLACEHOLDER}", basic(f"x:{PLACEHOLDER}"), None):
        result = plan(
            "GET", GIT, "/someone-else/repo/info/refs?service=git-upload-pack",
            login=login, policy=POLICY_READ_PUBLIC,
        )
        assert result.allowed and not result.with_token and result.kind == "git-read"
        assert result.authorization is None
    result = plan("GET", API, "/repos/someone-else/repo/pulls", policy=POLICY_READ_PUBLIC)
    assert result.allowed and not result.with_token and result.authorization is None


def test_another_login_is_still_refused_when_reading_unlisted_repos_is_allowed():
    result = plan(
        "GET", GIT, "/someone-else/repo/info/refs?service=git-upload-pack",
        login="token some-other-token", policy=POLICY_READ_PUBLIC,
    )
    assert (result.allowed, result.reason) == (False, "other-login")


def test_writing_to_an_unlisted_repo_is_refused_whatever_the_setting():
    for target in ("/someone-else/repo/info/refs?service=git-receive-pack",):
        result = plan("GET", GIT, target, policy=POLICY_READ_PUBLIC)
        assert (result.allowed, result.reason) == (False, "repo-not-listed")
    result = plan("POST", API, "/repos/someone-else/repo/issues/1/comments",
                  body=b'{"body":"x"}', policy=POLICY_READ_PUBLIC)
    assert (result.allowed, result.reason) == (False, "repo-not-listed")


def test_a_listed_repo_still_gets_the_token_when_reading_unlisted_repos_is_allowed():
    result = plan("GET", API, "/repos/some-owner/listed", policy=POLICY_READ_PUBLIC)
    assert result.allowed and result.with_token
    assert result.authorization == f"token {TOKEN.reveal()}"


# --- GraphQL, which arrives as a body -------------------------------------------------


def graphql(query: str, variables: dict | None = None) -> bytes:
    return json.dumps({"query": query, "variables": variables or {}}).encode()


def test_a_graphql_read_of_a_listed_repo_is_allowed_with_a_fresh_body():
    body = graphql('query { repository(owner: "some-owner", name: "listed") { id } }')
    result = plan("POST", API, "/graphql", body=body)
    assert result.allowed and result.kind == "graphql-read"
    assert json.loads(result.body)["query"].startswith("query")
    assert result.authorization == f"token {TOKEN.reveal()}"


def test_a_graphql_read_of_an_unlisted_repo_is_refused():
    body = graphql('query { repository(owner: "someone-else", name: "repo") { id } }')
    result = plan("POST", API, "/graphql", body=body)
    assert (result.allowed, result.reason) == (False, "repo-not-listed")


def test_a_graphql_change_by_id_is_refused_with_the_way_on():
    body = graphql('mutation { closePullRequest(input: {pullRequestId: "PR_kwDOAbCdEf8AAAABPlDjjg"}) { clientMutationId } }')
    result = plan("POST", API, "/graphql", body=body)
    assert (result.allowed, result.reason) == (False, "graphql-by-id")
    assert "gh api" in result.message
