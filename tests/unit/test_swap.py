"""Tests for broker/swap.py: the decisions the broker makes about one request.

They need no network, no VM and no mitmproxy. Run them from the repo with
`pytest tests/unit`.
"""

import base64
import json
import os
import pathlib
import sys
import threading

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "broker"))

import swap  # noqa: E402

TOKEN = swap.Secret("made-up-token-for-tests")
PLACEHOLDER = swap.PLACEHOLDER


def basic(text: str) -> str:
    return "Basic " + base64.b64encode(text.encode()).decode()


# --- The placeholder ---------------------------------------------------------


def test_the_placeholder_is_the_same_everywhere():
    """The VM and the checks each hold a copy of the placeholder."""
    for path in ("vm/default.nix", "tests/network-lock.sh", "tests/github-broker.sh"):
        assert f'"{PLACEHOLDER}"' in (REPO / path).read_text(), path


def test_the_placeholder_does_not_look_like_a_real_token():
    assert not PLACEHOLDER.startswith(("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"))
    assert "placeholder" in PLACEHOLDER


# --- Swapping the login ------------------------------------------------------


def test_no_login_is_passed_on_as_it_is():
    assert swap.swap_authorization([], TOKEN) == swap.Credential("none")


@pytest.mark.parametrize("scheme", ["token", "Token", "Bearer", "bearer", "BEARER"])
def test_token_and_bearer_get_the_real_token(scheme):
    result = swap.swap_authorization([f"{scheme} {PLACEHOLDER}"], TOKEN)
    assert result.action == "swap"
    assert result.value == f"{scheme} {TOKEN.reveal()}"


@pytest.mark.parametrize(
    "login",
    [
        f"x-access-token:{PLACEHOLDER}",
        f"someone:{PLACEHOLDER}",
        f":{PLACEHOLDER}",
        f"{PLACEHOLDER}:",
        f"{PLACEHOLDER}:x-oauth-basic",
    ],
)
def test_gits_login_gets_the_real_token(login):
    result = swap.swap_authorization([basic(login)], TOKEN)
    assert result.action == "swap"
    assert result.value == basic(f"x-access-token:{TOKEN.reveal()}")


def test_nothing_the_vm_sent_stays_in_gits_login():
    """A second login cannot ride along in the user name."""
    result = swap.swap_authorization([basic(f"ghp_someone-elses:{PLACEHOLDER}")], TOKEN)
    assert "someone-elses" not in base64.b64decode(result.value.split()[1]).decode()


@pytest.mark.parametrize(
    "header",
    [
        "token some-other-token",
        "Bearer some-other-token",
        f"token {PLACEHOLDER}x",
        f"token x{PLACEHOLDER}",
        f"token {PLACEHOLDER} extra",
        f"token {PLACEHOLDER.upper()}",
        "token",
        "",
        basic("someone:some-password"),
        basic(f"{PLACEHOLDER}:some-password"),
        basic(f"someone:{PLACEHOLDER}:more"),
        basic(PLACEHOLDER),
        "Basic not-base64!",
        "Basic \u00e9",
        "Basic \udcc3\udca9",
        "token \u00e9",
        "Basic " + "A" * 100_000,
        "token " + "a" * 100_000,
        f"token {PLACEHOLDER}\x00",
        f"token nixt3-placeholder\t-not-a-real-token",
        "Basic " + base64.b64encode(b"\xff\xfe:x").decode(),
        f"Digest {PLACEHOLDER}",
        f"Negotiate {PLACEHOLDER}",
        PLACEHOLDER,
    ],
)
def test_any_other_login_is_refused(header):
    result = swap.swap_authorization([header], TOKEN)
    assert result.action == "refuse"
    assert result.value is None


def test_two_logins_are_refused_even_if_both_are_the_placeholder():
    header = f"token {PLACEHOLDER}"
    assert swap.swap_authorization([header, header], TOKEN).action == "refuse"


def test_the_placeholder_is_refused_where_there_is_no_token():
    for header in (f"token {PLACEHOLDER}", basic(f"x:{PLACEHOLDER}")):
        result = swap.swap_authorization([header], None)
        assert (result.action, result.reason) == ("refuse", "no-token-for-host")


def test_another_login_is_refused_where_there_is_no_token():
    assert swap.swap_authorization(["token other"], None).action == "refuse"


def test_a_refusal_never_holds_the_token():
    for header in ("token other", basic("a:b"), f"Digest {PLACEHOLDER}"):
        assert TOKEN.reveal() not in repr(swap.swap_authorization([header], TOKEN))


def test_no_login_makes_the_swap_fail_with_an_error():
    """Whatever arrives, the answer is a decision, never an exception.

    An exception here once let a request through unchecked, because
    mitmproxy carries on when a hook fails.
    """
    odd = ["\u00e9", "\udcff", "\x00", "\x7f", " ", "\t", "=", "====", ":", "\U0001f600"]
    for scheme in ("Basic", "basic", "token", "Bearer", "Digest", ""):
        for value in odd + [PLACEHOLDER + extra for extra in odd]:
            for header in (f"{scheme} {value}", f"{scheme}{value}", value):
                result = swap.swap_authorization([header], TOKEN)
                assert result.action in ("refuse", "swap")
                assert result.action == "refuse" or value.strip() == PLACEHOLDER


# --- Headers that are left out -----------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "X-HTTP-Method-Override",
        "x-http-method",
        "X-Method-Override",
        "X-Forwarded-Host",
        "x-forwarded-for",
        "X-Forwarded-Proto",
        "Forwarded",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Host",
        " X-Real-IP ",
    ],
)
def test_headers_that_claim_another_method_or_host_are_left_out(name):
    assert swap.drops_header(name)


@pytest.mark.parametrize(
    "name", ["Host", "Accept", "User-Agent", "X-GitHub-Api-Version", "Content-Type", "X-Forward"]
)
def test_other_headers_stay(name):
    assert not swap.drops_header(name)


# --- The secret wrapper ------------------------------------------------------


def test_a_secret_does_not_print_itself():
    assert TOKEN.reveal() not in repr(TOKEN)
    assert TOKEN.reveal() not in str(TOKEN)
    assert TOKEN.reveal() not in f"{TOKEN} {[TOKEN]} { {'github': TOKEN} }"


def test_scrub_removes_every_token():
    text = f"error near {TOKEN.reveal()} and again {TOKEN.reveal()}"
    assert swap.scrub(text, [TOKEN]) == "error near <secret> and again <secret>"
    assert swap.scrub("nothing here", [TOKEN]) == "nothing here"


def copied(pieces: list[bytes], secrets: list[swap.Secret]) -> bytes:
    """What copy_scrubbed() lets through of `pieces`, written one by one."""
    source_read, source_write = os.pipe()
    target_read, target_write = os.pipe()
    result = bytearray()

    def collect() -> None:
        # Read while the copying goes on: a pipe holds only so much.
        while piece := os.read(target_read, 65536):
            result.extend(piece)

    def copy() -> None:
        swap.copy_scrubbed(source_read, target_write, secrets)
        os.close(target_write)

    helpers = [threading.Thread(target=collect), threading.Thread(target=copy)]
    for helper in helpers:
        helper.start()
    for piece in pieces:
        os.write(source_write, piece)
    os.close(source_write)
    for helper in helpers:
        helper.join(10)
        assert not helper.is_alive()
    os.close(source_read)
    os.close(target_read)
    return bytes(result)


def test_output_is_copied_with_tokens_replaced():
    token = TOKEN.reveal().encode()
    assert copied([b"plain line\n"], [TOKEN]) == b"plain line\n"
    assert copied([b"a " + token + b" b\n"], [TOKEN]) == b"a <secret> b\n"
    assert copied([b"no line break " + token], [TOKEN]) == b"no line break <secret>"
    assert copied([], [TOKEN]) == b""
    assert copied([b"nothing to hide\n"], []) == b"nothing to hide\n"


def test_a_token_that_arrives_in_parts_is_replaced_too():
    token = TOKEN.reveal().encode()
    for cut in range(1, len(token)):
        result = copied([b"start " + token[:cut], token[cut:] + b" end\n"], [TOKEN])
        assert result == b"start <secret> end\n", cut
    # Also in a line too long to be held back whole.
    long = b"x" * 200_000
    result = copied([long + token[:5], token[5:] + long], [TOKEN])
    assert result == long + b"<secret>" + long


def test_the_start_of_a_token_alone_is_let_through_at_the_end():
    token = TOKEN.reveal().encode()
    assert copied([b"cut off: " + token[:6]], [TOKEN]) == b"cut off: " + token[:6]


# --- Which host a request names ----------------------------------------------


@pytest.mark.parametrize(
    "authority, hosts",
    [
        ("", ["github.com"]),
        ("", ["GitHub.com"]),
        ("", ["github.com:443"]),
        ("github.com", []),
        ("github.com:443", ["github.com"]),
    ],
)
def test_a_request_that_names_the_host_is_accepted(authority, hosts):
    assert swap.names_the_host(authority, hosts, "github.com", 443)


@pytest.mark.parametrize(
    "authority, hosts",
    [
        ("", []),
        ("", ["other.example"]),
        ("", ["github.com", "other.example"]),
        ("other.example", ["github.com"]),
        ("", ["github.com:8443"]),
        ("", ["github.com."]),
        ("", ["api.github.com"]),
        ("", ["github.com.other.example"]),
        ("", ["github.com@other.example"]),
        ("", ["github.com, other.example"]),
    ],
)
def test_a_request_that_names_another_host_is_not(authority, hosts):
    assert not swap.names_the_host(authority, hosts, "github.com", 443)


# --- Whether a body is read in full -------------------------------------------


def test_a_small_declared_body_is_read():
    assert swap.reads_body(True, ["0"], False)
    assert swap.reads_body(True, ["12"], False)
    assert swap.reads_body(True, [str(swap.MAX_READ_BODY)], False)


def test_a_request_without_a_body_counts_as_small_in_http1_only():
    assert swap.reads_body(True, [], False)
    assert not swap.reads_body(False, [], False)


@pytest.mark.parametrize(
    "lengths, chunked",
    [
        ([str(swap.MAX_READ_BODY + 1)], False),
        (["99999999999999999999"], False),
        ([], True),
        (["12"], True),
        (["12", "12"], False),
        (["12", "99999999"], False),
        (["-1"], False),
        (["1e3"], False),
        (["0x10"], False),
        (["١٢"], False),
        ([""], False),
    ],
)
def test_a_large_or_unclear_body_is_not_read(lengths, chunked):
    assert not swap.reads_body(True, lengths, chunked)


# --- The path that is logged --------------------------------------------------


def test_the_query_string_is_split_off():
    assert swap.split_path("/a/b") == ("/a/b", "")
    assert swap.split_path("/a/b?c=d&e=f") == ("/a/b", "c=d&e=f")
    assert swap.split_path("/a?b?c") == ("/a", "b?c")
    assert swap.split_path("/a?b#c") == ("/a", "b")
    assert swap.split_path("?b") == ("/", "b")
    assert swap.split_path("") == ("/", "")


# --- The handover of tokens to the broker --------------------------------------


def handover(tokens) -> str:
    return json.dumps({"tokens": tokens})


def test_the_handover_gives_the_tokens_that_are_needed():
    result = swap.parse_handover(handover({"github": "abc", "unused": "def"}), {"github"})
    assert list(result) == ["github"]
    assert result["github"].reveal() == "abc"


def test_an_empty_handover_is_fine_when_nothing_is_needed():
    assert swap.parse_handover(handover({}), set()) == {}


@pytest.mark.parametrize(
    "text",
    [
        "",
        "not json",
        "[]",
        '{"github": "abc"}',
        handover([]),
        handover({}),
        handover({"other": "abc"}),
        handover({"github": ""}),
        handover({"github": 12}),
        handover({"github": None}),
        handover({"github": "two words"}),
        handover({"github": "line\nbreak"}),
        handover({"github": "abc\r\nX-Injected: 1"}),
        handover({"github": "café"}),
        handover({"github": PLACEHOLDER}),
    ],
)
def test_a_handover_without_a_usable_token_is_an_error(text):
    with pytest.raises(ValueError):
        swap.parse_handover(text, {"github"})


def test_an_error_about_the_handover_never_holds_what_arrived():
    for text in (
        handover({"github": "secret one two"}),
        '{"tokens": {"github": "secret-one"',
        handover({"other": "secret-one"}),
    ):
        with pytest.raises(ValueError) as caught:
            swap.parse_handover(text, {"github"})
        assert "secret" not in str(caught.value)
        # Nor does it drag along the error it came from, which might.
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None or caught.value.__suppress_context__
