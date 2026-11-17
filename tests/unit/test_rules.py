"""Tests for the rules in broker/proxy.py: reading rules.yaml, and the
decision whether a host and port may be reached.

They need no network and no VM, and they start no broker. They do need
mitmproxy to be installed, because proxy.py is a mitmproxy script; the
`proxy` fixture in conftest.py explains how the file is loaded. Run them from
the repo with `pytest tests/unit`, inside `nix develop`.

What these tests guard is that the broker fails closed: a rules file with a
mistake in it must be refused as a whole, and a destination that is not
listed exactly must be refused. A loader that is forgiving would let a typing
mistake change what the VM can reach without anyone noticing.
"""

import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]


@pytest.fixture
def load(proxy, tmp_path):
    """load(text) writes `text` to a rules file and returns what the broker reads."""

    def load(text: str | bytes):
        path = tmp_path / "rules.yaml"
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text, encoding="utf-8")
        return proxy.load_rules(str(path))

    return load


def rules_with(*entries: dict) -> str:
    """The text of a rules file with these destinations.

    The entries are written as JSON, which is also valid YAML. That way a
    value keeps the type it has here: "127.1" stays a text and does not turn
    into a number, as it would when written bare in YAML.
    """
    return json.dumps({"destinations": list(entries)})


def entry(host: str = "example.org", **fields) -> dict:
    """One destination with a note, plus or minus the given fields."""
    return {"host": host, "note": "A made-up destination.", **fields}


def decider(proxy, rules):
    """A broker that holds only these rules.

    The decision under test, Broker.refusal(), reads nothing but the rules.
    So the broker is made without running its start, which also wants the
    tokens and whatever later phases add.
    """
    broker = object.__new__(proxy.Broker)
    broker.rules = rules
    return broker


# --- A rules file without mistakes --------------------------------------------


def test_a_destination_with_only_a_host_and_a_note_gets_port_443(load):
    rules = load("destinations:\n  - host: example.org\n    note: Why the VM needs it.\n")
    assert set(rules) == {"example.org"}
    assert rules["example.org"].ports == frozenset({443})
    assert rules["example.org"].inspect is False
    assert rules["example.org"].token is None


def test_a_port_list_replaces_443_instead_of_adding_to_it(load):
    rules = load(rules_with(entry(ports=[8443, 9000])))
    assert rules["example.org"].ports == frozenset({8443, 9000})


def test_host_names_are_stored_in_lower_case(load):
    rules = load(rules_with(entry("API.Example.ORG")))
    assert set(rules) == {"api.example.org"}


def test_an_opened_destination_with_a_token(load):
    rules = load(rules_with(entry(inspect=True, token="github")))
    assert rules["example.org"].inspect is True
    assert rules["example.org"].token == "github"


def test_a_destination_may_be_opened_without_a_token(load):
    rules = load(rules_with(entry(inspect=True)))
    assert rules["example.org"].inspect is True
    assert rules["example.org"].token is None


def test_each_destination_keeps_its_own_settings(load):
    rules = load(
        rules_with(
            entry("one.example.org"),
            entry("two.example.org", ports=[8443]),
            entry("three.example.org", inspect=True, token="github"),
        )
    )
    assert list(rules) == ["one.example.org", "two.example.org", "three.example.org"]
    assert rules["one.example.org"].ports == frozenset({443})
    assert rules["two.example.org"].ports == frozenset({8443})
    assert rules["one.example.org"].token is None
    assert rules["three.example.org"].token == "github"


def test_an_empty_list_is_valid_and_allows_nothing(proxy, load):
    rules = load("destinations: []\n")
    assert rules == {}
    assert decider(proxy, rules).refusal("example.org", 443) == "host-not-listed"


# --- Mistakes: each must stop the broker, with a message that says what to fix -


def test_a_missing_file_is_a_mistake(proxy, tmp_path):
    with pytest.raises(proxy.RulesError, match="cannot read it"):
        proxy.load_rules(str(tmp_path / "no-such-file.yaml"))


def test_a_folder_instead_of_a_file_is_a_mistake(proxy, tmp_path):
    with pytest.raises(proxy.RulesError, match="cannot read it"):
        proxy.load_rules(str(tmp_path))


@pytest.mark.parametrize(
    ("text", "message"),
    [
        pytest.param(b"\xff\xfe\x00d", "not plain UTF-8", id="not-text"),
        pytest.param("destinations: [", "not valid YAML", id="broken-yaml"),
        pytest.param("destinations:\n  - host: a.example\n   note: x\n", "not valid YAML", id="bad-indent"),
        pytest.param("", "must start with a `destinations:` list", id="empty-file"),
        pytest.param("# only a comment\n", "must start with a `destinations:` list", id="only-a-comment"),
        pytest.param("- host: example.org\n  note: x\n", "must start with a `destinations:` list", id="list-at-the-top"),
        pytest.param("just some words\n", "must start with a `destinations:` list", id="plain-text"),
        pytest.param("{}\n", "`destinations` must be a list", id="no-destinations"),
        pytest.param("destinations:\n", "`destinations` must be a list", id="destinations-empty"),
        pytest.param("destinations: example.org\n", "`destinations` must be a list", id="destinations-is-text"),
        pytest.param("destinations:\n  example.org: {note: x}\n", "`destinations` must be a list", id="destinations-is-a-table"),
        pytest.param("destinations: []\nallow_all: true\n", "unknown top-level key: allow_all", id="extra-top-level-key"),
        pytest.param("destination: []\n", "unknown top-level key: destination", id="misspelt-top-level-key"),
        pytest.param("destinations:\n  - example.org\n", "destination 1 must have a `host` and a `note`", id="entry-is-text"),
        pytest.param("destinations:\n  - [example.org, 443]\n", "destination 1 must have a `host` and a `note`", id="entry-is-a-list"),
    ],
)
def test_a_file_of_the_wrong_shape_is_a_mistake(proxy, load, text, message):
    with pytest.raises(proxy.RulesError) as error:
        load(text)
    assert message in str(error.value)


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        pytest.param({"note": "x"}, "destination 1 has no `host`", id="no-host"),
        pytest.param({"host": "", "note": "x"}, "has no `host`", id="empty-host"),
        pytest.param({"host": 443, "note": "x"}, "has no `host`", id="host-is-a-number"),
        pytest.param({"host": ["example.org"], "note": "x"}, "has no `host`", id="host-is-a-list"),
        pytest.param({"host": None, "note": "x"}, "has no `host`", id="host-is-null"),
        pytest.param({"host": "example.org"}, "has no `note`", id="no-note"),
        pytest.param({"host": "example.org", "note": ""}, "has no `note`", id="empty-note"),
        pytest.param({"host": "example.org", "note": "  \n"}, "has no `note`", id="blank-note"),
        pytest.param({"host": "example.org", "note": 7}, "has no `note`", id="note-is-a-number"),
        # A misspelt key must not be read as "the key is absent": `inspct`
        # here would leave the destination unopened, `port` would leave it
        # on 443.
        pytest.param(entry(inspct=True), "unknown key `inspct`", id="misspelt-inspect"),
        pytest.param(entry(port=[8443]), "unknown key `port`", id="misspelt-ports"),
        pytest.param(entry(allow="everything"), "unknown key `allow`", id="made-up-key"),
    ],
)
def test_a_destination_with_a_missing_or_unknown_part_is_a_mistake(proxy, load, fields, message):
    with pytest.raises(proxy.RulesError) as error:
        load(rules_with(fields))
    assert message in str(error.value)


@pytest.mark.parametrize(
    "host",
    [
        "https://example.org",
        "example.org:443",
        "example.org/path",
        "*.example.org",
        "*",
        ".example.org",
        "example.org.",
        "example..org",
        "-example.org",
        "example-.org",
        "exa mple.org",
        " example.org",
        "example.org\n",
        "example_one.org",
        "exämple.org",
        "user@example.org",
        "[::1]",
        "::1",
    ],
)
def test_a_host_that_is_not_one_exact_name_is_a_mistake(proxy, load, host):
    with pytest.raises(proxy.RulesError, match="must be one exact host name"):
        load(rules_with(entry(host)))


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "10.0.2.2",
        # Other ways to write an address, which programs also understand.
        "127.1",
        "0x7f.0.0.1",
        "2130706433",
        "0",
        # Names that mean this Mac or its local network.
        "localhost",
        "router",
        "LOCALHOST",
    ],
)
def test_an_address_or_a_short_local_name_is_a_mistake(proxy, load, host):
    with pytest.raises(proxy.RulesError, match="not an IP address or a short local name"):
        load(rules_with(entry(host)))


@pytest.mark.parametrize("second", ["example.org", "EXAMPLE.org"])
def test_a_host_listed_twice_is_a_mistake(proxy, load, second):
    """Two entries for one host would leave it unclear which one counts."""
    with pytest.raises(proxy.RulesError, match="is listed twice"):
        load(rules_with(entry("example.org"), entry(second, ports=[8443])))


@pytest.mark.parametrize(
    "ports",
    [
        pytest.param(443, id="a-number-not-a-list"),
        pytest.param("443", id="text-not-a-list"),
        pytest.param([], id="empty-list"),
        pytest.param(["443"], id="text-in-the-list"),
        pytest.param([443, "8443"], id="one-text-among-numbers"),
        pytest.param([0], id="zero"),
        pytest.param([-1], id="negative"),
        pytest.param([65536], id="too-large"),
        pytest.param([443.0], id="a-fraction"),
        pytest.param([True], id="true"),
        pytest.param([None], id="null"),
        pytest.param([[443]], id="a-list-in-the-list"),
        pytest.param({"443": True}, id="a-table"),
        pytest.param(None, id="null-not-a-list"),
    ],
)
def test_ports_that_are_not_a_list_of_port_numbers_are_a_mistake(proxy, load, ports):
    with pytest.raises(proxy.RulesError, match="`ports` must be a list of port numbers"):
        load(rules_with(entry(ports=ports)))


@pytest.mark.parametrize("port", [1, 80, 443, 65535])
def test_every_real_port_number_is_accepted(load, port):
    assert load(rules_with(entry(ports=[port])))["example.org"].ports == frozenset({port})


@pytest.mark.parametrize("value", ["true", "yes", 1, 0, None, [True]])
def test_inspect_that_is_not_true_or_false_is_a_mistake(proxy, load, value):
    """`inspect: "false"` is a text, and a text counts as true in Python."""
    with pytest.raises(proxy.RulesError, match="`inspect` must be true or false"):
        load(rules_with(entry(inspect=value)))


@pytest.mark.parametrize(
    "token",
    [
        pytest.param("GitHub", id="upper-case"),
        pytest.param("git hub", id="a-space"),
        pytest.param("", id="empty"),
        pytest.param("-github", id="starts-with-a-sign"),
        pytest.param("a" * 65, id="too-long"),
        pytest.param("op://vault/item/field", id="a-place-not-a-name"),
        pytest.param(7, id="a-number"),
        pytest.param(True, id="true"),
        pytest.param(["github"], id="a-list"),
    ],
)
def test_a_token_that_is_not_a_short_name_is_a_mistake(proxy, load, token):
    with pytest.raises(proxy.RulesError, match="`token` must be the name of a token"):
        load(rules_with(entry(inspect=True, token=token)))


@pytest.mark.parametrize("fields", [{"token": "github"}, {"token": "github", "inspect": False}])
def test_a_token_on_a_destination_that_is_not_opened_is_a_mistake(proxy, load, fields):
    """The broker cannot add a token to traffic it does not read."""
    with pytest.raises(proxy.RulesError, match="has a `token` but not `inspect: true`"):
        load(rules_with(entry(**fields)))


def test_one_mistake_spoils_the_whole_file(proxy, load):
    """The good entries are not used on their own: nothing is loaded."""
    with pytest.raises(proxy.RulesError, match=r"destination 3 \(bad.example.org\)"):
        load(rules_with(entry("one.example.org"), entry("two.example.org"), {"host": "bad.example.org"}))


def test_a_message_names_the_entry_by_number_and_host(proxy, load):
    with pytest.raises(proxy.RulesError) as error:
        load(rules_with(entry("one.example.org"), entry("two.example.org", ports=[])))
    assert str(error.value).startswith("destination 2 (two.example.org)")


# --- The decision: may this host and port be reached? --------------------------


@pytest.fixture
def broker(proxy, load):
    return decider(
        proxy,
        load(
            rules_with(
                entry("example.org"),
                entry("api.example.org", ports=[8443, 9000]),
            )
        ),
    )


def test_a_listed_host_on_its_port_is_allowed(broker):
    assert broker.refusal("example.org", 443) is None
    assert broker.refusal("api.example.org", 8443) is None
    assert broker.refusal("api.example.org", 9000) is None


@pytest.mark.parametrize("host", ["EXAMPLE.ORG", "Example.Org", "eXample.org"])
def test_upper_and_lower_case_are_the_same_host(broker, host):
    assert broker.refusal(host, 443) is None


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        # There are no wildcards: a listed name covers neither the names
        # under it nor the name above it.
        "www.example.org",
        "a.b.example.org",
        "org",
        # Names that only look like the listed one.
        "example.org.evil.example",
        "notexample.org",
        "example.org.",
        "example.org ",
        " example.org",
        "example.org:443",
        "example.org/",
        "example.org\n",
        "example.org\x00",
        "exаmple.org",  # the second "a" is a Cyrillic letter
        "",
        # An address is never a listed host, whatever it points to.
        "127.0.0.1",
        "localhost",
        "::1",
    ],
)
def test_a_host_that_is_not_listed_exactly_is_refused(broker, host):
    assert broker.refusal(host, 443) == "host-not-listed"


@pytest.mark.parametrize("port", [80, 22, 8443, 444, 0, 65535])
def test_a_listed_host_on_another_port_is_refused(broker, port):
    assert broker.refusal("example.org", port) == "port-not-listed"


def test_a_port_list_does_not_include_443(broker):
    assert broker.refusal("api.example.org", 443) == "port-not-listed"


def test_a_port_allowed_on_one_host_is_not_allowed_on_another(broker):
    assert broker.refusal("example.org", 8443) == "port-not-listed"


def test_the_host_is_checked_before_the_port(broker):
    """An unlisted host is reported as such, on any port."""
    assert broker.refusal("example.com", 8443) == "host-not-listed"


# --- The rules file of this repo ----------------------------------------------


@pytest.fixture(scope="module")
def repo_rules(proxy):
    return proxy.load_rules(str(REPO / "broker" / "rules.yaml"))


def test_the_rules_file_of_the_repo_has_no_mistake(repo_rules):
    """Otherwise the broker would not start, and neither would the VM."""
    assert repo_rules


def test_the_connectors_of_the_claude_account_stay_out_of_reach(proxy, repo_rules):
    """mcp-proxy.anthropic.com leads to the user's other services (CLAUDE.md)."""
    assert "mcp-proxy.anthropic.com" not in repo_rules
    assert decider(proxy, repo_rules).refusal("mcp-proxy.anthropic.com", 443) == "host-not-listed"


def test_the_traffic_to_the_model_is_not_opened(repo_rules):
    """The broker has no business reading what is said to the model."""
    for host, rule in repo_rules.items():
        if host.endswith(("anthropic.com", "claude.ai", "claude.com")):
            assert not rule.inspect, host
            assert rule.token is None, host


def test_the_repo_allows_encrypted_ports_only(repo_rules):
    """Port 80 would carry requests in clear text."""
    for host, rule in repo_rules.items():
        assert 80 not in rule.ports, host


# --- What the VM is told, and what goes in the log ----------------------------


def test_every_refusal_text_can_be_filled_in(proxy):
    """A text with a misspelt {name} in it would fail when it is first needed."""
    for reason, text in proxy.REFUSALS.items():
        filled = text.format(host="example.org", port=443, reason=reason)
        assert "{" not in filled and "}" not in filled, reason


@pytest.mark.parametrize(
    ("value", "field"),
    [
        ("example.org", "example.org"),
        (443, "443"),
        ("", "-"),
        ("   ", "-"),
        ("two words", "two_words"),
        (" padded ", "padded"),
        # A host name comes from the VM. It must not be able to end the log
        # line and start a made-up one, or to add fields of its own.
        ("a.example\n2026-01-01T00:00:00 allowed b.example 443", "a.example_2026-01-01T00:00:00_allowed_b.example_443"),
        ("tab\there", "tab_here"),
        ("bell\x07", "bell?"),
        ("esc\x1b[31m", "esc?[31m"),
        ("exämple.org", "ex?mple.org"),
        ("nul\x00byte", "nul?byte"),
    ],
)
def test_a_log_field_is_one_word_of_plain_characters(proxy, value, field):
    assert proxy._clean(value) == field


def test_a_log_field_is_cut_off_at_255_characters(proxy):
    assert proxy._clean("a" * 10_000) == "a" * 255
