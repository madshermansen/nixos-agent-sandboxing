"""Tests for broker/settings.py: which settings of mitmproxy the broker
agrees to run with. They need no mitmproxy."""

import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "broker"))

import settings  # noqa: E402

# A few of mitmproxy's settings with the values it gives them by itself.
DEFAULTS = {
    "listen_host": "",
    "listen_port": None,
    "confdir": "~/.mitmproxy",
    "connection_strategy": "eager",
    "flow_detail": 1,
    "onboarding": True,
    "rawtcp": True,
    "http2": True,
    "termlog_verbosity": "info",
    "stream_large_bodies": None,
    "scripts": [],
    "ssl_verify_upstream_trusted_ca": None,
    "ssl_insecure": False,
    "map_remote": [],
    "map_local": [],
    "modify_headers": [],
    "modify_body": [],
    "mode": ["regular"],
    "stickyauth": None,
    "save_stream_file": None,
    "upstream_auth": None,
    "ignore_hosts": [],
}

# What the start command in darwin/commands.nix sets.
AS_STARTED = {
    **DEFAULTS,
    "listen_host": "127.0.0.1",
    "listen_port": 8474,
    "confdir": "/somewhere/broker",
    "connection_strategy": "lazy",
    "flow_detail": 0,
    "onboarding": False,
    "rawtcp": False,
    "http2": False,
    "termlog_verbosity": "error",
    "stream_large_bodies": "1m",
    "scripts": ["/nix/store/x-broker/proxy.py"],
}


def test_the_settings_of_the_start_command_are_accepted():
    assert settings.unreviewed(AS_STARTED, DEFAULTS) == []


def test_what_the_start_command_sets_is_what_this_file_requires():
    """Every `--set` in darwin/commands.nix is known here, with its value."""
    text = (REPO / "darwin/commands.nix").read_text()
    for name, value in settings.REQUIRED.items():
        shown = {True: "true", False: "false"}.get(value, value) if isinstance(value, bool) else value
        assert f"--set {name}={shown}" in text or f"--{name.replace('_', '-')} {shown}" in text, name
    import re

    for name in re.findall(r"--set ([a-z_0-9]+)=", text):
        assert name in settings.REQUIRED or name in settings.FREE, name


@pytest.mark.parametrize(
    "name, value",
    [
        ("map_remote", ["|a/b/info/refs|c/d/info/refs"]),
        ("map_local", ["|x|/tmp/y"]),
        ("modify_headers", ["/~q/Authorization/token x"]),
        ("modify_body", ["/~q/a/b"]),
        ("mode", ["upstream:http://127.0.0.1:9999"]),
        ("mode", ["regular", "socks5"]),
        ("stickyauth", ".*"),
        ("save_stream_file", "/tmp/flows"),
        ("upstream_auth", "user:pass"),
        ("ignore_hosts", ["github.com"]),
        ("ssl_insecure", True),
    ],
)
def test_a_setting_that_rewrites_redirects_or_records_is_refused(name, value):
    wrong = settings.unreviewed({**AS_STARTED, name: value}, DEFAULTS)
    assert len(wrong) == 1 and f"`{name}`" in wrong[0]


def test_the_value_of_a_refused_setting_is_not_repeated():
    """For some settings the value is a password."""
    wrong = settings.unreviewed({**AS_STARTED, "upstream_auth": "user:a-password"}, DEFAULTS)
    assert "a-password" not in " ".join(wrong)


@pytest.mark.parametrize(
    "name, value",
    [
        ("listen_host", "0.0.0.0"),
        ("listen_host", ""),
        ("listen_host", "::"),
        ("connection_strategy", "eager"),
        ("flow_detail", 1),
        ("flow_detail", 3),
        ("flow_detail", False),
        ("onboarding", True),
        ("rawtcp", True),
        ("http2", True),
        ("http2", 0),
        # mitmproxy passes a body on unread when it is larger than this, so
        # a smaller value would send a request before the broker judged it.
        ("stream_large_bodies", "1k"),
        ("stream_large_bodies", "1"),
        ("stream_large_bodies", None),
        ("stream_large_bodies", "2m"),
        # At "info" mitmproxy logs the bytes of a request that was cut off.
        ("termlog_verbosity", "info"),
        ("termlog_verbosity", "debug"),
    ],
)
def test_a_setting_of_the_start_command_must_have_its_one_value(name, value):
    wrong = settings.unreviewed({**AS_STARTED, name: value}, DEFAULTS)
    assert len(wrong) == 1 and f"`{name}`" in wrong[0]


def test_a_setting_this_file_has_never_heard_of_must_be_untouched():
    """As a later mitmproxy might add: covered without anyone noticing it."""
    defaults = {**DEFAULTS, "rewrite_everything": False}
    assert settings.unreviewed({**AS_STARTED, "rewrite_everything": False}, defaults) == []
    wrong = settings.unreviewed({**AS_STARTED, "rewrite_everything": True}, defaults)
    assert len(wrong) == 1 and "`rewrite_everything`" in wrong[0]
    # Not even known to mitmproxy's own list of defaults.
    assert settings.unreviewed({**AS_STARTED, "from_nowhere": 1}, DEFAULTS) != []


def test_a_mitmproxy_without_a_required_setting_is_refused():
    values = {name: value for name, value in AS_STARTED.items() if name != "rawtcp"}
    wrong = settings.unreviewed(values, DEFAULTS)
    assert len(wrong) == 1 and "`rawtcp`" in wrong[0]


def test_the_free_settings_may_have_any_value():
    for name in settings.FREE:
        assert settings.unreviewed({**AS_STARTED, name: "anything at all"}, DEFAULTS) == []


def test_no_setting_is_both_required_and_free():
    assert not set(settings.REQUIRED) & settings.FREE


# --- The environment ----------------------------------------------------------

# What mitmproxy has in its environment when the start command starts it.
STARTED_WITH = [
    "PYTHONUNBUFFERED", "AGENT_BROKER_RULES", "AGENT_BROKER_TOKENS_FD",
    "PATH", "PYTHONNOUSERSITE", "PWD", "SHLVL", "_", "__CF_USER_TEXT_ENCODING", "LC_CTYPE",
]  # fmt: skip


def test_the_environment_of_the_start_command_is_accepted():
    assert settings.unreviewed_environment(STARTED_WITH) == []
    assert settings.unreviewed_environment([]) == []


def test_the_start_command_passes_no_more_than_the_broker_allows():
    """Every variable given to mitmdump in darwin/commands.nix is known here."""
    import re

    text = (REPO / "darwin/commands.nix").read_text()
    start = text.index("exec /usr/bin/env -i")
    passed = re.findall(r"^\s+([A-Z_]+)=", text[start : text.index("mitmdump", start)], re.M)
    assert passed == ["PYTHONUNBUFFERED", "AGENT_BROKER_RULES", "AGENT_BROKER_TOKENS_FD"]
    assert set(passed) <= settings.ENVIRONMENT


@pytest.mark.parametrize(
    "name",
    [
        # Make mitmproxy write the keys of every encrypted connection to a file.
        "SSLKEYLOGFILE",
        "MITMPROXY_SSLKEYLOGFILE",
        # Load code or settings from somewhere else.
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONWARNINGS",
        "PYTHONUSERBASE",
        "OPENSSL_CONF",
        "OPENSSL_MODULES",
        "DYLD_INSERT_LIBRARIES",
        "BASH_ENV",
        # Change which servers are believed, or where connections go.
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "NIX_SSL_CERT_FILE",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "NO_PROXY",
        # Anything else, known or not.
        "HOME",
        "MITMPROXY_DEBUG_EXIT",
        "SOMETHING_NOBODY_HEARD_OF",
        "pythonunbuffered",
    ],
)
def test_any_other_variable_is_refused(name):
    wrong = settings.unreviewed_environment([*STARTED_WITH, name])
    assert len(wrong) == 1 and f"`{name}`" in wrong[0]


def test_the_value_of_a_variable_is_never_looked_at_or_shown():
    wrong = settings.unreviewed_environment({"SSLKEYLOGFILE": "/a/secret/path", "PATH": "/x"})
    assert len(wrong) == 1 and "/a/secret/path" not in wrong[0]


def test_a_settings_file_in_the_folder_is_found(tmp_path):
    assert settings.config_files(str(tmp_path)) == []
    (tmp_path / "config.yaml").write_text("map_remote: []\n")
    assert settings.config_files(str(tmp_path)) == [str(tmp_path / "config.yaml")]
    (tmp_path / "config.yml").write_text("")
    assert len(settings.config_files(str(tmp_path))) == 2


def test_a_dangling_link_counts_as_a_settings_file(tmp_path):
    """Something could make it point somewhere before mitmproxy reads it."""
    (tmp_path / "config.yaml").symlink_to(tmp_path / "not-there")
    assert settings.config_files(str(tmp_path)) == [str(tmp_path / "config.yaml")]
