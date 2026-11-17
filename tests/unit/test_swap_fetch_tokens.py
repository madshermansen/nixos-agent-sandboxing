"""Tests for broker/fetch_tokens.py: fetching tokens before the broker starts.

The commands used here are small programs every Mac and Linux system has.
No password manager is asked for anything.
"""

import json
import os
import pathlib
import subprocess
import sys

import pytest

pytest.importorskip("ruamel.yaml")

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "broker"))

import fetch_tokens  # noqa: E402
import swap  # noqa: E402

RULES = """\
destinations:
  - host: api.anthropic.com
    note: Passed on untouched.
  - host: github.com
    note: Opened.
    inspect: true
    token: github
  - host: api.github.com
    note: Opened, same token.
    inspect: true
    token: github
"""


def write(path: pathlib.Path, text: str, mode: int = 0o600) -> str:
    path.write_text(text)
    path.chmod(mode)
    return str(path)


def tokens_file(tmp_path, command: list[str], name: str = "github") -> str:
    return write(tmp_path / "tokens.yaml", json.dumps({"tokens": {name: {"command": command}}}))


def run(tmp_path, rules: str, tokens_path: str):
    """Run the program as the start command does. Returns (status, stdout, stderr)."""
    done = subprocess.run(
        [sys.executable, str(REPO / "broker/fetch_tokens.py"), write(tmp_path / "rules.yaml", rules), tokens_path],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    return done.returncode, done.stdout, done.stderr


def test_each_token_is_asked_for_once(tmp_path):
    assert fetch_tokens.needed_tokens(write(tmp_path / "rules.yaml", RULES)) == ["github"]


def test_the_token_is_printed_as_json(tmp_path):
    status, out, err = run(tmp_path, RULES, tokens_file(tmp_path, ["printf", "made-up\n"]))
    assert (status, err) == (0, "")
    assert json.loads(out) == {"tokens": {"github": "made-up"}}
    assert swap.parse_handover(out, {"github"})["github"].reveal() == "made-up"


def test_rules_without_a_token_need_no_tokens_file(tmp_path):
    rules = "destinations:\n  - host: example.org\n    note: Nothing to add.\n"
    status, out, _ = run(tmp_path, rules, str(tmp_path / "missing.yaml"))
    assert status == 0
    assert json.loads(out) == {"tokens": {}}


def test_a_missing_tokens_file_says_what_to_create(tmp_path):
    path = str(tmp_path / "missing.yaml")
    status, out, err = run(tmp_path, RULES, path)
    assert status == 1 and out == ""
    assert path in err and "command:" in err and "`github`" in err


def test_a_missing_entry_says_what_to_add(tmp_path):
    status, out, err = run(tmp_path, RULES, tokens_file(tmp_path, ["true"], name="other"))
    assert status == 1 and out == ""
    assert "no entry" in err and "github:" in err


@pytest.mark.parametrize(
    "entry",
    [
        "op read something",
        {"command": "op read something"},
        {"command": []},
        {"command": ["op", 3]},
        {"command": ["true"], "shell": True},
        {},
    ],
)
def test_a_malformed_entry_is_an_error(tmp_path, entry):
    path = write(tmp_path / "tokens.yaml", json.dumps({"tokens": {"github": entry}}))
    status, out, err = run(tmp_path, RULES, path)
    assert status == 1 and out == ""
    assert "command" in err


def test_a_failing_command_is_an_error(tmp_path):
    status, out, err = run(tmp_path, RULES, tokens_file(tmp_path, ["sh", "-c", "echo half-a-token; exit 3"]))
    assert status == 1 and out == ""
    assert "status 3" in err
    assert "half-a-token" not in err


def test_a_program_that_does_not_exist_is_an_error(tmp_path):
    status, out, err = run(tmp_path, RULES, tokens_file(tmp_path, ["no-such-program-anywhere"]))
    assert status == 1 and out == ""
    assert "no-such-program-anywhere" in err


@pytest.mark.parametrize("printed", ["", "\n", "two words", "line\nbreak", "café", swap.PLACEHOLDER])
def test_output_that_is_not_one_token_is_an_error_and_is_not_shown(tmp_path, printed):
    status, out, err = run(tmp_path, RULES, tokens_file(tmp_path, ["printf", "%s", printed]))
    assert status == 1 and out == ""
    if printed.strip() and printed != swap.PLACEHOLDER:
        assert printed not in err and printed.split()[0] not in err


def test_a_tokens_file_others_can_write_is_refused(tmp_path):
    path = tokens_file(tmp_path, ["printf", "made-up"])
    os.chmod(path, 0o666)
    status, out, err = run(tmp_path, RULES, path)
    assert status == 1 and out == ""
    assert "chmod 600" in err


def test_the_command_is_not_run_by_a_shell(tmp_path):
    marker = tmp_path / "marker"
    status, out, _ = run(tmp_path, RULES, tokens_file(tmp_path, ["printf", "%s", f"x;touch${{IFS}}{marker}"]))
    assert not marker.exists()
    assert status == 0 and json.loads(out)["tokens"]["github"].startswith("x;touch")
