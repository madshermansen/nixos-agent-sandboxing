"""Tests for broker/confinement.py, which asks macOS whether a process is
held in the broker's sandbox, and for the three places that must agree
about the sandbox: the profile, the start command and the broker.

Most of them put a made-up macOS in place of the real one, so they run
anywhere. What the real sandbox allows is shown by tests/broker-sandbox.sh,
which needs a Mac.
"""

import os
import pathlib
import re
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "broker"))

import confinement  # noqa: E402

PID = 4242


def made_up_macos(monkeypatch, allowed=(), sandboxed=True, alive=True):
    """Put answers in place of macOS's.

    `allowed` holds what the made-up sandbox allows beyond the broker's own
    folder: operations such as "process-fork", or pairs of an operation and
    a path. Returns the list of questions that were asked.
    """
    asked = []

    def refused(pid, operation, path=None):
        asked.append((pid, operation, path))
        if not alive:
            return True  # macOS answers "refused" to all for a process that is gone.
        if operation is None:
            return sandboxed
        if not sandboxed:
            return False
        if path is not None and os.path.basename(path) == "broker":
            return False
        return operation not in allowed and (operation, path) not in allowed

    monkeypatch.setattr(confinement, "refused", refused)
    return asked


@pytest.fixture
def broker_dir(tmp_path):
    folder = tmp_path / "state" / "broker"
    folder.mkdir(parents=True)
    # The sandbox goes by paths without symbolic links, and so do the tests.
    return os.path.realpath(folder)


def test_a_process_held_as_the_broker_should_be_has_no_problems(monkeypatch, broker_dir):
    asked = made_up_macos(monkeypatch)
    assert confinement.problems(PID, broker_dir) == []
    assert all(pid == PID for pid, _, _ in asked)


def test_it_asks_about_everything_the_sandbox_should_take_away(monkeypatch, broker_dir, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    asked = made_up_macos(monkeypatch)
    confinement.problems(PID, broker_dir, (str(home),))
    questions = {(operation, path) for _, operation, path in asked}
    state = os.path.dirname(broker_dir)
    assert questions >= {
        (None, None),
        ("process-fork", None),
        ("process-exec*", "/bin/sh"),
        ("mach-lookup", None),
        ("file-read-data", state),
        ("file-write-data", state),
        ("file-read-data", os.path.realpath(home)),
        ("file-write-data", os.path.realpath(home)),
    }


def test_a_process_in_no_sandbox_is_reported(monkeypatch, broker_dir):
    made_up_macos(monkeypatch, sandboxed=False)
    found = confinement.problems(PID, broker_dir)
    assert len(found) == 1 and "in no sandbox at all" in found[0]


def test_a_process_that_is_gone_is_not_taken_for_a_confined_one(monkeypatch, broker_dir):
    """macOS answers "refused" to everything then, which would look perfect."""
    made_up_macos(monkeypatch, alive=False)
    found = confinement.problems(PID, broker_dir)
    assert len(found) == 1 and "no such process" in found[0]


@pytest.mark.parametrize(
    "allowed, words",
    [
        ("process-fork", "start further processes"),
        (("process-exec*", "/bin/sh"), "run /bin/sh"),
        ("mach-lookup", "the system's services"),
    ],
)
def test_each_thing_a_wider_sandbox_allows_is_reported(monkeypatch, broker_dir, allowed, words):
    made_up_macos(monkeypatch, allowed=[allowed])
    found = confinement.problems(PID, broker_dir)
    assert len(found) == 1 and words in found[0]


@pytest.mark.parametrize("operation, words", [("file-read-data", "may read"), ("file-write-data", "may write to")])
def test_a_sandbox_that_reaches_the_state_folder_is_reported(monkeypatch, broker_dir, operation, words):
    state = os.path.dirname(broker_dir)
    made_up_macos(monkeypatch, allowed=[(operation, state)])
    assert confinement.problems(PID, broker_dir) == [f"it {words} {state}"]


def test_a_sandbox_that_reaches_a_folder_named_out_of_reach_is_reported(monkeypatch, broker_dir, tmp_path):
    home = os.path.realpath(tmp_path / "home")
    os.mkdir(home)
    made_up_macos(monkeypatch, allowed=[("file-read-data", home)])
    assert confinement.problems(PID, broker_dir, (home,)) == [f"it may read {home}"]


def test_a_folder_that_is_not_there_is_not_asked_about(monkeypatch, broker_dir, tmp_path):
    """macOS answers "refused" for a path that does not exist, whatever the sandbox."""
    asked = made_up_macos(monkeypatch)
    missing = str(tmp_path / "not-there")
    assert confinement.problems(PID, broker_dir, (missing,)) == []
    assert not any(path == missing for _, _, path in asked)


def test_a_link_to_the_broker_folder_is_followed(monkeypatch, broker_dir, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(broker_dir)
    asked = made_up_macos(monkeypatch)
    assert confinement.problems(PID, str(link)) == []
    assert ("file-read-data", broker_dir) in {(operation, path) for _, operation, path in asked}


def test_where_macos_cannot_be_asked_that_is_a_problem(monkeypatch, broker_dir):
    """On a system without the sandbox, or with one that changed, the answer is not "fine"."""

    def no_sandbox():
        raise confinement.Unknown("this system has no macOS sandbox to ask")

    monkeypatch.setattr(confinement, "_sandbox_check", no_sandbox)
    assert confinement.problems(PID, broker_dir) == ["this system has no macOS sandbox to ask"]


def test_an_answer_that_is_neither_yes_nor_no_is_a_problem(monkeypatch, broker_dir):
    monkeypatch.setattr(confinement, "_sandbox_check", lambda: lambda *arguments: -1)
    found = confinement.problems(PID, broker_dir)
    assert len(found) == 1 and "does not know the operation" in found[0]


def test_this_test_process_is_not_taken_for_a_confined_broker(broker_dir):
    """With the real macOS, or with none: the process that runs the tests is
    not in the broker's sandbox, so something must be reported."""
    assert confinement.problems(os.getpid(), broker_dir) != []


def test_the_command_prints_the_problems_and_ends_with_1(monkeypatch, broker_dir, capsys):
    made_up_macos(monkeypatch, allowed=["process-fork"])
    assert confinement.main([str(PID), broker_dir]) == 1
    assert capsys.readouterr().out == "it may start further processes\n"


def test_the_command_prints_nothing_and_ends_with_0_when_all_is_well(monkeypatch, broker_dir, capsys):
    made_up_macos(monkeypatch)
    assert confinement.main([str(PID), broker_dir, "/"]) == 0
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("arguments", [[], ["12"], ["not-a-number", "/somewhere"], ["-1", "/somewhere"]])
def test_the_command_refuses_arguments_it_does_not_understand(arguments, capsys):
    assert confinement.main(arguments) == 2
    assert "usage" in capsys.readouterr().err


# --- The profile, the start command and the broker agree ---------------------

PROFILE = (REPO / "broker/sandbox.sb").read_text()
COMMANDS = (REPO / "darwin/commands.nix").read_text()
# The profile without its comments, which start with `;`.
RULES = "\n".join(line for line in PROFILE.splitlines() if not line.lstrip().startswith(";"))


def test_the_start_command_gives_the_profile_the_values_it_asks_for():
    """A value the profile asks for and does not get stops the broker from
    starting; one it gets and does not use is a mistake waiting to be made."""
    asked_for = set(re.findall(r'\(param "([A-Z_]+)"\)', RULES))
    start = COMMANDS.index("/usr/bin/sandbox-exec \\")
    given = re.findall(r"^\s+-D ([A-Z_]+)=", COMMANDS[start : COMMANDS.index("/bin/mitmdump", start)], re.M)
    assert asked_for == {"BROKER_DIR", "PORT", "RULES"}
    assert sorted(given) == sorted(asked_for)


def test_mitmdump_is_started_through_the_sandbox_and_nothing_stands_between():
    start = COMMANDS.index("exec /usr/bin/env -i")
    lines = [line.strip().rstrip("\\").strip() for line in COMMANDS[start:].splitlines()]
    sandbox = lines.index("/usr/bin/sandbox-exec")
    mitmdump = lines.index("${mitmproxy}/bin/mitmdump")
    assert lines[sandbox + 1] == "-f ${brokerSandbox}"
    assert all(line.startswith("-D ") for line in lines[sandbox + 2 : mitmdump])
    # mitmdump is started in this one place only.
    assert COMMANDS.count("${mitmproxy}/bin/mitmdump \\") == 1


def test_the_profile_refuses_everything_first():
    rules = [line for line in RULES.splitlines() if line.strip()]
    assert rules[0] == "(version 1)"
    assert rules[1] == "(deny default)"
    assert "(allow default" not in RULES


def test_the_profile_allows_no_operation_everywhere_but_one():
    """`(allow file-read*)` on a line of its own would allow reading every file."""
    unlimited = re.findall(r"^\(allow [a-z*\- ]+\)$", RULES, re.M)
    assert unlimited == ["(allow sysctl-read)"]


@pytest.mark.parametrize(
    "operation",
    ["process-fork", "process-exec", "mach-lookup", "signal", "iokit-open", "system-socket", "ipc-posix-shm", "job-creation"],
)
def test_the_profile_has_no_rule_for(operation):
    """Starting a program is allowed where the commands are built, for
    mitmdump's own files, and nowhere in the file a person edits."""
    assert operation not in RULES


def test_the_profile_allows_writing_in_two_places_only():
    writes = re.findall(r"^\(allow [^\n]*file-write[^\n]*(?:\n  [^\n]*)*", RULES, re.M)
    assert writes == [
        '(allow file-write-data (literal "/dev/null"))',
        '(allow file-read* file-write* (subpath (param "BROKER_DIR")))',
    ]


def test_the_profile_allows_one_port_out_and_none_on_this_mac():
    out = re.findall(r"^\((allow|deny) network-outbound ([^\n]*)\)$", RULES, re.M)
    assert out == [
        ("allow", '(remote ip "*:443")'),
        ("deny", '(remote ip "localhost:*")'),
        ("allow", '(literal "/private/var/run/mDNSResponder")'),
    ]
    # The refusal of this Mac's own ports comes after the rule it narrows:
    # in a profile the later rule wins.
    assert RULES.index('(remote ip "*:443")') < RULES.index('(deny network-outbound (remote ip "localhost:*"))')


def test_the_profile_names_no_folder_of_the_user():
    for word in ("/Users", "HOME", "/Library", "/Applications", "/Volumes/", "/private/tmp", "/private/var/folders"):
        assert word not in RULES.replace("/System/Library", "").replace("/System/Volumes/Preboot", ""), word


def test_the_broker_checks_its_confinement_before_it_takes_the_tokens():
    proxy = (REPO / "broker/proxy.py").read_text()
    start = proxy.index("def start() -> Broker:")
    check = proxy.index("confinement.problems(os.getpid()", start)
    assert check < proxy.index("load_rules(path)", start) < proxy.index("receive_tokens(", start)
