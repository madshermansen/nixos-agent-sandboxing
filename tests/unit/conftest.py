"""Shared setup for the tests in this folder. pytest reads this file by itself.

It does two things.

1. It offers `proxy`: the code of broker/proxy.py with the broker not
   started. See the fixture below for why that takes a trick.

2. It can turn a skipped test into a failure. Some tests skip themselves
   when a library they need is missing, which is friendly on a laptop and
   wrong in the repo's own check: there, a missing library should stop the
   check, not quietly shrink it. `nix flake check` sets NIXT3_NO_SKIPS=1.
"""

import ast
import os
import pathlib
import sys
import types

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
BROKER = REPO / "broker"

NO_SKIPS = "NIXT3_NO_SKIPS"


def _starts_the_broker(node: ast.stmt) -> bool:
    """Whether this is the line `addons = [start()]` at the end of proxy.py."""
    return isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Name) and target.id == "addons" for target in node.targets
    )


@pytest.fixture(scope="session")
def proxy():
    """broker/proxy.py as a module, with everything in it but a started broker.

    proxy.py cannot be imported the ordinary way. mitmproxy loads it as a
    script, so its last line starts the broker: it changes mitmproxy's own
    code (limits.py), reads the rules file named in the environment, takes
    the tokens from an open pipe, and ends the whole process when any of
    that fails. None of it belongs in a test run.

    So the file is read as text, that one line is left out, and the rest is
    run. What comes back has the rules loader, the Broker class and the
    helpers, exactly as they are written in the file. Errors still point at
    the right lines of proxy.py.

    If the rules loader is moved to a module of its own one day, as swap.py
    was, this trick can go and the tests can import that module.
    """
    pytest.importorskip("mitmproxy", reason="proxy.py is a mitmproxy script")

    path = BROKER / "proxy.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    kept = [node for node in tree.body if not _starts_the_broker(node)]
    # If proxy.py starts the broker in some other way one day, fail here
    # with a clear message instead of starting a broker inside the tests.
    assert len(tree.body) - len(kept) == 1, (
        "expected exactly one line `addons = [...]` at the top level of proxy.py"
    )
    tree.body = kept

    # proxy.py imports swap.py and limits.py, which lie beside it.
    if str(BROKER) not in sys.path:
        sys.path.insert(0, str(BROKER))

    module = types.ModuleType("proxy_without_start")
    module.__file__ = str(path)
    # Python looks a class's module up by name when it builds a dataclass.
    sys.modules[module.__name__] = module
    exec(compile(tree, str(path), "exec"), module.__dict__)
    return module


def pytest_sessionfinish(session, exitstatus):
    """With NIXT3_NO_SKIPS set, a run that skipped anything fails."""
    if not os.environ.get(NO_SKIPS) or exitstatus != 0:
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    skipped = reporter.stats.get("skipped", []) if reporter else []
    if not skipped:
        return
    reporter.write_line("")
    reporter.write_line(
        f"{len(skipped)} test(s) or file(s) were skipped, and {NO_SKIPS} is set, "
        "so this run fails. Run pytest with -rs to see which and why.",
        red=True,
    )
    session.exitstatus = pytest.ExitCode.TESTS_FAILED
