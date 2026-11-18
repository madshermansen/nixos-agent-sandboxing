"""Whether a process is held in the broker's sandbox.

The start command starts the broker through macOS's `sandbox-exec`, with
the profile broker/sandbox.sb. That alone says the sandbox was asked for.
This file asks macOS what a process may in fact do, and reports whatever
the broker's sandbox should have taken away.

It is used in two places:

- The broker asks about itself when it starts (proxy.py), before it takes
  the tokens, and does not run if anything is reported. A broker started by
  hand without the sandbox, or by a `sandbox-exec` that some later macOS has
  made do nothing, therefore does not run.
- `nix run .#status` asks about the running broker from the outside, so it
  can say that the broker is confined, not only that it was meant to be.

The question is put to `sandbox_check`, a function of macOS that says
whether a process's sandbox allows one operation. It does not carry the
operation out: nothing is read, written or started by asking.

What it cannot be asked is where a process may connect to; it takes no
address. The network rules are shown by tests/broker-sandbox.sh, which
tries real connections under the same profile.

This file knows nothing of mitmproxy, so that it can be tested by itself
and run by any Python (tests/unit/test_confinement.py). Run by hand:

    python3 broker/confinement.py <process id> <the broker's folder> [a folder that must be out of reach...]

It prints one line per problem and ends with status 1 if there is one.
"""

import ctypes
import os
import sys

# Flags of sandbox_check, from macOS's <sandbox/private.h>: the argument
# after the operation is a path; and write no line to the system's log when
# the answer is "refused".
_FILTER_PATH = 1
_NO_REPORT = 0x40000000

# A program that is on every Mac and that the broker has no business
# starting.
SHELL = "/bin/sh"


class Unknown(Exception):
    """macOS could not be asked. The message says why."""


def _sandbox_check():
    """macOS's `sandbox_check`, or Unknown where there is none."""
    try:
        function = ctypes.CDLL(None).sandbox_check
    except (OSError, AttributeError):
        raise Unknown("this system has no macOS sandbox to ask") from None
    # Its last argument comes only with some flags. Naming the fixed ones
    # here is what makes Python pass such an argument the way macOS on
    # Apple's chips expects it.
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    function.restype = ctypes.c_int
    return function


def refused(pid: int, operation: str | None, path: str | None = None) -> bool:
    """Whether the sandbox of process `pid` refuses `operation`.

    With `operation` None, the question is whether the process is in a
    sandbox at all. `path` is what the operation is done to; it must exist,
    because macOS answers "refused" for a path that does not. It also
    answers "refused" to everything when there is no such process. So a
    caller should ask about something that must be allowed as well, as
    problems() does.
    """
    check = _sandbox_check()
    name = operation.encode() if operation else None
    if path is None:
        answer = check(pid, name, _NO_REPORT)
    else:
        answer = check(pid, name, _FILTER_PATH | _NO_REPORT, ctypes.c_char_p(os.fsencode(path)))
    if answer not in (0, 1):
        raise Unknown(f"macOS does not know the operation `{operation}`")
    return answer == 1


def problems(pid: int, broker_dir: str, out_of_reach: tuple[str, ...] = ()) -> list[str]:
    """What process `pid` may do that the broker's sandbox should prevent.

    `broker_dir` is the broker's own folder, `broker` in the state folder.
    The state folder around it holds the VM's disk and the SSH key that
    opens the VM, and must be out of reach; so must every folder in
    `out_of_reach`, such as the home folder. Returns one line per problem.
    An empty list means the process is held as it should be.
    """
    # The sandbox goes by full paths without symbolic links.
    broker_dir = os.path.realpath(broker_dir)
    state = os.path.dirname(broker_dir)
    try:
        # What must be allowed comes first. If it is not, either the process
        # is gone or it is in some other sandbox, and the answers below
        # would say "refused" without meaning anything.
        if refused(pid, "file-read-data", broker_dir) or refused(pid, "file-write-data", broker_dir):
            return [
                f"process {pid} may not use the broker's folder {broker_dir}, or there is no "
                "such process, so macOS cannot be asked what else it may do"
            ]
        if not refused(pid, None):
            return [f"process {pid} is in no sandbox at all: it has all of the user's rights"]
        found = []
        if not refused(pid, "process-fork"):
            found.append("it may start further processes")
        if not refused(pid, "process-exec*", SHELL):
            found.append(f"it may run {SHELL}")
        if not refused(pid, "mach-lookup"):
            found.append("it may talk to the system's services")
        for folder in (state, *out_of_reach):
            folder = os.path.realpath(folder)
            if not os.path.isdir(folder):
                continue
            if not refused(pid, "file-read-data", folder):
                found.append(f"it may read {folder}")
            if not refused(pid, "file-write-data", folder):
                found.append(f"it may write to {folder}")
        return found
    except Unknown as error:
        return [str(error)]


def main(arguments: list[str]) -> int:
    if len(arguments) < 2 or not arguments[0].isdigit():
        print(
            "usage: confinement.py <process id> <the broker's folder> [a folder that must be out of reach...]",
            file=sys.stderr,
        )
        return 2
    found = problems(int(arguments[0]), arguments[1], tuple(arguments[2:]))
    for line in found:
        print(line)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
