"""Fetches the tokens the broker needs, before the broker starts.

    fetch_tokens.py RULES_FILE TOKENS_FILE

rules.yaml in this repo is public, so it names a token only by a short name,
such as `github`. Where that token is kept is each user's own business, and
is written in a file on their Mac, outside the repo (by default
~/.config/nixt3/tokens.yaml). For each name, that file gives a command that
prints the token, for example one that asks a password manager for it. See
tokens.example.yaml.

This program reads both files, runs the command for each token that the rules
ask for, and prints the tokens as JSON on its standard output:

    {"tokens": {"github": "..."}}

The start command connects that output to a pipe which the broker inherits.
So a token goes from the password manager, through this program and the
pipe, into the broker's memory. It is never in a file, an environment
variable or a command line, where other programs on the Mac could read it.

Why this is a program of its own: the broker reads everything the VM sends,
so it is the part most likely to be attacked, and it is to be confined so
that it cannot run other programs. This one runs before it, reads nothing
from the VM, and ends.

It fails closed. If the tokens file, a name in it, or a command is missing or
fails, it prints what to create and ends with an error, and the start command
then does not start the broker. No token, and no output of a token's command,
is ever part of a message.
"""

import json
import os
import stat
import subprocess
import sys

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

import swap

# How long a command may take. Asking a password manager can mean waiting
# for a fingerprint.
COMMAND_SECONDS = 300

# The pipe to the broker holds this much without anyone reading from it.
MAX_OUTPUT = 8 * 1024

EXAMPLE = """\
    tokens:
      {name}:
        command: ["op", "read", "op://Private/agent-sandbox-github/credential"]
"""


class FetchError(Exception):
    """A token cannot be fetched. The message says what to create or fix."""


def needed_tokens(rules_path: str) -> list[str]:
    """The token names that rules.yaml asks for, in the order they appear.

    The broker checks the rules file in full when it starts. This only looks
    for `token` entries, and leaves every other mistake for the broker to
    report.
    """
    try:
        with open(rules_path, encoding="utf-8") as file:
            data = YAML(typ="safe").load(file)
    except OSError as error:
        raise FetchError(f"{rules_path}: cannot read it: {error.strerror}") from None
    except YAMLError as error:
        raise FetchError(f"{rules_path}: it is not valid YAML: {error}") from None

    names: list[str] = []
    destinations = data.get("destinations") if isinstance(data, dict) else None
    for entry in destinations if isinstance(destinations, list) else []:
        name = entry.get("token") if isinstance(entry, dict) else None
        if name is None or name in names:
            continue
        if not isinstance(name, str) or not swap.TOKEN_ID_SHAPE.fullmatch(name):
            raise FetchError(f"{rules_path}: `token` must be a name such as github")
        names.append(name)
    return names


def load_commands(tokens_path: str, names: list[str]) -> dict[str, list[str]]:
    """Read the tokens file and return the command for each name."""
    how = (
        f"Create it with a command that prints each token, like this:\n\n"
        f"{EXAMPLE.format(name=names[0])}\n"
        f"broker/tokens.example.yaml in the nixt3 repo explains the file."
    )
    try:
        with open(tokens_path, encoding="utf-8") as file:
            # The file names programs that will be run as this user. If
            # others could write to it, they could choose those programs. A
            # file owned by root is accepted, because a file that Nix manages
            # is a link into the Nix store.
            mode = os.fstat(file.fileno())
            if mode.st_uid not in (os.getuid(), 0) or mode.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise FetchError(
                    f"{tokens_path} can be changed by other users of this Mac. "
                    f"Make it yours alone: chmod 600 {tokens_path}"
                )
            data = YAML(typ="safe").load(file)
    except FileNotFoundError:
        raise FetchError(
            f"the rules ask for the token `{names[0]}`, and there is no tokens "
            f"file at {tokens_path}.\n{how}"
        ) from None
    except OSError as error:
        raise FetchError(f"{tokens_path}: cannot read it: {error.strerror}") from None
    except YAMLError as error:
        raise FetchError(f"{tokens_path}: it is not valid YAML: {error}") from None

    tokens = data.get("tokens") if isinstance(data, dict) else None
    if not isinstance(tokens, dict):
        raise FetchError(f"{tokens_path} must start with a `tokens:` table.\n{how}")

    commands: dict[str, list[str]] = {}
    for name in names:
        entry = tokens.get(name)
        if entry is None:
            raise FetchError(
                f"the rules ask for the token `{name}`, and {tokens_path} has "
                f"no entry for it. Add one:\n\n{EXAMPLE.format(name=name)}"
            )
        command = entry.get("command") if isinstance(entry, dict) else None
        if (
            not isinstance(entry, dict)
            or set(entry) != {"command"}
            or not isinstance(command, list)
            or not command
            or not all(isinstance(word, str) and word for word in command)
        ):
            raise FetchError(
                f"{tokens_path}: the entry for `{name}` must have one key, "
                f"`command`, with the program and its arguments as a list:\n\n"
                f"{EXAMPLE.format(name=name)}"
            )
        commands[name] = command
    return commands


def run_command(name: str, command: list[str]) -> str:
    """Run one token's command and return what it printed, as the token.

    The command is run as it is written, without a shell. Its error output
    goes to the terminal or the broker's log, so that a message such as "not
    signed in" can be read. What it prints on standard output is the token
    and is shown nowhere.
    """
    program = command[0]
    try:
        done = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            timeout=COMMAND_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        raise FetchError(
            f"the command for the token `{name}` cannot be run: there is no "
            f"program `{program}`. Install it, or write its full path in the "
            f"tokens file"
        ) from None
    except OSError as error:
        raise FetchError(
            f"the command for the token `{name}` cannot be run: `{program}`: "
            f"{error.strerror}"
        ) from None
    except subprocess.TimeoutExpired:
        raise FetchError(
            f"the command for the token `{name}` (`{program}`) did not finish "
            f"in {COMMAND_SECONDS} seconds"
        ) from None

    if done.returncode != 0:
        raise FetchError(
            f"the command for the token `{name}` (`{program}`) failed with "
            f"status {done.returncode}. What it reported is above"
        )
    try:
        token = done.stdout.decode("ascii").strip()
    except UnicodeDecodeError:
        token = ""
    if not swap.TOKEN_SHAPE.fullmatch(token):
        raise FetchError(
            f"the command for the token `{name}` (`{program}`) printed nothing, "
            f"or something that is not one token: a token is one word of "
            f"letters, digits and signs"
        )
    if token == swap.PLACEHOLDER:
        raise FetchError(
            f"the command for the token `{name}` printed the placeholder that "
            f"the VM uses, not a real token"
        )
    return token


def main(arguments: list[str]) -> int:
    if len(arguments) != 2:
        print("usage: fetch_tokens.py RULES_FILE TOKENS_FILE", file=sys.stderr)
        return 2
    rules_path, tokens_path = arguments

    if sys.stdout.isatty():
        print(
            "broker: fetch_tokens.py prints tokens, so it does not write to a "
            "terminal. It is run by `nix run .#broker`.",
            file=sys.stderr,
        )
        return 2

    try:
        names = needed_tokens(rules_path)
        tokens: dict[str, str] = {}
        if names:
            commands = load_commands(tokens_path, names)
            for name in names:
                tokens[name] = run_command(name, commands[name])
        output = json.dumps({"tokens": tokens})
        if len(output) > MAX_OUTPUT:
            raise FetchError("the tokens are too long to hand to the broker")
    except FetchError as error:
        print("broker: not starting, because a token cannot be fetched.", file=sys.stderr)
        for line in str(error).splitlines():
            print(f"broker: {line}".rstrip(), file=sys.stderr)
        return 1

    sys.stdout.write(output)
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
