# Testing

How nixt3 is tested, in layers. The first two run on the Mac alone, in
seconds to a minute, and need neither the VM nor a token. The third runs
inside the VM and is the only one that can prove the sandbox itself.

| Layer | Command | Needs | Takes |
| --- | --- | --- | --- |
| 1. Checks without the VM | `nix flake check` | Nix | Seconds once built |
| 2. A real broker against a stand-in server | `nix run .#test-broker` | Nix, a Mac | About a minute |
| 3. Inside the VM | `nix run .#check` | The VM running | A few minutes |
| 3. Inside the VM, with a real token | `tests/github-live.sh` | The VM and your GitHub token | A minute |

Run layers 1 and 2 before every push. Run layer 3 before a change to the VM,
the broker or the rules is merged; [CLAUDE.md](../CLAUDE.md) asks for its
result in the pull request.

## Layer 1: `nix flake check`

```sh
nix flake check        # add -L to see the output of each check
```

It needs no VM and no Linux builder: nothing in it builds a part of the VM.
It runs these checks, which are defined in
[`tests/default.nix`](../tests/default.nix):

| Check | What it proves |
| --- | --- |
| `format` | `nix fmt` would change no file. |
| `shell` | The scripts in `tests/` pass [shellcheck](https://www.shellcheck.net), which finds common mistakes in shell scripts. The few notes that are turned off are listed, with the reason, in [`tests/.shellcheckrc`](../tests/.shellcheckrc). |
| `python` | The Python files in `broker/` and `tests/unit/` compile with the Python the broker runs on, and pass [ruff](https://docs.astral.sh/ruff/)'s checks for real mistakes, such as a name that is never defined. Style is left alone; see [`tests/ruff.toml`](../tests/ruff.toml). |
| `unit` | Every pytest file in `tests/unit/` passes. See below. |
| `commands` | Every Mac-side command in `darwin/commands.nix` builds, and so does the broker test. Nix runs shellcheck over each of them as it builds it. The `vm` command is built with a stand-in for the VM, so that the VM is not built. |
| `vm-evaluates` | The VM's configuration still makes sense to Nix: every option in it can be worked out, down to the recipe for building the VM. The VM is not built or started. |

Besides these, `nix flake check` itself makes sure that every output of
`flake.nix` can be worked out.

To run one check and see its output:

```sh
nix build .#checks.aarch64-darwin.unit -L
```

### The unit tests

The files in [`tests/unit/`](../tests/unit) test the broker's decisions as
plain functions, with no network and no broker running:

| File | Covers |
| --- | --- |
| `test_rules.py` | Reading `rules.yaml`: what a correct file gives, and each kind of mistake that must stop the broker. The decision whether a host and port may be reached. The repo's own `rules.yaml`. |
| `test_swap.py` | Putting the token in place of the placeholder, and every login that must be refused instead. |
| `test_swap_fetch_tokens.py` | Fetching the tokens before the broker starts. |
| `test_github_policy.py` | Which GitHub requests are let through. |

The check picks up every file in the folder, so a new `test_*.py` file needs
no change anywhere else. It runs them with the same Python and the same
mitmproxy as the broker itself.

In the check, a skipped test counts as a failure. Some tests skip themselves
when a library is missing: with plain `pytest` and no `ruamel.yaml`, the
whole of `test_swap_fetch_tokens.py` is skipped and the run still ends
green. That is friendly on a laptop, and wrong in a check that is meant to
run everything. The switch is the variable `NIXT3_NO_SKIPS`, read in
[`tests/unit/conftest.py`](../tests/unit/conftest.py).

`broker/proxy.py` cannot be imported by a test, because its last line starts
the broker. `conftest.py` loads the file without that line; the `proxy`
fixture there explains how.

## Layer 2: `nix run .#test-broker`

```sh
nix run .#test-broker
```

This runs [`tests/github-broker.sh`](../tests/github-broker.sh) with the
programs it needs. The script starts a real broker, with the same options as
the VM's, on a free port and with a state folder of its own. It also starts a
small server on the same machine that stands in for a site on the internet.
Requests are then sent through the broker the way programs in the VM send
them, and the stand-in reports what arrived. The VM's own broker, its port
8474 and `~/.local/state/agent-vm` are not touched, and nothing leaves the
machine, so it needs no network and no token.

What it covers that the unit tests cannot: the broker as mitmproxy runs it.

- **Starting:** a missing or wrong rules file or tokens file stops the
  broker, and nothing is left listening.
- **The rules:** a host that is not listed, plain HTTP, a listed host on
  another port, and a tunnel used under another site's name are all refused,
  with a text that says why. A destination that is listed but not opened is
  passed on unread.
- **The token:** the placeholder is swapped, any other login is refused, and
  the token appears in no log, file or command line.
- **Failing closed:** when the broker's own code fails, the request is
  refused.
- **Limits:** requests that never end are cut off, and large uploads and
  downloads pass without being held in memory.

The script can also be run by hand, as `tests/github-broker.sh`. It then
uses the Mac's own `python3`, `openssl` and `curl`, and builds the broker
from the checkout it is in.

The stand-in is reached by the names `standin.localhost` and
`unopened.localhost`. A recent macOS reads every name that ends in
`.localhost` as the machine itself. macOS 15 does not: there the broker
cannot find the stand-in, and every check that needs it fails with
`nodename nor servname provided` in the broker's log. On such a Mac, add the
line `127.0.0.1 standin.localhost unopened.localhost` to `/etc/hosts`. CI
does this by itself.

## Layer 3: inside the VM

```sh
nix run .#check                                    # the VM must be running
nix run .#ssh -- bash -s < tests/github-live.sh    # needs your GitHub token
```

`nix run .#check` runs [`tests/network-lock.sh`](../tests/network-lock.sh)
inside the VM. Most of its checks pass when something fails: they try to get
around the lock. [`tests/github-live.sh`](../tests/github-live.sh) pushes a
branch and opens a pull request through the broker, then removes both.

### What only this layer can prove

The first two layers test the broker and the code around it. They cannot
see the wall the broker stands in. These things are only shown inside the
VM:

- **There is no way around the broker.** A direct connection, by name, by
  address or over IPv6, gets nowhere. Names cannot be looked up, QEMU's own
  name server does not answer, the Mac itself is out of reach, and so is SSH
  to GitHub. This is QEMU's restricted network at work, which nothing on the
  Mac side can test.
- **Programs in the VM really go through the broker.** The forward from
  `10.0.2.100:3128` to the broker works, the proxy settings reach `curl`,
  `git`, `gh` and Node, and a refusal arrives in the VM at once instead of
  after a time limit.
- **The VM trusts the broker's certificate, and only where it should.** The
  certificate handed over at start is trusted by curl, Node and `gh` for
  GitHub, while Anthropic still shows its own.
- **The VM holds the placeholder and no token.** `git`, `gh` and the T3
  server log in with the placeholder, and no file or program in the VM holds
  anything that looks like a GitHub token.
- **The real sites answer.** GitHub accepts the swapped token and Anthropic
  answers, with the rules file as it is in the repo. Layer 2 uses a stand-in
  and rules of its own.
- **The agent user is confined.** It has no `sudo`, and no folder is shared
  with the Mac.
- **The VM builds and starts at all.** Layer 1 only checks that its
  configuration makes sense, without building it.

## CI

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs layers 1 and
2 on GitHub, for every pull request and every push to `main`:
`nix flake check`, then `nix run .#test-broker`. The machine is a Mac with
an Apple Silicon chip and no Linux builder, so a green run also shows that
the checks build no part of the VM.

It cannot run layer 3: there is no VM there, and no token. A green run in
CI does not replace `nix run .#check`.

The workflow uses no secrets and may only read the repo. It runs on
`pull_request`, so a pull request from a fork gets the same read-only
treatment. Each action it uses is named by its exact commit.

The runner's macOS does not read `.localhost` names as the machine itself,
so the workflow adds the two names of the stand-in to the runner's hosts
file first.

A test that is a script of its own, as `tests/github-broker.sh` is, gets
into CI with one line: the step "Tests that start real programs" in the
workflow runs one command on each line. A script that only needs `nix` is
added there by its path, such as `tests/commands.sh`.

## Working on the tests

```sh
nix develop            # a shell with python, pytest, mitmproxy, shellcheck, ruff and treefmt
```

Inside it:

```sh
pytest tests/unit                                        # the unit tests
pytest tests/unit/test_rules.py -k ports                 # some of them
shellcheck tests/*.sh                                    # the shell scripts
ruff check --config tests/ruff.toml broker tests/unit    # the Python files
nix fmt                                                  # format the Nix files
```

Things to know:

- **Flakes ignore files that git does not know.** `git add` a new test
  before running `nix flake check`, or the check will not see it.
- **A new unit test goes in `tests/unit/`,** in a file named `test_*.py`.
  Nothing else has to change.
- **A new check for the running broker goes in `tests/github-broker.sh`.**
  Keep it off the internet: use the stand-in server, not GitHub.
- **A new check for the VM goes in `tests/network-lock.sh`.**
- **Never call your password manager from a test.** Use a tokens file whose
  command prints a made-up token, as `tests/github-broker.sh` does.
