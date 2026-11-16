# nixt3

Pronounced "nixty-three".

A headless NixOS VM for running coding agents from T3 Code on a Mac. Its
network is locked: the only way out is a broker on the Mac, which passes on
listed destinations. Planned: the broker also holds the keys, so the VM never
does.

Read [PLAN.md](PLAN.md) for the phases and [docs/architecture.md](docs/architecture.md)
for how the parts fit. The current phase is recorded at the bottom of this file.

## Rules for this repo

- **Everything about the VM lives here.** That includes what the Mac needs:
  it goes in `darwin/` as a nix-darwin module, and a personal `nix-config`
  only imports that module.
- **No secrets and no personal keys in the repo.** Keys are generated on the
  machine or read from a password manager. The VM must never hold a real cloud or
  GitHub token once the broker exists.
- **Keep it generic.** No names of private projects, clusters or companies.
- **Write for a reader who is new to the project.** Docs and comments use
  plain words and explain why, not only what.
- **Docs move with the code.** A change to behaviour updates `README.md`,
  `docs/` and this file in the same commit. Update the diagrams in
  `docs/images/` when the architecture changes; they are hand-written SVG.
- **Each phase ends with a check that proves it works.** Do not mark a phase
  done on the strength of a build alone.

## Layout

| Path | Contents |
| --- | --- |
| `flake.nix` | Entry point: the VM, `nix run` commands, the Mac module |
| `vm/default.nix` | The VM's NixOS configuration, including the network lock |
| `vm/t3.nix` | The T3 server package, pinned by version and checksum |
| `vm/agent-instructions.md` | What the agent in the VM is told about the sandbox; installed as `/etc/claude-code/CLAUDE.md` |
| `broker/rules.yaml` | The destinations the VM may reach |
| `broker/proxy.py` | The broker: a mitmproxy script that applies the rules |
| `darwin/commands.nix` | The Mac-side commands behind every `nix run .#…` |
| `darwin/default.nix` | nix-darwin module for the Mac |
| `tests/network-lock.sh` | Checks run inside the VM by `nix run .#check` |
| `docs/` | Setup, architecture, diagrams |

## Commands

```sh
nix run .#vm                 # build if needed, start the broker, then the VM in this terminal
nix run .#stop               # shut the VM down cleanly and stop the broker
nix run .#check              # run tests/network-lock.sh inside the VM
nix run .#logs               # follow the broker's log
nix run .#broker             # run the broker in this terminal, replacing the background one
nix run .#ssh                # shell in the VM as `agent`
nix run .#ssh -- <command>   # one command in the VM
nix run .#pair               # add the VM to the T3 app on the Mac
nix build .#vm --no-link     # build only
nix fmt                      # format the Nix files; run before committing
```

## Checking that T3 and Claude work in the VM

This starts a thread on the VM's T3 server and waits for the reply. A project
has no default model, so the provider and model must be given:

```sh
nix run .#ssh -- 't3 project add ~/sandbox-test'    # once
nix run .#ssh -- 't3 thread start --wait --provider claudeAgent \
  --model claude-haiku-5-5 ~/sandbox-test "Run uname -a and reply with its output."'
```

The reply should name Linux and the host `agent-vm`.

## The network lock and the broker

- **The VM reaches only the broker.** QEMU's restricted mode drops all other
  traffic, including name lookups and the Mac itself. `10.0.2.100:3128` in
  the VM is forwarded to the broker on the Mac's `localhost:8474`.
- **Rules are fixed when the command is built** and read once at broker
  start. After editing `broker/rules.yaml`, restart the VM, or run
  `nix run .#broker` to replace the running broker.
- **The broker fails closed.** A missing or invalid rules file stops it from
  starting, and then the VM is not started either. Keep it that way.
- **A refusal is a 403 on the tunnel.** Programs show `CONNECT tunnel failed,
  response 403`; `curl -v` shows the broker's text. In curl's `-w` format the
  status is `%{http_connect}`, not `%{http_code}`.
- **`nix shell` does not work in the VM,** because Nix's servers are not
  listed. Tools go in `environment.systemPackages`.
- **Keep `mcp-proxy.anthropic.com` off the list.** It leads to the
  connectors of the signed-in Claude account, which would give the agent the
  user's other services.
- **Every listed host is a place data can be sent.** Add one only when a
  task needs it, with a `note` saying why.
- **Log lines** are `time event host port how [reason]`, with the event one
  of `started`, `allowed`, `refused`, `failed`. Never log paths, headers or
  bodies.
- **mitmdump ignores an unknown `--set` option,** so the rules path is passed
  as the `AGENT_BROKER_RULES` variable.
- **State files** in `~/.local/state/agent-vm`: `disk.qcow2`, `ssh_key`,
  `qemu.pid`, `qmp.sock`, `broker.pid`, `broker.log`, `broker/`, `console.log`.
- **The broker runs with the user's rights on the Mac** and is the one Mac
  program the VM can talk to. Treat everything it receives as hostile.

## Things that are easy to get wrong

- **Flakes ignore untracked files.** `git add` a new file before building, or
  Nix reports that it does not exist.
- **The VM is Linux, the host is a Mac.** Linux parts are built by the Linux
  builder. If it is off, builds fail with "a 'aarch64-linux' ... is required".
  Changing system settings on the Mac needs `sudo`, which the user runs.
- **Mac-side scripts use `hostPkgs`, VM contents use `pkgs`.** Mixing them
  puts a Mac program in the VM or the reverse.
- **A change to the VM needs a restart.** There is no live rebuild. The disk
  in `~/.local/state/agent-vm` survives restarts; the system does not.
- **The T3 server is a prebuilt program.** It is installed untouched and run
  through `nix-ld`. Its version in `vm/t3.nix` should match the T3 app on the
  Mac.
- **The T3 server must listen on `0.0.0.0` in the VM.** QEMU delivers
  forwarded connections to the VM's network address, not its loopback. The
  Mac side of each forward is bound to `127.0.0.1`.
- **Nothing is shared with the Mac.** `useNixStoreImage` and the empty
  `sharedDirectories` are deliberate. Do not add a shared folder to move a
  file; use SSH.
- **The `agent` user has no `sudo`.** Add tools to
  `environment.systemPackages`. It also cannot power the VM off; stop it from
  the Mac with `nix run .#stop`.
- **`nix run .#vm` holds its terminal.** To start the VM from a tool call,
  detach it and send the console to a file:
  `nohup nix run .#vm > ~/.local/state/agent-vm/console.log 2>&1 < /dev/null &`.
  Then wait for SSH with `until nix run .#ssh -- true; do sleep 2; done`,
  which takes about a minute.
- **Two QEMU processes may be running.** The Linux builder is one too. Never
  stop the VM with a broad `pkill qemu`; use `nix run .#stop`.
- **A full VM build takes about 20 minutes.** The default Linux builder does
  one job at a time. Give background builds a long time limit.
- **Two ways to connect T3.** `nix run .#pair` adds the VM to the T3 app, so
  the user can start threads in it. `t3 environment link` lets agents on the
  Mac hand work to the VM, and needs Linked environments turned on under
  Settings → Labs in the app.

## How work is done

- **One pull request per phase or change,** on its own branch. Do not commit
  to `main` directly.
- **A separate agent reviews each pull request** before it is merged. Give it
  the diff and the goal, not your own conclusions.
- **Merge only when** the review's findings are fixed and the phase's check
  has been run in the VM. Put the check's result in the pull request.

## When several agents work at once

- **There is one VM and one broker,** in `~/.local/state/agent-vm`, on fixed
  ports. Only one agent may stop, start or reconfigure them at a time.
- **Take the VM before changing it:** `mkdir ~/.local/state/agent-vm/in-use`
  succeeds for one agent only. If it fails, someone else has the VM; wait and
  try again. Put a file in the folder saying who you are, and remove the
  folder when you are done. Reading from the VM through `nix run .#ssh` needs
  no turn, but expect it to restart under you.
- **Each agent works in its own checkout** on its own branch, and opens its
  own pull request. Keep to the files your task names, so pull requests do
  not collide.

## Git

- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org)
  with an emoji after the colon: `type(scope): emoji subject`. The scope is
  optional. The subject is short and imperative, and a body explains the
  reason when it is not obvious.

  | Type | Emoji | Use for |
  | --- | --- | --- |
  | `feat` | ✨ | A new capability |
  | `fix` | 🐛 | A bug fix |
  | `docs` | 📝 | Documentation only |
  | `refactor` | ♻️ | A change that keeps behaviour the same |
  | `test` | ✅ | Tests and checks |
  | `chore` | 🔧 | Config, tooling, dependency updates |
  | `ci` | 👷 | CI |
  | `perf` | ⚡ | Faster or lighter |

  A more specific emoji is fine when it fits better, such as 🔒 for a
  security change. Examples: `feat(vm): ✨ add a command that pairs the VM with T3`,
  `docs: 📝 describe the network lock`.
- Commits are signed through 1Password, which may ask the user to approve.

## Status

Update this section when a phase is finished or a decision is made.

- **Phase 0, the repo:** done.
- **Phase 1, the VM and the T3 link:** done. The VM boots, SSH works, the
  T3 app on the Mac is paired with it, and a T3 thread in the VM ran `uname`
  and printed Linux. Checked in the VM: no shared folders, no `sudo`, open
  internet.
- **Phase 2, the real VM:** partly done ahead of time: Claude Code, the tool
  list, the VM's own disk and no shared folders. Verified: the disk, the
  Claude sign-in and the T3 pairing survive a restart, and `nix run .#stop`
  shuts the VM down cleanly in a few seconds. The temporary GitHub token in
  the plan was skipped, so no token has been in the VM.
- **Phase 3, the network lock:** done. `nix run .#check` passes all checks,
  and a T3 thread in the locked VM reached Claude and was refused
  `example.com`.
- **Next, phase 4:** GitHub through the broker, with the token read from
  1Password. The repo the agent may push to is this one.
- **Decided:** the GitHub token is kept in 1Password. The broker reads it
  once at start through a command named in `rules.yaml` and keeps it in
  memory. It is never written to the repo, the VM, a Nix file or the Nix
  store, which every program on the Mac can read.
- **Open decision:** where Claude's own login lives. For now it is signed in
  inside the VM.
