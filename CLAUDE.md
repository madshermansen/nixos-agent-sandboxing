# nixt3

Pronounced "nixty-three".

A headless NixOS VM for running coding agents from T3 Code on a Mac. Its
network is locked: the only way out is a broker on the Mac, which passes on
listed destinations. The broker also holds the GitHub token and adds it on
the way out, so the VM never does.

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
| `broker/swap.py` | The decisions about one opened request, among them the token swap; no mitmproxy in it |
| `broker/github_policy.py` | Which GitHub requests may go out: the repos and actions allowed; pure, no mitmproxy |
| `broker/github_request.py` | Joins policy and swap for one request; pure, no mitmproxy |
| `broker/fetch_tokens.py` | Fetches the tokens before the broker starts |
| `broker/limits.py` | Size limits that mitmproxy lacks, patched into it; tied to the exact mitmproxy version |
| `broker/settings.py` | Which of mitmproxy's settings the broker agrees to run with; pure, no mitmproxy |
| `broker/tokens.example.yaml` | Example of `~/.config/nixt3/tokens.yaml`, which says where each token is kept |
| `darwin/commands.nix` | The Mac-side commands behind every `nix run .#…` |
| `darwin/default.nix` | nix-darwin module for the Mac |
| `tests/network-lock.sh` | Checks run inside the VM by `nix run .#check` |
| `tests/github-broker.sh` | The token swap and the policy, checked on the Mac through a real broker against a stand-in for GitHub |
| `tests/github-live.sh` | The round trip with a real token, run inside the VM |
| `tests/commands.sh` | The Mac-side commands, checked on the Mac with stand-ins for QEMU and ssh; no VM needed |
| `tests/unit/` | pytest files for the broker's decisions; no network needed |
| `docs/` | Setup, architecture, the threat model (`threat-model.md`), the decision log (`decisions.md`), advice for threads on the Mac (`local-threads.md`), diagrams |

## Commands

```sh
nix run .#vm                 # build if needed, start the broker, then the VM in this terminal
nix run .#vm-fresh           # the same, as a throwaway run: what the VM writes is discarded at stop
nix run .#stop               # shut the VM down cleanly and stop the broker
nix run .#status             # one screen: what is up, versions, sign-in, who holds the VM; changes nothing
nix run .#check              # run tests/network-lock.sh inside the VM
nix run .#logs               # follow the broker's log
nix run .#broker             # run the broker in this terminal, replacing the background one
nix run .#ssh                # shell in the VM as `agent`
nix run .#ssh -- <command>   # one command in the VM
nix run .#pair               # add the VM to the T3 app on the Mac
nix run .#update-t3          # write the T3 app's version and its checksum into vm/t3.nix
nix build .#vm --no-link     # build only
tests/github-broker.sh       # check the token swap and the policy on the Mac, without the VM or a token
tests/commands.sh            # check the Mac-side commands, without the VM
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
  of `allowed`, `refused`, `failed`. A `started` line, with the number of
  destinations and the rules file, marks each broker start. For a request to
  an opened destination, the method, the path without its query string, the
  answer's status and the kind of request (`git-read`, `api-write`, ...) are
  added. Never log query strings, headers, bodies or tokens, nor the text a
  refusal gives the agent, which can repeat part of the request.
- **Only a broker of ours may hold the port.** `nix run .#vm` refuses to
  start when `localhost:8474` is taken by anything but a broker started with
  `nix run .#broker`.
- **mitmdump ignores an unknown `--set` option,** so the rules path is passed
  as the `AGENT_BROKER_RULES` variable.
- **State files** in `~/.local/state/agent-vm`: `disk.qcow2`, `ssh_key`,
  `ssh_key.pub`, `qemu.pid`, `qmp.sock`, `broker.pid`,
  `broker-foreground.pid` (written by `nix run .#broker`), `broker.log`,
  `broker/` (mitmproxy's files, among them the certificate authority and its
  private key), `console.log` (only when the VM is started detached, as
  below), the folder `in-use` while an agent holds the VM, `vm.lock` (held
  by QEMU while a VM runs; the file itself stays), `throwaway.qcow2` during
  a throwaway run, and `broker.log.1` to `.3` and `console.log.1` to `.3`,
  older parts of the logs.
- **The broker runs with the user's rights on the Mac** and is the one Mac
  program the VM can talk to. Treat everything it receives as hostile.

## GitHub through the broker

- **The VM holds a placeholder, the Mac holds the token.** `git` and `gh` in
  the VM log in with `nixt3-placeholder-not-a-real-token`. The broker puts
  the real token in its place. The placeholder is written in three files:
  `broker/swap.py`, `vm/default.nix` and `tests/network-lock.sh`; a unit
  test checks that they agree.
- **`inspect: true` in `rules.yaml` makes the broker open a destination,**
  and `token: <name>` makes it swap the placeholder there. Only GitHub's
  hosts have them. Never mark Anthropic: its traffic is passed on unread.
- **A login that is not the placeholder is refused, not removed.** Keep it
  that way. Cookies are left out of the request.
- **A token is added only on a checked connection.** The tunnel, the name in
  the VM's encrypted connection, the Host header and the certificate of the
  server must all be the host from the rules. Clear text inside a tunnel is
  refused for every destination.
- **`proxy.py` runs no programs and reads no token from a file or the
  environment.** `fetch_tokens.py` gets the tokens first, and they reach the
  broker on an inherited pipe, number 3. This is so the broker can be
  confined without access to the password manager.
- **Where a token is kept is not in the repo.** `rules.yaml` names it;
  `~/.config/nixt3/tokens.yaml` on the Mac (or `AGENT_BROKER_TOKENS`) gives
  the command that prints it. A missing file, entry or failing command
  stops the broker from starting.
- **Never call the user's password manager from a test.** Use a tokens file
  whose command prints a made-up token, as `tests/github-broker.sh` does.
  That test shows the swap, because it sees what the broker sends out. From
  inside the VM a made-up token cannot show it: GitHub answers "Bad
  credentials" to it and to the placeholder alike.
- **The broker speaks HTTP/1.1 where it opens traffic** (`http2=false`).
  The body handling relies on it: in HTTP/2 a request can carry a body
  without declaring one.
- **Bodies are not held in memory.** A request body is read in full only
  when it is declared to be at most 1 MiB; everything else is passed on in
  pieces. `body_size_limit` must stay off: it cuts off a large push or
  clone before the broker's code runs.
- **The forward to the broker runs `socat`, not `nc`.** NixOS's own
  `forwardPorts` would run `nc` per connection, which does not pass a close
  from the broker on to the VM; a refused program then waited out its time
  limit. So `vm/default.nix` writes the QEMU network option out in full.
  With `socat` the VM sees a close about a second late. An answer that ends
  by closing the connection is still re-framed as chunked in `proxy.py`.
- **A hook that fails must refuse.** mitmproxy carries on when a hook raises
  an error, which for a broker means letting the request through. Every
  hook of `Broker` is wrapped by `fail_closed` in `proxy.py`. A new hook
  needs an entry in `ON_FAILURE` there, or the broker does not load.
- **Updating mitmproxy stops the broker until `limits.py` is checked.** It
  replaces three mitmproxy functions to cap what a connection may send
  before it makes sense (request heads, the first TLS message), and
  compares their checksums at start. After an update of `flake.lock`, read
  the top of `broker/limits.py`.
- **At most 256 connections at once** (`MAX_CLIENTS` in `proxy.py`). With
  the limits above this bounds the broker's memory.
- **Everything the broker writes passes a token filter** on its way to the
  log, also mitmproxy's and Python's own lines (`scrub_output`).
- **The VM trusts the broker's certificate authority,** handed over at start
  with QEMU's `-fw_cfg` and read in the VM from
  `/sys/firmware/qemu_fw_cfg/by_name/opt/nixt3/broker-ca/raw`. The trusted
  list is built at boot in `/run/broker-ca`, and `/etc/ssl/certs` points
  there. The private key (`broker/mitmproxy-ca.pem` in the state folder)
  must never be passed to the VM.
- **The policy is asked in one place:** `Broker.pass_on()` in `proxy.py`,
  through `github_request.plan()`, for every request to an opened host,
  before the token is put in. `github_policy.py` decides; do not change
  what it decides without reading `docs/github-rules.md` and its tests.
- **An opened host needs the `github` part of `rules.yaml`.** Without it, or
  with a mistake in it, the broker does not start. Only `github.com` and
  `api.github.com` can be opened: for any other host the policy refuses
  every request.
- **The policy must see what GitHub will see.** It is given the method, the
  path with its query string, the headers and the body as they arrived, and
  the broker sends on the same. Do not tidy a request before the policy is
  asked, and do not hand it a decoded or normalised form: a difference
  between what is judged and what is sent is a way around the policy.
- **mitmproxy's accessors are not the bytes.** `request.method` is in upper
  case whatever was sent, while the bytes that go out keep their spelling;
  `request.authority` is decoded. For anything that is judged, read
  `request.data` and `request.headers.fields` (`as_sent()` in `proxy.py`).
  A method that is not in capitals is refused as `odd-method`.
- **The one thing rewritten on purpose is a JSON body.** The policy writes
  out again what it read, and that copy is sent, so GitHub reads what was
  judged. A number may change its spelling (`1e2` leaves as `100.0`).
- **Each request is decided by itself.** Never remember a decision for a
  connection: a listed request may be followed by an unlisted one on the
  same connection.
- **The broker runs only with mitmproxy settings it knows.** A
  `config.yaml` or `config.yml` in the broker's folder stops it from
  starting. So does a setting that is not as `broker/settings.py` wants it:
  eight must have the value `darwin/commands.nix` gives them, five may have
  any value, every other must be at mitmproxy's default. Settings such as
  `map_remote` and `modify_headers` change a request after it was judged.
  The `configure` hook checks again whenever a setting changes, and stops
  the broker. A new `--set` in the start command needs an entry in
  `settings.py`; a unit test compares the two.
- **mitmproxy gets an environment of its own.** The start command runs
  mitmdump under `env -i` with three variables, and the broker refuses to
  start with any variable that is not in `ENVIRONMENT` in `settings.py`.
  `SSLKEYLOGFILE` in the shell would otherwise make mitmproxy write the
  keys of its connections, the token's among them, to a file. A new
  variable for mitmdump needs an entry there. The token fetcher still runs
  with the shell's environment, because the password manager needs it.
- **`stream_large_bodies` must stay `1m`,** equal to what the broker reads
  in full. mitmproxy passes a larger body on before the broker is asked.
  The broker also sets `flow.request.stream = False` for every request it
  refuses or reads first; keep both.
- **A header with a byte outside plain ASCII is refused** on opened hosts
  (`odd-header`). The policy strips more than HTTP's white space from a
  value before reading it, so such a byte could be judged away and still
  be sent.
- **A `Connection` header may say `close` or `keep-alive` only** on opened
  hosts. Anything else can name headers for GitHub's front servers to drop.
- **The API is decided after the body, git before it.** For
  `api.github.com` the body is read first (at most 1 MiB, not compressed,
  with a declared length) and a request whose body cannot be read that way
  is refused. For `github.com` the decision is made from the first lines
  and the body streams.
- **A refusal is worded for the program that gets it,** because the text is
  where the agent is told which `gh api` line to use instead, and each
  program shows only what it expects. For git: a 403 in plain text, shown
  as `remote:` lines. For the REST API: a 403 with JSON that has a
  `message`, as GitHub's own errors are; `gh api` shows it. For the
  address `/graphql`, whatever the method and the reason: the status 200
  with `errors` in place of data, as
  GraphQL itself refuses; the `gh pr` commands print the body of a 403 as
  one escaped line, and this form cleanly. `refusal_answer()` in
  `github_request.py`; each form was tried with the real `gh`.
- **`gh pr edit` is refused at a read,** not at its change: it first asks
  who can be assigned, which is not on the policy's list. The broker adds
  the `gh api` lines for changes to that refusal (`CHANGE_INSTEAD` in
  `github_request.py`), without changing what the policy allows.
- **`with_token` false means no login at all.** With
  `other_repos: read-public` the policy allows reading unlisted repos
  without the token. The broker then removes the Authorization header, the
  placeholder included.
- **The repos are named in four places:** the `github` part of
  `rules.yaml`, `vm/agent-instructions.md`, `listed=` in
  `tests/network-lock.sh`, and `tests/github-live.sh`. A unit test checks
  the first two against each other.
- **`nix run .#check` uses GitHub without a login,** and GitHub allows an
  address 60 such requests an hour. Do not add checks that make many, and
  run load tests against the stand-in only (`tests/github-broker.sh`).
- **The local test uses GitHub's real names.** `tests/github-broker.sh`
  sends requests to `github.com` and `api.github.com` through a broker
  with this repo's rules, and a script loaded only there sends the broker's
  connection to a stand-in. So the broker and the policy run unchanged.

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
  `environment.systemPackages`. It also cannot power the VM off: only root
  may ask systemd for that, because polkit, which could allow a logged-in
  user, is off in the VM (asked over SSH, the answer was "Access denied").
  Stop the VM from the Mac with `nix run .#stop`.
- **`nix run .#vm` holds its terminal.** To start the VM from a tool call,
  detach it and send the console to a file:
  `nohup nix run .#vm >> ~/.local/state/agent-vm/console.log 2>&1 < /dev/null &`.
  Use `>>`, not `>`: the start command moves a large console.log aside
  itself, and `>` would empty the file before it can.
  Then wait for SSH with `until nix run .#ssh -- true; do sleep 2; done`,
  which takes about a minute.
- **`nix run .#status` exits 0 only when everything is up.** 1 means a line
  says `FAIL`, 2 means the VM is not running or is still starting. `warn`
  lines do not count.
- **`nix run .#stop` waits for a VM that is still starting,** up to 90
  seconds, and then shuts it down. If the start takes longer, stop fails
  and leaves the broker alone. So after a stop that succeeded, nothing
  runs.
- **A `qemu.pid` proves nothing by itself.** After a crash its number can
  belong to another program. Ask `vm_pid` in `darwin/commands.nix`, which
  checks that the process is the QEMU of this state folder; never
  `kill -0 $(cat qemu.pid)`. Whether a VM is starting is told by the lock
  (`vm_lock_held`), not by a file.
- **Pick lines out of `broker.log` by their fields, never by a word.** The
  VM chooses the host and the path that are logged, so a host named
  `started` gives a line with that word in it. The first field is the time
  and the second the event; compare those, as `log_lines` in `status` does.
- **A throwaway run (`nix run .#vm-fresh`) keeps nothing.** It starts from
  the normal disk, so it is signed in and paired, and its changes are in
  `throwaway.qcow2`, deleted at stop. It takes the same lock as the normal
  VM, so the two never run together. A throwaway disk left by a crash is
  never reused; the next start or stop deletes it.
- **Logs are moved aside only at a start,** when over 5 MiB: `broker.log`
  just before a new background broker opens it, `console.log` by the start
  command. Do not move or cut a log while the broker runs; it keeps writing
  to the file it opened.
- **The start command drops `QEMU_OPTS`** and `NIXPKGS_QEMU_KERNEL_*` from
  the environment and says so. Options after `nix run .#vm --` still reach
  QEMU, with a note. Keep it that way: either can undo the lock.
- **Every ssh call goes through `agent-vm-ssh`,** which starts ssh with
  `-F none` so that the user's `~/.ssh/config` cannot add a forward, and
  refuses to start without the VM's own key, because ssh would then offer
  the user's keys to the VM. Do not call `ssh` directly in a new command.
- **Change `darwin/commands.nix`, then run `tests/commands.sh`.** It builds
  the real commands with stand-ins for QEMU and ssh on ports of its own.
  To make something replaceable in it, add an argument to `commands.nix`
  with the real thing as its default, as `stopWaitSeconds` is.
- **Avoid `LC_ALL=C command` inside a shell function.** Seen on one Mac on
  2026-11-17, cause not found: the bash that runs these commands (5.3.20
  from nixpkgs) ended with a segmentation fault in about one run in six of
  a script as small as `plain() { LC_ALL=C tr -c 'a-z' '?'; }; echo x | plain`,
  but only when `LANG` was not set in the environment; with `LANG` set
  there was no fault in 300 runs, and a reviewer saw none in 300. Tool
  calls and background services often run without `LANG`. `status` sets
  `LC_ALL` once at the top instead, which never faulted.
- **`compgen` does not exist in that bash.** Use `"${!PREFIX@}"` for the
  names of variables that start with a prefix.
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
  no turn, but expect it to restart under you. `nix run .#status` shows who
  holds the VM.
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
- **Phase 4, GitHub through the broker:** built, and checked with a made-up
  token: `nix run .#check` passes, `tests/github-broker.sh` passes, and a T3
  thread in the VM read a GitHub repo through the broker. Not done yet: the
  final check with a real token, `tests/github-live.sh` (push a branch, open
  a pull request). It waits for the user's token in 1Password.
- **Everyday commands:** `status`, `vm-fresh`, `update-t3` and the upkeep
  of the logs are in. Checked on the running system: a throwaway run booted
  signed in and paired, ran a T3 thread, and left the normal disk unchanged
  byte for byte; a crashed one was tidied up by the next start.
- **Phase 5, limits on GitHub:** built, and checked with a made-up token.
  The broker asks `github_policy.py` about every request to GitHub. The
  rules list one repo, `madshermansen/nixt3`, for writing; merging and
  reading other repos are off. `tests/github-broker.sh` shows allowed
  requests arriving with the token and refused ones never leaving, and
  `nix run .#check` shows the same refusals from inside the VM. Not done
  yet, as for phase 4: `tests/github-live.sh` with a real token.
- **Next, phase 6:** docs, background services, confining the broker.
- **Decided:** the GitHub token is kept in 1Password. `rules.yaml` names it
  only as `github`. `~/.config/nixt3/tokens.yaml` on the Mac names the
  command that prints it. That command is run once per broker start, and
  the token is handed to the broker through a pipe and kept in memory. It is
  never written to the repo, the VM, a Nix file or the Nix store, which
  every program on the Mac can read.
- **Decided:** a request to GitHub with a login other than the placeholder
  is refused, not passed on without it.
- **Open decision:** where Claude's own login lives. For now it is signed in
  inside the VM.
