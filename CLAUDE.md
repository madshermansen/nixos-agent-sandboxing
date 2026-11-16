# nixos-agent-sandboxing

A headless NixOS VM for running coding agents from T3 Code on a Mac, and
(planned) a broker on the Mac that holds the keys so the VM never does.

Read [PLAN.md](PLAN.md) for the phases and [docs/architecture.md](docs/architecture.md)
for how the parts fit. The current phase is recorded at the bottom of this file.

## Rules for this repo

- **Everything about the VM lives here.** That includes what the Mac needs:
  it goes in `darwin/` as a nix-darwin module, and a personal `nix-config`
  only imports that module.
- **No secrets and no personal keys in the repo.** Keys are generated on the
  machine or read from the Keychain. The VM must never hold a real cloud or
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
| `vm/default.nix` | The VM's NixOS configuration |
| `vm/t3.nix` | The T3 server package, pinned by version and checksum |
| `vm/host-scripts.nix` | The Mac-side commands behind `nix run .#vm` and `.#ssh` |
| `darwin/default.nix` | nix-darwin module for the Mac |
| `docs/` | Setup, architecture, diagrams |

## Commands

```sh
nix run .#vm                 # build if needed, then start the VM in this terminal
nix run .#ssh                # shell in the VM as `agent`
nix run .#ssh -- <command>   # one command in the VM
nix build .#vm --no-link     # build only
nix fmt                      # format the Nix files; run before committing
```

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
- **The `agent` user has no `sudo`.** Add tools to `environment.systemPackages`
  or use `nix shell`.

## Git

- Commits are signed through 1Password, which may ask the user to approve.
- Use short imperative commit subjects, with a body when the reason is not
  obvious.

## Status

Update this section when a phase is finished or a decision is made.

- **Phase 0, the repo:** done.
- **Phase 1, the VM and the T3 link:** the VM is written. Booting it, the
  Claude sign-in and the T3 link are not yet verified.
- **Open decision:** where Claude's own login lives. For now it is signed in
  inside the VM.
