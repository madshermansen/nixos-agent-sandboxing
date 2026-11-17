# Plan

## Goal

Run Claude Code from T3 inside a headless NixOS VM that holds no GitHub token. A broker on the Mac attaches the token to outgoing requests and refuses anything the rules don't allow.

GitHub is the only service for now. Other services can be added later as new rules.

## The repo

Everything lives in one repo, so the VM, the broker and the rules are versioned together and others can reuse them. That includes what the Mac itself needs, which is a nix-darwin module in `darwin/`.

```
nixt3/
  flake.nix          the VM, the Mac module, and the commands to start and reach the VM
  vm/                NixOS config: headless, tools, proxy settings, restricted network, T3 server
  darwin/            nix-darwin module: the Linux builder, later the VM and broker as background services
  broker/
    rules.yaml       destinations, where each key comes from, allow/deny, refusal messages
    proxy.py         the mitmproxy script that applies rules.yaml
  tests/             checks run inside the VM, mostly "this must fail"
  docs/              setup, architecture, what it protects against, how to add a service
  CLAUDE.md          instructions for agents working on this repo
  PLAN.md            this plan
```

One line lives outside it:

- **`nix-config`:** imports the repo's nix-darwin module, and nothing else.

## Phases

Each phase ends with a check that proves it works.

| # | Build | Done when |
| --- | --- | --- |
| 0 | Create the repo with the layout and `PLAN.md` | The repo exists |
| 1 | Linux builder through the repo's nix-darwin module. A minimal headless NixOS VM with open network, reachable by SSH from the Mac. T3 server in the VM, linked to the T3 app. | A T3 thread runs `uname` and prints Linux |
| 2 | The real VM: tool list, Claude Code, persistent disk, no shared folders, a test repo cloned inside. Uses a temporary GitHub token. | The agent commits a change in the clone and pushes a branch |
| 3 | Lock the network. The proxy on the Mac passes listed destinations through and adds no keys yet. | `curl https://example.com` fails in the VM. Claude and `git fetch` still work. |
| 4 | GitHub through the proxy: token in 1Password, a placeholder in the VM, a key-adding rule. `git` in the VM uses HTTPS so the proxy can see it. Remove the temporary token. | The agent pushes a branch and opens a PR. A search of the VM finds no real token. |
| 5 | GitHub limits: a list of allowed repos, and refusals for settings, secrets and repo deletion. | Requests to an unlisted repo are refused. So are changing repo settings and writing Actions secrets. |
| 6 | Docs, the VM and broker as background services, the broker confined so a bug in it cannot reach the rest of the Mac, and Claude's built-in sandbox for local Mac threads | It is used for a normal working day |

After phase 4 there is a usable sandboxed agent. Phase 5 narrows what it can do, and phase 6 makes it comfortable.

## Risks to check early

- **T3's server on NixOS.** T3 ships a self-contained Linux program through `npx t3`. NixOS can't run such programs without a compatibility setting (`nix-ld`). Phase 1 settled it: the server runs through `nix-ld`.
- **The network lock.** QEMU's restricted mode with only the broker's ports forwarded is untested with this VM setup. Phase 3 settled it: it works on a Mac, and every bypass in `tests/network-lock.sh` is blocked.
- **The proxy and large `git` pushes.** mitmproxy opening GitHub traffic may be slow or fragile. If so, the fallback is to keep a narrow GitHub token in the VM.
- **Limiting pushes by branch.** A push reaches the proxy as one upload that is hard to read reliably. "No push to `main`" is better enforced by branch protection on GitHub than by the proxy.

## Decisions

- **How work is done.** Each phase is one pull request on its own branch. A separate agent reviews it, the findings are fixed, the phase's check is run in the VM, and then it is merged.
- **The broker is not put in a container.** On a Mac that would mean a second VM, and the broker could no longer ask 1Password for the token. It will be confined with macOS's own tools in phase 6.
- **The test repo for the agent's pushes is this repo itself.**
- **Where the GitHub token is kept: 1Password.** The broker reads it once when it starts, which asks for Touch ID, and keeps it in memory only. Other programs on the Mac cannot read it silently, which they could from the Keychain. The cost is one prompt per broker start. `rules.yaml` names the token only by a short name. A file on the user's Mac, outside the repo (`~/.config/nixt3/tokens.yaml`), names the command that prints it, so someone else can use a different store without changing the broker or the repo.

## Open decisions

- **Claude's own login.** Claude Code needs a credential too. Either it lives in the VM as the one credential held there, or the broker attaches it like the GitHub token. For now it is signed in inside the VM.
