# Setup

How to get the agent VM running on a Mac and linked to T3 Code.

## Requirements

- An Apple Silicon Mac.
- Nix with flakes, managed by [nix-darwin](https://github.com/nix-darwin/nix-darwin).
- The T3 Code app.
- A Claude account.

## 1. Add the Mac module

The VM is a Linux system, and a Mac cannot build Linux packages by itself.
This repo has a nix-darwin module that turns on a Linux builder. Import it in
your nix-darwin flake:

```nix
{
  inputs.agent-sandbox.url = "github:madshermansen/nixos-agent-sandboxing";

  outputs = { nix-darwin, agent-sandbox, ... }: {
    darwinConfigurations.my-mac = nix-darwin.lib.darwinSystem {
      modules = [
        agent-sandbox.darwinModules.default
        # ... your own modules
      ];
    };
  };
}
```

While the repo is private, Nix cannot fetch it from GitHub without a token.
Point the input at a local clone instead:

```nix
inputs.agent-sandbox.url = "git+file:///Users/you/path/to/nixos-agent-sandboxing";
```

Apply it. This needs admin rights:

```sh
sudo darwin-rebuild switch --flake .
```

A local clone is read at the commit recorded in your `flake.lock`. After
pulling changes to the module, run `nix flake update agent-sandbox` and apply
again.

## 2. Start the VM

From a clone of this repo:

```sh
nix run .#vm
```

The first run builds the VM, which takes about 20 minutes because the Linux
builder does one job at a time. Later runs boot in under a minute unless the
VM's configuration changed.

The terminal becomes the VM's console, logged in as `agent`. Press `Ctrl-A`
then `X` to stop the VM.

## 3. Sign in to Claude

In a second terminal:

```sh
nix run .#ssh -- -t claude
```

Claude Code prints a URL. Open it on the Mac, sign in, and paste the code
back. The sign-in is stored on the VM's disk, so this is done once.

## 4. Link the VM to T3 Code

```sh
nix run .#pair
```

This asks the VM's T3 server for a one-time pairing code and opens it in the
T3 app. The VM now appears in the app as a second environment, named
`agent-vm`. A thread started there runs inside the VM.

The pairing is stored on the VM's disk and lasts 30 days.

To also let agents on the Mac hand work to the VM, turn on Linked
environments under Settings → Labs in the T3 app, then run:

```sh
nix run .#ssh -- t3 auth pairing create
t3 environment link http://127.0.0.1:3774 --pairing-code <code>
```

## Day to day

| Task | Command |
| --- | --- |
| Start the VM | `nix run .#vm` |
| Open a shell in it | `nix run .#ssh` |
| Add it to the T3 app | `nix run .#pair` |
| Run one command in it | `nix run .#ssh -- <command>` |
| Read the T3 server's log | `nix run .#ssh -- journalctl -u t3 -e` |
| Stop the VM | `Ctrl-A` then `X` in its terminal |
| Start over with a clean VM | Stop it, then delete `~/.local/state/agent-vm` |

Starting over removes everything in `/home/agent`, including the Claude
sign-in, and the link to T3 has to be made again.

## Updating T3

The T3 server in the VM should be the same version as the T3 app on the Mac.
When the app updates, change the version and checksum in
[`vm/t3.nix`](../vm/t3.nix) and restart the VM. The checksum is the line for
`linux-arm64` in the release's `SHA256SUMS` file on GitHub.

## Problems

**The build stops with "a 'aarch64-linux' with features {} is required".**
The Linux builder is not on. Check that step 1 was applied:
`nix config show | grep builders` should show a value.
