# Setup

How to get the agent VM running on a Mac and linked to T3 Code.

## Requirements

- An Apple Silicon Mac.
- Nix with flakes, managed by [nix-darwin](https://github.com/nix-darwin/nix-darwin).
- The T3 Code app.
- A Claude account.
- A GitHub token for the agent, kept in a password manager such as 1Password.

## 1. Add the Mac module

The VM is a Linux system, and a Mac cannot build Linux packages by itself.
This repo has a nix-darwin module that turns on a Linux builder. Import it in
your nix-darwin flake:

```nix
{
  inputs.nixt3.url = "github:madshermansen/nixt3";

  outputs = { nix-darwin, nixt3, ... }: {
    darwinConfigurations.my-mac = nix-darwin.lib.darwinSystem {
      modules = [
        nixt3.darwinModules.default
        # ... your own modules
      ];
    };
  };
}
```

To use a local clone instead, for example while changing the module, point
the input at it:

```nix
inputs.nixt3.url = "git+file:///Users/you/path/to/nixt3";
```

Apply it. This needs admin rights:

```sh
sudo darwin-rebuild switch --flake .
```

Either way the module is read at the commit recorded in your `flake.lock`.
To pick up changes to it, run `nix flake update nixt3` and apply again.

## Before the first start: the GitHub token

The agent uses GitHub with your token, but the token never enters the VM. It
stays in your password manager, and the broker adds it to each request on
the way out. The broker has to be told how to get it.

1. Create a token for the agent on GitHub. Make it as narrow as the work
   allows: a fine-grained token for the repos the agent should work on, with
   read and write access to contents and pull requests.
2. Store it in your password manager. With 1Password, save it in an item and
   use "Copy Secret Reference" on the field; that gives an address of the
   form `op://Private/agent-sandbox-github/credential`. Install the
   [1Password CLI](https://developer.1password.com/docs/cli/) and turn on
   its app integration, so that `op read` asks for Touch ID.
3. Tell the broker the command that prints the token:

   ```sh
   mkdir -p ~/.config/nixt3
   cp broker/tokens.example.yaml ~/.config/nixt3/tokens.yaml
   chmod 600 ~/.config/nixt3/tokens.yaml
   ```

   Then put your own address or command in the file. It holds no token, only
   how to get one. To keep it elsewhere, name it in `AGENT_BROKER_TOKENS`.

The command is run each time the broker starts, so 1Password asks once per
start. If the file or the command is missing or fails, the broker says what
is wrong and does not start, and neither does the VM.

## 2. Start the VM

From a clone of this repo:

```sh
nix run .#vm
```

The first run builds the VM, which takes about 20 minutes because the Linux
builder does one job at a time. Later runs boot in under a minute unless the
VM's configuration changed.

This also starts the broker, the proxy that is the VM's only way out, in the
background. The terminal becomes the VM's console, logged in as `agent`. To
stop both, run `nix run .#stop` in another terminal. It shuts the system down
cleanly, which takes a few seconds.

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

The pairing is stored on the VM's disk. How long it lasts is set by T3, not
by this repo. The one time it was looked at, the session ended 30 days after
it was made.

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
| Watch what the VM asks the broker for | `nix run .#logs` |
| Test the network lock and the GitHub setup | `nix run .#check` |
| Test GitHub end to end with the real token | `nix run .#ssh -- bash -s < tests/github-live.sh` |
| Test the token swap without a VM or a token | `tests/github-broker.sh` |
| Stop the VM and the broker | `nix run .#stop` |
| Start over with a clean VM | Stop it, then delete `~/.local/state/agent-vm` |

Starting over removes everything in `/home/agent`, including the Claude
sign-in, and the link to T3 has to be made again.

## Allowing a destination

The VM can reach only the hosts listed in
[`broker/rules.yaml`](../broker/rules.yaml). When the agent needs another one,
it gets `403 Refused by the sandbox broker`, and `nix run .#logs` shows a
`refused` line with the host name.

To allow it, add an entry with the exact host name and a note on why:

```yaml
  - host: objects.githubusercontent.com
    note: Downloads of GitHub release files.
```

Then restart the broker. `nix run .#vm` does that when it starts the VM. To
apply the change while the VM keeps running, run `nix run .#broker` in a
terminal; it takes over from the background broker and shows the log there.
When you end it, the VM has no way out until the next start.

Every host on the list is a place the agent can send data to, so add only
what a task needs.

## Changing the GitHub token

Change the command in `~/.config/nixt3/tokens.yaml`, or the secret it points
to, and restart the broker: `nix run .#stop` and `nix run .#vm`, or
`nix run .#broker` in a terminal while the VM keeps running. The broker reads
the token once, when it starts.

`tests/github-live.sh` checks the whole round trip from inside the VM: it
clones this repo, pushes a branch, opens a pull request, and removes both
again.

## Updating T3

The T3 server in the VM should be the same version as the T3 app on the Mac.
When the app updates, change the version and checksum in
[`vm/t3.nix`](../vm/t3.nix) and restart the VM. The checksum is the line for
`linux-arm64` in the release's `SHA256SUMS` file on GitHub.

## Problems

**A program in the VM reports "CONNECT tunnel failed, response 403".**
The broker refused the destination. `nix run .#logs` shows which host it was;
see "Allowing a destination" above.

**The VM does not start: "a token cannot be fetched".**
The broker needs the GitHub token and could not get it. The message says
which part is missing: the file `~/.config/nixt3/tokens.yaml`, the entry in
it, or the command. See "Before the first start" above. When the VM is
started in the background, the message is in `broker.log` in the state
folder.

**GitHub answers "Bad credentials" in the VM.**
The broker added the token it was given, and GitHub does not accept it. The
token has expired or been withdrawn, or the command in `tokens.yaml` prints
something else. Fix it on the Mac and restart the broker.

**A program in the VM is refused with "a token or password that is not this
sandbox's own".**
The request to GitHub carried a login other than the placeholder, for
example a token in a git address or in `GH_TOKEN`. The broker never passes
those on. Remove it; `git` and `gh` in the VM need no login of their own.

**A program in the VM reports a certificate error for GitHub.**
The VM trusts the broker's certificate only when it was started with
`nix run .#vm`, which hands the certificate over. If the broker's folder in
the state folder was deleted while the VM ran, restart the VM.

**`nix shell` or `nix run` fails inside the VM.**
Nix's download servers are not on the list of destinations. Add tools to
`environment.systemPackages` in `vm/default.nix` and restart the VM.

**The build stops with "a 'aarch64-linux' with features {} is required".**
The Linux builder is not on. Check that step 1 was applied:
`nix config show | grep builders` should show a value.
