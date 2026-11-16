# Architecture

A coding agent can be tricked by what it reads, or simply make a mistake. This
project gives it a machine of its own, so that a mistake stays inside that
machine and there is nothing in it worth stealing.

The work is done in phases, listed in [PLAN.md](../PLAN.md). This page
describes what runs today first, and the target design after it.

## What runs today

![The Mac, the agent VM inside it, the broker, and the internet](images/vm-today.svg)

| Part | Where | What it does |
| --- | --- | --- |
| T3 Code app | Mac | Where you start and follow threads. It is linked to the VM as a second environment. |
| Agent VM | Mac, in QEMU | A headless NixOS system, defined in [`vm/default.nix`](../vm/default.nix). |
| T3 server | VM | Receives threads from the app and starts Claude Code for each one. A system service, started at boot. |
| Claude Code | VM | The agent. It runs as the `agent` user, which has no `sudo`. |
| SSH server | VM | A shell for you, for signing in to Claude and for debugging. |
| Broker | Mac | A proxy that is the VM's only way out. It passes on the destinations listed in [`broker/rules.yaml`](../broker/rules.yaml) and refuses the rest. |
| State folder | Mac | `~/.local/state/agent-vm` holds the VM's disk, the SSH key that reaches it, and the broker's log. While the VM runs it also holds QEMU's control socket, which the stop command uses. |
| Linux builder | Mac | A small NixOS VM that builds Linux packages. It is needed to build the agent VM, and plays no part while the agent VM runs. |

### What crosses the line between the Mac and the VM

- **Into the VM:** two ports, both listening on the Mac's localhost only.
  Port 2222 leads to SSH and port 3774 leads to the T3 server.
- **Out of the VM:** one address, which leads to the broker. Nothing else:
  not the internet, not the Mac, not even a name server.
- **Not shared:** folders, the Mac's Nix store, and keys. The VM has its own
  copy of the Nix store and its own disk.

The only credential in the VM today is the Claude sign-in you do inside it.

### How the network lock works

1. **QEMU isolates the VM.** Its network runs in QEMU's restricted mode,
   which drops everything the VM sends except to forwards that are listed
   explicitly. This is enforced by QEMU on the Mac, so no program in the VM,
   not even one running as root, can lift it.
2. **One forward leads out.** Connections to `10.0.2.100:3128`, an address
   that exists only inside the VM, are handed to the broker on the Mac's
   `localhost:8474`.
3. **Programs are pointed at it.** The VM sets the usual proxy variables, so
   `curl`, `git`, `gh` and Claude Code send their requests to that address. A
   program that ignores the variables and connects directly gets no answer.
4. **The broker decides.** Each request names a host and a port. If
   `rules.yaml` lists them, the broker opens the connection; otherwise it
   answers `403 Refused by the sandbox broker` with a text that tells the
   agent why and what to ask you for.

The broker does not open the encrypted traffic it passes on. It checks that
the site named inside the encrypted connection is the one the request asked
for, because without that check an allowed site would also give access to
every other site hosted on the same servers.

If `rules.yaml` is missing or has a mistake, the broker refuses to start, and
the VM is not started without it. It never falls back to letting everything
through.

### Watching the traffic

The broker writes one line per decision to `broker.log` in the state folder:

```
2026-11-16T17:01:11+01:00 refused example.com 443 connect host-not-listed
2026-11-16T17:01:12+01:00 allowed github.com 443 connect
```

`nix run .#logs` follows it. Nothing from inside a request is logged: no
paths, no headers, no bodies.

### The clock

A locked VM cannot ask a time server, and its clock stops while the Mac
sleeps. The VM's hardware clock follows the Mac's, so the VM sets its system
clock from it every minute. A wrong clock would make HTTPS and sign-ins fail.

### How the VM gets its SSH key

No key is kept in this repo. The start command generates a key pair in the
state folder on first use and passes the public half to the VM on its kernel
command line. A service in the VM reads it at boot and tells the SSH server to
accept it. A public key is safe to pass this way; the private half never
leaves the Mac.

### How the VM is built and changed

1. `nix run .#vm` asks Nix for the VM described in this repo.
2. Nix hands the Linux parts to the Linux builder and gets back a system
   image and a start script.
3. The start script starts the broker, creates the disk on first use, and
   runs QEMU.

The system (programs, services, settings) comes from the repo on every start,
so a change to `vm/default.nix` takes effect after a restart. The disk is kept
between starts, and with it `/home/agent`: cloned repos, the Claude sign-in
and T3's data.

## What this does not protect against

- **An allowed destination is still a way out.** The agent can send data to
  any listed host, for example to someone else's repo on GitHub. The lock
  narrows where data can go; it does not stop it.
- **The Claude sign-in is in the VM.** A program in the VM can use it to talk
  to Anthropic as you. Claude's connectors to other services are not
  reachable, because their address is not on the list; keep it that way.
- **Programs on the Mac can use the broker's port.** Harmless today. Once the
  broker adds tokens, any local program could make requests with them.
- **A bug in the broker.** It is the one program on the Mac that reads what
  the VM sends, and it runs with your rights. Confining it is planned.
- **The Mac itself.** Everything here protects the Mac from the VM, not the
  VM's contents from the Mac.

## The target design

![The VM reaches the internet only through a broker that adds the keys](images/target.svg)

One thing changes from today: **the broker holds the keys.** For GitHub it
opens the request, checks it against `rules.yaml`, and swaps a placeholder
for the real token on the way out. The real token stays in 1Password. The
broker reads it once when it starts, which asks for Touch ID, and keeps it in
memory only.

The rules live on the Mac, outside the VM, so the agent cannot change them.
GitHub is the first service. Others can be added later as new rules.

## Where things are

| Path | Contents |
| --- | --- |
| [`flake.nix`](../flake.nix) | The entry point: the VM, the commands, and the Mac module |
| [`vm/default.nix`](../vm/default.nix) | The VM's system: services, tools, ports, the network lock |
| [`vm/t3.nix`](../vm/t3.nix) | The T3 server, pinned to a version |
| [`broker/rules.yaml`](../broker/rules.yaml) | The destinations the VM may reach |
| [`broker/proxy.py`](../broker/proxy.py) | The broker: a mitmproxy script that applies the rules |
| [`darwin/commands.nix`](../darwin/commands.nix) | The commands behind `nix run .#vm`, `.#stop`, `.#ssh` and the others |
| [`darwin/default.nix`](../darwin/default.nix) | What the Mac itself needs, as a nix-darwin module |
| [`tests/network-lock.sh`](../tests/network-lock.sh) | Checks run inside the VM by `nix run .#check` |
