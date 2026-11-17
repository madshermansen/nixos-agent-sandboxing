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
| Broker | Mac | A proxy that is the VM's only way out. It passes on the destinations listed in [`broker/rules.yaml`](../broker/rules.yaml) and refuses the rest. For GitHub it also puts the real token into each request. |
| State folder | Mac | `~/.local/state/agent-vm` holds the VM's disk, the SSH key that reaches it, and the broker's log. While the VM runs it also holds QEMU's control socket, which the stop command uses. |
| Linux builder | Mac | A small NixOS VM that builds Linux packages. It is needed to build the agent VM, and plays no part while the agent VM runs. |

### What crosses the line between the Mac and the VM

- **Into the VM:** two ports, both listening on the Mac's localhost only.
  Port 2222 leads to SSH and port 3774 leads to the T3 server.
- **Out of the VM:** one address, which leads to the broker. Nothing else:
  not the internet, not the Mac, not even a name server.
- **Not shared:** folders, the Mac's Nix store, and keys. The VM has its own
  copy of the Nix store and its own disk.
- **Handed to the VM at start:** two public values, the SSH public key and
  the broker's public certificate. Neither gives access to anything.

The only credential in the VM today is the Claude sign-in you do inside it.
The GitHub token is on the Mac; the VM holds a placeholder for it.

### How the network lock works

1. **QEMU isolates the VM.** Its network runs in QEMU's restricted mode,
   which drops everything the VM sends except to forwards that are listed
   explicitly. This is enforced by QEMU on the Mac, so no program in the VM,
   not even one running as root, can lift it.
2. **One forward leads out.** Connections to `10.0.2.100:3128`, an address
   that exists only inside the VM, are handed to the broker on the Mac's
   `localhost:8474`.
   QEMU runs a small helper (`socat`) on the Mac for each connection, which
   ends when either side closes, so the VM notices when the broker hangs up.
3. **Programs are pointed at it.** The VM sets the usual proxy variables, so
   `curl`, `git`, `gh` and Claude Code send their requests to that address. A
   program that ignores the variables and connects directly gets no answer.
4. **The broker decides.** Each request names a host and a port. If
   `rules.yaml` lists them, the broker opens the connection; otherwise it
   answers `403 Refused by the sandbox broker` with a text that tells the
   agent why and what to ask you for.

The broker does not open the encrypted traffic it passes on. It checks that
the site named at the start of the encrypted connection is the one the
request asked for, and refuses a connection that hides that name. This makes
it harder to reach other sites that share servers with an allowed one. It is
not a guarantee: what is sent later inside the encryption cannot be seen, so
how strict the separation is depends on the hosting company.

If `rules.yaml` is missing or has a mistake, the broker refuses to start, and
the VM is not started without it. It never falls back to letting everything
through.

### GitHub without a token in the VM

The agent has to push branches and open pull requests, which needs your
GitHub token. A token in the VM could be read by anything the agent runs, and
sent anywhere the VM can reach. So the token stays on the Mac, and the broker
adds it on the way out.

1. **The VM holds a placeholder.** `git` and `gh` in the VM log in with the
   fixed text `nixt3-placeholder-not-a-real-token`. It is public and gives no
   access.
2. **The broker opens GitHub's traffic.** The GitHub hosts in `rules.yaml`
   are marked `inspect: true`. For those, the broker ends the encrypted
   connection from the VM itself, reads each request, and sends it on over a
   new encrypted connection to GitHub. Every other destination, Anthropic
   among them, is still passed on unread.
3. **It swaps the placeholder for the token.** Where a request carries the
   placeholder as its login, the broker puts the real token there, in the
   form the request used: `git` sends a user name and password, `gh` sends a
   token header. A request without a login goes out without one.
4. **Any other login is refused.** If a request to GitHub carries a token or
   password that is not the placeholder, the broker answers 403 and nothing
   leaves. The alternative, removing the login and passing the request on,
   was rejected: an agent that has been handed someone's token by a web page
   should fail loudly and show up in the log, not carry on without one.
   Cookies are a login too; they are left out of the request, because
   nothing in the VM needs them and refusing them would break programs that
   merely keep the harmless ones.

The broker adds the token only when all of this holds:

- the request came in a tunnel that was opened for a GitHub host in the
  rules, over an encrypted connection that named that host;
- the request itself names that host and no other, so GitHub's servers
  cannot be made to hand it to a different site;
- it leaves over an encrypted connection to a server that has proved, with
  a valid certificate, to be that host.

Clear text sent inside a tunnel is refused for every destination, so a token
can never end up on an unencrypted connection.

**Where the token comes from.** `rules.yaml` is public, so it names the token
only as `github`. Where you keep it is in a file on your Mac, outside the
repo: `~/.config/nixt3/tokens.yaml` gives a command that prints it, such as
`op read …` for 1Password. The start command runs that command before the
broker starts and hands the result to the broker through a pipe, straight
into its memory. The token is never in a file, an environment variable, a
command line, a log, the Nix store or the VM. The broker itself runs no
programs. If the file, the entry or the command is missing or fails, the
broker does not start, and neither does the VM.

**How the VM comes to trust the broker.** To read GitHub's traffic the broker
has to answer the VM in GitHub's name. It signs those answers with a
certificate authority of its own, which mitmproxy creates in the state
folder on first start. The start command hands the authority's public
certificate to the VM through QEMU's `fw_cfg`, which gives a VM a small file
at start without a shared folder. A service in the VM adds it to the
certificates the system trusts, at every boot. The authority's private key
never leaves the Mac. The VM would accept that authority for any site, but
the broker uses it only for destinations marked `inspect: true`.

**Large pushes and clones.** The broker reads a request body only when it is
declared to be at most 1 MiB, so that later rules can look at it. Anything
larger, and every answer, is passed through piece by piece and never held in
memory. A refused request with a large body gets its connection closed
instead of an answer. Where the broker opens the traffic it speaks HTTP/1.1,
because there a request says up front whether a body follows.

**What the VM can make the broker hold in memory.** A hostile program in the
VM might try to fill the Mac's memory through the broker. Three limits bound
what it can achieve:

- *Bodies* are never collected beyond 1 MiB, as described above.
- *What comes before a request can be judged* is capped. The broker has to
  take in a request's first lines, or the first message of an encrypted
  connection, before it can decide anything. mitmproxy sets no limit there,
  so [`broker/limits.py`](../broker/limits.py) adds one from the outside:
  128 KiB of data that does not yet make up a request or an answer, and
  64 KiB for the first encrypted message. Beyond that the connection is
  closed. Because this changes mitmproxy's own code, the broker checks at
  start that mitmproxy is the exact version the change was written for, and
  refuses to start otherwise.
- *Connections* are capped at 256 at once.

Together that bounds the broker's memory at a few hundred megabytes in the
worst case, on top of what it uses when idle (about 100 MB). It does not
bound how much the VM can send *through* the broker to an allowed
destination; that is traffic, not memory.

**When the broker's own code fails.** mitmproxy calls the broker's code at
fixed points and, if that code stops with an error, carries on as if it had
agreed. For code whose job is to refuse, that would let things through. So
every such point is wrapped: an error nobody foresaw ends with the request
or connection refused and a `broker-error` line in the log, which names the
kind of error and where it arose, but not its message.

**Left out of requests to GitHub.** Besides cookies, the broker removes
headers by which a request claims to be something else than its first line
says: `X-HTTP-Method-Override` and its relatives, and `X-Forwarded-Host`,
`Forwarded` and the like. Nothing in the VM needs them, and a later rule
about a request's method or host should not be undone by a header. Requests
that ask to switch to another protocol (`Upgrade`, as WebSocket does) or
that carry lines after their body (trailers) are refused.

### Watching the traffic

The broker writes one line per decision to `broker.log` in the state folder:

```
2026-11-16T17:01:11+01:00 refused example.com 443 connect host-not-listed
2026-11-16T17:01:12+01:00 allowed github.com 443 connect
```

`nix run .#logs` follows it. For a destination that is passed on unread,
nothing from inside a request can be logged. For GitHub, which the broker
opens, each request gets a line with its method, its path without the query
string, and the status of the answer:

```
2026-11-16T17:01:13+01:00 allowed github.com 443 https POST /owner/repo.git/git-receive-pack 200
2026-11-16T17:01:14+01:00 refused api.github.com 443 https GET /user other-login
```

Headers, bodies and tokens are never logged. As a last safeguard,
everything the broker process writes, including what mitmproxy and Python
write by themselves when something fails, passes through a filter that
replaces the token before it reaches the log.

### The clock

A locked VM cannot ask a time server, and its clock stops while the Mac
sleeps. The VM's hardware clock follows the Mac's, so the VM sets its system
clock from it every minute. A wrong clock would make HTTPS and sign-ins fail.

### How the VM gets its SSH key and the broker's certificate

No key is kept in this repo. The start command generates a key pair in the
state folder on first use and passes the public half to the VM on its kernel
command line. A service in the VM reads it at boot and tells the SSH server to
accept it. A public key is safe to pass this way; the private half never
leaves the Mac.

The broker's public certificate is passed at start as well, through QEMU's
`fw_cfg`, because it is too long for the command line. See "GitHub without a
token in the VM" above.

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
- **Programs on the Mac can use the broker's port.** The broker adds the
  GitHub token for anyone who sends the placeholder, and the placeholder is
  public. So while the broker runs, any program on the Mac can act on GitHub
  with your token without asking 1Password.
- **Everything the token allows.** The agent can do on GitHub whatever the
  token can: push to any repo it reaches, change settings, read private
  repos. Until the limits of phase 5 exist, give the broker a token that is
  narrow by itself: a fine-grained token for the repos the agent works on.
- **The broker's certificate authority.** Its private key is in the state
  folder on the Mac. Whoever reads it can pose as any site towards the VM.
  Only the VM trusts it, not the Mac.
- **A connection that ends without an answer.** Some refusals cannot carry
  an explanation: a request with a large body, or an encrypted connection
  that names the wrong site, is simply closed. The program in the VM sees a
  failed connection within about a second, and the reason is only in the
  broker's log on the Mac.
- **Wearing out the Mac.** QEMU starts a small helper program on the Mac for
  each connection the VM opens. A program in the VM that opens thousands at
  once can use up the processes your account may run, and slow the Mac down
  until the VM is stopped.
- **A bug in the broker.** It is the one program on the Mac that reads what
  the VM sends, and it runs with your rights. Confining it is planned.
- **The Mac itself.** Everything here protects the Mac from the VM, not the
  VM's contents from the Mac.

## The target design

![The VM reaches the internet only through a broker that adds the keys](images/target.svg)

The central idea is that **the broker holds the keys.** For GitHub it
opens the request, checks it against `rules.yaml`, and swaps a placeholder
for the real token on the way out. The real token stays in 1Password. The
broker gets it once when it starts, which asks for Touch ID, and keeps it in
memory only.

The swap is built and described above. What is still to come is the
checking: a list of the repos the agent may use, and refusals for actions
such as changing a repo's settings.

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
| [`broker/swap.py`](../broker/swap.py) | The decisions about one opened request, among them the token swap |
| [`broker/fetch_tokens.py`](../broker/fetch_tokens.py) | Fetches the tokens before the broker starts |
| [`broker/limits.py`](../broker/limits.py) | Limits on what a connection may send before it makes sense, added to mitmproxy from the outside |
| [`broker/tokens.example.yaml`](../broker/tokens.example.yaml) | Example of the file on your Mac that says where each token is kept |
| [`darwin/commands.nix`](../darwin/commands.nix) | The commands behind `nix run .#vm`, `.#stop`, `.#ssh` and the others |
| [`darwin/default.nix`](../darwin/default.nix) | What the Mac itself needs, as a nix-darwin module |
| [`tests/network-lock.sh`](../tests/network-lock.sh) | Checks run inside the VM by `nix run .#check` |
| [`tests/github-broker.sh`](../tests/github-broker.sh) | Checks of the token swap, run on the Mac against a stand-in for GitHub |
| [`tests/github-live.sh`](../tests/github-live.sh) | The round trip with a real token: clone, push, pull request |
| [`tests/unit/`](../tests/unit) | Tests of the broker's decisions that need no network |
