# Threat model

This page is for someone deciding whether to trust nixt3 with their accounts.
It says what is protected, who the attacker is, what stops them, and what
does not stop them. The last part has the same weight as the rest. Read it
before you rely on this.

It describes the code on `main` after phase 3: the VM and the network lock.
Parts that are planned and not built are marked **planned**. The plan is in
[PLAN.md](../PLAN.md).

## The short version

- **Holds today:** a program in the VM cannot reach the Mac's files, the
  Mac's own services, your home network, or any host that is not on a list
  of five. `nix run .#check` tests most of this.
- **Does not hold:** the five listed hosts are still a way to send data out.
  The Claude sign-in is inside the VM and can be used or copied. The broker
  and QEMU are ordinary programs on the Mac that run with your rights, and a
  bug in either is a way onto the Mac.
- **Not built yet:** GitHub access without a token in the VM, limits on what
  the agent may do on GitHub, and a confined broker.

## What is protected

| Thing | Where it is | What must not happen |
| --- | --- | --- |
| The Mac's files | The Mac's disk | The agent reads, changes or deletes them |
| The Mac's programs and services | The Mac, many on `localhost` | The agent talks to them or starts them |
| Your home or office network | Around the Mac | The agent reaches other machines on it |
| Your tokens and keys | Keychain, 1Password, `~/.ssh`, `gh`'s own token | The agent reads them |
| Your accounts | GitHub, Claude, others | The agent acts as you beyond the task |
| The rules | [`broker/rules.yaml`](../broker/rules.yaml), on the Mac | The agent changes what it is allowed to reach |

What is **not** treated as worth protecting: the contents of the VM. Assume
that everything in the VM is known to the attacker, and that the attacker can
change all of it.

## The attacker

There are two ways to become the attacker. Both end in the same place.

1. **An agent that was tricked.** A coding agent reads web pages, issues,
   code and package files. Any of them can hold text that tells the agent to
   do something else. The agent then uses its own tools against you.
2. **A hostile program.** The agent installs or runs code that is hostile: a
   package, a build script, a test. It runs as the `agent` user in the VM.

In both cases the attacker is taken to have **full control of the `agent`
user in the VM**: every file in `/home/agent`, every program in the VM, and
the Claude sign-in stored there. The design also assumes the attacker may
become `root` in the VM. The network lock does not depend on stopping that.

### Out of scope

- **Someone who is already on the Mac.** A program that runs as you on the
  Mac can read the VM's disk, the SSH key that opens the VM and the rules.
  Everything here protects the Mac from the VM, not the VM from the Mac.
- **Someone with the Mac in their hands,** or another user account on it.
- **The services themselves.** A break-in at GitHub or Anthropic.
- **The supply chain of this project.** nixpkgs, QEMU, mitmproxy and the T3
  server are taken as they are. The T3 server is pinned by checksum in
  [`vm/t3.nix`](../vm/t3.nix); nixpkgs is pinned in `flake.lock`.
- **What the model provider sees.** What the agent reads is sent to
  Anthropic, with or without a sandbox.

## What the attacker can try, and what stops it

![The Mac, the agent VM inside it, the broker, and the internet](images/vm-today.svg)

The last column says what proves the claim. A name in quotes is a check in
[`tests/network-lock.sh`](../tests/network-lock.sh), run by
`nix run .#check`. "By hand" means it was tried once by hand and no check
repeats it. "Nothing" means the claim rests on reading the code.

### Going around the broker

All of this is stopped in one place: QEMU's restricted network. The VM's
network card is not connected to the Mac's network. QEMU itself plays the
network, and with `restrict=on` it drops everything the VM sends except to
forwards that are listed. QEMU runs on the Mac, outside the VM, so no program
in the VM can turn this off, not even as `root`.

The setting is `virtualisation.restrictNetwork = true` in
[`vm/default.nix`](../vm/default.nix).

| The attacker tries | What stops it | Proof |
| --- | --- | --- |
| Connect straight to a site, ignoring the proxy settings | QEMU drops it | "a direct connection by name is blocked", "a direct connection by address is blocked" |
| The same over IPv6 | QEMU drops it | "a direct connection over IPv6 is blocked" |
| Look up names, or hide data in name lookups | QEMU's built-in name server does not answer in restricted mode, and no other is in reach | "names cannot be looked up", "QEMU's own name server does not answer", "QEMU's own name server refuses connections", "a public name server is out of reach" |
| Reach the Mac itself, which the VM sees as `10.0.2.2` | QEMU drops it | "the Mac itself is out of reach" |
| Reach other machines on your network | QEMU drops it | Nothing tests a home-network address. It is the same mechanism as the rows above. |
| Use SSH, or any protocol that is not HTTP | QEMU drops it | "SSH to GitHub is blocked" |
| Become `root` in the VM and remove the lock | The lock is not in the VM | Nothing. No check runs as `root`. |

### Going through the broker

One forward leads out of the VM. Connections to `10.0.2.100:3128`, an address
that exists only inside the VM, are handed to the broker on the Mac's
`localhost:8474`. It is the one `from = "guest"` entry in `forwardPorts` in
[`vm/default.nix`](../vm/default.nix). The broker is
[`broker/proxy.py`](../broker/proxy.py), a script for mitmproxy.

| The attacker tries | What stops it | Proof |
| --- | --- | --- |
| Ask for a host that is not listed | `Broker.refusal` looks the host up in the rules and answers 403 | "a destination that is not listed is refused" |
| Ask for it over plain HTTP | The same check, in `requestheaders` | "plain HTTP is refused" |
| Ask for a listed host on another port | A host is allowed on port 443 only, unless its rule lists more | "an allowed host on another port is refused" |
| Open a tunnel to a listed host, then name another site inside it | `tls_clienthello` compares the name in the first TLS message with the tunnel's host | "a tunnel cannot be used for a different site", and on the Mac "the broker logged the wrong site name as refused" |
| Hide the real site name with Encrypted Client Hello | `tls_clienthello` refuses a first message that carries that part | Nothing |
| Send something in a tunnel that is neither TLS nor HTTP | `rawtcp=false` in [`darwin/commands.nix`](../darwin/commands.nix) makes mitmproxy drop it | Nothing |
| Put a listed host in the `Host` header and another host in the address | The broker checks where the connection will really go, not the header | By hand |
| Use the broker to reach the Mac's `localhost` or your network, by address | Only listed names pass. `load_rules` refuses a rule that is an address or a name without a dot, so `localhost` and `127.0.0.1` can never be listed | By hand: `127.0.0.1` and `localhost` were refused. Nothing in the check. |
| Find any other path through mitmproxy | `server_connect` is a last gate. It runs before every connection the broker opens and refuses an unlisted one | Nothing |
| Send a request that never ends, to fill the Mac's memory | The decision is made on the first lines, and `body_size_limit=1m` caps what is read | Nothing |
| Write false lines into the broker's log | `_clean` turns spaces and unprintable characters in a host name into `_` and `?`, and cuts it at 255 characters | Nothing |

"By hand" was done on 2026-11-16, from inside the VM, against the broker as
it was before the review fixes of phase 3.

### Changing the rules

| The attacker tries | What stops it | Proof |
| --- | --- | --- |
| Edit `rules.yaml` | It is on the Mac. Nothing on the Mac is shared with the VM | "no folder is shared with the Mac" |
| Make the broker start without rules | It fails closed. `start` in `proxy.py` exits when the file is missing or wrong, and `nix run .#vm` then does not start the VM | Nothing. It cannot be tested from inside the VM. |
| Have another program answer on the broker's port | `nix run .#vm` refuses to start when `localhost:8474` is held by a program that is not the broker | Nothing |
| Slip a rule in through a typing mistake | `load_rules` rejects unknown keys, wildcards, addresses and a missing `note` | Nothing |

The rules the background broker uses are the repo's copy, fixed when the
command was built. A rules file named in the shell applies to
`nix run .#broker` only.

### Reaching the Mac's files and keys

| The attacker tries | What stops it | Proof |
| --- | --- | --- |
| Read a shared folder | There is none. `sharedDirectories = lib.mkForce { }` removes the two exchange folders that a NixOS test VM has by default | "no folder is shared with the Mac". By hand: the running QEMU had no shared-folder option. |
| Read the Mac's Nix store | `useNixStoreImage = true` gives the VM a copy of only the packages it needs, read-only | By hand: `/nix/store` in the VM is a read-only disk image |
| Find a key in the VM that opens the Mac | No key of yours is put there. The VM gets only the **public** half of an SSH key made for it, on its kernel command line. The private half stays in the state folder on the Mac | By hand: the command line holds the public half only |
| Use your SSH keys through the SSH session | The SSH command in `darwin/commands.nix` offers only the VM's key and uses no SSH agent (`IdentitiesOnly=yes`, `IdentityAgent=none`) | Nothing |
| Find a GitHub token | None has been put in the VM | By hand: `gh auth status` reports no login. A search of the whole disk is **planned** as the check for phase 4. |
| Connect to the VM from another machine, to get in or to pass data | The two ports that lead into the VM, 2222 for SSH and 3774 for T3, listen on the Mac's `127.0.0.1` only | By hand: the running QEMU binds both to `127.0.0.1` |

### Becoming root in the VM

The `agent` user is in no group that may use `sudo`, and SSH refuses `root`
and passwords. This is in `users.users.agent` and `services.openssh` in
`vm/default.nix`.

- **Proof:** "the agent user has no sudo". By hand: `su` with an empty
  password was refused.
- **What it is for:** it keeps a mistake from changing the system. It is
  **not** what protects the Mac. A bug in Linux that makes `agent` into
  `root` changes little: the lock is outside the VM.

## What does not stop them

### An allowed destination is a way out

The broker passes on these hosts today: `api.anthropic.com`, `claude.ai`,
`platform.claude.com`, `github.com` and `api.github.com`. A program in the VM
can send anything it can read to any of them.

- **It does not need your account.** The broker does not open the encrypted
  traffic, so it cannot see whose account a request uses. The attacker can
  bring their own GitHub token or Anthropic key and upload to their own
  account.
- **The site-name check is not a guarantee.** The broker sees only the first
  message of an encrypted connection. What is sent later cannot be seen. How
  well a listed host is kept apart from other sites on the same servers
  depends on the hosting company.
- **What this means in practice:** the lock limits *where* data can go. It
  does not stop data from going. What limits the damage is that the VM holds
  little: the code you cloned into it, and the Claude sign-in.

**Planned:** in phase 4 the broker opens GitHub traffic, and in phase 5 it
limits which repos and actions are allowed. That narrows GitHub as a way
out. It does not close `api.anthropic.com`.

### The Claude sign-in is in the VM

You sign in to Claude inside the VM. The sign-in is a file in `/home/agent`
that the `agent` user owns, so the attacker can read it.

- The attacker can talk to Anthropic as you, on your plan.
- The attacker can copy the sign-in out through a listed host. Assume the
  copy then works from any machine until you revoke it. This was not tested.
- Claude's connectors to your other services are not reachable **from the
  VM**, because `mcp-proxy.anthropic.com` is not listed. Whether a copied
  sign-in can reach them from elsewhere is not known. Keep that host off the
  list either way.

Where the sign-in should live is an open decision; see
[decisions.md](decisions.md).

### Any program on the Mac can use the broker's port

The broker listens on `localhost:8474` and does not ask who connects.

- **Today** this gives a Mac program nothing it does not already have.
- **Planned:** once the broker attaches a GitHub token, any program on the
  Mac that connects to that port can make requests with it, within the rules.
  Nothing on this branch prevents that.

### The broker runs with your rights

The broker is the one program on the Mac that reads what the VM sends. It is
mitmproxy, a large program, with a script of about 330 lines. A bug in either
that lets hostile input run code would run it as you, with all your files and
keys in reach.

- **Today** nothing confines it.
- **Planned:** phase 6 confines it with macOS's own tools.
- The broker also holds a certificate authority in the state folder that it
  does not use yet. **Planned:** phase 4 uses it to open GitHub traffic. From
  then on the broker reads that traffic, and the VM must trust the broker's
  certificate.

### QEMU runs with your rights too

The whole design rests on QEMU keeping the VM inside. QEMU plays the VM's
disk, network card and other hardware, so it also reads what the VM sends. A
bug in QEMU that lets a program break out of the VM gives it your rights on
the Mac. Nothing in this repo tests for that or limits it.

### Wearing out the Mac

- QEMU starts a small helper program on the Mac for each connection the VM
  opens. A program in the VM that opens thousands at once can use up the
  processes your account may run, until the VM is stopped.
- The broker's log grows by one line per request and nothing trims it.
- The VM itself is bounded: 4 cores, 8 GB of memory and a 40 GB disk, set in
  `vm/default.nix`.

### What comes back from the VM

The lock controls what goes out of the VM. Things also come back to the Mac,
and nothing checks them:

- **Text on your screen.** The console, the SSH session and the T3 app show
  what the VM sends. The T3 server in the VM runs as `agent`, so the attacker
  controls what it tells the app. A bug in how the app or the terminal
  handles that data would be a way onto the Mac.
- **Work handed back to an agent on the Mac.** With `t3 environment link`, an
  agent on the Mac can give work to the VM and read the answer. That answer
  can hold text meant to trick the agent on the Mac, which is not in a
  sandbox. See [local-threads.md](local-threads.md).
- **Code.** A branch the agent pushed is code from an untrusted place.
  Running it on the Mac without reading it undoes the sandbox.

### The attacker can stay

The system part of the VM is built again from the repo at every start. The
disk is kept, and with it `/home/agent`. A hostile program that got in once
can leave something there that runs again later, such as a shell startup
file, a git hook or a Claude Code setting.

To be rid of it, stop the VM and delete the state folder, as in
[setup.md](setup.md). That also removes the Claude sign-in and the T3
pairing.

### The rules are only as good as their review

The rules are a file in this repo. **Planned:** from phase 4 the agent may
push branches to this repo. A branch can change `broker/rules.yaml` or the
broker itself. If such a change is merged and the broker restarted, the lock
is as wide as the change made it. Read every change to `broker/` and
`vm/default.nix` before merging, whoever wrote it.

## What nothing proves

These claims are made above and no check covers them:

- That a rules file with a mistake stops the broker and the VM from starting.
- The refusals for a hidden site name and for traffic that is neither TLS
  nor HTTP.
- The memory cap and the cleaning of log lines.
- That the broker cannot be used to reach the Mac's `localhost`. It was tried
  by hand only.
- That `root` in the VM cannot get around the lock.
- That QEMU and mitmproxy have no bug that matters here.
- That the T3 app handles hostile data from the VM's server safely.

## How planned work changes this

| Phase | Change | Effect on this page |
| --- | --- | --- |
| 4 | The broker opens GitHub traffic and attaches a token kept in 1Password | The agent can push and open pull requests without holding a token. The broker's port and the broker itself become worth more to an attacker. |
| 5 | Rules for which repos and actions are allowed | GitHub becomes a narrower way out |
| 6 | The broker is confined with macOS's own tools | A bug in the broker reaches less of the Mac |
| Open | Where the Claude sign-in lives | If the broker attaches it, the VM holds no credential at all |

## What you can do

- Keep the list in `rules.yaml` short. Every host is a way out.
- Put in the VM only the code the task needs.
- Read what the agent produced before you run it on the Mac or merge it.
- Watch `nix run .#logs` now and then. A `refused` line for a host you do
  not know is worth a look.
- If you think the VM was taken over: stop it, delete the state folder, and
  revoke the Claude sign-in that was in it from your Claude account. The
  steps for that were not checked for this page.
