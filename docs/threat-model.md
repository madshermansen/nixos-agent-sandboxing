# Threat model

This page is for someone deciding whether to trust nixt3 with their accounts.
It says what is protected, who the attacker is, what stops them, and what
does not stop them. The last part has the same weight as the rest. Read it
before you rely on this.

It describes the code on `main` after phase 4: the VM, the network lock, and
GitHub through the broker with the token kept on the Mac. The plan is in
[PLAN.md](../PLAN.md).

Two things are not finished, and each is described in one place below:

- The rules for what the agent may do on GitHub are written but not in use.
  See [GitHub rules: built, not yet enforced](#github-rules-built-not-yet-enforced).
- The check with a real GitHub token has not been run. See
  [What has not been run](#what-has-not-been-run).

## Words used on this page

| Word | Meaning here |
| --- | --- |
| Broker | The proxy on the Mac that is the VM's only way out. It is [`broker/proxy.py`](../broker/proxy.py), a script for the program mitmproxy. |
| TLS | The encryption that HTTPS uses. The first message of a TLS connection names the site in clear text; everything after it is encrypted. |
| Tunnel | What a program asks a proxy for when it wants HTTPS: "connect me to this host and pass on what I send". The proxy sees the host and the port, and then encrypted data. |
| Passed on unread | The broker lets the encrypted data of a tunnel through without opening it. This is what it does for Anthropic. |
| Opened | The broker ends the encryption itself, reads each request, and sends it on over a new encrypted connection. This is what it does for GitHub. |
| Certificate authority | A key that signs certificates. A program trusts a site when its certificate is signed by an authority the program trusts. The broker has one of its own, so that it can answer the VM in GitHub's name. |
| Placeholder | The fixed text `nixt3-placeholder-not-a-real-token`. Programs in the VM log in to GitHub with it. It is public and gives no access. |
| Fails closed | When something goes wrong, the answer is "no". A broker that fails closed refuses or does not start; it never lets everything through. |
| Domain fronting | Naming an allowed site at the start of an encrypted connection and asking for another site inside it, where a proxy cannot see. It works when both sites are served by the same company's machines. |

## The short version

- **Holds today:** a program in the VM cannot reach the Mac's files, the
  Mac's own services, your home network, or any host that is not on a list
  of five. It can use GitHub with your token without being able to read the
  token. `nix run .#check` and `tests/github-broker.sh` test most of this.
- **Does not hold:** the listed hosts are still a way to send data out. On
  GitHub the agent can do everything your token allows. The Claude sign-in
  is inside the VM and can be used or copied. Any program on the Mac can use
  the token through the broker's port. The broker and QEMU are ordinary
  programs on the Mac that run with your rights, and a bug in either is a
  way onto the Mac.
- **Not built yet:** a confined broker (phase 6).

## What is protected

| Thing | Where it is | What must not happen |
| --- | --- | --- |
| The Mac's files | The Mac's disk | The agent reads, changes or deletes them |
| The Mac's programs and services | The Mac, many on `localhost` | The agent talks to them or starts them |
| Your home or office network | Around the Mac | The agent reaches other machines on it |
| The GitHub token | Your password manager, and the broker's memory while it runs | The agent reads it, or gets it sent to a place of its choice |
| Your other tokens and keys | Keychain, 1Password, `~/.ssh`, `gh`'s own token | The agent reads them |
| Your accounts | GitHub, Claude, others | The agent acts as you beyond the task |
| The rules | [`broker/rules.yaml`](../broker/rules.yaml), on the Mac | The agent changes what it is allowed to reach |
| The tokens file | `~/.config/nixt3/tokens.yaml`, on the Mac | Someone changes it. It names a program that is run as you each time the broker starts. |
| The key of the broker's certificate authority | `broker/mitmproxy-ca.pem` in the state folder, on the Mac | It leaves the Mac. Whoever holds it can pose as any site towards the VM. |

**The contents of the VM are not protected from the attacker.** Assume the
attacker knows everything in the VM and can change all of it. One thing in
the VM is still worth something to them: the Claude sign-in. That is a known
loss, not something this design prevents. See
[The Claude sign-in is in the VM](#the-claude-sign-in-is-in-the-vm).

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
  Mac can read the VM's disk, the SSH key that opens the VM, the rules and
  the key of the broker's certificate authority. Everything here protects
  the Mac from the VM, not the VM from the Mac.
- **Someone with the Mac in their hands,** or another user account on it.
- **The services themselves.** A break-in at GitHub or Anthropic.
- **The supply chain of this project.** nixpkgs, QEMU, mitmproxy and the T3
  server are taken as they are. The T3 server is pinned by checksum in
  [`vm/t3.nix`](../vm/t3.nix); nixpkgs is pinned in `flake.lock`.
- **What the model provider sees.** What the agent reads is sent to
  Anthropic, with or without a sandbox.

## What the attacker can try, and what stops it

![The Mac, the agent VM inside it, the broker, and the internet](images/vm-today.svg)

The last column of each table says what proves the claim:

| Proof | Meaning |
| --- | --- |
| A name in quotes | A check in [`tests/network-lock.sh`](../tests/network-lock.sh), run inside the VM by `nix run .#check` |
| Mac test | A check in [`tests/github-broker.sh`](../tests/github-broker.sh). It runs a broker of its own on the Mac against a stand-in for GitHub, so it can see what the broker lets out. |
| By hand | Looked at once by hand. No check repeats it. |
| Nothing | The claim rests on reading the code |

All three were done on 2026-11-17, on `main` at commit `a0ad1a0`.
`nix run .#check` passed every check, `tests/github-broker.sh` passed all
103, and the 2139 unit tests in `tests/unit/` passed. "By hand" was done on
the running VM, which was the build of that commit. The token on the Mac was
a made-up one that day.

### Going around the broker

All of this is stopped in one place: QEMU's restricted network. The VM's
network card is not connected to the Mac's network. QEMU itself plays the
network, and with `restrict=on` it drops everything the VM sends except to
forwards that are listed. QEMU runs on the Mac, outside the VM, so no program
in the VM can turn this off, not even as `root`.

The setting is the `restrict=on` part of `qemu.networkingOptions` in
[`vm/default.nix`](../vm/default.nix). The whole network option is written
out there.

| The attacker tries | Proof |
| --- | --- |
| Connect straight to a site, ignoring the proxy settings | "a direct connection by name is blocked", "a direct connection by address is blocked" |
| The same over IPv6 | "a direct connection over IPv6 is blocked" |
| Look up names, or hide data in name lookups | "names cannot be looked up", "QEMU's own name server does not answer", "QEMU's own name server refuses connections", "a public name server is out of reach" |
| Reach the Mac itself, which the VM sees as `10.0.2.2` | "the Mac itself is out of reach" |
| Reach other machines on your network | Nothing. No check uses a home-network address. It is the same mechanism as the rows above. |
| Use SSH, or any protocol that is not HTTP | "SSH to GitHub is blocked" |
| Become `root` in the VM and remove the lock | Nothing. No check runs as `root`. |

### Going through the broker

One forward leads out of the VM. Connections to `10.0.2.100:3128`, an address
that exists only inside the VM, are handed to the broker on the Mac's
`localhost:8474`. It is the `guestfwd` part of the same network option.

| The attacker tries | What stops it | Proof |
| --- | --- | --- |
| Ask for a host that is not listed | `Broker.refusal` looks the host up in the rules and answers 403 | "a destination that is not listed is refused" |
| Ask for it over plain HTTP | The same check, in `requestheaders` | "plain HTTP is refused" |
| Ask for a listed host on another port | A host is allowed on port 443 only, unless its rule lists more | "an allowed host on another port is refused" |
| Open a tunnel to a listed host, then name another site at the start of the encryption | `tls_clienthello` compares that name with the tunnel's host | "a tunnel cannot be used for a different site"; on the Mac "the broker logged the wrong site name as refused" |
| Hide the real site name (Encrypted Client Hello) | `tls_clienthello` refuses a first message that carries a hidden name | Nothing |
| Start a tunnel inside a tunnel, or encryption inside an opened connection | `http_connect` and `tls_clienthello` refuse both | Nothing |
| Send something in a tunnel that is neither TLS nor HTTP | `rawtcp=false` in [`darwin/commands.nix`](../darwin/commands.nix) makes mitmproxy drop it | Nothing |
| Send plain HTTP inside a tunnel | `requestheaders` refuses it, for every destination | "clear text inside a tunnel to github.com is refused", and the same for `api.anthropic.com` |
| Name a listed host in the `Host` header and send to another | The broker checks where the request will really go, not the header | "plain HTTP to an unlisted host is refused, also when it names a listed one" |
| Use the broker to reach the Mac's `localhost` | Only listed names pass | "a tunnel to the Mac's own address is refused", "a tunnel to the Mac by the name localhost is refused" |
| Get `localhost` or an address onto the list | `load_rules` refuses a rule that is an address or a name without a dot | Nothing |
| Find any other path through mitmproxy | `server_connect` is a last gate. It runs before every connection the broker opens and refuses an unlisted one. | Nothing |
| Make the broker's own code fail, so that it lets a request through | Every point where mitmproxy calls the broker is wrapped (`fail_closed`). An error ends in a refusal. | Mac test: "When the broker's own code fails", for eight such points |

### Getting at the GitHub token

The token is not in the VM. Programs there log in with the placeholder, and
the broker puts the real token in its place on the way out. This is in
[`broker/swap.py`](../broker/swap.py) and `opened_request` in `proxy.py`.

| The attacker tries | What stops it | Proof |
| --- | --- | --- |
| Find the token in the VM | It was never put there | "gh's token in the VM is the placeholder", "git's password for GitHub in the VM is the placeholder", "no file in the VM holds something that looks like a GitHub token", and the same for programs' environments |
| Have the token sent to a site other than GitHub | A token is added only when the tunnel, the name at the start of the encryption and every name in the request are the GitHub host from the rules | "a request that names another site than its connection is refused"; Mac test: "a tunnel cannot be used under another name" |
| Pose as GitHub towards the broker | `server_connect` sets the name the server must prove, and mitmproxy checks the server's certificate against it. A broker started with that check off adds no token. | Nothing. No test uses a server with a wrong certificate. |
| Have the token sent without encryption | An opened destination is never contacted in clear text | Mac test: "clear text inside a tunnel is refused", "clear text sent to the broker directly is refused" |
| Ask GitHub to send the request back, token included (`TRACE`) | Refused | Mac test: "TRACE, which would send the token back, is refused" |
| Read the token in the broker's log | Headers are not logged. Everything the broker process writes also passes a filter that replaces the token. | Mac test: "the token is in no log and no file of the broker", "a token in a line that mitmproxy wrote is replaced" |
| Use another login on GitHub: a token of the attacker's own, or one found on a web page | Refused, not removed. Cookies are left out of the request. | "a request with any other token is refused by the broker"; Mac test: "another token is refused and never leaves", "a cookie is left out" |
| Hide a second login in a header that runs over two lines | A header with a line break is refused | Mac test: "a login on a continuation line", "a login after a lone carriage return" |
| Claim another method or host in a header such as `X-HTTP-Method-Override` | Such headers are left out | Mac test: "headers that claim another method or host are left out" |
| Switch the connection to another protocol, or send lines after the body | Refused | Mac test: "a request to switch to another protocol is refused", "a request that announces trailers is refused before anything is sent" |

What these rows do **not** say: which requests may go out with the token.
Today all of them do. See the next section but one.

### Filling the Mac's memory through the broker

| The attacker tries | What stops it | Proof |
| --- | --- | --- |
| Send a request whose first lines never end | [`broker/limits.py`](../broker/limits.py) closes a connection that has sent 128 KiB without making up a request | "a request that never ends is cut off by the broker"; Mac test: "More than the broker takes in" |
| Send a first TLS message that never ends | The same file allows 64 KiB | Mac test: "a first TLS message that never ends" |
| Send a body that never ends | A body is held in memory only when it is declared to be at most 1 MiB. A larger one is passed on in pieces, or cut off when the request is refused. | Mac test: "Large bodies" |
| Open very many connections | The broker holds at most 256 at once (`MAX_CLIENTS`) | Nothing |
| Run a mitmproxy that the limits do not fit | The broker does not start when mitmproxy's code differs from what `limits.py` was written for | Mac test: "the limits refuse to go into a mitmproxy they were not written for" |

This bounds the broker's memory. It does not bound how much the VM sends
*through* the broker to an allowed host.

### Changing the rules, or starting without them

| The attacker tries | What stops it | Proof |
| --- | --- | --- |
| Edit `rules.yaml` | It is on the Mac. Nothing on the Mac is shared with the VM. | "no folder is shared with the Mac" |
| Have the broker start with a rules file that is missing or wrong | `start` in `proxy.py` exits, and `nix run .#vm` then does not start the VM | Nothing. It cannot be tested from inside the VM, and no other test does. |
| Have the broker start without its token | `fetch_tokens.py` and `receive_tokens` stop the start | Mac test: "Starting without what it needs" |
| Slip a rule in through a typing mistake | `load_rules` rejects unknown keys, wildcards, addresses and a missing `note` | Nothing |
| Write false lines into the broker's log | `_clean` turns spaces and unprintable characters into `_` and `?`, and cuts a field at 255 characters | Nothing |

The rules the background broker uses are the repo's copy, fixed when the
command was built. A rules file named in the shell applies to
`nix run .#broker` only.

**Who holds the broker's port.** When `nix run .#vm` finds that something
already listens on `localhost:8474`, it goes on only if the file
`broker-foreground.pid` in the state folder names a live process whose
command line contains `mitmdump` or `agent-vm-broker-run`. That is a weak
test. It does not check that this process is the one holding the port, and it
is done once, at start. Nothing proves it.

### Reaching the Mac's files and keys

| The attacker tries | What stops it | Proof |
| --- | --- | --- |
| Read a shared folder | There is none. `sharedDirectories = lib.mkForce { }` removes the two exchange folders that a NixOS test VM has by default. | "no folder is shared with the Mac" shows that none is mounted. By hand: the running QEMU was given no shared-folder option, so none is offered either. |
| Read the Mac's Nix store | `useNixStoreImage = true` gives the VM a copy of only the packages it needs | By hand: `/nix/store` in the VM is a read-only disk image |
| Find a key in the VM that opens the Mac | The VM is handed two public values at start: the public half of its SSH key, and the public certificate of the broker's authority. The private halves stay on the Mac. | By hand: the kernel command line holds the public key only, and the certificate file in the VM holds no private key |
| Be handed the authority's private key by mistake | The start command, and the service in the VM, refuse a file that contains a private key | Nothing |
| Use your SSH keys through the SSH session | The SSH command offers only the VM's key and uses no SSH agent (`IdentitiesOnly=yes`, `IdentityAgent=none`) | Nothing. See also [SSH reads your own configuration](#ssh-reads-your-own-configuration). |
| Connect to the VM from another machine | The two ports that lead into the VM, 2222 for SSH and 3774 for T3, listen on the Mac's `127.0.0.1` only | By hand: the running QEMU binds both to `127.0.0.1` |

### Becoming root in the VM

The `agent` user is in no group that may use `sudo`, and SSH refuses `root`
and passwords. This is in `users.users.agent` and `services.openssh` in
`vm/default.nix`.

- **Proof:** "the agent user has no sudo". By hand: `su` with an empty
  password was refused.
- **What it is for:** it keeps a mistake from changing the system. It is
  **not** what protects the Mac. A bug in Linux that makes `agent` into
  `root` changes little: the lock is outside the VM.

## GitHub rules: built, not yet enforced

> **Update this section when the rules are put to use.** It is the one place
> on this page that describes their state.

[`broker/github_policy.py`](../broker/github_policy.py) decides which
requests to GitHub may go out: which repos, and which actions on them. It is
described in [github-rules.md](github-rules.md) and has its own tests in
`tests/unit/`.

**The broker does not call it yet.** The place where it will be called is the
method `policy` in `proxy.py`, which today allows every request. The rules
file also does not accept the `github:` part that page describes; a broker
given one does not start.

What this means today:

- **The agent can do on GitHub everything the token allows.** Push to any
  repo the token reaches, read private repos, change settings, write
  secrets, delete a repo, if the token may.
- **The token is the only limit.** Give the broker a fine-grained token for
  the repos the agent works on, with as few permissions as the work needs.
  [setup.md](setup.md) has the steps.

What changes when the rules are in use: a request to a repo that is not
listed, or for an action that is refused on every repo, does not leave the
Mac. [github-rules.md](github-rules.md) also lists what the rules will still
not see, such as what is inside a push.

## What does not stop them

### An allowed destination is a way out

The broker passes on these hosts: `api.anthropic.com`, `claude.ai`,
`platform.claude.com`, `github.com` and `api.github.com`. A program in the VM
can send anything it can read to any of them.

- **To Anthropic, with any account.** The three Anthropic hosts are passed on
  unread, so the broker cannot see whose account a request uses. The
  attacker can bring a key of their own and send data to their own account.
- **To GitHub, as you.** A login other than the placeholder is refused, so
  the attacker cannot use an account of their own there. They can use yours:
  anything the token may write to is a place to put data. If that place is
  public, so is the data.
- **A listed host can act for the VM.** The list limits which hosts the VM
  connects to. It does not limit where the data ends up after that.
  Anthropic's API has tools that run on Anthropic's machines; its
  [documentation](https://platform.claude.com/docs/en/agents-and-tools/tool-use/web-fetch-tool)
  says of the web fetch tool that "the API fetches the content during the
  request". GitHub can run Actions workflows when something is pushed.
  Either can pass data on to a third place. Neither was tried.
- **The site-name check is not a guarantee.** For a host that is passed on
  unread, the broker sees only the first message of the encrypted
  connection. What is sent later cannot be seen. How well a listed host is
  kept apart from other sites on the same machines depends on the hosting
  company. This is the "domain fronting" from the word list.

The lock limits *where* data can go. It does not stop data from going. What
limits the damage is that the VM holds little: the code you cloned into it,
and the Claude sign-in.

### The Claude sign-in is in the VM

You sign in to Claude inside the VM. The sign-in is a file in `/home/agent`
that the `agent` user owns, so the attacker can read it.

- The attacker can do whatever the sign-in allows on the listed Anthropic
  hosts, as you and on your plan.
- The attacker can copy the sign-in out through a listed host. Assume the
  copy then works from any machine until you revoke it. This was not tested.

About Claude's connectors to your other services:

- **Shown:** `mcp-proxy.anthropic.com` is not listed, and the broker refuses
  every host that is not listed. [CLAUDE.md](../CLAUDE.md) records that host
  as the one that leads to the connectors; this page did not check that.
- **Not shown:** that the three listed Anthropic hosts offer no other way to
  connectors, or to sessions that run on Anthropic's machines and have
  access of their own. Nothing in this repo tests that, either way.

Keep `mcp-proxy.anthropic.com` off the list. Where the sign-in should live is
an open decision; see [decisions.md](decisions.md).

### Any program on the Mac can use the token

The broker listens on `localhost:8474` and does not ask who connects. It
adds the token for anyone who sends the placeholder, and the placeholder is
public.

- While the broker runs, any program on the Mac can act on GitHub with your
  token, without asking your password manager.
- That includes a thread that runs on the Mac outside the VM. See
  [local-threads.md](local-threads.md).
- Nothing here prevents it. The VM cannot reach the port except through its
  one forward, which is the intended way.

### The broker runs with your rights

The broker is the one program on the Mac that reads what the VM sends. It is
mitmproxy, a large program, with about 1600 lines of this project's own code
in `proxy.py`, `swap.py` and `limits.py`. `limits.py` changes three of
mitmproxy's own functions while it runs. A bug that lets hostile input run
code would run it as you, with all your files and keys in reach, and with the
token in the same memory.

- **Today** nothing confines it.
- **Planned:** phase 6 confines it with macOS's own tools.
- The broker itself starts no programs. The token is fetched before it
  starts, by `fetch_tokens.py`, which reads nothing from the VM.

### The key of the broker's certificate authority

To open GitHub's traffic the broker signs certificates with an authority of
its own. The VM trusts that authority for every site, not only for GitHub.

- The broker uses it only for destinations marked `inspect: true`.
- The private key is a file in the state folder, readable by you. A program
  on the Mac that reads it can pose as any site towards the VM.
- The Mac does not trust this authority. Only the VM does.

### QEMU runs with your rights too

The whole design rests on QEMU keeping the VM inside. QEMU plays the VM's
disk, network card and other hardware, so it also reads what the VM sends. A
bug in QEMU that lets a program break out of the VM gives it your rights on
the Mac. Nothing in this repo tests for that or limits it.

### A start with extra QEMU options

The network option is fixed in `vm/default.nix`, and the start script no
longer reads `QEMU_NET_OPTS`. Two other ways in remain:

- The start script passes the variable `QEMU_OPTS` to QEMU.
- `nix run .#vm -- <options>` passes its arguments to QEMU.

Either can add a shared folder, or a second network card that is not
restricted. A program in the VM cannot set them. A value left over in your
shell can. Seen by hand in the generated start script on 2026-11-17.

### SSH reads your own configuration

`nix run .#ssh` starts `ssh` without `-F none`, so your `~/.ssh/config`
applies to the VM as well. Lines under `Host *` are the ones to look for:

- `RemoteForward` opens a port in the VM that leads back to the Mac.
- `SendEnv` sends variables from your shell into the VM.
- `ForwardAgent` offers your SSH agent to the VM. The command sets
  `IdentityAgent=none`; whether that also stops forwarding was not tested.

### Wearing out the Mac

- QEMU starts a small helper program (`socat`) on the Mac for each
  connection the VM opens. A program in the VM that opens thousands at once
  can use up the processes your account may run, until the VM is stopped.
  The broker's limit of 256 connections does not stop the helpers from being
  started.
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
  sandbox.
- **Code.** A branch the agent pushed is code from an untrusted place.
  Running it on the Mac without reading it undoes the sandbox.

### The attacker can stay

The programs in the VM come from a read-only image that is built from the
repo at every start. Everything else is kept: the disk that survives a
restart is the VM's whole root filesystem, not only `/home/agent`.

- As `agent`, a hostile program can leave something in `/home/agent` that
  runs again later: a shell startup file, a git hook, a Claude Code setting.
- As `root`, it can also change the parts of the disk that the system reads
  when it boots.

To be rid of it, stop the VM and delete the state folder, as in
[setup.md](setup.md). That also removes the Claude sign-in and the T3
pairing.

### The rules are only as good as their review

The rules and the broker are files in this repo, and the agent's test repo is
this repo. With a token that may push here, a branch from the agent can
change `broker/rules.yaml`, the broker itself or `vm/default.nix`. If such a
change is merged and the broker restarted, the lock is as wide as the change
made it. Read every change to `broker/`, `darwin/` and `vm/` before merging,
whoever wrote it. Protect `main` on GitHub.

### A refusal the agent cannot read

Some refusals carry no explanation: a request with a large body, or an
encrypted connection that names the wrong site, is closed without an answer.
The reason is in the broker's log on the Mac only. An agent may then try
other ways instead of stopping.

## What nothing proves

Every row above marked "Nothing", in one list:

- That other machines on your network are out of reach. No check uses such
  an address.
- That `root` in the VM cannot get around the lock.
- The refusal of a hidden site name, of a tunnel inside a tunnel, and of
  traffic that is neither TLS nor HTTP.
- That an address or `localhost` cannot be put on the list, and the other
  refusals of `load_rules`.
- The last gate in `server_connect`.
- That a server with a wrong certificate gets no token.
- The limit of 256 connections.
- That a rules file with a mistake stops the broker and the VM from starting.
- The cleaning of log lines.
- The test of who holds the broker's port, which is weak as well.
- That the start command and the VM refuse a private key in place of the
  certificate.
- That the SSH options keep your own keys out of the session.

And these, which no test can show:

- That QEMU and mitmproxy have no bug that matters here.
- That the T3 app handles hostile data from the VM's server safely.
- That a copied Claude sign-in is useless, or that connectors are out of
  reach by every route.

## What has not been run

- **The check with a real token.** [`tests/github-live.sh`](../tests/github-live.sh)
  clones, pushes a branch and opens a pull request from inside the VM. It
  needs a real token on the Mac and has not been run. On 2026-11-17 the
  token on the Mac was a made-up one.
- **What follows from that:** the swap itself is shown only against the
  stand-in on the Mac. `nix run .#check` says so in a note. The two searches
  for a token in the VM passed while no real token existed, so they have not
  yet had anything to find.

## How planned work changes this

| Work | Change | Effect on this page |
| --- | --- | --- |
| Phase 6 | The broker is confined with macOS's own tools | A bug in the broker reaches less of the Mac |
| Open decision | Where the Claude sign-in lives | If the broker attaches it, the VM holds no credential at all |

## What you can do

- Use a fine-grained GitHub token for the repos the agent works on, and
  protect `main` there.
- Keep the list in `rules.yaml` short. Every host is a way out.
- Put in the VM only the code the task needs.
- Stop the broker when you do not use the VM: `nix run .#stop`. The token is
  within reach of every program on the Mac only while it runs.
- Start the VM from a clean shell, without `QEMU_OPTS` set.
- Read what the agent produced before you run it on the Mac or merge it.
- Watch `nix run .#logs` now and then. A `refused` line for a host you do
  not know, or with the reason `other-login`, is worth a look.
- If you think the VM was taken over: stop it, delete the state folder,
  revoke the GitHub token, and revoke the Claude sign-in that was in the VM
  from your Claude account. The steps for the last were not checked for this
  page.
