# Decisions

A log of the choices made in this project: what was chosen, what was not, and
why. It is here so that nobody has to guess later, or argue a settled point
again without knowing the first reason.

How to read an entry:

- **Chosen** is what the project does.
- **Not chosen** is what was considered, or the obvious other way.
- **Why** is the reason that was given at the time. Where no reason was
  written down, it says "reason not recorded" instead of guessing.
- **Where** points at the code, or at the page that recorded it. "This page"
  means the reason was agreed in conversation and is written down here first.

Entries marked **planned** describe code that is not on `main` yet. An entry
marked **inferred** gives a reason that fits the code but is written down
nowhere. Add a new entry when a decision is made; do not rewrite old ones,
add a note to them.

This page describes `main` after phase 4. Words such as "tunnel", "opened"
and "fails closed" are explained in the word list at the top of
[threat-model.md](threat-model.md#words-used-on-this-page).

## The shape of the sandbox

### A QEMU virtual machine, not a Docker container

- **Chosen:** the agent runs in a NixOS VM started with QEMU.
- **Not chosen:** a Docker container on the Mac.
- **Why:**
  - On a Mac, Docker runs its containers inside a Linux VM of its own, so a
    container does not avoid a VM. It adds a layer on top of one.
  - Docker Desktop shares `/Users` and some other folders with that VM by
    default, so the home folder is one mount option away from a container.
    Here nothing is shared.
  - Containers share one kernel with each other.
  - The network lock relies on QEMU dropping the VM's traffic from outside
    the guest. See "The network is locked by QEMU" below.
- **Also said:** a quick throwaway environment is better served by a
  temporary disk for the VM than by a container. That is not built.
- **Where:** this page. Docker's default is from
  [Docker's settings page](https://docs.docker.com/desktop/settings-and-maintenance/settings/).

### The VM is headless

- **Chosen:** no screen and no desktop. You reach the VM through T3, through
  SSH, and through the console in the terminal that started it.
- **Not chosen:** a VM with a graphical desktop.
- **Why:** reason not recorded.
- **Where:** `virtualisation.graphics = false` in
  [`vm/default.nix`](../vm/default.nix).

### The console logs in as `agent` by itself

- **Chosen:** the terminal that runs `nix run .#vm` becomes a shell in the
  VM, logged in as `agent`, without a password.
- **Not chosen:** a login prompt.
- **Why:** reason not recorded. The account has no password to type.
- **Where:** `services.getty.autologinUser` in `vm/default.nix`.

### Nothing is shared with the Mac

- **Chosen:** no shared folders, and the VM gets its own copy of the Nix
  store as a disk image.
- **Not chosen:** the defaults of NixOS's VM module. They mount the Mac's
  whole Nix store into the VM and add two writable exchange folders.
- **Why:** a mistake should stay inside the VM, so nothing on the Mac is
  shared with it. Files go in and out through git, and through SSH when
  needed. Why the Nix store is copied, more than that: reason not recorded.
- **Cost:** the store image is built at every start, and tools cannot be
  added without a restart.
- **Where:** `useNixStoreImage` and `sharedDirectories = lib.mkForce { }` in
  `vm/default.nix`; the rule in [CLAUDE.md](../CLAUDE.md).

### The `agent` user has no `sudo`

- **Chosen:** the agent's account cannot become `root`. Tools are added to
  `environment.systemPackages` in the repo.
- **Not chosen:** letting the agent install what it needs.
- **Why:** recorded only in part. The locked network keeps Nix from
  downloading packages anyway, so tools have to come from the repo. Why the
  account has no `sudo` at all: reason not recorded.
- **Where:** `users.users.agent` in `vm/default.nix`.

### The system comes from the repo at every start, the disk is kept

- **Chosen:** programs come from a read-only image that is built from the
  repo each time. The VM's root disk survives restarts.
- **Not chosen:** rebuilding the system inside the running VM, or a VM that
  forgets everything.
- **Why:** reason not recorded. The effect is that cloned repos, the Claude
  sign-in and the T3 pairing survive a restart, and that a change to the
  system needs one.
- **Note:** what is kept is the whole root filesystem, not only
  `/home/agent`. See "The attacker can stay" in
  [threat-model.md](threat-model.md).
- **Where:** `NIX_DISK_IMAGE` in
  [`darwin/commands.nix`](../darwin/commands.nix);
  [architecture.md](architecture.md).

## The network lock

### The network is locked by QEMU, not by a firewall in the VM

- **Chosen:** QEMU's restricted mode drops everything the VM sends, except to
  listed forwards. One forward leads out, to the broker.
- **Not chosen:** a firewall inside the VM, or proxy settings alone.
- **Why:** QEMU enforces it from outside the VM, so nothing inside can lift
  it, not even `root`. Proxy settings alone are only a request: a program can
  ignore them.
- **Where:** `restrictNetwork` and `forwardPorts` in `vm/default.nix`.

### The VM's network is written out as one QEMU option

- **Chosen:** `vm/default.nix` gives QEMU its whole network option, with the
  three forwards in it. The helper that carries each connection to the
  broker is `socat`.
- **Not chosen:** NixOS's `forwardPorts`, which would run `nc` as the helper
  and read more options from the variable `QEMU_NET_OPTS`.
- **Why:**
  - `nc` does not tell the VM when the broker closes a connection. A program
    whose request was refused then waited until its own time limit, or
    forever. `socat` ends when either side closes.
  - No network option is read from the shell, so a variable left over there
    cannot add a forward.
- **Not covered:** `QEMU_OPTS` and the arguments of `nix run .#vm` still
  reach QEMU. Whether they should is not decided. See
  [threat-model.md](threat-model.md).
- **Where:** `qemu.networkingOptions` in `vm/default.nix`.

### The way out is a proxy that decides per request

- **Chosen:** a broker on the Mac that passes on listed destinations and
  refuses the rest with a `403` that says why.
- **Not chosen:** forwarding fixed addresses of the allowed services.
- **Why:** the refusal text tells the agent what happened and what to ask
  for, so it does not retry or look for a way around. The broker is also
  where the GitHub token is attached. Why not fixed forwards: reason not
  recorded.
- **Where:** [`broker/proxy.py`](../broker/proxy.py); [PLAN.md](../PLAN.md).

### The broker is a mitmproxy script

- **Chosen:** mitmproxy, with the rules applied by a Python script.
- **Not chosen:** another proxy, or one written for this project.
- **Why:** reason not recorded. The plan needed a proxy that can open GitHub
  traffic, which mitmproxy does since phase 4. The plan lists it as a risk
  that this may be slow or fragile for large pushes; the fallback there is a
  narrow GitHub token in the VM. Large pushes and clones were tried against
  a stand-in on the Mac (`tests/github-broker.sh`), not yet against GitHub
  with a real token.
- **Where:** PLAN.md, "Risks to check early".

### Only GitHub's traffic is opened

- **Chosen:** a destination marked `inspect: true` is opened: the broker
  ends the encryption itself and reads each request. Only the two GitHub
  hosts are marked. Every other destination is passed on unread; for those
  the broker checks only the site name in the first message.
- **Not chosen:** opening all traffic, or none.
- **Why:**
  - GitHub has to be opened so that the broker can put the token in.
  - Anthropic is not opened because "the broker has no business reading what
    is said to the model, and Claude Code logs in by itself".
  - The rule in `rules.yaml` is to open a destination only when the broker
    has to act on what is sent.
- **Cost:** for a destination that is passed on unread, the broker cannot
  see what is sent or whose account is used. See
  [threat-model.md](threat-model.md).
- **History:** in phase 3 nothing was opened.
- **Where:** the comments in [`broker/rules.yaml`](../broker/rules.yaml).

### Opened traffic is read as HTTP/1.1 only

- **Chosen:** where the broker opens the traffic, it speaks HTTP/1.1 with
  the VM. HTTP/2 is turned off there.
- **Why:** in HTTP/1.1 a request says in its first lines whether a body
  follows and how long it is. The broker relies on that to decide before it
  reads a body. In HTTP/2 a request need not say.
- **Where:** `http2=false` in `darwin/commands.nix`; `refuse` in
  `broker/proxy.py`.

### A hidden site name and traffic that is not HTTP are refused

- **Chosen:** the broker refuses an encrypted connection whose first message
  carries a second, hidden site name (Encrypted Client Hello). It drops
  traffic in a tunnel that is neither TLS nor HTTP, and it refuses plain
  HTTP inside a tunnel.
- **Not chosen:** passing on what it cannot read.
- **Why:**
  - Hidden name: "the name it did read proves nothing".
  - Plain HTTP in a tunnel: the broker would pass it on unencrypted, to a
    port that was allowed for encrypted traffic.
  - Traffic that is neither: reason not recorded.
- **Where:** `tls_clienthello` and `requestheaders` in `broker/proxy.py`;
  `rawtcp=false` in `darwin/commands.nix`.

### Rules name exact hosts

- **Chosen:** one exact host name per rule, port 443 unless the rule lists
  others, and a required `note` saying why. No wildcards, no addresses, no
  names without a dot. An unknown key is an error. Two more keys, `inspect`
  and `token`, are described under "Only GitHub's traffic is opened".
- **Not chosen:** wildcards such as `*.github.com`, or ignoring what the
  broker does not understand.
- **Why:**
  - Every listed host is a place data can be sent, so each one should be a
    choice.
  - The note is required so that nobody has to guess later whether an entry
    can be removed.
  - An unknown key stops the broker so that a typing mistake cannot quietly
    change what a rule means.
  - Addresses and short names are refused. **Inferred:** so that `localhost`
    and the Mac's own addresses can never be listed. The code says only that
    a real host name has a dot and does not end in a number.
- **Where:** [`broker/rules.yaml`](../broker/rules.yaml) and `load_rules` in
  `broker/proxy.py`.

### The broker fails closed

- **Chosen:** the broker refuses, or does not start, whenever something is
  wrong:
  - a rules file that is missing or has a mistake;
  - a token that the rules ask for and that cannot be fetched;
  - a mitmproxy whose code is not what `limits.py` was written for;
  - an error in the broker's own code while it decides about a request.
  When the broker does not start, the VM is not started. The VM is also not
  started when another program holds the broker's port.
- **Not chosen:** starting with no rules, or carrying on after an error.
- **Why:**
  - A proxy without rules lets everything through.
  - mitmproxy, when the broker's code stops with an error, carries on as if
    the code had agreed. For code whose job is to refuse, that means letting
    things through.
  - A program that is not the broker would become the VM's way out, with
    rules nobody chose.
- **Where:** `start` and `fail_closed` in `broker/proxy.py`; `brokerStart`
  in `darwin/commands.nix`.

### Rules are fixed when the command is built

- **Chosen:** the broker reads the repo's copy of the rules, once, at start.
  A rules file named in the shell applies to `nix run .#broker` only.
- **Not chosen:** reading the file again while running, or from a path that
  can be changed later.
- **Why:** a file left over from an experiment must not quietly replace the
  repo's rules. Why the rules are not read again while running: reason not
  recorded.
- **Where:** `brokerRun` and `brokerStart` in `darwin/commands.nix`.

### The log holds little

- **Chosen:** one line per decision: time, event, host, port, how, reason.
  For a request to an opened destination also the method, the path without
  its query string, and the status of the answer. No headers, no bodies, no
  tokens. Everything the broker process writes passes a filter that replaces
  the token.
- **Not chosen:** logging whole requests.
- **Why:**
  - The query string is left out because it "can hold search words and other
    things that are nobody's business".
  - The filter is there because mitmproxy and Python write to the same log
    by themselves when something fails, and those lines do not pass the
    broker's own code.
  - Why nothing more is logged: reason not recorded.
- **Where:** `log` and `scrub_output` in `broker/proxy.py`; `split_path` in
  `broker/swap.py`.

### Claude's connectors stay off the list

- **Chosen:** `mcp-proxy.anthropic.com` is not an allowed destination.
- **Why:** CLAUDE.md records that it leads to the connectors of the
  signed-in Claude account, which would give the agent your other services.
- **Not shown:** that the listed Anthropic hosts offer no other way to
  connectors. See [threat-model.md](threat-model.md).
- **Where:** [CLAUDE.md](../CLAUDE.md).

### Every port on the Mac listens on localhost only

- **Chosen:** the broker's port and the two ports that lead into the VM are
  bound to `127.0.0.1`.
- **Not chosen:** listening on all of the Mac's addresses.
- **Why:** only programs on this Mac should be able to connect.
- **Note:** the T3 server inside the VM listens on `0.0.0.0`. That is because
  QEMU delivers a forwarded connection to the VM's network address, not to
  its loopback. It does not open the server to your network.
- **Where:** `forwardPorts` in `vm/default.nix`; `--listen-host` in
  `darwin/commands.nix`.

## Keys and sign-ins

### The VM's SSH key is passed on the kernel command line

- **Chosen:** the start command makes a key pair on the Mac on first use and
  gives the VM the public half as a kernel parameter. A service in the VM
  reads it at boot.
- **Not chosen:** a key in the repo, or a key copied onto the VM's disk.
- **Why:** so that no key is kept in the repo. A public key is safe to pass
  this way; the private half never leaves the Mac.
- **Where:** `host-ssh-key` in `vm/default.nix`; `vm` in
  `darwin/commands.nix`.

### SSH does not remember the VM's host key

- **Chosen:** the SSH command skips the host key check, offers only the VM's
  key and uses no SSH agent.
- **Why:** the VM gets a new host key whenever its disk is made again, and it
  is reachable on localhost only. Why no agent is used: reason not recorded.
- **Where:** `ssh` in `darwin/commands.nix`.

### No GitHub token was ever put in the VM

- **Chosen:** phase 2 was done without the temporary GitHub token that the
  first plan gave it.
- **Not chosen:** a temporary token in the VM until the broker could attach
  one.
- **Why:** reason not recorded.
- **Where:** the status section of CLAUDE.md.

### The VM logs in with a placeholder, and the broker swaps it

- **Chosen:** `git` and `gh` in the VM log in to GitHub with a fixed, public
  text. The broker puts the real token in its place on the way out.
- **Not chosen:** a token in the VM, even a narrow one. The plan keeps that
  as the fallback if opening GitHub's traffic proves too fragile.
- **Why:** the VM can use the token without ever holding it. A token in the
  VM could be read by anything the agent runs, and sent anywhere the VM can
  reach.
- **Where:** [`broker/swap.py`](../broker/swap.py); `githubPlaceholder` in
  `vm/default.nix`; [architecture.md](architecture.md).

### Another login is refused, not removed

- **Chosen:** a request to GitHub with a token or password that is not the
  placeholder gets a 403. Cookies are left out of the request and the
  request goes on.
- **Not chosen:** removing the other login and passing the request on.
- **Why:**
  - An agent may have been handed a login by something it read, with
    instructions to push somewhere with it. Removing the login would hide
    that. Refusing makes the attempt fail loudly and shows up in the log.
  - Cookies are left out, not refused, because nothing in the VM needs
    GitHub's cookies and a program that merely keeps the harmless ones
    should still work.
- **Where:** `swap_authorization` in `broker/swap.py`; `pass_on` in
  `broker/proxy.py`; the status section of CLAUDE.md.

### The GitHub token is kept in a password manager

- **Chosen:** the token stays in your password manager. The example and the
  setup page use 1Password.
- **Not chosen:** the macOS Keychain, a file, a Nix file.
- **Why:** other programs on the Mac cannot read it silently from 1Password,
  which they could from the Keychain. The Nix store is ruled out because
  every program on the Mac can read it.
- **Cost:** one Touch ID prompt each time the broker starts.
- **State:** built. On 2026-11-17 no real token had been made yet; the Mac
  held a made-up one.
- **Where:** PLAN.md, "Decisions";
  [`broker/tokens.example.yaml`](../broker/tokens.example.yaml).

### A file on the Mac names the command that prints the token

- **Chosen:** `rules.yaml` names a token only by a short name, such as
  `github`. A file outside the repo, `~/.config/nixt3/tokens.yaml`, gives
  the command that prints it.
- **Not chosen:** naming the command, or the place the token is stored, in
  `rules.yaml`. That was the first plan.
- **Why:** `rules.yaml` is public and the same for everyone. Where you keep
  a token is yours to decide. Someone else can use a different store without
  changing the broker or the repo.
- **Where:** `broker/tokens.example.yaml`; PLAN.md, "Decisions".

### The token is fetched before the broker starts, and handed over on a pipe

- **Chosen:** a separate program, `fetch_tokens.py`, runs the command and
  writes the token into a pipe that the broker inherits. The broker itself
  starts no programs.
- **Not chosen:** the broker asking the password manager itself, or the
  token in an environment variable or a file.
- **Why:**
  - The broker reads everything the VM sends, so it is the part most likely
    to be attacked. It is to be confined so that it cannot run other
    programs.
  - An environment variable can be read by other programs of the same user,
    and so can a file.
- **Where:** the top of [`broker/fetch_tokens.py`](../broker/fetch_tokens.py);
  `receive_tokens` in `broker/proxy.py`.

### A fine-grained token for chosen repos

- **Chosen:** a fine-grained GitHub token limited to chosen repos.
- **Not chosen:** the broad token that `gh` on the Mac already holds, and,
  for now, a GitHub App.
- **Why:** it is limited to the chosen repos, where the token `gh` holds is
  broad. Why not a GitHub App yet: reason not recorded.
- **State:** this is advice in [setup.md](setup.md). The broker takes any
  token. No real token had been made on 2026-11-17.
- **Where:** this page; setup.md.

### The broker's certificate reaches the VM through `fw_cfg`

- **Chosen:** the public certificate of the broker's authority is given to
  the VM at start through QEMU's `fw_cfg`, which hands a VM a small file.
- **Not chosen:** the kernel command line, a shared folder, or a certificate
  built into the VM.
- **Why:** a certificate is too long for the command line, and `fw_cfg`
  needs no shared folder. Why it is not built into the VM: reason not
  recorded. mitmproxy creates the authority on the Mac on first start, so it
  differs per Mac.
- **Where:** `vm` in `darwin/commands.nix`; `broker-ca` in `vm/default.nix`.

### git in the VM turns SSH addresses into HTTPS

- **Chosen:** git rewrites `git@github.com:` and `ssh://` addresses to
  `https://github.com/`.
- **Why:** GitHub goes through the broker, which can only read HTTPS.
- **Where:** `programs.git` in `vm/default.nix`.

### Limits are put into mitmproxy from the outside

- **Chosen:** `limits.py` replaces three of mitmproxy's own functions while
  it runs, to cap what a connection may send before it makes sense. It first
  compares a checksum of each function with the one it was written for.
- **Not chosen:** leaving the gap, or a changed copy of mitmproxy.
- **Why:** mitmproxy has no setting for these limits, and without them a
  program in the VM can fill the Mac's memory. The checksum is there because
  a limit that silently stopped working after an update would be worse than
  a broker that does not start. Why not a changed copy: reason not recorded.
- **Where:** the top of [`broker/limits.py`](../broker/limits.py).

### Which GitHub requests go out: allowed if known

> **Update this entry when the rules are put to use.** It is the one place
> on this page that describes their state.

- **Chosen:** a request to GitHub goes out only when the broker recognises
  it as a kind that is allowed, for a repo that is listed. Everything else
  is refused, including harmless requests nobody thought of.
- **Not chosen:** refusing only what is known to be bad.
- **Why, and the choices inside it:** see [github-rules.md](github-rules.md).
- **State:** built in `broker/github_policy.py` with its own tests, and
  **not yet enforced**. The broker does not call it; today every request
  with the placeholder goes out with the token.
- **Where:** [github-rules.md](github-rules.md); `policy` in
  `broker/proxy.py`.

### The Claude sign-in lives in the VM (open)

- **For now:** you sign in to Claude inside the VM, and the sign-in is kept
  on its disk.
- **The other way:** the broker attaches it, as it does for the GitHub token.
- **Why it is open:** Claude Code needs a credential too. It is either the
  one credential held in the VM, or one more thing the broker holds. Not
  decided.
- **Where:** PLAN.md, "Open decisions".

### GitHub is the only service for now

- **Chosen:** the broker is built for GitHub first. No cloud provider keys.
- **Why:** reason not recorded, beyond that other services can be added later
  as new rules.
- **Where:** PLAN.md, "Goal".

## The Mac side

### The broker is a plain process, not a container

- **Chosen:** the broker runs as an ordinary program on the Mac. It is to be
  confined with macOS's own tools in phase 6 (planned).
- **Not chosen:** putting the broker in a container.
- **Why:** on a Mac a container means a second VM, and the broker could then
  no longer ask 1Password for the token.
- **Where:** PLAN.md, "Decisions".

### Everything about the VM lives in this repo

- **Chosen:** the VM, the broker, the rules and what the Mac itself needs are
  in one repo. The Mac's part is a nix-darwin module in `darwin/`. A personal
  configuration only imports it.
- **Not chosen:** keeping the Mac's part in a personal configuration.
- **Why:** the parts are versioned together, and others can reuse them.
- **Where:** PLAN.md, "The repo"; [`darwin/default.nix`](../darwin/default.nix).

### State lives outside the repo

- **Chosen:** the disk, the SSH key, the log and the process files are in
  `~/.local/state/agent-vm`, readable by you only.
- **Why:** reason not recorded.
- **Where:** the comment at the top of `darwin/commands.nix`.

### The VM is stopped through QEMU's control socket

- **Chosen:** `nix run .#stop` presses the VM's power button through the
  control socket. If the VM is still running after a minute, QEMU is told to
  quit.
- **Not chosen:** ending the QEMU process, or letting the agent power the VM
  off.
- **Why:** the system shuts down cleanly. A second QEMU process on the Mac is
  the Linux builder, so nothing may stop QEMU by name.
- **Where:** `stop` in `darwin/commands.nix`; CLAUDE.md.

## Inside the VM

### The T3 server is installed untouched and run through nix-ld

- **Chosen:** the prebuilt Linux program from T3's release is copied in as it
  is, pinned by version and checksum. `nix-ld` lets NixOS run it.
- **Not chosen:** patching the program to fit NixOS, or building it from
  source.
- **Why:** rewriting such a program can break it.
- **Where:** [`vm/t3.nix`](../vm/t3.nix); PLAN.md, "Risks to check early".

### The clock is set from the hardware clock every minute

- **Chosen:** a timer sets the system clock from the VM's hardware clock,
  which follows the Mac's clock.
- **Not chosen:** a time server.
- **Why:** the locked VM cannot reach a time server, and its clock stops
  while the Mac sleeps. A wrong clock makes HTTPS and sign-ins fail.
- **Where:** `clock-from-host` in `vm/default.nix`.

### The agent is told that it is in a sandbox

- **Chosen:** a file installed as `/etc/claude-code/CLAUDE.md` tells every
  Claude Code session in the VM about the limits and what a refusal means.
- **Why:** without it an agent tends to retry, or to look for a way around.
- **Note:** this is a help for an honest agent. It is not a protection.
- **Where:** [`vm/agent-instructions.md`](../vm/agent-instructions.md).

### The VM is added to the T3 app with `nix run .#pair`

- **Chosen:** `nix run .#pair` asks the VM's T3 server for a one-time code
  and opens it in the T3 app, which then lists the VM as an environment.
- **Not chosen:** `t3 environment link` as the main way.
- **Why:** `t3 environment link` needs a Labs setting, and it serves another
  purpose: letting agents on the Mac hand work to the VM. It is still
  described in [setup.md](setup.md) for that.
- **Where:** `pair` in `darwin/commands.nix`; the message of commit
  `16bba08`.

## How work is done

### Every change goes through a reviewed pull request

- **Chosen:** one pull request per phase or change, on its own branch. A
  separate agent reviews it. It is merged when the findings are fixed and the
  phase's check has run in the VM.
- **Not chosen:** committing to `main`, or review by the agent that wrote the
  change.
- **Why:** reason not recorded. The reviewer is given the diff and the goal,
  not the author's conclusions.
- **Where:** PLAN.md, "Decisions"; CLAUDE.md, "How work is done".

### A phase is done when a check proves it

- **Chosen:** each phase ends with a check that is run, not with a build.
- **Why:** reason not recorded.
- **Where:** the phase table in PLAN.md; CLAUDE.md.

### Commits follow Conventional Commits, with an emoji

- **Chosen:** `type(scope): emoji subject`.
- **Why:** reason not recorded.
- **Where:** CLAUDE.md, "Git".

### The agent's test repo is this repo

- **Chosen:** the repo the agent in the VM pushes to, for the last check of
  phase 4, is this one. `tests/github-live.sh` uses it unless another is
  named.
- **Why:** reason not recorded.
- **State:** that check has not been run; it waits for a real token.
- **Note:** a branch pushed there can change the rules and the broker. See
  "The rules are only as good as their review" in
  [threat-model.md](threat-model.md).
- **Where:** PLAN.md, "Decisions";
  [`tests/github-live.sh`](../tests/github-live.sh).

### "No push to `main`" is left to GitHub

- **Chosen:** branch protection on GitHub.
- **Not chosen:** the broker reading each push to find its branch.
- **Why:** a push reaches the proxy as one upload that is hard to read
  reliably.
- **Where:** PLAN.md, "Risks to check early".

### One VM, used by one agent at a time

- **Chosen:** there is one VM and one broker on fixed ports. An agent takes
  the VM by creating the folder `in-use` in the state folder before it
  stops, starts or changes it.
- **Not chosen:** a VM per agent.
- **Why:** reason not recorded.
- **Where:** CLAUDE.md, "When several agents work at once".
