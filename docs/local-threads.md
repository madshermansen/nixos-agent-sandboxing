# Threads on the Mac itself

Not every thread runs in the VM. A thread you start in the T3 app's own
environment, or with `claude` in a terminal, runs **on the Mac**, as you.
Nothing in this repo protects those threads.

Claude Code has a sandbox of its own for this case. It is much weaker than
the VM, and it is still better than nothing. This page says what it is, how
it differs from the VM, and how to turn it on.

This page is advice. Nothing in this repo changes your Claude Code settings.

Everything here about Claude Code comes from its official documentation, read
on 2026-11-17. The setting names are copied from these pages:

| Short name | Page |
| --- | --- |
| Sandboxing | <https://code.claude.com/docs/en/sandboxing> |
| Settings reference | <https://code.claude.com/docs/en/settings-reference> |
| Sandbox environments | <https://code.claude.com/docs/en/sandbox-environments> |
| Permissions | <https://code.claude.com/docs/en/permissions> |

None of it was tried on a Mac for this page. See "Not confirmed" at the end.

## What it is

Claude Code calls it the **sandboxed Bash tool**. When it is on, the shell
commands Claude runs, and the programs they start, are held inside a boundary
that macOS enforces. On macOS it uses Seatbelt, which is built in, so there
is nothing to install. It is **off by default**. (Sandboxing, "What the
sandbox restricts" and "Get started".)

What a sandboxed command can reach by default, from the same page:

| Access | Default |
| --- | --- |
| Writing files | The working directory, a temporary folder, and folders you added. Some paths inside them stay protected, such as Claude Code's own settings files. |
| Reading files | **Most of the Mac**, including key files such as `~/.ssh` and `~/.aws/credentials` |
| Network | No direct way out. Connections go through a proxy on the Mac that checks each host against a list of allowed domains. The list starts empty. |
| Environment variables | Inherited from Claude Code, including any secrets in them |

Three things run **outside** the sandbox, and matter most:

- **Claude's file and web tools.** Read, Edit, Write, WebFetch and WebSearch
  follow permission rules instead. A sandbox setting does not stop them.
- **Other programs Claude Code starts.** Hooks, local MCP servers and helper
  commands run with your full rights.
- **A command that is retried outside.** By default, when the sandbox blocks
  a command, Claude may ask to run it again without the sandbox.

## How it differs from the VM

| | The VM in this repo | Claude Code's sandbox on the Mac |
| --- | --- | --- |
| What is inside the boundary | The whole agent: Claude Code, its tools, everything it starts | Shell commands only |
| What it can read | Nothing on the Mac | Most of the Mac, unless you list paths to deny |
| What it can write | Its own disk | The project folder and a temporary folder |
| Where the boundary is | QEMU, a separate machine with its own kernel | A macOS rule on a process that shares the Mac's kernel |
| Who can lift it | Nobody inside the VM | Your settings. By default Claude can also ask to run a command outside it. |
| Network list | [`broker/rules.yaml`](../broker/rules.yaml): exact hosts, port 443 unless listed | `sandbox.network.allowedDomains`: wildcards allowed, every port unless you give one |
| An unlisted host | Always refused | Depends on the permission mode: you are asked, or in `bypassPermissions` mode it is allowed without asking. `strictAllowlist` makes it a refusal. |
| Checks the site name inside the encryption | Yes, the first message | Not stated. The documentation says the decision is made from the host name the program gives, and names domain fronting as a limit. |
| Keys in reach | The Claude sign-in in the VM | Whatever you can read, unless denied |

The documentation says the same in its own words: the sandboxed Bash tool
"on its own constrains only shell commands, so it is not sufficient for fully
unattended runs", and a virtual machine "provides the strongest separation".
(Sandbox environments.)

So: use the VM for work you do not watch. Use this sandbox for threads that
must run on the Mac, where the other choice is no boundary at all.

**What it shares with the VM:** an allowed host is a way to send data out.
Its proxy does not open encrypted traffic either.

## Turning it on

There are two ways.

- **In a session:** type `/sandbox` and pick a mode. This writes to
  `.claude/settings.local.json` in that project only.
- **For every project:** put the settings in `~/.claude/settings.json`. That
  is the one to use here, because threads on the Mac run in many folders.

If `~/.claude/settings.json` already has content, add the keys below to what
is there. Do not replace the file.

### The base

```json
{
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "allowUnsandboxedCommands": false
  }
}
```

| Setting | What it does | Why set it |
| --- | --- | --- |
| `sandbox.enabled` | Turns the sandbox on for shell commands. Default `false`. | The point of this page |
| `sandbox.failIfUnavailable` | Claude Code exits at start when the sandbox cannot start. Default `false`, which means commands then run **without** a sandbox. | It fails closed, like the broker |
| `sandbox.allowUnsandboxedCommands` | `false` makes Claude Code ignore a request to run a command outside the sandbox. Default `true`. The `/sandbox` panel calls `false` "Strict sandbox mode". | Without it, the boundary can be asked away |

With only this, commands still go through the usual permission prompts.
What happens when a command wants a new host depends on the permission mode
of the thread. In the usual modes you are asked. In `bypassPermissions` mode
the host is allowed without a prompt (Sandboxing, "Hosts outside your allowed
domains"). The next block closes that.

### Tighter: a fixed list of hosts

```json
{
  "sandbox": {
    "network": {
      "allowedDomains": ["github.com:443", "api.github.com:443"],
      "strictAllowlist": true
    }
  }
}
```

| Setting | What it does |
| --- | --- |
| `sandbox.network.allowedDomains` | Hosts that sandboxed commands may reach without a prompt. A `:port` limits an entry to one port; without it every port is allowed. |
| `sandbox.network.strictAllowlist` | `true` refuses every other host instead of asking. It is read from user or managed settings only; a repository cannot turn it on or off. Needs Claude Code v2.1.219 or later. |

List what your own work needs. The sandbox covers shell commands only, so
Claude Code's own connection to Anthropic should need no entry. Do not list
`localhost`: the documentation says such an entry opens every port on the
Mac's localhost to a command that uses the proxy.

This limits shell commands only. WebFetch follows its own permission rules.

### Tighter: keep keys out of reach

By default a sandboxed command can read your key files. The documentation is
plain about it: "There is no built-in credential deny list, so only the files
and variables you list are restricted."

```json
{
  "sandbox": {
    "credentials": {
      "files": [
        { "path": "~/.ssh", "mode": "deny" },
        { "path": "~/.aws/credentials", "mode": "deny" }
      ],
      "envVars": [
        { "name": "GITHUB_TOKEN", "mode": "deny" }
      ]
    }
  },
  "permissions": {
    "deny": [
      "Read(~/.ssh/**)",
      "Read(~/.aws/credentials)"
    ]
  }
}
```

| Setting | What it does |
| --- | --- |
| `sandbox.credentials.files` | With `"mode": "deny"`, sandboxed commands cannot read the path |
| `sandbox.credentials.envVars` | With `"mode": "deny"`, the variable is removed before each sandboxed command |
| `permissions.deny` with `Read(...)` | Stops Claude's own file tools, which the sandbox does not cover. The documentation calls this a best effort. |

The paths are examples. Put in the key files that exist on your Mac.

Two things to know before you add more paths:

- **`~/.ssh` and git.** On macOS, git over SSH does not work inside the
  sandbox at all (Sandboxing, "`git` over SSH fails with the sandbox on").
  Use HTTPS addresses for git in sandboxed threads.
- **This repo's state folder.** `~/.local/state/agent-vm` holds the SSH key
  that opens the VM. A local thread that can read it can get a shell in the
  VM. Denying the folder protects the VM from local threads. It also breaks
  `nix run .#ssh` and the other commands for a local thread that is meant to
  work on this repo. Choose per project.

### One more: fewer prompts

`sandbox.autoAllowBashIfSandboxed` set to `true` runs sandboxed commands
without asking. The default is `false`; before Claude Code v2.1.324 it was
`true`, so set it to `false` yourself on an older version. It trades the
prompt for the boundary, so turn it on only with the tighter settings above
in place.

## Check that it works

The documentation gives two commands. Ask Claude to run them; a command you
type yourself at the `!` prompt usually runs outside the sandbox.

| Command | Result inside the sandbox |
| --- | --- |
| `touch ~/sandbox-probe` | Fails with `Operation not permitted` |
| `curl --noproxy '*' https://example.com` | Fails with `Could not resolve host` |

If `touch` works, delete `~/sandbox-probe` and run `/sandbox` to see why.

## What it does not protect

Taken from "Limitations" on the Sandboxing page, and from the tables above:

- Claude's file tools, MCP servers and hooks are outside it.
- Reading is open by default. Only what you list is denied.
- An allowed host is a way out, and the proxy does not look inside encrypted
  traffic.
- It is a rule on a process, not a separate machine. The documentation says
  it "is not a complete isolation boundary".
- Settings such as `excludedCommands`, `allowAppleEvents`,
  `network.allowLocalBinding` and `filesystem.disabled` each open the
  boundary again. Leave them out unless you know why you need one.

For this project, one more: **the broker's port.** The documentation says a
sandboxed command on macOS cannot connect to a server on the Mac's localhost
unless `network.allowLocalBinding` is `true`. That would keep sandboxed
commands away from `localhost:8474`. Claude's other tools and unsandboxed
programs are not held back by it. This matters once the broker attaches a
token, which is planned; see [threat-model.md](threat-model.md).

## Not confirmed

- **Whether a T3 thread on the Mac reads `~/.claude/settings.json`.** In a
  T3 thread, T3 starts Claude Code, not you. The documentation says a program
  that starts it through the Agent SDK can choose which settings files are
  loaded (`settingSources`). Whether T3 does that, and what it chooses, was
  not checked. Run the two commands under "Check that it works" in a T3
  thread on the Mac to find out.
- **The settings on this page were not tried.** They are copied from the
  documentation. Claude Code changes often; some settings name a minimum
  version. If a key is refused or ignored, the Settings reference is the
  place to look.
- **The Keychain.** The pages read for this did not say whether a sandboxed
  command can ask the macOS Keychain for a secret.
- **Whether this is enough for phase 6.** [PLAN.md](../PLAN.md) lists
  "Claude's built-in sandbox for local Mac threads" under phase 6. This page
  is the advice for it. Applying it to your own settings is your step.
