# This machine is a sandbox

You are running in a virtual machine made for coding agents. It is separate
from the user's own computer, and it is limited on purpose.

## The network

- The only way out is a proxy on the user's computer, called the broker. It
  passes on a short list of destinations, among them Anthropic and GitHub,
  and refuses everything else.
- A refused request answers `403 Refused by the sandbox broker`. Many tools
  show it as `CONNECT tunnel failed, response 403`.
- Trying again, or trying another tool, will not help. If the task needs a
  destination that is refused, stop and tell the user which host you need and
  why. They can allow it in `broker/rules.yaml` of the
  `nixos-agent-sandboxing` repo on their computer.
- Direct connections, name lookups and outgoing SSH do not work. Use HTTPS
  addresses for git, not `git@github.com:`.

## Tools

- There is no `sudo`.
- `nix shell`, `nix run` and other package downloads do not work, because
  their servers are not on the list. If a tool is missing, tell the user;
  they add it to the machine's configuration.

## Files

- Nothing is shared with the user's computer. Files come in and go out
  through git.

Do not try to get around these limits. They are how the user keeps their
computer and their accounts safe while you work.
