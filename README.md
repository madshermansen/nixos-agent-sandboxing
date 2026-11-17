# nixt3

Pronounced "nixty-three": Nix plus T3.

A headless NixOS VM for running coding agents from T3 Code on a Mac.

An agent can be tricked by what it reads, or make a mistake. Here it works in
a machine of its own that shares nothing with the Mac. Its network is locked:
the only way out is a broker on the Mac, which passes on a short list of
destinations and refuses the rest.

The broker also holds the GitHub token. Programs in the VM log in with a
placeholder, and the broker puts the real token in its place on the way out,
so the VM never holds it. Limits on which repos and actions the agent may
use are planned.

![The Mac, the agent VM inside it, the broker, and the internet](docs/images/vm-today.svg)

## Quick start

With the Linux builder on (see [setup](docs/setup.md)):

```sh
nix run .#vm     # start the VM and its broker; the terminal becomes the console
nix run .#stop   # shut both down cleanly, from another terminal
nix run .#ssh    # open a shell in the VM as the `agent` user
nix run .#pair   # add the VM to the T3 app as an environment
nix run .#logs   # watch which destinations the VM asks for
nix run .#check  # test the network lock from inside the VM
```

Claude also needs a one-time sign-in inside the VM. The steps are in
[docs/setup.md](docs/setup.md).

## Documentation

| Page | Contents |
| --- | --- |
| [docs/setup.md](docs/setup.md) | Getting it running, day-to-day commands, problems |
| [docs/architecture.md](docs/architecture.md) | The parts, what crosses between Mac and VM, the target design |
| [PLAN.md](PLAN.md) | The phases and the risks |
| [CLAUDE.md](CLAUDE.md) | Instructions for agents working on this repo |
