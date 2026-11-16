# nix-darwin module: everything the Mac needs to build and run the agent VM.
#
# Import it from your own nix-darwin configuration; see docs/setup.md.
# The VM and the broker will be added here as background services. Until
# then they are started by the commands in commands.nix.
{ lib, ... }:
{
  # The VM is a Linux system, and a Mac cannot build Linux packages by itself.
  # This runs a small NixOS VM in the background that does those builds.
  nix.linux-builder.enable = lib.mkDefault true;
}
