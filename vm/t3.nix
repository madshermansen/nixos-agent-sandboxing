# The T3 Code server, from the project's GitHub release.
#
# Keep the version equal to the T3 app on the Mac. The checksum is the line for
# the linux-arm64 archive in the release's SHA256SUMS file.
{ stdenvNoCC, fetchurl }:
let
  version = "0.1.7";
in
stdenvNoCC.mkDerivation {
  pname = "t3";
  inherit version;

  src = fetchurl {
    url = "https://github.com/pingdotgg/t3code/releases/download/v${version}/t3-${version}-linux-arm64.tar.gz";
    sha256 = "5a528e23af394cc6f359036d3cb8441fda14129d477630fc6c53e4f4a1025bc8";
  };

  # The archive is a prebuilt program with its files beside it. It is installed
  # untouched, because rewriting such a program can break it; nix-ld runs it.
  dontConfigure = true;
  dontBuild = true;
  dontFixup = true;

  installPhase = ''
    mkdir -p $out/lib/t3 $out/bin
    cp -R . $out/lib/t3
    ln -s $out/lib/t3/t3 $out/bin/t3
  '';
}
