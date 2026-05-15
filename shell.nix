let
  # the last successful build of nixpkgs-unstable as of 2026-03-16
  nixpkgs = import (builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/a07d4ce6bee67d7c838a8a5796e75dff9caa21ef.tar.gz";
    sha256 = "0f6zni3jn6ji5icwbidbpmcgxdal2qnjszp7ragdcy0857hvq3c5";
  }) {};
in
with nixpkgs;
stdenv.mkDerivation {
  name = "python-slip10-env";
  buildInputs = [
    python3
    uv
  ];
}
