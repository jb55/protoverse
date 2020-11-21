{ pkgs ? import <nixpkgs> {} }:
with pkgs;
stdenv.mkDerivation {
  name = "protoverse";
  nativeBuildInputs = [ gdb wabt ];
}
