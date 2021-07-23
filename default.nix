{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = with pkgs; [ gdb wabt emscripten wasmtime cloc wasm-pack ];
}
