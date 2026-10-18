#!/bin/bash
# NumFranc — lanceur Linux :  ./lancer-numfranc.sh
cd "$(dirname "$0")" || exit 1
BIN="bin/numfranc-linux-$(uname -m)"

if [ ! -x "$BIN" ] || ! "$BIN" --aide >/dev/null 2>&1; then
  BIN="code/target/release/numfranc"
  if [ ! -x "$BIN" ]; then
    if ! command -v cc >/dev/null 2>&1; then
      echo "Un compilateur C est nécessaire : sudo apt install build-essential   (ou équivalent)"
      exit 1
    fi
    [ -x "$HOME/.cargo/bin/cargo" ] && export PATH="$HOME/.cargo/bin:$PATH"
    if ! command -v cargo >/dev/null 2>&1; then
      echo "Installation de Rust (une seule fois)..."
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || exit 1
      export PATH="$HOME/.cargo/bin:$PATH"
    fi
    echo "Compilation de NumFranc (1 à 3 minutes la première fois)..."
    cargo build --release --manifest-path code/Cargo.toml || exit 1
  fi
fi
exec "$BIN" "$@"
