#!/bin/bash
# NumFranc — lanceur macOS (double-clic dans le Finder)
cd "$(dirname "$0")" || exit 1
ARCH=$(uname -m)
BIN="bin/numfranc-macos-$ARCH"
xattr -dr com.apple.quarantine bin 2>/dev/null

if [ ! -x "$BIN" ] || ! "$BIN" --aide >/dev/null 2>&1; then
  BIN="code/target/release/numfranc"
  if [ ! -x "$BIN" ]; then
    if ! xcode-select -p >/dev/null 2>&1; then
      echo "Les outils de compilation d'Apple sont nécessaires (une seule fois)."
      xcode-select --install
      echo "Une fois l'installation terminée, relancez NumFranc."
      read -r -p "Appuyez sur Entrée pour fermer." _; exit 1
    fi
    [ -x "$HOME/.cargo/bin/cargo" ] && export PATH="$HOME/.cargo/bin:$PATH"
    if ! command -v cargo >/dev/null 2>&1; then
      echo "Installation de Rust (une seule fois)..."
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y || exit 1
      export PATH="$HOME/.cargo/bin:$PATH"
    fi
    echo "Compilation de NumFranc (1 à 3 minutes la première fois)..."
    cargo build --release --manifest-path code/Cargo.toml || { read -r -p "Échec. Entrée pour fermer." _; exit 1; }
  fi
fi
"$BIN" "$@"
read -r -p "NumFranc s'est arrêté. Appuyez sur Entrée pour fermer." _
