#!/bin/bash
# Compilation reproductible : deux personnes qui lancent ce script sur le même code
# obtiennent exactement le même programme (même empreinte SHA3-512).
#   Utilisation : ./scripts/build-reproductible.sh CIBLE      (ex. x86_64-unknown-linux-musl)
# Ce qui rend le résultat identique :
#   - la version de Rust est fixée (rust-toolchain.toml) et les dépendances aussi (Cargo.lock, --locked) ;
#   - les chemins propres à chaque ordinateur (dossier du code, de Cargo, de Rust) sont remplacés
#     par des chemins neutres dans le programme (--remap-path-prefix) ;
#   - pas de compilation incrémentale, et une date fixe (celle du dernier commit).
set -euo pipefail
CIBLE="${1:?indique la cible, ex. x86_64-unknown-linux-musl}"
cd "$(dirname "$0")/.."
ICI="$(pwd -W 2>/dev/null || pwd)"
CARGO_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUST_DIR="$(rustc --print sysroot)"
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct 2>/dev/null || echo 0)"
export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=$ICI=/numfranc --remap-path-prefix=$CARGO_DIR=/cargo --remap-path-prefix=$RUST_DIR=/rust ${RUSTFLAGS_EN_PLUS:-}"
cargo build --release --locked --target "$CIBLE"
BIN="target/$CIBLE/release/numfranc"
[ -f "$BIN.exe" ] && BIN="$BIN.exe"
PY="$(command -v python3 || command -v python)"
"$PY" -c "import hashlib,sys; print(hashlib.sha3_512(open(sys.argv[1],'rb').read()).hexdigest(), sys.argv[1])" "$BIN"
