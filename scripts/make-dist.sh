#!/bin/bash
# Assemble le dossier NumFranc/ à distribuer (lanceurs + code + binaires présents dans dist-bin/).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist}"
rm -rf "$OUT/NumFranc"
mkdir -p "$OUT/NumFranc/bin" "$OUT/NumFranc/code"
cp -p "$ROOT/packaging/"* "$OUT/NumFranc/"
cp -r "$ROOT/Cargo.toml" "$ROOT/Cargo.lock" "$ROOT/src" "$ROOT/examples" "$ROOT/assets" "$ROOT/README.md" "$OUT/NumFranc/code/"
if [ -d "$ROOT/dist-bin" ]; then cp -p "$ROOT/dist-bin/"* "$OUT/NumFranc/bin/" 2>/dev/null || true; fi
# Livre blanc (français et anglais) : inclus dans SHA3SUMS.txt, donc couvert par la signature.
if [ -d "$ROOT/docs" ]; then cp -p "$ROOT/docs/"*.pdf "$OUT/NumFranc/" 2>/dev/null || true; fi
cp "$ROOT/scripts/sha3sum.py" "$OUT/NumFranc/sha3sum.py"
( cd "$OUT/NumFranc" && python3 sha3sum.py . > SHA3SUMS.txt )
echo "Dossier prêt : $OUT/NumFranc"
