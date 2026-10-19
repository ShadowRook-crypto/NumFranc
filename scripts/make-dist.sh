#!/bin/bash
# Assemble le dossier NumFranc/ à distribuer (lanceurs + code + binaires présents dans dist-bin/).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist}"
rm -rf "$OUT/NumFranc"
mkdir -p "$OUT/NumFranc/bin" "$OUT/NumFranc/code"
cp -rp "$ROOT/packaging/"* "$OUT/NumFranc/"
cp -r "$ROOT/Cargo.toml" "$ROOT/Cargo.lock" "$ROOT/src" "$ROOT/examples" "$ROOT/assets" "$ROOT/README.md" "$OUT/NumFranc/code/"
if [ -d "$ROOT/dist-bin" ]; then cp -p "$ROOT/dist-bin/"* "$OUT/NumFranc/bin/" 2>/dev/null || true; fi
# Livre blanc (français et anglais) : inclus dans SHA3SUMS.txt, donc couvert par la signature.
if [ -d "$ROOT/docs" ]; then cp -p "$ROOT/docs/"*.pdf "$OUT/NumFranc/" 2>/dev/null || true; fi
cp "$ROOT/scripts/sha3sum.py" "$OUT/NumFranc/sha3sum.py"
# Première ligne : le numéro de version (lu par « Vérifier les mises à jour », couvert par la signature).
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
# Les installeurs (.dmg, .exe, .deb) sont publiés à part, mais leurs empreintes sont dans le même fichier
# SHA3SUMS.txt : la signature les couvre donc aussi (lignes « installeurs/NOM »).
( cd "$OUT/NumFranc" && { echo "# NumFranc $VERSION"; python3 sha3sum.py .; } > SHA3SUMS.txt )
if [ -d "$ROOT/dist-installeurs" ]; then
  python3 - "$ROOT/dist-installeurs" >> "$OUT/NumFranc/SHA3SUMS.txt" <<'PYEOF'
import hashlib, os, sys
d = sys.argv[1]
for n in sorted(os.listdir(d)):
    p = os.path.join(d, n)
    if os.path.isfile(p):
        h = hashlib.sha3_512(open(p, "rb").read()).hexdigest()
        print(f"{h}  installeurs/{n}")
PYEOF
fi
echo "Dossier prêt : $OUT/NumFranc"
