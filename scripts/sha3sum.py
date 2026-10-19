#!/usr/bin/env python3
"""Empreintes SHA3-512 (comme le reste de NumFranc).
   Créer :    python3 scripts/sha3sum.py DOSSIER > SHA3SUMS.txt
   Vérifier : cd DOSSIER && python3 sha3sum.py --check SHA3SUMS.txt
   Vérifier un installeur téléchargé à part (.dmg, .exe, .deb) :
              python3 sha3sum.py --fichier SHA3SUMS.txt NumFranc-macos.dmg"""
import hashlib, os, sys

def h(path):
    d = hashlib.sha3_512()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            d.update(chunk)
    return d.hexdigest()

if len(sys.argv) == 4 and sys.argv[1] == "--fichier":
    nom = os.path.basename(sys.argv[3])
    for line in open(sys.argv[2], encoding="utf-8"):
        line = line.rstrip("\n")
        if line and not line.startswith("#"):
            digest, path = line.split("  ", 1)
            if path == "installeurs/" + nom:
                ok = os.path.exists(sys.argv[3]) and h(sys.argv[3]) == digest
                print(("OK       " if ok else "ERREUR   ") + nom)
                sys.exit(0 if ok else 1)
    print("ERREUR   " + nom + " : absent de SHA3SUMS.txt")
    sys.exit(1)

if len(sys.argv) == 3 and sys.argv[1] == "--check":
    bad = 0
    for line in open(sys.argv[2], encoding="utf-8"):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        digest, path = line.split("  ", 1)
        if path.startswith("installeurs/") and not os.path.exists(path):
            print("(non téléchargé) " + path)  # installeur publié à part : voir --fichier
            continue
        ok = os.path.exists(path) and h(path) == digest
        print(("OK       " if ok else "ERREUR   ") + path)
        bad += not ok
    sys.exit(1 if bad else 0)

root = sys.argv[1]
for dp, dn, fn in os.walk(root):
    dn.sort()
    for name in sorted(fn):
        if name.startswith("SHA3SUMS"):
            continue
        p = os.path.join(dp, name)
        print(f"{h(p)}  {os.path.relpath(p, root)}")
