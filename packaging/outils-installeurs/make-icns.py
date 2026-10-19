#!/usr/bin/env python3
"""Fabrique NumFranc.icns (macOS) ou numfranc.ico (Windows) à partir des logos PNG, sans outil externe.
   python3 make-icns.py icns LOGO256.png LOGO512.png SORTIE.icns
   python3 make-icns.py ico  LOGO256.png SORTIE.ico
Même format que le code du programme (src/install.rs) : des images PNG rangées telles quelles."""
import struct, sys

def lire(p):
    return open(p, "rb").read()

mode = sys.argv[1]
if mode == "icns":
    corps = b""
    for genre, png in ((b"ic08", lire(sys.argv[2])), (b"ic09", lire(sys.argv[3]))):
        corps += genre + struct.pack(">I", len(png) + 8) + png
    open(sys.argv[4], "wb").write(b"icns" + struct.pack(">I", len(corps) + 8) + corps)
elif mode == "ico":
    png = lire(sys.argv[2])
    # 256 x 256 codé 0, palette 0, réservé 0, 1 plan, 32 bits, taille, position 22
    ent = bytes([0, 0, 0, 0]) + struct.pack("<HHII", 1, 32, len(png), 22)
    open(sys.argv[3], "wb").write(struct.pack("<HHH", 0, 1, 1) + ent + png)
else:
    sys.exit("mode inconnu")
