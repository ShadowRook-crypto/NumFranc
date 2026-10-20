#!/bin/bash
# Construit le paquet Linux (.deb) : double-clic dans le gestionnaire de fichiers, ou « sudo apt install ./fichier.deb ».
#   Utilisation : linux-deb.sh VERSION ARCHITECTURE PROGRAMME SORTIE.deb
#   ARCHITECTURE : amd64 ou arm64      (ex. linux-deb.sh 1.1.0 amd64 dist-bin/numfranc-linux-x86_64 numfranc_1.1.0_amd64.deb)
# Le paquet est reproductible : mêmes entrées, même fichier (dates fixées sur SOURCE_DATE_EPOCH).
set -euo pipefail
VERSION="${1:?version}"; ARCH="${2:?architecture amd64|arm64}"; BIN="${3:?programme}"; OUT="${4:?fichier .deb}"
ICI="$(cd "$(dirname "$0")/../.." && pwd)"
EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ICI" log -1 --format=%ct 2>/dev/null || echo 0)}"
export SOURCE_DATE_EPOCH="$EPOCH"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
P="$T/pkg"
install -d -m 755 "$P/DEBIAN" "$P/usr/bin" "$P/usr/share/applications" "$P/usr/share/icons/hicolor/256x256/apps" "$P/usr/share/doc/numfranc"
install -m 755 "$BIN" "$P/usr/bin/numfranc"
install -m 644 "$ICI/assets/logo-256.png" "$P/usr/share/icons/hicolor/256x256/apps/numfranc.png"
cat > "$P/usr/share/applications/numfranc.desktop" <<'DESK'
[Desktop Entry]
Type=Application
Name=NumFranc
Comment=Monnaie post-quantique NumFranc (NFR)
Comment[en]=NumFranc (NFR) post-quantum currency
Exec=numfranc %u
Icon=numfranc
Terminal=false
Categories=Finance;Network;
MimeType=x-scheme-handler/nfr;
StartupWMClass=numfranc
DESK
chmod 644 "$P/usr/share/applications/numfranc.desktop"
install -m 644 "$ICI/LICENSE" "$P/usr/share/doc/numfranc/copyright"
install -m 644 "$ICI/packaging/LISEZMOI.txt" "$P/usr/share/doc/numfranc/LISEZMOI.txt"
install -m 644 "$ICI/packaging/SERVEUR.txt" "$P/usr/share/doc/numfranc/SERVEUR.txt"
SIZE="$(du -sk "$P/usr" | cut -f1)"
cat > "$P/DEBIAN/control" <<CTL
Package: numfranc
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Installed-Size: $SIZE
Maintainer: ShadowRook <noreply@users.noreply.github.com>
Depends: libc6 (>= 2.35), libgl1, libxkbcommon0
Recommends: curl, libwayland-client0, libx11-6, libxcursor1, libxrandr2, libxi6, libxkbcommon-x11-0
Homepage: https://github.com/ShadowRook-crypto/NumFranc
Description: NumFranc (NFR), monnaie post-quantique
 Portefeuille, minage et noeud du reseau NumFranc, avec liens de paiement nfr:
 cliquables. Signatures ML-DSA-87, minage Argon2d. Licence MIT.
CTL
cat > "$P/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
# Enregistre le menu, l'icône et les liens nfr: (sans effet si ces outils sont absents).
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
exit 0
POST
cp "$P/DEBIAN/postinst" "$P/DEBIAN/postrm"
chmod 755 "$P/DEBIAN/postinst" "$P/DEBIAN/postrm"
find "$P" -exec touch -h -d "@$EPOCH" {} +
dpkg-deb --root-owner-group -Zxz -b "$P" "$OUT" >/dev/null
echo "Paquet prêt : $OUT"
