#!/bin/bash
# Construit NumFranc.dmg pour macOS (Apple Silicon ET Intel dans le même programme) :
# on l'ouvre, on glisse NumFranc vers Applications, c'est installé.
#   Utilisation (sur un Mac) : macos-dmg.sh VERSION PROGRAMME_ARM64 PROGRAMME_X86_64 SORTIE.dmg
set -euo pipefail
VERSION="${1:?version}"; ARM="${2:?programme arm64}"; X86="${3:?programme x86_64}"; OUT="${4:?fichier .dmg}"
ICI="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
APP="$T/disque/NumFranc.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
# Un seul programme qui marche sur les deux types de Mac.
lipo -create "$ARM" "$X86" -output "$APP/Contents/MacOS/NumFranc"
chmod 755 "$APP/Contents/MacOS/NumFranc"
python3 "$ICI/packaging/outils-installeurs/make-icns.py" icns "$ICI/assets/logo-256.png" "$ICI/assets/logo-512.png" "$APP/Contents/Resources/NumFranc.icns"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>NumFranc</string>
<key>CFBundleDisplayName</key><string>NumFranc</string>
<key>CFBundleIdentifier</key><string>org.numfranc.app</string>
<key>CFBundleExecutable</key><string>NumFranc</string>
<key>CFBundleIconFile</key><string>NumFranc</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$VERSION</string>
<key>CFBundleVersion</key><string>$VERSION</string>
<key>LSMinimumSystemVersion</key><string>11.0</string>
<key>LSApplicationCategoryType</key><string>public.app-category.finance</string>
<key>NSHumanReadableCopyright</key><string>ShadowRook — licence MIT</string>
<key>NSHighResolutionCapable</key><true/>
<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLName</key><string>org.numfranc.paiement</string><key>CFBundleTypeRole</key><string>Viewer</string><key>CFBundleURLSchemes</key><array><string>nfr</string></array></dict></array>
</dict></plist>
PLIST
# Signature « locale » (sans compte Apple) : indispensable pour qu'un Mac Apple Silicon accepte de lancer l'app.
codesign --force --deep -s - "$APP"
ln -s /Applications "$T/disque/Applications"
cat > "$T/disque/Lis-moi - Read me.txt" <<'TXT'
INSTALLER : glisse « NumFranc » sur « Applications ». Ensuite, ouvre-le depuis le Launchpad.

LA TOUTE PREMIERE FOIS, macOS affiche « NumFranc n'a pas été ouvert » : NumFranc est un projet indépendant,
sans compte développeur Apple, donc Apple ne peut pas vérifier l'éditeur. Fais alors, une seule fois :
  1. Clique sur « Terminé ».
  2. Ouvre Réglages Système > Confidentialité et sécurité.
  3. Descends tout en bas : à côté de « NumFranc a été bloqué », clique sur « Ouvrir quand même ».
  4. Entre le mot de passe de ton Mac, puis confirme avec « Ouvrir ».
(macOS 14 « Sonoma » et plus ancien : un clic droit sur NumFranc > Ouvrir > Ouvrir suffit.)

INSTALL: drag « NumFranc » onto « Applications », then open it from Launchpad.
THE VERY FIRST TIME, macOS shows « NumFranc Not Opened »: NumFranc is an independent project with no Apple
developer account, so Apple cannot verify the publisher. Then, only once:
  1. Click « Done ».
  2. Open System Settings > Privacy & Security.
  3. Scroll to the bottom: next to « NumFranc was blocked », click « Open Anyway ».
  4. Enter your Mac password, then confirm with « Open ».
(macOS 14 « Sonoma » and older: right-click NumFranc > Open > Open is enough.)
TXT
hdiutil create -volname "NumFranc" -srcfolder "$T/disque" -fs HFS+ -format UDZO -ov "$OUT" >/dev/null
echo "Disque prêt : $OUT"
