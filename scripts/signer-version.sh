#!/bin/bash
# Signature d'une version NumFranc, en UNE commande, sur le Mac.
#
#   Utilisation (dans le dossier du dépôt) :   ./scripts/signer-version.sh 1.1.0
#
# Le script :
#   1. compile l'outil de signature (une seule fois) ;
#   2. attend que GitHub ait fini de publier la version, puis télécharge SHA3SUMS.txt ;
#   3. COUPE LE WI-FI et vérifie qu'Internet est vraiment coupé ;
#   4. ouvre 2 dossiers protégés et déchiffre 2 morceaux (il demande les 4 codes, un par un ;
#      si un dossier ou un morceau refuse le code 3 fois, il passe au dossier suivant) ;
#   5. reconstitue la clé, signe, vérifie, puis EFFACE la clé (même en cas d'erreur) ;
#   6. rallume le Wi-Fi, envoie la signature sur GitHub et vérifie qu'elle est valide en ligne.
#
# Aucun secret dans ce fichier : il peut être publié. La clé reste dans ~/cles-numfranc
# (dossiers protégés morceau1.dmg, morceau2.dmg, morceau3.dmg) et sur tes papiers.

set -u
V="${1:-}"
if ! [[ "$V" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Utilisation : ./scripts/signer-version.sh 1.1.0   (le numéro de la version publiée)"
  exit 1
fi

REPO="ShadowRook-crypto/NumFranc"
URL="https://github.com/$REPO/releases/download/v$V"
DEPOT="$(cd "$(dirname "$0")/.." && pwd)"
CLES="${NUMFRANC_CLES:-$HOME/cles-numfranc}"
OUT="$CLES/signature-v$V"
S="$DEPOT/target/release/examples/signer_version"
T=""
MONTES=""
WIFI=""

titre() { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }
ok()    { printf '\033[32m✔ %s\033[0m\n' "$1"; }
stop()  { printf '\n\033[31m✘ %s\033[0m\n' "$1"; exit 1; }
en_ligne() { curl -s --max-time 4 -o /dev/null https://github.com; }

# Nettoyage, appelé quoi qu'il arrive (fin normale, erreur, Ctrl+C) :
# d'abord effacer la clé et refermer les dossiers protégés, ensuite seulement rallumer le Wi-Fi.
nettoyer() {
  [ -n "$T" ] && rm -rf "$T"
  for i in $MONTES; do hdiutil detach "/tmp/nfr-dossier$i" -quiet 2>/dev/null || hdiutil detach "/tmp/nfr-dossier$i" -force -quiet 2>/dev/null; done
  MONTES=""
  if [ -n "$WIFI" ]; then
    networksetup -setairportpower "$WIFI" on 2>/dev/null
    WIFI=""
  fi
}
trap nettoyer EXIT
trap 'echo; stop "Arrêté (Ctrl+C) : la clé a été effacée, le Wi-Fi est rallumé."' INT TERM

# ---------------------------------------------------------------------------
titre "1/6  Vérifications"
[ -f "$CLES/MACLE.pub" ] || stop "Introuvable : $CLES/MACLE.pub"
cmp -s "$CLES/MACLE.pub" "$DEPOT/packaging/cle-publique.txt" || stop "MACLE.pub ne correspond pas à packaging/cle-publique.txt"
for i in 1 2 3; do [ -f "$CLES/morceau$i.dmg" ] || echo "(attention : morceau$i.dmg absent)"; done
command -v age >/dev/null || stop "age n'est pas installé (brew install age)"
mkdir -p "$OUT"
ok "Clé publique, dossiers et outils présents"
DEJA=""
if [ -s "$OUT/SHA3SUMS.txt.sig" ] && [ -x "$S" ] && "$S" verifier "$OUT/SHA3SUMS.txt" "$OUT/SHA3SUMS.txt.sig" "$CLES/MACLE.pub" >/dev/null 2>&1; then
  DEJA=1
  ok "Signature déjà faite lors d'un essai précédent : on passe directement à l'envoi"
fi

if [ -z "$DEJA" ]; then
titre "2/6  Outil de signature (Wi-Fi allumé)"
( cd "$DEPOT" && cargo build --release -j 2 --example signer_version ) || stop "Compilation impossible"
ok "Outil prêt"

titre "3/6  Attente de la version v$V sur GitHub"
debut=$(date +%s)
until curl -sfL -o "$OUT/SHA3SUMS.txt" "$URL/SHA3SUMS.txt"; do
  [ $(( $(date +%s) - debut )) -gt 5400 ] && stop "Toujours rien après 90 minutes : regarde l'onglet Actions sur GitHub (étape rouge ?)."
  echo "GitHub compile encore… nouvel essai dans 1 minute ($(date +%H:%M))"
  sleep 60
done
[ "$(head -1 "$OUT/SHA3SUMS.txt")" = "# NumFranc $V" ] || stop "Le fichier téléchargé n'est pas celui de la version $V"
if curl -sfL -o /dev/null "$URL/SHA3SUMS.txt.sig"; then
  stop "La version v$V est déjà signée sur GitHub : rien à faire."
fi
ok "SHA3SUMS.txt de la version $V téléchargé"
# Contrôle humain avant de signer : ce que tu signes doit être exactement ce que tu as publié.
MINI_EN_LIGNE="$(sed -n 2p "$OUT/SHA3SUMS.txt" | sed -n 's/^# Version minimale sûre //p')"
MINI_DEPOT="$(tr -dc '0-9.' < "$DEPOT/scripts/version-minimale-sure.txt" 2>/dev/null)"
[ "${MINI_EN_LIGNE:-0}" = "${MINI_DEPOT:-0}" ] || stop "Version minimale sûre différente : en ligne « ${MINI_EN_LIGNE:-0} », dans ton dépôt « ${MINI_DEPOT:-0} ». Ne signe pas : regarde ce qui s'est passé."
echo
echo "Tu vas signer :  version $V  —  version minimale sûre : ${MINI_EN_LIGNE:-0}"
echo "Fichiers listés : $(grep -vc '^#' "$OUT/SHA3SUMS.txt")  (dont installeurs : $(grep -c '  installeurs/' "$OUT/SHA3SUMS.txt"))"
echo "Si ce n'est pas ce que tu attends, fais Ctrl+C. Sinon appuie sur Entrée."
read -r _

# ---------------------------------------------------------------------------
titre "4/6  Coupure d'Internet"
WIFI="$(networksetup -listallhardwareports 2>/dev/null | awk '/Hardware Port: (Wi-Fi|AirPort)/{getline; print $2; exit}')"
if [ -n "$WIFI" ]; then
  networksetup -setairportpower "$WIFI" off && echo "Wi-Fi coupé ($WIFI)."
fi
sleep 3
while en_ligne; do
  echo "Internet répond encore. Coupe le Wi-Fi à la main (icône Wi-Fi en haut à droite), débranche tout câble réseau, puis appuie sur Entrée."
  read -r _
done
ok "Hors ligne"

titre "5/6  Signature (hors ligne)"
T="$(mktemp -d)"
chmod 700 "$T"
PIECES=""
for i in 1 2 3; do
  [ "$(echo $PIECES | wc -w)" -ge 2 ] && break
  [ -f "$CLES/morceau$i.dmg" ] || continue
  mkdir -p "/tmp/nfr-dossier$i"
  monte=""
  for essai in 1 2 3; do
    echo
    echo ">>> Code du papier DOSSIER $i  (essai $essai/3)"
    if hdiutil attach "$CLES/morceau$i.dmg" -mountpoint "/tmp/nfr-dossier$i" -nobrowse >/dev/null; then monte=1; break; fi
  done
  if [ -z "$monte" ]; then echo "Dossier $i refusé : on essaie le suivant."; continue; fi
  MONTES="$MONTES $i"
  dechiffre=""
  for essai in 1 2 3; do
    echo
    echo ">>> Code du papier MORCEAU $i  (essai $essai/3)"
    if age -d -o "$T/m$i" "/tmp/nfr-dossier$i/MACLE.key.morceau$i.age"; then dechiffre=1; break; fi
  done
  if [ -z "$dechiffre" ]; then echo "Morceau $i refusé : on essaie le suivant."; continue; fi
  PIECES="$PIECES $i"
done
set -- $PIECES
[ $# -ge 2 ] || stop "Il faut 2 morceaux : signature impossible. Rien n'a été signé, la clé n'a pas été reconstituée."
echo
"$S" reconstruire "$T/m$1" "$T/m$2" "$CLES/MACLE.pub" "$T/cle.key" || stop "Reconstitution impossible"
"$S" signer "$OUT/SHA3SUMS.txt" "$T/cle.key" >/dev/null || stop "Signature impossible"
"$S" verifier "$OUT/SHA3SUMS.txt" "$OUT/SHA3SUMS.txt.sig" "$CLES/MACLE.pub" || stop "La signature créée n'est pas valide"
nettoyer   # clé effacée, dossiers refermés, Wi-Fi rallumé
ok "Signé avec les morceaux $1 et $2 ; clé effacée, dossiers refermés"
fi

# ---------------------------------------------------------------------------
titre "6/6  Envoi sur GitHub (Wi-Fi rallumé)"
for _ in $(seq 1 30); do en_ligne && break; sleep 2; done
while ! en_ligne; do
  echo "Pas encore d'Internet : rallume le Wi-Fi (icône en haut à droite), puis appuie sur Entrée."
  read -r _
done
TOKEN="$(cd "$DEPOT" && printf "protocol=https\nhost=github.com\n\n" | git credential fill 2>/dev/null | sed -n 's/^password=//p')"
[ -n "$TOKEN" ] || stop "Token GitHub introuvable (git credential)"
ID="$(curl -s -H "Authorization: Bearer $TOKEN" "https://api.github.com/repos/$REPO/releases/tags/v$V" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)"
[ -n "$ID" ] || { unset TOKEN; stop "Version v$V introuvable sur GitHub (token expiré ?)"; }
CODE="$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/octet-stream" \
  --data-binary @"$OUT/SHA3SUMS.txt.sig" "https://uploads.github.com/repos/$REPO/releases/$ID/assets?name=SHA3SUMS.txt.sig")"
unset TOKEN
case "$CODE" in
  201) ok "Signature envoyée" ;;
  422) echo "GitHub a déjà une signature pour cette version : on la vérifie." ;;
  401) stop "Token GitHub expiré : recrée-le, puis relance la commande." ;;
  *)   stop "Réponse inattendue de GitHub : $CODE" ;;
esac

V2="$(mktemp -d)"
curl -sfL -o "$V2/s.txt" "$URL/SHA3SUMS.txt" && curl -sfL -o "$V2/s.sig" "$URL/SHA3SUMS.txt.sig" \
  && "$S" verifier "$V2/s.txt" "$V2/s.sig" "$DEPOT/packaging/cle-publique.txt" >/dev/null
r=$?
rm -rf "$V2"
[ $r -eq 0 ] || stop "La signature en ligne ne se vérifie pas : envoie-moi ce message."

printf '\n\033[1;32m✅ Version %s signée et publiée. La signature en ligne est valide.\033[0m\n' "$V"
