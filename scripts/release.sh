#!/bin/bash
# Compila, verifica e pubblica una release di SubnetScout su GitHub.
#
#   scripts/release.sh <versione> <note.md> [--yes]
#
#   <versione>  es. 0.1.0 (il tag sarà v<versione>)
#   <note.md>   note di rilascio («Novità»); istruzioni di installazione e
#               SHA-256 dello zip vengono aggiunte automaticamente
#   --yes       pubblica senza chiedere conferma
#
# Passi: controlla il repository, imposta la versione (build + 1) in Info.plist,
# compila il bundle universale con scripts/bundle.sh, crea lo zip senza
# attributi Finder/iCloud, verifica l'app estratta (firma, architetture,
# versione, helper), poi (dopo conferma) fa commit, tag, push e crea la
# release su GitHub. Se un controllo fallisce non viene pubblicato nulla.
#
# Se massan71/homebrew-tap è clonato accanto a questo repository (o in
# $HOMEBREW_TAP_DIR), aggiorna anche il cask subnetscout e lo pubblica.
#
# Facoltativo: RELEASE_COMMIT_TRAILER viene aggiunto al messaggio di commit.

set -euo pipefail

RESTORE_ON_EXIT=0
die() {
  echo "errore: $*" >&2
  # exit non attiva il trap ERR: ripristina qui la versione se era già stata cambiata
  [[ "$RESTORE_ON_EXIT" == 1 ]] && git checkout -q -- Resources/Info.plist && echo "Modifica di versione annullata." >&2
  exit 1
}

VERSION="${1:-}"
NOTES="${2:-}"
YES="${3:-}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "uso: scripts/release.sh <versione> <note.md> [--yes]"
[[ -f "$NOTES" ]] || die "file delle note non trovato: $NOTES"
NOTES="$(cd "$(dirname "$NOTES")" && pwd)/$(basename "$NOTES")"
TAG="v$VERSION"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PLIST="Resources/Info.plist"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

# --- Controlli sul repository -----------------------------------------------
command -v gh >/dev/null || die "GitHub CLI (gh) non installata"
gh auth status >/dev/null 2>&1 || die "gh non è autenticato (gh auth login)"
[[ "$(git branch --show-current)" == "main" ]] || die "non sei su main"
[[ -z "$(git status --porcelain)" ]] || die "ci sono modifiche non committate"
git fetch -q origin
[[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/main)" ]] || die "main non è allineato con origin/main"
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null && die "il tag $TAG esiste già"
git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1 && die "il tag $TAG esiste già su GitHub"
TAP_DIR="${HOMEBREW_TAP_DIR:-$ROOT/../homebrew-tap}"
CASK="$TAP_DIR/Casks/subnetscout.rb"
if [[ -f "$CASK" && -n "$(git -C "$TAP_DIR" status --porcelain)" ]]; then
  die "il tap Homebrew $TAP_DIR ha modifiche non committate"
fi

# --- Versione ----------------------------------------------------------------
OLD_BUILD="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$PLIST")"
BUILD=$((OLD_BUILD + 1))
restore() { git checkout -q -- "$PLIST"; }
trap 'echo "Interrotto: modifica di versione annullata." >&2; restore' ERR INT
RESTORE_ON_EXIT=1
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" -c "Set :CFBundleVersion $BUILD" "$PLIST"
echo "Versione $VERSION (build $BUILD)"

# --- Test e build ------------------------------------------------------------
echo "Test…"
swift test --skip IntegrationTests -q >/dev/null 2>&1 || die "i test non passano (swift test)"
echo "Build universale…"
scripts/bundle.sh >/dev/null

OUT="build/release"
rm -rf "$OUT"
mkdir -p "$OUT/stage"
# Gli attributi estesi di Finder/iCloud invalidano la firma: si copia senza.
ditto --norsrc --noextattr --noacl build/SubnetScout.app "$OUT/stage/SubnetScout.app"
ZIP="$OUT/SubnetScout-$VERSION.zip"
ditto -c -k --norsrc --noextattr --keepParent "$OUT/stage/SubnetScout.app" "$ZIP"

# --- Verifica dell'app estratta ---------------------------------------------
CHECK="$(mktemp -d)"
ditto -x -k "$ZIP" "$CHECK"
APP="$CHECK/SubnetScout.app"
codesign --verify --deep --strict "$APP" || die "verifica della firma fallita"
for bin in SubnetScout SubnetScoutHelper; do
  ARCHS="$(lipo -archs "$APP/Contents/MacOS/$bin")"
  [[ "$ARCHS" == *arm64* && "$ARCHS" == *x86_64* ]] || die "$bin non è universale: $ARCHS"
done
[[ "$(codesign -dv "$APP/Contents/MacOS/SubnetScoutHelper" 2>&1 | grep '^Identifier=')" == "Identifier=net.sangalli.SubnetScout.helper" ]] \
  || die "identificatore del helper errato"
[[ -f "$APP/Contents/Library/LaunchDaemons/net.sangalli.SubnetScout.helper.plist" ]] || die "plist del helper mancante"
[[ -f "$APP/Contents/Resources/AppIcon.icns" ]] || die "icona mancante"
APP_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")"
[[ "$APP_VERSION" == "$VERSION" ]] || die "l'app riporta la versione $APP_VERSION"
rm -rf "$CHECK"
SHA="$(shasum -a 256 "$ZIP" | cut -d' ' -f1)"
echo "Verificato: firma, arm64 + x86_64 (app e helper), helper, icona, versione $APP_VERSION"
echo "$ZIP ($(du -h "$ZIP" | cut -f1)) SHA-256 $SHA"

# --- Note di rilascio --------------------------------------------------------
FULL_NOTES="$OUT/notes.md"
{
  cat "$NOTES"
  cat <<EOF

## Install

\`brew install --cask massan71/tap/subnetscout\` (also installs nmap), or manually:

1. Install nmap: \`brew install nmap\` or the official package from [nmap.org](https://nmap.org/download.html#macosx).
2. Download \`SubnetScout-$VERSION.zip\`, unzip it and move \`SubnetScout.app\` to \`/Applications\` (replacing the previous version).
3. **This build is not notarized** (no Apple Developer ID): the first time, macOS blocks it. Go to **System Settings › Privacy & Security** and click **Open Anyway**.
4. Recommended: click **Install Helper…** in the sidebar and approve it in **System Settings › General › Login Items & Extensions**, so scans never ask for a password. The helper only runs a root-owned nmap: with the nmap.org package use **Copy nmap to Protected Location…**.

Requires macOS 14 or later. Universal binary (Apple silicon and Intel).

⚠️ Only use SubnetScout on networks you own or are explicitly authorized to test.

SHA-256 of \`SubnetScout-$VERSION.zip\`:
\`$SHA\`
EOF
} > "$FULL_NOTES"

# --- Pubblicazione -----------------------------------------------------------
if [[ "$YES" != "--yes" ]]; then
  read -r -p "Commit, tag e pubblicazione di $TAG su GitHub? [s/N] " answer
  [[ "$answer" == "s" || "$answer" == "S" || "$answer" == "y" ]] || { restore; echo "Non pubblicato; versione ripristinata."; exit 1; }
fi
trap - ERR INT
RESTORE_ON_EXIT=0

MESSAGE="Release $VERSION"
[[ -n "${RELEASE_COMMIT_TRAILER:-}" ]] && MESSAGE="$MESSAGE"$'\n\n'"$RELEASE_COMMIT_TRAILER"
git commit -q -m "$MESSAGE" -- "$PLIST"
git tag -a "$TAG" -m "SubnetScout $VERSION"
git push -q origin main
git push -q origin "$TAG"
gh release create "$TAG" "$ZIP" --title "SubnetScout $VERSION" --notes-file "$FULL_NOTES" --verify-tag

# Verifica che GitHub abbia lo stesso file
REMOTE_SHA="$(gh release view "$TAG" --json assets --jq '.assets[0].digest' | sed 's/^sha256://')"
[[ "$REMOTE_SHA" == "$SHA" ]] || die "il checksum del file caricato è diverso: $REMOTE_SHA"
echo "Pubblicata $TAG: $(gh release view "$TAG" --json url --jq .url)"

# --- Cask Homebrew -----------------------------------------------------------
# Aggiorna massan71/homebrew-tap così `brew upgrade --cask subnetscout` trova la nuova versione.
if [[ -f "$CASK" ]]; then
  git -C "$TAP_DIR" pull -q --ff-only
  sed -i '' -E "s/^  version \"[^\"]*\"/  version \"$VERSION\"/; s/^  sha256 \"[^\"]*\"/  sha256 \"$SHA\"/" "$CASK"
  grep -q "version \"$VERSION\"" "$CASK" && grep -q "sha256 \"$SHA\"" "$CASK" \
    || { echo "attenzione: impossibile aggiornare $CASK, aggiornalo a mano" >&2; git -C "$TAP_DIR" checkout -q -- Casks/subnetscout.rb; exit 0; }
  ruby -c "$CASK" >/dev/null
  CASK_MESSAGE="Update SubnetScout to $VERSION"
  [[ -n "${RELEASE_COMMIT_TRAILER:-}" ]] && CASK_MESSAGE="$CASK_MESSAGE"$'\n\n'"$RELEASE_COMMIT_TRAILER"
  git -C "$TAP_DIR" commit -q -m "$CASK_MESSAGE" -- Casks/subnetscout.rb
  git -C "$TAP_DIR" push -q
  echo "Cask Homebrew aggiornato: brew upgrade --cask subnetscout"
else
  echo "Tap Homebrew non trovato in $TAP_DIR: cask non aggiornato"
fi
