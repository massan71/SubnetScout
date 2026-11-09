#!/bin/bash
# Compila SubnetScout in Release (universale arm64 + x86_64) e crea build/SubnetScout.app
# con il privileged helper incluso.
#
#   scripts/bundle.sh            # build + bundle + firma
#   scripts/bundle.sh --open     # ...e avvia l'app
#
#   SIGN_IDENTITY="Developer ID Application: Nome (TEAMID)" scripts/bundle.sh
#     firma con Developer ID: il helper accetterà solo client dello stesso team.
#     Senza, firma ad-hoc (solo sviluppo: il helper verifica solo l'identificatore).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
SIGN_IDENTITY="${SIGN_IDENTITY:--}"
ARCHS=(--arch arm64 --arch x86_64)

swift build -c release "${ARCHS[@]}"
BIN_DIR="$(swift build -c release "${ARCHS[@]}" --show-bin-path)"

APP="build/SubnetScout.app"
# Il bundle viene assemblato a parte e poi sincronizzato su quello esistente:
# NON va cancellato e ricreato, altrimenti macOS lo considera un'altra app e la
# registrazione del helper (SMAppService) resta legata al bundle vecchio
# (launchd: "copy_bundle_path … Invalid or missing Program").
STAGE="build/.stage/SubnetScout.app"
rm -rf "build/.stage"
mkdir -p "$STAGE/Contents/MacOS" "$STAGE/Contents/Resources" "$STAGE/Contents/Library/LaunchDaemons"
cp "$BIN_DIR/SubnetScout" "$STAGE/Contents/MacOS/SubnetScout"
cp "$BIN_DIR/SubnetScoutHelper" "$STAGE/Contents/MacOS/SubnetScoutHelper"
cp Resources/Info.plist "$STAGE/Contents/Info.plist"
cp Resources/net.sangalli.SubnetScout.helper.plist "$STAGE/Contents/Library/LaunchDaemons/"
[[ -f Resources/AppIcon.icns ]] && cp Resources/AppIcon.icns "$STAGE/Contents/Resources/" || true
mkdir -p "$APP"
rsync -a --delete "$STAGE/" "$APP/"
rm -rf "build/.stage"
xattr -cr "$APP"   # codesign rifiuta attributi estesi ("detritus")

# Prima il helper (con il suo identificatore), poi l'app che lo sigilla.
codesign --force --sign "$SIGN_IDENTITY" --options runtime --timestamp=none \
  --identifier net.sangalli.SubnetScout.helper "$APP/Contents/MacOS/SubnetScoutHelper"
codesign --force --sign "$SIGN_IDENTITY" --options runtime --timestamp=none "$APP"
codesign --verify --strict "$APP"
echo "✓ $APP (firma: $SIGN_IDENTITY)"

[[ "${1:-}" == "--open" ]] && open "$APP"
exit 0
