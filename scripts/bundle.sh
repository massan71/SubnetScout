#!/bin/bash
# Builds SubnetScout in Release (universal arm64 + x86_64) and creates build/SubnetScout.app
# with the privileged helper included.
#
#   scripts/bundle.sh            # build + bundle + sign
#   scripts/bundle.sh --open     # ...and launch the app
#
#   SIGN_IDENTITY="Developer ID Application: Name (TEAMID)" scripts/bundle.sh
#     signs with a Developer ID: the helper will only accept clients from the same team.
#
# Without SIGN_IDENTITY it uses the "SubnetScout Code Signing" certificate from the
# keychain, if present: app and helper then verify each other through the certificate.
# Otherwise it signs ad hoc. Without a Developer ID, macOS still ties the helper
# approval and Keychain access to the binary hash, so they are asked again after
# every new build.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
if [[ -z "${SIGN_IDENTITY:-}" ]]; then
  SIGN_IDENTITY="$(security find-identity -p codesigning 2>/dev/null | awk '/"SubnetScout Code Signing"/ { print $2; exit }')"
  SIGN_IDENTITY="${SIGN_IDENTITY:--}"
fi
ARCHS=(--arch arm64 --arch x86_64)

swift build -c release "${ARCHS[@]}"
BIN_DIR="$(swift build -c release "${ARCHS[@]}" --show-bin-path)"

APP="build/SubnetScout.app"
# The bundle is assembled and signed in a temporary folder, then
# synced onto the existing one. Two reasons:
#  1. It must NOT be deleted and recreated, otherwise macOS treats it as another app and
#     the helper registration (SMAppService) stays tied to the old bundle
#     (launchd: "copy_bundle_path … Invalid or missing Program").
#  2. In a folder synced with iCloud (e.g. Documents) macOS puts
#     com.apple.FinderInfo back on the bundle and codesign fails ("detritus not allowed").
STAGE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/subnetscout-bundle.XXXXXX")"
trap 'rm -rf "$STAGE_ROOT"' EXIT
STAGE="$STAGE_ROOT/SubnetScout.app"
mkdir -p "$STAGE/Contents/MacOS" "$STAGE/Contents/Resources" "$STAGE/Contents/Library/LaunchDaemons"
cp "$BIN_DIR/SubnetScout" "$STAGE/Contents/MacOS/SubnetScout"
cp "$BIN_DIR/SubnetScoutHelper" "$STAGE/Contents/MacOS/SubnetScoutHelper"
cp Resources/Info.plist "$STAGE/Contents/Info.plist"
cp Resources/net.sangalli.SubnetScout.helper.plist "$STAGE/Contents/Library/LaunchDaemons/"
[[ -f Resources/AppIcon.icns ]] && cp Resources/AppIcon.icns "$STAGE/Contents/Resources/" || true
xattr -cr "$STAGE"

# The helper first (with its own identifier), then the app that seals it.
codesign --force --sign "$SIGN_IDENTITY" --options runtime --timestamp=none \
  --identifier net.sangalli.SubnetScout.helper "$STAGE/Contents/MacOS/SubnetScoutHelper"
codesign --force --sign "$SIGN_IDENTITY" --options runtime --timestamp=none "$STAGE"
codesign --verify --strict "$STAGE"

# The signature lives in the files (_CodeSignature and Mach-O): copying them keeps it valid.
mkdir -p "$APP"
rsync -a --delete "$STAGE/" "$APP/"
codesign --verify "$APP"
echo "✓ $APP (signed with: $SIGN_IDENTITY)"

[[ "${1:-}" == "--open" ]] && open "$APP"
exit 0
