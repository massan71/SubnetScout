#!/bin/bash
# Builds, verifies and publishes a SubnetScout release on GitHub.
#
#   scripts/release.sh <version> <notes.md> [--yes]
#
#   <version>   e.g. 0.1.0 (the tag will be v<version>)
#   <notes.md>  release notes ("What's new"); install instructions and the
#               SHA-256 of the zip are appended automatically
#   --yes       publish without asking for confirmation
#
# Steps: checks the repository, sets the version (build + 1) in Info.plist,
# builds the universal bundle with scripts/bundle.sh, creates the zip without
# Finder/iCloud attributes, verifies the unzipped app (signature, architectures,
# version, helper), then (after confirmation) commits, tags, pushes and creates the
# GitHub release. If a check fails nothing is published.
#
# If massan71/homebrew-tap is cloned next to this repository (or in
# $HOMEBREW_TAP_DIR), it also updates and publishes the subnetscout cask.
#
# Optional: RELEASE_COMMIT_TRAILER is appended to the commit message.

set -euo pipefail

RESTORE_ON_EXIT=0
die() {
  echo "error: $*" >&2
  # exit does not trigger the ERR trap: restore the version here if it was already changed
  [[ "$RESTORE_ON_EXIT" == 1 ]] && git checkout -q -- Resources/Info.plist && echo "Version change reverted." >&2
  exit 1
}

VERSION="${1:-}"
NOTES="${2:-}"
YES="${3:-}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "usage: scripts/release.sh <version> <notes.md> [--yes]"
[[ -f "$NOTES" ]] || die "notes file not found: $NOTES"
NOTES="$(cd "$(dirname "$NOTES")" && pwd)/$(basename "$NOTES")"
TAG="v$VERSION"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PLIST="Resources/Info.plist"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

# --- Repository checks ------------------------------------------------------
command -v gh >/dev/null || die "GitHub CLI (gh) is not installed"
gh auth status >/dev/null 2>&1 || die "gh is not authenticated (gh auth login)"
[[ "$(git branch --show-current)" == "main" ]] || die "not on main"
[[ -z "$(git status --porcelain)" ]] || die "there are uncommitted changes"
git fetch -q origin
[[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/main)" ]] || die "main is not in sync with origin/main"
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null && die "tag $TAG already exists"
git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1 && die "tag $TAG already exists on GitHub"
TAP_DIR="${HOMEBREW_TAP_DIR:-$ROOT/../homebrew-tap}"
CASK="$TAP_DIR/Casks/subnetscout.rb"
if [[ -f "$CASK" && -n "$(git -C "$TAP_DIR" status --porcelain)" ]]; then
  die "the Homebrew tap $TAP_DIR has uncommitted changes"
fi

# --- Version -----------------------------------------------------------------
OLD_BUILD="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$PLIST")"
BUILD=$((OLD_BUILD + 1))
restore() { git checkout -q -- "$PLIST"; }
trap 'echo "Interrupted: version change reverted." >&2; restore' ERR INT
RESTORE_ON_EXIT=1
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" -c "Set :CFBundleVersion $BUILD" "$PLIST"
echo "Version $VERSION (build $BUILD)"

# --- Tests and build --------------------------------------------------------
echo "Tests…"
swift test --skip IntegrationTests -q >/dev/null 2>&1 || die "tests are failing (swift test)"
echo "Universal build…"
scripts/bundle.sh >/dev/null

OUT="build/release"
rm -rf "$OUT"
mkdir -p "$OUT/stage"
# Finder/iCloud extended attributes invalidate the signature: copy without them.
ditto --norsrc --noextattr --noacl build/SubnetScout.app "$OUT/stage/SubnetScout.app"
ZIP="$OUT/SubnetScout-$VERSION.zip"
ditto -c -k --norsrc --noextattr --keepParent "$OUT/stage/SubnetScout.app" "$ZIP"

# --- Verify the unzipped app -------------------------------------------------
CHECK="$(mktemp -d)"
ditto -x -k "$ZIP" "$CHECK"
APP="$CHECK/SubnetScout.app"
codesign --verify --deep --strict "$APP" || die "signature verification failed"
for bin in SubnetScout SubnetScoutHelper; do
  ARCHS="$(lipo -archs "$APP/Contents/MacOS/$bin")"
  [[ "$ARCHS" == *arm64* && "$ARCHS" == *x86_64* ]] || die "$bin is not universal: $ARCHS"
done
[[ "$(codesign -dv "$APP/Contents/MacOS/SubnetScoutHelper" 2>&1 | grep '^Identifier=')" == "Identifier=net.sangalli.SubnetScout.helper" ]] \
  || die "wrong helper identifier"
[[ -f "$APP/Contents/Library/LaunchDaemons/net.sangalli.SubnetScout.helper.plist" ]] || die "helper plist missing"
[[ -f "$APP/Contents/Resources/AppIcon.icns" ]] || die "icon missing"
APP_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")"
[[ "$APP_VERSION" == "$VERSION" ]] || die "the app reports version $APP_VERSION"
rm -rf "$CHECK"
SHA="$(shasum -a 256 "$ZIP" | cut -d' ' -f1)"
echo "Verified: signature, arm64 + x86_64 (app and helper), helper, icon, version $APP_VERSION"
echo "$ZIP ($(du -h "$ZIP" | cut -f1)) SHA-256 $SHA"

# --- Release notes -----------------------------------------------------------
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

# --- Publish -----------------------------------------------------------------
if [[ "$YES" != "--yes" ]]; then
  read -r -p "Commit, tag and publish $TAG on GitHub? [y/N] " answer
  [[ "$answer" == "y" || "$answer" == "Y" ]] || { restore; echo "Not published; version restored."; exit 1; }
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

# Check that GitHub has the same file
REMOTE_SHA="$(gh release view "$TAG" --json assets --jq '.assets[0].digest' | sed 's/^sha256://')"
[[ "$REMOTE_SHA" == "$SHA" ]] || die "the checksum of the uploaded file differs: $REMOTE_SHA"
echo "Published $TAG: $(gh release view "$TAG" --json url --jq .url)"

# --- Cask Homebrew -----------------------------------------------------------
# Updates massan71/homebrew-tap so that `brew upgrade --cask subnetscout` finds the new version.
if [[ -f "$CASK" ]]; then
  git -C "$TAP_DIR" pull -q --ff-only
  sed -i '' -E "s/^  version \"[^\"]*\"/  version \"$VERSION\"/; s/^  sha256 \"[^\"]*\"/  sha256 \"$SHA\"/" "$CASK"
  grep -q "version \"$VERSION\"" "$CASK" && grep -q "sha256 \"$SHA\"" "$CASK" \
    || { echo "warning: could not update $CASK, update it by hand" >&2; git -C "$TAP_DIR" checkout -q -- Casks/subnetscout.rb; exit 0; }
  ruby -c "$CASK" >/dev/null
  CASK_MESSAGE="Update SubnetScout to $VERSION"
  [[ -n "${RELEASE_COMMIT_TRAILER:-}" ]] && CASK_MESSAGE="$CASK_MESSAGE"$'\n\n'"$RELEASE_COMMIT_TRAILER"
  git -C "$TAP_DIR" commit -q -m "$CASK_MESSAGE" -- Casks/subnetscout.rb
  git -C "$TAP_DIR" push -q
  echo "Homebrew cask updated: brew upgrade --cask subnetscout"
else
  echo "Homebrew tap not found in $TAP_DIR: cask not updated"
fi
