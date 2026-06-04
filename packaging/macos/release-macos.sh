#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

APP_NAME="${APP_NAME:-Sniper}"
if [[ "$APP_NAME" != "Sniper" ]]; then
  echo "release-macos.sh only supports APP_NAME=Sniper; self-update pins the Sniper executable." >&2
  exit 1
fi
CARGO_VERSION="$(awk -F '\"' '/^version = / { print $2; exit }' Cargo.toml)"
VERSION="${VERSION:-$CARGO_VERSION}"
if [[ "$VERSION" != "$CARGO_VERSION" ]]; then
  echo "VERSION=$VERSION does not match Cargo.toml version $CARGO_VERSION" >&2
  exit 1
fi
REQUESTED_DMG_ARCH="${DMG_ARCH:-}"
SIGN_IDENTITY="${DEVELOPER_ID_APP:-${SIGN_IDENTITY:-}}"
ALLOW_ADHOC_RELEASE="${ALLOW_ADHOC_RELEASE:-0}"
HAS_APPLE_CREDS=0
HAS_PARTIAL_APPLE_CREDS=0
if [[ -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" && -n "${APPLE_APP_PASSWORD:-}" ]]; then
  HAS_APPLE_CREDS=1
elif [[ -n "${APPLE_ID:-}" || -n "${APPLE_TEAM_ID:-}" || -n "${APPLE_APP_PASSWORD:-}" ]]; then
  HAS_PARTIAL_APPLE_CREDS=1
fi

if [[ "$ALLOW_ADHOC_RELEASE" != "1" && -z "$SIGN_IDENTITY" ]]; then
  echo "Developer ID signing identity is required for release artifacts. Set DEVELOPER_ID_APP or SIGN_IDENTITY." >&2
  echo "For local-only unsigned testing, set ALLOW_ADHOC_RELEASE=1." >&2
  exit 1
fi

if [[ "$ALLOW_ADHOC_RELEASE" != "1" && "$HAS_APPLE_CREDS" == "1" ]]; then
  if [[ -z "$SIGN_IDENTITY" ]]; then
    echo "Apple notarization credentials were provided but no signing identity is configured." >&2
    exit 1
  fi
elif [[ "$ALLOW_ADHOC_RELEASE" != "1" ]]; then
  if [[ "$HAS_PARTIAL_APPLE_CREDS" == "1" ]]; then
    echo "Incomplete Apple notarization credentials. Set APPLE_ID, APPLE_TEAM_ID, and APPLE_APP_PASSWORD." >&2
    exit 1
  fi
  echo "Apple notarization credentials are required for signed release artifacts." >&2
  echo "Set APPLE_ID, APPLE_TEAM_ID, and APPLE_APP_PASSWORD." >&2
  exit 1
elif [[ "$HAS_PARTIAL_APPLE_CREDS" == "1" ]]; then
  echo "Ignoring incomplete Apple notarization credentials for explicit local-only release (ALLOW_ADHOC_RELEASE=1)." >&2
fi

mkdir -p "$ROOT_DIR/dist"
DMG_BUILD_MARKER="$(mktemp "$ROOT_DIR/dist/.release-dmg-marker.XXXXXX")"
cleanup_release_marker() {
  rm -f "$DMG_BUILD_MARKER"
}
trap cleanup_release_marker EXIT

"$ROOT_DIR/packaging/macos/make-app.sh"

if [[ -n "$REQUESTED_DMG_ARCH" ]]; then
  DMG_ARCH="$REQUESTED_DMG_ARCH" SKIP_BUILD=1 "$ROOT_DIR/packaging/macos/make-dmg.sh"
else
  SKIP_BUILD=1 "$ROOT_DIR/packaging/macos/make-dmg.sh"
fi

DMG_CANDIDATES=()
while IFS= read -r candidate; do
  DMG_CANDIDATES+=("$candidate")
done < <(find "$ROOT_DIR/dist" -maxdepth 1 -type f -name "${APP_NAME}-${VERSION}-*.dmg" -newer "$DMG_BUILD_MARKER" -print)

if [[ "${#DMG_CANDIDATES[@]}" -ne 1 ]]; then
  echo "Expected exactly one freshly built DMG for ${APP_NAME} ${VERSION}, found ${#DMG_CANDIDATES[@]}." >&2
  printf '  %s\n' "${DMG_CANDIDATES[@]}" >&2
  exit 1
fi

DMG_PATH="${DMG_CANDIDATES[0]}"

if [[ "$ALLOW_ADHOC_RELEASE" != "1" && "$HAS_APPLE_CREDS" == "1" ]]; then
  xcrun notarytool submit "$DMG_PATH" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD" \
    --wait
  xcrun stapler staple "$DMG_PATH"
elif [[ "$ALLOW_ADHOC_RELEASE" == "1" ]]; then
  echo "Skipping notarization for explicit local-only release (ALLOW_ADHOC_RELEASE=1)." >&2
fi

echo "macOS release artifacts ready in $ROOT_DIR/dist"
