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
RELEASE_TAG="v$VERSION"
GITHUB_RELEASE_REPO="${GITHUB_RELEASE_REPO:-${GITHUB_REPOSITORY:-sm1ee/Sniper}}"
ALLOW_ADHOC_RELEASE="${ALLOW_ADHOC_RELEASE:-0}"
if [[ "$ALLOW_ADHOC_RELEASE" != "1" ]] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  CURRENT_BRANCH="$(git symbolic-ref --quiet --short HEAD || true)"
  if [[ "$CURRENT_BRANCH" != "main" ]]; then
    echo "Release artifacts must be built from the main branch; current branch is ${CURRENT_BRANCH:-detached}." >&2
    echo "For local-only unsigned testing, set ALLOW_ADHOC_RELEASE=1." >&2
    exit 1
  fi
  if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
    echo "Release artifacts require a clean worktree." >&2
    git status --short --untracked-files=all >&2
    echo "Commit/stash/remove these files first, or set ALLOW_ADHOC_RELEASE=1 for local-only testing." >&2
    exit 1
  fi
  HEAD_COMMIT="$(git rev-parse HEAD)"
  REMOTE_MAIN_COMMIT=""
  if remote_main="$(git ls-remote origin refs/heads/main 2>/dev/null)"; then
    REMOTE_MAIN_COMMIT="$(printf '%s\n' "$remote_main" | awk 'NF >= 2 { print $1; exit }')"
  fi
  if [[ -z "$REMOTE_MAIN_COMMIT" ]]; then
    echo "Unable to verify origin/main before building release artifacts." >&2
    exit 1
  fi
  if [[ "$HEAD_COMMIT" != "$REMOTE_MAIN_COMMIT" ]]; then
    echo "Release artifacts must be built from origin/main ($REMOTE_MAIN_COMMIT), not $HEAD_COMMIT." >&2
    exit 1
  fi
fi
if [[ "$ALLOW_ADHOC_RELEASE" != "1" && "${ALLOW_EXISTING_RELEASE_VERSION:-0}" != "1" ]] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  HEAD_COMMIT="$(git rev-parse HEAD)"
  TAG_COMMIT=""
  if git rev-parse -q --verify "refs/tags/$RELEASE_TAG^{commit}" >/dev/null; then
    TAG_COMMIT="$(git rev-list -n 1 "$RELEASE_TAG")"
    if [[ "$TAG_COMMIT" != "$HEAD_COMMIT" ]]; then
      echo "$RELEASE_TAG already points to $TAG_COMMIT, not current HEAD $HEAD_COMMIT." >&2
      echo "Bump Cargo.toml before creating release artifacts for a new commit." >&2
      exit 1
    fi
  fi
  REMOTE_TAG_COMMIT=""
  if remote_tag="$(git ls-remote --tags origin "$RELEASE_TAG" 2>/dev/null)"; then
    REMOTE_TAG_COMMIT="$(printf '%s\n' "$remote_tag" | awk 'NF >= 2 { print $1; exit }')"
    if [[ -n "$REMOTE_TAG_COMMIT" ]]; then
      echo "$RELEASE_TAG already exists on origin at $REMOTE_TAG_COMMIT." >&2
      echo "Bump Cargo.toml before creating release artifacts for a published version." >&2
      exit 1
    fi
  else
    echo "Unable to verify whether $RELEASE_TAG exists on origin." >&2
    echo "Refusing to create release artifacts without a remote tag check. Set ALLOW_EXISTING_RELEASE_VERSION=1 to override." >&2
    exit 1
  fi
  if command -v gh >/dev/null 2>&1 && [[ -n "$GITHUB_RELEASE_REPO" ]] \
    && gh release view "$RELEASE_TAG" --repo "$GITHUB_RELEASE_REPO" >/dev/null 2>&1; then
    echo "GitHub release $RELEASE_TAG already exists in $GITHUB_RELEASE_REPO." >&2
    echo "Bump Cargo.toml before creating release artifacts for a new commit." >&2
    exit 1
  fi
fi
REQUESTED_DMG_ARCH="${DMG_ARCH:-}"
SIGN_IDENTITY="${DEVELOPER_ID_APP:-${SIGN_IDENTITY:-}}"
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
APP_NOTARY_ZIP=""
cleanup_release_marker() {
  rm -f "$DMG_BUILD_MARKER"
  if [[ -n "$APP_NOTARY_ZIP" ]]; then
    rm -f "$APP_NOTARY_ZIP"
  fi
}
trap cleanup_release_marker EXIT

"$ROOT_DIR/packaging/macos/make-app.sh"

APP_BUNDLE="$ROOT_DIR/dist/${APP_NAME}.app"
if [[ "$ALLOW_ADHOC_RELEASE" != "1" && "$HAS_APPLE_CREDS" == "1" ]]; then
  APP_NOTARY_ZIP="$ROOT_DIR/dist/.${APP_NAME}-${VERSION}-app-notary.zip"
  rm -f "$APP_NOTARY_ZIP"
  /usr/bin/ditto -c -k --keepParent "$APP_BUNDLE" "$APP_NOTARY_ZIP"
  xcrun notarytool submit "$APP_NOTARY_ZIP" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD" \
    --wait
  xcrun stapler staple "$APP_BUNDLE"
  /usr/sbin/spctl --assess --type execute "$APP_BUNDLE"
fi

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
