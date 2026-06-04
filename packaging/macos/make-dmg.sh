#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

APP_NAME="${APP_NAME:-Sniper}"

validate_path_component() {
  local label="$1"
  local name="$2"
  if [[ -z "$name" || "$name" == "." || "$name" == ".." || "$name" == *"/"* || "$name" == *"\\"* || "$name" == *"'"* || "$name" == *"\""* || "$name" == *'$'* || "$name" == *'`'* || "$name" == *$'\n'* || "$name" == *$'\r'* || "$name" == *$'\t'* ]]; then
    echo "Invalid $label: must be a single safe path component" >&2
    exit 1
  fi
}

validate_app_name() {
  validate_path_component "APP_NAME" "$1"
}

validate_app_name "$APP_NAME"

CARGO_VERSION="$(awk -F '\"' '/^version = / { print $2; exit }' Cargo.toml)"
VERSION="${VERSION:-$CARGO_VERSION}"
if [[ "$VERSION" != "$CARGO_VERSION" ]]; then
  echo "VERSION=$VERSION does not match Cargo.toml version $CARGO_VERSION" >&2
  exit 1
fi
APP_BUNDLE="$ROOT_DIR/dist/${APP_NAME}.app"
REQUESTED_DMG_ARCH="${DMG_ARCH:-}"
DMG_ARCH=""
DMG_PATH=""
TMP_ROOT=""
DMG_TMP=""
DMG_FINAL_TMP=""
STAGING_DIR=""
BG_IMG="$ROOT_DIR/packaging/macos/dmg-background.png"
VOLUME_NAME="$APP_NAME"
DEVICE=""

cleanup() {
  if [[ -n "$DEVICE" ]]; then
    hdiutil detach "$DEVICE" -quiet 2>/dev/null || hdiutil detach "$DEVICE" -force >/dev/null 2>&1 || true
  fi
  if [[ -n "$TMP_ROOT" ]]; then
    rm -rf "$TMP_ROOT"
  fi
}

trap cleanup EXIT

normalize_dmg_arch() {
  local arch
  arch="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$arch" in
    arm64 | aarch64)
      printf '%s\n' "arm64"
      ;;
    x86_64 | x64 | amd64)
      printf '%s\n' "x86_64"
      ;;
    universal)
      printf '%s\n' "universal"
      ;;
    *)
      return 1
      ;;
  esac
}

bundle_executable_path() {
  local app_bundle="$1"
  local info_plist="$app_bundle/Contents/Info.plist"
  local executable_name=""
  if [[ -f "$info_plist" ]]; then
    executable_name="$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$info_plist" 2>/dev/null || true)"
  fi
  if [[ -z "$executable_name" ]]; then
    executable_name="$APP_NAME"
  fi
  validate_path_component "CFBundleExecutable" "$executable_name"
  printf '%s\n' "$app_bundle/Contents/MacOS/$executable_name"
}

dmg_arch_from_lipo_archs() {
  local archs="$1"
  local has_arm64=0
  local has_x86_64=0
  local arch

  for arch in $archs; do
    case "$arch" in
      arm64 | aarch64)
        has_arm64=1
        ;;
      x86_64)
        has_x86_64=1
        ;;
      *)
        echo "Unsupported app executable architecture from lipo: $arch" >&2
        return 1
        ;;
    esac
  done

  if [[ "$has_arm64" == "1" && "$has_x86_64" == "1" ]]; then
    printf '%s\n' "universal"
  elif [[ "$has_arm64" == "1" ]]; then
    printf '%s\n' "arm64"
  elif [[ "$has_x86_64" == "1" ]]; then
    printf '%s\n' "x86_64"
  else
    echo "Unable to determine a supported app executable architecture" >&2
    return 1
  fi
}

detect_app_dmg_arch() {
  local app_bundle="$1"
  local executable_path
  local archs
  executable_path="$(bundle_executable_path "$app_bundle")"
  if [[ ! -x "$executable_path" ]]; then
    echo "Missing executable app binary: $executable_path" >&2
    return 1
  fi
  if ! archs="$(/usr/bin/lipo -archs "$executable_path" 2>/dev/null)"; then
    echo "Unable to inspect app executable architecture: $executable_path" >&2
    return 1
  fi
  dmg_arch_from_lipo_archs "$archs"
}

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  "$ROOT_DIR/packaging/macos/make-app.sh"
elif [[ ! -d "$APP_BUNDLE" ]]; then
  echo "SKIP_BUILD=1 was set but $APP_BUNDLE does not exist" >&2
  exit 1
fi

if ! DMG_ARCH="$(detect_app_dmg_arch "$APP_BUNDLE")"; then
  exit 1
fi

if [[ -n "$REQUESTED_DMG_ARCH" ]]; then
  if ! NORMALIZED_REQUESTED_DMG_ARCH="$(normalize_dmg_arch "$REQUESTED_DMG_ARCH")"; then
    echo "Unsupported DMG_ARCH value: $REQUESTED_DMG_ARCH" >&2
    exit 1
  fi
  if [[ "$NORMALIZED_REQUESTED_DMG_ARCH" != "$DMG_ARCH" || "$REQUESTED_DMG_ARCH" != "$DMG_ARCH" ]]; then
    echo "DMG_ARCH=$REQUESTED_DMG_ARCH does not match bundled app executable architecture: $DMG_ARCH. Use the canonical label $DMG_ARCH." >&2
    exit 1
  fi
fi

DMG_PATH="$ROOT_DIR/dist/${APP_NAME}-${VERSION}-${DMG_ARCH}.dmg"

if [[ ! -f "$BG_IMG" ]]; then
  echo "Missing DMG background image: $BG_IMG" >&2
  exit 1
fi

mkdir -p "$ROOT_DIR/dist"
TMP_ROOT="$(mktemp -d "$ROOT_DIR/dist/.dmg-build.XXXXXX")"
DMG_TMP="$TMP_ROOT/${APP_NAME}-tmp.dmg"
DMG_FINAL_TMP="$TMP_ROOT/${APP_NAME}-${VERSION}-${DMG_ARCH}.dmg"
STAGING_DIR="$TMP_ROOT/dmg-root"

mkdir -p "$STAGING_DIR/.background"
cp -R "$APP_BUNDLE" "$STAGING_DIR/"
ln -s /Applications "$STAGING_DIR/Applications"
cp "$BG_IMG" "$STAGING_DIR/.background/background.png"

VOLUME_ICON="$ROOT_DIR/packaging/macos/AppIcon.icns"
if [[ -f "$VOLUME_ICON" ]]; then
  cp "$VOLUME_ICON" "$STAGING_DIR/.VolumeIcon.icns"
  SetFile -c icnC "$STAGING_DIR/.VolumeIcon.icns" 2>/dev/null || true
  SetFile -a C "$STAGING_DIR" 2>/dev/null || true
fi

# Create read-write HFS+ DMG
hdiutil create \
  -volname "$VOLUME_NAME" \
  -srcfolder "$STAGING_DIR" \
  -ov \
  -fs HFS+ \
  -format UDRW \
  "$DMG_TMP"

# Mount
ATTACH_OUTPUT=$(hdiutil attach -readwrite -noverify -noautoopen "$DMG_TMP")
DEVICE=$(echo "$ATTACH_OUTPUT" | awk '/\/Volumes\// { print $1 }')
MOUNT_POINT=$(echo "$ATTACH_OUTPUT" | awk '/\/Volumes\// { for(i=NF;i>=1;i--) if($i ~ /^\/Volumes/) { s=$i; for(j=i+1;j<=NF;j++) s=s" "$j; print s; exit } }')
DISK_NAME=$(basename "$MOUNT_POINT")

echo "Mounted at: $MOUNT_POINT (device: $DEVICE)"
sleep 2

# Style with AppleScript — run twice to ensure Finder persists DS_Store
for pass in 1 2; do
  osascript <<APPLESCRIPT
tell application "Finder"
  tell disk "$DISK_NAME"
    open
    set current view of container window to icon view
    set toolbar visible of container window to false
    set statusbar visible of container window to false
    set bounds of container window to {200, 120, 854, 542}

    set theViewOptions to icon view options of container window
    set arrangement of theViewOptions to not arranged
    set icon size of theViewOptions to 100

    set background picture of theViewOptions to file ".background:background.png"

    set position of item "${APP_NAME}.app" to {170, 190}
    set position of item "Applications" to {490, 190}

    try
      set position of item ".background" to {900, 900}
    end try
    try
      set position of item ".fseventsd" to {900, 900}
    end try
    try
      set position of item ".VolumeIcon.icns" to {900, 900}
    end try

    update without registering applications
    delay 3
    close
  end tell
end tell
APPLESCRIPT
  sleep 2
done

sync
sleep 1
hdiutil detach "$DEVICE" -quiet || hdiutil detach "$DEVICE" -force
DEVICE=""

# Convert to compressed read-only DMG
hdiutil convert "$DMG_TMP" -format UDZO -imagekey zlib-level=9 -o "$DMG_FINAL_TMP"
mv -f "$DMG_FINAL_TMP" "$DMG_PATH"

echo "Created DMG: $DMG_PATH"
