#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

APP_NAME="${APP_NAME:-Sniper}"

validate_app_name() {
  local name="$1"
  if [[ -z "$name" || "$name" == "." || "$name" == ".." || "$name" == *"/"* || "$name" == *"\\"* || "$name" == *"'"* || "$name" == *"\""* || "$name" == *$'\n'* || "$name" == *$'\r'* || "$name" == *$'\t'* ]]; then
    echo "Invalid APP_NAME: must be a single safe app name" >&2
    exit 1
  fi
}

validate_app_name "$APP_NAME"

APP_BUNDLE="$ROOT_DIR/dist/${APP_NAME}.app"
CONTENTS_DIR="$APP_BUNDLE/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
PLIST_TEMPLATE="$ROOT_DIR/packaging/macos/Info.plist"
PLIST_OUT="$CONTENTS_DIR/Info.plist"
ENTITLEMENTS="$ROOT_DIR/packaging/macos/entitlements.plist"
BIN_PATH="$ROOT_DIR/target/release/sniper-desktop"
VERSION="${VERSION:-$(awk -F '\"' '/^version = / { print $2; exit }' Cargo.toml)}"

sed_escape_replacement() {
  printf '%s' "$1" | sed -e 's/[\/&\\]/\\&/g'
}

xml_escape() {
  local value="$1"
  value="${value//&/&amp;}"
  value="${value//</&lt;}"
  value="${value//>/&gt;}"
  printf '%s' "$value"
}

plist_sed_replacement() {
  sed_escape_replacement "$(xml_escape "$1")"
}

rm -rf "$APP_BUNDLE"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

cargo build --release --bin sniper-desktop --bin sniper-cli

cp "$BIN_PATH" "$MACOS_DIR/$APP_NAME"
chmod +x "$MACOS_DIR/$APP_NAME"

CLI_BIN_PATH="$ROOT_DIR/target/release/sniper-cli"
cp "$CLI_BIN_PATH" "$MACOS_DIR/sniper-cli"
chmod +x "$MACOS_DIR/sniper-cli"
sed \
  -e "s/__SNIPER_VERSION__/$(plist_sed_replacement "$VERSION")/g" \
  -e "s/__APP_NAME__/$(plist_sed_replacement "$APP_NAME")/g" \
  "$PLIST_TEMPLATE" > "$PLIST_OUT"

BUNDLED_ICON="$ROOT_DIR/packaging/macos/AppIcon.icns"
APP_ICON="${APP_ICON:-$BUNDLED_ICON}"
if [[ -f "$APP_ICON" ]]; then
  cp "$APP_ICON" "$RESOURCES_DIR/AppIcon.icns"
  /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string AppIcon" "$PLIST_OUT" 2>/dev/null || \
    /usr/libexec/PlistBuddy -c "Set :CFBundleIconFile AppIcon" "$PLIST_OUT"
fi

SIGN_IDENTITY="${DEVELOPER_ID_APP:-${SIGN_IDENTITY:-}}"
if [[ -n "$SIGN_IDENTITY" ]]; then
  codesign --force --deep --timestamp --options runtime --entitlements "$ENTITLEMENTS" --sign "$SIGN_IDENTITY" "$APP_BUNDLE"
else
  codesign --force --deep --sign - "$APP_BUNDLE"
fi

echo "Created app bundle: $APP_BUNDLE"
