#!/bin/bash
# Creates a local, user-distributable DMG. It never installs the monitor service.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd -P)
# Version and build number always come from the caller (the engine's reinstall
# command or an explicit command line); no built-in default may go stale.
: "${APP_VERSION:?Set APP_VERSION (for example 3.0.0)}"
: "${BUILD_NUMBER:?Set BUILD_NUMBER (for example 367)}"
APP_NAME='Claude Watch Monitor.app'
APP="${CW_APP_OUTPUT:-$ROOT/build/Claude Watch Monitor Rust Candidate.app}"
DIST="$ROOT/dist"
DMG_NAME="${DMG_NAME:-Claude-Watch-${APP_VERSION}-build${BUILD_NUMBER}-${CW_BUILD_ARCH:-arm64}.dmg}"
DMG="$DIST/$DMG_NAME"
SHA_FILE="$DMG.sha256"

if [[ "$(uname -s)" != 'Darwin' ]]; then
  printf 'DMG packaging requires macOS.\n' >&2
  exit 1
fi
if [[ ! "$APP_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf 'APP_VERSION must be semantic version (for example 2.2.0): %s\n' "$APP_VERSION" >&2
  exit 1
fi
if [[ "$DMG_NAME" == */* || "$DMG_NAME" == '.dmg' || "$DMG_NAME" != *.dmg ]]; then
  printf 'DMG_NAME must be a basename ending in .dmg: %s\n' "$DMG_NAME" >&2
  exit 1
fi
for tool in hdiutil shasum plutil; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'Missing required macOS tool: %s\n' "$tool" >&2; exit 1; }
done
USE_DISKUTIL_IMAGE=0
if /usr/sbin/diskutil image create from --help >/dev/null 2>&1 && \
   /usr/sbin/diskutil image attach --help >/dev/null 2>&1; then
  USE_DISKUTIL_IMAGE=1
fi
if [[ -e "$DMG" || -e "$SHA_FILE" ]]; then
  printf 'Refusing to overwrite an existing package: %s\n' "$DMG" >&2
  printf 'Move or rename the existing package before creating another one.\n' >&2
  exit 1
fi

APP_VERSION="$APP_VERSION" BUILD_NUMBER="$BUILD_NUMBER" CW_NETWORK_BACKEND="${CW_NETWORK_BACKEND:-seatbelt}" /bin/bash "$ROOT/build.sh"
[[ -d "$APP" ]] || { printf 'Build did not produce: %s\n' "$APP" >&2; exit 1; }
ACTUAL_VERSION=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")
ACTUAL_BUILD=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$APP/Contents/Info.plist")
[[ "$ACTUAL_BUILD" == "$BUILD_NUMBER" ]] || { printf 'Built app build number mismatch: %s\n' "$ACTUAL_BUILD" >&2; exit 1; }
[[ "$ACTUAL_VERSION" == "$APP_VERSION" ]] || { printf 'Built app version mismatch: %s\n' "$ACTUAL_VERSION" >&2; exit 1; }
[[ -f "$APP/Contents/Resources/BuildInfo.plist" ]] || { printf 'Build manifest missing.\n' >&2; exit 1; }
[[ "$('/usr/libexec/PlistBuddy' -c 'Print :CFBundleIconFile' "$APP/Contents/Info.plist")" == 'AppIcon.icns' && -s "$APP/Contents/Resources/AppIcon.icns" ]] || { printf 'Application icon missing.\n' >&2; exit 1; }

STAGE=$(mktemp -d "${TMPDIR:-/tmp}/claude-watch-dmg.XXXXXX")
MOUNT=$(mktemp -d "${TMPDIR:-/tmp}/claude-watch-mount.XXXXXX")
TEMP_DMG="$STAGE/$DMG_NAME"
ATTACHED=0
cleanup() {
  if [[ "$ATTACHED" == '1' ]]; then
    if [[ "$USE_DISKUTIL_IMAGE" == '1' ]]; then
      /usr/sbin/diskutil eject "$MOUNT" >/dev/null 2>&1 || true
    else
      hdiutil detach "$MOUNT" -quiet 2>/dev/null || true
    fi
  fi
  rmdir "$MOUNT" 2>/dev/null || true
  rm -rf "$STAGE"
}
trap cleanup EXIT

PAYLOAD="$STAGE/payload"
mkdir -p "$PAYLOAD"
cp -R "$APP" "$PAYLOAD/$APP_NAME"
ln -s /Applications "$PAYLOAD/Applications"
cp "$ROOT/Packaging/安装说明.txt" "$ROOT/Packaging/安装或更新后台.command" "$ROOT/Packaging/卸载应用.command" "$PAYLOAD/"
python3 - "$APP/Contents/Resources/BuildInfo.plist" "$PAYLOAD/安装说明.txt" "$ACTUAL_BUILD" <<'PY'
from pathlib import Path
import plistlib, sys
info = plistlib.loads(Path(sys.argv[1]).read_bytes())
target = Path(sys.argv[2])
architectures = {"arm64": "Apple Silicon（arm64）", "x86_64": "Intel（x86_64）",
                 "universal": "Apple Silicon + Intel（通用）"}
values = {"PRODUCT_VERSION": info["ProductVersion"], "BUILD_NUMBER": sys.argv[3],
          "BACKEND_VERSION": info["BackendVersion"], "MINIMUM_OS": info["MinimumSystemVersion"],
          "ARCHITECTURE": architectures[info["Architecture"]]}
text = target.read_text()
for key, value in values.items(): text = text.replace("{{" + key + "}}", str(value))
if "{{" in text: raise SystemExit("Unresolved installation instruction placeholder")
target.write_text(text)
PY
chmod 755 "$PAYLOAD/安装或更新后台.command"
chmod 755 "$PAYLOAD/卸载应用.command"

if [[ "$USE_DISKUTIL_IMAGE" == '1' ]]; then
  /usr/sbin/diskutil image create from --format UDZO --volumeName "Claude Watch $APP_VERSION" "$PAYLOAD" "$TEMP_DMG" >/dev/null
else
  hdiutil create -volname "Claude Watch $APP_VERSION" -srcfolder "$PAYLOAD" -format UDZO -ov "$TEMP_DMG" >/dev/null
fi
hdiutil verify "$TEMP_DMG" >/dev/null
if [[ "$USE_DISKUTIL_IMAGE" == '1' ]]; then
  /usr/sbin/diskutil image attach --readOnly --nobrowse --mountPoint "$MOUNT" "$TEMP_DMG" >/dev/null
else
  hdiutil attach -readonly -nobrowse -mountpoint "$MOUNT" "$TEMP_DMG" >/dev/null
fi
ATTACHED=1
[[ -d "$MOUNT/$APP_NAME" ]] || { printf 'Mounted DMG is missing the app.\n' >&2; exit 1; }
[[ -s "$MOUNT/$APP_NAME/Contents/Resources/AppIcon.icns" ]] || { printf 'Mounted DMG is missing the application icon.\n' >&2; exit 1; }
[[ -L "$MOUNT/Applications" ]] || { printf 'Mounted DMG is missing the Applications link.\n' >&2; exit 1; }
[[ -x "$MOUNT/安装或更新后台.command" ]] || { printf 'Mounted DMG is missing the installer command.\n' >&2; exit 1; }
[[ -f "$MOUNT/安装说明.txt" ]] || { printf 'Mounted DMG is missing the Chinese instructions.\n' >&2; exit 1; }
/usr/bin/codesign --verify --deep --strict "$MOUNT/$APP_NAME"
[[ "$('/usr/libexec/PlistBuddy' -c 'Print :CFBundleVersion' "$MOUNT/$APP_NAME/Contents/Info.plist")" == "$BUILD_NUMBER" ]] || { printf 'Mounted app build mismatch.\n' >&2; exit 1; }
for brand in claude chatgpt cloudflare; do
  [[ -s "$MOUNT/$APP_NAME/Contents/Resources/Identity/brands/$brand.png" ]] || { printf 'Brand logo missing: %s\n' "$brand" >&2; exit 1; }
done
FLAG_COUNT=$(find "$MOUNT/$APP_NAME/Contents/Resources/Identity/flags" -name '*.png' -type f | wc -l | tr -d ' ')
[[ "$FLAG_COUNT" == '257' ]] || { printf 'Country flag count mismatch: %s\n' "$FLAG_COUNT" >&2; exit 1; }
[[ -s "$MOUNT/$APP_NAME/Contents/Resources/Identity/FLAG-ICONS-LICENSE.txt" ]] || { printf 'Flag asset license missing.\n' >&2; exit 1; }
if [[ "$USE_DISKUTIL_IMAGE" == '1' ]]; then
  /usr/sbin/diskutil eject "$MOUNT" >/dev/null
else
  hdiutil detach "$MOUNT" -quiet
fi
ATTACHED=0

mkdir -p "$DIST"
mv "$TEMP_DMG" "$DMG"
(
  cd "$DIST"
  /usr/bin/shasum -a 256 "$DMG_NAME" > "$(basename "$SHA_FILE")"
)
printf 'Created: %s\nSHA-256: %s\n' "$DMG" "$SHA_FILE"
