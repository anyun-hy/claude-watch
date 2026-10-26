#!/bin/bash
# Build a local native app; does not install or change the monitor service.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd -P)
REPOSITORY_ROOT=$(cd "$ROOT/.." && pwd -P)
APP="${CW_APP_OUTPUT:-$ROOT/build/Claude Watch Monitor.app}"
BACKEND_SOURCE="$REPOSITORY_ROOT/claude-watch.sh"
APP_VERSION="${APP_VERSION:-2.9.5}"
BUILD_NUMBER="${BUILD_NUMBER:-297}"
CW_BUILD_ARCH="${CW_BUILD_ARCH:-arm64}"
case "$CW_BUILD_ARCH" in arm64|x86_64) CW_TARGETS="$CW_BUILD_ARCH";; universal) CW_TARGETS='arm64 x86_64';; *) echo 'Unsupported build architecture' >&2; exit 1;; esac

if [[ ! -f "$BACKEND_SOURCE" ]]; then
  printf 'Missing backend source: %s\n' "$BACKEND_SOURCE" >&2
  exit 1
fi
if [[ ! "$APP_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf 'APP_VERSION must be semantic version (for example 2.2.0): %s\n' "$APP_VERSION" >&2
  exit 1
fi
BACKEND_VERSION=$(/usr/bin/sed -n "s/^VERSION=['\"]\\([^'\"]*\\)['\"].*/\\1/p" "$BACKEND_SOURCE" | /usr/bin/head -n 1)
if [[ -z "$BACKEND_VERSION" ]]; then
  printf 'Could not read VERSION from: %s\n' "$BACKEND_SOURCE" >&2
  exit 1
fi
BACKEND_SHA256=$(/usr/bin/shasum -a 256 "$BACKEND_SOURCE" | /usr/bin/awk '{print $1}')

mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$ROOT/build/module-cache"
SWIFTC=$(xcrun --find swiftc)
CW_DEVELOPER=$(xcode-select -p)
SDK="$CW_DEVELOPER/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
if [[ ! -d "$SDK" ]]; then SDK=$(xcrun --sdk macosx --show-sdk-path); fi
for CW_TARGET_ARCH in $CW_TARGETS; do
  "$SWIFTC" -swift-version 5 -O -parse-as-library -target "$CW_TARGET_ARCH-apple-macosx13.0" \
    -sdk "$SDK" -module-cache-path "$ROOT/build/module-cache" \
    -framework SwiftUI -framework AppKit -framework WebKit "$ROOT"/Sources/*.swift \
    -o "$ROOT/build/ClaudeWatchMonitor.$CW_TARGET_ARCH"
  "$SWIFTC" -swift-version 5 -O -parse-as-library -D PROCESS_HELPER \
    -target "$CW_TARGET_ARCH-apple-macosx13.0" -sdk "$SDK" -module-cache-path "$ROOT/build/module-cache" \
    -framework AppKit "$ROOT/Sources/AIProcessControl.swift" "$ROOT/tools/ProcessHelper.swift" \
    -o "$ROOT/build/watch-process-control.$CW_TARGET_ARCH"
done
if [[ "$CW_BUILD_ARCH" == universal ]]; then
  /usr/bin/lipo -create "$ROOT/build/ClaudeWatchMonitor.arm64" "$ROOT/build/ClaudeWatchMonitor.x86_64" -output "$APP/Contents/MacOS/ClaudeWatchMonitor"
  /usr/bin/lipo -create "$ROOT/build/watch-process-control.arm64" "$ROOT/build/watch-process-control.x86_64" -output "$APP/Contents/Resources/watch-process-control"
else
  cp "$ROOT/build/ClaudeWatchMonitor.$CW_BUILD_ARCH" "$APP/Contents/MacOS/ClaudeWatchMonitor"
  cp "$ROOT/build/watch-process-control.$CW_BUILD_ARCH" "$APP/Contents/Resources/watch-process-control"
fi
cp "$ROOT/Resources/snapshot.sh" "$ROOT/Resources/snapshot.py" "$ROOT/Resources/process_roles.py" "$ROOT/Resources/server_reference.py" "$BACKEND_SOURCE" "$APP/Contents/Resources/"
cp "$ROOT/Resources/dns_probe.py" "$ROOT/Resources/webrtc_probe.html" "$ROOT/Resources/webrtc_probe.js" "$APP/Contents/Resources/"
cp "$ROOT/Resources/netcoffee_client.py" "$ROOT/Resources/netcoffee_probe.html" "$ROOT/Resources/netcoffee_probe.js" "$ROOT/Resources/netcoffee_probe.css" "$APP/Contents/Resources/"
cp "$ROOT/Resources/ai_probe.py" "$APP/Contents/Resources/"
cp "$ROOT/Resources/switcher.py" "$ROOT/Resources/watch-admin.sh" "$APP/Contents/Resources/"
if [[ -d "$APP/Contents/Resources/watch_switcher" ]]; then rm -rf "$APP/Contents/Resources/watch_switcher"; fi
mkdir -p "$APP/Contents/Resources/watch_switcher"
cp "$ROOT/Resources/watch_switcher/"*.py "$APP/Contents/Resources/watch_switcher/"
mkdir -p "$APP/Contents/Resources/ThirdParty"
cp -R "$ROOT/ThirdParty/ClaudeSwitcher" "$APP/Contents/Resources/ThirdParty/"
chmod 700 "$APP/Contents/Resources/watch-process-control" "$APP/Contents/Resources/watch-admin.sh"
/usr/bin/codesign --force --sign - "$APP/Contents/Resources/watch-process-control"
cp "$ROOT/Resources/AppIcon.icns" "$APP/Contents/Resources/"
chmod 700 "$APP/Contents/Resources/claude-watch.sh"
mkdir -p "$APP/Contents/Resources/Icons"
mkdir -p "$APP/Contents/Resources/Identity"
cp -R "$ROOT/Resources/Identity/brands" "$ROOT/Resources/Identity/flags" "$ROOT/Resources/Identity/SOURCES.json" "$ROOT/Resources/Identity/FLAG-ICONS-LICENSE.txt" "$APP/Contents/Resources/Identity/"
cp "$ROOT"/Resources/Icons/graph-*.png "$ROOT/Resources/Icons/LICENSE" "$ROOT/Resources/Icons/SOURCES.txt" "$APP/Contents/Resources/Icons/"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>io.local.watchpanel</string>
<key>CFBundleName</key><string>Claude Watch</string>
<key>CFBundleDisplayName</key><string>Claude Watch</string>
<key>CFBundleExecutable</key><string>ClaudeWatchMonitor</string>
<key>CFBundleIconFile</key><string>AppIcon.icns</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$APP_VERSION</string>
<key>CFBundleVersion</key><string>$BUILD_NUMBER</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
cat > "$APP/Contents/Resources/BuildInfo.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>ProductVersion</key><string>$APP_VERSION</string>
<key>BackendVersion</key><string>$BACKEND_VERSION</string>
<key>BackendSHA256</key><string>$BACKEND_SHA256</string>
<key>MinimumSystemVersion</key><string>13.0</string>
<key>Architecture</key><string>$CW_BUILD_ARCH</string>
<key>SwitcherSchema</key><integer>1</integer>
</dict></plist>
PLIST
python3 - "$APP/Contents/Resources" <<'PY'
from pathlib import Path
import hashlib, plistlib, sys
root = Path(sys.argv[1])
manifest = root / "BuildInfo.plist"
value = plistlib.loads(manifest.read_bytes())
files = [root / n for n in ("switcher.py", "watch-admin.sh", "watch-process-control", "dns_probe.py", "netcoffee_client.py")]
files += sorted((root / "watch_switcher").glob("*.py"))
files += sorted(p for p in (root / "ThirdParty/ClaudeSwitcher").rglob("*") if p.is_file())
value["RuntimeHashes"] = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
manifest.write_bytes(plistlib.dumps(value))
PY
/usr/bin/codesign --force --sign - "$APP"
printf 'Built: %s (app %s; backend %s)\n' "$APP" "$APP_VERSION" "$BACKEND_VERSION"
