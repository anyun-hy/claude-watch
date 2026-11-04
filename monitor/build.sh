#!/bin/bash
# Build a local native app; does not install or change the monitor service.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd -P)
CW_MACOS_MINIMUM=$(/bin/cat "$ROOT/macos-minimum.txt")
REPOSITORY_ROOT=$(cd "$ROOT/.." && pwd -P)
CW_BUILD_ARCH="${CW_BUILD_ARCH:-arm64}"
CW_BACKEND_VARIANT="${CW_BACKEND_VARIANT:-rust-candidate}"
BACKGROUND_EVIDENCE_SCHEMA=0
CW_TARGETS="$CW_BUILD_ARCH"
# The Python backend is retired: the app ships the Rust engine only. A build
# that asks for anything else is a stale command line, not a supported target.
if [[ "$CW_BACKEND_VARIANT" != rust-candidate ]]; then
  printf 'The legacy Python backend is retired; only rust-candidate can be built (got %s).\n' "$CW_BACKEND_VARIANT" >&2
  exit 1
fi
if [[ "$CW_BUILD_ARCH" != arm64 ]]; then
  echo 'The Rust build is arm64-only; use CW_BUILD_ARCH=arm64.' >&2
  exit 1
fi
if [[ -n "${CW_APP_OUTPUT:-}" ]]; then
  APP=$CW_APP_OUTPUT
else
  APP="$ROOT/build/Claude Watch Monitor Rust Candidate.app"
fi
case "$APP" in
  /Applications/*) echo 'Refusing to build into an installed application path.' >&2; exit 1;;
esac

# Version and build number always come from the caller (the engine's reinstall
# command or an explicit command line); no built-in default may go stale.
: "${APP_VERSION:?Set APP_VERSION (for example 3.0.0)}"
: "${BUILD_NUMBER:?Set BUILD_NUMBER (for example 367)}"
if [[ ! "$APP_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf 'APP_VERSION must be semantic version (for example 2.2.0): %s\n' "$APP_VERSION" >&2
  exit 1
fi
# The UI policy rows are generated from Rust. A stale checked-in table
# must fail before we compile or sign an app with mismatched action defaults.
python3 "$REPOSITORY_ROOT/tools/generate-ai-policy-swift.py" --check
# The engine's own manifest carries the version and digest of each component.
RUST_COMPONENTS_DIR="$ROOT/build/rust-components"
"$REPOSITORY_ROOT/tools/build-rust-components.sh" --output "$RUST_COMPONENTS_DIR"
RUST_COMPONENTS_MANIFEST="$RUST_COMPONENTS_DIR/components.json"
[[ -f "$RUST_COMPONENTS_MANIFEST" ]] || { echo 'Rust component manifest is missing.' >&2; exit 1; }
python3 - "$RUST_COMPONENTS_DIR" "$RUST_COMPONENTS_MANIFEST" <<'PY'
import hashlib, json, sys
from pathlib import Path
root, manifest = map(Path, sys.argv[1:])
try:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["schema"] == 1 and data["architecture"] == "arm64" and data["kind"] == "rust-candidate"
    components = data["components"]
    expected = {"engine", "native_observer", "process_control"}
    assert set(components) == expected
    for key in expected:
        item = components[key]
        name = item["bundle_name"]
        path = root / name
        assert name and '/' not in name and path.is_file() and not path.is_symlink()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
except (AssertionError, KeyError, OSError, ValueError, TypeError) as error:
    raise SystemExit(f"Invalid Rust component staging: {error}")
PY
BACKEND_VERSION=$("$RUST_COMPONENTS_DIR/watch-engine" --version | python3 -c 'import json,sys; print(json.load(sys.stdin)["backend_version"])')
BACKEND_SHA256=$(/usr/bin/shasum -a 256 "$RUST_COMPONENTS_DIR/watch-engine" | /usr/bin/awk '{print $1}')
RUNTIME_SCHEMA=2
BACKGROUND_EVIDENCE_SCHEMA=2

mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$ROOT/build/module-cache"
SWIFTC=$(xcrun --find swiftc)
CW_DEVELOPER=$(xcode-select -p)
SDK="$CW_DEVELOPER/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
if [[ ! -d "$SDK" ]]; then SDK=$(xcrun --sdk macosx --show-sdk-path); fi
for CW_TARGET_ARCH in $CW_TARGETS; do
  "$SWIFTC" -swift-version 5 -O -parse-as-library -target "$CW_TARGET_ARCH-apple-macosx$CW_MACOS_MINIMUM" \
    -sdk "$SDK" -module-cache-path "$ROOT/build/module-cache" \
    -framework SwiftUI -framework AppKit -framework WebKit "$ROOT"/Sources/*.swift \
    -o "$ROOT/build/ClaudeWatchMonitor.$CW_TARGET_ARCH"
  # The Rust component manifest supplies watch-process-control. Do not build
  # the retired Swift helper: it was overwritten by the Rust staging copy.
  "$SWIFTC" -swift-version 5 -O -parse-as-library -D BACKGROUND_LEAK_WORKER \
    -target "$CW_TARGET_ARCH-apple-macosx$CW_MACOS_MINIMUM" -sdk "$SDK" -module-cache-path "$ROOT/build/module-cache" \
    -framework AppKit -framework WebKit "$ROOT/Sources/IdentityPresentation.swift" "$ROOT/Sources/BundledBackendVariant.swift" \
    "$ROOT/Sources/LeakCheckModels.swift" "$ROOT/Sources/NetCoffeeModels.swift" "$ROOT/Sources/NetCoffeeLeakRunner.swift" "$ROOT/Sources/IPLeakDNSRunner.swift" "$ROOT/Sources/IPLeakDNSRetryRunner.swift" \
    "$ROOT/tools/BackgroundLeakWorker.swift" -o "$ROOT/build/watch-leak-worker.$CW_TARGET_ARCH"
done
cp "$ROOT/build/ClaudeWatchMonitor.$CW_BUILD_ARCH" "$APP/Contents/MacOS/ClaudeWatchMonitor"
cp "$ROOT/build/watch-leak-worker.$CW_BUILD_ARCH" "$APP/Contents/Resources/watch-leak-worker"
cp "$ROOT/Resources/webrtc_probe.html" "$ROOT/Resources/webrtc_probe.js" "$APP/Contents/Resources/"
cp "$ROOT/Resources/netcoffee_probe.html" "$ROOT/Resources/netcoffee_probe.js" "$ROOT/Resources/netcoffee_probe.css" "$ROOT/Resources/watch-admin.sh" "$APP/Contents/Resources/"
cp "$ROOT/Resources/ipleak_probe.html" "$ROOT/Resources/ipleak_probe.js" "$APP/Contents/Resources/"
mkdir -p "$APP/Contents/Resources/ThirdParty/ClaudeSwitcher"
cp "$ROOT/Resources/watch-native-collector.zsh" "$APP/Contents/Resources/"
chmod 700 "$APP/Contents/Resources/watch-native-collector.zsh"
cp "$ROOT/ThirdParty/ClaudeSwitcher/LICENSE" "$ROOT/ThirdParty/ClaudeSwitcher/UPSTREAM.json" "$APP/Contents/Resources/ThirdParty/ClaudeSwitcher/"
cp "$ROOT/ThirdParty/ClaudeSwitcher/RUST_NOTICE.txt" "$APP/Contents/Resources/ThirdParty/ClaudeSwitcher/NOTICE.txt"
python3 - "$RUST_COMPONENTS_DIR" "$RUST_COMPONENTS_MANIFEST" "$APP/Contents/Resources" <<'PY'
import json, shutil, sys
from pathlib import Path
root, manifest, resources = map(Path, sys.argv[1:])
components = json.loads(manifest.read_text(encoding="utf-8"))["components"]
for key in ("engine", "native_observer", "process_control"):
    item = components[key]
    source = root / item["bundle_name"]
    destination = resources / item["bundle_name"]
    shutil.copy2(source, destination)
    destination.chmod(0o700)
PY
chmod 700 "$APP/Contents/Resources/watch-process-control" "$APP/Contents/Resources/watch-admin.sh" "$APP/Contents/Resources/watch-leak-worker"
/usr/bin/codesign --force --sign - "$APP/Contents/Resources/watch-process-control"
/usr/bin/codesign --force --sign - "$APP/Contents/Resources/watch-leak-worker"
cp "$ROOT/Resources/AppIcon.icns" "$APP/Contents/Resources/"
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
<key>LSMinimumSystemVersion</key><string>$CW_MACOS_MINIMUM</string>
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
<key>MinimumSystemVersion</key><string>$CW_MACOS_MINIMUM</string>
<key>Architecture</key><string>$CW_BUILD_ARCH</string>
<key>BackendVariant</key><string>$CW_BACKEND_VARIANT</string>
<key>SwitcherSchema</key><integer>1</integer>
<key>RuntimeSchema</key><integer>$RUNTIME_SCHEMA</integer>
<key>BackgroundEvidenceSchema</key><integer>$BACKGROUND_EVIDENCE_SCHEMA</integer>
</dict></plist>
PLIST
python3 - "$APP/Contents/Resources" <<'PY'
from pathlib import Path
import hashlib, plistlib, sys
root = Path(sys.argv[1])
manifest = root / "BuildInfo.plist"
value = plistlib.loads(manifest.read_bytes())
forbidden = [p for p in root.rglob("*") if p.suffix == ".py" or p.name in ("claude-watch.sh", "snapshot.sh", "switcher.py")]
if forbidden: raise SystemExit("The bundle still contains retired Python backend resources")
files = [root / n for n in ("watch-engine", "watch-native-observer", "watch-admin.sh", "watch-process-control", "watch-native-collector.zsh", "watch-leak-worker", "netcoffee_probe.html", "netcoffee_probe.js", "netcoffee_probe.css", "ipleak_probe.html", "ipleak_probe.js")]
value["RuntimeHashes"] = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
manifest.write_bytes(plistlib.dumps(value))
PY
/usr/bin/codesign --force --sign - "$APP"
printf 'Built: %s (app %s; backend %s)\n' "$APP" "$APP_VERSION" "$BACKEND_VERSION"
