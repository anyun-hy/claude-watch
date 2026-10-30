#!/bin/bash
# Builds an isolated native check. Running AppKit needs a GUI-capable runner;
# compile-only is the default so restricted terminals do not crash on startup.
set -euo pipefail
RUN_NATIVE=0
case "${1:---build-only}" in
  --run) RUN_NATIVE=1 ;;
  --build-only) ;;
  *) printf 'Usage: %s [--build-only|--run]\n' "$0" >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || { printf 'Only one test mode is accepted.\n' >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
CW_MACOS_MINIMUM=$(/bin/cat "$ROOT/macos-minimum.txt")
TEST_APP="${LEAK_BRIDGE_APP:-$ROOT/build/Leak Bridge Tests.app}"
mkdir -p "$TEST_APP/Contents/MacOS" "$TEST_APP/Contents/Resources" "$ROOT/build/test-module-cache"
cp "$ROOT/Resources/webrtc_probe.html" "$ROOT/Resources/webrtc_probe.js" "$TEST_APP/Contents/Resources/"
cat > "$TEST_APP/Contents/Resources/BuildInfo.plist" <<'BACKEND'
<?xml version="1.0"?><plist version="1.0"><dict><key>BackendVariant</key><string>stable</string></dict></plist>
BACKEND
cat > "$TEST_APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>io.local.watchpanel.leak-bridge-tests</string>
<key>CFBundleExecutable</key><string>LeakBridgeTests</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
PLIST
xcrun swiftc -swift-version 5 -parse-as-library -target "arm64-apple-macosx$CW_MACOS_MINIMUM" -D UI_REVIEW -D LEAK_BRIDGE_TEST \
  -module-cache-path "$ROOT/build/test-module-cache" -framework SwiftUI -framework AppKit -framework WebKit \
  "$ROOT"/Sources/*.swift "$ROOT/tests/LeakBridgeTests.swift" \
  -o "$TEST_APP/Contents/MacOS/LeakBridgeTests"
if [[ "$RUN_NATIVE" == 1 ]]; then
  "$TEST_APP/Contents/MacOS/LeakBridgeTests"
else
  printf 'Built isolated WebKit test (not executed): %s\n' "$TEST_APP"
  printf 'Use --run only from a GUI-capable runner. Compile success is not a bridge-test pass.\n'
fi
