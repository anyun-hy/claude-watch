#!/bin/bash
# Builds an isolated test app; --live also performs a real IPLeak WebView probe.
set -euo pipefail
case "${1:---fixture}" in --fixture|--live) ;; *) printf 'Usage: %s [--fixture|--live]\n' "$0" >&2; exit 2;; esac
[[ $# -le 1 ]] || exit 2
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
CW_MACOS_MINIMUM=$(/bin/cat "$ROOT/macos-minimum.txt")
TEST_DIR=$(mktemp -d /private/tmp/claude-watch-ipleak-test.XXXXXX)
trap 'rm -rf "$TEST_DIR"' EXIT
APP="$TEST_DIR/IPLeak Test.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$TEST_DIR/module-cache"
cp "$ROOT/Resources/ipleak_probe.html" "$ROOT/Resources/ipleak_probe.js" "$ROOT/Resources/netcoffee_probe.css" "$APP/Contents/Resources/"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>io.local.watchpanel.ipleak-tests</string>
<key>CFBundleExecutable</key><string>IPLeakBridgeTests</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSUIElement</key><true/>
</dict></plist>
PLIST
xcrun swiftc -swift-version 5 -parse-as-library -D IPLEAK_BRIDGE_TEST -target "arm64-apple-macosx$CW_MACOS_MINIMUM" \
  -module-cache-path "$TEST_DIR/module-cache" -framework AppKit -framework WebKit \
  "$ROOT/Sources/IdentityPresentation.swift" "$ROOT/Sources/BundledBackendVariant.swift" \
  "$ROOT/Sources/LeakCheckModels.swift" "$ROOT/Sources/NetCoffeeModels.swift" \
  "$ROOT/Sources/NetCoffeeLeakRunner.swift" "$ROOT/Sources/IPLeakDNSRunner.swift" "$ROOT/Sources/IPLeakDNSRetryRunner.swift" \
  "$ROOT/Sources/EventDiagnostics.swift" "$ROOT/Sources/LeakCheckStore.swift" "$ROOT/tests/IPLeakBridgeTests.swift" \
  -o "$APP/Contents/MacOS/IPLeakBridgeTests"
/usr/bin/codesign --force --sign - "$APP" >/dev/null
xcrun swiftc -swift-version 5 -parse-as-library -target "arm64-apple-macosx$CW_MACOS_MINIMUM" \
  -module-cache-path "$TEST_DIR/module-cache" -framework AppKit -framework WebKit \
  "$ROOT/Sources/IdentityPresentation.swift" "$ROOT/Sources/LeakCheckModels.swift" \
  "$ROOT/Sources/IPLeakDNSRunner.swift" "$ROOT/Sources/IPLeakDNSRetryRunner.swift" "$ROOT/tests/IPLeakRetryTests.swift" \
  -o "$TEST_DIR/IPLeakRetryTests"
"$TEST_DIR/IPLeakRetryTests"
"$APP/Contents/MacOS/IPLeakBridgeTests" --fixture
if [[ "${1:---fixture}" == --live ]]; then
  "$APP/Contents/MacOS/IPLeakBridgeTests" --live
fi
