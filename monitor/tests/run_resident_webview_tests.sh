#!/bin/bash
# Real WebKit lifecycle, with all HTTP and ICE replaced by local fixtures.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
CW_TEST_DIR=$(mktemp -d /private/tmp/cw-resident-webview.XXXXXX)
trap 'rm -rf "$CW_TEST_DIR"' EXIT
APP="$CW_TEST_DIR/Resident WebView Tests.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$ROOT"/Resources/{netcoffee_probe.html,netcoffee_probe.js,netcoffee_probe.css,ipleak_probe.html,ipleak_probe.js} "$APP/Contents/Resources/"
cat > "$APP/Contents/Resources/watch-engine" <<'PY'
#!/usr/bin/python3
import json,sys
kind,query=sys.argv[2],sys.argv[3]
print(json.dumps({'kind':kind,'query':query,'sourceURL':'https://fixture.invalid/',
 'queriedAt':1,'finishedAt':2,'status':'complete','httpStatus':200,
 'raw':'ip=8.8.4.4\n' if kind=='trace' else '{}',
 'data':{'ip':query,'country':'US','country_code':'US'} if kind=='geoip' else None,'error':None}))
PY
chmod 700 "$APP/Contents/Resources/watch-engine"
cat > "$APP/Contents/Resources/BuildInfo.plist" <<'PLIST'
<?xml version="1.0"?><plist version="1.0"><dict><key>BackendVariant</key><string>rust-candidate</string></dict></plist>
PLIST
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.local.watchpanel.resident-tests</string><key>CFBundleExecutable</key><string>ResidentTests</string><key>CFBundlePackageType</key><string>APPL</string><key>LSUIElement</key><true/></dict></plist>
PLIST
CW_MACOS_MINIMUM=$(cat "$ROOT/macos-minimum.txt")
xcrun swiftc -swift-version 5 -parse-as-library -D COFFEE_BRIDGE_TEST -D IPLEAK_BRIDGE_TEST \
  -target "arm64-apple-macosx$CW_MACOS_MINIMUM" -module-cache-path "$CW_TEST_DIR/cache" -framework AppKit -framework WebKit \
  "$ROOT/Sources/IdentityPresentation.swift" "$ROOT/Sources/BundledBackendVariant.swift" "$ROOT/Sources/LeakCheckModels.swift" \
  "$ROOT/Sources/NetCoffeeModels.swift" "$ROOT/Sources/NetCoffeeLeakRunner.swift" "$ROOT/Sources/IPLeakDNSRunner.swift" \
  "$ROOT/Sources/IPLeakDNSRetryRunner.swift" "$ROOT/tests/ResidentWebViewTests.swift" -o "$APP/Contents/MacOS/ResidentTests"
/usr/bin/codesign --force --sign - "$APP"
if ! "$APP/Contents/MacOS/ResidentTests" >"$CW_TEST_DIR/stdout" 2>"$CW_TEST_DIR/stderr"; then
  cat "$CW_TEST_DIR/stdout" "$CW_TEST_DIR/stderr"
  exit 1
fi
rg '^ResidentWebViewTests passed' "$CW_TEST_DIR/stdout"
