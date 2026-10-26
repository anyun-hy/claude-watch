#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
APP="$ROOT/build/NetCoffee Integration Check.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
xcrun swiftc -swift-version 5 -parse-as-library -target arm64-apple-macosx14.0 -module-cache-path "$ROOT/build/module-cache" -framework AppKit -framework WebKit "$ROOT/Sources/IdentityPresentation.swift" "$ROOT/Sources/LeakCheckModels.swift" "$ROOT/Sources/NetCoffeeModels.swift" "$ROOT/Sources/NetCoffeeLeakRunner.swift" "$ROOT/tests/NetCoffeeLiveCheck.swift" -o "$APP/Contents/MacOS/NetCoffeeIntegrationCheck"
cp "$ROOT"/Resources/netcoffee_{client.py,probe.html,probe.js,probe.css} "$APP/Contents/Resources/"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.local.watchpanel.coffeecheck</string><key>CFBundleExecutable</key><string>NetCoffeeIntegrationCheck</string><key>CFBundlePackageType</key><string>APPL</string><key>LSUIElement</key><true/></dict></plist>
PLIST
codesign --force --sign - "$APP"
"$APP/Contents/MacOS/NetCoffeeIntegrationCheck" "$ROOT/reports/netcoffee/live-leak-results.json"
