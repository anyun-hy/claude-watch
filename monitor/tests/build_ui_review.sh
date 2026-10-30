#!/bin/bash
# Builds an isolated UI-review app. It contains fixtures and graph icons only.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
APP="${UI_REVIEW_APP:-$ROOT/build/Claude Watch UI Review.app}"
SWIFTC=$(xcrun --find swiftc)
REVIEW_OPTIMIZATION=${UI_REVIEW_OPTIMIZATION:--O}
case "$REVIEW_OPTIMIZATION" in -O|-Onone) ;; *) echo 'Unsupported UI review optimization' >&2; exit 1;; esac
DEVELOPER=$(xcode-select -p)
SDK="$DEVELOPER/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
if [[ ! -d "$SDK" ]]; then SDK=$(xcrun --sdk macosx --show-sdk-path); fi

mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/Icons" "$ROOT/build/ui-review-module-cache"
"$SWIFTC" -swift-version 5 "$REVIEW_OPTIMIZATION" -parse-as-library -D UI_REVIEW -target arm64-apple-macosx14.0 \
  -sdk "$SDK" -module-cache-path "$ROOT/build/ui-review-module-cache" \
  -framework SwiftUI -framework AppKit -framework WebKit "$ROOT"/Sources/*.swift "$ROOT/tests/UIReviewApp.swift" \
  -o "$APP/Contents/MacOS/ClaudeWatchUIReview"

mkdir -p "$APP/Contents/Resources/Identity"
cp -R "$ROOT/Resources/Identity/brands" "$ROOT/Resources/Identity/flags" "$ROOT/Resources/Identity/SOURCES.json" "$ROOT/Resources/Identity/FLAG-ICONS-LICENSE.txt" "$APP/Contents/Resources/Identity/"
cp "$ROOT"/Resources/Icons/graph-*.png "$ROOT"/Resources/Icons/LICENSE "$ROOT"/Resources/Icons/SOURCES.txt "$APP/Contents/Resources/Icons/"
cp "$ROOT"/tests/fixtures/netcoffee/coffee-*.json "$APP/Contents/Resources/"
if [[ -d "$ROOT/tests/fixtures/review" ]]; then
  mkdir -p "$APP/Contents/Resources/review"
  cp "$ROOT"/tests/fixtures/review/*.json "$APP/Contents/Resources/review/"
fi
if [[ "${UI_REVIEW_INCLUDE_LIVE_REPORTS:-1}" == 1 && -f "$ROOT/reports/netcoffee/live-leak-results.json" ]]; then
  cp "$ROOT/reports/netcoffee/live-leak-results.json" "$APP/Contents/Resources/coffee-live-leak-results.json"
fi
if [[ "${UI_REVIEW_INCLUDE_LIVE_REPORTS:-1}" == 1 && -f "$ROOT/reports/netcoffee/coffee-lookup-current.json" ]]; then
  cp "$ROOT/reports/netcoffee/coffee-lookup-current.json" "$APP/Contents/Resources/"
fi
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>io.local.watchpanel.review</string>
<key>CFBundleName</key><string>Claude Watch UI Review</string>
<key>CFBundleDisplayName</key><string>Claude Watch UI Review</string>
<key>CFBundleExecutable</key><string>ClaudeWatchUIReview</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>1.0.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
/usr/bin/codesign --force --sign - "$APP"
printf 'Built: %s\n' "$APP"
