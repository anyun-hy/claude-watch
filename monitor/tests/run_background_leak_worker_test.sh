#!/bin/bash
# Compile the fixed-resource helper and optionally run a local WebKit bridge
# test. The default mode does not open AppKit in a restricted terminal.
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
TEST_PARENT=$(mktemp -d "${TMPDIR:-/private/tmp}/cw-background-leak-test.XXXXXX")
trap 'rm -rf "$TEST_PARENT"' EXIT
APP="$TEST_PARENT/Background Leak Worker Tests.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$TEST_PARENT/module-cache"
cp "$ROOT/Resources/netcoffee_probe.html" "$ROOT/Resources/netcoffee_probe.js" "$ROOT/Resources/netcoffee_probe.css" "$APP/Contents/Resources/"
cp "$ROOT/Resources/watch-native-collector.zsh" "$APP/Contents/Resources/watch-engine"
chmod 700 "$APP/Contents/Resources/watch-engine"
cat > "$APP/Contents/Resources/BuildInfo.plist" <<'PLIST'
<?xml version="1.0"?><plist version="1.0"><dict><key>BackendVariant</key><string>rust-candidate</string><key>BackgroundEvidenceSchema</key><integer>1</integer></dict></plist>
PLIST
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.local.watchpanel.background-leak-tests</string><key>CFBundleExecutable</key><string>BackgroundLeakWorkerTests</string><key>CFBundlePackageType</key><string>APPL</string><key>LSUIElement</key><true/></dict></plist>
PLIST
xcrun swiftc -swift-version 5 -parse-as-library -target "arm64-apple-macosx$CW_MACOS_MINIMUM" -D COFFEE_BRIDGE_TEST \
  -module-cache-path "$TEST_PARENT/module-cache" -framework AppKit -framework WebKit \
  "$ROOT/Sources/IdentityPresentation.swift" "$ROOT/Sources/BundledBackendVariant.swift" "$ROOT/Sources/LeakCheckModels.swift" \
  "$ROOT/Sources/NetCoffeeModels.swift" "$ROOT/Sources/NetCoffeeLeakRunner.swift" "$ROOT/tools/BackgroundLeakWorker.swift" \
  "$ROOT/tests/BackgroundLeakWorkerTests.swift" -o "$APP/Contents/MacOS/BackgroundLeakWorkerTests"
cp "$APP/Contents/MacOS/BackgroundLeakWorkerTests" "$APP/Contents/Resources/watch-leak-worker"
chmod 700 "$APP/Contents/Resources/watch-leak-worker"
python3 - "$APP/Contents/Resources" <<'PY'
import hashlib, plistlib, sys
root = __import__('pathlib').Path(sys.argv[1])
manifest = root / 'BuildInfo.plist'
value = plistlib.loads(manifest.read_bytes())
names = ('watch-leak-worker', 'watch-engine', 'netcoffee_probe.html', 'netcoffee_probe.js', 'netcoffee_probe.css')
value['RuntimeHashes'] = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}
manifest.write_bytes(plistlib.dumps(value))
PY
/usr/bin/codesign --force --sign - "$APP"
if [[ "$RUN_NATIVE" == 1 ]]; then
  OUT="$TEST_PARENT/stdout.log"; ERR="$TEST_PARENT/stderr.log"
  /usr/bin/open -n -W -g --stdout "$OUT" --stderr "$ERR" "$APP"
  cat "$OUT"
  [[ ! -s "$ERR" ]] || cat "$ERR" >&2
  if grep -q '^FAIL:' "$OUT"; then exit 1; fi
else
  printf 'Compiled isolated background WebKit bridge test; temporary files will be removed.\n'
fi
