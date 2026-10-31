#!/bin/bash
# Exercise the real background helper entry point in a private fixed runtime
# tree. JavaScript returns local fixture receipts and never requests Coffee.
set -euo pipefail
MODE="${1:---app}"
case "$MODE" in --app|--bare) ;; *) printf 'Usage: %s [--app|--bare]\n' "$0" >&2; exit 2;; esac
[[ $# -le 1 ]] || { printf 'Only one test mode is accepted.\n' >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
CW_MACOS_MINIMUM=$(/bin/cat "$ROOT/macos-minimum.txt")
TEST_PARENT=$(mktemp -d "${TMPDIR:-/private/tmp}/cw-background-runtime-test.XXXXXX")
trap 'rm -rf "$TEST_PARENT"' EXIT
RUNTIME="$TEST_PARENT/runtime"
APP="$RUNTIME/WatchEvidence.app"
mkdir -p "$RUNTIME" "$TEST_PARENT/module-cache"
if [[ "$MODE" == --app ]]; then mkdir -p "$APP/Contents/MacOS"; fi
cp "$ROOT/Resources/netcoffee_probe.html" "$ROOT/Resources/netcoffee_probe.css" "$RUNTIME/"
cp "$ROOT/Resources/ipleak_probe.html" "$RUNTIME/"
cat > "$RUNTIME/ipleak_probe.js" <<'JS'
window.IPLeakProbe = {run: function(options) {
  window.webkit.messageHandlers.ipLeakProbe.postMessage({runID: options.runID, payload: {
    kind:'dns', status:'complete', startedAt:1, finishedAt:2, scope:'fixed runtime fixture',
    observations:[{address:'8.8.4.4',kind:'http',source:'fixture',family:4}],
    errors:[], contextChanged:false, details:['no network']
  }});
}, cancel:function(){}};
JS
cat > "$RUNTIME/netcoffee_probe.js" <<'JS'
(function () {
  'use strict';
  window.NetCoffeeProbe = {
    run: function (options) {
      window.webkit.messageHandlers.coffeeProbe.postMessage({runID: options.runID, payload: {
        kind: options.kind, status: 'complete', startedAt: 1, finishedAt: 2,
        scope: 'fixed runtime fixture',
        observations: [{address: '8.8.4.4', kind: 'http', source: 'fixture', family: 4}],
        errors: [], contextChanged: false, details: ['no network']
      }});
    },
    cancel: function () {}
  };
}());
JS
cat > "$RUNTIME/watch-engine" <<'SH'
#!/bin/sh
exit 97
SH
chmod 700 "$RUNTIME/watch-engine"
WORKER="$RUNTIME/watch-leak-worker"
WORKER_REL="watch-leak-worker"
if [[ "$MODE" == --app ]]; then
  WORKER="$APP/Contents/MacOS/watch-leak-worker"
  WORKER_REL="WatchEvidence.app/Contents/MacOS/watch-leak-worker"
fi
xcrun swiftc -swift-version 5 -parse-as-library -target "arm64-apple-macosx$CW_MACOS_MINIMUM" -D BACKGROUND_LEAK_WORKER \
  -module-cache-path "$TEST_PARENT/module-cache" -framework AppKit -framework WebKit \
  "$ROOT/Sources/IdentityPresentation.swift" "$ROOT/Sources/BundledBackendVariant.swift" "$ROOT/Sources/LeakCheckModels.swift" \
  "$ROOT/Sources/NetCoffeeModels.swift" "$ROOT/Sources/NetCoffeeLeakRunner.swift" "$ROOT/Sources/IPLeakDNSRunner.swift" "$ROOT/Sources/IPLeakDNSRetryRunner.swift" "$ROOT/tools/BackgroundLeakWorker.swift" \
  -o "$WORKER"
chmod 700 "$WORKER"
if [[ "$MODE" == --app ]]; then cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.local.watchpanel.evidence</string><key>CFBundleExecutable</key><string>watch-leak-worker</string><key>CFBundlePackageType</key><string>APPL</string><key>LSUIElement</key><true/></dict></plist>
PLIST
fi
cat > "$RUNTIME/BuildInfo.plist" <<'PLIST'
<?xml version="1.0"?><plist version="1.0"><dict><key>BackendVariant</key><string>rust-candidate</string><key>BackgroundEvidenceSchema</key><integer>2</integer></dict></plist>
PLIST
SIGN_TARGET="$WORKER"
if [[ "$MODE" == --app ]]; then SIGN_TARGET="$APP"; fi
/usr/bin/codesign --force --sign - "$SIGN_TARGET"
python3 - "$RUNTIME" "$WORKER_REL" "$MODE" <<'PY'
import hashlib, plistlib, sys
from pathlib import Path
root, worker, mode = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
manifest = root / 'BuildInfo.plist'
value = plistlib.loads(manifest.read_bytes())
names = [worker, 'watch-engine', 'netcoffee_probe.html', 'netcoffee_probe.js', 'netcoffee_probe.css', 'ipleak_probe.html', 'ipleak_probe.js']
if mode == '--app': names += ['WatchEvidence.app/Contents/Info.plist', 'WatchEvidence.app/Contents/_CodeSignature/CodeResources']
value['RuntimeHashes'] = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}
manifest.write_bytes(plistlib.dumps(value))
PY
python3 - "$WORKER" <<'PY'
import json, os, signal, subprocess, sys
worker = sys.argv[1]
for argument in ('--dns', '--webrtc'):
    process = subprocess.Popen([worker, argument], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        raise SystemExit(f'{argument}: helper timed out and was terminated')
    if process.returncode != 0:
        raise SystemExit(f'{argument}: unexpected exit={process.returncode} stderr={stderr!r}')
    lines = stdout.splitlines()
    if len(lines) != 1:
        raise SystemExit(f'{argument}: stdout was not one JSON line: {stdout!r}')
    value = json.loads(lines[0])
    if value.get('kind') != argument[2:] or value.get('status') != 'complete' or value.get('errors') != []:
        raise SystemExit(f'{argument}: invalid fixture receipt: {value!r}')
    traces = []
    for line in stderr.splitlines():
        try: row = json.loads(line)
        except json.JSONDecodeError: continue
        if isinstance(row, dict) and 'cw_trace' in row: traces.append(row)
    for expected in ('host_attached', 'navigation_finished', 'payload_received'):
        if not any(row.get('cw_trace') == expected for row in traces):
            raise SystemExit(f'{argument}: missing worker diagnostic {expected}')
    if any(set(row) != {'cw_trace', 'request_id', 'attached', 'elapsed_ms'} or not isinstance(row['attached'], bool) for row in traces):
        raise SystemExit(f'{argument}: worker trace contains unexpected fields')
    if len({row['request_id'] for row in traces}) != 1:
        raise SystemExit(f'{argument}: worker trace changed request identity')
    if '8.8.4.4' in stderr:
        raise SystemExit(f'{argument}: worker trace leaked an observation')
print('BackgroundLeakWorker runtime DNS/WebRTC fixture: passed')
PY
