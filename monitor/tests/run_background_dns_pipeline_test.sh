#!/bin/bash
# Offline end-to-end DNS background-helper check. The real IPLeak JS runs;
# an injected fetch supplies local session-bound responses.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
CW_MACOS_MINIMUM=$(/bin/cat "$ROOT/macos-minimum.txt")
TEST_PARENT=$(mktemp -d "${TMPDIR:-/private/tmp}/cw-background-dns-pipeline.XXXXXX")
trap 'rm -rf "$TEST_PARENT"' EXIT
RUNTIME="$TEST_PARENT/runtime"
HOME_FIXTURE="$TEST_PARENT/home"
mkdir -p "$RUNTIME" "$HOME_FIXTURE" "$TEST_PARENT/module-cache"
chmod 700 "$RUNTIME" "$HOME_FIXTURE"
cp "$ROOT/Resources/netcoffee_probe.html" "$ROOT/Resources/netcoffee_probe.js" "$ROOT/Resources/netcoffee_probe.css" "$ROOT/Resources/ipleak_probe.js" "$RUNTIME/"
cat > "$RUNTIME/ipleak_probe.html" <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self' 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'"><script>
window.fetch = async function(raw) { const u=new URL(raw); let body;
 if(u.pathname==='/dnsdetection/') { let m=u.hostname.match(/^([0-9a-f]{40})-[0-7]\.ipleak\.net$/); if(!m) throw Error('session'); body={session:m[1],ip:{'8.8.8.8':1}}; }
 else if(u.hostname==='ipleak.net' && u.pathname==='/json/') body={ip:'1.1.1.1',country_code:'JP'};
 else if(u.hostname==='ipleak.net' && u.pathname==='/json/8.8.8.8') body={ip:'8.8.8.8',country_code:'JP'};
 else throw Error('unexpected request');
 return new Response(JSON.stringify(body),{status:200,headers:{'content-type':'application/json'}});
};</script><script src="ipleak_probe.js" defer></script></head><body><span id="status"></span></body></html>
HTML
cat > "$RUNTIME/watch-engine" <<'SH'
#!/bin/sh
case "$1:$2" in
  coffee:trace) printf '%s\n' '{"kind":"trace","query":"","sourceURL":"https://fixture.invalid/trace","queriedAt":1,"finishedAt":2,"status":"complete","httpStatus":200,"raw":"ip=8.8.4.4\nloc=JP\n","data":null,"error":null}' ;;
  coffee:dns) printf '%s\n' '{"kind":"dns","query":"fixture","sourceURL":"https://fixture.invalid/dns","queriedAt":1,"finishedAt":2,"status":"complete","httpStatus":200,"raw":"{}","data":{"dns_servers":["8.8.4.4"]},"error":null}' ;;
  coffee:geoip) printf '%s\n' '{"kind":"geoip","query":"8.8.4.4","sourceURL":"https://fixture.invalid/geoip","queriedAt":1,"finishedAt":2,"status":"complete","httpStatus":200,"raw":"{}","data":{"ip":"8.8.4.4","country":"JP"},"error":null}' ;;
  *) exit 97 ;;
esac
SH
chmod 700 "$RUNTIME/watch-engine"
xcrun swiftc -swift-version 5 -parse-as-library -target "arm64-apple-macosx$CW_MACOS_MINIMUM" -D BACKGROUND_LEAK_WORKER -D BACKGROUND_LEAK_WORKER_TEST \
  -module-cache-path "$TEST_PARENT/module-cache" -framework AppKit -framework WebKit \
  "$ROOT/Sources/IdentityPresentation.swift" "$ROOT/Sources/BundledBackendVariant.swift" "$ROOT/Sources/LeakCheckModels.swift" \
  "$ROOT/Sources/NetCoffeeModels.swift" "$ROOT/Sources/NetCoffeeLeakRunner.swift" "$ROOT/Sources/IPLeakDNSRunner.swift" "$ROOT/Sources/IPLeakDNSRetryRunner.swift" "$ROOT/tools/BackgroundLeakWorker.swift" \
  -o "$RUNTIME/watch-leak-worker"
chmod 700 "$RUNTIME/watch-leak-worker"
/usr/bin/codesign --force --sign - "$RUNTIME/watch-leak-worker"
cat > "$RUNTIME/BuildInfo.plist" <<'PLIST'
<?xml version="1.0"?><plist version="1.0"><dict><key>Architecture</key><string>arm64</string><key>RuntimeSchema</key><integer>2</integer><key>BackendVariant</key><string>rust-candidate</string><key>BackgroundEvidenceSchema</key><integer>2</integer></dict></plist>
PLIST
python3 - "$RUNTIME" "$HOME_FIXTURE" <<'PY'
import hashlib, json, os, signal, subprocess, sys
from pathlib import Path
import plistlib
runtime, home = map(Path, sys.argv[1:])
manifest = runtime / 'BuildInfo.plist'
value = plistlib.loads(manifest.read_bytes())
names = ('watch-leak-worker', 'watch-engine', 'netcoffee_probe.html', 'netcoffee_probe.js', 'netcoffee_probe.css', 'ipleak_probe.html', 'ipleak_probe.js')
value['RuntimeHashes'] = {name: hashlib.sha256((runtime / name).read_bytes()).hexdigest() for name in names}
manifest.write_bytes(plistlib.dumps(value))
env = {**os.environ, 'HOME': str(home)}
process = subprocess.Popen([str(runtime / 'watch-leak-worker'), '--dns'], cwd=runtime, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
try:
    stdout, stderr = process.communicate(timeout=75)
except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGTERM)
    try: stdout, stderr = process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL); stdout, stderr = process.communicate()
    raise SystemExit('offline DNS pipeline timed out')
if process.returncode != 0:
    raise SystemExit(f'offline DNS pipeline exit={process.returncode}')
rows = stdout.splitlines()
if len(rows) != 1:
    raise SystemExit('offline DNS pipeline stdout was not one JSON line')
receipt = json.loads(rows[0])
errors = [str(item.get('code')) for item in receipt.get('errors', []) if isinstance(item, dict)]
summary = {'kind': receipt.get('kind'), 'status': receipt.get('status'), 'observation_count': len(receipt.get('observations', [])), 'error_codes': errors, 'temporary_home_mode': oct(home.stat().st_mode & 0o777), 'fixture_stage_count': stderr.count('background fixture stage:')}
if summary['kind'] != 'dns' or summary['status'] != 'complete' or errors or summary['observation_count'] < 2:
    raise SystemExit('offline DNS pipeline invalid result: ' + json.dumps(summary))
print(json.dumps(summary, ensure_ascii=False))
PY
