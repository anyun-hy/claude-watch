#!/bin/bash
# Actual Rust transport -> resident Swift helper -> JS -> persisted receipts.
# The default mode replaces every outbound primitive with local fixtures.
set -euo pipefail
MODE=--fixture
if [[ $# -gt 0 ]]; then MODE="$1"; fi
case "$MODE" in --fixture|--live) ;; *) exit 2;; esac
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
CW_TEST_DIR=$(mktemp -d /private/tmp/cw-resident-worker.XXXXXX)
trap 'rm -rf "$CW_TEST_DIR"' EXIT
RUNTIME="$CW_TEST_DIR/runtime"
mkdir -p "$RUNTIME" "$CW_TEST_DIR/home"
chmod 700 "$CW_TEST_DIR" "$RUNTIME" "$CW_TEST_DIR/home"
cp "$ROOT"/monitor/Resources/{netcoffee_probe.html,netcoffee_probe.js,netcoffee_probe.css,ipleak_probe.html,ipleak_probe.js} "$RUNTIME/"
if [[ "$MODE" == --fixture ]]; then
cat > "$RUNTIME/fixture.js" <<'JS'
window.fetch=async function(raw) { const u=new URL(raw);let data;
 if(u.pathname==='/dnsdetection/') {const m=u.hostname.match(/^([0-9a-f]{40})-[0-7]r?\.ipleak\.net$/);data={session:m[1],ip:{'8.8.8.8':1}};}
 else if(u.pathname==='/json/')data={ip:'8.8.4.4',country_code:'US'};
 else data={ip:'8.8.8.8',country_code:'US'};
 return new Response(JSON.stringify(data),{status:200});
};
window.RTCPeerConnection=class {
 constructor(){this.iceGatheringState='new';}createDataChannel(){}createOffer(){return Promise.resolve({});}
 setLocalDescription(){queueMicrotask(()=>{this.onicecandidate({candidate:{address:'8.8.4.4',type:'srflx',candidate:'candidate:1 1 udp 1 8.8.4.4 3478 typ srflx'}});this.onicecandidate({candidate:null});});return Promise.resolve();}
 close(){}
};
JS
python3 - "$RUNTIME" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
for name in ('ipleak_probe.html','netcoffee_probe.html'):
 f=p/name;s=f.read_text();f.write_text(s.replace('<script src=', '<script src="fixture.js"></script><script src=',1))
PY
cat > "$RUNTIME/watch-engine" <<'PY'
#!/usr/bin/python3
import json,sys
kind,query=sys.argv[2],sys.argv[3]
print(json.dumps({'kind':kind,'query':query,'sourceURL':'https://fixture.invalid/',
 'queriedAt':1,'finishedAt':2,'status':'complete','httpStatus':200,'raw':'ip=8.8.4.4\n' if kind=='trace' else '{}',
 'data':{'ip':query,'country':'US','country_code':'US'} if kind=='geoip' else None,'error':None}))
PY
else
  /Users/anyun/.cargo/bin/cargo build --manifest-path "$ROOT/Cargo.toml" -p claude-watch-engine
  cp "$ROOT/target/debug/claude-watch-engine" "$RUNTIME/watch-engine"
fi
chmod 700 "$RUNTIME/watch-engine"
# Only the live helper's Coffee cache is redirected with the existing --home
# option. The real HOME, settings and installed runtime are untouched.
python3 - "$ROOT" "$CW_TEST_DIR" "$MODE" <<'PY'
from pathlib import Path
import sys
root,out,mode=Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3]
s=(root/'monitor/Sources/NetCoffeeModels.swift').read_text()
if mode=='--live':
 old='p.arguments = ["coffee", kind, query]';assert s.count(old)==1
 s=s.replace(old,'p.arguments = ["--home", ProcessInfo.processInfo.environment["CW_RESIDENT_TEST_HOME"]!, "coffee", kind, query]')
(out/'NetCoffeeModels.swift').write_text(s)
PY
CW_MACOS_MINIMUM=$(cat "$ROOT/monitor/macos-minimum.txt")
xcrun swiftc -swift-version 5 -parse-as-library -D BACKGROUND_LEAK_WORKER -target "arm64-apple-macosx$CW_MACOS_MINIMUM" \
 -module-cache-path "$CW_TEST_DIR/cache" -framework AppKit -framework WebKit \
 "$ROOT/monitor/Sources/IdentityPresentation.swift" "$ROOT/monitor/Sources/BundledBackendVariant.swift" "$ROOT/monitor/Sources/LeakCheckModels.swift" \
 "$CW_TEST_DIR/NetCoffeeModels.swift" "$ROOT/monitor/Sources/NetCoffeeLeakRunner.swift" "$ROOT/monitor/Sources/IPLeakDNSRunner.swift" \
 "$ROOT/monitor/Sources/IPLeakDNSRetryRunner.swift" "$ROOT/monitor/tools/BackgroundLeakWorker.swift" -o "$RUNTIME/watch-leak-worker"
/usr/bin/codesign --force --sign - "$RUNTIME/watch-leak-worker"
python3 - "$RUNTIME" <<'PY'
from pathlib import Path
import hashlib,plistlib,sys
p=Path(sys.argv[1]);names=('watch-leak-worker','watch-engine','netcoffee_probe.html','netcoffee_probe.js','netcoffee_probe.css','ipleak_probe.html','ipleak_probe.js')
x={'Architecture':'arm64','BackendVariant':'rust-candidate','RuntimeSchema':2,'BackgroundEvidenceSchema':2,
 'RuntimeHashes':{n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in names}}
(p/'BuildInfo.plist').write_bytes(plistlib.dumps(x))
PY
CW_LIVE=0
if [[ "$MODE" == --live ]]; then CW_LIVE=1; fi
CW_TEST_RESIDENT_RUNTIME="$RUNTIME" CW_TEST_RESIDENT_LIVE="$CW_LIVE" CW_RESIDENT_TEST_HOME="$CW_TEST_DIR/home" \
 /Users/anyun/.cargo/bin/cargo test --manifest-path "$ROOT/Cargo.toml" -p claude-watch-runtime --test resident_evidence_contracts \
 real_webkit_helper_reuses_views_and_persists_only_current_receipts -- --ignored --nocapture
