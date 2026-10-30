#!/bin/bash
# One-user-authorized, one-round live DNS check. All local state is temporary.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
CW_TEST_PARENT=$(mktemp -d "${TMPDIR:-/private/tmp}/cw-background-dns-live.XXXXXX")
trap 'rm -rf "$CW_TEST_PARENT"' EXIT
CW_TEST_RUNTIME="$CW_TEST_PARENT/runtime"
CW_TEST_HOME="$CW_TEST_PARENT/home"
CW_TEST_CACHE="$CW_TEST_PARENT/module-cache"
mkdir -p "$CW_TEST_RUNTIME" "$CW_TEST_HOME" "$CW_TEST_CACHE"
chmod 700 "$CW_TEST_PARENT" "$CW_TEST_RUNTIME" "$CW_TEST_HOME"
ENGINE="$ROOT/../target/debug/claude-watch-engine"
[[ -x "$ENGINE" ]] || { printf 'Missing debug engine; run cargo build -p claude-watch-engine first.\n' >&2; exit 1; }
cp "$ROOT/Resources/netcoffee_probe.html" "$ROOT/Resources/netcoffee_probe.js" "$ROOT/Resources/netcoffee_probe.css" "$CW_TEST_RUNTIME/"
cp "$ENGINE" "$CW_TEST_RUNTIME/watch-engine"
chmod 700 "$CW_TEST_RUNTIME/watch-engine"
xcrun swiftc -swift-version 5 -parse-as-library -target arm64-apple-macosx14.0 -D BACKGROUND_LEAK_WORKER -D BACKGROUND_LEAK_WORKER_TEST -module-cache-path "$CW_TEST_CACHE" -framework AppKit -framework WebKit "$ROOT/Sources/IdentityPresentation.swift" "$ROOT/Sources/BundledBackendVariant.swift" "$ROOT/Sources/LeakCheckModels.swift" "$ROOT/Sources/NetCoffeeModels.swift" "$ROOT/Sources/NetCoffeeLeakRunner.swift" "$ROOT/tools/BackgroundLeakWorker.swift" -o "$CW_TEST_RUNTIME/watch-leak-worker"
chmod 700 "$CW_TEST_RUNTIME/watch-leak-worker"
/usr/bin/codesign --force --sign - "$CW_TEST_RUNTIME/watch-leak-worker"
cat > "$CW_TEST_RUNTIME/BuildInfo.plist" <<'PLIST'
<?xml version="1.0"?><plist version="1.0"><dict><key>Architecture</key><string>arm64</string><key>RuntimeSchema</key><integer>2</integer><key>BackendVariant</key><string>rust-candidate</string><key>BackgroundEvidenceSchema</key><integer>1</integer></dict></plist>
PLIST
python3 - "$CW_TEST_RUNTIME" <<'PY'
import hashlib, plistlib, sys
from pathlib import Path
root = Path(sys.argv[1]); manifest = root / "BuildInfo.plist"
value = plistlib.loads(manifest.read_bytes())
names = ("watch-leak-worker", "watch-engine", "netcoffee_probe.html", "netcoffee_probe.js", "netcoffee_probe.css")
value["RuntimeHashes"] = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}
manifest.write_bytes(plistlib.dumps(value))
PY
cat > "$CW_TEST_PARENT/LeakPolicyCheck.swift" <<'SWIFT'
import Foundation
@main struct LeakPolicyCheck {
static func main() throws {
let receipt = try JSONDecoder().decode(LeakProbeResult.self, from: FileHandle.standardInput.readDataToEndOfFile())
let verdict = LeakPolicy.evaluate(receipt, kind: .dns, expected: "", now: Date().timeIntervalSince1970)
let output: [String: Any] = ["verdict": verdict.state.rawValue, "http_count": receipt.observations.filter { $0.kind == "http" }.count, "resolver_count": receipt.observations.filter { $0.kind == "resolver" }.count, "error_stages": Array(Set(receipt.errors.map(\.stage))).sorted(), "error_codes": Array(Set(receipt.errors.map(\.code))).sorted()]
FileHandle.standardOutput.write(try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys]))
}
}
SWIFT
xcrun swiftc -swift-version 5 -parse-as-library -target arm64-apple-macosx14.0 -module-cache-path "$CW_TEST_CACHE" "$ROOT/Sources/IdentityPresentation.swift" "$ROOT/Sources/LeakCheckModels.swift" "$CW_TEST_PARENT/LeakPolicyCheck.swift" -o "$CW_TEST_PARENT/leak-policy-check"
python3 - "$CW_TEST_RUNTIME" "$CW_TEST_HOME" "$CW_TEST_PARENT/leak-policy-check" <<'PY'
import json, os, signal, subprocess, sys, time
from pathlib import Path
runtime, home, checker = map(Path, sys.argv[1:])
env = dict(os.environ); env["HOME"] = str(home)
started = time.monotonic()
child = subprocess.Popen([str(runtime / "watch-leak-worker"), "--dns"], cwd=runtime, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
try: stdout, stderr = child.communicate(timeout=80)
except subprocess.TimeoutExpired:
    os.killpg(child.pid, signal.SIGTERM)
    try: stdout, stderr = child.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL); stdout, stderr = child.communicate()
    raise SystemExit("live DNS helper exceeded 80 seconds and was terminated")
elapsed = round((time.monotonic() - started) * 1000)
lines = stdout.splitlines()
if child.returncode != 0 or len(lines) != 1: raise SystemExit("live DNS helper did not return one bounded receipt")
receipt = json.loads(lines[0])
if receipt.get("kind") != "dns": raise SystemExit("live DNS helper returned the wrong result kind")
policy = json.loads(subprocess.run([str(checker)], input=lines[0], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=True).stdout)
allowed = {"collector", "http", "dns_images", "dns_records", "geoip", "ice"}; timeline=[]
for line in stderr.splitlines():
    try: event=json.loads(line)
    except json.JSONDecodeError: continue
    phase, at = event.get("phase"), event.get("elapsed_ms")
    if phase in allowed and isinstance(at,(int,float)) and 0 <= at <= 75000: timeline.append({"phase":phase,"elapsed_ms":int(at)})
print(json.dumps({"kind":"dns","status":receipt.get("status"),"elapsed_ms":elapsed,"http_count":policy["http_count"],"resolver_count":policy["resolver_count"],"verdict":policy["verdict"],"error_stages":policy["error_stages"],"error_codes":policy["error_codes"],"phase_timeline":timeline,"temporary_home_mode":oct(home.stat().st_mode & 0o777)}, ensure_ascii=False, separators=(",",":")))
PY
