#!/bin/bash
# Build the arm64 Rust candidate runtime into an explicit local staging directory.
# This never installs, launches, or modifies an existing Claude Watch application.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: tools/build-rust-components.sh --output <directory>

Builds the local arm64 Rust candidate runtime and writes components.json plus:
  watch-engine, watch-native-observer, watch-process-control
USAGE
}

OUTPUT=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      [[ $# -ge 2 ]] || { echo 'Missing value for --output' >&2; exit 2; }
      OUTPUT=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "$OUTPUT" ]] || { usage >&2; exit 2; }
[[ "$(uname -m)" == 'arm64' ]] || { echo 'Rust candidate packaging requires an arm64 host.' >&2; exit 1; }

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
REPOSITORY_ROOT=$(cd "$SCRIPT_DIR/.." && pwd -P)
CW_MACOS_MINIMUM=$(/bin/cat "$REPOSITORY_ROOT/monitor/macos-minimum.txt")
CW_CARGO_BIN=${CW_CARGO_BIN:-cargo}
command -v "$CW_CARGO_BIN" >/dev/null 2>&1 || { echo 'Cargo is required to build the Rust candidate components.' >&2; exit 1; }

# Cargo's package/bin name is verified in crates/watch-engine/Cargo.toml. The
# native component locations are queried from the built engine, never guessed.
MACOSX_DEPLOYMENT_TARGET="$CW_MACOS_MINIMUM" "$CW_CARGO_BIN" build --manifest-path "$REPOSITORY_ROOT/Cargo.toml" --locked --release --target aarch64-apple-darwin \
  --package claude-watch-engine --bin claude-watch-engine

ENGINE="$REPOSITORY_ROOT/target/aarch64-apple-darwin/release/claude-watch-engine"
[[ -x "$ENGINE" ]] || { echo "Cargo did not produce executable engine: $ENGINE" >&2; exit 1; }
COMPONENT_PATHS=$("$ENGINE" --component-paths) || { echo 'Rust engine could not report component paths.' >&2; exit 1; }

STAGE=$(mktemp -d "${TMPDIR:-/tmp}/claude-watch-rust-components.XXXXXX")
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

python3 - "$COMPONENT_PATHS" "$ENGINE" "$STAGE" <<'PY'
import hashlib
import json
import os
import shutil
import stat
import sys
from pathlib import Path

reported = json.loads(sys.argv[1])
engine = Path(sys.argv[2])
stage = Path(sys.argv[3])
if not isinstance(reported, dict):
    raise SystemExit("Rust engine returned an invalid component-paths document")
components = {"engine": engine}
for field in ("native_observer", "process_control"):
    raw = reported.get(field)
    if not isinstance(raw, str) or not raw:
        raise SystemExit(f"Rust engine did not report required component path: {field}")
    candidate = Path(raw)
    if not candidate.is_absolute() or not candidate.is_file() or candidate.is_symlink():
        raise SystemExit(f"Rust engine reported unsafe or missing component path: {field}")
    if not os.access(candidate, os.X_OK):
        raise SystemExit(f"Rust engine reported non-executable component: {field}")
    components[field] = candidate
stage.mkdir(parents=True, exist_ok=True)
bundle_names = {"engine": "watch-engine"}
for field in ("native_observer", "process_control"):
    bundle_names[field] = components[field].name
if len(set(bundle_names.values())) != len(bundle_names):
    raise SystemExit("Rust engine reported colliding component filenames")
manifest = {"schema": 1, "architecture": "arm64", "kind": "rust-candidate", "components": {}}
for field, source in components.items():
    target = stage / bundle_names[field]
    shutil.copy2(source, target)
    target.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    manifest["components"][field] = {"bundle_name": target.name, "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}
(stage / "components.json").write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
PY

mkdir -p "$OUTPUT"
for item in "$STAGE"/*; do cp "$item" "$OUTPUT/"; done
printf 'Staged Rust candidate components: %s\n' "$OUTPUT"
