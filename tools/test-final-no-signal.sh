#!/bin/bash
# Source, mocked guard, transaction and macOS Swift typecheck acceptance.
# No real launch, installed configuration write, native signal or app install.
# The full Cargo test workspace is intentionally excluded: some legacy
# integration fixtures signal owned child processes.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$ROOT"
[[ $# -eq 0 ]] || { echo 'Usage: bash tools/test-final-no-signal.sh' >&2; exit 2; }

echo '===== SOURCE CONTRACTS ====='
command -v python3 >/dev/null || { echo 'python3 required' >&2; exit 1; }
python3 -m unittest -v \
  tools/tests/test_build_pipeline_contract.py \
  tools/tests/test_policy_catalog_generation.py \
  tools/tests/test_guard_stop_consolidation.py \
  tools/tests/test_platform_contract.py \
  tools/tests/test_architecture_boundaries.py
python3 tools/generate-ai-policy-swift.py --check
bash -n monitor/build.sh monitor/package-dmg.sh tools/build-rust-components.sh

echo '===== RUST COMPILE AND SAFE REGRESSIONS ====='
command -v cargo >/dev/null || { echo 'cargo required' >&2; exit 1; }
cargo check --locked -p claude-watch-core -p claude-watch-runtime -p claude-watch-engine -p claude-watch-installer
# Exact no-signal adapter test: does not start a real application or child.
cargo test --locked -p claude-watch-runtime --test controlled_contracts fake_family_switches_target_even_without_a_running_member -- --exact
bash tools/test-force-migration-regressions.sh
bash tools/test-storage-regressions.sh

echo '===== SWIFT ISOLATED PROCESS POLICY TESTS ====='
bash tools/test-guard-regressions.sh swift

if [[ "$(uname -s)" == Darwin ]]; then
  echo '===== COMPLETE PRODUCTION SWIFT TYPECHECK ====='
  command -v xcrun >/dev/null || { echo 'xcrun required on macOS' >&2; exit 1; }
  SWIFTC=$(xcrun --sdk macosx --find swiftc)
  SDK=$(xcrun --sdk macosx --show-sdk-path)
  MIN=$(cat monitor/macos-minimum.txt)
  [[ -x "$SWIFTC" && -d "$SDK" && "$MIN" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || {
    echo 'Swift compiler/SDK/minimum target invalid' >&2; exit 1;
  }
  ARCH=$(uname -m)
  case "$ARCH" in arm64|x86_64) ;; *) echo 'Unsupported Swift typecheck architecture' >&2; exit 1;; esac
  BUILD=$(mktemp -d /tmp/cw-final-typecheck.XXXXXX)
  trap 'rm -rf "$BUILD"' EXIT
  mkdir -p "$BUILD/module-cache"
  "$SWIFTC" -swift-version 5 -parse-as-library -typecheck \
    -target "$ARCH-apple-macosx$MIN" -sdk "$SDK" \
    -module-cache-path "$BUILD/module-cache" \
    -framework SwiftUI -framework AppKit -framework WebKit \
    monitor/Sources/*.swift
  echo '===== ISOLATED SWIFTUI FIXTURE ASSERTIONS ====='
  "$SWIFTC" -swift-version 5 -Onone -parse-as-library -D UI_REVIEW \
    -target "$ARCH-apple-macosx$MIN" -sdk "$SDK" \
    -module-cache-path "$BUILD/module-cache" \
    -framework SwiftUI -framework AppKit -framework WebKit \
    monitor/Sources/*.swift monitor/tests/SwitcherStoreTests.swift \
    -o "$BUILD/switcher-fixture-tests"
  "$BUILD/switcher-fixture-tests"
else
  echo 'SKIP: macOS production Swift typecheck (not running on macOS)'
fi
echo 'PASS: selected no-signal source, Rust, and Swift regressions completed'
