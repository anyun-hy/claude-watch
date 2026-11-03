#!/bin/bash
# Compile/check and run ONLY the isolated no-signal guard/evidence tests.
# No app launch, installed configuration write, native helper, or live signal.
# Existing all-tests suites contain owned-child signal fixtures; do not run them here.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$ROOT"
MODE=${1:-all}
case "$MODE" in all|rust|swift) ;; *) echo 'Usage: bash tools/test-guard-regressions.sh [all|rust|swift]' >&2; exit 2;; esac

if [[ "$MODE" != swift ]]; then
  command -v cargo >/dev/null || { echo 'cargo is required; no Rust tests have run.' >&2; exit 1; }
  cargo check --locked -p claude-watch-runtime -p claude-watch-engine
  cargo test --locked -p claude-watch-runtime --lib controlled::guard_regressions -- --nocapture
  cargo test --locked -p claude-watch-runtime --lib desktop_native::close_receipt::tests -- --nocapture
  cargo test --locked -p claude-watch-runtime --test supervised_evidence_regressions -- --nocapture
fi
if [[ "$MODE" != rust ]]; then
  if command -v xcrun >/dev/null; then SWIFTC=$(xcrun --find swiftc)
  else SWIFTC=$(command -v swiftc) || { echo 'swiftc is required; no Swift tests have run.' >&2; exit 1; }; fi
  BUILD=$(mktemp -d "${TMPDIR:-/tmp}/cw-no-signal-tests.XXXXXX")
  trap 'rm -rf "$BUILD"' EXIT
  "$SWIFTC" -swift-version 5 -D PROCESS_POLICY_TESTS -parse-as-library \
    monitor/Sources/AIProcessControl.swift monitor/tests/AIProcessExitEvidenceTests.swift \
    -o "$BUILD/process-exit-tests"
  "$BUILD/process-exit-tests"
fi
