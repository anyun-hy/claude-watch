#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$ROOT"
case "${1:-all}" in
  all|rust|swift) MODE=${1:-all};;
  *) echo 'Usage: bash tools/test-lifecycle-regressions.sh [all|rust|swift]' >&2; exit 2;;
esac
[[ $# -le 1 ]] || { echo 'Too many arguments.' >&2; exit 2; }

if [[ "$MODE" != swift ]]; then
  command -v cargo >/dev/null || { echo 'cargo is required; no Rust tests ran.' >&2; exit 1; }
  cargo check --locked -p claude-watch-runtime -p claude-watch-engine
  cargo test --locked -p claude-watch-core --lib guard_event::tests
  cargo test --locked -p claude-watch-runtime --test lifecycle_policy_regressions
fi

if [[ "$MODE" != rust ]]; then
  command -v python3 >/dev/null || { echo 'python3 is required for progress-routing checks.' >&2; exit 1; }
  python3 tools/test-account-progress-routing.py
  if command -v xcrun >/dev/null; then
    SWIFTC=$(xcrun --sdk macosx --find swiftc)
    SDK=$(xcrun --sdk macosx --show-sdk-path)
    MIN=$(/bin/cat monitor/macos-minimum.txt)
    ARCH=$(uname -m)
    "$SWIFTC" -parse -swift-version 5 -sdk "$SDK" -target "$ARCH-apple-macosx$MIN"       monitor/Sources/SetupProgress.swift monitor/Sources/SwitcherStore.swift >/dev/null
  fi
fi
