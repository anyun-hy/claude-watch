#!/bin/bash
# No-signal multi-desktop regressions plus the existing warning/evidence contracts.
# Temporary state and mock inventories only; no application, helper or network runs.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$ROOT"
if [[ $# -ne 0 ]]; then
  echo 'Usage: bash tools/test-multi-desktop-regressions.sh' >&2
  exit 2
fi
command -v cargo >/dev/null || { echo 'cargo is required; no tests have run.' >&2; exit 1; }
# Keep the exact no-signal selections maintained by the warning runner (46 tests).
bash tools/test-warning-regressions.sh
cargo test --locked -p claude-watch-runtime --test multi_desktop_regressions -- --nocapture
cargo test --locked -p claude-watch-runtime --test supervised_evidence_regressions -- --nocapture
