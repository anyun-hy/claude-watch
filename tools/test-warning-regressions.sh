#!/bin/bash
# Narrow, no-signal regression selection for policy faults and warning recovery.
# These tests use temporary state and mocks. Never run the whole controlled
# suite here: some unrelated legacy tests deliberately signal owned children.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$ROOT"
if [[ $# -ne 0 ]]; then
  echo 'Usage: bash tools/test-warning-regressions.sh' >&2
  exit 2
fi
command -v cargo >/dev/null || { echo 'cargo is required; no tests have run.' >&2; exit 1; }
cargo check --locked -p claude-watch-runtime -p claude-watch-engine
cargo test --locked -p claude-watch-core --test probe_independence_regressions -- --nocapture
cargo test --locked -p claude-watch-core --test probe_drift_contracts -- --nocapture
cargo test --locked -p claude-watch-runtime --lib controlled::warning_regressions -- --nocapture
cargo test --locked -p claude-watch-runtime --lib controlled::guard_regressions -- --nocapture
# Exact selection: all three use Fake::default with no owned child or signal.
for test_name in \
  invalid_configuration_reports_without_authorising_a_stop \
  warn_configured_drift_resumes_supervision_once_recovered \
  the_openai_family_is_supervised_and_closed_on_confirmed_drift; do
  cargo test --locked -p claude-watch-runtime --test controlled_contracts "$test_name" -- --exact --nocapture
done
