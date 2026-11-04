#!/bin/bash
# No-signal config/approval migration tests with temporary files and mock desktops.
# This does not touch installed config, launch apps or send OS signals.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$ROOT"
if [[ $# -ne 0 ]]; then
  echo 'Usage: bash tools/test-force-migration-regressions.sh' >&2
  exit 2
fi
command -v cargo >/dev/null || { echo 'cargo is required; no tests have run.' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'python3 is required; no tests have run.' >&2; exit 1; }

cargo check --locked -p claude-watch-core -p claude-watch-runtime -p claude-watch-engine
cargo test --locked -p claude-watch-core --test force_approval_contracts
cargo test --locked -p claude-watch-core --lib config::protection_tests
cargo test --locked -p claude-watch-runtime --test force_migration_regressions
cargo test --locked -p claude-watch-runtime --lib config_store::cli_settings_contracts::default_policy_digest_is_pinned_so_a_field_reorder_cannot_break_heartbeats
python3 tools/test-force-confirmation-routing.py
# Re-run the exact 87 previously passing no-signal guard/evidence contracts
# because their explicit Force fixtures now carry per-key authorization.
bash tools/test-multi-desktop-regressions.sh
# Existing stream/Swift syntax checks for the modified SwitcherStore.
bash tools/test-lifecycle-regressions.sh swift
