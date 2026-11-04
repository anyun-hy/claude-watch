#!/bin/bash
# File-only account commit and signed ZIP permission regressions.
# Mock OS/network adapters, temporary profiles and fixtures only. No login,
# app exit, service change, installation or extracted program execution.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$ROOT"
if [[ $# -ne 0 ]]; then
  echo 'Usage: bash tools/test-storage-regressions.sh' >&2
  exit 2
fi
command -v cargo >/dev/null || { echo 'cargo is required; no tests have run.' >&2; exit 1; }
cargo check --locked -p claude-watch-runtime -p claude-watch-engine
# Catch-unwind fault injection is expected in the account suite; keep normal
# output capture so a passing injected interruption is not presented as a crash.
cargo test --locked -p claude-watch-runtime --test account_commit_regressions
cargo test --locked -p claude-watch-runtime --test account_contracts
cargo test --locked -p claude-watch-runtime --lib update::permissions::tests
cargo test --locked -p claude-watch-runtime --test update_permissions_regressions
# Exact old contracts: no network transport, native updater or child process.
for test_name in \
  invalid_signature_and_unsafe_archive_are_rejected \
  rsa_signed_manifest_is_verified_before_archive_use \
  native_archives_require_matching_components_and_reject_old_business_resources; do
  cargo test --locked -p claude-watch-runtime --test update_contracts "$test_name" -- --exact
done
