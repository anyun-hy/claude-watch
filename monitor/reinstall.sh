#!/bin/bash
# One entry point: build the engine, then run the native reinstall flow.
# Usage: monitor/reinstall.sh <version> <build> [--dry-run]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd -P)
PROJECT=$(cd "$ROOT/.." && pwd -P)
source "$ROOT/network-backend.sh"
cw_require_seatbelt_backend
if [[ $# -lt 2 ]]; then
  printf 'usage: %s <version> <build> [--dry-run]\n' "${0##*/}" >&2
  exit 2
fi
version=$1
build=$2
shift 2
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
cd "$PROJECT"
# The flow replaces the installed app, so it must run the engine built from
# this tree, never the copy inside the app it is about to remove.
#
# Build exactly the packaging component set through its existing entry point.
# Matching only the target directory/linker/SDK is insufficient: adding nono's
# launcher later changes unified dependency features and recompiles the engine.
# The build-only mode runs no engine, stages nothing and installs no service.
# Logging wraps the existing two phases; it neither builds a second engine nor
# changes stdin ownership. Only the bounded saved copy is filtered; the console
# remains live, and original build/install failures retain their exit status.
CW_REINSTALL_LOGGER="$PROJECT/tools/reinstall_log.py"
CW_REINSTALL_LOG_RUN=''
if command -v python3 >/dev/null 2>&1 && [[ -f "$CW_REINSTALL_LOGGER" ]]; then
  CW_REINSTALL_LOG_RUN=$(python3 "$CW_REINSTALL_LOGGER" --init --version "$version" --build "$build") || CW_REINSTALL_LOG_RUN=''
  CW_CARGO_BIN=cargo python3 "$CW_REINSTALL_LOGGER" --run "$CW_REINSTALL_LOG_RUN" --phase build -- \
    "$PROJECT/tools/build-rust-components.sh" --build-only
  exec python3 "$CW_REINSTALL_LOGGER" --run "$CW_REINSTALL_LOG_RUN" --phase install -- \
    "$PROJECT/target/aarch64-apple-darwin/release/claude-watch-engine" reinstall \
    --version "$version" --build "$build" --project "$PROJECT" "$@"
else
  printf 'Watch 安装日志不可用；原流程继续，退出状态不变。\n' >&2
  CW_CARGO_BIN=cargo "$PROJECT/tools/build-rust-components.sh" --build-only
  exec "$PROJECT/target/aarch64-apple-darwin/release/claude-watch-engine" reinstall \
    --version "$version" --build "$build" --project "$PROJECT" "$@"
fi
