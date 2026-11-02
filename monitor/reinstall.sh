#!/bin/bash
# One entry point: build the engine, then run the native reinstall flow.
# Usage: monitor/reinstall.sh <version> <build> [--dry-run]
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd -P)
PROJECT=$(cd "$ROOT/.." && pwd -P)
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
cargo build --release -p claude-watch-engine >/dev/null
exec "$PROJECT/target/release/claude-watch-engine" reinstall \
  --version "$version" --build "$build" --project "$PROJECT" "$@"
