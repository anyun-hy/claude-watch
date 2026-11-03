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
#
# Build into the explicit `aarch64-apple-darwin` target. The packaging step
# (tools/build-rust-components.sh) compiles the same packages into that same
# directory, so a single cache serves both phases instead of compiling the
# whole tree twice (once as the host target, once as the explicit target).
cargo build --release --target aarch64-apple-darwin -p claude-watch-engine >/dev/null
exec "$PROJECT/target/aarch64-apple-darwin/release/claude-watch-engine" reinstall \
  --version "$version" --build "$build" --project "$PROJECT" "$@"
