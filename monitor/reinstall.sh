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
# (tools/build-rust-components.sh) compiles the same package into that same
# directory, so a single cargo cache serves both phases instead of compiling
# the whole tree twice. That cache reuse only holds when the two invocations
# carry the SAME environment: cargo folds MACOSX_DEPLOYMENT_TARGET and the
# target linker into its fingerprint, so a first build without them and a
# packaging build with them would otherwise rebuild every crate from scratch.
CW_MACOS_MINIMUM=$(/bin/cat "$PROJECT/monitor/macos-minimum.txt")
CW_APPLE_CLANG=$(/usr/bin/xcrun --sdk macosx --find clang)
CW_APPLE_SDK=$(/usr/bin/xcrun --sdk macosx --show-sdk-path)
SDKROOT="$CW_APPLE_SDK" \
CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER="$CW_APPLE_CLANG" \
CC_aarch64_apple_darwin="$CW_APPLE_CLANG" \
MACOSX_DEPLOYMENT_TARGET="$CW_MACOS_MINIMUM" \
cargo build --release --target aarch64-apple-darwin -p claude-watch-engine >/dev/null
exec "$PROJECT/target/aarch64-apple-darwin/release/claude-watch-engine" reinstall \
  --version "$version" --build "$build" --project "$PROJECT" "$@"
