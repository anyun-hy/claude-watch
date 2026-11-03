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
  SWIFT_FLAGS=(-swift-version 5 -D PROCESS_POLICY_TESTS -parse-as-library)
  if [[ "$(uname -s)" == Darwin ]]; then
    command -v xcrun >/dev/null || { echo 'xcrun is required for macOS Swift tests; no Swift tests have run.' >&2; exit 1; }
    # xcrun --find returns the real compiler, not the /usr/bin SDK-selecting
    # shim. Supply an explicit SDK and the project's deployment target rather
    # than inheriting a host-derived target (e.g. macosx28.0). Keep the caller's
    # DEVELOPER_DIR/TOOLCHAINS selection; never change xcode-select globally.
    unset SDKROOT MACOSX_DEPLOYMENT_TARGET
    SWIFTC=$(xcrun --sdk macosx --find swiftc) || { echo 'Cannot locate swiftc in the selected developer tools.' >&2; exit 1; }
    SDK=$(xcrun --sdk macosx --show-sdk-path) || { echo 'Cannot locate the macOS SDK in the selected developer tools.' >&2; exit 1; }
    [[ -x "$SWIFTC" && -d "$SDK" ]] || { echo 'The selected Swift compiler or macOS SDK is missing; no Swift tests have run.' >&2; exit 1; }
    MINIMUM=$(cat "$ROOT/monitor/macos-minimum.txt")
    [[ "$MINIMUM" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || { echo 'Invalid project macOS minimum; no Swift tests have run.' >&2; exit 1; }
    ARCH=$(uname -m)
    case "$ARCH" in arm64|x86_64) ;; *) echo "Unsupported macOS test architecture: $ARCH" >&2; exit 1;; esac
    TARGET="$ARCH-apple-macosx$MINIMUM"
    SWIFT_FLAGS+=(-sdk "$SDK" -target "$TARGET")
    # Align any compiler/linker subprocesses with the explicit command flags.
    # These exports only affect this test script and its children.
    export SDKROOT="$SDK" MACOSX_DEPLOYMENT_TARGET="$MINIMUM"
    printf '[swift] SDK: %s\n[swift] target: %s\n' "$SDK" "$TARGET"
  else
    SWIFTC=$(command -v swiftc) || { echo 'swiftc is required; no Swift tests have run.' >&2; exit 1; }
  fi
  printf '[swift] compiler: %s\n' "$SWIFTC"
  "$SWIFTC" --version
  BUILD=$(mktemp -d "${TMPDIR:-/tmp}/cw-no-signal-tests.XXXXXX")
  trap 'rm -rf "$BUILD"' EXIT
  mkdir -p "$BUILD/module-cache"
  if ! "$SWIFTC" "${SWIFT_FLAGS[@]}" -module-cache-path "$BUILD/module-cache" \
    monitor/Sources/AIProcessControl.swift monitor/tests/AIProcessExitEvidenceTests.swift \
    -o "$BUILD/process-exit-tests"; then
    echo 'Swift regression compilation failed; no Swift assertions have run.' >&2
    if [[ "$(uname -s)" == Darwin ]]; then
      echo 'Check the compiler, macOS SDK and target printed above. This runner does not install or switch developer tools.' >&2
    fi
    exit 1
  fi
  "$BUILD/process-exit-tests"
fi
