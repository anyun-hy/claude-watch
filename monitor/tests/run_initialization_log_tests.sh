#!/bin/bash
# Isolated log files and fixture-only first-run checks; no installed app actions.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/private/tmp}/cw-initialization-logs.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT
CW_MACOS_MINIMUM=$(cat "$ROOT/macos-minimum.txt")
xcrun swiftc -swift-version 5 -parse-as-library -D UI_REVIEW -target "arm64-apple-macosx$CW_MACOS_MINIMUM" \
  -module-cache-path "$TEST_ROOT/cache" -framework SwiftUI -framework AppKit -framework WebKit \
  "$ROOT"/Sources/*.swift "$ROOT/tests/InitializationConnectionLogTests.swift" -o "$TEST_ROOT/log-tests"
"$TEST_ROOT/log-tests"
