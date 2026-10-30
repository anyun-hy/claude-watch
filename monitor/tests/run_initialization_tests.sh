#!/bin/bash
# All probes/permissions/mutations are fixtures. No application is installed.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
CW_MACOS_MINIMUM=$(/bin/cat "$ROOT/macos-minimum.txt")
TEST_ROOT=$(mktemp -d "${TMPDIR:-/private/tmp}/cw-initialization.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT
# Check the real application entry against the shared macOS minimum target.
# The fixture build uses the same target to catch newer-only APIs as well.
xcrun swiftc -swift-version 5 -typecheck -parse-as-library -target "arm64-apple-macosx$CW_MACOS_MINIMUM" \
  -module-cache-path "$TEST_ROOT/cache" -framework SwiftUI -framework AppKit -framework WebKit \
  "$ROOT"/Sources/*.swift
xcrun swiftc -swift-version 5 -parse-as-library -D UI_REVIEW -target "arm64-apple-macosx$CW_MACOS_MINIMUM" \
  -module-cache-path "$TEST_ROOT/cache" -framework SwiftUI -framework AppKit -framework WebKit \
  "$ROOT"/Sources/*.swift "$ROOT/tests/InitializationTests.swift" -o "$TEST_ROOT/initialization-tests"
"$TEST_ROOT/initialization-tests"
xcrun swiftc -swift-version 5 -parse-as-library -D UI_REVIEW -target "arm64-apple-macosx$CW_MACOS_MINIMUM" \
  -module-cache-path "$TEST_ROOT/cache" -framework SwiftUI -framework AppKit -framework WebKit \
  "$ROOT"/Sources/*.swift "$ROOT/tests/InitializationStabilityTests.swift" -o "$TEST_ROOT/initialization-stability-tests"
"$TEST_ROOT/initialization-stability-tests"
