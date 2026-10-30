#!/bin/bash
# All probes/permissions/mutations are fixtures. No application is installed.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/private/tmp}/cw-initialization.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT
xcrun swiftc -swift-version 5 -parse-as-library -D UI_REVIEW -target arm64-apple-macosx14.0 \
  -module-cache-path "$TEST_ROOT/cache" -framework SwiftUI -framework AppKit -framework WebKit \
  "$ROOT"/Sources/*.swift "$ROOT/tests/InitializationTests.swift" -o "$TEST_ROOT/initialization-tests"
"$TEST_ROOT/initialization-tests"
