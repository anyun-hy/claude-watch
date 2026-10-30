#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
TEST_ROOT=$(mktemp -d /private/tmp/cw-observer-identity.XXXXXX)
trap 'rm -rf "$TEST_ROOT"' EXIT
cat "$ROOT/crates/watch-runtime/native/Observer.swift" "$ROOT/monitor/tests/ObserverIdentityTests.swift" > "$TEST_ROOT/ObserverTests.swift"
CW_MACOS_MINIMUM=$(/bin/cat "$ROOT/monitor/macos-minimum.txt")
xcrun swiftc -swift-version 5 -parse-as-library -D OBSERVER_TESTING -target "arm64-apple-macosx$CW_MACOS_MINIMUM" \
  -module-cache-path "$TEST_ROOT/cache" "$TEST_ROOT/ObserverTests.swift" -o "$TEST_ROOT/observer-tests"
"$TEST_ROOT/observer-tests"
