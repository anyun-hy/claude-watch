#!/bin/bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
CW_TEST_PARENT=$(mktemp -d /private/tmp/cw-leak-diagnostic-test.XXXXXX)
trap 'rm -rf "$CW_TEST_PARENT"' EXIT
CW_MACOS_MINIMUM=$(/bin/cat "$ROOT/macos-minimum.txt")
xcrun swiftc -swift-version 5 -parse-as-library -target "arm64-apple-macosx$CW_MACOS_MINIMUM" \
  -module-cache-path "$CW_TEST_PARENT/module-cache" \
  "$ROOT/Sources/IdentityPresentation.swift" "$ROOT/Sources/BundledBackendVariant.swift" \
  "$ROOT/Sources/LeakCheckModels.swift" "$ROOT/Sources/EventDiagnostics.swift" \
  "$ROOT/tests/LeakDiagnosticTraceTests.swift" -o "$CW_TEST_PARENT/leak-diagnostic-tests"
"$CW_TEST_PARENT/leak-diagnostic-tests"
