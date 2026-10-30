#!/bin/bash
# Render offscreen SwiftUI fixtures; no installed app, permission or network actions.
set -euo pipefail
[[ $# == 1 && -d "$1" ]] || { printf 'Usage: %s EXISTING_OUTPUT_DIRECTORY\n' "$0" >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/private/tmp}/cw-initialization-preview.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT
xcrun swiftc -swift-version 5 -parse-as-library -D UI_REVIEW -target arm64-apple-macosx14.0 \
  -module-cache-path "$TEST_ROOT/cache" -framework SwiftUI -framework AppKit -framework WebKit \
  "$ROOT"/Sources/*.swift "$ROOT/tests/InitializationPreview.swift" -o "$TEST_ROOT/initialization-preview"
"$TEST_ROOT/initialization-preview" "$1"
