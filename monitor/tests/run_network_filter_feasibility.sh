#!/bin/bash
# Compile-only NetworkExtension surface check. It never invokes NEFilterManager,
# activates a system extension, changes network settings, or observes traffic.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
CW_MACOS_MINIMUM=$(/bin/cat "$ROOT/macos-minimum.txt")
TEST_DIR=$(mktemp -d /private/tmp/claude-watch-network-filter.XXXXXX)
cleanup() { rm -rf "$TEST_DIR"; }
trap cleanup EXIT

SWIFTC=$(xcrun --find swiftc)
SDK=$(xcrun --sdk macosx --show-sdk-path)
"$SWIFTC" -swift-version 5 -parse-as-library -target "arm64-apple-macosx$CW_MACOS_MINIMUM" \
  -sdk "$SDK" -module-cache-path "$TEST_DIR/module-cache" -framework NetworkExtension \
  "$ROOT/tests/NetworkFilterFeasibility.swift" \
  -o "$TEST_DIR/network-filter-feasibility"

"$TEST_DIR/network-filter-feasibility"
printf '%s\n' 'No system extension, filter configuration, network setting, or process action was performed.'
