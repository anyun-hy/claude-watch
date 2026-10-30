#!/bin/bash
# Local verification only. Never installs toolchains or starts an application/service.
set -euo pipefail
CW_RUST_ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$CW_RUST_ROOT"
if command -v cargo >/dev/null 2>&1; then
  CW_CARGO_BIN=$(command -v cargo)
elif [[ -x "$HOME/.cargo/bin/cargo" ]]; then
  CW_CARGO_BIN="$HOME/.cargo/bin/cargo"
else
  printf '%s\n' 'Rust 工具链未找到；本脚本不会自动安装软件。' >&2
  exit 2
fi
[[ -f Cargo.lock ]] || { printf '%s\n' '缺少 Cargo.lock，请先明确解析并锁定依赖。' >&2; exit 2; }
"$CW_CARGO_BIN" fmt --all -- --check
"$CW_CARGO_BIN" test --workspace --locked
"$CW_CARGO_BIN" clippy --workspace --all-targets --locked -- -D warnings
"$CW_CARGO_BIN" build --release --locked --workspace
PYTHONDONTWRITEBYTECODE=1 python3 tools/rust_shadow.py "$@"
