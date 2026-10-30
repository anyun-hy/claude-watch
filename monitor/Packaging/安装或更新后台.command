#!/bin/bash
# User-triggered installer. It never runs until this command is opened manually.
set -euo pipefail
PATH='/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'

PRODUCT_NAME='Claude Watch'
APP_NAME='Claude Watch Monitor.app'
AGENT_LABEL='io.local.claudewatch.agent'

say() { printf '\n[%s] %s\n' "$PRODUCT_NAME" "$*"; }
fail() { printf '\n[%s] 错误：%s\n' "$PRODUCT_NAME" "$*" >&2; exit 1; }

COMMAND_DIR=$(cd "$(dirname "$0")" && pwd -P)
DMG_APP="$COMMAND_DIR/$APP_NAME"
APPLICATIONS_APP="/Applications/$APP_NAME"
MANIFEST="$DMG_APP/Contents/Resources/BuildInfo.plist"

[[ -d "$DMG_APP" ]] || fail "未找到同一磁盘映像中的 ${APP_NAME}。"
[[ -f "$MANIFEST" ]] || fail '安装包缺少版本清单。'

plist_value() {
  /usr/libexec/PlistBuddy -c "Print :$1" "$MANIFEST" 2>/dev/null
}

EXPECTED_PRODUCT_VERSION=$(plist_value ProductVersion) || fail '无法读取产品版本。'
BACKEND_VARIANT=$(plist_value BackendVariant 2>/dev/null || printf stable)
if [[ "$BACKEND_VARIANT" == 'rust-candidate' ]]; then
  ENGINE="$DMG_APP/Contents/Resources/watch-engine"
  [[ -f "$ENGINE" && -x "$ENGINE" && ! -L "$ENGINE" ]] || fail '缺少原生安装组件。'
  /usr/bin/codesign --verify --deep --strict "$DMG_APP" || fail '应用签名校验失败。'
  "$ENGINE" app-install --source "$DMG_APP"
  say "将安装产品 ${EXPECTED_PRODUCT_VERSION} 并更新自有后台。"
  printf '%s\n' '旧应用移入废纸篓，清理本工具旧辅助功能授权；保留账号、登录、代理和保护设置。'
  printf '%s' '输入“安装”并按回车以继续： '
  IFS= read -r ANSWER
  [[ "$ANSWER" == '安装' ]] || { say '已取消，未改变任何内容。'; exit 0; }
  exec "$ENGINE" app-install --source "$DMG_APP" --apply
fi
[[ "$BACKEND_VARIANT" == 'stable' ]] || fail '未知后台类型，未执行安装。'
EXPECTED_BACKEND_VERSION=$(plist_value BackendVersion) || fail '无法读取后台脚本版本。'
EXPECTED_BACKEND_SHA=$(plist_value BackendSHA256) || fail '无法读取后台脚本校验值。'

if ! PYTHON3=$(command -v python3); then
  fail '未找到 Python 3；请先提供 Python 3，再运行后台安装命令。'
fi
if ! "$PYTHON3" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
  fail '需要 Python 3.9 或更高版本。'
fi

backend_version() {
  /usr/bin/sed -n "s/^VERSION=['\"]\\([^'\"]*\\)['\"].*/\\1/p" "$1" | /usr/bin/head -n 1
}

valid_app_script() {
  local app_path=$1 script actual_version actual_sha
  script="$app_path/Contents/Resources/claude-watch.sh"
  [[ -f "$script" && ! -L "$script" ]] || return 1
  actual_version=$(backend_version "$script")
  actual_sha=$(/usr/bin/shasum -a 256 "$script" | /usr/bin/awk '{print $1}')
  [[ "$actual_version" == "$EXPECTED_BACKEND_VERSION" && "$actual_sha" == "$EXPECTED_BACKEND_SHA" ]] || return 1
  "$PYTHON3" - "$app_path/Contents/Resources" "$MANIFEST" <<'PY'
from pathlib import Path
import hashlib, plistlib, sys
root, manifest = map(Path, sys.argv[1:])
value = plistlib.loads(manifest.read_bytes())
if value.get("SwitcherSchema") is None:
    # Legacy packages remain installable; new packages declare all runtime files.
    raise SystemExit(0)
hashes = value.get("RuntimeHashes")
if value.get("SwitcherSchema") != 1 or not isinstance(hashes, dict) or not hashes:
    raise SystemExit(1)
required = {"switcher.py", "watch-admin.sh", "watch-process-control", "dns_probe.py", "netcoffee_client.py"}
required |= {"watch_switcher/" + name + ".py" for name in
             ("__init__", "common", "accounts", "audit", "system", "repair", "rules", "services", "stun", "update", "diagnostics", "onboarding", "region", "automatic_policy", "session_guard", "upstream_accounts", "dns_refresh")}
required |= {"ThirdParty/ClaudeSwitcher/UPSTREAM.json", "ThirdParty/ClaudeSwitcher/upstream/core/claude-switch.sh"}
if not required <= set(hashes):
    raise SystemExit(1)
for name, expected in hashes.items():
    rel = Path(name)
    if rel.is_absolute() or ".." in rel.parts:
        raise SystemExit(1)
    path = root / rel
    if not path.is_file() or any(p.is_symlink() for p in (path, *path.parents)):
        raise SystemExit(1)
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit(1)
PY
}

if valid_app_script "$APPLICATIONS_APP"; then
  SELECTED_APP="$APPLICATIONS_APP"
  say "已验证 Applications 中的 ${APP_NAME}（产品 ${EXPECTED_PRODUCT_VERSION}，后台 ${EXPECTED_BACKEND_VERSION}）。"
elif valid_app_script "$DMG_APP"; then
  SELECTED_APP="$DMG_APP"
  say "Applications 中未找到匹配版本，改用当前磁盘映像内已验证的脚本。"
else
  fail '应用内后台脚本版本或校验值不匹配；请重新下载完整 DMG。'
fi

BACKEND_SCRIPT="$SELECTED_APP/Contents/Resources/claude-watch.sh"
say "将替换应用并更新 ${AGENT_LABEL}。"
printf '%s\n' '旧应用移入废纸篓，清理本工具旧辅助功能授权；新版首次打开时重新请求。保留账号、日志、会话基准与保护设置。'
printf '%s\n' '不会启动 Claude、Codex 或 ChatGPT，也不会修改 TAG 配置。'
printf '%s' '输入“安装”并按回车以继续： '
IFS= read -r ANSWER
[[ "$ANSWER" == '安装' ]] || { say '已取消，未改变任何内容。'; exit 0; }

exec "$PYTHON3" "$COMMAND_DIR/app_lifecycle.py" install --source "$DMG_APP"
