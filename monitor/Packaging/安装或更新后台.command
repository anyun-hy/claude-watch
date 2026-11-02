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
# The Python backend is retired: a package that declares any other backend is
# an old download, not an install target.
BACKEND_VARIANT=$(plist_value BackendVariant) || fail '安装包未声明后台类型。'
[[ "$BACKEND_VARIANT" == 'rust-candidate' ]] || fail '该安装包使用已退役的后台类型，请下载新版。'
ENGINE="$DMG_APP/Contents/Resources/watch-engine"
[[ -f "$ENGINE" && -x "$ENGINE" && ! -L "$ENGINE" ]] || fail '缺少原生安装组件。'
/usr/bin/codesign --verify --deep --strict "$DMG_APP" || fail '应用签名校验失败。'
"$ENGINE" app-install --source "$DMG_APP"
say "将安装产品 ${EXPECTED_PRODUCT_VERSION} 并更新 ${AGENT_LABEL}。"
printf '%s\n' '旧应用移入废纸篓，清理本工具旧辅助功能授权；新版首次打开时重新请求。保留账号、日志、会话基准与保护设置。'
printf '%s\n' '不会启动 Claude、Codex 或 ChatGPT，也不会修改 TAG 配置。'
printf '%s' '输入“安装”并按回车以继续： '
IFS= read -r ANSWER
[[ "$ANSWER" == '安装' ]] || { say '已取消，未改变任何内容。'; exit 0; }
exec "$ENGINE" app-install --source "$DMG_APP" --apply
