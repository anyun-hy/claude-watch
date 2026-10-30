#!/bin/bash
set -euo pipefail
CW_PACKAGE_DIR=$(cd "$(dirname "$0")" && pwd -P)
CW_PACKAGE_APP="$CW_PACKAGE_DIR/Claude Watch Monitor.app"
CW_VARIANT=$(/usr/libexec/PlistBuddy -c 'Print :BackendVariant' "$CW_PACKAGE_APP/Contents/Resources/BuildInfo.plist" 2>/dev/null || printf stable)
printf '%s\n' '将 Claude Watch 应用和自有后台任务移入废纸篓，清理其辅助功能授权。保留账号 A/B、Claude 登录、工具配置、原版保镖和时区守护。'
printf '%s' '输入“卸载”继续：'
IFS= read -r CW_ANSWER
[[ "$CW_ANSWER" == '卸载' ]] || exit 0
if [[ "$CW_VARIANT" == 'rust-candidate' ]]; then
  /usr/bin/codesign --verify --deep --strict "$CW_PACKAGE_APP"
  exec "$CW_PACKAGE_APP/Contents/Resources/watch-engine" app-uninstall --apply
fi
[[ "$CW_VARIANT" == 'stable' ]] || { printf '%s\n' '未知后台类型，未执行卸载。' >&2; exit 1; }
exec /usr/bin/env python3 "$CW_PACKAGE_DIR/app_lifecycle.py" uninstall
