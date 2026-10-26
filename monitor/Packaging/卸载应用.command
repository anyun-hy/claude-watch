#!/bin/bash
set -euo pipefail
CW_PACKAGE_DIR=$(cd "$(dirname "$0")" && pwd -P)
printf '%s\n' '将 Claude Watch 应用和自有后台任务移入废纸篓，清理其辅助功能授权。保留账号 A/B、Claude 登录、工具配置、原版保镖和时区守护。'
printf '%s' '输入“卸载”继续：'
IFS= read -r CW_ANSWER
[[ "$CW_ANSWER" == '卸载' ]] || exit 0
exec /usr/bin/env python3 "$CW_PACKAGE_DIR/app_lifecycle.py" uninstall
