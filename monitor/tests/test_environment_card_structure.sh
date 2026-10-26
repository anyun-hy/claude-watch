#!/bin/bash
# Guards the compact-card contract: source failures appear once in the page
# notice, while row-specific diagnostics remain available only in hover details.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
PAGE="$ROOT/Sources/SwitcherPage.swift"

[[ $(rg -F 'InlineNotice(title: "数据源状态"' "$PAGE" | wc -l | tr -d ' ') == 1 ]]
[[ $(rg -F 'Text("本次查询失败："' "$PAGE" | wc -l | tr -d ' ') == 0 ]]
[[ $(rg -F 'detail("本次查询失败", error)' "$PAGE" | wc -l | tr -d ' ') == 1 ]]
[[ $(rg -F 'IP 注册地（Net.Coffee）' "$PAGE" | wc -l | tr -d ' ') == 1 ]]
[[ $(rg -F '注册地（来源 Net.Coffee）' "$PAGE" | wc -l | tr -d ' ') == 0 ]]
printf 'Environment card structure: source notice once; query error details-only\n'
