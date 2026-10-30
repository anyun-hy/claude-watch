#!/bin/bash
# Claude Watch — controlled launches, network observations and idle guarding.
# Detection only: no packet filtering or read() interception.
# 兼容 macOS 系统 Bash 3.2；不需要 sudo。

set -eo pipefail
umask 077
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin:${PATH:-}"
export LC_ALL=C

VERSION='2.8.4'
LABEL='io.local.claudewatch.agent'
CURRENT_UID=$(id -u)
DOMAIN="gui/$CURRENT_UID"
BASE_DIR="$HOME/Library/Application Support/ClaudeWatch"
STATE_DIR="$BASE_DIR/state"
MODE_FILE="$STATE_DIR/mode"
BASELINE_FILE="$STATE_DIR/baseline.conf"
SESSION_DIR="$STATE_DIR/sessions"
HEARTBEAT_FILE="$STATE_DIR/heartbeat"
TRACKED_FILE="$STATE_DIR/tracked"
PENDING_FILE="$STATE_DIR/desktop-pending"
INSTALLED_SCRIPT="$BASE_DIR/claude-watch.sh"
LAUNCH_AGENTS="$HOME/Library/LaunchAgents"
PLIST_FILE="$LAUNCH_AGENTS/$LABEL.plist"
LOG_DIR="$HOME/Library/Logs/ClaudeWatch"
EVENT_LOG="$LOG_DIR/events.log"
ERROR_LOG="$LOG_DIR/agent.stderr.log"
POLL_SECONDS=2
NETWORK_SECONDS=10
HEALTH_MAX_AGE=30
TMP_SCAN=''

SCAN_DESKTOP=0
SCAN_CODE=0
SCAN_DESKTOP_PID=''
SCAN_CODE_PID=''
SCAN_DESKTOP_COUNT=0
SCAN_CODE_COUNT=0
SCAN_CODEX_DESKTOP_COUNT=0
SCAN_CODEX_CLI_COUNT=0
SCAN_CHATGPT_DESKTOP_COUNT=0
SCAN_OPENAI_DESKTOP_COUNT=0
SCAN_UNKNOWN_COUNT=0
CLASS=''
COMM=''
START=''
WARNINGS=0; CRITICAL=0; MONITOR_MODE='GUARD'
ACTIVE_PIDS=''; UNAUTHORIZED_PIDS=''; SCAN_INCOMPLETE=0
CURRENT_FINGERPRINT=''; HEALTH='STOPPED'; HEALTH_REASON='未加载'
LAST_TAG_ALERT=''
ALERT_COOLDOWN_FILE="$STATE_DIR/alert-cooldowns"

say()  { printf '[Claude Watch] %s\n' "$*"; }
fail() { printf '[Claude Watch] 错误：%s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'HELP'
Claude Watch 2.7 — macOS / Bash 3.2 + Python 3（TAG 与可选账号保护）

  install / uninstall              安装并启动 / 卸载，保留基线和历史日志
  baseline [--online]              明确保存当前可信环境；在线选项包含后续预检
  preflight [--online]             只读预检：0=通过，3=变化/未知，4=拒绝
  snapshot [--online]              显示 IP、DNS、路由和脱敏代理，无需安装
  proxy-check                     核对 7890 监听者及受监控应用的 TAG 实际代理链
  diagnose-proxy --proxy URL|--config FILE|--stdin-config
                                  独立 HTTP/SOCKS 传输诊断，不创建账号状态或授予启动许可
  dns-check [--online] [--browser-report FILE ...] [--expected-resolvers IP,IP]
                                   对比递归出口和浏览器网站报告（只读）
  launch-desktop [--allow-changes]  预检及健康检查后启动桌面端
  launch-cli [--allow-changes] [--] [Claude 参数...]
                                   预检后登记独立 CLI 会话
  launch-codex [--allow-changes]  预检后启动 Codex 桌面端或共享 OpenAI 外壳
  launch-codex-cli [--allow-changes] [--] [Codex 参数...]
                                   预检后登记独立 Codex CLI 会话
  launch-chatgpt [--allow-changes] 预检后启动 ChatGPT 桌面端或共享 OpenAI 外壳
  status / audit / logs            健康状态 / 连接和文件描述符 / 本地日志
  arm                             撤销会话授权并恢复通知，不结束 Claude
  pause / snooze MINUTES           仅静默通知，继续采样，不授予权限
  test-alert / help
  switcher <command>              环境检查、账号、修复与更新（默认仅预览）
  account status|switch A|B        账号操作；写入须显式传 --apply
  checkdetail [--online]           统一 14 项检查，JSON 输出
  fix / set-region                生成修复或地区适配预览
  update                          查询自有签名发布源；--apply 才应用

说明：
  --online 访问 api.ipify.org、www.cloudflare.com/cdn-cgi/trace 和
  whoami.ds.akahelp.net（Akamai）。默认离线，不绕过已有代理设置。
  公网 IP 是探测进程的出口；浏览器报告只代表该浏览器当时的 DNS 路径。
  DNS 配置、递归出口与浏览器结果分开显示，未设置预期解析器时不判定无泄漏。
  网站：https://browserleaks.com/dns 和 https://www.dnsleaktest.com/
  报告格式与限制见 README.md；不自动操作浏览器或修改 Claude 设置。
  默认每 2 秒扫描进程、每 10 秒采样连接；不拦截启动、文件读取或网络包。
  直接从 Dock/普通终端启动不经过预检，独立 CLI 后台服务不自动授权。
  监控范围：Claude Desktop/Code、Codex Desktop/CLI、ChatGPT Mac 桌面端；
  浏览器中的 ChatGPT 不在本版本的进程归属范围内。
HELP
}

require_macos() {
  [[ "$(uname -s)" == 'Darwin' ]] || fail '只支持 macOS，未修改系统。'
  [[ "$CURRENT_UID" -ne 0 ]] || fail '请以普通登录用户运行，不要使用 sudo。'
}

init_dirs() {
  local dir
  for dir in "$BASE_DIR" "$STATE_DIR" "$SESSION_DIR" "$LOG_DIR"; do
    [[ ! -L "$dir" ]] || fail '拒绝通过符号链接写入状态目录。'
  done
  mkdir -p "$BASE_DIR" "$STATE_DIR" "$SESSION_DIR" "$LAUNCH_AGENTS" "$LOG_DIR" || fail '无法创建应用目录。'
  chmod 700 "$BASE_DIR" "$STATE_DIR" "$SESSION_DIR" "$LOG_DIR" || fail '无法设置应用目录权限。'
}

log_event() {
  # 保存事件、进程身份、网络端点及分类；不保存凭据、命令行或文件内容。
  [[ -d "$LOG_DIR" ]] || return 0
  if [[ -f "$EVENT_LOG" ]]; then
    local bytes
    bytes=$(wc -c < "$EVENT_LOG" 2>/dev/null) || bytes=0
    if [[ "$bytes" -gt 1048576 ]]; then
      mv -f "$EVENT_LOG" "$EVENT_LOG.1" 2>/dev/null || true
    fi
  fi
  printf '%s\t%s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$*" >> "$EVENT_LOG" 2>/dev/null || true
}

write_mode() {
  local value=$1 temp
  [[ -d "$STATE_DIR" ]] || fail '尚未安装。请先执行 install。'
  temp=$(mktemp "$STATE_DIR/.mode.XXXXXXXX") || fail '无法创建安全状态文件。'
  printf '%s\n' "$value" > "$temp"
  chmod 600 "$temp"
  mv -f "$temp" "$MODE_FILE"
}

read_mode() {
  local value='armed'
  if [[ -f "$MODE_FILE" ]]; then
    IFS= read -r value < "$MODE_FILE" || true
  fi
  case "$value" in
    armed|armed:*|paused|until:*) printf '%s\n' "$value" ;;
    *) printf 'invalid\n' ;;
  esac
}

require_installed() {
  [[ -f "$PLIST_FILE" && -f "$INSTALLED_SCRIPT" ]] || fail '尚未安装。请先执行 install。'
}

switcher_source_dir() {
  local here candidate
  here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
  for candidate in "$here/runtime" "$here" "$here/monitor/Resources"; do
    if [[ -f "$candidate/switcher.py" && -d "$candidate/watch_switcher" ]]; then
      printf '%s\n' "$candidate"; return 0
    fi
  done
  return 1
}
switcher_run() {
  local resources python
  resources=$(switcher_source_dir) || { say '缺少完整账号/环境运行组件，请更新后台安装包。' >&2; return 4; }
  python=$(command -v python3) || return 4
  PYTHONDONTWRITEBYTECODE=1 "$python" "$resources/switcher.py" "$@"
}
switcher_enabled() {
  # A fresh install uses the validated automatic defaults; a saved file is not
  # a prerequisite for protection. Explicitly saved disabled remains disabled.
  switcher_run config enabled >/dev/null 2>&1
}
switcher_install_runtime() {
  local source stage destination old resource
  source=$(switcher_source_dir) || return 0
  destination="$BASE_DIR/runtime"
  [[ "$source" != "$destination" ]] || return 0
  [[ ! -L "$destination" ]] || fail '运行组件路径为符号链接'
  stage=$(mktemp -d "$BASE_DIR/.runtime.XXXXXXXX")
  old="$BASE_DIR/.runtime.previous"
  [[ ! -e "$old" && ! -L "$old" ]] || fail '发现未处理的组件更新目录'
  cp -R "$source/watch_switcher" "$stage/"
  for resource in switcher.py watch-admin.sh watch-process-control dns_probe.py netcoffee_client.py; do
    if [[ ! -f "$source/$resource" ]]; then rm -rf "$stage"; fail "缺少运行组件：$resource"; fi
    cp "$source/$resource" "$stage/"
  done
  if [[ -d "$source/ThirdParty/ClaudeSwitcher" ]]; then
    mkdir -p "$stage/ThirdParty"
    cp -R "$source/ThirdParty/ClaudeSwitcher" "$stage/ThirdParty/"
  fi
  chmod -R go-rwx "$stage"
  chmod 700 "$stage/watch-process-control" "$stage/watch-admin.sh"
  [[ ! -d "$destination" ]] || mv "$destination" "$old"
  if ! mv "$stage" "$destination"; then
    [[ ! -d "$old" ]] || mv "$old" "$destination"
    fail '运行组件更新失败，已尝试恢复原目录'
  fi
  [[ ! -d "$old" ]] || rm -rf "$old"
}

xml_escape() {
  # 仅用于 plist 中固定路径的 XML 字符转义。
  local s=$1
  s=${s//&/\&amp;}
  s=${s//</\&lt;}
  s=${s//>/\&gt;}
  s=${s//\"/\&quot;}
  s=${s//\'/\&apos;}
  printf '%s' "$s"
}

install_agent() {
  require_macos
  init_dirs
  if [[ -L "$INSTALLED_SCRIPT" || -L "$PLIST_FILE" ]]; then
    fail '检测到安装目标是符号链接，出于安全考虑停止安装。'
  fi
  if [[ ! -f "$MODE_FILE" ]]; then
    write_mode 'armed'
  fi

  local source_file escaped_script escaped_err
  source_file=$(cd "$(dirname "$0")" && pwd -P)/$(basename "$0")
  if [[ "$source_file" != "$INSTALLED_SCRIPT" ]]; then
    cp "$source_file" "$INSTALLED_SCRIPT" || fail '复制监控脚本失败。'
  fi
  chmod 700 "$INSTALLED_SCRIPT"
  switcher_install_runtime

  escaped_script=$(xml_escape "$INSTALLED_SCRIPT")
  escaped_err=$(xml_escape "$ERROR_LOG")
  cat > "$PLIST_FILE" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$escaped_script</string>
    <string>daemon</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>15</integer>
  <key>StandardErrorPath</key><string>$escaped_err</string>
</dict>
</plist>
PLIST
  chmod 600 "$PLIST_FILE"
  if ! plutil -lint "$PLIST_FILE" >/dev/null 2>&1; then
    fail 'LaunchAgent plist 验证失败，未加载后台任务。'
  fi
  # 更新安装时先退出已存在的同名 Agent，再重新加载。
  if launchctl print "$DOMAIN/$LABEL" >/dev/null 2>&1; then
    launchctl bootout "$DOMAIN/$LABEL" || fail '无法停止旧后台任务。'
  fi
  launchctl enable "$DOMAIN/$LABEL" >/dev/null 2>&1 || true
  if ! launchctl bootstrap "$DOMAIN" "$PLIST_FILE"; then
    fail '安装文件已写入，但后台任务加载失败。请确认是在当前 macOS 图形桌面登录会话内运行。'
  fi
  log_event 'install'
  say '安装文件已写入，已向 launchd 提交启动。默认警戒。'
  say '请核实后台心跳；会话 IP 基准会在“检查并启动 Claude”完整校验通过后自动建立。'
}

uninstall_agent() {
  require_macos
  # 只处理自己固定的 LaunchAgent，不影响任何 Claude 服务。
  if launchctl print "$DOMAIN/$LABEL" >/dev/null 2>&1; then
    if ! launchctl bootout "$DOMAIN/$LABEL"; then
      fail '后台任务停止失败：不会删除脚本，以免产生失控后台任务。'
    fi
  fi
  log_event 'uninstall'
  if [[ -f "$BASE_DIR/runtime/switcher.py" ]]; then
    switcher_run uninstall --apply || fail '新增组件尚未完全卸载，安装文件保留供恢复'
  fi
  rm -f "$PLIST_FILE" "$INSTALLED_SCRIPT" "$MODE_FILE" "$HEARTBEAT_FILE" "$TRACKED_FILE" "$PENDING_FILE"
  rm -f "$SESSION_DIR"/*.session
  rmdir "$SESSION_DIR" 2>/dev/null || true
  rmdir "$STATE_DIR" 2>/dev/null || true
  rmdir "$BASE_DIR" 2>/dev/null || true
  say '已卸载监控任务；基线和历史日志保留。日志目录：'
  say "  $LOG_DIR"
}

arm_agent() {
  require_macos
  require_installed
  # 每次 arm 使用不同会话标记，以便重新发现警戒开启时已存在的进程。
  write_mode "armed:$(date +%s):$$"
  rm -f "$SESSION_DIR"/*.session "$PENDING_FILE"
  log_event 'arm'
  say '已撤销会话授权并恢复通知；现有 Claude 进程不会被自动结束。'
}

pause_agent() {
  require_macos
  require_installed
  write_mode 'paused'
  log_event 'pause'
  say '已静默通知；进程、网络和文件描述符仍持续采样，不会授予使用授权。'
}

snooze_agent() {
  require_macos
  require_installed
  local minutes=$1 until
  [[ "$minutes" =~ ^[0-9]{1,4}$ ]] || fail '暂停时间须为 1–1440 分钟的整数。'
  minutes=$((10#$minutes))
  [[ "$minutes" -ge 1 && "$minutes" -le 1440 ]] || fail '暂停时间须为 1–1440 分钟。'
  until=$(( $(date +%s) + minutes * 60 ))
  write_mode "until:$until"
  log_event "snooze minutes=$minutes"
  say "已静默通知 ${minutes} 分钟；采样继续，到期恢复通知。"
}

trim() {
  TRIMMED=$1
  TRIMMED="${TRIMMED#"${TRIMMED%%[![:space:]]*}"}"
  TRIMMED="${TRIMMED%"${TRIMMED##*[![:space:]]}"}"
}

hash_text() { shasum -a 256 | awk '{print $1}'; }
kv_get() {
  [[ -f "$1" && ! -L "$1" ]] || return 0
  awk -v k="$2" 'index($0,k "=")==1 {print substr($0,length(k)+2);exit}' "$1"
}
atomic_text() {
  local dest=$1 value=$2 temp
  [[ ! -L "$dest" ]] || return 1
  temp=$(mktemp "${dest}.XXXXXXXX") || return 1
  printf '%s\n' "$value" > "$temp"
  chmod 600 "$temp"
  mv -f "$temp" "$dest"
}
normalize_stamp() { awk '{$1=$1;print}'; }
process_stamp() { ps -p "$1" -o lstart= 2>/dev/null | normalize_stamp; }
valid_ip() {
  # Strict IPv4 and hexadecimal IPv6; no hostnames, whitespace or shell syntax.
  awk -v ip="$1" 'BEGIN {
    if (ip ~ /^[0-9.]+$/) {
      n=split(ip,a,"."); if(n!=4) exit 1;
      for(i=1;i<=4;i++) if(a[i]=="" || length(a[i])>3 || a[i]+0>255 || (length(a[i])>1 && substr(a[i],1,1)=="0")) exit 1;
      exit 0;
    }
    if(ip !~ /^[0-9A-Fa-f:]+$/ || index(ip,":")==0 || index(ip,":::")>0) exit 1;
    t=ip; dc=gsub(/::/,"@",t); if(dc>1) exit 1;
    if(dc==0 && (substr(ip,1,1)==":" || substr(ip,length(ip))==":")) exit 1;
    n=split(ip,a,":"); count=0;
    for(i=1;i<=n;i++) if(a[i]!="") {if(length(a[i])>4) exit 1;count++}
    if((dc==0 && count==8) || (dc==1 && count<8)) exit 0;
    exit 1;
  }'
}
public_ip_valid() {
  valid_ip "$1" || return 1
  case "$1" in
    *:*) case "$1" in 2001:db8:*|2001:DB8:*) return 1;; [23]*:*) return 0;; *) return 1;; esac ;;
    *) awk -F. '($1==0 || $1==10 || $1==127 || $1>=224 || ($1==169 && $2==254) || ($1==172 && $2>=16 && $2<=31) || ($1==192 && ($2==168 || ($2==0 && ($3==0 || $3==2)))) || ($1==100 && $2>=64 && $2<=127) || ($1==198 && ($2==18 || $2==19 || ($2==51 && $3==100))) || ($1==203 && $2==0 && $3==113)) {exit 1}' <<< "$1" ;;
  esac
}
csv_ips_valid() {
  local ip oldifs=$IFS
  [[ -n "$1" ]] || return 1
  case "$1" in ,*|*,|*,,*) return 1;; esac
  IFS=,; set -- $1; IFS=$oldifs
  for ip in "$@"; do valid_ip "$ip" || return 1; done
}
get_timezone() {
  local tz
  tz=$(readlink /etc/localtime 2>/dev/null || true)
  case "$tz" in *zoneinfo/*) printf '%s\n' "${tz##*zoneinfo/}";; *) printf 'unavailable\n';; esac
}
route_query() {
  if [[ "$1" == 6 ]]; then /sbin/route -n get -inet6 default; else /sbin/route -n get default; fi
}
route_snapshot() {
  local out rc=0
  out=$(route_query "$1" 2>&1) || rc=$?
  # macOS route can report "not in table" while returning zero.
  if printf '%s' "$out" | grep -Eqi 'not in table|no route|not found'; then printf 'absent\n'; return; fi
  if [[ "$rc" != 0 ]]; then printf 'unavailable\n'; return; fi
  printf '%s\n' "$out" | awk '/^[[:space:]]*interface:/ {i=$2} /^[[:space:]]*gateway:/ {g=$2} END {if(i!="") print i " gateway=" g; else print "unavailable"}'
}
redact_proxy() {
  # Never display URL credentials, query strings, PAC content or private NO_PROXY entries.
  local proxy=$1 scheme authority
  [[ -n "$proxy" ]] || { printf 'none'; return; }
  scheme=${proxy%%://*}; authority=${proxy#*://}; authority=${authority%%/*}; authority=${authority%%\?*}; authority=${authority%%\#*}; authority=${authority##*@}
  case "$scheme" in http|https|socks|socks4|socks5|socks5h) printf '%s://%s' "$scheme" "$authority" | tr -cd '[:alnum:].:\[\]/_%-';; *) printf '[configured; unrecognized format]';; esac
}
settings_proxy_values() {
  local settings key val
  for settings in "$HOME/.claude/settings.json" '/Library/Application Support/ClaudeCode/managed-settings.json'; do
    [[ -f "$settings" ]] || continue
    if ! plutil -lint "$settings" >/dev/null 2>&1; then printf 'invalid-json\n'; continue; fi
    for key in https_proxy HTTPS_PROXY http_proxy HTTP_PROXY NO_PROXY no_proxy; do
      if val=$(plutil -extract "env.${key}" raw -expect string -o - "$settings" 2>/dev/null); then
        [[ -z "$val" ]] || printf '%s:%s=%s\n' "${settings##*/}" "$key" "$val"
      fi
    done
  done
}
collect_environment() {
  local dns proxy settings
  CURRENT_TZ=$(get_timezone)
  CURRENT_V4=$(route_snapshot 4); CURRENT_V6=$(route_snapshot 6)
  dns=$(scutil --dns 2>/dev/null) || dns=''
  CURRENT_DNS=$(printf '%s\n' "$dns" | awk '/nameserver\[[0-9]+\]/ {print $3}' | sort -u | paste -sd, -)
  [[ -n "$CURRENT_DNS" ]] || CURRENT_DNS=unavailable
  CURRENT_DNS_SIG=$(printf '%s\n' "$dns" | awk '/resolver #|domain|nameserver\[|if_index|flags/ {print}' | hash_text)
  proxy=$(scutil --proxy 2>/dev/null) || proxy=''
  CURRENT_SYS_PROXY_SIG=$(printf '%s' "$proxy" | hash_text)
  CURRENT_SYS_PROXY=$(printf '%s\n' "$proxy" | awk '$1 ~ /^(HTTPEnable|HTTPSEnable|SOCKSEnable|HTTPProxy|HTTPSProxy|SOCKSProxy|HTTPPort|HTTPSPort|SOCKSPort|ProxyAutoConfigEnable)$/ {v=$3;sub(/^.*@/,"",v);gsub(/[^[:alnum:].:_-]/,"",v);print $1 "=" v}' | paste -sd, -)
  [[ -n "$CURRENT_SYS_PROXY" ]] || CURRENT_SYS_PROXY=unavailable
  CURRENT_CLI_PROXY=$(redact_proxy "${https_proxy:-${HTTPS_PROXY:-${http_proxy:-${HTTP_PROXY:-}}}}")
  CURRENT_CLI_PROXY_SIG=$(printf '%s\0' "${https_proxy:-}" "${HTTPS_PROXY:-}" "${http_proxy:-}" "${HTTP_PROXY:-}" "${NO_PROXY:-}" "${no_proxy:-}" "${ALL_PROXY:-}" "${all_proxy:-}" | hash_text)
  settings=$(settings_proxy_values)
  CURRENT_SETTINGS_SIG=$(printf '%s' "$settings" | hash_text)
  CURRENT_SETTINGS_PROXY=none
  [[ -z "$settings" ]] || CURRENT_SETTINGS_PROXY='configured; effective per-session proxy must be verified'
  [[ "$settings" != *invalid-json* ]] || CURRENT_SETTINGS_PROXY='unreadable-json'
  CURRENT_FINGERPRINT=$(printf '%s\n' "$CURRENT_TZ" "$CURRENT_V4" "$CURRENT_V6" "$CURRENT_DNS_SIG" "$CURRENT_SYS_PROXY_SIG" | hash_text)
}
online_probe() {
  local trace v6 txt rc=0
  PUBLIC_V4=unavailable; PUBLIC_V4_CHECK=unavailable; PUBLIC_V6=unavailable
  PUBLIC_COUNTRY=unavailable; DNS_EGRESS=''; DNS_ECS=''; ONLINE_ISSUES=0
  say '联网检测：ipify、Cloudflare HTTPS；Akamai DNS TXT。沿用当前网络/终端代理，不主动绕过代理。'
  PUBLIC_V4=$(curl -q -fsS --proto '=https' --connect-timeout 3 --max-time 6 -4 https://api.ipify.org 2>/dev/null) || PUBLIC_V4=unavailable
  public_ip_valid "$PUBLIC_V4" || PUBLIC_V4=unavailable
  trace=$(curl -q -fsS --proto '=https' --connect-timeout 3 --max-time 6 -4 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null) || trace=''
  PUBLIC_V4_CHECK=$(printf '%s\n' "$trace" | awk -F= '$1=="ip" {print $2;exit}')
  public_ip_valid "$PUBLIC_V4_CHECK" || PUBLIC_V4_CHECK=unavailable
  PUBLIC_COUNTRY=$(printf '%s\n' "$trace" | awk -F= '$1=="loc" && $2 ~ /^[A-Z][A-Z]$/ {print $2;exit}')
  PUBLIC_COUNTRY=${PUBLIC_COUNTRY:-unavailable}
  v6=$(curl -q -fsS --proto '=https' --connect-timeout 3 --max-time 6 -6 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null) || v6=''
  PUBLIC_V6=$(printf '%s\n' "$v6" | awk -F= '$1=="ip" {print $2;exit}')
  if ! public_ip_valid "$PUBLIC_V6" || [[ "$PUBLIC_V6" != *:* ]]; then PUBLIC_V6=unavailable; fi
  txt=$(dig +time=3 +tries=1 +short whoami.ds.akahelp.net TXT 2>/dev/null) || rc=$?
  if [[ "$rc" == 0 ]]; then
    DNS_EGRESS=$(printf '%s\n' "$txt" | awk -F'"' '$2=="ns" {print $4}' | sort -u | paste -sd, -)
    DNS_ECS=$(printf '%s\n' "$txt" | awk -F'"' '$2=="ecs" {print $4}' | tr -cd '0-9a-fA-F:./\n' | paste -sd, -)
    csv_ips_valid "$DNS_EGRESS" || DNS_EGRESS=''
  fi
  [[ "$PUBLIC_V4" != unavailable && "$PUBLIC_V4_CHECK" != unavailable && "$PUBLIC_V4" == "$PUBLIC_V4_CHECK" ]] || ONLINE_ISSUES=$((ONLINE_ISSUES+1))
  [[ -n "$DNS_EGRESS" ]] || ONLINE_ISSUES=$((ONLINE_ISSUES+1))
  # No IPv6 default route is a legitimate state, but a configured route with a failed probe is unknown.
  [[ "$CURRENT_V6" == absent || "$PUBLIC_V6" != unavailable ]] || ONLINE_ISSUES=$((ONLINE_ISSUES+1))
  printf '公网 IPv4 (ipify): %s\n公网 IPv4 (Cloudflare): %s\n公网 IPv6 (Cloudflare): %s\nCloudflare IP 地区: %s\n' "$PUBLIC_V4" "$PUBLIC_V4_CHECK" "$PUBLIC_V6" "$PUBLIC_COUNTRY"
  printf 'DNS 递归出口 (Akamai TXT): %s\nDNS ECS 子网: %s\n' "${DNS_EGRESS:-unavailable}" "${DNS_ECS:-not observed}"
  say 'dig 使用 /etc/resolv.conf 路径，可能不同于 macOS 分域解析、浏览器 DoH 和 Claude；公网探测不证明 Claude 的实际出口。'
  [[ -z "$DNS_ECS" ]] || say '[注意] 权威诊断服务看到了 ECS 子网信息；它不一定是本机真实公网地址。'
  return 0
}
print_environment() {
  printf '本机时间: %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')"
  printf '时区: %s\nIPv4 默认路由: %s\nIPv6 默认路由: %s\n系统 DNS 地址: %s\n系统代理: %s\n终端 HTTP(S) 代理: %s\nClaude 设置代理: %s\n网络指纹: %s\n' \
    "$CURRENT_TZ" "$CURRENT_V4" "$CURRENT_V6" "$CURRENT_DNS" "$CURRENT_SYS_PROXY" "$CURRENT_CLI_PROXY" "$CURRENT_SETTINGS_PROXY" "$CURRENT_FINGERPRINT"
  say '系统 DNS 地址是配置值，不是已验证的实际递归出口；本次未测量真实时钟偏差。'
}
snapshot() {
  require_macos
  [[ $# == 0 || ( $# == 1 && "$1" == --online ) ]] || fail 'snapshot 仅支持 --online'
  collect_environment; print_environment
  if [[ "${1:-}" == --online ]]; then online_probe; else say '公网 IP/DNS 递归出口：未检测；使用 --online 显式联网。'; fi
}
baseline_data() {
  require_macos
  [[ $# == 0 ]] || fail 'baseline-data 不接受参数'
  collect_environment
  [[ "$CURRENT_V4" != unavailable && "$CURRENT_V6" != unavailable && "$CURRENT_DNS" != unavailable && "$CURRENT_SYS_PROXY" != unavailable && "$CURRENT_TZ" != unavailable ]] || fail '环境读取不完整，未生成基线。'
  [[ "$CURRENT_V4" != absent || "$CURRENT_V6" != absent ]] || fail '没有默认路由，未生成基线。'
  # Read-only data for the preview-bound setup transaction; no TAG proof is
  # implied here. Its caller must separately validate fresh proxy ownership.
  python3 - "$CURRENT_TZ" "$CURRENT_V4" "$CURRENT_V6" "$CURRENT_DNS" "$CURRENT_DNS_SIG" "$CURRENT_SYS_PROXY_SIG" "$CURRENT_CLI_PROXY_SIG" "$CURRENT_SETTINGS_SIG" <<'PY_BASELINE'
import datetime, json, sys
keys = ('timezone', 'ipv4_route', 'ipv6_route', 'dns', 'dns_sig', 'sys_proxy_sig', 'cli_proxy_sig', 'settings_proxy_sig')
if any('\n' in value or '\r' in value for value in sys.argv[1:]):
    raise SystemExit(4)
text = 'format=2\ncreated=' + datetime.datetime.now().astimezone().isoformat() + '\nonline=no\n'
text += ''.join(key + '=' + value + '\n' for key, value in zip(keys, sys.argv[1:]))
print(json.dumps({'status': 'ok', 'baseline': text}))
PY_BASELINE
}
write_baseline() {
  require_macos
  [[ $# == 0 || ( $# == 1 && "$1" == --online ) ]] || fail 'baseline 仅支持 --online'
  local online=no temp tag_rc=0 tag_fields
  collect_environment; print_environment
  [[ "$CURRENT_V4" != unavailable && "$CURRENT_V6" != unavailable && "$CURRENT_DNS" != unavailable && "$CURRENT_SYS_PROXY" != unavailable && "$CURRENT_TZ" != unavailable ]] || fail '环境读取不完整，未保存基线。'
  [[ "$CURRENT_V4" != absent || "$CURRENT_V6" != absent ]] || fail '没有默认路由，未保存基线。'
  tag_preflight || tag_rc=$?
  [[ "$tag_rc" != 4 ]] || fail '7890 入口无法确认，未保存基线。'
  tag_fields=$(tag_bridge baseline "$TMP_SCAN/tag-report.json") || fail '预期 TAG 分组/节点不可确认，未保存基线。'
  if [[ "${1:-}" == --online ]]; then
    online=yes; online_probe
    [[ "$ONLINE_ISSUES" == 0 ]] || fail '在线结果不完整或出口不一致，未保存基线。'
  fi
  init_dirs
  temp=$(mktemp "$STATE_DIR/.baseline.XXXXXXXX") || fail '无法创建基线'
  {
    printf 'format=2\ncreated=%s\nonline=%s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$online"
    printf 'timezone=%s\nipv4_route=%s\nipv6_route=%s\ndns=%s\ndns_sig=%s\nsys_proxy_sig=%s\ncli_proxy_sig=%s\nsettings_proxy_sig=%s\n' "$CURRENT_TZ" "$CURRENT_V4" "$CURRENT_V6" "$CURRENT_DNS" "$CURRENT_DNS_SIG" "$CURRENT_SYS_PROXY_SIG" "$CURRENT_CLI_PROXY_SIG" "$CURRENT_SETTINGS_SIG"
    printf '%s\n' "$tag_fields"
    if [[ "$online" == yes ]]; then printf 'public_ipv4=%s\npublic_ipv6=%s\npublic_country=%s\ndns_egress=%s\n' "$PUBLIC_V4" "$PUBLIC_V6" "$PUBLIC_COUNTRY" "$DNS_EGRESS"; fi
  } > "$temp"
  chmod 600 "$temp"; mv -f "$temp" "$BASELINE_FILE"
  log_event "baseline-updated online=${online}"
  say '已保存用户确认的环境基线。基线表示已接受的配置，不是无泄漏证明。'
}
compare_value() {
  local key=$1 value=$2 label=$3 previous
  previous=$(kv_get "$BASELINE_FILE" "$key")
  if [[ "$value" == unavailable || -z "$previous" ]]; then
    printf '[未知] %s\n' "$label"; WARNINGS=$((WARNINGS+1))
  elif [[ "$value" != "$previous" ]]; then
    printf '[变化] %s：基线=%s 当前=%s\n' "$label" "$previous" "$value"; WARNINGS=$((WARNINGS+1))
  else printf '[通过] %s\n' "$label"; fi
}
preflight() {
  require_macos
  local tag_rc=0
  [[ $# == 0 || ( $# == 1 && "$1" == --online ) ]] || fail 'preflight 仅支持 --online'
  WARNINGS=0; CRITICAL=0
  collect_environment; print_environment
  if [[ "$(kv_get "$BASELINE_FILE" format)" != 2 ]]; then say '[拒绝] 尚未建立当前版本的可信基线。'; return 4; fi
  if [[ -z "$(kv_get "$BASELINE_FILE" tag_group)" || -z "$(kv_get "$BASELINE_FILE" tag_node)" ]]; then
    say '[未确认] 旧基线未固定 TAG 分组/节点，请确认后重新建立基线。'; WARNINGS=$((WARNINGS+1))
  fi
  compare_value timezone "$CURRENT_TZ" '时区'
  compare_value ipv4_route "$CURRENT_V4" 'IPv4 路由'
  compare_value ipv6_route "$CURRENT_V6" 'IPv6 路由'
  compare_value dns "$CURRENT_DNS" 'DNS 地址'
  compare_value dns_sig "$CURRENT_DNS_SIG" 'DNS 分域/接口配置'
  compare_value sys_proxy_sig "$CURRENT_SYS_PROXY_SIG" '系统代理摘要'
  compare_value cli_proxy_sig "$CURRENT_CLI_PROXY_SIG" '终端代理摘要'
  compare_value settings_proxy_sig "$CURRENT_SETTINGS_SIG" 'Claude 设置代理摘要'
  if [[ "$CURRENT_SETTINGS_PROXY" != none ]]; then say '[未知] Claude 设置含代理覆盖或无法解析，不能证明有效会话配置。'; WARNINGS=$((WARNINGS+1)); fi
  if [[ ( "$CURRENT_V4" == absent && "$CURRENT_V6" == absent ) || "$CURRENT_V4" == unavailable || "$CURRENT_V6" == unavailable || "$CURRENT_DNS" == unavailable || "$CURRENT_SYS_PROXY" == unavailable ]]; then CRITICAL=$((CRITICAL+1)); fi
  if [[ "${1:-}" == --online || "$(kv_get "$BASELINE_FILE" online)" == yes ]]; then
    online_probe; WARNINGS=$((WARNINGS+ONLINE_ISSUES))
    if [[ "$(kv_get "$BASELINE_FILE" online)" == yes ]]; then
      compare_value public_ipv4 "$PUBLIC_V4" '公网 IPv4'
      if [[ "$PUBLIC_V6" != unavailable || "$CURRENT_V6" != absent ]]; then compare_value public_ipv6 "$PUBLIC_V6" '公网 IPv6'; fi
      compare_value public_country "$PUBLIC_COUNTRY" '出口地区'
      compare_value dns_egress "${DNS_EGRESS:-unavailable}" 'DNS 递归出口（轮换也会产生变化）'
    fi
  else say '[未验证] 公网 IP、实际 DNS 递归出口；当前仅离线配置检查。'; fi
  tag_preflight || tag_rc=$?
  if [[ "$tag_rc" == 4 ]]; then CRITICAL=$((CRITICAL+1)); elif [[ "$tag_rc" != 0 ]]; then WARNINGS=$((WARNINGS+1)); fi
  [[ "$CRITICAL" == 0 ]] || { say '[拒绝] 关键环境或代理入口检查失败。'; return 4; }
  [[ "$WARNINGS" == 0 ]] || { say "[待确认] ${WARNINGS} 项变化或未知。"; return 3; }
  say '已完成配置一致性预检；不代表无泄漏或账号安全。'
}
dns_check() {
  require_macos
  local online=no expected='' file src ip ips epoch fingerprint now age match resolver files=()
  local result=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --online) online=yes; shift;;
      --browser-report) [[ $# -ge 2 ]] || fail '缺少报告路径'; files+=("$2"); shift 2;;
      --expected-resolvers) [[ $# -ge 2 ]] || fail '缺少 IP 列表'; expected=$2; csv_ips_valid "$expected" || fail '预期解析器必须是逗号分隔的 IP'; shift 2;;
      *) fail '未知 dns-check 参数';;
    esac
  done
  collect_environment; print_environment
  DNS_EGRESS=''; PUBLIC_V4=unavailable; PUBLIC_V6=unavailable
  if [[ "$online" == yes ]]; then online_probe; [[ "$ONLINE_ISSUES" == 0 ]] || result=3
  else say '[未验证] 本机递归出口；加 --online 后检测。'; fi
  now=$(date +%s)
  for file in "${files[@]}"; do
    [[ -r "$file" && ! -L "$file" && "$(kv_get "$file" format)" == 1 ]] || { say '[未知] 浏览器报告无效'; result=3; continue; }
    src=$(kv_get "$file" source); ip=$(kv_get "$file" public_ip); ips=$(kv_get "$file" dns_servers)
    epoch=$(kv_get "$file" observed_epoch); fingerprint=$(kv_get "$file" network_fingerprint)
    case "$src" in https://browserleaks.com/dns|https://www.dnsleaktest.com/results.html) ;; *) say '[未知] 报告来源不在支持列表'; result=3; continue;; esac
    if ! valid_ip "$ip" || ! csv_ips_valid "$ips" || [[ ! "$epoch" =~ ^[0-9]{1,10}$ ]]; then say '[未知] 报告字段不完整或无效'; result=3; continue; fi
    age=$((now-10#$epoch))
    printf '\n网站: %s\n浏览器公网 IP: %s\n网站观察到的 DNS 递归服务器: %s\n' "$src" "$ip" "$ips"
    if [[ "$age" -lt 0 || "$age" -gt 900 || "$fingerprint" != "$CURRENT_FINGERPRINT" ]]; then
      say '[过期/环境不同] 仅作历史证据，不参与当前通过判断。'; result=3; continue
    fi
    if [[ "$PUBLIC_V4" != unavailable && "$ip" != "$PUBLIC_V4" && "$ip" != "$PUBLIC_V6" ]]; then say '[差异] 浏览器与本次终端探测出口不同。'; result=3; fi
    if [[ -n "$DNS_EGRESS" ]]; then
      match=0
      for resolver in $(printf '%s' "$DNS_EGRESS" | tr ',' ' '); do
        case ",$ips," in *",$resolver,"*) match=1;; esac
      done
      if [[ "$match" == 1 ]]; then say '[交叉证据] 网站结果包含本机诊断观察到的递归出口；不等于排除了其他路径。'
      else say '[差异] 本机诊断与网站没有共同的递归 IP，可能涉及分流、DoH、轮换或缓存。'; result=3; fi
    fi
    if [[ -n "$expected" ]]; then
      for resolver in $(printf '%s' "$ips" | tr ',' ' '); do
        case ",$expected," in *",$resolver,"*) ;; *) printf '[策略差异] 网站出现未允许的解析出口 %s\n' "$resolver"; result=3;; esac
      done
    fi
  done
  if [[ -n "$expected" ]]; then
    for resolver in $(printf '%s' "$DNS_EGRESS" | tr ',' ' '); do
      case ",$expected," in *",$resolver,"*) ;; *) printf '[策略差异] 本机诊断出现未允许的解析出口 %s\n' "$resolver"; result=3;; esac
    done
    [[ -n "$DNS_EGRESS" || ${#files[@]} -gt 0 ]] || result=3
  else say '[未判定] 未指定预期 DNS 递归出口；不能输出“无泄漏”。'; fi
  say '不同网站使用不同测试域名与样本量；结果可不同。此检查不捕获 Claude DNS 请求，解析器 IPv6 地址也不证明本机存在 IPv6 直连。'
  return "$result"
}

tag_bridge() {
  local interpreter listener_rc=0 collector_status='-'
  if [[ -x /opt/homebrew/bin/python3 ]]; then interpreter=/opt/homebrew/bin/python3
  elif [[ -x /usr/local/bin/python3 ]]; then interpreter=/usr/local/bin/python3
  else interpreter=$(command -v python3 2>/dev/null || true); fi
  [[ -n "$interpreter" ]] || { say '[未确认] TAG 核对需要已有的 Python 3；不会自动安装。' >&2; return 4; }
  if [[ "$1" == collect ]]; then
    # Keep the original three collector arguments stable.  The optional receipt
    # is deliberately last so older direct callers remain valid.
    collector_status=${5:--}
    init_scan_tmp
    # Capture in the shell: this Mac returns empty output when netstat is spawned by Python.
    # Keep listener records in our private temporary directory. Python selects
    # 7890 and the configured loopback-reachable TAG DNS port from this same read.
    /usr/sbin/netstat -anv -p tcp 2> "$TMP_SCAN/tag-listeners-errors" |
      awk '$6=="LISTEN" {print}' > "$TMP_SCAN/tag-listeners" || listener_rc=$?
    set -- "$1" "$2" "$3" "$4" "$TMP_SCAN/tag-listeners" "$TMP_SCAN/tag-listeners-errors" "$listener_rc" "$collector_status"
  fi
  "$interpreter" - "$@" <<'PY_TAG'
# Standard-library TAG adapter: no installs, configuration writes or non-loopback HTTP.
import datetime
import ipaddress
import json
import math
import os
import pathlib
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HOST, PORT = "127.0.0.1", 7890
TAG_BINARY_DIR = "/Applications/TAG.app/Contents/Resources/bin/"
API_PATHS = frozenset(("/configs", "/proxies", "/connections", "/rules"))
RULE_DOMAINS = frozenset((
    "claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com",
    "challenges.cloudflare.com", "datadoghq.com", "segment.io", "stripe.com",
    "stripe.network", "stripecdn.com", "intercom.io", "intercomcdn.com",
    "intercomassets.com",
))
RULE_TYPES = frozenset(("DOMAIN", "DOMAIN-SUFFIX", "MATCH", "GEOSITE", "RULE-SET", "DOMAIN-KEYWORD",
                        "DST-PORT", "IP-CIDR", "IP-CIDR6", "GEOIP", "SRC-IP-CIDR", "SRC-PORT",
                        "NETWORK", "IN-TYPE", "PROCESS-NAME"))
MAX_RULE_ENTRIES = 16_384
MAX_RULE_TEXT = 1_024

def run_readonly(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=3)

def process_table():
    result = run_readonly(["/bin/ps", "-axo", "pid=,uid=,lstart=,comm="])
    if result.returncode:
        raise ValueError("process_metadata_unavailable")
    records = {}
    pattern = r"^\s*(\d+)\s+(\d+)\s+(\w+\s+\w+\s+\d+\s+\d\d:\d\d:\d\d\s+\d{4})\s+(.+)$"
    for line in result.stdout.splitlines():
        match = re.match(pattern, line)
        if match:
            pid, uid, stamp, executable = match.groups()
            records[int(pid)] = {"uid": int(uid), "stamp": " ".join(stamp.split()),
                                 "executable": os.path.realpath(executable)}
    return records

def is_tag_process(record):
    executable = record.get("executable", "")
    return (executable.startswith(TAG_BINARY_DIR)
            and "/" not in executable[len(TAG_BINARY_DIR):]
            and pathlib.Path(executable).name.startswith("mihomo")
            and record.get("uid") in (0, os.getuid()))

def parse_endpoint(value):
    host, port = value.split(" (", 1)[0].rsplit(":", 1)
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError("invalid_port")
    return str(ipaddress.ip_address(host.strip("[]").split("%", 1)[0])), int(port)

def tcp_reachable():
    try:
        with socket.create_connection((HOST, PORT), timeout=1):
            return True
    except OSError:
        return False

def listener_query(kernel_snapshot=None):
    result = run_readonly(["/usr/sbin/lsof", "-nP", "-a", "-iTCP:7890", "-sTCP:LISTEN", "-Fpn"])
    result.listener_source = "lsof"
    # macOS may hide root-owned sockets from unprivileged lsof without an error.
    # Only that exact empty result uses the kernel's read-only listener PID table.
    if result.returncode != 1 or result.stdout.strip() or result.stderr.strip():
        return result
    kernel = kernel_snapshot if kernel_snapshot is not None else run_readonly(["/usr/sbin/netstat", "-anv", "-p", "tcp"])
    output, incomplete = [], False
    if kernel.returncode == 0 and not kernel.stderr.strip():
        for line in kernel.stdout.splitlines():
            fields = line.split()
            if len(fields) < 6 or fields[0] not in ("tcp4", "tcp6", "tcp46") or fields[5] != "LISTEN":
                continue
            host, sep, port = fields[3].rpartition(".")
            if not sep or port != "7890" or host not in (HOST, "*", "0.0.0.0", "::"):
                continue
            owners = [match.group(1) for field in fields[6:]
                      for match in [re.fullmatch(r"[^:\s]+:([1-9]\d*)", field)] if match]
            if len(owners) != 1:
                incomplete = True
                continue
            address = "[::]" if host == "::" else host
            output.extend(("p" + owners[0], "n" + address + ":7890"))
    failed = kernel.returncode != 0 or bool(kernel.stderr.strip()) or incomplete or not output
    converted = subprocess.CompletedProcess(kernel.args, 1 if failed else 0,
                                             "\n".join(output), "kernel listener metadata incomplete" if failed else "")
    converted.listener_source = "netstat"
    return converted

def inspect_entry(before, after, lsof_result, reachable):
    pids, pid, public_listener = set(), None, False
    for line in lsof_result.stdout.splitlines():
        if re.fullmatch(r"p\d+", line):
            pid = int(line[1:])
        elif line.startswith("n") and pid is not None:
            endpoint = line[1:]
            if endpoint in ("127.0.0.1:7890", "*:7890", "0.0.0.0:7890", "[::]:7890"):
                pids.add(pid)
                public_listener |= endpoint != "127.0.0.1:7890"
    report = {"endpoint": "http://127.0.0.1:7890", "state": "unconfirmed",
              "owners": [], "public_listener": public_listener,
              "source": getattr(lsof_result, "listener_source", "lsof")}
    if not reachable:
        report.update(state="unavailable", reason="7890 不可连接")
        return report
    if not pids or lsof_result.returncode != 0 or lsof_result.stderr.strip():
        report["reason"] = "端口可连接，但监听者身份读取不完整"
        return report
    for pid in sorted(pids):
        first, second = before.get(pid), after.get(pid)
        if not first or not second or first != second:
            report["reason"] = "监听进程身份在采样间变化或不可读取"
            return report
        report["owners"].append({"pid": pid, **second})
        if not is_tag_process(second):
            report.update(state="mismatch", reason="7890 监听者不匹配 TAG 安装目录中的 Mihomo")
            return report
    report.update(state="verified", reason="端口可连接，监听进程路径及启动身份匹配 TAG")
    return report

def read_kv(filename):
    data = {}
    if filename == "-" or not os.path.isfile(filename) or os.path.islink(filename):
        return data
    with open(filename, encoding="utf-8") as stream:
        for line in stream:
            key, sep, value = line.rstrip("\n").partition("=")
            if sep and key not in data:
                data[key] = value
    return data

def yaml_scalar(raw):
    raw = raw.strip()
    if raw.startswith('"'):
        value = json.loads(raw)
    elif raw.startswith("'") and raw.endswith("'"):
        value = raw[1:-1].replace("''", "'")
    else:
        value = raw.split(" #", 1)[0].rstrip()
        if any(c.isspace() for c in value) or value.startswith(("!", "&", "*", "|", ">", "{", "[")):
            raise ValueError("unsupported_scalar")
    if not isinstance(value, str) or any(ord(c) < 32 for c in value):
        raise ValueError("invalid_scalar")
    return value

def controller_credentials(filename):
    # Only these top-level scalars; do not decrypt files or parse proxy credentials.
    values = {}
    with open(filename, encoding="utf-8") as stream:
        for line in stream:
            match = re.match(r"^(external-controller|secret):\s*(.*?)\s*$", line)
            if match:
                values[match[1]] = yaml_scalar(match[2])
            if len(values) == 2:
                break
    parsed = urllib.parse.urlsplit("http://" + values.get("external-controller", ""))
    if (parsed.hostname not in ("127.0.0.1", "::1", "localhost")
            or not parsed.port or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment):
        raise ValueError("controller_not_loopback")
    host = "[::1]" if parsed.hostname == "::1" else "127.0.0.1"
    return "http://" + host + ":" + str(parsed.port), values.get("secret", "")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def api_get(base, secret, endpoint):
    if endpoint not in API_PATHS:
        raise ValueError("api_path_not_allowed")
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "::1") or parsed.path:
        raise ValueError("controller_not_loopback")
    headers = {"Authorization": "Bearer " + secret} if secret else {}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(base + endpoint, headers=headers, method="GET")
    with opener.open(request, timeout=1.5) as response:
        payload = response.read(4 * 1024 * 1024 + 1)
    if len(payload) > 4 * 1024 * 1024:
        raise ValueError("api_response_too_large")
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("api_response_not_object")
    return data

def resolve_chain(proxies, group):
    seen, path, name = set(), [], group
    for _ in range(16):
        if name in seen or name not in proxies or not isinstance(proxies[name], dict):
            return None
        seen.add(name)
        path.append(name)
        entry = proxies[name]
        selected = entry.get("now")
        if selected:
            if not isinstance(selected, str):
                return None
            name = selected
        else:
            if name.upper() in ("DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"):
                return None
            if not isinstance(entry.get("type"), str) or "all" in entry or entry["type"].lower() in ("selector", "urltest", "fallback", "loadbalance", "relay"):
                return None
            return list(reversed(path))
    return None

def resolve_selection(proxies, group):
    chain = resolve_chain(proxies, group)
    return chain[0] if chain else None

def published_rules(payload):
    """Keep the controller's rule order, but publish only comparison evidence.

    This receives a Mihomo `/rules` response.  It intentionally omits unrelated
    user rules and never returns controller credentials, proxy URLs, or nodes.
    Literal entries for the watched domains plus broad fallback rule types are
    sufficient for Claude Watch's 13-domain comparison.
    """
    values = payload.get("rules") if isinstance(payload, dict) else None
    if not isinstance(values, list) or len(values) > MAX_RULE_ENTRIES:
        raise ValueError("api_rules_schema_invalid")
    type_map = {
        "domain": "DOMAIN", "domainsuffix": "DOMAIN-SUFFIX", "domainkeyword": "DOMAIN-KEYWORD",
        "match": "MATCH", "geosite": "GEOSITE", "ruleset": "RULE-SET", "dstport": "DST-PORT",
        "ipcidr": "IP-CIDR", "ipcidr6": "IP-CIDR6", "geoip": "GEOIP", "srcipcidr": "SRC-IP-CIDR",
        "srcport": "SRC-PORT", "network": "NETWORK", "intype": "IN-TYPE", "processname": "PROCESS-NAME",
    }
    def safe(value, limit):
        return isinstance(value, str) and 0 < len(value) <= limit and not any(ord(c) < 32 for c in value)
    def canonical(value):
        if isinstance(value, str):
            if not safe(value, MAX_RULE_TEXT):
                return None
            fields = [field.strip() for field in value.split(",")]
            if not fields:
                return None
            value = {"type": fields[0], "payload": fields[1] if len(fields) > 1 else "",
                     "proxy": fields[1] if fields[0].lower() == "match" and len(fields) > 1 else
                     (fields[2] if len(fields) > 2 else "")}
        if not isinstance(value, dict):
            return None
        # A rule the user switched off stays in the table but never matches;
        # only a structured rule can prove it.  A plain string carries no
        # extra block and is never assumed disabled.
        extra = value.get("extra")
        disabled = isinstance(extra, dict) and extra.get("disabled") is True
        raw_type, payload, proxy = value.get("type"), value.get("payload"), value.get("proxy")
        key = re.sub(r"[^a-z0-9]", "", raw_type.lower()) if isinstance(raw_type, str) else ""
        kind = type_map.get(key)
        if kind not in RULE_TYPES or not safe(proxy, 256):
            return None
        if kind == "MATCH":
            return "MATCH," + proxy, disabled
        if kind in ("DOMAIN", "DOMAIN-SUFFIX"):
            if not safe(payload, 253):
                return None
            subject = payload.lower().lstrip("+.")
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", subject):
                return None
            return kind + "," + subject + "," + proxy, disabled
        # Broad entries convey precedence, but their payload can be a private
        # rule-set name or URI.  It is deliberately replaced before publishing.
        return kind + ",*," + proxy, disabled

    entries, disabled_domains, relevant, broad = [], [], 0, 0
    for value in values:
        canonicalized = canonical(value)
        if canonicalized is None:
            continue
        value, disabled = canonicalized
        fields = [field.strip() for field in value.split(",")]
        if not fields or fields[0].upper() not in RULE_TYPES:
            continue
        kind = fields[0].upper()
        include = False
        if kind in ("DOMAIN", "DOMAIN-SUFFIX") and len(fields) >= 3:
            subject = fields[1].lower().lstrip("+.")
            include = any(domain == subject or (kind == "DOMAIN-SUFFIX" and domain.endswith("." + subject))
                          for domain in RULE_DOMAINS)
            relevant += int(include)
        elif kind in ("MATCH", "GEOSITE", "RULE-SET", "DOMAIN-KEYWORD", "DST-PORT", "IP-CIDR",
                      "IP-CIDR6", "GEOIP", "SRC-IP-CIDR", "SRC-PORT", "NETWORK", "IN-TYPE",
                      "PROCESS-NAME"):
            # These are kept as bounded context. They are not claimed to prove
            # a particular watched domain's route.
            include = broad < 128
            broad += int(include)
        if disabled:
            # The rule exists but never matches.  Naming the ecosystem domain
            # keeps the gap visible instead of silently reading as coverage.
            if include and kind in ("DOMAIN", "DOMAIN-SUFFIX") and len(fields) >= 3:
                disabled_domains.append(fields[1].lower().lstrip("+."))
            continue
        if include:
            entries.append(value)
    return {"state": "available", "reason": "", "entries": entries,
            "total": len(values), "relevant": relevant, "broad": broad,
            "disabled_domains": disabled_domains}

def group_is_direct(proxies, name, depth):
    """A selector whose current selection ultimately lands on a bypass target
    sends every rule pointing at it straight out.  Nested groups are followed;
    a missing or cyclic chain is never guessed into a verdict."""
    if depth == 0:
        return False
    value = proxies.get(name)
    if not isinstance(value, dict):
        return False
    now = value.get("now")
    if not isinstance(now, str):
        return False
    if now.upper() in ("DIRECT", "REJECT", "REJECT-DROP", "PASS"):
        return True
    return group_is_direct(proxies, now, depth - 1)

def api_snapshot(config_path, group):
    report = {"state": "unavailable", "reason": "TAG 控制接口未验证"}
    try:
        base, secret = controller_credentials(config_path)
        configs = api_get(base, secret, "/configs")
        proxies = api_get(base, secret, "/proxies").get("proxies", {})
        connections = api_get(base, secret, "/connections").get("connections")
        if (configs.get("mode") not in ("rule", "global", "direct")
                or not isinstance(proxies, dict) or not isinstance(connections, list)):
            raise ValueError("api_schema_incomplete")
        ports = [configs.get(k) for k in ("port", "mixed-port", "socks-port")]
        active_group = "GLOBAL" if configs["mode"] == "global" else group
        roots = {"GLOBAL", group}
        for connection in connections:
            chain = connection.get("chains") if isinstance(connection, dict) else None
            if isinstance(chain, list) and chain and isinstance(chain[-1], str): roots.add(chain[-1])
        routes = {root: resolve_chain(proxies, root) for root in roots if root and len(root) <= 256}
        direct_groups = sorted(name for name in proxies if group_is_direct(proxies, name, 8))
        report.update(state="available", controller=base, mode=configs["mode"],
                      covers_7890=PORT in ports, selected_node=resolve_selection(proxies, active_group),
                      route_chains=routes,
                      global_node=resolve_selection(proxies, "GLOBAL"),
                      direct_groups=direct_groups, reason="")
        try:
            report["rules"] = published_rules(api_get(base, secret, "/rules"))
        except urllib.error.HTTPError as error:
            report["rules"] = {"state": "unavailable", "reason": "控制接口规则表 HTTP " + str(error.code), "entries": []}
            error.close()
        except Exception:
            # A rules-table limitation must not invalidate independently
            # verified controller mode, selection, port ownership or flows.
            report["rules"] = {"state": "unavailable", "reason": "控制接口规则表不可用或格式不完整", "entries": []}
        return report, connections
    except urllib.error.HTTPError as error:
        report["reason"] = "控制接口 HTTP " + str(error.code)
        error.close()
    except Exception:
        report["reason"] = "本机控制接口配置、鉴权、响应或访问不可用"
    report["rules"] = {"state": "unavailable", "reason": "控制接口未验证", "entries": []}
    return report, []

def epoch_from_start(stamp):
    try:
        # Go's RFC3339Nano timestamps must also work with older Python 3 parsers.
        stamp = re.sub(r"(\.\d{6})\d+(?=Z|[+-]\d\d:\d\d$)", r"\1", stamp)
        return datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError, TypeError):
        return None

def process_epoch(stamp):
    try:
        return datetime.datetime.strptime(stamp, "%a %b %d %H:%M:%S %Y").timestamp()
    except ValueError:
        return None

def route_interface(address):
    try:
        parsed = ipaddress.ip_address(address)
        args = ["/sbin/route", "-n", "get"]
        if parsed.version == 6:
            args.append("-inet6")
        result = run_readonly(args + [str(parsed)])
        match = re.search(r"^\s*interface:\s*(\S+)", result.stdout, re.M)
        return match.group(1) if result.returncode == 0 and match else "unavailable"
    except Exception:
        return "unavailable"

def connection_policy(chains, group, expected_node, api, record):
    if api.get("state") != "available" or api.get("mode") not in ("global", "rule", "direct"):
        return "unconfirmed", "TAG 实际模式未能确认"
    if api["mode"] == "direct" or any(str(x).upper() in ("DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE") for x in chains):
        return "mismatch", "实测为直连或拒绝路径，未通过代理路径要求"
    if not chains:
        return "unconfirmed", "缺少实际代理链"
    if api["mode"] == "global":
        if group and group != "GLOBAL":
            return "mismatch", "实际为 GLOBAL 模式，与明确保存的分组要求不同"
        root = "GLOBAL"
    else:
        if not isinstance(record.get("rule"), str) or not record["rule"].strip():
            return "unconfirmed", "规则模式未提供这条连接的命中规则"
        root = group or chains[-1]
    selected = api.get("route_chains", {}).get(root)
    if not selected:
        return "unconfirmed", "未能独立解析当前模式下的分组选择及末端代理节点"
    if chains != selected or (expected_node and chains[0] != expected_node):
        return "mismatch", "实际代理链与当前模式的分组选择或已固定节点不一致"
    return "match", "已按 TAG " + api["mode"].upper() + " 模式核对实际代理链与末端节点"

FAKE_IP_NETWORK = ipaddress.ip_network("198.18.0.0/15")

def fakeip_dns_config(filename):
    """Read only simple DNS scalars; never change TAG's runtime configuration."""
    if os.path.islink(filename):
        raise ValueError("dns_config_symlink")
    values, inside, blocks, size = {}, False, 0, 0
    with open(filename, encoding="utf-8") as stream:
        for line in stream:
            size += len(line)
            if size > 4 * 1024 * 1024:
                raise ValueError("dns_config_oversize")
            if re.fullmatch(r"dns:\s*(?:#.*)?\n?", line):
                blocks += 1
                inside = True
                continue
            if inside and line.strip() and not line[0].isspace() and not line.startswith("#"):
                inside = False
            if inside:
                match = re.match(r"^  (enable|listen|enhanced-mode|fake-ip-range):\s*(.*?)\s*$", line)
                if match:
                    if match[1] in values:
                        raise ValueError("dns_config_duplicate")
                    values[match[1]] = yaml_scalar(match[2])
    if blocks != 1 or values.get("enable") != "true" or values.get("enhanced-mode") != "fake-ip":
        raise ValueError("dns_not_fakeip")
    network = ipaddress.ip_network(values.get("fake-ip-range", ""), strict=False)
    if network.version != 4 or not network.subnet_of(FAKE_IP_NETWORK):
        raise ValueError("unsupported_fakeip_range")
    address, separator, port = values.get("listen", "").rpartition(":")
    if not separator or address not in ("", "0.0.0.0", "127.0.0.1", "[::]") or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError("dns_listener_not_loopback_reachable")
    return int(port), network

def normalized_dns_host(value):
    if not isinstance(value, str):
        return None
    value = value.lower().rstrip(".")
    if not 1 <= len(value) <= 253 or not re.fullmatch(r"[a-z0-9.-]+", value):
        return None
    labels = value.split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in labels):
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        return value

def dns_listener_matches(kernel, port, owner, processes):
    if kernel.returncode or kernel.stderr.strip():
        return False
    pid = owner.get("pid")
    current = processes.get(pid, {})
    if not is_tag_process(current) or any(current.get(key) != owner.get(key) for key in ("uid", "stamp", "executable")):
        return False
    listeners = set()
    for line in kernel.stdout.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0] not in ("tcp4", "tcp46", "tcp6") or fields[5] != "LISTEN":
            continue
        host, separator, observed_port = fields[3].rpartition(".")
        if not separator or observed_port != str(port) or host not in ("127.0.0.1", "0.0.0.0", "*", "::"):
            continue
        owners = [int(match.group(1)) for field in fields[6:]
                  for match in [re.fullmatch(r"[^:\s]+:([1-9]\d*)", field)] if match]
        if len(owners) != 1:
            return False
        listeners.update(owners)
    return listeners == {pid}

def source_candidate(record, flow, stamp, now):
    if not isinstance(record, dict) or not isinstance(record.get("metadata"), dict):
        return False
    metadata = record["metadata"]
    try:
        if (str(ipaddress.ip_address(metadata.get("sourceIP", ""))) != flow["local"][0]
                or int(metadata.get("sourcePort", 0)) != flow["local"][1]
                or str(metadata.get("network", "")).lower() != flow["protocol"]):
            return False
        declared_pid = metadata.get("processID", metadata.get("pid"))
        if declared_pid and int(declared_pid) != flow["pid"]:
            return False
        started, source_started = epoch_from_start(record.get("start")), process_epoch(stamp)
        return (started is not None and source_started is not None and source_started - 2 <= started <= now + 2
                and isinstance(record.get("id"), str) and bool(record["id"])
                and isinstance(record.get("chains"), list) and all(isinstance(name, str) for name in record["chains"]))
    except (ValueError, TypeError):
        return False

def record_identity(record):
    return {key: record.get(key) for key in ("id", "start", "metadata", "chains", "rule", "rulePayload")}

def translated_fakeip_destination(metadata, peer):
    """A resolved public IP or omitted IP may represent the same fake-IP host.

    A different synthetic/private/malformed destination is a conflict, not a
    reason to bypass the original exact destination check.
    """
    if (str(metadata.get("type", "")).lower() != "tun" or metadata.get("dnsMode") != "fake-ip"
            or ipaddress.ip_address(peer[0]) not in FAKE_IP_NETWORK):
        return False
    value = metadata.get("destinationIP")
    if value in (None, ""):
        return True
    try:
        address = ipaddress.ip_address(value)
        return address.is_global and not address.is_multicast and not address.is_reserved
    except (ValueError, TypeError):
        return False

def query_fakeip_dns(host, port, timeout):
    # Same-core DNS A lookup is bounded diagnostic evidence. A miss may populate
    # that core's ordinary DNS cache; it is not a configuration or route change.
    result = subprocess.run(["/usr/bin/dig", "@127.0.0.1", "-p", str(port), "+tcp", "+time=1", "+tries=1",
                             "+nosearch", "+noall", "+answer", "+comments", "+nocmd", host, "A"],
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode or result.stderr.strip() or "status: NOERROR" not in result.stdout:
        raise ValueError("dns_query_failed")
    rows = [line.split() for line in result.stdout.splitlines() if line.strip() and not line.startswith(";")]
    if len(rows) != 1 or len(rows[0]) != 5:
        raise ValueError("dns_answer_not_unique")
    name, ttl, klass, kind, address = rows[0]
    if normalized_dns_host(name) != host or klass != "IN" or kind != "A" or not ttl.isdigit() or int(ttl) < 1:
        raise ValueError("dns_answer_invalid")
    return str(ipaddress.IPv4Address(address)), min(int(ttl), 2)

def collect_fakeip_evidence(config_path, entry, api, records, sampled_flows, processes, listener_snapshot=None):
    """Additional destination proof for omitted fake-IP metadata, within one round."""
    if entry.get("state") != "verified" or api.get("state") != "available" or len(entry.get("owners", [])) != 1:
        return {}
    try:
        if not any(valid and ipaddress.ip_address(flow["peer"][0]) in FAKE_IP_NETWORK
                   for flow, _, valid in sampled_flows):
            return {}
        port, network = fakeip_dns_config(config_path)
        owner = entry["owners"][0]
        if listener_snapshot is not None:
            kernel, captured_at = listener_snapshot
            if not 0 <= time.time() - captured_at <= 5:
                return {}
        else:
            kernel = run_readonly(["/usr/sbin/netstat", "-anv", "-p", "tcp"])
            captured_at = time.time()
        if not dns_listener_matches(kernel, port, owner, processes):
            return {}
        candidates = []
        for flow, stamp, valid in sampled_flows:
            if not valid or ipaddress.ip_address(flow["peer"][0]) not in network:
                continue
            matching = [r for r in records if source_candidate(r, flow, stamp, time.time())]
            # Reject reused UDP source ports and conflicting duplicate IDs before
            # consulting DNS. Missing destination metadata cannot disambiguate them.
            if len(matching) != 1:
                continue
            record = matching[0]; metadata = record["metadata"]
            host = normalized_dns_host(metadata.get("host"))
            if (not translated_fakeip_destination(metadata, flow["peer"]) or not host
                    or int(metadata.get("destinationPort", 0)) != flow["peer"][1]
                    or not re.fullmatch(r"utun\d+", route_interface(flow["peer"][0]))):
                continue
            candidates.append((flow, stamp, record, host))
        if not candidates:
            return {}
        deadline = time.monotonic() + 1.5
        answers = {}
        for host in sorted({item[3] for item in candidates})[:8]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                address, ttl = query_fakeip_dns(host, port, min(0.35, remaining))
                answers[host] = (address, time.time(), ttl)
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
        # Retain original records, accepting only identities still present after
        # DNS. Do not substitute a new record for an expired/closed connection.
        base, secret = controller_credentials(config_path)
        current_records = api_get(base, secret, "/connections").get("connections", [])
        current_processes = process_table()
        if listener_snapshot is None:
            kernel = run_readonly(["/usr/sbin/netstat", "-anv", "-p", "tcp"])
        if (not 0 <= time.time() - captured_at <= 5
                or fakeip_dns_config(config_path) != (port, network)
                or not dns_listener_matches(kernel, port, owner, current_processes)):
            return {}
        evidence = {}
        for flow, stamp, record, host in candidates:
            answer = answers.get(host)
            same_source = [r for r in current_records if source_candidate(r, flow, stamp, time.time())]
            if (not answer or answer[0] != flow["peer"][0] or not 0 <= time.time() - answer[1] <= answer[2]
                    or len(same_source) != 1 or record_identity(same_source[0]) != record_identity(record)
                    or current_processes.get(flow["pid"], {}).get("stamp") != stamp
                    or current_processes.get(flow["pid"], {}).get("uid") != os.getuid()):
                continue
            evidence[record["id"]] = {"host": host, "address": answer[0], "observed_at": answer[1],
                "expires_at": answer[1] + answer[2], "dns_endpoint": "127.0.0.1:" + str(port),
                "dns_owner_pid": owner["pid"], "dns_owner_started": owner["stamp"],
                "source_pid": flow["pid"], "source_started": stamp,
                "source": flow["local"], "peer": flow["peer"], "protocol": flow["protocol"],
                "connection_start": record["start"], "kind": "same_core_fakeip_mapping"}
        return evidence
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return {}

def fakeip_destination_matches(proof, record, flow, stamp, now):
    if not isinstance(proof, dict):
        return False
    metadata = record["metadata"]
    try:
        return (translated_fakeip_destination(metadata, flow["peer"])
                and proof.get("kind") == "same_core_fakeip_mapping"
                and proof.get("source_pid") == flow["pid"] and proof.get("source_started") == stamp
                and proof.get("source") == flow["local"] and proof.get("peer") == flow["peer"]
                and proof.get("protocol") == flow["protocol"] and proof.get("connection_start") == record["start"]
                and proof.get("host") == normalized_dns_host(metadata.get("host"))
                and proof.get("address") == flow["peer"][0]
                and proof["observed_at"] <= now <= proof["expires_at"] <= proof["observed_at"] + 2)
    except (KeyError, TypeError, ValueError):
        return False

def destination_evidence(metadata):
    """Return display-only target evidence without treating proxy transport as target IP."""
    raw_ip = metadata.get("destinationIP", "")
    raw_port = metadata.get("destinationPort")
    port = None
    try:
        if isinstance(raw_port, bool):
            raise ValueError("boolean_port")
        candidate_port = int(raw_port)
        if 0 < candidate_port < 65536:
            port = candidate_port
    except (TypeError, ValueError):
        pass
    if raw_ip in (None, ""):
        return "", port, "missing", ""
    try:
        address = ipaddress.ip_address(str(raw_ip))
    except ValueError:
        return "", port, "invalid", ""
    if address in FAKE_IP_NETWORK:
        return "", port, "synthetic", ""
    if (not address.is_global or address.is_loopback or address.is_private or address.is_link_local
            or address.is_multicast or address.is_reserved or address.is_unspecified):
        return "", port, "nonpublic", ""
    country = metadata.get("destinationGeoIP", "")
    if not isinstance(country, str) or not re.fullmatch(r"[A-Za-z]{2}", country):
        country = ""
    return str(address), port, "public", country.upper()

def correlate_flow(flow, stamp, api, records, group, expected_node, now, fakeip_evidence=None):
    result = {**flow, "association": "unconfirmed", "policy": "unconfirmed", "chains": []}
    local, peer = flow["local"], flow["peer"]
    via_proxy = peer == [HOST, PORT] and flow["protocol"] == "tcp"
    if ipaddress.ip_address(peer[0]).is_loopback and not via_proxy:
        result.update(association="local_service", policy="not_applicable", reason="其他本机服务连接，不视为代理绕过")
        return result
    if via_proxy and (api.get("state") != "available" or not api.get("covers_7890")):
        result["reason"] = "控制接口不可用或属于另一内核，不能把 7890 连接与外层 TUN 链强行对应"
        return result
    if not via_proxy:
        result["interface"] = route_interface(peer[0])
    candidates = []
    destination_unproven = False
    for record in records:
        if not source_candidate(record, flow, stamp, now):
            continue
        metadata = record["metadata"]
        try:
            kind = str(metadata.get("type", "")).lower()
            if via_proxy:
                if kind not in ("http", "https", "socks", "socks5"):
                    continue
                if metadata.get("inboundPort") and int(metadata["inboundPort"]) != PORT:
                    continue
                if metadata.get("inboundIP") and not ipaddress.ip_address(metadata["inboundIP"]).is_loopback:
                    continue
            else:
                if int(metadata.get("destinationPort", 0)) != peer[1]:
                    continue
                exact = metadata.get("destinationIP") not in (None, "") and str(ipaddress.ip_address(metadata["destinationIP"])) == peer[0]
                if not exact:
                    proof = (fakeip_evidence or {}).get(record["id"])
                    if not fakeip_destination_matches(proof, record, flow, stamp, now):
                        destination_unproven = destination_unproven or translated_fakeip_destination(metadata, peer)
                        continue
            candidates.append(record)
        except (ValueError, TypeError):
            continue
    unique = {record["id"]: record for record in candidates}
    if len(candidates) != len(unique):
        result["reason"] = "控制器连接标识重复，未关联"
        return result
    if len(unique) != 1:
        result["reason"] = ("TUN 目标经过 fake-IP 转换，但未取得同一 TAG 内核的有效映射证明；未关联，不能认定直连泄漏"
                            if not unique and destination_unproven else
                            "没有唯一且时间有效的完整连接匹配；可能被 TUN 接管，不能认定直连泄漏")
        return result
    record = next(iter(unique.values()))
    metadata = record["metadata"]
    destination_ip, destination_port, destination_ip_state, destination_country = destination_evidence(metadata)
    result.update(association="correlated", host=metadata.get("host", ""),
                  chains=record["chains"], rule=record.get("rule", ""),
                  rule_payload=record.get("rulePayload", ""), connection_id=record["id"],
                  path="local_proxy" if via_proxy else str(metadata.get("type", "unknown")),
                  destination_ip=destination_ip, destination_port=destination_port,
                  destination_ip_state=destination_ip_state, destination_country=destination_country)
    result["policy"], result["reason"] = connection_policy(record["chains"], group, expected_node, api, record)
    if not via_proxy and fakeip_destination_matches((fakeip_evidence or {}).get(record["id"]), record, flow, stamp, now):
        result["association_evidence"] = fakeip_evidence[record["id"]]
        result["reason"] += "；同一 TAG 内核 DNS 映射与本机 fake-IP 已核对"
        if destination_ip_state != "public":
            result["reason"] += "，公网目标 IP 未提供"
    return result

def _observation_default(detail="连接采样回执缺失；无法判断本轮是否观察到套接字"):
    return {"schema": 1, "round_id": "", "observed_at": time.time(), "collector_state": "unknown",
            "target_count": 0, "parsed_count": 0, "accepted_count": 0,
            "correlated_count": 0, "unconfirmed_count": 0, "dropped": {}, "detail": detail}

def read_connection_observation(filename):
    if filename in (None, "-") or not os.path.isfile(filename) or os.path.islink(filename):
        return _observation_default()
    try:
        value = json.loads(pathlib.Path(filename).read_text(encoding="utf-8"))
        required = ("schema", "round_id", "observed_at", "collector_state", "target_count", "parsed_count",
                    "accepted_count", "correlated_count", "unconfirmed_count", "dropped", "detail")
        if (set(required) - set(value) or type(value["schema"]) is not int or value["schema"] != 1
                or not isinstance(value["round_id"], str) or not value["round_id"].strip()
                or isinstance(value["observed_at"], bool) or not isinstance(value["observed_at"], (int, float))
                or not math.isfinite(value["observed_at"]) or not 0 <= time.time() - value["observed_at"] <= 15
                or value["collector_state"] not in ("ok", "empty", "partial", "failed", "no_targets", "unknown")
                or not all(type(value[key]) is int and value[key] >= 0 for key in required[4:9])
                or not isinstance(value["dropped"], dict) or not isinstance(value["detail"], str)):
            raise ValueError("invalid_connection_observation")
        if any(not isinstance(key, str) or not key or type(count) is not int or count < 0
               for key, count in value["dropped"].items()):
            raise ValueError("invalid_connection_observation_drops")
        return value
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return _observation_default("连接采样回执无效；无法判断本轮是否观察到套接字")

def observation_drop(observation, reason):
    observation["dropped"][reason] = observation["dropped"].get(reason, 0) + 1

def observation_file_receipt_current(observation, target_file, connection_file):
    """A receipt is only display evidence when it matches fresh files from this collection."""
    now, problems = time.time(), []
    for label, filename in (("target", target_file), ("connection", connection_file)):
        if filename == "-" or not os.path.isfile(filename) or os.path.islink(filename):
            problems.append("missing_" + label + "_file")
            continue
        mtime = os.path.getmtime(filename)
        if not 0 <= now - mtime <= 15 or abs(mtime - observation["observed_at"]) > 15:
            problems.append("stale_" + label + "_file")
    if problems:
        for problem in problems:
            observation_drop(observation, problem)
        observation["collector_state"] = "unknown"
        observation["detail"] = "连接采样回执与本轮目标或连接文件不匹配；无法判定采样范围"
        return False
    return True

def read_flows(target_file, connection_file, processes, observation=None):
    targets = {}
    if observation is not None:
        observation["target_count"] = observation["parsed_count"] = observation["accepted_count"] = 0
    if target_file != "-" and os.path.isfile(target_file):
        with open(target_file, encoding="utf-8") as stream:
            for line in stream:
                parts = line.rstrip("\n").split("|")
                if len(parts) == 3 and parts[0].isdigit():
                    targets[int(parts[0])] = parts[1]
                elif observation is not None:
                    observation_drop(observation, "malformed_target")
    if observation is not None:
        observation["target_count"] = len(targets)
    flows = []
    if connection_file == "-" or not os.path.isfile(connection_file):
        return flows
    fresh = 0 <= time.time() - os.path.getmtime(connection_file) <= 10
    with open(connection_file, encoding="utf-8") as stream:
        for line in stream:
            parts = line.rstrip("\n").split("|", 2)
            if len(parts) != 3 or not parts[0].isdigit():
                if observation is not None:
                    observation_drop(observation, "malformed_connection")
                continue
            # lsof also reports listeners and unconnected descriptors.  They
            # are in scope for raw collection but are not malformed flows.
            if "->" not in parts[2]:
                continue
            pid = int(parts[0])
            try:
                left, right = parts[2].split("->", 1)
                flow = {"pid": pid, "protocol": parts[1].lower(),
                        "local": list(parse_endpoint(left)), "peer": list(parse_endpoint(right))}
            except ValueError:
                if observation is not None:
                    observation_drop(observation, "malformed_endpoint")
                continue
            if observation is not None:
                observation["parsed_count"] += 1
            if pid not in targets:
                if observation is not None:
                    observation_drop(observation, "filtered_pid")
                continue
            identity = processes.get(pid, {})
            valid = fresh and identity.get("uid") == os.getuid() and identity.get("stamp") == targets[pid]
            if observation is not None:
                if not fresh:
                    observation_drop(observation, "stale_sample")
                elif not valid:
                    observation_drop(observation, "identity_stale")
                else:
                    observation["accepted_count"] += 1
            flows.append((flow, targets[pid], valid))
    return flows

def cli_proxy_state():
    value = next((os.environ[k] for k in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY")
                  if os.environ.get(k)), "")
    try:
        parsed = urllib.parse.urlsplit(value)
        matches = (parsed.scheme == "http" and parsed.hostname in ("localhost", HOST)
                   and parsed.port == PORT and parsed.path in ("", "/") and not parsed.query and not parsed.fragment)
    except ValueError:
        matches = False
    # Clients differ in NO_PROXY precedence; never hide a bypass in the other casing.
    bypass = os.environ.get("no_proxy", "") + "," + os.environ.get("NO_PROXY", "")
    exceptions = [v for v in re.split(r"[,\s]+", bypass) if v and v not in ("localhost", "127.0.0.1", "::1")]
    return {"matches_7890": matches, "other_bypass_rules": bool(exceptions), "bypass_all": "*" in exceptions}

def collect_report(target_file, connection_file, baseline_file, listener_file=None, listener_errors=None, listener_rc="0", collector_file=None):
    baseline = read_kv(baseline_file)
    group = os.environ.get("CLAUDE_WATCH_TAG_GROUP") or baseline.get("tag_group") or ""
    pinned = os.environ.get("CLAUDE_WATCH_TAG_NODE") or baseline.get("tag_node", "")
    config_path = os.environ.get("CLAUDE_WATCH_TAG_CONFIG") or os.path.expanduser("~/Library/Application Support/com.tag.lab/mihomo/runtime.yaml")
    report = {"schema": 1, "observed_epoch": int(time.time()), "expected_group": group,
              "expected_node": pinned, "pinned": bool(pinned), "flows": [], "cli": cli_proxy_state()}
    listener_snapshot = None
    try:
        before = process_table()
        kernel = None
        if listener_file is not None:
            if not 0 <= time.time() - os.path.getmtime(listener_file) <= 5:
                raise ValueError("listener_snapshot_expired")
            kernel = subprocess.CompletedProcess(["/usr/sbin/netstat"], int(listener_rc),
                        pathlib.Path(listener_file).read_text(), pathlib.Path(listener_errors).read_text())
            listener_snapshot = (kernel, os.path.getmtime(listener_file))
        listeners = listener_query(kernel)
        reachable = tcp_reachable()
        after = process_table()
        report["entry"] = inspect_entry(before, after, listeners, reachable)
    except Exception:
        after = {}
        report["entry"] = {"state": "unconfirmed", "reason": "无法验证 7890 监听者", "owners": []}
    if report["entry"]["state"] == "verified":
        report["api"], records = api_snapshot(config_path, group)
        report["rules"] = report["api"].pop("rules", {"state": "unavailable", "reason": "控制接口未提供规则表", "entries": []})
    else:
        report["api"], report["rules"], records = ({"state": "unavailable", "reason": "入口身份未验证，未读取鉴权信息或查询控制接口"},
            {"state": "unavailable", "reason": "入口身份未验证，未读取鉴权信息或查询控制接口", "entries": []}, [])
    if not group and report["api"].get("mode") == "global":
        group = "GLOBAL"
        report["expected_group"] = group
    if not pinned:
        report["expected_node"] = report["api"].get("selected_node") or ""
    report["selection_changed"] = bool(pinned and report["api"].get("selected_node") != pinned)
    observation = read_connection_observation(collector_file)
    observation_file_receipt_current(observation, target_file, connection_file)
    observation["correlated_count"] = observation["unconfirmed_count"] = 0
    sampled_flows = read_flows(target_file, connection_file, after, observation)
    fakeip_evidence = collect_fakeip_evidence(config_path, report["entry"], report["api"], records, sampled_flows, after, listener_snapshot)
    for flow, stamp, valid in sampled_flows:
        if not valid:
            item = {**flow, "association": "unconfirmed", "policy": "unconfirmed", "chains": [],
                    "reason": "进程身份变化、无法读取或连接采样过期"}
        elif flow["peer"] == [HOST, PORT] and report["entry"]["state"] != "verified":
            item = {**flow, "association": "unconfirmed", "policy": "unconfirmed", "chains": [],
                    "reason": "7890 监听者未通过身份核对"}
        else:
            item = correlate_flow(flow, stamp, report["api"], records, group, report["expected_node"], time.time(), fakeip_evidence)
        report["flows"].append(item)
        # A stale or reused identity remains visible in the safety report, but
        # cannot become accepted/correlated observation evidence.
        if valid:
            if item["association"] == "correlated":
                observation["correlated_count"] += 1
            else:
                observation["unconfirmed_count"] += 1
    if observation["collector_state"] in ("ok", "empty") and observation["dropped"]:
        observation["collector_state"] = "partial"
        observation["detail"] = "连接样本已读取，但部分记录未用于关联"
    report["connection_observation"] = observation
    return report

def report_exit(report):
    if report["entry"]["state"] != "verified":
        return 4
    api = report["api"]
    if (api["state"] != "available" or report["selection_changed"]
            or report["entry"].get("public_listener")):
        return 3
    if not api.get("covers_7890") or api.get("mode") == "direct" or (api.get("mode") == "global" and report["expected_group"] != "GLOBAL"):
        return 3
    if (api.get("mode") not in ("global", "rule")
            or (report["expected_group"] and not report["expected_node"])
            or (not report["expected_group"] and not any(f.get("association") == "correlated" and f.get("policy") == "match" for f in report["flows"]))):
        return 3
    if any(flow["policy"] in ("unconfirmed", "mismatch") for flow in report["flows"]):
        return 3
    return 0

def safe_text(value):
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(value))[:800]

def render(report, events=False):
    entry, api = report["entry"], report["api"]
    print("7890 入口: " + safe_text(entry["state"]) + "；" + safe_text(entry.get("reason", ""))
          + "；监听证据=" + safe_text(entry.get("source", "unavailable")))
    for owner in entry.get("owners", []):
        print("监听者 PID=" + str(owner["pid"]) + " 路径=" + safe_text(owner["executable"]))
    if entry.get("public_listener"):
        print("[变化] 监听地址包含非回环地址；未自动修改局域网访问设置。")
    print("TAG API: " + safe_text(api["state"]) + "；" + safe_text(api.get("reason", "")))
    if api.get("state") == "available" and not api.get("covers_7890"):
        print("[未确认] 此 API 内核未声明 7890 入口；双内核的跨层关联尚不可证明。")
    print("路径核对: " + safe_text(report["expected_group"] or "按实际命中规则逐连接核对") + "；节点: " + safe_text(report["expected_node"] or "逐连接核对"))
    if not report["pinned"]:
        print("[自动核对] 使用 TAG 实际模式与分组选择；会话 IP 基准由受控启动单独建立并校验。")
    if api.get("mode") == "global" and report["expected_group"] != "GLOBAL":
        print("[配置差异] 当前为 GLOBAL，选中 " + safe_text(api.get("global_node")) + "；不能认为海外 AI 分组规则正在生效。")
    if report.get("selection_changed"):
        print("[变化] TAG 分组选择与已固定的可信节点不同。")
    if not report["flows"]:
        print("[未验证] 本次没有可关联的受监控应用连接样本。")
    for flow in report["flows"]:
        endpoint = json.dumps({"local": flow["local"], "peer": flow["peer"]}, ensure_ascii=False)
        chain = " → ".join(reversed(flow.get("chains", []))) or "未确认"
        print("PID=" + str(flow["pid"]) + " " + endpoint + " 关联=" + flow["association"]
              + " 策略=" + flow["policy"] + " 域名=" + safe_text(flow.get("host", ""))
              + " 链=" + safe_text(chain) + " 参考路由=" + safe_text(flow.get("interface", "未查询"))
              + "；" + safe_text(flow["reason"]))
    if not events:
        print("端口可用不等于指定节点已生效；代理链核对不替代 DNS 出站检测，也不证明无泄漏。")
    return report_exit(report)

def main():
    action = sys.argv[1]
    if action == "collect":
        print(json.dumps(collect_report(*sys.argv[2:]), ensure_ascii=False, separators=(",", ":")))
    else:
        with open(sys.argv[2], encoding="utf-8") as stream:
            report = json.load(stream)
        if action == "publish":
            if (report.get("schema") != 1 or not isinstance(report.get("entry"), dict)
                    or not isinstance(report.get("api"), dict) or not report.get("observed_epoch")
                    or not sys.argv[3].isdigit() or not sys.argv[4]):
                return 4
            report["producer"] = {"pid": int(sys.argv[3]), "started": sys.argv[4]}
            report["monitor_version"] = "2.8.4"
            report["monitored_apps"] = ["claude", "codex", "chatgpt"]
            print(json.dumps(report, ensure_ascii=False, separators=(",", ":")))
            return 0
        if action in ("render", "events"):
            return render(report, events=action == "events")
        if action == "baseline":
            selected = report["api"].get("selected_node")
            explicit = os.environ.get("CLAUDE_WATCH_TAG_NODE")
            if (report["entry"]["state"] != "verified" or report["api"]["state"] != "available"
                    or not selected or (explicit and explicit != selected)):
                return 4
            # baseline is an explicit acceptance of the current selection, not reuse of a stale pin.
            for key, value in (("tag_group", report["expected_group"]), ("tag_node", selected)):
                if any(c in value for c in "\r\n"):
                    return 4
                print(key + "=" + value)
        elif action == "cli":
            if not report["cli"]["matches_7890"] or report["cli"].get("bypass_all"):
                return 4
            return 3 if report["cli"]["other_bypass_rules"] else 0
        elif action == "alert-key":
            policies = sorted(set(flow["policy"] for flow in report["flows"]))
            print("|".join((report["entry"]["state"], report["api"]["state"], str(report["api"].get("covers_7890")), str(report["api"].get("mode")), str(report["selection_changed"]), ",".join(policies))))
        else:
            return 4
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("[未确认] TAG 检查内部错误；未改变代理配置。", file=sys.stderr)
        sys.exit(4)

PY_TAG
}


tag_collect() {
  local target_file='-' connection_file='-' collector_status='-'
  [[ $# -lt 1 ]] || target_file=$1
  [[ $# -lt 2 ]] || connection_file=$2
  [[ $# -lt 3 ]] || collector_status=$3
  init_scan_tmp
  if ! tag_bridge collect "$target_file" "$connection_file" "$BASELINE_FILE" "$collector_status" > "$TMP_SCAN/tag-report.json"; then
    say '[未确认] 无法生成 TAG 入口/代理链报告。'
    return 4
  fi
}
tag_preflight() {
  local rc=0
  tag_collect || return 4
  tag_bridge render "$TMP_SCAN/tag-report.json" || rc=$?
  case "$rc" in 0|3) ;; *) rc=4;; esac
  return "$rc"
}
proxy_check() {
  require_macos
  [[ $# == 0 ]] || fail 'proxy-check 不接受额外参数；预期分组/节点见 README'
  scan_targets || fail '无法读取进程，不能核对代理归属'
  local csv rc=0
  csv=$(target_csv)
  if ! connection_sample "$csv" "$TMP_SCAN/connection-observation.json" > "$TMP_SCAN/connections"; then
    say '[未确认] 无法获取 Claude 连接样本，入口检查仍可显示。'
    rc=3
    : > "$TMP_SCAN/connections"
  fi
  tag_collect "$TMP_SCAN/targets" "$TMP_SCAN/connections" "$TMP_SCAN/connection-observation.json" || return 4
  tag_bridge render "$TMP_SCAN/tag-report.json" || rc=$?
  return "$rc"
}
publish_proxy_snapshot() {
  # The UI must consume the daemon's evidence, not repeat the privileged OS query
  # in an application subprocess where macOS can return a filtered empty table.
  local source=$1 snapshot=''
  if [[ "$source" != '-' && -f "$source" ]]; then
    snapshot=$(tag_bridge publish "$source" "$$" "$DAEMON_STAMP") || snapshot=''
  fi
  # Invalidate the previous sample immediately when collection/encoding fails.
  [[ -n "$snapshot" ]] || snapshot='{}'
  atomic_text "$STATE_DIR/proxy-snapshot.json" "$snapshot"
}
monitor_tag_proxy() {
  local rc=0 key line snapshot_source='-'
  if tag_collect "$TMP_SCAN/targets" "$TMP_SCAN/connections" "$TMP_SCAN/connection-observation.json"; then
    snapshot_source="$TMP_SCAN/tag-report.json"
    tag_bridge events "$TMP_SCAN/tag-report.json" > "$TMP_SCAN/tag-events" || rc=$?
    key=$(tag_bridge alert-key "$TMP_SCAN/tag-report.json") || key=unavailable
  else
    rc=4; key=unavailable
    printf '%s\n' 'TAG 入口/代理链检查不可用，原有进程和连接监控继续。' > "$TMP_SCAN/tag-events"
  fi
  publish_proxy_snapshot "$snapshot_source" || log_event 'proxy-snapshot-publish-failed'
  [[ -f "$TMP_SCAN/tag-events-prev" ]] || : > "$TMP_SCAN/tag-events-prev"
  sort -u "$TMP_SCAN/tag-events" -o "$TMP_SCAN/tag-events"
  comm -13 "$TMP_SCAN/tag-events-prev" "$TMP_SCAN/tag-events" > "$TMP_SCAN/tag-events-new"
  while IFS= read -r line; do log_event "tag-proxy $line"; done < "$TMP_SCAN/tag-events-new"
  cp "$TMP_SCAN/tag-events" "$TMP_SCAN/tag-events-prev"
  if [[ "$rc" != 0 && -s "$TMP_SCAN/targets" && "$LAST_TAG_ALERT" != "$key" ]]; then
    emit_alert 'Claude Watch：代理入口或代理链需核对' '7890 入口、实际代理链或预期节点尚未通过核对。请查看 proxy-check / audit；未自动改动 TAG。'
    LAST_TAG_ALERT=$key
  elif [[ "$rc" == 0 ]]; then LAST_TAG_ALERT=''; fi
  return 0
}


is_code_path() {
  case "$1" in
    "$HOME"/.local/bin/claude|"$HOME"/.claude/local/claude|"$HOME"/.local/share/claude/versions/*|\
    /opt/homebrew/bin/claude|/usr/local/bin/claude|\
    */node_modules/@anthropic-ai/claude-code/cli.js)
      return 0 ;;
  esac
  return 1
}

is_codex_cli_path() {
  case "$1" in
    /opt/homebrew/bin/codex|/usr/local/bin/codex|\
    /opt/homebrew/Caskroom/codex/*/bin/codex|/usr/local/Caskroom/codex/*/bin/codex|\
    */Caskroom/codex/*/bin/codex|\
    "$HOME"/*/node_modules/@openai/codex/bin/codex.js|\
    */node_modules/@openai/codex/bin/codex.js|\
    /Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex|\
    /Applications/ChatGPT.app/Contents/Resources/CodexCLI.app/Contents/MacOS/codex|\
    /Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex)
      return 0 ;;
  esac
  return 1
}

next_command_token() {
  trim "$1"
  COMMAND_TOKEN=${TRIMMED%%[[:space:]]*}
  if [[ "$TRIMMED" == *[[:space:]]* ]]; then COMMAND_REST=${TRIMMED#"$COMMAND_TOKEN"}; else COMMAND_REST=''; fi
}

is_codex_node_command() {
  # Do not treat a trusted-looking path in an arbitrary argument as execution.
  # This deliberately accepts only an unquoted, whitespace-free script entry
  # after the node executable and a short allowlist of non-executing flags.
  local remaining=$1 token
  next_command_token "$remaining"; token=$COMMAND_TOKEN; remaining=$COMMAND_REST
  case "${token##*/}" in node|nodejs) ;; *) return 1;; esac
  while :; do
    next_command_token "$remaining"; token=$COMMAND_TOKEN; remaining=$COMMAND_REST
    [[ -n "$token" ]] || return 1
    case "$token" in
      --) next_command_token "$remaining"; is_codex_cli_path "$COMMAND_TOKEN"; return;;
      --no-warnings|--enable-source-maps|--experimental-*|--trace-*|--disable-warning=*|--watch-preserve-output) ;;
      --require|--import|--conditions|--loader) next_command_token "$remaining"; [[ -n "$COMMAND_TOKEN" ]] || return 1;;
      --require=*|--import=*|--conditions=*|--loader=*) ;;
      -*) return 1;;
      *) is_codex_cli_path "$token"; return;;
    esac
  done
}

bundle_from_executable_path() {
  local value=$1 prefix
  case "$value" in
    *.app/Contents/*)
      prefix=${value%%.app/Contents/*}
      printf '%s.app\n' "$prefix"
      ;;
    *) return 1 ;;
  esac
}

bundle_identifier() {
  local bundle=$1 plist cached
  if [[ -n "$TMP_SCAN" && -f "$TMP_SCAN/bundle-identifiers" ]]; then
    cached=$(awk -F'|' -v b="$bundle" '$1==b {print $2; exit}' "$TMP_SCAN/bundle-identifiers")
    [[ -z "$cached" ]] || { printf '%s\n' "$cached"; return 0; }
  fi
  plist="$bundle/Contents/Info.plist"
  [[ -f "$plist" && ! -L "$plist" ]] || return 1
  cached=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$plist" 2>/dev/null) || return 1
  case "$cached" in com.openai.codex|com.openai.chat) ;; *) return 1;; esac
  if [[ -n "$TMP_SCAN" && -d "$TMP_SCAN" ]]; then printf '%s|%s\n' "$bundle" "$cached" >> "$TMP_SCAN/bundle-identifiers"; fi
  printf '%s\n' "$cached"
}

desktop_provider_for_bundle() {
  local bundle=$1 bundle_id base
  bundle_id=$(bundle_identifier "$bundle") || return 1
  base=${bundle##*/}; base=${base%.app}
  case "$bundle_id:$base" in
    com.openai.codex:Codex) printf 'codex\n' ;;
    com.openai.chat:ChatGPT) printf 'chatgpt\n' ;;
    com.openai.codex:ChatGPT) printf 'openai\n' ;;
    *) return 1 ;;
  esac
}

desktop_class_for_path() {
  local path=$1 bundle provider
  bundle=$(bundle_from_executable_path "$path") || return 1
  provider=$(desktop_provider_for_bundle "$bundle") || return 1
  case "$path" in
    "$bundle"/Contents/MacOS/*) printf '%s-desktop-main\n' "$provider" ;;
    "$bundle"/Contents/*) printf '%s-desktop-helper\n' "$provider" ;;
    *) return 1 ;;
  esac
}

provider_for_kind() {
  case "$1" in
    desktop-main|desktop-helper|code|child|launcher|claude-launcher) printf 'claude\n' ;;
    codex-desktop-main|codex-desktop-helper|codex-cli|codex-child|codex-launcher) printf 'codex\n' ;;
    chatgpt-desktop-main|chatgpt-desktop-helper|chatgpt-child|chatgpt-launcher) printf 'chatgpt\n' ;;
    openai-desktop-main|openai-desktop-helper|openai-child|openai-launcher) printf 'openai\n' ;;
    *) return 1 ;;
  esac
}

child_kind_for_parent() {
  case "$1" in
    codex-*) printf 'codex-child\n' ;;
    chatgpt-*) printf 'chatgpt-child\n' ;;
    openai-*) printf 'openai-child\n' ;;
    *) printf 'child\n' ;;
  esac
}

read_identity() {
  local pid=$1 process_uid comm cmd started state base first cached current
  CLASS=''; COMM=''; START=''
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  [[ "$pid" != "$$" && "$pid" != "$PPID" ]] || return 1
  # scan_targets has already captured UID, executable and start time together.
  # Reuse that short-lived identity snapshot so a busy Codex process tree does
  # not cause five ps calls per helper; re-read state and command together to
  # ensure the PID is still present and is not a zombie before classifying it.
  if [[ -n "$TMP_SCAN" && -f "$TMP_SCAN/processes" ]]; then
    cached=$(awk -F'|' -v p="$pid" '$1==p {print $2 "\034" $4; exit}' "$TMP_SCAN/processes")
  fi
  if [[ -n "$cached" ]]; then
    started=${cached%%$'\034'*}; comm=${cached#*$'\034'}
    current=$(ps -ww -p "$pid" -o stat= -o command= 2>/dev/null) || return 1
    trim "$current"; current=$TRIMMED
    state=${current%%[[:space:]]*}; cmd=${current#"$state"}; trim "$cmd"; cmd=$TRIMMED
    process_uid=$CURRENT_UID
  else
    process_uid=$(ps -p "$pid" -o uid= 2>/dev/null) || return 1
    trim "$process_uid"; process_uid=$TRIMMED
    [[ "$process_uid" == "$CURRENT_UID" ]] || return 1
    comm=$(ps -p "$pid" -o comm= 2>/dev/null) || return 1
    cmd=$(ps -ww -p "$pid" -o command= 2>/dev/null) || return 1
    started=$(ps -p "$pid" -o lstart= 2>/dev/null) || return 1
    state=$(ps -p "$pid" -o stat= 2>/dev/null) || return 1
  fi
  trim "$comm"; comm=$TRIMMED
  trim "$cmd"; cmd=$TRIMMED
  trim "$started"; started=$TRIMMED
  trim "$state"; state=$TRIMMED
  [[ -n "$comm" && -n "$cmd" && -n "$started" && "$state" != Z* ]] || return 1
  base=${comm##*/}
  first=${cmd%% *}

  # 忽略监控器本身及其通知辅助进程，避免自我触发误报。
  case "$comm" in */bash|*/sh|*/zsh|bash|sh|zsh)
    case "$cmd" in "/bin/bash $INSTALLED_SCRIPT "*|"/bin/bash ${BASH_SOURCE[0]} "*) return 1;; esac;;
  esac
  if [[ "$comm" == *'/Claude.app/Contents/MacOS/Claude' ]]; then
    CLASS='desktop-main'
  elif [[ "$comm" == *'/Claude.app/Contents/'* ]]; then
    CLASS='desktop-helper'
  elif [[ "$base" == 'Claude' && ( "$cmd" == *'/Claude.app/Contents/MacOS/Claude' || "$cmd" == *'/Claude.app/Contents/MacOS/Claude '* ) ]]; then
    CLASS='desktop-main'
  elif [[ "$base" == 'Claude Helper'* && "$cmd" == *'/Claude.app/Contents/Frameworks/'* ]]; then
    CLASS='desktop-helper'
  elif is_code_path "$comm"; then
    CLASS='code'
  elif [[ "$base" == 'claude' ]] && is_code_path "$first"; then
    CLASS='code'
  elif [[ ( "$base" == 'node' || "$base" == 'nodejs' ) && "$cmd" == *'/@anthropic-ai/claude-code/cli.js'* ]]; then
    CLASS='code'
  elif is_codex_cli_path "$comm"; then
    CLASS='codex-cli'
  elif [[ "$base" == 'codex' ]] && is_codex_cli_path "$first"; then
    CLASS='codex-cli'
  elif [[ "$base" == 'node' || "$base" == 'nodejs' ]] && is_codex_node_command "$cmd"; then
    CLASS='codex-cli'
  elif CLASS=$(desktop_class_for_path "$comm" 2>/dev/null); then
    :
  else
    CLASS='unknown'
  fi
  COMM=$comm
  START=$(printf '%s\n' "$started" | normalize_stamp)
  return 0
}

init_scan_tmp() {
  if [[ -z "$TMP_SCAN" ]]; then
    TMP_SCAN=$(mktemp -d "${TMPDIR:-/tmp}/claude-watch.XXXXXXXX") || fail '创建临时扫描目录失败。'
  fi
}

cleanup_scan_tmp() {
  if [[ -n "$TMP_SCAN" && -d "$TMP_SCAN" ]]; then
    rm -f "$TMP_SCAN"/*
    rmdir "$TMP_SCAN" 2>/dev/null || true
  fi
}

process_confirmed_exited_since_snapshot() {
  # A pgrep candidate can normally exit between the bulk ps snapshot and the
  # identity reread.  Only BSD ps's exact "no such PID" shape is safe to
  # ignore; permission/read failures remain incomplete and fail closed.
  local pid=$1 current rc error
  [[ "$pid" =~ ^[0-9]+$ && -n "$TMP_SCAN" ]] || return 1
  error="$TMP_SCAN/identity-absent-${pid}.err"
  current=$(ps -p "$pid" -o pid= 2> "$error")
  rc=$?
  [[ "$rc" -eq 1 && -z "$current" && ! -s "$error" ]]
}

scan_targets() {
  local rc pid line stamp kind file sk root rs owner os created candidate_comm
  SCAN_DESKTOP=0
  SCAN_CODE=0
  SCAN_DESKTOP_PID=''
  SCAN_CODE_PID=''
  SCAN_DESKTOP_COUNT=0
  SCAN_CODE_COUNT=0
  SCAN_UNKNOWN_COUNT=0
  SCAN_CODEX_DESKTOP_COUNT=0
  SCAN_CODEX_CLI_COUNT=0
  SCAN_CHATGPT_DESKTOP_COUNT=0
  SCAN_OPENAI_DESKTOP_COUNT=0
  SCAN_INCOMPLETE=0
  init_scan_tmp
  # Only process metadata; never write complete command lines to disk.
  if ! ps -axo pid=,ppid=,uid=,lstart=,comm= > "$TMP_SCAN/ps" 2> "$TMP_SCAN/errors"; then return 1; fi
  awk -v uid="$CURRENT_UID" '$3==uid && NF>=9 {p=$1;pp=$2;s=$4 " " $5 " " $6 " " $7 " " $8;for(i=1;i<=8;i++) $i="";sub(/^[[:space:]]+/,"");print p "|" s "|" pp "|" $0}' "$TMP_SCAN/ps" > "$TMP_SCAN/processes"
  [[ -s "$TMP_SCAN/processes" ]] || return 1
  : > "$TMP_SCAN/known"
  # pgrep is only a candidate filter. -a includes ancestor processes: when
  # this watch is invoked inside Codex, its own desktop parent must still be
  # observed. read_identity excludes this script's own PID/PPID and requires a
  # known executable path and, for desktop bundles, a matching outer bundle ID.
  if pgrep -a -f -i -u "$CURRENT_UID" 'claude|anthropic|codex|chatgpt|openai' > "$TMP_SCAN/pids" 2> "$TMP_SCAN/errors"; then
    :
  else
    rc=$?
    [[ "$rc" -eq 1 ]] || return 1
  fi
  while IFS= read -r pid; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    [[ "$pid" != "$$" && "$pid" != "$PPID" ]] || continue
    if ! read_identity "$pid"; then
      # A process that has definitely exited after the bulk snapshot is not a
      # sampling failure.  Do not treat permission errors, malformed output or
      # a still-live/reused PID as an exit.
      process_confirmed_exited_since_snapshot "$pid" && continue
      candidate_comm=$(awk -F'|' -v p="$pid" '$1==p {print $4;exit}' "$TMP_SCAN/processes")
      case "$candidate_comm" in
        *'/Claude.app/Contents/'*|*/claude|claude|*'/.local/share/claude/versions/'*|\
        *'/Codex.app/Contents/'*|*'/ChatGPT.app/Contents/'*|*/codex|codex)
          SCAN_INCOMPLETE=1;;
      esac
      continue
    fi
    case "$CLASS" in
      desktop-main|desktop-helper|code|\
      codex-desktop-main|codex-desktop-helper|codex-cli|\
      chatgpt-desktop-main|chatgpt-desktop-helper|\
      openai-desktop-main|openai-desktop-helper)
        printf '%s|%s|%s\n' "$pid" "$START" "$CLASS" >> "$TMP_SCAN/known";;
      unknown)
        SCAN_UNKNOWN_COUNT=$((SCAN_UNKNOWN_COUNT + 1))
        ;;
    esac
  done < "$TMP_SCAN/pids"
  # A CLI lease is created before executing the child, avoiding a scan/registration race.
  # Its wrapper is an identity anchor, not a Claude process to sample.
  for file in "$SESSION_DIR"/*.session; do
    [[ -f "$file" ]] || continue
    if session_valid "$file"; then
      IFS='|' read -r sk provider root rs owner os created < "$file"
      # Version 2.1 sessions did not have a provider field. They remain Claude-only.
      if [[ "$provider" =~ ^[0-9]+$ ]]; then
        created=$os; os=$owner; owner=$rs; rs=$root; root=$provider; provider=claude
      fi
      if [[ "$sk" == cli ]]; then printf '%s|%s|%s-launcher\n' "$root" "$rs" "$provider" >> "$TMP_SCAN/known"; fi
    fi
  done
  # Keep previously observed descendants after reparenting, checking PID + start time.
  if [[ -f "$TRACKED_FILE" && ! -L "$TRACKED_FILE" ]]; then cat "$TRACKED_FILE" >> "$TMP_SCAN/known"; fi
  # Include shell/curl/Python children even if their names do not contain Claude.
  awk -F'|' 'NR==FNR {st[$1]=$2;par[$1]=$3;next}
    function child_kind(parent) {if(parent ~ /^codex-/) return "codex-child"; if(parent ~ /^chatgpt-/) return "chatgpt-child"; if(parent ~ /^openai-/) return "openai-child"; return "child"}
    $1 ~ /^[0-9]+$/ && ($1 in st) && st[$1]==$2 && $3 ~ /^(desktop-main|desktop-helper|code|child|launcher|claude-launcher|codex-desktop-main|codex-desktop-helper|codex-cli|codex-child|codex-launcher|chatgpt-desktop-main|chatgpt-desktop-helper|chatgpt-child|chatgpt-launcher|openai-desktop-main|openai-desktop-helper|openai-child|openai-launcher)$/ {kind[$1]=$3}
    END {
      # The bundled Codex CLI inside a verified desktop bundle is a component
      # of that desktop session. The identical binary started from a terminal
      # has no verified desktop ancestor and remains an independent codex-cli.
      for(p in kind) if(kind[p]=="codex-cli") {q=par[p];for(depth=0;depth<64 && q in st;depth++){if(q in kind && kind[q] ~ /^(codex|chatgpt|openai)-desktop-(main|helper)$/){kind[p]=child_kind(kind[q]);break}if(!(q in par) || par[q]==q)break;q=par[q]}}
      for(round=0;round<64;round++){changed=0;for(p in st) if(!(p in kind) && (par[p] in kind)){kind[p]=child_kind(kind[par[p]]);changed=1}if(!changed)break}
      for(p in kind) if(kind[p]!="launcher" && kind[p] !~ /-launcher$/) print p "|" st[p] "|" kind[p]}' "$TMP_SCAN/processes" "$TMP_SCAN/known" | sort -u > "$TMP_SCAN/targets"
  while IFS='|' read -r pid stamp kind; do
    case "$kind" in
      desktop-main|desktop-helper) SCAN_DESKTOP=1; SCAN_DESKTOP_COUNT=$((SCAN_DESKTOP_COUNT+1)); [[ -n "$SCAN_DESKTOP_PID" ]] || SCAN_DESKTOP_PID=$pid;;
      code) SCAN_CODE=1; SCAN_CODE_COUNT=$((SCAN_CODE_COUNT+1)); [[ -n "$SCAN_CODE_PID" ]] || SCAN_CODE_PID=$pid;;
      codex-desktop-main|codex-desktop-helper) SCAN_CODEX_DESKTOP_COUNT=$((SCAN_CODEX_DESKTOP_COUNT+1));;
      codex-cli) SCAN_CODEX_CLI_COUNT=$((SCAN_CODEX_CLI_COUNT+1));;
      chatgpt-desktop-main|chatgpt-desktop-helper) SCAN_CHATGPT_DESKTOP_COUNT=$((SCAN_CHATGPT_DESKTOP_COUNT+1));;
      openai-desktop-main|openai-desktop-helper) SCAN_OPENAI_DESKTOP_COUNT=$((SCAN_OPENAI_DESKTOP_COUNT+1));;
    esac
  done < "$TMP_SCAN/targets"
  classify_authorization
  return 0
}

snapshot_identity_matches() {
  [[ "$1" =~ ^[0-9]+$ && -n "$2" ]] || return 1
  awk -F'|' -v p="$1" -v s="$2" '$1==p && $2==s {found=1} END {exit !found}' "$TMP_SCAN/processes"
}
session_valid() {
  local file=$1 kind provider root stamp owner ownerstamp created
  [[ -f "$file" && ! -L "$file" ]] || return 1
  IFS='|' read -r kind provider root stamp owner ownerstamp created < "$file" || return 1
  # 2.1 six-field records are retained as Claude sessions only.
  if [[ "$provider" =~ ^[0-9]+$ ]]; then
    created=$ownerstamp; ownerstamp=$owner; owner=$stamp; stamp=$root; root=$provider; provider=claude
  fi
  [[ "$kind" == desktop || "$kind" == cli ]] || return 1
  case "$provider" in claude|codex|chatgpt|openai) ;; *) return 1;; esac
  snapshot_identity_matches "$root" "$stamp" || return 1
  if [[ "$kind" == cli ]]; then snapshot_identity_matches "$owner" "$ownerstamp" || return 1; fi
  return 0
}
is_snapshot_descendant() {
  awk -F'|' -v child="$1" -v root="$2" '{parent[$1]=$3}
    END {for(i=0;i<64 && child>1;i++){if(child==root)exit 0;if(!(child in parent) || parent[child]==child)exit 1;child=parent[child]}exit 1}' "$TMP_SCAN/processes"
}
classify_authorization() {
  local file pid stamp kind target_provider sk provider root rs owner os created authorized
  ACTIVE_PIDS=''; UNAUTHORIZED_PIDS=''; MONITOR_MODE=GUARD
  : > "$TMP_SCAN/valid-sessions"
  for file in "$SESSION_DIR"/*.session; do
    [[ -f "$file" ]] || continue
    if session_valid "$file"; then
      IFS='|' read -r sk provider root rs owner os created < "$file"
      if [[ "$provider" =~ ^[0-9]+$ ]]; then
        created=$os; os=$owner; owner=$rs; rs=$root; root=$provider; provider=claude
      fi
      printf '%s|%s|%s|%s|%s|%s|%s\n' "$sk" "$provider" "$root" "$rs" "$owner" "$os" "$created" >> "$TMP_SCAN/valid-sessions"
    fi
  done
  : > "$TMP_SCAN/unauthorized"
  while IFS='|' read -r pid stamp kind; do
    authorized=0
    target_provider=$(provider_for_kind "$kind" || true)
    while IFS='|' read -r sk provider root rs owner os created; do
      if [[ "$target_provider" == "$provider" ]] && is_snapshot_descendant "$pid" "$root"; then authorized=1; break; fi
    done < "$TMP_SCAN/valid-sessions"
    if [[ "$authorized" == 1 ]]; then ACTIVE_PIDS="${ACTIVE_PIDS} ${pid}"; MONITOR_MODE=ACTIVE
    else UNAUTHORIZED_PIDS="${UNAUTHORIZED_PIDS} ${pid}"; printf '%s|%s|%s\n' "$pid" "$stamp" "$kind" >> "$TMP_SCAN/unauthorized"; fi
  done < "$TMP_SCAN/targets"
  sort -u "$TMP_SCAN/unauthorized" -o "$TMP_SCAN/unauthorized"
}
check_health() {
  local data pid state hp hs epoch quality mode now stamp
  HEALTH=STOPPED; HEALTH_REASON='未加载'
  if ! data=$(launchctl print "$DOMAIN/$LABEL" 2>/dev/null); then return 0; fi
  pid=$(printf '%s\n' "$data" | awk '$1=="pid" && $2=="=" {print $3;exit}')
  state=$(printf '%s\n' "$data" | awk '$1=="state" && $2=="=" {print $3;exit}')
  HEALTH=DEGRADED; HEALTH_REASON='已加载，但进程或心跳不可验证'
  [[ "$state" == running && "$pid" =~ ^[0-9]+$ && -r "$HEARTBEAT_FILE" && ! -L "$HEARTBEAT_FILE" ]] || return 0
  IFS='|' read -r hp hs epoch quality mode < "$HEARTBEAT_FILE" || return 0
  [[ "$hp" == "$pid" && "$epoch" =~ ^[0-9]{1,10}$ ]] || return 0
  stamp=$(process_stamp "$pid") || return 0
  [[ -n "$stamp" && "$hs" == "$stamp" ]] || return 0
  now=$(date +%s)
  [[ "$now" -ge "$epoch" && $((now-epoch)) -le "$HEALTH_MAX_AGE" ]] || { HEALTH_REASON='监控心跳已过期'; return 0; }
  [[ "$quality" == ok ]] || { HEALTH_REASON='采样不完整或出现错误'; return 0; }
  HEALTH=RUNNING; HEALTH_REASON='进程存活且最近采样心跳有效'
}
pending_launch_live() {
  local pid stamp epoch now
  [[ -r "$PENDING_FILE" && ! -L "$PENDING_FILE" ]] || return 1
  IFS='|' read -r pid stamp epoch < "$PENDING_FILE" || return 1
  [[ "$epoch" =~ ^[0-9]{1,10}$ ]] || return 1
  now=$(date +%s)
  [[ "$now" -ge "$epoch" && $((now-epoch)) -lt 15 ]] || return 1
  snapshot_identity_matches "$pid" "$stamp"
}
notifications_enabled() {
  local mode until now
  mode=$(read_mode)
  case "$mode" in
    paused) return 1;;
    until:*) until=${mode#until:}; now=$(date +%s); [[ "$until" =~ ^[0-9]+$ && "$now" -ge "$until" ]]; return;;
    *) return 0;;
  esac
}

alert_user() {
  # 在后台子进程中移除继承的退出 trap，不删除主监控器的临时扫描目录。
  trap - EXIT TERM INT
  # 只在发起此次告警的警戒会话仍有效时通知；用户暂停后取消排队提醒。
  local title=$1 message=$2 session=$3
  [[ "$(read_mode)" == "$session" ]] || return 0
  if ! command -v osascript >/dev/null 2>&1; then
    log_event 'alert-failed osascript-unavailable'
    return 1
  fi
  # 自动告警只发静音 Notification Center 通知，不显示阻塞对话框。
  # 文本作为 argv 传入，绝不拼接到 AppleScript 源码，避免转义/注入问题。
  if osascript \
    -e 'on run argv' \
    -e 'set titleText to item 1 of argv as text' \
    -e 'set messageText to item 2 of argv as text' \
    -e 'display notification messageText with title titleText' \
    -e 'end run' \
    -- "$title" "$message" >/dev/null 2>&1; then
    log_event 'alert-dispatched'
  else
    log_event 'alert-failed osascript'
    return 1
  fi
}

alert_cooldown_seconds() {
  case "$1" in *监控失效*|*采样失效*) printf '600\n';; *) printf '300\n';; esac
}

alert_cooldown_key() { printf '%s' "$1" | shasum -a 256 | awk '{print $1}'; }

alert_cooldown_allows() {
  local title=$1 key now last window file="$STATE_DIR/alert-cooldowns"
  key=$(alert_cooldown_key "$title") || return 0
  now=$(date +%s); window=$(alert_cooldown_seconds "$title")
  [[ -f "$file" && ! -L "$file" ]] || return 0
  last=$(awk -F '\t' -v k="$key" '$1==k && $2 ~ /^[0-9]+$/ {print $2; exit}' "$file")
  [[ "$last" =~ ^[0-9]+$ && "$now" -ge "$last" && $((now-last)) -lt "$window" ]] && return 1
  return 0
}

record_alert_cooldown() {
  local title=$1 key now temp file="$STATE_DIR/alert-cooldowns"
  key=$(alert_cooldown_key "$title") || return 1
  now=$(date +%s)
  [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] || return 1
  temp=$(mktemp "$STATE_DIR/.alert-cooldown.XXXXXXXX") || return 1
  if [[ -f "$file" && ! -L "$file" ]]; then
    awk -F '\t' -v k="$key" '$1!=k && $1 ~ /^[0-9a-f]{64}$/ && $2 ~ /^[0-9]+$/ {print}' "$file" > "$temp"
  fi
  printf '%s\t%s\n' "$key" "$now" >> "$temp"
  chmod 600 "$temp" && mv -f "$temp" "$file"
}

alert_severity() {
  case "$1" in
    *警戒期间网络端点*) printf 'info\n' ;;
    *监控失效*|*采样失效*) printf 'critical\n' ;;
    *) printf 'warning\n' ;;
  esac
}

critical_alert_user() {
  # This always runs in a background subshell: a confirmation dialog must not
  # delay the daemon's next process or network sample.
  trap - EXIT TERM INT
  local title=$1 message=$2 session=$3
  [[ "$(read_mode)" == "$session" ]] || return 0
  if ! command -v osascript >/dev/null 2>&1; then
    log_event 'critical-alert-failed osascript-unavailable'
    return 1
  fi
  if osascript \
    -e 'on run argv' \
    -e 'set titleText to item 1 of argv as text' \
    -e 'set messageText to item 2 of argv as text' \
    -e 'display dialog messageText with title titleText buttons {"知道了"} default button "知道了" with icon caution' \
    -e 'end run' \
    -- "$title" "$message" >/dev/null 2>&1; then
    log_event 'critical-alert-dispatched'
  else
    log_event 'critical-alert-failed osascript'
    return 1
  fi
}

emit_alert() {
  local title=$1 message=$2 mode severity
  # Muted notifications must not consume a cooldown, so a meaningful alert can
  # be shown once the user restores notifications.
  notifications_enabled || return 0
  severity=$(alert_severity "$title")
  [[ "$severity" != info ]] || return 0
  alert_cooldown_allows "$title" || return 0
  mode=$(read_mode)
  if [[ "$severity" == critical ]]; then
    # Reserve the cooldown before forking so repeated daemon ticks cannot open
    # concurrent confirmation dialogs while the first one is still visible.
    if record_alert_cooldown "$title"; then
      ( critical_alert_user "$title" "$message" "$mode" || log_event 'critical-alert-dispatch-failed' ) &
    else
      log_event 'critical-alert-cooldown-record-failed'
    fi
  elif ( alert_user "$title" "$message" "$mode" ); then
    record_alert_cooldown "$title" || log_event 'alert-cooldown-record-failed'
  fi
  return 0
}
target_csv() { awk -F'|' '{print $1}' "$TMP_SCAN/targets" | paste -sd, -; }
connection_sample() {
  local csv=$1 receipt=${2:-} rc=0 round_id now target_count parsed_count
  now=$(date +%s)
  round_id="$$-${now}-${RANDOM}-${SECONDS}"
  target_count=$(printf '%s' "$csv" | awk -F, 'NF {for(i=1;i<=NF;i++) if($i ~ /^[0-9]+$/) n++} END {print n+0}')
  connection_receipt() {
    [[ -n "$receipt" ]] || return 0
    atomic_text "$receipt" "{\"schema\":1,\"round_id\":\"${round_id}\",\"observed_at\":${now},\"collector_state\":\"$1\",\"target_count\":${target_count},\"parsed_count\":${2},\"accepted_count\":${3},\"correlated_count\":0,\"unconfirmed_count\":0,\"dropped\":{},\"detail\":\"$4\"}"
  }
  if [[ -z "$csv" ]]; then
    connection_receipt no_targets 0 0 '没有受监控目标进程；未运行 lsof'
    return 0
  fi
  lsof -nP -a -p "$csv" -i -FpfPnT > "$TMP_SCAN/lsof-net" 2> "$TMP_SCAN/lsof-net-errors" || rc=$?
  # Exit 1 without diagnostics is also used for no visible sockets. It is not proof of no traffic.
  if [[ "$rc" -gt 1 || -s "$TMP_SCAN/lsof-net-errors" ]]; then
    connection_receipt failed 0 0 'lsof 无法读取连接样本'
    return 1
  fi
  if ! awk '/^p[0-9]+$/ {p=substr($0,2)} /^f/ {proto="?"} /^P/ {proto=substr($0,2)} /^n/ {print p "|" proto "|" substr($0,2)}' "$TMP_SCAN/lsof-net" | sort -u > "$TMP_SCAN/connections-sampled"; then
    connection_receipt failed 0 0 '连接样本解析管道未完成'
    return 1
  fi
  parsed_count=$(awk -F'|' 'NF == 3 && $1 ~ /^[0-9]+$/ && index($3, "->") {n++} END {print n+0}' "$TMP_SCAN/connections-sampled")
  if [[ "$parsed_count" == 0 ]]; then
    connection_receipt empty 0 0 '本轮未显示已连接套接字；监听或未连接描述符不计入路径，不能证明没有网络活动'
  else
    connection_receipt ok "$parsed_count" "$parsed_count" 'lsof 已读取本轮可见套接字'
  fi
  if ! cat "$TMP_SCAN/connections-sampled"; then
    connection_receipt failed 0 0 '连接样本输出未完成'
    return 1
  fi
}
file_sample() {
  local csv=$1 rc=0
  [[ -n "$csv" ]] || return 0
  lsof -nP -a -p "$csv" -Fpfan > "$TMP_SCAN/lsof-files" 2> "$TMP_SCAN/lsof-files-errors" || rc=$?
  if [[ "$rc" -gt 1 || -s "$TMP_SCAN/lsof-files-errors" ]]; then return 1; fi
  awk -v home="$HOME" '/^p[0-9]+$/ {p=substr($0,2)} /^f/ {fd=substr($0,2);access="?"} /^a/ {access=substr($0,2)}
    /^n/ && fd ~ /^[0-9]+$/ {n=substr($0,2);cat="";
      if(index(n,home "/.ssh/")==1)cat="SSH";else if(index(n,home "/.aws/")==1)cat="AWS";
      else if(index(n,home "/.gnupg/")==1)cat="GPG";else if(index(n,home "/Desktop/")==1)cat="Desktop";
      else if(index(n,home "/Documents/")==1)cat="Documents";else if(index(n,home "/Downloads/")==1)cat="Downloads";
      else if(index(n,home "/Project/")==1)cat="Project";
      if(cat!="")print p "|" fd "|" access "|" cat}' "$TMP_SCAN/lsof-files" | sort -u
}
byte_sample() {
  local csv=$1 pid args=() rc=0 count=0 batch=0 raw
  [[ -n "$csv" ]] || return 0
  raw="$TMP_SCAN/nettop-bytes"
  : > "$raw"
  for pid in $(printf '%s' "$csv" | tr ',' ' '); do
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    args+=( -p "$pid" )
    count=$((count+1))
    if [[ "$count" -lt 20 ]]; then continue; fi
    batch=$((batch+1)); rc=0
    nettop -n -P -L 1 -x -J bytes_in,bytes_out "${args[@]}" > "$TMP_SCAN/nettop-${batch}" 2> "$TMP_SCAN/nettop-${batch}-errors" || rc=$?
    [[ "$rc" == 0 && ! -s "$TMP_SCAN/nettop-${batch}-errors" ]] || return 1
    # Parse by column name, not column position. The first two columns may be unnamed.
    # A valid empty batch means none of these PIDs had visible counters; it is
    # not a zero value and must not discard later batches with real counters.
    if ! awk -F, 'NR==1 {header=1;for(i=1;i<=NF;i++){if($i=="bytes_in")bi=i;if($i=="bytes_out")bo=i}if(!bi || !bo){bad=1;exit}next}
      bi && bo && $bi ~ /^[0-9]+$/ && $bo ~ /^[0-9]+$/ {for(i=1;i<bi;i++) if($i ~ /\.[0-9]+$/){p=$i;sub(/^.*\./,"",p);print p "|" $bi "|" $bo;found=1;break}}
      END {if(!header || bad)exit 1}' "$TMP_SCAN/nettop-${batch}" >> "$raw"; then return 1; fi
    args=(); count=0
  done
  if [[ "$count" -gt 0 ]]; then
    batch=$((batch+1)); rc=0
    nettop -n -P -L 1 -x -J bytes_in,bytes_out "${args[@]}" > "$TMP_SCAN/nettop-${batch}" 2> "$TMP_SCAN/nettop-${batch}-errors" || rc=$?
    [[ "$rc" == 0 && ! -s "$TMP_SCAN/nettop-${batch}-errors" ]] || return 1
    if ! awk -F, 'NR==1 {header=1;for(i=1;i<=NF;i++){if($i=="bytes_in")bi=i;if($i=="bytes_out")bo=i}if(!bi || !bo){bad=1;exit}next}
      bi && bo && $bi ~ /^[0-9]+$/ && $bo ~ /^[0-9]+$/ {for(i=1;i<bi;i++) if($i ~ /\.[0-9]+$/){p=$i;sub(/^.*\./,"",p);print p "|" $bi "|" $bo;found=1;break}}
      END {if(!header || bad)exit 1}' "$TMP_SCAN/nettop-${batch}" >> "$raw"; then return 1; fi
  fi
  [[ -s "$raw" ]] || return 1
  sort -u "$raw"
}
service_sample() {
  local pid label
  launchctl list > "$TMP_SCAN/services-raw" 2> "$TMP_SCAN/services-errors" || return 1
  awk 'NR>1 && $1 ~ /^[0-9]+$/ && tolower($3) ~ /claude|anthropic|codex|chatgpt|openai/ && $3 !~ /^io.local.claudewatch/ {print $1 "|" $3}' "$TMP_SCAN/services-raw" | sort -u > "$TMP_SCAN/services-candidates"
  while IFS='|' read -r pid label; do
    case " $ACTIVE_PIDS " in *" $pid "*) continue;; esac
    printf '%s|%s\n' "$pid" "$label"
  done < "$TMP_SCAN/services-candidates"
}
baseline_fingerprint() {
  printf '%s\n' "$(kv_get "$BASELINE_FILE" timezone)" "$(kv_get "$BASELINE_FILE" ipv4_route)" "$(kv_get "$BASELINE_FILE" ipv6_route)" "$(kv_get "$BASELINE_FILE" dns_sig)" "$(kv_get "$BASELINE_FILE" sys_proxy_sig)" | hash_text
}
monitor_tick() {
  local now csv file pid stamp kind line source new=0 pending=0 quality=ok unexpected_network=0
  now=$(date +%s)
  if ! scan_targets; then
    if [[ "${LAST_SCAN_ERROR:-0}" == 0 ]]; then log_event 'scan-failed'; emit_alert 'Claude Watch：监控失效' '进程扫描失败，无法确认 Claude 活动。'; fi
    LAST_SCAN_ERROR=1
    atomic_text "$HEARTBEAT_FILE" "$$|${DAEMON_STAMP}|${now}|error|UNKNOWN"
    return 0
  fi
  LAST_SCAN_ERROR=0
  [[ "$SCAN_INCOMPLETE" == 0 ]] || quality=error
  atomic_text "$TRACKED_FILE" "$(cat "$TMP_SCAN/targets")"
  for file in "$SESSION_DIR"/*.session; do
    [[ -f "$file" ]] || continue
    if [[ "$SCAN_INCOMPLETE" == 0 ]] && ! session_valid "$file"; then rm -f "$file"; log_event 'session-expired'; fi
  done
  [[ -f "$TMP_SCAN/unauthorized-prev" ]] || : > "$TMP_SCAN/unauthorized-prev"
  comm -13 "$TMP_SCAN/unauthorized-prev" "$TMP_SCAN/unauthorized" > "$TMP_SCAN/unauthorized-new"
  pending_launch_live && pending=1 || true
  # A bounded pending Desktop launch defers process popups only; never skips sampling.
  : > "$TMP_SCAN/unauthorized-alerted"
  while IFS='|' read -r pid stamp kind; do
    [[ -n "$pid" ]] || continue
    if [[ "$pending" == 1 ]]; then
      case "$kind" in desktop-main|desktop-helper|*-desktop-main|*-desktop-helper) continue;; esac
    fi
    log_event "unauthorized-process pid=${pid} started=${stamp} kind=${kind}"
    printf '%s|%s|%s\n' "$pid" "$stamp" "$kind" >> "$TMP_SCAN/unauthorized-alerted"
    new=1
  done < "$TMP_SCAN/unauthorized-new"
  if [[ "$new" == 1 ]]; then emit_alert 'Claude Watch：未授权进程' '发现新的 Claude、Codex 或 ChatGPT 相关进程。请查看 audit；不会自动终止进程。'; fi
  # Retain previously alerted live identities plus this tick; deferred identities remain new.
  comm -12 "$TMP_SCAN/unauthorized-prev" "$TMP_SCAN/unauthorized" > "$TMP_SCAN/unauthorized-kept"
  cat "$TMP_SCAN/unauthorized-kept" "$TMP_SCAN/unauthorized-alerted" | sort -u > "$TMP_SCAN/unauthorized-prev"
  if [[ "${LAST_MODE:-}" != "$MONITOR_MODE" ]]; then log_event "state=${MONITOR_MODE}"; LAST_MODE=$MONITOR_MODE; fi
  if [[ "$new" == 1 || $((now-${LAST_NET_TIME:-0})) -ge "$NETWORK_SECONDS" || "$now" -lt "${LAST_NET_TIME:-0}" ]]; then
    LAST_NET_TIME=$now
    csv=$(target_csv)
    [[ -f "$TMP_SCAN/connections-prev" ]] || : > "$TMP_SCAN/connections-prev"
    if connection_sample "$csv" "$TMP_SCAN/connection-observation.json" > "$TMP_SCAN/connections"; then
      comm -13 "$TMP_SCAN/connections-prev" "$TMP_SCAN/connections" > "$TMP_SCAN/connections-new"
      : > "$TMP_SCAN/connections-unexpected"
      while IFS='|' read -r pid kind line; do
        [[ -n "$pid" ]] || continue
        source=authorized; case " $UNAUTHORIZED_PIDS " in *" $pid "*) source=unauthorized;; esac
        log_event "connection scope=${source} pid=${pid} protocol=${kind} endpoints=${line}"
        if [[ "$source" == unauthorized ]]; then unexpected_network=1; printf '%s|%s|%s\n' "$pid" "$kind" "$line" >> "$TMP_SCAN/connections-unexpected"; fi
        if [[ "$line" =~ :(3478|5349|19302|19305)($|[^0-9]) ]]; then log_event "stun-turn-port-candidate pid=${pid}"; fi
      done < "$TMP_SCAN/connections-new"
      if [[ "$unexpected_network" == 1 ]]; then emit_alert 'Claude Watch：警戒期间网络端点' "未授权进程的新端点（PID|协议|IP:端口，最多显示 3 条）：
$(head -n 3 "$TMP_SCAN/connections-unexpected")
完整地址见日志。监听端点与连接均不证明上传了文件。"; fi
      cp "$TMP_SCAN/connections" "$TMP_SCAN/connections-prev"
    else quality=error; log_event 'connection-sample-unavailable'; fi
    if [[ -n "$csv" ]]; then
      if byte_sample "$csv" > "$TMP_SCAN/bytes"; then
        while IFS='|' read -r pid bytes_in bytes_out; do log_event "traffic-counter pid=${pid} bytes_in=${bytes_in} bytes_out=${bytes_out}"; done < "$TMP_SCAN/bytes"
      else quality=error; log_event 'traffic-counters-unavailable'; fi
    fi
    csv=$(printf '%s\n' "$UNAUTHORIZED_PIDS" | awk '{$1=$1;gsub(/ /,",");print}')
    [[ -f "$TMP_SCAN/files-prev" ]] || : > "$TMP_SCAN/files-prev"
    if file_sample "$csv" > "$TMP_SCAN/files"; then
      comm -13 "$TMP_SCAN/files-prev" "$TMP_SCAN/files" > "$TMP_SCAN/files-new"
      if [[ -s "$TMP_SCAN/files-new" ]]; then
        while IFS= read -r line; do log_event "sensitive-open-descriptor ${line}"; done < "$TMP_SCAN/files-new"
        emit_alert 'Claude Watch：敏感目录文件描述符' '未授权进程持有敏感目录文件描述符；这不是完整的文件读取记录。详情见 audit。'
      fi
      cp "$TMP_SCAN/files" "$TMP_SCAN/files-prev"
    else quality=error; log_event 'file-sample-unavailable'; fi
    [[ -f "$TMP_SCAN/services-prev" ]] || : > "$TMP_SCAN/services-prev"
    if service_sample > "$TMP_SCAN/services"; then
      comm -13 "$TMP_SCAN/services-prev" "$TMP_SCAN/services" > "$TMP_SCAN/services-new"
      if [[ -s "$TMP_SCAN/services-new" ]]; then
        while IFS= read -r line; do log_event "launchd-label-candidate ${line}"; done < "$TMP_SCAN/services-new"
        emit_alert 'Claude Watch：后台服务候选' '发现未经当前会话关联的 AI 应用标签服务；标签不能证明归属，请核对日志。'
      fi
      cp "$TMP_SCAN/services" "$TMP_SCAN/services-prev"
    else quality=error; log_event 'launchctl-list-unavailable'; fi
    collect_environment
    if [[ "$CURRENT_V4" == unavailable || "$CURRENT_V6" == unavailable || "$CURRENT_DNS" == unavailable ]]; then quality=error; fi
    if [[ "$MONITOR_MODE" == ACTIVE && -r "$BASELINE_FILE" ]]; then
      if [[ "$CURRENT_FINGERPRINT" != "$(baseline_fingerprint)" ]]; then
        if [[ "${LAST_DRIFT:-}" != "$CURRENT_FINGERPRINT" ]]; then
          log_event "environment-changed dns=${CURRENT_DNS} ipv4=${CURRENT_V4} ipv6=${CURRENT_V6}"
          emit_alert 'Claude Watch：网络环境变化' "DNS=${CURRENT_DNS}；IPv4=${CURRENT_V4}；请重新预检。不能据此判定泄漏。"
        fi
        LAST_DRIFT=$CURRENT_FINGERPRINT
      else LAST_DRIFT=''; fi
    fi
    monitor_tag_proxy
    # TAG errors are reported separately; they must not disable process/file guarding.
    # Sampling quality persists between slower network samples.
    LAST_NET_QUALITY=$quality
  fi
  [[ "${LAST_NET_QUALITY:-ok}" == ok ]] || quality=error
  atomic_text "$HEARTBEAT_FILE" "$$|${DAEMON_STAMP}|$(date +%s)|${quality}|${MONITOR_MODE}"
  # Protection runs on every process-poll cycle, independently of the slower
  # network inventory. At most one bounded guard request is in flight.
  if [[ -z "${SWITCHER_GUARD_PID:-}" ]] || ! kill -0 "$SWITCHER_GUARD_PID" 2>/dev/null; then
    switcher_run guard-tick >/dev/null 2>&1 &
    SWITCHER_GUARD_PID=$!
  fi
}
daemon_cleanup() {
  if [[ -n "${SWITCHER_GUARD_PID:-}" ]]; then
    kill "$SWITCHER_GUARD_PID" 2>/dev/null || true
    wait "$SWITCHER_GUARD_PID" 2>/dev/null || true
  fi
  cleanup_scan_tmp
  local owner
  owner=$(head -n 1 "$STATE_DIR/daemon.lock/owner" 2>/dev/null || true)
  if [[ "$owner" == "$$|${DAEMON_STAMP:-}" ]]; then
    rm -f "$STATE_DIR/daemon.lock/owner"
    rmdir "$STATE_DIR/daemon.lock" 2>/dev/null || true
  fi
}
daemon_loop() {
  require_macos; require_installed; init_dirs; init_scan_tmp
  DAEMON_STAMP=$(process_stamp "$$") || fail '无法读取守护进程身份'
  local oldpid oldstamp
  if ! mkdir "$STATE_DIR/daemon.lock" 2>/dev/null; then
    [[ ! -L "$STATE_DIR/daemon.lock" ]] || fail '监控锁异常'
    IFS='|' read -r oldpid oldstamp < "$STATE_DIR/daemon.lock/owner" || fail '监控锁不完整，请人工核对'
    [[ "$oldpid" =~ ^[0-9]+$ ]] || fail '监控锁无效'
    if [[ "$(process_stamp "$oldpid" || true)" == "$oldstamp" ]]; then fail '已有监控实例'; fi
    rm -f "$STATE_DIR/daemon.lock/owner"; rmdir "$STATE_DIR/daemon.lock" || fail '无法回收已失效的监控锁'
    mkdir "$STATE_DIR/daemon.lock" || fail '另一个监控实例正在启动'
  fi
  printf '%s|%s\n' "$$" "$DAEMON_STAMP" > "$STATE_DIR/daemon.lock/owner"
  trap daemon_cleanup EXIT
  trap 'log_event "daemon-stop signal=TERM"; exit 0' TERM
  trap 'log_event "daemon-stop signal=INT"; exit 0' INT
  log_event "daemon-start version=${VERSION} pid=$$"
  while :; do monitor_tick; sleep "$POLL_SECONDS"; done
}

show_status() {
  require_macos
  local mode
  say "版本：$VERSION"
  if [[ -f "$PLIST_FILE" && -f "$INSTALLED_SCRIPT" ]]; then
    say '安装：已安装'
  else
    say '安装：未安装'
  fi
  check_health
  say "监控健康：${HEALTH}（${HEALTH_REASON}）"
  mode=$(read_mode)
  case "$mode" in
    armed|armed:*) say '通知：开启' ;;
    paused) say '通知：静默；监控运行时仍继续采样' ;;
    until:*)
      if notifications_enabled; then say '通知：静默期已结束'; else say '通知：定时静默中，采样继续'; fi
      ;;
    *) say '通知：状态文件异常，监控运行时按开启处理';;
  esac
  if scan_targets; then
    say "Claude Desktop：${SCAN_DESKTOP_COUNT}；Claude Code：${SCAN_CODE_COUNT}；Codex Desktop：${SCAN_CODEX_DESKTOP_COUNT}；Codex CLI：${SCAN_CODEX_CLI_COUNT}；ChatGPT Desktop：${SCAN_CHATGPT_DESKTOP_COUNT}；共享 OpenAI 外壳：${SCAN_OPENAI_DESKTOP_COUNT}；其他候选：${SCAN_UNKNOWN_COUNT}"
    say "会话状态：${MONITOR_MODE}；授权 PID：${ACTIVE_PIDS:-无}；未授权 PID：${UNAUTHORIZED_PIDS:-无}"
    [[ "$HEALTH" == RUNNING ]] || say '[未有效监控] 以上仅是本次查询的会话分类，不代表后台正在保护。'
    [[ "$SCAN_INCOMPLETE" == 0 ]] || say '[未知] 部分进程身份无法读取。'
    say '独立后台服务/processWrapper：本版本未自动接入；无有效会话关联的进程不自动授权。'
  else
    printf '[Claude Watch] 警告：进程扫描失败，不能判断受监控应用是否在运行。\n' >&2
  fi
  say "日志：$EVENT_LOG"
  cleanup_scan_tmp
}

audit() {
  require_macos; scan_targets || fail '无法扫描进程'
  local csv collector_status="$TMP_SCAN/connection-observation.json"
  csv=$(target_csv)
  collect_environment; print_environment
  printf '\n进程身份 (PID|启动时间|类型):\n'; cat "$TMP_SCAN/targets"
  if [[ -n "$csv" ]]; then
    printf '\n连接 (PID|协议|本地与远端 IP:端口):\n'
    if connection_sample "$csv" "$collector_status" > "$TMP_SCAN/connections"; then cat "$TMP_SCAN/connections"
    else say '[未知] 连接采样失败'; : > "$TMP_SCAN/connections"; fi
    printf '\n流量累计计数 (PID|接收字节|发送字节):\n'
    byte_sample "$csv" || say '[未知] nettop 计数不可用，未估算上传量'
    printf '\n敏感文件描述符 (PID|FD|访问模式|类别，不是读取记录):\n'
    file_sample "$csv" || say '[未知] 文件描述符不可见'
  else
    say '本次未识别到 Claude、Codex 或 ChatGPT 相关进程。'
    connection_sample '' "$collector_status" > "$TMP_SCAN/connections" || :
  fi
  if tag_collect "$TMP_SCAN/targets" "$TMP_SCAN/connections" "$collector_status"; then tag_bridge render "$TMP_SCAN/tag-report.json" || true; fi
  say '空采样不证明没有网络通信或文件读取。'
}
preflight_for_launch() {
  local allow=$1 scope=${2:-general} provider=${3:-claude} rc=0 cli_rc=0
  check_health
  [[ "$HEALTH" == RUNNING ]] || fail "监控没有有效运行：${HEALTH_REASON}。本次不启动 Claude。"
  if [[ "$provider" == claude && "$scope" != cli ]]; then
    switcher_run check --online --require-ready || fail '统一环境预检未通过，已取消启动；不会回退到旧规则'
    check_health
    [[ "$HEALTH" == RUNNING ]] || fail '预检期间监控失效，已取消启动'
    return 0
  fi
  preflight || rc=$?
  [[ "$rc" != 4 ]] || fail '预检关键条件失败，已取消启动'
  if [[ "$rc" == 3 && "$allow" != yes ]]; then fail '预检存在变化或未知，已取消启动；确认本次变化后可用 --allow-changes'; fi
  [[ "$rc" == 0 || "$rc" == 3 ]] || fail '预检执行失败'
  if [[ "$scope" == cli ]]; then
    tag_bridge cli "$TMP_SCAN/tag-report.json" || cli_rc=$?
    case "$cli_rc" in 0|3) ;; *) fail 'CLI 的 HTTP(S) 代理环境未指向 127.0.0.1:7890、配置了全部绕过，或检查失败；不会自动改写环境。';; esac
    if [[ "$cli_rc" != 0 && "$allow" != yes ]]; then fail 'NO_PROXY 含非回环例外，无法确认全部目标使用代理。'; fi
  fi
  # Slow online probes must not leave a stale health result authorizing a launch.
  check_health
  [[ "$HEALTH" == RUNNING ]] || fail '预检期间监控失效，已取消启动'
  [[ "$rc" != 3 ]] || log_event 'preflight-changes-explicitly-accepted'
}
write_session() {
  local kind=$1 provider=$2 root=$3 stamp=$4 owner=$5 ownerstamp=$6 file
  [[ "$root" =~ ^[0-9]+$ && -n "$stamp" ]] || return 1
  file=$(mktemp "$SESSION_DIR/session.XXXXXXXX") || return 1
  case "$provider" in claude|codex|chatgpt|openai) ;; *) return 1;; esac
  printf '%s|%s|%s|%s|%s|%s|%s\n' "$kind" "$provider" "$root" "$stamp" "$owner" "$ownerstamp" "$(date +%s)" > "$file"
  chmod 600 "$file"; mv "$file" "${file}.session"
  SESSION_CREATED="${file}.session"
}
launch_desktop_provider() {
  require_macos; require_installed
  local provider=$1 app_name=$2 main_kind=$3 allow=no pid stamp kind count=0 ownerstamp
  shift 3
  [[ $# == 0 || ( $# == 1 && "$1" == --allow-changes ) ]] || fail '桌面启动参数无效'
  [[ "${1:-}" != --allow-changes ]] || allow=yes
  if [[ "$provider" == claude ]]; then
    # The Python entry owns the full fresh gate, immutable session-IP baseline,
    # process registration and launch failure recovery. No legacy fallback and
    # no second independent set of rules, including with --allow-changes.
    switcher_run launch --apply || fail 'Claude 受控启动未完成'
    return 0
  fi
  preflight_for_launch "$allow" general "$provider"
  if [[ "$provider" != claude ]]; then
    say '预检复用了系统网络基线与 TAG 入口核对；尚未读取 OpenAI 应用专属代理覆盖，因此不把本次结果表述为该桌面应用已保证走 7890。'
  fi
  init_dirs; scan_targets || fail '启动前扫描失败'
  if awk -F'|' -v k="$main_kind" '$3==k {found=1} END {exit !found}' "$TMP_SCAN/targets"; then fail '目标桌面主进程已存在，不能补做启动前检查；请退出后再受控启动。'; fi
  ownerstamp=$(process_stamp "$$") || fail '无法读取启动器身份'
  atomic_text "$PENDING_FILE" "$$|${ownerstamp}|$(date +%s)" || fail '无法登记启动请求'
  trap 'rm -f "$PENDING_FILE"; cleanup_scan_tmp' EXIT
  if ! /usr/bin/open -a "$app_name"; then fail '桌面启动失败'; fi
  while [[ "$count" -lt 10 ]]; do
    scan_targets || fail '启动后的身份扫描失败'
    while IFS='|' read -r pid stamp kind; do
      if [[ "$kind" == "$main_kind" ]]; then
        write_session desktop "$provider" "$pid" "$stamp" 0 '-' || fail '会话登记失败'
        rm -f "$PENDING_FILE"
        log_event "controlled-launch provider=${provider} desktop pid=${pid} started=${stamp}"
        say '桌面主进程已登记。主进程退出即撤销授权，Helper 不维持授权。'
        return 0
      fi
    done < "$TMP_SCAN/targets"
    count=$((count+1)); sleep 1
  done
  fail '未在启动窗口内确认桌面主进程；保持未授权，不自动结束任何进程。'
}
launch_desktop() { launch_desktop_provider claude Claude desktop-main "$@"; }

desktop_launch_target() {
  local requested=$1 bundle provider
  case "$requested" in
    codex)
      for bundle in /Applications/Codex.app /Applications/ChatGPT.app; do
        provider=$(desktop_provider_for_bundle "$bundle" 2>/dev/null || true)
        case "$provider:$bundle" in
          codex:/Applications/Codex.app) printf 'codex|Codex|codex-desktop-main\n'; return 0;;
          openai:/Applications/ChatGPT.app) printf 'openai|ChatGPT|openai-desktop-main\n'; return 0;;
        esac
      done;;
    chatgpt)
      bundle=/Applications/ChatGPT.app
      provider=$(desktop_provider_for_bundle "$bundle" 2>/dev/null || true)
      case "$provider" in
        chatgpt) printf 'chatgpt|ChatGPT|chatgpt-desktop-main\n'; return 0;;
        openai) printf 'openai|ChatGPT|openai-desktop-main\n'; return 0;;
      esac;;
  esac
  return 1
}

launch_codex() {
  local provider app_name main_kind
  IFS='|' read -r provider app_name main_kind <<EOF
$(desktop_launch_target codex || true)
EOF
  [[ -n "$provider" ]] || fail '未找到已验证的 Codex.app，或带 Codex 的共享 ChatGPT.app 外壳。'
  [[ "$provider" != openai ]] || say '此 Mac 的 Codex 桌面入口使用共享 OpenAI 外壳 ChatGPT.app；会话仅授权该外壳，不会授权独立 ChatGPT/Codex 进程。'
  launch_desktop_provider "$provider" "$app_name" "$main_kind" "$@"
}

launch_chatgpt() {
  local provider app_name main_kind
  IFS='|' read -r provider app_name main_kind <<EOF
$(desktop_launch_target chatgpt || true)
EOF
  [[ -n "$provider" ]] || fail '未找到已验证的 ChatGPT.app。'
  [[ "$provider" != openai ]] || say '此 Mac 的 ChatGPT 桌面入口使用共享 OpenAI 外壳；会话仅授权该外壳，不会授权独立 Codex 进程。'
  launch_desktop_provider "$provider" "$app_name" "$main_kind" "$@"
}

launch_cli_provider() {
  require_macos; require_installed
  local provider=$1 variable=$2 default_name=$3 allow=no cli ownerstamp rc=0 marker=''
  shift 3
  if [[ "${1:-}" == --allow-changes ]]; then allow=yes; shift; fi
  [[ "${1:-}" != -- ]] || shift
  cli=${!variable:-$(command -v "$default_name" 2>/dev/null || true)}
  [[ "$cli" == /* && -f "$cli" && -x "$cli" ]] || fail "找不到 ${default_name} CLI；可设置 ${variable} 为其绝对路径"
  if [[ "$provider" == codex ]]; then is_codex_cli_path "$cli" || fail 'Codex CLI 路径不在支持的 Homebrew、Caskroom、官方 node_modules 或应用内置位置。'; fi
  preflight_for_launch "$allow" cli "$provider"; init_dirs
  ownerstamp=$(process_stamp "$$") || fail '无法读取启动器身份'
  write_session cli "$provider" "$$" "$ownerstamp" "$$" "$ownerstamp" || fail 'CLI 会话登记失败'
  marker=$SESSION_CREATED
  trap 'rm -f "$marker"; cleanup_scan_tmp' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  log_event "controlled-launch provider=${provider} cli wrapper-pid=$$ started=${ownerstamp}"
  "$cli" "$@" || rc=$?
  [[ -z "$marker" ]] || rm -f "$marker"
  log_event "controlled-exit provider=${provider} cli rc=${rc}"
  trap cleanup_scan_tmp EXIT
  trap - INT TERM
  return "$rc"
}
launch_cli() { launch_cli_provider claude CLAUDE_CODE_BIN claude "$@"; }
launch_codex_cli() { launch_cli_provider codex CODEX_CLI_BIN codex "$@"; }

send_test_alert() {
  require_macos
  say '正在发送一条测试通知和警告弹窗。'
  # 测试不要求进入警戒模式，也不读取实际进程。
  local title='Claude Watch：弹窗测试'
  local message='这是一条本地测试提醒。如果看到它，表示 osascript 弹窗通道可用。'
  if osascript \
    -e 'on run argv' \
    -e 'set titleText to item 1 of argv as text' \
    -e 'set messageText to item 2 of argv as text' \
    -e 'try' \
    -e 'display notification messageText with title titleText sound name "Glass"' \
    -e 'end try' \
    -e 'display dialog messageText with title titleText buttons {"知道了"} default button "知道了" with icon caution giving up after 20' \
    -e 'end run' \
    -- "$title" "$message"; then
    say '测试命令已完成。如果没有看到提醒，请检查通知设置和图形桌面登录状态。'
  else
    fail '测试弹窗失败。请确认已登录 macOS 图形桌面，并允许相关通知。'
  fi
}

show_logs() {
  if [[ -f "$EVENT_LOG" ]]; then
    tail -n 30 "$EVENT_LOG"
  else
    say '暂无监控日志。'
  fi
}

main() {
case "${1:-help}" in
  install) [[ $# -eq 1 ]] || fail 'install 不接受额外参数'; install_agent ;;
  uninstall) [[ $# -eq 1 ]] || fail 'uninstall 不接受额外参数'; uninstall_agent ;;
  arm|resume) [[ $# -eq 1 ]] || fail 'arm 不接受额外参数'; arm_agent ;;
  pause|disarm) [[ $# -eq 1 ]] || fail 'pause 不接受额外参数'; pause_agent ;;
  snooze) [[ $# -eq 2 ]] || fail '用法：snooze <分钟数>'; snooze_agent "$2" ;;
  baseline) shift; trap cleanup_scan_tmp EXIT; write_baseline "$@";;
  baseline-data) shift; baseline_data "$@";;
  preflight) shift; trap cleanup_scan_tmp EXIT; preflight "$@";;
  proxy-check) shift; trap cleanup_scan_tmp EXIT; proxy_check "$@";;
  snapshot) shift; snapshot "$@";;
  dns-check) shift; dns_check "$@";;
  launch-desktop) shift; trap cleanup_scan_tmp EXIT; launch_desktop "$@";;
  launch-cli) shift; trap cleanup_scan_tmp EXIT; launch_cli "$@";;
  launch-codex) shift; trap cleanup_scan_tmp EXIT; launch_codex "$@";;
  launch-codex-cli) shift; trap cleanup_scan_tmp EXIT; launch_codex_cli "$@";;
  launch-chatgpt) shift; trap cleanup_scan_tmp EXIT; launch_chatgpt "$@";;
  status) [[ $# -eq 1 ]] || fail 'status 不接受额外参数'; trap cleanup_scan_tmp EXIT; show_status ;;
  audit) [[ $# -eq 1 ]] || fail 'audit 不接受额外参数'; trap cleanup_scan_tmp EXIT; audit;;
  logs) [[ $# -eq 1 ]] || fail 'logs 不接受额外参数'; show_logs ;;
  test-alert) [[ $# -eq 1 ]] || fail 'test-alert 不接受额外参数'; send_test_alert ;;
  switcher) shift; switcher_run "$@" ;;
  account|checkdetail|fix|set-region|update|diagnose-proxy) switcher_run "$@" ;;
  daemon) [[ $# -eq 1 ]] || fail 'daemon 不接受额外参数'; daemon_loop ;;
  help|--help|-h) usage ;;
  *) usage >&2; fail "未知命令：$1" ;;
esac
}

# Sourcing defines functions for isolated fixtures; it never installs or starts a monitor.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
