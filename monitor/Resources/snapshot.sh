#!/bin/bash
# Read-only UI collector; never calls install, daemon, launch-* or any TAG write API.
set -eo pipefail
umask 077
export LC_ALL=C
export PYTHONUTF8=1
resource_dir=$(cd "$(dirname "$0")" && pwd -P)
cw_ui_tmp=$(mktemp -d "${TMPDIR:-/tmp}/claude-watch-ui.XXXXXXXX")
TMP_SCAN=''
cleanup_ui() {
  if declare -F cleanup_scan_tmp >/dev/null; then cleanup_scan_tmp; fi
  rm -f "$cw_ui_tmp"/*
  rmdir "$cw_ui_tmp" 2>/dev/null || true
}
trap cleanup_ui EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
service_rc=0
/bin/launchctl print "gui/$(id -u)/io.local.claudewatch.agent" > "$cw_ui_tmp/service" 2>&1 || service_rc=$?
printf '%s\n' "$service_rc" > "$cw_ui_tmp/service-rc"
service_pid=$(awk '$1=="pid" && $2=="=" {print $3;exit}' "$cw_ui_tmp/service")
if [[ "$service_pid" =~ ^[0-9]+$ ]]; then
  /bin/ps -p "$service_pid" -o lstart= > "$cw_ui_tmp/process-stamp" 2>/dev/null || true
fi
full=no
if [[ "${1:-}" == --full ]]; then
  full=yes
  installed_watch="$HOME/Library/Application Support/ClaudeWatch/claude-watch.sh"
  if [[ -f "$installed_watch" && ! -L "$installed_watch" ]]; then
    source "$installed_watch"
    if scan_targets; then
      cp "$TMP_SCAN/targets" "$cw_ui_tmp/targets"
      printf '%s\n' "$ACTIVE_PIDS" > "$cw_ui_tmp/active"
      # Proxy evidence is read from the daemon's atomic snapshot by snapshot.py.
      # Do not run netstat/tag_collect again in the GUI's process context.
    else printf '进程采样暂不可用\n' > "$cw_ui_tmp/full-error"; fi
  else printf '监控脚本尚未安装\n' > "$cw_ui_tmp/full-error"; fi
fi
if [[ -x /opt/homebrew/bin/python3 ]]; then cw_ui_python=/opt/homebrew/bin/python3
elif [[ -x /usr/local/bin/python3 ]]; then cw_ui_python=/usr/local/bin/python3
else cw_ui_python=$(command -v python3); fi
role_targets="$HOME/Library/Application Support/ClaudeWatch/state/tracked"
if [[ -f "$cw_ui_tmp/targets" ]]; then role_targets="$cw_ui_tmp/targets"; fi
if [[ -f "$role_targets" && -f "$resource_dir/process_roles.py" ]]; then
  "$cw_ui_python" "$resource_dir/process_roles.py" --targets "$role_targets" > "$cw_ui_tmp/process-roles.json" 2>/dev/null || true
fi
if [[ "$full" == yes ]]; then
  "$cw_ui_python" "$resource_dir/snapshot.py" --scratch "$cw_ui_tmp" --full
else
  "$cw_ui_python" "$resource_dir/snapshot.py" --scratch "$cw_ui_tmp"
fi

