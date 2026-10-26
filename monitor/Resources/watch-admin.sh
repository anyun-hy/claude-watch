#!/bin/bash
# Fixed privileged operations. Installed root:wheel, 0755; never source user files.
set -euo pipefail
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
[[ "$(id -u)" == 0 ]] || { echo 'Administrator authorization required' >&2; exit 1; }
ROOT='/Library/Application Support/ClaudeWatch'
PLIST='/Library/LaunchDaemons/io.local.claudewatch.timezone.plist'
TARGET="$ROOT/timezone.target"
[[ ! -L "$ROOT" && ! -L "$TARGET" && ! -L "$PLIST" ]] || exit 1
zone_valid() {
    [[ -n "$1" && "$1" != *..* && "$1" != /* && "$1" != *[!A-Za-z0-9_+/-]* &&
       -f "/var/db/timezone/zoneinfo/$1" ]]
}
case "${1:-}" in
  status)
    [[ $# == 1 ]] || exit 2
    printf 'Claude Watch administrator component ABI 1\n'
    ;;
  timezone)
    [[ $# == 2 ]] && zone_valid "$2" || exit 2
    /usr/sbin/systemsetup -settimezone "$2"
    ;;
  ipv6)
    [[ $# == 3 && "$2" != *$'\n'* ]] || exit 2
    /usr/sbin/networksetup -listallnetworkservices | /usr/bin/grep -Fx -- "$2" >/dev/null || exit 2
    case "$3" in
      off) /usr/sbin/networksetup -setv6off "$2" ;;
      automatic) /usr/sbin/networksetup -setv6automatic "$2" ;;
      *) exit 2 ;;
    esac
    ;;
  flush-dns)
    [[ $# == 1 ]] || exit 2
    /usr/bin/dscacheutil -flushcache
    /usr/bin/killall -HUP mDNSResponder
    ;;
  watchdog)
    [[ $# == 2 ]] || exit 2
    if /bin/launchctl print system/io.local.claudewatch.timezone >/dev/null 2>&1; then
      /bin/launchctl bootout system/io.local.claudewatch.timezone
    fi
    if [[ "$2" == off ]]; then
      /bin/rm -f "$PLIST" "$TARGET"
      exit 0
    fi
    zone_valid "$2" || exit 2
    umask 022
    printf '%s\n' "$2" > "$TARGET"
    /usr/sbin/chown root:wheel "$TARGET"
    /bin/chmod 644 "$TARGET"
    cat > "$PLIST" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>io.local.claudewatch.timezone</string>
<key>ProgramArguments</key><array>
<string>/usr/bin/env</string><string>-i</string><string>PATH=/usr/bin:/bin:/usr/sbin:/sbin</string>
<string>/bin/bash</string><string>--noprofile</string><string>--norc</string>
<string>/Library/Application Support/ClaudeWatch/claude-watch-admin.sh</string><string>tick</string>
</array>
<key>RunAtLoad</key><true/><key>StartInterval</key><integer>3600</integer>
</dict></plist>
PLIST
    /usr/sbin/chown root:wheel "$PLIST"
    /bin/chmod 644 "$PLIST"
    /bin/launchctl bootstrap system "$PLIST"
    ;;
  tick)
    [[ $# == 1 && -f "$TARGET" && "$(stat -f '%u' "$TARGET")" == 0 ]] || exit 2
    IFS= read -r desired < "$TARGET"
    zone_valid "$desired" || exit 2
    actual=$(readlink /etc/localtime)
    if [[ "$actual" != "/var/db/timezone/zoneinfo/$desired" ]]; then
      /usr/sbin/systemsetup -settimezone "$desired"
    fi
    [[ ! -L "$ROOT/timezone.last-success" ]] || exit 1
    date +%s > "$ROOT/timezone.last-success"
    ;;
  legacy-stop)
    [[ $# == 1 ]] || exit 2
    for label in local.claude-bodyguard local.tz-watchdog local.claude-update; do
      if /bin/launchctl print "system/$label" >/dev/null 2>&1; then /bin/launchctl bootout "system/$label"; fi
    done
    ;;
  uninstall)
    [[ $# == 1 ]] || exit 2
    if /bin/launchctl print system/io.local.claudewatch.timezone >/dev/null 2>&1; then
      /bin/launchctl bootout system/io.local.claudewatch.timezone
    fi
    /bin/rm -f "$PLIST" "$TARGET" "$ROOT/timezone.last-success" "$ROOT/claude-watch-admin.sh"
    /bin/rmdir "$ROOT" 2>/dev/null || true
    ;;
  *) echo 'Unsupported operation' >&2; exit 2 ;;
esac
