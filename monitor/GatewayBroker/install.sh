#!/bin/sh
# This reviewed artifact is never executed by the build or prepare command.
# Fresh installation only. Existing services require a separately reviewed
# update/uninstall procedure while no protected instances are running.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Administrator authorization required.' >&2; exit 1; }
cw_source=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
cw_dest=/Library/PrivilegedHelperTools/io.local.claudewatch.gateway
cw_plist=/Library/LaunchDaemons/io.local.claudewatch.gateway.plist
[ ! -e "$cw_dest" ] && [ ! -L "$cw_dest" ] && [ ! -e "$cw_plist" ] && [ ! -L "$cw_plist" ] || {
  echo 'Refusing to replace an existing gateway service. Review an update procedure first.' >&2
  exit 1
}
/usr/bin/plutil -lint "$cw_source/io.local.claudewatch.gateway.plist"
/usr/bin/codesign --verify --strict "$cw_source/watch-gateway-broker"
/usr/bin/install -d -o root -g wheel -m 0755 "$cw_dest"
/usr/bin/install -o root -g wheel -m 0755 "$cw_source/watch-gateway-broker" "$cw_dest/watch-gateway-broker"
/usr/bin/install -o root -g wheel -m 0644 "$cw_source/config.json" "$cw_dest/config.json"
/usr/bin/install -o root -g wheel -m 0644 "$cw_source/io.local.claudewatch.gateway.plist" "$cw_plist"
/bin/launchctl bootstrap system "$cw_plist"
echo 'Service installed. Activation, fault containment, and real-client acceptance still require verification.'
