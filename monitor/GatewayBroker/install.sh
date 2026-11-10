#!/bin/sh
# An explicitly invoked administrator operation, never run by --prepare.
# Production reinstalls use the native transaction and verify the final engine
# descriptor handoff before committing; this prepared-artifact entry is manual.
set -eu
[ "$(/usr/bin/id -u)" = 0 ] || { echo 'Administrator authorization is required.' >&2; exit 1; }
cw_source=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && /bin/pwd -P)
cw_transaction=$(/usr/bin/uuidgen | /usr/bin/tr -d '-' | /usr/bin/tr '[:upper:]' '[:lower:]')
"$cw_source/watch-gateway-broker" --service-install --prepared "$cw_source" --transaction "$cw_transaction"
printf 'Gateway transaction %s is pending. Verify the final user engine gateway-endpoint-check, then explicitly commit; otherwise roll it back.\n' "$cw_transaction"
