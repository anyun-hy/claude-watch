#!/bin/bash
# Shared, read-only preflight for build, package and reinstall entry points.
# Call before compiling, creating logs, or changing any installed component.
cw_require_seatbelt_backend() {
  CW_NETWORK_BACKEND="${CW_NETWORK_BACKEND:-seatbelt}"
  case "$CW_NETWORK_BACKEND" in
    seatbelt|nono) CW_NETWORK_BACKEND=seatbelt ;;
    *) printf 'Unsupported network backend %s; only nono/Seatbelt is available.\n' "$CW_NETWORK_BACKEND" >&2; return 1 ;;
  esac
  if [[ "${CW_REQUIRE_ENTITLED_NETWORK_EXTENSION:-0}" != 0 ]]; then
    echo 'The NetworkExtension backend is retired; use nono/Seatbelt without extension signing.' >&2
    return 1
  fi
  local cw_retired_option
  for cw_retired_option in CW_HOST_PROVISION_PROFILE CW_HOST_PROFILE CW_APP_PROVISIONING_PROFILE \
    CW_EXTENSION_PROVISION_PROFILE CW_EXTENSION_PROFILE CW_EXTENSION_PROVISIONING_PROFILE; do
    if [[ -n "${!cw_retired_option-}" ]]; then
      printf 'Retired NetworkExtension option: %s. Remove it before building nono/Seatbelt.\n' "$cw_retired_option" >&2
      return 1
    fi
  done
}
