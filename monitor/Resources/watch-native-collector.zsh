#!/bin/zsh -f
# Fixed macOS listener collector for the Rust runtime.
#
# macOS 27 can return only TCP PCB headers when a non-Apple-signed process
# invokes netstat.  This script must therefore be the LaunchAgent's direct,
# Apple-signed zsh parent.  It owns no policy, configuration, account, proxy,
# notification, or application-control logic.  It emits bounded raw evidence
# only; Rust validates and interprets every record.

setopt pipefail
unsetopt bgnice # The owned Rust worker keeps the foreground version's priority.
unset BASH_ENV ENV
export PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export LC_ALL=C

readonly FRAME_MAGIC='CWLISTENER1'
readonly MAX_FILE_BLOCKS=4000 # zsh ulimit -f units are 512-byte blocks.
readonly MAX_FILE_BYTES=$((MAX_FILE_BLOCKS * 512))
readonly MAX_TOTAL_BYTES=$((MAX_FILE_BYTES * 4 + 1024))
readonly ROUND_SECONDS=2

fail() {
  print -u2 -r -- "watch-native-collector: $1"
  exit 64
}

script_path=$0
[[ -n "$script_path" && ! -L "$script_path" && -f "$script_path" && -x "$script_path" ]] || fail 'invalid collector path'
script_dir=${script_path:h}
[[ -n "$script_dir" && ! -L "$script_dir" && -d "$script_dir" ]] || fail 'invalid runtime directory'

private_temp_dir() {
  local temp_root=${TMPDIR:-/private/tmp}
  [[ "$temp_root" == /* && "$temp_root" != *$'\n'* ]] || return 1
  local result
  result=$(/usr/bin/mktemp -d "$temp_root/cw-listener.XXXXXXXX") || return 1
  [[ -n "$result" && ! -L "$result" && -d "$result" ]] || return 1
  [[ $(/usr/bin/stat -f '%u' "$result") == $(/usr/bin/id -u) ]] || { /bin/rmdir "$result" 2>/dev/null || true; return 1; }
  print -r -- "$result"
}

collect() {
  [[ $# == 1 && "$1" == <-> ]] || fail 'invalid collector parent'
  local supervisor_pid=$1
  [[ "$PPID" == "$supervisor_pid" ]] || fail 'collector parent mismatch'
  zmodload zsh/datetime || fail 'collector clock unavailable'
  zmodload -F zsh/stat b:zstat || fail 'collector file-size reader unavailable'
  local temp_dir
  temp_dir=$(private_temp_dir) || fail 'private temporary directory unavailable'
  cleanup_collector() {
    trap - EXIT HUP INT TERM PIPE
    /bin/rm -rf -- "$temp_dir" 2>/dev/null
  }
  trap 'cleanup_collector' EXIT
  # Handle EPIPE through the checked writes below. An exiting PIPE trap can
  # recurse; the default signal action skips temporary-file cleanup.
  trap '' PIPE
  trap 'cleanup_collector; exit 0' HUP INT TERM
  # Bound every child output before collecting a frame. A failed or truncated
  # command is evidence of an unavailable sample, never of a clean listener.
  ulimit -f "$MAX_FILE_BLOCKS" || fail 'cannot apply collector output limit'

  local seq=0
  while true; do
    /bin/kill -0 "$supervisor_pid" 2>/dev/null || break
    (( seq += 1 ))
    local before="$temp_dir/before" net="$temp_dir/net" err="$temp_dir/net.err" after="$temp_dir/after"
    : > "$before"; : > "$net"; : > "$err"; : > "$after"
    local start_epoch=$EPOCHREALTIME
    /bin/ps -ww -axo 'pid=,ppid=,uid=,lstart=,comm=' > "$before" 2>/dev/null
    local before_rc=$?
    /usr/sbin/netstat -anv -p tcp 2> "$err" | /usr/bin/awk '$6 == "LISTEN" { print }' > "$net"
    local net_rc=$?
    /bin/ps -ww -axo 'pid=,ppid=,uid=,lstart=,comm=' > "$after" 2>/dev/null
    local after_rc=$?
    local end_epoch=$EPOCHREALTIME
    local -a sizes
    zstat -A sizes +size -- "$before" "$net" "$err" "$after" || fail 'cannot read collector frame sizes'
    local before_len=${sizes[1]} net_len=${sizes[2]} err_len=${sizes[3]} after_len=${sizes[4]}
    local total_len=$((before_len + net_len + err_len + after_len))
    if (( before_len > MAX_FILE_BYTES || net_len > MAX_FILE_BYTES || err_len > MAX_FILE_BYTES || after_len > MAX_FILE_BYTES || total_len > MAX_TOTAL_BYTES )); then
      : > "$before"; : > "$net"; : > "$after"
      print -rn -- 'collector output exceeded bounded limit' > "$err"
      before_rc=125; net_rc=125; after_rc=125
      zstat -A sizes +size -- "$err" || fail 'cannot read collector error size'
      before_len=0; net_len=0; after_len=0; err_len=${sizes[1]}
    fi
    # External printf returns EPIPE as a normal child failure. zsh's builtin
    # can abort the function before its private-directory cleanup executes.
    /usr/bin/printf '%s\n' "$FRAME_MAGIC $supervisor_pid $$ $seq $start_epoch $end_epoch $before_rc $net_rc $after_rc $before_len $net_len $err_len $after_len" 2>/dev/null || break
    /bin/cat -- "$before" "$net" "$err" "$after" 2>/dev/null || break
    /usr/bin/printf '\n' 2>/dev/null || break
    # Include work and frame delivery in the interval. Sleeping a full round
    # after collection can leave a gap longer than the VPN evidence lifetime.
    local -F remaining=$(( ROUND_SECONDS - (EPOCHREALTIME - start_epoch) ))
    if (( remaining > ROUND_SECONDS )); then remaining=$ROUND_SECONDS; fi
    if (( remaining > 0 )); then /bin/sleep "$remaining"; fi
  done
  cleanup_collector
}

validate_engine_arguments() {
  local -a original
  original=("$@")
  local home_seen=0 command='' apply_seen=0
  local index=1
  while (( index <= $# )); do
    local value=${original[index]}
    if [[ "$value" == '--home' ]]; then
      (( home_seen == 0 && index < $# )) || return 1
      local home_path=${original[index + 1]}
      [[ "$home_path" == /* && "$home_path" != *$'\n'* && ! -L "$home_path" && -d "$home_path" ]] || return 1
      home_seen=1
      (( index += 2 ))
      continue
    fi
    if [[ -z "$command" ]]; then
      command=$value
    else
      case "$command:$value" in
        daemon:--apply)
          (( apply_seen == 0 )) || return 1
          apply_seen=1
          ;;
        daemon:--observe-only|daemon:--once) ;;
        *) return 1 ;;
      esac
    fi
    (( index += 1 ))
  done
  case "$command" in
    daemon) (( apply_seen == 1 )) ;;
    proxy-check) (( apply_seen == 0 )) ;;
    *) return 1 ;;
  esac
}

supervise() {
  [[ $# -ge 1 ]] || fail 'missing engine arguments'
  validate_engine_arguments "$@" || fail 'unsupported engine arguments'
  local engine="$script_dir/watch-engine"
  [[ -n "$engine" && ! -L "$engine" && -f "$engine" && -x "$engine" ]] || fail 'invalid watch-engine path'
  export CW_NATIVE_LISTENER_STREAM=1
  export CW_NATIVE_LISTENER_SUPERVISOR_PID=$$
  # Open the process substitution before the worker starts.  The direct zsh
  # parent remains alive for the entire worker lifetime, so macOS grants this
  # fixed collector its native listener view.
  exec 3< <("$script_path" --collect "$$")
  zmodload zsh/parameter || fail 'owned worker job table unavailable'
  local worker_pid='' stop_requested=0 signal_generation=0
  stop_supervised_worker() {
    stop_requested=1
    (( signal_generation += 1 ))
    # Only signal an unreaped job owned by this shell. A removed launchd job
    # must not leave its Rust worker behind, or target a reused numeric PID.
    local job_state
    for job_state in "${(@v)jobstates}"; do
      if [[ "$worker_pid" == <-> && ( "$job_state" == *":${worker_pid}=running"* || "$job_state" == *":${worker_pid}=stopped"* ) ]]; then
        /bin/kill -TERM "$worker_pid" 2>/dev/null || true
      fi
    done
  }
  trap 'stop_supervised_worker' HUP INT TERM
  "$engine" "$@" <&3 &
  worker_pid=$!
  if (( stop_requested )); then stop_supervised_worker; fi
  local worker_rc=0 before_signal
  while true; do
    before_signal=$signal_generation
    wait "$worker_pid"
    worker_rc=$?
    # A trapped signal can interrupt wait before the child exits. Keep this
    # registered parent alive until the actual worker has been reaped.
    (( before_signal == signal_generation || worker_rc < 128 )) && break
    # If wait already consumed a completed child's status while the trap ran,
    # waiting again would replace its real result with "not a child" (127).
    local pending_job=0 job_state
    for job_state in "${(@v)jobstates}"; do
      [[ "$job_state" == *":${worker_pid}="* ]] && pending_job=1
    done
    (( pending_job )) || break
  done
  trap - HUP INT TERM
  worker_pid=''
  exec 3<&-
  # zsh does not expose a process-substitution PID through $!, and killing
  # that value can target the caller's process group. Closing fd 3 makes the
  # collector exit on its next write; its parent-alive check bounds a sleeping
  # collector to one sampling interval.
  return "$worker_rc"
}

if [[ "${1:-}" == 'collect' || "${1:-}" == '--collect' ]]; then
  shift
  collect "$@"
  exit $?
fi
supervise "$@"
