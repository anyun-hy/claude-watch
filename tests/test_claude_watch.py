"""Isolated Bash 3.2 contract tests: no real Claude, launchd job, UI or network."""
import pathlib
import shlex
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "claude-watch.sh"

ENVIRONMENT = r'''
collect_environment() {
  CURRENT_TZ=Asia/Tokyo
  CURRENT_V4='en0 gateway=192.0.2.1'; CURRENT_V6=absent
  CURRENT_DNS=192.0.2.53; CURRENT_DNS_SIG=dns
  CURRENT_SYS_PROXY='HTTPEnable=0'; CURRENT_SYS_PROXY_SIG=proxy
  CURRENT_CLI_PROXY=none; CURRENT_CLI_PROXY_SIG=cli
  CURRENT_SETTINGS_SIG=settings; CURRENT_SETTINGS_PROXY=none
  CURRENT_FINGERPRINT=fingerprint
}
'''


class WatchTests(unittest.TestCase):
    def run_shell(self, body, expected=0):
        with tempfile.TemporaryDirectory(prefix="claude-watch-test-", dir="/private/tmp") as tmp:
            setup = f"source {shlex.quote(str(SCRIPT))}\nWATCH_SCRIPT={shlex.quote(str(SCRIPT))}\nTEST_ROOT={shlex.quote(tmp)}\n"
            setup += r'''
BASE_DIR="$TEST_ROOT/app"; STATE_DIR="$BASE_DIR/state"
ALERT_COOLDOWN_FILE="$STATE_DIR/alert-cooldowns"
SESSION_DIR="$STATE_DIR/sessions"; MODE_FILE="$STATE_DIR/mode"
BASELINE_FILE="$STATE_DIR/baseline.conf"; HEARTBEAT_FILE="$STATE_DIR/heartbeat"
TRACKED_FILE="$STATE_DIR/tracked"; PENDING_FILE="$STATE_DIR/desktop-pending"
LAUNCH_AGENTS="$TEST_ROOT/agents"; PLIST_FILE="$LAUNCH_AGENTS/watch.plist"
INSTALLED_SCRIPT="$BASE_DIR/claude-watch.sh"
LOG_DIR="$TEST_ROOT/logs"; EVENT_LOG="$LOG_DIR/events.log"
ERROR_LOG="$LOG_DIR/errors.log"
test_state_paths() {
  BASE_DIR="$TEST_ROOT/app"; STATE_DIR="$BASE_DIR/state"
  SESSION_DIR="$STATE_DIR/sessions"; MODE_FILE="$STATE_DIR/mode"
  BASELINE_FILE="$STATE_DIR/baseline.conf"; HEARTBEAT_FILE="$STATE_DIR/heartbeat"
  TRACKED_FILE="$STATE_DIR/tracked"; PENDING_FILE="$STATE_DIR/desktop-pending"
  LAUNCH_AGENTS="$TEST_ROOT/agents"; PLIST_FILE="$LAUNCH_AGENTS/watch.plist"
  INSTALLED_SCRIPT="$BASE_DIR/claude-watch.sh"
  LOG_DIR="$TEST_ROOT/logs"; EVENT_LOG="$LOG_DIR/events.log"; ERROR_LOG="$LOG_DIR/errors.log"
  ALERT_COOLDOWN_FILE="$STATE_DIR/alert-cooldowns"
}
curl() { printf 'FORBIDDEN_NETWORK\n' >&2; return 99; }
dig() { printf 'FORBIDDEN_NETWORK\n' >&2; return 99; }
launchctl() { return 113; }
ps() { return 1; }
pgrep() { return 1; }
lsof() { return 1; }
nettop() { return 1; }
tag_bridge() {
  case "$1" in
    collect) printf '%s\n' '{"fixture":true}';;
    baseline) printf 'tag_group=AI\ntag_node=JP11\n';;
    render|events) printf 'TAG fixture verified\n';;
    alert-key) printf 'verified\n';;
    cli) return 0;;
    *) return 99;;
  esac
}
alert_user() { printf '%s\n' "$1" >> "$TEST_ROOT/alerts"; }
require_installed() { :; }
init_dirs
init_scan_tmp
trap cleanup_scan_tmp EXIT
'''
            result = subprocess.run(
                ["/bin/bash", "-c", setup + ENVIRONMENT + body],
                text=True, capture_output=True, timeout=20,
            )
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            self.assertNotIn("FORBIDDEN_NETWORK", result.stderr)
            return result.stdout

    def test_sourcing_has_no_main_side_effect(self):
        result = subprocess.run(["/bin/bash", "-c", f"source {shlex.quote(str(SCRIPT))}; printf defined"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "defined")

    def test_setup_baseline_data_is_read_only_and_preserves_format2_fields(self):
        out = self.run_shell(r'''
baseline_data > "$TEST_ROOT/data.json"
[[ ! -e "$BASELINE_FILE" ]] || exit 11
python3 - "$TEST_ROOT/data.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
assert value['status'] == 'ok'
assert 'format=2\n' in value['baseline']
assert 'online=no\n' in value['baseline']
assert 'timezone=Asia/Tokyo\n' in value['baseline']
assert 'dns_sig=dns\n' in value['baseline']
assert 'tag_node=' not in value['baseline']
print('readonly baseline data')
PY
''')
        self.assertIn("readonly baseline data", out)

    def test_setup_baseline_data_rejects_missing_route(self):
        self.run_shell(r'''
collect_environment() { CURRENT_V4=absent; CURRENT_V6=absent; CURRENT_DNS=1.1.1.1; CURRENT_SYS_PROXY=none; CURRENT_TZ=Asia/Tokyo; }
baseline_data
''', expected=1)

    def test_ip_validation_rejects_fake_and_malformed_addresses(self):
        self.run_shell(r'''
for value in 999.1.2.3 1.2.3 1.02.3.4 2001:::1 'host.example' '1.2.3.4;echo'; do
  if valid_ip "$value"; then exit 11; fi
done
for value in 198.18.0.245 10.1.2.3 192.0.2.1 2001:db8::1; do
  if public_ip_valid "$value"; then exit 12; fi
done
valid_ip 2409:8070:b:1005::5033
public_ip_valid 1.1.1.1
''')

    def test_proxy_credentials_are_not_printed(self):
        out = self.run_shell('redact_proxy "http://alice:topsecret@proxy.example:8080/path?token=secret"\n')
        self.assertEqual(out, "http://proxy.example:8080")

    def test_missing_ipv6_route_is_not_a_permission_failure(self):
        out = self.run_shell(r'''
route_query() { printf 'route: writing to routing socket: not in table\n' >&2; return 0; }
route_snapshot 6
route_query() { printf 'route: socket: Operation not permitted\n' >&2; return 1; }
route_snapshot 6
''')
        self.assertEqual(out, "absent\nunavailable\n")

    def test_offline_baseline_and_preflight_never_request_network(self):
        out = self.run_shell('write_baseline\npreflight\n')
        self.assertIn("未验证", out)
        self.assertIn("192.0.2.53", out)

    def test_unknown_environment_cannot_be_saved_as_trusted(self):
        self.run_shell(ENVIRONMENT.replace("CURRENT_V4='en0 gateway=192.0.2.1'", "CURRENT_V4=unavailable") + 'write_baseline\n', 1)

    def test_preflight_changes_do_not_overwrite_baseline(self):
        out = self.run_shell(r'''
write_baseline
before=$(cat "$BASELINE_FILE")
''' + ENVIRONMENT.replace("CURRENT_DNS=192.0.2.53", "CURRENT_DNS=192.0.2.54") + r'''
rc=0; preflight || rc=$?
[[ "$rc" == 3 && "$(cat "$BASELINE_FILE")" == "$before" ]]
''')
        self.assertIn("192.0.2.54", out)

    def test_unverified_proxy_entry_is_a_critical_preflight_failure(self):
        self.run_shell(r'''
write_baseline
tag_preflight() { return 4; }
preflight
''', 4)

    def test_proxy_chain_uncertainty_is_reported_as_a_warning(self):
        self.run_shell(r'''
write_baseline
tag_preflight() { return 3; }
preflight
''', 3)

    def test_cli_override_cannot_skip_missing_proxy_configuration(self):
        self.run_shell(r'''
check_health() { HEALTH=RUNNING; HEALTH_REASON=fixture; }
preflight() { return 0; }
tag_bridge() { return 4; }
preflight_for_launch yes cli
''', 1)

    def test_stopped_monitor_blocks_launch_even_with_override(self):
        self.run_shell(r'''
preflight() { printf SHOULD_NOT_PREFLIGHT; exit 19; }
preflight_for_launch yes
''', 1)

    def test_health_is_rechecked_after_preflight(self):
        self.run_shell(r'''
checks=0
check_health() { checks=$((checks+1)); HEALTH=RUNNING; HEALTH_REASON=fixture; [[ "$checks" != 2 ]] || HEALTH=STOPPED; }
preflight() { return 0; }
switcher_run() { return 0; }
preflight_for_launch no
''', 1)

    def test_desktop_helper_cannot_keep_session_authorized(self):
        self.run_shell(r'''
printf '11|helper-start|1|Claude Helper\n' > "$TMP_SCAN/processes"
printf '11|helper-start|desktop-helper\n' > "$TMP_SCAN/targets"
printf 'desktop|10|main-start|0|-|1\n' > "$SESSION_DIR/desktop.session"
classify_authorization
[[ "$MONITOR_MODE" == GUARD && "$UNAUTHORIZED_PIDS" == ' 11' ]]
''')

    def test_pid_reuse_does_not_authorize_new_process(self):
        self.run_shell(r'''
printf '10|NEW-start|1|Claude\n' > "$TMP_SCAN/processes"
printf '10|NEW-start|desktop-main\n' > "$TMP_SCAN/targets"
printf 'desktop|10|OLD-start|0|-|1\n' > "$SESSION_DIR/desktop.session"
classify_authorization
[[ "$MONITOR_MODE" == GUARD ]]
''')

    def test_multiple_sessions_and_unrelated_cli_are_independent(self):
        self.run_shell(r'''
printf '20|w1|1|bash\n21|c1|20|claude\n30|w2|1|bash\n31|c2|30|claude\n91|rogue|1|claude\n' > "$TMP_SCAN/processes"
printf '21|c1|code\n31|c2|code\n91|rogue|code\n' > "$TMP_SCAN/targets"
printf 'cli|20|w1|20|w1|1\n' > "$SESSION_DIR/one.session"
printf 'cli|30|w2|30|w2|1\n' > "$SESSION_DIR/two.session"
classify_authorization
[[ "$ACTIVE_PIDS" == ' 21 31' && "$UNAUTHORIZED_PIDS" == ' 91' ]]
rm "$SESSION_DIR/one.session"
classify_authorization
[[ "$ACTIVE_PIDS" == ' 31' && "$UNAUTHORIZED_PIDS" == ' 21 91' ]]
''')

    def test_detached_child_is_not_authorized_by_live_unrelated_session(self):
        self.run_shell(r'''
printf '20|wrapper|1|bash\n21|cli|20|claude\n22|orphan|1|curl\n' > "$TMP_SCAN/processes"
printf '21|cli|code\n22|orphan|child\n' > "$TMP_SCAN/targets"
printf 'cli|20|wrapper|20|wrapper|1\n' > "$SESSION_DIR/one.session"
classify_authorization
[[ "$ACTIVE_PIDS" == ' 21' && "$UNAUTHORIZED_PIDS" == ' 22' ]]
''')

    def test_scan_follows_generic_children_and_retains_orphans(self):
        self.run_shell(r'''
ps() { printf ' 10 1 %s Fri Oct 16 10:00:00 2026 /Applications/Claude.app/Contents/MacOS/Claude\n 11 10 %s Fri Oct 16 10:00:01 2026 /usr/bin/curl\n 12 1 %s Fri Oct 16 09:59:00 2026 /usr/bin/python3\n' "$CURRENT_UID" "$CURRENT_UID" "$CURRENT_UID"; }
pgrep() { printf '10\n'; }
read_identity() { CLASS=desktop-main; START='Fri Oct 16 10:00:00 2026'; }
printf '12|Fri Oct 16 09:59:00 2026|child\n' > "$TRACKED_FILE"
scan_targets
[[ "$(wc -l < "$TMP_SCAN/targets" | tr -d ' ')" == 3 ]]
grep -q '^11|.*|child$' "$TMP_SCAN/targets"
grep -q '^12|.*|child$' "$TMP_SCAN/targets"
''')

    def test_candidate_exiting_after_ps_snapshot_does_not_degrade_quality(self):
        self.run_shell(r'''
ps() {
  case "$*" in
    *-axo*) printf ' 77 1 %s Fri Oct 16 10:00:00 2026 /Applications/Claude.app/Contents/MacOS/Claude\n' "$CURRENT_UID";;
    *'stat='*|*'command='*) return 1;;
    *'pid='*) return 1;;
  esac
}
pgrep() { printf '77\n'; }
connection_sample() { :; }; byte_sample() { :; }; file_sample() { :; }; service_sample() { :; }
monitor_tick
[[ "$SCAN_INCOMPLETE" == 0 ]]
grep -q '|ok|GUARD$' "$HEARTBEAT_FILE"
''')

    def test_live_candidate_with_unreadable_identity_remains_incomplete(self):
        self.run_shell(r'''
ps() {
  case "$*" in
    *-axo*) printf ' 77 1 %s Fri Oct 16 10:00:00 2026 /Applications/Claude.app/Contents/MacOS/Claude\n' "$CURRENT_UID";;
    *'stat='*|*'command='*) return 1;;
    *'pid='*) printf '77\n';;
  esac
}
pgrep() { printf '77\n'; }
scan_targets
[[ "$SCAN_INCOMPLETE" == 1 ]]
''')

    def test_permission_error_is_not_treated_as_an_exited_candidate(self):
        self.run_shell(r'''
ps() {
  case "$*" in
    *-axo*) printf ' 77 1 %s Fri Oct 16 10:00:00 2026 /Applications/Claude.app/Contents/MacOS/Claude\n' "$CURRENT_UID";;
    *'stat='*|*'command='*) return 1;;
    *'pid='*) printf 'Operation not permitted\n' >&2; return 1;;
  esac
}
pgrep() { printf '77\n'; }
scan_targets
[[ "$SCAN_INCOMPLETE" == 1 ]]
''')

    def monitor_fixture(self):
        return r'''
DAEMON_STAMP=daemon
scan_targets() {
  printf '77|start|1|claude\n' > "$TMP_SCAN/processes"
  printf '77|start|code\n' > "$TMP_SCAN/targets"
  SCAN_INCOMPLETE=0
  classify_authorization
}
connection_sample() { printf '77|TCP|192.0.2.2:4000->203.0.113.9:443\n'; }
file_sample() { [[ "$1" == 77 ]] && printf '77|4|r|SSH\n' || return 0; }
byte_sample() { printf '77|10|20\n'; }
service_sample() { return 0; }
'''

    def test_empty_or_malformed_tracked_state_does_not_create_phantom_targets(self):
        self.run_shell(r'''
DAEMON_STAMP=daemon
ps() { printf ' 90 1 %s Fri Oct 16 10:00:00 2026 /bin/bash\n' "$CURRENT_UID"; }
pgrep() { return 1; }
service_sample() { return 0; }
tag_bridge() {
  case "$1" in
    collect) printf '{}\n';;
    events) printf 'TAG unknown fixture\n'; return 3;;
    alert-key) printf 'unknown\n';;
    *) return 4;;
  esac
}
printf '\n||\n' > "$TRACKED_FILE"
monitor_tick
[[ ! -s "$TMP_SCAN/targets" && -z "$UNAUTHORIZED_PIDS" ]]
LAST_NET_TIME=0
monitor_tick
[[ ! -s "$TMP_SCAN/targets" && -z "$UNAUTHORIZED_PIDS" ]]
wait
[[ ! -e "$TEST_ROOT/alerts" ]]
''')

    def test_guard_samples_connections_and_sensitive_fds(self):
        self.run_shell(self.monitor_fixture() + r'''
monitor_tick
grep -q 'connection scope=unauthorized pid=77' "$EVENT_LOG"
grep -q '203.0.113.9:443' "$EVENT_LOG"
grep -q 'sensitive-open-descriptor' "$EVENT_LOG"
grep -q '|ok|GUARD$' "$HEARTBEAT_FILE"
wait
''')

    def test_tag_failure_keeps_original_guard_running(self):
        self.run_shell(self.monitor_fixture() + r'''
tag_bridge() { return 4; }
monitor_tick
grep -q 'connection scope=unauthorized pid=77' "$EVENT_LOG"
grep -q 'sensitive-open-descriptor' "$EVENT_LOG"
grep -q '|ok|GUARD$' "$HEARTBEAT_FILE"
wait
''')

    def test_repeated_tag_error_notifies_once(self):
        self.run_shell(self.monitor_fixture() + r'''
tag_bridge() { return 4; }
monitor_tick
LAST_NET_TIME=0
monitor_tick
wait
[[ "$(grep -c '代理入口或代理链需核对' "$TEST_ROOT/alerts")" == 1 ]]
''')

    def test_proxy_check_uses_existing_process_and_connection_samples(self):
        self.run_shell(self.monitor_fixture() + r'''
tag_bridge() {
  if [[ "$1" == collect ]]; then
    grep -q '^77|' "$2" || return 4
    grep -q '203.0.113.9:443' "$3" || return 4
    printf '{}\n'
  elif [[ "$1" == render ]]; then printf 'verified-fixture\n'
  else return 4; fi
}
proxy_check
''')

    def test_same_process_does_not_repeat_start_alert(self):
        self.run_shell(self.monitor_fixture() + r'''
monitor_tick
monitor_tick
[[ "$(grep -c 'unauthorized-process pid=77' "$EVENT_LOG")" == 1 ]]
wait
''')

    def test_pause_suppresses_notifications_but_not_sampling(self):
        self.run_shell(self.monitor_fixture() + r'''
write_mode paused
monitor_tick
grep -q 'connection scope=unauthorized' "$EVENT_LOG"
wait
[[ ! -e "$TEST_ROOT/alerts" ]]
''')

    def test_automatic_alert_is_a_silent_notification_without_a_modal_dialog(self):
        self.run_shell(r'''
source "$WATCH_SCRIPT"
test_state_paths
init_dirs
osascript() { printf '%s\n' "$@" > "$TEST_ROOT/osascript-args"; }
write_mode armed
alert_user 'Claude Watch：网络环境变化' 'fixture message' armed
grep -q 'display notification' "$TEST_ROOT/osascript-args"
! grep -q 'display dialog\|sound name' "$TEST_ROOT/osascript-args"
''')

    def test_alerts_are_rate_limited_by_stable_title_not_message_details(self):
        self.run_shell(r'''
write_mode armed
alert_user() { printf '%s|%s\n' "$1" "$2" >> "$TEST_ROOT/alerts"; }
emit_alert 'Claude Watch：网络环境变化' 'PID=1 endpoint=198.51.100.1:443'
emit_alert 'Claude Watch：网络环境变化' 'PID=2 endpoint=198.51.100.2:443'
emit_alert 'Claude Watch：敏感目录文件描述符' 'different category'
[[ "$(wc -l < "$TEST_ROOT/alerts" | tr -d ' ')" == 2 ]]
''')

    def test_muted_alert_does_not_consume_cooldown_and_can_notify_after_restore(self):
        self.run_shell(r'''
write_mode paused
alert_user() { printf '%s\n' "$1" >> "$TEST_ROOT/alerts"; }
emit_alert 'Claude Watch：网络环境变化' 'while muted'
[[ ! -e "$ALERT_COOLDOWN_FILE" && ! -e "$TEST_ROOT/alerts" ]]
write_mode armed
emit_alert 'Claude Watch：网络环境变化' 'after restore'
[[ "$(cat "$TEST_ROOT/alerts")" == 'Claude Watch：网络环境变化' ]]
''')

    def test_alert_dispatch_does_not_clear_the_daemon_shell_traps(self):
        self.run_shell(r'''
write_mode armed
trap 'printf cleanup' EXIT
before=$(trap -p EXIT)
alert_user() { trap - EXIT TERM INT; return 0; }
emit_alert 'Claude Watch：网络环境变化' 'fixture'
after=$(trap -p EXIT)
[[ "$before" == "$after" ]]
trap - EXIT
''')

    def test_alert_severity_routes_info_warning_and_critical_without_promoting_network_samples(self):
        self.run_shell(r'''
write_mode armed
alert_user() { printf 'warning|%s\n' "$1" >> "$TEST_ROOT/alerts"; }
critical_alert_user() { printf 'critical|%s\n' "$1" >> "$TEST_ROOT/alerts"; }
emit_alert 'Claude Watch：警戒期间网络端点' 'PID=1 endpoint=198.51.100.1:443'
emit_alert 'Claude Watch：网络环境变化' 'warning evidence'
emit_alert 'Claude Watch：监控失效' 'critical evidence'
wait
[[ "$(cat "$TEST_ROOT/alerts")" == $'warning|Claude Watch：网络环境变化\ncritical|Claude Watch：监控失效' ]]
''')

    def test_critical_alert_is_async_and_same_title_opens_once_per_cooldown(self):
        self.run_shell(r'''
write_mode armed
critical_alert_user() { sleep 2; printf '%s\n' "$1" >> "$TEST_ROOT/critical"; }
before=$(date +%s)
emit_alert 'Claude Watch：监控失效' 'first'
after=$(date +%s)
[[ $((after-before)) -le 1 ]]
emit_alert 'Claude Watch：监控失效' 'second changed details'
wait
[[ "$(wc -l < "$TEST_ROOT/critical" | tr -d ' ')" == 1 ]]
''')

    def test_critical_alert_uses_dialog_while_warning_does_not(self):
        self.run_shell(r'''
source "$WATCH_SCRIPT"
test_state_paths
init_dirs
osascript() { printf '%s\n' "$@" > "$TEST_ROOT/critical-osascript-args"; }
write_mode armed
critical_alert_user 'Claude Watch：监控失效' 'fixture critical' armed
grep -q 'display dialog' "$TEST_ROOT/critical-osascript-args"
''')

    def test_scan_failure_writes_error_heartbeat(self):
        self.run_shell(r'''
DAEMON_STAMP=daemon
scan_targets() { return 1; }
monitor_tick
grep -q '|error|UNKNOWN$' "$HEARTBEAT_FILE"
wait
''')

    def test_background_service_candidates_not_hidden_by_other_active_sessions(self):
        out = self.run_shell(r'''
ACTIVE_PIDS=' 10'
launchctl() { printf 'PID Status Label\n10 0 com.anthropic.active\n20 0 com.anthropic.unrelated\n30 0 io.local.claudewatch.agent\n'; }
service_sample
''')
        self.assertEqual(out, "20|com.anthropic.unrelated\n")

    def test_lsof_permission_failure_is_not_empty_success(self):
        self.run_shell(r'''
lsof() { printf 'permission denied\n' >&2; return 1; }
if connection_sample 77; then exit 11; fi
''')

    def test_file_sample_excludes_cwd_and_memory_mappings(self):
        out = self.run_shell(r'''
lsof() { printf 'p77\nfcwd\nn%s/Desktop\nftxt\nn%s/Desktop/tool\nf4\nar\nn%s/.ssh/config\n' "$HOME" "$HOME" "$HOME"; }
file_sample 77
''')
        self.assertEqual(out, "77|4|r|SSH\n")

    def test_byte_counter_parser_uses_column_headers(self):
        out = self.run_shell(r'''
nettop() { printf ',bytes_out,bytes_in,\nclaude.77,456,123,\n'; }
byte_sample 77
''')
        self.assertEqual(out, "77|123|456\n")

    def test_byte_counter_batches_more_than_twenty_pids_without_dropping_results(self):
        out = self.run_shell(r'''
nettop() {
  count=0; waiting=0; pids=''
  for value in "$@"; do
    if [[ "$waiting" == 1 ]]; then pids="$pids $value"; count=$((count+1)); waiting=0
    elif [[ "$value" == -p ]]; then waiting=1; fi
  done
  [[ "$count" -le 20 ]] || return 99
  printf '%s\n' "$count" >> "$TEST_ROOT/nettop-calls"
  printf ',bytes_out,bytes_in,\n'
  for pid in $pids; do printf 'agent.%s,%s,%s,\n' "$pid" "$((pid * 10))" "$pid"; done
}
byte_sample '1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21'
''')
        self.assertEqual(out.count("\n"), 21)
        self.assertIn("1|1|10", out)
        self.assertIn("21|21|210", out)

    def test_byte_counter_batch_failure_does_not_emit_partial_success(self):
        self.run_shell(r'''
nettop() {
  waiting=0; has21=0
  for value in "$@"; do
    if [[ "$waiting" == 1 ]]; then [[ "$value" == 21 ]] && has21=1; waiting=0
    elif [[ "$value" == -p ]]; then waiting=1; fi
  done
  [[ "$has21" == 0 ]] || return 7
  printf ',bytes_out,bytes_in,\nagent.1,10,1,\n'
}
rc=0; out=$(byte_sample '1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21') || rc=$?
[[ "$rc" == 1 && -z "$out" ]]
''')

    def test_byte_counter_all_empty_successful_batches_are_unknown_not_zero(self):
        self.run_shell(r'''
nettop() { printf ',bytes_out,bytes_in,\n'; }
rc=0; out=$(byte_sample 77) || rc=$?
[[ "$rc" == 1 && -z "$out" ]]
''')

    def test_byte_counter_allows_an_empty_batch_before_a_later_real_counter(self):
        out = self.run_shell(r'''
nettop() {
  waiting=0; last=''
  for value in "$@"; do
    if [[ "$waiting" == 1 ]]; then last=$value; waiting=0
    elif [[ "$value" == -p ]]; then waiting=1; fi
  done
  printf ',bytes_in,bytes_out,\n'
  [[ "$last" == 20 ]] || printf 'agent.%s,210,420,\n' "$last"
}
byte_sample '1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21'
''')
        self.assertEqual(out, "21|210|420\n")

    def test_byte_counter_malformed_header_fails_without_zero_output(self):
        self.run_shell(r'''
nettop() { printf 'not,a,nettop,header\n'; }
rc=0; out=$(byte_sample 77) || rc=$?
[[ "$rc" == 1 && -z "$out" ]]
''')

    def test_health_requires_fresh_matching_heartbeat(self):
        self.run_shell(r'''
launchctl() { printf 'state = running\npid = 77\n'; }
process_stamp() { printf 'start\n'; }
check_health; [[ "$HEALTH" == DEGRADED ]]
atomic_text "$HEARTBEAT_FILE" "77|start|$(date +%s)|ok|GUARD"
check_health; [[ "$HEALTH" == RUNNING ]]
atomic_text "$HEARTBEAT_FILE" "77|old|$(date +%s)|ok|GUARD"
check_health; [[ "$HEALTH" == DEGRADED ]]
atomic_text "$HEARTBEAT_FILE" "77|start|1|ok|GUARD"
check_health; [[ "$HEALTH" == DEGRADED ]]
''')

    def browser_fixture(self, epoch='$(date +%s)', fingerprint="fingerprint"):
        return f'''
cat > "$TEST_ROOT/browser.conf" <<EOF
format=1
source=https://browserleaks.com/dns
observed_epoch={epoch}
network_fingerprint={fingerprint}
public_ip=1.1.1.1
dns_servers=8.8.8.8,9.9.9.9
EOF
online_probe() {{ PUBLIC_V4=1.1.1.1; PUBLIC_V6=unavailable; DNS_EGRESS=8.8.8.8; ONLINE_ISSUES=0; }}
'''

    def test_dns_crosscheck_reports_matching_evidence_without_safe_claim(self):
        out = self.run_shell(self.browser_fixture() + 'dns_check --online --browser-report "$TEST_ROOT/browser.conf"\n')
        self.assertIn("交叉证据", out)
        self.assertIn("未指定预期", out)
        self.assertIn("8.8.8.8,9.9.9.9", out)

    def test_dns_report_is_stale_after_network_change(self):
        out = self.run_shell(self.browser_fixture(fingerprint="other") + 'dns_check --online --browser-report "$TEST_ROOT/browser.conf"\n', 3)
        self.assertIn("过期/环境不同", out)
        self.assertNotIn("交叉证据", out)

    def test_dns_report_is_stale_after_fifteen_minutes(self):
        self.run_shell(self.browser_fixture(epoch="1") + 'dns_check --online --browser-report "$TEST_ROOT/browser.conf"\n', 3)

    def test_dns_allowed_list_flags_unexpected_resolver(self):
        out = self.run_shell(self.browser_fixture() + 'dns_check --online --browser-report "$TEST_ROOT/browser.conf" --expected-resolvers 8.8.8.8\n', 3)
        self.assertIn("未允许的解析出口 9.9.9.9", out)

    def test_report_content_is_not_executed(self):
        out = self.run_shell(self.browser_fixture() + r'''
printf '%s\n' 'observed_epoch=$(false)' > "$TEST_ROOT/payload"
sed '/^observed_epoch=/d' "$TEST_ROOT/browser.conf" > "$TEST_ROOT/report"
cat "$TEST_ROOT/payload" >> "$TEST_ROOT/report"
dns_check --browser-report "$TEST_ROOT/report"
''', 3)
        self.assertIn("字段不完整或无效", out)

    def test_cli_lease_exists_before_child_and_cleans_up_on_exit(self):
        self.run_shell(r'''
preflight_for_launch() { :; }
process_stamp() { printf wrapper-start; }
cat > "$TEST_ROOT/mock-cli" <<'MOCK'
#!/bin/bash
[[ "$1" == 'argument with spaces' ]] || exit 17
[[ -n "$(ls "$MOCK_SESSION_DIR"/*.session 2>/dev/null)" ]] || exit 18
exit 7
MOCK
chmod +x "$TEST_ROOT/mock-cli"
CLAUDE_CODE_BIN="$TEST_ROOT/mock-cli"
export MOCK_SESSION_DIR="$SESSION_DIR"
rc=0; launch_cli -- 'argument with spaces' || rc=$?
[[ "$rc" == 7 ]]
[[ -z "$(ls "$SESSION_DIR"/*.session 2>/dev/null)" ]]
''')

    def test_openai_desktop_identity_requires_matching_outer_bundle(self):
        self.run_shell(r'''
ps() {
  case "$*" in
    *uid=*) printf '%s\n' "$CURRENT_UID";;
    *comm=*|*command=*) printf '%s\n' '/Applications/ChatGPT.app/Contents/MacOS/ChatGPT';;
    *lstart=*) printf '%s\n' 'Fri Oct 16 10:00:00 2026';;
    *stat=*) printf 'S\n';;
  esac
}
bundle_identifier() { printf 'com.openai.codex\n'; }
read_identity 42
[[ "$CLASS" == openai-desktop-main ]]
bundle_identifier() { printf 'com.example.other\n'; }
read_identity 42
[[ "$CLASS" == unknown ]]
''')

    def test_codex_embedded_cli_is_classified_from_its_exact_path(self):
        self.run_shell(r'''
ps() {
  case "$*" in
    *uid=*) printf '%s\n' "$CURRENT_UID";;
    *comm=*|*command=*) printf '%s\n' '/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex';;
    *lstart=*) printf '%s\n' 'Fri Oct 16 10:00:00 2026';;
    *stat=*) printf 'S\n';;
  esac
}
read_identity 43
[[ "$CLASS" == codex-cli ]]
''')

    def test_node_argument_mentioning_codex_path_is_not_classified_as_codex_cli(self):
        self.run_shell(r'''
ps() {
  case "$*" in
    *uid=*) printf '%s\n' "$CURRENT_UID";;
    *comm=*) printf '%s\n' '/usr/local/bin/node';;
    *command=*) printf '%s\n' '/usr/local/bin/node /tmp/unrelated.js --text=/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex';;
    *lstart=*) printf '%s\n' 'Fri Oct 16 10:00:00 2026';;
    *stat=*) printf 'S\n';;
  esac
}
read_identity 44
[[ "$CLASS" == unknown ]]
''')

    def test_cached_identity_still_rejects_a_zombie_process(self):
        self.run_shell(r'''
printf '45|Fri Oct 16 10:00:00 2026|1|/opt/homebrew/bin/codex\n' > "$TMP_SCAN/processes"
ps() { printf '%s\n' 'Z /opt/homebrew/bin/codex'; }
if read_identity 45; then exit 17; fi
''')

    def test_codex_children_keep_codex_kind_and_claude_session_cannot_authorize_them(self):
        self.run_shell(r'''
printf '10|main|1|Codex\n11|child|10|curl\n' > "$TMP_SCAN/processes"
printf '10|main|codex-desktop-main\n11|child|codex-child\n' > "$TMP_SCAN/targets"
printf 'desktop|claude|10|main|0|-|1\n' > "$SESSION_DIR/claude.session"
classify_authorization
[[ "$MONITOR_MODE" == GUARD && "$UNAUTHORIZED_PIDS" == ' 10 11' ]]
printf 'desktop|codex|10|main|0|-|1\n' > "$SESSION_DIR/codex.session"
classify_authorization
[[ "$ACTIVE_PIDS" == ' 10 11' && -z "$UNAUTHORIZED_PIDS" ]]
''')

    def test_embedded_codex_cli_inherits_verified_openai_desktop_provider(self):
        self.run_shell(r'''
ps() {
  case "$*" in
    *-axo*)
      printf ' 10 1 %s Fri Oct 16 10:00:00 2026 /Applications/ChatGPT.app/Contents/MacOS/ChatGPT\n' "$CURRENT_UID"
      printf ' 11 10 %s Fri Oct 16 10:00:01 2026 /Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex\n' "$CURRENT_UID"
      printf ' 12 1 %s Fri Oct 16 10:00:02 2026 /opt/homebrew/bin/codex\n' "$CURRENT_UID";;
  esac
}
pgrep() { case " $* " in *" -a "*) ;; *) exit 19;; esac; printf '10\n11\n12\n'; }
read_identity() {
  case "$1" in
    10) CLASS=openai-desktop-main; START='Fri Oct 16 10:00:00 2026';;
    11) CLASS=codex-cli; START='Fri Oct 16 10:00:01 2026';;
    12) CLASS=codex-cli; START='Fri Oct 16 10:00:02 2026';;
  esac
}
scan_targets
grep -q '^11|Fri Oct 16 10:00:01 2026|openai-child$' "$TMP_SCAN/targets"
grep -q '^12|Fri Oct 16 10:00:02 2026|codex-cli$' "$TMP_SCAN/targets"
''')

    def test_published_snapshot_advertises_multi_app_capability(self):
        out = self.run_shell(r'''
printf '%s\n' '{"schema":1,"observed_epoch":1,"entry":{},"api":{}}' > "$TEST_ROOT/report.json"
source "$WATCH_SCRIPT"
tag_bridge publish "$TEST_ROOT/report.json" 77 fixture-start
''')
        self.assertIn('"monitor_version":"2.8.4"', out)
        self.assertIn('"monitored_apps":["claude","codex","chatgpt"]', out)

    def test_invalid_switcher_config_cannot_fall_back_to_legacy_preflight(self):
        self.run_shell(r'''
mkdir -p "$BASE_DIR/switcher"
printf broken > "$BASE_DIR/switcher/config.json"
check_health() { HEALTH=RUNNING; HEALTH_REASON=fixture; }
switcher_run() { return 4; }
preflight() { exit 88; }
preflight_for_launch no general claude
''', expected=1)

    def test_new_gate_is_rechecked_without_affecting_openai_launcher(self):
        self.run_shell(r'''
mkdir -p "$BASE_DIR/switcher"
printf '{}' > "$BASE_DIR/switcher/config.json"
check_health() { HEALTH=RUNNING; HEALTH_REASON=fixture; }
switcher_run() { printf '%s\n' "$*" >> "$TEST_ROOT/new-gate"; }
preflight() { printf legacy > "$TEST_ROOT/legacy-gate"; }
preflight_for_launch no general claude
[[ ! -e "$TEST_ROOT/legacy-gate" ]]
grep -q 'check --online --require-ready' "$TEST_ROOT/new-gate"
preflight_for_launch no general openai
[[ -e "$TEST_ROOT/legacy-gate" ]]
''')

    def test_empty_install_uses_automatic_guard_defaults(self):
        self.run_shell(r'''
[[ ! -e "$BASE_DIR/switcher/config.json" ]]
switcher_run() { [[ "$*" == 'config enabled' ]]; }
switcher_enabled
''')

    def test_disabled_policy_never_falls_back_to_legacy_gate(self):
        self.run_shell(r'''
check_health() { HEALTH=RUNNING; HEALTH_REASON=fixture; }
switcher_run() { return 3; }
preflight() { exit 88; }
preflight_for_launch yes general claude
''', expected=1)

    def test_claude_shell_launch_delegates_once_even_with_legacy_override(self):
        self.run_shell(r'''
require_macos() { :; }
require_installed() { :; }
switcher_run() { printf '%s\n' "$*" >> "$TEST_ROOT/launch-calls"; }
preflight_for_launch() { exit 89; }
launch_desktop --allow-changes
[[ "$(cat "$TEST_ROOT/launch-calls")" == 'launch --apply' ]]
''')


if __name__ == "__main__":
    unittest.main(verbosity=2)

