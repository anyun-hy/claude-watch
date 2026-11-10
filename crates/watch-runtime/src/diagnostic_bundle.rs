//! Offline, bounded, allowlisted diagnostic export. Never runs probes or reads accounts/config.
use crate::{build_identity, storage::StateStore};
use serde_json::{json, Map, Value};
use std::{fs::{self, OpenOptions}, io::{Read, Seek, SeekFrom}, os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf}, time::UNIX_EPOCH};

const FILE_LIMIT: usize = 256 * 1024;
const OUTPUT_LIMIT: usize = 2_000_000;
const MAX_RECORDS: usize = 200;

// Deliberately no generic "message", "detail", path, URL, endpoint, IP, node,
// argv, account, token, expectation, observation or arbitrary object-map key.
fn allowed(key: &str) -> bool {
    matches!(key, "schema" | "time" | "ts_unix_ms" | "at" | "timestamp" | "observed_at" | "updated_at"
        | "captured_at" | "completed_at" | "issued_at" | "valid_until" | "executed_at" | "received_at"
        | "expires_at" | "started_at" | "finished_at" | "elapsed_seconds" | "duration_ms"
        | "id" | "category" | "component" | "operation" | "event" | "stage" | "step" | "step_id"
        | "status" | "state" | "result" | "reason" | "reason_code" | "code" | "error_code"
        | "last_error_code" | "unavailable_reason" | "action" | "phase" | "previous_state"
        | "version" | "build" | "app_version" | "app_build" | "source_revision" | "source_dirty"
        | "source_tree_digest" | "build_identity" | "run_id" | "attempt_id" | "transaction_id"
        | "session_id" | "round_id" | "correlation_id" | "flow_id" | "producer_boot_id"
        | "executor_boot_id" | "boot_id" | "family" | "pid" | "count" | "seq" | "event_seq"
        | "policy_version" | "policy_digest" | "guard_policy_digest" | "configured_policy_version"
        | "saved_policy_version" | "permit_generation" | "command_seq" | "applied_command_seq"
        | "applied_policy_version" | "permit_state" | "enforcement_state" | "backend" | "network_backend"
        | "components_ready" | "sandbox_ready" | "identity_report" | "blocking_gates" | "ready"
        | "gateway_endpoint_protected" | "i01_passed" | "i02_passed" | "i03_passed"
        | "i04_passed" | "i05_passed" | "i06_passed" | "health" | "channel_diagnostic" | "failure"
        | "last_failure" | "dropped" | "write_failed" | "state_write_failed" | "health_write_failed"
        | "written" | "scope" | "shutdown_flush_guaranteed" | "log_health" | "eventError"
        | "active_flows" | "active_flows_count" | "new_connections_blocked" | "terminated_flows_count"
        | "blocked_new_connections" | "direct_fallback_blocked" | "channels" | "families"
        | "authoritative_permits" | "enforcement_receipts" | "claude" | "codex" | "chatgpt" | "openai"
        | "process_complete" | "process_confirmed_exited_count" | "process_sampled_at"
        | "network_quality" | "network_round_id" | "network_sampled_at" | "network_reused"
        | "activity_state" | "bytes_state" | "activity_sampled_at" | "publisher_error_code"
        | "sampling_diagnostics" | "requires_migration" | "vpn_match" | "verdict" | "reasons"
        | "exit_code" | "build_exit_code" | "install_exit_code" | "signal" | "truncated"
        | "file_count" | "url_count" | "target_pid" | "reply_code" | "reply_error" | "ae_error"
        | "source" | "cause_code" | "passed_count" | "producer_pid" | "verified_pid" | "return_id"
        | "os_status" | "unmanaged_process_count" | "apple_event_reply_confirmed" | "appkit_activated"
        | "instance_id" | "target" | "trigger" | "outcome" | "error" | "family_state" | "snapshot_seq"
        | "coverage_scope" | "protection_state" | "phases" | "elapsed_ms" | "log_available" | "log_rotated"
        | "omitted_lines" | "heartbeat_present" | "heartbeat_pid" | "heartbeat_status" | "heartbeat_age_seconds"
        | "process_found" | "start_identity_matches" | "native_path_matches" | "launchd_registered"
        | "launchd_state" | "launchd_pid" | "worker_verified" | "worker_error_code" | "source_error_code"
        | "backend_read_error" | "backend_healthy" | "native_backend_healthy" | "backend_receipt_age_seconds"
        | "snapshot_read_failed" | "snapshot_present" | "snapshot_age_seconds" | "installed" | "auto_start"
        | "keep_alive" | "proxy_present" | "proxy_read_failed" | "proxy_age_seconds" | "proxy_entry_verified"
        | "proxy_api_available" | "proxy_port_covered" | "context_available" | "same_candidate_context"
        | "source_sample_advanced" | "deadline_remaining_seconds" | "differences" | "field"
        | "source_observed_at" | "recorded_at" | "writer_boot_id" | "component_version" | "os_error" | "target_version" | "target_build" | "binary_sha256"
        | "dropped_queue_records" | "failed_write_records" | "counts_saturated"
        | "truncation" | "file_or_records" | "object_fields" | "array_items" | "depth_limit")
        || claude_watch_core::policy::PolicyCatalog::families().iter().any(|f| f.id == key)
}
fn safe_label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 192
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
        && !value.contains("http:") && !value.contains("https:")
}
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct TruncationTracker {
    object_fields: bool,
    array_items: bool,
    depth_limit: bool,
}

impl TruncationTracker {
    fn any(&self) -> bool {
        self.object_fields || self.array_items || self.depth_limit
    }
}

fn project(value: &Value, depth: usize, tracker: &mut TruncationTracker) -> Option<Value> {
    if depth > 10 {
        tracker.depth_limit = true;
        return None;
    }
    match value {
        Value::Object(object) => {
            let mut result = Map::new();
            let filtered: Vec<(&String, &Value)> = object.iter().filter(|(key, _)| allowed(key)).collect();
            if filtered.len() > 96 {
                tracker.object_fields = true;
            }
            for (key, child) in filtered.into_iter().take(96) {
                if let Some(child) = project(child, depth + 1, tracker) {
                    result.insert(key.clone(), child);
                }
            }
            Some(Value::Object(result))
        }
        Value::Array(array) => {
            if array.len() > 64 {
                tracker.array_items = true;
            }
            Some(Value::Array(
                array
                    .iter()
                    .take(64)
                    .filter_map(|v| project(v, depth + 1, tracker))
                    .collect(),
            ))
        }
        Value::String(s) if safe_label(s) => Some(value.clone()),
        Value::Bool(_) | Value::Number(_) | Value::Null => Some(value.clone()),
        _ => None,
    }
}

fn read_bounded(path: &Path, tail: bool) -> Result<(Vec<u8>, bool), &'static str> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_type().is_symlink() => return Err("unsafe_path"),
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err("missing"),
            Err(_) => return Err("unreadable"),
        }
    }
    #[cfg(target_os = "macos")]
    const NOFOLLOW: i32 = 0x0100 | 0x0004; // O_NOFOLLOW | O_NONBLOCK: a replaced FIFO cannot stall export.
    #[cfg(target_os = "linux")]
    const NOFOLLOW: i32 = 0x20000 | 0x0800;
    let mut file = OpenOptions::new().read(true).custom_flags(NOFOLLOW).open(path).map_err(|_| "unreadable")?;
    let metadata = file.metadata().map_err(|_| "unreadable")?;
    if !metadata.is_file() { return Err("not_regular_file"); }
    let mut truncated = metadata.len() > FILE_LIMIT as u64;
    if truncated && !tail { return Err("oversize"); }
    if truncated { file.seek(SeekFrom::End(-(FILE_LIMIT as i64))).map_err(|_| "unreadable")?; }
    let mut bytes = Vec::new();
    file.take(FILE_LIMIT as u64 + 1).read_to_end(&mut bytes).map_err(|_| "unreadable")?;
    if bytes.len() > FILE_LIMIT { bytes.truncate(FILE_LIMIT); truncated = true; }
    if truncated {
        // A partial first line is not a malformed record and must not be parsed.
        let start = bytes.iter().position(|b| *b == b'\n').map_or(bytes.len(), |n| n + 1);
        bytes.drain(..start);
    }
    Ok((bytes, truncated))
}

fn source(path: &Path, label: &str, json_lines: bool) -> Value {
    let (bytes, mut file_truncated) = match read_bounded(path, json_lines) {
        Ok(result) => result,
        Err(reason) => return json!({"source":label,"status":reason}),
    };
    let mut invalid = 0;
    let mut records = Vec::new();
    let lines: Vec<&[u8]> = if json_lines { bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()).collect() } else { vec![&bytes] };
    if lines.len() > MAX_RECORDS { file_truncated = true; }
    let mut tracker = TruncationTracker::default();
    for line in lines.iter().rev().take(MAX_RECORDS).rev() {
        if json_lines && line.len() > 64 * 1024 { invalid += 1; continue; }
        match serde_json::from_slice::<Value>(line) {
            Ok(value) => if let Some(safe) = project(&value, 0, &mut tracker) { records.push(safe); },
            Err(_) => invalid += 1,
        }
    }
    let overall_truncated = file_truncated || tracker.any();
    let mut result = json!({
        "source": label,
        "status": "read",
        "truncated": overall_truncated,
        "invalid_records": invalid,
        "records": records
    });
    if overall_truncated {
        result["truncation"] = json!({
            "file_or_records": file_truncated,
            "object_fields": tracker.object_fields,
            "array_items": tracker.array_items,
            "depth_limit": tracker.depth_limit
        });
    }
    result
}

fn recent(dir: &Path, prefix: &str, suffix: &str, limit: usize) -> (Vec<PathBuf>, &'static str) {
    if dir.ancestors().any(|p| fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink())) {
        return (vec![], "unsafe_path");
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (vec![], "missing"),
        Err(_) => return (vec![], "unreadable"),
    };
    let mut paths = Vec::new();
    let mut visited = 0;
    for entry in entries.take(513) {
        visited += 1;
        let Ok(entry) = entry else { continue; };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue; };
        if name.starts_with(prefix) && name.ends_with(suffix)
            && !(prefix == "initialization-" && name.starts_with("initialization-flow-")) {
            paths.push(entry.path());
        }
    }
    paths.sort_by_cached_key(|path| (fs::symlink_metadata(path).ok().and_then(|m| m.modified().ok()), path.clone()));
    paths.reverse();
    let limited = paths.len() > limit || visited > 512;
    paths.truncate(limit);
    let status = if limited { "bounded_recent_subset" } else if paths.is_empty() { "missing" } else { "read" };
    (paths, status)
}

/// This is historical diagnostic evidence; it does not establish current protection.
pub fn collect(storage: &StateStore) -> Value {
    collect_with_broker(storage, Path::new("/Library/Logs/ClaudeWatchGateway"))
}
fn collect_with_broker(storage: &StateStore, broker: &Path) -> Value {
    let mut sources = Vec::new();
    let base = storage.paths.base();
    for name in ["events.jsonl", "events.previous.jsonl", "traffic-events.jsonl", "traffic-events.previous.jsonl", "diagnostic-events.jsonl", "diagnostic-events.previous.jsonl"] {
        sources.push(source(&base.join(name), name, true));
    }
    for name in ["channel-supervision.json", "channel-events.json", "vpn-supervision.json", "seatbelt-runtime.json", "channel-log-health.json"] {
        sources.push(source(&storage.paths.watch().join("state").join(name), name, false));
    }
    let logs = storage.paths.watch().join("logs");
    for prefix in ["initialization-flow-", "initialization-", "controlled-entry-", "leak-diagnostics-"] {
        let (paths, status) = recent(&logs, prefix, ".jsonl", 3);
        sources.push(json!({"source":prefix,"status":status,"selection_limit":3}));
        for (index, path) in paths.iter().enumerate() {
            sources.push(source(path, &format!("{prefix}recent-{index}"), true));
        }
    }
    for name in ["events.jsonl", "events.jsonl.1", "events.jsonl.2"] {
        sources.push(source(&broker.join(name), &format!("gateway-{name}"), true));
    }
    let installer = storage.paths.home.join("Library/Logs/ClaudeWatchInstaller");
    let (runs, status) = recent(&installer, "reinstall-", "", 3);
    sources.push(json!({"source":"installer","status":status,"selection_limit":3}));
    for (index, path) in runs.iter().enumerate() {
        sources.push(source(&path.join("run.json"), &format!("installer-recent-{index}"), false));
    }
    // Keep a report for each source even when the total budget omits its payload.
    let mut used = 4096;
    for source in &mut sources {
        let bytes = serde_json::to_vec(source).map_or(OUTPUT_LIMIT, |v| v.len());
        if used + bytes > OUTPUT_LIMIT - 16384 {
            *source = json!({"source":source["source"],"status":"export_budget_exceeded"});
        }
        used += serde_json::to_vec(source).map_or(0, |v| v.len());
    }
    json!({"schema":1,"kind":"claude_watch_diagnostics","generated_at":std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64(),
        "exporter_build":build_identity::current(),"sources":sources,"bounded":true,
        "scope":"historical_evidence_not_current_protection","sensitive_fields":"omitted_by_allowlist",
        "projection_limits":{"file_tail_bytes":FILE_LIMIT,"records_per_file":MAX_RECORDS,"array_items_per_record":64,"nesting_depth":10},
        "omitted":"raw output, URLs, IPs, paths, node names, account data, credentials, arbitrary messages",
        "code_locations":{"channel_enforcer":"crates/watch-runtime/src/channel_enforcer.rs",
            "channel_supervisor":"crates/watch-runtime/src/channel_supervisor.rs",
            "channel_diagnostics":"crates/watch-runtime/src/channel_diagnostics.rs",
            "initialization":"monitor/Sources/FirstRunInitialization.swift",
            "controlled_entry":"monitor/ControlledEntry/ControlledEntryApp.swift",
            "gateway_broker":"crates/watch-gateway-broker/src/main.rs","reinstall":"monitor/reinstall.sh"}})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Paths;
    #[test]
    fn complete_snapshot_uses_file_budget_and_recent_logs_use_modification_time() {
        let root = std::env::temp_dir().join(format!("cw-large-snapshot-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let path = root.join("snapshot.json");
        let data = serde_json::to_vec(&json!({
            "families": {
                "claude": {"reason_code": "vpn_expectation_mismatched", "command_seq": 71},
                "openai": {"reason_code": "vpn_expectation_mismatched", "command_seq": 99}
            },
            "authoritative_permits": {
                "claude": {"permit_generation": 1},
                "openai": {"permit_generation": 2}
            },
            "enforcement_receipts": {
                "claude": {"action": "disconnect-and-force-quit"},
                "openai": {"action": "disconnect-channel"}
            },
            "private_padding": "private-network-address".repeat(4000)
        })).unwrap();
        assert!(data.len() > 64 * 1024 && data.len() < FILE_LIMIT);
        fs::write(&path, &data).unwrap();
        let snapshot = source(&path, "snapshot", false);
        assert_eq!(snapshot["invalid_records"], 0, "{snapshot}");
        assert_eq!(snapshot["records"][0]["families"]["claude"]["command_seq"], 71);
        assert_eq!(snapshot["records"][0]["families"]["openai"]["command_seq"], 99);
        assert_eq!(snapshot["records"][0]["authoritative_permits"]["openai"]["permit_generation"], 2);
        assert_eq!(snapshot["records"][0]["enforcement_receipts"]["openai"]["action"], "disconnect-channel");
        assert!(!snapshot.to_string().contains("private-network-address"));
        let old = root.join("initialization-flow-zzz.jsonl");
        let new = root.join("initialization-flow-aaa.jsonl");
        fs::write(&old, b"{}\n").unwrap(); fs::write(&new, b"{}\n").unwrap();
        fs::File::options().write(true).open(&old).unwrap().set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1))).unwrap();
        assert_eq!(recent(&root, "initialization-flow-", ".jsonl", 1).0, vec![new]);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn truncation_metadata_is_reported_when_arrays_objects_or_depth_exceed_limits() {
        let root = std::env::temp_dir().join(format!("cw-truncation-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();

        // 1. Array with 65 items (exceeding 64 limit)
        let array_path = root.join("oversize_array.json");
        let array_data = json!({
            "stage": "sampling",
            "reasons": (0..65).map(|i| format!("code_{i}")).collect::<Vec<_>>()
        });
        fs::write(&array_path, serde_json::to_vec(&array_data).unwrap()).unwrap();
        let array_source = source(&array_path, "oversize_array", false);
        assert_eq!(array_source["truncated"], true);
        assert_eq!(array_source["truncation"]["array_items"], true);
        assert_eq!(array_source["truncation"]["file_or_records"], false);
        assert_eq!(array_source["records"][0]["reasons"].as_array().unwrap().len(), 64);

        // 2. Normal small record without any truncation
        let normal_path = root.join("normal.json");
        let normal_data = json!({"status": "ok", "component": "enforcer"});
        fs::write(&normal_path, serde_json::to_vec(&normal_data).unwrap()).unwrap();
        let normal_source = source(&normal_path, "normal", false);
        assert_eq!(normal_source["truncated"], false);
        assert!(normal_source.get("truncation").is_none());

        // 3. Deeply nested structure exceeding depth 10
        let mut deep = json!({"status": "ok"});
        for _ in 0..12 {
            deep = json!({"state": deep});
        }
        let deep_path = root.join("deep.json");
        fs::write(&deep_path, serde_json::to_vec(&deep).unwrap()).unwrap();
        let deep_source = source(&deep_path, "deep", false);
        assert_eq!(deep_source["truncated"], true);
        assert_eq!(deep_source["truncation"]["depth_limit"], true);

        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn diagnostic_export_is_bounded_redacted_and_reports_evidence_gaps() {
        let root = std::env::temp_dir().join(format!("cw-export-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let storage = StateStore::new(Paths::new(&root).unwrap());
        fs::create_dir_all(storage.paths.base()).unwrap();
        let record = json!({"category":"channel-diagnostic","time":12,"channel_diagnostic":{
            "component":"channel_enforcer","stage":"termination_confirmed","executor_boot_id":"boot-123",
            "flow_id":"flow-456","command_seq":3,"failure":{"code":"fixture_failure","reason":"https://private.invalid"}},
            "url":"https://secret.invalid/key", "account":"private-account", "token":"private-token",
            "message":"PRIVATE-PAYLOAD", "args":["PRIVATE-ARGV"], "state":{"pid":123,"endpoint":"private-endpoint"}});
        let line = format!("{}\n", record);
        fs::write(storage.paths.base().join("events.jsonl"), line.repeat(4000)).unwrap();
        fs::write(storage.paths.base().join("diagnostic-events.jsonl"), b"invalid\n").unwrap();
        fs::create_dir_all(storage.paths.watch().join("state")).unwrap();
        std::os::unix::fs::symlink(storage.paths.base().join("events.jsonl"), storage.paths.watch().join("state/seatbelt-runtime.json")).unwrap();
        let broker = root.join("broker"); fs::create_dir(&broker).unwrap();
        fs::write(broker.join("events.jsonl"), b"{\"operation\":\"logging_recovery\",\"dropped_queue_records\":1,\"failed_write_records\":2,\"counts_saturated\":false}\n").unwrap();
        let bundle = collect_with_broker(&storage, &broker);
        let encoded = serde_json::to_string(&bundle).unwrap();
        assert!(encoded.len() < OUTPUT_LIMIT);
        for secret in ["secret.invalid", "private-account", "private-token", "PRIVATE-PAYLOAD", "PRIVATE-ARGV", "private-endpoint", "private.invalid"] {
            assert!(!encoded.contains(secret), "leaked {secret}");
        }
        assert!(encoded.contains("flow-456") && encoded.contains("fixture_failure"));
        let sources = bundle["sources"].as_array().unwrap();
        assert_eq!(sources[0]["truncated"], true);
        assert!(sources.iter().any(|s| s["status"] == "missing"));
        assert!(sources.iter().any(|s| s["status"] == "unsafe_path"));
        assert!(sources.iter().any(|s| s["invalid_records"] == 1));
        let recovery = sources.iter().find(|s| s["source"] == "gateway-events.jsonl").unwrap();
        assert_eq!(recovery["records"][0]["dropped_queue_records"], 1);
        assert_eq!(recovery["records"][0]["failed_write_records"], 2);
        assert_eq!(recovery["records"][0]["counts_saturated"], false);
        fs::remove_dir_all(root).unwrap();
    }
}
