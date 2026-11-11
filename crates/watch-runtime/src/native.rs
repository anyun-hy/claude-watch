//! Validated internal OS observation protocol. Raw argument data stays inside the runtime.
use crate::{
    commands::{ObserverAction, ReadCommand, ReadRunner},
    storage::strict_json,
};
use claude_watch_core::{
    error::{CoreError, Result},
    processes::Identity,
    tag_flow::Flow,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn notify_channel_update() {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("/usr/bin/notifyutil")
            .args(["-p", "io.local.watchpanel.channel_update"])
            .spawn();
    }
}
pub fn built_observer_path() -> Option<&'static std::path::Path> {
    let path = env!("CW_NATIVE_OBSERVER_BUILD_PATH");
    if path.is_empty() {
        None
    } else {
        Some(std::path::Path::new(path))
    }
}
pub fn built_process_control_path() -> Option<&'static std::path::Path> {
    let path = env!("CW_PROCESS_CONTROL_BUILD_PATH");
    if path.is_empty() {
        None
    } else {
        Some(std::path::Path::new(path))
    }
}
pub fn built_sandbox_launcher_path() -> Option<std::path::PathBuf> {
    if let Some(raw) = std::env::var_os("CW_SANDBOX_LAUNCHER_BUILD_PATH") {
        let candidate = std::path::PathBuf::from(raw);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let exe = std::env::current_exe().ok()?;
    let candidate = exe.parent()?.join("watch-sandbox-launcher");
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}
#[derive(Clone, Deserialize, Serialize)]
pub struct ProcessRecord {
    #[serde(flatten)]
    pub identity: Identity,
    #[serde(default)]
    pub bundle_path: Option<String>,
    #[serde(default)]
    pub bundle_id: Option<String>,
}
pub struct Inventory {
    pub uid: u32,
    pub(crate) requested_count: u64,
    pub processes: BTreeMap<u32, ProcessRecord>,
    pub unavailable: Vec<Value>,
    pub exited: Vec<u32>,
    pub complete: bool,
    pub diagnostic_reasons: BTreeMap<String, u32>,
    pub confirmed_exited_count: u32,
    pub started_at: f64,
    pub finished_at: f64,
}
impl Inventory {
    pub(crate) fn incomplete_summary(&self) -> String {
        let reasons = self.diagnostic_reasons.iter()
            .map(|(reason, count)| format!("{reason}:{count}"))
            .collect::<Vec<_>>().join(",");
        let accounted = self.processes.len() as u64 + self.exited.len() as u64 + self.unavailable.len() as u64;
        format!("requested_count={}, parsed_count={}, confirmed_exited_count={}, unavailable_count={}, unaccounted_count={}, reasons={reasons}",
            self.requested_count, self.processes.len(), self.confirmed_exited_count, self.unavailable.len(),
            self.requested_count.saturating_sub(accounted))
    }
}
pub struct Arguments {
    pub identity: Identity,
    pub tokens: Vec<String>,
    pub cwd: String,
    pub truncated: bool,
}
pub struct SocketResult {
    pub flows: Vec<Flow>,
    pub rows: Vec<Value>,
    pub dropped: BTreeMap<String, u64>,
    pub confirmed_exited_count: usize,
    pub complete: bool,
    pub parsed_count: usize,
    pub accepted_count: usize,
    pub observed_at: f64,
}
fn invalid() -> CoreError {
    CoreError::new(
        "invalid_native_observation",
        "原生采样回执格式、范围或时间无效",
    )
}
fn valid_identity(identity: &Identity, uid: u32) -> bool {
    identity.valid()
        && identity.uid == uid
        && !identity.start_stamp.is_empty()
        && identity.start_stamp.len() <= 80
        && !identity.start_stamp.chars().any(char::is_control)
}
fn envelope(value: &Value, sent: f64, received: f64, round: Option<&str>) -> Result<u32> {
    let uid = value["uid"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v > 0)
        .ok_or_else(invalid)?;
    let start = value["started_at"]
        .as_f64()
        .filter(|v| v.is_finite())
        .ok_or_else(invalid)?;
    let finish = value["finished_at"]
        .as_f64()
        .filter(|v| v.is_finite())
        .ok_or_else(invalid)?;
    if value["schema"] != 1
        || value["status"] != "ok"
        || !sent.is_finite()
        || !received.is_finite()
        || start < sent - 1.0
        || finish < start
        || finish > received + 1.0
        || received - finish > 10.0
        || finish - start > 8.0
        || round.is_some_and(|r| value["round_id"] != r)
    {
        return Err(invalid());
    }
    Ok(uid)
}
pub fn decode_inventory(value: &Value, sent: f64, received: f64) -> Result<Inventory> {
    let uid = envelope(value, sent, received, None)?;
    let rows = value["processes"]
        .as_array()
        .filter(|v| v.len() <= 65536)
        .ok_or_else(invalid)?;
    let mut processes = BTreeMap::new();
    for row in rows {
        let record: ProcessRecord = serde_json::from_value(row.clone()).map_err(|_| invalid())?;
        if !valid_identity(&record.identity, uid)
            || processes.insert(record.identity.pid, record).is_some()
        {
            return Err(invalid());
        }
    }
    let unavailable = value["unavailable"]
        .as_array()
        .filter(|v| v.len() <= 65536)
        .ok_or_else(invalid)?
        .clone();
    let exited: Vec<u32> =
        serde_json::from_value(value["exited"].clone()).map_err(|_| invalid())?;
    if unavailable
        .iter()
        .any(|v| v["pid"].as_u64().is_none() || v["code"].as_str().is_none())
        || exited.iter().any(|p| *p <= 1)
        || !matches!(value["state"].as_str(), Some("ok" | "partial"))
        || !value["truncated"].is_boolean()
    {
        return Err(invalid());
    }
    let requested = value["requested_count"].as_u64().ok_or_else(invalid)?;
    let complete = value["state"] == "ok"
        && value["truncated"] == false
        && unavailable.is_empty()
        && requested == processes.len() as u64 + exited.len() as u64;
    let mut diagnostic_reasons = BTreeMap::<String, u32>::new();
    if value["state"] != "ok" { diagnostic_reasons.insert("inventory_partial".into(), 1); }
    if value["truncated"] == true { diagnostic_reasons.insert("inventory_truncated".into(), 1); }
    if requested != processes.len() as u64 + exited.len() as u64 { diagnostic_reasons.insert("inventory_count_mismatch".into(), 1); }
    for row in &unavailable {
        let key = match row["code"].as_str() { Some("identity_unavailable") => "identity_unavailable", Some("inventory_deadline") => "inventory_deadline", _ => "other" };
        let count = diagnostic_reasons.entry(key.into()).or_default(); *count = count.saturating_add(1);
    }
    Ok(Inventory {
        uid,
        requested_count: requested,
        processes,
        unavailable,
        confirmed_exited_count: u32::try_from(exited.len()).unwrap_or(u32::MAX),
        exited,
        complete,
        diagnostic_reasons,
        started_at: value["started_at"].as_f64().unwrap(),
        finished_at: value["finished_at"].as_f64().unwrap(),
    })
}
pub fn decode_arguments(
    value: &Value,
    expected: &[Identity],
    round: &str,
    sent: f64,
    received: f64,
) -> Result<BTreeMap<u32, Arguments>> {
    let uid = envelope(value, sent, received, Some(round))?;
    let rows = value["argument_prefixes"]
        .as_array()
        .filter(|v| v.len() <= 2048)
        .ok_or_else(invalid)?;
    let expected: BTreeMap<_, _> = expected.iter().map(|p| (p.pid, p)).collect();
    let mut result = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for row in rows {
        let pid = row["pid"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(invalid)?;
        if !seen.insert(pid) || !expected.contains_key(&pid) {
            return Err(invalid());
        }
        if row["state"] != "ok" {
            continue;
        }
        let identity: Identity =
            serde_json::from_value(row["identity"].clone()).map_err(|_| invalid())?;
        if !valid_identity(&identity, uid)
            || identity.pid != pid
            || !identity.same_process(expected[&pid])
        {
            continue;
        }
        let tokens: Vec<String> =
            serde_json::from_value(row["arguments"].clone()).map_err(|_| invalid())?;
        let cwd = row["cwd"].as_str().ok_or_else(invalid)?;
        if tokens.len() > 256
            || tokens.iter().any(|v| v.len() > 16384 || v.contains('\0'))
            || cwd.len() > 16384
            || !row["truncated"].is_boolean()
        {
            return Err(invalid());
        }
        result.insert(
            pid,
            Arguments {
                identity,
                tokens,
                cwd: cwd.into(),
                truncated: row["truncated"].as_bool().unwrap(),
            },
        );
    }
    Ok(result)
}
pub fn decode_sockets(
    value: &Value,
    expected: &[Identity],
    round: &str,
    sent: f64,
    received: f64,
) -> Result<SocketResult> {
    let uid = envelope(value, sent, received, Some(round))?;
    let rows = value["socket_samples"]
        .as_array()
        .filter(|v| v.len() <= 2048)
        .ok_or_else(invalid)?;
    let expected: BTreeMap<_, _> = expected.iter().map(|p| (p.pid, p)).collect();
    let mut seen = BTreeSet::new();
    let mut flows = Vec::new();
    let mut dropped = BTreeMap::<String, u64>::new();
    let mut parsed = 0;
    let mut accepted = 0;
    let mut confirmed_exited_count = 0;
    let mut add_drop = |key: &str, count: u64| {
        *dropped.entry(key.into()).or_default() += count;
    };
    for row in rows {
        let pid = row["pid"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(invalid)?;
        if !seen.insert(pid) || !expected.contains_key(&pid) {
            return Err(invalid());
        }
        if row["code"] == "process_exited" {
            // The native observer emits exactly these fields for a confirmed exit.
            // Contradictory socket/identity payloads are not exit evidence.
            if row["state"] != "unknown"
                || !row.as_object().is_some_and(|v| {
                    v.len() == 3
                        && v.contains_key("pid")
                        && v.contains_key("state")
                        && v.contains_key("code")
                })
            {
                return Err(invalid());
            }
            confirmed_exited_count += 1;
            continue;
        }
        if !matches!(row["state"].as_str(), Some("ok" | "partial")) {
            add_drop(
                row["code"].as_str().unwrap_or("socket_sample_unavailable"),
                1,
            );
            continue;
        }
        let identity: Identity =
            serde_json::from_value(row["identity"].clone()).map_err(|_| invalid())?;
        let bound = valid_identity(&identity, uid)
            && identity.pid == pid
            && identity.same_process(expected[&pid]);
        let sockets = row["sockets"]
            .as_array()
            .filter(|v| v.len() <= 32768)
            .ok_or_else(invalid)?;
        let detail = row["dropped"].as_object().ok_or_else(invalid)?;
        for (key, count) in detail {
            let count = count
                .as_u64()
                .filter(|_| !key.is_empty() && key.len() <= 120)
                .ok_or_else(invalid)?;
            add_drop(key, count);
        }
        if !bound {
            add_drop("identity_changed", 1);
            continue;
        }
        for socket in sockets {
            parsed += 1;
            let mut wire = socket.clone();
            if let Some(object) = wire.as_object_mut() {
                object.remove("fd");
                object.remove("socket_state");
            }
            let flow = Flow::from_value(wire).map_err(|_| invalid())?;
            if flow.pid != pid {
                add_drop("foreign_socket_pid", 1);
                continue;
            }
            accepted += 1;
            flows.push(flow);
        }
        if row["state"] == "partial" && detail.is_empty() {
            add_drop("socket_sample_partial", 1);
        }
    }
    let missing = expected.len().saturating_sub(seen.len());
    if missing > 0 {
        add_drop("missing_target_sample", missing as u64);
    }
    flows.sort_by(|a, b| {
        (a.pid, &a.protocol, &a.local, &a.peer).cmp(&(b.pid, &b.protocol, &b.local, &b.peer))
    });
    flows.dedup();
    let complete = dropped.is_empty();
    Ok(SocketResult {
        flows,
        rows: rows.clone(),
        dropped,
        confirmed_exited_count,
        complete,
        parsed_count: parsed,
        accepted_count: accepted,
        observed_at: value["finished_at"].as_f64().unwrap(),
    })
}
pub struct Observer<'a, R: ReadRunner> {
    pub runner: &'a R,
}
impl<R: ReadRunner> Observer<'_, R> {
    pub fn environment(&self) -> Result<Value> {
        let (value, sent, received) = self.call(ObserverAction::Environment, Value::Null)?;
        envelope(&value, sent, received, None)?;
        Ok(value)
    }
    pub fn identities(&self, targets: &[Identity], round: &str) -> Result<BTreeMap<u32, Identity>> {
        if targets.is_empty() {
            return Ok(BTreeMap::new());
        }
        let (v, s, r) = self.call(
            ObserverAction::Identities,
            json!({"schema":1,"round_id":round,"targets":targets}),
        )?;
        let uid = envelope(&v, s, r, Some(round))?;
        let expected: BTreeMap<_, _> = targets.iter().map(|i| (i.pid, i)).collect();
        let mut result = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for row in v["identities"]
            .as_array()
            .filter(|r| r.len() <= 2048)
            .ok_or_else(invalid)?
        {
            let pid = row["pid"]
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(invalid)?;
            if !seen.insert(pid) || !expected.contains_key(&pid) {
                return Err(invalid());
            }
            if row["state"] != "ok" {
                continue;
            }
            let identity: Identity =
                serde_json::from_value(row["identity"].clone()).map_err(|_| invalid())?;
            if valid_identity(&identity, uid) && identity.same_process(expected[&pid]) {
                result.insert(pid, identity);
            }
        }
        Ok(result)
    }
    fn call(&self, action: ObserverAction, input: Value) -> Result<(Value, f64, f64)> {
        let bytes = if input.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(&input).map_err(|_| invalid())?
        };
        let sent = now();
        let output = self.runner.run(
            ReadCommand::Observer(action),
            &bytes,
            Duration::from_secs(8),
            8 * 1024 * 1024,
        )?;
        let received = now();
        if output.status != 0 || !output.stderr.is_empty() {
            return Err(CoreError::new(
                "native_observation_unavailable",
                "macOS 原生采样组件未完成本轮读取",
            ));
        }
        Ok((strict_json(&output.stdout)?, sent, received))
    }
    pub fn inventory(&self) -> Result<Inventory> {
        let (v, s, r) = self.call(ObserverAction::Inventory, Value::Null)?;
        decode_inventory(&v, s, r)
    }
    pub fn arguments(&self, targets: &[Identity], round: &str) -> Result<BTreeMap<u32, Arguments>> {
        if targets.is_empty() {
            return Ok(BTreeMap::new());
        }
        let (v, s, r) = self.call(
            ObserverAction::Arguments,
            json!({"schema":1,"round_id":round,"targets":targets}),
        )?;
        decode_arguments(&v, targets, round, s, r)
    }
    pub fn sockets(&self, targets: &[Identity], round: &str) -> Result<SocketResult> {
        let (v, s, r) = self.call(
            ObserverAction::Sockets,
            json!({"schema":1,"round_id":round,"targets":targets}),
        )?;
        decode_sockets(&v, targets, round, s, r)
    }
}
