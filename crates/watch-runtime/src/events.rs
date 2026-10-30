//! Private event history, bounded diagnostic export, and local alert cooldown.
#![forbid(unsafe_code)]

use crate::storage::{sha256, StateStore};
use claude_watch_core::error::{CoreError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
};

const EVENT_MAX_BYTES: usize = 1_048_576;
const EXPORT_MAX_BYTES: usize = 2_000_000;
const DEFAULT_COOLDOWN: f64 = 300.0;
const CRITICAL_COOLDOWN: f64 = 600.0;
#[cfg(target_os = "macos")]
const NOFOLLOW: i32 = 0x0100;
#[cfg(target_os = "linux")]
const NOFOLLOW: i32 = 0x20000;

fn invalid(message: &str) -> CoreError {
    CoreError::new("invalid_event", message)
}
fn valid_label(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
}

/// The log schema intentionally has no arbitrary message, argv, URL, account,
/// credential, cookie, token, controller secret, or process-command field.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct EventFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard_diagnostics: Option<crate::guard_diagnostics::GuardRound>,
}
impl EventFields {
    fn validate(&self) -> Result<()> {
        for value in [
            &self.operation,
            &self.account,
            &self.status,
            &self.code,
            &self.version,
            &self.action,
            &self.stage,
            &self.archive_method,
        ]
        .into_iter()
        .flatten()
        {
            if !valid_label(value, 160) {
                return Err(invalid("事件字段格式无效或疑似包含敏感内容"));
            }
        }
        if self
            .service_label
            .as_ref()
            .is_some_and(|v| !valid_label(v, 256))
        {
            return Err(invalid("后台任务名称无效"));
        }
        if self
            .elapsed_seconds
            .is_some_and(|v| !v.is_finite() || v < 0.0)
        {
            return Err(invalid("事件耗时无效"));
        }
        if self.pid.is_some_and(|v| v <= 1 || v > i32::MAX as u32) {
            return Err(invalid("事件进程身份无效"));
        }
        if let Some(value) = &self.guard_diagnostics { value.validate()?; }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    #[serde(default)]
    pub id: String,
    pub time: f64,
    pub category: String,
    #[serde(flatten)]
    pub fields: EventFields,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Mode {
    Armed { session: String },
    Paused,
    Snoozed { until: i64 },
}
impl Default for Mode {
    fn default() -> Self {
        Self::Armed {
            session: "default".into(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}
#[derive(Debug, Clone)]
pub struct Alert {
    pub title: String,
    pub message: String,
    pub severity: Severity,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyError {
    pub code: String,
    pub detail: String,
}
pub trait Notifier: Send + Sync {
    fn notify(&self, alert: &Alert) -> std::result::Result<(), NotifyError>;
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertOutcome {
    Sent,
    Muted,
    Cooldown,
    ClockRollback,
    InfoOnly,
    Failed(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Cooldowns {
    entries: BTreeMap<String, f64>,
}

pub struct EventStore {
    pub storage: StateStore,
}
pub struct EventHistory {
    pub events: Vec<Event>,
    pub invalid_records: usize,
}
/// Only fixed labels enter this stream. Probe payloads and free-form errors do not.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticEventInput {
    pub kind: String,
    pub source: String,
    pub outcome: String,
    pub reason: String,
    pub stage: Option<String>,
    pub elapsed_seconds: Option<f64>,
}
impl EventStore {
    pub fn new(storage: StateStore) -> Self {
        Self { storage }
    }
    fn events(&self) -> PathBuf {
        self.storage.paths.base().join("events.jsonl")
    }
    fn previous(&self) -> PathBuf {
        self.storage.paths.base().join("events.previous.jsonl")
    }
    fn stream_paths(&self, stream: &str) -> (PathBuf, PathBuf) {
        let base = self.storage.paths.base();
        match stream {
            "traffic" => (
                base.join("traffic-events.jsonl"),
                base.join("traffic-events.previous.jsonl"),
            ),
            "diagnostics" => (
                base.join("diagnostic-events.jsonl"),
                base.join("diagnostic-events.previous.jsonl"),
            ),
            _ => (self.events(), self.previous()),
        }
    }
    fn mode_path(&self) -> PathBuf {
        self.storage.paths.base().join("alert-mode.json")
    }
    fn cooldowns_path(&self) -> PathBuf {
        self.storage.paths.base().join("alert-cooldowns.json")
    }
    pub fn append(&self, category: &str, fields: EventFields, at: f64) -> Result<Event> {
        let stream = if category == "traffic-counter" {
            "traffic"
        } else {
            "events"
        };
        self.append_stream(stream, category, fields, at, false)?
            .ok_or_else(|| invalid("事件未写入"))
    }
    pub fn record_diagnostic(&self, input: &DiagnosticEventInput, at: f64) -> Result<bool> {
        let valid_source = matches!(
            (input.kind.as_str(), input.source.as_str()),
            ("dns", "netcoffee" | "ipleak") | ("webrtc", "netcoffee" | "local")
        );
        let valid_reason = match input.outcome.as_str() {
            "matched" => input.reason == "matched",
            "difference" => input.reason == "difference",
            "incomplete" => matches!(
                input.reason.as_str(),
                "timeout"
                    | "context_changed"
                    | "component_missing"
                    | "invalid_result"
                    | "page_failed"
                    | "script_failed"
                    | "network_error"
                    | "incomplete"
            ),
            _ => false,
        };
        if !valid_source
            || !valid_reason
            || input
                .stage
                .as_deref()
                .is_some_and(|s| !matches!(s, "dns" | "dns_images" | "dns_records" | "http" | "geoip" | "ice" | "collector"))
            || input
                .elapsed_seconds
                .is_some_and(|v| !v.is_finite() || !(0.0..=120.0).contains(&v))
        {
            return Err(invalid("诊断日志只接受固定的来源和状态"));
        }
        let category = if input.kind == "dns" {
            "dns-diagnostic"
        } else {
            "webrtc-diagnostic"
        };
        Ok(self
            .append_stream(
                "diagnostics",
                category,
                EventFields {
                    operation: Some(input.kind.clone()),
                    action: Some(input.source.clone()),
                    status: Some(input.outcome.clone()),
                    code: Some(input.reason.clone()),
                    stage: input.stage.clone(),
                    elapsed_seconds: input.elapsed_seconds,
                    ..Default::default()
                },
                at,
                true,
            )?
            .is_some())
    }
    pub fn record_guard_diagnostic(
        &self,
        round: &crate::guard_diagnostics::GuardRound,
        at: f64,
    ) -> Result<bool> {
        round.validate()?;
        let status = if round.before.decision == "ok" && round.after.decision == "ok" {
            "ok"
        } else if round.before.decision == "disabled" || round.after.decision == "disabled" {
            "disabled"
        } else {
            "unknown"
        };
        Ok(self
            .append_stream(
                "diagnostics",
                "guard-diagnostic",
                EventFields {
                    operation: Some("environment".into()),
                    action: Some("environment".into()),
                    status: Some(status.into()),
                    guard_diagnostics: Some(round.clone()),
                    ..Default::default()
                },
                at,
                true,
            )?
            .is_some())
    }
    fn append_stream(
        &self,
        stream: &str,
        category: &str,
        fields: EventFields,
        at: f64,
        deduplicate: bool,
    ) -> Result<Option<Event>> {
        if !valid_label(category, 80) || !at.is_finite() || at < 0.0 {
            return Err(invalid("事件类别或时间无效"));
        }
        fields.validate()?;
        let lock_name = match stream {
            "traffic" => "traffic-events",
            "diagnostics" => "diagnostic-events",
            _ => "events",
        };
        let _lock = self.storage.lock(lock_name, None)?;
        let (path, previous) = self.stream_paths(stream);
        self.storage.guarded(&path)?;
        self.storage
            .private_dir(path.parent().ok_or_else(|| invalid("事件路径无效"))?)?;
        if deduplicate {
            let bytes = self
                .storage
                .read_bytes(&path, EXPORT_MAX_BYTES)?
                .unwrap_or_default();
            if Self::parse(&bytes)
                .iter()
                .rev()
                .find(|event| event.category == category && event.fields.action == fields.action)
                .is_some_and(|event| {
                    event.fields.status == fields.status
                        && event.fields.code == fields.code
                        && event.fields.stage == fields.stage
                        && match (&event.fields.guard_diagnostics, &fields.guard_diagnostics) {
                            (Some(a), Some(b)) => a.same_condition(b),
                            (None, None) => true,
                            _ => false,
                        }
                        && (0.0..300.0).contains(&(at - event.time))
                })
            {
                return Ok(None);
            }
        }
        if fs::metadata(&path)
            .map(|m| m.len() as usize > EVENT_MAX_BYTES)
            .unwrap_or(false)
        {
            self.storage.guarded(&previous)?;
            fs::rename(&path, &previous)
                .map_err(|_| CoreError::new("event_rotation_failed", "事件日志轮转失败"))?;
        }
        let event = Event {
            id: uuid::Uuid::new_v4().simple().to_string(),
            time: at,
            category: category.into(),
            fields,
        };
        let mut raw = serde_json::to_vec(&event).map_err(|_| invalid("事件无法序列化"))?;
        raw.push(b'\n');
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(NOFOLLOW)
            .open(&path)
            .map_err(|_| CoreError::new("event_write_failed", "私有事件日志不可写"))?;
        file.write_all(&raw)
            .and_then(|_| file.sync_data())
            .map_err(|_| CoreError::new("event_write_failed", "私有事件日志不可写"))?;
        Ok(Some(event))
    }
    fn parse(bytes: &[u8]) -> Vec<Event> {
        bytes
            .split(|b| *b == b'\n')
            .filter_map(|line| serde_json::from_slice::<Event>(line).ok())
            .filter(|v| {
                v.time.is_finite()
                    && v.time >= 0.0
                    && valid_label(&v.category, 80)
                    && v.fields.validate().is_ok()
            })
            .collect()
    }
    /// Reads only the bounded current and previous files for each stream.
    /// A partial trailing write is ignored; invalid complete lines are reported.
    pub fn history(&self) -> Result<EventHistory> {
        let mut events = Vec::new();
        let mut invalid_records = 0;
        for (stream_index, stream) in ["events", "traffic", "diagnostics"].into_iter().enumerate() {
            let (current, previous) = self.stream_paths(stream);
            for (file_index, path) in [previous, current].into_iter().enumerate() {
                let bytes = self
                    .storage
                    .read_bytes(&path, EXPORT_MAX_BYTES)?
                    .unwrap_or_default();
                for (line_index, chunk) in bytes.split_inclusive(|b| *b == b'\n').enumerate() {
                    let complete = chunk.ends_with(b"\n");
                    let line = chunk.strip_suffix(b"\n").unwrap_or(chunk);
                    if line.is_empty() {
                        continue;
                    }
                    match serde_json::from_slice::<Event>(line) {
                        Ok(mut event)
                            if event.time.is_finite()
                                && event.time >= 0.0
                                && valid_label(&event.category, 80)
                                && event.fields.validate().is_ok() =>
                        {
                            if event.id.is_empty() {
                                event.id =
                                    format!("legacy-{stream_index}-{file_index}-{line_index}");
                            }
                            events.push(event);
                        }
                        _ if !complete => {}
                        _ => invalid_records += 1,
                    }
                }
            }
        }
        events.sort_by(|a, b| b.time.total_cmp(&a.time).then_with(|| b.id.cmp(&a.id)));
        Ok(EventHistory {
            events,
            invalid_records,
        })
    }
    pub fn recent(&self, maximum: usize) -> Result<Vec<Event>> {
        let maximum = maximum.clamp(1, 200);
        let bytes = self
            .storage
            .read_bytes(&self.events(), EXPORT_MAX_BYTES)?
            .unwrap_or_default();
        let mut values = Self::parse(&bytes);
        if values.len() > maximum {
            values.drain(..values.len() - maximum);
        }
        Ok(values)
    }
    pub fn recent_non_traffic(&self, maximum: usize) -> Result<Vec<Event>> {
        let bytes = self
            .storage
            .read_bytes(&self.events(), EXPORT_MAX_BYTES)?
            .unwrap_or_default();
        let mut values: Vec<_> = Self::parse(&bytes)
            .into_iter()
            .filter(|event| event.category != "traffic-counter")
            .collect();
        let maximum = maximum.clamp(1, 200);
        if values.len() > maximum {
            values.drain(..values.len() - maximum);
        }
        Ok(values)
    }
    /// Export only structured, redacted event history; it never exports raw
    /// process, account, network, configuration, or notification data.
    pub fn export(&self, maximum: usize) -> Result<Value> {
        let maximum = maximum.clamp(1, 400);
        let history = self.history()?;
        let mut values: Vec<_> = history.events.into_iter().take(maximum).collect();
        values.reverse();
        Ok(json!({"schema":1,"events":values,"bounded":true,"sensitive_fields":"excluded"}))
    }
    pub fn arm(&self, session: &str, at: f64) -> Result<Mode> {
        if !valid_label(session, 128) || !at.is_finite() {
            return Err(invalid("警戒会话无效"));
        }
        let mode = Mode::Armed {
            session: session.into(),
        };
        self.save_mode(&mode)?;
        self.append(
            "arm",
            EventFields {
                action: Some("arm".into()),
                ..Default::default()
            },
            at,
        )?;
        Ok(mode)
    }
    pub fn pause(&self, at: f64) -> Result<Mode> {
        let mode = Mode::Paused;
        self.save_mode(&mode)?;
        self.append(
            "pause",
            EventFields {
                action: Some("pause".into()),
                ..Default::default()
            },
            at,
        )?;
        Ok(mode)
    }
    pub fn snooze(&self, minutes: u16, at: f64) -> Result<Mode> {
        if !(1..=1440).contains(&minutes) || !at.is_finite() {
            return Err(invalid("暂停时间须为 1–1440 分钟"));
        }
        let mode = Mode::Snoozed {
            until: (at + f64::from(minutes) * 60.0) as i64,
        };
        self.save_mode(&mode)?;
        self.append(
            "snooze",
            EventFields {
                action: Some("snooze".into()),
                count: Some(u32::from(minutes)),
                ..Default::default()
            },
            at,
        )?;
        Ok(mode)
    }
    fn save_mode(&self, mode: &Mode) -> Result<()> {
        let _lock = self.storage.lock("alert-mode", None)?;
        self.storage.atomic_json(
            &self.mode_path(),
            &serde_json::to_value(mode).map_err(|_| invalid("通知模式无效"))?,
        )
    }
    pub fn mode(&self) -> Mode {
        if !self.mode_path().exists() {
            if let Ok(Some(bytes)) = self
                .storage
                .read_bytes(&self.storage.paths.watch().join("state/mode"), 4096)
            {
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    let text = text.trim();
                    if text == "paused" {
                        return Mode::Paused;
                    }
                    if let Some(until) = text
                        .strip_prefix("until:")
                        .and_then(|v| v.parse::<i64>().ok())
                        .filter(|v| *v >= 0)
                    {
                        return Mode::Snoozed { until };
                    }
                    if let Some(session) =
                        text.strip_prefix("armed:").filter(|v| valid_label(v, 128))
                    {
                        return Mode::Armed {
                            session: session.into(),
                        };
                    }
                }
            }
        }
        self.storage
            .read_json(&self.mode_path(), Value::Null)
            .ok()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default()
    }
    pub fn notifications_enabled(&self, at: f64) -> bool {
        match self.mode() {
            Mode::Paused => false,
            Mode::Snoozed { until } => at >= until as f64,
            Mode::Armed { .. } => true,
        }
    }
    fn cooldown_seconds(alert: &Alert) -> f64 {
        if alert.severity == Severity::Critical {
            CRITICAL_COOLDOWN
        } else {
            DEFAULT_COOLDOWN
        }
    }
    fn key(alert: &Alert) -> String {
        sha256(alert.title.as_bytes())
    }
    pub fn emit<N: Notifier + ?Sized>(
        &self,
        notifier: &N,
        alert: &Alert,
        at: f64,
    ) -> Result<AlertOutcome> {
        if alert.title.trim().is_empty()
            || alert.title.len() > 240
            || alert.title.chars().any(char::is_control)
            || alert.message.len() > 2_000
            || !at.is_finite()
        {
            return Err(invalid("通知内容无效"));
        }
        if !self.notifications_enabled(at) {
            return Ok(AlertOutcome::Muted);
        }
        if alert.severity == Severity::Info {
            return Ok(AlertOutcome::InfoOnly);
        }
        let _lock = self.storage.lock("alert-cooldowns", None)?;
        let mut cooldowns: Cooldowns = self
            .storage
            .read_json(&self.cooldowns_path(), json!({}))
            .ok()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let key = Self::key(alert);
        if let Some(last) = cooldowns.entries.get(&key).copied() {
            if at < last {
                return Ok(AlertOutcome::ClockRollback);
            }
            if at - last < Self::cooldown_seconds(alert) {
                return Ok(AlertOutcome::Cooldown);
            }
        }
        if alert.severity == Severity::Critical {
            // Reserve before a modal notification so retries cannot create
            // repeated dialogs while the first request awaits dismissal.
            cooldowns.entries.insert(key.clone(), at);
            self.storage.atomic_json(
                &self.cooldowns_path(),
                &serde_json::to_value(&cooldowns).map_err(|_| invalid("冷却状态无效"))?,
            )?;
        }
        match notifier.notify(alert) {
            Ok(()) => {
                cooldowns.entries.insert(key, at);
                self.storage.atomic_json(
                    &self.cooldowns_path(),
                    &serde_json::to_value(cooldowns).map_err(|_| invalid("冷却状态无效"))?,
                )?;
                self.append(
                    "alert-dispatched",
                    EventFields {
                        status: Some("sent".into()),
                        action: Some(
                            match alert.severity {
                                Severity::Critical => "critical",
                                Severity::Warning => "warning",
                                Severity::Info => "info",
                            }
                            .into(),
                        ),
                        ..Default::default()
                    },
                    at,
                )?;
                Ok(AlertOutcome::Sent)
            }
            Err(error) => {
                let _ = self.append(
                    "alert-failed",
                    EventFields {
                        status: Some("failed".into()),
                        code: Some(if valid_label(&error.code, 80) {
                            error.code
                        } else {
                            "notify_failed".into()
                        }),
                        ..Default::default()
                    },
                    at,
                );
                Ok(AlertOutcome::Failed("notification_failed".into()))
            }
        }
    }
    /// `test-alert` maps here. The dispatcher supplies a platform notifier; this
    /// module neither invokes osascript nor claims delivery when it fails.
    pub fn test_alert<N: Notifier + ?Sized>(&self, notifier: &N, at: f64) -> Result<AlertOutcome> {
        let alert = Alert {
            title: "Claude-Watch-Test".into(),
            message: "Claude Watch notification test".into(),
            severity: Severity::Warning,
        };
        self.emit(notifier, &alert, at)
    }
}
