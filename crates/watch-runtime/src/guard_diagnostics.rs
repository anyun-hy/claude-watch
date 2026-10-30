//! Privacy-bounded observations for troubleshooting guard decisions.
//! These are sampled immediately after each decision and never feed policy.
use crate::{
    config_store::guard_heartbeat_policy_matches,
    storage::{strict_json, StateStore},
};
use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_AGE: f64 = 7.0 * 24.0 * 60.0 * 60.0;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GuardPhase {
    /// The actual state returned by the existing decision, not a new decision.
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_healthy: Option<bool>,
    /// Process identity/heartbeat liveness used by the guard. It may be true
    /// while the independent activity sample is incomplete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard_backend_healthy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_native: Option<bool>,
    pub backend_reason: String,
    pub enabled: bool,
    pub guard_enabled: bool,
    /// Heartbeat details below are a separate read immediately after the decision.
    pub sampled_at: f64,
    pub backend_heartbeat_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_heartbeat_age_seconds: Option<f64>,
    pub guard_heartbeat_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard_heartbeat_age_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard_heartbeat_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_matches: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GuardRound {
    pub observation_id: String,
    pub before: GuardPhase,
    pub after: GuardPhase,
}

#[derive(Default)]
pub struct GuardCapture {
    pub before: Option<GuardPhase>,
    pub after: Option<GuardPhase>,
}

fn backend_reason(detail: &str) -> &'static str {
    match detail {
        "未找到或无法读取采集后台心跳" => "heartbeat_unreadable",
        "后台心跳编码无效" => "heartbeat_encoding",
        "心跳未报告有效采样" => "sample_not_ok",
        "心跳 PID 无效" => "pid_invalid",
        "心跳时间字段无效" => "time_invalid",
        "后台心跳已过期或时间异常" => "heartbeat_stale",
        "系统进程采样失败" => "process_sample_failed",
        "心跳 PID 已退出或无法确认" => "pid_unconfirmed",
        "采集后台用户身份无效" => "uid_invalid",
        "心跳 PID 的启动身份不匹配" => "identity_mismatch",
        "launchd 任务、PID 或运行状态未通过核对" => "job_unconfirmed",
        "当前采集后台为旧组件，不支持原生观察租约" => "legacy_backend",
        "原生采集后台身份与心跳已核对" => "confirmed",
        _ => "unavailable",
    }
}

fn age(now: f64, timestamp: Option<f64>) -> Option<f64> {
    timestamp
        .filter(|t| t.is_finite())
        .map(|t| now - t)
        .filter(|n| n.is_finite() && n.abs() <= MAX_AGE)
}

/// Never stores PID, policy digest, addresses, node names, paths or error text.
pub fn capture_phase(store: &StateStore, config: &Config, local: &Value, now: f64) -> GuardPhase {
    let (backend_status, backend_age) =
        match store.read_bytes(&store.paths.watch().join("state/heartbeat"), 4096) {
            Ok(None) => ("missing", None),
            Err(_) => ("unreadable", None),
            Ok(Some(bytes)) => match std::str::from_utf8(&bytes) {
                Ok(text) => {
                    let fields: Vec<_> = text.trim().split('|').collect();
                    if fields.len() != 5 {
                        ("invalid", None)
                    } else {
                        let status = match fields[3] {
                            "ok" => "ok",
                            "error" => "error",
                            _ => "invalid",
                        };
                        (status, age(now, fields[2].parse::<f64>().ok()))
                    }
                }
                Err(_) => ("invalid", None),
            },
        };
    let (guard_status, guard_age, guard_code, matches_policy) =
        match store.read_bytes(&store.paths.base().join("guard-heartbeat.json"), 4096) {
            Ok(None) => ("missing", None, None, None),
            Err(_) => ("unreadable", None, None, None),
            Ok(Some(bytes)) => match strict_json(&bytes) {
                Ok(value) if value.is_object() => {
                    let status = match value["status"].as_str() {
                        Some("ok") => "ok",
                        Some("degraded") => "degraded",
                        Some("unknown") => "unknown",
                        Some("disabled") => "disabled",
                        Some("protection_triggered") => "protection_triggered",
                        _ => "invalid",
                    };
                    let matches_policy = guard_heartbeat_policy_matches(&value, config);
                    let code = value["code"].as_str().map(|code| {
                        match code {
                            "invalid_native_observation"
                            | "native_observation_unavailable"
                            | "desktop_inventory_incomplete"
                            | "process_metadata_unavailable"
                            | "state_io_failed"
                            | "unsafe_path"
                            | "home_owner_mismatch"
                            | "invalid_config"
                            | "invalid_snapshot_producer"
                            | "snapshot_producer_changed"
                            | "sampling_failed" => code,
                            _ => "other",
                        }
                        .to_owned()
                    });
                    (
                        status,
                        age(now, value["time"].as_f64()),
                        code,
                        matches_policy,
                    )
                }
                _ => ("invalid", None, None, None),
            },
        };
    let decision = match local["guard_state"].as_str() {
        Some("ok") => "ok",
        Some("unknown") => "unknown",
        Some("disabled") => "disabled",
        _ => "unavailable",
    };
    GuardPhase {
        decision: decision.into(),
        backend_healthy: local["backend_healthy"].as_bool(),
        guard_backend_healthy: local["guard_backend_healthy"].as_bool(),
        backend_native: local["backend_native"].as_bool(),
        backend_reason: backend_reason(local["backend_detail"].as_str().unwrap_or("")).into(),
        enabled: config.enabled,
        guard_enabled: config.guard_enabled,
        sampled_at: now,
        backend_heartbeat_status: backend_status.into(),
        backend_heartbeat_age_seconds: backend_age,
        guard_heartbeat_status: guard_status.into(),
        guard_heartbeat_age_seconds: guard_age,
        guard_heartbeat_code: guard_code,
        policy_matches: matches_policy,
    }
}

impl GuardPhase {
    fn validate(&self) -> bool {
        matches!(
            self.decision.as_str(),
            "ok" | "unknown" | "disabled" | "unavailable"
        ) && matches!(
            self.backend_reason.as_str(),
            "heartbeat_unreadable"
                | "heartbeat_encoding"
                | "sample_not_ok"
                | "pid_invalid"
                | "time_invalid"
                | "heartbeat_stale"
                | "process_sample_failed"
                | "pid_unconfirmed"
                | "uid_invalid"
                | "identity_mismatch"
                | "job_unconfirmed"
                | "legacy_backend"
                | "confirmed"
                | "unavailable"
        ) && matches!(
            self.backend_heartbeat_status.as_str(),
            "ok" | "error" | "missing" | "unreadable" | "invalid"
        ) && matches!(
            self.guard_heartbeat_status.as_str(),
            "ok" | "degraded" | "unknown" | "disabled" | "protection_triggered" | "missing" | "unreadable" | "invalid"
        ) && self.guard_heartbeat_code.as_deref().is_none_or(|code| {
            matches!(
                code,
                "invalid_native_observation"
                    | "native_observation_unavailable"
                    | "desktop_inventory_incomplete"
                    | "process_metadata_unavailable"
                    | "state_io_failed"
                    | "unsafe_path"
                    | "home_owner_mismatch"
                    | "invalid_config"
                    | "invalid_snapshot_producer"
                    | "snapshot_producer_changed"
                    | "sampling_failed"
                    | "other"
            )
        }) && self.sampled_at.is_finite()
            && self.sampled_at >= 0.0
            && [
                self.backend_heartbeat_age_seconds,
                self.guard_heartbeat_age_seconds,
            ]
            .into_iter()
            .flatten()
            .all(|value| value.is_finite() && value.abs() <= MAX_AGE)
    }
    fn same_condition(&self, other: &Self) -> bool {
        fn freshness(value: Option<f64>, limit: f64) -> &'static str {
            match value {
                None => "unknown",
                Some(value) if value < 0.0 => "future",
                Some(value) if value <= limit => "fresh",
                Some(_) => "stale",
            }
        }
        self.decision == other.decision
            && self.backend_healthy == other.backend_healthy
            && self.guard_backend_healthy == other.guard_backend_healthy
            && self.backend_native == other.backend_native
            && self.backend_reason == other.backend_reason
            && self.enabled == other.enabled
            && self.guard_enabled == other.guard_enabled
            && self.backend_heartbeat_status == other.backend_heartbeat_status
            && self.guard_heartbeat_status == other.guard_heartbeat_status
            && self.guard_heartbeat_code == other.guard_heartbeat_code
            && self.policy_matches == other.policy_matches
            && freshness(self.backend_heartbeat_age_seconds, 30.0)
                == freshness(other.backend_heartbeat_age_seconds, 30.0)
            && freshness(self.guard_heartbeat_age_seconds, 35.0)
                == freshness(other.guard_heartbeat_age_seconds, 35.0)
    }
}
impl GuardRound {
    pub fn validate(&self) -> Result<()> {
        if uuid::Uuid::parse_str(&self.observation_id).is_err()
            || !self.before.validate()
            || !self.after.validate()
        {
            return Err(CoreError::new(
                "invalid_guard_diagnostic",
                "保护心跳诊断字段无效",
            ));
        }
        Ok(())
    }
    pub fn same_condition(&self, other: &Self) -> bool {
        self.before.same_condition(&other.before) && self.after.same_condition(&other.after)
    }
}
