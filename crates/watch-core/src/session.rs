//! Complete controlled-session transitions. All observations and time are explicit inputs.
//! Persistence and action ownership are handled by watch-runtime under a shared file lock.
use crate::error::{CoreError, Result};
use crate::network::public_unicast;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const UNKNOWN_LIMIT: u32 = 2;
/// A transient sampling gap needs both repeated observations and time to
/// persist before it can stop a running Claude session.
pub const UNKNOWN_GRACE: f64 = 15.0;
pub const RISK_EVIDENCE_TTL: f64 = 300.0;
pub const AUDIT_EGRESS_TTL: f64 = 30.0;
pub const GUARD_EGRESS_TTL: f64 = 10.0;
pub const GROUP_KEY: &str = "desktop_group_v1";
pub const GROUP_RECHECK_KEY: &str = "desktop_group_recheck_v1";
pub const GROUP_CONTINUITY_KEY: &str = "desktop_group_continuity_v1";
pub const MAX_DESKTOP_MEMBERS: usize = 32;

pub fn canonical_desktops(mut members: Vec<Desktop>) -> Result<Vec<Desktop>> {
    if members.len() > MAX_DESKTOP_MEMBERS || members.iter().any(|d| !d.valid()) {
        return Err(CoreError::new(
            "desktop_identity_unavailable",
            "主进程集合超限或身份无效",
        ));
    }
    members.sort_by_key(|d| (d.pid, d.start_seconds, d.start_microseconds));
    if members.windows(2).any(|pair| pair[0].pid == pair[1].pid) {
        return Err(CoreError::new(
            "desktop_inventory_incomplete",
            "同一轮主进程身份重复或冲突",
        ));
    }
    Ok(members)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reason {
    pub code: String,
    pub detail: String,
    pub source: String,
    pub observed_at: f64,
}
impl Reason {
    pub fn new(code: &str, detail: &str, now: f64) -> Self {
        Self {
            code: code.chars().take(80).collect(),
            detail: detail.chars().take(240).collect(),
            source: "session guard".into(),
            observed_at: now,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Egress {
    pub ip: String,
    pub country: String,
    pub observed_at: f64,
    pub source: String,
}
impl Egress {
    pub fn parse(value: &Value, now: f64) -> Option<Self> {
        let ip = public_unicast(value.get("ip")?.as_str()?)?;
        let country = value.get("country")?.as_str()?;
        let observed_at = value.get("observed_at")?.as_f64()?;
        if country.len() != 2
            || !country.bytes().all(|c| c.is_ascii_uppercase())
            || !observed_at.is_finite()
            || observed_at <= 0.0
            || observed_at > now + 5.0
        {
            return None;
        }
        let source = value
            .get("source")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("HTTP egress")
            .chars()
            .take(160)
            .collect();
        Some(Self {
            ip,
            country: country.into(),
            observed_at,
            source,
        })
    }
    pub fn fresh(value: &Value, now: f64, ttl: f64) -> Option<Self> {
        let value = Self::parse(value, now)?;
        (now - value.observed_at <= ttl).then_some(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Pending,
    Active,
    /// The old process has exited; a replacement is being fully rechecked.
    Rechecking,
    /// The bound process has been confirmed absent or replaced.
    Ended,
    Locked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Desktop {
    pub pid: u32,
    pub start_seconds: u64,
    pub start_microseconds: u32,
}
impl Desktop {
    pub fn valid(&self) -> bool {
        self.pid > 1 && self.start_seconds > 0 && self.start_microseconds < 1_000_000
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Launcher {
    pub pid: u32,
    pub start: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Session {
    pub schema: u32,
    pub state: Phase,
    pub session_id: String,
    pub baseline: Egress,
    #[serde(default)]
    pub context_id: String,
    #[serde(default)]
    pub audit_observation_id: String,
    #[serde(default)]
    pub created_at: f64,
    #[serde(default)]
    pub pending_deadline: f64,
    #[serde(default)]
    pub launcher: Option<Launcher>,
    #[serde(default)]
    pub desktop: Option<Desktop>,
    #[serde(default)]
    pub bound_at: Option<f64>,
    #[serde(default)]
    pub unknown_count: u32,
    /// First timestamp in the current uninterrupted unknown streak. Missing
    /// fields from older sessions begin a new bounded streak on the next check.
    #[serde(default)]
    pub unknown_since: Option<f64>,
    #[serde(default)]
    pub risk_evidence: Value,
    #[serde(default)]
    pub reason: Option<Reason>,
    #[serde(default)]
    pub last_reason: Option<Reason>,
    #[serde(default)]
    pub last_risk_state: Option<String>,
    #[serde(default)]
    pub last_check: Option<Egress>,
    #[serde(default)]
    pub locked_at: Option<f64>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
impl Session {
    pub fn has_desktop_group(&self) -> bool {
        self.extra.contains_key(GROUP_KEY)
    }
    pub fn group_rechecking(&self) -> bool {
        self.extra.get(GROUP_RECHECK_KEY) == Some(&json!(true))
    }
    /// Unified membership accessor for both single-desktop (`desktop`) and
    /// multi-desktop (`desktop_group_v1`) sessions.
    pub fn desktop_members(&self) -> Result<Vec<Desktop>> {
        let Some(raw) = self.extra.get(GROUP_KEY) else {
            if self.extra.contains_key(GROUP_RECHECK_KEY)
                || self.extra.contains_key(GROUP_CONTINUITY_KEY)
            {
                return Err(CoreError::new(
                    "invalid_session",
                    "集合复核标记缺少对应主进程集合",
                ));
            }
            return canonical_desktops(self.desktop.iter().cloned().collect());
        };
        let members: Vec<Desktop> = serde_json::from_value(raw.clone())
            .map_err(|_| CoreError::new("invalid_session", "会话主进程集合格式无效"))?;
        let sorted = canonical_desktops(members.clone())
            .map_err(|_| CoreError::new("invalid_session", "会话主进程集合身份无效"))?;
        if sorted.is_empty() || sorted != members || self.desktop.as_ref() != sorted.first() {
            return Err(CoreError::new(
                "invalid_session",
                "会话主进程集合与兼容身份不一致",
            ));
        }
        for key in [GROUP_RECHECK_KEY, GROUP_CONTINUITY_KEY] {
            if self.extra.get(key).is_some_and(|v| v != &json!(true)) {
                return Err(CoreError::new("invalid_session", "会话集合复核标记无效"));
            }
        }
        if self.extra.contains_key(GROUP_CONTINUITY_KEY) && !self.group_rechecking() {
            return Err(CoreError::new(
                "invalid_session",
                "集合连续基线标记缺少复核状态",
            ));
        }
        if self.group_rechecking()
            && (!matches!(self.state, Phase::Rechecking | Phase::Locked | Phase::Ended)
                || !self.created_at.is_finite()
                || self.created_at <= 0.0
                || !self.pending_deadline.is_finite()
                || self.pending_deadline <= self.created_at)
        {
            return Err(CoreError::new("invalid_session", "会话集合复核期限无效"));
        }
        Ok(sorted)
    }
    pub fn validate(&mut self, now: f64) -> Result<()> {
        if self.schema != 1
            || self.session_id.is_empty()
            || self.session_id.len() > 256
            || !now.is_finite()
            || now <= 0.0
        {
            return Err(CoreError::new("invalid_session", "受控会话记录无效"));
        }
        self.baseline = Egress::parse(
            &serde_json::to_value(&self.baseline)
                .map_err(|_| CoreError::new("invalid_session", "会话基准格式无效"))?,
            now,
        )
        .ok_or_else(|| CoreError::new("invalid_session", "会话基准不是有效公网出口"))?;
        if self.desktop.as_ref().is_some_and(|v| !v.valid()) {
            return Err(CoreError::new("invalid_session", "会话进程身份无效"));
        }
        if self.state == Phase::Rechecking
            && (self.desktop.is_none()
                || !self.created_at.is_finite()
                || self.created_at <= 0.0
                || !self.pending_deadline.is_finite()
                || self.pending_deadline <= self.created_at
                || self
                    .extra
                    .get("recheck_baseline_pending")
                    .is_some_and(|v| v != &json!(true)))
        {
            return Err(CoreError::new("invalid_session", "新进程复核状态无效"));
        }
        if self.state == Phase::Ended
            && self
                .extra
                .get("exit_tree_pending")
                .is_some_and(|v| !v.is_boolean())
        {
            return Err(CoreError::new("invalid_session", "旧会话退出状态无效"));
        }
        Ok(())
    }
}

fn risk(value: &Value, now: f64) -> Value {
    if value.is_object()
        && matches!(
            value.get("state").and_then(Value::as_str),
            Some("safe" | "risk" | "unknown")
        )
    {
        return value.clone();
    }
    json!({"state":"unknown","reason":Reason::new("risk_evidence_invalid","DNS/WebRTC 风险证据格式无效",now)})
}
fn risk_fresh(value: &Value, now: f64) -> bool {
    value
        .get("observed_at")
        .and_then(Value::as_f64)
        .is_some_and(|time| {
            time.is_finite() && time > 0.0 && (-5.0..=RISK_EVIDENCE_TTL).contains(&(now - time))
        })
}

pub fn verify_launch(
    audit: &Value,
    current: &Value,
    initial_risk: &Value,
    now: f64,
    target: crate::processes::LaunchTarget,
) -> Result<(Egress, Value)> {
    if audit["grants_launch_permission"] == false
        || matches!(
            audit.get("purpose").and_then(Value::as_str),
            Some("environment_detection" | "launch_requirements_preview" | "scoped_detection")
        )
    {
        return Err(CoreError::new(
            "display_receipt_not_authority",
            "检查或展示回执不能授权启动",
        ));
    }
    if (!target.protected()
        && (audit["launch_target"] != target.as_str()
            || audit["authorization_scope"] != "observation"))
        || (target.protected()
            && audit
                .get("authorization_scope")
                .is_some_and(|s| s != "protected-desktop"))
        || audit
            .get("launch_target")
            .is_some_and(|t| t != target.as_str())
    {
        return Err(CoreError::new(
            "launch_target_mismatch",
            "启动审计与目标或授权范围不一致",
        ));
    }
    if !now.is_finite() || now <= 0.0 {
        return Err(CoreError::new("clock_unavailable", "无法核对启动时间"));
    }
    if audit.get("ready") != Some(&Value::Bool(true)) {
        return Err(CoreError::new(
            "preflight_blocked",
            audit["message"]
                .as_str()
                .filter(|v| !v.is_empty() && v.len() <= 16384)
                .unwrap_or("完整启动校验未通过，未建立运行会话"),
        ));
    }
    let invalid = || CoreError::new("egress_unconfirmed", "完整启动校验缺少新鲜的实测出口证据");
    let observed = audit
        .get("observed_at")
        .and_then(Value::as_f64)
        .ok_or_else(invalid)?;
    let expires = audit
        .get("expires_at")
        .and_then(Value::as_f64)
        .ok_or_else(invalid)?;
    let context = audit
        .get("context_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let reference = audit
        .get("egress_reference")
        .cloned()
        .unwrap_or(Value::Null);
    let mut mapped = reference.clone();
    if let Some(obj) = mapped.as_object_mut() {
        obj.insert(
            "observed_at".into(),
            reference.get("checked_at").cloned().unwrap_or(Value::Null),
        );
    }
    let audited = Egress::fresh(&mapped, now, AUDIT_EGRESS_TTL).ok_or_else(invalid)?;
    if !observed.is_finite()
        || !expires.is_finite()
        || observed <= 0.0
        || observed > now + 5.0
        || now - observed > AUDIT_EGRESS_TTL
        || now > expires
        || expires < observed
        || audit
            .pointer("/context_transition/state")
            .and_then(Value::as_str)
            != Some("stable")
        || context.is_empty()
        || reference.get("context").and_then(Value::as_str) != Some(context)
    {
        return Err(invalid());
    }
    let current = Egress::fresh(current, now, GUARD_EGRESS_TTL)
        .ok_or_else(|| CoreError::new("egress_unconfirmed", "启动时实际 HTTP 出口未能确认"))?;
    if current.ip != audited.ip || current.country != audited.country {
        return Err(CoreError::new(
            "egress_changed",
            "完整校验与启动前快速出口不一致，未建立会话",
        ));
    }
    // Leak evidence is recorded for the session baseline and later drift
    // comparison, but it no longer vetoes the launch: the probe measures its
    // own UDP/DNS path, not Claude's, and a missing sample must not keep the
    // desktop unguarded. Running-session drift is owned by the configured
    // per-criterion actions.
    let initial_risk = risk(initial_risk, now);
    if current.country == "CN" {
        return Err(CoreError::new("egress_country_cn", "启动时检测到 CN 出口"));
    }
    Ok((current, initial_risk))
}

/// Which service the launch audit authorises. The audit carries the target it
/// was evaluated against, so a session established for one family is verified
/// against that family instead of a fixed one. A protected target writes no
/// target at all — that is the Claude desktop, and the default stands.
pub fn audit_target(audit: &Value) -> crate::processes::LaunchTarget {
    audit
        .get("launch_target")
        .and_then(Value::as_str)
        .and_then(crate::processes::LaunchTarget::parse)
        .unwrap_or(crate::processes::LaunchTarget::ClaudeDesktop)
}

pub fn begin(
    audit: &Value,
    current: &Value,
    initial_risk: &Value,
    id: &str,
    now: f64,
) -> Result<Session> {
    let (current, initial_risk) = verify_launch(audit, current, initial_risk, now, audit_target(audit))?;
    let context = audit["context_id"].as_str().unwrap_or("");
    if id.is_empty() || id.len() > 256 {
        return Err(CoreError::new("invalid_session", "会话编号无效"));
    }
    Ok(Session {
        schema: 1,
        state: Phase::Pending,
        session_id: id.into(),
        created_at: now,
        context_id: context.chars().take(160).collect(),
        audit_observation_id: audit
            .get("observation_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .chars()
            .take(80)
            .collect(),
        baseline: current,
        unknown_count: 0,
        unknown_since: None,
        risk_evidence: initial_risk,
        reason: None,
        pending_deadline: now + 15.0,
        launcher: None,
        desktop: None,
        bound_at: None,
        last_reason: None,
        last_risk_state: None,
        last_check: None,
        locked_at: None,
        extra: BTreeMap::new(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    Matches,
    Changed,
    Unavailable,
}
#[derive(Debug, Clone)]
pub struct CheckInput {
    pub now: f64,
    pub launcher_live: bool,
    pub identity: Identity,
    pub egress: Value,
    pub risk: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outcome {
    pub state: String,
    pub reason: Option<Reason>,
    pub baseline: Option<Egress>,
    pub current: Option<Egress>,
    pub risk_evidence: Option<Value>,
    pub session: Option<Session>,
}
impl Outcome {
    fn session(state: &str, session: Session, reason: Option<Reason>) -> Self {
        Self {
            state: state.into(),
            reason,
            baseline: None,
            current: None,
            risk_evidence: None,
            session: Some(session),
        }
    }
    pub fn changed(now: f64) -> Self {
        Self {
            state: "unknown".into(),
            reason: Some(Reason::new(
                "session_changed",
                "会话已由新的受控启动替换",
                now,
            )),
            baseline: None,
            current: None,
            risk_evidence: None,
            session: None,
        }
    }
    pub fn missing(now: f64) -> Self {
        Self {
            state: "risk".into(),
            reason: Some(Reason::new(
                "session_missing",
                "未绑定受控启动会话",
                now,
            )),
            baseline: None,
            current: None,
            risk_evidence: None,
            session: None,
        }
    }
}

pub fn lock(
    mut session: Session,
    code: &str,
    detail: &str,
    now: f64,
    current: Option<Egress>,
    evidence: Option<Value>,
) -> Session {
    session.state = Phase::Locked;
    session.locked_at = Some(now);
    session.reason = Some(Reason::new(code, detail, now));
    if let Some(current) = current {
        session.last_check = Some(current);
    }
    if let Some(evidence) = evidence {
        session.risk_evidence = evidence;
    }
    session
}
pub fn uncertain(session: Session, code: &str, detail: &str, now: f64) -> Outcome {
    uncertain_with_terminal(session, code, detail, detail, now)
}
fn uncertain_with_terminal(
    mut session: Session,
    code: &str,
    detail: &str,
    terminal_detail: &str,
    now: f64,
) -> Outcome {
    if session.state == Phase::Locked {
        return Outcome::session("locked", session.clone(), session.reason.clone());
    }
    let invalid_since = session
        .unknown_since
        .is_some_and(|at| !at.is_finite() || at <= 0.0 || at > now);
    let since = if invalid_since || session.unknown_since.is_none() {
        session.unknown_since = Some(now);
        now
    } else {
        session.unknown_since.unwrap_or(now)
    };
    session.unknown_count = session.unknown_count.saturating_add(1);
    session.last_reason = Some(Reason::new(code, detail, now));
    session.last_risk_state = Some("unknown".into());
    if session.unknown_count < UNKNOWN_LIMIT || (!invalid_since && now - since < UNKNOWN_GRACE) {
        return Outcome::session("unknown", session.clone(), session.last_reason.clone());
    }
    let session = lock(session, code, terminal_detail, now, None, None);
    Outcome::session("risk", session.clone(), session.reason.clone())
}

pub fn check(session: &Session, input: &CheckInput) -> Outcome {
    let mut session = session.clone();
    let now = input.now;
    if session.state == Phase::Ended {
        return Outcome::session("idle", session, None);
    }
    if session.state == Phase::Locked {
        return Outcome::session("locked", session.clone(), session.reason.clone());
    }
    if session.state == Phase::Pending {
        if now <= session.pending_deadline && input.launcher_live {
            return Outcome::session(
                "unknown",
                session,
                Some(Reason::new(
                    "session_pending",
                    "Claude 启动身份正在确认",
                    now,
                )),
            );
        }
        let value = lock(
            session,
            "session_pending",
            "Claude 启动身份未在宽限期内完成绑定",
            now,
            None,
            None,
        );
        return Outcome::session("risk", value.clone(), value.reason.clone());
    }
    let current = Egress::fresh(&input.egress, now, GUARD_EGRESS_TTL).filter(|exit| {
        session.state != Phase::Rechecking || exit.observed_at >= session.created_at
    });
    let evidence = risk(&input.risk, now);
    if let Some(exit) = current.as_ref() {
        let baseline_pending = session.state == Phase::Rechecking
            && session.extra.get("recheck_baseline_pending") == Some(&json!(true));
        let cause = if exit.country == "CN" {
            Some(("egress_country_cn", "运行中实测 HTTP 出口为 CN"))
        } else if !baseline_pending && exit.ip != session.baseline.ip {
            Some(("egress_ip_changed", "运行中实测 HTTP 出口 IP 已变化"))
        } else {
            None
        };
        if let Some((code, detail)) = cause {
            let baseline = session.baseline.clone();
            let value = lock(session, code, detail, now, Some(exit.clone()), None);
            let mut out = Outcome::session("risk", value.clone(), value.reason.clone());
            out.baseline = Some(baseline);
            out.current = Some(exit.clone());
            return out;
        }
        if baseline_pending {
            session.baseline = exit.clone();
            session.extra.remove("recheck_baseline_pending");
        }
    }
    if input.identity == Identity::Changed {
        let value = lock(
            session,
            "session_identity_changed",
            "运行中的 Claude 主进程不再匹配受控启动身份",
            now,
            None,
            None,
        );
        return Outcome::session("risk", value.clone(), value.reason.clone());
    }
    if evidence.get("state").and_then(Value::as_str) == Some("risk") {
        let cause = evidence.get("reason");
        let code = cause
            .and_then(|v| v.get("code"))
            .and_then(Value::as_str)
            .unwrap_or("network_leak_risk");
        let detail = cause
            .and_then(|v| v.get("detail"))
            .and_then(Value::as_str)
            .unwrap_or("DNS 或 WebRTC 风险证据触发");
        let baseline = session.baseline.clone();
        let value = lock(
            session,
            code,
            detail,
            now,
            current.clone(),
            Some(evidence.clone()),
        );
        let mut out = Outcome::session("risk", value.clone(), value.reason.clone());
        out.baseline = Some(baseline);
        out.current = current;
        out.risk_evidence = Some(evidence);
        return out;
    }
    if input.identity == Identity::Unavailable {
        return uncertain_with_terminal(
            session,
            "session_identity_unconfirmed",
            "主进程身份暂未能复核",
            "主进程身份连续未能复核",
            now,
        );
    }
    let Some(current) = current else {
        let detail = input
            .egress
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("未收到有效公网 IP 与国家");
        return uncertain(
            session,
            "egress_unconfirmed",
            &format!("运行中出口查询失败：{detail}"),
            now,
        );
    };
    if session.state == Phase::Rechecking {
        if !session.pending_deadline.is_finite() || now > session.pending_deadline {
            let value = lock(
                session,
                "revalidation_timeout",
                "新进程的完整保护校验未在时限内完成",
                now,
                Some(current),
                None,
            );
            return Outcome::session("risk", value.clone(), value.reason.clone());
        }
        session.unknown_count = 0;
        session.unknown_since = None;
        session.last_check = Some(current.clone());
        let mut out = Outcome::session(
            "pending",
            session,
            Some(Reason::new(
                "session_rechecking",
                "正在重新核验 Claude 进程和环境",
                now,
            )),
        );
        out.current = Some(current);
        return out;
    }
    if evidence.get("state").and_then(Value::as_str) == Some("safe") {
        session.risk_evidence = evidence.clone();
    }
    if !risk_fresh(&session.risk_evidence, now) {
        // Stale probe evidence no longer locks the session: the probes measure
        // their own UDP/DNS path, drift comparison owns freshness, and the
        // egress baseline check above keeps running on its own TTL. The stale
        // sample is recorded as unknown so the UI can show the gap.
        session.risk_evidence = json!({"state":"unknown","reason":Reason::new(
            "evidence_expired",
            "DNS/WebRTC 有效风险证据已超过 300 秒或时间无效",
            now,
        )});
    }
    let safe = evidence.get("state").and_then(Value::as_str) == Some("safe");
    session.unknown_count = 0;
    session.unknown_since = None;
    session.last_check = Some(current.clone());
    session.last_risk_state = evidence
        .get("state")
        .and_then(Value::as_str)
        .map(str::to_owned);
    session.last_reason = if safe {
        None
    } else {
        evidence
            .get("reason")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    };
    let baseline = session.baseline.clone();
    let mut out = Outcome::session(if safe { "safe" } else { "unknown" }, session, None);
    out.baseline = Some(baseline);
    out.current = Some(current);
    out.risk_evidence = Some(evidence);
    out
}

pub fn status(session: &Session, now: f64, running: Option<bool>) -> Value {
    let phase = match session.state {
        Phase::Pending => "pending",
        Phase::Active => "active",
        Phase::Rechecking => "rechecking",
        Phase::Ended => "ended",
        Phase::Locked => "locked",
    };
    let fresh = session
        .last_check
        .as_ref()
        .is_some_and(|v| (0.0..=10.0).contains(&(now - v.observed_at)));
    let state = if session.state == Phase::Ended {
        if running == Some(false) {
            "idle"
        } else {
            "unknown"
        }
    } else if session.state == Phase::Locked {
        "locked"
    } else if matches!(session.state, Phase::Pending | Phase::Rechecking) {
        "pending"
    } else if running == Some(false) {
        "idle"
    } else if fresh && session.last_risk_state.as_deref() == Some("safe") {
        "safe"
    } else {
        "unknown"
    };
    let baseline = if session.state == Phase::Rechecking
        && session.extra.get("recheck_baseline_pending") == Some(&json!(true))
    {
        Value::Null
    } else {
        json!(session.baseline)
    };
    json!({"state":state,"phase":phase,"baseline":baseline,"current":session.last_check,
        "reason":session.reason.as_ref().or(session.last_reason.as_ref()),"risk_evidence":session.risk_evidence,"locked_at":session.locked_at,"sampled_at":session.extra.get("guard_checked_at"),"valid_until":session.last_check.as_ref().map(|v| v.observed_at + GUARD_EGRESS_TTL)})
}
