//! Explicit multi-main bindings for a policy family. This does not expand the
//! family's existing close scope: it records every verified desktop instead
//! of treating two legitimate mains as a missing session.
use super::*;
use crate::{config_store::ConfigStore, receipt_store::ReceiptStore};
use claude_watch_core::config::Config;

pub(crate) const GROUP: &str = "desktop_group_v1";
const RECHECK: &str = "desktop_group_recheck_v1";
const CONTINUITY: &str = "desktop_group_continuity_v1";
pub const MAX_DESKTOP_MEMBERS: usize = 32;

pub fn canonical_desktops(mut members: Vec<Desktop>) -> Result<Vec<Desktop>> {
    if members.len() > MAX_DESKTOP_MEMBERS || members.iter().any(|d| !d.valid()) {
        return Err(CoreError::new("desktop_identity_unavailable", "主进程集合超限或身份无效"));
    }
    members.sort_by_key(|d| (d.pid, d.start_seconds, d.start_microseconds));
    if members.windows(2).any(|pair| pair[0].pid == pair[1].pid) {
        return Err(CoreError::new("desktop_inventory_incomplete", "同一轮主进程身份重复或冲突"));
    }
    Ok(members)
}

pub fn observed_desktops(rows: &[(Desktop, bool, String)]) -> Result<Vec<Desktop>> {
    canonical_desktops(rows.iter().filter(|(_, main, _)| *main).map(|(d, _, _)| d.clone()).collect())
}

/// Pure adapter contract shared with the native evidence worker. Only an exact,
/// complete main set yields stamps; helpers are not promoted to main members.
pub fn group_stamps(expected: &[Desktop], rows: &[(Desktop, bool, String)])
    -> Result<Option<Vec<(Desktop, String)>>>
{
    if expected.is_empty() || canonical_desktops(expected.to_vec())? != observed_desktops(rows)? {
        return Ok(None);
    }
    let mut bindings = Vec::new();
    for (desktop, main, stamp) in rows {
        if !*main { continue; }
        if stamp.is_empty() || stamp.len() > 80 || stamp.contains('|') || stamp.chars().any(char::is_control) {
            return Err(CoreError::new("desktop_identity_unavailable", "主进程启动时间无法绑定"));
        }
        bindings.push((desktop.clone(), stamp.clone()));
    }
    bindings.sort_by_key(|(d, _)| (d.pid, d.start_seconds, d.start_microseconds));
    Ok(Some(bindings))
}

pub fn desktop_members(session: &Session) -> Result<Vec<Desktop>> {
    let Some(raw) = session.extra.get(GROUP) else {
        if session.extra.contains_key(RECHECK) || session.extra.contains_key(CONTINUITY) {
            return Err(CoreError::new("invalid_session", "集合复核标记缺少对应主进程集合"));
        }
        return canonical_desktops(session.desktop.iter().cloned().collect());
    };
    let members: Vec<Desktop> = serde_json::from_value(raw.clone())
        .map_err(|_| CoreError::new("invalid_session", "会话主进程集合格式无效"))?;
    let sorted = canonical_desktops(members.clone())
        .map_err(|_| CoreError::new("invalid_session", "会话主进程集合身份无效"))?;
    if sorted.is_empty() || sorted != members || session.desktop.as_ref() != sorted.first() {
        return Err(CoreError::new("invalid_session", "会话主进程集合与兼容身份不一致"));
    }
    for key in [RECHECK, CONTINUITY] {
        if session.extra.get(key).is_some_and(|v| v != &json!(true)) {
            return Err(CoreError::new("invalid_session", "会话集合复核标记无效"));
        }
    }
    if session.extra.contains_key(CONTINUITY) && !group_rechecking(session) {
        return Err(CoreError::new("invalid_session", "集合连续基线标记缺少复核状态"));
    }
    if group_rechecking(session) && (!matches!(session.state, Phase::Rechecking | Phase::Locked | Phase::Ended)
        || !session.created_at.is_finite()
        || session.created_at <= 0.0 || !session.pending_deadline.is_finite()
        || session.pending_deadline <= session.created_at)
    {
        return Err(CoreError::new("invalid_session", "会话集合复核期限无效"));
    }
    Ok(sorted)
}

pub fn group_rechecking(session: &Session) -> bool {
    session.extra.get(RECHECK) == Some(&json!(true))
}

pub fn has_desktop_group(session: &Session) -> bool {
    session.extra.contains_key(GROUP)
}

pub fn desktop_set_matches(session: &Session, rows: &[(Desktop, bool, String)]) -> Result<bool> {
    let members = desktop_members(session)?;
    Ok(!members.is_empty() && members == observed_desktops(rows)?)
}

fn put_members(value: &mut Session, members: Vec<Desktop>) -> Result<()> {
    let members = canonical_desktops(members)?;
    if members.is_empty() {
        return Err(CoreError::new("desktop_identity_unavailable", "不能绑定空主进程集合"));
    }
    value.desktop = members.first().cloned();
    value.extra.insert(GROUP.into(), json!(members));
    Ok(())
}

impl SessionStore {
    /// Initial adoption publishes all members and the baseline in one write.
    /// The caller must have re-read the same complete native set after audit.
    pub(crate) fn adopt_desktop_group(
        &self, receipts: &ReceiptStore, audit: &Value, egress: &Value,
        members: Vec<Desktop>, config: &Config, now: f64,
    ) -> Result<Option<Session>> {
        self.require_audit_family(audit, None)?;
        if self.family != "openai" || members.len() < 2 {
            return Err(CoreError::new("protected_scope_mismatch", "此入口只接受多桌面 OpenAI 会话"));
        }
        let _operation = self.storage.lock("operation", None)?;
        let _session = self.storage.lock(&self.lock_name(), None)?;
        if self.load(now)?.is_some()
            || (ConfigStore { storage: self.storage.clone() }).load()? != *config
            || !config.enabled || !config.guard_enabled
        { return Ok(None); }
        let _observations = self.storage.lock("observations", None)?;
        let context = audit["context_id"].as_str().unwrap_or("");
        let risk = receipts.session_risk(context, egress["ip"].as_str(), now);
        let mut value = session::begin(audit, egress, &risk, &Uuid::new_v4().to_string(), now)?;
        Self::anchor_probe_baseline(&mut value, receipts, now);
        put_members(&mut value, members)?;
        value.state = Phase::Active;
        value.bound_at = Some(now);
        value.extra.insert("adopted_from".into(), json!("running_desktop_group"));
        self.save(&value)?;
        Ok(Some(value))
    }

    /// Called only after every disappeared member was independently confirmed
    /// gone. Added identities are provisional, never silently made Active.
    /// Any membership revision gets a new id so a delayed audit cannot commit.
    pub(crate) fn reconcile_desktop_group(
        &self, expected: &Session, members: Vec<Desktop>, config: &Config, now: f64,
    ) -> Result<Option<Session>> {
        let members = canonical_desktops(members)?;
        let old = desktop_members(expected)?;
        if members.is_empty() || !now.is_finite() || now <= 0.0 || self.family != "openai" {
            return Err(CoreError::new("desktop_identity_unavailable", "无法确认多桌面会话变更"));
        }
        let _operation = self.storage.lock("operation", None)?;
        let _session = self.storage.lock(&self.lock_name(), None)?;
        if self.load(now)?.as_ref() != Some(expected)
            || (ConfigStore { storage: self.storage.clone() }).load()? != *config
            || !config.enabled || !config.guard_enabled
            || expected.extra.get("guard_checked_at").and_then(Value::as_f64).is_some_and(|at| at > now)
        { return Ok(None); }
        if expected.state == Phase::Pending { return Ok(None); }
        if expected.state == Phase::Locked && expected.reason.as_ref().is_none_or(|reason| {
            config.close_action(&reason.code, Provider::Codex) != "warn"
        }) { return Ok(None); }
        let mut value = expected.clone();
        let continuing = expected.state != Phase::Ended
            || expected.extra.get("exit_tree_pending") == Some(&json!(true));
        // A confirmed empty family ends the old deadline as well as its
        // baseline lifetime. Lingering helpers do not count as an empty tree.
        let pending = continuing && (group_rechecking(expected) || expected.state == Phase::Rechecking);
        if pending && now >= expected.pending_deadline {
            value = session::lock(value, "revalidation_timeout", "桌面集合复核未在原时限内完成", now, None, None);
            self.save(&value)?;
            return Ok(Some(value));
        }
        if old == members && expected.state != Phase::Ended { return Ok(Some(value)); }
        let added = members.iter().any(|d| !old.contains(d)) || expected.state == Phase::Ended;
        value.session_id = Uuid::new_v4().to_string();
        put_members(&mut value, members)?;
        if added {
            let continuity = continuing
                && expected.extra.get("recheck_baseline_pending") != Some(&json!(true));
            value.created_at = now;
            value.pending_deadline = if pending { expected.pending_deadline }
                else { now + session::RISK_EVIDENCE_TTL };
            value.bound_at = Some(now);
            value.launcher = None;
            value.unknown_count = 0;
            value.unknown_since = None;
            value.last_check = None;
            value.last_risk_state = None;
            value.extra.remove("guard_checked_at");
            value.extra.remove("ended_at");
            value.extra.remove("exit_tree_pending");
            value.extra.insert(RECHECK.into(), json!(true));
            if continuity {
                value.extra.insert(CONTINUITY.into(), json!(true));
                value.extra.remove("recheck_baseline_pending");
            } else {
                value.extra.remove(CONTINUITY);
                value.extra.insert("recheck_baseline_pending".into(), json!(true));
            }
            // Preserve a warn latch while the new membership is audited. A
            // background audit cannot resolve that warning on the guard's behalf.
            if expected.state != Phase::Locked {
                value.state = Phase::Rechecking;
                value.reason = None;
                value.last_reason = None;
                value.locked_at = None;
            }
        }
        self.save(&value)?;
        Ok(Some(value))
    }

    /// A group audit must supply every exact member and its current native
    /// start stamp. No fallback to the first/representative process is allowed.
    pub fn complete_group_recheck(
        &self, expected: &Session, bindings: &[(Desktop, String)], audit: &Value,
        egress: &Value, now: f64, provider: Provider,
    ) -> Result<Option<Session>> {
        self.require_audit_family(audit, Some(provider))?;
        let members = canonical_desktops(bindings.iter().map(|(d, _)| d.clone()).collect())?;
        if !has_desktop_group(expected) || members != desktop_members(expected)?
            || bindings.iter().any(|(_, stamp)| stamp.is_empty() || stamp.len() > 80
                || stamp.contains('|') || stamp.chars().any(char::is_control))
        { return Err(CoreError::new("target_identity_mismatch", "复核结果不包含完整原生主进程集合")); }
        let _operation = self.storage.lock("operation", None)?;
        let _session = self.storage.lock(&self.lock_name(), None)?;
        let Some(current) = self.load(now)? else { return Ok(None) };
        let config = ConfigStore { storage: self.storage.clone() }.load()?;
        let warn = current.state == Phase::Locked && current.reason.as_ref()
            .is_some_and(|r| config.close_action(&r.code, provider) == "warn");
        if current.session_id != expected.session_id || desktop_members(&current)? != members
            || current.extra.get("guard_checked_at").and_then(Value::as_f64).is_some_and(|at| at > now)
            || !group_rechecking(&current) || !(current.state == Phase::Rechecking || warn)
        { return Ok(None); }
        if !now.is_finite() || now <= 0.0 || now > current.pending_deadline {
            return Err(CoreError::new("revalidation_timeout", "桌面集合完整校验已超时"));
        }
        if current.extra.get("recheck_baseline_pending") == Some(&json!(true)) {
            return Err(CoreError::new("egress_unconfirmed", "新会话出口基准尚未确认"));
        }
        let policy = crate::config_store::policy_digest(&config.value()?)?;
        if !config.enabled || !config.guard_enabled
            || audit["context_id"].as_str() != Some(current.context_id.as_str())
            || !crate::audit_store::audit_matches_policy(audit, &policy) {
            return Err(CoreError::new("revalidation_context_changed", "集合复核期间保护设置已变化"));
        }
        let measured = session::Egress::fresh(egress, now, session::GUARD_EGRESS_TTL)
            .ok_or_else(|| CoreError::new("egress_unconfirmed", "集合复核出口未确认"))?;
        if measured.ip != current.baseline.ip {
            return Err(CoreError::new("egress_changed", "集合复核不能吸收已变化的出口"));
        }
        if measured.observed_at < current.created_at
            || audit["observed_at"].as_f64().is_none_or(|at| !at.is_finite() || at < current.created_at)
            || audit["egress_reference"]["checked_at"].as_f64().is_none_or(|at| !at.is_finite() || at < current.created_at)
        { return Err(CoreError::new("egress_unconfirmed", "集合复核需要成员变化之后的新采样")); }
        let _observations = self.storage.lock("observations", None)?;
        let receipts = ReceiptStore { storage: self.storage.clone() };
        let risk = receipts.session_risk(audit["context_id"].as_str().unwrap_or(""), Some(&measured.ip), now);
        if ["dns", "webrtc"].iter().any(|kind| risk["sources"][*kind]["observed_at"].as_f64()
            .is_none_or(|at| !at.is_finite() || at < current.created_at))
        { return Err(CoreError::new("risk_evidence_unavailable", "集合复核需要重新采集 DNS 和 WebRTC 证据")); }
        let mut verified = session::begin(audit, egress, &risk, &current.session_id, now)?;
        put_members(&mut verified, members)?;
        verified.state = Phase::Active;
        verified.bound_at = Some(now);
        verified.extra.insert("guard_checked_at".into(), json!(now));
        Self::anchor_probe_baseline(&mut verified, &receipts, now);
        if current.extra.get(CONTINUITY) == Some(&json!(true)) {
            verified.baseline = current.baseline.clone();
            for key in ["baseline_dns_countries", "baseline_webrtc_addresses"] {
                match current.extra.get(key) {
                    Some(value) => { verified.extra.insert(key.into(), value.clone()); }
                    None => { verified.extra.remove(key); }
                }
            }
        }
        if warn {
            verified.state = Phase::Locked;
            verified.reason = current.reason.clone();
            verified.last_reason = current.last_reason.clone();
            verified.locked_at = current.locked_at;
        }
        // Leases are observation records, not stop permissions. Roll back all
        // writes if either a later lease or the authoritative session fails.
        let mut previous = Vec::new();
        for (desktop, _) in bindings {
            let path = self.storage.paths.watch().join(format!("state/sessions/rust-{}.session", desktop.pid));
            previous.push((path.clone(), self.storage.read_bytes(&path, 16 * 1024)?));
        }
        let result = (|| {
            let controller = crate::controlled::Controller::new(self.storage.clone());
            for (desktop, stamp) in bindings { controller.lease(desktop, stamp, now, provider)?; }
            self.save(&verified)
        })();
        if let Err(error) = result {
            let mut failed = false;
            for (path, old) in previous {
                let restored = match old {
                    Some(bytes) => self.storage.atomic_bytes(&path, &bytes, 0o600),
                    None => self.storage.guarded(&path).and_then(|()| {
                        match std::fs::remove_file(&path) {
                            Ok(()) => Ok(()),
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                            Err(_) => Err(CoreError::new("revalidation_lease_rollback_failed", "观察记录撤销失败")),
                        }
                    }),
                };
                failed |= restored.is_err();
            }
            if failed { return Err(CoreError::new("revalidation_lease_rollback_failed", "集合观察记录未全部恢复")); }
            return Err(error);
        }
        Ok(Some(verified))
    }
}
