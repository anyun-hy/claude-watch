//! Explicit multi-main bindings for a policy family. This does not expand the
//! family's existing close scope: it records every verified desktop instead
//! of treating two legitimate mains as a missing session.
use super::*;
use crate::{config_store::ConfigStore, receipt_store::ReceiptStore};

pub(crate) const GROUP: &str = claude_watch_core::session::GROUP_KEY;
const CONTINUITY: &str = claude_watch_core::session::GROUP_CONTINUITY_KEY;
pub const MAX_DESKTOP_MEMBERS: usize = claude_watch_core::session::MAX_DESKTOP_MEMBERS;

pub fn canonical_desktops(members: Vec<Desktop>) -> Result<Vec<Desktop>> {
    claude_watch_core::session::canonical_desktops(members)
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
    session.desktop_members()
}

pub fn group_rechecking(session: &Session) -> bool {
    session.group_rechecking()
}

pub fn has_desktop_group(session: &Session) -> bool {
    session.has_desktop_group()
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
                    None => self.storage.guarded(&path).and_then(|path| {
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
