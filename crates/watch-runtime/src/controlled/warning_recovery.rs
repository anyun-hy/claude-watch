//! Reason-specific warning recovery. A healthy probe is not proof that a
//! failed proxy, backend or process identity recovered. This path never opens
//! or closes an application and never changes the session's original baseline.
use super::*;
use claude_watch_core::session::{Egress, Phase, Session};

#[derive(Clone, Copy)]
enum RecoveryCheck { Egress, Dns, WebRtc, Both, Local, Identity, Sampling }
fn recovery_check(code: &str) -> Option<RecoveryCheck> {
    Some(match code {
        "egress_ip_changed" | "egress_country_cn" | "egress_unconfirmed" => RecoveryCheck::Egress,
        "dns_egress_changed" => RecoveryCheck::Dns,
        "webrtc_egress_changed" => RecoveryCheck::WebRtc,
        "dns_and_webrtc_egress_changed" => RecoveryCheck::Both,
        "proxy_or_tun_failed" | "proxy_or_tun_unconfirmed" => RecoveryCheck::Local,
        "session_identity_changed" | "session_identity_unconfirmed" => RecoveryCheck::Identity,
        "guard_sampling_failed" => RecoveryCheck::Sampling,
        // Creation/revalidation failures, unknown reasons and legacy absolute
        // leak verdicts require their own verified lifecycle, not a drift-safe
        // sample. In particular, never bless an unbound or timed-out session.
        _ => return None,
    })
}
fn baseline(session: &Session, key: &str) -> Vec<String> {
    session.extra.get(key).and_then(Value::as_array).into_iter().flatten()
        .filter_map(Value::as_str).map(str::to_owned).collect()
}
fn current_main<S: DesktopSystem>(system: &mut S, expected: &Session) -> Result<bool> {
    if crate::session_store::desktop_groups::group_rechecking(expected) { return Ok(false); }
    crate::session_store::desktop_groups::desktop_set_matches(expected, &system.desktops()?)
}
fn same_exit(value: &Value, expected: &Session, now: f64, since: f64) -> bool {
    Egress::fresh(value, now, session::GUARD_EGRESS_TTL).is_some_and(|e| {
        e.observed_at >= since && e.country != "CN" && e.ip == expected.baseline.ip
    })
}
fn probe_safe(risk: &Value, raw: &Value, kind: &str, context: &str, since: f64) -> bool {
    let context_key = if kind == "dns" { "context" } else { "context_id" };
    raw[context_key].as_str() == Some(context)
        && risk["sources"][kind]["state"] == "safe"
        && risk["sources"][kind]["observed_at"].as_f64().is_some_and(|at| at >= since)
}

impl Controller {
    /// true means a recovery or a race was handled; false retains the warning.
    pub(super) fn resume_warning<S: DesktopSystem>(
        &self, system: &mut S, sessions: &SessionStore, family: &'static str,
        expected: &Session, receipt: &mut Value,
    ) -> Result<bool> {
        let code = expected.reason.as_ref().map(|r| r.code.as_str()).unwrap_or("");
        let Some(check) = recovery_check(code) else { return Ok(false) };
        let config = ConfigStore { storage: self.storage.clone() }.load()?;
        let provider = system.launch_target().provider();
        if expected.state != Phase::Locked || !config.enabled || !config.guard_enabled
            || PolicyCatalog::family_for(provider).map(|f| f.id) != Some(family)
            || config.close_action(code, provider) != "warn"
        {
            return Ok(false);
        }
        let since = expected.locked_at.unwrap_or(expected.created_at);
        let receipts = ReceiptStore { storage: self.storage.clone() };
        let probes = if matches!(check, RecoveryCheck::Dns | RecoveryCheck::WebRtc | RecoveryCheck::Both) {
            let _observations = self.storage.lock("observations", None)?;
            Some(receipts.probe_receipts())
        } else { None };
        // These are fresh reads, not the old cached probe's 'safe' verdict.
        // All recoveries retain a confirmed current main and a working guard.
        let local = system.local_guard()?;
        let backend = match local["guard_backend_healthy"].as_bool() {
            Some(value) => value,
            None => system.guard_backend_healthy()?,
        };
        if local["proxy"] != "ok" || local["tun"] != "ok" || !backend
            || !current_main(system, expected)?
        {
            return Ok(false);
        }
        let exit = system.egress();
        let sampled_at = system.now();
        if !sampled_at.is_finite() || sampled_at <= 0.0
            || !same_exit(&exit, expected, sampled_at, since)
        {
            return Ok(false);
        }
        if let Some((dns, rtc)) = probes.as_ref() {
            let risk = claude_watch_core::risk::probe_drift(
                &baseline(expected, "baseline_dns_countries"),
                &baseline(expected, "baseline_webrtc_addresses"), dns, rtc, sampled_at);
            let dns_ok = probe_safe(&risk, dns, "dns", &expected.context_id, since);
            let rtc_ok = probe_safe(&risk, rtc, "webrtc", &expected.context_id, since);
            let resolved = match check {
                RecoveryCheck::Dns => dns_ok,
                RecoveryCheck::WebRtc => rtc_ok,
                RecoveryCheck::Both => dns_ok && rtc_ok,
                _ => false,
            };
            if !resolved { return Ok(false); }
        }
        // Same lock order as complete_recheck: operation -> session -> receipts.
        // No network work is performed while holding these locks. A newer
        // reason, policy, probe or identity cannot be cleared by this result.
        let _operation = self.storage.lock("operation", None)?;
        let changed = sessions.close_if_current(Some(&expected.session_id), system.now(), || {
            if sessions.load(system.now())?.as_ref() != Some(expected)
                || (ConfigStore { storage: self.storage.clone() }).load()? != config
                || expected.extra.get("guard_checked_at").and_then(Value::as_f64)
                    .is_some_and(|at| at >= sampled_at)
                || !current_main(system, expected)?
            {
                return Ok(false);
            }
            let at = system.now();
            if !same_exit(&exit, expected, at, since) { return Ok(false); }
            let _observations = self.storage.lock("observations", None)?;
            if let Some(original) = probes.as_ref() {
                if &receipts.probe_receipts() != original { return Ok(false); }
                let risk = claude_watch_core::risk::probe_drift(
                    &baseline(expected, "baseline_dns_countries"),
                    &baseline(expected, "baseline_webrtc_addresses"), &original.0, &original.1, at);
                let dns_ok = probe_safe(&risk, &original.0, "dns", &expected.context_id, since);
                let rtc_ok = probe_safe(&risk, &original.1, "webrtc", &expected.context_id, since);
                if !(match check { RecoveryCheck::Dns => dns_ok, RecoveryCheck::WebRtc => rtc_ok,
                    RecoveryCheck::Both => dns_ok && rtc_ok, _ => false }) { return Ok(false); }
            }
            let mut resumed = expected.clone();
            resumed.state = Phase::Active;
            resumed.reason = None;
            resumed.last_reason = None;
            resumed.locked_at = None;
            resumed.last_risk_state = None;
            resumed.unknown_count = 0;
            resumed.unknown_since = None;
            resumed.risk_evidence = json!({"state":"unknown"});
            resumed.extra.insert("guard_checked_at".into(), json!(at));
            self.storage.atomic_json(&self.storage.paths.session_for(family),
                &serde_json::to_value(&resumed).map_err(|_| {
                    CoreError::new("guard_encoding_failed", "恢复状态无法编码")
                })?)?;
            Ok(true)
        })?;
        receipt["action"] = json!("observe");
        if changed == Some(true) {
            receipt["session_guard"] = json!({"state":"active","phase":"active",
                "reason":{"code":"session_resumed","detail":"原告警原因已复核恢复，继续逐项监管"}});
            receipt["session_notice"] = json!({"code":"session_resumed","action":"resume",
                "previous_code":code,"detail":"已按原告警原因复核，未改变会话基线"});
            receipt["stop_state"] = json!("recovered");
        } else {
            receipt["stop_state"] = json!("session_changed");
        }
        Ok(true)
    }
}
