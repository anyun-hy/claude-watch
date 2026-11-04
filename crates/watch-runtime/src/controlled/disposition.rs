//! Decision/execution boundary for the guard. A skipped action is not a stop.
use super::*;
use claude_watch_core::session::{Egress, Phase, Session};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StopOutcome {
    SkippedWarn,
    Confirmed,
}

/// Keep the *observed* reason with the session when its durable write failed.
/// A storage error is not evidence that another, more severe criterion fired.
#[derive(Debug, Clone)]
pub(super) struct PendingRisk {
    pub session_id: String,
    pub code: String,
}

pub(super) fn confirmed_egress_code(
    session: &Session,
    egress: &Value,
    now: f64,
) -> Option<&'static str> {
    let exit = Egress::fresh(egress, now, session::GUARD_EGRESS_TTL)?;
    if session.state == Phase::Rechecking && exit.observed_at < session.created_at {
        return None;
    }
    if exit.country == "CN" {
        Some("egress_country_cn")
    } else if session.extra.get("recheck_baseline_pending") != Some(&json!(true))
        && exit.ip != session.baseline.ip
    {
        Some("egress_ip_changed")
    } else {
        None
    }
}

impl Controller {
    /// An absent criterion can use its declared default inside a valid config.
    /// A failed config read is different: it grants no process-stop authority.
    /// Do not cache a force policy across an unreadable/disabled configuration.
    fn resolve_close_action(&self, code: &str, provider: Provider) -> Result<String> {
        let config = ConfigStore { storage: self.storage.clone() }.load()?;
        Ok(if config.enabled && config.guard_enabled {
            config.close_action(code, provider)
        } else {
            "warn".to_string()
        })
    }

    pub(super) fn close_action(&self, code: &str, provider: Provider) -> String {
        self.resolve_close_action(code, provider).unwrap_or_else(|_| "warn".to_string())
    }

    pub(super) fn pending_risk(
        &self,
        family: &'static str,
        id: Option<&str>,
    ) -> Result<Option<PendingRisk>> {
        let mut risks = self.failed_persistence_session.lock().map_err(|_| {
            CoreError::new("guard_memory_unavailable", "保护内存状态不可用")
        })?;
        if risks.get(family).is_some_and(|risk| Some(risk.session_id.as_str()) != id) {
            risks.remove(family);
        }
        Ok(risks.get(family).cloned())
    }

    pub(super) fn remember_risk(
        &self,
        family: &'static str,
        id: Option<&str>,
        code: &str,
    ) -> Result<()> {
        let id = id.filter(|id| !id.is_empty()).ok_or_else(|| {
            CoreError::new("session_changed", "风险所属会话已变化，未缓存处置决定")
        })?;
        self.failed_persistence_session.lock().map_err(|_| {
            CoreError::new("guard_memory_unavailable", "保护内存状态不可用")
        })?.insert(family, PendingRisk { session_id: id.into(), code: code.into() });
        Ok(())
    }

    pub(super) fn forget_risk(&self, family: &'static str, id: Option<&str>) -> Result<()> {
        let mut risks = self.failed_persistence_session.lock().map_err(|_| {
            CoreError::new("guard_memory_unavailable", "保护内存状态不可用")
        })?;
        if risks.get(family).is_some_and(|risk| Some(risk.session_id.as_str()) == id) {
            risks.remove(family);
        }
        Ok(())
    }

    pub(super) fn timed_guard_quit<S: DesktopSystem>(
        &self,
        system: &mut S,
        receipt: &mut Value,
    ) -> Result<StopOutcome> {
        let started = std::time::Instant::now();
        receipt["stop_started_at"] = json!(system.now());
        let reported = receipt["session_guard"]["reason"]["code"]
            .as_str().unwrap_or("").to_string();
        let code = if reported == "egress_risk_persist_failed" {
            // A missing original reason cannot authorise an invented stop.
            receipt["persistence_risk_code"].as_str().unwrap_or(&reported).to_string()
        } else if reported == "session_missing"
            && Egress::fresh(&system.egress(), system.now(), session::GUARD_EGRESS_TTL)
                .is_some_and(|exit| exit.country == "CN")
        {
            "egress_country_cn".to_string()
        } else {
            reported.clone()
        };
        let provider = system.launch_target().provider();
        let family = PolicyCatalog::family_for(provider);
        let resolved = self.resolve_close_action(&code, provider);
        let policy_available = resolved.is_ok();
        let action = match resolved {
            Ok(action) => action,
            Err(error) => {
                receipt["policy_state"] = json!("unavailable");
                receipt["policy_error"] = json!(error.code);
                "warn".to_string()
            }
        };
        receipt["stop_action"] = json!(action);
        receipt["stop_reason_code"] = json!(code);
        let result = if action == "warn" {
            receipt["stop_state"] = json!("skipped_warn_only");
            receipt["action"] = json!("observe");
            // A notice is not a latched stop. Keep evaluating fresh risks on
            // the next round, even if this round could not persist its state.
            // An unreadable policy is NOT a user-selected notice: preserve its
            // pending risk for re-evaluation after configuration is readable.
            if policy_available && reported == "egress_risk_persist_failed" {
                if let Some(family) = family {
                    self.forget_risk(family.id, receipt["session_id"].as_str())?;
                }
            }
            Ok(StopOutcome::SkippedWarn)
        } else if action == "force" && family.is_some_and(|f| f.performable("force")) {
            let mut forced = None;
            let result = system.quit_for_confirmed_ip_risk(&mut forced);
            receipt["stop_force_requested"] = json!(forced);
            receipt["stop_force_reported"] = json!(forced.is_some());
            result.map(|()| StopOutcome::Confirmed)
        } else {
            system.quit_desktop().map(|()| StopOutcome::Confirmed)
        };
        receipt["stop_completed_at"] = json!(system.now());
        receipt["stop_elapsed_seconds"] = json!(started.elapsed().as_secs_f64());
        result
    }

    /// One stop-record serializer for both the normal guard and warning
    /// recovery. Caller decides whether a log write error is propagated or
    /// recorded as a secondary diagnostic after an already completed stop.
    pub(super) fn persist_stop_record<S: DesktopSystem>(
        &self,
        system: &S,
        session_id: Option<&str>,
        reason: Value,
        receipt: &Value,
    ) -> Result<()> {
        self.storage.atomic_json(
            &self.storage.paths.base().join("last-guard-stop.json"),
            &json!({
                "stopped_at": system.now(),
                "session_id": session_id,
                "reason": reason,
                "force_requested": receipt["stop_force_requested"],
                "force_reported": receipt["stop_force_reported"],
            }),
        )
    }

    /// Centralize the outcome of one identity-checked, transaction-guarded
    /// stop. Callers decide which risk is actionable; this function never
    /// widens stop authority or changes the process scope.
    pub(super) fn finish_current_stop<S: DesktopSystem>(
        &self,
        sessions: &SessionStore,
        system: &mut S,
        expected_session: Option<&str>,
        receipt: &mut Value,
        persist_reason: Option<Value>,
    ) -> Result<()> {
        let result = sessions.close_if_current(expected_session, system.now(), || {
            self.timed_guard_quit(system, receipt)
        });
        match result {
            Ok(Some(StopOutcome::SkippedWarn)) => {}
            Ok(Some(StopOutcome::Confirmed)) => {
                receipt["action"] = json!("close-desktop");
                receipt["stop_state"] = json!("confirmed");
                if let Some(reason) = persist_reason {
                    self.persist_stop_record(system, expected_session, reason, receipt)?;
                }
            }
            Ok(None) => receipt["stop_state"] = json!("session_changed"),
            Err(error) => {
                receipt["stop_state"] = json!("failed");
                receipt["stop_error"] = json!(error.code);
            }
        }
        Ok(())
    }

    /// Recheck independent confirmed risks while the previous finding only
    /// warns. The fast HTTP exit is checked before any slower local sampling.
    /// Returns true when this round handled a new actionable risk (or a race).
    pub(super) fn recheck_warning<S: DesktopSystem>(
        &self,
        system: &mut S,
        sessions: &SessionStore,
        family: &'static str,
        expected: &Session,
        receipt: &mut Value,
    ) -> Result<bool> {
        let config = ConfigStore { storage: self.storage.clone() }.load()?;
        let provider = system.launch_target().provider();
        if !config.enabled || !config.guard_enabled
            || PolicyCatalog::family_for(provider).map(|f| f.id) != Some(family)
        {
            return Ok(false);
        }
        let old_code = expected.reason.as_ref().map(|r| r.code.as_str()).unwrap_or("");
        if config.close_action(old_code, provider) != "warn" {
            return Ok(false);
        }
        let egress = system.egress();
        let checked_at = system.now();
        let measured = Egress::fresh(&egress, checked_at, session::GUARD_EGRESS_TTL)
            .filter(|exit| exit.observed_at >= expected.created_at);
        let actionable = |code: &str| config.close_action(code, provider) != "warn";
        let mut evidence = None;
        let candidate = if measured.as_ref().is_some_and(|e| e.country == "CN")
            && actionable("egress_country_cn")
        {
            Some(("egress_country_cn".to_string(), "运行中实测 HTTP 出口为 CN".to_string()))
        } else if measured.as_ref().is_some_and(|e| e.ip != expected.baseline.ip)
            && expected.extra.get("recheck_baseline_pending") != Some(&json!(true))
            && actionable("egress_ip_changed")
        {
            Some(("egress_ip_changed".to_string(), "运行中实测 HTTP 出口 IP 已变化".to_string()))
        } else {
            let extra = serde_json::to_value(&expected.extra)
                .map_err(|_| CoreError::new("guard_encoding_failed", "保护状态无法编码"))?;
            let risk = ReceiptStore { storage: self.storage.clone() }
                .probe_drift_risk(&extra, checked_at);
            let code = risk["reason"]["code"].as_str().unwrap_or("");
            if risk["state"] == "risk" && actionable(code) {
                let candidate = (code.to_string(), risk["reason"]["detail"].as_str()
                    .unwrap_or("DNS/WebRTC 漂移已确认").to_string());
                evidence = Some(risk);
                Some(candidate)
            } else if let Ok(local) = system.local_guard() {
                if (local["proxy"] == "fail" || local["tun"] == "fail")
                    && actionable("proxy_or_tun_failed")
                {
                    Some(("proxy_or_tun_failed".to_string(), "代理或TUN已确认失效".to_string()))
                } else { None }
            } else { None }
        };
        let Some((code, detail)) = candidate else { return Ok(false) };
        // Use the store's existing session lock, but compare the complete
        // observation as well as the id. There is no unlocked Active interval
        // in which another worker could lose a newer lock/replacement.
        let changed = sessions.close_if_current(Some(&expected.session_id), system.now(), || {
            if sessions.load(system.now())?.as_ref() != Some(expected)
                || expected.extra.get("guard_checked_at").and_then(Value::as_f64)
                    .is_some_and(|at| at >= checked_at)
                || (ConfigStore { storage: self.storage.clone() }).load()? != config
            {
                return Ok(None);
            }
            let mut updated = session::lock(expected.clone(), &code, &detail,
                checked_at, measured.clone(), evidence.clone());
            updated.extra.insert("guard_checked_at".into(), json!(checked_at));
            self.storage.atomic_json(&self.storage.paths.session_for(family),
                &serde_json::to_value(&updated).map_err(|_| {
                    CoreError::new("guard_encoding_failed", "保护状态无法编码")
                })?)?;
            Ok(Some(updated))
        });
        let bound = match changed {
            Ok(Some(Some(updated))) => updated,
            Ok(_) => {
                receipt["stop_state"] = json!("session_changed");
                receipt["action"] = json!("observe");
                return Ok(true);
            }
            Err(error) if error.code == "state_io_failed" => {
                self.remember_risk(family, Some(&expected.session_id), &code)?;
                receipt["persistence_error"] = json!(error.code);
                expected.clone()
            }
            Err(error) => return Err(error),
        };
        receipt["session_id"] = json!(expected.session_id);
        receipt["session_guard"] = json!({"state":"risk", "phase":"locked",
            "reason":{"code":code,"detail":detail,"source":"session guard","observed_at":checked_at},
            "baseline":expected.baseline,"current":measured,"risk_evidence":evidence});
        if receipt["persistence_error"] == "state_io_failed" {
            receipt["persistence_risk_code"] = json!(code);
            receipt["session_guard"]["reason"]["code"] = json!("egress_risk_persist_failed");
        }
        let result = sessions.close_if_current(Some(&expected.session_id), system.now(), || {
            if sessions.load(system.now())?.as_ref() != Some(&bound) {
                return Ok(None);
            }
            self.timed_guard_quit(system, receipt).map(Some)
        });
        match result {
            Ok(Some(Some(StopOutcome::Confirmed))) => {
                receipt["action"] = json!("close-desktop");
                receipt["stop_state"] = json!("confirmed");
                if let Err(error) = self.persist_stop_record(
                    system,
                    Some(expected.session_id.as_str()),
                    receipt["session_guard"]["reason"].clone(),
                    receipt,
                ) {
                    receipt["stop_log_error"] = json!(error.code);
                }
            }
            Ok(Some(Some(StopOutcome::SkippedWarn))) => {}
            Ok(_) => {
                receipt["action"] = json!("observe");
                receipt["stop_state"] = json!("session_changed");
            }
            Err(error) => {
                receipt["action"] = json!("observe");
                receipt["stop_state"] = json!("failed");
                receipt["stop_error"] = json!(error.code);
            }
        }
        Ok(true)
    }
}
