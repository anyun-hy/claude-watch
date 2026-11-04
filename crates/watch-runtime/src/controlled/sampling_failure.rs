//! Handling for failed guard-sampling rounds. This does not authorize any
//! additional stop; the shared policy gate and StopOutcome remain authoritative.
use super::*;

impl Controller {
    pub(super) fn sampling_failure<S: DesktopSystem>(
        &self,
        system: &mut S,
        family: &'static str,
        receipt: &mut Value,
        error: CoreError,
    ) -> Result<()> {
        receipt["code"] = json!(error.code);
        receipt["message"] = json!(error.message);
        receipt["status"] = json!("unknown");
        if !system.desktops().is_ok_and(|d| !d.is_empty()) {
            return Ok(());
        }
        let sessions = SessionStore::for_family(self.storage.clone(), family);
        let current = match sessions.load(system.now()) {
            Ok(value) => value,
            Err(_) => {
                receipt["session_guard"] = json!({"state":"risk","reason":{"code":"session_state_invalid","detail":"会话记录无法验证，未允许无保护运行"}});
                match sessions
                    .close_if_unreadable(system.now(), || self.timed_guard_quit(system, receipt))
                {
                    Ok(Some(StopOutcome::SkippedWarn)) => {}
                    Ok(Some(StopOutcome::Confirmed)) => {
                        receipt["action"] = json!("close-desktop");
                        receipt["stop_state"] = json!("confirmed");
                    }
                    Err(error) => {
                        receipt["stop_error"] = json!(error.code);
                        receipt["stop_state"] = json!("failed");
                    }
                    _ => {}
                }
                return Ok(());
            }
        };
        let id = current.as_ref().map(|s| s.session_id.clone());
        receipt["session_id"] = json!(id);
        let latched = self.pending_risk(family, id.as_deref())?;
        if let Some(risk) = latched {
            receipt["persistence_risk_code"] = json!(risk.code);
            receipt["status"] = json!("protection_triggered");
            receipt["persistence_error"] = json!("state_io_failed");
            receipt["session_guard"] = json!({"state":"locked", "phase":"locked", "reason":{"code":"egress_risk_persist_failed", "detail":"出口风险已确认，会话记录写入失败"}});
            self.finish_current_stop(&sessions, system, id.as_deref(), receipt, None)?;
            return Ok(());
        }
        if let Some(value) = current
            .as_ref()
            .filter(|s| s.state == session::Phase::Locked)
        {
            receipt["status"] = json!("protection_triggered");
            receipt["session_guard"] = session::status(value, system.now(), Some(true));
            let found = value
                .reason
                .as_ref()
                .map(|reason| reason.code.clone())
                .unwrap_or_default();
            if self.close_action(&found, system.launch_target().provider()) == "warn" {
                // A failure in another sampler cannot hide a fresh HTTP exit.
                // Failure to recheck is still unknown, never invented risk.
                match self.recheck_warning(system, &sessions, family, value, receipt) {
                    Ok(true) => return Ok(()),
                    Ok(false) => {},
                    Err(error) => receipt["warning_recheck_error"] = json!(error.code),
                }
                receipt["session_notice"] = json!({
                    "code": found,
                    "detail": value.reason.as_ref().map(|reason| reason.detail.clone()),
                    "action": "warn",
                });
                receipt["action"] = json!("observe");
                receipt["stop_state"] = json!("skipped_warn_only");
                return Ok(());
            }
            self.finish_current_stop(&sessions, system, id.as_deref(), receipt, None)?;
            return Ok(());
        }
        match sessions.mark_failure(
            id.as_deref(),
            system.now(),
            "guard_sampling_failed",
            "保护采样未能完成",
            false,
        ) {
            Ok(outcome) => {
                receipt["session_guard"] = serde_json::to_value(&outcome)
                    .map_err(|_| CoreError::new("guard_encoding_failed", "保护状态无法编码"))?;
                if matches!(outcome.state.as_str(), "risk" | "locked") {
                    let found = outcome
                        .reason
                        .as_ref()
                        .map(|reason| reason.code.clone())
                        .unwrap_or_else(|| "guard_sampling_failed".into());
                    if self.close_action(&found, system.launch_target().provider()) == "warn" {
                        receipt["session_notice"] = json!({
                            "code": found,
                            "detail": outcome.reason.as_ref().map(|reason| reason.detail.clone()),
                            "action": "warn",
                        });
                        receipt["action"] = json!("observe");
                        receipt["stop_state"] = json!("skipped_warn_only");
                        return Ok(());
                    }
                    self.finish_current_stop(&sessions, system, id.as_deref(), receipt, None)?;
                }
            }
            Err(error) => receipt["sampling_error"] = json!(error.code),
        }
        Ok(())
    }
}
