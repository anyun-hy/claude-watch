//! Family-cohort lifecycle. All mains are bound explicitly; no first-process
//! shortcut grants supervision to the rest. Stop scope remains family-wide.
use super::*;
use claude_watch_core::{config::Config, session::{Phase, Session}};
use crate::session_store::desktop_groups::{
    desktop_members, group_rechecking, has_desktop_group, observed_desktops,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum GroupRound { Legacy, Continue, Handled, DeferredSlowAdopt }

impl Controller {
    /// Reconcile membership before the legacy single-main lifecycle runs.
    /// Only native inventory and identity reads occur here for existing groups;
    /// a joining/restarted app gets a bounded background audit, not a new baseline.
    pub(super) fn prepare_desktop_group<S: DesktopSystem>(
        &self, system: &mut S, sessions: &SessionStore, receipts: &ReceiptStore,
        family: &'static str, config: &Config, allow_slow_adopt: bool,
        rows: &mut Vec<(Desktop, bool, String)>, current: &mut Option<Session>,
        identity_unconfirmed: &mut bool, exit_pending: &mut bool, receipt: &mut Value,
    ) -> Result<GroupRound> {
        if family != "openai" { return Ok(GroupRound::Legacy); }
        let observed = observed_desktops(rows)?;
        if observed.len() < 2 && !current.as_ref().is_some_and(has_desktop_group) {
            return Ok(GroupRound::Legacy);
        }
        let Some(expected) = current.clone() else {
            let before = system.egress();
            let Some(initial) = session::Egress::fresh(&before, system.now(), session::GUARD_EGRESS_TTL)
                .filter(|e| e.country != "CN") else { return Ok(GroupRound::Legacy) };
            if !allow_slow_adopt {
                return Ok(GroupRound::DeferredSlowAdopt);
            }
            let audit = match system.full_audit() {
                Ok(value) => value,
                Err(error) => { receipt["adopt_error"] = json!(error.code); return Ok(GroupRound::Legacy); }
            };
            let after = system.egress();
            let checked_at = system.now();
            let stable = session::Egress::fresh(&after, checked_at, session::GUARD_EGRESS_TTL)
                .is_some_and(|e| e.ip == initial.ip && e.country == initial.country);
            *rows = system.desktops()?;
            if !stable || observed_desktops(rows)? != observed {
                receipt["action"] = json!("observe");
                receipt["stop_state"] = json!("session_changed");
                receipt["session_guard"] = json!({"state":"unknown","reason":{
                    "code":"session_changed","detail":"接管期间主进程集合或出口变化，等待新一轮核验"}});
                return Ok(GroupRound::Handled);
            }
            let adopted = match sessions.adopt_desktop_group(receipts, &audit, &after, observed, config, checked_at) {
                Ok(Some(value)) => value,
                Ok(None) => {
                    receipt["action"] = json!("observe");
                    receipt["stop_state"] = json!("session_changed");
                    return Ok(GroupRound::Handled);
                }
                Err(error) => { receipt["adopt_error"] = json!(error.code); return Ok(GroupRound::Legacy); }
            };
            let mut lease_errors = Vec::new();
            for (desktop, main, stamp) in rows.iter() {
                if *main {
                    if let Err(error) = self.lease(desktop, stamp, system.now(), system.launch_target().provider()) {
                        lease_errors.push(json!({"pid":desktop.pid,"code":error.code}));
                    }
                }
            }
            receipt["status"] = json!(if lease_errors.is_empty() { "ok" } else { "degraded" });
            receipt["session_id"] = json!(adopted.session_id);
            receipt["action"] = json!("observe");
            receipt["desktop_members"] = json!(desktop_members(&adopted)?);
            receipt["desktop_count"] = json!(desktop_members(&adopted)?.len());
            receipt["session_guard"] = json!({"state":"active","phase":"active","reason":{
                "code":"session_adopted","detail":"全部已核实桌面主进程已绑定到共享策略会话"}});
            if !lease_errors.is_empty() { receipt["lease_errors"] = json!(lease_errors); }
            *current = Some(adopted);
            return Ok(GroupRound::Handled);
        };
        if expected.state == Phase::Pending { return Ok(GroupRound::Legacy); }
        let previous = desktop_members(&expected)?;
        if previous.is_empty() { return Ok(GroupRound::Legacy); }
        // A missing main entry can be incomplete metadata, not an exit. Every
        // removed identity is checked independently, including non-anchor mains.
        for old in previous.iter().filter(|d| !observed.contains(d)) {
            if system.desktop_alive(old)? {
                *identity_unconfirmed = true;
                receipt["desktop_members"] = json!(previous);
                return Ok(GroupRound::Continue);
            }
        }
        let pending_stop = self.pending_risk(family, Some(&expected.session_id))?.is_some();
        let mandatory = pending_stop || (expected.state == Phase::Locked
            && expected.reason.as_ref().is_none_or(|r| config.close_action(&r.code, system.launch_target().provider()) != "warn"));
        if observed.is_empty() {
            let tree = system.desktop_tree_running()?;
            if mandatory && tree {
                *exit_pending = true;
                return Ok(GroupRound::Continue);
            }
            if expected.state != Phase::Ended {
                if !sessions.end_desktop(&expected.session_id, expected.desktop.as_ref().unwrap(), system.now(), tree)? {
                    receipt["stop_state"] = json!("session_changed");
                    return Ok(GroupRound::Handled);
                }
                receipt["ended_session_id"] = json!(expected.session_id);
                *current = sessions.load(system.now())?;
            }
            return Ok(GroupRound::Continue);
        }
        // Never erase or transfer a required stop by changing its membership.
        // In particular a new safe sample cannot cancel an earlier failed stop.
        if mandatory {
            *exit_pending = true;
            return Ok(GroupRound::Continue);
        }
        let expired = group_rechecking(&expected) && system.now() >= expected.pending_deadline;
        if observed != previous || expected.state == Phase::Ended || expired {
            match sessions.reconcile_desktop_group(&expected, observed, config, system.now())? {
                Some(value) => *current = Some(value),
                None => {
                    receipt["action"] = json!("observe");
                    receipt["stop_state"] = json!("session_changed");
                    return Ok(GroupRound::Handled);
                }
            }
        }
        if let Some(value) = current.as_ref() {
            let members = desktop_members(value)?;
            receipt["desktop_count"] = json!(members.len());
            receipt["desktop_members"] = json!(members);
            receipt["desktop_group_rechecking"] = json!(group_rechecking(value));
        }
        Ok(GroupRound::Continue)
    }
}
