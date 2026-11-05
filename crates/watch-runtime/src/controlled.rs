//! Sole controlled desktop launch and guard orchestration. No account or proxy changes.
use crate::{
    config_store::ConfigStore, receipt_store::ReceiptStore, session_store::SessionStore,
    storage::StateStore,
};
use claude_watch_core::{
    error::{CoreError, Result},
    policy::PolicyCatalog,
    processes::{Identity as ProcessIdentity, LaunchTarget, Provider, Target},
    session::{self, Desktop, Identity, Launcher},
};
use serde_json::{json, Value};
use std::time::Duration;

mod disposition;
mod sampling_failure;
mod launch;
mod desktop_groups;
use desktop_groups::GroupRound;
mod warning_recovery;
#[cfg(test)]
mod warning_regressions;
use disposition::{confirmed_egress_code, PendingRisk, StopOutcome};
#[cfg(test)]
mod guard_regressions;

pub fn read_process_real_uid(pid: u32) -> u32 {
    #[cfg(unix)]
    {
        if pid > 1 {
            if let Ok(output) = std::process::Command::new("/usr/sbin/lsof")
                .args(["-nP", "-F", "pu", "-p", &pid.to_string()])
                .output()
            {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    for line in text.lines() {
                        if let Some(u) = line.strip_prefix('u') {
                            if let Ok(uid) = u.trim().parse::<u32>() {
                                if uid > 0 {
                                    return uid;
                                }
                            }
                        }
                    }
                }
            }
        }
        let home = std::env::var_os("HOME").unwrap_or_default();
        if let Ok(m) = std::fs::metadata(home) {
            let uid = std::os::unix::fs::MetadataExt::uid(&m);
            if uid > 0 {
                return uid;
            }
        }
    }
    1000
}

pub trait DesktopSystem {
    fn prepare_cli(&mut self) -> Result<()> {
        Err(CoreError::new(
            "cli_adapter_unavailable",
            "CLI执行适配尚不可用",
        ))
    }
    fn cli_interrupted(&self) -> Option<i32> {
        None
    }
    fn spawn_cli(&mut self, _args: &[String]) -> Result<Box<dyn CliProcess>> {
        Err(CoreError::new(
            "cli_adapter_unavailable",
            "CLI执行适配尚不可用",
        ))
    }
    fn launch_target(&self) -> LaunchTarget {
        LaunchTarget::ClaudeDesktop
    }
    /// Point the guard at one policy family before its next tick. The guard
    /// supervises every family the policy table declares, one at a time; this
    /// is how a single engine answers for each of them. Adapters that cannot
    /// change target (a fixed CLI entry) leave the default error.
    fn set_family(&mut self, _family_id: &str) -> Result<()> {
        Err(CoreError::new(
            "target_adapter_unavailable",
            "目标进程适配尚不可用",
        ))
    }
    /// Native-verified, current-user main processes for the selected target.
    fn observation_roots(&mut self) -> Result<Vec<Target>> {
        Err(CoreError::new(
            "target_adapter_unavailable",
            "目标进程适配尚不可用",
        ))
    }
    fn observation_owner(&mut self) -> Result<ProcessIdentity> {
        Err(CoreError::new(
            "target_adapter_unavailable",
            "启动器身份适配尚不可用",
        ))
    }
    fn now(&self) -> f64;
    fn monotonic(&self) -> Duration;
    fn wait(&mut self, duration: Duration);
    /// Each returned identity is native-verified as this user's Claude desktop tree.
    fn desktops(&mut self) -> Result<Vec<(Desktop, bool, String)>>;
    /// A false result requires a complete native inventory showing that this
    /// exact PID and start identity is no longer present.
    fn desktop_alive(&mut self, desktop: &Desktop) -> Result<bool>;
    /// Includes verified Claude desktop helpers, not just the main process.
    fn desktop_tree_running(&mut self) -> Result<bool>;
    fn launcher(&mut self) -> Result<Launcher>;
    fn full_audit(&mut self) -> Result<Value>;
    fn egress(&mut self) -> Value;
    fn local_guard(&mut self) -> Result<Value>;
    fn backend_healthy(&mut self) -> Result<bool>;
    fn guard_backend_healthy(&mut self) -> Result<bool> {
        self.backend_healthy()
    }
    fn launcher_matches(&mut self, launcher: &Launcher) -> Result<bool>;
    fn open_desktop(&mut self) -> Result<()>;
    fn quit_desktop(&mut self) -> Result<()>;
    /// Writes the verified force-request count when the helper can report it,
    /// including when some processes still remain.
    fn quit_for_confirmed_ip_risk(&mut self, forced: &mut Option<u32>) -> Result<()>;
    /// Default disposition is cutting off the application's network channel
    /// while keeping its processes alive (`断流保进程`), rather than calling
    /// legacy process exit (`quit_desktop` / `quit_for_confirmed_ip_risk`).
    fn channel_mode(&self) -> bool {
        true
    }
    /// When true, slow initial-adoption `full_audit()` is handled by the
    /// background async audit worker (`ChannelSupervisor::spawn_async_audit_worker`)
    /// rather than blocking the synchronous guard execution path.
    fn delegates_slow_audit_to_worker(&self) -> bool {
        false
    }
    /// Sends a versioned, sequenced channel command to the network enforcer
    /// and returns its execution receipt.
    fn enforce_channel(
        &mut self,
        _command: &claude_watch_core::channel::ChannelEnforcementCommand,
    ) -> Result<Option<claude_watch_core::channel::ChannelEnforcementReceipt>> {
        Ok(None)
    }
    /// Queries the latest execution receipt for `family` from the network
    /// enforcer (including autonomous lease-expiry actions).
    fn channel_receipt(
        &mut self,
        _family: &str,
    ) -> Result<Option<claude_watch_core::channel::ChannelEnforcementReceipt>> {
        Ok(None)
    }
    /// Returns supervised process tokens with verified system identities (`uid > 0`,
    /// `audit_token: Some([u32; 8])`) for all desktop main, helper, and CLI processes.
    fn supervised_processes(
        &mut self,
    ) -> Result<Vec<claude_watch_core::channel::BoundProcessToken>> {
        let desktops = self.desktops().unwrap_or_default();
        let tokens = desktops
            .into_iter()
            .map(|(d, main, _)| {
                let real_uid = read_process_real_uid(d.pid);
                claude_watch_core::channel::BoundProcessToken::with_system_identity(
                    d.pid,
                    real_uid,
                    d.start_seconds,
                    d.start_microseconds,
                    if main {
                        claude_watch_core::processes::ProcessRole::DesktopMain
                    } else {
                        claude_watch_core::processes::ProcessRole::DesktopHelper
                    },
                )
            })
            .collect();
        Ok(tokens)
    }
}
pub trait CliProcess {
    fn wait(&mut self) -> Result<i32>;
}
pub struct CliOutcome {
    pub exit_code: i32,
    pub diagnostic: Option<String>,
}
#[derive(Debug, Clone, Default)]
struct FamilyChannelLedger {
    permit_generation: u64,
    command_seq: u64,
    last_permit: Option<claude_watch_core::channel::ChannelPermit>,
    revoked_at: Option<f64>,
}
pub struct Controller {
    pub storage: StateStore,
    failed_persistence_session:
        std::sync::Mutex<std::collections::HashMap<&'static str, PendingRisk>>,
    channel_ledger:
        std::sync::Mutex<std::collections::HashMap<&'static str, FamilyChannelLedger>>,
}
impl Controller {
    pub fn new(storage: StateStore) -> Self {
        Self {
            storage,
            failed_persistence_session: std::sync::Mutex::new(std::collections::HashMap::new()),
            channel_ledger: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}
enum FamilyTickPass {
    Complete(Value),
    DeferredSlowAdopt,
}
impl FamilyTickPass {
    #[cfg(test)]
    fn into_value(self) -> Value {
        match self {
            Self::Complete(v) => v,
            Self::DeferredSlowAdopt => {
                json!({"status":"pending","action":"observe","deferred_slow_adopt":true})
            }
        }
    }
}

impl Controller {
    pub fn guard_tick<S: DesktopSystem>(&self, system: &mut S) -> Result<Value> {
        // Which services the guard supervises is declared by the policy table,
        // not by the caller: one engine answers for every family the table
        // declares. Each family runs its own tick against its own session
        // record, then the receipts are folded into one heartbeat. Adding a
        // service later is one row in the policy table — nothing here changes.
        let mut families = Vec::new();
        for family in PolicyCatalog::families() {
            if PolicyCatalog::guard_target(family).is_none() {
                continue;
            }
            families.push(family);
        }
        if families.is_empty() {
            return Ok(json!({"status":"disabled","action":"observe"}));
        }
        let mut receipts = Vec::with_capacity(families.len());
        let mut deferred_slow_adopts = Vec::new();
        for (index, family) in families.iter().enumerate() {
            // Pass 1 runs fast supervision and immediate stops across every
            // family before any family enters a slow initial-adoption full_audit().
            // One family's failure must not stop the others: record it as an
            // unknown round for that family and keep supervising the rest of
            // the table.
            let receipt = match system
                .set_family(family.id)
                .and_then(|()| self.guard_tick_family(system, family.id, false))
            {
                Ok(FamilyTickPass::Complete(receipt)) => receipt,
                Ok(FamilyTickPass::DeferredSlowAdopt) => {
                    deferred_slow_adopts.push((index, family.id));
                    Value::Null
                }
                Err(error) => json!({
                    "family": family.id,
                    "status": "unknown",
                    "action": "observe",
                    "time": system.now(),
                    "code": error.code,
                    "message": error.message,
                }),
            };
            receipts.push(receipt);
        }
        for (index, family_id) in deferred_slow_adopts {
            receipts[index] = match system
                .set_family(family_id)
                .and_then(|()| self.guard_tick_family(system, family_id, true))
            {
                Ok(FamilyTickPass::Complete(receipt)) => receipt,
                Ok(FamilyTickPass::DeferredSlowAdopt) => json!({
                    "family": family_id,
                    "status": "unknown",
                    "action": "observe",
                    "time": system.now(),
                    "code": "deferred_adoption_incomplete",
                    "message": "延后的首次接管未能完成",
                }),
                Err(error) => json!({
                    "family": family_id,
                    "status": "unknown",
                    "action": "observe",
                    "time": system.now(),
                    "code": error.code,
                    "message": error.message,
                }),
            };
        }
        let heartbeat = fold_guard_receipts(receipts);
        self.storage.atomic_json(
            &self.storage.paths.base().join("guard-heartbeat.json"),
            &heartbeat,
        )?;
        Ok(heartbeat)
    }
    fn guard_tick_family<S: DesktopSystem>(
        &self,
        system: &mut S,
        family: &'static str,
        allow_slow_adopt: bool,
    ) -> Result<FamilyTickPass> {
        // Supervision is a desktop matter: a CLI target has its own shared
        // lifecycle entry and never enters this automatic-exit path.
        let target = system.launch_target();
        if target.cli() || PolicyCatalog::family_for(target.provider()).is_none() {
            return Err(CoreError::new(
                "protected_scope_mismatch",
                "观察目标不能进入自动退出保护",
            ));
        }
        let config = match (ConfigStore {
            storage: self.storage.clone(),
        })
        .load()
        {
            Ok(value) => value,
            Err(error) => {
                return Ok(FamilyTickPass::Complete(json!({"status":"unknown","action":"observe","family":family,
                    "time":system.now(),"code":error.code,"message":error.message,
                    "stop_action":"warn","stop_state":"skipped_warn_only",
                    "policy_state":"unavailable"})));
            }
        };
        if !config.enabled || !config.guard_enabled {
            return Ok(FamilyTickPass::Complete(json!({"status":"disabled","action":"observe","family":family})));
        }
        let sessions = SessionStore::for_family(self.storage.clone(), family);
        let receipts = ReceiptStore {
            storage: self.storage.clone(),
        };
        let now = system.now();
        let policy_digest = crate::config_store::policy_digest(&config.value()?)?;
        let guard_policy_digest = crate::config_store::guard_policy_digest(&config)?;
        let mut receipt = json!({"status":"unknown","action":"observe","family":family,"time":now,"policy":policy_digest,"guard_policy_v1":guard_policy_digest});
        let mut deferred = false;
        let result: Result<()> = (|| {
            let mut desktops = system.desktops()?;
            let mut current = sessions.load(system.now())?;
            let mut identity_unconfirmed = false;
            let mut exit_pending = false;
            let group_round = self.prepare_desktop_group(
                system, &sessions, &receipts, family, &config, allow_slow_adopt,
                &mut desktops, &mut current, &mut identity_unconfirmed,
                &mut exit_pending, &mut receipt,
            )?;
            if group_round == GroupRound::DeferredSlowAdopt {
                deferred = true;
                return Ok(());
            }
            if group_round == GroupRound::Handled { return Ok(()); }
            if let Some(previous) = current.as_ref().filter(|s| {
                group_round == GroupRound::Legacy && matches!(
                    s.state,
                    session::Phase::Active | session::Phase::Rechecking | session::Phase::Locked
                )
            }) {
                if let Some(expected) = previous.desktop.as_ref() {
                    if !desktops
                        .iter()
                        .any(|(actual, main, _)| *main && actual == expected)
                    {
                        if system.desktop_alive(expected)? {
                            // The PID still exists, but this inventory did not
                            // establish it as the main app. Never call it replaced.
                            identity_unconfirmed = true;
                        } else {
                            let tree_running = system.desktop_tree_running()?;
                            let risk_latched = previous.state == session::Phase::Locked
                                && previous
                                    .reason
                                    .as_ref()
                                    .is_none_or(|reason| reason.code != "session_identity_changed")
                                || self
                                    .failed_persistence_session
                                    .lock()
                                    .map_err(|_| {
                                        CoreError::new(
                                            "guard_memory_unavailable",
                                            "保护内存状态不可用",
                                        )
                                    })?
                                    .get(family)
                                    .map(|risk| &risk.session_id)
                                    == Some(&previous.session_id);
                            if risk_latched && tree_running {
                                // A confirmed risk stays latched until the
                                // entire desktop tree is gone.
                                exit_pending = true;
                            } else if sessions.end_desktop(
                                &previous.session_id,
                                expected,
                                system.now(),
                                tree_running,
                            )? {
                                receipt["ended_session_id"] = json!(previous.session_id);
                                current = sessions.load(system.now())?;
                                if tree_running {
                                    // A replacement may have appeared while
                                    // confirming the old process exit.
                                    desktops = system.desktops()?;
                                }
                            } else {
                                receipt["session_guard"] = json!({"state":"unknown","reason":{"code":"session_changed","detail":"会话已变化，等待下一轮核对"}});
                                return Ok(());
                            }
                        }
                    }
                }
            }
            if let Some(ended) = current
                .as_ref()
                .filter(|s| s.state == session::Phase::Ended)
            {
                receipt["session_id"] = json!(ended.session_id);
                let mains: Vec<_> = desktops.iter().filter(|(_, main, _)| *main).collect();
                if mains.len() == 1 {
                    let candidate = mains[0].0.clone();
                    current = sessions.begin_recheck(&ended.session_id, candidate, system.now())?;
                    if current.is_none() {
                        receipt["session_guard"] = json!({"state":"unknown","reason":{"code":"session_changed","detail":"会话已变化，等待下一轮核对"}});
                        return Ok(());
                    }
                } else if mains.is_empty() {
                    let tree_pending = ended.extra.get("exit_tree_pending") == Some(&json!(true));
                    let remaining =
                        !desktops.is_empty() || (tree_pending && system.desktop_tree_running()?);
                    if !remaining {
                        if !sessions.clear_ended_tree(&ended.session_id, system.now())? {
                            receipt["session_guard"] = json!({"state":"unknown","reason":{"code":"session_changed","detail":"会话已变化，等待下一轮核对"}});
                            return Ok(());
                        }
                        receipt["status"] = json!("ok");
                        receipt["session_guard"] = json!({"state":"idle","phase":"ended","reason":{"code":"session_ended","detail":"已确认旧会话进程退出"}});
                        return Ok(());
                    }
                    // While verified helpers remain, keep the fast exit check
                    // active; a confirmed risk still requires full shutdown.
                    let egress = system.egress();
                    let checked_at = system.now();
                    let mut code =
                        session::Egress::fresh(&egress, checked_at, session::GUARD_EGRESS_TTL)
                            .and_then(|v| {
                                if v.country == "CN" {
                                    Some("egress_country_cn")
                                } else if ended.extra.get("recheck_baseline_pending")
                                    != Some(&json!(true))
                                    && v.ip != ended.baseline.ip
                                {
                                    Some("egress_ip_changed")
                                } else {
                                    None
                                }
                            });
                    if code.is_none() {
                        let local = system.local_guard()?;
                        if local["proxy"] == "fail" || local["tun"] == "fail" {
                            code = Some("proxy_or_tun_failed");
                        } else if let Some(current) =
                            session::Egress::fresh(&egress, checked_at, session::GUARD_EGRESS_TTL)
                        {
                            let risk = receipts.session_risk(
                                &ended.context_id,
                                Some(&current.ip),
                                checked_at,
                            );
                            if risk["state"] == "risk" {
                                code = Some(match risk["reason"]["source"].as_str() {
                                    Some("dns") => "dns_risk",
                                    Some("webrtc") => "webrtc_risk",
                                    _ => "network_leak_risk",
                                });
                            }
                        }
                    }
                    if let Some(code) = code {
                        let outcome = sessions.mark_failure(
                            Some(&ended.session_id),
                            checked_at,
                            code,
                            "受监督应用的关联进程尚未退出且保护风险已确认",
                            true,
                        )?;
                        receipt["session_id"] = json!(ended.session_id);
                        receipt["session_guard"] =
                            serde_json::to_value(&outcome).map_err(|_| {
                                CoreError::new("guard_encoding_failed", "保护状态无法编码")
                            })?;
                        if matches!(outcome.state.as_str(), "risk" | "locked") {
                            // A warn-only criterion reports without closing, in
                            // this branch too: the related processes outliving a
                            // exited main is the same class of finding the probe
                            // criteria govern, so the configured action decides.
                            if self.close_action(code, system.launch_target().provider()) == "warn" {
                                receipt["session_notice"] = json!({
                                    "code": code,
                                    "detail": outcome.reason.as_ref().map(|r| r.detail.clone()),
                                    "action": "warn",
                                });
                                receipt["action"] = json!("observe");
                                receipt["stop_state"] = json!("skipped_warn_only");
                                return Ok(());
                            }
                            self.finish_current_stop(&sessions, system, Some(ended.session_id.as_str()), &mut receipt, Some(json!(&outcome.reason)))?;
                        }
                    } else {
                        receipt["status"] = json!("unknown");
                        receipt["session_guard"] = json!({"state":"unknown","phase":"ended","reason":{"code":"session_identity_unconfirmed","detail":"旧主进程已退出，仍有受监督应用的关联进程待退出"}});
                    }
                    return Ok(());
                } else {
                    // Multiple mains cannot be adopted, but must not suspend
                    // the independent fast IP check while they are running.
                    let egress = system.egress();
                    let checked_at = system.now();
                    let measured =
                        session::Egress::fresh(&egress, checked_at, session::GUARD_EGRESS_TTL);
                    let code = measured.as_ref().and_then(|v| {
                        if v.country == "CN" {
                            Some("egress_country_cn")
                        } else if ended.extra.get("recheck_baseline_pending") != Some(&json!(true))
                            && v.ip != ended.baseline.ip
                        {
                            Some("egress_ip_changed")
                        } else {
                            None
                        }
                    });
                    let outcome = sessions.mark_failure(
                        Some(&ended.session_id),
                        checked_at,
                        code.unwrap_or("session_identity_unconfirmed"),
                        if code.is_some() {
                            "新进程出口风险已确认"
                        } else {
                            "存在多个主进程，无法完成身份复核"
                        },
                        code.is_some(),
                    )?;
                    receipt["session_id"] = json!(ended.session_id);
                    receipt["session_guard"] = serde_json::to_value(&outcome)
                        .map_err(|_| CoreError::new("guard_encoding_failed", "保护状态无法编码"))?;
                    if matches!(outcome.state.as_str(), "risk" | "locked") {
                        let found = code.unwrap_or("session_identity_unconfirmed");
                        if self.close_action(found, system.launch_target().provider()) == "warn" {
                            receipt["session_notice"] = json!({
                                "code": found,
                                "detail": outcome.reason.as_ref().map(|r| r.detail.clone()),
                                "action": "warn",
                            });
                            receipt["action"] = json!("observe");
                            receipt["stop_state"] = json!("skipped_warn_only");
                            return Ok(());
                        }
                        self.finish_current_stop(&sessions, system, Some(ended.session_id.as_str()), &mut receipt, Some(json!(&outcome.reason)))?;
                    }
                    return Ok(());
                }
            }
            // Supervision follows the Claude process, not only the entry that
            // started it. A desktop opened from Dock, Finder or `open -a` has
            // no launcher session; reading that absence as a stop reason would
            // leave the user with "close it or run unguarded". Adopt it into a
            // verified session instead, with the currently verified egress as
            // its baseline. The full audit must still grant launch permission,
            // so an unverified or already-changed environment is refused here
            // and falls through to the existing no-session handling.
            if current.is_none() && !identity_unconfirmed && !exit_pending {
                let mains: Vec<_> = desktops.iter().filter(|(_, main, _)| *main).collect();
                if mains.len() == 1 {
                    let (desktop, _, stamp) = mains[0];
                    let now = system.now();
                    let egress = system.egress();
                    let healthy = session::Egress::fresh(&egress, now, session::GUARD_EGRESS_TTL)
                        .is_some_and(|exit| exit.country != "CN");
                    if healthy {
                        if system.delegates_slow_audit_to_worker() {
                            receipt["status"] = json!("ok");
                            receipt["action"] = json!("observe");
                            receipt["session_guard"] = json!({
                                "state": "pending_verification",
                                "phase": "pending",
                                "reason": {
                                    "code": "initial_audit_pending",
                                    "detail": "新发现的桌面进程已转交后台异步审计线程核验，不阻塞保护路径"
                                }
                            });
                            return Ok(());
                        }
                        if !allow_slow_adopt {
                            deferred = true;
                            return Ok(());
                        }
                        let adopted = system
                            .full_audit()
                            .and_then(|audit| {
                                sessions.begin_verified(&receipts, &audit, &egress, system.now())
                            })
                            .and_then(|pending| {
                                let id = pending.session_id.clone();
                                sessions.bind_desktop(&id, desktop.clone(), system.now())?;
                                sessions.mark_adopted(&id, system.now())?;
                                self.lease(
                                    desktop,
                                    stamp,
                                    system.now(),
                                    system.launch_target().provider(),
                                )?;
                                Ok(id)
                            });
                        match adopted {
                            Ok(id) => {
                                receipt["status"] = json!("ok");
                                receipt["session_id"] = json!(id);
                                receipt["session_guard"] = json!({
                                    "state": "active",
                                    "phase": "active",
                                    "reason": {"code": "session_adopted", "detail": "手动启动的应用已纳入当前确认出口的监管"}
                                });
                                receipt["action"] = json!("observe");
                                return Ok(());
                            }
                            Err(error) => receipt["adopt_error"] = json!(error.code),
                        }
                    }
                }
            }
            let now = system.now();
            let id = current.as_ref().map(|s| s.session_id.clone());
            let latched = self.pending_risk(family, id.as_deref())?;
            if let Some(risk) = latched {
                receipt["persistence_risk_code"] = json!(risk.code);
                receipt["persistence_error"] = json!("state_io_failed");
                receipt["status"] = json!("protection_triggered");
                receipt["session_id"] = json!(id);
                receipt["session_guard"] = json!({"state":"locked", "phase":"locked", "reason":{"code":"egress_risk_persist_failed", "detail":"出口风险已确认，会话记录写入失败"}});
                if desktops.is_empty() && !identity_unconfirmed && !exit_pending {
                    receipt["stop_state"] = json!("confirmed");
                } else {
                    self.finish_current_stop(&sessions, system, id.as_deref(), &mut receipt, None)?;
                }
                return Ok(());
            }
            if (!desktops.is_empty() || identity_unconfirmed || exit_pending)
                && current
                    .as_ref()
                    .is_some_and(|s| s.state == session::Phase::Locked)
            {
                receipt["status"] = json!("protection_triggered");
                receipt["session_id"] = json!(id);
                receipt["session_guard"] =
                    session::status(current.as_ref().unwrap(), system.now(), Some(true));
                // A warn-configured criterion keeps notifying without closing,
                // including later Locked rounds. Before reporting the old
                // notice, recheck independent confirmed risks against their
                // own actions; a notice is not a global supervision pause.
                let code = current
                    .as_ref()
                    .and_then(|s| s.reason.as_ref())
                    .map(|r| r.code.clone())
                    .unwrap_or_default();
                if self.close_action(&code, system.launch_target().provider()) == "warn" {
                    // A warn tier never closes. When the underlying condition
                    // has cleared, resume normal supervision instead of
                    // latching the notice until the session ends.
                    let session = current.as_ref().unwrap();
                    if self.recheck_warning(system, &sessions, family, session, &mut receipt)? {
                        return Ok(());
                    }
                    if self.resume_warning(system, &sessions, family, session, &mut receipt)? {
                        return Ok(());
                    }
                    receipt["session_notice"] = json!({
                        "code": code,
                        "detail": current.as_ref().and_then(|s| s.reason.as_ref()).map(|r| r.detail.clone()),
                        "action": "warn",
                    });
                    receipt["action"] = json!("observe");
                    receipt["stop_state"] = json!("skipped_warn_only");
                    return Ok(());
                }
                self.finish_current_stop(&sessions, system, id.as_deref(), &mut receipt,
                                    Some(json!(current.as_ref().and_then(|value| value.reason.as_ref()))))?;
                return Ok(());
            }
            let local = system.local_guard()?;
            let guard_backend = match local["guard_backend_healthy"].as_bool() {
                Some(value) => value,
                None => system.guard_backend_healthy()?,
            };
            let healthy = local["proxy"] == "ok" && local["tun"] == "ok" && guard_backend;
            receipt["status"] = json!(if healthy { "ok" } else { "degraded" });
            if desktops.is_empty() && !identity_unconfirmed {
                receipt["session_guard"] = current
                    .as_ref()
                    .map(|s| session::status(s, now, Some(false)))
                    .unwrap_or(json!({"state":"idle","detail":"后台保护待命，无需操作"}));
                return Ok(());
            }
            let outcome = if local["proxy"] == "fail" || local["tun"] == "fail" {
                sessions.mark_failure(
                    id.as_deref(),
                    now,
                    "proxy_or_tun_failed",
                    "代理或TUN已确认失效",
                    true,
                )?
            } else {
                let launcher_live = current
                    .as_ref()
                    .and_then(|s| s.launcher.as_ref())
                    .map(|l| system.launcher_matches(l))
                    .transpose()?
                    .unwrap_or(false);
                let identity =
                    if let Some(expected) = current.as_ref().and_then(|s| s.desktop.as_ref()) {
                        let group_matches = current.as_ref()
                            .filter(|s| crate::session_store::desktop_groups::has_desktop_group(s))
                            .map(|s| crate::session_store::desktop_groups::desktop_set_matches(s, &desktops))
                            .transpose()?.unwrap_or(true);
                        if !identity_unconfirmed && group_matches
                            && desktops.iter().any(|(d, main, _)| *main && d == expected)
                        {
                            Identity::Matches
                        } else {
                            Identity::Unavailable
                        }
                    } else {
                        Identity::Matches
                    };
                let egress = system.egress();
                let checked_at = system.now();
                let confirmed_exit = current.as_ref()
                    .and_then(|session| confirmed_egress_code(session, &egress, checked_at));
                let local_unknown = local["proxy"] != "ok" || local["tun"] != "ok";
                match sessions.check_verified_local(
                    &receipts,
                    id.as_deref(),
                    checked_at,
                    launcher_live,
                    identity,
                    egress,
                    local_unknown,
                ) {
                    Ok(outcome) => outcome,
                    Err(error) if confirmed_exit.is_some() && error.code == "state_io_failed" => {
                        let risk_code = confirmed_exit.ok_or_else(|| {
                            CoreError::new("egress_unconfirmed", "未确认出口风险，未授权处置")
                        })?;
                        receipt["persistence_risk_code"] = json!(risk_code);
                        receipt["status"] = json!("degraded");
                        receipt["session_id"] = json!(id);
                        receipt["session_guard"] = json!({"state":"risk", "reason":{"code":"egress_risk_persist_failed", "detail":"出口风险已确认，会话记录写入失败"}});
                        receipt["persistence_error"] = json!(error.code);
                        self.remember_risk(family, id.as_deref(), risk_code)?;
                        match sessions.close_if_current_before(
                            id.as_deref(),
                            system.now(),
                            checked_at,
                            || self.timed_guard_quit(system, &mut receipt),
                        ) {
                            Ok(Some(StopOutcome::SkippedWarn)) => {}
                            Ok(Some(StopOutcome::Confirmed)) => {
                                receipt["action"] = json!("close-desktop");
                                receipt["stop_state"] = json!("confirmed");
                            }
                            Ok(None) => {
                                self.forget_risk(family, id.as_deref())?;
                                receipt["stop_state"] = json!("session_changed");
                            }
                            Err(stop_error) => {
                                receipt["stop_state"] = json!("failed");
                                receipt["stop_error"] = json!(stop_error.code);
                            }
                        }
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            };
            receipt["session_id"] = json!(id);
            receipt["session_guard"] = serde_json::to_value(&outcome)
                .map_err(|_| CoreError::new("guard_encoding_failed", "保护状态无法编码"))?;
            if current
                .as_ref()
                .is_some_and(|s| s.state == session::Phase::Rechecking)
                && outcome.state == "pending"
            {
                receipt["session_guard"]["phase"] = json!("rechecking");
            }
            if matches!(outcome.state.as_str(), "risk" | "locked") {
                let code = outcome
                    .reason
                    .as_ref()
                    .map(|r| r.code.clone())
                    .unwrap_or_default();
                // "No session" is the absence of supervision, not a diagnosis:
                // it must not mask a drift that is confirmed independently of
                // any session. A mainland exit is confirmed by the same
                // measurement that would have refused to adopt the process, so
                // it keeps the action its own criterion declares instead of
                // inheriting the mild default of the unconfirmed row.
                let code = if code == "session_missing"
                    && session::Egress::fresh(
                        &system.egress(),
                        system.now(),
                        session::GUARD_EGRESS_TTL,
                    )
                    .is_some_and(|exit| exit.country == "CN")
                {
                    "egress_country_cn".to_string()
                } else {
                    code
                };
                // A warn-configured criterion reports but never closes: the
                // session stays active and the next round re-evaluates. The
                // risk round latches the session to Locked, so later rounds
                // arrive as "locked" with the same reason; warn must cover
                // those too, or it would degrade into a delayed close.
                if self.close_action(&code, system.launch_target().provider()) == "warn" {
                    receipt["session_notice"] = json!({
                        "code": code,
                        "detail": outcome.reason.as_ref().map(|r| r.detail.clone()),
                        "action": "warn",
                    });
                    receipt["action"] = json!("observe");
                    receipt["stop_state"] = json!("skipped_warn_only");
                    return Ok(());
                }
                let expected = outcome.session.as_ref().map(|s| s.session_id.as_str());
                self.finish_current_stop(&sessions, system, expected, &mut receipt, Some(json!(&outcome.reason)))?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.sampling_failure(system, family, &mut receipt, error)?;
        }
        if deferred {
            return Ok(FamilyTickPass::DeferredSlowAdopt);
        }
        let latest_session = sessions.load(system.now()).ok().flatten();
        self.sync_family_channel(
            system,
            family,
            &config,
            latest_session.as_ref(),
            claude_watch_core::channel::PolicyVersion {
                policy_digest,
                guard_policy_digest,
            },
            &mut receipt,
        )?;
        Ok(FamilyTickPass::Complete(receipt))
    }

    fn sync_family_channel<S: DesktopSystem>(
        &self,
        system: &mut S,
        family: &'static str,
        config: &claude_watch_core::config::Config,
        latest_session: Option<&session::Session>,
        policy_version: claude_watch_core::channel::PolicyVersion,
        receipt: &mut Value,
    ) -> Result<()> {
        use claude_watch_core::channel::{
            evaluate_channel_supervision, verify_channel_recovery, BoundProcessToken,
            ChannelEnforcementCommand, ChannelPermit, ChannelPermitState,
            ChannelSupervisionVerdict, DEFAULT_PERMIT_TTL,
        };
        use claude_watch_core::processes::ProcessRole;

        let now = system.now();
        let (prev_permit, prev_revoked_at, base_gen, next_cmd_seq) = {
            let mut map = self.channel_ledger.lock().map_err(|_| {
                CoreError::new("guard_memory_unavailable", "保护内存状态不可用")
            })?;
            let entry = map.entry(family).or_default();
            if entry.permit_generation == 0 {
                entry.permit_generation = 1;
            }
            entry.command_seq = entry.command_seq.saturating_add(1);
            (
                entry.last_permit.clone(),
                entry.revoked_at,
                entry.permit_generation,
                entry.command_seq,
            )
        };

        let mut candidate = ChannelPermit::from_guard_round(
            family,
            latest_session,
            receipt,
            policy_version.clone(),
            base_gen,
            next_cmd_seq,
            now,
            DEFAULT_PERMIT_TTL,
        )?;
        if candidate.state == ChannelPermitState::Permitted {
            if let Some(exit) =
                session::Egress::fresh(&system.egress(), now, session::GUARD_EGRESS_TTL)
            {
                let evidence_expires_at = exit.observed_at + session::GUARD_EGRESS_TTL;
                if evidence_expires_at > now {
                    candidate.valid_until = candidate.valid_until.min(evidence_expires_at);
                } else if system.channel_mode() {
                    candidate.state = ChannelPermitState::Revoked;
                    candidate.reason_code = "egress_evidence_expired".into();
                }
            } else if system.channel_mode() {
                candidate.state = ChannelPermitState::Revoked;
                candidate.reason_code = "egress_evidence_expired".into();
            }
        }

        if let Some(prev) = prev_permit.as_ref() {
            let session_changed = prev.session_id != candidate.session_id;
            let policy_changed = prev.policy_version != candidate.policy_version;
            let state_changed = prev.state != candidate.state;
            if session_changed || policy_changed || state_changed {
                candidate.permit_generation = prev.permit_generation.saturating_add(1);
            }
            // If previously revoked under the same session, returning to
            // Permitted requires passing `verify_channel_recovery` with fresh
            // post-revocation evidence under the current policy version.
            if prev.state == ChannelPermitState::Revoked
                && candidate.state == ChannelPermitState::Permitted
                && !session_changed
            {
                let audit_path = self.storage.paths.base().join("last-audit.json");
                let stored_audit = self
                    .storage
                    .read_json(&audit_path, Value::Null)
                    .unwrap_or(Value::Null);
                let audit_ready = stored_audit["ready"] == true
                    && stored_audit["grants_launch_permission"] == true;
                let audit_observed_at = stored_audit["observed_at"]
                    .as_f64()
                    .or_else(|| latest_session.map(|s| s.created_at))
                    .unwrap_or(0.0);
                let egress = system.egress();
                let context_id = candidate
                    .context_id
                    .clone()
                    .unwrap_or_else(|| "recovered-ctx".into());
                match verify_channel_recovery(
                    prev,
                    prev_revoked_at.unwrap_or(prev.issued_at),
                    candidate.session_id.as_deref(),
                    audit_ready,
                    audit_observed_at,
                    &policy_version,
                    &egress,
                    candidate.session_id.as_deref(),
                    &policy_version,
                    &context_id,
                    candidate.permit_generation,
                    candidate.command_seq,
                    now,
                    DEFAULT_PERMIT_TTL,
                ) {
                    Ok(recovered) => candidate = recovered,
                    Err(err) if system.channel_mode() => {
                        candidate.state = ChannelPermitState::Revoked;
                        candidate.reason_code = err.code;
                    }
                    Err(_) => {}
                }
            }
        }

        let allowed_processes: Vec<BoundProcessToken> = {
            let desktops = system.desktops().unwrap_or_default();
            desktops
                .into_iter()
                .map(|(d, main, _)| {
                    let real_uid = read_process_real_uid(d.pid);
                    BoundProcessToken::with_system_identity(
                        d.pid,
                        real_uid,
                        d.start_seconds,
                        d.start_microseconds,
                        if main {
                            ProcessRole::DesktopMain
                        } else {
                            ProcessRole::DesktopHelper
                        },
                    )
                })
                .collect()
        };

        let upstream_endpoint = if config.proxy_url.trim().is_empty() {
            "127.0.0.1:7890".to_string()
        } else {
            config.proxy_url.clone()
        };

        let command = ChannelEnforcementCommand {
            family: family.into(),
            session_id: candidate.session_id.clone(),
            policy_version: policy_version.clone(),
            permit_generation: candidate.permit_generation,
            command_seq: candidate.command_seq,
            permit: candidate.clone(),
            allowed_processes,
            upstream_endpoint,
            issued_at: now,
        };

        // Single authoritative entry point: In full supervisor mode,
        // ChannelSupervisor is the sole command issuer. Controller synchronizes
        // observations and reads the authoritative permit persisted by the supervisor,
        // never inventing fake permits with hardcoded valid_until periods.
        let (effective_permit, enforcer_receipt, verdict) = if system.delegates_slow_audit_to_worker() {
            let r = system.channel_receipt(family)?;
            let supervisor_permit = self
                .storage
                .read_json(
                    &self.storage.paths.watch().join("state/channel-permits.json"),
                    serde_json::Value::Null,
                )
                .ok()
                .and_then(|val| {
                    val.get(family)
                        .and_then(|p| serde_json::from_value::<ChannelPermit>(p.clone()).ok())
                });
            if let Some(auth_permit) = supervisor_permit {
                let v = evaluate_channel_supervision(&auth_permit, r.as_ref(), &policy_version, now);
                (auth_permit, r, v)
            } else if let Some(ref receipt) = r {
                let mut p = candidate.clone();
                p.session_id = receipt.session_id.clone();
                p.permit_generation = receipt.permit_generation;
                p.command_seq = receipt.command_seq;
                p.state = receipt.permit_state;
                if let Some(ref err) = receipt.error_code {
                    p.reason_code = err.clone();
                }
                let v = evaluate_channel_supervision(&p, Some(receipt), &policy_version, now);
                (p, r, v)
            } else {
                let v = evaluate_channel_supervision(&candidate, None, &policy_version, now);
                (candidate, None, v)
            }
        } else {
            let r = match system.enforce_channel(&command)? {
                Some(r) => Some(r),
                None => system.channel_receipt(family)?,
            };
            let v = evaluate_channel_supervision(&candidate, r.as_ref(), &policy_version, now);
            (candidate, r, v)
        };

        {
            let mut map = self.channel_ledger.lock().map_err(|_| {
                CoreError::new("guard_memory_unavailable", "保护内存状态不可用")
            })?;
            let entry = map.entry(family).or_default();
            entry.permit_generation = effective_permit.permit_generation;
            entry.command_seq = effective_permit.command_seq;
            if effective_permit.state == ChannelPermitState::Revoked
                && entry
                    .last_permit
                    .as_ref()
                    .is_none_or(|p| p.state != ChannelPermitState::Revoked)
            {
                entry.revoked_at = Some(now);
            } else if effective_permit.state == ChannelPermitState::Permitted {
                entry.revoked_at = None;
            }
            entry.last_permit = Some(effective_permit.clone());
        }

        if let Ok(value) = serde_json::to_value(&effective_permit) {
            receipt["channel_permit"] = value;
        }
        if let Some(r) = &enforcer_receipt {
            if let Ok(value) = serde_json::to_value(r) {
                receipt["channel_receipt"] = value;
            }
        }
        if let Ok(value) = serde_json::to_value(&verdict) {
            receipt["channel_supervision"] = value;
        }

        if system.channel_mode() {
            receipt["disposition_mode"] = json!("disconnect_channel_keep_process");
            receipt["process_preserved"] = json!(true);
            if effective_permit.state == ChannelPermitState::Revoked {
                receipt["action"] = json!("disconnect-channel");
                match &verdict {
                    ChannelSupervisionVerdict::IsolatedKeepProcess => {
                        receipt["stop_state"] = json!("channel_blocked");
                        receipt["channel_state"] = json!("blocked");
                        receipt["channel_status_label"] = json!("已阻断");
                    }
                    ChannelSupervisionVerdict::PendingIsolation { .. } => {
                        receipt["stop_state"] = json!("disconnecting");
                        receipt["channel_state"] = json!("disconnecting");
                        receipt["channel_status_label"] = json!("正在断开");
                    }
                    ChannelSupervisionVerdict::EnforcementFailed {
                        code,
                        status_label_zh,
                    } => {
                        receipt["status"] = json!("protection_unavailable");
                        receipt["stop_state"] = json!("enforcement_failed");
                        receipt["channel_state"] = json!("failed");
                        receipt["channel_error"] = json!(code);
                        receipt["channel_status_label"] = json!(status_label_zh);
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

}

/// Fold one receipt per supervised family into a single heartbeat. The top
/// level carries the most severe family's receipt verbatim so the existing UI
/// and diagnostics keep reading the fields they know (`status`, `action`,
/// `stop_state`, `session_guard`, `session_id`), while the `families` array
/// keeps every family's full receipt. Adding a service is a new entry in the
/// policy table; nothing here needs to know about it.
fn fold_guard_receipts(receipts: Vec<Value>) -> Value {
    let severity = |status: &str| -> u8 {
        match status {
            "protection_unavailable" => 6,
            "protection_triggered" => 5,
            "unknown" => 4,
            "degraded" => 3,
            "ok" => 2,
            "disabled" => 1,
            _ => 0,
        }
    };
    let rank = |receipt: &Value| -> (u8, u8) {
        // A family that actually closed or disconnected outranks one that only reported.
        let acted = u8::from(matches!(
            receipt["action"].as_str(),
            Some("close-desktop" | "disconnect-channel")
        ));
        (severity(receipt["status"].as_str().unwrap_or("")), acted)
    };
    let mut primary: Option<Value> = None;
    for receipt in &receipts {
        let take = primary
            .as_ref()
            .is_none_or(|current| rank(receipt) > rank(current));
        if take {
            primary = Some(receipt.clone());
        }
    }
    let mut folded = primary.unwrap_or_else(|| {
        serde_json::json!({"status":"disabled","action":"observe"})
    });
    folded["families"] = serde_json::json!(receipts);
    folded
}
