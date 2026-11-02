//! Sole controlled desktop launch and guard orchestration. No account or proxy changes.
use crate::{
    config_store::ConfigStore, receipt_store::ReceiptStore, session_store::SessionStore,
    storage::StateStore,
};
use claude_watch_core::{
    error::{CoreError, Result},
    processes::{Identity as ProcessIdentity, LaunchTarget, Lease, Target},
    session::{self, Desktop, Identity, Launcher},
};
use serde_json::{json, Value};
use std::{fs, time::Duration};

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
}
pub trait CliProcess {
    fn wait(&mut self) -> Result<i32>;
}
pub struct CliOutcome {
    pub exit_code: i32,
    pub diagnostic: Option<String>,
}
pub struct Controller {
    pub storage: StateStore,
    failed_persistence_session: std::sync::Mutex<Option<String>>,
}
impl Controller {
    pub fn new(storage: StateStore) -> Self {
        Self {
            storage,
            failed_persistence_session: std::sync::Mutex::new(None),
        }
    }
    fn record_launch(&self, target: LaunchTarget, pid: u32, now: f64) -> Option<Value> {
        crate::events::EventStore::new(self.storage.clone())
            .append(
                "controlled-launch",
                crate::events::EventFields {
                    operation: Some(target.as_str().into()),
                    pid: Some(pid),
                    status: Some("ok".into()),
                    ..Default::default()
                },
                now,
            )
            .err()
            .map(|e| json!({"code":e.code,"message":e.message}))
    }
    fn pending_path(&self) -> std::path::PathBuf {
        self.storage.paths.watch().join("state/desktop-pending")
    }
    fn clear_pending(&self) -> Result<()> {
        let path = self.pending_path();
        self.storage.guarded(&path)?;
        if path.exists() {
            fs::remove_file(path)
                .map_err(|_| CoreError::new("pending_cleanup_failed", "启动等待记录无法清理"))?
        }
        Ok(())
    }
    pub(crate) fn lease(&self, desktop: &Desktop, stamp: &str, now: f64) -> Result<()> {
        if stamp.contains(['|', '\n', '\r']) || stamp.is_empty() {
            return Err(CoreError::new(
                "desktop_identity_unavailable",
                "主进程启动时间未能确认",
            ));
        }
        let path = self
            .storage
            .paths
            .watch()
            .join(format!("state/sessions/rust-{}.session", desktop.pid));
        self.storage.atomic_bytes(
            &path,
            format!(
                "desktop|claude|{}|{}|0|-|{}\n",
                desktop.pid,
                stamp,
                now.floor()
            )
            .as_bytes(),
            0o600,
        )
    }
    pub fn launch<S: DesktopSystem>(&self, system: &mut S) -> Result<Value> {
        if system.launch_target().cli() {
            return Err(CoreError::new(
                "invalid_target_entry",
                "CLI必须使用带生命周期的共享入口",
            ));
        }
        let _launch = self.storage.lock("launch", None)?;
        if !system.launch_target().protected() {
            return self.launch_observation(system);
        }
        if !system.desktops()?.is_empty() {
            return Err(CoreError::new(
                "claude_already_running",
                "Claude 已在运行，不能补建受控启动会话",
            ));
        }
        let audit = system.full_audit()?;
        let current = system.egress();
        if !system.desktops()?.is_empty() {
            return Err(CoreError::new(
                "claude_already_running",
                "预检期间Claude已由其他入口启动，未补建保护会话",
            ));
        }
        let sessions = SessionStore::new(self.storage.clone());
        let receipts = ReceiptStore {
            storage: self.storage.clone(),
        };
        let pending = sessions.begin_verified(&receipts, &audit, &current, system.now())?;
        let id = pending.session_id.clone();
        let result: Result<Value> = (|| {
            let launcher = system.launcher()?;
            sessions.bind_launcher(&id, launcher.clone(), system.now())?;
            self.storage.atomic_bytes(
                &self.pending_path(),
                format!(
                    "{}|{}|{}\n",
                    launcher.pid,
                    launcher.start,
                    system.now().floor()
                )
                .as_bytes(),
                0o600,
            )?;
            system.open_desktop()?;
            let deadline = system.monotonic() + Duration::from_secs(10);
            while system.monotonic() < deadline {
                let processes = system.desktops()?;
                let mains: Vec<_> = processes.into_iter().filter(|p| p.1).collect();
                if mains.len() == 1 {
                    let (desktop, _, stamp) = &mains[0];
                    sessions.bind_desktop(&id, desktop.clone(), system.now())?;
                    self.lease(desktop, stamp, system.now())?;
                    self.clear_pending()?;
                    let logging_error =
                        self.record_launch(LaunchTarget::ClaudeDesktop, desktop.pid, system.now());
                    return Ok(
                        json!({"status":"ok","session_id":id,"audit":audit,"logging_error":logging_error,"message":"已通过受控入口启动，不代表账号服务可用"}),
                    );
                }
                system.wait(Duration::from_millis(200));
            }
            Err(CoreError::new(
                "desktop_identity_unavailable",
                "启动后未能确认唯一Claude主进程",
            ))
        })();
        if result.is_err() {
            let _ = sessions.mark_failure(
                Some(&id),
                system.now(),
                "launch_failed",
                "Claude受控启动未完成",
                true,
            );
            let _ = self.clear_pending();
            let _ = sessions.close_if_current(Some(&id), system.now(), || system.quit_desktop());
        }
        result
    }
    fn observation_audit<S: DesktopSystem>(
        &self,
        system: &mut S,
        owner: &ProcessIdentity,
    ) -> Result<Value> {
        let target = system.launch_target();
        if !system.backend_healthy()? {
            return Err(CoreError::new(
                "backend_unhealthy",
                "采集后台未有效运行，未启动",
            ));
        }
        let audit = system.full_audit()?;
        let current = system.egress();
        let now = system.now();
        let risk = ReceiptStore {
            storage: self.storage.clone(),
        }
        .session_risk(
            audit["context_id"].as_str().unwrap_or(""),
            current["ip"].as_str(),
            now,
        );
        session::verify_launch(&audit, &current, &risk, now, target)?;
        if !system.backend_healthy()? || !system.observation_owner()?.same_process(owner) {
            return Err(CoreError::new(
                "launcher_context_changed",
                "预检期间后台或启动器身份变化，未启动",
            ));
        }
        Ok(audit)
    }
    fn launch_observation<S: DesktopSystem>(&self, system: &mut S) -> Result<Value> {
        let target = system.launch_target();
        let owner = system.observation_owner()?;
        if !owner.valid() {
            return Err(CoreError::new(
                "launcher_identity_unavailable",
                "启动器身份未确认",
            ));
        }
        if !system.observation_roots()?.is_empty() {
            return Err(CoreError::new(
                "target_already_running",
                "目标已在运行，不能补登记观察会话",
            ));
        }
        let audit = self.observation_audit(system, &owner)?;
        if !system.observation_roots()?.is_empty() {
            return Err(CoreError::new(
                "target_already_running",
                "预检期间目标已由其他入口启动，未补登记观察会话",
            ));
        }
        system.open_desktop()?;
        let deadline = system.monotonic() + Duration::from_secs(10);
        while system.monotonic() < deadline {
            let roots = system.observation_roots()?;
            if roots.len() == 1 {
                let root = &roots[0];
                if !target.accepts(root.kind)
                    || root.identity.uid != owner.uid
                    || !root.identity.valid()
                {
                    return Err(CoreError::new(
                        "target_identity_mismatch",
                        "目标身份不匹配，未登记观察会话",
                    ));
                }
                let verified = system.observation_roots()?;
                if system.monotonic() >= deadline
                    || verified.len() != 1
                    || !verified[0].identity.same_process(&root.identity)
                    || verified[0].kind != root.kind
                {
                    return Err(CoreError::new(
                        "target_identity_changed",
                        "目标身份变化或超时，未登记观察会话",
                    ));
                }
                crate::lease_store::LeaseStore {
                    storage: self.storage.clone(),
                }
                .save(
                    &Lease {
                        provider: root.kind.provider(),
                        root: root.identity.clone(),
                        owner: None,
                        cli: false,
                    },
                    system.now(),
                )?;
                let logging_error = self.record_launch(target, root.identity.pid, system.now());
                return Ok(
                    json!({"status":"ok","target":target,"provider":root.kind.provider(),"authorization_scope":"observation","pid":root.identity.pid,"audit":audit,"logging_error":logging_error,
                    "message":"已登记目标主进程的观察关联；不创建Claude保护会话，不代表应用专属代理或账号服务已验证"}),
                );
            }
            system.wait(Duration::from_millis(200));
        }
        Err(CoreError::new(
            "target_start_unconfirmed",
            "启动窗口内未确认唯一目标主进程；未授权，也未结束应用",
        ))
    }
    pub fn launch_cli<S: DesktopSystem>(
        &self,
        system: &mut S,
        args: &[String],
    ) -> Result<CliOutcome> {
        let target = system.launch_target();
        let provider = target
            .cli_provider()
            .ok_or_else(|| CoreError::new("invalid_target_entry", "目标不是CLI"))?;
        let operation = self.storage.lock("operation", None)?;
        let launch = self.storage.lock("launch", None)?;
        let owner = system.observation_owner()?;
        if !owner.valid() {
            return Err(CoreError::new(
                "launcher_identity_unavailable",
                "CLI启动器身份未确认",
            ));
        }
        self.observation_audit(system, &owner)?;
        system.prepare_cli()?;
        if let Some(code) = system.cli_interrupted() {
            return Ok(CliOutcome {
                exit_code: code,
                diagnostic: None,
            });
        }
        let mut lease = crate::lease_store::LeaseStore {
            storage: self.storage.clone(),
        }
        .save_cli(provider, &owner, system.now())?;
        if let Some(code) = system.cli_interrupted() {
            let diagnostic = lease.clear().err().map(|e| e.message);
            return Ok(CliOutcome {
                exit_code: code,
                diagnostic,
            });
        }
        let mut child = system.spawn_cli(args)?;
        let _ = self.record_launch(target, owner.pid, system.now());
        drop(launch);
        drop(operation);
        let (code, mut diagnostic) = match child.wait() {
            Ok(code) => (code, None),
            Err(e) => (4, Some(e.message)),
        };
        if let Err(e) = lease.clear() {
            diagnostic = Some(e.message);
        }
        let _ = crate::events::EventStore::new(self.storage.clone()).append(
            "controlled-exit",
            crate::events::EventFields {
                operation: Some(target.as_str().into()),
                pid: Some(owner.pid),
                status: Some("exited".into()),
                code: Some(code.to_string()),
                ..Default::default()
            },
            system.now(),
        );
        Ok(CliOutcome {
            exit_code: code,
            diagnostic,
        })
    }
    /// Configured action for a confirmed risk code. Codes without a config
    /// key keep the historical normal-exit path; a load failure falls back to
    /// the same historical mapping so an unreadable policy neither widens nor
    /// narrows the forced set.
    fn close_action(&self, code: &str) -> String {
        ConfigStore {
            storage: self.storage.clone(),
        }
        .load()
        .map(|config| {
            let severity = |value: &str| match value {
                "force" => 2,
                "close" => 1,
                _ => 0,
            };
            match code {
                "egress_ip_changed" => config.claude_close_ip,
                "egress_country_cn" => config.claude_close_cn,
                "dns_egress_changed" => config.claude_close_dns,
                "webrtc_egress_changed" => config.claude_close_webrtc,
                // Both probe families drifted: apply the stricter of the two
                // configured actions so a wider drift can never be handled
                // more leniently than a single-family drift.
                "dns_and_webrtc_egress_changed" => {
                    if severity(&config.claude_close_dns) >= severity(&config.claude_close_webrtc) {
                        config.claude_close_dns
                    } else {
                        config.claude_close_webrtc
                    }
                }
                _ => "close".to_string(),
            }
        })
        .unwrap_or_else(|_| {
            match code {
                "egress_ip_changed" | "egress_country_cn" => "force",
                _ => "close",
            }
            .to_string()
        })
    }
    fn timed_guard_quit<S: DesktopSystem>(
        &self,
        system: &mut S,
        receipt: &mut Value,
    ) -> Result<()> {
        let started = std::time::Instant::now();
        receipt["stop_started_at"] = json!(system.now());
        let code = receipt["session_guard"]["reason"]["code"]
            .as_str()
            .unwrap_or("");
        // A persistence failure means session state can no longer be tracked,
        // so the bounded force fallback applies regardless of configuration.
        let confirmed_ip = code == "egress_risk_persist_failed" || {
            let action = self.close_action(code);
            receipt["stop_action"] = json!(action);
            action == "force"
        };
        let result = if confirmed_ip {
            let mut forced = None;
            let result = system.quit_for_confirmed_ip_risk(&mut forced);
            receipt["stop_force_requested"] = json!(forced);
            receipt["stop_force_reported"] = json!(forced.is_some());
            result
        } else {
            system.quit_desktop()
        };
        receipt["stop_completed_at"] = json!(system.now());
        receipt["stop_elapsed_seconds"] = json!(started.elapsed().as_secs_f64());
        result
    }
    pub fn guard_tick<S: DesktopSystem>(&self, system: &mut S) -> Result<Value> {
        if !system.launch_target().protected() {
            return Err(CoreError::new(
                "protected_scope_mismatch",
                "观察目标不能进入Claude自动退出保护",
            ));
        }
        let config = match (ConfigStore {
            storage: self.storage.clone(),
        })
        .load()
        {
            Ok(value) => value,
            Err(error) => {
                let mut receipt =
                    json!({"status":"unknown","action":"observe","time":system.now()});
                self.sampling_failure(system, &mut receipt, error)?;
                self.storage.atomic_json(
                    &self.storage.paths.base().join("guard-heartbeat.json"),
                    &receipt,
                )?;
                return Ok(receipt);
            }
        };
        if !config.enabled || !config.guard_enabled {
            return Ok(json!({"status":"disabled","action":"observe"}));
        }
        let sessions = SessionStore::new(self.storage.clone());
        let receipts = ReceiptStore {
            storage: self.storage.clone(),
        };
        let now = system.now();
        let mut receipt = json!({"status":"unknown","action":"observe","time":now,"policy":crate::config_store::policy_digest(&config.value()?)?,"guard_policy_v1":crate::config_store::guard_policy_digest(&config)?});
        let result: Result<()> = (|| {
            let mut desktops = system.desktops()?;
            let mut current = sessions.load(system.now())?;
            let mut identity_unconfirmed = false;
            let mut exit_pending = false;
            if let Some(previous) = current.as_ref().filter(|s| {
                matches!(
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
                                    .as_ref()
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
                            "Claude 关联进程尚未退出且保护风险已确认",
                            true,
                        )?;
                        receipt["session_id"] = json!(ended.session_id);
                        receipt["session_guard"] =
                            serde_json::to_value(&outcome).map_err(|_| {
                                CoreError::new("guard_encoding_failed", "保护状态无法编码")
                            })?;
                        if matches!(outcome.state.as_str(), "risk" | "locked") {
                            match sessions.close_if_current(
                                Some(&ended.session_id),
                                system.now(),
                                || self.timed_guard_quit(system, &mut receipt),
                            ) {
                                Ok(Some(())) => {
                                    receipt["action"] = json!("close-desktop");
                                    receipt["stop_state"] = json!("confirmed");
                                    self.storage.atomic_json(&self.storage.paths.base().join("last-guard-stop.json"), &json!({"stopped_at":system.now(),"session_id":ended.session_id,"reason":outcome.reason,"force_requested":receipt["stop_force_requested"],"force_reported":receipt["stop_force_reported"]}))?;
                                }
                                Ok(None) => receipt["stop_state"] = json!("session_changed"),
                                Err(error) => {
                                    receipt["stop_state"] = json!("failed");
                                    receipt["stop_error"] = json!(error.code);
                                }
                            }
                        }
                    } else {
                        receipt["status"] = json!("unknown");
                        receipt["session_guard"] = json!({"state":"unknown","phase":"ended","reason":{"code":"session_identity_unconfirmed","detail":"旧主进程已退出，仍有 Claude 关联进程待退出"}});
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
                            "存在多个 Claude 主进程，无法完成身份复核"
                        },
                        code.is_some(),
                    )?;
                    receipt["session_id"] = json!(ended.session_id);
                    receipt["session_guard"] = serde_json::to_value(&outcome)
                        .map_err(|_| CoreError::new("guard_encoding_failed", "保护状态无法编码"))?;
                    if matches!(outcome.state.as_str(), "risk" | "locked") {
                        match sessions.close_if_current(
                            Some(&ended.session_id),
                            system.now(),
                            || self.timed_guard_quit(system, &mut receipt),
                        ) {
                            Ok(Some(())) => {
                                receipt["action"] = json!("close-desktop");
                                receipt["stop_state"] = json!("confirmed");
                                self.storage.atomic_json(&self.storage.paths.base().join("last-guard-stop.json"), &json!({"stopped_at":system.now(),"session_id":ended.session_id,"reason":outcome.reason,"force_requested":receipt["stop_force_requested"],"force_reported":receipt["stop_force_reported"]}))?;
                            }
                            Ok(None) => receipt["stop_state"] = json!("session_changed"),
                            Err(error) => {
                                receipt["stop_state"] = json!("failed");
                                receipt["stop_error"] = json!(error.code);
                            }
                        }
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
                        let adopted = system
                            .full_audit()
                            .and_then(|audit| {
                                sessions.begin_verified(&receipts, &audit, &egress, system.now())
                            })
                            .and_then(|pending| {
                                let id = pending.session_id.clone();
                                sessions.bind_desktop(&id, desktop.clone(), system.now())?;
                                sessions.mark_adopted(&id, system.now())?;
                                self.lease(desktop, stamp, system.now())?;
                                Ok(id)
                            });
                        match adopted {
                            Ok(id) => {
                                receipt["status"] = json!("ok");
                                receipt["session_id"] = json!(id);
                                receipt["session_guard"] = json!({
                                    "state": "active",
                                    "phase": "active",
                                    "reason": {"code": "session_adopted", "detail": "手动启动的 Claude 已纳入当前确认出口的监管"}
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
            let latched = {
                let mut remembered = self.failed_persistence_session.lock().map_err(|_| {
                    CoreError::new("guard_memory_unavailable", "保护内存状态不可用")
                })?;
                if remembered.as_ref() != id.as_ref() {
                    *remembered = None;
                }
                remembered.is_some()
            };
            if latched {
                receipt["persistence_error"] = json!("state_io_failed");
                receipt["status"] = json!("protection_triggered");
                receipt["session_id"] = json!(id);
                receipt["session_guard"] = json!({"state":"locked", "phase":"locked", "reason":{"code":"egress_risk_persist_failed", "detail":"出口风险已确认，会话记录写入失败"}});
                if desktops.is_empty() && !identity_unconfirmed && !exit_pending {
                    receipt["stop_state"] = json!("confirmed");
                } else {
                    match sessions.close_if_current(id.as_deref(), system.now(), || {
                        self.timed_guard_quit(system, &mut receipt)
                    }) {
                        Ok(Some(())) => {
                            receipt["action"] = json!("close-desktop");
                            receipt["stop_state"] = json!("confirmed");
                        }
                        Ok(None) => receipt["stop_state"] = json!("session_changed"),
                        Err(error) => {
                            receipt["stop_state"] = json!("failed");
                            receipt["stop_error"] = json!(error.code);
                        }
                    }
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
                // including every round after the session latched to Locked.
                // Codes without a warn tier (notably persistence failures)
                // keep the configured close/force behavior below.
                let code = current
                    .as_ref()
                    .and_then(|s| s.reason.as_ref())
                    .map(|r| r.code.clone())
                    .unwrap_or_default();
                if self.close_action(&code) == "warn" {
                    receipt["session_notice"] = json!({
                        "code": code,
                        "detail": current.as_ref().and_then(|s| s.reason.as_ref()).map(|r| r.detail.clone()),
                        "action": "warn",
                    });
                    receipt["action"] = json!("observe");
                    receipt["stop_state"] = json!("skipped_warn_only");
                    return Ok(());
                }
                match sessions.close_if_current(id.as_deref(), system.now(), || {
                    self.timed_guard_quit(system, &mut receipt)
                }) {
                    Ok(Some(())) => {
                        receipt["action"] = json!("close-desktop");
                        receipt["stop_state"] = json!("confirmed");
                        self.storage.atomic_json(&self.storage.paths.base().join("last-guard-stop.json"), &json!({"stopped_at":system.now(),"session_id":id,"reason":current.as_ref().and_then(|value| value.reason.as_ref()),"force_requested":receipt["stop_force_requested"],"force_reported":receipt["stop_force_reported"]}))?;
                    }
                    Ok(None) => receipt["stop_state"] = json!("session_changed"),
                    Err(error) => {
                        receipt["stop_state"] = json!("failed");
                        receipt["stop_error"] = json!(error.code);
                    }
                }
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
                        if desktops.iter().any(|(d, main, _)| *main && d == expected) {
                            Identity::Matches
                        } else {
                            Identity::Unavailable
                        }
                    } else {
                        Identity::Matches
                    };
                let egress = system.egress();
                let checked_at = system.now();
                let confirmed_exit = current
                    .as_ref()
                    .and_then(|s| {
                        session::Egress::fresh(&egress, checked_at, session::GUARD_EGRESS_TTL).map(
                            |e| {
                                (s.state != session::Phase::Rechecking
                                    || e.observed_at >= s.created_at)
                                    && (e.country == "CN"
                                        || (s.extra.get("recheck_baseline_pending")
                                            != Some(&json!(true))
                                            && e.ip != s.baseline.ip))
                            },
                        )
                    })
                    .unwrap_or(false);
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
                    Err(error) if confirmed_exit && error.code == "state_io_failed" => {
                        receipt["status"] = json!("degraded");
                        receipt["session_id"] = json!(id);
                        receipt["session_guard"] = json!({"state":"risk", "reason":{"code":"egress_risk_persist_failed", "detail":"出口风险已确认，会话记录写入失败"}});
                        receipt["persistence_error"] = json!(error.code);
                        *self.failed_persistence_session.lock().map_err(|_| {
                            CoreError::new("guard_memory_unavailable", "保护内存状态不可用")
                        })? = id.clone();
                        match sessions.close_if_current_before(
                            id.as_deref(),
                            system.now(),
                            checked_at,
                            || self.timed_guard_quit(system, &mut receipt),
                        ) {
                            Ok(Some(())) => {
                                receipt["action"] = json!("close-desktop");
                                receipt["stop_state"] = json!("confirmed");
                            }
                            Ok(None) => {
                                *self.failed_persistence_session.lock().map_err(|_| {
                                    CoreError::new("guard_memory_unavailable", "保护内存状态不可用")
                                })? = None;
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
                // A warn-configured criterion reports but never closes: the
                // session stays active and the next round re-evaluates. The
                // risk round latches the session to Locked, so later rounds
                // arrive as "locked" with the same reason; warn must cover
                // those too, or it would degrade into a delayed close.
                if self.close_action(&code) == "warn" {
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
                match sessions.close_if_current(expected, system.now(), || {
                    self.timed_guard_quit(system, &mut receipt)
                }) {
                    Ok(Some(())) => {
                        receipt["action"] = json!("close-desktop");
                        receipt["stop_state"] = json!("confirmed");
                        self.storage.atomic_json(&self.storage.paths.base().join("last-guard-stop.json"), &json!({"stopped_at":system.now(),"session_id":expected,"reason":outcome.reason,"force_requested":receipt["stop_force_requested"],"force_reported":receipt["stop_force_reported"]}))?;
                    }
                    Ok(None) => receipt["stop_state"] = json!("session_changed"),
                    Err(error) => {
                        receipt["stop_state"] = json!("failed");
                        receipt["stop_error"] = json!(error.code);
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.sampling_failure(system, &mut receipt, error)?;
        }
        self.storage.atomic_json(
            &self.storage.paths.base().join("guard-heartbeat.json"),
            &receipt,
        )?;
        Ok(receipt)
    }
    fn sampling_failure<S: DesktopSystem>(
        &self,
        system: &mut S,
        receipt: &mut Value,
        error: CoreError,
    ) -> Result<()> {
        receipt["code"] = json!(error.code);
        receipt["message"] = json!(error.message);
        receipt["status"] = json!("unknown");
        if !system.desktops().is_ok_and(|d| !d.is_empty()) {
            return Ok(());
        }
        let sessions = SessionStore::new(self.storage.clone());
        let current = match sessions.load(system.now()) {
            Ok(value) => value,
            Err(_) => {
                receipt["session_guard"] = json!({"state":"risk","reason":{"code":"session_state_invalid","detail":"会话记录无法验证，未允许无保护运行"}});
                match sessions
                    .close_if_unreadable(system.now(), || self.timed_guard_quit(system, receipt))
                {
                    Ok(Some(_)) => {
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
        let latched = self
            .failed_persistence_session
            .lock()
            .map_err(|_| CoreError::new("guard_memory_unavailable", "保护内存状态不可用"))?
            .as_ref()
            .is_some_and(|v| Some(v) == id.as_ref());
        if latched {
            receipt["status"] = json!("protection_triggered");
            receipt["persistence_error"] = json!("state_io_failed");
            receipt["session_guard"] = json!({"state":"locked", "phase":"locked", "reason":{"code":"egress_risk_persist_failed", "detail":"出口风险已确认，会话记录写入失败"}});
            match sessions.close_if_current(id.as_deref(), system.now(), || {
                self.timed_guard_quit(system, receipt)
            }) {
                Ok(Some(())) => {
                    receipt["action"] = json!("close-desktop");
                    receipt["stop_state"] = json!("confirmed");
                }
                Ok(None) => receipt["stop_state"] = json!("session_changed"),
                Err(error) => {
                    receipt["stop_error"] = json!(error.code);
                    receipt["stop_state"] = json!("failed");
                }
            }
            return Ok(());
        }
        if let Some(value) = current
            .as_ref()
            .filter(|s| s.state == session::Phase::Locked)
        {
            receipt["status"] = json!("protection_triggered");
            receipt["session_guard"] = session::status(value, system.now(), Some(true));
            match sessions.close_if_current(id.as_deref(), system.now(), || {
                self.timed_guard_quit(system, receipt)
            }) {
                Ok(Some(())) => {
                    receipt["action"] = json!("close-desktop");
                    receipt["stop_state"] = json!("confirmed");
                }
                Ok(None) => receipt["stop_state"] = json!("session_changed"),
                Err(error) => {
                    receipt["stop_error"] = json!(error.code);
                    receipt["stop_state"] = json!("failed");
                }
            }
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
                    match sessions.close_if_current(id.as_deref(), system.now(), || {
                        self.timed_guard_quit(system, receipt)
                    }) {
                        Ok(Some(_)) => {
                            receipt["action"] = json!("close-desktop");
                            receipt["stop_state"] = json!("confirmed");
                        }
                        Err(error) => {
                            receipt["stop_error"] = json!(error.code);
                            receipt["stop_state"] = json!("failed");
                        }
                        _ => {}
                    }
                }
            }
            Err(error) => receipt["sampling_error"] = json!(error.code),
        }
        Ok(())
    }
}
