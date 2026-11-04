//! Controlled launch, observation leases and CLI execution. These effects
//! never belong in the background guard tick: the guard only supervises.
use super::*;
use claude_watch_core::processes::Lease;
use std::fs;

impl Controller {
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
    /// The lease record names the supervised service, parsed back by the
    /// lease store's provider table.
    pub(crate) fn lease(
        &self,
        desktop: &Desktop,
        stamp: &str,
        now: f64,
        provider: Provider,
    ) -> Result<()> {
        if stamp.contains(['|', '\n', '\r']) || stamp.is_empty() {
            return Err(CoreError::new(
                "desktop_identity_unavailable",
                "主进程启动时间未能确认",
            ));
        }
        let name = match provider {
            Provider::Claude => "claude",
            Provider::Codex => "codex",
            Provider::Chatgpt => "chatgpt",
            Provider::Openai => "openai",
        };
        let path = self
            .storage
            .paths
            .watch()
            .join(format!("state/sessions/rust-{}.session", desktop.pid));
        self.storage.atomic_bytes(
            &path,
            format!(
                "desktop|{name}|{}|{}|0|-|{}\n",
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
        // The caller has already bound the supervised target via `select_target`
        // (see runtime.rs) before entering here. A launch must honor that target
        // instead of re-binding to Claude: ChatGPT/Codex route through the
        // observation path below, Claude through the protected session path.
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
        // The audit is the slow stage: it measures the exit, DNS, WebRTC and
        // the service endpoints. Announce it before it starts so the user sees
        // which part of the pre-launch check is running instead of a button
        // that stops answering.
        crate::setup_progress::emit(crate::setup_progress::Phase::CollectEvidence);
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
        crate::setup_progress::emit(crate::setup_progress::Phase::VerifyLaunchConditions);
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
            crate::setup_progress::emit(crate::setup_progress::Phase::BindSession);
            system.open_desktop()?;
            crate::setup_progress::emit(crate::setup_progress::Phase::OpenApplication);
            let deadline = system.monotonic() + Duration::from_secs(10);
            while system.monotonic() < deadline {
                let processes = system.desktops()?;
                let mains: Vec<_> = processes.into_iter().filter(|p| p.1).collect();
                if mains.len() == 1 {
                    let (desktop, _, stamp) = &mains[0];
                    sessions.bind_desktop(&id, desktop.clone(), system.now())?;
                    self.lease(desktop, stamp, system.now(), Provider::Claude)?;
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
        crate::setup_progress::emit(crate::setup_progress::Phase::CollectEvidence);
        let audit = self.observation_audit(system, &owner)?;
        if !system.observation_roots()?.is_empty() {
            return Err(CoreError::new(
                "target_already_running",
                "预检期间目标已由其他入口启动，未补登记观察会话",
            ));
        }
        crate::setup_progress::emit(crate::setup_progress::Phase::VerifyLaunchConditions);
        system.open_desktop()?;
        crate::setup_progress::emit(crate::setup_progress::Phase::OpenApplication);
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
}
