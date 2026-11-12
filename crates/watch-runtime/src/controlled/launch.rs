//! Controlled entry auditing and identity leases. The supervisor owns sessions.
use super::*;
use claude_watch_core::processes::Lease;

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
    pub fn launch<S: DesktopSystem>(&self, system: &mut S) -> Result<Value> {
        if system.launch_target().cli() {
            return Err(CoreError::new("invalid_target_entry", "CLI必须使用带生命周期的共享入口"));
        }
        let _launch = self.storage.lock("launch", None)?;
        self.launch_observation(system)
    }
    fn require_launch_backend<S: DesktopSystem>(system: &mut S) -> Result<()> {
        if !system.backend_healthy()? {
            return Err(CoreError::new(
                "backend_unhealthy",
                "采集后台未有效运行，未启动",
            ));
        }
        Ok(())
    }
    fn observation_audit<S: DesktopSystem>(
        &self,
        system: &mut S,
        owner: &ProcessIdentity,
    ) -> Result<Value> {
        let target = system.launch_target();
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
        // Collection is an independent launch requirement. A missing
        // heartbeat can rule out launch before scanning the full inventory.
        // Keep both target scans and the post-audit backend/owner recheck.
        Self::require_launch_backend(system)?;
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
                "目标已在运行（未受控实例 running_unprotected），不能补登记观察或受控会话",
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
                    "message":"已启动并登记目标进程，联网状态以监管执行回执为准"}),
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
        Self::require_launch_backend(system)?;
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
