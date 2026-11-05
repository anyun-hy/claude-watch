use claude_watch_core::{
    channel::{BoundProcessToken, ChannelMonitorSnapshot, PolicyVersion},
    cli::Request,
    error::{CoreError, Result},
    policy::PolicyCatalog,
    processes::ProcessRole,
};
use claude_watch_runtime::{
    alert_gate::AlertGate,
    channel_enforcer::{
        register_production_enforcer, unregister_production_enforcer, LocalTunnelEnforcer,
    },
    channel_supervisor::{AsyncAuditRequest, ChannelSupervisor, SupervisionEvent},
    config_store::ConfigStore,
    controlled::{Controller, DesktopSystem},
    daemon::{DaemonLease, PROCESS_INTERVAL},
    desktop_native::{DesktopRuntime, NativeDesktop},
    events::{Alert, EventFields, EventStore, Severity},
    macos::Authority,
    native::{self, Observer},
    native_notifications::{AlertDispatcher, NativeNotifier},
    sampler::{pinned_node, Sampler},
    snapshot_publication::SnapshotPublisher,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Receiver,
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

pub struct ProductionChannelStack {
    pub enforcer: Arc<LocalTunnelEnforcer>,
    pub supervisor: ChannelSupervisor,
    pub event_rx: Receiver<SupervisionEvent>,
    pub lease_watchdog: thread::JoinHandle<()>,
    pub async_audit_worker: thread::JoinHandle<()>,
    pub last_policy_version: Option<PolicyVersion>,
}

pub fn assemble_production_channel_stack<F>(
    storage: StateStore,
    stop: Arc<AtomicBool>,
    activate_local_interception: bool,
    run_audit: F,
) -> Result<ProductionChannelStack>
where
    F: FnMut(&AsyncAuditRequest) -> Result<(Value, Value, f64)> + Send + 'static,
{
    let boot_id = format!(
        "daemon-{}-{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let enforcer = Arc::new(LocalTunnelEnforcer::new(boot_id, Some(storage.clone())));
    if activate_local_interception {
        let now_ts = native::now();
        // Production: starts local proxy listener, keeping system_extension_active as false
        // until verified system extension activation is confirmed by the host manager.
        if let Err(e) = enforcer.start_local_proxy_listener("127.0.0.1:0", stop.clone(), now_ts) {
            let _ = enforcer.record_activation_failure(&e.code, now_ts);
        }
    }
    let _ = storage.atomic_json(
        &storage
            .paths
            .watch()
            .join("state/channel-protocol-coverage.json"),
        &enforcer.protocol_coverage_boundaries(),
    );
    register_production_enforcer(&storage.paths.watch(), enforcer.clone());

    let (event_tx, event_rx) = std::sync::mpsc::channel();

    // Wire receipt sink: Active and closed flows immediately emit events to supervisor
    let sink_tx = event_tx.clone();
    let _ = enforcer.set_receipt_event_sink(move |receipt| {
        let received_at = native::now();
        let _ = sink_tx.send(SupervisionEvent::EnforcementReceiptArrived {
            receipt,
            received_at,
        });
    });

    let lease_tx = event_tx.clone();
    let lease_watchdog = enforcer.spawn_lease_watchdog(
        stop.clone(),
        Duration::from_millis(250),
        native::now,
        move |expired_receipts| {
            let received_at = native::now();
            for receipt in expired_receipts {
                let _ = lease_tx.send(SupervisionEvent::EnforcementReceiptArrived {
                    receipt,
                    received_at,
                });
            }
        },
    )?;

    let (audit_req_tx, async_audit_worker) =
        ChannelSupervisor::spawn_async_audit_worker(stop, event_tx, run_audit)?;

    let supervisor = ChannelSupervisor::new(
        storage,
        Some(enforcer.clone()),
        Some(audit_req_tx),
    )?;

    Ok(ProductionChannelStack {
        enforcer,
        supervisor,
        event_rx,
        lease_watchdog,
        async_audit_worker,
        last_policy_version: None,
    })
}

impl ProductionChannelStack {
    pub fn drain_background_events(&mut self) -> Result<()> {
        while let Ok(ev) = self.event_rx.try_recv() {
            self.supervisor.handle_event(ev)?;
        }
        Ok(())
    }

    pub fn step_with_system<S: DesktopSystem>(
        &mut self,
        system: &mut S,
    ) -> Result<ChannelMonitorSnapshot> {
        self.drain_background_events()?;
        let now = system.now();
        if let Ok(cfg) = (ConfigStore {
            storage: self.supervisor.storage.clone(),
        })
        .load()
        {
            if let Ok(ver) = ChannelSupervisor::compute_policy_version(&cfg) {
                if self.last_policy_version.as_ref() != Some(&ver) {
                    self.last_policy_version = Some(ver);
                    self.supervisor.handle_event(SupervisionEvent::PolicyUpdated {
                        config: cfg,
                        observed_at: now,
                    })?;
                }
            }
        }
        let egress = system.egress();
        let local_guard = system
            .local_guard()
            .unwrap_or_else(|_| json!({"proxy": "unknown", "tun": "unknown"}));
        self.supervisor
            .handle_event(SupervisionEvent::EnvironmentUpdated {
                egress,
                local_guard,
                observed_at: now,
            })?;

        for family in PolicyCatalog::families() {
            if PolicyCatalog::guard_target(family).is_none() {
                continue;
            }
            if system.set_family(family.id).is_ok() {
                let desktops = system.desktops().unwrap_or_default();
                let processes = system.supervised_processes().unwrap_or_else(|_| {
                    desktops
                        .iter()
                        .map(|(d, main, _)| {
                            let role = if *main {
                                ProcessRole::DesktopMain
                            } else {
                                ProcessRole::DesktopHelper
                            };
                            BoundProcessToken::with_system_identity(
                                d.pid,
                                501,
                                d.start_seconds,
                                d.start_microseconds,
                                role,
                            )
                        })
                        .collect()
                });
                self.supervisor
                    .handle_event(SupervisionEvent::ProcessInventoryUpdated {
                        family: family.id.to_string(),
                        desktops,
                        processes,
                        observed_at: system.now(),
                    })?;
            }
        }
        self.drain_background_events()?;
        Ok(self.supervisor.snapshot(system.now()))
    }

    pub fn wait_or_drain(&mut self, deadline: Instant, stop: &AtomicBool) {
        while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
            let wait_for = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100));
            match self.event_rx.recv_timeout(wait_for) {
                Ok(ev) => {
                    let _ = self.supervisor.handle_event(ev);
                    let _ = self.drain_background_events();
                    break;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    thread::sleep(wait_for);
                }
            }
        }
    }

    pub fn shutdown(self) {
        unregister_production_enforcer(&self.supervisor.storage.paths.watch());
        let _ = self.lease_watchdog.join();
        let _ = self.async_audit_worker.join();
    }
}

/// `PROCESS_INTERVAL` rounds of continuous degradation before the user is
/// interrupted (15 × 2 s ≈ 30 s).
const SUSTAINED_SAMPLING_ROUNDS: u32 = 15;
/// While an outage continues, remind at most once per half hour.
const SAMPLING_QUIET: Duration = Duration::from_secs(30 * 60);
/// Stable identity of a non-empty evidence set.
///
/// `None` means "nothing to report". Two equal signatures describe the same
/// standing fact, so the owner reports it once instead of once per sampling
/// round.
fn evidence_signature(rows: &Value) -> Option<String> {
    let rows = rows.as_array()?;
    if rows.is_empty() {
        return None;
    }
    Some(Value::Array(rows.clone()).to_string())
}

fn sleep_until(deadline: Instant, stop: &AtomicBool) {
    while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
        thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100)),
        );
    }
}

// An online baseline can take much longer than a guard heartbeat interval.
// Collect it independently so login/reboot cannot stall the guard worker.
fn spawn_baseline<F>(stop: Arc<AtomicBool>, mut collect: F) -> Result<thread::JoinHandle<()>>
where
    F: FnMut() -> Result<bool> + Send + 'static,
{
    thread::Builder::new()
        .name("claude-environment-baseline".into())
        .spawn(move || {
            for _ in 0..3 {
                if stop.load(Ordering::Acquire) || collect().is_ok() {
                    break;
                }
            }
        })
        .map_err(|_| CoreError::new("baseline_start_failed", "后台环境采样线程无法启动"))
}
pub fn run(request: &Request, paths: Paths) -> Result<Value> {
    request.require_apply()?;
    let runner = super::runtime::runner()?;
    let inventory = Observer {
        runner: runner.as_ref(),
    }
    .inventory()?;
    let producer = inventory
        .processes
        .get(&std::process::id())
        .ok_or_else(|| CoreError::new("daemon_identity_unavailable", "后台自身身份不可读取"))?
        .identity
        .clone();
    let identities = inventory
        .processes
        .into_iter()
        .map(|(pid, p)| (pid, p.identity))
        .collect();
    let storage = StateStore::new(paths.clone());
    let owner = DaemonLease::acquire(storage.clone(), producer.clone(), &identities)?;
    let mut publisher = SnapshotPublisher::new(
        storage.clone(),
        Sampler::new(runner.clone(), paths.clone()),
        producer,
    )?;
    let stop = Arc::new(AtomicBool::new(false));
    let _shutdown_signals = claude_watch_runtime::daemon::shutdown_signals(stop.clone())?;
    let alerts = if request.flag("observe-only") {
        None
    } else {
        Some(Arc::new(AlertDispatcher::new(
            storage.clone(),
            Arc::new(NativeNotifier::system()),
        )))
    };
    let diagnostic_queue = super::diagnostic_queue::DiagnosticQueue::new(storage.clone());
    let events = EventStore::new(storage.clone());
    events.append(
        "daemon-start",
        EventFields {
            operation: Some("native-daemon".into()),
            pid: Some(std::process::id()),
            version: Some(claude_watch_runtime::monitor_snapshot::VERSION.into()),
            ..Default::default()
        },
        native::now(),
    )?;
    let baseline = if request.flag("observe-only") {
        None
    } else {
        let paths = paths.clone();
        let store = storage.clone();
        let mut runtime = None;
        Some(spawn_baseline(stop.clone(), move || {
            // Construct the adapter once inside this independent worker. A
            // failed observation must never terminate the guard worker.
            if runtime.is_none() {
                let host = super::runtime::host(paths.clone(), Authority::ExplicitPermit)?;
                let desktop = NativeDesktop::new(
                    host.runner.clone(),
                    super::runtime::process_component()?,
                    Authority::ExplicitPermit,
                )?;
                runtime = Some((host, desktop));
            }
            let (host, desktop) = runtime.as_mut().unwrap();
            let network = host.network.clone();
            DesktopRuntime {
                desktop,
                system: host,
                network,
                storage: store.clone(),
                started: Instant::now(),
                cli: None,
            }
            .ensure_baseline_audit()
        })?)
    };
    let guard = if request.flag("observe-only") {
        None
    } else {
        let guard_diagnostics = diagnostic_queue.clone();
        let mut host = super::runtime::host(paths.clone(), Authority::ExplicitPermit)?;
        let mut desktop = NativeDesktop::new(
            host.runner.clone(),
            super::runtime::process_component()?,
            Authority::ExplicitPermit,
        )?;
        let store = storage.clone();
        let stop = stop.clone();
        let guard_alerts = alerts.clone();
        let audit_paths = paths.clone();
        Some(
            thread::Builder::new()
                .name("claude-session-guard".into())
                .spawn(move || -> Result<()> {
                    let audit_store_state = store.clone();
                    let mut channel_stack = assemble_production_channel_stack(
                        store.clone(),
                        stop.clone(),
                        true,
                        move |req| {
                            let mut audit_host = super::runtime::host(
                                audit_paths.clone(),
                                Authority::ExplicitPermit,
                            )?;
                            let target = PolicyCatalog::family(&req.family)
                                .and_then(PolicyCatalog::guard_target)
                                .unwrap_or(
                                    claude_watch_core::processes::LaunchTarget::ClaudeDesktop,
                                );
                            let audit = claude_watch_runtime::audit_store::AuditStore::new(
                                audit_store_state.clone(),
                            )
                            .collect_target(
                                &mut audit_host,
                                &claude_watch_runtime::region_catalog::load_system_catalog(),
                                target,
                                claude_watch_runtime::audit_store::AuditOptions {
                                    online: true,
                                    persist: true,
                                    launch: true,
                                },
                            )?;
                            let egress = audit_host
                                .network
                                .fast_egress()
                                .data
                                .unwrap_or_else(|| {
                                    json!({"state":"unknown","observed_at":native::now()})
                                });
                            Ok((audit, egress, native::now()))
                        },
                    )?;
                    let controller = Controller::new(store.clone());
                    let network = host.network.clone();
                    let mut runtime = DesktopRuntime {
                        desktop: &mut desktop,
                        system: &mut host,
                        network,
                        storage: store,
                        started: Instant::now(),
                        cli: None,
                    };
                    // `guard_tick` answers `unknown` whenever the process
                    // inventory cannot be fully confirmed, which on macOS is
                    // ordinary churn: a PID disappears between `proc_listpids`
                    // and the identity sysctl, or the scan hits its deadline.
                    // Paging on the very first such round is what makes the
                    // "保护采样异常" dialog reappear after every dismissal, so
                    // it gets the same sustained-streak gate as the sampling
                    // alerts instead of firing immediately.
                    let mut guard_history = super::diagnostic_queue::GuardHistory::default();
                    let mut unknown_gate =
                        AlertGate::new(SUSTAINED_SAMPLING_ROUNDS, SAMPLING_QUIET);
                    let loop_result: Result<()> = (|| {
                        while !stop.load(Ordering::Acquire) {
                            let started = Instant::now();
                            let _ = channel_stack.step_with_system(&mut runtime);
                            let receipt = controller.guard_tick(&mut runtime)?;
                            guard_history.observe(&guard_diagnostics, &receipt, native::now());
                            if let Some(alerts) = &guard_alerts {
                                if matches!(
                                    receipt["action"].as_str(),
                                    Some("close-desktop" | "disconnect-channel")
                                ) {
                                    unknown_gate.observe(false);
                                    alerts.enqueue(Alert {
                                        title: "Claude Watch：已触发保护".into(),
                                        message: "检测到会话风险并已按配置处置受监督的应用。请查看具体检测结果；重新启动仍会执行完整校验。".into(),
                                        severity: Severity::Warning,
                                    });
                                } else if unknown_gate.observe(receipt["status"] == "unknown") {
                                    alerts.enqueue(Alert {
                                        title: "Claude Watch：保护采样异常".into(),
                                        message: "本轮保护证据未能完整取得，后台正在重试。详情见环境状态；这不等于已检测到网络泄漏。".into(),
                                        severity: Severity::Critical,
                                    });
                                }
                            }
                            channel_stack.wait_or_drain(started + PROCESS_INTERVAL, &stop);
                        }
                        Ok(())
                    })();
                    channel_stack.shutdown();
                    loop_result
                })
                .map_err(|_| CoreError::new("guard_start_failed", "后台保护工作线程无法启动"))?,
        )
    };
    let evidence = if request.flag("observe-only") {
        None
    } else {
        match super::evidence_run::spawn(paths, stop.clone()) {
            Ok(worker) => Some(worker),
            Err(error) => {
                stop.store(true, Ordering::Release);
                if let Some(guard) = guard {
                    let _ = guard.join();
                }
                return Err(error);
            }
        }
    };
    let mut sampling_history = super::diagnostic_queue::SamplingHistory::default();
    let mut sampling_gate = AlertGate::new(SUSTAINED_SAMPLING_ROUNDS, SAMPLING_QUIET);
    // Last reported sensitive-file evidence set.
    let mut reported_files: Option<String> = None;
    let outcome = (|| {
        let mut rounds = 0u64;
        loop {
            if stop.load(Ordering::Acquire) {
                return Ok(json!({"status":"stopped","rounds":rounds}));
            }
            if evidence.as_ref().is_some_and(|worker| worker.is_finished()) {
                return Err(CoreError::new(
                    "evidence_worker_failed",
                    "保护证据线程异常退出，等待后台重新启动",
                ));
            }
            if guard.as_ref().is_some_and(|g| g.is_finished()) {
                return Err(CoreError::new(
                    "guard_worker_failed",
                    "保护循环已退出，后台停止发布正常心跳",
                ));
            }
            let started = Instant::now();
            let config = ConfigStore {
                storage: storage.clone(),
            }
            .load()?;
            runner.publish_listeners(&storage)?;
            if runner.listener_channel_finished() {
                // EOF may arrive immediately after a successful publication.
                // Publish the terminal error before exiting, never leave that
                // preceding listener sample presented as the current source.
                runner.publish_listeners(&storage)?;
                return Err(CoreError::new(
                    "native_listener_worker_failed",
                    "系统采样通道已结束；后台停止发布，等待已注册任务重新启动",
                ));
            }
            let pin = pinned_node(&storage.paths, &config.proxy_group);
            let sample = publisher.poll(&config.proxy_group, &pin, false);
            let mut log_error = diagnostic_queue.health_message();
            if let Some(count) = alerts.as_ref().map(|a| a.record_failures()).filter(|n| *n > 0) {
                let note = format!("本次后台运行的通知事件记录或冷却写入失败 {count} 次。");
                log_error = Some(log_error.map(|existing| format!("{existing}；{note}")).unwrap_or(note));
            }
            let snapshot = owner.publish_with_log_health(sample, native::now(), log_error.as_deref())?;
            sampling_history.observe(&diagnostic_queue, &snapshot, native::now());
            if let Some(alerts) = &alerts {
                // `quality` is a per-round verdict: one missing `lsof` sample
                // or an empty traffic counter flips it to "degraded" and the
                // next round usually restores it. Alerting on the first bad
                // round turned the watchdog into a recurring pop-up, because
                // the queue only suppresses an alert that is still pending or
                // on screen — dismissing one let the next round raise it
                // again. Require a sustained streak, then one reminder per
                // quiet period. The control panel keeps showing live state.
                if sampling_gate.observe(snapshot["health"]["state"] != "running") {
                    alerts.enqueue(Alert {
                        title: "Claude Watch：监控采样异常".into(),
                        message:
                            "本轮进程或连接观察未完成，采样仍会继续。请查看事件记录中的具体来源。"
                                .into(),
                        severity: Severity::Critical,
                    });
                }
                // Report each distinct sensitive-file evidence set once;
                // service-name candidates remain in the event log only.
                let files_signature = evidence_signature(&snapshot["activity"]["files"]["rows"]);
                if files_signature.is_some() && files_signature != reported_files {
                    alerts.enqueue(Alert{title:"Claude Watch：敏感目录文件描述符".into(),message:"未关联会话的进程持有敏感目录文件描述符；这不是完整的文件读取记录。详情见事件记录。".into(),severity:Severity::Warning});
                }
                reported_files = files_signature;
            }
            rounds = rounds.saturating_add(1);
            if request.flag("once") {
                return Ok(
                    json!({"status":"ok","rounds":rounds,"protection":if request.flag("observe-only"){"observation_only"}else{"enabled"},"snapshot":snapshot}),
                );
            }
            sleep_until(started + PROCESS_INTERVAL, &stop);
        }
    })();
    stop.store(true, Ordering::Release);
    let _ = events.append(
        "daemon-stop",
        EventFields {
            operation: Some("native-daemon".into()),
            status: Some(if outcome.is_err() { "error" } else { "stopped" }.into()),
            code: outcome.as_ref().err().map(|error| {
                match error.code.as_str() {
                    "native_listener_worker_failed" => "native_listener_worker_failed",
                    _ => "backend_error",
                }
                .into()
            }),
            ..Default::default()
        },
        native::now(),
    );
    let guard_result = if let Some(guard) = guard {
        match guard.join() {
            Ok(result) => result,
            Err(_) => Err(CoreError::new("guard_worker_failed", "保护循环异常退出")),
        }
    } else {
        Ok(())
    };
    // Always finish helper cancellation, even if the guard worker failed.
    if let Some(evidence) = evidence {
        let _ = evidence.join();
    }
    if let Some(baseline) = baseline {
        // A display-only HTTPS baseline has bounded requests but cannot be
        // interrupted mid-request. It must not delay launchd stop/replacement.
        if baseline.is_finished() {
            let _ = baseline.join();
        }
    }
    guard_result?;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_baseline_does_not_block_other_guard_work() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let worker = spawn_baseline(stop, move || {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            Ok(true)
        })
        .unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let guard_work = thread::spawn(|| "guard tick");
        assert_eq!(guard_work.join().unwrap(), "guard tick");
        release_tx.send(()).unwrap();
        worker.join().unwrap();
    }

    /// No evidence means nothing to report — not an empty alert.
    #[test]
    fn an_empty_evidence_set_is_not_reported() {
        assert!(evidence_signature(&json!([])).is_none());
    }

    #[test]
    fn an_unreadable_evidence_set_is_not_reported() {
        assert!(evidence_signature(&Value::Null).is_none());
        assert!(evidence_signature(&json!({"state": "unavailable"})).is_none());
    }

    /// A standing fact must produce one alert, not one per sampling round:
    /// identical rows have to compare equal so the caller can skip repeats.
    #[test]
    fn the_same_rows_yield_the_same_signature() {
        let first = json!([{"pid": 7, "label": "com.example.helper", "ownership": "unconfirmed"}]);
        let again = json!([{"pid": 7, "label": "com.example.helper", "ownership": "unconfirmed"}]);
        assert_eq!(evidence_signature(&first), evidence_signature(&again));
    }

    /// A new process appearing is a new fact and must be reported again.
    #[test]
    fn a_changed_row_set_yields_a_new_signature() {
        let before = json!([{"pid": 7, "label": "com.example.helper", "ownership": "unconfirmed"}]);
        let after = json!([
            {"pid": 7, "label": "com.example.helper", "ownership": "unconfirmed"},
            {"pid": 9, "label": "com.example.other", "ownership": "unconfirmed"}
        ]);
        assert_ne!(evidence_signature(&before), evidence_signature(&after));
    }

    #[test]
    fn production_daemon_channel_stack_wires_enforcer_supervisor_async_audit_and_lease_watchdog() {
        use claude_watch_core::{
            channel::{ChannelMonitorDisplayState, ChannelPermitState},
            config::Config,
            processes::LaunchTarget,
            session::{Desktop, Launcher},
        };
        use claude_watch_runtime::channel_enforcer::{registered_production_enforcer, ChannelEnforcer};

        struct DaemonFixtureSystem {
            family: &'static str,
            now: f64,
            country: &'static str,
        }
        impl DesktopSystem for DaemonFixtureSystem {
            fn launch_target(&self) -> LaunchTarget {
                if self.family == "openai" {
                    LaunchTarget::CodexDesktop
                } else {
                    LaunchTarget::ClaudeDesktop
                }
            }
            fn set_family(&mut self, family_id: &str) -> Result<()> {
                self.family = if family_id == "openai" { "openai" } else { "claude" };
                Ok(())
            }
            fn now(&self) -> f64 {
                self.now
            }
            fn monotonic(&self) -> Duration {
                Duration::from_secs(1)
            }
            fn wait(&mut self, _: Duration) {}
            fn desktops(&mut self) -> Result<Vec<(Desktop, bool, String)>> {
                if self.family == "claude" {
                    Ok(vec![(
                        Desktop {
                            pid: 4100,
                            start_seconds: 900,
                            start_microseconds: 1,
                        },
                        true,
                        "u501:900:1".into(),
                    )])
                } else {
                    Ok(vec![])
                }
            }
            fn desktop_alive(&mut self, _: &Desktop) -> Result<bool> {
                Ok(true)
            }
            fn desktop_tree_running(&mut self) -> Result<bool> {
                Ok(self.family == "claude")
            }
            fn launcher(&mut self) -> Result<Launcher> {
                Ok(Launcher {
                    pid: 1,
                    start: "init".into(),
                })
            }
            fn full_audit(&mut self) -> Result<Value> {
                panic!("guard loop must not call synchronous full_audit when async worker is active")
            }
            fn egress(&mut self) -> Value {
                json!({
                    "ip": if self.country == "CN" { "223.5.5.5" } else { "1.1.1.1" },
                    "country": self.country,
                    "observed_at": self.now,
                    "source": "fixture"
                })
            }
            fn local_guard(&mut self) -> Result<Value> {
                Ok(json!({
                    "context": "ctx",
                    "context_id": "ctx",
                    "proxy": "ok",
                    "tun": "ok",
                    "guard_backend_healthy": true,
                    "observation_unavailable": []
                }))
            }
            fn backend_healthy(&mut self) -> Result<bool> {
                Ok(true)
            }
            fn launcher_matches(&mut self, _: &Launcher) -> Result<bool> {
                Ok(true)
            }
            fn open_desktop(&mut self) -> Result<()> {
                Ok(())
            }
            fn quit_desktop(&mut self) -> Result<()> {
                panic!("channel mode must preserve process and never call quit_desktop")
            }
            fn quit_for_confirmed_ip_risk(&mut self, _: &mut Option<u32>) -> Result<()> {
                panic!("channel mode must preserve process and never call quit_for_confirmed_ip_risk")
            }
        }

        let short_id = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let root = std::path::PathBuf::from("/tmp").join(format!("cwdm-{short_id}"));
        std::fs::create_dir_all(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        let mut cfg = Config::default();
        cfg.enabled = true;
        cfg.guard_enabled = true;
        store
            .atomic_json(&store.paths.config(), &cfg.value().unwrap())
            .unwrap();

        let now = native::now();
        let stop = Arc::new(AtomicBool::new(false));
        let (release_audit_tx, release_audit_rx) = std::sync::mpsc::channel();
        let mut stack = assemble_production_channel_stack(
            store.clone(),
            stop.clone(),
            true,
            move |req| {
                let _ = release_audit_rx.recv_timeout(Duration::from_secs(2));
                Ok((
                    json!({
                        "ready": true,
                        "observed_at": req.requested_at + 0.1,
                        "expires_at": req.requested_at + 30.1,
                        "context_id": "ctx",
                        "observation_id": "fixture",
                        "context_transition": {"state": "stable"},
                        "policy": req.policy_version.policy_digest,
                        "egress_reference": {
                            "ip": "1.1.1.1",
                            "country": "JP",
                            "checked_at": req.requested_at + 0.1,
                            "context": "ctx",
                            "source": "fixture"
                        }
                    }),
                    json!({
                        "ip": "1.1.1.1",
                        "country": "JP",
                        "observed_at": req.requested_at + 0.1,
                        "source": "fixture"
                    }),
                    req.requested_at + 0.1,
                ))
            },
        )
        .unwrap();

        // The enforcer requires both local proxy and system extension to be active.
        // Local proxy is ready, but system extension is not yet confirmed -> not ready!
        assert!(!stack.enforcer.is_ready().unwrap());
        stack.enforcer.set_system_extension_active(true, None, now).unwrap();
        assert!(stack.enforcer.is_ready().unwrap());
        assert!(registered_production_enforcer(&store.paths.watch()).is_some());

        let mut sys = DaemonFixtureSystem {
            family: "claude",
            now,
            country: "JP",
        };
        // Step 1: Running Claude without a session schedules async audit on the worker
        let snap1 = stack.step_with_system(&mut sys).unwrap();
        assert_eq!(
            snap1.families["claude"].permit_state,
            ChannelPermitState::PendingVerification
        );

        // Wait for async audit completion via `wait_or_drain`
        let _ = release_audit_tx.send(());
        stack.wait_or_drain(Instant::now() + Duration::from_secs(2), &stop);
        sys.now += 0.2;
        let snap2 = stack.step_with_system(&mut sys).unwrap();
        assert_eq!(
            snap2.families["claude"].permit_state,
            ChannelPermitState::Permitted
        );
        assert_eq!(
            snap2.families["claude"].display_state,
            ChannelMonitorDisplayState::Forwarding
        );

        // Step 2: Trigger CN exit risk -> cuts off channel while preserving process
        sys.now += 1.0;
        sys.country = "CN";
        let snap3 = stack.step_with_system(&mut sys).unwrap();
        assert_eq!(
            snap3.families["claude"].permit_state,
            ChannelPermitState::Revoked
        );
        assert_eq!(
            snap3.families["claude"].display_state,
            ChannelMonitorDisplayState::Blocked
        );
        assert!(snap3.families["claude"].process_preserved);

        stop.store(true, Ordering::Release);
        stack.shutdown();
        assert!(registered_production_enforcer(&store.paths.watch()).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }
}
