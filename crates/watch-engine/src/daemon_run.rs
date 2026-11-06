use claude_watch_core::{
    channel::{ChannelMonitorSnapshot, PolicyVersion},
    cli::Request,
    error::{CoreError, Result},
    policy::PolicyCatalog,
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
    stop: Arc<AtomicBool>,
    pub enforcer: Arc<LocalTunnelEnforcer>,
    pub supervisor: ChannelSupervisor,
    pub event_rx: Receiver<SupervisionEvent>,
    pub lease_watchdog: thread::JoinHandle<()>,
    pub async_audit_worker: thread::JoinHandle<()>,
    pub extension_watcher: Option<thread::JoinHandle<()>>,
    pub last_policy_version: Option<PolicyVersion>,
}

pub fn assemble_production_channel_stack<F>(
    storage: StateStore,
    stop: Arc<AtomicBool>,
    activate_local_interception: bool,
    run_audit: F,
) -> Result<ProductionChannelStack>
where
    F: Fn(&AsyncAuditRequest) -> Result<(Value, Value, f64)> + Send + Sync + 'static,
{
    let boot_id = format!(
        "daemon-{}-{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let enforcer = Arc::new(LocalTunnelEnforcer::new(boot_id, Some(storage.clone())));
    enforcer.set_strict_peer_verification(activate_local_interception);
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

    if activate_local_interception {
        enforcer.start_extension_gateway(stop.clone())?;
    }
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

    let extension_watcher = if activate_local_interception {
        let enforcer = enforcer.clone();
        let stop = stop.clone();
        Some(thread::Builder::new().name("channel-extension-observations".into()).spawn(move || {
            let mut notification = claude_watch_runtime::channel_extension::ObservationSignal::new();
            while !stop.load(Ordering::Acquire) {
                let _ = enforcer.refresh_system_extension(native::now());
                notification.wait(Duration::from_millis(250));
            }
        }).map_err(|_| CoreError::new("extension_observer_failed", "扩展回执订阅线程启动失败"))?)
    } else { None };

    let (audit_req_tx, async_audit_worker) =
        ChannelSupervisor::spawn_async_audit_worker(stop.clone(), event_tx, run_audit)?;

    let supervisor = ChannelSupervisor::new(
        storage,
        Some(enforcer.clone()),
        Some(audit_req_tx),
    )?;

    Ok(ProductionChannelStack {
        stop,
        enforcer,
        supervisor,
        event_rx,
        lease_watchdog,
        async_audit_worker,
        extension_watcher,
        last_policy_version: None,
    })
}

impl ProductionChannelStack {
    pub fn drain_background_events(&mut self) -> Result<()> {
        while let Ok(ev) = self.event_rx.try_recv() {
            let event = match ev {
                SupervisionEvent::EnforcementReceiptArrived { receipt, .. } =>
                    SupervisionEvent::EnforcementReceiptArrived { receipt, received_at: native::now() },
                other => other,
            };
            self.supervisor.handle_event(event)?;
        }
        Ok(())
    }

    pub fn step_with_system<S: DesktopSystem>(
        &mut self,
        system: &mut S,
    ) -> Result<ChannelMonitorSnapshot> {
        self.drain_background_events()?;
        let now = system.now();

        self.enforcer.refresh_system_extension(now)?;

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
                observed_at: system.now(),
            })?;

        for family in PolicyCatalog::families() {
            if PolicyCatalog::guard_target(family).is_none() {
                continue;
            }
            if system.set_family(family.id).is_ok() {
                let (desktops, processes) = match (system.desktops(), system.supervised_processes()) {
                    (Ok(desktops), Ok(processes)) => (desktops, processes),
                    _ => {
                        self.supervisor.handle_event(SupervisionEvent::ProcessInventoryUnavailable {
                            family: family.id.to_string(), observed_at: system.now(),
                        })?;
                        continue;
                    }
                };
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
        let snapshot = self.supervisor.snapshot(system.now());

        Ok(snapshot)
    }

    pub fn wait_or_drain(&mut self, deadline: Instant, stop: &AtomicBool) {
        while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
            let wait_for = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100));
            match self.event_rx.recv_timeout(wait_for) {
                Ok(ev) => {
                    let event = match ev {
                        SupervisionEvent::EnforcementReceiptArrived { receipt, .. } =>
                            SupervisionEvent::EnforcementReceiptArrived { receipt, received_at: native::now() },
                        other => other,
                    };
                    let _ = self.supervisor.handle_event(event);
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
        // The guard loop can leave on error while the daemon is still alive.
        // Signal the owned workers before joining; callers need not do it first.
        self.stop.store(true, Ordering::Release);
        unregister_production_enforcer(&self.supervisor.storage.paths.watch());
        let _ = self.lease_watchdog.join();
        let _ = self.async_audit_worker.join();
        if let Some(worker) = self.extension_watcher { let _ = worker.join(); }
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
                    let mut channel_stack = assemble_production_channel_stack(
                        store.clone(),
                        stop.clone(),
                        true,
                        move |req| {
                            let enforcer = claude_watch_runtime::channel_enforcer::registered_production_enforcer(&audit_paths.watch())
                                .ok_or_else(|| CoreError::new("controlled_channel_missing", "受控诊断执行器不可用，保持待验证"))?;
                            super::channel_audit::run(&audit_paths, &enforcer, req)
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
                            if let Err(error) = channel_stack.step_with_system(&mut runtime) {
                                channel_stack.enforcer.record_activation_failure(&error.code, native::now())?;
                            }
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
            channel::{BoundProcessToken, ChannelMonitorDisplayState, ChannelPermitState},
            config::Config,
            processes::{LaunchTarget, ProcessRole},
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
            fn supervised_processes(&mut self) -> Result<Vec<BoundProcessToken>> {
                // Explicit fixture identities avoid querying real host PIDs/UIDs.
                Ok(self
                    .desktops()?
                    .into_iter()
                    .map(|(desktop, main, _)| {
                        BoundProcessToken::with_system_identity(
                            desktop.pid,
                            501,
                            desktop.start_seconds,
                            desktop.start_microseconds,
                            if main {
                                ProcessRole::DesktopMain
                            } else {
                                ProcessRole::DesktopHelper
                            },
                        )
                        .with_audit_token([501, 501, 20, 501, 20, desktop.pid, 0, 9])
                    })
                    .collect())
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
                let mut dummy_config = claude_watch_core::config::Config::default();
                dummy_config.enabled = true;
                dummy_config.guard_enabled = true;
                let policy_ver = ChannelSupervisor::compute_policy_version(&dummy_config).unwrap();
                json!({
                    "ip": if self.country == "CN" { "223.5.5.5" } else { "1.1.1.1" },
                    "country": self.country,
                    "observed_at": self.now,
                    "source": "fixture",
                    "family": "*",
                    "upstream_endpoint": "127.0.0.1:7890",
                    "policy_version": policy_ver,
                    "context_id": "ctx",
                    "via_controlled_path": true
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
        let release_audit_rx = Arc::new(std::sync::Mutex::new(release_audit_rx));
        let rx = Arc::clone(&release_audit_rx);
        let mut stack = assemble_production_channel_stack(
            store.clone(),
            stop.clone(),
            false,
            move |req| {
                rx.lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|_| {
                        CoreError::new("fixture_audit_barrier_timeout", "审计测试未收到释放信号")
                    })?;
                let completed_at = native::now();
                Ok((
                    json!({
                        "ready": true,
                        "observed_at": completed_at,
                        "expires_at": completed_at + 30.0,
                        "context_id": "ctx",
                        "observation_id": "fixture",
                        "context_transition": {"state": "stable"},
                        "policy": req.policy_version.policy_digest,
                        "egress_reference": {
                            "ip": "1.1.1.1",
                            "country": "JP",
                            "checked_at": completed_at,
                            "context": "ctx",
                            "source": "fixture"
                        }
                    }),
                    json!({
                        "ip": "1.1.1.1",
                        "country": "JP",
                        "observed_at": completed_at,
                        "source": "fixture",
                        "family": "claude",
                        "upstream_endpoint": "127.0.0.1:7890",
                        "policy_version": req.policy_version,
                        "context_id": "ctx",
                        "via_controlled_path": true
                    }),
                    completed_at,
                ))
            },
        )
        .unwrap();

        // Isolated orchestration fixture: inject kernel observations separately
        // from the production authenticated observation tests.
        stack.enforcer.start_local_proxy_listener("127.0.0.1:0", stop.clone(), now).unwrap();
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
        assert!(sys
            .supervised_processes()
            .unwrap()
            .iter()
            .all(|p| p.has_verified_audit_token()));
        // Step 1: Running Claude without a session schedules async audit on the worker
        sys.now = native::now();
        let snap1 = stack.step_with_system(&mut sys).unwrap();
        assert_eq!(
            snap1.families["claude"].permit_state,
            ChannelPermitState::PendingVerification
        );

        // wait_or_drain wakes for any event, including unrelated receipts.
        // Wait for the audited state, using the workers' clock and a real deadline.
        release_audit_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let snap2 = loop {
            sys.now = native::now();
            let snapshot = stack.step_with_system(&mut sys).unwrap();
            if snapshot.families["claude"].permit_state == ChannelPermitState::Permitted {
                break snapshot;
            }
            assert!(
                Instant::now() < deadline,
                "async audit did not reach Permitted: {:?}",
                snapshot.families["claude"]
            );
            stack.wait_or_drain(deadline, &stop);
        };
        assert_eq!(
            snap2.families["claude"].permit_state,
            ChannelPermitState::Permitted
        );
        assert_eq!(
            snap2.families["claude"].display_state,
            ChannelMonitorDisplayState::Forwarding
        );

        // Step 2: Trigger CN exit risk -> cuts off channel while preserving process
        sys.now = native::now();
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

        stack.shutdown();
        assert!(stop.load(Ordering::Acquire));
        assert!(registered_production_enforcer(&store.paths.watch()).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }
}
