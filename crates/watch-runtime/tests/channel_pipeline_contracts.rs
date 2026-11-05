use claude_watch_core::{
    channel::{
        BoundProcessToken, ChannelEnforcementState, ChannelMonitorDisplayState,
        ChannelMonitorSubscriber, PolicySyncState, SubscriptionApplyOutcome,
    },
    config::Config,
    error::Result,
    processes::{LaunchTarget, ProcessRole},
    session::{Desktop, Launcher},
};
use claude_watch_runtime::{
    background_evidence::ProbeKind,
    channel_enforcer::{
        ChannelEnforcer, ConnectionTracePhase as RuntimeTracePhase, LocalTunnelEnforcer,
        TunnelStream,
    },
    channel_supervisor::{AsyncAuditRequest, ChannelSupervisor, SupervisionEvent},
    config_store::{policy_digest, ConfigStore},
    controlled::{Controller, DesktopSystem},
    receipt_store::ReceiptStore,
    session_store::SessionStore,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};

struct TempRoot(PathBuf);
impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture_local() -> Value {
    json!({
        "context": "ctx",
        "context_id": "ctx",
        "proxy": "ok",
        "tun": "ok",
        "guard_backend_healthy": true,
        "observation_unavailable": []
    })
}

fn fixture_egress(now: f64, ip: &str, country: &str) -> Value {
    json!({
        "ip": ip,
        "country": country,
        "observed_at": now,
        "source": "fixture"
    })
}

fn fixture_audit(store: &StateStore, now: f64, openai: bool, ip: &str, country: &str) -> Value {
    let config = (ConfigStore {
        storage: store.clone(),
    })
    .load()
    .unwrap();
    let mut value = json!({
        "ready": true,
        "observed_at": now,
        "expires_at": now + 30.0,
        "context_id": "ctx",
        "observation_id": "fixture",
        "context_transition": {"state": "stable"},
        "policy": policy_digest(&config.value().unwrap()).unwrap(),
        "egress_reference": {
            "ip": ip,
            "country": country,
            "checked_at": now,
            "context": "ctx",
            "source": "fixture"
        }
    });
    if openai {
        value["launch_target"] = json!("codex-desktop");
        value["authorization_scope"] = json!("observation");
    }
    value
}

fn fixture_probe(kind: ProbeKind, now: f64, dns_country: &str) -> Value {
    let mut value = json!({
        "kind": kind.label(),
        "status": "complete",
        "contextChanged": false,
        "startedAt": now - 1.0,
        "finishedAt": now,
        "errors": [],
        "observations": [{"kind": "http", "address": "1.1.1.1", "country": "JP"}]
    });
    value["observations"]
        .as_array_mut()
        .unwrap()
        .push(match kind {
            ProbeKind::Dns => json!({"kind": "resolver", "address": "8.8.8.8", "country": dns_country}),
            ProbeKind::WebRtc => json!({"kind": "srflx", "address": "1.1.1.1", "country": "JP"}),
        });
    if kind == ProbeKind::Dns {
        value["externalJSON"] = json!(json!({
            "session": "a".repeat(40),
            "dns_servers": {"8.8.8.8": 5},
            "http": {"address": "1.1.1.1", "country": "JP"},
            "geoip": [{"ip": "8.8.8.8", "country_code": dns_country}]
        })
        .to_string());
    }
    value
}

struct ChannelSystem {
    store: StateStore,
    enforcer: Option<Arc<LocalTunnelEnforcer>>,
    channel_mode: bool,
    family: &'static str,
    now: f64,
    monotonic: Duration,
    ip: String,
    country: String,
    claude_mains: Vec<Desktop>,
    openai_mains: Vec<Desktop>,
    closes: usize,
    forces: usize,
}

impl ChannelSystem {
    fn new(store: StateStore, enforcer: Option<Arc<LocalTunnelEnforcer>>, channel_mode: bool) -> Self {
        Self {
            store,
            enforcer,
            channel_mode,
            family: "claude",
            now: 1_710_000_000.0,
            monotonic: Duration::from_secs(10),
            ip: "1.1.1.1".into(),
            country: "JP".into(),
            claude_mains: vec![Desktop {
                pid: 4100,
                start_seconds: 900,
                start_microseconds: 1,
            }],
            openai_mains: vec![Desktop {
                pid: 5100,
                start_seconds: 905,
                start_microseconds: 1,
            }],
            closes: 0,
            forces: 0,
        }
    }
}

impl DesktopSystem for ChannelSystem {
    fn launch_target(&self) -> LaunchTarget {
        if self.family == "openai" {
            LaunchTarget::CodexDesktop
        } else {
            LaunchTarget::ClaudeDesktop
        }
    }

    fn set_family(&mut self, family_id: &str) -> Result<()> {
        self.family = if family_id == "openai" {
            "openai"
        } else {
            "claude"
        };
        Ok(())
    }

    fn now(&self) -> f64 {
        self.now
    }

    fn monotonic(&self) -> Duration {
        self.monotonic
    }

    fn wait(&mut self, dur: Duration) {
        self.monotonic += dur;
    }

    fn desktops(&mut self) -> Result<Vec<(Desktop, bool, String)>> {
        let list = if self.family == "openai" {
            &self.openai_mains
        } else {
            &self.claude_mains
        };
        Ok(list
            .iter()
            .cloned()
            .map(|d| {
                let stamp = format!("u501:{}:{}", d.start_seconds, d.start_microseconds);
                (d, true, stamp)
            })
            .collect())
    }

    fn desktop_alive(&mut self, desktop: &Desktop) -> Result<bool> {
        Ok(self.desktops()?.iter().any(|(d, _, _)| d == desktop))
    }

    fn desktop_tree_running(&mut self) -> Result<bool> {
        Ok(!self.desktops()?.is_empty())
    }

    fn launcher(&mut self) -> Result<Launcher> {
        Ok(Launcher {
            pid: 100,
            start: "launcher-1".into(),
        })
    }

    fn full_audit(&mut self) -> Result<Value> {
        Ok(fixture_audit(
            &self.store,
            self.now,
            self.family == "openai",
            &self.ip,
            &self.country,
        ))
    }

    fn egress(&mut self) -> Value {
        fixture_egress(self.now, &self.ip, &self.country)
    }

    fn local_guard(&mut self) -> Result<Value> {
        Ok(fixture_local())
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
        self.closes += 1;
        Ok(())
    }

    fn quit_for_confirmed_ip_risk(&mut self, forced: &mut Option<u32>) -> Result<()> {
        self.forces += 1;
        *forced = Some(1);
        Ok(())
    }

    fn channel_mode(&self) -> bool {
        self.channel_mode
    }

    fn enforce_channel(
        &mut self,
        command: &claude_watch_core::channel::ChannelEnforcementCommand,
    ) -> Result<Option<claude_watch_core::channel::ChannelEnforcementReceipt>> {
        let Some(enforcer) = &self.enforcer else {
            return Ok(None);
        };
        Ok(Some(enforcer.apply_command(command, self.now)?))
    }

    fn channel_receipt(
        &mut self,
        family: &str,
    ) -> Result<Option<claude_watch_core::channel::ChannelEnforcementReceipt>> {
        let Some(enforcer) = &self.enforcer else {
            return Ok(None);
        };
        enforcer.receipt_for(family, self.now)
    }
}

fn setup_store() -> (TempRoot, StateStore) {
    let short_id = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let root = PathBuf::from("/tmp").join(format!("cwc-{short_id}"));
    fs::create_dir_all(&root).unwrap();
    let store = StateStore::new(Paths::new(&root).unwrap());
    let mut cfg = Config::default();
    cfg.enabled = true;
    cfg.guard_enabled = true;
    store
        .atomic_json(&store.paths.config(), &cfg.value().unwrap())
        .unwrap();
    (TempRoot(root), store)
}

fn seed_receipts(store: &StateStore, now: f64, country: &str) {
    let r = ReceiptStore {
        storage: store.clone(),
    };
    r.record_dns(
        &fixture_probe(ProbeKind::Dns, now, country),
        &fixture_local(),
        None,
        now,
    )
    .unwrap();
    r.record_webrtc(
        &fixture_probe(ProbeKind::WebRtc, now, country),
        &fixture_local(),
        None,
        now,
    )
    .unwrap();
}

#[test]
fn real_tcp_connection_traces_permit_forwarding_revocation_disconnecting_and_confirmed_blocked_while_preserving_process() {
    let (_dir, store) = setup_store();

    let mut cfg = (ConfigStore {
        storage: store.clone(),
    })
    .load()
    .unwrap();
    cfg.proxy_url = "http://127.0.0.1:7890".into();
    (ConfigStore {
        storage: store.clone(),
    })
    .save(cfg.value().unwrap())
    .unwrap();

    let enforcer = Arc::new(LocalTunnelEnforcer::new("boot-live-1", Some(store.clone())));
    // Verify Item 2: At construction, interception_active and direct_fallback_blocked
    // are false until actual interception activation succeeds!
    assert!(!enforcer.is_ready().unwrap());
    enforcer.activate_interception(1_710_000_000.0).unwrap();
    assert!(enforcer.is_ready().unwrap());

    let (upstream_eof_tx, upstream_eof_rx) = mpsc::channel();
    // Wire a real kernel socketpair echo upstream representing TAG / controlled tunnel
    enforcer
        .set_upstream_connector(move |_endpoint| {
            let eof_tx = upstream_eof_tx.clone();
            let (client_end, mut server_end) = UnixStream::pair()?;
            thread::spawn(move || {
                let mut buf = [0u8; 64];
                while let Ok(n) = server_end.read(&mut buf) {
                    if n == 0 {
                        let _ = eof_tx.send(());
                        break;
                    }
                    if server_end.write_all(&buf[..n]).is_err() {
                        let _ = eof_tx.send(());
                        break;
                    }
                    let _ = server_end.flush();
                }
            });
            Ok(TunnelStream::Unix(client_end))
        })
        .unwrap();
    // Hold flow termination confirmation until we explicitly verify the intermediate
    // `Disconnecting` ("正在断开") state
    enforcer.set_defer_auto_flow_confirm(true).unwrap();

    let controller = Controller::new(store.clone());
    let mut system = ChannelSystem::new(store.clone(), Some(enforcer.clone()), true);
    seed_receipts(&store, system.now, "JP");

    // Round 1: Adopt running Claude & OpenAI desktops and grant `Permitted` channel leases
    let hb1 = controller.guard_tick(&mut system).unwrap();
    let families1 = hb1["families"].as_array().unwrap();
    assert_eq!(families1[0]["family"], "claude");
    assert_eq!(families1[0]["channel_permit"]["state"], "permitted");
    assert_eq!(
        families1[0]["channel_supervision"]["verdict"],
        "forwarding_verified"
    );

    // Connect a real TCP socket from Claude's verified process through the enforcer
    let claude_proc = BoundProcessToken::with_system_identity(
        4100,
        501,
        900,
        1,
        ProcessRole::DesktopMain,
    );
    let (flow_id, mut client_stream) = enforcer
        .connect_supervised_tcp("claude", &claude_proc, system.now)
        .unwrap();
    client_stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client_stream.write_all(b"hello-tunnel").unwrap();
    let mut reply = [0u8; 12];
    client_stream.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"hello-tunnel");

    // Unattributed process is rejected immediately by process attribution check
    let rogue_proc = BoundProcessToken::with_system_identity(
        9999,
        501,
        999,
        1,
        ProcessRole::Cli,
    );
    assert_eq!(
        enforcer
            .connect_supervised_tcp("claude", &rogue_proc, system.now)
            .unwrap_err()
            .code,
        "process_attribution_rejected"
    );

    // Round 2: Trigger exit IP drift ("1.1.1.1" -> "8.8.8.8")
    system.now += 1.0;
    system.ip = "8.8.8.8".into();
    let hb2 = controller.guard_tick(&mut system).unwrap();
    let families2 = hb2["families"].as_array().unwrap();

    // Verify Item 2: Process is preserved (0 quit_desktop, 0 quit_for_confirmed_ip_risk)
    assert_eq!((system.closes, system.forces), (0, 0));
    assert_eq!(system.claude_mains.len(), 1);
    assert_eq!(families2[0]["action"], "disconnect-channel");
    assert_eq!(families2[0]["process_preserved"], true);

    // Verify Item 3: Before `confirm_flow_terminated`, state is `disconnecting` ("正在断开"),
    // NEVER `"blocked"` ("已阻断")!
    assert_eq!(families2[0]["stop_state"], "disconnecting");
    assert_eq!(families2[0]["channel_state"], "disconnecting");
    assert_eq!(families2[0]["channel_status_label"], "正在断开");

    // Verify the existing TCP stream was actively shut down by `Shutdown::Both`
    // (explicitly excluding TimedOut / WouldBlock, and verifying upstream EOF!)
    let mut eof_buf = [0u8; 8];
    let read_after_revoke = client_stream.read(&mut eof_buf);
    assert!(
        !matches!(
            read_after_revoke,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
        ),
        "must not be a read timeout; socket must be closed or reset"
    );
    assert!(
        matches!(read_after_revoke, Ok(0) | Err(_)),
        "revoked flow socket must be shut down"
    );
    assert!(
        upstream_eof_rx.recv_timeout(Duration::from_secs(2)).is_ok(),
        "upstream relay must observe EOF when flow is revoked"
    );

    // Verify new connection attempts from Claude are blocked while interception stays active
    assert_eq!(
        enforcer
            .connect_supervised_tcp("claude", &claude_proc, system.now)
            .unwrap_err()
            .code,
        "channel_connection_blocked"
    );

    // Confirm flow termination on the enforcer and verify transition to `Blocked` ("已阻断")
    let confirmed_receipt = enforcer
        .confirm_flow_terminated("claude", &flow_id, system.now)
        .unwrap()
        .unwrap();
    assert_eq!(
        confirmed_receipt.enforcement_state,
        ChannelEnforcementState::Blocked
    );
    assert!(confirmed_receipt.active_flows_closed);
    assert_eq!(confirmed_receipt.active_flows_count, 0);
    assert_eq!(confirmed_receipt.terminated_flows_count, 1);

    system.now += 0.5;
    let hb3 = controller.guard_tick(&mut system).unwrap();
    let families3 = hb3["families"].as_array().unwrap();
    assert_eq!(families3[0]["stop_state"], "channel_blocked");
    assert_eq!(families3[0]["channel_state"], "blocked");
    assert_eq!(families3[0]["channel_status_label"], "已阻断");
    assert_eq!(
        families3[0]["channel_supervision"]["verdict"],
        "isolated_keep_process"
    );

    // Verify full lifecycle trace recorded all 5 phases for `flow_id`
    let traces: Vec<_> = enforcer
        .traces()
        .unwrap()
        .into_iter()
        .filter(|t| t.flow_id == flow_id)
        .map(|t| t.phase)
        .collect();
    assert_eq!(
        traces,
        vec![
            RuntimeTracePhase::PermitVerified,
            RuntimeTracePhase::ForwardingEstablished,
            RuntimeTracePhase::BytesForwarded,
            RuntimeTracePhase::RevocationRequested,
            RuntimeTracePhase::TerminationConfirmed,
        ]
    );
}

#[test]
fn missing_or_failed_enforcer_reports_protection_unavailable_or_failed_never_blocked() {
    let (_dir, store) = setup_store();
    let controller = Controller::new(store.clone());
    // Channel mode enabled, but no enforcer is available
    let mut system = ChannelSystem::new(store.clone(), None, true);
    seed_receipts(&store, system.now, "JP");
    controller.guard_tick(&mut system).unwrap();

    system.now += 1.0;
    system.ip = "8.8.8.8".into();
    let hb = controller.guard_tick(&mut system).unwrap();
    let claude = &hb["families"][0];
    assert_eq!((system.closes, system.forces), (0, 0));
    assert_eq!(claude["status"], "protection_unavailable");
    assert_eq!(claude["stop_state"], "enforcement_failed");
    assert_eq!(claude["channel_state"], "failed");
    assert_eq!(claude["channel_error"], "channel_enforcer_unavailable");
    assert_eq!(claude["channel_status_label"], "保护不可用");
}

#[test]
fn active_lease_expiry_cuts_off_existing_long_lived_connection_with_zero_new_connections() {
    let (_dir, store) = setup_store();

    let mut cfg = (ConfigStore {
        storage: store.clone(),
    })
    .load()
    .unwrap();
    cfg.proxy_url = "http://127.0.0.1:7890".into();
    (ConfigStore {
        storage: store.clone(),
    })
    .save(cfg.value().unwrap())
    .unwrap();

    let enforcer = Arc::new(LocalTunnelEnforcer::new("boot-expiry-1", Some(store.clone())));
    enforcer.activate_interception(1_710_000_000.0).unwrap();
    let (upstream_eof_tx, upstream_eof_rx) = mpsc::channel();
    enforcer
        .set_upstream_connector(move |_endpoint| {
            let eof_tx = upstream_eof_tx.clone();
            let (client_end, mut server_end) = UnixStream::pair()?;
            thread::spawn(move || {
                let mut buf = [0u8; 64];
                while let Ok(n) = server_end.read(&mut buf) {
                    if n == 0 {
                        let _ = eof_tx.send(());
                        break;
                    }
                    let _ = server_end.write_all(&buf[..n]);
                }
            });
            Ok(TunnelStream::Unix(client_end))
        })
        .unwrap();
    let controller = Controller::new(store.clone());
    let mut system = ChannelSystem::new(store.clone(), Some(enforcer.clone()), true);
    seed_receipts(&store, system.now, "JP");

    let hb1 = controller.guard_tick(&mut system).unwrap();
    let valid_until = hb1["families"][0]["channel_permit"]["valid_until"]
        .as_f64()
        .unwrap();

    let claude_proc = BoundProcessToken::with_system_identity(
        4100,
        501,
        900,
        1,
        ProcessRole::DesktopMain,
    );
    let (_flow_id, mut client_stream) = enforcer
        .connect_supervised_tcp("claude", &claude_proc, system.now)
        .unwrap();
    client_stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    // Start the real background lease watchdog thread (`spawn_lease_watchdog`)
    // instead of manually calling `enforce_active_deadlines`.
    let watchdog_stop = Arc::new(AtomicBool::new(false));
    let watchdog_clock = Arc::new(std::sync::Mutex::new(system.now));
    let clock_for_thread = watchdog_clock.clone();
    let (expired_tx, expired_rx) = mpsc::channel();
    let watchdog_handle = enforcer
        .spawn_lease_watchdog(
            watchdog_stop.clone(),
            Duration::from_millis(20),
            move || *clock_for_thread.lock().unwrap(),
            move |receipts| {
                for r in receipts {
                    if r.family == "claude" {
                        let _ = expired_tx.send(r);
                    }
                }
            },
        )
        .unwrap();

    // Rust stops renewing the lease and zero new connections are made.
    // Advance the clock to exact inclusive boundary `valid_until`: the running
    // background watchdog thread autonomously fires and cuts off the connection!
    *watchdog_clock.lock().unwrap() = valid_until;
    let expired_receipt = expired_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("background lease watchdog must autonomously emit expiry receipt");
    assert!(
        matches!(
            expired_receipt.enforcement_state,
            ChannelEnforcementState::Disconnecting | ChannelEnforcementState::Blocked
        ),
        "watchdog must transition family to Disconnecting or Blocked immediately upon expiry"
    );

    let mut buf = [0u8; 16];
    let read_res = client_stream.read(&mut buf);
    assert!(
        !matches!(
            read_res,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
        ),
        "must not be a read timeout; socket must be closed by watchdog"
    );
    assert!(
        matches!(read_res, Ok(0) | Err(_)),
        "existing long-lived TCP connection must be cut off upon lease expiry without any new connection"
    );
    assert!(
        upstream_eof_rx.recv_timeout(Duration::from_secs(2)).is_ok(),
        "upstream relay must observe EOF when lease expires"
    );

    let mut final_receipt = enforcer
        .receipt_for("claude", valid_until)
        .unwrap()
        .unwrap();
    for _ in 0..20 {
        if final_receipt.enforcement_state == ChannelEnforcementState::Blocked {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        final_receipt = enforcer
            .receipt_for("claude", valid_until)
            .unwrap()
            .unwrap();
    }
    assert_eq!(
        final_receipt.enforcement_state,
        ChannelEnforcementState::Blocked
    );
    assert!(final_receipt.active_flows_closed);
    assert_eq!(final_receipt.active_flows_count, 0);
    assert_eq!(final_receipt.terminated_flows_count, 1);

    watchdog_stop.store(true, Ordering::Release);
    let _ = watchdog_handle.join();
}

#[test]
fn slow_async_audit_does_not_block_revocation_and_policy_hot_reload_discards_stale_audit() {
    let (_dir, store) = setup_store();
    let enforcer = Arc::new(LocalTunnelEnforcer::new("boot-event-1", Some(store.clone())));
    enforcer.activate_interception(1_710_000_000.0).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (event_tx, event_rx) = mpsc::channel();
    let (audit_started_tx, audit_started_rx) = mpsc::channel();
    let (release_audit_tx, release_audit_rx) = mpsc::channel();

    let (audit_req_tx, worker_handle) = ChannelSupervisor::spawn_async_audit_worker(
        stop.clone(),
        event_tx,
        move |req: &AsyncAuditRequest| {
            let _ = audit_started_tx.send(req.clone());
            // Hold the slow audit until released by the test
            let _ = release_audit_rx.recv_timeout(Duration::from_secs(5));
            Ok((
                json!({
                    "ready": true,
                    "observed_at": req.requested_at + 0.5,
                    "expires_at": req.requested_at + 30.5,
                    "context_id": "ctx",
                    "observation_id": "fixture",
                    "context_transition": {"state": "stable"},
                    "policy": req.policy_version.policy_digest,
                    "launch_target": "codex-desktop",
                    "authorization_scope": "observation",
                    "egress_reference": {
                        "ip": "1.1.1.1",
                        "country": "JP",
                        "checked_at": req.requested_at + 0.5,
                        "context": "ctx",
                        "source": "fixture"
                    }
                }),
                fixture_egress(req.requested_at + 0.5, "1.1.1.1", "JP"),
                req.requested_at + 0.5,
            ))
        },
    )
    .unwrap();

    let mut supervisor =
        ChannelSupervisor::new(store.clone(), Some(enforcer.clone()), Some(audit_req_tx)).unwrap();
    let mut subscriber = ChannelMonitorSubscriber::default();

    let now = 1_710_000_000.0;
    seed_receipts(&store, now, "JP");

    // Establish an active Claude session first
    let claude_sessions = SessionStore::for_family(store.clone(), "claude");
    let config = (ConfigStore {
        storage: store.clone(),
    })
    .load()
    .unwrap();
    let claude_audit = fixture_audit(&store, now, false, "1.1.1.1", "JP");
    let pending = claude_sessions
        .begin_verified(
            &ReceiptStore {
                storage: store.clone(),
            },
            &claude_audit,
            &fixture_egress(now, "1.1.1.1", "JP"),
            now,
        )
        .unwrap();
    let claude_desktop = Desktop {
        pid: 4100,
        start_seconds: 900,
        start_microseconds: 1,
    };
    claude_sessions
        .bind_desktop(&pending.session_id, claude_desktop.clone(), now)
        .unwrap();

    // Update process inventories: Claude has an active session, OpenAI has a new
    // desktop without a session (which triggers an async slow audit on the background worker)
    supervisor
        .handle_event(SupervisionEvent::EnvironmentUpdated {
            egress: json!({"ip":"1.1.1.1","country":"JP","observed_at":now,"source":"fixture"}),
            local_guard: json!({"proxy":"ok","tun":"ok"}),
            observed_at: now,
        })
        .unwrap();
    supervisor
        .handle_event(SupervisionEvent::ProcessInventoryUpdated {
            family: "claude".into(),
            desktops: vec![(claude_desktop, true, "u501:900:1".into())],
            processes: vec![],
            observed_at: now + 0.1,
        })
        .unwrap();
    let snap_initial = supervisor
        .handle_event(SupervisionEvent::ProcessInventoryUpdated {
            family: "openai".into(),
            desktops: vec![(
                Desktop {
                    pid: 5100,
                    start_seconds: 905,
                    start_microseconds: 1,
                },
                true,
                "u501:905:1".into(),
            )],
            processes: vec![],
            observed_at: now + 0.2,
        })
        .unwrap();

    // Wait until the background worker has started OpenAI's slow audit
    let in_flight_req = audit_started_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    assert_eq!(in_flight_req.family, "openai");
    assert_eq!(
        snap_initial.families["claude"].display_state,
        ChannelMonitorDisplayState::Forwarding
    );
    assert_eq!(
        snap_initial.families["openai"].display_state,
        ChannelMonitorDisplayState::PendingVerification
    );

    subscriber.apply_snapshot(snap_initial);
    let _ = supervisor.drain_emitted_events();

    // WHILE OpenAI's slow audit is still blocked in the background worker:
    // 1. Trigger a confirmed CN exit risk -> Claude's channel is immediately revoked!
    let snap_risk = supervisor
        .handle_event(SupervisionEvent::EnvironmentUpdated {
            egress: json!({"ip":"223.5.5.5","country":"CN","observed_at":now + 1.0,"source":"fixture"}),
            local_guard: json!({"proxy":"ok","tun":"ok"}),
            observed_at: now + 1.0,
        })
        .unwrap();
    assert_eq!(
        snap_risk.families["claude"].display_state,
        ChannelMonitorDisplayState::Blocked
    );
    assert_eq!(snap_risk.families["claude"].display_label_zh, "已阻断");
    assert!(snap_risk.families["claude"].process_preserved);

    // 2. Hot-reload policy without restarting (`PolicyUpdated`) while slow audit is still blocked
    let mut new_cfg = config.clone();
    new_cfg
        .policy_actions
        .insert("gpt_close_ip".into(), "warn".into());
    let snap_hot_reload = supervisor
        .handle_event(SupervisionEvent::PolicyUpdated {
            config: new_cfg,
            observed_at: now + 1.2,
        })
        .unwrap();
    assert_eq!(
        snap_hot_reload.families["claude"].policy_sync_state,
        PolicySyncState::Applied
    );
    assert_eq!(
        snap_hot_reload.families["claude"].policy_sync_label_zh,
        "执行器已应用"
    );

    // Feed sequenced events into the subscriber and verify reconnect/gap resync
    let events = supervisor.drain_emitted_events();
    assert!(events.len() >= 2);
    // Simulate a dropped first event -> subscriber detects sequence gap and requests resync
    let gap_outcome = subscriber.apply_event(events.last().unwrap().clone());
    assert!(matches!(
        gap_outcome,
        SubscriptionApplyOutcome::GapDetectedResyncRequired { .. }
    ));
    assert!(subscriber.needs_resync);
    assert!(subscriber.apply_snapshot(snap_hot_reload.clone()));
    assert!(!subscriber.needs_resync);

    // Now release the old in-flight OpenAI slow audit (started under the old policy version)
    release_audit_tx.send(()).unwrap();
    let stale_completed = event_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let snap_after_stale = supervisor.handle_event(stale_completed).unwrap();
    // Stale async audit result from the old policy version must be discarded and
    // must NOT grant Permitted to OpenAI!
    assert_ne!(
        snap_after_stale.families["openai"].display_state,
        ChannelMonitorDisplayState::Forwarding
    );

    // Verify subscriber effective state degrades when disconnected or expired
    let expired_view = subscriber
        .effective_family_state("claude", now + 100.0, 30.0)
        .unwrap();
    assert_eq!(
        expired_view.display_state,
        ChannelMonitorDisplayState::PendingVerification
    );
    assert_eq!(expired_view.reason_code, "monitor_evidence_expired");

    stop.store(true, Ordering::Release);
    let _ = worker_handle.join();
}

#[test]
fn evidence_expiry_caps_lease_and_prevents_infinite_renewal_on_process_events() {
    use claude_watch_core::channel::ChannelPermitState;
    use claude_watch_core::session::GUARD_EGRESS_TTL;

    let (_dir, store) = setup_store();
    let enforcer = Arc::new(LocalTunnelEnforcer::new("boot-ev-cap-1", Some(store.clone())));
    let now = 1_710_000_000.0;
    enforcer.activate_interception(now).unwrap();
    seed_receipts(&store, now, "JP");

    let claude_sessions = SessionStore::for_family(store.clone(), "claude");
    let claude_audit = fixture_audit(&store, now, false, "1.1.1.1", "JP");
    let pending = claude_sessions
        .begin_verified(
            &ReceiptStore {
                storage: store.clone(),
            },
            &claude_audit,
            &fixture_egress(now, "1.1.1.1", "JP"),
            now,
        )
        .unwrap();
    let claude_desktop = Desktop {
        pid: 4100,
        start_seconds: 900,
        start_microseconds: 1,
    };
    claude_sessions
        .bind_desktop(&pending.session_id, claude_desktop.clone(), now)
        .unwrap();

    let mut supervisor =
        ChannelSupervisor::new(store.clone(), Some(enforcer.clone()), None).unwrap();

    // Seed egress observed at `now` (GUARD_EGRESS_TTL = 10.0 -> expires at `now + GUARD_EGRESS_TTL`)
    supervisor
        .handle_event(SupervisionEvent::EnvironmentUpdated {
            egress: fixture_egress(now, "1.1.1.1", "JP"),
            local_guard: json!({"proxy": "ok", "tun": "ok"}),
            observed_at: now,
        })
        .unwrap();
    let snap1 = supervisor
        .handle_event(SupervisionEvent::ProcessInventoryUpdated {
            family: "claude".into(),
            desktops: vec![(claude_desktop.clone(), true, "u501:900:1".into())],
            processes: vec![],
            observed_at: now,
        })
        .unwrap();
    assert_eq!(
        snap1.families["claude"].permit_state,
        ChannelPermitState::Permitted
    );

    // At `now + 4.0` (only 6s of egress TTL left before `now + GUARD_EGRESS_TTL`), a
    // ProcessInventoryUpdated event arrives without any new egress sample.
    // The renewed permit's `valid_until` must be capped at `now + GUARD_EGRESS_TTL` (NOT `now + 14.0`)!
    let snap_renewed = supervisor
        .handle_event(SupervisionEvent::ProcessInventoryUpdated {
            family: "claude".into(),
            desktops: vec![(claude_desktop.clone(), true, "u501:900:1".into())],
            processes: vec![],
            observed_at: now + 4.0,
        })
        .unwrap();
    assert_eq!(
        snap_renewed.families["claude"].permit_state,
        ChannelPermitState::Permitted
    );
    let cmd_at_4: Value = store
        .read_json(
            &store.paths.watch().join("state/channel-command-claude.json"),
            Value::Null,
        )
        .unwrap();
    let valid_until_4 = cmd_at_4["permit"]["valid_until"].as_f64().unwrap();
    assert!(
        (valid_until_4 - (now + GUARD_EGRESS_TTL)).abs() < 1e-6,
        "valid_until ({valid_until_4}) must be capped at evidence expiry ({})",
        now + GUARD_EGRESS_TTL
    );

    // At `now + GUARD_EGRESS_TTL`, egress evidence has expired.
    // Even though the session in SessionStore was Active and ProcessInventoryUpdated
    // continues arriving, ChannelSupervisor must refuse to renew Permitted and revoke!
    let snap_expired = supervisor
        .handle_event(SupervisionEvent::ProcessInventoryUpdated {
            family: "claude".into(),
            desktops: vec![(claude_desktop, true, "u501:900:1".into())],
            processes: vec![],
            observed_at: now + GUARD_EGRESS_TTL,
        })
        .unwrap();
    assert_eq!(
        snap_expired.families["claude"].permit_state,
        ChannelPermitState::Revoked
    );
    assert_eq!(
        snap_expired.families["claude"].reason_code,
        "egress_evidence_expired"
    );
    assert_eq!(
        snap_expired.families["claude"].display_state,
        ChannelMonitorDisplayState::Blocked
    );
}

#[test]
fn mid_dial_policy_session_or_revocation_change_aborts_connection_and_shuts_down_upstream() {
    use claude_watch_core::channel::{
        ChannelEnforcementCommand, ChannelPermit, ChannelPermitState, PolicyVersion,
    };

    let (_dir, store) = setup_store();
    let now = 1_710_000_000.0;
    let enforcer = Arc::new(LocalTunnelEnforcer::new("boot-dial-race-1", Some(store.clone())));
    enforcer.activate_interception(now).unwrap();

    let (upstream_eof_tx, upstream_eof_rx) = mpsc::channel();
    enforcer
        .set_upstream_connector(move |_endpoint| {
            let eof_tx = upstream_eof_tx.clone();
            let (client_end, mut server_end) = UnixStream::pair()?;
            thread::spawn(move || {
                let mut buf = [0u8; 32];
                while let Ok(n) = server_end.read(&mut buf) {
                    if n == 0 {
                        let _ = eof_tx.send(());
                        break;
                    }
                }
            });
            Ok(TunnelStream::Unix(client_end))
        })
        .unwrap();

    let proc_token = BoundProcessToken::with_system_identity(
        4100,
        501,
        900,
        1,
        ProcessRole::DesktopMain,
    );
    let policy_v1 = PolicyVersion {
        policy_digest: "a".repeat(64),
        guard_policy_digest: "b".repeat(64),
    };
    let policy_v2 = PolicyVersion {
        policy_digest: "c".repeat(64),
        guard_policy_digest: "d".repeat(64),
    };

    let cmd1 = ChannelEnforcementCommand {
        family: "claude".into(),
        session_id: Some("sess-1".into()),
        policy_version: policy_v1.clone(),
        permit_generation: 1,
        command_seq: 1,
        permit: ChannelPermit {
            family: "claude".into(),
            session_id: Some("sess-1".into()),
            policy_version: policy_v1,
            permit_generation: 1,
            command_seq: 1,
            state: ChannelPermitState::Permitted,
            reason_code: "active".into(),
            issued_at: now,
            valid_until: now + 30.0,
            context_id: Some("ctx".into()),
            baseline_ip: Some("1.1.1.1".into()),
            members: vec![Desktop {
                pid: 4100,
                start_seconds: 900,
                start_microseconds: 1,
            }],
        },
        allowed_processes: vec![proc_token.clone()],
        upstream_endpoint: "127.0.0.1:7890".into(),
        issued_at: now,
    };
    enforcer.apply_command(&cmd1, now).unwrap();

    // Install a mid-dial hook that switches to `policy_v2` / `sess-2` (still Permitted!)
    // while `connect_supervised_tcp_to` is in the middle of dialing upstream.
    // Even though `enforcement_state` remains `Forwarding`, post-dial re-verification
    // must detect the policy/session/generation change and abort the connection!
    let enforcer_in_hook = enforcer.clone();
    let proc_for_hook = proc_token.clone();
    enforcer
        .set_on_dial_hook(move |_dest| {
            let cmd2 = ChannelEnforcementCommand {
                family: "claude".into(),
                session_id: Some("sess-2".into()),
                policy_version: policy_v2.clone(),
                permit_generation: 2,
                command_seq: 2,
                permit: ChannelPermit {
                    family: "claude".into(),
                    session_id: Some("sess-2".into()),
                    policy_version: policy_v2.clone(),
                    permit_generation: 2,
                    command_seq: 2,
                    state: ChannelPermitState::Permitted,
                    reason_code: "active".into(),
                    issued_at: now + 0.1,
                    valid_until: now + 30.1,
                    context_id: Some("ctx".into()),
                    baseline_ip: Some("1.1.1.1".into()),
                    members: vec![Desktop {
                        pid: 4100,
                        start_seconds: 900,
                        start_microseconds: 1,
                    }],
                },
                allowed_processes: vec![proc_for_hook.clone()],
                upstream_endpoint: "127.0.0.1:7890".into(),
                issued_at: now + 0.1,
            };
            enforcer_in_hook.apply_command(&cmd2, now + 0.1).unwrap();
        })
        .unwrap();

    let err = enforcer
        .connect_supervised_tcp_to("claude", &proc_token, "api.anthropic.com:443", now)
        .unwrap_err();
    assert_eq!(err.code, "channel_changed_during_dial");
    assert!(
        upstream_eof_rx.recv_timeout(Duration::from_secs(2)).is_ok(),
        "aborted mid-dial upstream socket must be shut down immediately"
    );
    let receipt = enforcer.receipt_for("claude", now + 0.2).unwrap().unwrap();
    assert_eq!(receipt.active_flows_count, 0);
    assert!(receipt.blocked_new_connections >= 1);
}

#[test]
fn out_of_order_or_conflicting_commands_do_not_mutate_state_and_duplicate_commands_are_idempotent() {
    use claude_watch_core::channel::{
        ChannelEnforcementCommand, ChannelPermit, ChannelPermitState, PolicyVersion,
    };

    let (_dir, store) = setup_store();
    let now = 1_710_000_000.0;
    let enforcer = Arc::new(LocalTunnelEnforcer::new("boot-order-1", Some(store)));
    enforcer.activate_interception(now).unwrap();

    let policy_v1 = PolicyVersion {
        policy_digest: "1".repeat(64),
        guard_policy_digest: "2".repeat(64),
    };
    let rogue_policy = PolicyVersion {
        policy_digest: "9".repeat(64),
        guard_policy_digest: "8".repeat(64),
    };

    let make_cmd =
        |gen: u64, seq: u64, state: ChannelPermitState, policy: &PolicyVersion, at: f64| {
            ChannelEnforcementCommand {
                family: "claude".into(),
                session_id: Some("sess-1".into()),
                policy_version: policy.clone(),
                permit_generation: gen,
                command_seq: seq,
                permit: ChannelPermit {
                    family: "claude".into(),
                    session_id: Some("sess-1".into()),
                    policy_version: policy.clone(),
                    permit_generation: gen,
                    command_seq: seq,
                    state,
                    reason_code: if state == ChannelPermitState::Permitted {
                        "active".into()
                    } else {
                        "egress_ip_changed".into()
                    },
                    issued_at: at,
                    valid_until: at + 30.0,
                    context_id: Some("ctx".into()),
                    baseline_ip: Some("1.1.1.1".into()),
                    members: vec![],
                },
                allowed_processes: vec![],
                upstream_endpoint: "127.0.0.1:7890".into(),
                issued_at: at,
            }
        };

    // 1. Apply valid Revoked command (gen = 2, seq = 2)
    let cmd_revoke = make_cmd(2, 2, ChannelPermitState::Revoked, &policy_v1, now);
    let r1 = enforcer.apply_command(&cmd_revoke, now).unwrap();
    assert_eq!(r1.enforcement_state, ChannelEnforcementState::Blocked);

    // 2. Attempt stale command (gen = 1, seq = 99) carrying `rogue_policy` and a
    // far-future timestamp `now + 500.0`. Must be rejected BEFORE mutating
    // `last_wall_now` or `current_policy`!
    let stale_cmd = make_cmd(1, 99, ChannelPermitState::Permitted, &rogue_policy, now + 500.0);
    assert_eq!(
        enforcer
            .apply_command(&stale_cmd, now + 500.0)
            .unwrap_err()
            .code,
        "stale_or_out_of_order_command"
    );

    // Verify `last_wall_now` and `current_policy` were NOT polluted by `stale_cmd`:
    // applying a normal command at `now + 1.0` with `policy_v1` must NOT trigger
    // false clock rollback or false policy change!
    let dup_revoke = enforcer.apply_command(&cmd_revoke, now + 1.0).unwrap();
    assert_eq!(dup_revoke.enforcement_state, ChannelEnforcementState::Blocked);
    assert_eq!(dup_revoke.policy_version, policy_v1);

    // 3. Same (gen = 2, seq = 2) with conflicting content (Permitted instead of Revoked)
    // must be rejected as `conflicting_command_seq` and never re-permit the channel!
    let conflicting_cmd = make_cmd(2, 2, ChannelPermitState::Permitted, &policy_v1, now + 1.0);
    assert_eq!(
        enforcer
            .apply_command(&conflicting_cmd, now + 1.0)
            .unwrap_err()
            .code,
        "conflicting_command_seq"
    );
    let current_receipt = enforcer.receipt_for("claude", now + 1.0).unwrap().unwrap();
    assert_eq!(
        current_receipt.enforcement_state,
        ChannelEnforcementState::Blocked
    );
}

#[test]
fn async_audit_failure_timeout_and_request_id_mismatch_recover_and_respect_bounded_retries() {
    use claude_watch_core::{
        channel::{ChannelPermitState, PolicyVersion},
        error::CoreError,
    };
    use claude_watch_runtime::channel_supervisor::{
        AsyncAuditOutcome, ASYNC_AUDIT_RETRY_BACKOFF_SECONDS, MAX_ASYNC_AUDIT_RETRIES,
    };

    let (_dir, store) = setup_store();
    let now = 1_710_000_000.0;
    let enforcer = Arc::new(LocalTunnelEnforcer::new("boot-audit-retry-1", Some(store.clone())));
    enforcer.activate_interception(now).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let (event_tx, event_rx) = mpsc::channel();
    let (audit_req_tx, worker_handle) = ChannelSupervisor::spawn_async_audit_worker(
        stop.clone(),
        event_tx,
        move |_req: &AsyncAuditRequest| {
            Err(CoreError::new("probe_failed", "模拟慢审计探针失败"))
        },
    )
    .unwrap();

    let mut supervisor =
        ChannelSupervisor::new(store, Some(enforcer), Some(audit_req_tx)).unwrap();
    supervisor
        .handle_event(SupervisionEvent::EnvironmentUpdated {
            egress: fixture_egress(now, "1.1.1.1", "JP"),
            local_guard: json!({"proxy": "ok", "tun": "ok"}),
            observed_at: now,
        })
        .unwrap();

    let openai_desktop = Desktop {
        pid: 5100,
        start_seconds: 905,
        start_microseconds: 1,
    };

    // Attempt 1..=MAX_ASYNC_AUDIT_RETRIES: each failed audit sends back
    // `AsyncAuditCompleted` with `AsyncAuditOutcome::Failed`, clears `audit_in_flight`,
    // and after MAX_ASYNC_AUDIT_RETRIES transitions the family to `Revoked`
    // (`async_audit_retries_exhausted`) instead of hanging in `PendingVerification`!
    let mut current_time = now;
    for attempt in 1..=MAX_ASYNC_AUDIT_RETRIES {
        let snap = supervisor
            .handle_event(SupervisionEvent::ProcessInventoryUpdated {
                family: "openai".into(),
                desktops: vec![(openai_desktop.clone(), true, "u501:905:1".into())],
                processes: vec![],
                observed_at: current_time,
            })
            .unwrap();

        // Inject a bogus completion with a mismatched `request_id: 999` while the
        // real request is in flight -> must be ignored without clearing `audit_in_flight`!
        let _ = supervisor
            .handle_event(SupervisionEvent::AsyncAuditCompleted {
                request_id: 999,
                family: "openai".into(),
                session_id: None,
                policy_version: PolicyVersion {
                    policy_digest: "a".repeat(64),
                    guard_policy_digest: "b".repeat(64),
                },
                requested_at: current_time,
                outcome: AsyncAuditOutcome::TimedOut {
                    elapsed_seconds: 20.0,
                },
                completed_at: current_time + 0.01,
            })
            .unwrap();

        let failed_ev = event_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("worker must emit AsyncAuditCompleted even when run_audit returns Err");
        let after_fail = supervisor.handle_event(failed_ev).unwrap();
        if attempt < MAX_ASYNC_AUDIT_RETRIES {
            assert_eq!(
                after_fail.families["openai"].permit_state,
                ChannelPermitState::PendingVerification
            );
            assert_eq!(snap.families["openai"].family, "openai");
        } else {
            assert_eq!(
                after_fail.families["openai"].permit_state,
                ChannelPermitState::Revoked
            );
            assert_eq!(
                after_fail.families["openai"].reason_code,
                "async_audit_retries_exhausted"
            );
            assert_eq!(
                after_fail.families["openai"].display_state,
                ChannelMonitorDisplayState::Blocked
            );
        }
        current_time += ASYNC_AUDIT_RETRY_BACKOFF_SECONDS + 0.5;
    }

    stop.store(true, Ordering::Release);
    let _ = worker_handle.join();
}

#[test]
fn receiver_clock_and_executor_boot_id_handshake_reject_delayed_or_pre_restart_receipts() {
    use claude_watch_core::channel::ChannelEnforcementReceipt;

    let (_dir, store) = setup_store();
    let now = 1_710_000_000.0;
    let enforcer = Arc::new(LocalTunnelEnforcer::new("boot-current-1", Some(store.clone())));
    enforcer.activate_interception(now).unwrap();
    seed_receipts(&store, now, "JP");

    let claude_sessions = SessionStore::for_family(store.clone(), "claude");
    let claude_audit = fixture_audit(&store, now, false, "1.1.1.1", "JP");
    let pending = claude_sessions
        .begin_verified(
            &ReceiptStore {
                storage: store.clone(),
            },
            &claude_audit,
            &fixture_egress(now, "1.1.1.1", "JP"),
            now,
        )
        .unwrap();
    let claude_desktop = Desktop {
        pid: 4100,
        start_seconds: 900,
        start_microseconds: 1,
    };
    claude_sessions
        .bind_desktop(&pending.session_id, claude_desktop.clone(), now)
        .unwrap();

    let mut supervisor =
        ChannelSupervisor::new(store, Some(enforcer), None).unwrap();
    assert_eq!(supervisor.expected_executor_boot_id(), Some("boot-current-1"));

    supervisor
        .handle_event(SupervisionEvent::EnvironmentUpdated {
            egress: fixture_egress(now, "1.1.1.1", "JP"),
            local_guard: json!({"proxy": "ok", "tun": "ok"}),
            observed_at: now,
        })
        .unwrap();
    let snap_ok = supervisor
        .handle_event(SupervisionEvent::ProcessInventoryUpdated {
            family: "claude".into(),
            desktops: vec![(claude_desktop, true, "u501:900:1".into())],
            processes: vec![],
            observed_at: now + 0.1,
        })
        .unwrap();
    let claude_state = &snap_ok.families["claude"];
    assert_eq!(
        claude_state.display_state,
        ChannelMonitorDisplayState::Forwarding
    );

    // 1. A receipt with a pre-restart `executor_boot_id` ("boot-old-0") arrives with
    // matching `permit_generation` and `command_seq` -> rejected by boot_id check!
    let pre_restart_receipt = ChannelEnforcementReceipt {
        family: "claude".into(),
        session_id: claude_state.session_id.clone(),
        policy_version: claude_state.saved_policy_version.clone(),
        permit_generation: claude_state.permit_generation,
        command_seq: claude_state.command_seq,
        permit_state: claude_watch_core::channel::ChannelPermitState::Permitted,
        enforcement_state: ChannelEnforcementState::Forwarding,
        interception_active: true,
        direct_fallback_blocked: true,
        local_proxy_ready: true,
        system_extension_active: true,
        new_connections_blocked: false,
        active_flows_closed: false,
        active_flows_count: 1,
        terminated_flows_count: 0,
        blocked_new_connections: 0,
        error_code: None,
        executor_boot_id: "boot-old-0".into(),
        observed_at: now + 0.2,
    };
    let snap_bad_boot = supervisor
        .handle_event(SupervisionEvent::EnforcementReceiptArrived {
            receipt: pre_restart_receipt,
            received_at: now + 0.2,
        })
        .unwrap();
    assert_eq!(
        snap_bad_boot.families["claude"].display_state,
        ChannelMonitorDisplayState::Failed
    );
    assert_eq!(
        snap_bad_boot.families["claude"].policy_sync_state,
        PolicySyncState::ApplyFailed
    );

    // 2. A receipt with the correct `boot-current-1` and `observed_at = now + 0.2`,
    // but arriving late at `received_at = now + 15.0` -> rejected by receiver clock!
    let delayed_receipt = ChannelEnforcementReceipt {
        executor_boot_id: "boot-current-1".into(),
        observed_at: now + 0.2,
        ..snap_bad_boot
            .families["claude"]
            .clone()
            .into_iter_dummy_receipt()
    };
    let snap_delayed = supervisor
        .handle_event(SupervisionEvent::EnforcementReceiptArrived {
            receipt: delayed_receipt,
            received_at: now + 15.0,
        })
        .unwrap();
    assert_eq!(
        snap_delayed.families["claude"].display_state,
        ChannelMonitorDisplayState::Failed
    );
    assert_eq!(
        snap_delayed.families["claude"].policy_sync_state,
        PolicySyncState::ApplyFailed
    );

    // 3. Handshaking a new executor boot ID bumps `permit_generation` so old
    // sequence numbers cannot be reused!
    let prev_gen = snap_delayed.families["claude"].permit_generation;
    supervisor.register_executor_handshake("boot-current-2", now + 16.0);
    let snap_handshaken = supervisor.snapshot(now + 16.0);
    assert_eq!(
        snap_handshaken.families["claude"].permit_generation,
        prev_gen + 1
    );
}

trait DummyReceiptExt {
    fn into_iter_dummy_receipt(self) -> claude_watch_core::channel::ChannelEnforcementReceipt;
}
impl DummyReceiptExt for claude_watch_core::channel::FamilyChannelMonitorState {
    fn into_iter_dummy_receipt(self) -> claude_watch_core::channel::ChannelEnforcementReceipt {
        claude_watch_core::channel::ChannelEnforcementReceipt {
            family: self.family,
            session_id: self.session_id,
            policy_version: self.saved_policy_version,
            permit_generation: self.permit_generation,
            command_seq: self.command_seq,
            permit_state: self.permit_state,
            enforcement_state: ChannelEnforcementState::Forwarding,
            interception_active: true,
            direct_fallback_blocked: true,
            local_proxy_ready: true,
            system_extension_active: true,
            new_connections_blocked: false,
            active_flows_closed: false,
            active_flows_count: 1,
            terminated_flows_count: 0,
            blocked_new_connections: 0,
            error_code: None,
            executor_boot_id: "boot-current-1".into(),
            observed_at: self.updated_at,
        }
    }
}

#[test]
fn upstream_tag_connect_handshake_verifies_200_and_clears_read_timeout_or_rejects() {
    let (_dir, store) = setup_store();
    let enforcer = Arc::new(LocalTunnelEnforcer::new("boot-tag-1", Some(store)));
    enforcer.activate_interception(1_710_000_000.0).unwrap();

    // 1. Success case: Upstream proxy returns HTTP/1.1 200 Connection Established
    let (client_end, mut server_end) = UnixStream::pair().unwrap();
    let server_thread = thread::spawn(move || {
        let mut buf = [0u8; 128];
        let n = server_end.read(&mut buf).unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);
        assert!(req.starts_with("CONNECT api.anthropic.com:443 HTTP/1.1\r\n"));
        assert!(req.contains("Host: api.anthropic.com:443\r\n"));
        assert!(req.contains("Proxy-Connection: keep-alive\r\n"));
        server_end
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        // Server continues to echo
        let mut echo_buf = [0u8; 64];
        let en = server_end.read(&mut echo_buf).unwrap();
        server_end.write_all(&echo_buf[..en]).unwrap();
    });

    let mut stream = TunnelStream::Unix(client_end);
    LocalTunnelEnforcer::perform_upstream_connect_handshake(
        &mut stream,
        "api.anthropic.com:443",
    )
    .unwrap();
    // After handshake, stream is ready and unblocked by handshake timeout
    stream.write_all(b"ping-through-tag").unwrap();
    let mut resp = [0u8; 16];
    stream.read_exact(&mut resp).unwrap();
    assert_eq!(&resp, b"ping-through-tag");
    server_thread.join().unwrap();

    // 2. Failure case: Upstream proxy returns HTTP/1.1 502 Bad Gateway
    let (bad_client, mut bad_server) = UnixStream::pair().unwrap();
    let bad_server_thread = thread::spawn(move || {
        let mut buf = [0u8; 128];
        let _ = bad_server.read(&mut buf);
        bad_server
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            .unwrap();
    });
    let mut bad_stream = TunnelStream::Unix(bad_client);
    let err = LocalTunnelEnforcer::perform_upstream_connect_handshake(
        &mut bad_stream,
        "api.anthropic.com:443",
    )
    .unwrap_err();
    assert_eq!(err.code, "upstream_connect_rejected");
    bad_server_thread.join().unwrap();
}

#[test]
fn daemon_restart_resync_with_producer_boot_id() {
    let mut subscriber = ChannelMonitorSubscriber::default();
    let initial_now = 1_710_000_000.0;

    let dummy_state = claude_watch_core::channel::FamilyChannelMonitorState {
        producer_boot_id: "sup-boot-1".into(),
        family: "claude".into(),
        session_id: Some("sess-1".into()),
        saved_policy_version: claude_watch_core::channel::PolicyVersion {
            policy_digest: "p1".repeat(32),
            guard_policy_digest: "g1".repeat(32),
        },
        applied_policy_version: Some(claude_watch_core::channel::PolicyVersion {
            policy_digest: "p1".repeat(32),
            guard_policy_digest: "g1".repeat(32),
        }),
        permit_generation: 1,
        command_seq: 1,
        permit_state: claude_watch_core::channel::ChannelPermitState::Permitted,
        display_state: ChannelMonitorDisplayState::Forwarding,
        display_label_zh: "受控放行中".into(),
        policy_sync_state: PolicySyncState::Applied,
        policy_sync_label_zh: "执行器已应用".into(),
        reason_code: "active".into(),
        process_preserved: true,
        active_member_pids: vec![4100],
        active_members: vec![],
        local_proxy_ready: true,
        system_extension_active: true,
        active_flows_count: 1,
        terminated_flows_count: 0,
        blocked_new_connections: 0,
        updated_at: initial_now,
    };

    let snap = claude_watch_core::channel::ChannelMonitorSnapshot {
        producer_boot_id: "sup-boot-1".into(),
        snapshot_seq: 0,
        captured_at: initial_now,
        saved_policy_version: claude_watch_core::channel::PolicyVersion {
            policy_digest: "p1".repeat(32),
            guard_policy_digest: "g1".repeat(32),
        },
        families: [("claude".into(), dummy_state.clone())].into_iter().collect(),
    };
    assert!(subscriber.apply_snapshot(snap));

    let ev1 = claude_watch_core::channel::ChannelMonitorEvent {
        producer_boot_id: "sup-boot-1".into(),
        event_seq: 1,
        family_state: dummy_state.clone(),
    };
    assert_eq!(
        subscriber.apply_event(ev1),
        SubscriptionApplyOutcome::Applied
    );

    // Daemon restarts: event_seq resets to 1, but producer_boot_id is different ("sup-boot-2")
    let mut restart_state = dummy_state;
    restart_state.producer_boot_id = "sup-boot-2".into();
    let ev_restart = claude_watch_core::channel::ChannelMonitorEvent {
        producer_boot_id: "sup-boot-2".into(),
        event_seq: 1,
        family_state: restart_state,
    };
    // Must recognize producer restart and request resync!
    assert_eq!(
        subscriber.apply_event(ev_restart),
        SubscriptionApplyOutcome::GapDetectedResyncRequired {
            expected_seq: 2,
            received_seq: 1,
        }
    );
    assert!(subscriber.needs_resync);
}

#[test]
fn launch_failure_in_channel_mode_revokes_channel_and_preserves_process_without_quit() {
    let (_dir, store) = setup_store();
    let enforcer = Arc::new(LocalTunnelEnforcer::new("boot-lnch-1", Some(store.clone())));
    enforcer.activate_interception(1_710_000_000.0).unwrap();

    let mut system = ChannelSystem::new(store.clone(), Some(enforcer), true);
    // Desktops empty initially so launch check proceeds past `already_running`
    system.claude_mains.clear();

    let controller = Controller::new(store);
    // Launch will fail because desktops remains empty during post-open wait
    let result = controller.launch(&mut system);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, "desktop_identity_unavailable");

    // Channel mode must preserve the process and NEVER call quit_desktop!
    assert_eq!(system.closes, 0);
    assert_eq!(system.forces, 0);

    // Channel must be revoked with reason launch_failed
    let receipt = system.channel_receipt("claude").unwrap().unwrap();
    assert_eq!(
        receipt.permit_state,
        claude_watch_core::channel::ChannelPermitState::Revoked
    );
    assert_eq!(receipt.error_code.as_deref(), Some("launch_failed"));
}
