#[path = "support/hardened_helper.rs"]
mod hardened_helper;

use claude_watch_core::{
    channel::{
        BoundProcessToken, ChannelEnforcementState, ChannelPermitState, NetworkBackendKind,
    },
    config::Config,
    processes::ProcessRole,
    session::Desktop,
    vpn::{
        ObservationConsistency, ObservedField, UpstreamProtocol, VpnEpoch, VpnExpectation,
        VpnMatch, VpnObservation,
    },
};
use claude_watch_runtime::{
    channel_enforcer::{ChannelEnforcer, LocalTunnelEnforcer, TunnelStream},
    channel_supervisor::{AsyncAuditOutcome, AsyncAuditRequest, ChannelSupervisor, SupervisionEvent},
    config_store::{policy_digest, ConfigStore},
    receipt_store::ReceiptStore,
    session_store::SessionStore,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::{mpsc, Arc},
    thread,
    time::Duration,
};

struct TempRoot(PathBuf);
impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn setup_store_with_vpn_expectation(
    mut configure: impl FnMut(&mut Config, &mut VpnExpectation),
) -> (TempRoot, StateStore, Config) {
    let dir = std::env::temp_dir().join(format!("cw-vpn-guard-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let store = StateStore::new(Paths::new(&dir).unwrap());
    let mut cfg = Config::default_for_new_install();
    cfg.enabled = true;
    cfg.guard_enabled = true;
    cfg.proxy_mode = "clash-verge".into();
    cfg.proxy_url = "http://127.0.0.1:17890".into();
    cfg.proxy_group = "AI-Group".into();
    let mut exp = VpnExpectation::unconfigured();
    exp.configured = true;
    exp.proxy_mode = "clash-verge".into();
    exp.proxy_url = "http://127.0.0.1:17890".into();
    exp.proxy_group = "AI-Group".into();
    exp.running_mode = Some("rule".into());
    exp.expected_node = Some("US-West-01".into());
    exp.expected_chain = vec!["AI-Group".into(), "US-West-01".into()];
    exp.require_tun = None;
    configure(&mut cfg, &mut exp);
    cfg.vpn_expectation = Some(exp);
    let saved = ConfigStore {
        storage: store.clone(),
    }
    .save(cfg.value().unwrap())
    .unwrap();
    (TempRoot(dir), store, saved)
}

fn sample_vpn_observation(now: f64, change_generation: u64) -> VpnObservation {
    VpnObservation {
        source: "clash-verge".into(),
        source_instance: Some("inst-1".into()),
        source_revision: Some(format!("rev-{change_generation}")),
        upstream_endpoint: Some("http://127.0.0.1:17890".into()),
        upstream_protocol: ObservedField::Known(UpstreamProtocol::MixedHttp),
        running_mode: ObservedField::Known("rule".into()),
        tun_enabled: ObservedField::Known(false),
        system_proxy_enabled: ObservedField::Known(false),
        selected_group: ObservedField::Known("AI-Group".into()),
        selected_node: ObservedField::Known("US-West-01".into()),
        proxy_chain: ObservedField::Known(vec!["AI-Group".into(), "US-West-01".into()]),
        rules_digest: ObservedField::Unknown("controller_rules_not_sampled".into()),
        sample_started_at: now,
        observed_at: now,
        valid_until: now + 3.5,
        consistency: ObservationConsistency::RevisionVerified,
        source_error: None,
        sample_seq: change_generation,
        epoch: VpnEpoch::new("vpn-obs-boot-1", change_generation),
    }
}

fn controlled_egress(
    cfg: &Config,
    now: f64,
    ip: &str,
    country: &str,
    vpn_epoch: Option<VpnEpoch>,
) -> Value {
    let policy_ver = ChannelSupervisor::compute_policy_version(cfg).unwrap();
    let mut val = json!({
        "ip": ip,
        "country": country,
        "observed_at": now,
        "source": "fixture",
        "family": "*",
        "upstream_endpoint": cfg.proxy_url,
        "policy_version": policy_ver,
        "context_id": "ctx-vpn",
        "backend": "seatbelt", "via_controlled_path": true
    });
    if let Some(ep) = vpn_epoch {
        val["vpn_epoch"] = json!(ep);
    }
    val
}

fn fixture_audit_val(store: &StateStore, now: f64, ip: &str, country: &str) -> Value {
    let config = (ConfigStore {
        storage: store.clone(),
    })
    .load()
    .unwrap();
    json!({
        "ready": true,
        "observed_at": now,
        "expires_at": now + 30.0,
        "context_id": "ctx-vpn",
        "observation_id": "fixture",
        "context_transition": {"state": "stable"},
        "policy": policy_digest(&config.value().unwrap()).unwrap(),
        "egress_reference": {
            "ip": ip,
            "country": country,
            "checked_at": now,
            "context": "ctx-vpn",
            "source": "fixture"
        }
    })
}

fn seed_probe_receipts(store: &StateStore, now: f64, country: &str) {
    let receipts = ReceiptStore {
        storage: store.clone(),
    };
    let local = json!({
        "context": "ctx-vpn",
        "context_id": "ctx-vpn",
        "proxy": "ok",
        "tun": "ok",
        "guard_backend_healthy": true,
        "observation_unavailable": []
    });
    for kind in [
        claude_watch_runtime::background_evidence::ProbeKind::Dns,
        claude_watch_runtime::background_evidence::ProbeKind::WebRtc,
    ] {
        let mut val = json!({
            "kind": kind.label(),
            "status": "complete",
            "contextChanged": false,
            "startedAt": now - 1.0,
            "finishedAt": now,
            "errors": [],
            "observations": [{"kind": "http", "address": "1.1.1.1", "country": country}]
        });
        val["observations"].as_array_mut().unwrap().push(match kind {
            claude_watch_runtime::background_evidence::ProbeKind::Dns => {
                json!({"kind": "resolver", "address": "8.8.8.8", "country": country})
            }
            claude_watch_runtime::background_evidence::ProbeKind::WebRtc => {
                json!({"kind": "srflx", "address": "1.1.1.1", "country": country})
            }
        });
        if kind == claude_watch_runtime::background_evidence::ProbeKind::Dns {
            val["externalJSON"] = json!(json!({
                "session": "a".repeat(40),
                "dns_servers": {"8.8.8.8": 5},
                "http": {"address": "1.1.1.1", "country": country},
                "geoip": [{"ip": "8.8.8.8", "country_code": country}]
            })
            .to_string());
            receipts.record_dns(&val, &local, None, now).unwrap();
        } else {
            receipts.record_webrtc(&val, &local, None, now).unwrap();
        }
    }
}

fn setup_active_session_and_supervisor(
    configure: impl FnMut(&mut Config, &mut VpnExpectation),
    mut configure_obs: impl FnMut(&mut VpnObservation),
) -> (
    TempRoot,
    StateStore,
    Config,
    Arc<LocalTunnelEnforcer>,
    ChannelSupervisor,
    mpsc::Receiver<AsyncAuditRequest>,
    BoundProcessToken,
    f64,
) {
    let (tmp, store, cfg) = setup_store_with_vpn_expectation(configure);
    let now = 1_720_000_000.0;
    seed_probe_receipts(&store, now, "US");
    let enforcer = Arc::new(LocalTunnelEnforcer::new("boot-vpn-guard", Some(store.clone())));
    enforcer.set_local_proxy_ready(true, now).unwrap();
    enforcer
        .configure_seatbelt_backend(true, now)
        .unwrap();
    enforcer
        .set_upstream_connector(|_ep| {
            let (a, _b) = UnixStream::pair()?;
            Ok(TunnelStream::Unix(a))
        })
        .unwrap();

    let (tx, rx) = mpsc::channel();
    let mut supervisor =
        ChannelSupervisor::new(store.clone(), Some(enforcer.clone()), Some(tx)).unwrap();

    let sessions = SessionStore::for_family(store.clone(), "claude");
    let mut obs = sample_vpn_observation(now, 1);
    configure_obs(&mut obs);
    let mut eg = controlled_egress(&cfg, now, "1.1.1.1", "US", Some(obs.epoch.clone()));
    eg["policy_version"] = json!(supervisor.saved_policy_version());
    let pending = sessions
        .begin_verified(
            &ReceiptStore {
                storage: store.clone(),
            },
            &fixture_audit_val(&store, now, "1.1.1.1", "US"),
            &eg,
            now,
        )
        .unwrap();
    let desktop = Desktop {
        pid: 5100,
        start_seconds: 900,
        start_microseconds: 1,
    };
    sessions.bind_desktop(&pending.session_id, desktop.clone(), now).unwrap();

    let proc_tok = BoundProcessToken::with_system_identity(5100, 501, 900, 1, ProcessRole::DesktopMain)
        .with_audit_token([501, 501, 20, 501, 20, 5100, 0, 9]);

    supervisor
        .handle_event(SupervisionEvent::VpnObservationUpdated {
            observation: obs,
            observed_at: now,
        })
        .unwrap();
    let local_tun = if cfg
        .vpn_expectation
        .as_ref()
        .is_some_and(|e| e.require_tun == Some(true))
    {
        "ok"
    } else {
        "disabled"
    };
    supervisor
        .handle_event(SupervisionEvent::EnvironmentUpdated {
            egress: eg,
            local_guard: json!({"proxy": "ok", "tun": local_tun, "context_id": "ctx-vpn"}),
            observed_at: now,
        })
        .unwrap();
    let snap = supervisor
        .handle_event(SupervisionEvent::ProcessInventoryUpdated {
            family: "claude".into(),
            desktops: vec![(desktop, true, "u501:900:1".into())],
            processes: vec![proc_tok.clone()],
            observed_at: now,
        })
        .unwrap();
    assert_eq!(
        snap.families["claude"].permit_state,
        ChannelPermitState::Permitted,
        "initial session with matching VPN observation and require_tun=None should be Permitted (V04), got reason: {}",
        snap.families["claude"].reason_code
    );
    assert_eq!(snap.families["claude"].backend, NetworkBackendKind::Seatbelt);
    assert!(snap.families["claude"].sandbox_ready);

    (tmp, store, cfg, enforcer, supervisor, rx, proc_tok, now)
}

#[test]
fn r1_target_inventory_invalidation_closes_live_flow_and_rejects_reconnect() {
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicBool, Ordering};
    let (_tmp, _store, _cfg, enforcer, mut supervisor, _rx, token, now) =
        setup_active_session_and_supervisor(|_, _| {}, |_| {});
    enforcer.set_clock(move || now + 0.1).unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut header = Vec::new();
        let mut byte = [0];
        while !header.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
        }
        stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").unwrap();
        accepted_tx.send(stream).unwrap();
    });
    enforcer.set_upstream_connector(move |_| Ok(TunnelStream::Tcp(TcpStream::connect(upstream_addr)?))).unwrap();
    let attributed_token = token.clone();
    enforcer.set_accepted_connection_attributor(move |_| Some(("claude".into(), attributed_token.clone()))).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let (addr, listener) = enforcer.start_local_proxy_listener("127.0.0.1:0", stop.clone(), now).unwrap();
    let mut client = TcpStream::connect(addr).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    client.write_all(b"CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\n\r\n").unwrap();
    let mut header = Vec::new();
    let mut byte = [0];
    while !header.ends_with(b"\r\n\r\n") { client.read_exact(&mut byte).unwrap(); header.push(byte[0]); }
    assert!(header.starts_with(b"HTTP/1.1 200"));
    let mut remote = accepted_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    server.join().unwrap();
    client.write_all(b"before").unwrap();
    let mut payload = [0; 6]; remote.read_exact(&mut payload).unwrap(); assert_eq!(&payload, b"before");

    // This is the production target-refresh event, not a direct enforcer revoke call.
    let snapshot = supervisor.handle_event(SupervisionEvent::ProcessInventoryUnavailable {
        family: "claude".into(), observed_at: now + 0.1,
    }).unwrap();
    assert_eq!(snapshot.families["claude"].permit_state, ChannelPermitState::Revoked);
    assert_eq!(client.read(&mut byte).expect("timeout is not EOF"), 0);
    assert_eq!(remote.read(&mut byte).expect("timeout is not EOF"), 0);
    for _ in 0..10 { assert!(enforcer.connect_supervised_tcp("claude", &token, now + 0.2).is_err()); }
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while enforcer.receipt_for("claude", now + 0.2).unwrap().unwrap().active_flows_count != 0 {
        assert!(std::time::Instant::now() < deadline, "relay completion receipt missing");
        thread::sleep(Duration::from_millis(10));
    }
    stop.store(true, Ordering::Release);
    listener.join().unwrap();
}

#[test]
fn queued_vpn_refresh_uses_delivery_clock_without_extending_sample_expiry() {
    let (_tmp, _store, _cfg, enforcer, mut supervisor, _rx, _token, start) =
        setup_active_session_and_supervisor(|_, _| {}, |_| {});
    let mut delayed = sample_vpn_observation(start + 0.25, 1);
    delayed.sample_seq = 2;
    let delivered_at = start + 0.75;
    enforcer.enforce_active_deadlines(delivered_at, false).unwrap();
    let renewed = supervisor.handle_queued_event(SupervisionEvent::VpnObservationUpdated {
        observed_at: delayed.observed_at,
        observation: delayed.clone(),
    }, delivered_at).unwrap();
    assert_eq!(renewed.captured_at, delivered_at);
    assert_eq!(supervisor.latest_vpn_observation(), Some(&delayed));
    assert_eq!(renewed.families["claude"].permit_state, ChannelPermitState::Permitted);
    let receipt = enforcer.receipt_for("claude", delivered_at).unwrap().unwrap();
    assert_eq!(receipt.enforcement_state, ChannelEnforcementState::Forwarding);
    assert_eq!(receipt.observed_at, delivered_at);
    assert_eq!(renewed.families["claude"].valid_until, Some(delayed.valid_until));

    let mut expired = sample_vpn_observation(start + 0.8, 1);
    expired.sample_seq = 3;
    expired.valid_until = start + 1.0;
    let delivered_at = start + 1.1;
    let blocked = supervisor.handle_queued_event(SupervisionEvent::VpnObservationUpdated {
        observed_at: expired.observed_at,
        observation: expired.clone(),
    }, delivered_at).unwrap();
    assert_eq!(supervisor.latest_vpn_observation(), Some(&expired));
    let state = &blocked.families["claude"];
    assert_eq!(state.vpn_match, Some(VpnMatch::Stale));
    assert_eq!(state.permit_state, ChannelPermitState::Revoked);
    assert_eq!(state.reason_code, "vpn_observation_stale");
    assert!(state.process_preserved);
    println!("queued refresh renewed at receiver time; a newer but expired sample was retained unchanged and revoked");
}

#[test]
fn v01_v02_v03_v10_vpn_node_mode_or_direct_chain_mismatch_revokes_immediately_without_egress_change_or_warn_exemption() {
    // Configure ALL warn policies to "warn" to prove V10: warn policy NEVER exempts VPN mismatch/unknown/stale
    let (_tmp, _store, _cfg, enforcer, mut supervisor, _rx, proc_tok, now) =
        setup_active_session_and_supervisor(
            |cfg, _exp| {
                for val in cfg.policy_actions.values_mut() {
                    *val = "warn".into();
                }
            },
            |_| {},
        );

    // Establish an active flow while permitted
    let (flow_id, _stream) = enforcer
        .connect_supervised_tcp("claude", &proc_tok, now + 0.1)
        .unwrap();
    assert_eq!(
        enforcer.receipt_for("claude", now + 0.1).unwrap().unwrap().active_flows_count,
        1
    );

    // V01: Node changes from US-West-01 to US-West-02 while egress IP stays identical (1.1.1.1)
    let mut node_changed = sample_vpn_observation(now + 0.5, 2);
    node_changed.selected_node = ObservedField::Known("US-West-02".into());
    node_changed.proxy_chain = ObservedField::Known(vec!["AI-Group".into(), "US-West-02".into()]);
    let snap = supervisor
        .handle_event(SupervisionEvent::VpnObservationUpdated {
            observation: node_changed,
            observed_at: now + 0.5,
        })
        .unwrap();
    assert_eq!(snap.families["claude"].permit_state, ChannelPermitState::Revoked);
    assert_eq!(snap.families["claude"].reason_code, "vpn_expectation_mismatched");
    assert!(snap.families["claude"].process_preserved);

    // New connections must be rejected immediately, and active flow closed
    assert!(enforcer
        .connect_supervised_tcp("claude", &proc_tok, now + 0.51)
        .is_err());
    let _ = flow_id;

    // V02: Running mode changes from rule to direct
    let mut mode_direct = sample_vpn_observation(now + 1.0, 3);
    mode_direct.running_mode = ObservedField::Known("direct".into());
    let snap2 = supervisor
        .handle_event(SupervisionEvent::VpnObservationUpdated {
            observation: mode_direct,
            observed_at: now + 1.0,
        })
        .unwrap();
    assert_eq!(snap2.families["claude"].permit_state, ChannelPermitState::Revoked);
    assert_eq!(snap2.families["claude"].reason_code, "vpn_expectation_mismatched");

    // V03: Proxy chain contains DIRECT hop
    let mut chain_direct = sample_vpn_observation(now + 1.5, 4);
    chain_direct.proxy_chain =
        ObservedField::Known(vec!["AI-Group".into(), "DIRECT".into()]);
    let snap3 = supervisor
        .handle_event(SupervisionEvent::VpnObservationUpdated {
            observation: chain_direct,
            observed_at: now + 1.5,
        })
        .unwrap();
    assert_eq!(snap3.families["claude"].permit_state, ChannelPermitState::Revoked);
    assert_eq!(snap3.families["claude"].reason_code, "vpn_expectation_mismatched");
}

#[test]
fn v04_v05_v06_v07_tun_requirement_socks_only_and_stale_or_unknown_observation_fail_closed() {
    // V04 is already verified in setup (require_tun: None allows tun_enabled: false).
    // Now test V05: require_tun = Some(true) with initial tun_enabled = true, then tun_enabled = false or Unknown -> Revoked
    let (_tmp, _store, _cfg, _enforcer, mut supervisor, _rx, _proc_tok, now) =
        setup_active_session_and_supervisor(
            |_cfg, exp| {
                exp.require_tun = Some(true);
            },
            |obs| {
                obs.tun_enabled = ObservedField::Known(true);
            },
        );
    // Now update with tun_enabled = false -> must revoke
    let obs_tun_false = sample_vpn_observation(now + 0.2, 2);
    let snap = supervisor
        .handle_event(SupervisionEvent::VpnObservationUpdated {
            observation: obs_tun_false,
            observed_at: now + 0.2,
        })
        .unwrap();
    assert_eq!(snap.families["claude"].permit_state, ChannelPermitState::Revoked);
    assert_eq!(snap.families["claude"].reason_code, "vpn_expectation_mismatched");

    let mut obs_tun_unknown = sample_vpn_observation(now + 0.4, 3);
    obs_tun_unknown.tun_enabled = ObservedField::Unknown("tun_probe_unavailable".into());
    let snap_unk = supervisor
        .handle_event(SupervisionEvent::VpnObservationUpdated {
            observation: obs_tun_unknown,
            observed_at: now + 0.4,
        })
        .unwrap();
    assert_eq!(snap_unk.families["claude"].permit_state, ChannelPermitState::Revoked);
    assert_eq!(snap_unk.families["claude"].reason_code, "vpn_observation_unknown");

    // V06: Upstream port is SOCKS-only -> Revoked
    let (_tmp2, _store2, _cfg2, _enforcer2, mut sup2, _rx2, _proc_tok2, now2) =
        setup_active_session_and_supervisor(|_, _| {}, |_| {});
    let mut obs_socks = sample_vpn_observation(now2 + 0.2, 2);
    obs_socks.upstream_protocol = ObservedField::Known(UpstreamProtocol::SocksOnly);
    let snap_socks = sup2
        .handle_event(SupervisionEvent::VpnObservationUpdated {
            observation: obs_socks,
            observed_at: now2 + 0.2,
        })
        .unwrap();
    assert_eq!(snap_socks.families["claude"].permit_state, ChannelPermitState::Revoked);
    assert_eq!(snap_socks.families["claude"].reason_code, "vpn_expectation_mismatched");

    // V07: Observation expires (LeaseExpired past valid_until) or becomes unavailable -> Revoked
    let (_tmp3, _store3, _cfg3, _enforcer3, mut sup3, _rx3, _proc_tok3, now3) =
        setup_active_session_and_supervisor(|_, _| {}, |_| {});
    let snap_stale = sup3
        .handle_event(SupervisionEvent::LeaseExpired {
            observed_at: now3 + 10.0,
            woke_from_sleep: false,
        })
        .unwrap();
    assert_eq!(snap_stale.families["claude"].permit_state, ChannelPermitState::Revoked);
    assert_eq!(snap_stale.families["claude"].reason_code, "vpn_observation_stale");
}

#[test]
fn v08_v09_mid_dial_vpn_epoch_change_aborts_connection_and_recovery_requires_new_epoch_audit() {
    let (_tmp, store, cfg, enforcer, mut supervisor, rx, proc_tok, now) =
        setup_active_session_and_supervisor(|_, _| {}, |_| {});

    // V08: Mid-dial VPN epoch change aborts in-flight dial
    let enforcer_for_hook = enforcer.clone();
    let store_for_hook = store.clone();
    enforcer
        .set_on_dial_hook(move |fam| {
            // Simulate supervisor issuing a new command or VPN epoch changing during dial
            let mut cmd =
                serde_json::from_value::<claude_watch_core::channel::ChannelEnforcementCommand>(
                    store_for_hook
                        .read_json(
                            &store_for_hook
                                .paths
                                .watch()
                                .join(format!("state/channel-command-{fam}.json")),
                            Value::Null,
                        )
                        .unwrap(),
                )
                .unwrap();
            cmd.command_seq += 1;
            cmd.permit.command_seq = cmd.command_seq;
            cmd.permit.vpn_epoch = Some(VpnEpoch::new("vpn-obs-boot-1", 99));
            let _ = enforcer_for_hook.apply_command(&cmd, now + 0.2);
        })
        .unwrap();

    let dial_err = enforcer
        .connect_supervised_tcp("claude", &proc_tok, now + 0.1)
        .unwrap_err();
    assert_eq!(dial_err.code, "channel_changed_during_dial");

    // Clear dial hook for V09 recovery verification
    enforcer.set_on_dial_hook(|_| {}).unwrap();

    // Trigger VPN mismatch at generation 2
    let mut bad_obs = sample_vpn_observation(now + 1.0, 2);
    bad_obs.selected_node = ObservedField::Known("HK-Unexpected".into());
    bad_obs.proxy_chain = ObservedField::Known(vec!["AI-Group".into(), "HK-Unexpected".into()]);
    let revoked_snap = supervisor
        .handle_event(SupervisionEvent::VpnObservationUpdated {
            observation: bad_obs,
            observed_at: now + 1.0,
        })
        .unwrap();
    assert_eq!(revoked_snap.families["claude"].permit_state, ChannelPermitState::Revoked);

    // VPN returns to expected node at generation 3 (with fresh valid_until > now + 7.6)
    let mut restored_obs = sample_vpn_observation(now + 2.0, 3);
    restored_obs.valid_until = now + 20.0;
    let restored_epoch = restored_obs.epoch.clone();
    let pending_recovery = supervisor
        .handle_event(SupervisionEvent::VpnObservationUpdated {
            observation: restored_obs,
            observed_at: now + 2.0,
        })
        .unwrap();
    // V09: Must NOT auto-permit on VPN observation match alone; must wait for fresh recovery audit!
    assert_eq!(
        pending_recovery.families["claude"].permit_state,
        ChannelPermitState::Revoked
    );

    // Drain the latest AsyncAuditRequest and verify it carries the new VpnEpoch (generation 3)
    let mut latest_req = None;
    while let Ok(r) = rx.try_recv() {
        latest_req = Some(r);
    }
    let req = if let Some(r) = latest_req {
        r
    } else {
        // Trigger evaluation with fresh egress for generation 3 so recovery audit is requested
        let mut fresh_eg = controlled_egress(
            &cfg,
            now + 2.1,
            "1.1.1.1",
            "US",
            Some(restored_epoch.clone()),
        );
        fresh_eg["policy_version"] = json!(supervisor.saved_policy_version());
        supervisor
            .handle_event(SupervisionEvent::EnvironmentUpdated {
                egress: fresh_eg,
                local_guard: json!({"proxy": "ok", "tun": "disabled", "context_id": "ctx-vpn"}),
                observed_at: now + 2.1,
            })
            .unwrap();
        rx.recv_timeout(Duration::from_secs(1)).unwrap()
    };
    assert_eq!(req.vpn_epoch, Some(restored_epoch.clone()));

    // Stale audit completion with old VpnEpoch (generation 1) must NOT restore Permit
    let mut stale_egress = controlled_egress(
        &cfg,
        now + 2.2,
        "1.1.1.1",
        "US",
        Some(VpnEpoch::new("vpn-obs-boot-1", 1)),
    );
    stale_egress["policy_version"] = json!(supervisor.saved_policy_version());
    stale_egress["observed_at"] = json!(now + 2.2);
    seed_probe_receipts(&store, now + 2.2, "US");
    let mut audit1 = fixture_audit_val(&store, now + 2.2, "1.1.1.1", "US");
    audit1["policy"] = json!(supervisor.saved_policy_version().policy_digest);
    let after_stale = supervisor
        .handle_event(SupervisionEvent::AsyncAuditCompleted {
            request_id: req.request_id,
            family: req.family.clone(),
            session_id: req.session_id.clone(),
            policy_version: req.policy_version.clone(),
            requested_at: req.requested_at,
            completed_at: now + 2.2,
            outcome: AsyncAuditOutcome::Succeeded {
                audit: audit1,
                egress: stale_egress,
            },
        })
        .unwrap();
    assert_eq!(
        after_stale.families["claude"].permit_state,
        ChannelPermitState::Revoked,
        "audit carrying stale vpn_epoch must be rejected"
    );

    // Trigger another evaluation after backoff (>= 5.0s after stale failure at now + 2.2) to get a fresh audit request for generation 3
    let mut fresh_egress = controlled_egress(
        &cfg,
        now + 7.5,
        "1.1.1.1",
        "US",
        Some(restored_epoch.clone()),
    );
    fresh_egress["policy_version"] = json!(supervisor.saved_policy_version());
    supervisor
        .handle_event(SupervisionEvent::EnvironmentUpdated {
            egress: fresh_egress.clone(),
            local_guard: json!({"proxy": "ok", "tun": "disabled", "context_id": "ctx-vpn"}),
            observed_at: now + 7.5,
        })
        .unwrap();
    let req2 = rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(req2.vpn_epoch, Some(restored_epoch));
    seed_probe_receipts(&store, now + 7.6, "US");
    let mut audit2 = fixture_audit_val(&store, now + 7.6, "1.1.1.1", "US");
    audit2["policy"] = json!(supervisor.saved_policy_version().policy_digest);
    fresh_egress["observed_at"] = json!(now + 7.6);
    let recovered = supervisor
        .handle_event(SupervisionEvent::AsyncAuditCompleted {
            request_id: req2.request_id,
            family: req2.family,
            session_id: req2.session_id,
            policy_version: req2.policy_version,
            requested_at: req2.requested_at,
            completed_at: now + 7.6,
            outcome: AsyncAuditOutcome::Succeeded {
                audit: audit2,
                egress: fresh_egress,
            },
        })
        .unwrap();
    assert_eq!(
        recovered.families["claude"].permit_state,
        ChannelPermitState::Permitted
    );
    assert_eq!(recovered.families["claude"].vpn_match_or_matched(), true);
}

trait FamilyStateTestExt {
    fn vpn_match_or_matched(&self) -> bool;
}
impl FamilyStateTestExt for claude_watch_core::channel::FamilyChannelMonitorState {
    fn vpn_match_or_matched(&self) -> bool {
        matches!(self.vpn_match, Some(VpnMatch::Matched))
    }
}

#[test]
fn f01_f02_f03_gateway_revoke_and_upstream_disconnect_close_active_flows_while_preserving_process() {
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicBool, Ordering};

    let (_tmp, _store, _cfg, enforcer, mut supervisor, _rx, proc_tok, now) =
        setup_active_session_and_supervisor(|_, _| {}, |_| {});

    // Start a real mock upstream proxy listener supporting HTTP, WS upgrade, HTTPS CONNECT, and WSS over CONNECT
    let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (upstream_accepted_tx, upstream_accepted_rx) = mpsc::channel();
    thread::spawn(move || {
        while let Ok((mut s, _)) = upstream_listener.accept() {
            let tx = upstream_accepted_tx.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 1024];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                if req.starts_with("CONNECT ") {
                    let _ = s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                } else if req.contains("Upgrade: websocket") {
                    let _ = s.write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                    );
                } else {
                    let _ = s.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\ndata: ping\n\n",
                    );
                }
                let _ = s.flush();
                let _ = tx.send(s);
            });
        }
    });

    enforcer
        .set_upstream_connector(move |_ep| {
            let s = TcpStream::connect(upstream_addr)?;
            Ok(TunnelStream::Tcp(s))
        })
        .unwrap();
    enforcer.set_clock(move || now + 0.06).unwrap();
    let tok_for_attr = proc_tok.clone();
    enforcer
        .set_accepted_connection_attributor(move |_ctx| {
            Some(("claude".into(), tok_for_attr.clone()))
        })
        .unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let (proxy_addr, proxy_handle) = enforcer
        .start_local_proxy_listener("127.0.0.1:0", stop.clone(), now + 0.06)
        .unwrap();

    // Open 4 live connections through the real gateway:
    // 1. HTTP streaming GET (`http://...`)
    let mut http_client = TcpStream::connect(proxy_addr).unwrap();
    http_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    http_client
        .write_all(
            format!("GET http://{upstream_addr}/v1/stream HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
    let _up_http = upstream_accepted_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    let mut http_initial = [0u8; 256];
    let n_http = http_client.read(&mut http_initial).expect("read http initial");
    assert!(
        n_http > 0 && String::from_utf8_lossy(&http_initial[..n_http]).contains("200 OK"),
        "HTTP stream must be established through gateway"
    );

    // 2. WebSocket Upgrade (`ws://`)
    let mut ws_client = TcpStream::connect(proxy_addr).unwrap();
    ws_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    ws_client
        .write_all(
            format!(
                "GET http://{upstream_addr}/realtime HTTP/1.1\r\nHost: {upstream_addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
    let _up_ws = upstream_accepted_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    let mut ws_initial = [0u8; 256];
    let n_ws = ws_client.read(&mut ws_initial).expect("read ws initial");
    assert!(
        n_ws > 0 && String::from_utf8_lossy(&ws_initial[..n_ws]).contains("101 Switching Protocols"),
        "WS upgrade must be established through gateway"
    );

    // 3. HTTPS CONNECT tunnel (`https://`)
    let mut https_client = TcpStream::connect(proxy_addr).unwrap();
    https_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    https_client
        .write_all(
            format!("CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n").as_bytes(),
        )
        .unwrap();
    let mut up_https = upstream_accepted_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    let mut https_initial = [0u8; 256];
    let n_https = https_client
        .read(&mut https_initial)
        .expect("read https 200");
    assert!(
        n_https > 0 && String::from_utf8_lossy(&https_initial[..n_https]).starts_with("HTTP/1.1 200"),
        "HTTPS CONNECT tunnel must be established"
    );
    https_client.write_all(b"tls-client-hello").unwrap();
    let mut up_buf = [0u8; 64];
    let n_up = up_https.read(&mut up_buf).expect("upstream read tls hello");
    assert_eq!(&up_buf[..n_up], b"tls-client-hello");

    // 4. WSS over CONNECT tunnel (`wss://`)
    let mut wss_client = TcpStream::connect(proxy_addr).unwrap();
    wss_client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    wss_client
        .write_all(
            format!("CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n").as_bytes(),
        )
        .unwrap();
    let mut up_wss = upstream_accepted_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    let mut wss_initial = [0u8; 256];
    let n_wss = wss_client.read(&mut wss_initial).expect("read wss 200");
    assert!(
        n_wss > 0 && String::from_utf8_lossy(&wss_initial[..n_wss]).starts_with("HTTP/1.1 200")
    );
    wss_client.write_all(b"wss-frame-1").unwrap();
    let n_wss_up = up_wss.read(&mut up_buf).expect("upstream read wss frame");
    assert_eq!(&up_buf[..n_wss_up], b"wss-frame-1");

    // F03: Drop `up_wss` (upstream disconnect) while permitted -> `wss_client.read` must return Ok(0) EOF (not timeout!)
    drop(up_wss);
    let mut eof_buf = [0u8; 32];
    let n_wss_eof = wss_client
        .read(&mut eof_buf)
        .expect("upstream drop must propagate clean Ok(0) EOF to client, never timeout");
    assert_eq!(n_wss_eof, 0, "F03: upstream disconnect must yield EOF (0 bytes)");

    // F01 & F02: Trigger VPN node mismatch via Supervisor (`SupervisionEvent::VpnObservationUpdated`).
    // Do NOT call `confirm_flow_terminated` manually! The gateway relay threads must shut down
    // all 3 remaining streams (HTTP, WS, HTTPS) and self-report `confirm_flow_terminated`!
    let mut bad_obs = sample_vpn_observation(now + 0.5, 2);
    bad_obs.selected_node = ObservedField::Known("DE-Unexpected".into());
    bad_obs.proxy_chain = ObservedField::Known(vec!["AI-Group".into(), "DE-Unexpected".into()]);
    let snap = supervisor
        .handle_event(SupervisionEvent::VpnObservationUpdated {
            observation: bad_obs,
            observed_at: now + 0.5,
        })
        .unwrap();
    assert_eq!(snap.families["claude"].permit_state, ChannelPermitState::Revoked);
    assert!(snap.families["claude"].process_preserved);

    // Verify all 3 active client streams receive real Ok(0) EOF (never unwrap_or(0)!)
    let n_http_eof = http_client
        .read(&mut eof_buf)
        .expect("HTTP stream must receive Ok(0) EOF on VPN cutoff, not timeout");
    assert_eq!(n_http_eof, 0);
    let n_ws_eof = ws_client
        .read(&mut eof_buf)
        .expect("WS stream must receive Ok(0) EOF on VPN cutoff, not timeout");
    assert_eq!(n_ws_eof, 0);
    let n_https_eof = https_client
        .read(&mut eof_buf)
        .expect("HTTPS CONNECT stream must receive Ok(0) EOF on VPN cutoff, not timeout");
    assert_eq!(n_https_eof, 0);

    // Wait briefly for relay threads to finish `confirm_flow_terminated` automatically
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let final_receipt = loop {
        let r = enforcer.receipt_for("claude", now + 0.6).unwrap().unwrap();
        if r.enforcement_state == ChannelEnforcementState::Blocked && r.active_flows_count == 0 {
            break r;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "gateway relay threads did not automatically transition receipt to Blocked: {r:?}"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(final_receipt.enforcement_state, ChannelEnforcementState::Blocked);
    assert_eq!(final_receipt.active_flows_count, 0);
    assert!(final_receipt.terminated_flows_count >= 4);
    assert!(final_receipt.new_connections_blocked);
    assert!(final_receipt.active_flows_closed);

    // Feed the real Blocked receipt back into Supervisor and verify display_state becomes Blocked (`已阻断`)
    let blocked_snap = supervisor
        .handle_event(SupervisionEvent::EnforcementReceiptArrived {
            receipt: final_receipt,
            received_at: now + 0.65,
        })
        .unwrap();
    assert_eq!(
        blocked_snap.families["claude"].display_state,
        claude_watch_core::channel::ChannelMonitorDisplayState::Blocked
    );

    stop.store(true, Ordering::Release);
    let _ = proxy_handle.join();
}

#[test]
fn v08_supervisor_rejects_stale_observer_boot_out_of_order_seq_and_aba_revision_invalidates_slow_audit() {
    let (_tmp, store, cfg, _enforcer, mut supervisor, rx, _proc_tok, now) =
        setup_active_session_and_supervisor(|_, _| {}, |_| {});

    // 1. Advance to sample_seq=5, change_generation=1 (same epoch as initial egress so channel stays Permitted)
    let mut obs_seq5 = sample_vpn_observation(now + 0.2, 1);
    obs_seq5.sample_seq = 5;
    obs_seq5.source_revision = Some("rev-1".into());
    let snap_seq5 = supervisor
        .handle_event(SupervisionEvent::VpnObservationUpdated {
            observation: obs_seq5,
            observed_at: now + 0.2,
        })
        .unwrap();
    assert_eq!(snap_seq5.families["claude"].permit_state, ChannelPermitState::Permitted);

    // 2. Out-of-order sample_seq (sample_seq=4) with rogue node must be ignored by Supervisor!
    let mut stale_seq = sample_vpn_observation(now + 0.3, 1);
    stale_seq.sample_seq = 4;
    stale_seq.selected_node = ObservedField::Known("CN-Stale".into());
    let snap_after_stale_seq = supervisor
        .handle_event(SupervisionEvent::VpnObservationUpdated {
            observation: stale_seq,
            observed_at: now + 0.3,
        })
        .unwrap();
    assert_eq!(
        snap_after_stale_seq.families["claude"].permit_state,
        ChannelPermitState::Permitted,
        "out-of-order sample_seq must be ignored"
    );

    // 3. Stale observer_boot_id with rogue node must be ignored!
    let mut old_boot = sample_vpn_observation(now + 0.4, 1);
    old_boot.sample_seq = 6;
    old_boot.epoch = VpnEpoch::new("old-observer-boot", 1);
    old_boot.selected_node = ObservedField::Known("CN-OldBoot".into());
    let snap_after_old_boot = supervisor
        .handle_event(SupervisionEvent::VpnObservationUpdated {
            observation: old_boot,
            observed_at: now + 0.4,
        })
        .unwrap();
    assert_eq!(
        snap_after_old_boot.families["claude"].permit_state,
        ChannelPermitState::Permitted,
        "stale observer_boot_id must be ignored"
    );

    // 4. EnvironmentUpdated WITHOUT `vpn_epoch` when VPN supervision is enabled must be rejected!
    let eg_missing_epoch = controlled_egress(&cfg, now + 0.5, "1.1.1.1", "US", None);
    let snap_missing_epoch = supervisor
        .handle_event(SupervisionEvent::EnvironmentUpdated {
            egress: eg_missing_epoch,
            local_guard: json!({"proxy": "ok", "tun": "disabled", "context_id": "ctx-vpn"}),
            observed_at: now + 0.5,
        })
        .unwrap();
    assert_eq!(
        snap_missing_epoch.families["claude"].permit_state,
        ChannelPermitState::Revoked,
        "controlled path evidence missing vpn_epoch must revoke when VPN supervision is active"
    );

    // 5. V08: Advance to generation 2 (`rev-2`), request recovery audit at generation 2,
    //    then simulate A->B->A where VPN returns to A with `source_revision = "rev-4"` (`change_generation = 4`),
    //    invalidating the slow audit from generation 2!
    let mut obs_g2 = sample_vpn_observation(now + 0.55, 2);
    obs_g2.sample_seq = 6;
    obs_g2.source_revision = Some("rev-2".into());
    supervisor
        .handle_event(SupervisionEvent::VpnObservationUpdated {
            observation: obs_g2,
            observed_at: now + 0.55,
        })
        .unwrap();
    let mut eg_g2 = controlled_egress(
        &cfg,
        now + 0.6,
        "1.1.1.1",
        "US",
        Some(VpnEpoch::new("vpn-obs-boot-1", 2)),
    );
    eg_g2["policy_version"] = json!(supervisor.saved_policy_version());
    supervisor
        .handle_event(SupervisionEvent::EnvironmentUpdated {
            egress: eg_g2.clone(),
            local_guard: json!({"proxy": "ok", "tun": "disabled", "context_id": "ctx-vpn"}),
            observed_at: now + 0.6,
        })
        .unwrap();
    let mut audit_req_g2 = None;
    while let Ok(r) = rx.try_recv() {
        audit_req_g2 = Some(r);
    }
    let audit_req_g2 = audit_req_g2.expect("audit request at generation 2");
    assert_eq!(
        audit_req_g2.vpn_epoch,
        Some(VpnEpoch::new("vpn-obs-boot-1", 2))
    );

    // While slow audit is running, VPN switches A -> B -> A: `source_revision` is now `"rev-4"`, `change_generation = 4`
    let mut obs_aba = sample_vpn_observation(now + 0.7, 4);
    obs_aba.sample_seq = 7;
    obs_aba.source_revision = Some("rev-4".into());
    supervisor
        .handle_event(SupervisionEvent::VpnObservationUpdated {
            observation: obs_aba,
            observed_at: now + 0.7,
        })
        .unwrap();

    // Now the slow audit from generation 2 completes (even if its egress claims generation 2 or has no epoch) -> MUST be rejected!
    seed_probe_receipts(&store, now + 0.8, "US");
    let mut audit_val = fixture_audit_val(&store, now + 0.8, "1.1.1.1", "US");
    audit_val["policy"] = json!(supervisor.saved_policy_version().policy_digest);
    let after_aba_audit = supervisor
        .handle_event(SupervisionEvent::AsyncAuditCompleted {
            request_id: audit_req_g2.request_id,
            family: audit_req_g2.family,
            session_id: audit_req_g2.session_id,
            policy_version: audit_req_g2.policy_version,
            requested_at: audit_req_g2.requested_at,
            completed_at: now + 0.8,
            outcome: AsyncAuditOutcome::Succeeded {
                audit: audit_val,
                egress: eg_g2,
            },
        })
        .unwrap();
    assert_eq!(
        after_aba_audit.families["claude"].permit_state,
        ChannelPermitState::Revoked,
        "V08: slow audit started before A->B->A epoch advance must not re-authorize the channel"
    );
}

#[test]
fn r1_r2_seatbelt_missing_vpn_expectation_corrupt_config_or_legacy_migration_fails_closed() {
    fn make_local_store(prefix: &str) -> (TempRoot, StateStore) {
        let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let store = StateStore::new(Paths::new(&dir).unwrap());
        (TempRoot(dir), store)
    }
    fn local_member(pid: u32) -> (String, BoundProcessToken) {
        (
            "claude".into(),
            BoundProcessToken::with_system_identity(pid, 501, 1000, 1, ProcessRole::DesktopMain),
        )
    }

    // 1. Fresh install without `config.json`: resolves `Seatbelt` uniformly in ConfigStore and ChannelSupervisor,
    //    and because `vpn_expectation` is unconfigured (`None`), Seatbelt VPN gate returns Unknown("vpn_expectation_unconfigured")
    //    and refuses to grant Permitted even if egress/audit are clean!
    let (_tmp1, store1) = make_local_store("cw-r1-fresh");
    let cfg_store1 = ConfigStore {
        storage: store1.clone(),
    };
    let resolved_fresh = cfg_store1.resolve_runtime_config_state(Some(NetworkBackendKind::Seatbelt));
    assert_eq!(
        resolved_fresh.config.effective_network_backend(),
        NetworkBackendKind::Seatbelt
    );
    assert!(resolved_fresh.blocking_reason().is_none());

    let enforcer1: Arc<dyn ChannelEnforcer> =
        Arc::new(LocalTunnelEnforcer::new("boot-r1-fresh", Some(store1.clone())));
    let (tx1, _rx1) = mpsc::channel();
    let mut sup1 = ChannelSupervisor::new_with_config(
        store1.clone(),
        resolved_fresh.config.clone(),
        resolved_fresh.blocking_reason(),
        Some(enforcer1),
        Some(tx1),
    )
    .unwrap();
    let snap1 = sup1
        .handle_event(SupervisionEvent::ProcessInventoryUpdated {
            family: "claude".into(),
            desktops: vec![(
                Desktop {
                    pid: 7001,
                    start_seconds: 1000,
                    start_microseconds: 1,
                },
                true,
                "Claude.app".into(),
            )],
            processes: vec![local_member(7001).1],
            observed_at: 1_700_000_000.0,
        })
        .unwrap();
    assert_eq!(
        sup1.latest_vpn_match(),
        Some(&VpnMatch::Unknown {
            reasons: vec!["vpn_expectation_unconfigured".into()]
        })
    );
    assert_ne!(
        snap1.families["claude"].permit_state,
        ChannelPermitState::Permitted,
        "Seatbelt mode without configured vpn_expectation must never grant Permitted"
    );

    // 2. Corrupt `config.json`: resolve_runtime_config_state reports `config_error`,
    //    and `ChannelSupervisor::new` fails closed (never falls back to unrestricted default).
    let (_tmp2, store2) = make_local_store("cw-r1-corrupt");
    std::fs::create_dir_all(store2.paths.config().parent().unwrap()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            store2.paths.config().parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    std::fs::write(store2.paths.config(), b"{corrupt json").unwrap();
    let cfg_store2 = ConfigStore {
        storage: store2.clone(),
    };
    let resolved_corrupt =
        cfg_store2.resolve_runtime_config_state(Some(NetworkBackendKind::Seatbelt));
    assert!(
        resolved_corrupt
            .blocking_reason()
            .as_deref()
            .is_some_and(|r| r.starts_with("config_invalid:")),
        "corrupt config.json must produce config_invalid blocking reason"
    );
    let enforcer2: Arc<dyn ChannelEnforcer> =
        Arc::new(LocalTunnelEnforcer::new("boot-r1-corrupt", Some(store2.clone())));
    let (tx2, _rx2) = mpsc::channel();
    let mut sup2 = ChannelSupervisor::new(store2.clone(), Some(enforcer2), Some(tx2)).unwrap();
    let snap2 = sup2
        .handle_event(SupervisionEvent::ProcessInventoryUpdated {
            family: "claude".into(),
            desktops: vec![(
                Desktop {
                    pid: 7002,
                    start_seconds: 1000,
                    start_microseconds: 1,
                },
                true,
                "Claude.app".into(),
            )],
            processes: vec![local_member(7002).1],
            observed_at: 1_700_000_000.0,
        })
        .unwrap();
    assert_ne!(
        snap2.families["claude"].permit_state,
        ChannelPermitState::Permitted,
        "corrupt config.json must hold permits blocked"
    );

    // 3. Legacy `schema: 1` without `network_backend`: requires explicit migration confirmation.
    let (_tmp3, store3) = make_local_store("cw-r1-legacy");
    std::fs::create_dir_all(store3.paths.config().parent().unwrap()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            store3.paths.config().parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    std::fs::write(
        store3.paths.config(),
        serde_json::to_vec(&json!({
            "schema": 1,
            "enabled": true,
            "guard_enabled": true,
            "proxy_mode": "tag",
            "proxy_url": "http://127.0.0.1:7890"
        }))
        .unwrap(),
    )
    .unwrap();
    let cfg_store3 = ConfigStore {
        storage: store3.clone(),
    };
    let resolved_legacy =
        cfg_store3.resolve_runtime_config_state(Some(NetworkBackendKind::Seatbelt));
    assert!(resolved_legacy.legacy_migration_required);
    assert_eq!(
        resolved_legacy.blocking_reason().as_deref(),
        Some("legacy_config_migration_required")
    );

    // 4. Explicit retired backend is retained for migration, never executed.
    let (_tmp4, store4) = make_local_store("cw-r1-mismatch");
    std::fs::create_dir_all(store4.paths.config().parent().unwrap()).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            store4.paths.config().parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    std::fs::write(
        store4.paths.config(),
        serde_json::to_vec(&json!({
            "schema": 2,
            "network_backend": "network_extension"
        }))
        .unwrap(),
    )
    .unwrap();
    let cfg_store4 = ConfigStore {
        storage: store4.clone(),
    };
    let resolved_mismatch =
        cfg_store4.resolve_runtime_config_state(Some(NetworkBackendKind::Seatbelt));
    assert!(resolved_mismatch.legacy_migration_required);
    assert_eq!(
        resolved_mismatch.blocking_reason().as_deref(),
        Some("legacy_config_migration_required")
    );
}

// F02/F03 intentionally test the actual helper/apply/exec and enforcer lifecycle below
// the blocked production I03 dispatch gate. They do not certify backend enablement.
#[test]
fn f02_f03_gateway_process_crash_preserves_target_for_5s_and_stalled_supervisor_lease_expiry_cuts_off_in_enforcer()
 {
    use claude_watch_core::{
        channel::{ChannelEnforcementCommand, ChannelPermit, PolicyVersion},
        controlled_launch::{ControlledLaunchRequest, ProxyAdaptationKind},
        processes::LaunchTarget,
    };
    use claude_watch_runtime::sandbox_launch::{
        SandboxLaunchRegistry, build_helper_verifier_from_manifest,
    };
    use claude_watch_system::{effective_uid, inspect_process_identity, sha256_file_hex};
    use std::{
        io::{BufRead, BufReader},
        net::{SocketAddr, TcpStream},
        process::{Child, Command, Stdio},
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
        time::Instant,
    };
    const TEST: &str = "f02_f03_gateway_process_crash_preserves_target_for_5s_and_stalled_supervisor_lease_expiry_cuts_off_in_enforcer";
    fn assert_same_lifetime(
        current: &claude_watch_system::ProcessKernelIdentity,
        original: &claude_watch_system::ProcessKernelIdentity,
    ) {
        // Parent death legitimately reparents the surviving target; PPID is not its identity.
        assert_eq!(
            (
                current.pid,
                current.uid,
                current.start_seconds,
                current.start_microseconds
            ),
            (
                original.pid,
                original.uid,
                original.start_seconds,
                original.start_microseconds
            )
        );
        assert_eq!(current.executable_path, original.executable_path);
        assert_eq!(current.audit_token, original.audit_token);
    }
    fn write_line(line: &str) {
        // With --test-threads=1 libtest prints `test name ... ` without a
        // newline before entering this child. Keep its protocol on its own
        // line so the parent's exact prefix parser cannot lose READY.
        println!("\n{line}");
        std::io::stdout().flush().unwrap();
    }
    fn read_header_result(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut b = [0];
        loop {
            stream.read_exact(&mut b)?;
            bytes.push(b[0]);
            if bytes.ends_with(b"\r\n\r\n") {
                return Ok(bytes);
            }
            assert!(bytes.len() < 16384);
        }
    }
    fn read_header(stream: &mut TcpStream) -> Vec<u8> {
        read_header_result(stream).expect("complete response header, not timeout")
    }
    fn lines(child: &mut Child) -> mpsc::Receiver<String> {
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        rx
    }
    fn await_line(rx: &mpsc::Receiver<String>, prefix: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let line = rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|e| panic!("missing {prefix}: {e}"));
            if line.starts_with(prefix) {
                return line;
            }
        }
    }
    let role = std::env::var("CW_FAULT_ROLE").unwrap_or_default();
    if role == "ordinary" {
        let upstream: SocketAddr = std::env::var("CW_FAULT_UPSTREAM").unwrap().parse().unwrap();
        write_line(&format!(
            "ORDINARY_READY {} {}",
            std::process::id(),
            effective_uid()
        ));
        for line in std::io::stdin().lock().lines() {
            let line = line.unwrap();
            if line == "QUIT" {
                break;
            }
            let mut s = TcpStream::connect_timeout(&upstream, Duration::from_secs(1)).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            s.write_all(line.as_bytes()).unwrap();
            let mut got = vec![0; line.len()];
            s.read_exact(&mut got).unwrap();
            assert_eq!(got, line.as_bytes());
            write_line(&format!("ORDINARY_PONG {line}"));
        }
        return;
    }
    if role == "target" {
        let root = PathBuf::from(std::env::var("CW_FAULT_ROOT").unwrap());
        let upstream: SocketAddr = std::env::var("CW_FAULT_UPSTREAM").unwrap().parse().unwrap();
        let gateway: SocketAddr = std::env::var("HTTP_PROXY")
            .unwrap()
            .trim_start_matches("http://")
            .parse()
            .unwrap();
        assert_eq!(std::env::var("CW_CONTROLLED_SANDBOX").unwrap(), "1");
        let id = inspect_process_identity(std::process::id()).unwrap();
        fs::write(root.join("target-identity.json"), serde_json::to_vec(&json!({
            "pid":id.pid,"uid":id.uid,"start_seconds":id.start_seconds,"start_microseconds":id.start_microseconds
        })).unwrap()).unwrap();
        let until = Instant::now() + Duration::from_secs(8);
        while !root.join("permit-ready").exists() {
            assert!(Instant::now() < until);
            thread::sleep(Duration::from_millis(10));
        }
        let mut stream = TcpStream::connect(gateway).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .write_all(
                format!("CONNECT {upstream} HTTP/1.1\r\nHost: {upstream}\r\n\r\n").as_bytes(),
            )
            .unwrap();
        assert!(
            String::from_utf8(read_header(&mut stream))
                .unwrap()
                .starts_with("HTTP/1.1 200")
        );
        stream.write_all(b"before-cutoff").unwrap();
        let mut echo = [0; 13];
        stream.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"before-cutoff");
        write_line(&format!(
            "TARGET_READY {} {} {} {}",
            id.pid, id.uid, id.start_seconds, id.start_microseconds
        ));
        let mut b = [0; 1];
        match stream.read(&mut b) {
            Ok(0) => write_line("CUTOFF EOF"),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => write_line("CUTOFF RESET"),
            other => panic!("cutoff must be EOF/reset, never timeout/error-as-zero: {other:?}"),
        }
        let host_crashed = std::env::var("CW_FAULT_MODE").as_deref() == Ok("host_crash");
        for _ in 0..10 {
            match TcpStream::connect_timeout(&gateway, Duration::from_secs(1)) {
                Ok(mut reconnect) => {
                    reconnect
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let response = reconnect
                        .write_all(
                            format!("CONNECT {upstream} HTTP/1.1\r\nHost: {upstream}\r\n\r\n")
                                .as_bytes(),
                        )
                        .and_then(|_| read_header_result(&mut reconnect));
                    match response {
                        Ok(bytes) => {
                            let reply = String::from_utf8(bytes).unwrap();
                            assert!(
                                reply.starts_with("HTTP/1.1 502")
                                    || reply.starts_with("HTTP/1.1 403"),
                                "reconnect unexpectedly permitted: {reply}"
                            );
                        }
                        // A connect racing the crashed host's TCP backlog can complete then
                        // reset/close. These are explicit transport rejection, never a timeout.
                        Err(e)
                            if host_crashed
                                && matches!(
                                    e.kind(),
                                    std::io::ErrorKind::ConnectionReset
                                        | std::io::ErrorKind::BrokenPipe
                                        | std::io::ErrorKind::UnexpectedEof
                                ) => {}
                        Err(e) => panic!("reconnect rejection not proven: {e}"),
                    }
                }
                Err(e) => assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionRefused,
                    "only closed listener proves crash rejection"
                ),
            }
        }
        let direct = TcpStream::connect_timeout(&upstream, Duration::from_millis(500));
        assert!(
            direct.is_err(),
            "sandboxed target must not fall back directly"
        );
        write_line("RECONNECTS_REJECTED 10 DIRECT_BLOCKED");
        for line in std::io::stdin().lock().lines() {
            let line = line.unwrap();
            if line == "QUIT" {
                break;
            }
            let current = inspect_process_identity(id.pid).unwrap();
            assert_same_lifetime(&current, &id);
            write_line(&format!("TARGET_PONG {line}"));
        }
        return;
    }
    if role == "host" {
        let root = PathBuf::from(std::env::var("CW_FAULT_ROOT").unwrap());
        let upstream: SocketAddr = std::env::var("CW_FAULT_UPSTREAM").unwrap().parse().unwrap();
        let exe = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let launcher = exe
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("watch-sandbox-launcher");
        assert!(
            launcher.is_file(),
            "build production helper beside integration tests before F02/F03"
        );
        let launcher = hardened_helper::copy_signed(&launcher, &root.join("watch-sandbox-launcher"));
        fs::create_dir_all(root.join("manifest")).unwrap();
        fs::write(
            root.join("manifest/components.json"),
            hardened_helper::components(&launcher).to_string(),
        )
        .unwrap();
        let verifier =
            build_helper_verifier_from_manifest(&root.join("manifest"), &launcher).unwrap();
        let pv = PolicyVersion {
            policy_digest: "fault-component".into(),
            guard_policy_digest: "fault-guard".into(),
        };
        let boot = "fault-component-boot";
        let now = 1_720_010_000.0;
        let store = StateStore::new(Paths::new(&root).unwrap());
        let registry = Arc::new(SandboxLaunchRegistry::new(
            boot,
            pv.clone(),
            verifier,
            Some(store.clone()),
        ));
        registry.approve_target_executable(exe.to_string_lossy(), sha256_file_hex(&exe).unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let socket = root.join("reg.sock");
        let registration = registry
            .start_registration_listener(&socket, stop.clone())
            .unwrap();
        let enforcer = Arc::new(LocalTunnelEnforcer::new(boot, Some(store)));
        // Component-only capability injection. The production identity-report gate is not
        // changed or supplied with a fabricated authentication success.
        enforcer.configure_seatbelt_backend(true, now).unwrap();
        let clock = Arc::new(AtomicU64::new((now * 1000.0) as u64));
        let read_clock = clock.clone();
        enforcer
            .set_clock(move || read_clock.load(Ordering::Acquire) as f64 / 1000.0)
            .unwrap();
        let reg = registry.clone();
        enforcer
            .set_accepted_connection_attributor(move |ctx| {
                reg.attribute_accepted_connection(ctx, now + 1.0)
            })
            .unwrap();
        enforcer
            .set_upstream_connector(move |_| Ok(TunnelStream::Tcp(TcpStream::connect(upstream)?)))
            .unwrap();
        let receipt_path = root.join("receipt.json");
        enforcer
            .set_receipt_event_sink(move |receipt| {
                let tmp = receipt_path.with_extension("tmp");
                if fs::write(&tmp, serde_json::to_vec(&receipt).unwrap()).is_ok() {
                    let _ = fs::rename(&tmp, &receipt_path);
                }
            })
            .unwrap();
        let (gateway, listener) = enforcer
            .start_local_proxy_listener("127.0.0.1:0", stop.clone(), now)
            .unwrap();
        let read_clock = clock.clone();
        let watchdog = enforcer
            .spawn_lease_watchdog(
                stop.clone(),
                Duration::from_millis(25),
                move || read_clock.load(Ordering::Acquire) as f64 / 1000.0,
                |_| {},
            )
            .unwrap();
        let req = ControlledLaunchRequest {
            entry_id: "io.local.watchpanel.entry.claude-cli".into(),
            target: LaunchTarget::ClaudeCli,
            target_executable: exe.to_string_lossy().into_owned(),
            target_fingerprint: sha256_file_hex(&exe).unwrap(),
            args: vec!["--exact".into(), TEST.into(), "--nocapture".into()],
            cwd: Some(root.to_string_lossy().into_owned()),
            proxy_adaptation: ProxyAdaptationKind::EnvOnly,
            gateway_endpoint: gateway.to_string(),
            policy_version: pv.clone(),
            vpn_epoch: Some(VpnEpoch::new("fault-vpn", 1)),
            launch_nonce: uuid::Uuid::new_v4().to_string(),
            executor_boot_id: boot.into(),
            script_entry: None,
            script_fingerprint: None,
            interpreter: None,
            interpreter_fingerprint: None,
            script_source: None,
        };
        // Production helper owns apply -> verified registration -> exec. Standard streams
        // inherit through the host; killing that host must not close the child's copies.
        let mut target = Command::new(&launcher)
            .arg("--launch-json")
            .arg(serde_json::to_string(&req).unwrap())
            .arg("--registration-socket")
            .arg(&socket)
            .arg("--deny-port")
            .arg(upstream.port().to_string())
            .env("CW_FAULT_ROLE", "target")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        let token = loop {
            let found = registry
                .verified_family_tokens("claude", now + 0.5)
                .into_iter()
                .find(|t| t.pid == target.id());
            if let Some(tok) = found {
                break tok;
            }
            assert!(
                target.try_wait().unwrap().is_none(),
                "helper/target failed before registration"
            );
            assert!(Instant::now() < deadline, "target was not exec verified");
            thread::sleep(Duration::from_millis(10));
        };
        let permit = ChannelPermit {
            family: "claude".into(),
            session_id: Some("fault-component".into()),
            policy_version: pv.clone(),
            permit_generation: 1,
            command_seq: 1,
            state: ChannelPermitState::Permitted,
            reason_code: "component_fixture".into(),
            issued_at: now,
            valid_until: now + 60.0,
            context_id: Some("fixture".into()),
            baseline_ip: Some("1.1.1.1".into()),
            members: vec![Desktop {
                pid: token.pid,
                start_seconds: token.start_seconds,
                start_microseconds: token.start_microseconds,
            }],
            backend: NetworkBackendKind::Seatbelt,
            vpn_epoch: Some(VpnEpoch::new("fault-vpn", 1)),
            coverage_scope: None,
        };
        enforcer
            .apply_command(
                &ChannelEnforcementCommand {
                    family: permit.family.clone(),
                    session_id: permit.session_id.clone(),
                    policy_version: pv,
                    permit_generation: 1,
                    command_seq: 1,
                    permit,
                    allowed_processes: vec![token],
                    upstream_endpoint: upstream.to_string(),
                    target_executor_boot_id: Some(boot.into()),
                    issued_at: now,
                },
                now,
            )
            .unwrap();
        fs::write(root.join("permit-ready"), b"ready").unwrap();
        while target.try_wait().unwrap().is_none() {
            if root.join("expire-lease").exists() {
                clock.store(((now + 61.0) * 1000.0) as u64, Ordering::Release);
            }
            thread::sleep(Duration::from_millis(10));
        }
        stop.store(true, Ordering::Release);
        watchdog.join().unwrap();
        listener.join().unwrap();
        registration.join().unwrap();
        return;
    }
    struct Children {
        host: Child,
        ordinary: Child,
        identity: PathBuf,
    }
    impl Drop for Children {
        fn drop(&mut self) {
            // Only this fixture's recorded UID/PID/birth tuple is eligible for cleanup.
            if let Ok(bytes) = fs::read(&self.identity) {
                if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                    if let Some(id) = v["pid"]
                        .as_u64()
                        .and_then(|pid| inspect_process_identity(pid as u32))
                    {
                        if id.uid == effective_uid()
                            && v["uid"] == id.uid
                            && v["start_seconds"] == id.start_seconds
                            && v["start_microseconds"] == id.start_microseconds
                        {
                            unsafe {
                                libc::kill(id.pid as i32, libc::SIGTERM);
                            }
                        }
                    }
                }
            }
            let _ = self.host.kill();
            let _ = self.host.wait();
            let _ = self.ordinary.kill();
            let _ = self.ordinary.wait();
        }
    }
    for fault in ["host_crash", "stalled_authority"] {
        let dir = PathBuf::from("/tmp").join(format!(
            "cw-fault-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        fs::create_dir_all(&dir).unwrap();
        let tmp = TempRoot(dir);
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        upstream.set_nonblocking(true).unwrap();
        let echo_stop = Arc::new(AtomicBool::new(false));
        let echo_quit = echo_stop.clone();
        let echo_thread = thread::spawn(move || {
            while !echo_quit.load(Ordering::Acquire) {
                match upstream.accept() {
                    Ok((mut s, _)) => {
                        // macOS inherits the polling listener's O_NONBLOCK.
                        // A partially delivered echo must wait for its bytes.
                        s.set_nonblocking(false).unwrap();
                        thread::spawn(move || {
                            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                            let mut first = [0; 1];
                            if s.read_exact(&mut first).is_err() {
                                return;
                            }
                            if first[0] == b'C' {
                                let mut h = vec![first[0]];
                                let mut b = [0];
                                while !h.ends_with(b"\r\n\r\n") {
                                    if s.read_exact(&mut b).is_err() {
                                        return;
                                    }
                                    h.push(b[0]);
                                }
                                s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                                    .unwrap();
                            } else {
                                s.write_all(&first).unwrap();
                            }
                            s.set_read_timeout(None).unwrap();
                            let mut b = [0; 512];
                            loop {
                                match s.read(&mut b) {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if s.write_all(&b[..n]).is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("echo accept: {e}"),
                }
            }
        });
        let exe = std::env::current_exe().unwrap();
        let spawn_role = |role: &str| {
            Command::new(&exe)
                .args(["--exact", TEST, "--nocapture"])
                .env("CW_FAULT_ROLE", role)
                .env("CW_FAULT_MODE", fault)
                .env("CW_FAULT_ROOT", &tmp.0)
                .env("CW_FAULT_UPSTREAM", upstream_addr.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap()
        };
        let mut children = Children {
            host: spawn_role("host"),
            ordinary: spawn_role("ordinary"),
            identity: tmp.0.join("target-identity.json"),
        };
        // Keep the inherited target pipe independently of Child::wait(), which otherwise
        // drops the host stdin handle as part of reaping the killed host.
        let mut target_input = children.host.stdin.take().unwrap();
        let host_lines = lines(&mut children.host);
        let ordinary_lines = lines(&mut children.ordinary);
        let ordinary_ready = await_line(&ordinary_lines, "ORDINARY_READY ");
        assert!(ordinary_ready.ends_with(&format!(" {}", effective_uid())));
        let ready = await_line(&host_lines, "TARGET_READY ");
        let fields: Vec<_> = ready.split_whitespace().collect();
        let target_pid: u32 = fields[1].parse().unwrap();
        let original = inspect_process_identity(target_pid).unwrap();
        assert_eq!(original.uid, effective_uid());
        writeln!(
            children.ordinary.stdin.as_mut().unwrap(),
            "positive-control"
        )
        .unwrap();
        assert_eq!(
            await_line(&ordinary_lines, "ORDINARY_PONG "),
            "ORDINARY_PONG positive-control"
        );
        let fault_at = Instant::now();
        if fault == "host_crash" {
            children.host.kill().unwrap();
            children.host.wait().unwrap();
        } else {
            fs::write(
                tmp.0.join("expire-lease"),
                b"advance fixture clock; no new permits",
            )
            .unwrap();
        }
        let cutoff = await_line(&host_lines, "CUTOFF ");
        assert!(cutoff == "CUTOFF EOF" || cutoff == "CUTOFF RESET");
        assert_eq!(
            await_line(&host_lines, "RECONNECTS_REJECTED "),
            "RECONNECTS_REJECTED 10 DIRECT_BLOCKED"
        );
        // Reconnection attribution can take time; that must not consume the separate
        // five-second responsiveness proof. The cutoff itself retains the read deadline.
        let responsive_since = Instant::now();
        let mut replies = 0;
        while responsive_since.elapsed() < Duration::from_millis(5200) {
            let seq = format!("ping-{replies}");
            writeln!(target_input, "{seq}").unwrap();
            writeln!(children.ordinary.stdin.as_mut().unwrap(), "{seq}").unwrap();
            assert_eq!(
                await_line(&host_lines, "TARGET_PONG "),
                format!("TARGET_PONG {seq}")
            );
            assert_eq!(
                await_line(&ordinary_lines, "ORDINARY_PONG "),
                format!("ORDINARY_PONG {seq}")
            );
            assert_same_lifetime(&inspect_process_identity(target_pid).unwrap(), &original);
            replies += 1;
            thread::sleep(Duration::from_millis(100));
        }
        assert!(
            replies >= 10,
            "target/control must repeatedly respond after cutoff"
        );
        if fault == "stalled_authority" {
            let receipt: Value =
                serde_json::from_slice(&fs::read(tmp.0.join("receipt.json")).unwrap()).unwrap();
            assert_eq!(receipt["new_connections_blocked"], true);
            assert_eq!(receipt["active_flows_closed"], true);
            assert_eq!(receipt["active_flows_count"], 0);
        }
        println!(
            "COMPONENT_ONLY {fault}: {cutoff}, target={target_pid}, responsive_replies={replies}, ordinary_control=ok, elapsed_ms={}",
            fault_at.elapsed().as_millis()
        );
        writeln!(target_input, "QUIT").unwrap();
        writeln!(children.ordinary.stdin.as_mut().unwrap(), "QUIT").unwrap();
        children.ordinary.wait().unwrap();
        if fault != "host_crash" {
            assert!(children.host.wait().unwrap().success());
        }
        drop(children);
        echo_stop.store(true, Ordering::Release);
        echo_thread.join().unwrap();
    }
}

/// Actual helper -> sandboxed parent -> inherited child. This exercises the R3
/// registry/permit lifecycle, not the still-blocked production I03 dispatcher.
#[test]
fn r3_verified_orphan_child_retains_gateway_permission_and_survives_revocation() {
    use claude_watch_core::{
        channel::{ChannelEnforcementCommand, ChannelPermit, PolicyVersion},
        controlled_launch::{ControlledLaunchRequest, ProxyAdaptationKind},
        processes::LaunchTarget,
    };
    use claude_watch_runtime::sandbox_launch::{
        SandboxLaunchRegistry, build_helper_verifier_from_manifest,
    };
    use claude_watch_system::{effective_uid, inspect_process_identity, sha256_file_hex};
    use std::{
        io::{BufRead, BufReader},
        net::{SocketAddr, TcpStream},
        process::{Command, Stdio},
        sync::atomic::{AtomicBool, Ordering},
        time::Instant,
    };
    const TEST: &str =
        "r3_verified_orphan_child_retains_gateway_permission_and_survives_revocation";
    fn say(s: &str) {
        println!("{s}");
        std::io::stdout().flush().unwrap();
    }
    fn wait_file(path: &std::path::Path) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !path.exists() {
            assert!(
                Instant::now() < deadline,
                "missing fixture marker {}",
                path.display()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn header(s: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut b = [0];
        loop {
            s.read_exact(&mut b)
                .expect("complete HTTP response, not timeout");
            bytes.push(b[0]);
            if bytes.ends_with(b"\r\n\r\n") {
                return String::from_utf8(bytes).unwrap();
            }
            assert!(bytes.len() < 16384);
        }
    }
    let role = std::env::var("CW_R3_ROLE").unwrap_or_default();
    if role == "parent" {
        assert_eq!(std::env::var("CW_CONTROLLED_SANDBOX").unwrap(), "1");
        let root = PathBuf::from(std::env::var("CW_R3_ROOT").unwrap());
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("CW_R3_ROLE", "child")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        // Keeping Child does not add a supervisor-kill fallback. Normal parent exit is the
        // event being verified; the already sandboxed child retains inherited stdio.
        fs::write(root.join("spawned-child"), child.id().to_string()).unwrap();
        wait_file(&root.join("parent-may-exit"));
        return;
    }
    if role == "child" {
        let root = PathBuf::from(std::env::var("CW_R3_ROOT").unwrap());
        let upstream: SocketAddr = std::env::var("CW_R3_UPSTREAM").unwrap().parse().unwrap();
        let gateway: SocketAddr = std::env::var("HTTP_PROXY")
            .unwrap()
            .trim_start_matches("http://")
            .parse()
            .unwrap();
        let id = inspect_process_identity(std::process::id()).unwrap();
        fs::write(root.join("child-identity.json"),json!({"pid":id.pid,"uid":id.uid,"start_seconds":id.start_seconds,"start_microseconds":id.start_microseconds}).to_string()).unwrap();
        wait_file(&root.join("orphan-permit-ready"));
        let mut s = TcpStream::connect(gateway).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(format!("CONNECT {upstream} HTTP/1.1\r\nHost: {upstream}\r\n\r\n").as_bytes())
            .unwrap();
        assert!(header(&mut s).starts_with("HTTP/1.1 200"));
        s.write_all(b"orphan-positive").unwrap();
        let mut echo = [0; 15];
        s.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"orphan-positive");
        say("ORPHAN_CONNECTED");
        let mut one = [0];
        assert_eq!(
            s.read(&mut one)
                .expect("revocation must produce EOF, not timeout"),
            0
        );
        say("ORPHAN_EOF");
        let mut denied = TcpStream::connect(gateway).unwrap();
        denied
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        denied
            .write_all(
                format!("CONNECT {upstream} HTTP/1.1\r\nHost: {upstream}\r\n\r\n").as_bytes(),
            )
            .unwrap();
        assert!(header(&mut denied).starts_with("HTTP/1.1 502"));
        assert!(TcpStream::connect_timeout(&upstream, Duration::from_millis(500)).is_err());
        say("ORPHAN_RECONNECT_BLOCKED");
        for line in std::io::stdin().lock().lines() {
            let line = line.unwrap();
            if line == "QUIT" {
                break;
            }
            let live = inspect_process_identity(id.pid).unwrap();
            assert_eq!(
                (
                    live.pid,
                    live.uid,
                    live.start_seconds,
                    live.start_microseconds
                ),
                (id.pid, id.uid, id.start_seconds, id.start_microseconds)
            );
            assert_eq!(live.executable_path, id.executable_path);
            assert_eq!(live.audit_token, id.audit_token);
            say(&format!("ORPHAN_PONG {line}"));
        }
        fs::write(
            root.join("child-finished"),
            b"responded and exited normally",
        )
        .unwrap();
        return;
    }
    let root = PathBuf::from("/tmp").join(format!(
        "cw-r3-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    fs::create_dir_all(&root).unwrap();
    let tmp = TempRoot(root);
    let exe = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let helper = exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("watch-sandbox-launcher");
    assert!(helper.is_file(), "build actual helper before this test");
    let helper = hardened_helper::copy_signed(&helper, &tmp.0.join("watch-sandbox-launcher"));
    fs::create_dir_all(tmp.0.join("manifest")).unwrap();
    fs::write(
        tmp.0.join("manifest/components.json"),
        hardened_helper::components(&helper).to_string(),
    )
    .unwrap();
    let verifier = build_helper_verifier_from_manifest(&tmp.0.join("manifest"), &helper).unwrap();
    let pv = PolicyVersion {
        policy_digest: "r3-component".into(),
        guard_policy_digest: "r3-guard".into(),
    };
    let boot = "r3-component-boot";
    let now = 1_720_030_000.0;
    let store = StateStore::new(Paths::new(&tmp.0).unwrap());
    let registry = Arc::new(SandboxLaunchRegistry::new(
        boot,
        pv.clone(),
        verifier,
        Some(store.clone()),
    ));
    registry.approve_target_executable(exe.to_string_lossy(), sha256_file_hex(&exe).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let reg_sock = tmp.0.join("reg.sock");
    let reg_thread = registry
        .start_registration_listener(&reg_sock, stop.clone())
        .unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    upstream.set_nonblocking(true).unwrap();
    let echo_stop = stop.clone();
    let echo_thread = thread::spawn(move || {
        while !echo_stop.load(Ordering::Acquire) {
            match upstream.accept() {
                Ok((mut s, _)) => {
                    s.set_nonblocking(false).unwrap();
                    thread::spawn(move || {
                        let mut b = [0; 1];
                        if s.read_exact(&mut b).is_err() {
                            return;
                        }
                        if b[0] == b'C' {
                            let mut bytes = vec![b[0]];
                            while !bytes.ends_with(b"\r\n\r\n") {
                                if s.read_exact(&mut b).is_err() {
                                    return;
                                }
                                bytes.push(b[0]);
                            }
                            s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                                .unwrap();
                        } else {
                            s.write_all(&b).unwrap();
                        }
                        let mut buf = [0; 256];
                        loop {
                            match s.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    if s.write_all(&buf[..n]).is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("echo accept: {e}"),
            }
        }
    });
    let enforcer = Arc::new(LocalTunnelEnforcer::new(boot, Some(store)));
    enforcer.configure_seatbelt_backend(true, now).unwrap();
    enforcer.set_clock(move || now + 0.5).unwrap();
    let reg = registry.clone();
    enforcer
        .set_accepted_connection_attributor(move |ctx| {
            reg.attribute_accepted_connection(ctx, now + 0.5)
        })
        .unwrap();
    enforcer
        .set_upstream_connector(move |_| Ok(TunnelStream::Tcp(TcpStream::connect(upstream_addr)?)))
        .unwrap();
    let (gateway, gateway_thread) = enforcer
        .start_local_proxy_listener("127.0.0.1:0", stop.clone(), now)
        .unwrap();
    let req = ControlledLaunchRequest {
        entry_id: "io.local.watchpanel.entry.claude-cli".into(),
        target: LaunchTarget::ClaudeCli,
        target_executable: exe.to_string_lossy().into_owned(),
        target_fingerprint: sha256_file_hex(&exe).unwrap(),
        args: vec!["--exact".into(), TEST.into(), "--nocapture".into()],
        cwd: Some(tmp.0.to_string_lossy().into_owned()),
        proxy_adaptation: ProxyAdaptationKind::EnvOnly,
        gateway_endpoint: gateway.to_string(),
        policy_version: pv.clone(),
        vpn_epoch: Some(VpnEpoch::new("r3-vpn", 1)),
        launch_nonce: uuid::Uuid::new_v4().to_string(),
        executor_boot_id: boot.into(),
        script_entry: None,
        script_fingerprint: None,
        interpreter: None,
        interpreter_fingerprint: None,
        script_source: None,
    };
    let mut parent = Command::new(helper)
        .arg("--launch-json")
        .arg(serde_json::to_string(&req).unwrap())
        .arg("--registration-socket")
        .arg(&reg_sock)
        .arg("--deny-port")
        .arg(upstream_addr.port().to_string())
        .env("CW_R3_ROLE", "parent")
        .env("CW_R3_ROOT", &tmp.0)
        .env("CW_R3_UPSTREAM", upstream_addr.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut child_input = parent.stdin.take().unwrap();
    let output = parent.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            if let Ok(line) = line {
                if tx.send(line).is_err() {
                    break;
                }
            } else {
                break;
            }
        }
    });
    struct Cleanup {
        parent: std::process::Child,
        identity: PathBuf,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Ok(bytes) = fs::read(&self.identity) {
                if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                    if let Some(id) = v["pid"]
                        .as_u64()
                        .and_then(|p| inspect_process_identity(p as u32))
                    {
                        if id.uid == effective_uid()
                            && v["uid"] == id.uid
                            && v["start_seconds"] == id.start_seconds
                            && v["start_microseconds"] == id.start_microseconds
                        {
                            unsafe {
                                libc::kill(id.pid as i32, libc::SIGTERM);
                            }
                        }
                    }
                }
            }
            let _ = self.parent.kill();
            let _ = self.parent.wait();
        }
    }
    let mut cleanup = Cleanup {
        parent,
        identity: tmp.0.join("child-identity.json"),
    };
    wait_file(&cleanup.identity);
    let identity: Value = serde_json::from_slice(&fs::read(&cleanup.identity).unwrap()).unwrap();
    let child_pid = identity["pid"].as_u64().unwrap() as u32;
    let parent_pid = cleanup.parent.id();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let tokens = registry.verified_family_tokens("claude", now);
        if tokens.iter().any(|t| t.pid == parent_pid) && tokens.iter().any(|t| t.pid == child_pid) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "parent and actual inherited child were not verified before parent exit"
        );
        thread::sleep(Duration::from_millis(20));
    }
    fs::write(
        tmp.0.join("parent-may-exit"),
        b"verified child before normal parent exit",
    )
    .unwrap();
    assert!(cleanup.parent.wait().unwrap().success());
    let tokens = registry.verified_family_tokens("claude", now + 0.1);
    assert!(!tokens.iter().any(|t| t.pid == parent_pid));
    let token = tokens
        .into_iter()
        .find(|t| t.pid == child_pid)
        .expect("verified orphan retains current token");
    let child_before = inspect_process_identity(child_pid).unwrap();
    assert_eq!(child_before.uid, effective_uid());
    let permit = ChannelPermit {
        family: "claude".into(),
        session_id: Some("r3-session".into()),
        policy_version: pv.clone(),
        permit_generation: 1,
        command_seq: 1,
        state: ChannelPermitState::Permitted,
        reason_code: "component_fixture".into(),
        issued_at: now,
        valid_until: now + 60.0,
        context_id: Some("fixture".into()),
        baseline_ip: Some("1.1.1.1".into()),
        members: vec![Desktop {
            pid: token.pid,
            start_seconds: token.start_seconds,
            start_microseconds: token.start_microseconds,
        }],
        backend: NetworkBackendKind::Seatbelt,
        vpn_epoch: Some(VpnEpoch::new("r3-vpn", 1)),
        coverage_scope: None,
    };
    let mut command = ChannelEnforcementCommand {
        family: permit.family.clone(),
        session_id: permit.session_id.clone(),
        policy_version: pv,
        permit_generation: 1,
        command_seq: 1,
        permit,
        allowed_processes: vec![token],
        upstream_endpoint: upstream_addr.to_string(),
        target_executor_boot_id: Some(boot.into()),
        issued_at: now,
    };
    enforcer.apply_command(&command, now).unwrap();
    fs::write(tmp.0.join("orphan-permit-ready"), b"current orphan permit").unwrap();
    let await_line = |prefix: &str| {
        let until = Instant::now() + Duration::from_secs(8);
        loop {
            let line = rx
                .recv_timeout(until.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|e| panic!("missing {prefix}: {e}"));
            if line.starts_with(prefix) {
                break line;
            }
        }
    };
    assert_eq!(await_line("ORPHAN_CONNECTED"), "ORPHAN_CONNECTED");
    command.command_seq = 2;
    command.permit.command_seq = 2;
    command.permit.state = ChannelPermitState::Revoked;
    command.permit.reason_code = "fixture_risk".into();
    command.issued_at = now + 0.2;
    command.permit.issued_at = now + 0.2;
    enforcer.apply_command(&command, now + 0.2).unwrap();
    assert_eq!(await_line("ORPHAN_EOF"), "ORPHAN_EOF");
    assert_eq!(
        await_line("ORPHAN_RECONNECT_BLOCKED"),
        "ORPHAN_RECONNECT_BLOCKED"
    );
    let responsive = Instant::now();
    let mut responses = 0;
    while responsive.elapsed() < Duration::from_millis(5200) {
        let ping = format!("r3-{responses}");
        writeln!(child_input, "{ping}").unwrap();
        assert_eq!(await_line("ORPHAN_PONG "), format!("ORPHAN_PONG {ping}"));
        let mut ordinary = TcpStream::connect(upstream_addr).unwrap();
        ordinary
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        ordinary.write_all(ping.as_bytes()).unwrap();
        let mut echoed = vec![0; ping.len()];
        ordinary.read_exact(&mut echoed).unwrap();
        assert_eq!(echoed, ping.as_bytes());
        let live = inspect_process_identity(child_pid).unwrap();
        assert_eq!(
            (
                live.pid,
                live.uid,
                live.start_seconds,
                live.start_microseconds
            ),
            (
                child_before.pid,
                child_before.uid,
                child_before.start_seconds,
                child_before.start_microseconds
            )
        );
        responses += 1;
        thread::sleep(Duration::from_millis(100));
    }
    let receipt = enforcer.receipt_for("claude", now + 0.5).unwrap().unwrap();
    assert!(receipt.active_flows_closed && receipt.new_connections_blocked);
    assert_eq!(receipt.active_flows_count, 0);
    assert!(responses >= 10);
    writeln!(child_input, "QUIT").unwrap();
    wait_file(&tmp.0.join("child-finished"));
    println!(
        "COMPONENT_ONLY R3: parent={parent_pid} exited normally; verified orphan={child_pid}; forwarded after parent exit; revoke=EOF; responses={responses}; ordinary_control=ok; response_window_ms={}",
        responsive.elapsed().as_millis()
    );
    drop(cleanup);
    stop.store(true, Ordering::Release);
    gateway_thread.join().unwrap();
    reg_thread.join().unwrap();
    echo_thread.join().unwrap();
}
