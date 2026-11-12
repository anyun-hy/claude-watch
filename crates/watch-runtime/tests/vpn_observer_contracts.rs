use claude_watch_core::{
    channel::NetworkBackendKind,
    config::Config,
    tag_config::Credentials,
    vpn::{
        rules_digest_from_published, ObservationConsistency, ObservedField, UpstreamProtocol,
        VpnExpectation, VpnMatch,
    },
};
use claude_watch_runtime::{
    config_store::ConfigStore,
    local_http::Client,
    macos::Mutator,
    proxy_mutations::{self, ProxyMutationAdapter},
    repair,
    storage::{Paths, StateStore},
    vpn_observer::{HttpControllerVpnReader, VpnObserver},
};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
};

struct TempRoot(PathBuf);
impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn setup_store() -> (TempRoot, StateStore) {
    let dir = std::env::temp_dir().join(format!("cw-vpn-obs-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let store = StateStore::new(Paths::new(&dir).unwrap());
    (TempRoot(dir), store)
}

struct MockControllerServer {
    port: u16,
    proxy_port: u16,
    request_paths: Arc<Mutex<Vec<String>>>,
}

#[derive(Clone)]
struct MockControllerData {
    configs_seq: Vec<Value>,
    proxies_seq: Vec<Value>,
    rules_body: Value,
    call_idx: Arc<AtomicUsize>,
}

impl MockControllerServer {
    fn start(
        proxy_port_override: Option<u16>,
        configs_seq: Vec<Value>,
        proxies_seq: Vec<Value>,
        rules_body: Value,
    ) -> Self {
        let proxy_port = if let Some(p) = proxy_port_override {
            p
        } else {
            let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let p = proxy_listener.local_addr().unwrap().port();
            thread::spawn(move || {
                for stream in proxy_listener.incoming() {
                    if stream.is_err() {
                        break;
                    }
                }
            });
            p
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(MockControllerData {
            configs_seq,
            proxies_seq,
            rules_body,
            call_idx: Arc::new(AtomicUsize::new(0)),
        }));
        let request_paths = Arc::new(Mutex::new(Vec::new()));
        let state_clone = state.clone();
        let paths_clone = request_paths.clone();

        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut stream) = incoming else { break };
                let mut buf = [0u8; 2048];
                let Ok(n) = stream.read(&mut buf) else {
                    continue;
                };
                if n == 0 {
                    continue;
                }
                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or("");
                let path = first_line.split_whitespace().nth(1).unwrap_or("/");
                paths_clone.lock().unwrap().push(path.to_string());

                let data = state_clone.lock().unwrap().clone();
                let body = match path {
                    "/configs" => {
                        let idx = data.call_idx.fetch_add(1, Ordering::SeqCst);
                        data.configs_seq
                            .get(idx)
                            .or_else(|| data.configs_seq.last())
                            .cloned()
                            .unwrap_or_else(|| json!({}))
                    }
                    "/proxies" => {
                        let idx = data.call_idx.load(Ordering::SeqCst).saturating_sub(1);
                        data.proxies_seq
                            .get(idx)
                            .or_else(|| data.proxies_seq.last())
                            .cloned()
                            .unwrap_or_else(|| json!({}))
                    }
                    "/rules" => data.rules_body,
                    _ => json!({"error": "unexpected_endpoint"}),
                };
                let body_bytes = serde_json::to_vec(&body).unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body_bytes.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(&body_bytes);
            }
        });

        Self {
            port,
            proxy_port,
            request_paths,
        }
    }

    fn credentials(&self) -> Credentials {
        Credentials::from_parts(&format!("127.0.0.1:{}", self.port), "test-secret".into()).unwrap()
    }
}

fn current_live_source_instance() -> String {
    let me = claude_watch_system::inspect_process_identity(std::process::id()).unwrap();
    format!("pid:{}:{}:{}", me.pid, me.start_seconds, me.start_microseconds)
}

fn live_owner_fixture() -> (MockControllerServer, VpnExpectation) {
    let server = MockControllerServer::start(Some(7890),
        vec![json!({"mode":"rule","mixed-port":7890,"revision":"stable"})],
        vec![json!({"proxies":{"AI":{"name":"AI","type":"Selector","now":"US"},"US":{"name":"US","type":"Trojan"}}})],
        json!({"rules":[]}));
    let mut expectation = VpnExpectation::unconfigured();
    expectation.configured = true;
    expectation.proxy_mode = "tag".into();
    expectation.proxy_url = "http://127.0.0.1:7890".into();
    expectation.proxy_group = "AI".into();
    (server, expectation)
}

fn captured_listener(server: &MockControllerServer, captured_at: f64, sequence: u64, origin: &str)
    -> claude_watch_runtime::vpn_observer::KernelListenerSnapshot {
    claude_watch_runtime::vpn_observer::KernelListenerSnapshot {
        evidence: claude_watch_core::tag_flow::CommandEvidence { status: 0,
            stdout: format!("tcp4 0 0 127.0.0.1.{} *.* LISTEN 0 0 1 1 fixture:{} 0\n", server.port, std::process::id()),
            stderr: String::new(), source: "native-listener".into() },
        captured_at, origin_id: Some(origin.into()), sequence: Some(sequence),
    }
}

#[test]
fn batch_listener_reads_are_two_per_sample_and_same_frame_cannot_renew_evidence() {
    let (server, expectation) = live_owner_fixture();
    let snapshot = captured_listener(&server, 999.0, 7, "collector-A");
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let reader = HttpControllerVpnReader::new_live("tag", server.credentials())
        .with_listener_snapshot_probe(Box::new(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Some(snapshot.clone())
        }));
    let mut observer = VpnObserver::new("snapshot", None);
    for now in [1000.0, 1001.0] {
        let result = observer.observe_from_reader(&reader, &expectation, false, now).unwrap();
        assert_eq!(result.verdict, VpnMatch::Matched);
        assert_eq!(result.observation.valid_until, 1002.5);
        assert_eq!(result.observation.observed_at, now);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    let expired = observer.observe_from_reader(&reader, &expectation, false, 1003.0).unwrap();
    assert_eq!(expired.observation.source_error.as_deref(), Some("vpn_listener_snapshot_stale"));
    assert!(matches!(expired.verdict, VpnMatch::Unknown { .. }));
}

#[test]
fn collector_replacement_or_frame_replay_fails_source_pair_verification() {
    let (server, expectation) = live_owner_fixture();
    let before = captured_listener(&server, 999.5, 7, "collector-A");
    let mut variants = Vec::new();
    variants.push(captured_listener(&server, 999.5, 7, "collector-B"));
    variants.push(captured_listener(&server, 999.5, 6, "collector-A"));
    variants.push(captured_listener(&server, 1000.0, 7, "collector-A"));
    for after in variants {
        let before = before.clone();
        let reads = AtomicUsize::new(0);
        let reader = HttpControllerVpnReader::new_live("tag", server.credentials())
            .with_listener_snapshot_probe(Box::new(move |_| Some(if reads.fetch_add(1, Ordering::SeqCst) == 0 {
                before.clone()
            } else { after.clone() })));
        let result = VpnObserver::new("replacement", None).observe_from_reader(&reader, &expectation, false, 1000.0).unwrap();
        assert_eq!(result.observation.source_error.as_deref(), Some("vpn_listener_source_changed_during_sample"));
        assert!(matches!(result.verdict, VpnMatch::Unknown { .. }));
    }
}

#[test]
fn missing_or_empty_kernel_snapshot_cannot_replace_verified_source() {
    let (server, expectation) = live_owner_fixture();
    let mut empty = captured_listener(&server, 999.5, 7, "collector-A");
    empty.evidence.stdout.clear();
    for snapshot in [None, Some(empty)] {
        let reader = HttpControllerVpnReader::new_live("tag", server.credentials())
            .with_listener_snapshot_probe(Box::new(move |_| snapshot.clone()));
        let result = VpnObserver::new("missing", None).observe_from_reader(&reader, &expectation, false, 1000.0).unwrap();
        assert!(result.observation.source_instance.is_none());
        assert!(result.observation.source_error.is_some());
        assert!(!result.observation.consistency.is_consistent());
        assert!(matches!(result.verdict, VpnMatch::Unknown { .. }));
    }
}

#[test]
fn cross_user_owner_probe_is_authoritative_and_reverified_each_sample() {
    let (server, expectation) = live_owner_fixture();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let reader = HttpControllerVpnReader::new_live("tag", server.credentials())
        .with_listener_owner_probe(Box::new(move |_, remaining| {
            assert!(!remaining.is_zero());
            assert!(remaining <= claude_watch_runtime::vpn_observer::VPN_OBSERVATION_BUDGET);
            observed.fetch_add(1, Ordering::SeqCst);
            Some(std::process::id())
        }));
    let mut observer = VpnObserver::new("cross-user", None);
    for timestamp in [1000.0, 1001.0] {
        let transition = observer.observe_from_reader(&reader, &expectation, false, timestamp).unwrap();
        assert_eq!(transition.observation.source_instance, Some(current_live_source_instance()));
        assert_eq!(transition.verdict, VpnMatch::Matched);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 4,
        "controller owner must be read twice, without a same-UID full scan replacing it");

    // The controller is really owned by this test process. An ambiguous kernel
    // lookup must nevertheless stay unverified, not be overridden by a UID scan.
    let unavailable = HttpControllerVpnReader::new_live("tag", server.credentials())
        .with_listener_owner_probe(Box::new(|_, _| None));
    let transition = observer.observe_from_reader(&unavailable, &expectation, false, 1002.0).unwrap();
    assert!(transition.observation.source_instance.is_none());
    assert!(matches!(transition.verdict, VpnMatch::Unknown { .. }));
}

#[test]
fn owner_handoff_during_recheck_never_produces_verified_instance() {
    let (server, expectation) = live_owner_fixture();
    let count = AtomicUsize::new(0);
    let reader = HttpControllerVpnReader::new_live("tag", server.credentials())
        .with_listener_owner_probe(Box::new(move |_, _| {
            (count.fetch_add(1, Ordering::SeqCst) % 2 == 0).then_some(std::process::id())
        }));
    let transition = VpnObserver::new("handoff", None)
        .observe_from_reader(&reader, &expectation, false, 1000.0).unwrap();
    assert!(transition.observation.source_instance.is_none());
    assert!(matches!(transition.verdict, VpnMatch::Unknown { .. }));
}

#[test]
fn exhausted_sample_budget_fails_closed_without_timestamp_renewal() {
    use claude_watch_runtime::vpn_observer::{DEFAULT_VPN_OBSERVATION_TTL_SECONDS, VPN_OBSERVATION_BUDGET};
    let (server, expectation) = live_owner_fixture();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let reader = HttpControllerVpnReader::new_live("tag", server.credentials())
        .with_listener_owner_probe(Box::new(move |_, remaining| {
            observed.fetch_add(1, Ordering::SeqCst);
            thread::sleep(remaining);
            Some(std::process::id())
        }));
    let started = std::time::Instant::now();
    let transition = VpnObserver::new("budget", None)
        .observe_from_reader(&reader, &expectation, false, 1000.0).unwrap();
    assert!(started.elapsed() >= VPN_OBSERVATION_BUDGET);
    assert!(started.elapsed() < std::time::Duration::from_millis(3300));
    assert_eq!(calls.load(Ordering::SeqCst), 1, "no unbounded second check after deadline");
    assert_eq!(transition.observation.source_error.as_deref(), Some("vpn_observation_budget_exceeded"));
    assert!(!transition.observation.consistency.is_consistent());
    assert!(transition.observation.source_instance.is_none());
    assert_eq!(transition.observation.sample_started_at, 1000.0);
    assert_eq!(transition.observation.observed_at, 1000.0);
    assert_eq!(transition.observation.valid_until, 1000.0 + DEFAULT_VPN_OBSERVATION_TTL_SECONDS);
    assert!(matches!(transition.verdict, VpnMatch::Unknown { .. }));
}

#[test]
#[ignore = "macOS read-only host diagnostic; owns its temporary controller listener"]
fn owned_controller_live_kernel_source_finishes_inside_evidence_ttl() {
    use claude_watch_runtime::{commands::SystemRunner, vpn_observer::{
        read_vpn_kernel_snapshot, VPN_OBSERVATION_BUDGET,
    }};
    let (server, expectation) = live_owner_fixture();
    let runner = SystemRunner::development().unwrap();
    let reader = HttpControllerVpnReader::new_live("tag", server.credentials())
        .with_listener_snapshot_probe(Box::new(move |remaining| {
            let snapshot = read_vpn_kernel_snapshot(&runner, remaining)?;
            eprintln!("owned controller kernel read status={} stdout_bytes={} stderr_bytes={}",
                snapshot.evidence.status, snapshot.evidence.stdout.len(), snapshot.evidence.stderr.len());
            Some(snapshot)
        }));
    let started = std::time::Instant::now();
    let transition = VpnObserver::new("owned-live-controller", None)
        .observe_from_reader(&reader, &expectation, false, claude_watch_runtime::native::now()).unwrap();
    let elapsed = started.elapsed();
    eprintln!("owned controller + live kernel owner double-check elapsed={elapsed:?}; budget={VPN_OBSERVATION_BUDGET:?}");
    assert_eq!(transition.observation.source_instance, Some(current_live_source_instance()));
    assert_eq!(transition.verdict, VpnMatch::Matched);
    assert!(elapsed < VPN_OBSERVATION_BUDGET);
}

#[test]
fn fast_vpn_state_observes_custom_ports_protocol_selector_chain_and_never_calls_connections() {
    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in proxy_listener.incoming() {
            if stream.is_err() {
                break;
            }
        }
    });

    let rules_json = json!({
        "rules": [
            {"type": "DOMAIN-SUFFIX", "payload": "anthropic.com", "proxy": "AI-Group"},
            {"type": "MATCH", "payload": "", "proxy": "AI-Group"}
        ]
    });
    let server = MockControllerServer::start(
        Some(proxy_port),
        vec![json!({
            "mode": "rule",
            "mixed-port": proxy_port,
            "socks-port": proxy_port + 1,
            "tun": {"enable": false},
            "revision": "rev-101"
        })],
        vec![json!({
            "proxies": {
                "AI-Group": {"name": "AI-Group", "type": "Selector", "now": "Auto-US"},
                "Auto-US": {"name": "Auto-US", "type": "URLTest", "now": "US-West-01"},
                "US-West-01": {"name": "US-West-01", "type": "Trojan"}
            }
        })],
        rules_json,
    );

    let mut exp = VpnExpectation::unconfigured();
    exp.configured = true;
    exp.proxy_mode = "clash-verge".into();
    exp.proxy_url = format!("http://127.0.0.1:{}", server.proxy_port);
    exp.proxy_group = "AI-Group".into();
    exp.running_mode = Some("rule".into());
    exp.expected_node = Some("US-West-01".into());
    exp.expected_chain = vec!["AI-Group".into(), "Auto-US".into(), "US-West-01".into()];
    exp.require_tun = None;
    exp.expected_rules_digest = rules_digest_from_published(&json!({
        "state": "available",
        "entries": [
            "DOMAIN-SUFFIX,anthropic.com,AI-Group",
            "MATCH,AI-Group"
        ]
    }));

    let reader = HttpControllerVpnReader::new(
        "clash-verge",
        current_live_source_instance(),
        server.credentials(),
    );
    let mut observer = VpnObserver::new("obs-boot-1", None);
    let transition = observer
        .observe_from_reader(&reader, &exp, true, 1000.0)
        .unwrap();

    assert_eq!(transition.verdict, VpnMatch::Matched);
    assert_eq!(
        transition.observation.system_proxy_enabled,
        ObservedField::Unknown("system_proxy_not_sampled".into()),
        "unsampled system proxy must be Unknown, never Known(false)"
    );
    assert_eq!(
        transition.observation.consistency,
        ObservationConsistency::RevisionVerified
    );
    assert_eq!(
        transition.observation.upstream_protocol,
        ObservedField::Known(UpstreamProtocol::MixedHttp)
    );
    assert_eq!(
        transition.observation.selected_node,
        ObservedField::Known("US-West-01".into())
    );
    assert_eq!(transition.observation.tun_enabled, ObservedField::Known(false));
    assert_eq!(transition.observation.epoch.change_generation, 1);

    // Same-content refresh advances sample_seq only, keeping VpnEpoch unchanged
    let transition2 = observer
        .observe_from_reader(&reader, &exp, false, 1001.0)
        .unwrap();
    assert!(!transition2.epoch_changed);
    assert_eq!(transition2.observation.epoch, transition.observation.epoch);
    assert_eq!(transition2.observation.sample_seq, 2);

    // Fast path must never query slow `/connections`
    let paths = server.request_paths.lock().unwrap().clone();
    assert!(!paths.iter().any(|p| p.contains("connections")));
}

#[test]
fn mid_switch_inconsistency_between_two_phase_reads_fails_closed_as_unknown() {
    let server = MockControllerServer::start(
        None,
        vec![
            json!({
                "mode": "rule",
                "mixed-port": 17890,
                "tun": {"enable": true}
            }),
            json!({
                "mode": "global",
                "mixed-port": 17890,
                "tun": {"enable": true}
            }),
            json!({
                "mode": "rule",
                "mixed-port": 17890,
                "tun": {"enable": true}
            }),
            json!({
                "mode": "global",
                "mixed-port": 17890,
                "tun": {"enable": true}
            }),
        ],
        vec![
            json!({
                "proxies": {
                    "TAG": {"name": "TAG", "type": "Selector", "now": "JP-01"},
                    "JP-01": {"name": "JP-01", "type": "Shadowsocks"}
                }
            }),
            json!({
                "proxies": {
                    "TAG": {"name": "TAG", "type": "Selector", "now": "SG-02"},
                    "SG-02": {"name": "SG-02", "type": "Shadowsocks"}
                }
            }),
            json!({
                "proxies": {
                    "TAG": {"name": "TAG", "type": "Selector", "now": "JP-01"},
                    "JP-01": {"name": "JP-01", "type": "Shadowsocks"}
                }
            }),
            json!({
                "proxies": {
                    "TAG": {"name": "TAG", "type": "Selector", "now": "SG-02"},
                    "SG-02": {"name": "SG-02", "type": "Shadowsocks"}
                }
            }),
        ],
        json!({"rules": []}),
    );

    let client = Client::new(server.credentials());
    let (_snap, consistency) = client
        .observe_fast_vpn_state("TAG", "127.0.0.1", Some(17890), false)
        .unwrap();
    assert!(matches!(
        consistency,
        ObservationConsistency::InconsistentSnapshot(_)
    ));

    let mut exp = VpnExpectation::unconfigured();
    exp.configured = true;
    exp.proxy_mode = "tag".into();
    exp.proxy_url = format!("http://127.0.0.1:{}", server.proxy_port);
    exp.proxy_group = "TAG".into();
    exp.expected_node = Some("JP-01".into());

    let reader = HttpControllerVpnReader::new(
        "tag",
        current_live_source_instance(),
        server.credentials(),
    );
    let mut observer = VpnObserver::new("obs-boot-2", None);
    let transition = observer
        .observe_from_reader(&reader, &exp, false, 2000.0)
        .unwrap();
    assert!(matches!(
        transition.observation.consistency,
        ObservationConsistency::InconsistentSnapshot(_)
    ));
    assert!(matches!(transition.verdict, VpnMatch::Unknown { .. }));
}

#[test]
fn vpn_read_only_boundary_blocks_all_proxy_and_tun_mutations_and_omits_from_repair_plan() {
    let cfg = Config::default_for_new_install();
    assert_eq!(cfg.effective_network_backend(), NetworkBackendKind::Seatbelt);
    assert!(cfg.vpn_is_read_only());

    for action in ["start_proxy", "reload_proxy", "enable_tun", "rules"] {
        let err = proxy_mutations::verify_vpn_write_allowed(&cfg, action).unwrap_err();
        assert_eq!(err.code, "vpn_managed_externally");
    }

    let (_tmp, store) = setup_store();
    ConfigStore {
        storage: store.clone(),
    }
    .save(cfg.value().unwrap())
    .unwrap();
    let mut adapter = ProxyMutationAdapter::native(store);
    for action_id in ["start_proxy", "reload_proxy", "enable_tun", "rules"] {
        let err = adapter
            .apply(&json!({
                "id": action_id,
                "context": "ctx-1",
                "before": "clash-verge",
                "after": "clash-verge"
            }))
            .unwrap_err();
        assert_eq!(err.code, "vpn_managed_externally");
    }

    let local = json!({
        "country": "US",
        "locale": "en_US",
        "time_zone": "America/Los_Angeles",
        "proxy": "fail",
        "tun": "fail",
        "controller": {"state": "unavailable"},
        "rules": {"state": "drifted"}
    });
    let plan = repair::make_plan(&cfg, &local, Some("rules:\n  - MATCH,DIRECT\n")).unwrap();
    let actions: Vec<&str> = plan["actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["id"].as_str())
        .collect();
    assert!(
        !actions.iter().any(|id| matches!(*id, "start_proxy" | "reload_proxy" | "enable_tun" | "rules")),
        "read-only VPN config must not include any proxy/TUN mutation in repair plan, got {actions:?}"
    );
}

#[test]
fn v06_v07_unsampled_system_proxy_is_unknown_live_source_pid_verified_and_revision_advances_epoch() {
    let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in proxy_listener.incoming() {
            if stream.is_err() {
                break;
            }
        }
    });

    // Server returns rev-1 (for bad_trans), rev-1 (for t1), rev-2 (for t2), rev-2 (for t3)
    let server = MockControllerServer::start(
        Some(proxy_port),
        vec![
            json!({"mode": "rule", "mixed-port": proxy_port, "tun": {"enable": false}, "revision": "rev-1"}),
            json!({"mode": "rule", "mixed-port": proxy_port, "tun": {"enable": false}, "revision": "rev-1"}),
            json!({"mode": "rule", "mixed-port": proxy_port, "tun": {"enable": false}, "revision": "rev-1"}),
            json!({"mode": "rule", "mixed-port": proxy_port, "tun": {"enable": false}, "revision": "rev-1"}),
            json!({"mode": "rule", "mixed-port": proxy_port, "tun": {"enable": false}, "revision": "rev-2"}),
            json!({"mode": "rule", "mixed-port": proxy_port, "tun": {"enable": false}, "revision": "rev-2"}),
            json!({"mode": "rule", "mixed-port": proxy_port, "tun": {"enable": false}, "revision": "rev-2"}),
            json!({"mode": "rule", "mixed-port": proxy_port, "tun": {"enable": false}, "revision": "rev-2"}),
        ],
        vec![
            json!({"proxies": {"TAG": {"name": "TAG", "type": "Selector", "now": "JP-01"}, "JP-01": {"name": "JP-01", "type": "Trojan"}}}),
            json!({"proxies": {"TAG": {"name": "TAG", "type": "Selector", "now": "JP-01"}, "JP-01": {"name": "JP-01", "type": "Trojan"}}}),
            json!({"proxies": {"TAG": {"name": "TAG", "type": "Selector", "now": "JP-01"}, "JP-01": {"name": "JP-01", "type": "Trojan"}}}),
            json!({"proxies": {"TAG": {"name": "TAG", "type": "Selector", "now": "JP-01"}, "JP-01": {"name": "JP-01", "type": "Trojan"}}}),
            json!({"proxies": {"TAG": {"name": "TAG", "type": "Selector", "now": "JP-01"}, "JP-01": {"name": "JP-01", "type": "Trojan"}}}),
            json!({"proxies": {"TAG": {"name": "TAG", "type": "Selector", "now": "JP-01"}, "JP-01": {"name": "JP-01", "type": "Trojan"}}}),
            json!({"proxies": {"TAG": {"name": "TAG", "type": "Selector", "now": "JP-01"}, "JP-01": {"name": "JP-01", "type": "Trojan"}}}),
            json!({"proxies": {"TAG": {"name": "TAG", "type": "Selector", "now": "JP-01"}, "JP-01": {"name": "JP-01", "type": "Trojan"}}}),
        ],
        json!({"rules": []}),
    );

    let mut exp = VpnExpectation::unconfigured();
    exp.configured = true;
    exp.proxy_mode = "tag".into();
    exp.proxy_url = format!("http://127.0.0.1:{proxy_port}");
    exp.proxy_group = "TAG".into();
    exp.running_mode = Some("rule".into());
    exp.expected_node = Some("JP-01".into());
    exp.expected_chain = vec!["TAG".into(), "JP-01".into()];

    // 1. Static unverified source_instance string is rejected as Unknown
    let unverified_reader = HttpControllerVpnReader::new("tag", "static-fake-inst", server.credentials());
    let mut observer = VpnObserver::new("obs-v07", None);
    let bad_trans = observer
        .observe_from_reader(&unverified_reader, &exp, false, 1000.0)
        .unwrap();
    assert!(
        matches!(
            &bad_trans.verdict,
            VpnMatch::Unknown { reasons } if reasons.iter().any(|r| r.contains("source_instance_unconfirmed"))
        ),
        "static unverified source_instance must fail closed as Unknown: {:?}",
        bad_trans.verdict
    );

    // 2. Live kernel PID identity passes V07 source_instance check; require_system_proxy=None passes even though system_proxy_enabled is Unknown
    let live_reader = HttpControllerVpnReader::new(
        "tag",
        current_live_source_instance(),
        server.credentials(),
    );
    let mut observer2 = VpnObserver::new("obs-v07-live", None);
    let t1 = observer2
        .observe_from_reader(&live_reader, &exp, false, 1001.0)
        .unwrap();
    assert_eq!(t1.verdict, VpnMatch::Matched);
    assert_eq!(t1.observation.source_revision.as_deref(), Some("rev-1"));
    assert_eq!(t1.observation.epoch.change_generation, 1);

    // 3. Revision change (rev-1 -> rev-2) advances VpnEpoch.change_generation even when node/mode are identical (A->B->A)
    let t2 = observer2
        .observe_from_reader(&live_reader, &exp, false, 1002.0)
        .unwrap();
    assert!(t2.epoch_changed, "source_revision change must advance VpnEpoch");
    assert_eq!(t2.observation.source_revision.as_deref(), Some("rev-2"));
    assert_eq!(t2.observation.epoch.change_generation, 2);

    // 4. V06: When user explicitly requires system_proxy (`require_system_proxy = Some(true)`), unsampled Unknown fails closed,
    //    and Known(true) matches while Known(false) mismatches.
    let mut exp_sys = exp.clone();
    exp_sys.require_system_proxy = Some(true);
    let mut reader_unknown_sys = HttpControllerVpnReader::new(
        "tag",
        current_live_source_instance(),
        server.credentials(),
    );
    reader_unknown_sys.system_proxy_override =
        Some(ObservedField::Unknown("system_proxy_not_sampled".into()));
    let t3 = observer2
        .observe_from_reader(&reader_unknown_sys, &exp_sys, false, 1003.0)
        .unwrap();
    assert_eq!(
        t3.verdict,
        VpnMatch::Unknown {
            reasons: vec!["system_proxy_not_sampled".into()]
        }
    );

    reader_unknown_sys.system_proxy_override = Some(ObservedField::Known(true));
    let _ = (
        claude_watch_runtime::vpn_observer::parse_scutil_proxy_output(
            &format!("ExceptionsList : <array> {{\n}}\nHTTPEnable : 1\nHTTPPort : {proxy_port}\nHTTPProxy : 127.0.0.1\nHTTPSEnable : 1\nHTTPSPort : {proxy_port}\nHTTPSProxy : 127.0.0.1\n"),
            "127.0.0.1",
            Some(proxy_port),
        ),
        claude_watch_runtime::vpn_observer::parse_scutil_proxy_output(
            "HTTPEnable : 0\nHTTPSEnable : 0\n",
            "127.0.0.1",
            Some(proxy_port),
        ),
    );
}

#[test]
fn r2_rules_digest_cache_invalidates_on_revision_or_instance_change_before_reuse_and_scutil_proxy_parser_verifies_endpoints() {
    use claude_watch_runtime::vpn_observer::{parse_scutil_proxy_output, VpnSourceReader};

    struct MockRevisionRulesReader {
        source_instance: std::sync::Mutex<Option<String>>,
        revision: std::sync::Mutex<Option<String>>,
        rules_digest: std::sync::Mutex<ObservedField<String>>,
    }

    impl VpnSourceReader for MockRevisionRulesReader {
        fn read_observation(
            &self,
            expectation: &VpnExpectation,
            include_rules: bool,
            sample_seq: u64,
            epoch: claude_watch_core::vpn::VpnEpoch,
            now: f64,
        ) -> claude_watch_core::vpn::VpnObservation {
            claude_watch_core::vpn::VpnObservation {
                source: "tag".into(),
                source_instance: self.source_instance.lock().unwrap().clone(),
                source_revision: self.revision.lock().unwrap().clone(),
                upstream_endpoint: Some(expectation.proxy_url.clone()),
                upstream_protocol: ObservedField::Known(
                    claude_watch_core::vpn::UpstreamProtocol::MixedHttp,
                ),
                running_mode: ObservedField::Known("rule".into()),
                tun_enabled: ObservedField::Known(false),
                system_proxy_enabled: ObservedField::Known(true),
                selected_group: ObservedField::Known("TAG".into()),
                selected_node: ObservedField::Known("JP-01".into()),
                proxy_chain: ObservedField::Known(vec!["TAG".into(), "JP-01".into()]),
                rules_digest: if include_rules {
                    self.rules_digest.lock().unwrap().clone()
                } else {
                    ObservedField::Unknown("controller_rules_not_sampled".into())
                },
                sample_started_at: now,
                observed_at: now,
                valid_until: now + 3.5,
                consistency: claude_watch_core::vpn::ObservationConsistency::RevisionVerified,
                source_error: None,
                sample_seq,
                epoch,
            }
        }
    }

    let digest_a = "a".repeat(64);
    let mut exp = VpnExpectation::unconfigured();
    exp.configured = true;
    exp.proxy_mode = "tag".into();
    exp.proxy_url = "http://127.0.0.1:7890".into();
    exp.proxy_group = "TAG".into();
    exp.running_mode = Some("rule".into());
    exp.expected_node = Some("JP-01".into());
    exp.expected_rules_digest = Some(digest_a.clone());

    let reader = MockRevisionRulesReader {
        source_instance: std::sync::Mutex::new(Some(current_live_source_instance())),
        revision: std::sync::Mutex::new(Some("rev-1".into())),
        rules_digest: std::sync::Mutex::new(ObservedField::Known(digest_a.clone())),
    };

    let mut observer = VpnObserver::new("obs-r2-rules", None);
    // 1. First sample with include_rules=true caches digest_a bound to (instance, rev-1)
    let t1 = observer
        .observe_from_reader(&reader, &exp, true, 2000.0)
        .unwrap();
    assert_eq!(t1.verdict, VpnMatch::Matched);
    assert_eq!(
        t1.observation.rules_digest,
        ObservedField::Known(digest_a.clone())
    );

    // 2. Fast poll at 2005.0 (within 60s) with same revision reuses cached digest_a
    let t2 = observer
        .observe_from_reader(&reader, &exp, false, 2005.0)
        .unwrap();
    assert_eq!(t2.verdict, VpnMatch::Matched);
    assert_eq!(
        t2.observation.rules_digest,
        ObservedField::Known(digest_a.clone())
    );

    // 3. Revision changes to `rev-2` at 2006.0 (still within 60s TTL!) on a fast poll (include_rules=false).
    //    `VpnObserver` MUST invalidate the cached rules_digest BEFORE reusing it, so the observation
    //    does NOT carry the stale `digest_a` onto `rev-2`!
    *reader.revision.lock().unwrap() = Some("rev-2".into());
    let t3 = observer
        .observe_from_reader(&reader, &exp, false, 2006.0)
        .unwrap();
    assert!(t3.epoch_changed);
    assert!(
        matches!(t3.observation.rules_digest, ObservedField::Unknown(_)),
        "stale rules_digest from rev-1 must NOT be reused when revision changes to rev-2: {:?}",
        t3.observation.rules_digest
    );
    assert!(
        matches!(t3.verdict, VpnMatch::Unknown { .. }),
        "expected_rules_digest must fail-closed as Unknown until rules are re-sampled on rev-2"
    );

    // 4. Verify scutil --proxy parser read-only evaluation
    let scutil_enabled = "<dictionary> {\n  HTTPEnable : 1\n  HTTPPort : 7890\n  HTTPProxy : 127.0.0.1\n  HTTPSEnable : 1\n  HTTPSPort : 7890\n  HTTPSProxy : 127.0.0.1\n}\n";
    assert_eq!(
        parse_scutil_proxy_output(scutil_enabled, "127.0.0.1", Some(7890)),
        ObservedField::Known(true)
    );
    assert_eq!(
        parse_scutil_proxy_output(scutil_enabled, "127.0.0.1", Some(7891)),
        ObservedField::Unknown("system_proxy_endpoint_mismatch".into())
    );
    let scutil_disabled = "<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 0\n}\n";
    assert_eq!(
        parse_scutil_proxy_output(scutil_disabled, "127.0.0.1", Some(7890)),
        ObservedField::Known(false)
    );
}
