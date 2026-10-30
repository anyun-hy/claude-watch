use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
};
use claude_watch_runtime::{
    audit_store::AuditSystem,
    commands::{ObserverAction, Output, ReadCommand, ReadRunner},
    macos::{Authority, Macos, Mutator},
    native,
    network_client::{NetworkClient, Request, Response, Transport, TransportError},
    services::ServiceSystem,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{fs, sync::Arc, time::Duration};

struct Fixture {
    mode: &'static str,
    route: Option<&'static str>,
    parent: std::sync::atomic::AtomicU32,
    backend_executable: std::path::PathBuf,
    process_reads: std::sync::atomic::AtomicU32,
}
fn output(text: &str) -> Result<Output> {
    Ok(Output {
        status: 0,
        stdout: text.as_bytes().to_vec(),
        stderr: vec![],
    })
}
impl ReadRunner for Fixture {
    fn run(&self, command: ReadCommand, _: &[u8], _: Duration, _: usize) -> Result<Output> {
        match command {
            ReadCommand::Observer(ObserverAction::Environment) => {
                let now=native::now();
                output(&json!({"schema":1,"status":"ok","uid":501,"started_at":now,"finished_at":now,"timezone":"Asia/Tokyo","locale":"ja_JP","language":["en-JP"],"app_language":[],"network":{"service":"Wi-Fi","interface":"en0","service_id":"svc"},"ipv6":"ok"}).to_string())
            }
            ReadCommand::Observer(ObserverAction::Inventory) => {let now=native::now();output(&json!({"schema":1,"status":"ok","uid":501,"started_at":now,"finished_at":now,"state":"ok","truncated":false,"requested_count":1,"unavailable":[],"exited":[],"processes":[{"pid":42,"parent":self.parent.load(std::sync::atomic::Ordering::SeqCst),"uid":501,"executable":if self.mode=="tag"{"/Applications/TAG.app/Contents/Resources/bin/mihomo"}else{"/Applications/Surge.app/Contents/MacOS/Surge"},"start_seconds":1000,"start_microseconds":1,"start_stamp":"Mon Oct 26 01:02:03 2026"}]}).to_string())},
            ReadCommand::ProcessTable => {
                self.process_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                output(&format!("42 {} 501 Mon Oct 26 01:02:03 2026 {}\n77 1 501 Mon Oct 26 01:02:03 2026 {}\n", self.parent.load(std::sync::atomic::Ordering::SeqCst),if self.mode=="tag" {"/Applications/TAG.app/Contents/Resources/bin/mihomo"} else {"/Applications/Surge.app/Contents/MacOS/Surge"}, self.backend_executable.display()))
            }
            ReadCommand::LaunchctlGuiAgent { .. } => output("state = running\npid = 77\n"),
            ReadCommand::Route(_) => self.route.map(output).unwrap_or_else(||Err(CoreError::new("sampling_failed","route sampler unavailable"))),
            ReadCommand::Interfaces => output("utun4: flags=8051<UP> mtu 9000\n\tinet 198.18.0.1 netmask 0xffff0000\nen0: flags=8863<UP> mtu 1500\n\tinet 192.168.0.5 netmask 0xffffff00\n"),
            _ => Err(CoreError::new("sampling_failed","fixture intentionally unavailable")),
        }
    }
}

#[test]
fn guard_liveness_survives_a_degraded_monitoring_round_without_claiming_complete_sampling() {
    let home = Home::new();
    let host = home.host("surge", Some("interface: utun4\n"));
    let mut config = Config::default();
    config.guard_enabled = true;
    let now = native::now();
    host.storage
        .atomic_bytes(
            &host.storage.paths.watch().join("runtime/watch-engine"),
            b"fixture",
            0o700,
        )
        .unwrap();
    host.storage
        .atomic_bytes(
            &host.storage.paths.watch().join("state/heartbeat"),
            format!("77|Mon Oct 26 01:02:03 2026|{now}|error|GUARD\n").as_bytes(),
            0o600,
        )
        .unwrap();
    host.storage.atomic_json(
        &host.storage.paths.base().join("guard-heartbeat.json"),
        &json!({"time":now,"status":"ok","guard_policy_v1":claude_watch_runtime::config_store::guard_policy_digest(&config).unwrap()}),
    ).unwrap();
    let local = AuditSystem::local(&host, &config).unwrap();
    assert_eq!(local["backend_healthy"], false);
    assert_eq!(local["guard_backend_healthy"], true);
    assert_eq!(local["guard"], true);
    assert!(local["backend_detail"]
        .as_str()
        .unwrap()
        .contains("监控采样"));
    assert!(
        local["guard_backend_detail"]
            .as_str()
            .unwrap()
            .contains("本轮监控采样未完整"),
        "{local}"
    );
    assert!(!claude_watch_runtime::services::ServiceSystem::backend_healthy(&host));
    assert!(claude_watch_runtime::services::ServiceSystem::guard_backend_healthy(&host));
    assert!(claude_watch_runtime::services::ServiceSystem::guard_status(&host, &config).unwrap());
    assert!(claude_watch_runtime::onboarding::require_transport(&local).is_ok(),
        "initialization must use the same native liveness as service-status despite monitoring incompleteness");
}
struct NoNetwork;
impl Transport for NoNetwork {
    fn get(&self, _: &Request) -> std::result::Result<Response, TransportError> {
        panic!("offline facts must not query external network")
    }
}
struct NoWrites;
impl Mutator for NoWrites {
    fn apply(&mut self, _: &Value) -> Result<()> {
        panic!("offline facts must not mutate")
    }
    fn restore(&mut self, _: &Value) -> Result<bool> {
        panic!("offline facts must not restore")
    }
}
struct Home(std::path::PathBuf);
impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("cw-local-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn host(
        &self,
        mode: &'static str,
        route: Option<&'static str>,
    ) -> Macos<Fixture, NoNetwork, NoWrites> {
        self.host_with_backend(mode, route, None)
    }
    fn host_with_backend(
        &self,
        mode: &'static str,
        route: Option<&'static str>,
        backend_executable: Option<std::path::PathBuf>,
    ) -> Macos<Fixture, NoNetwork, NoWrites> {
        Macos {
            runner: Fixture {
                mode,
                route,
                parent: std::sync::atomic::AtomicU32::new(1),
                backend_executable: backend_executable.unwrap_or_else(|| {
                    self.0
                        .join("Library/Application Support/ClaudeWatch/runtime/watch-engine")
                }),
                process_reads: std::sync::atomic::AtomicU32::new(0),
            },
            network: NetworkClient::new(Arc::new(NoNetwork), None).unwrap(),
            storage: StateStore::new(Paths::new(&self.0).unwrap()),
            authority: Authority::ReadOnly,
            mutator: NoWrites,
            probes: Arc::new(|| panic!("offline must not probe")),
        }
    }
}

#[test]
fn service_status_uses_one_backend_snapshot_for_liveness_and_sampling_quality() {
    let home = Home::new();
    let host = home.host("surge", Some("interface: utun4\n"));
    let mut config = Config::default();
    config.guard_enabled = true;
    let now = native::now();
    host.storage
        .atomic_bytes(
            &host.storage.paths.watch().join("runtime/watch-engine"),
            b"fixture",
            0o700,
        )
        .unwrap();
    host.storage
        .atomic_bytes(
            &host.storage.paths.watch().join("state/heartbeat"),
            format!("77|Mon Oct 26 01:02:03 2026|{now}|error|GUARD\n").as_bytes(),
            0o600,
        )
        .unwrap();
    host.storage
        .atomic_json(
            &host.storage.paths.base().join("guard-heartbeat.json"),
            &json!({"time":now,"status":"ok","guard_policy_v1":claude_watch_runtime::config_store::guard_policy_digest(&config).unwrap()}),
        )
        .unwrap();
    let status = claude_watch_runtime::services::service_status(&host, &config).unwrap();
    assert_eq!(status["backend_healthy"], false);
    assert_eq!(status["guard_backend_healthy"], true);
    assert_eq!(status["backend_sampling_state"], "incomplete");
    assert_eq!(status["services"][0]["state"], "running");
    assert_eq!(
        host.runner
            .process_reads
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[test]
fn path_mismatch_never_counts_as_guard_liveness_even_when_sampling_is_complete() {
    let home = Home::new();
    let wrong = home.0.join("other-runtime/watch-engine");
    fs::create_dir_all(wrong.parent().unwrap()).unwrap();
    fs::write(&wrong, b"wrong").unwrap();
    let host = home.host_with_backend("surge", Some("interface: utun4\n"), Some(wrong));
    let mut config = Config::default();
    config.guard_enabled = true;
    let now = native::now();
    host.storage
        .atomic_bytes(
            &host.storage.paths.watch().join("runtime/watch-engine"),
            b"expected",
            0o700,
        )
        .unwrap();
    host.storage
        .atomic_bytes(
            &host.storage.paths.watch().join("state/heartbeat"),
            format!("77|Mon Oct 26 01:02:03 2026|{now}|ok|GUARD\n").as_bytes(),
            0o600,
        )
        .unwrap();
    host.storage
        .atomic_json(
            &host.storage.paths.base().join("guard-heartbeat.json"),
            &json!({"time":now,"status":"ok","guard_policy_v1":claude_watch_runtime::config_store::guard_policy_digest(&config).unwrap()}),
        )
        .unwrap();
    let local = AuditSystem::local(&host, &config).unwrap();
    assert_eq!(local["backend_healthy"], true);
    assert_eq!(local["guard_backend_healthy"], false);
    assert_eq!(local["guard"], false);
    assert!(!claude_watch_runtime::services::ServiceSystem::guard_status(&host, &config).unwrap());
    assert!(
        claude_watch_runtime::onboarding::require_transport(&local).is_err(),
        "complete socket sampling must never hide a wrong native runtime identity"
    );
}

#[test]
fn initialization_rejects_missing_stale_and_wrong_identity_heartbeats() {
    let home = Home::new();
    let host = home.host("surge", Some("interface: utun4\n"));
    let config = Config::default();
    let path = host.storage.paths.watch().join("state/heartbeat");
    let now = native::now();
    assert!(claude_watch_runtime::onboarding::require_transport(
        &AuditSystem::local(&host, &config).unwrap()
    )
    .is_err());
    for heartbeat in [
        format!("77|Mon Oct 26 01:02:03 2026|{}|ok|GUARD\n", now - 31.0),
        format!("77|Mon Oct 26 01:02:03 2026|{}|ok|GUARD\n", now + 30.0),
        format!("88|Mon Oct 26 01:02:03 2026|{now}|ok|GUARD\n"),
        format!("77|different-process-start|{now}|ok|GUARD\n"),
        format!("77|Mon Oct 26 01:02:03 2026|{now}|invalid|GUARD\n"),
    ] {
        host.storage
            .atomic_bytes(&path, heartbeat.as_bytes(), 0o600)
            .unwrap();
        let local = AuditSystem::local(&host, &config).unwrap();
        assert_eq!(local["proxy"], "ok");
        assert_eq!(local["tun"], "ok");
        assert_eq!(local["guard_backend_healthy"], false);
        assert!(claude_watch_runtime::onboarding::require_transport(&local).is_err());
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn auto_detection_has_stable_identity_and_does_not_scan_ai_sockets() {
    let home = Home::new();
    let host = home.host("surge", Some("interface: utun4\n"));
    let first = AuditSystem::local(&host, &Config::default()).unwrap();
    let second = AuditSystem::local(&host, &Config::default()).unwrap();
    assert_eq!(first["mode"], "surge");
    assert_eq!(first["proxy"], "ok");
    assert_eq!(first["tun"], "ok");
    assert_eq!(first["context_id"], second["context_id"]);
    assert_eq!(first["context_id"].as_str().unwrap().len(), 64);
    assert_eq!(first["guard"], false);
    assert!(first["rules"].is_object());
}
#[test]
fn tag_process_and_listener_do_not_prove_tun_or_guard_health() {
    let home = Home::new();
    let host = home.host("tag", Some("interface: en0\n"));
    let fact = AuditSystem::local(&host, &Config::default()).unwrap();
    assert_eq!(fact["mode"], "tag");
    assert_eq!(fact["proxy"], "unknown");
    assert_eq!(fact["tun"], "fail");
    assert_eq!(fact["guard"], false);
    assert!(fact["observation_unavailable"]
        .as_array()
        .unwrap()
        .contains(&json!("tag_snapshot")));
}
#[test]
fn failed_route_and_launchd_reads_are_unknown_not_confirmed_changes_or_absence() {
    let home = Home::new();
    let host = home.host("surge", None);
    let fact = AuditSystem::local(&host, &Config::default()).unwrap();
    assert_eq!(fact["tun"], "unknown");
    assert!(fact["observation_unavailable"]
        .as_array()
        .unwrap()
        .contains(&json!("tun_sampling")));
    let job = host.service_job("original").unwrap();
    assert!(job["registered"].is_null());
    assert_eq!(job["trusted"], false);
}
#[test]
fn context_matches_legacy_native_inventory_projection_and_ignores_reparenting() {
    let home = Home::new();
    let host = home.host("surge", Some("interface: utun4\n"));
    let first = AuditSystem::local(&host, &Config::default()).unwrap();
    let expected = json!({"mode":"surge","tun":"ok","interface":"utun4","processes":[{"pid":42,"uid":501,"executable":"/Applications/Surge.app/Contents/MacOS/Surge","start_stamp":null,"start_seconds":1000,"start_microseconds":1}]});
    assert_eq!(first["network_identity"], expected);
    assert_eq!(
        first["context_id"],
        claude_watch_runtime::config_store::policy_digest(&expected).unwrap()
    );
    host.runner
        .parent
        .store(900, std::sync::atomic::Ordering::SeqCst);
    let later = AuditSystem::local(&host, &Config::default()).unwrap();
    assert_eq!(later["context_id"], first["context_id"]);
    assert_eq!(later["processes"][0]["parent"], 900);
}
