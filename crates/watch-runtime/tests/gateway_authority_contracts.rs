use claude_watch_core::{channel::*, processes::ProcessRole};
use claude_watch_runtime::{
    channel_enforcer::{ChannelEnforcer, LocalTunnelEnforcer},
    storage::{Paths, StateStore},
};
use serde_json::json;
use std::{
    io::{Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};

fn command(state: ChannelPermitState, seq: u64, now: f64) -> ChannelEnforcementCommand {
    let version = PolicyVersion {
        policy_digest: "policy".into(),
        guard_policy_digest: "guard".into(),
    };
    let process =
        BoundProcessToken::with_system_identity(1234, 501, 50, 1, ProcessRole::DesktopMain)
            .with_audit_token([501, 501, 20, 501, 20, 1234, 0, 9]);
    ChannelEnforcementCommand {
        family: "claude".into(),
        session_id: Some("session".into()),
        policy_version: version.clone(),
        command_seq: seq,
        permit_generation: 1,
        upstream_endpoint: "http://127.0.0.1:7890".into(),
        target_executor_boot_id: Some("boot".into()),
        issued_at: now,
        allowed_processes: vec![process],
        permit: ChannelPermit {
            family: "claude".into(),
            session_id: Some("session".into()),
            policy_version: version,
            command_seq: seq,
            permit_generation: 1,
            state,
            issued_at: now,
            valid_until: now + 10.,
            reason_code: "fixture".into(),
            context_id: Some("new-network".into()),
            baseline_ip: Some("1.1.1.1".into()),
            members: vec![],
            backend: NetworkBackendKind::Seatbelt,
            vpn_epoch: None,
            coverage_scope: None,
        },
    }
}
fn enforcer() -> LocalTunnelEnforcer {
    let e = LocalTunnelEnforcer::new("boot", None);
    e.set_strict_peer_verification(true);
    e.set_local_proxy_ready(true, 100.).unwrap();
    e.configure_seatbelt_backend(true, 100.).unwrap();
    e
}
#[test]
fn first_flow_capture_catalog_matches_core_classification() {
    use claude_watch_core::{process_roots::{self, Classification, RootEvidence, TrustedCliPaths}, processes::Identity};
    use std::path::Path;
    let home = "/Users/capture-fixture";
    let aliases = process_roots::cli_aliases(Path::new(home));
    let mut trusted = TrustedCliPaths::default();
    let mut resolved = Vec::new();
    for (index, (_, claude)) in aliases.iter().enumerate() {
        let path = format!("/fixture/canonical/{index}/tool");
        if *claude { trusted.claude.insert(path.clone()); } else { trusted.codex.insert(path.clone()); }
        resolved.push(path);
    }
    let mut cases = Vec::new();
    let mut add = |executable: &str, arguments: Vec<&str>, cwd: Option<&str>, bundle_id: Option<&str>, expected: bool| {
        let identity = Identity { pid: 1234, parent: 1, uid: 501, executable: executable.into(), start_seconds: 50, start_microseconds: 1, start_stamp: String::new() };
        let args: Vec<String> = arguments.iter().map(|s| s.to_string()).collect();
        let bundle = executable.split_once(".app/Contents/").map(|(prefix, _)| format!("{prefix}.app"));
        let actual = matches!(process_roots::classify(RootEvidence { identity: &identity, bundle_path: bundle.as_deref(), bundle_id,
            arguments: Some(&args), cwd }, Path::new(home), &trusted, |_| None), Classification::Root(_));
        assert_eq!(actual, expected, "Rust root classification for {executable} / {arguments:?}");
        cases.push(json!({"executable":executable,"arguments":args,"cwd":cwd,"bundle_id":bundle_id,"managed":actual}));
    };
    for path in &resolved { add(path, vec![path], None, None, true); }
    add("/Users/capture-fixture/.local/share/claude/versions/2.1", vec![], None, None, true);
    add("/Applications/Claude.app/Contents/MacOS/Claude", vec![], None, Some("com.anthropic.claudefordesktop"), true);
    add("/Applications/Codex.app/Contents/MacOS/Codex", vec![], None, Some("com.openai.codex"), true);
    add("/Applications/ChatGPT.app/Contents/MacOS/ChatGPT", vec![], None, Some("com.openai.chat"), true);
    add("/tmp/Claude.app/Contents/MacOS/Claude", vec![], None, Some("com.example.ordinary"), false);
    let daemon = "/Users/capture-fixture/.codex/packages/app-server-daemon/releases/v1/bin/codex";
    add(daemon, vec!["codex", "app-server", "daemon"], None, None, true);
    add(daemon, vec!["codex", "app-server", "--listen", "unix:///tmp/fixture.sock"], None, None, true);
    add(daemon, vec!["codex", "app-server", "--listen", "--not-an-endpoint"], None, None, false);
    add(daemon, vec!["codex", "status"], None, None, false);
    add("/opt/bin/node", vec!["node", "--no-warnings", "/opt/node_modules/@anthropic-ai/claude-code/cli.js"], None, None, true);
    add("/opt/bin/bun", vec!["bun", "--", "node_modules/@openai/codex/bin/codex.js"], Some("/opt"), None, true);
    add("/opt/bin/node", vec!["node", "--require", "/opt/node_modules/@anthropic-ai/claude-code/cli.js", "/tmp/server.js"], None, None, false);
    add("/opt/bin/node", vec!["node", "/tmp/server.js", "claude"], None, None, false);
    add("/usr/bin/python3", vec!["python3", "/tmp/ordinary.py"], None, None, false);
    add("/tmp/claude", vec!["claude"], None, None, false);
    if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
        std::fs::write(Path::new(&dir).join("root-capture.json"), serde_json::to_vec(&json!({
            "home":home, "aliases":aliases.iter().map(|(p,_)| p.to_string_lossy()).collect::<Vec<_>>(),
            "resolved_aliases":resolved, "cases":cases,
        })).unwrap()).unwrap();
    }
}
#[test]
fn local_expiry_keeps_authority_command_immutable_and_other_family_renewable() {
    let e = enforcer();
    let mut idle = command(ChannelPermitState::PendingVerification, 1, 100.);
    idle.allowed_processes.clear();
    let mut live = command(ChannelPermitState::Permitted, 1, 108.);
    live.family = "openai".into(); live.permit.family = "openai".into();
    e.apply_command(&idle, 100.).unwrap();
    e.apply_command(&live, 108.).unwrap();
    let before = e.receipt_for("claude", 100.).unwrap().unwrap();
    e.enforce_active_deadlines(111., false).unwrap();
    let after = e.apply_command(&idle, 111.).unwrap();
    assert_eq!(after.command_seq, before.command_seq);
    assert_eq!(after.permit_generation, before.permit_generation);
    // An identical command remains idempotent after local expiry; changing
    // authority under the same sequence would have returned a conflict.

    let mut renewed = live.clone();
    renewed.command_seq = 2; renewed.permit.command_seq = 2;
    renewed.issued_at = 111.; renewed.permit.issued_at = 111.; renewed.permit.valid_until = 121.;
    e.apply_command(&renewed, 111.).unwrap();
    assert_eq!(e.receipt_for("openai", 111.).unwrap().unwrap().enforcement_state, ChannelEnforcementState::Forwarding);
    assert_eq!(e.receipt_for("claude", 111.).unwrap().unwrap().command_seq, before.command_seq);
}

#[test]
fn autonomous_cutoff_cannot_be_undone_by_replaying_the_old_command() {
    let e = enforcer();
    let cmd = command(ChannelPermitState::Permitted, 5, 100.);
    e.apply_command(&cmd, 100.).unwrap();
    e.mark_upstream_unhealthy(101.).unwrap();
    e.mark_upstream_healthy().unwrap();
    let replayed = e.apply_command(&cmd, 101.).unwrap();
    assert_eq!(replayed.permit_state, ChannelPermitState::Revoked);
    let mut invalid = command(ChannelPermitState::Permitted, 4, 101.);
    invalid.permit_generation = 2; invalid.permit.permit_generation = 2;
    assert_eq!(e.apply_command(&invalid, 101.).unwrap_err().code, "stale_or_out_of_order_command");
    let result = e.connect_supervised_tcp("claude", &cmd.allowed_processes[0], 101.);
    assert!(result.is_err(), "even an unexpired command cannot reopen a locally revoked channel");
    let held = command(ChannelPermitState::Permitted, 6, 102.);
    assert_eq!(e.apply_command(&held, 102.).unwrap().permit_state, ChannelPermitState::Revoked,
        "advanced renewal must wait for explicit supervisor revocation");
    let mut revoke = command(ChannelPermitState::Revoked, 7, 103.);
    revoke.permit_generation = 2; revoke.permit.permit_generation = 2;
    e.apply_command(&revoke, 103.).unwrap();
    let mut renewed = command(ChannelPermitState::Permitted, 8, 104.);
    renewed.permit_generation = 3; renewed.permit.permit_generation = 3;
    e.apply_command(&renewed, 104.).unwrap();
    assert_eq!(e.receipt_for("claude", 104.).unwrap().unwrap().enforcement_state, ChannelEnforcementState::Forwarding);
}

#[test]
fn strict_permission_requires_the_audit_identity_and_duplicate_payload_is_exact() {
    let e = enforcer();
    let cmd = command(ChannelPermitState::Permitted, 1, 100.);
    e.apply_command(&cmd, 100.).unwrap();
    for missing_or_changed in [0, 1] {
        let mut process = cmd.allowed_processes[0].clone();
        if missing_or_changed == 0 { process.audit_token = None; }
        else { process.audit_token.as_mut().unwrap()[7] += 1; }
        assert_eq!(e.connect_supervised_tcp("claude", &process, 100.).err().expect("unverified identity must be rejected").code, "process_attribution_rejected");
    }
    for field in [0, 1, 2] {
        let mut changed = cmd.clone();
        match field {
            0 => changed.permit.context_id = Some("different-network".into()),
            1 => changed.permit.baseline_ip = Some("8.8.8.8".into()),
            _ => { changed.issued_at += 0.1; changed.permit.issued_at += 0.1; }
        }
        assert_eq!(e.apply_command(&changed, 100.1).unwrap_err().code, "conflicting_command_seq");
    }
    assert_eq!(e.apply_command(&cmd, 100.1).unwrap().command_seq, cmd.command_seq);
}

#[test]
fn failed_inventory_revokes_but_retains_managed_cli_membership() {
    use claude_watch_runtime::channel_supervisor::{ChannelSupervisor, SupervisionEvent};
    let root = std::env::temp_dir().join(format!("cw-inventory-contract-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let store = StateStore::new(Paths::new(&root).unwrap());
    let enforcer = Arc::new(LocalTunnelEnforcer::new("boot", Some(store.clone())));
    enforcer.activate_interception(100.).unwrap();
    let mut supervisor = ChannelSupervisor::new(store.clone(), Some(enforcer.clone()), None).unwrap();
    let mut processes = command(ChannelPermitState::Revoked, 1, 100.).allowed_processes;
    processes[0].role = ProcessRole::Cli;
    supervisor.handle_event(SupervisionEvent::ProcessInventoryUpdated {
        family: "claude".into(), desktops: vec![], processes, observed_at: 100.,
    }).unwrap();
    let snapshot = supervisor.handle_event(SupervisionEvent::ProcessInventoryUnavailable {
        family: "claude".into(), observed_at: 101.,
    }).unwrap();
    assert_eq!(snapshot.families["claude"].permit_state, ChannelPermitState::Revoked);
    let command = store.read_json(&store.paths.watch().join("state/channel-command-claude.json"), json!(null)).unwrap();
    assert_eq!(command["allowed_processes"][0]["pid"], 1234);
    assert_eq!(command["permit"]["reason_code"], "channel_inventory_incomplete");
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn client_identity_headers_cannot_replace_kernel_attribution() {
    let e = Arc::new(enforcer());
    let stop = Arc::new(AtomicBool::new(false));
    let (address, worker) = e
        .start_local_proxy_listener("127.0.0.1:0", stop.clone(), 100.)
        .unwrap();
    let mut socket = std::net::TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let _ = socket.write_all(
        b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nX-Watch-PID: 1234\r\nX-Watch-UID: 501\r\n\r\n",
    );
    let mut bytes = [0; 128];
    let count = socket.read(&mut bytes).unwrap();
    assert!(String::from_utf8_lossy(&bytes[..count]).contains("403"));
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
}

#[test]
fn explicit_proxy_connection_does_not_tunnel_upstream_back_to_itself() {
    let tag = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = tag.local_addr().unwrap().to_string();
    let (tx, rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = tag.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut header = Vec::new();
        let mut byte = [0];
        while !header.ends_with(b"\r\n\r\n") {
            peer.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
        }
        assert!(String::from_utf8_lossy(&header).starts_with("CONNECT api.anthropic.com:443 "));
        peer.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        tx.send(()).unwrap();
        assert_eq!(
            peer.read(&mut byte).unwrap(),
            0,
            "revocation must close the real TAG connection"
        );
    });
    let e = LocalTunnelEnforcer::new("explicit-proxy", None);
    e.activate_interception(100.).unwrap();
    let mut cmd = command(ChannelPermitState::Permitted, 1, 100.);
    cmd.target_executor_boot_id = Some(e.boot_id().unwrap());
    cmd.upstream_endpoint = format!("http://{endpoint}");
    e.apply_command(&cmd, 100.).unwrap();
    let (_, mut stream) = e
        .connect_supervised_tcp_to("claude", &cmd.allowed_processes[0], &endpoint, 100.)
        .unwrap();
    stream
        .write_all(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n")
        .unwrap();
    rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let mut revoked = command(ChannelPermitState::Revoked, 2, 100.1);
    revoked.target_executor_boot_id = Some(e.boot_id().unwrap());
    revoked.upstream_endpoint = cmd.upstream_endpoint;
    e.apply_command(&revoked, 100.1).unwrap();
    server.join().unwrap();
}
#[test]
fn unchanged_observation_does_not_outrun_acknowledgements_but_identity_change_does() {
    use claude_watch_runtime::channel_supervisor::{ChannelSupervisor, SupervisionEvent};
    let root = std::env::temp_dir().join(format!("cw-command-contract-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let store = StateStore::new(Paths::new(&root).unwrap());
    let mut supervisor = ChannelSupervisor::new(store, None, None).unwrap();
    let event = |time, processes| SupervisionEvent::ProcessInventoryUpdated {
        family: "claude".into(),
        desktops: vec![],
        processes,
        observed_at: time,
    };
    let a = supervisor.handle_event(event(100., vec![])).unwrap();
    let b = supervisor.handle_event(event(101., vec![])).unwrap();
    assert_eq!(
        a.families["claude"].command_seq,
        b.families["claude"].command_seq
    );
    let c = supervisor
        .handle_event(event(
            102.,
            command(ChannelPermitState::Revoked, 1, 102.).allowed_processes,
        ))
        .unwrap();
    assert!(c.families["claude"].command_seq > b.families["claude"].command_seq);
    std::fs::remove_dir_all(root).unwrap();
}


#[test]
fn legacy_command_cannot_mutate_or_replace_seatbelt_authority() {
    let e = enforcer();
    let cmd = command(ChannelPermitState::Permitted, 1, 100.);
    let before = e.apply_command(&cmd, 100.).unwrap();
    let mut legacy = command(ChannelPermitState::Permitted, 2, 101.);
    legacy.permit.backend = NetworkBackendKind::NetworkExtension;
    assert_eq!(e.apply_command(&legacy, 101.).unwrap_err().code, "legacy_network_backend_removed");
    let after = e.receipt_for("claude", 101.).unwrap().unwrap();
    assert_eq!(after.command_seq, before.command_seq);
    assert_eq!(after.backend, NetworkBackendKind::Seatbelt);
    assert!(!after.system_extension_active);
    let coverage = e.protocol_coverage_boundaries();
    assert_eq!(coverage["backend"], "seatbelt");
    assert_eq!(coverage["unmanaged_processes"]["disposition"], "outside_protected_scope");
    assert!(coverage.get("system_extension_active").is_none());
}
