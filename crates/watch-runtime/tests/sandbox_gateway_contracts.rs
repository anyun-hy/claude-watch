#[path = "support/hardened_helper.rs"]
mod hardened_helper;

use claude_watch_core::{
    channel::{
        BoundProcessToken, ChannelEnforcementCommand, ChannelPermit, ChannelPermitState,
        NetworkBackendKind, PolicyVersion,
    },
    controlled_launch::{
        ControlledLaunchRequest, ManagedInstanceState, ProxyAdaptationKind,
    },
    processes::{LaunchTarget, ProcessRole},
    session::Desktop,
    vpn::VpnEpoch,
};
use claude_watch_runtime::{
    channel_enforcer::{ChannelEnforcer, LocalTunnelEnforcer},
    sandbox_launch::{
        generate_nono_seatbelt_profile, register_helper_with_daemon, PortTakeoverProbeOutcome,
        SandboxLaunchRegistry,
    },
    storage::{Paths, StateStore},
};
use claude_watch_system::{
    apply_macos_seatbelt_profile, effective_uid, inspect_process_identity, sha256_file_hex,
    SandboxPeerVerifier,
};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
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

fn make_temp_store(prefix: &str) -> (TempRoot, StateStore) {
    let short_id = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let dir = PathBuf::from("/tmp").join(format!("{prefix}-{short_id}"));
    fs::create_dir_all(&dir).unwrap();
    let store = StateStore::new(Paths::new(&dir).unwrap());
    (TempRoot(dir), store)
}

fn test_policy_version() -> PolicyVersion {
    PolicyVersion {
        policy_digest: "policy-digest-v1".into(),
        guard_policy_digest: "guard-digest-v1".into(),
    }
}

fn current_test_binary_verifier() -> (String, String, SandboxPeerVerifier) {
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .expect("current test exe");
    let exe_str = exe.to_string_lossy().into_owned();
    let sha = sha256_file_hex(&exe).expect("test exe sha256");
    let verifier = SandboxPeerVerifier {
        expected_uid: effective_uid(),
        expected_helper_executable: exe_str.clone(),
        expected_helper_sha256: sha.clone(),
        expected_helper_cdhash: hardened_helper::cdhash(&exe),
    };
    (exe_str, sha, verifier)
}

#[test]
fn i01_manifest_bound_helper_verifier_rejects_unmanifested_or_tampered_helper() {
    use claude_watch_runtime::sandbox_launch::build_helper_verifier_from_manifest;
    let (tmp, _store) = make_temp_store("cw-sandbox-manifest-i01");
    let (exe_str, _, _) = current_test_binary_verifier();
    let helper_copy = tmp.0.join("watch-sandbox-launcher");
    hardened_helper::copy_signed(Path::new(&exe_str), &helper_copy);
    let exe_sha = sha256_file_hex(&helper_copy).unwrap();

    // 1. Missing manifest directory must fail closed (`helper_manifest_hash_missing`)
    let err_missing = build_helper_verifier_from_manifest(&tmp.0, &helper_copy).unwrap_err();
    assert_eq!(err_missing.code, "helper_manifest_hash_missing");

    // 2. Manifest with mismatched SHA-256 must reject the helper (`helper_manifest_hash_mismatch`)
    fs::write(
        tmp.0.join("components.json"),
        serde_json::json!({
            "hashes": {
                "watch-sandbox-launcher": "f".repeat(64)
            }
        })
        .to_string(),
    )
    .unwrap();
    let err_mismatch = build_helper_verifier_from_manifest(&tmp.0, &helper_copy).unwrap_err();
    assert_eq!(err_mismatch.code, "helper_manifest_hash_mismatch");

    // 3. A matching SHA without a CDHash is incomplete.
    fs::write(tmp.0.join("components.json"), serde_json::json!({"hashes":{"watch-sandbox-launcher":exe_sha}}).to_string()).unwrap();
    assert_eq!(build_helper_verifier_from_manifest(&tmp.0, &helper_copy).unwrap_err().code, "helper_manifest_cdhash_missing");
    // 4. Both final-byte pins must match the same manifest.
    fs::write(
        tmp.0.join("components.json"),
        hardened_helper::components(&helper_copy).to_string(),
    )
    .unwrap();
    let verifier = build_helper_verifier_from_manifest(&tmp.0, &helper_copy)
        .expect("manifest-bound verifier");
    assert_eq!(verifier.expected_helper_sha256, exe_sha);
    let primary = tmp.0.join("BuildInfo.plist");
    let hashes = format!("<key>RuntimeHashes</key><dict><key>watch-sandbox-launcher</key><string>{exe_sha}</string></dict>");
    fs::write(&primary, format!("<plist version=\"1.0\"><dict>{hashes}</dict></plist>")).unwrap();
    assert_eq!(build_helper_verifier_from_manifest(&tmp.0, &helper_copy).unwrap_err().code,
        "helper_manifest_cdhash_missing", "incomplete primary may not borrow fallback signing identity");
    let cdhash = hardened_helper::cdhash(&helper_copy);
    fs::write(&primary, format!("<plist version=\"1.0\"><dict>{hashes}<key>RuntimeCDHashes</key><dict><key>watch-sandbox-launcher</key><string>{cdhash}</string></dict></dict></plist>")).unwrap();
    assert_eq!(build_helper_verifier_from_manifest(&tmp.0, &helper_copy).unwrap().expected_helper_cdhash, cdhash);
}

#[test]
fn weak_live_peer_with_matching_manifest_cannot_register_or_publish_evidence() {
    use claude_watch_runtime::sandbox_launch::build_helper_verifier_from_manifest;
    let (tmp, store) = make_temp_store("cw-weak-helper");
    let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
    fs::write(tmp.0.join("components.json"), hardened_helper::components(&exe).to_string()).unwrap();
    let verifier = build_helper_verifier_from_manifest(&tmp.0, &exe).unwrap();
    let registry = Arc::new(SandboxLaunchRegistry::new("weak-peer", test_policy_version(), verifier, Some(store)));
    let listener = UnixListener::bind(tmp.0.join("registration.sock")).unwrap();
    let mut client = UnixStream::connect(tmp.0.join("registration.sock")).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let (server, _) = listener.accept().unwrap();
    let rejection = registry.handle_helper_registration_stream(server, 100.).unwrap();
    assert_eq!(rejection.error_code.as_deref(), Some("untrusted_sandbox_helper_peer"));
    assert!(!rejection.accepted && rejection.instance_id.is_none());
    assert!(registry.instances().is_empty());
    let mut wire = String::new();
    client.read_to_string(&mut wire).unwrap();
    assert!(wire.contains("untrusted_sandbox_helper_peer"));
    println!("matching disk SHA/CDHash with default weak runtime rejected before request read; registry empty");
}

#[test]
fn i01_and_i04_helper_registration_verifies_kernel_peer_and_rejects_spoofing_or_stale_boot_id() {
    if !hardened_helper::hardened_test_process("i01_and_i04_helper_registration_verifies_kernel_peer_and_rejects_spoofing_or_stale_boot_id") { return; }
    let (tmp, store) = make_temp_store("cw-sandbox-i01");
    let (exe_str, exe_sha, verifier) = current_test_binary_verifier();
    let (peer, _other) = UnixStream::pair().unwrap();
    let mut incorrect = verifier.clone();
    incorrect.expected_helper_cdhash = "0".repeat(40);
    assert!(claude_watch_system::verify_sandbox_helper_peer(&peer, &incorrect).is_none());
    let pv = test_policy_version();

    let registry = Arc::new(SandboxLaunchRegistry::new(
        "boot-epoch-1",
        pv.clone(),
        verifier,
        Some(store),
    ));
    registry.approve_target_executable(&exe_str, &exe_sha);

    let sock_path = tmp.0.join("sandbox-reg.sock");
    let stop = Arc::new(AtomicBool::new(false));
    let handle = registry
        .start_registration_listener(&sock_path, Arc::clone(&stop))
        .expect("listener");

    let gw: SocketAddr = "127.0.0.1:18899".parse().unwrap();
    let sbpl = generate_nono_seatbelt_profile(gw, &[7890]).expect("sbpl");

    // 1. Valid registration succeeds
    let valid_req = ControlledLaunchRequest {
        entry_id: "io.local.watchpanel.entry.claude-cli".into(),
        target: LaunchTarget::ClaudeCli,
        target_executable: exe_str.clone(),
        target_fingerprint: exe_sha.clone(),
        args: vec!["--version".into()],
        cwd: None,
        proxy_adaptation: ProxyAdaptationKind::EnvOnly,
        gateway_endpoint: gw.to_string(),
        policy_version: pv.clone(),
        vpn_epoch: Some(VpnEpoch::new("vpn-boot-1", 1)),
        launch_nonce: "nonce-valid-001".into(),
        executor_boot_id: "boot-epoch-1".into(),
        script_entry: None,
        script_fingerprint: None,
        interpreter: None,
        interpreter_fingerprint: None,
        script_source: None,
    };
    let resp = register_helper_with_daemon(&sock_path, valid_req.clone(), true, &sbpl)
        .expect("register valid");
    assert!(
        resp.accepted,
        "valid helper registration must succeed: {resp:?}"
    );
    assert!(resp.instance_id.is_some());

    // 2. Replay with same nonce is rejected
    let replay_resp = register_helper_with_daemon(&sock_path, valid_req.clone(), true, &sbpl)
        .expect("register replay");
    assert!(!replay_resp.accepted);
    assert_eq!(
        replay_resp.error_code.as_deref(),
        Some("launch_nonce_replayed")
    );

    // 3. Stale executor_boot_id is rejected (`I04`)
    let mut stale_boot_req = valid_req.clone();
    stale_boot_req.launch_nonce = "nonce-stale-boot-002".into();
    stale_boot_req.executor_boot_id = "boot-epoch-old".into();
    let stale_resp =
        register_helper_with_daemon(&sock_path, stale_boot_req, true, &sbpl).expect("stale boot");
    assert!(!stale_resp.accepted);
    assert_eq!(
        stale_resp.error_code.as_deref(),
        Some("executor_boot_id_mismatch")
    );

    // 4. Unapproved target executable or mismatched fingerprint is rejected (`I01`)
    let mut bad_fp_req = valid_req.clone();
    bad_fp_req.launch_nonce = "nonce-bad-fp-003".into();
    bad_fp_req.target_fingerprint = "0".repeat(64);
    let bad_fp_resp =
        register_helper_with_daemon(&sock_path, bad_fp_req, true, &sbpl).expect("bad fp");
    assert!(!bad_fp_resp.accepted);
    assert_eq!(
        bad_fp_resp.error_code.as_deref(),
        Some("target_fingerprint_mismatch")
    );

    // 5. Helper that has not applied sandbox (`sandbox_applied == false`) is rejected
    let mut unsandboxed_req = valid_req.clone();
    unsandboxed_req.launch_nonce = "nonce-unsandboxed-004".into();
    let unsandboxed_resp =
        register_helper_with_daemon(&sock_path, unsandboxed_req, false, &sbpl)
            .expect("unsandboxed");
    assert!(!unsandboxed_resp.accepted);
    assert_eq!(
        unsandboxed_resp.error_code.as_deref(),
        Some("sandbox_not_applied")
    );

    stop.store(true, Ordering::Release);
    let _ = handle.join();
}

#[test]
fn i02_and_p01_live_loopback_tcp_socket_attribution_and_protocol_relay() {
    if !hardened_helper::hardened_test_process("i02_and_p01_live_loopback_tcp_socket_attribution_and_protocol_relay") { return; }
    let (tmp, store) = make_temp_store("cw-sandbox-i02-p01");
    let (exe_str, exe_sha, verifier) = current_test_binary_verifier();
    let pv = test_policy_version();

    // Start mock HTTP + WebSocket + CONNECT upstream server
    let upstream_listener = TcpListener::bind("127.0.0.1:0").expect("upstream bind");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_stop = Arc::new(AtomicBool::new(false));
    let upstream_stop_bg = Arc::clone(&upstream_stop);
    let _ = upstream_listener.set_nonblocking(true);
    let upstream_handle = thread::spawn(move || {
        while !upstream_stop_bg.load(Ordering::Acquire) {
            match upstream_listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                    let mut buf = [0u8; 2048];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    if req_str.contains("Upgrade: websocket") {
                        let resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nws-ack";
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.flush();
                    } else if req_str.starts_with("GET ") {
                        let body = "http-forward-ok";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.flush();
                    } else {
                        let _ = stream.write_all(b"connect-tunnel-ok");
                        let _ = stream.flush();
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    // Start Watch LocalTunnelEnforcer in Seatbelt mode
    let boot_id = "boot-sandbox-p01".to_string();
    let enforcer = Arc::new(LocalTunnelEnforcer::new(boot_id.clone()));
    let now = 1_700_000_100.0;
    enforcer.set_clock(move || now + 1.0).unwrap();
    enforcer.configure_seatbelt_backend(true, now).unwrap();
    let proxy_stop = Arc::new(AtomicBool::new(false));
    let (proxy_addr, proxy_handle) = enforcer
        .start_local_proxy_listener("127.0.0.1:0", Arc::clone(&proxy_stop), now)
        .expect("proxy listener");
    // Our mock upstream server speaks target HTTP/WS/raw directly after connect
    enforcer.set_require_upstream_connect_handshake(false).unwrap();

    let registry = Arc::new(SandboxLaunchRegistry::new(
        boot_id.clone(),
        pv.clone(),
        verifier,
        Some(store),
    ));
    registry.approve_target_executable(&exe_str, &exe_sha);

    // Wire I02 live socket attributor into LocalTunnelEnforcer
    let reg_for_attr = Arc::clone(&registry);
    enforcer
        .set_accepted_connection_attributor(move |ctx| {
            reg_for_attr.attribute_accepted_connection(ctx, 1_700_000_105.0)
        })
        .unwrap();

    let me = inspect_process_identity(std::process::id()).expect("me");
    let my_token = BoundProcessToken::with_system_identity(
        me.pid,
        me.uid,
        me.start_seconds,
        me.start_microseconds,
        ProcessRole::Cli,
    )
    .with_audit_token(me.audit_token);

    let vpn_epoch = VpnEpoch::new("vpn-boot-p01", 1);
    let permit = ChannelPermit {
        family: "claude".into(),
        session_id: Some("sess-p01".into()),
        policy_version: pv.clone(),
        permit_generation: 1,
        command_seq: 1,
        state: ChannelPermitState::Permitted,
        reason_code: "verified".into(),
        issued_at: now,
        valid_until: now + 300.0,
        context_id: Some("ctx-p01".into()),
        baseline_ip: Some("1.1.1.1".into()),
        members: vec![Desktop {
            pid: me.pid,
            start_seconds: me.start_seconds,
            start_microseconds: me.start_microseconds,
        }],
        backend: NetworkBackendKind::Seatbelt,
        vpn_epoch: Some(vpn_epoch),
        coverage_scope: None,
    };
    let cmd = ChannelEnforcementCommand {
        family: "claude".into(),
        session_id: Some("sess-p01".into()),
        policy_version: pv.clone(),
        permit_generation: 1,
        command_seq: 1,
        permit,
        allowed_processes: vec![my_token],
        upstream_endpoint: upstream_addr.to_string(),
        target_executor_boot_id: enforcer.boot_id().ok(),
        issued_at: now,
    };
    let receipt = enforcer.apply_command(&cmd, now).expect("apply command");
    assert_eq!(
        receipt.enforcement_state,
        claude_watch_core::channel::ChannelEnforcementState::Forwarding
    );

    // Before registering this process in SandboxLaunchRegistry, an unattributed connection must be rejected (403)
    {
        let mut s = TcpStream::connect(proxy_addr).expect("connect unattributed");
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        let req = format!(
            "GET http://{upstream_addr}/v1/messages HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n"
        );
        s.write_all(req.as_bytes()).expect("write");
        let mut resp = String::new();
        let _ = s.read_to_string(&mut resp);
        assert!(
            resp.starts_with("HTTP/1.1 403"),
            "unregistered process must be rejected by I02 live socket attribution, got: {resp}"
        );
    }

    // Now register the current process via the kernel-verified Unix registration socket
    let sock_path = tmp.0.join("sandbox-reg-p01.sock");
    let reg_stop = Arc::new(AtomicBool::new(false));
    let reg_handle = registry
        .start_registration_listener(&sock_path, Arc::clone(&reg_stop))
        .expect("reg listener");
    let sbpl = generate_nono_seatbelt_profile(proxy_addr, &[7890]).expect("sbpl");
    let launch_req = ControlledLaunchRequest {
        entry_id: "io.local.watchpanel.entry.claude-cli".into(),
        target: LaunchTarget::ClaudeCli,
        target_executable: exe_str,
        target_fingerprint: exe_sha,
        args: vec![],
        cwd: None,
        proxy_adaptation: ProxyAdaptationKind::EnvOnly,
        gateway_endpoint: proxy_addr.to_string(),
        policy_version: pv.clone(),
        vpn_epoch: Some(VpnEpoch::new("vpn-boot-p01", 1)),
        launch_nonce: "nonce-p01-001".into(),
        executor_boot_id: boot_id.clone(),
        script_entry: None,
        script_fingerprint: None,
        interpreter: None,
        interpreter_fingerprint: None,
        script_source: None,
    };
    let reg_resp = register_helper_with_daemon(&sock_path, launch_req, true, &sbpl).expect("reg");
    assert!(reg_resp.accepted);

    // 1. HTTP forward proxy (`GET http://...`) now succeeds and attributes via I02!
    {
        let mut s = TcpStream::connect(proxy_addr).expect("connect http");
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        let req = format!(
            "GET http://{upstream_addr}/v1/messages HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n"
        );
        s.write_all(req.as_bytes()).expect("write http");
        let mut resp = String::new();
        let _ = s.read_to_string(&mut resp);
        assert!(
            resp.contains("200 OK") && resp.contains("http-forward-ok"),
            "expected HTTP forward proxy 200 OK, got: {resp}"
        );
    }

    // Verify instance transitioned to `ExecVerified`
    let instances = registry.instances();
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].state, ManagedInstanceState::ExecVerified);
    assert!(instances[0].has_verified_protection(&boot_id, &pv));

    // 2. WebSocket upgrade (`Upgrade: websocket`) succeeds over loopback gateway
    {
        let mut s = TcpStream::connect(proxy_addr).expect("connect ws");
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        let req = format!(
            "GET http://{upstream_addr}/ws HTTP/1.1\r\nHost: {upstream_addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
        );
        s.write_all(req.as_bytes()).expect("write ws");
        let mut resp = String::new();
        let mut buf = [0u8; 512];
        for _ in 0..4 {
            if let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                resp.push_str(&String::from_utf8_lossy(&buf[..n]));
                if resp.contains("101 Switching Protocols") && resp.contains("ws-ack") {
                    break;
                }
            } else {
                break;
            }
        }
        assert!(
            resp.contains("101 Switching Protocols") && resp.contains("ws-ack"),
            "expected WebSocket 101 Switching Protocols, got: {resp}"
        );
    }

    // 3. HTTPS `CONNECT` tunnel succeeds over loopback gateway
    {
        let mut s = TcpStream::connect(proxy_addr).expect("connect tunnel");
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        let req = format!("CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n");
        s.write_all(req.as_bytes()).expect("write connect");
        let mut buf = [0u8; 256];
        let n = s.read(&mut buf).expect("read connect 200");
        let head = String::from_utf8_lossy(&buf[..n]);
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "expected CONNECT 200 Connection Established, got: {head}"
        );
        s.write_all(b"hello-tunnel").expect("write payload");
        let n2 = s.read(&mut buf).expect("read tunnel payload");
        let payload = String::from_utf8_lossy(&buf[..n2]);
        assert_eq!(payload, "connect-tunnel-ok");
    }

    proxy_stop.store(true, Ordering::Release);
    let _ = proxy_handle.join();
    reg_stop.store(true, Ordering::Release);
    let _ = reg_handle.join();
    upstream_stop.store(true, Ordering::Release);
    let _ = upstream_handle.join();
}

#[test]
fn p01_child_process_seatbelt_profile_blocks_direct_tcp_vpn_udp_and_unix_relays_while_allowing_gateway() {
    if std::env::var("CW_TEST_SEATBELT_CHILD").as_deref() == Ok("1") {
        let gw_addr: SocketAddr = std::env::var("CW_TEST_GW_ADDR")
            .unwrap()
            .parse()
            .unwrap();
        let direct_addr: SocketAddr = std::env::var("CW_TEST_DIRECT_ADDR")
            .unwrap()
            .parse()
            .unwrap();
        let vpn_port: u16 = std::env::var("CW_TEST_VPN_PORT")
            .unwrap()
            .parse()
            .unwrap();
        let unix_path = std::env::var("CW_TEST_UNIX_SOCK").unwrap();
        let reg_sock = std::env::var("CW_TEST_REG_SOCK").unwrap();

        let sbpl = generate_nono_seatbelt_profile(gw_addr, &[vpn_port]).expect("sbpl");
        let pre_reg_stream = UnixStream::connect(&reg_sock).expect("pre-connect reg stream");
        apply_macos_seatbelt_profile(&sbpl).expect("apply seatbelt in child");

        // 1. Direct TCP to non-gateway must fail (EPERM / PermissionDenied)
        let direct_res = TcpStream::connect_timeout(&direct_addr, Duration::from_millis(500));
        assert!(
            direct_res.is_err(),
            "direct non-gateway TCP must be blocked by Seatbelt"
        );

        // 2. Direct TCP to VPN port must fail
        let vpn_addr = SocketAddr::from(([127, 0, 0, 1], vpn_port));
        let vpn_res = TcpStream::connect_timeout(&vpn_addr, Duration::from_millis(500));
        assert!(
            vpn_res.is_err(),
            "direct VPN port TCP must be blocked by Seatbelt"
        );

        // 3. Outbound UDP/DNS (:53) must fail
        if let Ok(udp) = UdpSocket::bind("127.0.0.1:0") {
            let dns_res = udp.send_to(b"dns-probe", "127.0.0.1:53");
            assert!(
                dns_res.is_err(),
                "outbound UDP DNS :53 must be blocked by Seatbelt"
            );
        }

        // 4. New Unix domain socket connect after Seatbelt must fail (`(deny network*)`)
        let unix_res = UnixStream::connect(&unix_path);
        assert!(
            unix_res.is_err(),
            "new AF_UNIX connect must be blocked by Seatbelt"
        );

        drop(pre_reg_stream);

        // 5. Loopback TCP to Watch gateway port MUST succeed!
        let mut gw_stream =
            TcpStream::connect_timeout(&gw_addr, Duration::from_secs(1)).expect("connect gateway");
        gw_stream.write_all(b"gateway-allowed").expect("write gw");
        let mut ack = [0u8; 16];
        let n = gw_stream.read(&mut ack).expect("read gw");
        assert_eq!(&ack[..n], b"gw-ok");
        return;
    }

    let (tmp, _store) = make_temp_store("cw-sandbox-child-p01");
    let gw_listener = TcpListener::bind("127.0.0.1:0").expect("gw listener");
    let gw_addr = gw_listener.local_addr().unwrap();

    let direct_listener = TcpListener::bind("127.0.0.1:0").expect("direct listener");
    let direct_addr = direct_listener.local_addr().unwrap();

    let vpn_listener = TcpListener::bind("127.0.0.1:0").expect("vpn listener");
    let vpn_port = vpn_listener.local_addr().unwrap().port();

    let unix_path = tmp.0.join("relay.sock");
    let _unix_listener = UnixListener::bind(&unix_path).expect("unix listener");

    let reg_sock = tmp.0.join("reg.sock");
    let _reg_listener = UnixListener::bind(&reg_sock).expect("reg listener");

    let gw_handle = thread::spawn(move || {
        if let Ok((mut s, _)) = gw_listener.accept() {
            let mut buf = [0u8; 32];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"gw-ok");
        }
    });

    let exe = std::env::current_exe().expect("current exe");
    let status = Command::new(exe)
        .arg("--exact")
        .arg("p01_child_process_seatbelt_profile_blocks_direct_tcp_vpn_udp_and_unix_relays_while_allowing_gateway")
        .arg("--nocapture")
        .env("CW_TEST_SEATBELT_CHILD", "1")
        .env("CW_TEST_GW_ADDR", gw_addr.to_string())
        .env("CW_TEST_DIRECT_ADDR", direct_addr.to_string())
        .env("CW_TEST_VPN_PORT", vpn_port.to_string())
        .env("CW_TEST_UNIX_SOCK", &unix_path)
        .env("CW_TEST_REG_SOCK", &reg_sock)
        .status()
        .expect("spawn child");

    assert!(status.success(), "child seatbelt boundary check failed");
    let _ = gw_handle.join();
}

#[test]
fn i03_gateway_port_takeover_probe_triggers_fail_closed_production_gate() {
    if std::env::var("CW_TEST_I03_SANDBOX_CHILD").as_deref() == Ok("1") {
        let p_gw: SocketAddr = std::env::var("CW_TEST_I03_PGW")
            .unwrap()
            .parse()
            .unwrap();
        let echo_q: SocketAddr = std::env::var("CW_TEST_I03_ECHO_Q")
            .unwrap()
            .parse()
            .unwrap();
        let sbpl = generate_nono_seatbelt_profile(p_gw, &[7890]).expect("sbpl");
        apply_macos_seatbelt_profile(&sbpl).expect("apply seatbelt in i03 child");

        // Verify direct connection to echo_q is blocked by Seatbelt
        assert!(
            TcpStream::connect_timeout(&echo_q, Duration::from_millis(300)).is_err(),
            "Seatbelt child must not be able to connect directly to echo_q"
        );

        // Reconnect to P_gw (now bound by rogue listener) inside Seatbelt!
        let mut exp = TcpStream::connect_timeout(&p_gw, Duration::from_secs(1))
            .expect("sandboxed child connect to rogue P_gw");
        let req = format!("CONNECT {echo_q} HTTP/1.1\r\nHost: {echo_q}\r\n\r\n");
        exp.write_all(req.as_bytes())
            .expect("sandboxed child write CONNECT headers to rogue P_gw");
        let mut resp = [0u8; 256];
        let _ = exp.read(&mut resp);
        return;
    }

    let (_tmp, store) = make_temp_store("cw-sandbox-i03");
    let (_, _, verifier) = current_test_binary_verifier();
    let registry = SandboxLaunchRegistry::new(
        "boot-i03",
        test_policy_version(),
        verifier,
        Some(store.clone()),
    );

    // 1. Start echo server Q on loopback
    let echo_q = TcpListener::bind("127.0.0.1:0").expect("bind Q");
    let echo_q_addr = echo_q.local_addr().unwrap();
    let echo_handle = thread::spawn(move || {
        for _ in 0..2 {
            if let Ok((mut s, _)) = echo_q.accept() {
                let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nQ-OK");
            }
        }
    });

    // 2. Bind legitimate gateway on port P_gw, then stop it to release P_gw
    let legit_gw = TcpListener::bind("127.0.0.1:0").expect("bind P_gw");
    let p_gw = legit_gw.local_addr().unwrap();
    drop(legit_gw);

    // 3. Bind rogue local proxy on the exact same port P_gw
    let rogue_gw = TcpListener::bind(p_gw).expect("rogue bind P_gw");
    let rogue_handle = thread::spawn(move || {
        let mut received_headers_before_auth = false;
        let mut captured_len = 0usize;
        let mut control_forwarded = false;
        let mut echo_received = false;
        for idx in 0..2 {
            if let Ok((mut client, _)) = rogue_gw.accept() {
                let _ = client.set_read_timeout(Some(Duration::from_millis(500)));
                let mut buf = [0u8; 1024];
                let n = client.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                if req.starts_with("CONNECT ") || req.starts_with("GET ") {
                    if idx == 1 {
                        received_headers_before_auth = true;
                        captured_len = n;
                    }
                    if let Ok(mut q_stream) = TcpStream::connect(echo_q_addr) {
                        let _ = q_stream.write_all(&buf[..n]);
                        let mut q_resp = Vec::new();
                        let _ = q_stream.read_to_end(&mut q_resp);
                        let _ = client.write_all(&q_resp);
                        if String::from_utf8_lossy(&q_resp).contains("Q-OK") {
                            if idx == 0 {
                                control_forwarded = true;
                            } else {
                                echo_received = true;
                            }
                        }
                    }
                }
            }
        }
        (
            control_forwarded,
            received_headers_before_auth,
            captured_len,
            echo_received,
        )
    });

    // 4. Control group: normal client connects to rogue proxy on P_gw and reaches echo Q
    {
        let mut ctrl = TcpStream::connect(p_gw).expect("ctrl connect");
        let req = format!("GET http://{echo_q_addr}/probe HTTP/1.1\r\nHost: {echo_q_addr}\r\n\r\n");
        ctrl.write_all(req.as_bytes()).expect("ctrl write");
        let mut resp = String::new();
        let _ = ctrl.read_to_string(&mut resp);
        assert!(resp.contains("Q-OK"));
    }

    // 5. Experimental group: spawn a REAL child process that applies the Seatbelt profile
    //    allowing ONLY `localhost:<P_gw>`, and attempts to reconnect to `P_gw` after port takeover!
    let exe = std::env::current_exe().expect("current exe");
    let child_status = Command::new(exe)
        .arg("--exact")
        .arg("i03_gateway_port_takeover_probe_triggers_fail_closed_production_gate")
        .arg("--nocapture")
        .env("CW_TEST_I03_SANDBOX_CHILD", "1")
        .env("CW_TEST_I03_PGW", p_gw.to_string())
        .env("CW_TEST_I03_ECHO_Q", echo_q_addr.to_string())
        .status()
        .expect("spawn sandboxed i03 child");
    let sandboxed_connected = child_status.success();

    let (control_forwarded, sent_before_auth, captured_len, echo_received) =
        rogue_handle.join().expect("rogue join");
    let _ = echo_handle.join();

    let outcome = PortTakeoverProbeOutcome {
        control_client_forwarded: control_forwarded,
        sandboxed_client_reconnected: sandboxed_connected,
        rogue_gateway_received_headers_or_data: sent_before_auth,
        rogue_captured_bytes_len: captured_len,
        echo_server_received_target_payload: echo_received,
        server_identity_gate_passed: !sent_before_auth,
        failure_reason: Some("rogue_port_listener_received_http_proxy_headers_before_server_auth".into()),
    };
    assert!(outcome.control_client_forwarded);
    assert!(outcome.sandboxed_client_reconnected);
    assert!(outcome.rogue_gateway_received_headers_or_data);
    assert!(outcome.rogue_captured_bytes_len > 0);
    assert!(
        !outcome.server_identity_gate_passed,
        "standard HTTP_PROXY over localhost:<port> inside Seatbelt must fail I03 server identity gate on port takeover"
    );

    // A probe boolean must not manufacture a trusted endpoint proof.
    registry.set_gateway_endpoint_protection(None);
    let report = registry.identity_report(true, true, true);
    assert!(report.helper_identity_verified);
    assert!(report.tcp_socket_attribution_verified);
    assert!(report.executor_boot_binding_verified);
    assert!(!report.gateway_server_identity_verified);
    assert!(
        !report.can_enable_production_backend(),
        "production backend enablement must remain blocked when I03 fails"
    );
    assert_eq!(
        report.blocker_code.as_deref(),
        Some("gateway_server_identity_unverified_i03")
    );

    // 6. Verify that passing this report into the production enforcer gate keeps `sandbox_ready = false`
    //    and blocks `apply_command` with `seatbelt_identity_gate_blocked`!
    let enforcer = LocalTunnelEnforcer::new("boot-i03");
    enforcer
        .configure_seatbelt_backend_with_identity_gate(&report, 1_700_000_900.0)
        .expect("configure with identity gate");
    assert!(
        !enforcer.sandbox_ready().unwrap(),
        "production enforcer must keep sandbox_ready = false when I03 fails"
    );
}

#[test]
fn r4_p01_http_framing_validation_concurrent_connect_and_real_tls_https_wss_frames() {
    if !hardened_helper::hardened_test_process("r4_p01_http_framing_validation_concurrent_connect_and_real_tls_https_wss_frames") { return; }
    let (tmp, store) = make_temp_store("cw-sandbox-r4-p01");
    let now = 1_700_002_000.0;
    let boot_id = "boot-r4-p01";
    let pv = test_policy_version();
    let epoch = VpnEpoch::new("vpn-r4", 1);

    // 1. Generate a temporary self-signed TLS certificate for the local TLS origin server
    let cert_path = tmp.0.join("origin.crt");
    let key_path = tmp.0.join("origin.key");
    let openssl_status = Command::new("/usr/bin/openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key_path.to_str().unwrap(),
            "-out",
            cert_path.to_str().unwrap(),
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("openssl generate cert");
    assert!(openssl_status.success(), "openssl cert generation failed");

    // 2. Start a real Python TLS origin server supporting HTTPS GET and WSS Upgrade + WebSocket frames
    let tls_port_file = tmp.0.join("tls_origin.port");
    let tls_server_py = tmp.0.join("tls_origin_server.py");
    fs::write(
        &tls_server_py,
        r#"import socket, ssl, sys, threading, base64, hashlib

cert_file, key_file, port_file = sys.argv[1], sys.argv[2], sys.argv[3]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0))
srv.listen(16)
with open(port_file, "w") as f:
    f.write(str(srv.getsockname()[1]))

def handle(conn):
    try:
        with ctx.wrap_socket(conn, server_side=True) as tls:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(1024)
                if not chunk:
                    return
                data += chunk
            text = data.decode("latin1")
            if "Upgrade: websocket" in text or "upgrade: websocket" in text:
                headers = dict(line.split(":", 1) for line in text.split("\r\n")[1:] if ":" in line)
                assert headers.get("Sec-WebSocket-Version", "").strip() == "13"
                key = headers["Sec-WebSocket-Key"].strip()
                assert len(base64.b64decode(key, validate=True)) == 16
                accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
                tls.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
                frame = tls.recv(64)
                if len(frame) >= 7 and (frame[1] & 0x80):
                    length = frame[1] & 0x7f
                    mask = frame[2:6]
                    payload = bytes(frame[6 + i] ^ mask[i % 4] for i in range(length))
                    reply = b"wss-pong:" + payload
                    tls.sendall(bytes([0x81, len(reply)]) + reply)
            else:
                body = b"https-tls-origin-ok"
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 19\r\nConnection: close\r\n\r\n" + body)
    except Exception:
        pass

while True:
    try:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()
    except Exception:
        break
"#,
    )
    .unwrap();
    let mut tls_origin_child = Command::new("/usr/bin/python3")
        .args([
            tls_server_py.to_str().unwrap(),
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            tls_port_file.to_str().unwrap(),
        ])
        .spawn()
        .expect("spawn tls origin server");
    let tls_origin_port: u16 = loop {
        if let Ok(s) = fs::read_to_string(&tls_port_file) {
            if let Ok(p) = s.trim().parse() {
                break p;
            }
        }
        thread::sleep(Duration::from_millis(20));
    };
    let tls_origin_addr = SocketAddr::from(([127, 0, 0, 1], tls_origin_port));

    // 3. Start mock upstream VPN proxy that handles:
    //    - HTTP GET requests (including keep-alive multi-request on same socket)
    //    - Plain WS Upgrade + masked WebSocket frame -> unmasked WebSocket frame
    //    - HTTP CONNECT -> tunnels TCP to `tls_origin_addr`!
    let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_stop = Arc::new(AtomicBool::new(false));
    let up_stop_clone = Arc::clone(&upstream_stop);
    let upstream_handle = thread::spawn(move || {
        let _ = upstream_listener.set_nonblocking(true);
        while !up_stop_clone.load(Ordering::Acquire) {
            match upstream_listener.accept() {
                Ok((mut s, _)) => {
                    thread::spawn(move || {
                        let _ = s.set_nonblocking(false);
                        let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
                        loop {
                            let mut buf = [0u8; 2048];
                            let n = match s.read(&mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            let req = String::from_utf8_lossy(&buf[..n]);
                            if req.starts_with("CONNECT ") {
                                let _ =
                                    s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                                if let Ok(mut origin) = TcpStream::connect(tls_origin_addr) {
                                    let mut o_clone = origin.try_clone().unwrap();
                                    let mut s_clone = s.try_clone().unwrap();
                                    thread::spawn(move || {
                                        let _ = std::io::copy(&mut s_clone, &mut o_clone);
                                    });
                                    let _ = std::io::copy(&mut origin, &mut s);
                                }
                                break;
                            } else if req.to_ascii_lowercase().contains("upgrade: websocket") {
                                let _ = s.write_all(
                                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                                );
                                assert!(req.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
                                assert!(req.contains("Sec-WebSocket-Version: 13\r\n"));
                                // Read masked WebSocket text frame from client and reply with unmasked frame
                                let mut frame = [0u8; 64];
                                if let Ok(fn_len) = s.read(&mut frame) {
                                    if fn_len >= 7 && (frame[1] & 0x80) != 0 {
                                        let len = (frame[1] & 0x7f) as usize;
                                        let mask = &frame[2..6];
                                        let mut decoded = Vec::with_capacity(len);
                                        for i in 0..len {
                                            decoded.push(frame[6 + i] ^ mask[i % 4]);
                                        }
                                        let mut reply = b"ws-pong:".to_vec();
                                        reply.extend_from_slice(&decoded);
                                        let mut out_frame = vec![0x81, reply.len() as u8];
                                        out_frame.extend_from_slice(&reply);
                                        let _ = s.write_all(&out_frame);
                                    }
                                }
                                break;
                            } else {
                                let body = b"http-keepalive-ok";
                                let resp = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    body.len()
                                );
                                let _ = s.write_all(resp.as_bytes());
                                let _ = s.write_all(body);
                                let _ = s.flush();
                                break;
                            }
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    // 4. Register current test process in SandboxLaunchRegistry and start LocalTunnelEnforcer
    let (exe_path, exe_sha, verifier) = current_test_binary_verifier();
    let registry = Arc::new(SandboxLaunchRegistry::new(
        boot_id,
        pv.clone(),
        verifier,
        Some(store.clone()),
    ));
    registry.approve_target_executable(&exe_path, &exe_sha);
    let reg_sock = tmp.0.join("reg-r4.sock");
    let reg_stop = Arc::new(AtomicBool::new(false));
    let reg_handle = registry
        .start_registration_listener(&reg_sock, Arc::clone(&reg_stop))
        .unwrap();

    let enforcer = Arc::new(LocalTunnelEnforcer::new(boot_id));
    enforcer.set_clock(move || now + 1.0).unwrap();
    enforcer.configure_seatbelt_backend(true, now).unwrap();
    let gw_stop = Arc::new(AtomicBool::new(false));
    let (gw_addr, gw_handle) = enforcer
        .start_local_proxy_listener("127.0.0.1:0", Arc::clone(&gw_stop), now)
        .expect("proxy listener");
    // Notice we do NOT disable `require_upstream_connect_handshake` globally!
    // Per-connection `handshake_override` in `serve_gateway_connection` handles both HTTP and CONNECT concurrently!

    let reg_for_attr = Arc::clone(&registry);
    enforcer
        .set_accepted_connection_attributor(move |ctx| {
            reg_for_attr.attribute_accepted_connection(ctx, now + 2.0)
        })
        .unwrap();

    let me = inspect_process_identity(std::process::id()).expect("me");
    let my_token = BoundProcessToken::with_system_identity(
        me.pid,
        me.uid,
        me.start_seconds,
        me.start_microseconds,
        ProcessRole::Cli,
    )
    .with_audit_token(me.audit_token);
    let permit = ChannelPermit {
        family: "claude".into(),
        session_id: Some("sess-r4".into()),
        policy_version: pv.clone(),
        permit_generation: 1,
        command_seq: 1,
        state: ChannelPermitState::Permitted,
        reason_code: "verified".into(),
        issued_at: now,
        valid_until: now + 300.0,
        context_id: Some("ctx-r4".into()),
        baseline_ip: Some("1.1.1.1".into()),
        members: vec![Desktop {
            pid: me.pid,
            start_seconds: me.start_seconds,
            start_microseconds: me.start_microseconds,
        }],
        backend: NetworkBackendKind::Seatbelt,
        vpn_epoch: Some(epoch.clone()),
        coverage_scope: None,
    };
    let cmd = ChannelEnforcementCommand {
        family: "claude".into(),
        session_id: Some("sess-r4".into()),
        policy_version: pv.clone(),
        permit_generation: 1,
        command_seq: 1,
        permit,
        allowed_processes: vec![my_token],
        upstream_endpoint: upstream_addr.to_string(),
        target_executor_boot_id: enforcer.boot_id().ok(),
        issued_at: now,
    };
    enforcer.apply_command(&cmd, now).expect("apply command");

    let sbpl = generate_nono_seatbelt_profile(gw_addr, &[7890]).expect("sbpl");
    let launch_req = ControlledLaunchRequest {
        entry_id: "io.local.watchpanel.entry.claude-cli".into(),
        target: LaunchTarget::ClaudeCli,
        target_executable: exe_path,
        target_fingerprint: exe_sha,
        args: vec![],
        cwd: None,
        proxy_adaptation: ProxyAdaptationKind::EnvOnly,
        gateway_endpoint: gw_addr.to_string(),
        policy_version: test_policy_version(),
        vpn_epoch: Some(VpnEpoch::new("vpn-r4", 1)),
        launch_nonce: "nonce-r4-001".into(),
        executor_boot_id: boot_id.into(),
        script_entry: None,
        script_fingerprint: None,
        interpreter: None,
        interpreter_fingerprint: None,
        script_source: None,
    };
    let wire_resp = register_helper_with_daemon(&reg_sock, launch_req, true, &sbpl).unwrap();
    assert!(wire_resp.accepted);

    // 5. R4.2: Reject incomplete headers, duplicate Host, conflicting Content-Length + Transfer-Encoding
    {
        // Incomplete header
        let mut s = TcpStream::connect(gw_addr).unwrap();
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        s.write_all(format!("GET http://{upstream_addr}/incomplete HTTP/1.1\r\nHost: {upstream_addr}\r\n").as_bytes()).unwrap();
        let _ = s.shutdown(std::net::Shutdown::Write);
        let mut resp = String::new();
        let _ = s.read_to_string(&mut resp);
        assert!(resp.starts_with("HTTP/1.1 400"), "incomplete header must return 400: {resp}");
    }
    {
        // Duplicate Host header
        let mut s = TcpStream::connect(gw_addr).unwrap();
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        s.write_all(
            format!(
                "GET http://{upstream_addr}/dup HTTP/1.1\r\nHost: {upstream_addr}\r\nHost: evil.example:80\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        let mut resp = String::new();
        let _ = s.read_to_string(&mut resp);
        assert!(resp.starts_with("HTTP/1.1 400"), "duplicate Host must return 400: {resp}");
    }
    {
        // Conflicting Content-Length and Transfer-Encoding
        let mut s = TcpStream::connect(gw_addr).unwrap();
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        s.write_all(
            format!(
                "POST http://{upstream_addr}/smuggle HTTP/1.1\r\nHost: {upstream_addr}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        let mut resp = String::new();
        let _ = s.read_to_string(&mut resp);
        assert!(
            resp.starts_with("HTTP/1.1 400"),
            "conflicting Content-Length and Transfer-Encoding must return 400: {resp}"
        );
    }

    // 6. R4.2: Keep-alive HTTP connection validates every request and rejects a second request that switches Host!
    {
        let mut s = TcpStream::connect(gw_addr).unwrap();
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        // First request with lowercase `host:` succeeds
        let req1 = format!("GET http://{upstream_addr}/first HTTP/1.1\r\nhost: {upstream_addr}\r\n\r\n");
        s.write_all(req1.as_bytes()).unwrap();
        let mut resp1 = String::new();
        let mut buf = [0u8; 512];
        for _ in 0..4 {
            if let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                resp1.push_str(&String::from_utf8_lossy(&buf[..n]));
                if resp1.contains("http-keepalive-ok") {
                    break;
                }
            } else {
                break;
            }
        }
        assert!(resp1.contains("http-keepalive-ok"), "first request failed: {resp1}");

        // Second request on same socket with mismatched Host MUST be rejected with 400 (proving no raw TCP passthrough after request 1!)
        let req2_bad = "GET http://evil.example:80/second HTTP/1.1\r\nHost: evil.example:80\r\n\r\n";
        s.write_all(req2_bad.as_bytes()).unwrap();
        let n2 = s.read(&mut buf).unwrap();
        let resp2 = String::from_utf8_lossy(&buf[..n2]);
        assert!(
            resp2.starts_with("HTTP/1.1 400"),
            "second request on keep-alive socket switching Host must be rejected with 400: {resp2}"
        );
    }

    // 7. P01: Plain WebSocket 101 Upgrade + masked WebSocket application frame exchange
    {
        let mut s = TcpStream::connect(gw_addr).unwrap();
        let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
        let ws_req = format!(
            "GET http://{upstream_addr}/ws HTTP/1.1\r\nHost: {upstream_addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        s.write_all(ws_req.as_bytes()).unwrap();
        let mut buf = [0u8; 256];
        let n = s.read(&mut buf).unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.starts_with("HTTP/1.1 101 Switching Protocols"));
        // Endpoint verification, not proxy MITM: RFC 6455's published key/accept pair.
        assert!(resp.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));

        // Send masked WebSocket text frame for "ping" (mask = [1, 2, 3, 4])
        let payload = b"ping";
        let mask = [1u8, 2, 3, 4];
        let mut frame = vec![0x81, 0x80 | (payload.len() as u8)];
        frame.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i % 4]);
        }
        s.write_all(&frame).unwrap();
        let fn_read = s.read(&mut buf).unwrap();
        assert!(fn_read >= 2 && buf[0] == 0x81);
        let rlen = (buf[1] & 0x7f) as usize;
        assert_eq!(&buf[2..2 + rlen], b"ws-pong:ping");
    }

    // 8. P01 + R4.1: Real TLS 1.3 HTTPS and WSS over CONNECT tunnel through Watch Gateway,
    //    executed concurrently with plain HTTP requests to verify zero handshake race!
    let client_py = tmp.0.join("tls_client_verify.py");
    fs::write(
        &client_py,
        r#"import socket, ssl, sys, base64, hashlib

gw_host, gw_port, origin_port, cert_file = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
ctx = ssl.create_default_context(cafile=cert_file)
ctx.check_hostname = False

# 1. Real HTTPS over CONNECT
with socket.create_connection((gw_host, gw_port), timeout=3) as sock:
    connect_req = f"CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n".encode()
    sock.sendall(connect_req)
    resp = sock.recv(256)
    assert resp.startswith(b"HTTP/1.1 200"), f"CONNECT failed: {resp}"
    with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as tls:
        tls.sendall(f"GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n".encode())
        https_resp = tls.recv(1024)
        assert b"https-tls-origin-ok" in https_resp, f"unexpected HTTPS response: {https_resp}"

# 2. Real WSS (WebSocket over TLS) over CONNECT
with socket.create_connection((gw_host, gw_port), timeout=3) as sock:
    connect_req = f"CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n".encode()
    sock.sendall(connect_req)
    resp = sock.recv(256)
    assert resp.startswith(b"HTTP/1.1 200"), f"CONNECT failed: {resp}"
    with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as tls:
        ws_upgrade = (
            f"GET /realtime HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
        tls.sendall(ws_upgrade)
        up_resp = tls.recv(256)
        while b"\r\n\r\n" not in up_resp:
            more = tls.recv(256)
            assert more, "truncated WSS response"
            up_resp += more
        assert up_resp.split(b"\r\n", 1)[0].split()[1] == b"101", f"WSS upgrade failed: {up_resp}"
        headers = dict(line.split(b":", 1) for line in up_resp.split(b"\r\n")[1:] if b":" in line)
        expected_accept = base64.b64encode(hashlib.sha1(b"dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
        assert headers[b"Sec-WebSocket-Accept"].strip() == expected_accept
        assert headers[b"Upgrade"].strip().lower() == b"websocket"
        assert b"upgrade" in headers[b"Connection"].strip().lower().split(b",")
        # Send masked WebSocket frame "tls-ws"
        payload = b"tls-ws"
        mask = bytes([5, 6, 7, 8])
        masked = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
        tls.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + masked)
        ws_frame = tls.recv(128)
        assert ws_frame.startswith(b"\x81\x0fwss-pong:tls-ws"), f"unexpected WSS frame: {ws_frame}"

print("TLS_HTTPS_AND_WSS_OK")
"#,
    )
    .unwrap();

    // Local in-process relay so subprocess python3 TLS client sockets to `gw_addr` are owned by `me.pid`
    let py_bridge_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let py_bridge_port = py_bridge_listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for _ in 0..2 {
            if let Ok((mut py_sock, _)) = py_bridge_listener.accept() {
                let mut gw_sock = TcpStream::connect(gw_addr).unwrap();
                let mut py_r = py_sock.try_clone().unwrap();
                let mut gw_w = gw_sock.try_clone().unwrap();
                let t = thread::spawn(move || {
                    let _ = std::io::copy(&mut py_r, &mut gw_w);
                    let _ = gw_w.shutdown(std::net::Shutdown::Both);
                });
                let _ = std::io::copy(&mut gw_sock, &mut py_sock);
                let _ = py_sock.shutdown(std::net::Shutdown::Both);
                let _ = t.join();
            }
        }
    });

    // Run concurrent plain HTTP requests while TLS HTTPS + WSS client runs
    let http_thread = thread::spawn(move || {
        for _ in 0..8 {
            let mut s = TcpStream::connect(gw_addr).unwrap();
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let req = format!(
                "GET http://{upstream_addr}/concurrent HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n"
            );
            s.write_all(req.as_bytes()).unwrap();
            let mut resp = String::new();
            let _ = s.read_to_string(&mut resp);
            assert!(
                resp.contains("http-keepalive-ok"),
                "concurrent HTTP request failed: {resp}"
            );
        }
    });

    let py_out = Command::new("/usr/bin/python3")
        .args([
            client_py.to_str().unwrap(),
            "127.0.0.1",
            &py_bridge_port.to_string(),
            &tls_origin_port.to_string(),
            cert_path.to_str().unwrap(),
        ])
        .output()
        .expect("run python tls client");
    http_thread.join().expect("concurrent http thread");
    assert!(
        py_out.status.success()
            && String::from_utf8_lossy(&py_out.stdout).contains("TLS_HTTPS_AND_WSS_OK"),
        "real TLS HTTPS/WSS verification failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&py_out.stdout),
        String::from_utf8_lossy(&py_out.stderr)
    );

    let _ = tls_origin_child.kill();
    let _ = tls_origin_child.wait();
    gw_stop.store(true, Ordering::Release);
    let _ = gw_handle.join();
    reg_stop.store(true, Ordering::Release);
    let _ = reg_handle.join();
    upstream_stop.store(true, Ordering::Release);
    let _ = upstream_handle.join();
}

/// Component-only protocol regression: the injected peer token isolates HTTP framing from
/// the separately-blocked I03 production identity gate. All network I/O is loopback.
#[test]
fn r4_chunked_request_and_upgrade_boundaries_use_the_live_gateway() {
    use claude_watch_runtime::channel_enforcer::TunnelStream;
    use std::net::Shutdown;
    use std::sync::{atomic::AtomicUsize, mpsc};
    fn header(stream: &mut TcpStream) -> Vec<u8> {
        let mut data = Vec::new();
        let mut b = [0];
        while data.len() < 16384 {
            stream.read_exact(&mut b).expect("complete fixture header");
            data.push(b[0]);
            if data.ends_with(b"\r\n\r\n") {
                return data;
            }
        }
        panic!("fixture header overflow");
    }
    let (tmp, _store) = make_temp_store("cw-r4-boundaries");
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    upstream.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let accepted = Arc::new(AtomicUsize::new(0));
    let (request_tx, request_rx) = mpsc::channel();
    let up_stop = stop.clone();
    let up_accepted = accepted.clone();
    let expected_body = b"4;note=ok\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Fixture: yes\r\n\r\n";
    let up_thread = thread::spawn(move || {
        while !up_stop.load(Ordering::Acquire) {
            let (mut stream, _) = match upstream.accept() {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => panic!("fixture accept: {e}"),
            };
            // BSD accept inherits O_NONBLOCK from this polling listener.
            // read_exact needs blocking mode; SO_RCVTIMEO alone does not clear it.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let req = String::from_utf8(header(&mut stream)).unwrap();
            up_accepted.fetch_add(1, Ordering::SeqCst);
            if req
                .to_ascii_lowercase()
                .contains("transfer-encoding: chunked")
            {
                let mut body = vec![0; expected_body.len()];
                stream.read_exact(&mut body).unwrap();
                assert_eq!(body, expected_body);
            }
            request_tx.send(req.clone()).unwrap();
            let bad_response: Option<&[u8]> = if req.contains("/wrong-upgrade ") {
                Some(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: notwebsocket\r\nConnection: Upgrade\r\n\r\n".as_slice())
            } else if req.contains("/missing-connection ") {
                Some(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
            } else if req.contains("/wrong-code ") {
                Some(b"HTTP/1.1 1010 Invalid\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            } else if req.contains("/truncated-upgrade ") {
                Some(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n")
            } else {
                None
            };
            if let Some(response) = bad_response {
                let mut wire = response.to_vec();
                if !req.contains("/truncated-upgrade ") {
                    wire.extend_from_slice(b"MUST_NOT_RELAY");
                }
                stream.write_all(&wire).unwrap();
            } else {
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .unwrap();
            }
            stream.shutdown(Shutdown::Write).unwrap();
        }
    });
    let now = 1_700_003_000.0;
    let pv = test_policy_version();
    let me = inspect_process_identity(std::process::id()).unwrap();
    let token = BoundProcessToken::with_system_identity(
        me.pid,
        me.uid,
        me.start_seconds,
        me.start_microseconds,
        ProcessRole::Cli,
    )
    .with_audit_token(me.audit_token);
    let enforcer = Arc::new(LocalTunnelEnforcer::new("r4-boundaries"));
    enforcer.configure_seatbelt_backend(true, now).unwrap();
    enforcer.set_clock(move || now + 0.5).unwrap();
    let attribution = token.clone();
    enforcer
        .set_accepted_connection_attributor(move |_| Some(("claude".into(), attribution.clone())))
        .unwrap();
    enforcer
        .set_upstream_connector(move |_| Ok(TunnelStream::Tcp(TcpStream::connect(upstream_addr)?)))
        .unwrap();
    let (gateway, gateway_thread) = enforcer
        .start_local_proxy_listener("127.0.0.1:0", stop.clone(), now)
        .unwrap();
    let permit = ChannelPermit {
        family: "claude".into(),
        session_id: Some("r4-boundaries".into()),
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
            pid: me.pid,
            start_seconds: me.start_seconds,
            start_microseconds: me.start_microseconds,
        }],
        backend: NetworkBackendKind::Seatbelt,
        vpn_epoch: Some(VpnEpoch::new("fixture", 1)),
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
                upstream_endpoint: upstream_addr.to_string(),
                target_executor_boot_id: enforcer.boot_id().ok(),
                issued_at: now,
            },
            now,
        )
        .unwrap();

    // A body arriving in separately-written fragments is forwarded unchanged; the next
    // request remains an independently parsed request rather than part of the body.
    let mut client = TcpStream::connect(gateway).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    client.write_all(format!("POST http://{upstream_addr}/chunked HTTP/1.1\r\nHost: {upstream_addr}\r\nTransfer-Encoding: chunked\r\n\r\n").as_bytes()).unwrap();
    for bytes in expected_body.chunks(3) {
        client.write_all(bytes).unwrap();
    }
    assert!(
        String::from_utf8(header(&mut client))
            .unwrap()
            .contains("200 OK")
    );
    let mut body = [0; 2];
    client.read_exact(&mut body).unwrap();
    assert_eq!(&body, b"ok");
    client.write_all(format!("GET http://{upstream_addr}/next HTTP/1.1\r\nHost: {upstream_addr}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.contains("200 OK") && response.ends_with("ok"));
    assert!(
        request_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .contains("/chunked ")
    );
    assert!(
        request_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .contains("/next ")
    );

    let mut cases: Vec<(String, Vec<u8>, &str)> = vec![
        (
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n".into(),
            b"0\r\n\r\n".to_vec(),
            "400",
        ),
        (
            "Transfer-Encoding: gzip, chunked\r\n".into(),
            b"0\r\n\r\n".to_vec(),
            "501",
        ),
        (
            "Transfer-Encoding: chunked\r\n".into(),
            format!("0\r\n{}", "x".repeat(4096)).into_bytes(),
            "400",
        ),
        (
            "Transfer-Encoding: chunked\r\n".into(),
            b"4\r\nabc".to_vec(),
            "400",
        ),
        (
            "Transfer-Encoding: chunked\r\n".into(),
            format!("1\r\nx\r\n{:x}\r\n", usize::MAX).into_bytes(),
            "413",
        ),
    ];
    let mut too_much_framing = Vec::new();
    for _ in 0..70 {
        too_much_framing.extend_from_slice(format!("1;x={}\r\nx\r\n", "a".repeat(1000)).as_bytes());
    }
    cases.push((
        "Transfer-Encoding: chunked\r\n".into(),
        too_much_framing,
        "413",
    ));
    for (headers, body, expected_status) in cases {
        let mut c = TcpStream::connect(gateway).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut request = format!("POST http://{upstream_addr}/rejected HTTP/1.1\r\nHost: {upstream_addr}\r\n{headers}\r\n").into_bytes();
        request.extend(body);
        c.write_all(&request).unwrap();
        c.shutdown(Shutdown::Write).unwrap();
        let response = String::from_utf8(header(&mut c)).unwrap();
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expected_status}")),
            "{response}"
        );
    }
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "invalid bodies must never reach upstream"
    );
    for path in [
        "wrong-upgrade",
        "missing-connection",
        "wrong-code",
        "truncated-upgrade",
    ] {
        let mut c = TcpStream::connect(gateway).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        c.write_all(format!("GET http://{upstream_addr}/{path} HTTP/1.1\r\nHost: {upstream_addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").as_bytes()).unwrap();
        let mut bytes = Vec::new();
        c.read_to_end(&mut bytes)
            .expect("gateway must close invalid upgrade; timeout is not EOF");
        assert!(!String::from_utf8_lossy(&bytes).contains("MUST_NOT_RELAY"));
        assert!(
            request_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_else(|err| panic!("upstream did not receive {path}: {err}"))
                .contains(path),
            "upstream received a different upgrade case than {path}"
        );
    }
    stop.store(true, Ordering::Release);
    gateway_thread.join().unwrap();
    up_thread.join().unwrap();
    drop(tmp);
}
