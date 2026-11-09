use claude_watch_core::{
    channel::{
        evaluate_channel_supervision_with_boot_id, verify_channel_recovery_with_vpn_epoch,
        BackendCoverageScope, BoundProcessToken, ChannelEnforcementReceipt,
        ChannelEnforcementState, ChannelPermit, ChannelPermitState, ChannelSupervisionVerdict,
        ControlledPathEvidence, FlowTransportProtocol, NetworkBackendKind, PolicyVersion,
    },
    config::Config,
    controlled_launch::{
        AcceptedConnectionContext, ControlledLaunchRequest, ManagedInstanceState,
        ManagedLaunchInstance, ProxyAdaptationKind, SandboxLaunchEvidence,
    },
    processes::{LaunchTarget, ProcessRole},
    vpn::{
        canonical_rules_digest, compare_vpn, rules_digest_from_published, ObservationConsistency,
        ObservedField, UpstreamProtocol, VpnEpoch, VpnExpectation, VpnMatch, VpnObservation,
    },
};
use serde_json::json;

fn sample_epoch(gen: u64) -> VpnEpoch {
    VpnEpoch {
        observer_boot_id: "obs-boot-1".into(),
        change_generation: gen,
    }
}

fn sample_expectation() -> VpnExpectation {
    VpnExpectation {
        configured: true,
        proxy_mode: "clash-verge".into(),
        proxy_url: "http://127.0.0.1:7890".into(),
        proxy_group: "TAG".into(),
        running_mode: Some("rule".into()),
        require_tun: None,
        require_system_proxy: None,
        expected_node: Some("JP-Tokyo-01".into()),
        expected_chain: vec!["TAG".into(), "JP-Tokyo-01".into()],
        expected_rules_digest: Some(canonical_rules_digest(&[
            "DOMAIN-SUFFIX,anthropic.com,TAG".into(),
            "DOMAIN-SUFFIX,claude.ai,TAG".into(),
        ])),
    }
}

fn sample_observation(epoch_gen: u64) -> VpnObservation {
    VpnObservation {
        source: "clash-verge".into(),
        source_instance: Some("clash-verge:pid=1001".into()),
        source_revision: Some("rev-1".into()),
        upstream_endpoint: Some("http://127.0.0.1:7890".into()),
        upstream_protocol: ObservedField::Known(UpstreamProtocol::MixedHttp),
        running_mode: ObservedField::Known("rule".into()),
        tun_enabled: ObservedField::Known(false),
        system_proxy_enabled: ObservedField::Known(false),
        selected_group: ObservedField::Known("TAG".into()),
        selected_node: ObservedField::Known("JP-Tokyo-01".into()),
        proxy_chain: ObservedField::Known(vec!["TAG".into(), "JP-Tokyo-01".into()]),
        rules_digest: ObservedField::Known(canonical_rules_digest(&[
            "DOMAIN-SUFFIX,claude.ai,TAG".into(),
            "DOMAIN-SUFFIX,anthropic.com,TAG".into(),
        ])),
        sample_started_at: 1004.5,
        observed_at: 1005.0,
        valid_until: 1010.0,
        consistency: ObservationConsistency::RevisionVerified,
        source_error: None,
        sample_seq: 1,
        epoch: sample_epoch(epoch_gen),
    }
}

#[test]
fn unconfigured_vpn_expectation_never_defaults_to_matched() {
    let obs = sample_observation(1);
    let unconfigured = VpnExpectation::default();
    assert!(!unconfigured.configured);
    assert_eq!(
        compare_vpn(&unconfigured, &obs, 1006.0),
        VpnMatch::Unknown {
            reasons: vec!["vpn_expectation_unconfigured".into()]
        }
    );

    let candidate = obs.to_candidate_expectation().unwrap();
    assert!(candidate.configured);
    assert_eq!(candidate.proxy_url, "http://127.0.0.1:7890");
    assert_eq!(candidate.expected_node.as_deref(), Some("JP-Tokyo-01"));
}

#[test]
fn compare_vpn_enforces_freshness_consistency_and_all_expected_fields() {
    let exp = sample_expectation();
    let obs = sample_observation(1);
    assert_eq!(compare_vpn(&exp, &obs, 1006.0), VpnMatch::Matched);

    // Stale at or after valid_until
    assert_eq!(compare_vpn(&exp, &obs, 1010.0), VpnMatch::Stale);

    // Inconsistent two-phase snapshot must fail closed as Unknown
    let mut inconsistent = obs.clone();
    inconsistent.consistency =
        ObservationConsistency::InconsistentSnapshot("revision_changed".into());
    assert_eq!(
        compare_vpn(&exp, &inconsistent, 1006.0),
        VpnMatch::Unknown {
            reasons: vec!["vpn_snapshot_inconsistent:revision_changed".into()]
        }
    );

    // Node change -> Mismatched on expected_node
    let mut node_changed = obs.clone();
    node_changed.selected_node = ObservedField::Known("US-West-02".into());
    match compare_vpn(&exp, &node_changed, 1006.0) {
        VpnMatch::Mismatched { differences } => {
            assert!(differences.iter().any(|d| d.field == "expected_node"
                && d.expected == "JP-Tokyo-01"
                && d.observed == "US-West-02"));
        }
        other => panic!("expected Mismatched, got {other:?}"),
    }

    // Mode change (rule -> direct) -> Mismatched on running_mode
    let mut mode_changed = obs.clone();
    mode_changed.running_mode = ObservedField::Known("direct".into());
    match compare_vpn(&exp, &mode_changed, 1006.0) {
        VpnMatch::Mismatched { differences } => {
            assert!(differences.iter().any(|d| d.field == "running_mode"));
        }
        other => panic!("expected Mismatched, got {other:?}"),
    }

    // Port / protocol: SocksOnly -> Mismatched on upstream_protocol
    let mut socks_only = obs.clone();
    socks_only.upstream_protocol = ObservedField::Known(UpstreamProtocol::SocksOnly);
    match compare_vpn(&exp, &socks_only, 1006.0) {
        VpnMatch::Mismatched { differences } => {
            assert!(differences.iter().any(|d| d.field == "upstream_protocol"));
        }
        other => panic!("expected Mismatched, got {other:?}"),
    }

    // require_tun == None does not require TUN when TUN is false or Unknown
    let mut tun_unknown = obs.clone();
    tun_unknown.tun_enabled = ObservedField::Unknown("tun_unobserved".into());
    assert_eq!(compare_vpn(&exp, &tun_unknown, 1006.0), VpnMatch::Matched);

    // require_tun == Some(true) mismatches when TUN is false and returns Unknown when TUN is Unknown
    let mut exp_tun = exp.clone();
    exp_tun.require_tun = Some(true);
    match compare_vpn(&exp_tun, &obs, 1006.0) {
        VpnMatch::Mismatched { differences } => {
            assert!(differences.iter().any(|d| d.field == "require_tun"));
        }
        other => panic!("expected Mismatched, got {other:?}"),
    }
    assert_eq!(
        compare_vpn(&exp_tun, &tun_unknown, 1006.0),
        VpnMatch::Unknown {
            reasons: vec!["tun_unobserved".into()]
        }
    );

    // Rules digest mismatch
    let mut rules_changed = obs.clone();
    rules_changed.rules_digest = ObservedField::Known(
        rules_digest_from_published(&json!({
            "state": "available",
            "entries": ["MATCH,DIRECT"]
        }))
        .unwrap(),
    );
    match compare_vpn(&exp, &rules_changed, 1006.0) {
        VpnMatch::Mismatched { differences } => {
            assert!(differences.iter().any(|d| d.field == "expected_rules_digest"));
        }
        other => panic!("expected Mismatched, got {other:?}"),
    }
}

#[test]
fn config_supports_schema_2_seatbelt_backend_and_validated_vpn_expectation() {
    let legacy = Config::from_value(json!({})).unwrap();
    assert_eq!(legacy.schema, 1);
    assert_eq!(legacy.network_backend, None);
    assert_eq!(legacy.vpn_expectation, None);
    assert_eq!(
        legacy.effective_network_backend(),
        NetworkBackendKind::NetworkExtension
    );
    assert!(legacy.requires_backend_migration_setup());

    let new_install = Config::default_for_new_install();
    assert_eq!(new_install.schema, 2);
    assert_eq!(
        new_install.effective_network_backend(),
        NetworkBackendKind::Seatbelt
    );
    assert!(!new_install.requires_backend_migration_setup());

    let exp = sample_expectation();
    let configured = Config::from_value(json!({
        "schema": 2,
        "proxy_mode": "clash-verge",
        "proxy_url": "http://127.0.0.1:7890",
        "proxy_group": "TAG",
        "network_backend": "seatbelt",
        "vpn_expectation": exp,
    }))
    .unwrap();
    assert_eq!(
        configured.network_backend,
        Some(NetworkBackendKind::Seatbelt)
    );
    assert_eq!(configured.vpn_expectation, Some(sample_expectation()));

    // Non-loopback upstream or direct running_mode in vpn_expectation is rejected
    let mut bad_exp = sample_expectation();
    bad_exp.proxy_url = "http://192.168.1.1:7890".into();
    assert!(Config::from_value(json!({
        "schema": 2,
        "vpn_expectation": bad_exp,
    }))
    .is_err());

    let mut direct_exp = sample_expectation();
    direct_exp.running_mode = Some("direct".into());
    assert!(Config::from_value(json!({
        "schema": 2,
        "vpn_expectation": direct_exp,
    }))
    .is_err());
}

#[test]
fn channel_permit_and_supervision_enforce_backend_and_vpn_epoch_binding() {
    let policy = PolicyVersion {
        policy_digest: "p1".into(),
        guard_policy_digest: "g1".into(),
    };
    let epoch1 = sample_epoch(1);
    let epoch2 = sample_epoch(2);
    let scope = BackendCoverageScope {
        backend: NetworkBackendKind::Seatbelt,
        configured_entries: vec!["entry-claude-desktop".into()],
        protected_pids: vec![100],
        unprotected_pids: vec![],
        uncovered_boundaries: vec![],
        server_identity_verified: false,
        gateway_endpoint_protection_verified: false,
        gateway_endpoint_protection_method: None,
    };
    let permit = ChannelPermit {
        family: "claude".into(),
        session_id: Some("s1".into()),
        policy_version: policy.clone(),
        permit_generation: 1,
        command_seq: 1,
        state: ChannelPermitState::Permitted,
        reason_code: "ok".into(),
        issued_at: 1000.0,
        valid_until: 1010.0,
        context_id: Some("ctx-1".into()),
        baseline_ip: Some("1.1.1.1".into()),
        members: vec![],
        backend: NetworkBackendKind::Seatbelt,
        vpn_epoch: Some(epoch1.clone()),
        coverage_scope: Some(scope.clone()),
    };

    assert_eq!(
        permit.effective_state_with_vpn_epoch(1005.0, Some(1004.0), false, &policy, Some(&epoch1)),
        (ChannelPermitState::Permitted, "current_permit")
    );
    assert_eq!(
        permit.effective_state_with_vpn_epoch(1005.0, Some(1004.0), false, &policy, Some(&epoch2)),
        (ChannelPermitState::Revoked, "vpn_epoch_changed")
    );

    // Seatbelt receipt must not claim system_extension_active == true, and must match backend + vpn_epoch
    let mut receipt = ChannelEnforcementReceipt {
        family: "claude".into(),
        session_id: Some("s1".into()),
        policy_version: policy.clone(),
        permit_generation: 1,
        command_seq: 1,
        executor_boot_id: "exec-1".into(),
        permit_state: ChannelPermitState::Permitted,
        enforcement_state: ChannelEnforcementState::Forwarding,
        interception_active: true,
        local_proxy_ready: true,
        system_extension_active: false,
        new_connections_blocked: false,
        active_flows_closed: false,
        direct_fallback_blocked: true,
        active_flows_count: 1,
        terminated_flows_count: 0,
        blocked_new_connections: 0,
        observed_at: 1005.0,
        error_code: None,
        backend: NetworkBackendKind::Seatbelt,
        vpn_epoch: Some(epoch1.clone()),
        coverage_scope: Some(scope),
        sandbox_ready: true,
    };
    assert_eq!(
        evaluate_channel_supervision_with_boot_id(
            &permit,
            Some(&receipt),
            &policy,
            Some("exec-1"),
            1005.0
        ),
        ChannelSupervisionVerdict::ForwardingVerified
    );

    // Faking system_extension_active under Seatbelt is rejected
    receipt.system_extension_active = true;
    assert_eq!(
        evaluate_channel_supervision_with_boot_id(
            &permit,
            Some(&receipt),
            &policy,
            Some("exec-1"),
            1005.0
        ),
        ChannelSupervisionVerdict::EnforcementFailed {
            code: "sandbox_receipt_claims_system_extension".into(),
            status_label_zh: "执行失败".into(),
        }
    );
    receipt.system_extension_active = false;

    // Stale vpn_epoch on receipt is rejected
    receipt.vpn_epoch = Some(epoch2.clone());
    assert_eq!(
        evaluate_channel_supervision_with_boot_id(
            &permit,
            Some(&receipt),
            &policy,
            Some("exec-1"),
            1005.0
        ),
        ChannelSupervisionVerdict::EnforcementFailed {
            code: "stale_vpn_epoch_receipt".into(),
            status_label_zh: "执行失败".into(),
        }
    );

    // Recovery requires matching current_vpn_epoch in controlled path evidence
    let mut revoked = permit.clone();
    revoked.state = ChannelPermitState::Revoked;
    let stale_egress = json!({
        "ip": "1.1.1.1",
        "country": "JP",
        "observed_at": 1006.0,
        "source": "fixture",
        "via_controlled_path": true,
        "family": "claude",
        "upstream_endpoint": "127.0.0.1:7890",
        "context_id": "ctx-2",
        "policy_version": policy,
        "vpn_epoch": epoch1,
    });
    assert_eq!(
        verify_channel_recovery_with_vpn_epoch(
            &revoked,
            1005.0,
            Some("s1"),
            true,
            1006.0,
            &policy,
            &stale_egress,
            Some("s1"),
            &policy,
            Some(&epoch2),
            "ctx-2",
            2,
            2,
            1006.5,
            10.0,
        )
        .unwrap_err()
        .code,
        "recovery_vpn_epoch_mismatch"
    );
}

#[test]
fn controlled_launch_and_evidence_types_roundtrip_and_validate() {
    let policy = PolicyVersion {
        policy_digest: "p1".into(),
        guard_policy_digest: "g1".into(),
    };
    let req = ControlledLaunchRequest {
        entry_id: "entry-claude-desktop".into(),
        target: LaunchTarget::ClaudeDesktop,
        target_executable: "/tmp/mock-app".into(),
        target_fingerprint: "sha256:1234".into(),
        args: vec!["--flag".into()],
        cwd: Some("/tmp".into()),
        proxy_adaptation: ProxyAdaptationKind::EnvAndElectronSwitches,
        gateway_endpoint: "127.0.0.1:18888".into(),
        policy_version: policy.clone(),
        vpn_epoch: Some(sample_epoch(1)),
        launch_nonce: "nonce-1".into(),
        executor_boot_id: "boot-1".into(),
    };
    req.validate().unwrap();
    let raw = serde_json::to_value(&req).unwrap();
    let parsed: ControlledLaunchRequest = serde_json::from_value(raw).unwrap();
    assert_eq!(parsed, req);
    assert!(!ManagedInstanceState::RunningUnprotected.is_protected_active());
    assert!(ManagedInstanceState::ExecVerified.is_protected_active());

    let helper_tok = BoundProcessToken {
        pid: 100,
        uid: 501,
        start_seconds: 1000,
        start_microseconds: 500,
        role: ProcessRole::DesktopMain,
        audit_token: Some([0, 501, 20, 501, 20, 100, 1, 1]),
    };
    let ev = SandboxLaunchEvidence {
        applied: true,
        backend: NetworkBackendKind::Seatbelt,
        policy_version: policy.clone(),
        allowed_gateway_endpoint: "127.0.0.1:18888".into(),
        direct_network_blocked: true,
        unix_relay_blocked: true,
        verified_helper_origin: true,
        helper_cdhash: "cdhash-1".into(),
        helper_identity: helper_tok.clone(),
        executor_boot_id: "boot-1".into(),
        applied_at: 1001.0,
    };
    assert!(ev.is_trusted("boot-1", &policy));

    let instance = ManagedLaunchInstance {
        instance_id: "inst-1".into(),
        entry_id: "entry-claude-desktop".into(),
        family: "claude".into(),
        target: LaunchTarget::ClaudeDesktop,
        launch_nonce: "nonce-1".into(),
        executor_boot_id: "boot-1".into(),
        helper_identity: Some(helper_tok.clone()),
        expected_executable: "/tmp/mock-app".into(),
        expected_fingerprint: "sha256:1234".into(),
        exec_identity: Some(helper_tok),
        verified_executable: Some("/tmp/mock-app".into()),
        pid: 100,
        uid: 501,
        start_seconds: 1000,
        start_microseconds: 500,
        controlled_subtree_pids: vec![101],
        state: ManagedInstanceState::ExecVerified,
        sandbox_evidence: Some(ev),
        updated_at: 1001.5,
        error_code: None,
    };
    assert!(instance.has_verified_protection("boot-1", &policy));
    assert!(instance.covers_process(101));

    let ctx = AcceptedConnectionContext {
        connection_id: 1,
        protocol: FlowTransportProtocol::TcpIpv4,
        peer_addr: "127.0.0.1:54321".parse().unwrap(),
        local_addr: "127.0.0.1:18888".parse().unwrap(),
        listener_boot_id: "boot-1".into(),
        accepted_at: 1002.0,
        socket_fd: Some(10),
    };
    assert!(ctx.is_valid_for_listener("boot-1"));

    let path_ev = ControlledPathEvidence {
        via_controlled_path: true,
        family: "claude".into(),
        upstream_endpoint: "127.0.0.1:7890".into(),
        context_id: "ctx-1".into(),
        policy_version: policy.clone(),
        observed_at: 1001.0,
        backend: NetworkBackendKind::Seatbelt,
        vpn_epoch: Some(sample_epoch(1)),
        executor_boot_id: Some("boot-1".into()),
    };
    assert_eq!(
        path_ev.matches_path_with_vpn(
            "claude",
            "127.0.0.1:7890",
            &policy,
            Some("ctx-1"),
            Some(&sample_epoch(1)),
            1002.0,
            10.0,
        ),
        Ok(())
    );
}
