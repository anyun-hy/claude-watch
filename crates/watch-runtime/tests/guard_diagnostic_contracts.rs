use claude_watch_core::config::Config;
use claude_watch_runtime::{
    config_store::{guard_policy_digest, policy_digest},
    events::EventStore,
    guard_diagnostics::{capture_phase, GuardRound},
    monitor_snapshot::{event_history, EventHistoryQuery},
    storage::{Paths, StateStore},
};
use serde_json::json;
use std::{fs, path::PathBuf};

struct Fixture {
    root: PathBuf,
    store: StateStore,
}

#[test]
fn multi_family_guard_heartbeat_remains_bounded_readable_and_unhealthy() {
    let f = Fixture::new(); let config = Config::default();
    let heartbeat = json!({"time":1000.0,"status":"protection_unavailable",
        "guard_policy_v1":guard_policy_digest(&config).unwrap(),"family_receipts":[{"padding":"x".repeat(12_000)}]});
    let path = f.store.paths.base().join("guard-heartbeat.json");
    f.store.atomic_json(&path,&heartbeat).unwrap();
    let phase = capture_phase(&f.store,&config,&json!({"guard_state":"unknown","guard_backend_healthy":true}),1001.0);
    assert_eq!(phase.guard_heartbeat_status,"protection_unavailable");
    assert_eq!(phase.policy_matches,Some(true)); assert_eq!(phase.decision,"unknown");
    let round = GuardRound { observation_id:uuid::Uuid::new_v4().to_string(),before:phase.clone(),after:phase };
    assert!(EventStore::new(f.store.clone()).record_guard_diagnostic(&round,1001.0).is_ok());
    f.store.atomic_bytes(&path,&vec![b' ';2_000_001],0o600).unwrap();
    assert_eq!(capture_phase(&f.store,&config,&json!({"guard_state":"unknown"}),1001.0).guard_heartbeat_status,"unreadable");
}

#[test]
fn diagnostics_use_the_same_scoped_guard_policy_after_timezone_change() {
    let f = Fixture::new();
    let before = Config {
        guard_enabled: true,
        ..Default::default()
    };
    let mut after = before.clone();
    after.timezone_watchdog = true;
    after.country = "JP".into();
    after.timezone = "Asia/Tokyo".into();
    f.store
        .atomic_json(
            &f.store.paths.base().join("guard-heartbeat.json"),
            &json!({"time":1000.,"status":"ok",
            "policy":policy_digest(&before.value().unwrap()).unwrap(),
            "guard_policy_v1":guard_policy_digest(&before).unwrap()}),
        )
        .unwrap();
    let phase = capture_phase(&f.store, &after, &json!({"guard_state":"ok"}), 1001.0);
    assert_eq!(phase.policy_matches, Some(true));
    after.proxy_mode = "tag".into();
    let changed = capture_phase(&f.store, &after, &json!({"guard_state":"unknown"}), 1001.0);
    assert_eq!(changed.policy_matches, Some(false));
}
impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("cw-guard-diagnostic-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        Self { root, store }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn decision_and_followup_heartbeat_are_separate_and_do_not_leak_private_input() {
    let f = Fixture::new();
    let config = Config::default();
    let digest = policy_digest(&config.value().unwrap()).unwrap();
    f.store
        .atomic_bytes(
            &f.store.paths.watch().join("state/heartbeat"),
            b"123|secret-process-stamp|990|error|GUARD\n",
            0o600,
        )
        .unwrap();
    f.store
        .atomic_json(
            &f.store.paths.base().join("guard-heartbeat.json"),
            &json!({
                "time":995.0,"status":"ok","policy":digest,
                "session_id":"private-token-123","ip":"203.0.113.9"
            }),
        )
        .unwrap();
    let local = json!({"guard_state":"unknown","backend_healthy":false,"backend_native":false,
        "backend_detail":"心跳未报告有效采样","tag":{"node":"private-node"},
        "account":"private-user","ip":"203.0.113.9"});
    let phase = capture_phase(&f.store, &config, &local, 1000.0);
    assert_eq!(phase.decision, "unknown");
    assert_eq!(phase.backend_reason, "sample_not_ok");
    assert_eq!(phase.backend_heartbeat_status, "error");
    assert_eq!(phase.backend_heartbeat_age_seconds, Some(10.0));
    // The additional heartbeat read may already differ from the actual decision.
    assert_eq!(phase.guard_heartbeat_status, "ok");
    assert_eq!(phase.guard_heartbeat_age_seconds, Some(5.0));
    assert_eq!(phase.policy_matches, Some(true));
    let json = serde_json::to_string(&phase).unwrap();
    for secret in [
        "203.0.113.9",
        "private-token",
        "private-user",
        "private-node",
        "secret-process",
        &digest,
    ] {
        assert!(!json.contains(secret), "unexpected private data: {secret}");
    }
}

#[test]
fn invalid_missing_and_future_heartbeats_remain_diagnostic_only() {
    let f = Fixture::new();
    let config = Config::default();
    let local = json!({"guard_state":"unknown","backend_detail":"unsupported-private-string"});
    let missing = capture_phase(&f.store, &config, &local, 1000.0);
    assert_eq!(missing.backend_heartbeat_status, "missing");
    assert_eq!(missing.guard_heartbeat_status, "missing");
    assert_eq!(missing.backend_reason, "unavailable");
    f.store
        .atomic_bytes(
            &f.store.paths.watch().join("state/heartbeat"),
            b"bad",
            0o600,
        )
        .unwrap();
    f.store
        .atomic_bytes(
            &f.store.paths.base().join("guard-heartbeat.json"),
            b"{bad",
            0o600,
        )
        .unwrap();
    let invalid = capture_phase(&f.store, &config, &local, 1000.0);
    assert_eq!(invalid.backend_heartbeat_status, "invalid");
    assert_eq!(invalid.guard_heartbeat_status, "invalid");
    f.store
        .atomic_json(
            &f.store.paths.base().join("guard-heartbeat.json"),
        &json!({"time":1002.0,"status":"unknown","policy":"different","code":"native_observation_unavailable","message":"private-token"}),
        )
        .unwrap();
    let future = capture_phase(&f.store, &config, &local, 1000.0);
    assert_eq!(future.guard_heartbeat_age_seconds, Some(-2.0));
    assert_eq!(future.policy_matches, Some(false));
    assert_eq!(
        future.guard_heartbeat_code.as_deref(),
        Some("native_observation_unavailable")
    );
    assert_eq!(future.decision, "unknown");
    let round = GuardRound {
        observation_id: uuid::Uuid::new_v4().to_string(),
        before: future.clone(),
        after: future.clone(),
    };
    EventStore::new(f.store.clone())
        .record_guard_diagnostic(&round, 1000.0)
        .unwrap();
    let view = event_history(
        &f.store,
        &EventHistoryQuery {
            filter: "attention".into(),
            query: "".into(),
            offset: 0,
        },
    )
    .unwrap();
    assert!(view["events"][0]["explanation"]
        .as_str()
        .unwrap()
        .contains("未来 2.0 秒"));
    f.store
        .atomic_json(
            &f.store.paths.base().join("guard-heartbeat.json"),
            &json!({"time":1000.0,"status":"unknown","code":"secret-token-123"}),
        )
        .unwrap();
    let redacted = capture_phase(&f.store, &config, &local, 1000.0);
    assert_eq!(redacted.guard_heartbeat_code.as_deref(), Some("other"));
    assert!(!serde_json::to_string(&redacted)
        .unwrap()
        .contains("secret-token-123"));
}

#[test]
fn history_keeps_changes_but_deduplicates_repeated_rounds_and_rejects_untrusted_fields() {
    let f = Fixture::new();
    let config = Config::default();
    let before = capture_phase(
        &f.store,
        &config,
        &json!({"guard_state":"ok","backend_healthy":true,
        "backend_native":true,"backend_detail":"原生采集后台身份与心跳已核对"}),
        1000.0,
    );
    let after = capture_phase(
        &f.store,
        &config,
        &json!({"guard_state":"unknown","backend_healthy":false,
        "backend_native":false,"backend_detail":"心跳未报告有效采样"}),
        1001.0,
    );
    let mut round = GuardRound {
        observation_id: uuid::Uuid::new_v4().to_string(),
        before,
        after,
    };
    let events = EventStore::new(f.store.clone());
    assert!(events.record_guard_diagnostic(&round, 1002.0).unwrap());
    round.observation_id = uuid::Uuid::new_v4().to_string();
    round.before.sampled_at += 20.0;
    assert!(!events.record_guard_diagnostic(&round, 1022.0).unwrap());
    round.after.guard_heartbeat_status = "degraded".into();
    assert!(events.record_guard_diagnostic(&round, 1023.0).unwrap());
    round.after.guard_heartbeat_age_seconds = Some(5.0);
    assert!(events.record_guard_diagnostic(&round, 1024.0).unwrap());
    round.after.guard_heartbeat_age_seconds = Some(40.0);
    assert!(events.record_guard_diagnostic(&round, 1025.0).unwrap());
    let view = event_history(
        &f.store,
        &EventHistoryQuery {
            filter: "attention".into(),
            query: "采样未正常".into(),
            offset: 0,
        },
    )
    .unwrap();
    assert_eq!(view["total"], 4);
    assert_eq!(view["events"][0]["title"], "保护后台心跳检查");
    assert!(view["events"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("检测前：已确认"));
    assert!(view["events"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("检测后：未确认"));
    assert!(view["events"][0]["explanation"]
        .as_str()
        .unwrap()
        .contains("判定后附读"));
    round.after.backend_reason = "secret-token-123".into();
    assert!(events.record_guard_diagnostic(&round, 1026.0).is_err());
    let raw = fs::read_to_string(f.store.paths.base().join("diagnostic-events.jsonl")).unwrap();
    assert!(!raw.contains("secret-token-123"));
    assert!(!raw.contains(":null"));
}

#[test]
fn triggered_heartbeat_is_preserved_and_unknown_still_rejected() {
    let f = Fixture::new();
    let config = Config::default();
    f.store.atomic_json(&f.store.paths.base().join("guard-heartbeat.json"), &json!({"time":1000.0,"status":"protection_triggered"})).unwrap();
    let phase = capture_phase(&f.store, &config, &json!({"guard_state":"unknown","guard_backend_healthy":true}), 1001.0);
    assert_eq!(phase.guard_heartbeat_status, "protection_triggered");
    assert_eq!(phase.guard_backend_healthy, Some(true));
    let mut bad = phase.clone(); bad.guard_heartbeat_status = "private-address-1.2.3.4".into();
    let round = GuardRound { observation_id: uuid::Uuid::new_v4().to_string(), before: phase.clone(), after: phase };
    assert!(EventStore::new(f.store.clone()).record_guard_diagnostic(&round, 1001.0).is_ok());
    let bad_round = GuardRound { after: bad, ..round };
    assert!(EventStore::new(f.store.clone()).record_guard_diagnostic(&bad_round, 1002.0).is_err());
}
