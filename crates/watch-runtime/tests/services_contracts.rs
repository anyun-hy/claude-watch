use claude_watch_core::{config::Config, error::Result};
use claude_watch_runtime::{
    config_store::{guard_policy_digest, policy_digest, ConfigStore},
    macos::guard_heartbeat_confirmed,
    services::{self, ServiceSystem},
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};
use uuid::Uuid;
struct Fake {
    now: f64,
    watchdog: Value,
    jobs: Value,
    applied: Vec<Value>,
    runtime: bool,
    fail_after_apply: bool,
    native_healthy: bool,
    guard_healthy: bool,
    diagnostics: Value,
}
impl ServiceSystem for Fake {
    fn now(&self) -> f64 {
        self.now
    }
    fn backend_healthy(&self) -> bool {
        true
    }
    fn guard_status(&self, c: &Config) -> Result<bool> {
        Ok(c.enabled && c.guard_enabled && self.guard_healthy)
    }
    fn backend_health_snapshot(&self, c: &Config) -> Result<services::BackendHealthSnapshot> {
        Ok(services::BackendHealthSnapshot {
            sampling_healthy: self.backend_healthy(),
            guard_backend_healthy: self.native_healthy,
            guard_healthy: self.guard_status(c)?,
            diagnostics: self.diagnostics.clone(),
        })
    }
    fn service_job(&self, n: &str) -> Result<Value> {
        Ok(self.jobs[n].clone())
    }
    fn watchdog_state(&self) -> Result<Value> {
        Ok(self.watchdog.clone())
    }
    fn admin_helper_status(&self) -> Result<Value> {
        Ok(json!({"trusted":true,"abi":1}))
    }
    fn runtime_present(&self) -> bool {
        self.runtime
    }
    fn apply_service(&mut self, a: &Value) -> Result<()> {
        match a["id"].as_str() {
            Some("watchdog") => {
                self.watchdog["target"] = a["after"].clone();
                self.watchdog["registered"] = json!(!a["after"].is_null());
                self.jobs["watchdog"]["registered"] = self.watchdog["registered"].clone()
            }
            Some("updater") => self.jobs["updater"]["registered"] = a["after"].clone(),
            _ => {}
        }
        self.applied.push(a.clone());
        if self.fail_after_apply {
            return Err(claude_watch_core::error::CoreError::new(
                "injected_failure",
                "fixture",
            ));
        }
        Ok(())
    }
    fn restore_service(&mut self, a: &Value) -> Result<bool> {
        if a["id"] == "updater" && self.jobs["updater"]["registered"] == a["after"] {
            self.jobs["updater"]["registered"] = a["before"].clone();
            return Ok(true);
        }
        if a["id"] == "watchdog" && self.watchdog["target"] == a["after"] {
            self.watchdog["target"] = a["before"].clone();
            self.watchdog["registered"] = json!(!a["before"].is_null());
            return Ok(true);
        }
        Ok(false)
    }
}
fn store() -> (PathBuf, StateStore) {
    let p = std::env::temp_dir().join(format!("cw-service-{}", Uuid::new_v4()));
    fs::create_dir(&p).unwrap();
    let s = StateStore::new(Paths::new(&p).unwrap());
    (p, s)
}
fn fake() -> Fake {
    Fake {
        now: 100.,
        watchdog: json!({"target":"Asia/Tokyo","registered":true}),
        jobs: json!({"original":{"registered":true,"trusted":true,"last_exit":0},"watchdog":{"registered":true,"trusted":true,"definition":"v1"},"updater":{"registered":false,"trusted":false,"definition":"v1"}}),
        applied: vec![],
        runtime: true,
        fail_after_apply: false,
        native_healthy: true,
        guard_healthy: true,
        diagnostics: json!({"reason":"confirmed"}),
    }
}
#[test]
fn service_status_preserves_the_same_failed_backend_observation() {
    let mut f = fake();
    f.native_healthy = false;
    f.diagnostics = json!({"reason":"job_unconfirmed","heartbeat_pid":42,"heartbeat_age_seconds":1.5,
        "launchd_pid":40,"worker_verified":false,"worker_error_code":"native_listener_worker_mismatch"});
    let status = services::service_status(&f, &Config::default()).unwrap();
    assert_eq!(status["guard_backend_healthy"], false);
    assert_eq!(status["backend_diagnostics"], f.diagnostics);
}
#[test]
fn guard_service_reports_verified_failure_without_promoting_settings_to_readiness() {
    let mut f = fake(); f.guard_healthy = false;
    f.diagnostics["guard"] = json!({"reason_code":"gateway_not_installed","evidence_observed_at":100.0});
    let config = Config { enabled:true, guard_enabled:true, ..Config::default_for_new_install() };
    let failed = services::service_status(&f,&config).unwrap();
    let row = &failed["services"][0];
    assert_eq!(row["state"],"error"); assert_eq!(row["execution_verified"],false);
    assert_eq!(row["reason_code"],"gateway_not_installed");
    assert!(row["detail"].as_str().unwrap().contains("受控网关尚未安装完整"));
    f.guard_healthy = true;
    let recovered = services::service_status(&f,&config).unwrap();
    assert_eq!(recovered["services"][0]["reason_code"],"guard_ready");
    assert_eq!(recovered["services"][0]["state"],"running");
    assert!(!recovered["services"][0]["detail"].as_str().unwrap().contains("未安装"));
}
#[test]
fn saved_intent_is_not_actual_service() {
    let f = fake();
    let c = Config {
        auto_update: true,
        ..Config::default()
    };
    let s = services::service_status(&f, &c).unwrap();
    assert_eq!(s["services"][3]["state"], "unavailable");
    assert_eq!(s["services"][1]["state"], "scheduled");
}
#[test]
fn updater_definition_is_fixed_to_twelve_hours_and_safe_arguments() {
    let definition = services::update_task_definition("/runtime/watch-engine").unwrap();
    assert_eq!(definition["label"], "io.local.claudewatch.update");
    assert_eq!(definition["start_interval"], 43_200);
    assert_eq!(
        definition["program_arguments"],
        json!(["/runtime/watch-engine", "update", "--auto", "--apply"])
    );
    assert_eq!(
        services::update_task_definition("bad\npath")
            .unwrap_err()
            .code,
        "invalid_runtime"
    );
}
#[test]
fn watchdog_uses_recent_measured_reference_not_saved_timezone() {
    let (home, st) = store();
    st.atomic_json(&st.paths.base().join("last-audit.json"),&json!({"ready":true,"context_transition":{"state":"stable"},"egress_reference":{"checked_at":100.,"country":"JP","timezone":"Asia/Tokyo"}})).unwrap();
    let f = fake();
    let p = services::protection_preview(&st, &f, &json!({"timezone_watchdog":true})).unwrap();
    assert_eq!(p["actions"][0]["after"], "Asia/Tokyo");
    assert_eq!(p["desired_config"]["country"], "JP");
    let _ = fs::remove_dir_all(home);
}
#[test]
fn every_protection_action_carries_the_fields_the_ui_decodes() {
    // SwitcherRepairAction requires `id`, `title` and `scope`; a missing title
    // makes the whole plan undecodable, which used to look like a dead button.
    let (home, st) = store();
    st.atomic_json(&st.paths.base().join("last-audit.json"),&json!({"ready":true,"context_transition":{"state":"stable"},"egress_reference":{"checked_at":100.,"country":"JP","timezone":"Asia/Tokyo"}})).unwrap();
    let f = fake();
    for changes in [
        json!({"guard_enabled":false}),
        json!({"timezone_watchdog":true}),
        json!({"auto_update":false}),
    ] {
        let p = services::protection_preview(&st, &f, &changes).unwrap();
        let actions = p["actions"].as_array().unwrap();
        assert_eq!(actions.len(), 1, "{changes}");
        for action in actions {
            for field in ["id", "title", "scope"] {
                assert!(
                    action[field].as_str().is_some_and(|v| !v.is_empty()),
                    "{changes} action is missing `{field}`: {action}"
                );
            }
        }
    }
    let _ = fs::remove_dir_all(home);
}
#[test]
fn watchdog_preview_plans_the_helper_install_instead_of_refusing_to_enable() {
    struct Untrusted(Fake);
    impl ServiceSystem for Untrusted {
        fn now(&self) -> f64 {
            self.0.now()
        }
        fn backend_healthy(&self) -> bool {
            true
        }
        fn guard_status(&self, c: &Config) -> Result<bool> {
            self.0.guard_status(c)
        }
        fn service_job(&self, n: &str) -> Result<Value> {
            self.0.service_job(n)
        }
        fn watchdog_state(&self) -> Result<Value> {
            self.0.watchdog_state()
        }
        fn admin_helper_status(&self) -> Result<Value> {
            Ok(json!({"trusted":false,"abi":null}))
        }
        fn runtime_present(&self) -> bool {
            true
        }
        fn apply_service(&mut self, a: &Value) -> Result<()> {
            self.0.apply_service(a)
        }
    }
    let (home, st) = store();
    st.atomic_json(&st.paths.base().join("last-audit.json"),&json!({"ready":true,"context_transition":{"state":"stable"},"egress_reference":{"checked_at":100.,"country":"JP","timezone":"Asia/Tokyo"}})).unwrap();
    // A fresh install has no root helper yet; the same administrator
    // authorization that applies the change installs it, so the preview must
    // still produce a usable plan (2.9.5 behaviour).
    let p =
        services::protection_preview(&st, &Untrusted(fake()), &json!({"timezone_watchdog":true}))
            .unwrap();
    assert_eq!(p["actions"][0]["after"], "Asia/Tokyo");
    assert_eq!(p["actions"][0]["admin_helper_required"], true);
    assert!(p["actions"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("管理员授权"));
    let helper_ready =
        services::protection_preview(&st, &fake(), &json!({"timezone_watchdog":true})).unwrap();
    assert_eq!(helper_ready["actions"][0]["admin_helper_required"], false);
    let _ = fs::remove_dir_all(home);
}
#[test]
fn update_preview_requires_pinned_source_and_apply_reads_back() {
    let (home, st) = store();
    let mut f = fake();
    assert_eq!(
        services::protection_preview(&st, &f, &json!({"auto_update":true}))
            .unwrap_err()
            .code,
        "update_source_missing"
    );
    let mut c = Config::default().value().unwrap();
    c["update_url"] = json!("https://updates.invalid/release.json");
    c["update_public_key"] = json!("key");
    st.atomic_json(&st.paths.config(), &c).unwrap();
    let p = services::protection_preview(&st, &f, &json!({"auto_update":true})).unwrap();
    let out = services::protection_apply(
        &st,
        &mut f,
        &json!({"auto_update":true}),
        p["id"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(out["status"], "ok");
    assert_eq!(f.jobs["updater"]["registered"], true);
    let _ = fs::remove_dir_all(home);
}
#[test]
fn recovery_restores_config_only_when_current_value_is_ours() {
    let (home, st) = store();
    let mut before = Config::default().value().unwrap();
    before["guard_enabled"] = json!(true);
    let mut after = before.clone();
    after["guard_enabled"] = json!(false);
    st.atomic_json(&st.paths.config(), &after).unwrap();
    st.atomic_json(&st.paths.base().join("service-transaction.json"), &json!({"schema":1,"origin":"protection","desired_config":after,"config_before":before,"config_after":after,"actions":[]})).unwrap();
    assert_eq!(services::recover(&st, &mut fake()).unwrap()["status"], "ok");
    assert_eq!(
        st.read_json(&st.paths.config(), Value::Null).unwrap()["guard_enabled"],
        true
    );
    let _ = fs::remove_dir_all(home);
}

#[test]
fn fresh_enable_clock_and_reopen_preserve_independent_guard() {
    let (home, st) = store();
    let mut system = fake();
    system.watchdog = json!({"target":null,"registered":false});
    system.jobs["watchdog"]["registered"] = json!(false);
    let configs = || ConfigStore {
        storage: st.clone(),
    };
    let fresh = configs().load().unwrap();
    assert!(!fresh.guard_enabled && !fresh.timezone_watchdog);

    let guard_change = json!({"guard_enabled":true});
    let plan = services::protection_preview(&st, &system, &guard_change).unwrap();
    services::protection_apply(
        &st,
        &mut system,
        &guard_change,
        plan["id"].as_str().unwrap(),
    )
    .unwrap();
    let before = configs().load().unwrap();
    assert!(before.guard_enabled && !before.timezone_watchdog);
    let heartbeat = json!({"time":100.,"status":"ok",
        "policy":policy_digest(&before.value().unwrap()).unwrap(),
        "guard_policy_v1":guard_policy_digest(&before).unwrap()});
    assert!(guard_heartbeat_confirmed(&before, true, 100., &heartbeat));

    st.atomic_json(
        &st.paths.base().join("last-audit.json"),
        &json!({
            "ready":true,"context_transition":{"state":"stable"},
            "egress_reference":{"checked_at":100.,"country":"JP","timezone":"Asia/Tokyo"}
        }),
    )
    .unwrap();
    let clock_change = json!({"timezone_watchdog":true});
    let plan = services::protection_preview(&st, &system, &clock_change).unwrap();
    services::protection_apply(
        &st,
        &mut system,
        &clock_change,
        plan["id"].as_str().unwrap(),
    )
    .unwrap();
    let reopened = configs().load().unwrap();
    assert!(reopened.guard_enabled && reopened.timezone_watchdog);
    assert_eq!(reopened.country, "JP");
    assert_eq!(reopened.timezone, "Asia/Tokyo");
    assert_ne!(
        policy_digest(&before.value().unwrap()).unwrap(),
        policy_digest(&reopened.value().unwrap()).unwrap()
    );
    assert!(guard_heartbeat_confirmed(&reopened, true, 101., &heartbeat));
    assert!(!guard_heartbeat_confirmed(
        &reopened, false, 101., &heartbeat
    ));
    assert!(!guard_heartbeat_confirmed(
        &reopened, true, 136., &heartbeat
    ));
    let mut failed = heartbeat.clone();
    failed["status"] = json!("degraded");
    assert!(!guard_heartbeat_confirmed(&reopened, true, 101., &failed));
    let mut changed_proxy = reopened.clone();
    changed_proxy.proxy_mode = "tag".into();
    assert!(!guard_heartbeat_confirmed(
        &changed_proxy,
        true,
        101.,
        &heartbeat
    ));
    let mut bad_scoped = heartbeat.clone();
    bad_scoped["guard_policy_v1"] = json!(null);
    assert!(!guard_heartbeat_confirmed(&before, true, 101., &bad_scoped));
    let legacy = json!({"time":100.,"status":"ok","policy":heartbeat["policy"]});
    assert!(guard_heartbeat_confirmed(&before, true, 101., &legacy));
    assert!(!guard_heartbeat_confirmed(&reopened, true, 101., &legacy));

    let disabled = json!({"guard_enabled":false});
    let plan = services::protection_preview(&st, &system, &disabled).unwrap();
    services::protection_apply(&st, &mut system, &disabled, plan["id"].as_str().unwrap()).unwrap();
    let after_reopen = configs().load().unwrap();
    assert!(!after_reopen.guard_enabled && after_reopen.timezone_watchdog);
    assert!(!guard_heartbeat_confirmed(
        &after_reopen,
        true,
        101.,
        &heartbeat
    ));
    fs::remove_dir_all(home).unwrap();
}
#[test]
fn failed_service_write_rolls_back_and_does_not_leave_an_unreachable_confirmation() {
    let (home, store) = store();
    let mut system = fake();
    system.fail_after_apply = true;
    let mut config = Config::default().value().unwrap();
    config["update_url"] = json!("https://updates.invalid/release.json");
    config["update_public_key"] = json!("key");
    store.atomic_json(&store.paths.config(), &config).unwrap();
    let plan = services::protection_preview(&store, &system, &json!({"auto_update":true})).unwrap();
    let error = services::protection_apply(
        &store,
        &mut system,
        &json!({"auto_update":true}),
        plan["id"].as_str().unwrap(),
    )
    .unwrap_err();
    assert_eq!(error.code, "protection_rolled_back");
    assert_eq!(system.jobs["updater"]["registered"], false);
    assert_eq!(
        store.read_json(&store.paths.config(), Value::Null).unwrap(),
        config
    );
    assert!(!store.paths.base().join("service-transaction.json").exists());
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn legacy_bodyguard_conflict_is_projected_in_service_status_and_policy_issues() {
    let (home, store) = store();
    let mut system = fake();
    system.jobs["original"]["registered"] = json!(true);

    let mut config = Config::default();
    config.guard_enabled = false;
    config.policy_actions.insert("claude_close_session".into(), "warn".into());
    store.atomic_json(&store.paths.config(), &config.value().unwrap()).unwrap();

    let status = services::service_status(&system, &config).unwrap();
    let arb = &status["authority_arbitration"];
    assert_eq!(arb["legacy_bodyguard_active"], true);
    assert_eq!(arb["effective_proxy_loss_enforcement"], "legacy_root_kill");

    let issues = status["policy_issues"].as_array().unwrap();
    assert!(issues.iter().any(|i| i["id"] == "legacy_bodyguard_overrides_policy"));

    let _ = fs::remove_dir_all(home);
}

#[test]
fn dual_timezone_writer_conflict_is_projected() {
    let (home, store) = store();
    let mut system = fake();
    system.jobs.as_object_mut().unwrap().insert(
        "legacy_watchdog".into(),
        json!({"registered":true,"trusted":true}),
    );

    let mut config = Config::default();
    config.timezone_watchdog = true;
    store.atomic_json(&store.paths.config(), &config.value().unwrap()).unwrap();

    let status = services::service_status(&system, &config).unwrap();
    let arb = &status["authority_arbitration"];
    assert_eq!(arb["legacy_tz_active"], true);

    let issues = status["policy_issues"].as_array().unwrap();
    assert!(issues.iter().any(|i| i["id"] == "dual_timezone_writer_conflict"));

    let _ = fs::remove_dir_all(home);
}

#[test]
fn execution_receipt_and_health_basis_are_projected_truthfully() {
    let (home, _store) = store();
    let mut system = fake();
    let mut config = Config::default();
    config.timezone_watchdog = true;
    config.timezone = "Asia/Tokyo".into();
    system.jobs["watchdog"]["registered"] = json!(true);
    system.jobs["original"]["registered"] = json!(true);

    // 1. Fresh execution receipt (now = 1000., last_success = 900., delta = 100s <= 7200s)
    system.now = 1000.0;
    system.watchdog = json!({
        "registered": true,
        "target": "Asia/Tokyo",
        "last_success_at": 900.0,
    });
    let status = services::service_status(&system, &config).unwrap();
    let rows = status["services"].as_array().unwrap();

    let watchdog_row = rows.iter().find(|r| r["id"] == "watchdog").unwrap();
    assert_eq!(watchdog_row["state"], "scheduled");
    assert_eq!(watchdog_row["execution_verified"], true);
    assert_eq!(watchdog_row["health_basis"], "root_execution_receipt");

    let original_row = rows.iter().find(|r| r["id"] == "original").unwrap();
    assert_eq!(original_row["state"], "scheduled");
    assert_eq!(original_row["execution_verified"], false);
    assert_eq!(original_row["health_basis"], "launchd_registration_only");

    // 2. Expired execution receipt (now = 10000., last_success = 900., delta = 9100s > 7200s)
    system.now = 10000.0;
    let status_expired = services::service_status(&system, &config).unwrap();
    let rows_expired = status_expired["services"].as_array().unwrap();
    let watchdog_expired = rows_expired.iter().find(|r| r["id"] == "watchdog").unwrap();
    assert_eq!(watchdog_expired["execution_verified"], false);
    assert_eq!(watchdog_expired["health_basis"], "launchd_registration_only");

    let _ = fs::remove_dir_all(home);
}

#[test]
fn receipt_timestamp_reader_rejects_missing_wrong_owner_writable_and_symlink() {
    use claude_watch_runtime::service_native::read_receipt_timestamp;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    let (home, _store) = store();
    let uid = fs::metadata(&home).unwrap().uid();
    let missing = home.join("missing.last-success");
    assert_eq!(read_receipt_timestamp(&missing, uid), None);

    let receipt = home.join("timezone.last-success");
    fs::write(&receipt, "1700000000\n").unwrap();
    fs::set_permissions(&receipt, fs::Permissions::from_mode(0o644)).unwrap();

    // 1. Valid owner and mode 0644 succeeds
    assert_eq!(read_receipt_timestamp(&receipt, uid), Some(1_700_000_000.0));

    // 2. Non-matching owner (e.g. expecting root uid 0 on a user-owned file) is rejected
    if uid != 0 {
        assert_eq!(read_receipt_timestamp(&receipt, 0), None);
    }
    assert_eq!(read_receipt_timestamp(&receipt, uid.wrapping_add(1)), None);

    // 3. Group/world-writable mode is rejected
    fs::set_permissions(&receipt, fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(read_receipt_timestamp(&receipt, uid), None);
    fs::set_permissions(&receipt, fs::Permissions::from_mode(0o644)).unwrap();

    // 4. Symlink is rejected via symlink_metadata + O_NOFOLLOW
    let link = home.join("symlink.last-success");
    symlink(&receipt, &link).unwrap();
    assert_eq!(read_receipt_timestamp(&link, uid), None);

    let _ = fs::remove_dir_all(home);
}
