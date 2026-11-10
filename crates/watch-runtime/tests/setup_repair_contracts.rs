use claude_watch_core::{config::Config, error::Result, region::ZoneCatalog};
use claude_watch_runtime::{
    onboarding::{self, OnboardingSystem},
    repair::{self, RepairSystem},
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{
    cell::{Cell, RefCell},
    fs,
    path::PathBuf,
};
use uuid::Uuid;

struct Fake {
    packaged_backend: Option<claude_watch_core::channel::NetworkBackendKind>,
    vpn: Option<claude_watch_core::vpn::VpnObservation>,
    vpn_after_baseline: Option<claude_watch_core::vpn::VpnObservation>,
    now: f64,
    local: Value,
    applied: Vec<Value>,
    fail_action: Option<String>,
    restore_ok: bool,
    baseline: String,
    network: Value,
    network_after_baseline: Option<Value>,
    baseline_read: Cell<bool>,
    local_reads: Cell<usize>,
    egress_reads: Cell<usize>,
    lose_backend_after_first_read: bool,
    egress: Value,
    egress_after_first_read: Option<Value>,
    progress: RefCell<Vec<claude_watch_runtime::setup_progress::Phase>>,
}
impl RepairSystem for Fake {
    fn local(&self, _: &Config) -> Result<Value> {
        let reads = self.local_reads.get();
        self.local_reads.set(reads + 1);
        let mut value = self.local.clone();
        if self.lose_backend_after_first_read && reads > 0 {
            value["guard_backend_healthy"] = json!(false);
        }
        Ok(value)
    }
    fn apply(&mut self, a: &Value) -> Result<()> {
        if self.fail_action.as_deref() == a["id"].as_str() {
            return Err(claude_watch_core::error::CoreError::new(
                "injected_failure",
                "fixture action failure",
            ));
        }
        if let Some(k) = a["id"]
            .as_str()
            .filter(|k| matches!(*k, "timezone" | "locale"))
        {
            self.local[k] = a["after"].clone();
        }
        if a["id"] == "language" {
            self.local["app_language"] = json!(["en-US"]);
        }
        self.applied.push(a.clone());
        Ok(())
    }
    fn restore(&mut self, a: &Value) -> Result<bool> {
        if !self.restore_ok {
            return Ok(false);
        }
        if let Some(k) = a["id"]
            .as_str()
            .filter(|k| matches!(*k, "timezone" | "locale"))
        {
            self.local[k] = a["before"].clone();
        }
        Ok(true)
    }
    fn egress_reference(&self, _: &Config) -> Result<Value> {
        let prior = self.egress_reads.get();
        self.egress_reads.set(self.egress_reads.get() + 1);
        Ok(if prior > 0 {
            self.egress_after_first_read
                .clone()
                .unwrap_or_else(|| self.egress.clone())
        } else {
            self.egress.clone()
        })
    }
}
impl OnboardingSystem for Fake {
    fn packaged_backend(&self) -> Option<claude_watch_core::channel::NetworkBackendKind> { self.packaged_backend }
    fn vpn_observation(&self, _: &claude_watch_core::vpn::VpnExpectation) -> Result<claude_watch_core::vpn::VpnObservation> {
        if self.baseline_read.get() {
            if let Some(ref observed) = self.vpn_after_baseline { return Ok(observed.clone()); }
        }
        self.vpn.clone().ok_or_else(|| claude_watch_core::error::CoreError::new("vpn_observation_unavailable", "fixture no VPN sample"))
    }
    fn progress(&self, phase: claude_watch_runtime::setup_progress::Phase) {
        self.progress.borrow_mut().push(phase);
    }
    fn network(&self) -> Result<Value> {
        Ok(if self.baseline_read.get() {
            self.network_after_baseline
                .clone()
                .unwrap_or_else(|| self.network.clone())
        } else {
            self.network.clone()
        })
    }
    fn now(&self) -> f64 {
        self.now
    }
    fn baseline_data(&self) -> Result<String> {
        self.baseline_read.set(true);
        Ok(self.baseline.clone())
    }
}
fn store() -> (PathBuf, StateStore) {
    let p = std::env::temp_dir().join(format!("cw-setup-{}", Uuid::new_v4()));
    fs::create_dir(&p).unwrap();
    let s = StateStore::new(Paths::new(&p).unwrap());
    (p, s)
}
fn fake() -> Fake {
    Fake {
        packaged_backend: None,
        vpn: None,
        vpn_after_baseline: None,
        now: 100.0,
        local: json!({"proxy":"ok","tun":"ok","backend_healthy":true,"guard_backend_healthy":true,"mode":"tag","context":"same","timezone":"America/New_York","locale":"en_US","language":"zh-CN","app_language":["zh-CN"],"ipv6":"ok","processes":[{"pid":7,"executable":"/TAG","uid":501,"start_stamp":"s"}],"tag":{"entry":{"state":"verified","public_listener":false,"owners":[{"pid":7,"executable":"/TAG","uid":501,"stamp":"s"}]},"api":{"state":"available","covers_7890":true,"mode":"rule"}}}),
        applied: vec![],
        fail_action: None,
        restore_ok: true,
        baseline: "format=2\ntimezone=America/New_York\n".into(),
        network: json!({"service":"Wi-Fi","interface":"en0"}),
        network_after_baseline: None,
        baseline_read: Cell::new(false),
        local_reads: Cell::new(0),
        egress_reads: Cell::new(0),
        lose_backend_after_first_read: false,
        egress: json!({"trace":{"ip":"1.1.1.1","loc":"JP"},"geo":{"ip":"1.1.1.1","country":"JP","timezone":"Asia/Tokyo"}}),
        egress_after_first_read: None,
        progress: RefCell::new(Vec::new()),
    }
}

fn seatbelt_fake() -> Fake {
    use claude_watch_core::{channel::NetworkBackendKind, vpn::*};
    let mut f = fake();
    f.packaged_backend = Some(NetworkBackendKind::Seatbelt);
    f.local["tag"]["expected_group"] = json!("AI");
    f.local["tag"]["api"]["selected_node"] = json!("JP-1");
    f.vpn = Some(VpnObservation {
        source: "tag".into(), source_instance: Some("pid:7:10:0".into()), source_revision: Some("r1".into()),
        upstream_endpoint: Some("http://127.0.0.1:7890".into()), upstream_protocol: ObservedField::Known(UpstreamProtocol::MixedHttp),
        running_mode: ObservedField::Known("rule".into()), tun_enabled: ObservedField::Known(true), system_proxy_enabled: ObservedField::Known(false),
        selected_group: ObservedField::Known("AI".into()), selected_node: ObservedField::Known("JP-1".into()),
        proxy_chain: ObservedField::Known(vec!["AI".into(), "JP-1".into()]), rules_digest: ObservedField::Known("a".repeat(64)),
        sample_started_at: 99.0, observed_at: 99.2, valid_until: 102.5, consistency: ObservationConsistency::BoundaryVerified,
        source_error: None, sample_seq: 1, epoch: VpnEpoch {observer_boot_id:"fixture-vpn".into(),change_generation:1},
    });
    f
}

fn settings_only_options() -> Value {
    json!({"apply_environment":false,"enable_policy":true,"guard_enabled":true,"timezone_watchdog":false,"auto_update":false})
}

#[test]
fn seatbelt_setup_saves_backend_and_confirmed_vpn_in_one_transaction_without_vpn_actions() {
    let (home, store) = store(); let mut f = seatbelt_fake();
    let c = onboarding::detect(&store, &f, "auto", true, &claude_watch_runtime::region_catalog::load_system_catalog()).unwrap();
    assert!(!store.paths.config().exists(), "detection cannot save or migrate configuration");
    assert_eq!(c["vpn_observation"]["observed_at"], 99.2, "retain actual source time");
    assert_eq!(c["vpn_expectation"]["require_system_proxy"], false);
    let options = settings_only_options();
    let p = onboarding::preview(&store, &f, c["id"].as_str().unwrap(), &options, None).unwrap();
    assert_eq!(p["desired_config"]["schema"], 2);
    assert_eq!(p["desired_config"]["network_backend"], "seatbelt");
    assert!(p["confirmation_lines"].as_array().unwrap().iter().any(|v| v.as_str().unwrap().contains("不修改 VPN")));
    assert!(p["actions"].as_array().unwrap().iter().all(|v| matches!(v["id"].as_str(), Some("watchdog" | "updater"))));
    onboarding::apply(&store, &mut f, c["id"].as_str().unwrap(), &options, p["id"].as_str().unwrap(), None).unwrap();
    let saved = claude_watch_runtime::config_store::ConfigStore {storage:store.clone()}.load().unwrap();
    assert_eq!(saved.schema, 2);
    assert_eq!(saved.network_backend, Some(claude_watch_core::channel::NetworkBackendKind::Seatbelt));
    assert_eq!(saved.vpn_expectation.unwrap().expected_node.as_deref(), Some("JP-1"));
    assert!(f.applied.iter().all(|v| matches!(v["id"].as_str(), Some("watchdog" | "updater"))));
    let repeated = onboarding::detect(&store, &f, "auto", true, &claude_watch_runtime::region_catalog::load_system_catalog()).unwrap();
    let repeated_plan = onboarding::preview(&store, &f, repeated["id"].as_str().unwrap(), &options, None).unwrap();
    assert_eq!(repeated_plan["confirmation_lines"], json!([]), "unchanged approved VPN expectations do not trigger another migration confirmation");
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn seatbelt_setup_rejects_replaced_source_after_candidate_creation() {
    let (home, store) = store(); let mut f = seatbelt_fake();
    let c = onboarding::detect(&store, &f, "auto", true, &claude_watch_runtime::region_catalog::load_system_catalog()).unwrap();
    f.vpn.as_mut().unwrap().source_instance = Some("pid:8:11:0".into());
    assert_eq!(onboarding::preview(&store, &f, c["id"].as_str().unwrap(), &settings_only_options(), None).unwrap_err().code, "stale_candidate");
    assert!(!store.paths.config().exists());
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn seatbelt_setup_legacy_migration_requires_the_explicit_current_plan() {
    let (home, store) = store(); let mut f = seatbelt_fake();
    store.atomic_json(&store.paths.config(), &Config::default().value().unwrap()).unwrap();
    let before = fs::read(store.paths.config()).unwrap();
    let c = onboarding::detect(&store, &f, "auto", true, &claude_watch_runtime::region_catalog::load_system_catalog()).unwrap();
    let options = settings_only_options();
    let p = onboarding::preview(&store, &f, c["id"].as_str().unwrap(), &options, None).unwrap();
    assert_eq!(fs::read(store.paths.config()).unwrap(), before);
    assert_eq!(onboarding::apply(&store, &mut f, c["id"].as_str().unwrap(), &options, "unapproved", None).unwrap_err().code, "stale_plan");
    assert_eq!(fs::read(store.paths.config()).unwrap(), before);
    onboarding::apply(&store, &mut f, c["id"].as_str().unwrap(), &options, p["id"].as_str().unwrap(), None).unwrap();
    assert_eq!(claude_watch_runtime::config_store::ConfigStore {storage:store.clone()}.load().unwrap().schema, 2);
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn seatbelt_setup_rejects_unknown_stale_inconsistent_and_different_source_evidence() {
    use claude_watch_core::vpn::{ObservedField, ObservationConsistency};
    for case in 0..5 {
        let (home, store) = store(); let mut f = seatbelt_fake(); let sample = f.vpn.as_mut().unwrap();
        match case {
            0 => sample.valid_until = 99.9,
            1 => sample.system_proxy_enabled = ObservedField::Unknown("unavailable".into()),
            2 => sample.consistency = ObservationConsistency::InconsistentSnapshot("changed".into()),
            3 => sample.source_instance = None,
            _ => sample.upstream_endpoint = Some("http://127.0.0.1:7891".into()),
        }
        assert!(onboarding::detect(&store, &f, "auto", true, &claude_watch_runtime::region_catalog::load_system_catalog()).is_err(), "case {case}");
        assert!(!store.paths.config().exists());
        fs::remove_dir_all(home).unwrap();
    }
}

#[test]
fn seatbelt_setup_rechecks_vpn_before_preview_and_final_save_preserving_saved_expectations() {
    use claude_watch_core::vpn::ObservedField;
    for at_final_save in [false, true] {
        let (home, store) = store(); let mut f = seatbelt_fake();
        let c = onboarding::detect(&store, &f, "auto", true, &claude_watch_runtime::region_catalog::load_system_catalog()).unwrap();
        let options = settings_only_options();
        let p = onboarding::preview(&store, &f, c["id"].as_str().unwrap(), &options, None).unwrap();
        let mut changed = f.vpn.clone().unwrap(); changed.selected_node = ObservedField::Known("JP-2".into());
        if at_final_save { f.vpn_after_baseline = Some(changed); } else { f.vpn = Some(changed); }
        let failure = onboarding::apply(&store, &mut f, c["id"].as_str().unwrap(), &options, p["id"].as_str().unwrap(), None).unwrap_err();
        assert_eq!(failure.code, if at_final_save { "setup_rolled_back" } else { "vpn_expectation_mismatched" });
        assert!(failure.message.contains("JP-2"), "the actual VPN deviation survives transaction rollback reporting");
        assert!(!store.paths.config().exists());
        fs::remove_dir_all(home).unwrap();
    }
    let (home, store) = store(); let mut f = seatbelt_fake();
    let mut cfg = Config::default_for_new_install(); cfg.proxy_mode="tag".into(); cfg.proxy_url="http://127.0.0.1:7890".into(); cfg.proxy_group="AI".into();
    cfg.vpn_expectation = Some(f.vpn.as_ref().unwrap().to_candidate_expectation().unwrap());
    store.atomic_json(&store.paths.config(), &cfg.value().unwrap()).unwrap();
    let before = fs::read(store.paths.config()).unwrap();
    f.vpn.as_mut().unwrap().selected_node = ObservedField::Known("JP-2".into());
    assert_eq!(onboarding::detect(&store, &f, "auto", true, &claude_watch_runtime::region_catalog::load_system_catalog()).unwrap_err().code, "vpn_expectation_mismatched");
    assert_eq!(fs::read(store.paths.config()).unwrap(), before);
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn missing_timezone_uses_same_unique_zone_for_detection_and_confirmation() {
    let (home, store) = store();
    let zones = claude_watch_runtime::region_catalog::load_system_catalog();
    let mut system = fake();
    system.egress["geo"]["timezone"] = Value::Null;
    let candidate = onboarding::detect(&store, &system, "auto", true, &zones).unwrap();
    assert_eq!(candidate["values"]["timezone"], "Asia/Tokyo");
    let options = json!({"apply_environment":false,"enable_policy":true,"guard_enabled":true,"timezone_watchdog":false,"auto_update":false});
    let plan = onboarding::preview(
        &store,
        &system,
        candidate["id"].as_str().unwrap(),
        &options,
        None,
    )
    .unwrap();
    assert_eq!(
        onboarding::apply(
            &store,
            &mut system,
            candidate["id"].as_str().unwrap(),
            &options,
            plan["id"].as_str().unwrap(),
            None
        )
        .unwrap()["status"],
        "ok"
    );
    assert_eq!(
        *system.progress.borrow(),
        vec![
            claude_watch_runtime::setup_progress::Phase::VerifyEgress,
            claude_watch_runtime::setup_progress::Phase::VerifySettings,
            claude_watch_runtime::setup_progress::Phase::SaveBaseline,
        ],
        "a settings-only initialization must never announce an administrator request"
    );
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn changed_or_incomplete_confirmation_never_applies_settings() {
    let zones = claude_watch_runtime::region_catalog::load_system_catalog();
    for (replacement, expected_code) in [
        (
            json!({"trace":{"ip":"8.8.8.8","loc":"JP"},"geo":{"ip":"8.8.8.8","country":"JP","timezone":"Asia/Tokyo"}}),
            "egress_changed",
        ),
        (
            json!({"trace":{"ip":"1.1.1.1","loc":"US"},"geo":{"ip":"1.1.1.1","country":"US","timezone":"America/New_York"}}),
            "egress_changed",
        ),
        (
            json!({"trace":{"ip":"1.1.1.1","loc":"JP"},"geo":{"ip":"1.1.1.1","country":null,"timezone":null}}),
            "egress_unconfirmed",
        ),
        (
            json!({"trace":{"ip":null,"loc":null},"geo":{"ip":null,"country":null,"timezone":null}}),
            "egress_unconfirmed",
        ),
    ] {
        let (home, store) = store();
        let mut system = fake();
        system.egress_after_first_read = Some(replacement);
        let candidate = onboarding::detect(&store, &system, "auto", true, &zones).unwrap();
        let options = json!({"apply_environment":false,"enable_policy":true,"guard_enabled":true,"timezone_watchdog":false,"auto_update":false});
        let plan = onboarding::preview(
            &store,
            &system,
            candidate["id"].as_str().unwrap(),
            &options,
            None,
        )
        .unwrap();
        let error = onboarding::apply(
            &store,
            &mut system,
            candidate["id"].as_str().unwrap(),
            &options,
            plan["id"].as_str().unwrap(),
            None,
        )
        .unwrap_err();
        assert_eq!(error.code, expected_code);
        assert_eq!(
            *system.progress.borrow(),
            vec![claude_watch_runtime::setup_progress::Phase::VerifyEgress],
            "a failed egress recheck must not report an administrator request or system action"
        );
        assert!(system.applied.is_empty());
        assert!(!store.paths.config().exists());
        assert!(!store.paths.base().join("setup-transaction.json").exists());
        fs::remove_dir_all(home).unwrap();
    }
}

#[test]
fn ambiguous_missing_timezone_and_actual_timezone_change_fail_closed() {
    let zones: ZoneCatalog =
        serde_json::from_value(json!({"US":["America/New_York","America/Los_Angeles"]})).unwrap();
    let values =
        json!({"ip":"1.1.1.1","country":"US","timezone":"America/New_York","locale":"en_US"});
    let missing = json!({"trace":{"ip":"1.1.1.1","loc":"US"},"geo":{"ip":"1.1.1.1","country":"US","timezone":null}});
    assert_eq!(
        onboarding::confirm_reference(&values, &missing, &zones)
            .unwrap_err()
            .code,
        "egress_unconfirmed"
    );
    let changed = json!({"trace":{"ip":"1.1.1.1","loc":"US"},"geo":{"ip":"1.1.1.1","country":"US","timezone":"America/Los_Angeles"}});
    assert_eq!(
        onboarding::confirm_reference(&values, &changed, &zones)
            .unwrap_err()
            .code,
        "egress_changed"
    );
}

#[test]
fn initialization_uses_native_liveness_through_detection_preview_and_apply() {
    let (home, store) = store();
    let zones: ZoneCatalog = serde_json::from_value(json!({"JP":["Asia/Tokyo"]})).unwrap();
    let mut system = fake();
    system.local["backend_healthy"] = json!(false);
    // Exactly the installed-315 case: complete proxy/TUN evidence and live
    // native daemon, while an unrelated process exited during socket sampling.
    assert!(onboarding::require_transport(&system.local).is_ok());
    let candidate = onboarding::detect(&store, &system, "auto", true, &zones).unwrap();
    let options = json!({"apply_environment":false,"enable_policy":true,"guard_enabled":true,"timezone_watchdog":false,"auto_update":false});
    let plan = onboarding::preview(
        &store,
        &system,
        candidate["id"].as_str().unwrap(),
        &options,
        None,
    )
    .unwrap();
    let result = onboarding::apply(
        &store,
        &mut system,
        candidate["id"].as_str().unwrap(),
        &options,
        plan["id"].as_str().unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(result["status"], "ok");
    assert!(system.applied.iter().all(|a| !matches!(
        a["id"].as_str(),
        Some("rules" | "enable_tun" | "reload_proxy" | "legacy_stop")
    )));
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn initialization_real_transport_faults_block_before_any_egress_probe() {
    let zones: ZoneCatalog = serde_json::from_value(json!({"JP":["Asia/Tokyo"]})).unwrap();
    for (path, replacement) in [
        ("/guard_backend_healthy", json!(false)),
        ("/guard_backend_healthy", Value::Null),
        ("/guard_backend_healthy", json!("true")),
        ("/proxy", json!("fail")),
        ("/proxy", json!("unknown")),
        ("/tun", json!("fail")),
        ("/tun", json!("unknown")),
        ("/tag/entry/state", json!("mismatch")),
        ("/tag/entry/public_listener", json!(true)),
        ("/tag/api/state", json!("unavailable")),
        ("/tag/api/covers_7890", json!(false)),
        ("/tag/entry/owners/0/stamp", json!("reused-pid")),
        ("/tag/entry/owners/0/uid", json!(999)),
    ] {
        let (home, store) = store();
        let mut system = fake();
        *system.local.pointer_mut(path).unwrap() = replacement;
        assert!(
            onboarding::detect(&store, &system, "auto", true, &zones).is_err(),
            "{path}"
        );
        assert_eq!(system.egress_reads.get(), 0, "{path}");
        assert!(!store
            .paths
            .base()
            .join("environment-candidate.json")
            .exists());
        assert!(!store.paths.config().exists());
        fs::remove_dir_all(home).unwrap();
    }
    let mut missing = fake();
    missing
        .local
        .as_object_mut()
        .unwrap()
        .remove("guard_backend_healthy");
    assert!(
        onboarding::require_transport(&missing.local).is_err(),
        "sampling health cannot substitute for missing native liveness"
    );
}

#[test]
fn initialization_losing_native_heartbeat_during_detection_discards_candidate() {
    let (home, store) = store();
    let zones: ZoneCatalog = serde_json::from_value(json!({"JP":["Asia/Tokyo"]})).unwrap();
    let mut system = fake();
    system.lose_backend_after_first_read = true;
    assert!(onboarding::detect(&store, &system, "auto", true, &zones).is_err());
    assert_eq!(system.egress_reads.get(), 1);
    assert!(!store
        .paths
        .base()
        .join("environment-candidate.json")
        .exists());
    assert!(system.applied.is_empty());
    fs::remove_dir_all(home).unwrap();
}
#[test]
fn candidate_plan_is_expiring_and_context_bound_without_system_commands() {
    let (home, store) = store();
    let zones: ZoneCatalog = serde_json::from_value(json!({"JP":["Asia/Tokyo"]})).unwrap();
    let mut f = fake();
    let c = onboarding::detect(&store, &f, "auto", true, &zones).unwrap();
    let options = json!({"apply_environment":false,"enable_policy":true,"guard_enabled":true,"timezone_watchdog":false,"auto_update":false});
    let p = onboarding::preview(&store, &f, c["id"].as_str().unwrap(), &options, None).unwrap();
    let out = onboarding::apply(
        &store,
        &mut f,
        c["id"].as_str().unwrap(),
        &options,
        p["id"].as_str().unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(out["status"], "ok");
    let _ = fs::remove_dir_all(home);
}

#[test]
fn auto_detection_still_pins_node_when_observed_proxy_is_tag() {
    // Requested CLI mode "auto" must not silence node pinning: the pin is
    // bound to the observed TAG transport (values.proxy_mode), so auto
    // detection records the baseline photo exactly like explicit "tag".
    let (home, store) = store();
    let zones: ZoneCatalog = serde_json::from_value(json!({"JP":["Asia/Tokyo"]})).unwrap();
    let mut f = fake();
    let c = onboarding::detect(&store, &f, "auto", true, &zones).unwrap();
    assert_eq!(c["values"]["runtime_mode"], "rule");
    let options = json!({"apply_environment":false,"enable_policy":true,"guard_enabled":true,"timezone_watchdog":false,"auto_update":false});
    let p = onboarding::preview(&store, &f, c["id"].as_str().unwrap(), &options, None).unwrap();
    onboarding::apply(
        &store,
        &mut f,
        c["id"].as_str().unwrap(),
        &options,
        p["id"].as_str().unwrap(),
        None,
    )
    .unwrap();
    let baseline = fs::read_to_string(store.paths.watch().join("state/baseline.conf")).unwrap();
    assert!(baseline.contains("tag_group=\ntag_node=\n"));
    let _ = fs::remove_dir_all(home);
}

#[test]
fn non_tag_transport_never_writes_node_pin() {
    // A non-TAG client exposes no control API: without observed tag transport
    // the pin lines must stay absent regardless of the requested CLI mode.
    let (home, store) = store();
    let zones: ZoneCatalog = serde_json::from_value(json!({"JP":["Asia/Tokyo"]})).unwrap();
    let mut f = fake();
    f.local["mode"] = json!("clashx");
    f.local["tag"] = json!(null);
    let c = onboarding::detect(&store, &f, "clashx", true, &zones).unwrap();
    assert!(c["values"]["runtime_mode"].is_null());
    let options = json!({"apply_environment":false,"enable_policy":true,"guard_enabled":true,"timezone_watchdog":false,"auto_update":false});
    let p = onboarding::preview(&store, &f, c["id"].as_str().unwrap(), &options, None).unwrap();
    onboarding::apply(
        &store,
        &mut f,
        c["id"].as_str().unwrap(),
        &options,
        p["id"].as_str().unwrap(),
        None,
    )
    .unwrap();
    let baseline = fs::read_to_string(store.paths.watch().join("state/baseline.conf")).unwrap();
    assert!(!baseline.contains("tag_group="));
    assert!(!baseline.contains("tag_node="));
    let _ = fs::remove_dir_all(home);
}

#[test]
fn tag_apply_commits_all_three_files_and_only_tag_baseline_fields() {
    let (home, store) = store();
    let zones: ZoneCatalog = serde_json::from_value(json!({"JP":["Asia/Tokyo"]})).unwrap();
    let mut f = fake();
    let c = onboarding::detect(&store, &f, "tag", true, &zones).unwrap();
    let options = json!({"apply_environment":false,"enable_policy":true,"guard_enabled":true,"timezone_watchdog":false,"auto_update":false});
    let p = onboarding::preview(&store, &f, c["id"].as_str().unwrap(), &options, None).unwrap();
    onboarding::apply(
        &store,
        &mut f,
        c["id"].as_str().unwrap(),
        &options,
        p["id"].as_str().unwrap(),
        None,
    )
    .unwrap();
    let baseline = fs::read_to_string(store.paths.watch().join("state/baseline.conf")).unwrap();
    assert!(baseline.contains("tag_group=\ntag_node=\n"));
    assert!(store.paths.config().is_file());
    assert!(store
        .paths
        .base()
        .join("confirmed-environment.json")
        .is_file());
    assert!(!store.paths.base().join("setup-transaction.json").exists());
    let _ = fs::remove_dir_all(home);
}

#[test]
fn injected_action_failure_rolls_back_only_its_fresh_journal() {
    let (home, store) = store();
    let zones: ZoneCatalog = serde_json::from_value(json!({"JP":["Asia/Tokyo"]})).unwrap();
    let mut f = fake();
    f.fail_action = Some("language".into());
    let c = onboarding::detect(&store, &f, "tag", true, &zones).unwrap();
    let options = json!({"apply_environment":true,"enable_policy":true,"guard_enabled":true,"timezone_watchdog":false,"auto_update":false});
    let p = onboarding::preview(&store, &f, c["id"].as_str().unwrap(), &options, None).unwrap();
    let error = onboarding::apply(
        &store,
        &mut f,
        c["id"].as_str().unwrap(),
        &options,
        p["id"].as_str().unwrap(),
        None,
    )
    .unwrap_err();
    assert_eq!(error.code, "setup_rolled_back");
    assert!(!store.paths.base().join("setup-transaction.json").exists());
    assert_eq!(f.local["timezone"], "America/New_York");
    let _ = fs::remove_dir_all(home);
}

#[test]
fn network_change_during_baseline_read_rolls_back_without_writing_files() {
    let (home, store) = store();
    let zones: ZoneCatalog = serde_json::from_value(json!({"JP":["Asia/Tokyo"]})).unwrap();
    let mut f = fake();
    f.network_after_baseline = Some(json!({"service":"Ethernet","interface":"en7"}));
    let c = onboarding::detect(&store, &f, "tag", true, &zones).unwrap();
    let options = json!({"apply_environment":false,"enable_policy":true,"guard_enabled":true,"timezone_watchdog":false,"auto_update":false});
    let p = onboarding::preview(&store, &f, c["id"].as_str().unwrap(), &options, None).unwrap();
    let error = onboarding::apply(
        &store,
        &mut f,
        c["id"].as_str().unwrap(),
        &options,
        p["id"].as_str().unwrap(),
        None,
    )
    .unwrap_err();
    assert_eq!(error.code, "setup_rolled_back");
    assert!(!store.paths.config().exists());
    assert!(!store.paths.watch().join("state/baseline.conf").exists());
    assert!(!store
        .paths
        .base()
        .join("confirmed-environment.json")
        .exists());
    let _ = fs::remove_dir_all(home);
}
#[test]
fn repair_rejects_stale_preview_before_fake_apply() {
    let cfg = Config::default();
    let local = json!({"mode":"tag","timezone":"Asia/Tokyo","locale":"en_US","language":"en-US","ipv6":"ok"});
    let plan = repair::make_plan(&cfg, &local, None).unwrap();
    assert!(!plan["id"].as_str().unwrap().is_empty());
}

#[test]
fn recovery_preserves_a_journal_when_adapter_cannot_prove_restore() {
    let (home, store) = store();
    let config = Config::default().value().unwrap();
    let files = json!({"config":{"before":null,"after":null},"baseline":{"before":null,"after":null},"confirmation":{"before":null,"after":null}});
    store
        .atomic_json(
            &store.paths.base().join("setup-transaction.json"),
            &json!({"schema":1,"desired_config":config,"files":files,"actions":[{"action":{"id":"timezone","before":"America/New_York","after":"Asia/Tokyo"},"state":"applied"}]}),
        )
        .unwrap();
    let mut system = fake();
    system.restore_ok = false;
    let result = onboarding::recover(&store, &mut system).unwrap();
    assert_eq!(result["status"], "partial");
    assert!(store.paths.base().join("setup-transaction.json").exists());
    let _ = fs::remove_dir_all(home);
}

#[test]
fn old_setup_journal_without_managed_file_records_is_rejected_unchanged() {
    let (home, store) = store();
    let path = store.paths.base().join("setup-transaction.json");
    let old = json!({"schema":1,"desired_config":Config::default().value().unwrap(),"actions":[]});
    store.atomic_json(&path, &old).unwrap();
    assert_eq!(
        onboarding::recover(&store, &mut fake()).unwrap_err().code,
        "invalid_transaction"
    );
    assert_eq!(store.read_json(&path, Value::Null).unwrap(), old);
    let _ = fs::remove_dir_all(home);
}

#[test]
fn complete_setup_recovery_restores_all_three_files_but_preserves_external_change() {
    let (home, store) = store();
    let config = Config::default().value().unwrap();
    let paths = [
        (
            "config",
            store.paths.config(),
            "old-config\n",
            "new-config\n",
        ),
        (
            "baseline",
            store.paths.watch().join("state/baseline.conf"),
            "old-base\n",
            "new-base\n",
        ),
        (
            "confirmation",
            store.paths.base().join("confirmed-environment.json"),
            "old-confirm\n",
            "new-confirm\n",
        ),
    ];
    for (_, path, _, after) in &paths {
        store.atomic_bytes(path, after.as_bytes(), 0o600).unwrap();
    }
    let files = json!({"config":{"before":"old-config\n","after":"new-config\n"},"baseline":{"before":"old-base\n","after":"new-base\n"},"confirmation":{"before":"old-confirm\n","after":"new-confirm\n"}});
    store
        .atomic_json(
            &store.paths.base().join("setup-transaction.json"),
            &json!({"schema":1,"desired_config":config,"files":files,"actions":[]}),
        )
        .unwrap();
    assert_eq!(
        onboarding::recover(&store, &mut fake()).unwrap()["status"],
        "ok"
    );
    for (_, path, before, _) in &paths {
        assert_eq!(std::fs::read_to_string(path).unwrap(), *before);
    }
    let _ = fs::remove_dir_all(home);
}
