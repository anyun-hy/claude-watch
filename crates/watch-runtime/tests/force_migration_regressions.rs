//! File-only OpenAI Force migration tests. No process control, app launches
//! or installed configuration changes. Each test owns a private temp home.
use claude_watch_core::{config::Config, processes::Provider};
use claude_watch_runtime::{
    config_store::ConfigStore,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
    store: ConfigStore,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("cw-force-migration-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let store = ConfigStore {
            storage: StateStore::new(Paths::new(&root).unwrap()),
        };
        store.storage.initialize().unwrap();
        Self { root, store }
    }
    fn disk(&self) -> Value {
        self.store.storage.read_json(&self.store.storage.paths.config(), json!({})).unwrap()
    }
    fn write(&self, value: Value) {
        self.store.storage.atomic_json(&self.store.storage.paths.config(), &value).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); }
}
fn action(config: &Config, reason: &str) -> String {
    config.close_action(reason, Provider::Codex)
}

#[test]
fn old_force_strings_are_non_terminating_as_force_and_read_only_load_preserves_disk() {
    let f = Fixture::new();
    let legacy = json!({"schema":1,"gpt_close_ip":"force","gpt_close_cn":"force","guard_enabled":true});
    f.write(legacy.clone());
    let loaded = f.store.load().unwrap();
    assert_eq!(f.store.legacy_force_pending().unwrap(),
        vec!["gpt_close_ip".to_string(), "gpt_close_cn".to_string()]);
    assert_eq!(loaded.action("openai", "ip"), "close");
    assert_eq!(loaded.action("openai", "cn"), "close");
    assert_eq!(action(&loaded, "egress_ip_changed"), "close");
    assert_eq!(action(&loaded, "egress_country_cn"), "close");
    assert_eq!(f.disk(), legacy, "read-only guard loading cannot rewrite user state");
}

#[test]
fn unrelated_save_downgrades_legacy_force_without_creating_a_grant() {
    let f = Fixture::new();
    let mut legacy = json!({"schema":1,"gpt_close_ip":"force","gpt_close_cn":"force"});
    f.write(legacy.clone());
    legacy["auto_check_on_open"] = json!(false);
    let saved = f.store.save(legacy).unwrap();
    assert_eq!(saved.action("openai", "ip"), "close");
    assert_eq!(saved.action("openai", "cn"), "close");
    assert!(saved.gpt_force_approved_v1.is_empty());
    assert_eq!(f.disk()["gpt_close_ip"], "close");
    assert_eq!(f.disk()["gpt_close_cn"], "close");
    assert!(f.store.legacy_force_pending().unwrap().is_empty());
}

#[test]
fn new_force_without_per_key_confirmation_is_rejected_and_writes_nothing() {
    let f = Fixture::new();
    let before = f.disk();
    assert_eq!(
        f.store.save(json!({"gpt_close_ip":"force"})).unwrap_err().code,
        "force_confirmation_required"
    );
    assert_eq!(f.disk(), before);
}

#[test]
fn explicit_confirmation_commits_one_key_and_its_approval_atomically() {
    let f = Fixture::new();
    let confirmed = f.store.save_with_force_confirmation(
        json!({"gpt_close_ip":"force","gpt_close_cn":"close"}),
        Some("gpt_close_ip"),
    ).unwrap();
    assert_eq!(confirmed.gpt_force_approved_v1, ["gpt_close_ip"]);
    assert_eq!(action(&confirmed, "egress_ip_changed"), "force");
    assert_eq!(action(&confirmed, "egress_country_cn"), "close");
    assert_eq!(f.disk()["gpt_force_approved_v1"], json!(["gpt_close_ip"]));
    assert_eq!(action(&f.store.load().unwrap(), "egress_ip_changed"), "force");
    assert!(f.store.legacy_force_pending().unwrap().is_empty());
    assert_eq!(f.store.load().unwrap().close_action("egress_ip_changed", Provider::Claude), "force");
}

#[test]
fn multiple_keys_require_individual_confirmation_and_combined_probes_resolve_strictly() {
    let f = Fixture::new();
    let input = json!({"gpt_close_dns":"force","gpt_close_webrtc":"warn"});
    let confirmed = f.store.save_with_force_confirmation(input, Some("gpt_close_dns")).unwrap();
    assert_eq!(action(&confirmed, "dns_egress_changed"), "force");
    assert_eq!(action(&confirmed, "webrtc_egress_changed"), "warn");
    assert_eq!(action(&confirmed, "dns_and_webrtc_egress_changed"), "force");
    // A different new Force value cannot hitchhike on an unrelated consent.
    let before = f.disk();
    let mut proposed = confirmed.value().unwrap();
    proposed["gpt_close_webrtc"] = json!("force");
    assert_eq!(
        f.store.save_with_force_confirmation(proposed, Some("gpt_close_dns"))
            .unwrap_err().code,
        "force_confirmation_required"
    );
    assert_eq!(f.disk(), before);
}

#[test]
fn prior_approved_force_survives_unrelated_settings_save_without_renewed_consent() {
    let f = Fixture::new();
    let confirmed = f.store.save_with_force_confirmation(
        json!({"gpt_close_cn":"force"}), Some("gpt_close_cn")
    ).unwrap();
    let mut input = confirmed.value().unwrap();
    input["auto_update"] = json!(true);
    let saved = f.store.save(input).unwrap();
    assert_eq!(action(&saved, "egress_country_cn"), "force");
    assert_eq!(f.disk()["gpt_force_approved_v1"], json!(["gpt_close_cn"]));
}

#[test]
fn removing_force_revokes_only_its_key_and_readding_requires_new_consent() {
    let f = Fixture::new();
    let first = f.store.save_with_force_confirmation(
        json!({"gpt_close_ip":"force","gpt_close_cn":"force"}),
        Some("gpt_close_cn,gpt_close_ip"),
    ).unwrap();
    let mut input = first.value().unwrap();
    input["gpt_close_ip"] = json!("warn");
    let saved = f.store.save(input).unwrap();
    assert_eq!(saved.gpt_force_approved_v1, ["gpt_close_cn"]);
    assert_eq!(action(&saved, "egress_country_cn"), "force");
    assert_eq!(action(&saved, "egress_ip_changed"), "warn");
    let mut stale = saved.value().unwrap();
    stale["gpt_close_ip"] = json!("force");
    assert_eq!(f.store.save(stale).unwrap_err().code, "force_confirmation_required");
}

#[test]
fn forged_approval_marker_in_input_cannot_authorize_a_force() {
    let f = Fixture::new();
    let before = f.disk();
    let result = f.store.save(json!({
        "gpt_close_ip":"force","gpt_force_approved_v1":["gpt_close_ip"]
    }));
    assert_eq!(result.unwrap_err().code, "force_confirmation_invalid");
    assert_eq!(f.disk(), before);
}

#[test]
fn malformed_or_mismatched_confirmation_cannot_write_anything() {
    let f = Fixture::new();
    for (input, consent) in [
        (json!({"gpt_close_ip":"force"}), ""),
        (json!({"gpt_close_ip":"force"}), "gpt_close_ip,gpt_close_ip"),
        (json!({"gpt_close_ip":"warn"}), "gpt_close_ip"),
        (json!({"gpt_close_ip":"force"}), "claude_close_ip"),
        (json!({"gpt_close_ip":"force"}), "gpt_close_unknown"),
        (json!({"gpt_close_ip":"force"}), "gpt_close_ip,"),
    ] {
        assert_eq!(
            f.store.save_with_force_confirmation(input, Some(consent))
                .unwrap_err().code,
            "force_confirmation_invalid"
        );
        assert_eq!(f.disk(), json!({}));
    }
}

#[test]
fn invalid_stored_state_is_repairable_but_cannot_grant_force() {
    let f = Fixture::new();
    f.write(json!({"schema":999,"gpt_close_ip":"force"}));
    assert!(f.store.load().is_err());
    assert!(f.store.save_with_force_confirmation(
        json!({"gpt_close_ip":"force"}), Some("gpt_close_ip"),
    ).is_err());
    let fixed = f.store.save(json!({"gpt_close_ip":"warn"})).unwrap();
    assert_eq!(fixed.action("openai", "ip"), "warn");
    assert_eq!(f.store.load().unwrap().action("openai", "ip"), "warn");
}

#[test]
fn legacy_stale_force_cannot_gain_authority_through_another_keys_confirmation() {
    let f = Fixture::new();
    f.write(json!({"gpt_close_ip":"force"}));
    let saved = f.store.save_with_force_confirmation(
        json!({"gpt_close_ip":"force","gpt_close_cn":"force"}),
        Some("gpt_close_cn"),
    ).unwrap();
    assert_eq!(saved.action("openai", "ip"), "close");
    assert_eq!(saved.action("openai", "cn"), "force");
    assert_eq!(saved.gpt_force_approved_v1, ["gpt_close_cn"]);
}

#[test]
fn valid_grants_do_not_leak_to_other_families_or_unrelated_criteria() {
    let f = Fixture::new();
    let saved = f.store.save_with_force_confirmation(
        json!({"gpt_close_dns":"force","claude_close_dns":"warn"}),
        Some("gpt_close_dns"),
    ).unwrap();
    assert_eq!(saved.close_action("dns_egress_changed", Provider::Codex), "force");
    assert_eq!(saved.close_action("dns_egress_changed", Provider::Chatgpt), "force");
    assert_eq!(saved.close_action("dns_egress_changed", Provider::Claude), "warn");
    assert_eq!(saved.close_action("webrtc_egress_changed", Provider::Codex), "close");
}
