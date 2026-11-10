//! Migration is read-only until explicitly saved. Retired or missing backend
//! metadata must never enable a replacement execution path.
use claude_watch_core::{channel::NetworkBackendKind, vpn::VpnExpectation};
use claude_watch_runtime::{config_store::ConfigStore, storage::{Paths, StateStore}};
use serde_json::json;
use std::{fs, path::PathBuf};

struct Fixture { root: PathBuf, config: ConfigStore }
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("cw-backend-retirement-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let storage = StateStore::new(Paths::new(&root).unwrap());
        Self { root, config: ConfigStore { storage } }
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); } }

#[test]
fn missing_or_retired_package_metadata_blocks_without_selecting_ne_or_writing_config() {
    let fixture = Fixture::new();
    for (packaged, reason) in [(None, "packaged_network_backend_missing"),
        (Some(NetworkBackendKind::NetworkExtension), "legacy_network_backend_removed")] {
        let resolved = fixture.config.resolve_runtime_config_state(packaged);
        assert_eq!(resolved.config.schema, 2);
        assert_eq!(resolved.config.effective_network_backend(), NetworkBackendKind::Seatbelt);
        assert_eq!(resolved.blocking_reason().as_deref(), Some(reason));
        assert_eq!(fixture.config.resolve_runtime_config(packaged).unwrap_err().code, reason);
        assert!(!fixture.config.storage.paths.config().exists());
    }
    let resolved = fixture.config.resolve_runtime_config_state(Some(NetworkBackendKind::Seatbelt));
    assert!(resolved.blocking_reason().is_none());
    assert_eq!(resolved.config.network_backend, Some(NetworkBackendKind::Seatbelt));
}

#[test]
fn legacy_documents_require_explicit_migration_preserve_settings_and_reject_ne_reenablement() {
    for legacy in [json!({"schema":1}), json!({"schema":1,"network_backend":"ne"}),
        json!({"schema":2,"network_backend":"network_extension"})] {
        let fixture = Fixture::new();
        let mut raw = legacy;
        raw["proxy_mode"] = json!("tag");
        raw["proxy_url"] = json!("http://127.0.0.1:7890");
        raw["country"] = json!("JP");
        raw["guard_enabled"] = json!(true);
        fixture.config.storage.atomic_json(&fixture.config.storage.paths.config(), &raw).unwrap();
        let bytes = fs::read(fixture.config.storage.paths.config()).unwrap();
        let resolved = fixture.config.resolve_runtime_config_state(Some(NetworkBackendKind::Seatbelt));
        assert!(resolved.legacy_migration_required);
        assert!(resolved.config.vpn_is_read_only());
        assert_eq!(resolved.blocking_reason().as_deref(), Some("legacy_config_migration_required"));
        assert_eq!(fs::read(fixture.config.storage.paths.config()).unwrap(), bytes);
        assert_eq!(fixture.config.save_network_backend(NetworkBackendKind::NetworkExtension).unwrap_err().code,
            "legacy_network_backend_removed");
        assert_eq!(fs::read(fixture.config.storage.paths.config()).unwrap(), bytes);
        let migrated = fixture.config.save_network_backend(NetworkBackendKind::Seatbelt).unwrap();
        assert_eq!(migrated.schema, 2);
        assert_eq!(migrated.proxy_url, "http://127.0.0.1:7890");
        assert_eq!(migrated.country, "JP");
        assert!(migrated.guard_enabled);
        assert!(migrated.vpn_expectation.is_none(), "migration cannot invent a VPN expectation");
        assert!(!migrated.requires_backend_migration_setup());
        assert!(fixture.config.resolve_runtime_config_state(Some(NetworkBackendKind::Seatbelt)).blocking_reason().is_none());
    }
}

#[test]
fn confirmed_vpn_save_migrates_legacy_backend_but_invalid_config_stays_blocked() {
    let fixture = Fixture::new();
    fixture.config.storage.atomic_json(&fixture.config.storage.paths.config(),
        &json!({"schema":1,"network_backend":"ne","proxy_url":"http://127.0.0.1:7890","country":"JP"})).unwrap();
    let expectation = VpnExpectation {
        proxy_mode: "tag".into(), proxy_url: "http://127.0.0.1:7890".into(),
        running_mode: Some("rule".into()), ..VpnExpectation::default()
    };
    assert_eq!(fixture.config.save_vpn_expectation(expectation.clone(), false).unwrap_err().code,
        "vpn_expectation_unconfirmed");
    let migrated = fixture.config.save_vpn_expectation(expectation, true).unwrap();
    assert_eq!(migrated.network_backend, Some(NetworkBackendKind::Seatbelt));
    assert!(migrated.vpn_expectation.unwrap().configured);
    assert_eq!(migrated.country, "JP");
    for invalid in [json!({"schema":2,"network_backend":"unknown"}), json!({"schema":99})] {
        fixture.config.storage.atomic_json(&fixture.config.storage.paths.config(), &invalid).unwrap();
        let bytes = fs::read(fixture.config.storage.paths.config()).unwrap();
        let state = fixture.config.resolve_runtime_config_state(Some(NetworkBackendKind::Seatbelt));
        assert!(state.config_error.is_some());
        assert!(state.blocking_reason().unwrap().starts_with("config_invalid:"));
        assert!(fixture.config.save_network_backend(NetworkBackendKind::Seatbelt).is_err());
        assert_eq!(fs::read(fixture.config.storage.paths.config()).unwrap(), bytes);
    }
}
