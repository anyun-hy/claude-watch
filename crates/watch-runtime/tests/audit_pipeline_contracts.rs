use claude_watch_core::{config::Config, error::Result, region::ZoneCatalog};
use claude_watch_runtime::{
    audit_store::{audit_matches_policy, AuditOptions, AuditScope, AuditStore, AuditSystem},
    receipt_store::ReceiptStore,
    session_store::SessionStore,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::fs;

/// The background baseline collector and `status` must agree on when a stored
/// audit is current. A fresh install has no file at all; a policy change
/// leaves the previous digest behind. Both cases have to read as "collect a
/// new baseline", otherwise the first screen keeps reporting "未取得".
#[test]
fn baseline_audit_is_required_unless_the_stored_policy_matches() {
    let policy = "sha256:current";
    assert!(!audit_matches_policy(&Value::Null, policy));
    assert!(!audit_matches_policy(&json!({"rows": []}), policy));
    assert!(!audit_matches_policy(
        &json!({"policy": "sha256:previous", "rows": []}),
        policy
    ));
    assert!(audit_matches_policy(
        &json!({"policy": policy, "rows": []}),
        policy
    ));
}
struct Fake {
    now: f64,
}

struct ScopedFake {
    dns_refreshes: usize,
    fail_refresh: bool,
}
impl AuditSystem for ScopedFake {
    fn now(&self) -> f64 {
        1700000000.
    }
    fn network(&self) -> Result<Value> {
        Fake { now: self.now() }.network()
    }
    fn local(&self, config: &Config) -> Result<Value> {
        let mut local = Fake { now: self.now() }.local(config)?;
        // An unrelated full-audit blocker must not contaminate a scope view.
        local["guard"] = json!(false);
        local["guard_state"] = json!("fail");
        Ok(local)
    }
    fn online(&mut self, _: &Config, _: &Value) -> Result<Value> {
        panic!("scope must not run full online/ASN/STUN/service collection")
    }
    fn refresh_dns(&mut self) -> Result<Option<Value>> {
        self.dns_refreshes += 1;
        if self.fail_refresh {
            return Err(claude_watch_core::error::CoreError::new(
                "dns_bridge_unavailable",
                "图形DNS刷新未响应",
            ));
        }
        Ok(None)
    }
    fn refresh_webrtc(&mut self) -> Result<Option<Value>> {
        panic!("scope must not refresh WebRTC")
    }
}
#[test]
fn scoped_commands_share_policy_and_receipts_without_full_probes_or_audit_writes() {
    let root = std::env::temp_dir().join(format!("audit-scopes-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let storage = StateStore::new(Paths::new(&root).unwrap());
    let store = AuditStore::new(storage.clone());
    let mut system = ScopedFake {
        dns_refreshes: 0,
        fail_refresh: false,
    };
    let zones = ZoneCatalog::new();
    let options = AuditOptions {
        online: true,
        persist: true,
        launch: false,
    };
    let proxy = store
        .collect_scope(&mut system, &zones, AuditScope::Proxy, options)
        .unwrap();
    assert_eq!(proxy["state"], "ok");
    assert_eq!(proxy["rows"].as_array().unwrap().len(), 3);
    assert_eq!(system.dns_refreshes, 0);
    assert!(!storage.paths.home.join("Library").exists());
    assert!(proxy.get("ready").is_none());
    assert_eq!(proxy["grants_launch_permission"], false);
    let missing = store
        .collect_scope(
            &mut system,
            &zones,
            AuditScope::Dns,
            AuditOptions {
                online: false,
                ..options
            },
        )
        .unwrap();
    assert_eq!(missing["state"], "unknown");
    assert_eq!(system.dns_refreshes, 0);
    storage.atomic_json(&storage.paths.base().join("dns-leak-receipt.json"),&json!({"schema":1,"status":"complete","finished_at":1700000000.,"recorded_at":1700000000.,"launch_expires_at":1700000030.,"display_expires_at":1700000300.,"context":"ctx","comparison":{"state":"ok"},"errors":[],"dns":{"egress_ips":["8.8.8.8"],"countries":["JP"]},"http":{"egress_ips":["1.1.1.1"],"countries":["JP"]}})).unwrap();
    let dns = store
        .collect_scope(&mut system, &zones, AuditScope::Dns, options)
        .unwrap();
    assert_eq!(dns["state"], "ok");
    assert_eq!(system.dns_refreshes, 1);
    assert_eq!(dns["rows"].as_array().unwrap().len(), 1);
    assert!(dns.get("ready").is_none());
    assert_eq!(
        dns["evidence"]["dns"]["receipt"]["finished_at"],
        1700000000.
    );
    system.fail_refresh = true;
    let failed_refresh = store
        .collect_scope(&mut system, &zones, AuditScope::Dns, options)
        .unwrap();
    assert_eq!(
        failed_refresh["evidence"]["dns_refresh"]["error"]["code"],
        "dns_bridge_unavailable"
    );
    assert_eq!(
        failed_refresh["evidence"]["dns"]["receipt"]["finished_at"],
        1700000000.
    );
    let path = storage.paths.base().join("dns-leak-receipt.json");
    let mut mismatch = storage.read_json(&path, Value::Null).unwrap();
    mismatch["comparison"] = json!({"state":"fail","reason":"country_mismatch"});
    mismatch["dns"]["countries"] = json!(["CN"]);
    storage.atomic_json(&path, &mismatch).unwrap();
    let risk = store
        .collect_scope(
            &mut system,
            &zones,
            AuditScope::Dns,
            AuditOptions {
                online: false,
                ..options
            },
        )
        .unwrap();
    assert_eq!(risk["state"], "fail");
    assert_eq!(risk["rows"][0]["state"], "fail");
    assert!(!storage.paths.base().join("last-audit.json").exists());
    assert!(!storage
        .paths
        .base()
        .join("last-environment-detection.json")
        .exists());
    assert!(!storage.paths.base().join("ip-history.json").exists());
    assert!(!storage.paths.session().exists());
    assert_eq!(
        store
            .collect_scope(
                &mut system,
                &zones,
                AuditScope::Dns,
                AuditOptions {
                    launch: true,
                    ..options
                }
            )
            .unwrap_err()
            .code,
        "invalid_audit_scope"
    );
    fs::remove_dir_all(root).unwrap();
}
impl AuditSystem for Fake {
    fn now(&self) -> f64 {
        self.now
    }
    fn network(&self) -> Result<Value> {
        Ok(json!({"service":"Wi-Fi","interface":"en0"}))
    }
    fn local(&self, _: &Config) -> Result<Value> {
        Ok(
            json!({"proxy":"ok","tun":"ok","mode":"tag","context":"ctx","context_id":"ctx","network_identity":{"entry":"127.0.0.1:7890"},"timezone":"Asia/Tokyo","locale":"ja_JP","ipv6":"ok","language":"en-US","backend_healthy":true,"backend_native":true,"guard":true,"guard_state":"ok","rules":{"state":"ok","detail":"ok"},"date_format":{"state":"available","configured_locale":"ja_JP","patterns":{"short":"y/MM/dd","medium":"y/MM/dd","long":"y年M月d日"},"reference_patterns":{"ja_JP":{"short":"y/MM/dd","medium":"y/MM/dd","long":"y年M月d日"}},"short_sample":"2023/11/14","reference_samples":{"ja_JP":"2023/11/14"}}}),
        )
    }
    fn online(&mut self, _: &Config, _: &Value) -> Result<Value> {
        Ok(
            json!({"trace":{"ip":"1.1.1.1","loc":"JP"},"geo":{"ip":"1.1.1.1","country":"JP","timezone":"Asia/Tokyo"},"stun":{"complete":true,"observations":[{"status":"ok","address":"1.1.1.1"}]},"claude":403,"api":401,"service_responses":{"claude":{"status":"ok","transport_reached":true,"http_status":403,"access":"challenge","source":"https://claude.ai/","challenge":{"provider":"cloudflare","mitigated":"challenge"}},"api":{"status":"ok","transport_reached":true,"http_status":401,"access":"authentication_required","source":"https://api.anthropic.com/v1/models"}},"asn":{},"dns":{},"webrtc":{}}),
        )
    }
}
#[test]
fn environment_guard_diagnostics_do_not_change_audit_or_write_on_readonly_rounds() {
    use claude_watch_core::processes::LaunchTarget;
    let root =
        std::env::temp_dir().join(format!("audit-guard-diagnostics-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let storage = StateStore::new(Paths::new(&root).unwrap());
    let audit = AuditStore::new(storage.clone());
    let options = AuditOptions {
        online: false,
        persist: false,
        launch: false,
    };
    let zones = ZoneCatalog::new();
    let mut original = audit
        .collect_target(
            &mut Fake {
                now: 1_700_000_000.0,
            },
            &zones,
            LaunchTarget::ClaudeDesktop,
            options,
        )
        .unwrap();
    let (mut observed, trace) = audit
        .collect_environment(
            &mut Fake {
                now: 1_700_000_000.0,
            },
            &zones,
            LaunchTarget::ClaudeDesktop,
            options,
        )
        .unwrap();
    let trace = trace.unwrap();
    assert_eq!(
        trace.observation_id,
        observed["observation_id"].as_str().unwrap()
    );
    assert_eq!(trace.before.decision, "ok");
    assert_eq!(trace.after.decision, "ok");
    assert_eq!(trace.before.guard_heartbeat_status, "missing");
    assert!(observed.get("guard_diagnostics").is_none());
    original.as_object_mut().unwrap().remove("observation_id");
    observed.as_object_mut().unwrap().remove("observation_id");
    assert_eq!(
        original, observed,
        "diagnostic capture must not alter the audit result"
    );
    assert!(!root.join("Library").exists());
    assert_eq!(
        audit
            .collect_environment(
                &mut Fake {
                    now: 1_700_000_000.0
                },
                &zones,
                LaunchTarget::ClaudeDesktop,
                AuditOptions {
                    launch: true,
                    ..options
                }
            )
            .unwrap_err()
            .code,
        "invalid_audit_scope"
    );
    fs::remove_dir_all(root).unwrap();
}

struct GuardFlip {
    calls: std::cell::Cell<usize>,
}
impl AuditSystem for GuardFlip {
    fn now(&self) -> f64 {
        1_700_000_000.0
    }
    fn network(&self) -> Result<Value> {
        Fake { now: self.now() }.network()
    }
    fn local(&self, config: &Config) -> Result<Value> {
        let mut value = Fake { now: self.now() }.local(config)?;
        let call = self.calls.get();
        self.calls.set(call + 1);
        if call > 0 {
            value["guard"] = json!(false);
            value["guard_state"] = json!("unknown");
            value["backend_healthy"] = json!(false);
            value["backend_native"] = json!(false);
            value["backend_detail"] = json!("心跳未报告有效采样");
        } else {
            value["backend_detail"] = json!("原生采集后台身份与心跳已核对");
        }
        Ok(value)
    }
    fn online(&mut self, _: &Config, _: &Value) -> Result<Value> {
        panic!("offline guard diagnostic test must not probe")
    }
}

#[test]
fn guard_round_records_both_decisions_without_changing_a_fluctuating_audit() {
    use claude_watch_core::processes::LaunchTarget;
    let root = std::env::temp_dir().join(format!("audit-guard-flip-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let storage = StateStore::new(Paths::new(&root).unwrap());
    let audit = AuditStore::new(storage);
    let options = AuditOptions {
        online: false,
        persist: false,
        launch: false,
    };
    let mut original = audit
        .collect_target(
            &mut GuardFlip {
                calls: std::cell::Cell::new(0),
            },
            &ZoneCatalog::new(),
            LaunchTarget::ClaudeDesktop,
            options,
        )
        .unwrap();
    let (mut observed, trace) = audit
        .collect_environment(
            &mut GuardFlip {
                calls: std::cell::Cell::new(0),
            },
            &ZoneCatalog::new(),
            LaunchTarget::ClaudeDesktop,
            options,
        )
        .unwrap();
    let trace = trace.unwrap();
    assert_eq!(trace.before.decision, "ok");
    assert_eq!(trace.after.decision, "unknown");
    assert_eq!(trace.after.backend_reason, "sample_not_ok");
    assert_eq!(
        observed["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == "guard")
            .unwrap()["state"],
        "unknown"
    );
    original.as_object_mut().unwrap().remove("observation_id");
    observed.as_object_mut().unwrap().remove("observation_id");
    assert_eq!(original, observed);
    assert!(!serde_json::to_string(&trace).unwrap().contains("127.0.0.1"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unreadable_diagnostic_heartbeat_never_changes_environment_audit() {
    use claude_watch_core::processes::LaunchTarget;
    use std::os::unix::fs::symlink;
    let root =
        std::env::temp_dir().join(format!("audit-guard-unreadable-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let storage = StateStore::new(Paths::new(&root).unwrap());
    fs::create_dir_all(storage.paths.base()).unwrap();
    symlink(
        "missing-fixture",
        storage.paths.base().join("guard-heartbeat.json"),
    )
    .unwrap();
    let audit = AuditStore::new(storage);
    let options = AuditOptions {
        online: false,
        persist: false,
        launch: false,
    };
    let mut original = audit
        .collect_target(
            &mut Fake {
                now: 1_700_000_000.0,
            },
            &ZoneCatalog::new(),
            LaunchTarget::ClaudeDesktop,
            options,
        )
        .unwrap();
    let (mut observed, trace) = audit
        .collect_environment(
            &mut Fake {
                now: 1_700_000_000.0,
            },
            &ZoneCatalog::new(),
            LaunchTarget::ClaudeDesktop,
            options,
        )
        .unwrap();
    assert_eq!(trace.unwrap().before.guard_heartbeat_status, "unreadable");
    original.as_object_mut().unwrap().remove("observation_id");
    observed.as_object_mut().unwrap().remove("observation_id");
    assert_eq!(original, observed);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn persisted_audit_has_context_and_observation_identity() {
    let root = std::env::temp_dir().join(format!("audit-pipeline-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let storage = StateStore::new(Paths::new(&root).unwrap());
    storage.atomic_json(&storage.paths.base().join("dns-leak-receipt.json"),&json!({"schema":1,"status":"complete","finished_at":1_700_000_000.,"recorded_at":1_700_000_000.,"launch_expires_at":1_700_000_030.,"display_expires_at":1_700_000_300.,"context":"ctx","comparison":{"state":"ok"},"errors":[],"dns":{"egress_ips":["1.1.1.1"],"countries":["JP"]},"http":{"egress_ips":["1.1.1.1"],"countries":["JP"]}})).unwrap();
    storage.atomic_json(&storage.paths.base().join("webrtc-risk-receipt.json"),&json!({"schema":1,"status":"complete","sampled_at":1_700_000_000.,"recorded_at":1_700_000_000.,"context_id":"ctx","risk":{"state":"ok","detail":"same"},"observations":[{"kind":"http","address":"1.1.1.1","country":"JP"},{"kind":"srflx","address":"1.1.1.1","country":"JP"}]})).unwrap();
    let out = AuditStore::new(storage.clone())
        .collect(
            &mut Fake { now: 1700000000. },
            &serde_json::from_value::<ZoneCatalog>(json!({"JP":["Asia/Tokyo"]})).unwrap(),
            false,
        )
        .unwrap();
    assert_eq!(out["context_id"], "ctx");
    assert!(out["observation_id"].as_str().is_some());
    assert_eq!(
        storage
            .read_json(&storage.paths.base().join("last-audit.json"), Value::Null)
            .unwrap()["observation_id"],
        out["observation_id"]
    );
    assert!(out["ready"].as_bool().unwrap());
    let session = SessionStore::new(storage.clone())
        .begin_verified(
            &ReceiptStore {
                storage: storage.clone(),
            },
            &out,
            &json!({"ip":"1.1.1.1","country":"JP","observed_at":1_700_000_000.}),
            1_700_000_000.,
        )
        .unwrap_or_else(|error| panic!("{error:?}: {out}"));
    assert_eq!(session.context_id, "ctx");
    fs::remove_dir_all(root).unwrap();
}

struct Changing {
    network_calls: std::cell::Cell<usize>,
    local_calls: std::cell::Cell<usize>,
    after_network: Value,
    unavailable: bool,
    changed_identity: bool,
}
impl AuditSystem for Changing {
    fn now(&self) -> f64 {
        1700000000.
    }
    fn network(&self) -> Result<Value> {
        let index = self.network_calls.get();
        self.network_calls.set(index + 1);
        Ok(if index == 0 {
            json!({"service":"Wi-Fi","interface":"en0"})
        } else {
            self.after_network.clone()
        })
    }
    fn local(&self, config: &Config) -> Result<Value> {
        let index = self.local_calls.get();
        self.local_calls.set(index + 1);
        let mut value = Fake { now: self.now() }.local(config)?;
        if index > 0 && (self.unavailable || self.changed_identity) {
            value["context_id"] = json!("second-context");
            value["context"] = json!("second-context");
            value["network_identity"] =
                json!({"entry":if self.unavailable{Value::Null}else{json!("127.0.0.1:7891")}});
            if self.unavailable {
                value["observation_unavailable"] = json!(["tag_snapshot"]);
                value["proxy"] = json!("unknown");
            }
        }
        Ok(value)
    }
    fn online(&mut self, c: &Config, l: &Value) -> Result<Value> {
        Fake { now: self.now() }.online(c, l)
    }
}
#[test]
fn failed_samples_do_not_become_network_changes_but_positive_changes_still_block() {
    let root = std::env::temp_dir().join(format!("audit-transition-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let store = StateStore::new(Paths::new(&root).unwrap());
    let zones = serde_json::from_value::<ZoneCatalog>(json!({"JP":["Asia/Tokyo"]})).unwrap();
    for (network, unavailable, identity, expected) in [
        (
            json!({"service":"Wi-Fi","interface":"en0"}),
            true,
            false,
            "sampling_unavailable",
        ),
        (
            json!({"service":null,"interface":"en0"}),
            false,
            false,
            "sampling_unavailable",
        ),
        (
            json!({"interface":"en0"}),
            false,
            false,
            "sampling_unavailable",
        ),
        (
            json!({"service":"Wi-Fi","interface":"en1"}),
            true,
            false,
            "changed",
        ),
        (
            json!({"service":"Wi-Fi","interface":"en0"}),
            false,
            true,
            "changed",
        ),
    ] {
        let mut system = Changing {
            network_calls: 0.into(),
            local_calls: 0.into(),
            after_network: network,
            unavailable,
            changed_identity: identity,
        };
        let result = AuditStore::new(store.clone())
            .collect_options(
                &mut system,
                &zones,
                claude_watch_runtime::audit_store::AuditOptions {
                    online: false,
                    persist: false,
                    launch: false,
                },
            )
            .unwrap();
        assert_eq!(result["context_transition"]["state"], expected, "{result}");
        assert_eq!(result["ready"], false);
    }
    assert!(!store.paths.base().join("last-audit.json").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn target_specific_audits_cannot_overwrite_the_claude_page_receipts() {
    use claude_watch_core::processes::LaunchTarget;
    let root = std::env::temp_dir().join(format!("audit-target-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let storage = StateStore::new(Paths::new(&root).unwrap());
    let saved = br#"{"observed_at":100,"purpose":"existing Claude receipt"}"#;
    for name in ["last-audit.json", "last-environment-detection.json"] {
        storage
            .atomic_bytes(&storage.paths.base().join(name), saved, 0o600)
            .unwrap();
    }
    let audit = AuditStore::new(storage.clone());
    let mut system = Fake { now: 1700000000. };
    let zones = serde_json::from_value::<ZoneCatalog>(json!({"JP":["Asia/Tokyo"]})).unwrap();
    for target in [LaunchTarget::CodexDesktop, LaunchTarget::ChatgptDesktop] {
        let value = audit
            .collect_target(
                &mut system,
                &zones,
                target,
                AuditOptions {
                    online: true,
                    persist: true,
                    launch: true,
                },
            )
            .unwrap();
        assert_eq!(value["launch_target"], target.as_str());
        for name in ["last-audit.json", "last-environment-detection.json"] {
            assert_eq!(fs::read(storage.paths.base().join(name)).unwrap(), saved);
        }
        assert!(!storage.paths.session().exists());
        assert!(!storage.paths.base().join("ip-history.json").exists());
    }
    fs::remove_dir_all(root).unwrap();
}

struct ChangingCli {
    reads: std::cell::Cell<usize>,
}
impl AuditSystem for ChangingCli {
    fn now(&self) -> f64 {
        1700000000.
    }
    fn network(&self) -> Result<Value> {
        Fake { now: self.now() }.network()
    }
    fn local(&self, c: &Config) -> Result<Value> {
        Fake { now: self.now() }.local(c)
    }
    fn local_for_target(
        &self,
        c: &Config,
        _: claude_watch_core::processes::LaunchTarget,
    ) -> Result<Value> {
        let mut value = self.local(c)?;
        let n = self.reads.get();
        self.reads.set(n + 1);
        value["backend_healthy"] = json!(true);
        value["backend_native"] = json!(true);
        value["cli_proxy"] = if n == 0 {
            json!({"state":"ok","detail":"verified"})
        } else {
            json!({"state":"fail","detail":"override changed"})
        };
        Ok(value)
    }
    fn online(&mut self, c: &Config, l: &Value) -> Result<Value> {
        Fake { now: self.now() }.online(c, l)
    }
}
#[test]
fn cli_setting_change_is_local_to_cli_requirement_and_never_becomes_an_ip_mismatch() {
    let root = std::env::temp_dir().join(format!("cli-change-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let storage = StateStore::new(Paths::new(&root).unwrap());
    let result = AuditStore::new(storage)
        .collect_target(
            &mut ChangingCli {
                reads: std::cell::Cell::new(0),
            },
            &serde_json::from_value(json!({"JP":["Asia/Tokyo"]})).unwrap(),
            claude_watch_core::processes::LaunchTarget::ClaudeCli,
            AuditOptions {
                online: true,
                persist: false,
                launch: false,
            },
        )
        .unwrap();
    let rows = result["rows"].as_array().unwrap();
    assert_eq!(
        rows.iter().find(|r| r["id"] == "cli_proxy").unwrap()["state"],
        "unknown"
    );
    assert_eq!(
        rows.iter().find(|r| r["id"] == "egress").unwrap()["state"],
        "ok"
    );
    assert_eq!(
        rows.iter().find(|r| r["id"] == "proxy").unwrap()["state"],
        "ok"
    );
    assert_eq!(result["ready"], false);
    fs::remove_dir_all(root).unwrap();
}
