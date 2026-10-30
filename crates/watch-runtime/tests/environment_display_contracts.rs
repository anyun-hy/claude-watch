use claude_watch_runtime::{
    environment_display::receipt,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};
use uuid::Uuid;

const NOW: f64 = 1_700_000_000.0;

fn store() -> (PathBuf, StateStore) {
    let home = std::env::temp_dir().join(format!("cw-environment-display-{}", Uuid::new_v4()));
    fs::create_dir(&home).unwrap();
    let store = StateStore::new(Paths::new(&home).unwrap());
    (home, store)
}

fn row(id: &str, state: &str) -> Value {
    json!({"id":id,"state":state,"detail":format!("{id} detail"),"required":true})
}

fn audit() -> Value {
    json!({
        "observed_at": NOW,
        "expires_at": NOW + 17.0,
        "context_id": "ctx",
        "ready": true,
        "blocked": [],
        "rows": [row("egress", "ok"), row("timezone", "ok"), row("locale", "ok"), row("asn", "ok"), row("guard", "ok"), row("ip_history", "ok")],
        "display_facts": {
            "network": {"service":"Wi-Fi"},
            "local": {"proxy":"ok","tun":"ok","mode":"tag","timezone":"Asia/Tokyo","locale":"ja_JP","date_format":{"state":"available"},"context_transition":{"state":"stable"},"tag":{"entry":{"state":"verified","endpoint":"127.0.0.1:7890"}}},
            "online": {"trace":{"ip":"1.1.1.1","loc":"JP"},"geo":{"ip":"1.1.1.1","country":"JP","timezone":"Asia/Tokyo"},"asn":{"number":2516,"organization":"KDDI","queried_at":NOW - 1.0},"source_times":{"geo":NOW - 2.0,"asn":NOW - 1.0}}
        }
    })
}

fn session() -> Value {
    json!({"state":"idle"})
}

#[test]
fn no_record_reads_cache_but_never_creates_or_rewrites_it() {
    let (home, store) = store();
    let path = store.paths.base().join("environment-valid-samples.json");
    let out = receipt(&store, audit(), session(), false).unwrap();
    assert!(!path.exists());
    assert_eq!(out["rows"][0]["current"], "1.1.1.1 / JP");

    let mut saved = audit();
    let first = receipt(&store, saved.clone(), session(), true).unwrap();
    assert!(path.exists());
    let before = fs::read_to_string(&path).unwrap();
    saved["rows"][0]["state"] = json!("unknown");
    saved["display_facts"]["online"]["query_errors"] =
        json!({"trace":{"source":"fixture","message":"offline"}});
    let cached = receipt(&store, saved, session(), false).unwrap();
    assert_eq!(cached["rows"][0]["state"], "cached");
    assert_eq!(fs::read_to_string(&path).unwrap(), before);
    assert_eq!(first["expires_at"], json!(NOW + 300.0));
    let _ = fs::remove_dir_all(home);
}

#[test]
fn receipt_keeps_same_round_display_window_without_mutating_launch_audit() {
    let (home, store) = store();
    let launch_audit = audit();
    let out = receipt(&store, launch_audit.clone(), session(), false).unwrap();
    assert_eq!(launch_audit["expires_at"], json!(NOW + 17.0));
    assert_eq!(out["observed_at"], json!(NOW));
    assert_eq!(out["expires_at"], json!(NOW + 300.0));
    assert_eq!(out["policy_evaluation"]["observed_at"], json!(NOW));
    assert_eq!(out["policy_evaluation"]["expires_at"], json!(NOW + 300.0));
    assert_eq!(out["policy_evaluation"]["grants_launch_permission"], false);
    assert!(out.get("display_facts").is_none());
    assert!(out["policy_evaluation"].get("display_facts").is_none());
    assert_eq!(out["rows"][0]["current"], "1.1.1.1 / JP");
    let _ = fs::remove_dir_all(home);
}

#[test]
fn conflicts_never_fall_back_and_session_baseline_remains_visible() {
    let (home, store) = store();
    receipt(&store, audit(), session(), true).unwrap();
    let mut conflict = audit();
    conflict["rows"][0]["state"] = json!("unknown");
    conflict["display_facts"]["online"]["geo"]["ip"] = json!("8.8.8.8");
    conflict["display_facts"]["online"]["query_errors"] =
        json!({"trace":{"source":"fixture","message":"offline"}});
    let active = json!({"state":"active","baseline":{"ip":"9.9.9.9"}});
    let out = receipt(&store, conflict, active, false).unwrap();
    assert_ne!(out["rows"][0]["state"], "cached");
    let history = out["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "ip_history")
        .unwrap();
    assert_eq!(history["state"], "fail");
    assert_eq!(history["reference"], "会话基准 9.9.9.9");
    let _ = fs::remove_dir_all(home);
}

#[test]
fn future_or_non_ok_cache_samples_are_not_valid_display_evidence() {
    let (home, store) = store();
    receipt(&store, audit(), session(), true).unwrap();
    let path = store.paths.base().join("environment-valid-samples.json");
    let mut saved = store.read_json(&path, Value::Null).unwrap();
    saved["rows"]["egress"]["sampled_at"] = json!(NOW + 1.0);
    saved["rows"]["egress"]["row"]["state"] = json!("ok");
    store.atomic_json(&path, &saved).unwrap();
    let mut failed = audit();
    failed["rows"][0]["state"] = json!("unknown");
    failed["display_facts"]["online"]["query_errors"] =
        json!({"trace":{"source":"fixture","message":"offline"}});
    assert_ne!(
        receipt(&store, failed, session(), false).unwrap()["rows"][0]["state"],
        "cached"
    );
    let _ = fs::remove_dir_all(home);
}

#[test]
fn sampling_gap_can_show_same_context_cache_but_never_refreshes_or_extends_it() {
    let (home, store) = store();
    receipt(&store, audit(), session(), true).unwrap();
    let path = store.paths.base().join("environment-valid-samples.json");
    let before = fs::read_to_string(&path).unwrap();
    let mut missing = audit();
    missing["observed_at"] = json!(NOW + 120.0);
    missing["context_transition"] = json!({"state":"sampling_unavailable"});
    missing["rows"][0]["state"] = json!("unknown");
    missing["display_facts"]["online"]["query_errors"] =
        json!({"trace":{"source":"fixture","message":"temporary"}});
    let result = receipt(&store, missing, session(), true).unwrap();
    assert_eq!(result["rows"][0]["state"], "cached");
    assert_eq!(result["rows"][0]["sampled_at"], json!(NOW - 2.0));
    assert_eq!(fs::read_to_string(&path).unwrap(), before);
    assert_ne!(result["policy_evaluation"]["rows"][0]["state"], "cached");
    let _ = fs::remove_dir_all(home);
}

#[test]
fn cache_expires_without_reusing_or_rewriting_the_old_timestamp() {
    let (home, store) = store();
    receipt(&store, audit(), session(), true).unwrap();
    let mut stale = audit();
    stale["observed_at"] = json!(NOW + 301.0);
    stale["rows"][0]["state"] = json!("unknown");
    stale["display_facts"]["online"]["query_errors"] =
        json!({"trace":{"source":"fixture","message":"temporary"}});
    let result = receipt(&store, stale, session(), false).unwrap();
    assert_ne!(result["rows"][0]["state"], "cached");
    assert_ne!(result["rows"][0]["sampled_at"], json!(NOW + 301.0));
    let _ = fs::remove_dir_all(home);
}

/// A reused observation is a pass whose sample is minutes old — a STUN
/// receipt hit or a cached ASN answer — not a fresh probe.  Saying so keeps
/// the page honest instead of showing a fresh clock next to stale evidence.
/// The two channels differ in where the old clock lives: the four online
/// rows take it from `source_times` (a cache hit clones the original entry,
/// so `queried_at` trails the round; RIPEstat alone caches for 24 h), while
/// every other row keeps the `sampled_at` the audit already carried.  The
/// audit never writes `sampled_at` onto the asn row itself, so asserting
/// through the row would test a path production never takes.
#[test]
fn a_reused_observation_is_marked_while_a_fresh_round_is_not() {
    let (home, store) = store();
    let mut reused = audit();
    reused["display_facts"]["online"]["source_times"]["asn"] = json!(NOW - 240.0);
    // A STUN receipt hit keeps the receipt's own sample time on the row.
    reused["rows"].as_array_mut().unwrap().push(json!(
        {"id":"stun","state":"ok","detail":"stun detail","required":true,"sampled_at":NOW - 240.0}
    ));
    let out = receipt(&store, reused, session(), false).unwrap();
    let rows = out["rows"].as_array().unwrap();
    let asn = rows.iter().find(|r| r["id"] == "asn").unwrap();
    assert_eq!(asn["state"], "ok");
    assert_eq!(asn["sample_reused"], json!(true));
    let stun = rows.iter().find(|r| r["id"] == "stun").unwrap();
    assert_eq!(stun["state"], "ok");
    assert_eq!(stun["sample_reused"], json!(true));
    let fresh = receipt(&store, audit(), session(), false).unwrap();
    let asn = fresh["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "asn")
        .unwrap();
    assert!(asn.get("sample_reused").is_none());
    let _ = fs::remove_dir_all(home);
}
