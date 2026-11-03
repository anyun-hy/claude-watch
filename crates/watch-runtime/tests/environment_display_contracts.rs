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
    assert_eq!(out["rows"][0]["current"], "1.1.1.1 / \u{1F1EF}\u{1F1F5} JP");

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
    // The UI receipt keeps the curated display subset consumed by the mode
    // card and summary strip; the raw local snapshot never crosses IPC.
    assert!(out["display_facts"].is_object());
    assert_eq!(out["display_facts"]["online"]["geo"]["country"], json!("JP"));
    assert_eq!(out["display_facts"]["online"]["geo"]["timezone"], json!("Asia/Tokyo"));
    assert!(out["display_facts"]["local"].get("proxy").is_none());
    assert!(out["display_facts"]["local"].get("timezone").is_none());
    assert!(out["policy_evaluation"].get("display_facts").is_none());
    assert_eq!(out["rows"][0]["current"], "1.1.1.1 / \u{1F1EF}\u{1F1F5} JP");
    let _ = fs::remove_dir_all(home);
}

#[test]
fn every_service_card_reports_the_same_way_for_the_same_measurement() {
    let (home, store) = store();
    let service = |source: &str, code: i64| {
        json!({"source":source,"status":"ok","transport_reached":true,"http_status":code})
    };
    let mut observed = audit();
    // Both services answered: claude.ai with a challenge page, the API with a
    // missing key. Neither is a failure — the probe carries no credentials.
    observed["rows"].as_array_mut().unwrap().push(json!({
        "id":"reachability","state":"ok","required":true,
        "service_responses":{
            "claude":service("https://claude.ai/",403),
            "api":service("https://api.anthropic.com/v1/models",401)
        }
    }));
    observed["rows"].as_array_mut().unwrap().push(json!({
        "id":"chatgpt_reachability","state":"ok","required":false,
        "service_responses":{
            "chatgpt":service("https://chatgpt.com/",403),
            "openai_api":service("https://api.openai.com/v1/models",401)
        }
    }));
    let current = |value: &Value, id: &str| {
        value["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .unwrap()["current"]
            .as_str()
            .unwrap_or("")
            .to_owned()
    };
    let answered = receipt(&store, observed.clone(), session(), false).unwrap();
    let claude = current(&answered, "reachability");
    let chatgpt = current(&answered, "chatgpt_reachability");
    assert_eq!(claude, "网页：已响应 HTTP 403 · API：已响应 HTTP 401");
    // Same measurement, same sentence: the two cards must not drift apart.
    assert_eq!(claude, chatgpt);

    // One endpoint silent, one answering: the difference is visible, and the
    // wording still matches between the two services.
    let mut silent = observed.clone();
    for row in silent["rows"].as_array_mut().unwrap() {
        for key in ["claude", "chatgpt"] {
            if row["service_responses"][key].is_object() {
                row["service_responses"][key]["status"] = json!("unknown");
                row["service_responses"][key]["transport_reached"] = json!(false);
                row["service_responses"][key]["http_status"] = Value::Null;
                row["service_responses"][key]["error"] = json!("timeout: connect");
            }
        }
    }
    let partial = receipt(&store, silent, session(), false).unwrap();
    let claude = current(&partial, "reachability");
    assert_eq!(claude, "网页：无响应 · API：已响应 HTTP 401");
    assert_eq!(claude, current(&partial, "chatgpt_reachability"));
    let _ = fs::remove_dir_all(home);
}

#[test]
fn initialization_receipt_evidence_uses_current_backend_receipts_not_display_cache() {
    let (home, store) = store();
    let mut observed = audit();
    observed["display_facts"]["online"]["dns"] = json!({
        "state":"unknown", "receipt":{"context_id":"new", "finished_at":NOW-5.0},
        "display_receipt":{"context_id":"old", "finished_at":NOW-20.0}
    });
    observed["display_facts"]["online"]["webrtc"] = json!({
        "state":"ok", "receipt":{"context_id":"new", "sampled_at":NOW-3.0}
    });
    let out = receipt(&store, observed, session(), false).unwrap();
    assert_eq!(out["initialization_receipts"]["dns"]["state"], "unknown");
    assert_eq!(out["initialization_receipts"]["dns"]["context_id"], "new");
    assert_eq!(
        out["initialization_receipts"]["dns"]["sampled_at"],
        json!(NOW - 5.0)
    );
    assert_eq!(out["initialization_receipts"]["webrtc"]["state"], "ok");
    assert_eq!(
        out["initialization_receipts"]["webrtc"]["context_id"],
        "new"
    );
    assert_eq!(
        out["initialization_receipts"]["webrtc"]["sampled_at"],
        json!(NOW - 3.0)
    );
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

/// The environment page must carry the card detail the Python reference
/// rendered: STUN candidates, DNS resolver exits, proxy node selection,
/// measured proxy candidates and the online-failure footer.  These are the
/// fields the Rust migration originally dropped.
#[test]
fn cards_carry_stun_dns_proxy_and_candidate_detail_not_blank_or_empty() {
    let (home, store) = store();
    let mut observed = audit();
    // Enrich local facts: a selected TAG node, measured candidates, and the
    // controller selection the proxy card appends.
    observed["display_facts"]["local"]["tag"]["api"] = json!({
        "mode": "rule", "selected_node": "日本 01", "global_node": ""
    });
    observed["display_facts"]["local"]["candidates"] = json!(["tag"]);
    // The audit must carry the proxy and dns rows for `present_rows` to enrich
    // them; the real audit always emits these, the minimal fixture does not.
    observed["rows"].as_array_mut().unwrap().push(json!(
        {"id":"proxy","state":"ok","detail":"proxy detail","required":true}
    ));
    observed["rows"].as_array_mut().unwrap().push(json!(
        {"id":"dns","state":"ok","detail":"dns detail","required":true}
    ));
    // A STUN receipt with one accepted public candidate.
    observed["rows"].as_array_mut().unwrap().push(json!({
        "id": "stun", "state": "ok", "required": true,
        "stun_probe": {"observations": [
            {"status": "ok", "accepted": true, "address": "8.8.8.8", "server": "s1"}
        ]}
    }));
    // A DNS status with a resolver exit and country.
    observed["display_facts"]["online"]["dns"] = json!({
        "state": "ok", "detail": "DNS 泄漏检测完成",
        "display_receipt": {"finished_at": NOW - 3.0,
            "dns": {"egress_ips": ["8.8.8.8"], "countries": ["JP"]},
            "http": {"countries": ["JP"]}},
        "receipt": {"finished_at": NOW - 3.0}
    });

    let out = receipt(&store, observed, session(), false).unwrap();
    let rows = out["rows"].as_array().unwrap();
    let by_id = |id: &str| rows.iter().find(|r| r["id"] == id).unwrap();

    let stun = by_id("stun");
    assert!(stun["current"].as_str().unwrap_or("").contains("8.8.8.8"));
    assert!(stun["source"]
        .as_str()
        .unwrap_or("")
        .contains("不等于 Claude 实际 socket"));

    let dns = by_id("dns");
    assert!(dns["current"].as_str().unwrap_or("").contains("8.8.8.8"));
    assert!(dns["current"].as_str().unwrap_or("").contains("JP"));
    assert!(dns.get("sampled_at").is_some());

    let proxy = by_id("proxy");
    // The proxy card names kernel and entry only; node selection moved to the
    // 代理模式 / IP 一致性 cards by user decision.
    assert!(proxy["current"]
        .as_str()
        .unwrap_or("")
        .contains("tag · 127.0.0.1:7890"));
    assert!(!proxy["current"].as_str().unwrap_or("").contains("日本 01"));

    let history = by_id("ip_history");
    assert!(history["current"]
        .as_str()
        .unwrap_or("")
        .contains("1.1.1.1 / \u{1F1EF}\u{1F1F5} JP"));
    assert!(history["current"]
        .as_str()
        .unwrap_or("")
        .contains("线路 日本 01"));

    assert_eq!(out["candidates"], json!(["tag"]));
    let _ = fs::remove_dir_all(home);
}

/// An online-detection failure must appear in the footer message, matching the
/// Python behaviour that explained why the round fell back to local facts.
#[test]
fn footer_message_appends_online_detection_failure_reason() {
    let (home, store) = store();
    let mut observed = audit();
    observed["display_facts"]["online"]["query_errors"] =
        json!({"egress": {"source": "Cloudflare trace", "message": "未完成"}});
    let out = receipt(&store, observed, session(), false).unwrap();
    assert!(out["message"].as_str().unwrap_or("").contains("未完成"));
    let _ = fs::remove_dir_all(home);
}
