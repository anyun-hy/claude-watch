//! Reachability rows must read the current round's receipt.
//!
//! The runtime stopped writing the legacy flat `online.claude` / `online.api`
//! fields; a receipt that carries its own `http_status` is authoritative.

use claude_watch_core::presentation;
use serde_json::json;

fn receipt(source: &str, status: i64, access: &str) -> serde_json::Value {
    json!({
        "source": source,
        "http_status": status,
        "status": "ok",
        "transport_reached": true,
        "access": access,
        "queried_at": 1_700_000_000.0,
    })
}

#[test]
fn current_receipt_is_authoritative_without_legacy_flat_status() {
    let online = json!({
        "service_responses": {
            "claude": receipt("https://claude.ai/cdn-cgi/trace", 200, "granted"),
            "api": receipt("https://api.anthropic.com/v1/models", 401, "authentication_required"),
        }
    });
    let (state, detail, _, sampled) = presentation::services(&online);
    assert_eq!(state, "ok", "detail={detail}");
    assert!(detail.contains("HTTP 200"), "detail={detail}");
    assert!(sampled.is_some());
}

#[test]
fn legacy_flat_status_still_drives_the_row() {
    let online = json!({
        "claude": 200,
        "api": 401,
        "service_responses": {
            "claude": receipt("https://claude.ai/cdn-cgi/trace", 200, "granted"),
            "api": receipt("https://api.anthropic.com/v1/models", 401, "authentication_required"),
        }
    });
    let (state, detail, _, _) = presentation::services(&online);
    assert_eq!(state, "ok", "detail={detail}");
}

#[test]
fn a_conflicting_legacy_status_is_never_silently_dropped() {
    let online = json!({
        "claude": 404,
        "api": 401,
        "service_responses": {
            "claude": receipt("https://claude.ai/cdn-cgi/trace", 200, "granted"),
            "api": receipt("https://api.anthropic.com/v1/models", 401, "authentication_required"),
        }
    });
    let (state, detail, _, _) = presentation::services(&online);
    assert_eq!(state, "warn", "detail={detail}");
    assert!(detail.contains("HTTP 404"), "detail={detail}");
}

#[test]
fn an_unreachable_receipt_still_reports_unknown() {
    let mut claude = receipt("https://claude.ai/cdn-cgi/trace", 200, "granted");
    claude["status"] = json!("unknown");
    claude["transport_reached"] = json!(false);
    let online = json!({
        "service_responses": { "claude": claude, "api": receipt("https://api.anthropic.com/v1/models", 401, "authentication_required") }
    });
    let (state, detail, _, _) = presentation::services(&online);
    assert_eq!(state, "unknown", "detail={detail}");
}
