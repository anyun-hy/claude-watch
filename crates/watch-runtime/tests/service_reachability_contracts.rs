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
fn a_stale_legacy_status_cannot_override_the_receipt() {
    // The runtime stopped writing these flat fields. When an old snapshot still
    // carries them they cannot fabricate a verdict: the receipt that measured
    // this round is the only answer, and it answered 200.
    let online = json!({
        "claude": 404,
        "api": 401,
        "service_responses": {
            "claude": receipt("https://claude.ai/cdn-cgi/trace", 200, "granted"),
            "api": receipt("https://api.anthropic.com/v1/models", 401, "authentication_required"),
        }
    });
    let (state, detail, _, _) = presentation::services(&online);
    assert_eq!(state, "ok", "detail={detail}");
    assert!(detail.contains("已响应 HTTP 200"), "detail={detail}");
    assert!(!detail.contains("404"), "detail={detail}");
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

#[test]
fn every_http_answer_counts_as_a_response() {
    // The probe is anonymous, so a challenge page and a plain denial are both
    // answers. They must read identically; the only failure is silence.
    let api = receipt(
        "https://api.anthropic.com/v1/models",
        401,
        "authentication_required",
    );
    let mut homepage = receipt("https://claude.ai/", 403, "challenge");
    homepage["challenge"] = json!({"provider":"cloudflare","mitigated":"challenge"});
    let online = json!({"service_responses":{"claude":homepage,"api":api}});
    let (state, detail, _, _) = presentation::services(&online);
    assert_eq!(state, "ok", "HTTP 403 is a response");
    assert!(detail.contains("已响应 HTTP 403"), "detail={detail}");
    let challenged_detail = detail.clone();

    let mut denied = online;
    denied["service_responses"]["claude"]["access"] = json!("unknown");
    denied["service_responses"]["claude"]["challenge"] = serde_json::Value::Null;
    let (state, detail, _, _) = presentation::services(&denied);
    assert_eq!(state, "ok");
    assert_eq!(
        detail, challenged_detail,
        "the same response code must read the same way regardless of how the site chose to answer"
    );
}
