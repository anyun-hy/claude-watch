//! Distinguishes a failed sampler from a confirmed identity/environment change.
use crate::json_value::truthy;
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const LOCAL_FIELDS: [&str; 6] = [
    "timezone",
    "locale",
    "date_format",
    "ipv6",
    "language",
    "app_language",
];
fn view(value: &Value) -> Value {
    let fallback = json!({"context":value.get("context").unwrap_or(&json!(""))});
    let identity = value
        .get("network_identity")
        .filter(|v| truthy(v))
        .unwrap_or(&fallback);
    let unavailable = value
        .get("observation_unavailable")
        .filter(|v| v.is_array())
        .cloned()
        .unwrap_or(json!([]));
    json!({"context_id":value.get("context_id").or_else(||value.get("context")).unwrap_or(&json!("")),
        "identity":identity,"unavailable":unavailable})
}
pub fn transition(before: &Value, after: &Value) -> Value {
    let left = view(before);
    let right = view(after);
    let mut unavailable: BTreeSet<_> = [&left, &right]
        .iter()
        .flat_map(|v| v["unavailable"].as_array().into_iter().flatten())
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    if !left["identity"].is_object() || !right["identity"].is_object() {
        unavailable.insert("network_identity_format".into());
    }
    let mut fields = BTreeSet::new();
    if unavailable.is_empty() {
        let keys: BTreeSet<_> = [&left, &right]
            .iter()
            .flat_map(|v| v["identity"].as_object().into_iter().flat_map(|v| v.keys()))
            .collect();
        for key in keys {
            if left["identity"].get(key) != right["identity"].get(key) {
                fields.insert(key.clone());
            }
        }
    }
    json!({"state":if !unavailable.is_empty(){"sampling_unavailable"}else if !fields.is_empty(){"changed"}else{"stable"},
        "before":left,"after":right,"changed_fields":fields,"unavailable":unavailable})
}
pub fn reconcile(before: &mut Value, after: &Value) -> Value {
    let mut result = transition(before, after);
    let mut unavailable: BTreeSet<String> = result["unavailable"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let mut changed: BTreeSet<String> = result["changed_fields"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    for key in LOCAL_FIELDS {
        let left = &before[key];
        let right = &after[key];
        if left == right {
            continue;
        }
        let missing = |v: &Value| {
            v.is_null()
                || v == "unknown"
                || (key == "date_format" && v.is_object() && v["state"] != "available")
        };
        if key == "app_language" {
            changed.insert(key.into());
        } else if missing(left) || missing(right) {
            unavailable.insert(key.into());
            if missing(right) {
                before[key] = right.clone();
            }
        } else {
            changed.insert(key.into());
        }
    }
    for key in ["proxy", "tun"] {
        let previous = before[key].as_str();
        let next = after[key].as_str();
        // A confirmed local failure is an OR condition within a single
        // observation: a later missing sample cannot erase it. Conversely an
        // unknown then an OK sample has not produced two complete agreeing
        // observations, so it remains unknown for this receipt.
        if next == Some("fail") || previous == Some("fail") {
            before[key] = json!("fail");
            if key == "proxy" && next == Some("fail") {
                before["proxy_detail"] = after
                    .get("proxy_detail")
                    .cloned()
                    .unwrap_or(json!("代理已确认失效"));
            }
        } else if next == Some("unknown") || previous == Some("unknown") {
            before[key] = json!("unknown");
            unavailable.insert(format!("{key}_sampling"));
            if key == "proxy" && next == Some("unknown") {
                before["proxy_detail"] = after
                    .get("proxy_detail")
                    .cloned()
                    .unwrap_or(json!("代理采样未确认"));
            }
        }
    }
    if !truthy(&before["guard"]) || !truthy(&after["guard"]) {
        let disabled = before["guard_state"] == "disabled" || after["guard_state"] == "disabled";
        before["guard"] = json!(false);
        before["guard_state"] = json!(if disabled { "disabled" } else { "unknown" });
        before["guard_detail"] = json!(if disabled {
            "保护策略已禁用"
        } else {
            "本轮保护心跳或后台身份未能持续确认"
        });
    }
    result["state"] = json!(if !changed.is_empty() {
        "changed"
    } else if !unavailable.is_empty() {
        "sampling_unavailable"
    } else {
        "stable"
    });
    result["changed_fields"] = json!(changed);
    result["unavailable"] = json!(unavailable);
    before["context_changed"] = json!(result["state"] == "changed");
    before["context_transition"] = result.clone();
    result
}
