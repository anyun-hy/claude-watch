use crate::network::public_unicast;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type ZoneCatalog = BTreeMap<String, BTreeSet<String>>;
pub fn locale_for(country: &str) -> Option<&'static str> {
    match country {
        "US" => Some("en_US"),
        "JP" => Some("ja_JP"),
        "CN" => Some("zh_CN"),
        "TW" => Some("zh_TW"),
        "HK" => Some("zh_HK"),
        "SG" => Some("en_SG"),
        "GB" => Some("en_GB"),
        "DE" => Some("de_DE"),
        "FR" => Some("fr_FR"),
        "KR" => Some("ko_KR"),
        "AU" => Some("en_AU"),
        "CA" => Some("en_CA"),
        _ => None,
    }
}
pub fn valid_timezone_name(value: &str) -> bool {
    let parts: Vec<_> = value.split('/').collect();
    parts.len() >= 2
        && parts.iter().all(|v| {
            !v.is_empty()
                && v.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_+-".contains(&c))
        })
}
pub fn reference(trace: &Value, geo: &Value, zones: &ZoneCatalog) -> Value {
    let Some(ip) = trace
        .get("ip")
        .and_then(Value::as_str)
        .and_then(public_unicast)
    else {
        return json!({});
    };
    let Some(country) = geo.get("country").and_then(Value::as_str) else {
        return json!({});
    };
    if country.len() != 2
        || !country.bytes().all(|c| c.is_ascii_uppercase())
        || geo.get("ip").and_then(Value::as_str) != Some(ip.as_str())
        || trace.get("loc").and_then(Value::as_str) != Some(country)
    {
        return json!({});
    }
    let timezone = geo.get("timezone");
    let candidates = zones.get(country);
    let mut selected = None;
    let mut source = String::new();
    if let Some(value) = timezone.and_then(Value::as_str) {
        if valid_timezone_name(value) && candidates.is_some_and(|v| v.contains(value)) {
            selected = Some(value.to_owned());
            source = geo
                .get("timezone_source")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .unwrap_or("Net.Coffee / IPinfo timezone")
                .chars()
                .take(160)
                .collect();
        }
    }
    if selected.is_none() && !timezone.is_some_and(crate::json_value::truthy) {
        if let Some(candidates) = candidates.filter(|v| v.len() == 1) {
            selected = candidates.first().cloned();
            source = "出口国家唯一 IANA 时区".into();
        }
    }
    json!({"ip":ip,"country":country,"timezone":selected,"locale":locale_for(country),
        "timezone_source":if source.is_empty(){"出口时区未确认"}else{&source},"locale_source":"出口国家对应的地区格式；界面语言独立"})
}
pub fn date_check(local: &Value, expected_locale: Option<&str>) -> &'static str {
    let Some(expected_locale) = expected_locale.filter(|v| !v.is_empty()) else {
        return "unknown";
    };
    let Some(date) = local.get("date_format").filter(|v| v.is_object()) else {
        return "unknown";
    };
    if date.get("state").and_then(Value::as_str) != Some("available") {
        return "unknown";
    }
    let Some(actual) = date.get("patterns").and_then(Value::as_object) else {
        return "unknown";
    };
    let Some(expected) = date
        .get("reference_patterns")
        .and_then(|v| v.get(expected_locale))
        .and_then(Value::as_object)
    else {
        return "unknown";
    };
    for style in ["short", "medium", "long"] {
        if [actual, expected].iter().any(|v| {
            v.get(style)
                .and_then(Value::as_str)
                .is_none_or(|v| v.is_empty())
        }) {
            return "unknown";
        }
    }
    if date.get("configured_locale") != local.get("locale") {
        return "unknown";
    }
    if ["short", "medium", "long"]
        .iter()
        .all(|style| actual.get(*style) == expected.get(*style))
    {
        "ok"
    } else {
        "fail"
    }
}
pub fn locale_check(local: &Value, expected: Option<&str>) -> &'static str {
    let Some(expected) = expected.filter(|v| !v.is_empty()) else {
        return "unknown";
    };
    let Some(actual) = local
        .get("locale")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
    else {
        return "unknown";
    };
    if actual != expected {
        "fail"
    } else {
        date_check(local, Some(expected))
    }
}
pub fn date_summary(local: &Value) -> String {
    let locale = local
        .get("locale")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .unwrap_or("未知");
    match local
        .pointer("/date_format/short_sample")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
    {
        Some(sample) => format!("{locale} · 示例 {sample}"),
        None => format!("{locale} · 日期格式未确认"),
    }
}
pub fn expected_date_summary(local: &Value, locale: Option<&str>) -> String {
    let label = locale
        .filter(|v| !v.is_empty())
        .unwrap_or("出口地区格式未确认");
    match locale
        .and_then(|v| {
            local
                .pointer("/date_format/reference_samples")
                .and_then(|m| m.get(v))
        })
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
    {
        Some(sample) => format!("{label} · 示例 {sample}"),
        None => label.into(),
    }
}
