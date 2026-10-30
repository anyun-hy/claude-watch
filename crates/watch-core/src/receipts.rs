//! Shared DNS/WebRTC receipts. Historical display evidence never grants launch permission.
use crate::{
    error::{CoreError, Result},
    json_value::truthy,
    network::public_unicast,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const DNS_DISPLAY_TTL: f64 = 300.0;
pub const DNS_LAUNCH_TTL: f64 = 30.0;
pub const MAX_PROBE_BYTES: usize = 768_000;
/// A UDP/STUN probe is cached as a receipt for this window so one server's
/// packet loss cannot flip the row between sampling rounds.  Upstream
/// `stun-probe.py` never required every server to answer, so a cached
/// observation stays authoritative while the egress context is unchanged.
pub const STUN_RECEIPT_TTL: f64 = 300.0;

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}
fn clipped(v: &Value, key: &str, limit: usize) -> String {
    text(v, key).chars().take(limit).collect()
}
fn number(v: &Value) -> Option<f64> {
    v.as_f64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .filter(|v| v.is_finite())
}
fn country(v: &Value) -> String {
    let s = v.as_str().unwrap_or("").trim().to_ascii_uppercase();
    if s.len() == 2 && s.bytes().all(|v| v.is_ascii_uppercase()) {
        s
    } else {
        String::new()
    }
}
fn public(v: &Value) -> Option<String> {
    v.as_str().and_then(public_unicast)
}
fn errors(v: &Value) -> Value {
    Value::Array(v.as_array().into_iter().flatten().filter(|v|v.is_object()).take(32).map(|v|json!({
        "stage":clipped(v,"stage",80),"code":clipped(v,"code",80),"message":clipped(v,"message",240)
    })).collect())
}
fn context_unavailable(probe: &Value) -> bool {
    probe["errors"].as_array().is_some_and(|errors| {
        errors.iter().any(|item| {
            text(item, "stage") == "context" && text(item, "code") == "context_unavailable"
        })
    })
}
fn query_error(v: &Value) -> String {
    let Some(v) = v.as_array().and_then(|v| v.iter().find(|v| v.is_object())) else {
        return String::new();
    };
    [
        (if v.get("stage").is_some() {
            clipped(v, "stage", 80)
        } else {
            "检测".into()
        }),
        (if v.get("code").is_some() {
            clipped(v, "code", 80)
        } else {
            "失败".into()
        }),
        clipped(v, "message", 240),
    ]
    .into_iter()
    .filter(|v| !v.is_empty())
    .collect::<Vec<_>>()
    .join(" / ")
}
fn check_probe(probe: &Value, kind: &str, now: f64) -> Result<(f64, f64)> {
    let invalid = format!("invalid_{kind}_receipt");
    if !probe.is_object() || text(probe, "kind") != kind {
        return Err(CoreError::new(&invalid, "检测回执类型无效"));
    }
    if serde_json::to_vec(probe).map_or(true, |v| v.len() > MAX_PROBE_BYTES) {
        return Err(CoreError::new(
            &format!("oversize_{kind}_receipt"),
            "检测回执过大",
        ));
    }
    if probe["contextChanged"].as_bool().is_none()
        || !matches!(
            text(probe, "status"),
            "complete" | "partial" | "error" | "timeout"
        )
        || !probe["observations"]
            .as_array()
            .is_some_and(|v| v.len() <= 128)
        || !probe["errors"].as_array().is_some_and(|v| v.len() <= 32)
    {
        return Err(CoreError::new(&invalid, "检测状态、上下文或地址列表无效"));
    }
    let times = number(&probe["startedAt"]).zip(number(&probe["finishedAt"]));
    let Some((started, finished)) = times else {
        return Err(CoreError::new(&invalid, "检测时间无效"));
    };
    if !now.is_finite()
        || started > finished
        || finished - started > 120.0
        || finished > now + 5.0
        || now - finished > 90.0
    {
        return Err(CoreError::new(
            &format!("{kind}_stale"),
            "检测结果不在可接受时间范围内",
        ));
    }
    Ok((started, finished))
}
pub fn tag_signature(local: &Value) -> String {
    [
        local.pointer("/tag/entry/endpoint"),
        local.pointer("/tag/api/mode"),
        local.pointer("/tag/api/selected_node"),
        local.pointer("/tag/api/global_node"),
    ]
    .iter()
    .map(|v| v.and_then(Value::as_str).unwrap_or(""))
    .collect::<Vec<_>>()
    .join("|")
}
fn local_context<'a>(local: &'a Value, expected: Option<&str>, webrtc: bool) -> Result<&'a str> {
    let context = if webrtc {
        local.get("context_id").unwrap_or(&local["context"])
    } else {
        &local["context"]
    };
    let context = context.as_str().unwrap_or("");
    let context_ok = if webrtc {
        expected.is_none_or(|s| s == context || s == tag_signature(local))
    } else {
        expected.is_none_or(|s| !s.is_empty() && s == tag_signature(local))
    };
    if (webrtc || expected.is_some())
        && (context.is_empty()
            || !context_ok
            || text(local, "proxy") != "ok"
            || text(local, "tun") != "ok"
            || truthy(&local["observation_unavailable"]))
    {
        return Err(CoreError::new(
            if webrtc {
                "webrtc_context_changed"
            } else {
                "dns_context_changed"
            },
            "采样所属网络与当前验证网络不一致或未能确认，未覆盖检测记录",
        ));
    }
    if context.is_empty() {
        return Err(CoreError::new(
            "dns_context_unknown",
            "当前代理或网络上下文未能确认",
        ));
    }
    Ok(context)
}
pub fn netcoffee_countries(raw: &Value) -> BTreeMap<String, String> {
    let Some(raw) = raw.as_str().filter(|v| v.len() <= 512_000) else {
        return BTreeMap::new();
    };
    let Ok(Value::Array(rows)) = serde_json::from_str(raw) else {
        return BTreeMap::new();
    };
    if rows.len() > 32 {
        return BTreeMap::new();
    }
    let mut codes = BTreeMap::new();
    for row in rows {
        if text(&row, "kind") != "geoip" || text(&row, "status") != "complete" {
            continue;
        }
        let Some(address) = public(&row["query"]) else {
            continue;
        };
        let code = country(&row["data"]["country_code"]);
        if !code.is_empty() {
            codes.insert(address, code);
        }
    }
    codes
}
fn comparison(state: &str, reason: &str, detail: &str) -> Value {
    json!({"state":state,"reason":reason,"detail":detail})
}

/// The IPLeak response binds each resolver and the HTTP reference to one
/// bounded session. Country values must come from that response, not the
/// independently mutable presentation fields of the observations.
fn ipleak_evidence(raw: &Value) -> Option<(BTreeMap<String, String>, BTreeSet<String>, String)> {
    let text = raw.as_str().filter(|v| v.len() <= 512_000)?;
    let value: Value = serde_json::from_str(text).ok()?;
    let session = value["session"].as_str()?;
    if session.len() != 40
        || !session
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return None;
    }
    let servers = value["dns_servers"]
        .as_object()
        .filter(|v| v.len() <= 127)?;
    let mut resolvers = BTreeSet::new();
    for (address, count) in servers {
        if count.as_u64().filter(|v| *v > 0).is_none() {
            return None;
        }
        resolvers.insert(public(&json!(address))?);
    }
    let http = public(&value["http"]["address"])?;
    let http_country = country(&value["http"]["country"]);
    if http_country.is_empty() {
        return None;
    }
    let mut countries = BTreeMap::from([(http.clone(), http_country)]);
    let rows = value["geoip"].as_array().filter(|v| v.len() <= 32)?;
    for row in rows {
        let address = public(&row["ip"])?;
        if !resolvers.contains(&address) {
            return None;
        }
        let code = country(&row["country_code"]);
        if code.is_empty() {
            return None;
        }
        if countries.get(&address).is_some_and(|old| old != &code) {
            return None;
        }
        countries.insert(address, code);
    }
    Some((countries, resolvers, http))
}

pub fn record_dns(probe: &Value, local: &Value, expected: Option<&str>, now: f64) -> Result<Value> {
    let (started, finished) = check_probe(probe, "dns", now)?;
    let evidence = ipleak_evidence(&probe["externalJSON"]);
    let codes = evidence.as_ref().map(|v| &v.0);
    let mut dns = BTreeSet::new();
    let mut http = BTreeSet::new();
    let (mut seen_dns, mut seen_http, mut missing) = (false, false, false);
    for row in probe["observations"].as_array().into_iter().flatten() {
        let bucket = match text(row, "kind") {
            "http" => {
                seen_http = true;
                &mut http
            }
            "resolver" => {
                seen_dns = true;
                &mut dns
            }
            _ => {
                missing = true;
                continue;
            }
        };
        let Some(address) = public(&row["address"]) else {
            missing = true;
            continue;
        };
        let in_evidence = evidence.as_ref().is_some_and(|(_, resolvers, reference)| {
            if text(row, "kind") == "http" {
                &address == reference
            } else {
                resolvers.contains(&address)
            }
        });
        let Some(code) = codes.and_then(|v| v.get(&address)).filter(|_| in_evidence) else {
            missing = true;
            continue;
        };
        bucket.insert((address, code.clone()));
    }
    if let Some((_, resolvers, reference)) = &evidence {
        if resolvers
            .iter()
            .any(|address| !dns.iter().any(|(ip, _)| ip == address))
            || !http.iter().any(|(ip, _)| ip == reference)
        {
            missing = true;
        }
    } else {
        missing = true;
    }
    let dns_countries: BTreeSet<_> = dns.iter().map(|v| v.1.clone()).collect();
    let http_countries: BTreeSet<_> = http.iter().map(|v| v.1.clone()).collect();
    let mismatched =
        http_countries.len() == 1 && dns_countries.iter().any(|c| !http_countries.contains(c));
    let compare = if probe["contextChanged"] == true {
        comparison(
            "unknown",
            "context_changed",
            "DNS 检测期间网络或代理上下文变化，不能给出通过结论",
        )
    } else if context_unavailable(probe) {
        comparison(
            "unknown",
            "context_unavailable",
            "DNS 检测期间代理上下文未能持续确认，不能给出通过结论",
        )
    } else if mismatched {
        comparison(
            "fail",
            "country_mismatch",
            "DNS 递归出口与同轮公网出口国家不一致，存在泄漏风险",
        )
    } else if text(probe, "status") == "complete"
        && !truthy(&probe["errors"])
        && !missing
        && dns_countries.len() == 1
        && http_countries.len() == 1
        && dns_countries == http_countries
    {
        comparison(
            "ok",
            "same_country",
            "DNS 递归出口与同轮公网出口国家一致；范围仅限本次采样路径",
        )
    } else if !seen_http {
        comparison(
            "unknown",
            "dns_http_reference_missing",
            "DNS 检测未取得同轮 HTTP 出口参考，不能给出通过结论",
        )
    } else if !seen_dns {
        comparison(
            "unknown",
            "dns_resolver_missing",
            "DNS 检测未取得递归出口，不能给出通过结论",
        )
    } else if missing {
        comparison(
            "unknown",
            "country_missing",
            "DNS 或同轮公网出口缺少国家归属，不能给出通过结论",
        )
    } else if dns_countries.len() != 1 || http_countries.len() != 1 {
        comparison(
            "unknown",
            "country_ambiguous",
            "DNS 或同轮公网出口存在多个国家归属，不能给出通过结论",
        )
    } else {
        comparison(
            "unknown",
            "incomplete",
            "DNS 检测未完整完成，不能给出通过结论",
        )
    };
    let context = local_context(local, expected, false)?;
    Ok(
        json!({"schema":1,"status":probe["status"],"observed_at":now,"recorded_at":now,
        "started_at":started,"finished_at":finished,"sampled_at":finished,
        "display_expires_at":finished+DNS_DISPLAY_TTL,"launch_expires_at":finished+DNS_LAUNCH_TTL,
        "context":context,"context_id":context,"provider":"ipleak",
        "dns":{"egress_ips":dns.iter().map(|v|v.0.clone()).collect::<Vec<_>>(),"countries":dns_countries,"source":"IPLeak.net WebView authoritative DNS"},
        "http":{"egress_ips":http.iter().map(|v|v.0.clone()).collect::<Vec<_>>(),"countries":http_countries,"source":"IPLeak.net WebView HTTP reference"},
        "comparison":compare,"errors":errors(&probe["errors"]),"query_error":query_error(&probe["errors"]),
        "scope":probe.get("scope").and_then(Value::as_str).unwrap_or("IPLeak.net DNS 泄漏检测")}),
    )
}
pub fn dns_last_valid(receipt: &Value, context: &str, now: f64) -> bool {
    let valid_time = number(&receipt["finished_at"])
        .zip(number(&receipt["recorded_at"]))
        .is_some_and(|(finished, recorded)| {
            now.is_finite()
                && finished <= now + 5.0
                && (0.0..=90.0).contains(&(recorded - finished))
        });
    receipt["schema"] == 1
        && text(receipt, "provider") == "ipleak"
        && valid_time
        && !context.is_empty()
        && text(receipt, "context") == context
        && text(receipt, "status") == "complete"
        && !truthy(&receipt["errors"])
        && text(&receipt["comparison"], "state") == "ok"
}
fn dns_state(
    receipt: &Value,
    context: &str,
    launch: bool,
    now: f64,
    stamp: &impl Fn(f64) -> String,
) -> (String, String) {
    let result = |state: &str, detail: &str| (state.into(), detail.into());
    if receipt["schema"] != 1 {
        return result("unknown", "DNS 泄漏检测尚未完成");
    }
    if text(receipt, "provider") != "ipleak" {
        return result("unknown", "请使用 IPLeak 重新检测 DNS 出口");
    }
    let (Some(finished), Some(recorded), Some(expires)) = (
        number(&receipt["finished_at"]),
        number(&receipt["recorded_at"]),
        number(
            &receipt[if launch {
                "launch_expires_at"
            } else {
                "display_expires_at"
            }],
        ),
    ) else {
        return result("unknown", "DNS 检测回执格式不完整");
    };
    let ttl = if launch {
        DNS_LAUNCH_TTL
    } else {
        DNS_DISPLAY_TTL
    };
    if !now.is_finite()
        || !(0.0..=90.0).contains(&(recorded - finished))
        || finished > now + 5.0
        || now > expires
        || expires > finished + ttl
    {
        return result("unknown", "DNS 检测结果已过期，请重新检测");
    }
    if context.is_empty() || text(receipt, "context") != context {
        return result("unknown", "DNS 检测后的网络或代理上下文已变化，请重新检测");
    }
    if !receipt["comparison"].is_object() {
        return result("unknown", "DNS 检测比较结果缺失");
    }
    let sampled = stamp(finished);
    match text(&receipt["comparison"], "state") {
        "ok" => (
            "ok".into(),
            format!("本轮 DNS 递归出口与同轮公网出口国家一致；采样 {sampled}"),
        ),
        "fail" => (
            "fail".into(),
            format!("DNS 递归出口与同轮公网出口国家不一致，存在泄漏风险；采样 {sampled}"),
        ),
        _ => {
            let detail = receipt["comparison"]["detail"]
                .as_str()
                .filter(|v| !v.is_empty())
                .unwrap_or("DNS 检测未取得完整国家归属");
            let error = text(receipt, "query_error");
            let suffix = if error.is_empty() {
                String::new()
            } else {
                format!("；查询失败：{error}")
            };
            (
                "unknown".into(),
                format!("{detail}{suffix}；采样 {sampled}"),
            )
        }
    }
}
pub fn dns_status(
    receipt: &Value,
    last_valid: &Value,
    context: &str,
    launch: bool,
    now: f64,
    stamp: impl Fn(f64) -> String,
) -> Value {
    let (state, detail) = dns_state(receipt, context, launch, now, &stamp);
    let cacheable = state == "unknown"
        && text(receipt, "context") == context
        && (matches!(text(receipt, "status"), "partial" | "error" | "timeout")
            || matches!(
                text(&receipt["comparison"], "reason"),
                "country_missing" | "dns_http_reference_missing" | "dns_resolver_missing"
            ))
        && !matches!(
            text(&receipt["comparison"], "reason"),
            "context_changed" | "context_unavailable"
        );
    let valid = dns_last_valid(last_valid, context, now);
    let fresh = dns_state(last_valid, context, false, now, &stamp).0 == "ok";
    let cached = cacheable && valid;
    json!({"state":state,"detail":detail,"receipt":if receipt.is_object(){receipt.clone()}else{json!({})},
        "display_receipt":if cached{last_valid.clone()}else if receipt.is_object(){receipt.clone()}else{json!({})},
        "display_cached":cached,"last_valid":{"available":valid,"fresh":fresh,"expired":valid && !fresh,
        "sampled_at":last_valid["finished_at"],"context_matches":text(last_valid,"context")==context}})
}

pub fn record_webrtc(
    probe: &Value,
    local: &Value,
    expected: Option<&str>,
    now: f64,
) -> Result<Value> {
    let (_, finished) = check_probe(probe, "webrtc", now)?;
    let context = local_context(local, expected, true)?;
    if probe["contextChanged"] != false {
        return Err(CoreError::new(
            "webrtc_context_changed",
            "WebRTC 检测期间网络上下文变化",
        ));
    }
    if context_unavailable(probe) {
        return Err(CoreError::new(
            "webrtc_context_unavailable",
            "WebRTC 检测期间代理上下文未能持续确认",
        ));
    }
    let countries = netcoffee_countries(&probe["externalJSON"]);
    let mut clean = Vec::new();
    let mut references = BTreeSet::new();
    let mut candidates = BTreeSet::new();
    let mut cn = Vec::new();
    for row in probe["observations"].as_array().into_iter().flatten() {
        if !row.is_object() {
            return Err(CoreError::new(
                "invalid_webrtc_receipt",
                "WebRTC 地址记录无效",
            ));
        }
        let Some(address) = public(&row["address"]) else {
            continue;
        };
        let kind = text(row, "kind");
        if !matches!(kind, "http" | "host" | "srflx" | "prflx") {
            continue;
        }
        let mut code = countries
            .get(&address)
            .cloned()
            .unwrap_or_else(|| country(&row["country"]));
        if code.is_empty() {
            code = match text(row, "country").to_uppercase().as_str() {
                "CHINA" | "中国" => "CN",
                "JAPAN" | "日本" => "JP",
                _ => "",
            }
            .into();
        }
        if kind == "http" {
            references.insert(address.clone());
        } else {
            candidates.insert(address.clone());
        }
        if code == "CN" {
            cn.push(address.clone());
        }
        clean.push(json!({"address":address,"kind":kind,"country":code,"source":clipped(row,"source",160)}));
    }
    let mismatch =
        !references.is_empty() && !candidates.is_empty() && !candidates.is_subset(&references);
    let state = if !cn.is_empty() || mismatch {
        "fail"
    } else if references.len() == 1
        && !candidates.is_empty()
        && text(probe, "status") == "complete"
        && !truthy(&probe["errors"])
    {
        "ok"
    } else {
        "unknown"
    };
    let detail = if !cn.is_empty() {
        "WebRTC 本轮公网出口或候选含中国归属"
    } else if mismatch {
        "WebRTC 公网候选与同轮 HTTP 出口不一致"
    } else if state == "ok" {
        "WebRTC 公网候选与同轮 HTTP 出口一致"
    } else {
        "WebRTC 未取得完整的同轮 HTTP 出口与公网候选"
    };
    Ok(
        json!({"schema":1,"kind":"webrtc","status":probe["status"],"sampled_at":finished,"recorded_at":now,
        "context_id":context,"risk":{"state":state,"detail":detail,"cn_candidates":cn},"observations":clean,"errors":errors(&probe["errors"])}),
    )
}
pub fn webrtc_status(receipt: &Value, context: &str, now: f64) -> Value {
    let unknown = |detail: &str| json!({"state":"unknown","detail":detail});
    if receipt["schema"] != 1 || text(receipt, "context_id") != context || context.is_empty() {
        return unknown("WebRTC 尚无当前网络的检测回执");
    }
    let Some((sampled, recorded)) =
        number(&receipt["sampled_at"]).zip(number(&receipt["recorded_at"]))
    else {
        return unknown("WebRTC 时间记录无效");
    };
    if !now.is_finite()
        || !(0.0..=300.0).contains(&(now - sampled))
        || !(-5.0..=90.0).contains(&(recorded - sampled))
    {
        return unknown("WebRTC 检测回执已过期");
    }
    let risk = &receipt["risk"];
    if !risk.is_object() || !matches!(text(risk, "state"), "ok" | "fail" | "unknown") {
        return unknown("WebRTC 比较结果无效");
    }
    json!({"state":risk["state"],"detail":risk.get("detail").unwrap_or(&json!("WebRTC 本轮检测")),
        "sampled_at":sampled,"observations":receipt.get("observations").unwrap_or(&json!([])),"receipt":receipt})
}

/// A STUN receipt only carries evidence when it holds at least one usable
/// per-server observation.  An empty list — or entries that are not objects —
/// is a shape no real probe produces: judged downstream, "no candidates"
/// reads as "zero exposure", so a corrupt or forged file would manufacture a
/// pass.  Write and read share this rule, so a receipt refused here is never
/// reused either.
fn usable_stun_probe(probe: &Value) -> bool {
    probe["observations"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty() && rows.iter().all(Value::is_object))
}

/// Persist one bounded UDP/STUN observation round.
///
/// The receipt keeps the raw probe so the judging side stays a pure function
/// of the observation; only the *probing* (the part that jitters) is cached.
/// `ProbeReceipt` carries no `kind` field, so it cannot reuse `check_probe`;
/// the same time sanity rules are applied directly.
pub fn record_stun(probe: &Value, context: &str, now: f64) -> Result<Value> {
    let invalid = "invalid_stun_receipt";
    if !probe.is_object() {
        return Err(CoreError::new(invalid, "STUN 探测回执无效"));
    }
    let Some(observations) = probe["observations"].as_array() else {
        return Err(CoreError::new(invalid, "STUN 探测回执缺少观测列表"));
    };
    if !usable_stun_probe(probe) {
        return Err(CoreError::new(invalid, "STUN 探测回执没有可用观测"));
    }
    if observations.len() > 128
        || serde_json::to_vec(probe).map_or(true, |v| v.len() > MAX_PROBE_BYTES)
    {
        return Err(CoreError::new("oversize_stun_receipt", "STUN 探测回执过大"));
    }
    let Some((started, finished)) = number(&probe["started_at"]).zip(number(&probe["finished_at"]))
    else {
        return Err(CoreError::new(invalid, "STUN 探测时间无效"));
    };
    if !now.is_finite()
        || started > finished
        || finished - started > 120.0
        || finished > now + 5.0
        || now - finished > 90.0
    {
        return Err(CoreError::new(
            "stun_stale",
            "STUN 探测结果不在可接受时间范围内",
        ));
    }
    Ok(
        json!({"schema":1,"kind":"stun","sampled_at":finished,"recorded_at":now,
            "context_id":context,"probe":probe}),
    )
}

/// Reuse a STUN receipt only while it is fresh and bound to the current
/// egress context.  `None` tells the caller to probe again; an expired or
/// foreign-context receipt is never silently reused, and a receipt never
/// grants anything on its own — the audit still judges the observation.
pub fn stun_fact(receipt: &Value, context: &str, now: f64) -> Option<Value> {
    if receipt["schema"] != 1 || text(receipt, "context_id") != context || context.is_empty() {
        return None;
    }
    let (sampled, recorded) =
        number(&receipt["sampled_at"]).zip(number(&receipt["recorded_at"]))?;
    if !now.is_finite()
        || !(0.0..=STUN_RECEIPT_TTL).contains(&(now - sampled))
        || !(-5.0..=90.0).contains(&(recorded - sampled))
    {
        return None;
    }
    let probe = receipt.get("probe")?;
    usable_stun_probe(probe).then(|| probe.clone())
}

/// The UI consumes this row; it must not re-evaluate a display cache as a pass.
pub fn dns_row(status: &Value) -> Value {
    let receipt = status
        .get("display_receipt")
        .filter(|v| truthy(v))
        .or_else(|| status.get("receipt").filter(|v| truthy(v)))
        .cloned()
        .unwrap_or(json!({}));
    let ips: Vec<_> = receipt["dns"]["egress_ips"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let countries = receipt["dns"]["countries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("、");
    let http_countries = receipt["http"]["countries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("、");
    let label = if countries.is_empty() {
        "国家未确认"
    } else {
        &countries
    };
    let current = match ips.len() {
        0 => "未知".into(),
        1 => format!("{} / {label}", ips[0]),
        n => format!("{label} · {n} 个 DNS 出口"),
    };
    let cached = status["display_cached"] == true;
    let mut detail = if text(status, "detail").is_empty() {
        "DNS 泄漏检测尚未完成".into()
    } else {
        text(status, "detail").to_owned()
    };
    if !ips.is_empty() {
        detail += &format!(
            "；DNS 出口 {}",
            ips.iter().take(128).copied().collect::<Vec<_>>().join("、")
        );
    }
    if cached {
        detail += "；此为历史显示，最新失败仍阻止受控启动";
    }
    json!({"id":"dns","name":"DNS","state":if cached{"cached"}else{status.get("state").and_then(Value::as_str).unwrap_or("unknown")},
        "detail":detail,"scope":"IPLeak.net DNS 泄漏采样；不代表所有应用或浏览器 DoH","required":true,
        "current":current,"reference":format!("同轮 HTTP 出口国家 {}",if http_countries.is_empty(){"未确认"}else{&http_countries}),
        "source":"IPLeak.net 权威 DNS 记录 + 同轮 HTTP 参考","sampled_at":receipt["finished_at"],
        "query_error":if status["state"]=="unknown"{status.get("detail").cloned().unwrap_or(Value::Null)}else{json!("")},
        "display_cached":cached,"last_valid":truthy(&status["last_valid"]["available"])})
}
