use crate::{json_value::truthy, network::public_unicast, session::Reason};
use serde_json::{json, Value};

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}
fn public(value: &Value) -> bool {
    text(value, "ip").and_then(public_unicast).is_some()
}
fn entry(id: &str, source: &str, value: &str, reason: &str) -> Value {
    json!({"id":id,"source":source,"value":value,"reason":reason,"required":true})
}

pub fn extract_risks(online: &Value, measured: &Value) -> Value {
    let mut risks = Vec::new();
    let trace = &online["trace"];
    let geo = &online["geo"];
    let trace_cn = text(trace, "loc") == Some("CN") && public(trace);
    let geo_cn = text(geo, "country") == Some("CN") && public(geo);
    if trace_cn || geo_cn {
        risks.push(entry(
            "cn_egress",
            if trace_cn && geo_cn {
                "trace/geo"
            } else if trace_cn {
                "trace"
            } else {
                "geo"
            },
            "CN",
            "本轮出口来源显示中国归属",
        ));
    }
    let disagree = public(trace)
        && public(geo)
        && (trace.get("ip") != geo.get("ip")
            || (trace.get("loc").is_some_and(truthy)
                && geo.get("country").is_some_and(truthy)
                && trace.get("loc") != geo.get("country")));
    if disagree
        || online
            .get("query_errors")
            .and_then(Value::as_object)
            .is_some_and(|v| v.contains_key("egress_consistency"))
    {
        risks.push(entry(
            "egress_conflict",
            "egress_consistency",
            "conflict",
            "出口来源返回不一致",
        ));
    }
    if online
        .pointer("/dns/receipt/dns/countries")
        .and_then(Value::as_array)
        .is_some_and(|v| v.iter().any(|c| c == "CN"))
    {
        risks.push(entry("cn_dns", "dns", "CN", "同轮 DNS 递归出口含中国归属"));
    }
    let webrtc = &online["webrtc"];
    if webrtc
        .get("observations")
        .and_then(Value::as_array)
        .is_some_and(|v| v.iter().any(|v| text(v, "country") == Some("CN")))
    {
        risks.push(entry(
            "cn_webrtc",
            "webrtc",
            "CN",
            "同轮 WebRTC 公网候选含中国归属",
        ));
    } else if text(webrtc, "state") == Some("fail") {
        risks.push(entry(
            "webrtc_mismatch",
            "webrtc",
            "mismatch",
            text(webrtc, "detail")
                .filter(|v| !v.is_empty())
                .unwrap_or("WebRTC 公网候选与同轮出口不一致"),
        ));
    }
    let lookup = online
        .pointer("/netcoffee_lookup/data/ip")
        .and_then(Value::as_str);
    if online
        .pointer("/asn/registered_country")
        .and_then(Value::as_str)
        == Some("CN")
        && lookup.is_some_and(|v| !v.is_empty())
        && lookup == text(trace, "ip")
    {
        risks.push(entry(
            "cn_asn_registration",
            "asn",
            "CN",
            "当前 IP 的 ASN 注册归属为中国；这是归属风险，不等同已证实泄漏",
        ));
    }
    json!({"state":if risks.is_empty(){"ok"}else{"fail"},"risks":risks,"evidence":{"country":measured.get("country").cloned().unwrap_or(Value::Null)}})
}

pub struct SessionRiskInput<'a> {
    pub dns: &'a Value,
    pub webrtc: &'a Value,
    pub environment_receipts: &'a [Value],
    pub context_id: &'a str,
    pub current_ip: Option<&'a str>,
    pub now: f64,
}

pub fn session_risk(input: &SessionRiskInput<'_>) -> Value {
    let now = input.now;
    let mut reasons = Vec::new();
    let mut sources = serde_json::Map::new();
    let mut times = Vec::<f64>::new();
    let mut dns_valid = false;
    let mut rtc_valid = false;
    let current_ip = input.current_ip.filter(|v| !v.is_empty());
    for (key, value) in [("dns", input.dns), ("webrtc", input.webrtc)] {
        let receipt = &value["receipt"];
        let sampled_raw = receipt
            .get(if key == "dns" {
                "finished_at"
            } else {
                "sampled_at"
            })
            .cloned()
            .unwrap_or(Value::Null);
        let sampled = sampled_raw.as_f64();
        let fresh = sampled.is_some_and(|v| v.is_finite() && (0.0..=300.0).contains(&(now - v)));
        let addresses = if key == "dns" {
            receipt
                .pointer("/http/egress_ips")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        } else {
            receipt
                .get("observations")
                .and_then(Value::as_array)
                .map(|v| {
                    v.iter()
                        .filter(|v| text(v, "kind") == Some("http"))
                        .map(|v| v.get("address").cloned().unwrap_or(Value::Null))
                        .collect()
                })
                .unwrap_or_default()
        };
        let bound = current_ip.is_none_or(|ip| addresses == vec![Value::String(ip.into())]);
        let state = if fresh && bound {
            text(value, "state").unwrap_or("unknown")
        } else {
            "unknown"
        };
        let detail = if bound {
            text(value, "detail").unwrap_or("检测证据缺失")
        } else {
            "检测参考 IP 与当前会话出口不同"
        };
        sources.insert(key.into(),json!({"state":state,"observed_at":if fresh{sampled_raw.clone()}else{Value::Null},"detail":detail}));
        if state == "fail" {
            reasons.push(json!({"code":format!("{key}_risk"),"detail":detail,"source":key,"observed_at":sampled_raw}));
        }
        if state == "ok" {
            if let Some(sampled) = sampled {
                times.push(sampled);
            }
        }
        if key == "dns" {
            dns_valid = state != "unknown";
        } else {
            rtc_valid = state != "unknown";
        }
    }
    let combined = json!({"dns":if dns_valid{input.dns.clone()}else{json!({})},"webrtc":if rtc_valid{input.webrtc.clone()}else{json!({})}});
    if let Some(risks) = extract_risks(&combined, &json!({}))["risks"].as_array() {
        for risk in risks {
            let key = if text(risk, "source") == Some("dns") {
                "dns"
            } else {
                "webrtc"
            };
            reasons.push(json!({"code":risk["id"],"detail":risk["reason"],"source":risk["source"],"observed_at":sources[key]["observed_at"]}));
        }
    }
    for value in input.environment_receipts {
        if text(value, "context_id") != Some(input.context_id) {
            continue;
        }
        let evidence = value
            .get("policy_evaluation")
            .filter(|v| truthy(v))
            .unwrap_or(value);
        let facts = &evidence["facts"];
        let measured = &facts["measured"];
        let fresh = value
            .get("observed_at")
            .and_then(Value::as_f64)
            .is_some_and(|v| v.is_finite() && (0.0..=300.0).contains(&(now - v)));
        if !fresh || current_ip.is_none() || text(measured, "ip") != current_ip {
            continue;
        }
        if let Some(risks) = facts.get("risks").and_then(Value::as_array) {
            for risk in risks {
                if !risk.is_object() {
                    continue;
                }
                if ["id", "reason", "source"]
                    .iter()
                    .any(|key| text(risk, key).is_none())
                {
                    return json!({"state":"unknown","reason":Reason::new("risk_evidence_invalid","同轮保护风险事实格式无效",now),"sources":sources,"observed_at":Value::Null});
                }
                reasons.push(json!({"code":risk["id"],"detail":risk["reason"],"source":risk["source"],"observed_at":value["observed_at"]}));
            }
        }
    }
    if !reasons.is_empty() {
        let observed = reasons
            .iter()
            .filter_map(|v| v["observed_at"].as_f64())
            .min_by(f64::total_cmp);
        return json!({"state":"risk","observed_at":observed,"reason":reasons[0],"reasons":reasons,"sources":sources});
    }
    let observed = times.iter().copied().min_by(f64::total_cmp);
    if times.len() == 2 {
        return json!({"state":"safe","observed_at":observed,"sources":sources});
    }
    json!({"state":"unknown","observed_at":observed,"sources":sources,"reason":{"code":"risk_evidence_unavailable","detail":"DNS/WebRTC 当前有效证据尚未齐全","source":"自动检测","observed_at":now}})
}
