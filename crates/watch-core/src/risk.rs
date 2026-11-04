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

/// Probe exit fingerprint used for session drift detection. The DNS side
/// compares by the country set of recursive exits (recursive servers rotate
/// individual addresses inside one country without changing the exit path),
/// the WebRTC side by the public srflx candidate address set. Both sets are
/// sorted; an empty set means "no usable observation", never "no change".
pub fn probe_fingerprint(
    dns_receipt: &Value,
    webrtc_receipt: &Value,
) -> (Vec<String>, Vec<String>) {
    let mut dns: Vec<String> = dns_receipt
        .pointer("/dns/countries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|v| v.len() == 2 && v.bytes().all(|c| c.is_ascii_uppercase()))
        .map(str::to_owned)
        .collect();
    dns.sort();
    dns.dedup();
    let mut rtc: Vec<String> = webrtc_receipt
        .get("observations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|v| text(v, "kind") == Some("srflx"))
        .filter_map(|v| v.get("address").and_then(Value::as_str))
        .filter(|v| public_unicast(v).is_some())
        .map(str::to_owned)
        .collect();
    rtc.sort();
    rtc.dedup();
    (dns, rtc)
}

fn probe_fresh(receipt: &Value, time_key: &str, now: f64) -> bool {
    now.is_finite() && now > 0.0
        && receipt
            .get(time_key)
            .and_then(Value::as_f64)
            .is_some_and(|v| v.is_finite() && v > 0.0 && (0.0..=300.0).contains(&(now - v)))
}

/// Each source needs its own fresh observation AND baseline. An unavailable
/// source is unknown, not safe, and cannot suppress another confirmed drift.
fn probe_state(fresh: bool, baseline: &[String], current: &[String]) -> &'static str {
    if !fresh || baseline.is_empty() || current.is_empty() {
        "unknown"
    } else if baseline == current {
        "safe"
    } else {
        "risk"
    }
}

/// Compare each probe independently. Only confirmed changed sources contribute
/// to the returned risk code, so an unknown source cannot lend its stricter
/// configured action to the source that actually drifted. Overall safety still
/// requires both sources to be usable and unchanged.
pub fn probe_drift(
    baseline_dns: &[String],
    baseline_webrtc: &[String],
    dns_receipt: &Value,
    webrtc_receipt: &Value,
    now: f64,
) -> Value {
    let dns_ready = probe_fresh(dns_receipt, "finished_at", now);
    let rtc_ready = probe_fresh(webrtc_receipt, "sampled_at", now);
    let (current_dns, current_rtc) = probe_fingerprint(dns_receipt, webrtc_receipt);
    let dns_state = probe_state(dns_ready, baseline_dns, &current_dns);
    let rtc_state = probe_state(rtc_ready, baseline_webrtc, &current_rtc);
    let sources = json!({
        "dns": {"observed": dns_ready, "state": dns_state, "countries": current_dns,
            "observed_at": if dns_ready { dns_receipt["finished_at"].clone() } else { Value::Null }},
        "webrtc": {"observed": rtc_ready, "state": rtc_state, "addresses": current_rtc,
            "observed_at": if rtc_ready { webrtc_receipt["sampled_at"].clone() } else { Value::Null }},
    });
    let cause = match (dns_state == "risk", rtc_state == "risk") {
        (true, true) => Some((
            "dns_and_webrtc_egress_changed",
            "运行中 DNS 递归出口与 WebRTC 公网候选均偏离会话基线",
        )),
        (true, false) => Some((
            "dns_egress_changed",
            "运行中 DNS 递归出口国家集合偏离会话基线",
        )),
        (false, true) => Some((
            "webrtc_egress_changed",
            "运行中 WebRTC 公网候选偏离会话基线",
        )),
        (false, false) => None,
    };
    if let Some((code, detail)) = cause {
        // Retain the actual oldest contributing sample time, not the time a
        // cached receipt happened to be read by this guard round.
        let observed = [(dns_state, &dns_receipt["finished_at"]),
                        (rtc_state, &webrtc_receipt["sampled_at"])]
            .into_iter()
            .filter(|(state, _)| *state == "risk")
            .filter_map(|(_, at)| at.as_f64())
            .min_by(f64::total_cmp)
            .unwrap_or(now);
        return json!({"state":"risk","observed_at":observed,
            "reason":Reason::new(code, detail, observed),"sources":sources});
    }
    if dns_state == "safe" && rtc_state == "safe" {
        let observed = dns_receipt["finished_at"].as_f64().unwrap_or(now)
            .min(webrtc_receipt["sampled_at"].as_f64().unwrap_or(now));
        return json!({"state":"safe","observed_at":observed,"sources":sources});
    }
    let (code, detail) = if !dns_ready || !rtc_ready {
        ("risk_evidence_unavailable", "部分 DNS/WebRTC 探针样本缺失或已过期，未确认整体安全")
    } else if current_dns.is_empty() || current_rtc.is_empty() {
        ("probe_sample_empty", "部分探针未取得可用观测，未确认整体安全")
    } else {
        ("risk_baseline_missing", "部分探针缺少会话基线，无法确认整体漂移状态")
    };
    json!({"state":"unknown","observed_at":Value::Null,
        "reason":Reason::new(code, detail, now),"sources":sources})
}
