//! Complete shared preflight policy. Inputs are measured facts, never saved targets.
use crate::{
    config::Config,
    error::{CoreError, Result},
    json_value::truthy,
    network::public_unicast,
    observation::LOCAL_FIELDS,
    presentation::{self as p, text},
    region::{self, ZoneCatalog},
    risk,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const CHECKS: [(&str, &str); 15] = [
    ("proxy", "代理内核"),
    ("tun", "TUN 网卡"),
    ("egress", "出口国家"),
    ("ip_history", "IP 一致性"),
    ("timezone", "时区"),
    ("locale", "地区与日期格式"),
    ("ipv6", "IPv6 策略"),
    ("dns", "DNS"),
    ("stun", "UDP/STUN 出口"),
    ("guard", "保护后台"),
    ("routing", "代理规则覆盖"),
    ("language", "Claude 语言"),
    ("asn", "ASN 属性"),
    ("reachability", "Claude 服务"),
    ("chatgpt_reachability", "ChatGPT 服务"),
];
pub struct AuditInput<'a> {
    pub config: &'a Config,
    pub local: &'a Value,
    pub online: &'a Value,
    pub history: &'a [Value],
    pub zones: &'a ZoneCatalog,
    pub policy: &'a str,
    pub now: f64,
}
fn row(id: &str, state: &str, detail: impl Into<String>, required: bool, scope: &str) -> Value {
    let name = CHECKS.iter().find(|v| v.0 == id).map(|v| v.1).unwrap_or(id);
    let state = if matches!(state, "ok" | "fail" | "warn" | "unknown") {
        state
    } else {
        "unknown"
    };
    json!({"id":id,"name":name,"state":state,"detail":detail.into(),"required":required,"scope":scope})
}
pub fn preferred_language(v: &Value) -> Option<String> {
    let value = v.as_str()?.trim();
    let value = if value.starts_with('(') && value.ends_with(')') {
        &value[1..value.len() - 1]
    } else {
        value
    };
    let items: Vec<_> = value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_matches('"'))
        .collect();
    let valid = |s: &&str| {
        let parts: Vec<_> = s.split(['-', '_']).collect();
        (2..=3).contains(&parts[0].len())
            && parts[0].bytes().all(|v| v.is_ascii_alphabetic())
            && parts.iter().skip(1).all(|s| {
                !s.is_empty() && s.len() <= 8 && s.bytes().all(|v| v.is_ascii_alphanumeric())
            })
    };
    if items.is_empty() || !items.iter().all(valid) {
        None
    } else {
        Some(items[0].into())
    }
}

/// Only the child environment changes. App-owned overrides must agree with
/// the same measured loopback endpoint; no values or credentials are echoed.
pub fn cli_proxy_state(proxy: Option<&str>, overrides: &[Value]) -> Value {
    let Some(proxy) = proxy.filter(|p| crate::config::valid_loopback_proxy(p)) else {
        return json!({"state":"unknown","detail":"尚未识别支持CLI的已验证本地HTTP入口"});
    };
    let expected = url::Url::parse(proxy).ok();
    for settings in overrides {
        let Some(settings) = settings.as_object() else {
            return json!({"state":"unknown","detail":"CLI代理设置格式无法核实"});
        };
        for (key, value) in settings {
            let Some(value) = value.as_str() else {
                return json!({"state":"unknown","detail":"CLI代理设置类型无法核实"});
            };
            if value.is_empty() {
                continue;
            }
            if matches!(key.as_str(), "NO_PROXY" | "no_proxy") {
                if value
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .any(|v| !v.is_empty() && !matches!(v, "localhost" | "127.0.0.1" | "::1"))
                {
                    return json!({"state":"unknown","detail":"CLI设置含无法核实的代理绕过项"});
                }
            } else {
                let matches = url::Url::parse(value)
                    .ok()
                    .zip(expected.as_ref())
                    .is_some_and(|(u, e)| {
                        u.scheme() == "http"
                            && u.username().is_empty()
                            && u.password().is_none()
                            && matches!(u.path(), "" | "/")
                            && u.query().is_none()
                            && u.fragment().is_none()
                            && u.port() == e.port()
                            && (u.host_str() == e.host_str()
                                || u.host_str() == Some("localhost")
                                    && e.host_str() == Some("127.0.0.1"))
                    });
                if !matches {
                    return json!({"state":"fail","detail":"CLI自身代理覆盖与已验证入口不一致"});
                }
            }
        }
    }
    json!({"state":"ok","detail":"仅为新子进程使用已验证入口；实际流量仍按进程绑定证据判定"})
}

/// A scope changes collection and presentation, never the row policy or the
/// authority of a launch. Partial views deliberately contain no `ready` flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Full,
    Proxy,
    Dns,
}
impl Scope {
    pub fn ids(self) -> &'static [&'static str] {
        match self {
            Self::Full => &[],
            Self::Proxy => &["proxy", "tun", "routing"],
            Self::Dns => &["dns"],
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Proxy => "proxy",
            Self::Dns => "dns",
        }
    }
}
pub fn project(scope: Scope, audit: Value, evidence: Value) -> Result<Value> {
    if scope == Scope::Full {
        return Ok(audit);
    }
    let rows = audit["rows"]
        .as_array()
        .ok_or_else(|| CoreError::new("invalid_audit", "检测回执缺少标准项目"))?
        .iter()
        .filter(|row| scope.ids().contains(&text(row, "id")))
        .cloned()
        .collect::<Vec<_>>();
    let state = if rows.iter().any(|r| r["state"] == "fail") {
        "fail"
    } else if rows.len() != scope.ids().len()
        || rows
            .iter()
            .any(|r| !matches!(text(r, "state"), "ok" | "warn"))
    {
        "unknown"
    } else if rows.iter().any(|r| r["state"] == "warn") {
        "warn"
    } else {
        "ok"
    };
    let mut result = json!({"schema":1,"scope":scope.name(),"purpose":"scoped_detection","state":state,
        "grants_launch_permission":false,"rows":rows,"evidence":evidence});
    for key in [
        "observed_at",
        "expires_at",
        "context_id",
        "observation_id",
        "policy",
        "context_transition",
        "network_identity",
    ] {
        if let Some(value) = audit.get(key) {
            result[key] = value.clone();
        }
    }
    Ok(result)
}
pub fn apply_risks(rows: &mut [Value], facts: &Value) {
    for risk in facts["risks"].as_array().into_iter().flatten() {
        let id = match text(risk, "source") {
            "dns" => "dns",
            "asn" => "asn",
            "webrtc" => "guard",
            _ => "egress",
        };
        if let Some(row) = rows.iter_mut().find(|v| v["id"] == id) {
            row["state"] = json!("fail");
            row["detail"] = risk["reason"].clone();
            // The dns row's required flag is owned by the require_dns config:
            // an absolute probe verdict stays visible as fail without gating.
            if id != "dns" {
                row["required"] = json!(true);
            }
        }
    }
}
pub fn evaluate(input: AuditInput<'_>, stamp: impl Fn(f64) -> String) -> Result<Value> {
    evaluate_target(input, crate::processes::LaunchTarget::ClaudeDesktop, stamp)
}
pub fn evaluate_target(
    input: AuditInput<'_>,
    target: crate::processes::LaunchTarget,
    stamp: impl Fn(f64) -> String,
) -> Result<Value> {
    let AuditInput {
        config,
        local,
        online,
        history,
        zones,
        policy,
        now,
    } = input;
    if !now.is_finite() || !local.is_object() || !online.is_object() {
        return Err(CoreError::new(
            "invalid_audit_input",
            "预检时钟或采样对象无效",
        ));
    }
    let mut rows = Vec::with_capacity(14);
    let mode = text(local, "mode");
    let proxy_detail = if !text(local, "proxy_detail").is_empty() {
        text(local, "proxy_detail").into()
    } else if !mode.is_empty() {
        format!("已识别 {mode}")
    } else {
        "代理未运行、身份不完整或多个候选需明确选择".into()
    };
    rows.push(row(
        "proxy",
        text(local, "proxy"),
        proxy_detail,
        true,
        "本机环境",
    ));
    rows.push(row(
        "tun",
        text(local, "tun"),
        "接口与代理状态核对；不构成逐包出站保证",
        true,
        "本机环境",
    ));
    let measured = region::reference(&online["trace"], &online["geo"], zones);
    let mut automatic = risk::extract_risks(online, &measured);
    automatic["measured"] = measured.clone();
    let address = online["trace"]["ip"]
        .as_str()
        .and_then(public_unicast)
        .unwrap_or_default();
    let country = text(&measured, "country");
    let risks: Vec<_> = automatic["risks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|v| matches!(text(v, "id"), "cn_egress" | "egress_conflict"))
        .collect();
    if !risks.is_empty() {
        rows.push(row(
            "egress",
            "fail",
            format!(
                "{}；{}",
                if address.is_empty() {
                    "未取得 IP"
                } else {
                    &address
                },
                risks
                    .iter()
                    .map(|v| text(v, "reason"))
                    .collect::<Vec<_>>()
                    .join("；")
            ),
            true,
            "诊断请求",
        ));
    } else if !truthy(&measured) {
        rows.push(row(
            "egress",
            "unknown",
            "本轮出口/国家未能交叉确认",
            true,
            "诊断请求",
        ));
    } else {
        rows.push(row(
            "egress",
            "ok",
            format!("{address} / {country}"),
            true,
            "诊断请求",
        ));
    }
    let history: Vec<_> = history
        .iter()
        .filter(|v| {
            v.is_object()
                && p::number(&v["time"]).is_some_and(|t| (0.0..=172800.0).contains(&(now - t)))
        })
        .collect();
    let mut addresses: BTreeSet<_> = history
        .iter()
        .filter_map(|v| v["ip"].as_str().and_then(public_unicast))
        .collect();
    let previous = history.last().map(|v| text(v, "ip")).unwrap_or("");
    if !address.is_empty() {
        addresses.insert(address.clone());
    }
    let changed = !address.is_empty() && !previous.is_empty() && previous != address;
    rows.push(row(
        "ip_history",
        if address.is_empty() {
            "unknown"
        } else if changed || addresses.len() >= 3 {
            "warn"
        } else {
            "ok"
        },
        format!("48 小时内观测到 {} 个出口；变化不等同泄漏", addresses.len()),
        false,
        "检测历史；运行中 IP 变化由不可滚动的会话基准阻断",
    ));
    let expected_tz = text(&measured, "timezone");
    let actual_tz = local.get("timezone");
    let state = if expected_tz.is_empty() || actual_tz.is_none_or(Value::is_null) {
        "unknown"
    } else if actual_tz.and_then(Value::as_str) == Some(expected_tz) {
        "ok"
    } else {
        "fail"
    };
    rows.push(row(
        "timezone",
        state,
        format!(
            "当前 {}；本轮实测出口所属时区 {}",
            if text(local, "timezone").is_empty() {
                "未知"
            } else {
                text(local, "timezone")
            },
            if expected_tz.is_empty() {
                "未确认"
            } else {
                expected_tz
            }
        ),
        true,
        "本机环境",
    ));
    let expected_locale = measured["locale"].as_str();
    let locale_state = region::locale_check(local, expected_locale);
    rows.push(row(
        "locale",
        locale_state,
        format!(
            "当前 {}；本轮出口要求 {}；短、中、长日期模板{}，界面语言独立",
            region::date_summary(local),
            region::expected_date_summary(local, expected_locale),
            if locale_state == "ok" {
                "已核对"
            } else {
                "不匹配或未确认"
            }
        ),
        true,
        "本机环境",
    ));
    rows.push(row(
        "ipv6",
        text(local, "ipv6"),
        if config.require_ipv6_off {
            "关闭策略已启用"
        } else {
            "未要求关闭；此项不能证明 IPv6 无泄漏"
        },
        config.require_ipv6_off,
        "本机环境",
    ));
    let dns = &online["dns"];
    let dns_state = if matches!(text(dns, "state"), "ok" | "fail" | "unknown") {
        text(dns, "state")
    } else {
        "unknown"
    };
    rows.push(row(
        "dns",
        dns_state,
        if text(dns, "detail").is_empty() {
            "DNS 泄漏检测尚未完成"
        } else {
            text(dns, "detail")
        },
        config.require_dns,
        "IPLeak.net DNS 泄漏采样；不代表所有应用或浏览器 DoH",
    ));
    let stun = &online["stun"];
    let observed_candidates: BTreeSet<_> = stun["observations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|v| v["status"] == "ok")
        .filter_map(|v| v["address"].as_str().and_then(public_unicast))
        .collect();
    let candidates: BTreeSet<_> = stun["observations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|v| v["status"] == "ok" && v["accepted"] != false && v["deadline_exceeded"] != true)
        .filter_map(|v| v["address"].as_str().and_then(public_unicast))
        .collect();
    let reference: BTreeSet<_> = if address.is_empty() {
        BTreeSet::new()
    } else {
        BTreeSet::from([address.clone()])
    };
    // No response does not prove UDP is blocked. A pass requires at least one
    // accepted public response. Partial coverage remains visible in the detail;
    // even a late mismatching observed address remains risk evidence.
    let state = if reference.is_empty() {
        "unknown"
    } else if !observed_candidates.is_subset(&reference) {
        "fail"
    } else if candidates.is_empty() {
        "unknown"
    } else {
        "ok"
    };
    let (detail, sampled, observations) = p::stun(stun, &candidates, &reference, &stamp);
    let mut stun_row = row(
        "stun",
        state,
        detail,
        config.require_stun,
        "原生 UDP/STUN 探针，用于 AI 受控启动网络检查；不等于 Claude 实际 socket 或 WebRTC",
    );
    stun_row["sampled_at"] = json!(sampled);
    stun_row["stun_finished_at"] = json!(sampled);
    stun_row["stun_observations"] = observations;
    stun_row["stun_probe"] = if stun.is_object() {
        stun.clone()
    } else {
        json!({})
    };
    rows.push(stun_row);
    let guard_state = if !target.protected() {
        if local["backend_healthy"] == true && local["backend_native"] == true {
            "ok"
        } else {
            "unknown"
        }
    } else if truthy(&local["guard"]) {
        "ok"
    } else if local["guard_state"] == "disabled" {
        "fail"
    } else {
        "unknown"
    };
    rows.push(row(
        "guard",
        guard_state,
        if !target.protected() {
            if text(local, "backend_detail").is_empty() {
                "需要支持原生观察租约的采集后台；不代表Claude专属保护已开启"
            } else {
                text(local, "backend_detail")
            }
        } else if text(local, "guard_detail").is_empty() {
            "要求保护已启用且收到新鲜心跳"
        } else {
            text(local, "guard_detail")
        },
        true,
        "本机环境",
    ));
    if !target.protected() {
        rows.last_mut().unwrap()["name"] = json!("采集后台");
    }
    rows.push(row(
        "routing",
        text(&local["rules"], "state"),
        local["rules"]
            .get("detail")
            .and_then(Value::as_str)
            .unwrap_or("规则未确认；请配置或查看代理实际连接"),
        config.require_pinned_rules,
        "规则配置；实际流量另见连接页",
    ));
    if target.cli() {
        let state = &local["cli_proxy"];
        let mut r = row(
            "cli_proxy",
            text(state, "state"),
            text(state, "detail"),
            true,
            "子进程配置；不代表每条SDK连接已验证",
        );
        r["name"] = json!("CLI代理环境");
        rows.push(r);
    }
    let language = preferred_language(&local["language"]);
    let english = language
        .as_ref()
        .is_some_and(|v| v.split(['-', '_']).next() == Some("en"));
    if target.protected() {
        rows.push(row(
            "language",
            if language.is_none() {
                "unknown"
            } else if english {
                "ok"
            } else {
                "fail"
            },
            "Claude 应用语言或系统首选语言",
            config.require_english,
            "本机环境",
        ));
    }
    let asn = &online["asn"];
    let raw_country = text(asn, "registered_country").trim().to_ascii_uppercase();
    let asn_country =
        if raw_country.len() == 2 && raw_country.bytes().all(|v| v.is_ascii_uppercase()) {
            raw_country.as_str()
        } else {
            ""
        };
    let exit_country = if country.is_empty() {
        "未确认"
    } else {
        country
    };
    let (state, detail) = if let Some(n) = asn["number"].as_i64().filter(|v| *v > 0) {
        let registration = if asn_country.is_empty() {
            "ASN 注册国家暂未取得（RIPEstat 查询失败不会否定已读取的 ASN）".into()
        } else {
            format!(
                "ASN 注册国家 {asn_country}（RIPEstat RIR；统计日期 {}，本次查询 {}）",
                if text(asn, "result_time").is_empty() {
                    "未提供"
                } else {
                    text(asn, "result_time")
                },
                p::number(&asn["registered_queried_at"])
                    .filter(|v| *v > 0.0)
                    .map(&stamp)
                    .unwrap_or("未提供".into())
            )
        };
        (
            "ok",
            format!(
                "AS{n}{}；{registration}。当前 IP 出口归属国家 {exit_country}（Net.Coffee）。",
                if text(asn, "organization").is_empty() {
                    String::new()
                } else {
                    format!(" · {}", text(asn, "organization"))
                }
            ),
        )
    } else {
        ("unknown",format!("未取得与本轮出口 ASN 严格匹配的注册国家；出口地理国家 {exit_country}（Net.Coffee）不替代 ASN 注册国家。"))
    };
    rows.push(row(
        "asn",
        state,
        detail,
        false,
        "Net.Coffee 出口归属 / RIPEstat RIR",
    ));
    if target.protected() {
        let (state, detail, responses, sampled) = p::services(online);
        let mut reach = row("reachability", state, detail, true, "无账号凭据的诊断请求");
        reach["service_responses"] = responses;
        reach["sampled_at"] = json!(sampled);
        rows.push(reach);
    }
    // The ChatGPT / Codex service is measured on its own endpoints whenever the
    // round probes them. It is informational here: the supervised service is
    // the one this target protects, so a second service's reachability must
    // never decide whether the current target may launch.
    if let Some((state, detail, responses, sampled)) = p::chatgpt_services(online) {
        let mut reach = row(
            "chatgpt_reachability",
            state,
            detail,
            false,
            "无账号凭据的诊断请求",
        );
        reach["service_responses"] = responses;
        reach["sampled_at"] = json!(sampled);
        rows.push(reach);
    }
    for row in &mut rows {
        let keys: &[&str] = match text(row, "id") {
            "egress" | "timezone" | "locale" => &["trace", "geo"],
            "asn" => &["geo", "asn"],
            "reachability" => &["claude", "api"],
            "chatgpt_reachability" => &["chatgpt", "openai_api"],
            _ => &[],
        };
        if row["state"] == "unknown" {
            let error = p::query_errors(online, keys);
            if !error.is_empty() {
                row["query_error"] = json!(error);
                row["detail"] = json!(format!("{}；查询原因：{error}", text(row, "detail")));
            }
        }
    }
    let transition = &local["context_transition"];
    if transition["state"] == "sampling_unavailable" {
        let reasons: Vec<_> = transition["unavailable"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if reasons.iter().any(|v| !LOCAL_FIELDS.contains(v)) {
            for row in &mut rows {
                if matches!(
                    text(row, "id"),
                    "proxy" | "routing" | "egress" | "dns" | "stun" | "reachability"
                ) && row["state"] != "fail"
                {
                    row["state"] = json!("unknown");
                    row["detail"] = json!(format!(
                        "本轮代理或网络采样未能持续确认；未判定为网络切换。原因：{}",
                        reasons.join("、")
                    ));
                }
            }
        }
    }
    if truthy(&local["context_changed"]) {
        for row in &mut rows {
            if row["required"] == true {
                row["state"] = json!("unknown");
                row["detail"] = json!("检测期间网络上下文变化，请重新检测")
            }
        }
    } else {
        apply_risks(&mut rows, &automatic)
    }
    let blocked: Vec<_> = rows
        .iter()
        .filter(|v| v["required"] == true && matches!(text(v, "state"), "fail" | "unknown"))
        .map(|v| v["id"].clone())
        .collect();
    let message = if !blocked.is_empty() {
        format!(
            "启动预检未通过：{}",
            rows.iter()
                .filter(|v| blocked.contains(&v["id"]))
                .map(|v| format!("{}：{}", text(v, "name"), text(v, "detail")))
                .collect::<Vec<_>>()
                .join("；")
        )
    } else if !config.enabled {
        "启动策略尚未启用；检测已完成，但尚未允许受控启动".into()
    } else {
        "预检通过，仅限当前策略和采样范围".into()
    };
    let mut result = json!({"schema":1,"observed_at":now,"expires_at":now+30.0,"context":local.get("context").unwrap_or(&json!("")),"policy":policy,
        "rows":rows,"ready":blocked.is_empty() && config.enabled,"blocked":blocked,"message":message,"netcoffee_lookup":online["netcoffee_lookup"],
        "source_notices":p::source_notices(online),"egress_reference":{"ip":address,"country":country,"timezone":measured["timezone"],"checked_at":now,
        "context":local.get("context").unwrap_or(&json!(""))},"facts":automatic});
    if !target.protected() {
        result["launch_target"] = json!(target);
        result["authorization_scope"] = json!("observation");
    }
    Ok(result)
}
