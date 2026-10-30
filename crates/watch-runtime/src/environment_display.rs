//! Display-only environment receipts.
//!
//! This module deliberately accepts an already collected audit and a session
//! snapshot.  It has no system adapter and therefore cannot make an online
//! request, change a policy, or turn historical presentation data into launch
//! evidence.
use crate::storage::StateStore;
use claude_watch_core::{error::Result, presentation};
use serde_json::{json, Value};

const CACHE: &str = "environment-valid-samples.json";
const DISPLAY_ROWS: [&str; 4] = ["egress", "timezone", "locale", "asn"];
/// Display caches explain a transient external-query failure. They are never
/// current evidence and may not outlive the same five-minute display window.
const DISPLAY_CACHE_TTL: f64 = 300.0;

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}
fn number(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .filter(|value| value.is_finite() && *value >= 0.0)
}
fn row<'a>(rows: &'a mut [Value], id: &str) -> Option<&'a mut Value> {
    rows.iter_mut().find(|value| value["id"] == id)
}
fn query_error(online: &Value, keys: &[&str]) -> String {
    presentation::query_errors(online, keys)
}
fn source_time(online: &Value, key: &str, now: f64) -> f64 {
    number(&online["source_times"][key])
        .or_else(|| number(&online["asn"]["queried_at"]))
        .unwrap_or(now)
}
fn valid_ip(value: &Value) -> String {
    value
        .as_str()
        .filter(|value| claude_watch_core::network::public_unicast(value).is_some())
        .unwrap_or("")
        .to_owned()
}
fn local_snapshot(local: &Value, id: &str) -> Value {
    match id {
        "timezone" => json!({"timezone":local["timezone"]}),
        "locale" => json!({"locale":local["locale"],"date_format":local["date_format"]}),
        _ => json!({}),
    }
}
fn stable_context(audit: &Value) -> bool {
    let transition = audit["context_transition"]["state"]
        .as_str()
        .or_else(|| audit["display_facts"]["local"]["context_transition"]["state"].as_str());
    transition == Some("stable")
        && audit["display_facts"]["local"]["proxy"] == "ok"
        && audit["display_facts"]["local"]["tun"] == "ok"
}

/// A temporary sampling gap is not proof of a changed network. A saved display
/// sample can be shown only when the caller retained the same context ID and
/// no newly observed egress fact disagrees with it. This does not make the
/// sample current, usable for policy, or eligible to refresh the cache.
fn cache_context_matches(
    saved: &Value,
    context: &str,
    ip: &str,
    country: &str,
    local: &Value,
    id: &str,
    now: f64,
) -> bool {
    let Some(sampled) = number(&saved["sampled_at"]) else {
        return false;
    };
    !context.is_empty()
        && (0.0..=DISPLAY_CACHE_TTL).contains(&(now - sampled))
        && saved["context"] == context
        && (ip.is_empty() || saved["egress_ip"] == ip)
        && (country.is_empty() || saved["country"] == country)
        && saved["local_value"] == local_snapshot(local, id)
        && saved["row"].is_object()
        && saved["row"]["state"] == "ok"
}
fn reference_conflict(online: &Value) -> bool {
    let trace_ip = valid_ip(&online["trace"]["ip"]);
    let geo_ip = valid_ip(&online["geo"]["ip"]);
    let trace_country = text(&online["trace"], "loc");
    let geo_country = text(&online["geo"], "country");
    (!trace_ip.is_empty() && !geo_ip.is_empty() && trace_ip != geo_ip)
        || (!trace_country.is_empty() && !geo_country.is_empty() && trace_country != geo_country)
}

/// Adds every optional field consumed by Swift's `EnvironmentCheckRow` and
/// supplies descriptive values from the single captured sample.
fn present_rows(audit: &Value) -> Vec<Value> {
    let mut rows = audit["rows"].as_array().cloned().unwrap_or_default();
    let local = &audit["display_facts"]["local"];
    let online = &audit["display_facts"]["online"];
    let now = number(&audit["observed_at"]).unwrap_or(0.0);
    let address = valid_ip(&online["trace"]["ip"]);
    let country = text(&online["geo"], "country");
    let timezone = text(&online["geo"], "timezone");
    let asn = &online["asn"];
    for value in &mut rows {
        let id = text(value, "id");
        // Preserve audit's gate states. `info`/`cached` only describe evidence
        // in this receipt and therefore never feed its copied policy preview.
        let (current, reference, source) = match id.as_str() {
            "proxy" => {
                let entry = &local["tag"]["entry"];
                let endpoint = text(entry, "endpoint");
                let current = if text(entry, "state") == "verified" && !endpoint.is_empty() {
                    format!("{} · {endpoint}", text(local, "mode"))
                } else {
                    text(local, "mode")
                };
                (
                    current,
                    "运行进程与监听者身份".into(),
                    "进程清单 / 后台新鲜样本 / 控制接口".into(),
                )
            }
            "tun" => (
                text(local, "interface"),
                "代理与 TUN 路由同时存在".into(),
                "ifconfig / route".into(),
            ),
            "egress" => (
                if country.is_empty() {
                    address.clone()
                } else {
                    format!("{address} / {country}")
                },
                "Cloudflare 与 Net.Coffee 本轮出口一致".into(),
                "Cloudflare trace + Net.Coffee lookup".into(),
            ),
            "ip_history" => (
                address.clone(),
                "48 小时检测历史，仅提示变化".into(),
                "本轮出口 / 独立检测历史".into(),
            ),
            "timezone" => (
                text(local, "timezone"),
                if timezone.is_empty() {
                    "本轮出口时区未确认".into()
                } else {
                    timezone.clone()
                },
                "/etc/localtime / 本轮出口时区".into(),
            ),
            "locale" => (
                claude_watch_core::region::date_summary(local),
                "本轮出口国家的地区与日期格式".into(),
                "Foundation 日期模板 / AppleLocale / 本轮出口国家".into(),
            ),
            "ipv6" => (
                match text(local, "ipv6").as_str() {
                    "ok" => "已关闭".into(),
                    "fail" => "未关闭".into(),
                    _ => "未知".into(),
                },
                "实际 IPv6 状态；不证明无泄漏".into(),
                format!(
                    "networksetup -getinfo {}",
                    text(&audit["display_facts"]["network"], "service")
                ),
            ),
            "dns" => (
                text(&online["dns"], "current"),
                "同轮 HTTP 出口国家".into(),
                "Net.Coffee 权威 DNS 记录 + 同轮 HTTP 参考".into(),
            ),
            "stun" => (
                "".into(),
                if address.is_empty() {
                    "本轮 HTTP 出口未确认".into()
                } else {
                    address.clone()
                },
                "原生 UDP/STUN 逐台探针".into(),
            ),
            "guard" => (
                match text(local, "guard_state").as_str() {
                    "disabled" => "保护未启用".into(),
                    "ok" => "心跳已确认".into(),
                    _ => "保护心跳暂未确认".into(),
                },
                "当前后台真实状态".into(),
                "保护心跳 / 已启用状态 / 后台身份".into(),
            ),
            "routing" => (
                text(&local["rules"], "current"),
                "当前代理规则覆盖".into(),
                text(&local["rules"], "source"),
            ),
            "language" => (
                claude_watch_core::audit::preferred_language(&local["language"])
                    .unwrap_or_else(|| "未取得".into()),
                "英文偏好；与国家分开判断".into(),
                "Claude AppleLanguages / 系统 AppleLanguages".into(),
            ),
            "asn" => (
                if let Some(number) = asn["number"].as_i64().filter(|value| *value > 0) {
                    format!(
                        "AS{number}{} · ASN 注册 {} · 出口 {}",
                        if text(asn, "organization").is_empty() {
                            String::new()
                        } else {
                            format!(" {}", text(asn, "organization"))
                        },
                        if text(asn, "registered_country").is_empty() {
                            "未取得".into()
                        } else {
                            text(asn, "registered_country")
                        },
                        if country.is_empty() {
                            "未取得".into()
                        } else {
                            country.clone()
                        }
                    )
                } else {
                    "未取得".into()
                },
                "ASN 注册国家与本轮出口国家".into(),
                "Net.Coffee lookup / RIPEstat RIR".into(),
            ),
            "reachability" => (
                "网页/API 网络响应".into(),
                "不证明登录或账号可用".into(),
                "本轮无账号凭据的 HTTPS 请求".into(),
            ),
            _ => (String::new(), String::new(), String::new()),
        };
        value["current"] = json!(current);
        value["reference"] = json!(reference);
        value["source"] = json!(source);
        if matches!(id.as_str(), "egress" | "timezone" | "locale") {
            value["sampled_at"] = json!(source_time(online, "geo", now));
        } else if id == "asn" {
            value["sampled_at"] = json!(source_time(online, "asn", now));
        }
        // A confirmed disagreement is already `fail`; never disguise it as a
        // transient request failure.
        let keys: &[&str] = match id.as_str() {
            "egress" | "timezone" | "locale" => &["trace", "geo", "netcoffee"],
            "asn" => &["asn", "geo", "netcoffee"],
            "reachability" => &["claude", "api"],
            _ => &[],
        };
        let failure = query_error(online, keys);
        if value["state"] != "fail" && !failure.is_empty() {
            value["query_error"] = json!(failure);
        }
    }
    // A reused observation is a pass carrying an older timestamp — a STUN
    // receipt hit or a cached ASN query — not a fresh probe.  Marking it keeps
    // the row honest: the user reads "复用采样" instead of wondering why this
    // clock trails the rest of the page.  A fresh round finishes in seconds, so
    // anything older than 90 s was not probed in this round.
    for value in &mut rows {
        if value["state"] != "ok" {
            continue;
        }
        if let Some(sampled) = number(&value["sampled_at"]) {
            if now.is_finite() && now - sampled > 90.0 {
                value["sample_reused"] = json!(true);
            }
        }
    }
    rows
}

fn cache_rows(store: &StateStore, audit: &Value, rows: &mut [Value], persist: bool) -> Result<()> {
    let local = &audit["display_facts"]["local"];
    let online = &audit["display_facts"]["online"];
    let now = number(&audit["observed_at"]).unwrap_or(0.0);
    let ip = valid_ip(&online["trace"]["ip"]);
    let country = text(&online["trace"], "loc");
    let context = text(audit, "context_id");
    let path = store.paths.base().join(CACHE);
    let mut previous = store.read_json(&path, json!({"schema":1,"rows":{}}))?;
    if !previous["rows"].is_object() {
        previous["rows"] = json!({});
    }
    let write_eligible = stable_context(audit) && !ip.is_empty() && !reference_conflict(online);
    for id in DISPLAY_ROWS {
        let Some(value) = row(rows, id) else { continue };
        let failure = text(value, "query_error");
        if value["state"] == "ok" && write_eligible {
            let sampled = number(&value["sampled_at"]).unwrap_or(now);
            previous["rows"][id] = json!({"row":value,"sampled_at":sampled,"context":context,"egress_ip":ip,"country":country,"local_value":local_snapshot(local,id)});
            continue;
        }
        if value["state"] == "fail" || failure.is_empty() || reference_conflict(online) {
            continue;
        }
        // Local observations remain useful on an external-source failure.
        if id == "timezone" && !text(local, "timezone").is_empty() {
            value["state"] = json!("info");
            value["reference"] = json!("本机时区已读取；出口时区核对暂未完成");
        } else if id == "locale" && !text(local, "locale").is_empty() {
            value["state"] = json!("info");
            value["reference"] = json!("本机地区与日期已读取；出口地区核对暂未完成");
        } else if id == "egress" && !ip.is_empty() {
            value["state"] = json!("info");
            value["reference"] = json!("Cloudflare 已返回出口；交叉核对暂未完成");
        }
        let saved = previous["rows"][id].clone();
        if !cache_context_matches(&saved, &context, &ip, &country, local, id, now) {
            continue;
        }
        let sampled = number(&saved["sampled_at"]).expect("validated cache sample");
        value["current"] = saved["row"]["current"].clone();
        value["state"] = json!("cached");
        value["sampled_at"] = json!(sampled);
        value["reference"] = json!("上次有效结果");
        value["source"] = saved["row"]["source"].clone();
        value["detail"] = json!(format!(
            "本轮查询失败：{failure}。保留上次有效数据，仅供显示，不用于启动放行。\n{}",
            text(&saved["row"], "detail")
        ));
    }
    if persist && write_eligible {
        store.atomic_json(&path, &previous)?;
    }
    Ok(())
}

fn apply_session_rows(rows: &mut [Value], session: &Value, address: &str) -> Option<String> {
    let state = text(session, "state");
    let mut policy_message = None;
    if matches!(state.as_str(), "locked" | "unknown" | "pending") {
        let row_state = if state == "locked" { "fail" } else { "unknown" };
        let explanation = text(&session["reason"], "detail");
        let explanation = if explanation.is_empty() {
            "受控会话尚在核验".to_owned()
        } else {
            explanation
        };
        if let Some(row) = row(rows, "guard") {
            row["state"] = json!(row_state);
            row["name"] = json!("会话保护");
            row["current"] = json!(if row_state == "fail" {
                "已停止"
            } else {
                "正在核验"
            });
            row["detail"] = json!(format!("{explanation}；后台心跳与会话安全分别核对。"));
            row["required"] = json!(true);
            row["reference"] = json!("再次启动仍执行完整校验");
            row["source"] = json!("持久会话保护状态");
        }
        policy_message = Some(explanation);
    }
    let baseline = if matches!(state.as_str(), "idle" | "missing") {
        String::new()
    } else {
        text(&session["baseline"], "ip")
    };
    if baseline.is_empty() {
        return policy_message;
    }
    let locked_change =
        state == "locked" && text(&session["reason"], "code") == "egress_ip_changed";
    let different = !address.is_empty() && address != baseline;
    let (row_state, detail) = if locked_change {
        (
            "fail",
            "会话已因 IP 变化停止；再次启动必须完整核验并建立新基准。",
        )
    } else if different {
        ("fail", "当前出口 IP 与本次会话基准不同，保护正在处理。")
    } else if !address.is_empty() {
        ("ok", "当前出口 IP 与本次受控会话基准一致。")
    } else {
        ("unknown", "本轮公网 IP 尚未取得，保留会话基准。")
    };
    if let Some(row) = row(rows, "ip_history") {
        row["state"] = json!(row_state);
        row["current"] = json!(if address.is_empty() {
            "未取得"
        } else {
            address
        });
        row["reference"] = json!(format!("会话基准 {baseline}"));
        row["detail"] = json!(detail);
        row["source"] = json!("本轮实测出口 / 受控启动会话基准");
        row["required"] = json!(true);
    }
    if matches!(row_state, "fail" | "unknown") {
        Some(detail.to_owned())
    } else {
        policy_message
    }
}

/// Render the complete environment-page receipt from a single audit sample.
/// `audit` is retained untouched inside `policy_evaluation`; cache states and
/// source notices are display metadata and cannot make it ready.
pub fn receipt(store: &StateStore, audit: Value, session: Value, persist: bool) -> Result<Value> {
    // Both display pages use the mature five-minute presentation window.
    // The original launch audit and its 30-second evidence window are not modified.
    let display_expires = number(&audit["observed_at"]).unwrap_or(0.0) + 300.0;
    let mut rows = present_rows(&audit);
    cache_rows(store, &audit, &mut rows, persist)?;
    let address = valid_ip(&audit["display_facts"]["online"]["trace"]["ip"]);
    let policy_message = apply_session_rows(&mut rows, &session, &address);
    let mut preview = audit.clone();
    preview["purpose"] = json!("launch_requirements_preview");
    preview["grants_launch_permission"] = json!(false);
    preview["expires_at"] = json!(display_expires);
    preview["session_guard"] = session.clone();
    let mut policy_rows = preview["rows"].as_array().cloned().unwrap_or_default();
    let policy_message =
        apply_session_rows(&mut policy_rows, &session, &address).or(policy_message);
    preview["rows"] = json!(policy_rows);
    if let Some(message) = policy_message {
        preview["ready"] = json!(false);
        let row_blocks: Vec<_> = ["guard", "ip_history"]
            .into_iter()
            .filter(|row| {
                preview["rows"]
                    .as_array()
                    .and_then(|rows| rows.iter().find(|value| value["id"] == *row))
                    .is_some_and(|value| {
                        matches!(value["state"].as_str(), Some("fail" | "unknown"))
                            && value["required"] == true
                    })
            })
            .collect();
        if let Some(blocked) = preview["blocked"].as_array_mut() {
            for row in row_blocks {
                if !blocked.iter().any(|value| value == row) {
                    blocked.push(json!(row));
                }
            }
        }
        preview["message"] = json!(message);
    }
    preview.as_object_mut().map(|v| v.remove("display_facts"));
    let mut output = audit;
    output["status"] = json!("ok");
    output["purpose"] = json!("environment_detection");
    output["grants_launch_permission"] = json!(false);
    output["expires_at"] = json!(display_expires);
    output["rows"] = json!(rows);
    output["candidates"] = json!([]);
    output["session_guard"] = session;
    output["source_notices"] = presentation::source_notices(&output["display_facts"]["online"]);
    output["message"] = json!("本轮实测结果；未知项保留未知。受控启动仍需独立预检。");
    output["policy_evaluation"] = preview;
    output.as_object_mut().map(|v| v.remove("display_facts"));
    Ok(output)
}

/// Make setup inspect/detect/preview output safe for the production Swift
/// decoder. Existing values are preserved; absent presentation fields are
/// explicit empty strings rather than omitted or null.
pub fn setup_value_rows(value: &Value) -> Vec<Value> {
    let values = value.get("values").unwrap_or(value);
    ["proxy_mode", "proxy_url", "proxy_group", "node", "network_service", "country", "ip", "timezone", "locale", "language"]
        .into_iter()
        .map(|id| json!({"id":id,"title":id,"current":values[id].as_str().unwrap_or(""),"target":"","proposed":"","source":"本轮自动检测","target_source":"","proposed_source":""}))
        .collect()
}
