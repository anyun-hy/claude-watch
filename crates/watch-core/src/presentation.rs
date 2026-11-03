//! Human-readable evidence. Presentation does not change the audit pass criteria.
use crate::network::public_unicast;
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}
pub fn number(v: &Value) -> Option<f64> {
    v.as_f64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .filter(|v| v.is_finite())
}
pub fn clip(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}
pub fn http_result(status: &Value) -> (&'static str, String) {
    let Some(status) = status.as_i64().filter(|v| *v > 0) else {
        return ("unknown", "未收到有效 HTTP 响应".into());
    };
    match status {
        401 => ("ok", "HTTP 401，需要账号认证（本轮未携带凭据）".into()),
        403 => (
            "warn",
            "HTTP 403，访问被拒绝；不能仅据此判断是地区或账号问题".into(),
        ),
        429 => ("warn", "HTTP 429，请求受到限流".into()),
        500..=i64::MAX => ("warn", format!("HTTP {status}，服务端错误")),
        400..=499 => ("warn", format!("HTTP {status}，请求未被接受")),
        _ => ("ok", format!("HTTP {status}，已收到响应")),
    }
}
pub fn service_response(
    service: &str,
    response: &Value,
    status: &Value,
) -> (&'static str, String, Option<String>) {
    let (fallback_state, fallback_detail) = http_result(status);
    if !response.is_object() {
        return (fallback_state, fallback_detail, None);
    }
    let expected: &[&str] = match service {
        // Current observations check the homepage; keep trace receipts
        // readable for snapshots made by earlier runtime versions.
        "claude" => &["https://claude.ai/", "https://claude.ai/cdn-cgi/trace"],
        "chatgpt" => &[
            "https://chatgpt.com/",
            "https://chatgpt.com/cdn-cgi/trace",
        ],
        "openai_api" => &["https://api.openai.com/v1/models"],
        _ => &["https://api.anthropic.com/v1/models"],
    };
    let source = clip(text(response, "source"), 160);
    let observed = response["http_status"].as_i64();
    // 旧扁平字段只在回执里没有 http_status 时才作数；回执自带状态码时以回执为准。
    // 之前要求两者必须相等，一旦运行时不写旧字段，成功回执会被判成“未收到有效响应”。
    let conflict = match status.as_i64() {
        Some(legacy) => observed != Some(legacy),
        None => false,
    };
    if !expected.contains(&source.as_str()) || observed.is_none() || conflict {
        return (fallback_state, fallback_detail, Some(expected[0].into()));
    }
    let code = observed.unwrap_or(0);
    let (fallback_state, fallback_detail) = http_result(&json!(code));
    let reached = response["transport_reached"] == true;
    if matches!(service, "api" | "openai_api")
        && response["status"] == "ok"
        && reached
        && response["access"] == "authentication_required"
        && code == 401
    {
        return (
            "ok",
            "网络可达；API HTTP 401，未提供密钥，需要认证。".into(),
            Some(source),
        );
    }
    if matches!(service, "claude" | "chatgpt")
        && response["status"] == "ok"
        && reached
        && response["access"] == "challenge"
        && code == 403
        && response["challenge"]["provider"] == "cloudflare"
        && response["challenge"]["mitigated"] == "challenge"
    {
        return (
            "ok",
            "网络可达；网页 HTTP 403，需要浏览器验证（Cloudflare challenge）。".into(),
            Some(source),
        );
    }
    if response["status"] == "unknown" || response["access"] == "network_error" || !reached {
        let error = text(response, "error");
        let code = text(response, "error_code");
        let detail = if !error.is_empty() {
            error
        } else if !code.is_empty() {
            code
        } else {
            "请求未完成"
        };
        return (
            "unknown",
            format!("网络未确认：{}", clip(detail, 240)),
            Some(source),
        );
    }
    (fallback_state, fallback_detail, Some(source))
}
pub fn service_label(service: &str, response: &Value, status: &Value) -> String {
    let (state, detail, _) = service_response(service, response, status);
    if state == "ok"
        && matches!(service, "claude" | "chatgpt")
        && response["access"] == "challenge"
    {
        return "需要浏览器验证".into();
    }
    if state == "ok"
        && matches!(service, "api" | "openai_api")
        && response["access"] == "authentication_required"
    {
        return "未提供密钥".into();
    }
    if state == "unknown" {
        return "网络未确认".into();
    }
    let code = if response.is_object() {
        &response["http_status"]
    } else {
        status
    };
    code.as_i64().map_or(detail, |n| format!("HTTP {n}"))
}
pub fn services(online: &Value) -> (&'static str, String, Value, Option<f64>) {
    let values = &online["service_responses"];
    let web = service_response("claude", &values["claude"], &online["claude"]);
    let api = service_response("api", &values["api"], &online["api"]);
    let state = if [web.0, api.0].contains(&"unknown") {
        "unknown"
    } else if [web.0, api.0].contains(&"warn") {
        "warn"
    } else {
        "ok"
    };
    let detail = format!(
        "网页：{}\nAPI：{}\n范围：网络可达不代表已登录、账号可用或订阅状态。",
        web.1.trim_end_matches(['。', '；']),
        api.1.trim_end_matches(['。', '；'])
    );
    let sampled = values
        .as_object()
        .into_iter()
        .flat_map(|v| v.values())
        .filter_map(|v| number(&v["queried_at"]))
        .filter(|v| *v > 0.0)
        .max_by(f64::total_cmp);
    (
        state,
        detail,
        json!({"claude":values["claude"],"api":values["api"]}),
        sampled,
    )
}
/// The ChatGPT / Codex service observations, when this round probed them.
/// `None` keeps the card out of the grid entirely, so a round that never
/// measured these endpoints cannot render a stale or invented verdict.
pub fn chatgpt_services(online: &Value) -> Option<(&'static str, String, Value, Option<f64>)> {
    let values = &online["service_responses"];
    if !values["chatgpt"].is_object() && !values["openai_api"].is_object() {
        return None;
    }
    let web = service_response("chatgpt", &values["chatgpt"], &Value::Null);
    let api = service_response("openai_api", &values["openai_api"], &Value::Null);
    let state = if [web.0, api.0].contains(&"unknown") {
        "unknown"
    } else if [web.0, api.0].contains(&"warn") {
        "warn"
    } else {
        "ok"
    };
    let detail = format!(
        "网页：{}\nAPI：{}\n范围：网络可达不代表已登录、账号可用或订阅状态。",
        web.1.trim_end_matches(['。', '；']),
        api.1.trim_end_matches(['。', '；'])
    );
    let sampled = ["chatgpt", "openai_api"]
        .iter()
        .filter_map(|key| number(&values[*key]["queried_at"]))
        .filter(|value| *value > 0.0)
        .max_by(f64::total_cmp);
    Some((
        state,
        detail,
        json!({"chatgpt":values["chatgpt"],"openai_api":values["openai_api"]}),
        sampled,
    ))
}
pub fn query_errors(online: &Value, keys: &[&str]) -> String {    keys.iter()
        .filter_map(|key| {
            online["query_errors"]
                .get(key)
                .filter(|v| v.is_object())
                .map(|v| {
                    let source = v.get("source").and_then(Value::as_str).unwrap_or(key);
                    let message = v
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("查询未完成");
                    clip(&format!("{source}：{message}"), 400)
                })
        })
        .collect::<Vec<_>>()
        .join("；")
}
pub fn source_notices(online: &Value) -> Value {
    let mut grouped = Vec::<Value>::new();
    for (key, error) in online["query_errors"].as_object().into_iter().flatten() {
        if !error.is_object() || matches!(key.as_str(), "claude" | "api") {
            continue;
        }
        let source = clip(
            error
                .get("source")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or(key),
            120,
        );
        let detail = clip(
            error
                .get("message")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or("查询未完成"),
            240,
        );
        let severity = if key == "egress_consistency" {
            "fail"
        } else {
            "warn"
        };
        let value = json!({"id":clip(key,80),"title":source,"detail":detail,"severity":severity});
        if let Some(index) = grouped.iter().position(|v| v["title"] == source) {
            if severity == "fail" && grouped[index]["severity"] != "fail" {
                grouped[index] = value
            }
        } else {
            grouped.push(value)
        }
    }
    json!(grouped)
}
fn stun_status(s: &str) -> &'static str {
    match s {
        "ok" => "成功",
        "timeout" => "等待 UDP 回包超时",
        "network_error" => "网络失败",
        "unexpected_sender" => "收到非目标服务器响应",
        "invalid_response" => "报文校验失败",
        "budget_exhausted" => "总预算耗尽",
        _ => "未完成",
    }
}
fn stamp(v: &Value, time: &impl Fn(f64) -> String) -> String {
    number(v)
        .filter(|v| *v > 0.0)
        .map(time)
        .unwrap_or("未提供".into())
}
pub fn stun(
    stun: &Value,
    candidates: &BTreeSet<String>,
    reference: &BTreeSet<String>,
    time: impl Fn(f64) -> String,
) -> (String, Option<f64>, Value) {
    let empty = Vec::new();
    let observations = stun["observations"].as_array().unwrap_or(&empty);
    let sampled = number(&stun["started_at"])
        .zip(number(&stun["finished_at"]))
        .filter(|(s, f)| f >= s)
        .map(|(_, f)| f);
    // Failures lead: a server that did not answer must never sit below the
    // fold while every visible row reads "成功".  `false` sorts first.
    let mut ordered: Vec<&Value> = observations.iter().filter(|v| v.is_object()).collect();
    ordered.sort_by_key(|row| {
        let answered =
            row["status"] == "ok" && row["accepted"] != false && row["deadline_exceeded"] != true;
        answered
    });
    let answered = ordered
        .iter()
        .filter(|row| {
            row["status"] == "ok" && row["accepted"] != false && row["deadline_exceeded"] != true
        })
        .count();
    let mut lines = vec![format!(
        "汇总：{} 个公网候选；参考：{}；{}",
        candidates.len(),
        if reference.is_empty() {
            "无".into()
        } else {
            reference.iter().cloned().collect::<Vec<_>>().join(", ")
        },
        if candidates.is_empty() {
            "未取得可用的公网 STUN 回包，无法确认 UDP 出口".to_string()
        } else {
            format!("{answered} / {} 台服务器应答", ordered.len())
        }
    )];
    for row in ordered.into_iter().take(16) {
        let server = clip(
            if text(row, "server").is_empty() {
                "未知服务器"
            } else {
                text(row, "server")
            },
            160,
        );
        let endpoint = row["port"]
            .as_i64()
            .filter(|v| (1..65536).contains(v))
            .map_or(server.clone(), |n| format!("{server}:{n}"));
        let display = stun_status(text(row, "status"));
        let address = row["address"]
            .as_str()
            .and_then(public_unicast)
            .unwrap_or_default();
        let late = row["deadline_exceeded"] == true || row["accepted"] == false;
        let final_status = format!(
            "；最终状态：{display}{}",
            if late {
                "（超出整轮时限，未采纳）"
            } else {
                ""
            }
        );
        let attempts = row["attempts"].as_array().unwrap_or(&empty);
        let mut parts = Vec::new();
        if !attempts.is_empty() {
            for attempt in attempts.iter().take(8).filter(|v| v.is_object()) {
                let label = attempt["attempt"]
                    .as_i64()
                    .filter(|v| *v > 0)
                    .map_or("一次尝试".into(), |v| format!("第{v}次"));
                let started = stamp(&attempt["started_at"], &time);
                let finished = stamp(&attempt["finished_at"], &time);
                let status = text(attempt, "status");
                let suffix = if status == "ok" && late {
                    "已收到回包，但超出整轮时限，未采纳".into()
                } else if status == "ok" {
                    format!(
                        "成功{}",
                        if address.is_empty() {
                            String::new()
                        } else {
                            format!("，出口 {address}")
                        }
                    )
                } else {
                    let stage = match text(attempt, "stage") {
                        "resolve" => "域名解析",
                        "send" => "发送请求",
                        "receive" => "等待 UDP 回包",
                        "validation" => "报文校验",
                        "budget" => "预算",
                        _ => "",
                    };
                    let mut reason = clip(text(attempt, "error"), 160);
                    if !stage.is_empty() {
                        reason = format!(
                            "{stage}{}",
                            if reason.is_empty() {
                                String::new()
                            } else {
                                format!("：{reason}")
                            }
                        );
                    }
                    let code = clip(text(attempt, "error_code"), 80);
                    if !code.is_empty() {
                        if !reason.is_empty() {
                            reason.push('；')
                        };
                        reason += &format!("错误代码 {code}")
                    }
                    if let Some(errno) = attempt["errno"].as_i64() {
                        if !reason.is_empty() {
                            reason.push('；')
                        };
                        reason += &format!("系统错误 {errno}")
                    }
                    format!(
                        "{}{}",
                        stun_status(status),
                        if reason.is_empty() {
                            String::new()
                        } else {
                            format!("：{reason}")
                        }
                    )
                };
                parts.push(format!("{label} {started}–{finished} {suffix}"));
            }
            let joined = if parts.is_empty() {
                display.into()
            } else {
                parts.join("；")
            };
            lines.push(format!(
                "{endpoint}：{joined}{}{final_status}",
                if address.is_empty() {
                    String::new()
                } else {
                    format!("；最终出口 {address}")
                }
            ));
        } else {
            lines.push(format!(
                "{endpoint}：{display}{}；未提供逐次尝试记录{final_status}",
                if address.is_empty() {
                    String::new()
                } else {
                    format!("；出口 {address}")
                }
            ));
        }
    }
    if observations.len() > 16 {
        lines.push(format!(
            "其余 {} 台服务器结果已省略。",
            observations.len() - 16
        ))
    }
    (lines.join("\n"), sampled, json!(observations))
}

#[cfg(test)]
mod chatgpt_service_tests {
    use super::*;
    use serde_json::json;

    fn observation(source: &str, status: u16, access: &str) -> Value {
        let challenge = if access == "challenge" {
            json!({"provider":"cloudflare","mitigated":"challenge"})
        } else {
            Value::Null
        };
        json!({"source":source,"status":"ok","http_status":status,"transport_reached":true,
               "access":access,"challenge":challenge,"queried_at":10.0})
    }

    #[test]
    fn a_round_that_probed_chatgpt_reports_its_own_state_and_endpoints() {
        let online = json!({"service_responses":{
            "chatgpt": observation("https://chatgpt.com/", 403, "challenge"),
            "openai_api": observation("https://api.openai.com/v1/models", 401, "authentication_required")
        }});
        let (state, detail, responses, sampled) =
            chatgpt_services(&online).expect("both endpoints were measured");
        assert_eq!(state, "ok");
        assert!(detail.contains("需要浏览器验证"), "{detail}");
        assert!(detail.contains("API HTTP 401"), "{detail}");
        assert_eq!(responses["chatgpt"]["source"], "https://chatgpt.com/");
        assert_eq!(sampled, Some(10.0));
    }

    #[test]
    fn an_unmeasured_round_renders_no_card_instead_of_an_invented_verdict() {
        let online = json!({"service_responses":{
            "claude": observation("https://claude.ai/", 403, "challenge"),
            "api": observation("https://api.anthropic.com/v1/models", 401, "authentication_required")
        }});
        assert!(chatgpt_services(&online).is_none());
    }

    #[test]
    fn an_unreachable_chatgpt_endpoint_is_reported_as_unconfirmed() {
        let online = json!({"service_responses":{
            "chatgpt": json!({"source":"https://chatgpt.com/","status":"unknown","http_status":Value::Null,
                              "transport_reached":false,"access":"unknown","error":"timeout: connect"}),
            "openai_api": observation("https://api.openai.com/v1/models", 401, "authentication_required")
        }});
        let (state, detail, _, _) = chatgpt_services(&online).expect("the round probed the service");
        assert_eq!(state, "unknown");
        // Same wording the Claude card uses for an endpoint that never answered,
        // so an unreachable service is never rendered as a pass.
        assert!(detail.contains("未收到有效 HTTP 响应"), "{detail}");
    }
}
