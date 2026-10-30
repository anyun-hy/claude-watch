//! Bounded DNS-path observation shared by the native engine and GUI bridge.
//!
//! This is deliberately a collector, not a policy engine: a receipt records
//! what the selected DNS and explicit-proxy HTTP paths returned in one round.
use crate::{
    commands::{ReadCommand, ReadRunner},
    network_client::{NetworkClient, Transport},
    storage::sha256,
};
use claude_watch_core::network::public_unicast;
use serde_json::{json, Value};
use std::{
    net::IpAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const SCOPE: &str = "dig/resolv.conf DNS 路径；HTTP 经 7890 参考";
const LIMIT: usize = 32 * 1024;
const TOTAL: Duration = Duration::from_secs(25);
const CONTEXT_TIMEOUT: Duration = Duration::from_millis(1500);
const DNS_TIMEOUT: Duration = Duration::from_secs(4);

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |v| v.as_secs_f64())
}
fn error(stage: &str, code: &str, message: &str) -> Value {
    json!({"stage":stage,"code":code,"message":message})
}
fn bounded_timeout(deadline: Instant, ordinary: Duration) -> Option<Duration> {
    let remaining = deadline.checked_duration_since(Instant::now())?;
    (!remaining.is_zero()).then_some(ordinary.min(remaining).max(Duration::from_millis(1)))
}
fn public_address(raw: &str) -> Option<(String, u8)> {
    if raw.contains('%') {
        return None;
    }
    let address: IpAddr = raw.trim().parse().ok()?;
    let address = match address {
        IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => IpAddr::V4(v6.to_ipv4_mapped().unwrap()),
        value => value,
    };
    // The Python collector normalizes IPv4-mapped IPv6 to IPv4 before both
    // validation and family reporting.
    let canonical = match address {
        IpAddr::V6(value) if value.to_ipv4_mapped().is_some() => {
            value.to_ipv4_mapped().unwrap().to_string()
        }
        value => value.to_string(),
    };
    let canonical = public_unicast(&canonical)?;
    let family = if canonical.parse::<std::net::Ipv4Addr>().is_ok() {
        4
    } else {
        6
    };
    Some((canonical, family))
}

/// Stable subset of `netstat -rn -f inet6`; no complete routing configuration
/// is returned to the UI or persisted in the receipt.
pub fn stable_inet6_defaults(output: &str) -> Option<String> {
    let mut columns = None;
    let mut defaults = Vec::new();
    for line in output.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let lowered: Vec<_> = fields.iter().map(|v| v.to_ascii_lowercase()).collect();
        if lowered.iter().any(|v| v == "destination") && lowered.iter().any(|v| v == "gateway") {
            columns = Some(lowered);
            continue;
        }
        if fields.first() != Some(&"default") {
            continue;
        }
        let keep = if let Some(names) = &columns {
            ["destination", "gateway", "netif"]
                .iter()
                .filter_map(|wanted| {
                    names
                        .iter()
                        .position(|v| v == wanted)
                        .and_then(|i| fields.get(i))
                        .copied()
                })
                .collect::<Vec<_>>()
        } else {
            fields.iter().take(2).copied().collect()
        };
        if !keep.is_empty() {
            defaults.push(keep.join(" "));
        }
    }
    columns.map(|_| {
        defaults.sort();
        defaults.dedup();
        if defaults.is_empty() {
            "absent".into()
        } else {
            defaults.join("\n")
        }
    })
}

fn context_snapshot<R: ReadRunner>(
    runner: &R,
    deadline: Instant,
    errors: &mut Vec<Value>,
) -> Option<String> {
    let commands = [
        ("dns", ReadCommand::ScutilDns),
        ("proxy", ReadCommand::ScutilProxy),
        ("route4", ReadCommand::RouteDefaultV4),
        ("route6", ReadCommand::NetstatRouteV6),
    ];
    let mut parts = Vec::new();
    for (name, command) in commands {
        let Some(timeout) = bounded_timeout(deadline, CONTEXT_TIMEOUT) else {
            errors.push(error(
                "context",
                "context_unknown",
                "网络上下文无法完整读取",
            ));
            return None;
        };
        let text = match runner.run(command, &[], timeout, LIMIT) {
            // Python discards child stderr.  A successful command with usable
            // stdout remains a usable context observation.
            Ok(out) if out.status == 0 => match out.text() {
                Ok(value) if !value.trim().is_empty() => value.to_owned(),
                _ => {
                    errors.push(error(
                        "context",
                        "context_unknown",
                        "网络上下文无法完整读取",
                    ));
                    return None;
                }
            },
            _ => {
                errors.push(error(
                    "context",
                    "context_unknown",
                    "网络上下文无法完整读取",
                ));
                return None;
            }
        };
        let text = if name == "route6" {
            match stable_inet6_defaults(&text) {
                Some(value) => value,
                None => {
                    errors.push(error(
                        "context",
                        "context_unknown",
                        "网络上下文无法完整读取",
                    ));
                    return None;
                }
            }
        } else {
            text
        };
        parts.push(format!("{name}\0{text}"));
    }
    Some(sha256(parts.join("\0").as_bytes()))
}

pub fn parse_dns_ns(output: &str, errors: &mut Vec<Value>) -> Vec<Value> {
    let mut observations = std::collections::BTreeMap::new();
    let mut saw = false;
    for line in output.lines() {
        // dig's quoted TXT form is fixed here; retain only unescaped fields.
        let quoted: Vec<_> = line.split('"').skip(1).step_by(2).collect();
        if quoted.len() < 2 || !quoted[0].trim().eq_ignore_ascii_case("ns") {
            continue;
        }
        saw = true;
        match public_address(quoted[1]) {
            Some((address, family)) => {
                observations.insert(address.clone(), json!({"address":address,"kind":"resolver","source":"akamai-whoami-ns","family":family}));
            }
            None => errors.push(error(
                "dns",
                "invalid_ns",
                "DNS 返回了非公网或无效的 NS 地址",
            )),
        }
    }
    if !saw {
        errors.push(error("dns", "no_ns", "DNS 返回中没有 NS 递归出口"));
    }
    let mut rows: Vec<_> = observations.into_values().collect();
    rows.sort_by_key(|row| {
        (
            row["family"].as_u64().unwrap_or(9),
            row["address"].as_str().unwrap_or("").to_owned(),
        )
    });
    rows
}
fn parse_http_ip(output: &str, errors: &mut Vec<Value>) -> Option<Value> {
    // The trace response carries the egress country for free (`loc=`); dropping
    // it forced every downstream geography verdict into "incomplete" even when
    // both addresses were observed.  Only a well-formed short code is kept —
    // anything else stays absent so the verdict still fails closed.
    let country = output.lines().find_map(|line| {
        let value = line.strip_prefix("loc=")?;
        let code = value.trim();
        (!code.is_empty()
            && code.len() <= 8
            && code.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then(|| code.to_owned())
    });
    for line in output.lines() {
        let Some(value) = line.strip_prefix("ip=") else {
            continue;
        };
        return match public_address(value) {
            Some((address, family)) => {
                let mut row = json!({"address":address,"kind":"http","source":"cloudflare-trace-via-7890","family":family});
                if let Some(code) = &country {
                    row["country"] = json!(code);
                }
                Some(row)
            }
            None => {
                errors.push(error(
                    "http",
                    "invalid_ip",
                    "HTTP 参考返回了非公网或无效 IP",
                ));
                None
            }
        };
    }
    errors.push(error("http", "no_ip", "HTTP 参考未返回 IP"));
    None
}

/// One attribution lookup for an observed resolver address, through the same
/// proxy as the HTTP reference.  The answer is enrichment only: any failure
/// leaves the observation unattributed, and the downstream geography verdict
/// keeps failing closed on that missing evidence rather than on a broken side
/// channel — so nothing here is recorded in `errors`.
fn resolver_country<T: Transport>(network: &NetworkClient<T>, address: &str) -> Option<String> {
    let receipt = network.metadata("geoip", address);
    let data = receipt.data.as_ref().filter(|data| data.is_object())?;
    (receipt.status == "complete"
        && receipt.http_status == Some(200)
        && receipt.query == address)
        .then_some(())?;
    // `/api/geoip/` reports the full country name in `country` and the ISO
    // code in `country_code`, so the code wins; a name-shaped value must
    // never be read as a country code.
    ["countryCode", "country_code", "country"]
        .iter()
        .filter_map(|key| data.get(*key).and_then(Value::as_str))
        .map(|country| country.trim().to_ascii_uppercase())
        .find(|country| country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_uppercase()))
}

/// Collect one compatibility receipt.  Failures deliberately remain in the
/// result so a partial sample can never be mistaken for a clean DNS path.
pub fn collect<R: ReadRunner, T: Transport>(runner: &R, network: &NetworkClient<T>) -> Value {
    let started = now();
    let deadline = Instant::now() + TOTAL;
    let mut errors = Vec::new();
    let mut observations = Vec::new();
    let before = context_snapshot(runner, deadline, &mut errors);
    let mut dns_timeout = false;
    let mut dns_ok = false;
    match bounded_timeout(deadline, DNS_TIMEOUT)
        .map(|timeout| runner.run(ReadCommand::DnsProbeWhoamiTxt, &[], timeout, LIMIT))
    {
        // Match the established collector: stderr is diagnostic-only when
        // dig exits successfully and provides bounded stdout.
        Some(Ok(out)) if out.status == 0 => match out.text() {
            Ok(text) => {
                let rows = parse_dns_ns(text, &mut errors);
                dns_ok = !rows.is_empty();
                observations.extend(rows);
            }
            Err(_) => errors.push(error("dns", "query_failed", "DNS 查询未完成")),
        },
        Some(Ok(_)) => errors.push(error("dns", "query_failed", "DNS 查询未完成")),
        Some(Err(problem)) => {
            let code = if problem.code == "command_timeout" {
                dns_timeout = true;
                "timeout"
            } else if problem.code == "command_output_oversize" {
                "output_limit"
            } else {
                "unavailable"
            };
            errors.push(error("dns", code, "DNS 查询未完成"));
        }
        None => {
            dns_timeout = true;
            errors.push(error("dns", "timeout", "DNS 查询未完成"));
        }
    }
    let receipt = network
        .clone()
        .with_timeout(Duration::from_secs(6))
        .with_connect_timeout(Duration::from_secs(3))
        .trace("https://www.cloudflare.com/cdn-cgi/trace");
    if receipt.status != "complete" {
        errors.push(error(
            "http",
            if receipt.status == "timeout" {
                "timeout"
            } else {
                "request_failed"
            },
            "HTTP 7890 参考未完成",
        ));
    } else if receipt.raw.len() > LIMIT {
        errors.push(error("http", "output_limit", "HTTP 7890 参考未完成"));
    } else if let Some(row) = parse_http_ip(&receipt.raw, &mut errors) {
        observations.push(row);
    }
    let after = context_snapshot(runner, deadline, &mut errors);
    // Resolver attribution is enrichment, not evidence.  A failed lookup stays
    // out of `errors` so it cannot downgrade a complete round; it only leaves
    // the verdict failing closed on missing attribution.
    if deadline
        .checked_duration_since(Instant::now())
        .is_some_and(|left| left > Duration::from_secs(3))
    {
        for row in observations.iter_mut() {
            if row["kind"] != "resolver" {
                continue;
            }
            let address = row["address"].as_str().unwrap_or_default();
            if let Some(country) = resolver_country(network, address) {
                row["country"] = json!(country);
            }
        }
    }
    let context_changed = before.is_some() && after.is_some() && before != after;
    let dns_error = errors.iter().any(|v| v["stage"] == "dns");
    let http_error = errors.iter().any(|v| v["stage"] == "http");
    let context_error = errors.iter().any(|v| v["stage"] == "context");
    let status = if dns_timeout {
        "timeout"
    } else if dns_error && !dns_ok {
        "error"
    } else if dns_error || http_error || context_error || context_changed {
        "partial"
    } else {
        "complete"
    };
    json!({"kind":"dns","status":status,"startedAt":started,"finishedAt":now(),"scope":SCOPE,"observations":observations,"errors":errors,"contextChanged":context_changed,"details":["DNS 使用 Akamai whoami TXT；HTTP 参考经本机 7890 访问 Cloudflare。","dig 走 resolv.conf DNS 路径，可能不同于浏览器的 DoH 或分域解析。"]})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::Output,
        network_client::{Request as HttpRequest, Response, TransportError},
    };
    use std::{collections::HashMap, sync::Arc};

    struct Runner {
        dns: std::result::Result<Vec<u8>, &'static str>,
        stderr: Vec<u8>,
    }
    impl ReadRunner for Runner {
        fn run(
            &self,
            command: ReadCommand,
            _: &[u8],
            _: Duration,
            _: usize,
        ) -> std::result::Result<Output, claude_watch_core::error::CoreError> {
            match command {
                ReadCommand::DnsProbeWhoamiTxt => match &self.dns {
                    Ok(stdout) => Ok(Output {
                        status: 0,
                        stdout: stdout.clone(),
                        stderr: self.stderr.clone(),
                    }),
                    Err(code) => Err(claude_watch_core::error::CoreError::new(code, "fixture")),
                },
                ReadCommand::NetstatRouteV6 => Ok(Output {
                    status: 0,
                    stdout: b"Internet6:\nDestination Gateway Flags Netif\n".to_vec(),
                    stderr: self.stderr.clone(),
                }),
                ReadCommand::ScutilDns | ReadCommand::ScutilProxy | ReadCommand::RouteDefaultV4 => {
                    Ok(Output {
                        status: 0,
                        stdout: b"context\n".to_vec(),
                        stderr: self.stderr.clone(),
                    })
                }
                _ => panic!("unexpected command"),
            }
        }
    }
    struct Http {
        body: Vec<u8>,
        geo: Option<Vec<u8>>,
    }
    impl Transport for Http {
        fn get(&self, request: &HttpRequest) -> std::result::Result<Response, TransportError> {
            assert_eq!(request.proxy.as_deref(), Some("http://127.0.0.1:7890"));
            if let Some(address) = request.url.strip_prefix("https://ip.net.coffee/api/geoip/") {
                let body = self
                    .geo
                    .clone()
                    .unwrap_or_else(|| format!(r#"{{"ip":"{address}","country_code":"JP"}}"#).into_bytes());
                return Ok(Response {
                    status: 200,
                    headers: HashMap::new(),
                    body,
                });
            }
            assert_eq!(request.url, "https://www.cloudflare.com/cdn-cgi/trace");
            Ok(Response {
                status: 200,
                headers: HashMap::new(),
                body: self.body.clone(),
            })
        }
    }
    fn client(body: &[u8]) -> NetworkClient<Http> {
        client_with_geo(body, None)
    }
    fn client_with_geo(body: &[u8], geo: Option<&[u8]>) -> NetworkClient<Http> {
        NetworkClient::new(
            Arc::new(Http {
                body: body.to_vec(),
                geo: geo.map(|v| v.to_vec()),
            }),
            Some("http://127.0.0.1:7890".into()),
        )
        .unwrap()
    }
    #[test]
    fn preserves_complete_python_wire_shape_with_fixed_proxy_reference() {
        let runner = Runner {
            dns: Ok(b"\"ns\" \"8.8.8.8\"\n\"ns\" \"2606:4700:4700::1111\"\n".to_vec()),
            stderr: vec![],
        };
        let result = collect(&runner, &client(b"ip=1.1.1.1\n"));
        assert_eq!(result["status"], "complete");
        assert_eq!(result["scope"], SCOPE);
        assert_eq!(result["observations"].as_array().unwrap().len(), 3);
        assert!(result["errors"].as_array().unwrap().is_empty());
    }
    #[test]
    fn resolver_attribution_enriches_without_downgrading_the_round() {
        let runner = Runner {
            dns: Ok(b"\"ns\" \"8.8.8.8\"\n".to_vec()),
            stderr: vec![],
        };
        let result = collect(
            &runner,
            &client_with_geo(b"ip=1.1.1.1\nloc=US\n", Some(b"{\"country_code\":\"US\"}")),
        );
        let resolver = result["observations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["kind"] == "resolver")
            .unwrap();
        assert_eq!(resolver["country"], "US");
        assert_eq!(result["status"], "complete");
        assert!(result["errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn failed_resolver_attribution_stays_silent_and_the_round_remains_complete() {
        let runner = Runner {
            dns: Ok(b"\"ns\" \"8.8.8.8\"\n".to_vec()),
            stderr: vec![],
        };
        // A broken side channel must not write into `errors`: the geography
        // verdict keeps failing closed on the missing attribution instead.
        let result = collect(
            &runner,
            &client_with_geo(b"ip=1.1.1.1\nloc=US\n", Some(b"{\"error\":\"rate limited\"}")),
        );
        let resolver = result["observations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["kind"] == "resolver")
            .unwrap();
        assert!(resolver.get("country").is_none());
        assert_eq!(result["status"], "complete");
        assert!(result["errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn http_reference_keeps_the_free_trace_country_when_well_formed() {
        let runner = Runner {
            dns: Ok(b"\"ns\" \"8.8.8.8\"\n".to_vec()),
            stderr: vec![],
        };
        let result = collect(&runner, &client(b"ip=1.1.1.1\nloc=US\n"));
        assert_eq!(result["observations"][1]["country"], "US");
        let blank = collect(&runner, &client(b"ip=1.1.1.1\nloc=\n"));
        assert!(blank["observations"][1].get("country").is_none());
        let junk = collect(&runner, &client(b"ip=1.1.1.1\nloc=?? too long\n"));
        assert!(junk["observations"][1].get("country").is_none());
    }
    #[test]
    fn dns_timeout_is_not_erased_by_a_successful_http_reference() {
        let runner = Runner {
            dns: Err("command_timeout"),
            stderr: vec![],
        };
        let result = collect(&runner, &client(b"ip=1.1.1.1\n"));
        assert_eq!(result["status"], "timeout");
        assert!(result["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["stage"] == "dns" && v["code"] == "timeout"));
    }
    #[test]
    fn fake_and_private_dns_answers_remain_partial_observations_not_success() {
        let runner = Runner {
            dns: Ok(b"\"ns\" \"198.18.1.2\"\n\"ns\" \"8.8.8.8\"\n".to_vec()),
            stderr: vec![],
        };
        let result = collect(&runner, &client(b"ip=10.0.0.1\n"));
        assert_eq!(result["status"], "partial");
        assert_eq!(result["observations"][0]["address"], "8.8.8.8");
        assert!(result["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["code"] == "invalid_ns"));
        assert!(result["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["stage"] == "http" && v["code"] == "invalid_ip"));
    }
    #[test]
    fn malformed_ipv6_route_is_context_unknown_not_an_absent_default() {
        assert_eq!(
            stable_inet6_defaults("Internet6:\nDestination Gateway Flags Netif\n"),
            Some("absent".into())
        );
        assert_eq!(stable_inet6_defaults("Internet6:\ndefault fe80::1\n"), None);
    }
    #[test]
    fn mapped_ipv6_dns_answer_uses_python_ipv4_canonical_form() {
        let mut errors = vec![];
        let rows = parse_dns_ns("\"ns\" \"::ffff:8.8.8.8\"\n", &mut errors);
        assert_eq!(
            rows,
            vec![
                json!({"address":"8.8.8.8","kind":"resolver","source":"akamai-whoami-ns","family":4})
            ]
        );
        assert!(errors.is_empty());
    }
    #[test]
    fn successful_dns_and_context_stdout_remain_usable_with_diagnostic_stderr() {
        let runner = Runner {
            dns: Ok(b"\"ns\" \"8.8.8.8\"\n".to_vec()),
            stderr: b"diagnostic warning\n".to_vec(),
        };
        let result = collect(&runner, &client(b"ip=1.1.1.1\n"));
        assert_eq!(result["status"], "complete");
        assert!(result["errors"].as_array().unwrap().is_empty());
    }
}
