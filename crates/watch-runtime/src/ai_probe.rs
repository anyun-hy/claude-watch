//! Bounded, credential-free AI service observations for the monitor UI.
//!
//! This preserves the Python collector's public JSON contract.  In particular,
//! an HTTP response is an observation, not evidence that an account works.
use crate::network_client::{NetworkClient, Receipt, Transport};
use claude_watch_core::network::public_unicast;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PROXY: &str = "http://127.0.0.1:7890";
pub const REFERENCE_URL: &str = "https://1.1.1.1/cdn-cgi/trace";
const CLAUDE: [(&str, bool); 2] = [
    ("https://claude.ai/cdn-cgi/trace", true),
    ("https://www.anthropic.com/cdn-cgi/trace", false),
];
const GPT: [(&str, bool); 2] = [
    ("https://chatgpt.com/cdn-cgi/trace", true),
    ("https://api.openai.com/v1/models", false),
];

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |v| v.as_secs_f64())
}
fn clip(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}
fn issue(stage: &str, code: &str, message: impl Into<String>) -> Value {
    json!({"stage":stage,"code":code,"message":clip(&message.into(), 256)})
}
fn endpoint_message(status: Option<u16>, problem: Option<&str>) -> &'static str {
    match problem {
        Some("timeout") | Some("budget_timeout") => "请求超时",
        Some(_) => "请求未完成",
        None => match status {
            Some(401) => "服务已响应；该端点需要认证",
            Some(403) => "服务已响应；访问被拒绝",
            Some(429) => "服务已响应；请求受限",
            Some(500..=599) => "服务已响应；服务端异常",
            _ => "服务已响应",
        },
    }
}

/// Minimal, injectable response boundary; tests never create real sockets.
pub trait AiProbeTransport: Send + Sync {
    fn get(&self, url: &str) -> ProbeResponse;
}
#[derive(Clone, Debug)]
pub struct ProbeResponse {
    pub http_status: Option<u16>,
    pub body: String,
    pub problem: Option<String>,
}
impl ProbeResponse {
    pub fn failed(code: &str) -> Self {
        Self {
            http_status: None,
            body: String::new(),
            problem: Some(code.into()),
        }
    }
}

/// Production adapter is deliberately backed by `NetworkClient`, retaining its
/// explicit loopback-proxy validation, disabled redirects and TLS defaults.
pub struct NetworkAiProbeTransport<T: Transport> {
    client: NetworkClient<T>,
}
impl<T: Transport> NetworkAiProbeTransport<T> {
    pub fn new(client: NetworkClient<T>) -> Self {
        Self {
            client: client
                .with_timeout(std::time::Duration::from_secs(6))
                .with_connect_timeout(std::time::Duration::from_secs(6)),
        }
    }
    fn receipt(receipt: Receipt) -> ProbeResponse {
        ProbeResponse {
            http_status: receipt.http_status,
            body: receipt.raw,
            problem: if receipt.http_status.is_some() {
                None
            } else {
                receipt.error
            },
        }
    }
}
impl<T: Transport> AiProbeTransport for NetworkAiProbeTransport<T> {
    fn get(&self, url: &str) -> ProbeResponse {
        Self::receipt(self.client.ai_probe(url))
    }
}

fn trace_ip(body: &str) -> Option<String> {
    body.lines()
        .find_map(|line| line.strip_prefix("ip="))
        .and_then(canonical_probe_ip)
}
/// Preserve Python's probe-local normalization of IPv4-mapped IPv6.  The core
/// classifier intentionally retains its existing representation for unrelated
/// callers.
fn canonical_probe_ip(value: &str) -> Option<String> {
    let value = value.trim();
    let mapped = value
        .parse::<std::net::Ipv6Addr>()
        .ok()
        .and_then(|address| address.to_ipv4_mapped())
        .map(|address| address.to_string());
    public_unicast(mapped.as_deref().unwrap_or(value))
}
fn endpoints(service: &str) -> Option<&'static [(&'static str, bool)]> {
    match service {
        "claude" => Some(&CLAUDE),
        "gpt" => Some(&GPT),
        _ => None,
    }
}
fn observed_endpoint<T: AiProbeTransport>(
    transport: &T,
    url: &str,
    errors: &mut Vec<Value>,
) -> (Value, Option<String>) {
    let started = now();
    let response = transport.get(url);
    let elapsed = ((now() - started).max(0.0) * 1000.0 * 1000.0).round() / 1000.0;
    if let Some(problem) = response.problem.as_deref() {
        let code = if matches!(problem, "timeout" | "budget_timeout") {
            "timeout"
        } else {
            problem
        };
        errors.push(issue("endpoint", code, format!("{url} 请求未完成")));
        return (
            json!({"url":url,"status":if code == "timeout" {"timeout"} else {"error"},"httpStatus":response.http_status,"elapsedMs":elapsed,"message":endpoint_message(response.http_status, Some(problem))}),
            None,
        );
    }
    let status = response.http_status;
    if !status.is_some_and(|code| (100..=599).contains(&code)) {
        errors.push(issue(
            "endpoint",
            "invalid_http_status",
            format!("{url} 返回无效 HTTP 状态"),
        ));
        return (
            json!({"url":url,"status":"error","httpStatus":status,"elapsedMs":elapsed,"message":"请求未完成"}),
            None,
        );
    }
    let status = status.unwrap();
    if status != 401 && !(200..300).contains(&status) {
        errors.push(issue(
            "endpoint",
            "http_status",
            format!("{url} 返回 HTTP {status}"),
        ));
    }
    (
        json!({"url":url,"status":"responded","httpStatus":status,"elapsedMs":elapsed,"message":endpoint_message(Some(status), None)}),
        Some(response.body),
    )
}

fn geo<T: AiProbeTransport>(transport: &T, address: &str, errors: &mut Vec<Value>) -> Value {
    let url = format!("https://ipinfo.io/{address}/json");
    let (endpoint, body) = observed_endpoint(transport, &url, errors);
    if endpoint["status"] != "responded"
        || !endpoint["httpStatus"]
            .as_u64()
            .is_some_and(|v| (200..300).contains(&v))
    {
        errors.push(issue("geo", "lookup_failed", "出口 IP 地理信息查询未完成"));
        return json!({});
    }
    let Ok(payload) = serde_json::from_str::<Value>(&body.unwrap_or_default()) else {
        errors.push(issue("geo", "invalid_json", "出口 IP 地理信息格式无效"));
        return json!({});
    };
    let country = payload.get("country").and_then(Value::as_str).unwrap_or("");
    if payload.get("error").is_some()
        || payload.get("ip").and_then(Value::as_str) != Some(address)
        || country.len() != 2
        || !country.is_ascii()
        || !country.bytes().all(|b| b.is_ascii_alphabetic())
    {
        errors.push(issue(
            "geo",
            "identity_mismatch",
            "地理信息未验证为当前出口 IP",
        ));
        return json!({});
    }
    let text = |key| {
        payload
            .get(key)
            .and_then(Value::as_str)
            .map(|v| clip(v, 256))
            .unwrap_or_default()
    };
    let country_name = text("country_name");
    let country_name = if country_name.is_empty() {
        country.to_ascii_uppercase()
    } else {
        country_name
    };
    json!({"countryCode":country.to_ascii_uppercase(),"country":country_name,"region":text("region"),"city":text("city"),"organization":text("org"),"ipTimezone":text("timezone")})
}

/// Collect a JSON value that decodes directly into the established Swift
/// `AIProbeResult`.  Invalid service input gets a bounded error object instead
/// of selecting a caller-provided URL.
pub fn collect<T: AiProbeTransport>(service: &str, transport: &T) -> Value {
    let started = now();
    let Some(targets) = endpoints(service) else {
        return json!({"service":service,"status":"error","startedAt":started,"finishedAt":now(),"exitIP":"","referenceIP":"","exitSource":"","countryCode":"","country":"","region":"","city":"","organization":"","ipTimezone":"","endpoints":[],"errors":[issue("collector","invalid_service","不支持的 AI 服务")],"details":["所有请求经本机 7890 HTTPS 代理；未跟随重定向或回退直连。"]});
    };
    let mut errors: Vec<Value> = Vec::new();
    let mut details: Vec<String> = Vec::new();
    let mut output: Vec<Value> = Vec::new();
    let mut exit_ip = None;
    for (url, primary) in targets {
        let (endpoint, body) = observed_endpoint(transport, url, &mut errors);
        if *primary {
            if endpoint["status"] == "responded"
                && endpoint["httpStatus"]
                    .as_u64()
                    .is_some_and(|v| (200..300).contains(&v))
            {
                exit_ip = body.as_deref().and_then(trace_ip);
                if exit_ip.is_none() {
                    errors.push(issue(
                        "exit",
                        "invalid_exit_ip",
                        "主服务 trace 未返回有效公网出口 IP",
                    ));
                }
            } else {
                details.push("主服务 trace 未成功，未使用其他端点替代 AI 出口。".into());
            }
        }
        output.push(endpoint);
    }
    let (reference, body) = observed_endpoint(transport, REFERENCE_URL, &mut errors);
    let reference_ip = if reference["status"] == "responded"
        && reference["httpStatus"]
            .as_u64()
            .is_some_and(|v| (200..300).contains(&v))
    {
        let value = body.as_deref().and_then(trace_ip);
        if value.is_none() {
            errors.push(issue(
                "reference",
                "invalid_reference_ip",
                "HTTP 参考未返回有效公网 IP",
            ));
        };
        value
    } else {
        errors.push(issue("reference", "unavailable", "HTTP 参考未完成"));
        None
    };
    let location = exit_ip
        .as_deref()
        .map(|ip| geo(transport, ip, &mut errors))
        .unwrap_or_else(|| json!({}));
    let all_timeout = output
        .iter()
        .chain(std::iter::once(&reference))
        .all(|row| row["status"] == "timeout");
    let status = if all_timeout {
        "timeout"
    } else if !errors.is_empty() || exit_ip.is_none() {
        "partial"
    } else {
        "complete"
    };
    details.push("所有请求经本机 7890 HTTPS 代理；未跟随重定向或回退直连。".into());
    let exit_source = if exit_ip.is_some() { targets[0].0 } else { "" };
    let exit_ip = exit_ip.unwrap_or_default();
    let mut result = json!({"service":service,"status":status,"startedAt":started,"finishedAt":now(),"exitIP":exit_ip,"referenceIP":reference_ip.unwrap_or_default(),"exitSource":exit_source,"countryCode":"","country":"","region":"","city":"","organization":"","ipTimezone":"","endpoints":output,"errors":errors,"details":details});
    for key in [
        "countryCode",
        "country",
        "region",
        "city",
        "organization",
        "ipTimezone",
    ] {
        if let Some(value) = location.get(key) {
            result[key] = value.clone();
        }
    }
    result
}

pub fn production<T: Transport>(client: NetworkClient<T>, service: &str) -> Value {
    collect(service, &NetworkAiProbeTransport::new(client))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_client::{Request, Response, TransportError};
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };
    struct Fake(HashMap<String, ProbeResponse>);
    impl AiProbeTransport for Fake {
        fn get(&self, url: &str) -> ProbeResponse {
            self.0
                .get(url)
                .cloned()
                .unwrap_or_else(|| ProbeResponse::failed("missing"))
        }
    }
    fn fake(service: &str, primary: u16, secondary: u16) -> Fake {
        let mut map = HashMap::new();
        let main = endpoints(service).unwrap();
        map.insert(
            main[0].0.into(),
            ProbeResponse {
                http_status: Some(primary),
                body: "ip=8.8.8.8\n".into(),
                problem: None,
            },
        );
        map.insert(
            main[1].0.into(),
            ProbeResponse {
                http_status: Some(secondary),
                body: String::new(),
                problem: None,
            },
        );
        map.insert(
            REFERENCE_URL.into(),
            ProbeResponse {
                http_status: Some(200),
                body: "ip=1.1.1.1\n".into(),
                problem: None,
            },
        );
        map.insert(
            "https://ipinfo.io/8.8.8.8/json".into(),
            ProbeResponse {
                http_status: Some(200),
                body: r#"{"ip":"8.8.8.8","country":"US","country_name":"United States"}"#.into(),
                problem: None,
            },
        );
        Fake(map)
    }
    #[test]
    fn gpt_401_is_response_not_auth_claim() {
        let value = collect("gpt", &fake("gpt", 200, 401));
        assert_eq!(value["status"], "complete");
        assert_eq!(value["endpoints"][1]["status"], "responded");
        assert_eq!(value["endpoints"][1]["httpStatus"], 401);
    }
    #[test]
    fn primary_403_does_not_use_secondary_exit() {
        let value = collect("claude", &fake("claude", 403, 200));
        assert_eq!(value["status"], "partial");
        assert_eq!(value["exitIP"], "");
        assert_eq!(value["referenceIP"], "1.1.1.1");
    }
    #[test]
    fn injected_timeout_remains_a_timeout_receipt() {
        let mut transport = fake("claude", 200, 200);
        transport
            .0
            .insert(CLAUDE[0].0.into(), ProbeResponse::failed("timeout"));
        transport
            .0
            .insert(CLAUDE[1].0.into(), ProbeResponse::failed("timeout"));
        transport
            .0
            .insert(REFERENCE_URL.into(), ProbeResponse::failed("timeout"));
        let value = collect("claude", &transport);
        assert_eq!(value["status"], "timeout");
        assert!(value["endpoints"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["status"] == "timeout"));
    }
    #[test]
    fn mapped_trace_ip_uses_python_ipv4_canonical_form() {
        assert_eq!(trace_ip("ip=::ffff:8.8.8.8\n"), Some("8.8.8.8".into()));
    }
    #[test]
    fn invalid_geo_is_discarded() {
        let mut transport = fake("claude", 200, 200);
        transport
            .0
            .get_mut("https://ipinfo.io/8.8.8.8/json")
            .unwrap()
            .body = r#"{"ip":"1.1.1.1","country":"US"}"#.into();
        let value = collect("claude", &transport);
        assert_eq!(value["countryCode"], "");
        assert_eq!(value["status"], "partial");
    }
    #[derive(Default)]
    struct NativeFake(Mutex<Vec<Request>>);
    impl Transport for NativeFake {
        fn get(&self, request: &Request) -> Result<Response, TransportError> {
            self.0.lock().unwrap().push(request.clone());
            Ok(Response {
                status: 401,
                headers: HashMap::new(),
                body: Vec::new(),
            })
        }
    }
    #[test]
    fn native_adapter_keeps_loopback_proxy_and_401_response() {
        let native = Arc::new(NativeFake::default());
        let client = NetworkClient::new(native.clone(), Some(PROXY.into())).unwrap();
        let response = NetworkAiProbeTransport::new(client).get("https://api.openai.com/v1/models");
        assert_eq!(response.http_status, Some(401));
        assert!(response.problem.is_none());
        let request = native.0.lock().unwrap().pop().unwrap();
        assert_eq!(request.proxy.as_deref(), Some(PROXY));
        assert_eq!(request.max_body, 32 * 1024);
        assert_eq!(request.timeout, std::time::Duration::from_secs(6));
        assert_eq!(
            request.connect_timeout,
            Some(std::time::Duration::from_secs(6))
        );
    }
}
