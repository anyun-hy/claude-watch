//! Fixed, proxy-only DNS and GeoIP reference lookup for supported AI hosts.
//!
//! This produces display metadata, never path or egress evidence.  In
//! particular, a DNS answer must not be promoted to a connection's observed
//! destination and an observed destination must not be promoted to proxy exit.
#![forbid(unsafe_code)]

use crate::network_client::{Request, Response, Transport};
use claude_watch_core::network::public_destination;
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const REFERENCE_TTL_SECONDS: i64 = 600;
pub const FAILURE_TTL_SECONDS: i64 = 300;
pub const MAX_RESPONSE_BYTES: usize = 65_536;
pub const DNS_URL: &str = "https://cloudflare-dns.com/dns-query";
pub const GEO_URL_PREFIX: &str = "https://ipinfo.io/";
const ROOTS: [&str; 5] = [
    "chatgpt.com",
    "openai.com",
    "oaiusercontent.com",
    "claude.ai",
    "anthropic.com",
];

fn epoch_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupRequest {
    pub host: String,
    pub observed_ip: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServerReference {
    pub host: String,
    pub basis: String,
    pub address: String,
    pub addresses: Vec<String>,
    pub country_code: String,
    pub country: String,
    pub region: String,
    pub city: String,
    pub status: String,
    pub message: String,
    pub queried_at: i64,
    pub expires_at: i64,
    pub dns_source: String,
    pub geo_source: String,
}

fn empty(host: &str, now: i64, message: &str) -> ServerReference {
    ServerReference {
        host: host.into(),
        basis: "dns_reference".into(),
        address: String::new(),
        addresses: vec![],
        country_code: String::new(),
        country: String::new(),
        region: String::new(),
        city: String::new(),
        status: "unavailable".into(),
        message: message.into(),
        queried_at: now,
        expires_at: now + FAILURE_TTL_SECONDS,
        dns_source: "Cloudflare DoH".into(),
        geo_source: "IPinfo".into(),
    }
}

pub fn normalize_host(input: &str) -> Option<String> {
    let mut candidate = input.trim().to_ascii_lowercase();
    if candidate.is_empty()
        || ["://", "/", "@", "?", "#", "[", "]"]
            .iter()
            .any(|bad| candidate.contains(bad))
    {
        return None;
    }
    if candidate.ends_with('.') {
        candidate.pop();
    }
    if let Some((host, port)) = candidate.rsplit_once(':') {
        if host.is_empty() || port.parse::<u16>().ok().filter(|port| *port > 0).is_none() {
            return None;
        }
        candidate = host.into();
    }
    if candidate.is_empty()
        || candidate.len() > 253
        || candidate.parse::<std::net::IpAddr>().is_ok()
    {
        return None;
    }
    let labels: Vec<_> = candidate.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return None;
    }
    ROOTS
        .iter()
        .any(|root| candidate == *root || candidate.ends_with(&format!(".{root}")))
        .then_some(candidate)
}

fn valid_ip(value: &str) -> Option<String> {
    public_destination(value).filter(|ip| !ip.starts_with("198.18.") && !ip.starts_with("198.19."))
}
fn json(response: Result<Response, crate::network_client::TransportError>) -> Option<Value> {
    let response = response.ok()?;
    (response.status == 200 && response.body.len() <= MAX_RESPONSE_BYTES).then_some(())?;
    serde_json::from_slice(&response.body).ok()
}
fn get<T: Transport>(transport: &T, url: String) -> Option<Value> {
    let is_dns = url.starts_with(DNS_URL);
    json(transport.get(&Request {
        url,
        proxy: Some(crate::network_client::DEFAULT_PROXY.into()),
        timeout: Duration::from_secs(8),
        connect_timeout: Some(Duration::from_secs(3)),
        max_body: MAX_RESPONSE_BYTES,
        safe_headers: if is_dns {
            vec![("Accept".into(), "application/dns-json".into())]
        } else {
            vec![]
        },
    }))
}
fn dns<T: Transport>(transport: &T, host: &str) -> Vec<String> {
    for (name, kind) in [("A", 1u64), ("AAAA", 28u64)] {
        let Some(payload) = get(transport, format!("{DNS_URL}?name={host}&type={name}")) else {
            continue;
        };
        if payload
            .get("Status")
            .and_then(Value::as_i64)
            .is_some_and(|status| status != 0)
        {
            continue;
        }
        let mut addresses: Vec<String> = payload
            .get("Answer")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|answer| {
                (answer.get("type").and_then(Value::as_u64) == Some(kind)).then_some(())?;
                answer
                    .get("data")
                    .and_then(Value::as_str)
                    .and_then(valid_ip)
            })
            .collect();
        addresses.sort();
        addresses.dedup();
        if !addresses.is_empty() {
            return addresses;
        }
    }
    vec![]
}
fn geo<T: Transport>(transport: &T, address: &str) -> Option<(String, String, String)> {
    let payload = get(transport, format!("{GEO_URL_PREFIX}{address}/json"))?;
    if payload.get("error").is_some() || payload.get("ip").and_then(Value::as_str) != Some(address)
    {
        return None;
    }
    let country = payload.get("country").and_then(Value::as_str)?;
    if country.len() != 2 || !country.bytes().all(|v| v.is_ascii_alphabetic()) {
        return None;
    }
    Some((
        country.to_ascii_uppercase(),
        payload
            .get("region")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into(),
        payload
            .get("city")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .into(),
    ))
}

pub struct ServerReferenceClient<T: Transport> {
    transport: Arc<T>,
    cache: Mutex<HashMap<String, ServerReference>>,
}
impl<T: Transport> ServerReferenceClient<T> {
    pub fn new(transport: Arc<T>) -> Self {
        Self {
            transport,
            cache: Mutex::new(HashMap::new()),
        }
    }
    pub fn lookup_at(&self, request: LookupRequest, now: i64) -> ServerReference {
        let Some(host) = normalize_host(&request.host) else {
            return empty("", now, "仅支持指定 AI 服务的域名或子域名。");
        };
        let observed = match request.observed_ip {
            Some(value) => match valid_ip(value.trim()) {
                Some(ip) => Some(ip),
                None => return empty(&host, now, "目标 IP 不是可查询的公网地址。"),
            },
            None => None,
        };
        let key = format!("{}|{}", host, observed.as_deref().unwrap_or("dns"));
        if let Some(value) = self
            .cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&key).cloned())
            .filter(|value| now < value.expires_at)
        {
            return value;
        }
        let (basis, addresses, dns_source) = if let Some(ip) = observed {
            ("observed_ip", vec![ip], "")
        } else {
            let addresses = dns(&*self.transport, &host);
            if addresses.is_empty() {
                return empty(&host, now, "DNS 参考查询未返回可用公网地址。");
            }
            ("dns_reference", addresses, "Cloudflare DoH")
        };
        let address = addresses[0].clone();
        let geo_value = geo(&*self.transport, &address);
        let complete = geo_value.is_some();
        let (country_code, region, city) = geo_value.unwrap_or_default();
        let value = ServerReference {
            host,
            basis: basis.into(),
            address,
            addresses,
            country_code,
            country: String::new(),
            region,
            city,
            status: if complete || basis == "dns_reference" {
                "ready"
            } else {
                "unavailable"
            }
            .into(),
            message: if complete {
                if basis == "dns_reference" {
                    "DNS 解析与 IP 归属仅作参考，非这条连接的实测目标 IP。"
                } else {
                    "基于已观测目标 IP 的归属参考。"
                }
            } else {
                "IP 归属参考查询未完成。"
            }
            .into(),
            queried_at: now,
            expires_at: now
                + if complete || basis == "dns_reference" {
                    REFERENCE_TTL_SECONDS
                } else {
                    FAILURE_TTL_SECONDS
                },
            dns_source: dns_source.into(),
            geo_source: "IPinfo".into(),
        };
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(key, value.clone());
        }
        value
    }
    pub fn lookup(&self, request: LookupRequest) -> ServerReference {
        self.lookup_at(request, epoch_now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_client::TransportError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Fake {
        replies: Mutex<Vec<Response>>,
        calls: AtomicUsize,
        requests: Mutex<Vec<Request>>,
    }
    impl Transport for Fake {
        fn get(&self, request: &Request) -> Result<Response, TransportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.requests.lock().unwrap().push(request.clone());
            self.replies.lock().unwrap().remove(0).pipe(Ok)
        }
    }
    trait Pipe: Sized {
        fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
            f(self)
        }
    }
    impl<T> Pipe for T {}
    fn response(body: &str) -> Response {
        Response {
            status: 200,
            headers: HashMap::new(),
            body: body.into(),
        }
    }
    #[test]
    fn rejects_private_and_fakeip_without_transport() {
        let fake = Arc::new(Fake {
            replies: Mutex::new(vec![]),
            calls: AtomicUsize::new(0),
            requests: Mutex::new(vec![]),
        });
        let client = ServerReferenceClient::new(fake.clone());
        for ip in ["127.0.0.1", "10.0.0.1", "198.18.0.1", "::1"] {
            let value = client.lookup_at(
                LookupRequest {
                    host: "openai.com".into(),
                    observed_ip: Some(ip.into()),
                },
                100,
            );
            assert_eq!(value.status, "unavailable");
        }
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn dns_reference_is_scoped_and_cached_by_ttl() {
        let fake = Arc::new(Fake {
            replies: Mutex::new(vec![
                response(r#"{"Answer":[{"type":1,"data":"1.1.1.1"}]}"#),
                response(
                    r#"{"ip":"1.1.1.1","country":"AU","region":"Queensland","city":"South Brisbane"}"#,
                ),
                response(r#"{"ip":"8.8.8.8","country":"US"}"#),
                response(r#"{"Answer":[{"type":1,"data":"1.0.0.1"}]}"#),
                response(r#"{"ip":"1.0.0.1","country":"AU"}"#),
            ]),
            calls: AtomicUsize::new(0),
            requests: Mutex::new(vec![]),
        });
        let client = ServerReferenceClient::new(fake.clone());
        let one = client.lookup_at(
            LookupRequest {
                host: "api.chatgpt.com:443".into(),
                observed_ip: None,
            },
            100,
        );
        let hit = client.lookup_at(
            LookupRequest {
                host: "api.chatgpt.com".into(),
                observed_ip: None,
            },
            101,
        );
        let observed = client.lookup_at(
            LookupRequest {
                host: "api.chatgpt.com".into(),
                observed_ip: Some("8.8.8.8".into()),
            },
            101,
        );
        let renewed = client.lookup_at(
            LookupRequest {
                host: "api.chatgpt.com".into(),
                observed_ip: None,
            },
            700,
        );
        assert_eq!(one.basis, "dns_reference");
        assert_eq!(hit.address, "1.1.1.1");
        assert_eq!(observed.basis, "observed_ip");
        assert_eq!(renewed.address, "1.0.0.1");
        assert_eq!(fake.calls.load(Ordering::SeqCst), 5);
        let requests = fake.requests.lock().unwrap();
        assert_eq!(requests[0].connect_timeout, Some(Duration::from_secs(3)));
        assert_eq!(
            requests[0].safe_headers,
            vec![("Accept".into(), "application/dns-json".into())]
        );
        assert!(requests[1].safe_headers.is_empty());
    }
}
