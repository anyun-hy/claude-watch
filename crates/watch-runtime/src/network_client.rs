//! Bounded, credential-free egress and service observations.
//!
//! This deliberately does not use the TAG control client: a TAG server address is
//! a local control-plane destination, while these receipts describe the proxy
//! egress observed by public HTTPS origins.
#![forbid(unsafe_code)]

use crate::storage::{sha256, OperationLock, StateStore};
use claude_watch_core::{config::valid_loopback_proxy, network::public_unicast};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::Read,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const CACHE_TTL: Duration = Duration::from_secs(300);
pub const MAX_BODY: usize = 512 * 1024;
pub const DEFAULT_PROXY: &str = "http://127.0.0.1:7890";
pub const FAST_EGRESS_URL: &str = "https://www.cloudflare.com/cdn-cgi/trace";
pub const CONTEXT_MAX_AGE: Duration = Duration::from_secs(30);
const NETCOFFEE: &str = "https://ip.net.coffee";
const DISK_SINGLEFLIGHT_WAIT: Duration = Duration::from_secs(5);

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |v| v.as_secs_f64())
}
fn clip(s: impl AsRef<str>, n: usize) -> String {
    s.as_ref().chars().take(n).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub url: String,
    pub proxy: Option<String>,
    pub timeout: Duration,
    /// Bound only the connect/proxy-negotiation/TLS phase when a caller has a
    /// historical connect-time contract in addition to its total deadline.
    pub connect_timeout: Option<Duration>,
    /// Maximum response body bytes; zero reads only the status and headers.
    pub max_body: usize,
    /// Fixed, caller-owned protocol headers.  This is intentionally not a
    /// general user-input header surface.
    pub safe_headers: Vec<(String, String)>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError {
    pub code: String,
    pub detail: String,
}
impl TransportError {
    pub fn new(code: &str, detail: &str) -> Self {
        Self {
            code: code.into(),
            detail: clip(detail, 240),
        }
    }
}
pub trait Transport: Send + Sync + 'static {
    fn get(&self, request: &Request) -> Result<Response, TransportError>;
}

/// The production transport. Redirects and proxy bypass are disabled.  HTTPS
/// requests require ureq's `rustls` feature; callers get a receipt error when
/// that capability was intentionally omitted from a build.
#[derive(Default)]
pub struct UreqTransport;
impl Transport for UreqTransport {
    fn get(&self, request: &Request) -> Result<Response, TransportError> {
        let mut config = ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(request.timeout));
        if let Some(timeout) = request.connect_timeout {
            config = config.timeout_connect(Some(timeout));
        }
        if let Some(proxy) = &request.proxy {
            let proxy = ureq::Proxy::new(proxy)
                .map_err(|_| TransportError::new("invalid_proxy", "诊断代理格式无效"))?;
            config = config.proxy(Some(proxy));
        } else {
            config = config.proxy(None);
        }
        let agent: ureq::Agent = config.build().into();
        let mut call = agent
            .get(&request.url)
            .header("Accept", "application/json, text/plain;q=0.9")
            .header("Accept-Encoding", "identity")
            .header("User-Agent", "ClaudeWatch-Diagnostics/1.0")
            .header("Connection", "close");
        for (name, value) in &request.safe_headers {
            call = call.header(name, value);
        }
        let mut response = call.call().map_err(|e| {
            TransportError::new(
                if matches!(e, ureq::Error::Timeout(_)) {
                    "timeout"
                } else {
                    "transport"
                },
                &e.to_string(),
            )
        })?;
        let status = response.status().as_u16();
        let mut body = Vec::new();
        if request.max_body > 0 {
            response
                .body_mut()
                .with_config()
                .limit(request.max_body as u64 + 1)
                .reader()
                .take(request.max_body as u64 + 1)
                .read_to_end(&mut body)
                .map_err(|e| {
                    let inner = e
                        .get_ref()
                        .and_then(|value| value.downcast_ref::<ureq::Error>());
                    let code = if e.kind() == std::io::ErrorKind::TimedOut
                        || matches!(inner, Some(ureq::Error::Timeout(_)))
                    {
                        "timeout"
                    } else if matches!(inner, Some(ureq::Error::BodyExceedsLimit(_))) {
                        "body_too_large"
                    } else {
                        "read_failed"
                    };
                    TransportError::new(code, &e.to_string())
                })?;
        }
        if body.len() > request.max_body {
            return Err(TransportError::new("body_too_large", "响应超过上限"));
        }
        let headers = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.to_string().to_ascii_lowercase(), v.to_string()))
            })
            .collect();
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Receipt {
    pub kind: String,
    pub query: String,
    pub source_url: String,
    pub queried_at: f64,
    pub finished_at: f64,
    pub status: String,
    pub http_status: Option<u16>,
    pub raw: String,
    pub data: Option<Value>,
    pub error: Option<String>,
    /// The caller's same-round egress measurement. Cached metadata is stamped
    /// with the new context, never silently reused as a fresh measurement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement_at: Option<f64>,
    /// Only allowlisted protocol metadata; cookies and credentials are never kept.
    pub response_headers: HashMap<String, String>,
    pub transport: String,
    pub cache_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_age: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_good: Option<Box<Receipt>>,
}
impl Receipt {
    /// JSON shape consumed by the existing macOS `CoffeeReceipt` decoder.
    /// Internal persistence deliberately keeps Rust's snake_case serde schema;
    /// this is only the GUI-facing compatibility boundary.
    pub fn display_value(&self) -> Value {
        json!({
            "kind": self.kind,
            "query": self.query,
            "sourceURL": self.source_url,
            "queriedAt": self.queried_at,
            "finishedAt": self.finished_at,
            "status": self.status,
            "httpStatus": self.http_status,
            "raw": self.raw,
            "data": self.data,
            "error": self.error,
            "transport": self.transport,
            "cache_state": self.cache_state,
            "last_good": self.last_good.as_ref().map(|receipt| receipt.display_value()),
        })
    }
    fn error(kind: &str, query: &str, url: &str, begun: f64, code: &str, message: &str) -> Self {
        Self {
            kind: kind.into(),
            query: query.into(),
            source_url: url.into(),
            queried_at: begun,
            finished_at: now(),
            status: if code == "timeout" {
                "timeout"
            } else {
                "error"
            }
            .into(),
            http_status: None,
            raw: String::new(),
            data: None,
            error: Some(clip(message, 240)),
            context_id: None,
            measurement_at: None,
            response_headers: HashMap::new(),
            transport: "HTTPS CONNECT via explicit loopback proxy".into(),
            cache_state: "miss".into(),
            cache_age: None,
            retry_after: None,
            last_good: None,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct CacheEntry {
    good: Option<Receipt>,
    failure: Option<Receipt>,
    retry_at: f64,
    attempt: u32,
    loading: bool,
}
#[derive(Default)]
struct Cache {
    entries: Mutex<HashMap<String, CacheEntry>>,
    wake: Condvar,
}

pub struct NetworkClient<T: Transport> {
    transport: Arc<T>,
    proxy: Option<String>,
    timeout: Duration,
    connect_timeout: Option<Duration>,
    cache: Arc<Cache>,
    storage: Option<StateStore>,
}
impl<T: Transport> Clone for NetworkClient<T> {
    fn clone(&self) -> Self {
        Self {
            transport: self.transport.clone(),
            proxy: self.proxy.clone(),
            timeout: self.timeout,
            connect_timeout: self.connect_timeout,
            cache: self.cache.clone(),
            storage: self.storage.clone(),
        }
    }
}
impl<T: Transport> NetworkClient<T> {
    /// Direct system-TUN diagnostic egress probe. It is intentionally uncached
    /// and separate from Claude/API reachability probes.
    pub fn fast_egress(&self) -> Receipt {
        self.fast_egress_via(None)
    }
    pub fn fast_egress_via(&self, proxy: Option<&str>) -> Receipt {
        if proxy.is_some_and(|v| !valid_loopback_proxy(v)) {
            return Receipt::error(
                "trace",
                "",
                FAST_EGRESS_URL,
                now(),
                "invalid_proxy",
                "CLI代理未通过受限回环校验",
            );
        }
        let mut client = self.clone();
        client.proxy = proxy.map(str::to_owned);
        client.timeout = Duration::from_secs(3);
        let mut last = Receipt::error(
            "trace",
            "",
            FAST_EGRESS_URL,
            now(),
            "timeout",
            "出口诊断未完成",
        );
        for _ in 0..2 {
            let receipt = client.request("trace", "", FAST_EGRESS_URL.into());
            if receipt.status == "complete" {
                let mut ip = String::new();
                let mut country = String::new();
                for line in receipt.raw.lines() {
                    if let Some(v) = line.strip_prefix("ip=") {
                        ip = public_unicast(v).unwrap_or_default()
                    }
                    if let Some(v) = line.strip_prefix("loc=") {
                        if v.len() == 2 && v.bytes().all(|b| b.is_ascii_uppercase()) {
                            country = v.into()
                        }
                    }
                }
                if !ip.is_empty() && !country.is_empty() {
                    let mut out = receipt;
                    out.data = Some(
                        json!({"ip":ip,"country":country,"observed_at":out.finished_at,"source":FAST_EGRESS_URL}),
                    );
                    return out;
                }
                last = Receipt::error(
                    "trace",
                    "",
                    FAST_EGRESS_URL,
                    receipt.queried_at,
                    "invalid_egress",
                    "Cloudflare trace 未返回有效公网 IP/国家",
                );
            } else {
                last = receipt
            }
        }
        last
    }
    pub fn new(transport: Arc<T>, proxy: Option<String>) -> Result<Self, TransportError> {
        if proxy.as_deref().is_some_and(|p| !valid_loopback_proxy(p)) {
            return Err(TransportError::new(
                "invalid_proxy",
                "代理只允许明确的数字本机 HTTP 入口",
            ));
        }
        Ok(Self {
            transport,
            proxy,
            timeout: Duration::from_secs(16),
            connect_timeout: Some(Duration::from_secs(5)),
            cache: Arc::default(),
            storage: None,
        })
    }
    /// Opt in to the runtime's private state store for reuse across processes.
    /// A corrupt, unavailable or unsafe entry is ignored rather than becoming
    /// an observation success.
    pub fn with_state_store(mut self, storage: StateStore) -> Self {
        self.storage = Some(storage);
        self
    }
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout.clamp(Duration::from_millis(100), Duration::from_secs(30));
        self
    }
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout.clamp(Duration::from_millis(1), self.timeout));
        self
    }
    fn cache_path(&self, key: &str) -> Option<std::path::PathBuf> {
        self.storage.as_ref().map(|store| {
            store
                .paths
                .base()
                .join(format!("network-meta-{}.json", sha256(key.as_bytes())))
        })
    }
    fn disk_entry(&self, key: &str) -> Option<CacheEntry> {
        let store = self.storage.as_ref()?;
        let path = self.cache_path(key)?;
        serde_json::from_value(store.read_json(&path, Value::Null).ok()?).ok()
    }
    fn save_disk_entry(&self, key: &str, entry: &CacheEntry) {
        let (Some(store), Some(path)) = (&self.storage, self.cache_path(key)) else {
            return;
        };
        let Ok(value) = serde_json::to_value(entry) else {
            return;
        };
        let _ = store.atomic_json(&path, &value);
    }
    fn disk_lock(&self, key: &str) -> Result<Option<OperationLock>, String> {
        let Some(store) = &self.storage else {
            return Ok(None);
        };
        // StateStore lock names are deliberately bounded. A SHA-256 prefix is
        // sufficient to separate keys while keeping this an internal filename.
        let hash = sha256(key.as_bytes());
        let name = format!("netmeta-{}", &hash[..48]);
        let deadline = Instant::now() + self.timeout.min(DISK_SINGLEFLIGHT_WAIT);
        loop {
            match store.lock(&name, None) {
                Ok(lock) => return Ok(Some(lock)),
                // Initial private-directory creation can race between freshly
                // launched processes; retry it under the same bounded budget.
                Err(error)
                    if matches!(error.code.as_str(), "busy" | "state_io_failed")
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) if matches!(error.code.as_str(), "busy" | "state_io_failed") => {
                    return Err("singleflight_wait_timeout".into())
                }
                Err(error) => return Err(format!("state_store_{}", error.code)),
            }
        }
    }
    fn cached_result(
        entry: &CacheEntry,
        now: f64,
        kind: &str,
        query: &str,
        url: &str,
    ) -> Option<Receipt> {
        if let Some(good) = &entry.good {
            let ttl = if kind == "ripe-asn" {
                86400.0
            } else {
                CACHE_TTL.as_secs_f64()
            };
            if good.kind == kind
                && good.query == query
                && good.source_url == url
                && good.status == "complete"
                && (0.0..=ttl).contains(&(now - good.finished_at))
            {
                let mut value = good.clone();
                value.cache_state = "hit".into();
                value.cache_age = Some(now - good.finished_at);
                return Some(value);
            }
        }
        if now < entry.retry_at
            && entry
                .failure
                .as_ref()
                .is_none_or(|v| v.source_url == url && v.kind == kind && v.query == query)
        {
            let mut failed = entry.failure.clone().unwrap_or_else(|| {
                Receipt::error(kind, query, url, now, "backoff", "元数据查询冷却中")
            });
            failed.cache_state = "backoff".into();
            failed.retry_after = Some(entry.retry_at - now);
            failed.last_good = entry
                .good
                .as_ref()
                .filter(|v| v.source_url == url && v.kind == kind && v.query == query)
                .cloned()
                .map(Box::new);
            return Some(failed);
        }
        None
    }
    fn waiting_unknown(kind: &str, query: &str, url: &str, code: &str) -> Receipt {
        let mut value = Receipt::error(
            kind,
            query,
            url,
            now(),
            code,
            "元数据跨进程查询仍在等待；本轮结果未知",
        );
        value.status = "unknown".into();
        value.cache_state = "wait_timeout".into();
        value
    }
    fn request(&self, kind: &str, query: &str, url: String) -> Receipt {
        self.request_limited(kind, query, url, MAX_BODY)
    }
    fn request_limited(&self, kind: &str, query: &str, url: String, max_body: usize) -> Receipt {
        let started = now();
        let response = self.transport.get(&Request {
            url: url.clone(),
            proxy: self.proxy.clone(),
            timeout: self.timeout,
            connect_timeout: self.connect_timeout,
            max_body,
            safe_headers: vec![],
        });
        let mut out = match response {
            Err(e) => Receipt::error(kind, query, &url, started, &e.code, &e.detail),
            Ok(r) => {
                let retry_after = r.headers.get("retry-after").and_then(|v| v.parse().ok());
                let response_headers = r
                    .headers
                    .into_iter()
                    .filter(|(key, _)| key == "cf-mitigated")
                    .collect();
                Receipt {
                    kind: kind.into(),
                    query: query.into(),
                    source_url: url,
                    queried_at: started,
                    finished_at: now(),
                    status: if r.status == 200 { "complete" } else { "error" }.into(),
                    http_status: Some(r.status),
                    raw: String::from_utf8_lossy(&r.body)
                        .chars()
                        .take(max_body)
                        .collect(),
                    data: None,
                    error: if r.status == 200 {
                        None
                    } else {
                        Some(format!("HTTP {}", r.status))
                    },
                    context_id: None,
                    measurement_at: None,
                    response_headers,
                    transport: "HTTPS CONNECT via explicit loopback proxy".into(),
                    cache_state: "miss".into(),
                    cache_age: None,
                    retry_after,
                    last_good: None,
                }
            }
        };
        if out.status == "complete" && !matches!(kind, "trace" | "service") {
            match serde_json::from_str::<Value>(&out.raw) {
                Ok(v) if v.is_object() => out.data = Some(v),
                _ => {
                    out.status = "error".into();
                    out.error = Some("JSON 对象格式无效".into())
                }
            }
        }
        if matches!(kind, "lookup" | "risk")
            && out.status == "complete"
            && out
                .data
                .as_ref()
                .and_then(|v| v.get("ip"))
                .and_then(Value::as_str)
                .and_then(public_unicast)
                .as_deref()
                != Some(query)
        {
            out.status = "error".into();
            out.error = Some("响应 IP 与请求出口不一致".into());
            out.data = None;
        }
        out
    }
    fn cached(&self, key: String, kind: &str, query: &str, url: String) -> Receipt {
        loop {
            let mut entries = self.cache.entries.lock().expect("cache lock");
            let t = now();
            let entry = entries.entry(key.clone()).or_insert(CacheEntry {
                good: None,
                failure: None,
                retry_at: 0.0,
                attempt: 0,
                loading: false,
            });
            if entry.good.is_none() && entry.failure.is_none() && !entry.loading {
                if let Some(mut disk) = self.disk_entry(&key) {
                    // `loading` is process-local and never persisted as true.
                    disk.loading = false;
                    *entry = disk;
                }
            }
            if let Some(value) = Self::cached_result(entry, t, kind, query, &url) {
                return value;
            }
            if entry.loading {
                drop(self.cache.wake.wait(entries).expect("cache lock"));
                continue;
            }
            entry.loading = true;
            drop(entries);
            let disk_lock = self.disk_lock(&key);
            // The lock holder before us may have completed while we waited.
            // Re-read its durable success, failure or 429 cooling receipt before
            // deciding whether an HTTP request is still permitted.
            if let Some(mut disk) = self.disk_entry(&key) {
                disk.loading = false;
                if let Some(value) = Self::cached_result(&disk, now(), kind, query, &url) {
                    let mut entries = self.cache.entries.lock().expect("cache lock");
                    *entries.get_mut(&key).expect("entry") = disk;
                    self.cache.wake.notify_all();
                    return value;
                }
            }
            let disk_lock = match disk_lock {
                Ok(lock) => lock,
                Err(code) => {
                    let mut entries = self.cache.entries.lock().expect("cache lock");
                    entries.get_mut(&key).expect("entry").loading = false;
                    self.cache.wake.notify_all();
                    return Self::waiting_unknown(kind, query, &url, &code);
                }
            };
            let mut receipt = self.request(kind, query, url.clone());
            let mut entries = self.cache.entries.lock().expect("cache lock");
            let entry = entries.get_mut(&key).expect("entry");
            entry.loading = false;
            if receipt.status == "complete" {
                entry.good = Some(receipt.clone());
                entry.failure = None;
                entry.attempt = 0;
                entry.retry_at = 0.0;
            } else {
                entry.attempt = entry.attempt.saturating_add(1);
                let delay = if receipt.http_status == Some(429) {
                    receipt.retry_after.unwrap_or(900.0).max(900.0)
                } else {
                    (15.0 * (2u32.pow(entry.attempt.saturating_sub(1).min(6)) as f64))
                        .clamp(15.0, 900.0)
                };
                entry.retry_at = now() + delay;
                entry.failure = Some(receipt.clone());
                receipt.last_good = entry.good.clone().map(Box::new);
            }
            self.save_disk_entry(&key, entry);
            self.cache.wake.notify_all();
            drop(disk_lock);
            return receipt;
        }
    }
    pub fn metadata(&self, kind: &str, address: &str) -> Receipt {
        let Some(ip) = public_unicast(address) else {
            return Receipt::error(kind, address, "", now(), "invalid_ip", "仅允许公网出口 IP");
        };
        let path = match kind {
            "lookup" => "/api/ip/lookup/",
            "geoip" => "/api/geoip/",
            "risk" => "/api/iprisk/",
            _ => {
                return Receipt::error(
                    kind,
                    &ip,
                    "",
                    now(),
                    "unsupported_kind",
                    "不支持的元数据类型",
                )
            }
        };
        self.cached(
            format!("{kind}:{ip}"),
            kind,
            &ip,
            format!("{NETCOFFEE}{path}{ip}"),
        )
    }
    /// Returns a completed Net.Coffee DNS probe receipt for a token issued by
    /// the local WebView flow. The token is deliberately constrained before it
    /// becomes part of the fixed, allowlisted URL.
    pub fn netcoffee_dns(&self, token: &str) -> Receipt {
        if !(16..=48).contains(&token.len())
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Receipt::error(
                "dns",
                token,
                "",
                now(),
                "invalid_dns_token",
                "Net.Coffee DNS 令牌无效",
            );
        }
        let mut receipt = self.request("dns", token, format!("{NETCOFFEE}/api/dns/result/{token}"));
        if receipt.status == "complete"
            && !receipt
                .data
                .as_ref()
                .and_then(|value| value.get("dns_servers"))
                .and_then(Value::as_array)
                .is_some_and(|servers| servers.iter().all(Value::is_string))
        {
            receipt.status = "error".into();
            receipt.error = Some("DNS 服务列表格式无效".into());
            receipt.data = None;
        }
        receipt
    }
    /// Adds explicit same-IP, current-round provenance to a metadata receipt.
    /// `egress_ip` must be an independently observed public egress value, not a
    /// destination or local TAG-control address.
    pub fn metadata_for_context(
        &self,
        kind: &str,
        context_id: &str,
        egress_ip: &str,
        measured_at: f64,
    ) -> Receipt {
        if context_id.is_empty()
            || context_id.len() > 128
            || !context_id
                .bytes()
                .all(|b| b.is_ascii_graphic() || b == b'-' || b == b'_')
        {
            return Receipt::error(
                kind,
                egress_ip,
                "",
                now(),
                "invalid_context",
                "测量上下文标识无效",
            );
        }
        let age = now() - measured_at;
        if !measured_at.is_finite() || age < -1.0 || age > CONTEXT_MAX_AGE.as_secs_f64() {
            return Receipt::error(
                kind,
                egress_ip,
                "",
                now(),
                "stale_context",
                "出口测量不属于当前采样轮次",
            );
        }
        let mut receipt = self.metadata(kind, egress_ip);
        receipt.context_id = Some(context_id.into());
        receipt.measurement_at = Some(measured_at);
        receipt
    }
    pub fn ripe_asn(&self, asn: u32) -> Receipt {
        let query = asn.to_string();
        self.cached(
            format!("ripe-asn:{asn}"),
            "ripe-asn",
            &query,
            format!("https://stat.ripe.net/data/rir-stats-country/data.json?resource=AS{asn}"),
        )
    }
    pub fn trace(&self, url: &str) -> Receipt {
        if !matches!(
            url,
            "https://1.1.1.1/cdn-cgi/trace"
                | "https://www.cloudflare.com/cdn-cgi/trace"
                | "https://claude.ai/cdn-cgi/trace"
                | "https://api.anthropic.com/v1/models"
        ) {
            return Receipt::error(
                "trace",
                "",
                url,
                now(),
                "endpoint_not_allowed",
                "端点不在固定允许列表",
            );
        }
        self.request("trace", "", url.into())
    }
    /// A narrow compatibility boundary for the AI diagnostic collector.  The
    /// caller cannot provide an arbitrary origin: only the historical probe
    /// endpoints (and a public-IP-qualified ipinfo lookup) are admitted.
    /// These are uncached observations and retain HTTP 401/403 in the receipt.
    pub fn ai_probe(&self, url: &str) -> Receipt {
        let allowed = matches!(
            url,
            "https://claude.ai/cdn-cgi/trace"
                | "https://www.anthropic.com/cdn-cgi/trace"
                | "https://chatgpt.com/cdn-cgi/trace"
                | "https://api.openai.com/v1/models"
                | "https://1.1.1.1/cdn-cgi/trace"
        ) || url
            .strip_prefix("https://ipinfo.io/")
            .and_then(|path| path.strip_suffix("/json"))
            .and_then(claude_watch_core::network::public_unicast)
            .is_some();
        if !allowed {
            return Receipt::error(
                "ai_probe",
                "",
                url,
                now(),
                "endpoint_not_allowed",
                "端点不在 AI 诊断固定允许列表",
            );
        }
        self.request_limited("ai_probe", "", url.into(), 32 * 1024)
    }
    pub fn service_metadata(&self, service: &str) -> Receipt {
        let client = self.clone().with_timeout(Duration::from_secs(8));
        match service {
            "claude" => client.trace("https://claude.ai/cdn-cgi/trace"),
            "api" => client.trace("https://api.anthropic.com/v1/models"),
            _ => Receipt::error(
                "service",
                service,
                "",
                now(),
                "unsupported_service",
                "不支持的服务",
            ),
        }
    }

    /// Observe the actual homepage without credentials or downloading its body.
    /// Egress sampling continues to use `service_metadata` and its trace URL.
    pub fn claude_homepage(&self) -> Receipt {
        self.clone()
            .with_timeout(Duration::from_secs(8))
            .request_limited("service", "", "https://claude.ai/".into(), 0)
    }
}

/// A RIPE country is accepted only when every accepted row names this exact ASN
/// and exactly one ISO country is present; an ASN prefix match is not enough.
pub fn ripe_registered_country(receipt: &Receipt, asn: u32) -> Option<String> {
    if receipt.status != "complete" {
        return None;
    }
    let rows = receipt
        .data
        .as_ref()?
        .pointer("/data/located_resources")?
        .as_array()?;
    if rows.len() > 64 {
        return None;
    };
    let mut countries = std::collections::BTreeSet::new();
    for row in rows {
        // RIPEstat returns the resource without the routing prefix
        // (`"2516"`); older caches and fixtures use `"AS2516"`.  Accept the
        // optional prefix instead of demanding it, otherwise every real
        // response is discarded and the registered country is never shown.
        let exact = row
            .get("resource")
            .and_then(Value::as_str)
            .map(str::trim)
            .is_some_and(|s| {
                let digits = s
                    .get(..2)
                    .filter(|p| p.eq_ignore_ascii_case("as"))
                    .map_or(s, |_| &s[2..]);
                !digits.is_empty()
                    && digits.bytes().all(|b| b.is_ascii_digit())
                    && digits == asn.to_string()
            });
        if !exact {
            continue;
        };
        let c = row.get("location").and_then(Value::as_str)?;
        if c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()) {
            countries.insert(c.to_owned());
        }
    }
    (countries.len() == 1).then(|| countries.into_iter().next().unwrap())
}

/// Extract an explicit `AS<number>` prefix only; organization text is not an
/// ASN and cannot be used to query RIPEstat.
pub fn lookup_asn(receipt: &Receipt) -> Option<u32> {
    let data = receipt.data.as_ref()?;
    let numeric = data.get("asn").and_then(|value| {
        value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .or_else(|| {
                value.as_str().and_then(|value| {
                    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
                        .then_some(value)
                        .and_then(|value| value.parse::<u32>().ok())
                })
            })
    });
    numeric
        .or_else(|| {
            let org = data.get("org")?.as_str()?.trim();
            let number = org.strip_prefix("AS")?.split_whitespace().next()?;
            (!number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()))
                .then_some(number)
                .and_then(|number| number.parse::<u32>().ok())
        })
        .filter(|number| *number > 0)
}

pub fn service_observation(service: &str, receipt: &Receipt) -> Value {
    let status = receipt.http_status;
    let reached = receipt.http_status.is_some();
    let cloudflare_challenge = matches!(
        receipt.source_url.as_str(),
        "https://claude.ai/" | "https://claude.ai/cdn-cgi/trace"
    ) && receipt
        .response_headers
        .get("cf-mitigated")
        .is_some_and(|v| v.eq_ignore_ascii_case("challenge"));
    let (access, challenge) = match (service, status) {
        ("api", Some(401)) => ("authentication_required", Value::Null),
        ("claude", Some(403)) if cloudflare_challenge => (
            "challenge",
            json!({"provider":"cloudflare","mitigated":"challenge"}),
        ),
        _ => ("unknown", Value::Null),
    };
    json!({"source":receipt.source_url,"status":if reached{"ok"}else{"unknown"},"http_status":status,"transport_reached":reached,"access":access,"challenge":challenge,"queried_at":receipt.queried_at,"error":receipt.error})
}

/// Parse the egress address reported by a Cloudflare trace without accepting a
/// similarly named field elsewhere in an untrusted response body.
pub fn trace_ip(receipt: &Receipt) -> Option<String> {
    (receipt.status == "complete").then_some(())?;
    receipt
        .raw
        .lines()
        .find_map(|line| line.strip_prefix("ip="))
        .and_then(public_unicast)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressCollection {
    pub service: String,
    pub context_id: String,
    pub started_at: f64,
    pub finished_at: f64,
    pub status: String,
    pub exit_ip: Option<String>,
    pub reference_ip: Option<String>,
    pub service_response: Receipt,
    pub reference_response: Receipt,
    pub geo: Option<Receipt>,
    pub errors: Vec<Value>,
}

impl<T: Transport> NetworkClient<T> {
    /// Resolve the registration country only from the exact ASN extracted from
    /// a validated lookup receipt. Failure stays local to this source.
    pub fn registered_asn_country(&self, lookup: &Receipt) -> Option<(u32, String)> {
        let asn = lookup_asn(lookup)?;
        let ripe = self.ripe_asn(asn);
        ripe_registered_country(&ripe, asn).map(|country| (asn, country))
    }
    /// Collects two independent sources: a service endpoint and Cloudflare's
    /// fixed reference trace.  The service exit is only populated when that
    /// service endpoint itself returned a valid public trace address; reference
    /// data is never substituted for a failed service measurement.
    pub fn collect_egress(&self, service: &str, context_id: &str) -> EgressCollection {
        let started = now();
        let service_response = self.service_metadata(service);
        let reference_response = self.trace("https://1.1.1.1/cdn-cgi/trace");
        let exit_ip = if service == "claude" {
            trace_ip(&service_response)
        } else {
            None
        };
        let reference_ip = trace_ip(&reference_response);
        let geo = exit_ip
            .as_deref()
            .map(|ip| self.metadata_for_context("geoip", context_id, ip, started));
        let mut errors = Vec::new();
        for (source, receipt) in [
            ("service", &service_response),
            ("reference", &reference_response),
        ] {
            if receipt.status != "complete" {
                errors.push(json!({"stage":source,"code":receipt.error.as_deref().unwrap_or("query_failed"),"source":receipt.source_url}));
            }
        }
        if exit_ip.is_none() {
            errors.push(json!({"stage":"exit","code":"invalid_exit_ip","source":"service","message":"服务端点未返回已验证公网出口 IP"}));
        }
        if let Some(receipt) = &geo {
            if receipt.status != "complete" {
                errors.push(json!({"stage":"geo","code":receipt.error.as_deref().unwrap_or("query_failed"),"source":receipt.source_url}));
            }
        }
        let status =
            if service_response.status == "timeout" && reference_response.status == "timeout" {
                "timeout"
            } else if errors.is_empty() {
                "complete"
            } else {
                "partial"
            };
        EgressCollection {
            service: service.into(),
            context_id: clip(context_id, 128),
            started_at: started,
            finished_at: now(),
            status: status.into(),
            exit_ip,
            reference_ip,
            service_response,
            reference_response,
            geo,
            errors,
        }
    }
}
