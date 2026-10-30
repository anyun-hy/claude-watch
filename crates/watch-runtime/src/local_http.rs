//! Read-only Mihomo HTTP transport. Fixed GET paths, literal loopback, no proxy or redirects.
use crate::storage::strict_json;
use claude_watch_core::tag_config::{self, Credentials, API_PATHS};
use serde_json::{json, Value};
use std::{
    fmt,
    io::{self, Read},
    time::{Duration, Instant},
};

const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_HEADERS: usize = 32 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Path,
    Timeout,
    Transport,
    Protocol,
    TooLarge,
    Json,
    Status(u16),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Path => "控制接口路径未获允许",
            Self::Timeout => "本机控制接口超时",
            Self::Transport => "本机控制接口传输失败",
            Self::Protocol => "本机控制接口HTTP格式无效",
            Self::TooLarge => "本机控制接口响应过大",
            Self::Json => "本机控制接口JSON格式无效",
            Self::Status(_) => "本机控制接口返回非成功状态",
        })
    }
}
fn map_error(error: &ureq::Error) -> Error {
    match error {
        ureq::Error::Timeout(_) => Error::Timeout,
        ureq::Error::LargeResponseHeader(..) | ureq::Error::BodyExceedsLimit(_) => Error::TooLarge,
        ureq::Error::Protocol(_) | ureq::Error::Http(_) => Error::Protocol,
        ureq::Error::Io(error) => map_io(error),
        _ => Error::Transport,
    }
}
fn map_io(error: &io::Error) -> Error {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        return Error::Timeout;
    }
    if let Some(inner) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<ureq::Error>())
    {
        return map_error(inner);
    }
    Error::Transport
}
pub struct Client {
    credentials: Credentials,
    timeout: Duration,
}
impl Client {
    pub fn new(credentials: Credentials) -> Self {
        Self {
            credentials,
            timeout: Duration::from_millis(1500),
        }
    }
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout.clamp(Duration::from_millis(1), Duration::from_millis(1500));
        self
    }
    pub fn base(&self) -> String {
        self.credentials.base()
    }
    pub fn get(&self, path: &str) -> Result<Value, Error> {
        if !API_PATHS.contains(&path) {
            return Err(Error::Path);
        }
        let started = Instant::now();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(self.timeout))
            .max_response_header_size(MAX_HEADERS)
            .build()
            .into();
        let mut request = agent
            .get(format!("{}{path}", self.base()))
            .header("Accept", "application/json")
            .header("Accept-Encoding", "identity")
            .header("Connection", "close");
        if let Some(authorization) = self.credentials.authorization() {
            request = request.header("Authorization", authorization);
        }
        let mut response = request.call().map_err(|e| map_error(&e))?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(Error::Status(status));
        }
        let headers = response.headers();
        let lengths: Vec<_> = headers.get_all("content-length").iter().collect();
        if lengths.len() > 1 || (!lengths.is_empty() && headers.contains_key("transfer-encoding")) {
            return Err(Error::Protocol);
        }
        if headers
            .get("content-encoding")
            .is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
        {
            return Err(Error::Protocol);
        }
        if let Some(length) = lengths.first() {
            let length = length.to_str().map_err(|_| Error::Protocol)?;
            if length.is_empty() || !length.bytes().all(|v| v.is_ascii_digit()) {
                return Err(Error::Protocol);
            }
            if length.parse::<u64>().map_err(|_| Error::TooLarge)? > MAX_BODY as u64 {
                return Err(Error::TooLarge);
            }
        }
        let mut bytes = Vec::new();
        response
            .body_mut()
            .with_config()
            .limit(MAX_BODY as u64 + 1)
            .reader()
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| map_io(&e))?;
        if bytes.len() > MAX_BODY {
            return Err(Error::TooLarge);
        }
        let value = strict_json(&bytes).map_err(|_| Error::Json)?;
        if !value.is_object() {
            return Err(Error::Json);
        }
        if started.elapsed() > self.timeout {
            return Err(Error::Timeout);
        }
        Ok(value)
    }
    pub fn snapshot(&self, group: &str) -> (Value, Vec<Value>) {
        let unavailable = || {
            (
                json!({"state":"unavailable","reason":"本机控制接口配置、鉴权、响应或访问不可用", "rules":{"state":"unavailable","reason":"控制接口未验证","entries":[]}}),
                Vec::new(),
            )
        };
        let required = (|| {
            Ok::<_, Error>((
                self.get("/configs")?,
                self.get("/proxies")?,
                self.get("/connections")?,
            ))
        })();
        let (configs, proxies, connections) = match required {
            Ok(v) => v,
            Err(Error::Status(code)) => {
                let (mut report, records) = unavailable();
                report["reason"] = json!(format!("控制接口 HTTP {code}"));
                return (report, records);
            }
            Err(_) => return unavailable(),
        };
        let rules=match self.get("/rules"){
            Ok(value)=>tag_config::published_rules(&value).unwrap_or_else(|_|json!({"state":"unavailable","reason":"控制接口规则表不可用或格式不完整","entries":[]})),
            Err(Error::Status(code))=>json!({"state":"unavailable","reason":format!("控制接口规则表 HTTP {code}"),"entries":[]}),
            Err(_)=>json!({"state":"unavailable","reason":"控制接口规则表不可用或格式不完整","entries":[]})
        };
        tag_config::api_snapshot(&self.base(), group, &configs, &proxies, &connections, rules)
            .unwrap_or_else(|_| unavailable())
    }
}
