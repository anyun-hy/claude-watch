use claude_watch_core::{network::public_unicast, stun};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{ToSocketAddrs, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const SERVERS: [(&str, u16); 4] = [
    ("stun.miwifi.com", 3478),
    ("stun.chat.bilibili.com", 3478),
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
];
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);
pub const RETRY_DELAY: Duration = Duration::from_millis(200);
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}
#[derive(Debug, Clone)]
pub struct ProbeError {
    pub stage: String,
    pub code: String,
    pub detail: String,
    pub errno: Option<i32>,
}
impl ProbeError {
    pub fn new(stage: &str, code: &str, detail: &str) -> Self {
        Self {
            stage: stage.into(),
            code: code.into(),
            detail: detail.chars().take(240).collect(),
            errno: None,
        }
    }
    fn status(&self) -> &'static str {
        match self.code.as_str() {
            "timeout" => "timeout",
            "budget_exhausted" => "budget_exhausted",
            "unexpected_sender" => "unexpected_sender",
            _ if self.stage == "validation" => "invalid_response",
            _ => "network_error",
        }
    }
    fn io(stage: &str, code: &str, error: std::io::Error) -> Self {
        let mut value = Self::new(stage, code, &format!("UDP/STUN {stage} 失败：{error}"));
        value.errno = error.raw_os_error();
        value
    }
}
pub trait Requester: Send + Sync + 'static {
    fn request(&self, endpoint: &Endpoint, deadline: Instant) -> Result<String, ProbeError>;
}
#[derive(Default)]
pub struct NativeRequester;
impl Requester for NativeRequester {
    fn request(&self, endpoint: &Endpoint, deadline: Instant) -> Result<String, ProbeError> {
        let destination = (endpoint.host.as_str(), endpoint.port)
            .to_socket_addrs()
            .map_err(|e| ProbeError::io("resolve", "dns_resolution_failed", e))?
            .find(|v| v.is_ipv4())
            .ok_or_else(|| {
                ProbeError::new("resolve", "dns_resolution_failed", "未取得 IPv4 STUN 目标")
            })?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ProbeError::new(
                "budget",
                "budget_exhausted",
                "DNS 解析后整轮预算已耗尽，未发送 UDP 数据包",
            ));
        }
        let socket =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| ProbeError::io("send", "socket_failed", e))?;
        let timeout = remaining.min(ATTEMPT_TIMEOUT);
        socket
            .set_write_timeout(Some(timeout))
            .map_err(|e| ProbeError::io("send", "timeout_config_failed", e))?;
        let mut transaction = [0; 12];
        getrandom::fill(&mut transaction)
            .map_err(|_| ProbeError::new("request", "random_failed", "无法生成 STUN 事务编号"))?;
        if Instant::now() >= deadline {
            return Err(ProbeError::new(
                "budget",
                "budget_exhausted",
                "发送前整轮 STUN 预算已耗尽",
            ));
        }
        socket
            .send_to(&stun::binding_request(transaction), destination)
            .map_err(|e| ProbeError::io("send", "send_failed", e))?;
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .min(ATTEMPT_TIMEOUT);
        if timeout.is_zero() {
            return Err(ProbeError::new(
                "budget",
                "budget_exhausted",
                "接收前整轮 STUN 预算已耗尽",
            ));
        }
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|e| ProbeError::io("receive", "timeout_config_failed", e))?;
        let mut bytes = [0; 4096];
        let (size, sender) = socket.recv_from(&mut bytes).map_err(|e| {
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) {
                ProbeError::new(
                    "receive",
                    "timeout",
                    &format!("等待 UDP STUN 回包超时（{:.2} 秒）", timeout.as_secs_f64()),
                )
            } else {
                ProbeError::io("receive", "receive_failed", e)
            }
        })?;
        if sender != destination {
            return Err(ProbeError::new(
                "validation",
                "unexpected_sender",
                "STUN 回包来源与目标不一致",
            ));
        }
        stun::decode(&bytes[..size], &transaction)
            .map_err(|code| ProbeError::new("validation", code, "STUN 回包未通过严格校验"))
    }
}
fn wallclock() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |v| v.as_secs_f64())
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attempt {
    pub attempt: u32,
    pub started_at: f64,
    pub finished_at: f64,
    pub status: String,
    pub error_code: String,
    pub error: String,
    pub stage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errno: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline_exceeded: Option<bool>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub server: String,
    pub port: u16,
    pub status: String,
    pub started_at: f64,
    pub finished_at: f64,
    pub attempts: Vec<Attempt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeReceipt {
    pub scope: String,
    pub started_at: f64,
    pub finished_at: f64,
    pub complete: bool,
    pub observations: Vec<Observation>,
    pub missing: usize,
}

pub fn probe(
    servers: &[Endpoint],
    requester: Arc<dyn Requester>,
    budget: Duration,
) -> ProbeReceipt {
    probe_with_delay(servers, requester, budget, RETRY_DELAY)
}
pub fn probe_default() -> ProbeReceipt {
    probe(
        &SERVERS
            .iter()
            .map(|(host, port)| Endpoint {
                host: (*host).into(),
                port: *port,
            })
            .collect::<Vec<_>>(),
        Arc::new(NativeRequester),
        Duration::from_secs(8),
    )
}
pub fn probe_with_delay(
    servers: &[Endpoint],
    requester: Arc<dyn Requester>,
    budget: Duration,
    retry_delay: Duration,
) -> ProbeReceipt {
    let started = wallclock();
    let deadline = Instant::now() + budget;
    let cancelled = Arc::new(AtomicBool::new(false));
    let progress = Arc::new(Mutex::new(BTreeMap::<Endpoint, Vec<Attempt>>::new()));
    let (tx, rx) = mpsc::channel();
    for endpoint in servers.iter().cloned() {
        let tx = tx.clone();
        let requester = Arc::clone(&requester);
        let progress = Arc::clone(&progress);
        let cancelled = Arc::clone(&cancelled);
        thread::spawn(move || {
            let mut attempts = Vec::new();
            let mut address = None;
            for index in 1..=2 {
                if Instant::now() >= deadline || cancelled.load(Ordering::Acquire) {
                    break;
                }
                let started_at = wallclock();
                let result = requester.request(&endpoint, deadline).and_then(|address| {
                    public_unicast(&address).ok_or_else(|| {
                        ProbeError::new(
                            "validation",
                            "nonpublic_address",
                            "STUN 回包不是有效公网单播地址",
                        )
                    })
                });
                let finished_at = wallclock();
                let (status, code, error, stage, errno) = match result {
                    Ok(value) => {
                        address = Some(value);
                        (
                            "ok".to_owned(),
                            String::new(),
                            String::new(),
                            "request".to_owned(),
                            None,
                        )
                    }
                    Err(error) => (
                        error.status().to_owned(),
                        error.code,
                        error.detail,
                        error.stage,
                        error.errno,
                    ),
                };
                attempts.push(Attempt {
                    attempt: index,
                    started_at,
                    finished_at,
                    status: status.clone(),
                    error_code: code,
                    error,
                    stage,
                    errno,
                    accepted: None,
                    deadline_exceeded: None,
                });
                if let Ok(mut shared) = progress.lock() {
                    shared.insert(endpoint.clone(), attempts.clone());
                }
                if address.is_some()
                    || matches!(status.as_str(), "invalid_response" | "unexpected_sender")
                    || index == 2
                {
                    break;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining <= retry_delay {
                    break;
                }
                thread::sleep(retry_delay);
            }
            let finished = wallclock();
            if attempts.is_empty() {
                attempts.push(budget_attempt(
                    1,
                    finished,
                    "整轮 STUN 预算已耗尽，未发起请求",
                ));
            }
            let mut status = attempts
                .last()
                .map(|v| v.status.clone())
                .unwrap_or_else(|| "budget_exhausted".into());
            if status == "ok" && (Instant::now() >= deadline || cancelled.load(Ordering::Acquire)) {
                if let Some(last) = attempts.last_mut() {
                    last.accepted = Some(false);
                    last.deadline_exceeded = Some(true);
                }
                status = "budget_exhausted".into();
                address = None;
            }
            let value = Observation {
                server: endpoint.host,
                port: endpoint.port,
                status,
                started_at: attempts[0].started_at,
                finished_at: attempts.last().map_or(finished, |v| v.finished_at),
                attempts,
                address,
            };
            let _ = tx.send(value);
        });
    }
    drop(tx);
    let mut received = BTreeMap::new();
    while received.len() < servers.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok(row) if Instant::now() < deadline => {
                received.insert(
                    Endpoint {
                        host: row.server.clone(),
                        port: row.port,
                    },
                    row,
                );
            }
            _ => break,
        }
    }
    cancelled.store(true, Ordering::Release);
    let finished = wallclock();
    let mut observations = Vec::new();
    for endpoint in servers {
        let row = received.remove(endpoint).unwrap_or_else(|| {
            let mut attempts = progress
                .lock()
                .ok()
                .and_then(|v| v.get(endpoint).cloned())
                .unwrap_or_default();
            if attempts.len() < 2 {
                attempts.push(budget_attempt(
                    attempts.len() as u32 + 1,
                    finished,
                    "整轮 STUN 预算耗尽，工作线程未在截止前返回",
                ));
            } else if let Some(last) = attempts.last_mut() {
                last.accepted = Some(false);
                last.deadline_exceeded = Some(true);
            }
            Observation {
                server: endpoint.host.clone(),
                port: endpoint.port,
                status: "budget_exhausted".into(),
                started_at: started,
                finished_at: finished,
                attempts,
                address: None,
            }
        });
        observations.push(row);
    }
    ProbeReceipt {
        scope: "原生 IPv4 UDP/STUN 探针，不代表 Claude 或浏览器 ICE".into(),
        started_at: started,
        finished_at: finished,
        complete: !observations.is_empty() && observations.iter().all(|v| v.status == "ok"),
        missing: observations
            .iter()
            .filter(|v| v.status == "budget_exhausted")
            .count(),
        observations,
    }
}
fn budget_attempt(attempt: u32, now: f64, detail: &str) -> Attempt {
    Attempt {
        attempt,
        started_at: now,
        finished_at: now,
        status: "budget_exhausted".into(),
        error_code: "budget_exhausted".into(),
        error: detail.into(),
        stage: "budget".into(),
        errno: None,
        accepted: None,
        deadline_exceeded: None,
    }
}
