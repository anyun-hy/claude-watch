//! Bounded same-core mapping collection with mandatory post-query identity/connection rechecks.
use claude_watch_core::{
    error::Result,
    presentation::text,
    tag_config::{self, is_fake, normalized_dns_host},
    tag_flow::{self, CommandEvidence, Flow},
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

#[derive(Clone)]
pub struct SampledFlow {
    pub flow: Flow,
    pub stamp: String,
    pub process_start: Option<f64>,
    pub valid: bool,
}
pub trait Source {
    fn now(&self) -> f64;
    fn monotonic(&mut self) -> Duration;
    fn config(&mut self) -> Result<String>;
    fn listeners(&mut self) -> Result<CommandEvidence>;
    fn route_interface(&mut self, address: &str) -> Result<String>;
    fn query_dns(&mut self, host: &str, port: u16, timeout: Duration) -> Result<(String, u32)>;
    fn connections(&mut self) -> Result<Vec<Value>>;
    fn processes(&mut self) -> Result<BTreeMap<u32, Value>>;
}
pub struct Input<'a> {
    pub entry: &'a Value,
    pub api: &'a Value,
    pub records: &'a [Value],
    pub flows: &'a [SampledFlow],
    pub processes: &'a BTreeMap<u32, Value>,
    pub listener_snapshot: Option<(&'a CommandEvidence, f64)>,
    pub uid: u32,
}
#[derive(Debug)]
pub struct Collected {
    pub proofs: Value,
    pub attempts: Vec<Value>,
    pub reason: &'static str,
}
impl Default for Collected {
    fn default() -> Self {
        Self {
            proofs: json!({}),
            attempts: Vec::new(),
            reason: "尚无同一内核的有效 fake-IP 映射证据",
        }
    }
}
fn utun(name: &str) -> bool {
    name.strip_prefix("utun")
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
}
pub fn collect(source: &mut impl Source, input: Input<'_>) -> Collected {
    let mut result = Collected::default();
    let Input {
        entry,
        api,
        records,
        flows,
        processes,
        listener_snapshot,
        uid,
    } = input;
    let owners = entry["owners"].as_array();
    if entry["state"] != "verified"
        || api["state"] != "available"
        || !owners.is_some_and(|v| v.len() == 1)
        || !flows.iter().any(|s| s.valid && is_fake(&s.flow.peer.0))
    {
        return result;
    }
    let owner = &owners.unwrap()[0];
    let Ok(config) = source.config() else {
        result.reason = "未能读取同一内核的 DNS 配置";
        return result;
    };
    let Ok((port, range)) = tag_config::fakeip_dns_config(&config) else {
        result.reason = "未能确认唯一的本机 fake-IP DNS 监听配置";
        return result;
    };
    let (kernel, captured) = if let Some((snapshot, captured)) = listener_snapshot {
        (snapshot.clone(), captured)
    } else {
        let Ok(kernel) = source.listeners() else {
            result.reason = "DNS 监听采样不可读取";
            return result;
        };
        (kernel, source.now())
    };
    let fresh_listener = |now: f64| {
        now.is_finite() && captured.is_finite() && (0.0..=5.0).contains(&(now - captured))
    };
    if !fresh_listener(source.now())
        || !tag_flow::dns_listener_matches(&kernel, port, owner, processes, uid)
    {
        result.reason = "DNS 监听身份不匹配或采样已过期";
        return result;
    }
    let mut candidates = Vec::new();
    for sample in flows {
        if !sample.valid || !range.contains(&sample.flow.peer.0) {
            continue;
        }
        let matching: Vec<_> = records
            .iter()
            .filter(|r| {
                tag_flow::source_candidate(r, &sample.flow, sample.process_start, source.now())
            })
            .collect();
        if matching.len() != 1 {
            continue;
        }
        let record = matching[0];
        let metadata = &record["metadata"];
        let Some(host) = normalized_dns_host(text(metadata, "host")) else {
            continue;
        };
        let destination_port = metadata["destinationPort"].as_u64().or_else(|| {
            metadata["destinationPort"]
                .as_str()
                .and_then(|s| s.parse().ok())
        });
        if !tag_flow::translated_fakeip_destination(metadata, &sample.flow.peer)
            || destination_port != Some(u64::from(sample.flow.peer.1))
        {
            continue;
        }
        if !source
            .route_interface(&sample.flow.peer.0)
            .is_ok_and(|v| utun(&v))
        {
            continue;
        }
        candidates.push((sample, record, host));
    }
    if candidates.is_empty() {
        result.reason = "未取得唯一且身份有效的 TUN/fake-IP 完整连接候选";
        return result;
    }
    let deadline = source.monotonic() + Duration::from_millis(1500);
    let hosts: BTreeSet<_> = candidates.iter().map(|v| v.2.clone()).collect();
    let mut answers = BTreeMap::new();
    for host in hosts.into_iter().take(8) {
        let remaining = deadline.saturating_sub(source.monotonic());
        if remaining.is_zero() {
            break;
        }
        let started = source.now();
        let timeout = remaining.min(Duration::from_millis(350));
        match source.query_dns(&host,port,timeout){
            Ok((address,ttl))if ttl>0 && address.parse::<std::net::Ipv4Addr>().is_ok()=>{
                let observed=source.now();let accepted=source.monotonic()<=deadline && observed.is_finite();
                result.attempts.push(json!({"host":host,"endpoint":format!("127.0.0.1:{port}"),"state":if accepted{"ok"}else{"deadline_exceeded"},"accepted":accepted,"started_at":started,"finished_at":observed}));
                if accepted{answers.insert(host,(address,observed,ttl.min(2)));}
            }
            Ok(_)=>result.attempts.push(json!({"host":host,"state":"invalid_answer","started_at":started,"finished_at":source.now()})),
            Err(error)=>result.attempts.push(json!({"host":host,"state":"unknown","code":error.code,"started_at":started,"finished_at":source.now()}))
        }
    }
    let Ok(current_records) = source.connections() else {
        result.reason = "DNS 查询后未能复核控制器连接表";
        return result;
    };
    let Ok(current_processes) = source.processes() else {
        result.reason = "DNS 查询后未能复核进程身份";
        return result;
    };
    let current_kernel = if listener_snapshot.is_some() {
        kernel
    } else {
        let Ok(kernel) = source.listeners() else {
            result.reason = "DNS 查询后未能复核监听状态";
            return result;
        };
        kernel
    };
    let current_config = source
        .config()
        .and_then(|v| tag_config::fakeip_dns_config(&v));
    if !fresh_listener(source.now())
        || current_config.as_ref().ok() != Some(&(port, range))
        || !tag_flow::dns_listener_matches(&current_kernel, port, owner, &current_processes, uid)
    {
        result.reason = "DNS 查询期间内核、监听配置或进程身份变化";
        return result;
    }
    for (sample, record, host) in candidates {
        let Some((address, observed, ttl)) = answers.get(&host) else {
            continue;
        };
        let now = source.now();
        let same: Vec<_> = current_records
            .iter()
            .filter(|r| tag_flow::source_candidate(r, &sample.flow, sample.process_start, now))
            .collect();
        if address != &sample.flow.peer.0
            || !now.is_finite()
            || !(0.0..=f64::from(*ttl)).contains(&(now - observed))
            || same.len() != 1
            || tag_flow::record_identity(same[0]) != tag_flow::record_identity(record)
            || current_processes
                .get(&sample.flow.pid)
                .is_none_or(|p| p["stamp"] != sample.stamp || p["uid"] != uid)
        {
            continue;
        }
        if let Some(before) = processes.get(&sample.flow.pid) {
            if ["executable", "start_seconds", "start_microseconds"]
                .iter()
                .any(|key| {
                    before.get(*key).is_some()
                        && current_processes
                            .get(&sample.flow.pid)
                            .and_then(|p| p.get(*key))
                            != before.get(*key)
                })
            {
                continue;
            }
        }
        result.proofs[text(record, "id")] = json!({"host":host,"address":address,"observed_at":observed,"expires_at":observed+f64::from(*ttl),
            "dns_endpoint":format!("127.0.0.1:{port}"),"dns_owner_pid":owner["pid"],"dns_owner_started":owner["stamp"],
            "source_pid":sample.flow.pid,"source_started":sample.stamp,"source":sample.flow.local,"peer":sample.flow.peer,"protocol":sample.flow.protocol,
            "connection_start":record["start"],"kind":"same_core_fakeip_mapping"});
    }
    result.reason = if result.proofs.as_object().is_some_and(|v| !v.is_empty()) {
        "已复核同一 TAG 内核的 DNS 映射、完整连接与进程身份"
    } else {
        "DNS 映射、连接或进程在二次核对时不再有效"
    };
    result
}
