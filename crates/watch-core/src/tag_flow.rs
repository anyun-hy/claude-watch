//! Stable listener ownership, complete connection tuples, and same-core fake-IP evidence.
use crate::{
    error::{CoreError, Result},
    json_value::truthy,
    network::public_destination,
    presentation::text,
    tag_config::{is_fake, normalized_dns_host},
    tag_policy::{self, Evidence, Mode},
    time_parse,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

pub const TAG_BINARY_DIR: &str = "/Applications/TAG.app/Contents/Resources/bin/";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flow {
    pub pid: u32,
    pub protocol: String,
    pub local: (String, u16),
    pub peer: (String, u16),
}
impl Flow {
    pub fn from_value(value: Value) -> Result<Self> {
        let mut flow: Self = serde_json::from_value(value)
            .map_err(|_| CoreError::new("invalid_flow", "连接样本字段无效"))?;
        if flow.pid <= 1
            || flow.pid > i32::MAX as u32
            || !["tcp", "udp"].contains(&flow.protocol.as_str())
            || flow.local.1 == 0
            || flow.peer.1 == 0
        {
            return Err(CoreError::new("invalid_flow", "连接进程、协议或端口无效"));
        }
        for address in [&mut flow.local.0, &mut flow.peer.0] {
            *address = address
                .parse::<IpAddr>()
                .map_err(|_| CoreError::new("invalid_flow", "连接地址无效"))?
                .to_string();
        }
        Ok(flow)
    }
}
fn integer(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|s| s.trim().parse().ok()))
}
pub fn parse_endpoint(value: &str) -> Result<(String, u16)> {
    let raw = value.split(" (").next().unwrap_or("");
    let (host, port) = raw
        .rsplit_once(':')
        .ok_or_else(|| CoreError::new("invalid_endpoint", "连接端点格式无效"))?;
    if port.is_empty() || !port.bytes().all(|v| v.is_ascii_digit()) {
        return Err(CoreError::new("invalid_port", "连接端口无效"));
    }
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| CoreError::new("invalid_port", "连接端口无效"))?;
    let host = host
        .trim_matches(['[', ']'])
        .split('%')
        .next()
        .unwrap_or("");
    let address = host
        .parse::<IpAddr>()
        .map_err(|_| CoreError::new("invalid_endpoint", "连接地址不是明确IP"))?;
    Ok((address.to_string(), port))
}
pub fn is_tag_process(record: &Value, uid: u32) -> bool {
    let Some(executable) = record.get("executable").and_then(Value::as_str) else {
        return false;
    };
    let Some(name) = executable.strip_prefix(TAG_BINARY_DIR) else {
        return false;
    };
    name.starts_with("mihomo")
        && !name.contains('/')
        && record["uid"]
            .as_u64()
            .is_some_and(|v| v == 0 || v == u64::from(uid))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEvidence {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
    pub source: String,
}
fn owner_from_field(value: &str) -> Option<u32> {
    let (name, pid) = value.split_once(':')?;
    if name.is_empty()
        || name.chars().any(|c| c == ':' || c.is_whitespace())
        || pid.starts_with('0')
        || !pid.bytes().all(|v| v.is_ascii_digit())
    {
        return None;
    }
    pid.parse::<u32>().ok().filter(|v| *v > 0)
}
fn kernel_listener_owners(kernel: &CommandEvidence, port: u16) -> (BTreeSet<u32>, bool) {
    let mut owners = BTreeSet::new();
    let mut incomplete = kernel.status != 0 || !kernel.stderr.trim().is_empty();
    for line in kernel.stdout.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 6
            || !["tcp4", "tcp6", "tcp46"].contains(&fields[0])
            || fields[5] != "LISTEN"
        {
            continue;
        }
        let Some((host, raw_port)) = fields[3].rsplit_once('.') else {
            continue;
        };
        if raw_port != port.to_string() || !["127.0.0.1", "*", "0.0.0.0", "::"].contains(&host) {
            continue;
        }
        let ids: Vec<_> = fields[6..]
            .iter()
            .filter_map(|v| owner_from_field(v))
            .collect();
        if ids.len() != 1 {
            incomplete = true;
        } else {
            owners.insert(ids[0]);
        }
    }
    (owners, incomplete)
}
pub fn listener_fallback(
    lsof: CommandEvidence,
    kernel: Option<&CommandEvidence>,
) -> CommandEvidence {
    listener_fallback_for_port(lsof, kernel, 7890)
}
pub fn listener_fallback_for_port(
    lsof: CommandEvidence,
    kernel: Option<&CommandEvidence>,
    port: u16,
) -> CommandEvidence {
    if port == 0 {
        return CommandEvidence { status:1, stdout:String::new(), stderr:"invalid listener port".into(), source:lsof.source };
    }
    if lsof.status != 1 || !lsof.stdout.trim().is_empty() || !lsof.stderr.trim().is_empty() {
        return lsof;
    }
    let Some(kernel) = kernel else { return lsof };
    let (_, mut failed) = kernel_listener_owners(kernel, port);
    let port_text = port.to_string();
    let mut output = Vec::new();
    if kernel.status == 0 && kernel.stderr.trim().is_empty() {
        for line in kernel.stdout.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 6
                || !["tcp4", "tcp6", "tcp46"].contains(&fields[0])
                || fields[5] != "LISTEN"
            {
                continue;
            }
            let Some((host, raw_port)) = fields[3].rsplit_once('.') else {
                continue;
            };
            if raw_port != port_text || !["127.0.0.1", "*", "0.0.0.0", "::"].contains(&host) {
                continue;
            }
            let owners: Vec<_> = fields[6..]
                .iter()
                .filter_map(|v| owner_from_field(v))
                .collect();
            if owners.len() != 1 {
                failed = true;
                continue;
            }
            output.push(format!("p{}", owners[0]));
            output.push(format!(
                "n{}:{port}",
                if host == "::" { "[::]" } else { host }
            ));
        }
    }
    failed |= output.is_empty();
    CommandEvidence {
        status: if failed { 1 } else { 0 },
        stdout: output.join("\n"),
        stderr: if failed {
            "kernel listener metadata incomplete".into()
        } else {
            String::new()
        },
        source: "netstat".into(),
    }
}
pub fn inspect_entry(
    before: &BTreeMap<u32, Value>,
    after: &BTreeMap<u32, Value>,
    listener: &CommandEvidence,
    reachable: bool,
    uid: u32,
) -> Value {
    let mut pids = BTreeSet::new();
    let mut pid = None;
    let mut public = false;
    for line in listener.stdout.lines() {
        if let Some(raw) = line
            .strip_prefix('p')
            .filter(|v| !v.is_empty() && v.bytes().all(|v| v.is_ascii_digit()))
        {
            pid = raw.parse::<u32>().ok();
        } else if let Some(endpoint) = line.strip_prefix('n') {
            if let Some(pid) = pid {
                if ["127.0.0.1:7890", "*:7890", "0.0.0.0:7890", "[::]:7890"].contains(&endpoint) {
                    pids.insert(pid);
                    public |= endpoint != "127.0.0.1:7890";
                }
            }
        }
    }
    let mut report = json!({"endpoint":"http://127.0.0.1:7890","state":"unconfirmed","owners":[],"public_listener":public,"source":listener.source});
    if !reachable {
        report["state"] = json!("unavailable");
        report["reason"] = json!("7890 不可连接");
        return report;
    }
    if pids.is_empty() || listener.status != 0 || !listener.stderr.trim().is_empty() {
        report["reason"] = json!("端口可连接，但监听者身份读取不完整");
        return report;
    }
    let mut owners = Vec::new();
    for pid in pids {
        let first = before.get(&pid).filter(|v| v.is_object() && truthy(v));
        let second = after.get(&pid).filter(|v| v.is_object() && truthy(v));
        if first.is_none() || first != second {
            report["owners"] = json!(owners);
            report["reason"] = json!("监听进程身份在采样间变化或不可读取");
            return report;
        }
        let second = second.unwrap();
        let mut owner = second.clone();
        owner["pid"] = json!(pid);
        owners.push(owner);
        if !is_tag_process(second, uid) {
            report["owners"] = json!(owners);
            report["state"] = json!("mismatch");
            report["reason"] = json!("7890 监听者不匹配 TAG 安装目录中的 Mihomo");
            return report;
        }
    }
    report["owners"] = json!(owners);
    report["state"] = json!("verified");
    report["reason"] = json!("端口可连接，监听进程路径及启动身份匹配 TAG");
    report
}
pub fn dns_listener_matches(
    kernel: &CommandEvidence,
    port: u16,
    owner: &Value,
    processes: &BTreeMap<u32, Value>,
    uid: u32,
) -> bool {
    let Some(pid) = owner["pid"].as_u64().and_then(|v| u32::try_from(v).ok()) else {
        return false;
    };
    let Some(current) = processes.get(&pid) else {
        return false;
    };
    if !is_tag_process(current, uid)
        || ["uid", "stamp", "executable"]
            .iter()
            .any(|k| current.get(*k) != owner.get(*k))
    {
        return false;
    }
    if ["start_seconds", "start_microseconds"]
        .iter()
        .any(|key| owner.get(*key).is_some() && current.get(*key) != owner.get(*key))
    {
        return false;
    }
    let (listeners, incomplete) = kernel_listener_owners(kernel, port);
    !incomplete && listeners == BTreeSet::from([pid])
}
pub fn source_candidate(record: &Value, flow: &Flow, process_start: Option<f64>, now: f64) -> bool {
    let metadata = &record["metadata"];
    if !record.is_object() || !metadata.is_object() || !now.is_finite() {
        return false;
    }
    let address = metadata["sourceIP"]
        .as_str()
        .and_then(|s| s.parse::<IpAddr>().ok())
        .map(|v| v.to_string());
    if address.as_deref() != Some(&flow.local.0)
        || integer(&metadata["sourcePort"]) != Some(i64::from(flow.local.1))
        || text(metadata, "network").to_lowercase() != flow.protocol
    {
        return false;
    }
    let declared = metadata.get("processID").unwrap_or(&metadata["pid"]);
    if truthy(declared) && integer(declared) != Some(i64::from(flow.pid)) {
        return false;
    }
    let started = record["start"].as_str().and_then(time_parse::rfc3339);
    let Some((started, process_start)) = started.zip(process_start.filter(|v| v.is_finite()))
    else {
        return false;
    };
    started >= process_start - 2.0
        && started <= now + 2.0
        && !text(record, "id").is_empty()
        && record["chains"]
            .as_array()
            .is_some_and(|v| v.iter().all(Value::is_string))
}
pub fn record_identity(record: &Value) -> Value {
    let mut result = serde_json::Map::new();
    for key in ["id", "start", "metadata", "chains", "rule", "rulePayload"] {
        result.insert(key.into(), record[key].clone());
    }
    Value::Object(result)
}

pub fn parse_dns_answer(
    stdout: &str,
    stderr: &str,
    status: i32,
    host: &str,
) -> Result<(String, u32)> {
    if status != 0 || !stderr.trim().is_empty() || !stdout.contains("status: NOERROR") {
        return Err(CoreError::new(
            "dns_query_failed",
            "本机 DNS 查询没有返回成功响应",
        ));
    }
    let rows: Vec<_> = stdout
        .lines()
        .filter(|s| !s.trim().is_empty() && !s.starts_with(';'))
        .collect();
    if rows.len() != 1 {
        return Err(CoreError::new(
            "dns_answer_not_unique",
            "DNS 没有返回唯一 A 记录",
        ));
    }
    let fields: Vec<_> = rows[0].split_whitespace().collect();
    if fields.len() != 5 {
        return Err(CoreError::new(
            "dns_answer_not_unique",
            "DNS A 记录字段不完整",
        ));
    }
    let ttl = fields[1].parse::<u32>().ok().filter(|v| *v > 0);
    if normalized_dns_host(fields[0]).as_deref() != Some(host)
        || fields[2] != "IN"
        || fields[3] != "A"
        || !fields[1].bytes().all(|b| b.is_ascii_digit())
        || ttl.is_none()
    {
        return Err(CoreError::new(
            "dns_answer_invalid",
            "DNS A 记录名称、类别或时效无效",
        ));
    }
    let address = fields[4]
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| CoreError::new("dns_answer_invalid", "DNS A 记录地址无效"))?;
    Ok((address.to_string(), ttl.unwrap().min(2)))
}
pub fn translated_fakeip_destination(metadata: &Value, peer: &(String, u16)) -> bool {
    if !text(metadata, "type").eq_ignore_ascii_case("tun")
        || metadata["dnsMode"] != "fake-ip"
        || !is_fake(&peer.0)
    {
        return false;
    }
    let ip = &metadata["destinationIP"];
    ip.is_null() || ip == "" || ip.as_str().and_then(public_destination).is_some()
}
pub fn fakeip_destination_matches(
    proof: &Value,
    record: &Value,
    flow: &Flow,
    stamp: &str,
    now: f64,
) -> bool {
    let metadata = &record["metadata"];
    let expected_host = normalized_dns_host(text(metadata, "host"));
    if expected_host.is_none() {
        return false;
    }
    let Some(observed) = proof["observed_at"].as_f64().filter(|v| v.is_finite()) else {
        return false;
    };
    let Some(expires) = proof["expires_at"].as_f64().filter(|v| v.is_finite()) else {
        return false;
    };
    proof.is_object()
        && now.is_finite()
        && translated_fakeip_destination(metadata, &flow.peer)
        && proof["kind"] == "same_core_fakeip_mapping"
        && proof["source_pid"] == flow.pid
        && proof["source_started"] == stamp
        && proof["source"] == json!(flow.local)
        && proof["peer"] == json!(flow.peer)
        && proof["protocol"] == flow.protocol
        && proof.get("connection_start") == record.get("start")
        && proof["host"].as_str().map(str::to_owned) == expected_host
        && proof["address"] == flow.peer.0
        && observed <= now
        && now <= expires
        && expires <= observed + 2.0
}
pub fn destination_evidence(metadata: &Value) -> Value {
    let port = integer(&metadata["destinationPort"]).filter(|v| (1..65536).contains(v));
    let raw = &metadata["destinationIP"];
    let empty = |state: &str| json!(["", port, state, ""]);
    if raw.is_null() || raw == "" {
        return empty("missing");
    }
    let Some(raw) = raw.as_str() else {
        return empty("invalid");
    };
    let Ok(address) = raw.parse::<IpAddr>() else {
        return empty("invalid");
    };
    if is_fake(&address.to_string()) {
        return empty("synthetic");
    }
    let Some(address) = public_destination(raw) else {
        return empty("nonpublic");
    };
    let country = text(metadata, "destinationGeoIP");
    let country = if country.len() == 2 && country.bytes().all(|b| b.is_ascii_alphabetic()) {
        country.to_ascii_uppercase()
    } else {
        String::new()
    };
    json!([address, port, "public", country])
}
pub struct CorrelationInput<'a> {
    pub flow: &'a Flow,
    pub stamp: &'a str,
    pub process_start: Option<f64>,
    pub api: &'a Value,
    pub records: &'a [Value],
    pub group: &'a str,
    pub expected_node: &'a str,
    pub now: f64,
    pub fakeip_evidence: &'a Value,
    pub interface: Option<&'a str>,
}
pub fn correlate(input: CorrelationInput<'_>) -> Value {
    let CorrelationInput {
        flow,
        stamp,
        process_start,
        api,
        records,
        group,
        expected_node,
        now,
        fakeip_evidence,
        interface,
    } = input;
    let mut result = json!(flow);
    result["association"] = json!("unconfirmed");
    result["policy"] = json!("unconfirmed");
    result["chains"] = json!([]);
    let via_proxy = flow.peer.0 == "127.0.0.1" && flow.peer.1 == 7890 && flow.protocol == "tcp";
    if flow.peer.0.parse::<IpAddr>().is_ok_and(|v| v.is_loopback()) && !via_proxy {
        result["association"] = json!("local_service");
        result["policy"] = json!("not_applicable");
        result["reason"] = json!("其他本机服务连接，不视为代理绕过");
        return result;
    }
    if via_proxy && (api["state"] != "available" || !truthy(&api["covers_7890"])) {
        result["reason"] =
            json!("控制接口不可用或属于另一内核，不能把 7890 连接与外层 TUN 链强行对应");
        return result;
    }
    if !via_proxy {
        result["interface"] = json!(interface.unwrap_or("unavailable"));
    }
    let mut candidates = Vec::new();
    let mut unproven = false;
    for record in records {
        if !source_candidate(record, flow, process_start, now) {
            continue;
        }
        let metadata = &record["metadata"];
        if via_proxy {
            if !["http", "https", "socks", "socks5"]
                .contains(&text(metadata, "type").to_lowercase().as_str())
            {
                continue;
            }
            if truthy(&metadata["inboundPort"]) && integer(&metadata["inboundPort"]) != Some(7890) {
                continue;
            }
            if truthy(&metadata["inboundIP"])
                && !text(metadata, "inboundIP")
                    .parse::<IpAddr>()
                    .is_ok_and(|v| v.is_loopback())
            {
                continue;
            }
        } else {
            if integer(&metadata["destinationPort"]) != Some(i64::from(flow.peer.1)) {
                continue;
            }
            let exact = metadata["destinationIP"]
                .as_str()
                .and_then(|v| v.parse::<IpAddr>().ok())
                .is_some_and(|v| v.to_string() == flow.peer.0);
            if !exact
                && !fakeip_destination_matches(
                    &fakeip_evidence[text(record, "id")],
                    record,
                    flow,
                    stamp,
                    now,
                )
            {
                unproven |= translated_fakeip_destination(metadata, &flow.peer);
                continue;
            }
        }
        candidates.push(record);
    }
    let ids: BTreeSet<_> = candidates.iter().map(|v| text(v, "id")).collect();
    if ids.len() != candidates.len() {
        result["reason"] = json!("控制器连接标识重复，未关联");
        return result;
    }
    if candidates.len() != 1 {
        result["reason"] = json!(if candidates.is_empty() && unproven {
            "TUN 目标经过 fake-IP 转换，但未取得同一 TAG 内核的有效映射证明；未关联，不能认定直连泄漏"
        } else {
            "没有唯一且时间有效的完整连接匹配；可能被 TUN 接管，不能认定直连泄漏"
        });
        return result;
    }
    let record = candidates[0];
    let metadata = &record["metadata"];
    let destination = destination_evidence(metadata);
    result["association"] = json!("correlated");
    result["host"] = metadata.get("host").cloned().unwrap_or(json!(""));
    result["chains"] = record["chains"].clone();
    result["rule"] = record.get("rule").cloned().unwrap_or(json!(""));
    result["rule_payload"] = record.get("rulePayload").cloned().unwrap_or(json!(""));
    result["connection_id"] = record["id"].clone();
    result["path"] = if via_proxy {
        json!("local_proxy")
    } else {
        metadata.get("type").cloned().unwrap_or(json!("unknown"))
    };
    for (key, index) in [
        ("destination_ip", 0),
        ("destination_port", 1),
        ("destination_ip_state", 2),
        ("destination_country", 3),
    ] {
        result[key] = destination[index].clone();
    }
    let routes: BTreeMap<String, Option<Vec<String>>> = api["route_chains"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(root, v)| {
            (
                root.clone(),
                v.as_array()
                    .and_then(|v| v.iter().map(|v| v.as_str().map(str::to_owned)).collect()),
            )
        })
        .collect();
    let evidence = Evidence {
        api_available: api["state"] == "available",
        mode: Mode::from_wire(api["mode"].as_str()),
        observed_chain: record["chains"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        required_group: group.into(),
        pinned_node: expected_node.into(),
        route_chains: routes,
        matched_rule: record["rule"].as_str().map(str::to_owned),
    };
    let decision = tag_policy::evaluate(&evidence);
    result["policy"] = json!(decision.state.as_str());
    let mut reason = decision.reason.detail().to_owned();
    let proof = &fakeip_evidence[text(record, "id")];
    if !via_proxy && fakeip_destination_matches(proof, record, flow, stamp, now) {
        result["association_evidence"] = proof.clone();
        reason += "；同一 TAG 内核 DNS 映射与本机 fake-IP 已核对";
        if destination[2] != "public" {
            reason += "，公网目标 IP 未提供";
        }
    }
    result["reason"] = json!(reason);
    result
}
