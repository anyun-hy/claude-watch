//! Only public routing evidence is serialized. Controller credentials are never Debug/Serialize payloads.
use crate::{
    error::{CoreError, Result},
    json_value::truthy,
    vpn::{rules_digest_from_published, ObservedField, UpstreamProtocol},
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

pub const RULE_DOMAINS: [&str; 13] = [
    "claude.ai",
    "claude.com",
    "anthropic.com",
    "claudeusercontent.com",
    "challenges.cloudflare.com",
    "datadoghq.com",
    "segment.io",
    "stripe.com",
    "stripe.network",
    "stripecdn.com",
    "intercom.io",
    "intercomcdn.com",
    "intercomassets.com",
];
pub const API_PATHS: [&str; 4] = ["/configs", "/proxies", "/connections", "/rules"];
pub const CONFIG_LIMIT: usize = 4 * 1024 * 1024;
pub fn yaml_scalar(raw: &str) -> Result<String> {
    let raw = raw.trim();
    let value = if raw.starts_with('"') {
        serde_json::from_str::<String>(raw)
            .map_err(|_| CoreError::new("invalid_scalar", "代理标量格式无效"))?
    } else if raw.starts_with('\'') && raw.ends_with('\'') && raw.len() >= 2 {
        raw[1..raw.len() - 1].replace("''", "'")
    } else {
        let value = raw.split(" #").next().unwrap_or("").trim_end();
        if value.chars().any(char::is_whitespace)
            || value.starts_with(['!', '&', '*', '|', '>', '{', '['])
        {
            return Err(CoreError::new("unsupported_scalar", "不支持的代理标量格式"));
        }
        value.into()
    };
    if value.chars().any(|c| (c as u32) < 32) {
        return Err(CoreError::new("invalid_scalar", "代理标量含控制字符"));
    }
    Ok(value)
}
pub struct Credentials {
    endpoint: SocketAddr,
    secret: String,
}
impl Credentials {
    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
    pub fn base(&self) -> String {
        format!("http://{}", self.endpoint)
    }
    pub fn authorization(&self) -> Option<String> {
        if self.secret.is_empty() {
            None
        } else {
            Some(format!("Bearer {}", self.secret))
        }
    }
    pub fn from_parts(authority: &str, secret: String) -> Result<Self> {
        let authority = authority
            .rsplit_once(':')
            .filter(|(host, _)| host.eq_ignore_ascii_case("localhost"))
            .map(|(_, port)| format!("127.0.0.1:{port}"))
            .unwrap_or_else(|| authority.into());
        if authority.contains('%') {
            return Err(CoreError::new(
                "controller_not_loopback",
                "控制接口不接受作用域或模糊主机地址",
            ));
        }
        let endpoint = authority.parse::<SocketAddr>().map_err(|_| {
            CoreError::new(
                "controller_not_loopback",
                "控制接口必须是明确的本机回环地址和端口",
            )
        })?;
        if !matches!(endpoint.ip(),IpAddr::V4(v) if v==Ipv4Addr::LOCALHOST)
            && endpoint.ip() != IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        {
            return Err(CoreError::new(
                "controller_not_loopback",
                "控制接口必须属于本机回环",
            ));
        }
        if endpoint.port() == 0 || secret.len() > 16_384 || secret.chars().any(char::is_control) {
            return Err(CoreError::new(
                "invalid_controller_credentials",
                "控制接口鉴权字段无效",
            ));
        }
        Ok(Self { endpoint, secret })
    }
}
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("endpoint", &self.endpoint)
            .field("secret", &"[redacted]")
            .finish()
    }
}
pub fn controller_credentials(source: &str) -> Result<Credentials> {
    if source.len() > CONFIG_LIMIT {
        return Err(CoreError::new("config_oversize", "代理配置过大"));
    }
    let mut values = BTreeMap::new();
    for line in source.lines() {
        for key in ["external-controller", "secret"] {
            if let Some(raw) = line.strip_prefix(&format!("{key}:")) {
                if values.insert(key, yaml_scalar(raw)?).is_some() {
                    return Err(CoreError::new(
                        "duplicate_controller_field",
                        "控制接口配置含重复字段",
                    ));
                }
            }
        }
    }
    Credentials::from_parts(
        values
            .get("external-controller")
            .map(String::as_str)
            .unwrap_or(""),
        values.get("secret").cloned().unwrap_or_default(),
    )
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FakeRange {
    network: u32,
    prefix: u32,
}
impl FakeRange {
    pub fn parse(value: &str) -> Option<Self> {
        let (ip, prefix) = value.split_once('/')?;
        let ip = ip.parse::<Ipv4Addr>().ok()?;
        let prefix = prefix.parse::<u32>().ok()?;
        if !(15..=32).contains(&prefix)
            || u32::from(ip) >> 17 != u32::from(Ipv4Addr::new(198, 18, 0, 0)) >> 17
        {
            return None;
        }
        let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
        Some(Self {
            network: u32::from(ip) & mask,
            prefix,
        })
    }
    pub fn contains(&self, ip: &str) -> bool {
        ip.parse::<Ipv4Addr>()
            .is_ok_and(|v| u32::from(v) >> (32 - self.prefix) == self.network >> (32 - self.prefix))
    }
    pub fn canonical(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network), self.prefix)
    }
}
pub fn is_fake(ip: &str) -> bool {
    FakeRange {
        network: 0xc6120000,
        prefix: 15,
    }
    .contains(ip)
}
pub fn fakeip_dns_config(source: &str) -> Result<(u16, FakeRange)> {
    if source.len() > CONFIG_LIMIT {
        return Err(CoreError::new("dns_config_oversize", "DNS 配置过大"));
    }
    let mut values = BTreeMap::new();
    let mut inside = false;
    let mut blocks = 0;
    for line in source.lines() {
        if line
            .strip_prefix("dns:")
            .is_some_and(|s| s.trim().is_empty() || s.trim_start().starts_with('#'))
        {
            blocks += 1;
            inside = true;
            continue;
        }
        if inside
            && !line.trim().is_empty()
            && !line.starts_with(char::is_whitespace)
            && !line.starts_with('#')
        {
            inside = false
        }
        if inside {
            for key in ["enable", "listen", "enhanced-mode", "fake-ip-range"] {
                if let Some(raw) = line.strip_prefix(&format!("  {key}:")) {
                    if values.insert(key, yaml_scalar(raw)?).is_some() {
                        return Err(CoreError::new("dns_config_duplicate", "DNS 配置含重复字段"));
                    }
                }
            }
        }
    }
    if blocks != 1
        || values.get("enable").map(String::as_str) != Some("true")
        || values.get("enhanced-mode").map(String::as_str) != Some("fake-ip")
    {
        return Err(CoreError::new(
            "dns_not_fakeip",
            "未确认唯一启用的 fake-IP DNS 配置",
        ));
    }
    let range = values
        .get("fake-ip-range")
        .and_then(|s| FakeRange::parse(s))
        .ok_or_else(|| CoreError::new("unsupported_fakeip_range", "fake-IP 地址范围不受支持"))?;
    let (address, port) = values
        .get("listen")
        .and_then(|s| s.rsplit_once(':'))
        .ok_or_else(|| {
            CoreError::new(
                "dns_listener_not_loopback_reachable",
                "未取得本机 DNS 监听地址",
            )
        })?;
    if port.is_empty() || !port.bytes().all(|v| v.is_ascii_digit()) {
        return Err(CoreError::new(
            "dns_listener_not_loopback_reachable",
            "DNS 监听端口无效",
        ));
    }
    let port =
        port.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(|| {
            CoreError::new("dns_listener_not_loopback_reachable", "DNS 监听端口无效")
        })?;
    if !["", "0.0.0.0", "127.0.0.1", "[::]"].contains(&address) {
        return Err(CoreError::new(
            "dns_listener_not_loopback_reachable",
            "DNS 监听地址不属于本机范围",
        ));
    }
    Ok((port, range))
}
pub fn normalized_dns_host(value: &str) -> Option<String> {
    let value = value.to_ascii_lowercase().trim_end_matches('.').to_owned();
    if value.is_empty() || value.len() > 253 || value.parse::<IpAddr>().is_ok() {
        return None;
    }
    let parts: Vec<_> = value.split('.').collect();
    if parts.len() < 2
        || parts.iter().any(|s| {
            s.is_empty()
                || s.len() > 63
                || !s.as_bytes()[0].is_ascii_alphanumeric()
                || !s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
                || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return None;
    }
    Some(value)
}
/// True when a selector group's current selection ultimately resolves to a
/// bypass target (DIRECT / REJECT / REJECT-DROP / PASS), including groups that
/// select other groups.  A missing, cyclic or otherwise unresolvable chain is
/// never guessed: it answers false so callers cannot invent a bypass verdict.
fn group_is_direct(proxies: &Value, name: &str, depth: u8) -> bool {
    if depth == 0 {
        return false;
    }
    let Some(value) = proxies.get(name).filter(|v| v.is_object()) else {
        return false;
    };
    let Some(now) = value.get("now").and_then(Value::as_str) else {
        return false;
    };
    if matches!(
        now.to_ascii_uppercase().as_str(),
        "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS"
    ) {
        return true;
    }
    group_is_direct(proxies, now, depth - 1)
}
pub fn resolve_chain(proxies: &Value, group: &str) -> Option<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut path = Vec::new();
    let mut name = group;
    for _ in 0..16 {
        if !seen.insert(name) {
            return None;
        }
        let value = proxies.get(name).filter(|v| v.is_object())?;
        path.push(name.to_owned());
        if value.get("now").is_some_and(truthy) {
            name = value["now"].as_str()?;
        } else {
            if ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"]
                .contains(&name.to_uppercase().as_str())
                || value.get("type").and_then(Value::as_str).is_none()
                || value.get("all").is_some()
                || ["selector", "urltest", "fallback", "loadbalance", "relay"]
                    .contains(&value["type"].as_str()?.to_lowercase().as_str())
            {
                return None;
            }
            path.reverse();
            return Some(path);
        }
    }
    None
}
pub fn published_rules(payload: &Value) -> Result<Value> {
    let values = payload["rules"]
        .as_array()
        .filter(|v| v.len() <= 16_384)
        .ok_or_else(|| {
            CoreError::new("api_rules_schema_invalid", "控制接口规则表格式不完整或过大")
        })?;
    fn safe(s: &str, max: usize) -> bool {
        !s.is_empty() && s.chars().count() <= max && !s.chars().any(|c| (c as u32) < 32)
    }
    /// Normalizes one runtime rule.  The second tuple member reports a rule the
    /// user disabled in the client: it still appears in the table but never
    /// matches, so counting it as coverage would be a lie.
    fn canonical(v: &Value) -> Option<(String, bool)> {
        let owned;
        let v = if let Some(s) = v.as_str() {
            if !safe(s, 1024) {
                return None;
            }
            let parts: Vec<_> = s.split(',').map(str::trim).collect();
            let kind = parts.first()?;
            owned = json!({"type":kind,"payload":parts.get(1).copied().unwrap_or(""),"proxy":if kind.eq_ignore_ascii_case("match"){parts.get(1).copied().unwrap_or("")}else{parts.get(2).copied().unwrap_or("")}});
            &owned
        } else {
            v
        };
        // A plain-string rule carries no extra block; only a structured rule
        // can prove it was switched off.
        let disabled = v["extra"]["disabled"].as_bool() == Some(true);
        let raw = v["type"].as_str()?;
        let key: String = raw
            .to_ascii_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        let kind = match key.as_str() {
            "domain" => "DOMAIN",
            "domainsuffix" => "DOMAIN-SUFFIX",
            "domainkeyword" => "DOMAIN-KEYWORD",
            "match" => "MATCH",
            "geosite" => "GEOSITE",
            "ruleset" => "RULE-SET",
            "dstport" => "DST-PORT",
            "ipcidr" => "IP-CIDR",
            "ipcidr6" => "IP-CIDR6",
            "geoip" => "GEOIP",
            "srcipcidr" => "SRC-IP-CIDR",
            "srcport" => "SRC-PORT",
            "network" => "NETWORK",
            "intype" => "IN-TYPE",
            "processname" => "PROCESS-NAME",
            _ => return None,
        };
        let proxy = v["proxy"].as_str()?;
        if !safe(proxy, 256) {
            return None;
        }
        if kind == "MATCH" {
            return Some((format!("MATCH,{proxy}"), disabled));
        }
        if ["DOMAIN", "DOMAIN-SUFFIX"].contains(&kind) {
            let payload = v["payload"].as_str()?;
            if !safe(payload, 253) {
                return None;
            }
            let subject = payload
                .to_lowercase()
                .trim_start_matches(['+', '.'])
                .to_owned();
            if subject.is_empty()
                || !subject.as_bytes()[0].is_ascii_alphanumeric()
                || !subject.as_bytes()[subject.len() - 1].is_ascii_alphanumeric()
                || !subject
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            {
                return None;
            }
            Some((format!("{kind},{subject},{proxy}"), disabled))
        } else {
            Some((format!("{kind},*,{proxy}"), disabled))
        }
    }
    let mut entries = Vec::new();
    let mut disabled_domains = Vec::new();
    let mut relevant = 0;
    let mut broad = 0;
    for value in values {
        let Some((value, disabled)) = canonical(value) else {
            continue;
        };
        let fields: Vec<_> = value.split(',').map(str::trim).collect();
        let include = if ["DOMAIN", "DOMAIN-SUFFIX"].contains(&fields[0]) {
            let keep = RULE_DOMAINS.iter().any(|d| {
                *d == fields[1]
                    || (fields[0] == "DOMAIN-SUFFIX" && d.ends_with(&format!(".{}", fields[1])))
            });
            relevant += usize::from(keep);
            keep
        } else {
            let keep = broad < 128;
            broad += usize::from(keep);
            keep
        };
        if disabled {
            // The rule exists but never matches.  Naming the ecosystem domain
            // keeps the gap visible instead of silently reading as coverage.
            if include && ["DOMAIN", "DOMAIN-SUFFIX"].contains(&fields[0]) {
                disabled_domains.push(fields[1].to_owned());
            }
            continue;
        }
        if include {
            entries.push(value)
        }
    }
    Ok(
        json!({"state":"available","reason":"","entries":entries,"total":values.len(),"relevant":relevant,"broad":broad,"disabled_domains":disabled_domains}),
    )
}
/// Builds independent public API evidence. A missing rule table does not erase a verified mode.
pub fn api_snapshot(
    base: &str,
    group: &str,
    configs: &Value,
    proxies_payload: &Value,
    connections_payload: &Value,
    rules: Value,
) -> Result<(Value, Vec<Value>)> {
    let mode = configs["mode"]
        .as_str()
        .filter(|v| ["rule", "global", "direct"].contains(v))
        .ok_or_else(|| CoreError::new("api_schema_incomplete", "控制接口模式无效"))?;
    let proxies = proxies_payload
        .get("proxies")
        .filter(|v| v.is_object())
        .ok_or_else(|| CoreError::new("api_schema_incomplete", "控制接口代理选择表无效"))?;
    let connections = connections_payload["connections"]
        .as_array()
        .ok_or_else(|| CoreError::new("api_schema_incomplete", "控制接口连接表无效"))?;
    let mut roots = BTreeSet::from(["GLOBAL", group]);
    for connection in connections {
        if let Some(root) = connection["chains"]
            .as_array()
            .and_then(|v| v.last())
            .and_then(Value::as_str)
        {
            roots.insert(root);
        }
    }
    let routes: BTreeMap<_, _> = roots
        .into_iter()
        .filter(|v| !v.is_empty() && v.chars().count() <= 256)
        .map(|root| (root, resolve_chain(proxies, root)))
        .collect();
    let global = resolve_chain(proxies, "GLOBAL").and_then(|v| v.first().cloned());
    // An empty group is a normal default (e.g. the observe path hardcodes "").
    // Fall back to GLOBAL for both `global` mode and an empty rule group so the
    // selected node is still resolvable instead of silently reading as null.
    let selected = resolve_chain(
        proxies,
        if mode == "global" || group.is_empty() { "GLOBAL" } else { group },
    )
    .and_then(|v| v.first().cloned());
    // Rules pointing at a selector whose current selection is DIRECT/REJECT
    // never reach a proxy node.  Nested groups are followed; an unresolvable
    // chain is never guessed into either answer.
    let mut direct_groups = Vec::new();
    if let Some(map) = proxies.as_object() {
        for (name, _) in map {
            // Leaf nodes carry no "now" and answer false on their own; no
            // shape-based prefilter is needed or trusted here.
            if group_is_direct(proxies, name, 8) {
                direct_groups.push(name.clone());
            }
        }
    }
    direct_groups.sort();
    let covers = ["port", "mixed-port", "socks-port"]
        .iter()
        .any(|key| configs[*key] == 7890);
    Ok((
        json!({"state":"available","controller":base,"mode":mode,"covers_7890":covers,
        "selected_node":selected,"route_chains":routes,"global_node":global,"direct_groups":direct_groups,"reason":"","rules":rules}),
        connections.clone(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerFastSnapshot {
    pub controller_base: String,
    pub running_mode: String,
    pub upstream_endpoint: Option<String>,
    pub upstream_protocol: ObservedField<UpstreamProtocol>,
    pub tun_enabled: ObservedField<bool>,
    pub selected_group: ObservedField<String>,
    pub selected_node: ObservedField<String>,
    pub proxy_chain: ObservedField<Vec<String>>,
    pub rules_digest: ObservedField<String>,
    pub revision: Option<String>,
}

pub fn inspect_controller_port(
    configs: &Value,
    expected_host: &str,
    expected_port: Option<u16>,
) -> (Option<String>, ObservedField<UpstreamProtocol>) {
    let host = if expected_host.trim().is_empty() {
        "127.0.0.1"
    } else {
        expected_host.trim()
    };
    let http_port = configs
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .filter(|&p| p > 0);
    let mixed_port = configs
        .get("mixed-port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .filter(|&p| p > 0);
    let socks_port = configs
        .get("socks-port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .filter(|&p| p > 0);

    if let Some(target) = expected_port {
        if http_port == Some(target) {
            return (
                Some(format!("http://{host}:{target}")),
                ObservedField::Known(UpstreamProtocol::HttpConnect),
            );
        }
        if mixed_port == Some(target) {
            return (
                Some(format!("http://{host}:{target}")),
                ObservedField::Known(UpstreamProtocol::MixedHttp),
            );
        }
        if socks_port == Some(target) {
            return (
                Some(format!("http://{host}:{target}")),
                ObservedField::Known(UpstreamProtocol::SocksOnly),
            );
        }
    }

    if let Some(p) = mixed_port {
        return (
            Some(format!("http://{host}:{p}")),
            ObservedField::Known(UpstreamProtocol::MixedHttp),
        );
    }
    if let Some(p) = http_port {
        return (
            Some(format!("http://{host}:{p}")),
            ObservedField::Known(UpstreamProtocol::HttpConnect),
        );
    }
    if let Some(p) = socks_port {
        return (
            Some(format!("http://{host}:{p}")),
            ObservedField::Known(UpstreamProtocol::SocksOnly),
        );
    }
    (
        None,
        ObservedField::Unknown("controller_proxy_ports_disabled".into()),
    )
}

pub fn fast_controller_snapshot(
    base: &str,
    group: &str,
    expected_host: &str,
    expected_port: Option<u16>,
    configs: &Value,
    proxies_payload: &Value,
    rules_payload: Option<&Value>,
) -> Result<ControllerFastSnapshot> {
    let mode_raw = configs["mode"]
        .as_str()
        .ok_or_else(|| CoreError::new("api_schema_incomplete", "控制接口模式无效"))?;
    let running_mode = mode_raw.to_ascii_lowercase();
    if !matches!(running_mode.as_str(), "rule" | "global" | "direct") {
        return Err(CoreError::new("api_schema_incomplete", "控制接口模式无效"));
    }
    let proxies = proxies_payload
        .get("proxies")
        .filter(|v| v.is_object())
        .ok_or_else(|| CoreError::new("api_schema_incomplete", "控制接口代理选择表无效"))?;
    let effective_group = if running_mode == "global" || group.trim().is_empty() {
        "GLOBAL"
    } else {
        group.trim()
    };
    let (selected_group, selected_node, proxy_chain) = if running_mode == "direct" {
        (
            ObservedField::Known(effective_group.to_string()),
            ObservedField::Known("DIRECT".into()),
            ObservedField::Known(vec!["DIRECT".into()]),
        )
    } else if let Some(chain_leaf_first) = resolve_chain(proxies, effective_group) {
        let leaf = chain_leaf_first.first().cloned().unwrap_or_default();
        let mut root_to_leaf = chain_leaf_first;
        root_to_leaf.reverse();
        (
            ObservedField::Known(effective_group.to_string()),
            ObservedField::Known(leaf),
            ObservedField::Known(root_to_leaf),
        )
    } else if let Some(now) = proxies
        .get(effective_group)
        .and_then(|v| v.get("now"))
        .and_then(Value::as_str)
    {
        // Even if the group currently selects DIRECT or REJECT (which `resolve_chain`
        // returns None for), expose the actual selection so `compare_vpn` reports Mismatched!
        (
            ObservedField::Known(effective_group.to_string()),
            ObservedField::Known(now.to_string()),
            ObservedField::Known(vec![effective_group.to_string(), now.to_string()]),
        )
    } else {
        (
            ObservedField::Unknown("selector_group_unresolvable".into()),
            ObservedField::Unknown("selected_node_unresolvable".into()),
            ObservedField::Unknown("proxy_chain_unresolvable".into()),
        )
    };

    let (upstream_endpoint, upstream_protocol) =
        inspect_controller_port(configs, expected_host, expected_port);
    let tun_enabled = match configs
        .get("tun")
        .and_then(|t| t.get("enable"))
        .and_then(Value::as_bool)
    {
        Some(v) => ObservedField::Known(v),
        None => ObservedField::Unknown("controller_tun_field_absent".into()),
    };
    let rules_digest = match rules_payload {
        Some(raw) => match published_rules(raw)
            .ok()
            .and_then(|pub_rules| rules_digest_from_published(&pub_rules))
        {
            Some(digest) => ObservedField::Known(digest),
            None => ObservedField::Unknown("controller_rules_invalid".into()),
        },
        None => ObservedField::Unknown("controller_rules_not_sampled".into()),
    };
    let revision = configs
        .get("revision")
        .or_else(|| proxies_payload.get("revision"))
        .and_then(|v| {
            v.as_str()
                .map(str::to_owned)
                .or_else(|| v.as_u64().map(|n| n.to_string()))
        });

    Ok(ControllerFastSnapshot {
        controller_base: base.to_string(),
        running_mode,
        upstream_endpoint,
        upstream_protocol,
        tun_enabled,
        selected_group,
        selected_node,
        proxy_chain,
        rules_digest,
        revision,
    })
}
