//! Pure VPN supervision expectation, read-only observation, epoch, and comparison contracts.
//!
//! Watch never mutates VPN configuration, switches nodes/modes, or accepts an observed
//! drift as a new expectation. Comparison is a pure function over saved expectation,
//! read-only observation, and wall clock.

use crate::{
    channel::CLOCK_ROLLBACK_TOLERANCE_SECONDS,
    config::valid_loopback_proxy,
    error::{CoreError, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use url::Url;

const RESERVED_DIRECT_HOPS: [&str; 5] = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocol {
    HttpConnect,
    MixedHttp,
    SocksOnly,
}

impl UpstreamProtocol {
    pub fn supports_http_connect(self) -> bool {
        matches!(self, Self::HttpConnect | Self::MixedHttp)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::HttpConnect => "http_connect",
            Self::MixedHttp => "mixed_http",
            Self::SocksOnly => "socks_only",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
pub enum ObservedField<T> {
    Known(T),
    Unknown(String),
    Unsupported(String),
}

impl<T> Default for ObservedField<T> {
    fn default() -> Self {
        Self::Unknown("unobserved".into())
    }
}

impl<T> ObservedField<T> {
    pub fn known(&self) -> Option<&T> {
        match self {
            Self::Known(v) => Some(v),
            Self::Unknown(_) | Self::Unsupported(_) => None,
        }
    }

    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known(_))
    }

    pub fn unavailable_reason(&self, fallback: &str) -> String {
        match self {
            Self::Known(_) => String::new(),
            Self::Unknown(reason) if !reason.trim().is_empty() => reason.clone(),
            Self::Unsupported(reason) if !reason.trim().is_empty() => {
                format!("unsupported:{reason}")
            }
            Self::Unknown(_) => fallback.to_string(),
            Self::Unsupported(_) => format!("unsupported:{fallback}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VpnEpoch {
    pub observer_boot_id: String,
    pub change_generation: u64,
}

impl VpnEpoch {
    pub fn new(observer_boot_id: impl Into<String>, change_generation: u64) -> Self {
        Self {
            observer_boot_id: observer_boot_id.into(),
            change_generation,
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.observer_boot_id.trim().is_empty()
            && self.observer_boot_id.len() <= 128
            && !self.observer_boot_id.chars().any(char::is_control)
            && self.change_generation > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "level", content = "detail", rename_all = "snake_case")]
pub enum ObservationConsistency {
    /// Verified via monotonic source revision or continuous event stream.
    RevisionVerified,
    /// Verified via pre/post read boundary check; cannot prove absence of
    /// sub-interval A->B->A transient switches between polls.
    #[default]
    BoundaryVerified,
    /// Pre/post read mismatch or source restart detected during non-atomic sampling.
    InconsistentSnapshot(String),
    /// Source unreachable, timed out, or failed validation.
    Unavailable(String),
}

impl ObservationConsistency {
    pub fn is_consistent(&self) -> bool {
        matches!(self, Self::RevisionVerified | Self::BoundaryVerified)
    }

    /// True only when backed by a monotonic source revision or continuous stream
    /// that can detect rapid A->B->A transitions between polls.
    pub fn detects_inter_poll_transient_switches(&self) -> bool {
        matches!(self, Self::RevisionVerified)
    }
}

/// User-confirmed VPN supervision expectation saved in Watch config.
///
/// Client type (`proxy_mode`), upstream proxy URL (`proxy_url`), and selector group
/// (`proxy_group`) share authority with top-level `Config`. Optional requirements
/// (`running_mode`, `require_tun`, `require_system_proxy`, `expected_node`,
/// `expected_chain`, `expected_rules_digest`) use `None` (or empty vec) when the
/// user has not required checking that attribute; `None` is never conflated with `Some(false)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct VpnExpectation {
    pub configured: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy_mode: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proxy_group: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_tun: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_system_proxy: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_node: Option<String>,
    #[serde(default)]
    pub expected_chain: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_rules_digest: Option<String>,
}

fn invalid_vpn(detail: &str) -> CoreError {
    CoreError::new("invalid_config", detail)
}

pub fn normalize_loopback_http_endpoint(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if !valid_loopback_proxy(trimmed) {
        return None;
    }
    let parsed = Url::parse(trimmed).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port()?;
    Some(format!("http://{host}:{port}"))
}

fn valid_node_or_hop(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty()
        && trimmed == name
        && name.chars().count() <= 256
        && !name.chars().any(char::is_control)
        && !RESERVED_DIRECT_HOPS.contains(&name.to_ascii_uppercase().as_str())
}

fn valid_sha256_hex(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl VpnExpectation {
    pub fn unconfigured() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if !self.proxy_mode.is_empty()
            && !matches!(
                self.proxy_mode.as_str(),
                "tag" | "clash-verge" | "shadowrocket" | "sing-box" | "clashx" | "surge" | "auto"
            )
        {
            return Err(invalid_vpn("VPN 预期代理客户端类型无效"));
        }
        if !self.proxy_url.is_empty() && !valid_loopback_proxy(&self.proxy_url) {
            return Err(invalid_vpn("VPN 预期上游地址必须为数字回环 HTTP 入口"));
        }
        if self.configured && self.proxy_url.trim().is_empty() {
            return Err(invalid_vpn("已启用 VPN 监督预期时必须明确配置 HTTP 上游地址"));
        }
        if self.proxy_group.chars().count() > 256
            || self.proxy_group.chars().any(|c| matches!(c, '\n' | '\r' | '\0'))
        {
            return Err(invalid_vpn("VPN 预期代理组名称无效"));
        }
        if let Some(ref mode) = self.running_mode {
            if !matches!(mode.as_str(), "global" | "rule" | "direct") {
                return Err(invalid_vpn("VPN 预期运行模式必须为 global、rule 或 direct"));
            }
            if mode == "direct" {
                return Err(invalid_vpn("VPN 监督预期不允许将 direct 直连模式作为受保护预期"));
            }
        }
        if let Some(ref node) = self.expected_node {
            if !valid_node_or_hop(node) {
                return Err(invalid_vpn("VPN 预期节点名称无效或指向直连/拒绝节点"));
            }
        }
        if self.expected_chain.len() > 16
            || self.expected_chain.iter().any(|hop| !valid_node_or_hop(hop))
        {
            return Err(invalid_vpn("VPN 预期代理链无效或包含直连/拒绝节点"));
        }
        if let Some(ref digest) = self.expected_rules_digest {
            if !valid_sha256_hex(digest) {
                return Err(invalid_vpn("VPN 预期规则摘要必须为 64 位小写十六进制 SHA-256"));
            }
        }
        Ok(())
    }

    pub fn bind_top_level_authority(
        &mut self,
        proxy_mode: &str,
        proxy_url: &str,
        proxy_group: &str,
    ) -> Result<()> {
        if !self.proxy_mode.is_empty() && self.proxy_mode != proxy_mode {
            return Err(invalid_vpn("VPN 预期中的 proxy_mode 与顶层配置不一致"));
        }
        if !self.proxy_url.is_empty() {
            let norm_self = normalize_loopback_http_endpoint(&self.proxy_url);
            let norm_top = normalize_loopback_http_endpoint(proxy_url);
            if norm_self.is_none() || norm_self != norm_top {
                return Err(invalid_vpn("VPN 预期中的 proxy_url 与顶层配置不一致"));
            }
        }
        if !self.proxy_group.is_empty() && self.proxy_group != proxy_group {
            return Err(invalid_vpn("VPN 预期中的 proxy_group 与顶层配置不一致"));
        }
        self.proxy_mode = proxy_mode.to_string();
        self.proxy_url = proxy_url.to_string();
        self.proxy_group = proxy_group.to_string();
        self.validate()
    }

    /// Strip top-level duplicated authority fields before serializing inside `Config`
    /// so `Config.proxy_mode/proxy_url/proxy_group` remain the single stored authority.
    pub fn without_top_level_duplicates(&self) -> Self {
        let mut copy = self.clone();
        copy.proxy_mode.clear();
        copy.proxy_url.clear();
        copy.proxy_group.clear();
        copy
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VpnObservation {
    pub source: String,
    pub source_instance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    pub upstream_endpoint: Option<String>,
    pub upstream_protocol: ObservedField<UpstreamProtocol>,
    pub running_mode: ObservedField<String>,
    pub tun_enabled: ObservedField<bool>,
    pub system_proxy_enabled: ObservedField<bool>,
    pub selected_group: ObservedField<String>,
    pub selected_node: ObservedField<String>,
    pub proxy_chain: ObservedField<Vec<String>>,
    pub rules_digest: ObservedField<String>,
    pub sample_started_at: f64,
    pub observed_at: f64,
    pub valid_until: f64,
    #[serde(default)]
    pub consistency: ObservationConsistency,
    #[serde(default)]
    pub source_error: Option<String>,
    pub sample_seq: u64,
    pub epoch: VpnEpoch,
}

impl VpnObservation {
    pub fn is_fresh(&self, now: f64) -> bool {
        now.is_finite()
            && self.observed_at.is_finite()
            && self.valid_until.is_finite()
            && self.valid_until > self.observed_at
            && now + 1.0 >= self.observed_at
            && now < self.valid_until
    }

    /// Builds an unpersisted candidate expectation from a current read-only observation.
    /// Does not modify any saved configuration; the user must explicitly confirm saving.
    pub fn to_candidate_expectation(&self) -> Result<VpnExpectation> {
        if self.source_error.is_some() || !self.consistency.is_consistent() {
            return Err(CoreError::new(
                "vpn_observation_unavailable",
                "当前 VPN 观测不完整或不一致，不能生成监督预期候选值",
            ));
        }
        let upstream = self
            .upstream_endpoint
            .as_deref()
            .and_then(normalize_loopback_http_endpoint)
            .ok_or_else(|| {
                CoreError::new(
                    "vpn_upstream_unconfirmed",
                    "当前未确认有效的本机 HTTP 代理入口，不能生成监督预期候选值",
                )
            })?;
        match self.upstream_protocol.known() {
            Some(proto) if proto.supports_http_connect() => {}
            _ => {
                return Err(CoreError::new(
                    "vpn_protocol_unsupported",
                    "当前代理端口不支持 HTTP CONNECT，不能生成监督预期候选值",
                ))
            }
        }
        let candidate = VpnExpectation {
            configured: true,
            proxy_mode: self.source.clone(),
            proxy_url: upstream,
            proxy_group: self.selected_group.known().cloned().unwrap_or_default(),
            running_mode: self.running_mode.known().cloned(),
            require_tun: self.tun_enabled.known().copied(),
            require_system_proxy: self.system_proxy_enabled.known().copied(),
            expected_node: self.selected_node.known().cloned(),
            expected_chain: self.proxy_chain.known().cloned().unwrap_or_default(),
            expected_rules_digest: self.rules_digest.known().cloned(),
        };
        candidate.validate()?;
        Ok(candidate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnFieldDifference {
    pub field: String,
    pub expected: String,
    pub observed: String,
}

impl VpnFieldDifference {
    pub fn new(
        field: impl Into<String>,
        expected: impl Into<String>,
        observed: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            expected: expected.into(),
            observed: observed.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum VpnMatch {
    Matched,
    Mismatched { differences: Vec<VpnFieldDifference> },
    Unknown { reasons: Vec<String> },
    Stale,
}

impl VpnMatch {
    pub fn is_matched(&self) -> bool {
        matches!(self, Self::Matched)
    }

    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Matched => "vpn_expectation_matched",
            Self::Mismatched { .. } => "vpn_expectation_mismatched",
            Self::Unknown { .. } => "vpn_observation_unknown",
            Self::Stale => "vpn_observation_stale",
        }
    }
}

/// Pure comparison between Watch's saved VPN expectation and a read-only observation.
/// Never writes config, sends signals, or performs network requests.
pub fn compare_vpn(
    expectation: &VpnExpectation,
    observation: &VpnObservation,
    now: f64,
) -> VpnMatch {
    if !expectation.configured {
        return VpnMatch::Unknown {
            reasons: vec!["vpn_expectation_unconfigured".into()],
        };
    }
    if expectation.validate().is_err() {
        return VpnMatch::Unknown {
            reasons: vec!["vpn_expectation_invalid".into()],
        };
    }
    let Some(expected_upstream) = normalize_loopback_http_endpoint(&expectation.proxy_url) else {
        return VpnMatch::Unknown {
            reasons: vec!["vpn_expectation_upstream_missing".into()],
        };
    };

    if let Some(ref err) = observation.source_error {
        return VpnMatch::Unknown {
            reasons: vec![if err.trim().is_empty() {
                "vpn_source_error".into()
            } else {
                err.clone()
            }],
        };
    }
    match &observation.consistency {
        ObservationConsistency::InconsistentSnapshot(detail) => {
            return VpnMatch::Unknown {
                reasons: vec![if detail.trim().is_empty() {
                    "vpn_snapshot_inconsistent".into()
                } else {
                    format!("vpn_snapshot_inconsistent:{detail}")
                }],
            };
        }
        ObservationConsistency::Unavailable(detail) => {
            return VpnMatch::Unknown {
                reasons: vec![if detail.trim().is_empty() {
                    "vpn_observation_unavailable".into()
                } else {
                    detail.clone()
                }],
            };
        }
        ObservationConsistency::RevisionVerified | ObservationConsistency::BoundaryVerified => {}
    }

    if !now.is_finite()
        || !observation.sample_started_at.is_finite()
        || !observation.observed_at.is_finite()
        || !observation.valid_until.is_finite()
        || observation.sample_started_at <= 0.0
        || observation.observed_at < observation.sample_started_at
        || observation.valid_until <= observation.observed_at
        || observation.observed_at > now + CLOCK_ROLLBACK_TOLERANCE_SECONDS
        || now >= observation.valid_until
        || observation.sample_seq == 0
        || !observation.epoch.is_valid()
    {
        return VpnMatch::Stale;
    }

    let mut differences = Vec::new();
    let mut unknown_reasons = Vec::new();

    // 1. Required fact: source instance identity
    if observation
        .source_instance
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        unknown_reasons.push("source_instance_unconfirmed".into());
    }

    // 2. Required fact: proxy source / client type
    let obs_source = observation.source.trim();
    if obs_source.is_empty() || obs_source == "unknown" {
        unknown_reasons.push("proxy_source_unconfirmed".into());
    } else if !expectation.proxy_mode.is_empty()
        && expectation.proxy_mode != "auto"
        && obs_source != expectation.proxy_mode
    {
        differences.push(VpnFieldDifference::new(
            "proxy_mode",
            &expectation.proxy_mode,
            obs_source,
        ));
    }

    // 3. Required fact: upstream endpoint
    match observation
        .upstream_endpoint
        .as_deref()
        .and_then(normalize_loopback_http_endpoint)
    {
        Some(actual_upstream) => {
            if actual_upstream != expected_upstream {
                differences.push(VpnFieldDifference::new(
                    "proxy_url",
                    expected_upstream,
                    actual_upstream,
                ));
            }
        }
        None => {
            if let Some(raw) = observation
                .upstream_endpoint
                .as_deref()
                .filter(|s| !s.trim().is_empty())
            {
                differences.push(VpnFieldDifference::new("proxy_url", expected_upstream, raw));
            } else {
                unknown_reasons.push("upstream_endpoint_unconfirmed".into());
            }
        }
    }

    // 4. Required fact: upstream HTTP CONNECT capability (SOCKS-only is rejected)
    match &observation.upstream_protocol {
        ObservedField::Known(protocol) => {
            if !protocol.supports_http_connect() {
                differences.push(VpnFieldDifference::new(
                    "upstream_protocol",
                    "http_connect",
                    protocol.as_str(),
                ));
            }
        }
        other => {
            unknown_reasons.push(other.unavailable_reason("upstream_protocol_unconfirmed"));
        }
    }

    // 5. User-selected optional field: running_mode ("global" / "rule")
    if let Some(ref expected_mode) = expectation.running_mode {
        match &observation.running_mode {
            ObservedField::Known(actual_mode) => {
                if actual_mode != expected_mode {
                    differences.push(VpnFieldDifference::new(
                        "running_mode",
                        expected_mode,
                        actual_mode,
                    ));
                }
            }
            other => {
                unknown_reasons.push(other.unavailable_reason("running_mode_unconfirmed"));
            }
        }
    }

    // 6. User-selected optional field: require_tun (Some(true) / Some(false) / None)
    if let Some(expected_tun) = expectation.require_tun {
        match &observation.tun_enabled {
            ObservedField::Known(actual_tun) => {
                if *actual_tun != expected_tun {
                    differences.push(VpnFieldDifference::new(
                        "require_tun",
                        expected_tun.to_string(),
                        actual_tun.to_string(),
                    ));
                }
            }
            other => {
                unknown_reasons.push(other.unavailable_reason("tun_state_unconfirmed"));
            }
        }
    }

    // 7. User-selected optional field: require_system_proxy
    if let Some(expected_sys_proxy) = expectation.require_system_proxy {
        match &observation.system_proxy_enabled {
            ObservedField::Known(actual_sys_proxy) => {
                if *actual_sys_proxy != expected_sys_proxy {
                    differences.push(VpnFieldDifference::new(
                        "require_system_proxy",
                        expected_sys_proxy.to_string(),
                        actual_sys_proxy.to_string(),
                    ));
                }
            }
            other => {
                unknown_reasons.push(other.unavailable_reason("system_proxy_unconfirmed"));
            }
        }
    }

    // 8. User-selected optional field: proxy_group
    if !expectation.proxy_group.trim().is_empty() {
        match &observation.selected_group {
            ObservedField::Known(actual_group) => {
                if actual_group != &expectation.proxy_group {
                    differences.push(VpnFieldDifference::new(
                        "proxy_group",
                        &expectation.proxy_group,
                        actual_group,
                    ));
                }
            }
            other => {
                unknown_reasons.push(other.unavailable_reason("proxy_group_unconfirmed"));
            }
        }
    }

    // 9. User-selected optional field: expected_node
    if let Some(ref expected_node) = expectation.expected_node {
        match &observation.selected_node {
            ObservedField::Known(actual_node) => {
                if actual_node != expected_node {
                    differences.push(VpnFieldDifference::new(
                        "expected_node",
                        expected_node,
                        actual_node,
                    ));
                }
            }
            other => {
                unknown_reasons.push(other.unavailable_reason("selected_node_unconfirmed"));
            }
        }
    }

    // 10. User-selected optional field: expected_chain
    if !expectation.expected_chain.is_empty() {
        match &observation.proxy_chain {
            ObservedField::Known(actual_chain) => {
                if actual_chain != &expectation.expected_chain {
                    differences.push(VpnFieldDifference::new(
                        "expected_chain",
                        expectation.expected_chain.join("->"),
                        actual_chain.join("->"),
                    ));
                }
            }
            other => {
                unknown_reasons.push(other.unavailable_reason("proxy_chain_unconfirmed"));
            }
        }
    }

    // 11. User-selected optional field: expected_rules_digest
    if let Some(ref expected_digest) = expectation.expected_rules_digest {
        match &observation.rules_digest {
            ObservedField::Known(actual_digest) => {
                if actual_digest != expected_digest {
                    differences.push(VpnFieldDifference::new(
                        "expected_rules_digest",
                        expected_digest,
                        actual_digest,
                    ));
                }
            }
            other => {
                unknown_reasons.push(other.unavailable_reason("rules_digest_unconfirmed"));
            }
        }
    }

    if !differences.is_empty() {
        VpnMatch::Mismatched { differences }
    } else if !unknown_reasons.is_empty() {
        VpnMatch::Unknown {
            reasons: unknown_reasons,
        }
    } else {
        VpnMatch::Matched
    }
}

/// Computes a canonical SHA-256 hex digest over active rule entries only,
/// excluding volatile counters, timestamps, hit statistics, or disabled rules.
pub fn canonical_rules_digest(entries: &[String]) -> String {
    let mut normalized = BTreeSet::new();
    for entry in entries {
        let trimmed = entry.trim();
        if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
            continue;
        }
        // Keep only the canonical `<TYPE>,<PAYLOAD>,<PROXY>` or `MATCH,<PROXY>` parts.
        let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
        match parts.as_slice() {
            [kind, proxy, ..] if kind.eq_ignore_ascii_case("MATCH") && !proxy.is_empty() => {
                normalized.insert(format!("MATCH,{proxy}"));
            }
            [kind, payload, proxy, ..] if !kind.is_empty() && !proxy.is_empty() => {
                normalized.insert(format!(
                    "{},{},{}",
                    kind.to_ascii_uppercase(),
                    payload.to_ascii_lowercase(),
                    proxy
                ));
            }
            _ => {
                normalized.insert(trimmed.to_string());
            }
        }
    }
    let joined = normalized.into_iter().collect::<Vec<_>>().join("\n");
    sha256_hex(joined.as_bytes())
}

/// Extracts canonical rules digest from a `published_rules` JSON object, ignoring
/// volatile fields (`total`, `relevant`, `broad`, timestamps, connection counts).
pub fn rules_digest_from_published(rules_value: &Value) -> Option<String> {
    if rules_value.get("state").and_then(Value::as_str) != Some("available") {
        return None;
    }
    let entries = rules_value.get("entries")?.as_array()?;
    let mut strings = Vec::with_capacity(entries.len());
    for item in entries {
        strings.push(item.as_str()?.to_string());
    }
    Some(canonical_rules_digest(&strings))
}

/// Pure-Rust FIPS 180-4 SHA-256 implementation for `watch-core`.
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = String::with_capacity(64);
    for word in h {
        use std::fmt::Write;
        let _ = write!(&mut out, "{word:08x}");
    }
    out
}
