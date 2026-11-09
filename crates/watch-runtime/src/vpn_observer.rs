//! Read-only VPN state observer and single authority for `VpnEpoch` / `sample_seq`.
//!
//! Watch never mutates VPN configuration, switches nodes/modes, or overwrites
//! `VpnExpectation` from observations. Same-content refreshes advance `sample_seq`
//! only; any effective VPN state change, source restart, or invalidation advances
//! `VpnEpoch.change_generation`.

use crate::{local_http::Client, storage::StateStore};
use claude_watch_core::{
    channel::CLOCK_ROLLBACK_TOLERANCE_SECONDS,
    error::{CoreError, Result},
    tag_config::Credentials,
    vpn::{
        compare_vpn, normalize_loopback_http_endpoint, ObservationConsistency, ObservedField,
        VpnEpoch, VpnExpectation, VpnMatch, VpnObservation,
    },
};
use std::time::Duration;
use url::Url;
use uuid::Uuid;

pub const DEFAULT_VPN_OBSERVATION_TTL_SECONDS: f64 = 3.5;
pub const RULES_CACHE_TTL_SECONDS: f64 = 5.0;

#[derive(Debug, Clone, PartialEq)]
pub struct VpnObservationTransition {
    pub observation: VpnObservation,
    pub verdict: VpnMatch,
    pub epoch_changed: bool,
    pub verdict_changed: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct CachedRulesDigest {
    source_instance: Option<String>,
    source_revision: Option<String>,
    digest: String,
    cached_at: f64,
}

/// Single authority for `VpnEpoch` (`observer_boot_id` + `change_generation`) and
/// `sample_seq`. Rejects stale or out-of-order samples and ensures that a
/// same-content refresh never rotates `VpnEpoch`.
#[derive(Debug, Clone)]
pub struct VpnObservationState {
    observer_boot_id: String,
    change_generation: u64,
    last_sample_seq: u64,
    current: Option<VpnObservation>,
    last_verdict: Option<VpnMatch>,
    cached_rules_digest: Option<CachedRulesDigest>,
}

impl Default for VpnObservationState {
    fn default() -> Self {
        Self::new(format!("vpn-obs-{}", Uuid::new_v4()))
    }
}

impl VpnObservationState {
    pub fn new(observer_boot_id: impl Into<String>) -> Self {
        let boot_id = observer_boot_id.into();
        let boot_id = if boot_id.trim().is_empty() {
            format!("vpn-obs-{}", Uuid::new_v4())
        } else {
            boot_id
        };
        Self {
            observer_boot_id: boot_id,
            change_generation: 1,
            last_sample_seq: 0,
            current: None,
            last_verdict: None,
            cached_rules_digest: None,
        }
    }

    pub fn observer_boot_id(&self) -> &str {
        &self.observer_boot_id
    }

    pub fn change_generation(&self) -> u64 {
        self.change_generation
    }

    pub fn last_sample_seq(&self) -> u64 {
        self.last_sample_seq
    }

    pub fn current_epoch(&self) -> VpnEpoch {
        VpnEpoch::new(self.observer_boot_id.clone(), self.change_generation)
    }

    pub fn current_observation(&self) -> Option<&VpnObservation> {
        self.current.as_ref()
    }

    pub fn allocate_sample_seq(&mut self) -> u64 {
        self.last_sample_seq = self.last_sample_seq.saturating_add(1);
        self.last_sample_seq
    }

    pub fn needs_rules_refresh(&self, expectation: &VpnExpectation, now: f64) -> bool {
        if expectation.expected_rules_digest.is_none() {
            return false;
        }
        match self.cached_rules_digest {
            Some(ref cached)
                if now.is_finite()
                    && cached.cached_at.is_finite()
                    && now >= cached.cached_at
                    && (now - cached.cached_at) < RULES_CACHE_TTL_SECONDS =>
            {
                if let Some(ref prev) = self.current {
                    if prev.source_instance != cached.source_instance
                        || prev.source_revision != cached.source_revision
                    {
                        return true;
                    }
                }
                false
            }
            _ => true,
        }
    }

    pub fn invalidate_rules_cache(&mut self) {
        self.cached_rules_digest = None;
    }

    /// Marks the current VPN observation as invalidated due to a network change,
    /// config file mutation, sleep/wake, or controller failure, immediately
    /// advancing `change_generation`.
    pub fn invalidate(
        &mut self,
        reason: impl Into<String>,
        expectation: &VpnExpectation,
        now: f64,
    ) -> VpnObservationTransition {
        let reason = reason.into();
        self.change_generation = self.change_generation.saturating_add(1);
        self.last_sample_seq = self.last_sample_seq.saturating_add(1);
        self.cached_rules_digest = None;
        let epoch = self.current_epoch();
        let obs = VpnObservation {
            source: expectation.proxy_mode.clone(),
            source_instance: None,
            source_revision: None,
            upstream_endpoint: None,
            upstream_protocol: ObservedField::Unknown(reason.clone()),
            running_mode: ObservedField::Unknown(reason.clone()),
            tun_enabled: ObservedField::Unknown(reason.clone()),
            system_proxy_enabled: ObservedField::Unknown(reason.clone()),
            selected_group: ObservedField::Unknown(reason.clone()),
            selected_node: ObservedField::Unknown(reason.clone()),
            proxy_chain: ObservedField::Unknown(reason.clone()),
            rules_digest: ObservedField::Unknown(reason.clone()),
            sample_started_at: now,
            observed_at: now,
            valid_until: now + DEFAULT_VPN_OBSERVATION_TTL_SECONDS,
            consistency: ObservationConsistency::Unavailable(reason.clone()),
            source_error: Some(reason),
            sample_seq: self.last_sample_seq,
            epoch,
        };
        let verdict = compare_vpn(expectation, &obs, now);
        let verdict_changed = self.last_verdict.as_ref() != Some(&verdict);
        self.current = Some(obs.clone());
        self.last_verdict = Some(verdict.clone());
        VpnObservationTransition {
            observation: obs,
            verdict,
            epoch_changed: true,
            verdict_changed,
        }
    }

    fn effective_fields_equal(a: &VpnObservation, b: &VpnObservation) -> bool {
        let revision_equal = match (&a.source_revision, &b.source_revision) {
            (Some(ra), Some(rb)) => ra == rb,
            (None, None) => true,
            _ => false,
        };
        a.source == b.source
            && a.source_instance == b.source_instance
            && revision_equal
            && a.upstream_endpoint == b.upstream_endpoint
            && a.upstream_protocol == b.upstream_protocol
            && a.running_mode == b.running_mode
            && a.tun_enabled == b.tun_enabled
            && a.system_proxy_enabled == b.system_proxy_enabled
            && a.selected_group == b.selected_group
            && a.selected_node == b.selected_node
            && a.proxy_chain == b.proxy_chain
            && a.rules_digest == b.rules_digest
            && a.source_error == b.source_error
            && a.consistency.is_consistent() == b.consistency.is_consistent()
    }

    /// Validates and applies a read-only observation sample.
    /// Rejects stale, out-of-order, or foreign-boot-id samples.
    pub fn apply_sample(
        &mut self,
        mut sample: VpnObservation,
        expectation: &VpnExpectation,
        now: f64,
    ) -> Result<VpnObservationTransition> {
        if !sample.epoch.observer_boot_id.is_empty()
            && sample.epoch.observer_boot_id != self.observer_boot_id
        {
            return Err(CoreError::new(
                "stale_observer_boot_id",
                "VPN 观测样本来自旧观察器实例，已拒绝",
            ));
        }
        if sample.sample_seq == 0 {
            sample.sample_seq = self.allocate_sample_seq();
        } else if sample.sample_seq <= self.last_sample_seq {
            return Err(CoreError::new(
                "stale_or_out_of_order_vpn_sample",
                "VPN 观测样本序号乱序或已过期，已拒绝",
            ));
        } else {
            self.last_sample_seq = sample.sample_seq;
        }

        if !now.is_finite()
            || !sample.sample_started_at.is_finite()
            || !sample.observed_at.is_finite()
            || !sample.valid_until.is_finite()
            || sample.sample_started_at <= 0.0
            || sample.observed_at < sample.sample_started_at
            || sample.valid_until <= sample.observed_at
            || sample.observed_at > now + CLOCK_ROLLBACK_TOLERANCE_SECONDS
        {
            return Err(CoreError::new(
                "invalid_vpn_sample_timestamps",
                "VPN 观测样本时间戳无效或晚于接收时钟，已拒绝",
            ));
        }

        let is_healthy = sample.consistency.is_consistent() && sample.source_error.is_none();
        if !is_healthy {
            self.cached_rules_digest = None;
        }

        // Invalidate cached rules_digest BEFORE reusing it if source_instance or source_revision
        // changed compared to either the previous observation or the cached entry itself.
        let source_identity_changed = self.current.as_ref().is_some_and(|prev| {
            prev.source_instance != sample.source_instance
                || prev.source_revision != sample.source_revision
        }) || self.cached_rules_digest.as_ref().is_some_and(|cached| {
            cached.source_instance != sample.source_instance
                || cached.source_revision != sample.source_revision
        });
        if source_identity_changed {
            self.cached_rules_digest = None;
        }

        // Fill rules_digest from cache ONLY if still valid and bound to the same source_instance + source_revision
        if matches!(
            &sample.rules_digest,
            ObservedField::Unknown(reason) if reason == "controller_rules_not_sampled"
        ) {
            if let Some(ref cached) = self.cached_rules_digest {
                if now >= cached.cached_at && (now - cached.cached_at) < RULES_CACHE_TTL_SECONDS {
                    sample.rules_digest = ObservedField::Known(cached.digest.clone());
                }
            } else if source_identity_changed {
                sample.rules_digest =
                    ObservedField::Unknown("rules_digest_invalidated_on_source_change".into());
            }
        } else if let ObservedField::Known(ref digest) = sample.rules_digest {
            if is_healthy {
                self.cached_rules_digest = Some(CachedRulesDigest {
                    source_instance: sample.source_instance.clone(),
                    source_revision: sample.source_revision.clone(),
                    digest: digest.clone(),
                    cached_at: sample.observed_at,
                });
            }
        }

        let epoch_changed = match &self.current {
            None => {
                // First observation uses initial change_generation (1) if healthy,
                // or increments if unhealthy.
                if !is_healthy {
                    self.change_generation = self.change_generation.saturating_add(1);
                    true
                } else {
                    false
                }
            }
            Some(prev) => {
                // Re-establishing facts after the previous observation expired also rotates epoch
                // so any diagnostic/recovery started before the gap is invalidated.
                let prev_expired = !prev.is_fresh(sample.sample_started_at);
                if !is_healthy || prev_expired || !Self::effective_fields_equal(prev, &sample) {
                    self.change_generation = self.change_generation.saturating_add(1);
                    true
                } else {
                    false
                }
            }
        };

        sample.epoch = self.current_epoch();
        let verdict = compare_vpn(expectation, &sample, now);
        let verdict_changed = self.last_verdict.as_ref() != Some(&verdict);
        self.current = Some(sample.clone());
        self.last_verdict = Some(verdict.clone());

        Ok(VpnObservationTransition {
            observation: sample,
            verdict,
            epoch_changed,
            verdict_changed,
        })
    }
}

pub trait VpnSourceReader: Send + Sync {
    fn read_observation(
        &self,
        expectation: &VpnExpectation,
        include_rules: bool,
        sample_seq: u64,
        epoch: VpnEpoch,
        now: f64,
    ) -> VpnObservation;
}

/// Read-only HTTP controller reader that queries a local Mihomo/Clash controller
/// (`/configs`, `/proxies`, and optional `/rules`) without touching `/connections`
/// or modifying any external state.
pub struct HttpControllerVpnReader {
    pub source_name: String,
    pub source_instance_override: Option<String>,
    pub source_pid: Option<u32>,
    pub client: Client,
    pub tun_override: Option<ObservedField<bool>>,
    pub system_proxy_override: Option<ObservedField<bool>>,
}

impl HttpControllerVpnReader {
    pub fn new(
        source_name: impl Into<String>,
        source_instance: impl Into<String>,
        credentials: Credentials,
    ) -> Self {
        let inst = source_instance.into();
        Self {
            source_name: source_name.into(),
            source_instance_override: (!inst.trim().is_empty()).then_some(inst),
            source_pid: None,
            client: Client::new(credentials).with_timeout(Duration::from_millis(800)),
            tun_override: None,
            system_proxy_override: None,
        }
    }

    pub fn new_live(source_name: impl Into<String>, credentials: Credentials) -> Self {
        Self {
            source_name: source_name.into(),
            source_instance_override: None,
            source_pid: None,
            client: Client::new(credentials).with_timeout(Duration::from_millis(800)),
            tun_override: None,
            system_proxy_override: None,
        }
    }

    pub fn with_source_pid(mut self, pid: u32) -> Self {
        self.source_pid = Some(pid);
        self
    }

    fn verify_source_instance(&self, upstream_endpoint: Option<&str>) -> Option<String> {
        if let Some(pid) = self.source_pid {
            let proc_id = claude_watch_system::inspect_process_identity(pid)?;
            return Some(format!(
                "pid:{}:{}:{}",
                proc_id.pid, proc_id.start_seconds, proc_id.start_microseconds
            ));
        }
        if let Some(ref raw) = self.source_instance_override {
            let rest = raw.strip_prefix("pid:")?;
            let parts: Vec<&str> = rest.split(':').collect();
            let pid = parts.first().and_then(|s| s.parse::<u32>().ok())?;
            let proc_id = claude_watch_system::inspect_process_identity(pid)?;
            if parts.len() >= 3 {
                let exp_sec = parts[1].parse::<u64>().ok()?;
                let exp_usec = parts[2].parse::<u32>().ok()?;
                if proc_id.start_seconds != exp_sec || proc_id.start_microseconds != exp_usec {
                    return None;
                }
            }
            return Some(format!(
                "pid:{}:{}:{}",
                proc_id.pid, proc_id.start_seconds, proc_id.start_microseconds
            ));
        }
        // Verify the live process owning the controller HTTP port or upstream proxy port via kernel socket inspection
        if let Ok(url) = Url::parse(&self.client.base()) {
            if let (Some(host), Some(port)) = (url.host_str(), url.port()) {
                if let Ok(addr) = format!("{host}:{port}").parse::<std::net::SocketAddr>() {
                    if let Some(proc_id) = claude_watch_system::inspect_loopback_tcp_listener(addr)
                    {
                        return Some(format!(
                            "pid:{}:{}:{}",
                            proc_id.pid, proc_id.start_seconds, proc_id.start_microseconds
                        ));
                    }
                }
            }
        }
        if let Some(up) = upstream_endpoint.and_then(|u| Url::parse(u).ok()) {
            if let (Some(host), Some(port)) = (up.host_str(), up.port()) {
                if let Ok(addr) = format!("{host}:{port}").parse::<std::net::SocketAddr>() {
                    if let Some(proc_id) = claude_watch_system::inspect_loopback_tcp_listener(addr)
                    {
                        return Some(format!(
                            "pid:{}:{}:{}",
                            proc_id.pid, proc_id.start_seconds, proc_id.start_microseconds
                        ));
                    }
                }
            }
        }
        None
    }
}

/// Resolves read-only Clash/Mihomo controller credentials from the user's local VPN config files
/// without modifying any VPN/TAG configuration.
pub fn resolve_vpn_controller_credentials(
    storage: &StateStore,
    proxy_mode: &str,
) -> claude_watch_core::error::Result<claude_watch_core::tag_config::Credentials> {
    let home = &storage.paths.home;
    let candidates = match proxy_mode {
        "tag" => vec![home.join("Library/Application Support/com.tag.lab/mihomo/runtime.yaml")],
        "clash-verge" | "clash" => vec![
            home.join("Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml"),
            home.join("Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/config.yaml"),
            home.join(".config/clash-verge/clash-verge.yaml"),
            home.join(".config/clash/config.yaml"),
        ],
        _ => vec![
            home.join("Library/Application Support/com.tag.lab/mihomo/runtime.yaml"),
            home.join("Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml"),
            home.join("Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/config.yaml"),
        ],
    };
    for path in candidates {
        if let Ok(Some(bytes)) = storage.read_bytes(&path, claude_watch_core::tag_config::CONFIG_LIMIT) {
            if let Ok(text) = String::from_utf8(bytes) {
                if let Ok(creds) = claude_watch_core::tag_config::controller_credentials(&text) {
                    return Ok(creds);
                }
            }
        }
    }
    Err(claude_watch_core::error::CoreError::new(
        "vpn_controller_credentials_unavailable",
        "未找到可读的本地 VPN 控制器配置",
    ))
}

/// Parses read-only `scutil --proxy` output and checks whether system HTTP/HTTPS/SOCKS proxy
/// is enabled and (if `expected_port` is provided) whether the enabled loopback proxy port
/// matches the expected VPN proxy port.
///
/// Safety invariant:
/// - If system proxy is genuinely disabled across all protocols, returns `Known(false)`.
/// - If system proxy is enabled and matches the expected endpoint, returns `Known(true)`.
/// - If system proxy is enabled on a mismatched endpoint/port, returns `Unknown("system_proxy_endpoint_mismatch")`
///   so that both `require_system_proxy = Some(false)` and `require_system_proxy = Some(true)`
///   fail closed without false-negative bypasses.
/// - If `scutil` output cannot be parsed, returns `Unknown("system_proxy_unavailable")`.
pub fn parse_scutil_proxy_output(
    text: &str,
    expected_host: &str,
    expected_port: Option<u16>,
) -> ObservedField<bool> {
    if !text.contains("<dictionary>") {
        return ObservedField::Unknown("system_proxy_unavailable".into());
    }
    let mut kv = std::collections::BTreeMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            kv.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    let http_en = kv.get("HTTPEnable").map(String::as_str) == Some("1");
    let https_en = kv.get("HTTPSEnable").map(String::as_str) == Some("1");
    let socks_en = kv.get("SOCKSEnable").map(String::as_str) == Some("1");
    if !http_en && !https_en && !socks_en {
        return ObservedField::Known(false);
    }
    if let Some(exp_port) = expected_port {
        let verify_protocol_endpoint = |en: bool, host_key: &str, port_key: &str| -> std::result::Result<(), ()> {
            if !en {
                return Ok(());
            }
            let host_ok = kv
                .get(host_key)
                .is_some_and(|h| {
                    let h = h.rsplit_once('@').map(|(_, rhs)| rhs).unwrap_or(h.as_str());
                    h == "127.0.0.1"
                        || h.eq_ignore_ascii_case("localhost")
                        || h.eq_ignore_ascii_case(expected_host)
                });
            let port_ok = kv
                .get(port_key)
                .and_then(|p| p.parse::<u16>().ok())
                .is_some_and(|p| p == exp_port);
            if host_ok && port_ok {
                Ok(())
            } else {
                Err(())
            }
        };

        if verify_protocol_endpoint(http_en, "HTTPProxy", "HTTPPort").is_err()
            || verify_protocol_endpoint(https_en, "HTTPSProxy", "HTTPSPort").is_err()
            || verify_protocol_endpoint(socks_en, "SOCKSProxy", "SOCKSPort").is_err()
        {
            return ObservedField::Unknown("system_proxy_endpoint_mismatch".into());
        }
    }
    ObservedField::Known(true)
}

fn sample_macos_system_proxy_readonly(
    expected_host: &str,
    expected_port: Option<u16>,
) -> ObservedField<bool> {
    let Ok(output) = std::process::Command::new("/usr/sbin/scutil")
        .arg("--proxy")
        .env("LC_ALL", "C")
        .output()
    else {
        return ObservedField::Unknown("system_proxy_unavailable".into());
    };
    if !output.status.success() {
        return ObservedField::Unknown("system_proxy_unavailable".into());
    }
    let Ok(text) = String::from_utf8(output.stdout) else {
        return ObservedField::Unknown("system_proxy_unavailable".into());
    };
    parse_scutil_proxy_output(&text, expected_host, expected_port)
}

impl VpnSourceReader for HttpControllerVpnReader {
    fn read_observation(
        &self,
        expectation: &VpnExpectation,
        include_rules: bool,
        sample_seq: u64,
        epoch: VpnEpoch,
        now: f64,
    ) -> VpnObservation {
        let parsed_proxy = normalize_loopback_http_endpoint(&expectation.proxy_url)
            .and_then(|u| Url::parse(&u).ok());
        let expected_host = parsed_proxy
            .as_ref()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_else(|| "127.0.0.1".into());
        let expected_port = parsed_proxy.as_ref().and_then(Url::port);

        let pre_sys_proxy = if let Some(ref ov) = self.system_proxy_override {
            Some(ov.clone())
        } else if expectation.require_system_proxy.is_some() {
            Some(sample_macos_system_proxy_readonly(
                &expected_host,
                expected_port,
            ))
        } else {
            None
        };

        match self.client.observe_fast_vpn_state(
            &expectation.proxy_group,
            &expected_host,
            expected_port,
            include_rules,
        ) {
            Ok((snap, mut consistency)) => {
                let verified_instance =
                    self.verify_source_instance(snap.upstream_endpoint.as_deref());
                let system_proxy_enabled = match pre_sys_proxy {
                    Some(pre) => {
                        if self.system_proxy_override.is_some() {
                            pre
                        } else {
                            let post = sample_macos_system_proxy_readonly(
                                &expected_host,
                                expected_port,
                            );
                            if pre != post {
                                consistency = ObservationConsistency::InconsistentSnapshot(
                                    "system_proxy_changed_during_sample".into(),
                                );
                                ObservedField::Unknown("system_proxy_inconsistent".into())
                            } else {
                                post
                            }
                        }
                    }
                    None => ObservedField::Unknown("system_proxy_not_sampled".into()),
                };
                VpnObservation {
                    source: self.source_name.clone(),
                    source_instance: verified_instance,
                    source_revision: snap.revision,
                    upstream_endpoint: snap.upstream_endpoint,
                    upstream_protocol: snap.upstream_protocol,
                    running_mode: ObservedField::Known(snap.running_mode),
                    tun_enabled: self
                        .tun_override
                        .clone()
                        .unwrap_or(snap.tun_enabled),
                    system_proxy_enabled,
                    selected_group: snap.selected_group,
                    selected_node: snap.selected_node,
                    proxy_chain: snap.proxy_chain,
                    rules_digest: snap.rules_digest,
                    sample_started_at: now,
                    observed_at: now,
                    valid_until: now + DEFAULT_VPN_OBSERVATION_TTL_SECONDS,
                    consistency,
                    source_error: None,
                    sample_seq,
                    epoch,
                }
            }
            Err(err) => {
                let reason = format!("controller_error:{err}");
                VpnObservation {
                    source: self.source_name.clone(),
                    source_instance: None,
                    source_revision: None,
                    upstream_endpoint: None,
                    upstream_protocol: ObservedField::Unknown(reason.clone()),
                    running_mode: ObservedField::Unknown(reason.clone()),
                    tun_enabled: ObservedField::Unknown(reason.clone()),
                    system_proxy_enabled: ObservedField::Unknown(reason.clone()),
                    selected_group: ObservedField::Unknown(reason.clone()),
                    selected_node: ObservedField::Unknown(reason.clone()),
                    proxy_chain: ObservedField::Unknown(reason.clone()),
                    rules_digest: ObservedField::Unknown(reason.clone()),
                    sample_started_at: now,
                    observed_at: now,
                    valid_until: now + DEFAULT_VPN_OBSERVATION_TTL_SECONDS,
                    consistency: ObservationConsistency::Unavailable(reason.clone()),
                    source_error: Some(reason),
                    sample_seq,
                    epoch,
                }
            }
        }
    }
}

pub struct VpnObserver {
    pub state: VpnObservationState,
    pub storage: Option<StateStore>,
}

impl VpnObserver {
    pub fn new(observer_boot_id: impl Into<String>, storage: Option<StateStore>) -> Self {
        Self {
            state: VpnObservationState::new(observer_boot_id),
            storage,
        }
    }

    pub fn observe_from_reader(
        &mut self,
        reader: &dyn VpnSourceReader,
        expectation: &VpnExpectation,
        force_rules_refresh: bool,
        now: f64,
    ) -> Result<VpnObservationTransition> {
        let include_rules = force_rules_refresh || self.state.needs_rules_refresh(expectation, now);
        let next_seq = self.state.last_sample_seq().saturating_add(1);
        let epoch = self.state.current_epoch();
        let sample = reader.read_observation(expectation, include_rules, next_seq, epoch, now);
        let transition = self.state.apply_sample(sample, expectation, now)?;
        self.persist_observation(&transition.observation);
        Ok(transition)
    }

    pub fn handle_invalidation_event(
        &mut self,
        reason: impl Into<String>,
        expectation: &VpnExpectation,
        now: f64,
    ) -> VpnObservationTransition {
        let transition = self.state.invalidate(reason, expectation, now);
        self.persist_observation(&transition.observation);
        transition
    }

    fn persist_observation(&self, observation: &VpnObservation) {
        if let Some(ref store) = self.storage {
            if let Ok(val) = serde_json::to_value(observation) {
                let path = store.paths.base().join("vpn-observation.json");
                let _ = store.atomic_json(&path, &val);
            }
        }
    }
}
