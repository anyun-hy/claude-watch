//! Read-only VPN state observer and single authority for `VpnEpoch` / `sample_seq`.
//!
//! Watch never mutates VPN configuration, switches nodes/modes, or overwrites
//! `VpnExpectation` from observations. Same-content refreshes advance `sample_seq`
//! only; any effective VPN state change, source restart, or invalidation advances
//! `VpnEpoch.change_generation`.

use crate::{
    commands::{ReadCommand, ReadRunner},
    local_http::Client,
    storage::StateStore,
};
use claude_watch_core::{
    channel::CLOCK_ROLLBACK_TOLERANCE_SECONDS,
    error::{CoreError, Result},
    tag_config::Credentials,
    tag_flow::{listener_fallback_for_port, CommandEvidence},
    vpn::{
        compare_vpn, normalize_loopback_http_endpoint, ObservationConsistency, ObservedField,
        VpnEpoch, VpnExpectation, VpnMatch, VpnObservation,
    },
};
use std::time::{Duration, Instant};
use subprocess::{Exec, Job, Redirection};
use url::Url;
use uuid::Uuid;

pub const DEFAULT_VPN_OBSERVATION_TTL_SECONDS: f64 = 3.5;
/// Leave time for publication and consumption inside the unchanged evidence TTL.
pub const VPN_OBSERVATION_BUDGET: Duration = Duration::from_millis(2500);
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

    fn confirmed_fields_changed(a: &VpnObservation, b: &VpnObservation) -> bool {
        fn known<T: PartialEq>(a: &ObservedField<T>, b: &ObservedField<T>) -> bool {
            matches!((a, b), (ObservedField::Known(a), ObservedField::Known(b)) if a != b)
        }
        fn present<T: PartialEq>(a: &Option<T>, b: &Option<T>) -> bool {
            matches!((a, b), (Some(a), Some(b)) if a != b)
        }
        a.source != b.source
            || present(&a.source_instance, &b.source_instance)
            || present(&a.source_revision, &b.source_revision)
            || present(&a.upstream_endpoint, &b.upstream_endpoint)
            || known(&a.upstream_protocol, &b.upstream_protocol)
            || known(&a.running_mode, &b.running_mode)
            || known(&a.tun_enabled, &b.tun_enabled)
            || known(&a.system_proxy_enabled, &b.system_proxy_enabled)
            || known(&a.selected_group, &b.selected_group)
            || known(&a.selected_node, &b.selected_node)
            || known(&a.proxy_chain, &b.proxy_chain)
            || known(&a.rules_digest, &b.rules_digest)
    }

    fn healthy(sample: &VpnObservation) -> bool {
        sample.consistency.is_consistent() && sample.source_error.is_none() && sample.source_instance.is_some()
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

        let is_healthy = Self::healthy(&sample);
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
                let prev_healthy = Self::healthy(prev);
                // Evidence loss invalidates once; another failed read is not a
                // newly observed VPN change. Known changes still rotate even
                // during an outage, and recovery always needs a new epoch.
                let changed = if !prev_healthy && !is_healthy {
                    Self::confirmed_fields_changed(prev, &sample)
                } else {
                    prev_healthy != is_healthy || prev_expired || !Self::effective_fields_equal(prev, &sample)
                };
                if changed {
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
    /// Preferred cross-user owner lookup, bounded by the remaining sample budget.
    pub listener_owner_probe: Option<ListenerOwnerProbe>,
    pub listener_snapshot_probe: Option<ListenerSnapshotProbe>,
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
            listener_owner_probe: None,
            listener_snapshot_probe: None,
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
            listener_owner_probe: None,
            listener_snapshot_probe: None,
        }
    }

    pub fn with_listener_owner_probe(mut self, probe: ListenerOwnerProbe) -> Self {
        self.listener_owner_probe = Some(probe);
        self
    }

    pub fn with_listener_snapshot_probe(mut self, probe: ListenerSnapshotProbe) -> Self {
        self.listener_snapshot_probe = Some(probe);
        self
    }

    pub fn with_source_pid(mut self, pid: u32) -> Self {
        self.source_pid = Some(pid);
        self
    }

    fn verify_source_instance(
        &self,
        upstream_endpoint: Option<&str>,
        probe: Option<&dyn Fn(u16, Duration) -> Option<u32>>,
        deadline: Instant,
    ) -> Option<String> {
        if Instant::now() >= deadline {
            return None;
        }
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
        // The VPN core may run under another user (TAG starts Mihomo as root via
        // its privileged helper). Query the authoritative cross-user listener
        // evidence first; walking every same-UID process and FD cannot find it.
        // A missing/ambiguous owner fails closed instead of a slower, weaker
        // same-user fallback overriding the kernel result.
        let probe = probe?;
        let mut ports = Vec::new();
        if let Ok(url) = Url::parse(&self.client.base()) {
            ports.extend(url.host_str().filter(|h| is_loopback_host(h)).and(url.port()));
        }
        if let Some(up) = upstream_endpoint.and_then(|u| Url::parse(u).ok()) {
            ports.extend(up.host_str().filter(|h| is_loopback_host(h)).and(up.port()));
        }
        for port in ports {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() { return None; }
            let Some(pid) = probe(port, remaining) else { continue };
            let Some((seconds, micros)) = claude_watch_system::process_start_time_any_user(pid)
            else {
                continue;
            };
            // Re-read so a listener handoff or PID reuse in between fails closed.
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() { return None; }
            if probe(port, remaining) != Some(pid)
                || claude_watch_system::process_start_time_any_user(pid) != Some((seconds, micros))
                || Instant::now() >= deadline
            {
                continue;
            }
            return Some(format!("pid:{pid}:{seconds}:{micros}"));
        }
        None
    }

    fn bind_snapshot_owner(&self, snapshot: &KernelListenerSnapshot, upstream: Option<&str>) -> Option<(u16, u32, u64, u32)> {
        let mut ports = Vec::new();
        for endpoint in [Some(self.client.base().as_str()), upstream].into_iter().flatten() {
            let url = Url::parse(endpoint).ok()?;
            if url.host_str().is_some_and(is_loopback_host) {
                if let Some(port) = url.port() { if !ports.contains(&port) { ports.push(port); } }
            }
        }
        for port in ports {
            let Some(pid) = kernel_listener_owner(&snapshot.evidence, port) else { continue };
            let Some((seconds, micros)) = claude_watch_system::process_start_time_any_user(pid) else { continue };
            return Some((port, pid, seconds, micros));
        }
        None
    }

    fn verify_snapshot_pair(
        &self,
        before: Option<&KernelListenerSnapshot>,
        owner: Option<(u16, u32, u64, u32)>,
        after: Option<&KernelListenerSnapshot>,
        upstream: Option<&str>,
        received_at: f64,
    ) -> std::result::Result<(String, f64), String> {
        let (Some(before), Some(after)) = (before, after) else { return Err("vpn_listener_unavailable".into()); };
        let valid_until = before.captured_at.min(after.captured_at) + DEFAULT_VPN_OBSERVATION_TTL_SECONDS;
        if !before.captured_at.is_finite() || !after.captured_at.is_finite()
            || before.captured_at <= 0.0 || after.captured_at <= 0.0
            || before.captured_at > received_at + CLOCK_ROLLBACK_TOLERANCE_SECONDS
            || after.captured_at > received_at + CLOCK_ROLLBACK_TOLERANCE_SECONDS
            || valid_until <= received_at
        { return Err("vpn_listener_snapshot_stale".into()); }
        if before.origin_id != after.origin_id
            || before.sequence.zip(after.sequence).is_some_and(|(a, b)| b < a || (a == b && before.captured_at != after.captured_at))
        { return Err("vpn_listener_source_changed_during_sample".into()); }
        let Some((port, pid, seconds, micros)) = owner else { return Err("vpn_listener_owner_unavailable".into()); };
        if self.bind_snapshot_owner(after, upstream) != Some((port, pid, seconds, micros)) {
            return Err("vpn_listener_owner_changed_during_sample".into());
        }
        Ok((format!("pid:{pid}:{seconds}:{micros}"), valid_until))
    }
}

fn reconcile_system_proxy_samples(
    before: ObservedField<bool>, after: ObservedField<bool>, consistency: &mut ObservationConsistency,
) -> ObservedField<bool> {
    match (before, after) {
        (ObservedField::Known(a), ObservedField::Known(b)) if a != b => {
            *consistency = ObservationConsistency::InconsistentSnapshot("system_proxy_changed_during_sample".into());
            ObservedField::Unknown("system_proxy_inconsistent".into())
        }
        (ObservedField::Unknown(reason), _) | (_, ObservedField::Unknown(reason)) => {
            *consistency = ObservationConsistency::Unavailable(reason.clone());
            ObservedField::Unknown(reason)
        }
        (_, after) => after,
    }
}

fn is_loopback_host(host: &str) -> bool {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// Lazily resolves the single owner PID of a loopback TCP listener port.
pub type ListenerOwnerProbe = Box<dyn Fn(u16, Duration) -> Option<u32> + Send + Sync>;

pub type ListenerSnapshotProbe = Box<dyn Fn(Duration) -> Option<KernelListenerSnapshot> + Send + Sync>;

/// One kernel table, with its original capture time when supplied by the
/// authenticated native collector. Re-reading one frame does not renew it.
#[derive(Clone)]
pub struct KernelListenerSnapshot {
    pub evidence: CommandEvidence,
    pub captured_at: f64,
    pub origin_id: Option<String>,
    pub sequence: Option<u64>,
}

pub fn read_vpn_kernel_snapshot<R: ReadRunner + ?Sized>(runner: &R, timeout: Duration) -> Option<KernelListenerSnapshot> {
    let started = crate::native::now();
    let evidence = read_kernel_listeners_with_timeout(runner, timeout)?;
    if evidence.status != 0 || !evidence.stderr.trim().is_empty() { return None; }
    let metadata = evidence.stdout.lines().find_map(|line| line.strip_prefix(crate::native_listener::FRAME_META_PREFIX));
    let (captured_at, origin_id, sequence) = if let Some(metadata) = metadata {
        let value = crate::storage::strict_json(metadata.as_bytes()).ok()?;
        let captured_at = value["captured_at"].as_f64().filter(|time| time.is_finite() && *time > 0.0)?;
        let origin = value["origin_id"].as_str().filter(|id| !id.is_empty() && id.len() <= 256)?.to_owned();
        let sequence = value["sequence"].as_u64().filter(|seq| *seq > 0)?;
        (captured_at, Some(origin), Some(sequence))
    } else {
        // Plain netstat is a new bounded command, not a cached collector frame.
        (started, None, None)
    };
    Some(KernelListenerSnapshot { evidence, captured_at, origin_id, sequence })
}

/// Single unambiguous owner PID of a loopback/wildcard TCP listener on `port`,
/// from the kernel listener table (`ReadCommand::Listeners`, which reports owners
/// across users). Returns `None` when the table is incomplete or ambiguous.
pub fn kernel_listener_owner(kernel: &CommandEvidence, port: u16) -> Option<u32> {
    let empty = CommandEvidence {
        status: 1,
        stdout: String::new(),
        stderr: String::new(),
        source: "lsof".into(),
    };
    let evidence = listener_fallback_for_port(empty, Some(kernel), port);
    listener_owner_at(&evidence, port, None)
}

/// The same owner parser for a fresh, port-targeted lsof observation.
pub(crate) fn listener_owner_at(evidence: &CommandEvidence, port: u16, address: Option<std::net::IpAddr>) -> Option<u32> {
    if evidence.status != 0 || !evidence.stderr.trim().is_empty() {
        return None;
    }
    let accepted = [
        format!("127.0.0.1:{port}"),
        format!("*:{port}"),
        format!("0.0.0.0:{port}"),
        format!("[::]:{port}"),
    ];
    let mut owners = std::collections::BTreeSet::new();
    let mut pid = None;
    for line in evidence.stdout.lines() {
        if let Some(raw) = line.strip_prefix('p') {
            pid = raw.parse::<u32>().ok().filter(|v| *v > 1);
        } else if let Some(endpoint) = line.strip_prefix('n') {
            let matches = address.map_or_else(|| accepted.iter().any(|value| value == endpoint), |expected|
                endpoint == format!("*:{port}") || claude_watch_core::tag_flow::parse_endpoint(endpoint).ok()
                    .is_some_and(|(host, actual_port)| actual_port == port && host.parse::<std::net::IpAddr>().is_ok_and(|actual|
                        actual == expected || (actual.is_unspecified() && actual.is_ipv4() == expected.is_ipv4()))));
            if matches {
                owners.insert(pid?);
            }
        }
    }
    (owners.len() == 1).then(|| owners.into_iter().next()).flatten()
}

pub(crate) fn kernel_listener_owner_at(kernel: &CommandEvidence, port: u16, address: std::net::IpAddr) -> Option<u32> {
    let empty = CommandEvidence { status:1, stdout:String::new(), stderr:String::new(), source:"lsof".into() };
    let evidence = claude_watch_core::tag_flow::listener_fallback_for_address(empty, Some(kernel), port, address);
    listener_owner_at(&evidence, port, Some(address))
}

/// Reads the kernel listener table once through `runner`.
pub fn read_kernel_listeners<R: ReadRunner + ?Sized>(runner: &R) -> Option<CommandEvidence> {
    read_kernel_listeners_with_timeout(runner, Duration::from_secs(3))
}

pub fn read_kernel_listeners_with_timeout<R: ReadRunner + ?Sized>(
    runner: &R,
    timeout: Duration,
) -> Option<CommandEvidence> {
    if timeout.is_zero() { return None; }
    let out = runner
        .run(ReadCommand::Listeners, &[], timeout.min(Duration::from_secs(3)), 4 * 1024 * 1024)
        .ok()?;
    Some(CommandEvidence {
        status: out.status,
        stdout: out.text().ok()?.into(),
        stderr: out.error_text().ok()?.into(),
        source: "netstat".into(),
    })
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
    deadline: Instant,
) -> ObservedField<bool> {
    let command = Exec::cmd("/usr/sbin/scutil").args(&["--proxy"]).env("LC_ALL", "C");
    match bounded_proxy_output(command, deadline) {
        Some(text) => parse_scutil_proxy_output(&text, expected_host, expected_port),
        None => ObservedField::Unknown("system_proxy_unavailable".into()),
    }
}

fn bounded_proxy_output(command: Exec, deadline: Instant) -> Option<String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() { return None; }
    // Bound both output collection and process exit. Only this owned read-only
    // child is terminated on timeout; VPN processes/settings are never touched.
    let mut job = match command
        .stdout(Redirection::Pipe)
        .stderr(Redirection::Pipe)
        .start() {
        Ok(job) => job,
        Err(_) => return None,
    };
    let output = job.communicate().and_then(|comm| comm
        .limit_time(deadline.saturating_duration_since(Instant::now()))
        .limit_size(64 * 1024 + 1)
        .read());
    let Ok((stdout, stderr)) = output else {
        stop_proxy_reader(job);
        return None;
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    let status = if remaining.is_zero() { None } else { job.wait_timeout(remaining).ok().flatten() };
    if status.is_none() {
        stop_proxy_reader(job);
        return None;
    }
    if status.and_then(|status| status.code()) != Some(0)
        || stdout.len() + stderr.len() > 64 * 1024
        || !stderr.is_empty()
    {
        return None;
    }
    String::from_utf8(stdout).ok()
}

fn stop_proxy_reader(job: Job) {
    let _ = job.kill();
    if !matches!(job.wait_timeout(Duration::from_millis(50)), Ok(Some(_))) {
        job.detach();
    }
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
        self.read_observation_with_probes(
            expectation, include_rules, sample_seq, epoch, now,
            self.listener_owner_probe.as_deref().map(|probe| probe as &dyn Fn(u16, Duration) -> Option<u32>),
            self.listener_snapshot_probe.as_deref().map(|probe| probe as &dyn Fn(Duration) -> Option<KernelListenerSnapshot>),
        )
    }
}

impl HttpControllerVpnReader {
    /// The onboarding runner can be borrowed here, so both owner checks read
    /// fresh evidence instead of closing over one pre-sampled listener table.
    pub(crate) fn read_observation_with_snapshot_probe(
        &self, expectation: &VpnExpectation, include_rules: bool, sample_seq: u64,
        epoch: VpnEpoch, now: f64, probe: &dyn Fn(Duration) -> Option<KernelListenerSnapshot>,
    ) -> VpnObservation {
        self.read_observation_with_probes(expectation, include_rules, sample_seq, epoch, now, None, Some(probe))
    }

    fn read_observation_with_probes(
        &self,
        expectation: &VpnExpectation,
        include_rules: bool,
        sample_seq: u64,
        epoch: VpnEpoch,
        now: f64,
        probe: Option<&dyn Fn(u16, Duration) -> Option<u32>>,
        snapshot_probe: Option<&dyn Fn(Duration) -> Option<KernelListenerSnapshot>>,
    ) -> VpnObservation {
        let started = Instant::now();
        let deadline = started + VPN_OBSERVATION_BUDGET;
        let parsed_proxy = normalize_loopback_http_endpoint(&expectation.proxy_url)
            .and_then(|u| Url::parse(&u).ok());
        let expected_host = parsed_proxy
            .as_ref()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_else(|| "127.0.0.1".into());
        let expected_port = parsed_proxy.as_ref().and_then(Url::port);

        let before_listener = snapshot_probe.and_then(|probe| probe(deadline.saturating_duration_since(Instant::now())));
        let before_owner = before_listener.as_ref().and_then(|snapshot| {
            self.bind_snapshot_owner(snapshot, Some(&expectation.proxy_url))
        });

        let pre_sys_proxy = if let Some(ref ov) = self.system_proxy_override {
            Some(ov.clone())
        } else if expectation.require_system_proxy.is_some() {
            Some(sample_macos_system_proxy_readonly(
                &expected_host,
                expected_port,
                deadline,
            ))
        } else {
            None
        };

        let mut observation = match self.client.observe_fast_vpn_state_before(
            &expectation.proxy_group,
            &expected_host,
            expected_port,
            include_rules,
            deadline,
        ) {
            Ok((snap, mut consistency)) => {
                let (verified_instance, source_valid_until, listener_error) = if let Some(snapshot_probe) = snapshot_probe {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    let after = (!remaining.is_zero()).then(|| snapshot_probe(remaining)).flatten();
                    match self.verify_snapshot_pair(before_listener.as_ref(), before_owner,
                        after.as_ref(), snap.upstream_endpoint.as_deref(), now + started.elapsed().as_secs_f64()) {
                        Ok((identity, valid_until)) => (Some(identity), Some(valid_until), None),
                        Err(reason) => (None, None, Some(reason)),
                    }
                } else {
                    (self.verify_source_instance(snap.upstream_endpoint.as_deref(), probe, deadline), None, None)
                };
                let system_proxy_enabled = match pre_sys_proxy {
                    Some(pre) => {
                        if self.system_proxy_override.is_some() {
                            pre
                        } else {
                            let post = sample_macos_system_proxy_readonly(
                                &expected_host,
                                expected_port,
                                deadline,
                            );
                            reconcile_system_proxy_samples(pre, post, &mut consistency)
                        }
                    }
                    None => ObservedField::Unknown("system_proxy_not_sampled".into()),
                };
                if let Some(ref reason) = listener_error {
                    consistency = ObservationConsistency::Unavailable(reason.clone());
                }
                let source_error = listener_error.or_else(|| match &consistency {
                    ObservationConsistency::Unavailable(reason) => Some(reason.clone()), _ => None,
                });
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
                    valid_until: source_valid_until.unwrap_or(now + DEFAULT_VPN_OBSERVATION_TTL_SECONDS)
                        .min(now + DEFAULT_VPN_OBSERVATION_TTL_SECONDS),
                    consistency,
                    source_error,
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
        };
        // Keep original sample timestamps. Late complete/partial data must not
        // become fresh evidence simply because it has finally been published.
        if Instant::now() >= deadline {
            let reason = "vpn_observation_budget_exceeded".to_string();
            observation.source_instance = None;
            observation.consistency = ObservationConsistency::Unavailable(reason.clone());
            observation.source_error = Some(reason);
        } else if snapshot_probe.is_some() && observation.source_error.is_none()
            && observation.valid_until <= now + started.elapsed().as_secs_f64()
        {
            let reason = "vpn_listener_snapshot_stale".to_string();
            observation.source_instance = None;
            observation.consistency = ObservationConsistency::Unavailable(reason.clone());
            observation.source_error = Some(reason);
        }
        observation
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

#[cfg(test)]
mod tests {
    use super::{kernel_listener_owner, CommandEvidence};

    #[test]
    fn failed_system_proxy_read_is_not_a_confirmed_change() {
        use super::{ObservedField, ObservationConsistency, reconcile_system_proxy_samples};
        for (before, after) in [
            (ObservedField::Known(true), ObservedField::Unknown("system_proxy_timeout".into())),
            (ObservedField::Unknown("system_proxy_timeout".into()), ObservedField::Known(true)),
        ] {
            let mut consistency = ObservationConsistency::RevisionVerified;
            let result = reconcile_system_proxy_samples(before, after, &mut consistency);
            assert_eq!(result, ObservedField::Unknown("system_proxy_timeout".into()));
            assert_eq!(consistency, ObservationConsistency::Unavailable("system_proxy_timeout".into()));
        }
        let mut consistency = ObservationConsistency::RevisionVerified;
        assert_eq!(reconcile_system_proxy_samples(ObservedField::Known(true), ObservedField::Known(false), &mut consistency),
            ObservedField::Unknown("system_proxy_inconsistent".into()));
        assert!(matches!(consistency, ObservationConsistency::InconsistentSnapshot(_)));
    }

    #[test]
    fn repeated_unavailable_samples_invalidate_once_but_known_changes_and_recovery_rotate() {
        use super::*;
        let mut state = VpnObservationState::new("stable-failure");
        let expectation = VpnExpectation::unconfigured();
        let first = state.invalidate("controller_timeout", &expectation, 1000.0);
        let mut failed = first.observation;
        failed.running_mode = ObservedField::Known("rule".into());
        let initial_epoch = failed.epoch.clone();
        for seq in 2..=12 {
            failed.sample_seq = seq;
            failed.sample_started_at = 1000.0 + (seq as f64 * 4.0);
            failed.observed_at = failed.sample_started_at;
            failed.valid_until = failed.observed_at + DEFAULT_VPN_OBSERVATION_TTL_SECONDS;
            failed.source_error = Some(format!("unavailable_attempt_{seq}"));
            let result = state.apply_sample(failed.clone(), &expectation, failed.observed_at).unwrap();
            assert!(!result.epoch_changed);
            assert_eq!(result.observation.epoch, initial_epoch);
            assert!(result.observation.source_error.is_some());
        }
        failed.sample_seq += 1;
        failed.running_mode = ObservedField::Known("global".into());
        let changed = state.apply_sample(failed.clone(), &expectation, failed.observed_at).unwrap();
        assert!(changed.epoch_changed, "confirmed facts still change during source failure");
        failed.sample_seq += 1;
        failed.consistency = ObservationConsistency::RevisionVerified;
        failed.source_error = None;
        failed.source_instance = Some("verified-live-source".into());
        assert!(state.apply_sample(failed.clone(), &expectation, failed.observed_at).unwrap().epoch_changed);
    }

    #[test]
    fn stalled_proxy_reader_is_bounded_and_terminated() {
        let started = std::time::Instant::now();
        let output = super::bounded_proxy_output(
            subprocess::Exec::cmd("/bin/sleep").args(&["5"]),
            started + std::time::Duration::from_millis(40),
        );
        assert!(output.is_none());
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
    }

    fn table(stdout: &str) -> CommandEvidence {
        CommandEvidence { status: 0, stdout: stdout.into(), stderr: String::new(), source: "netstat".into() }
    }

    #[test]
    fn kernel_listener_owner_reads_root_owned_tag_listener() {
        let t = table("tcp4 0 0 127.0.0.1.7890 *.* LISTEN 0 0 131072 131072 mihomo-universal:26032 00180 00000006\n\
                       tcp4 0 0 127.0.0.1.9090 *.* LISTEN 0 0 131072 131072 mihomo-universal:26032 00180 00000006\n\
                       tcp4 0 0 127.0.0.1.9090 127.0.0.1.61739 TIME_WAIT 0 0 1 1 mihomo-universal:26032 021b1\n");
        assert_eq!(kernel_listener_owner(&t, 9090), Some(26032));
        assert_eq!(kernel_listener_owner(&t, 7890), Some(26032));
        assert_eq!(kernel_listener_owner(&t, 1234), None);
    }

    #[test]
    fn kernel_listener_owner_fails_closed_on_ambiguous_or_incomplete_tables() {
        let two = table("tcp4 0 0 127.0.0.1.9090 *.* LISTEN 0 0 1 1 a:77 0\ntcp4 0 0 *.9090 *.* LISTEN 0 0 1 1 b:78 0\n");
        assert_eq!(kernel_listener_owner(&two, 9090), None);
        let ownerless = table("tcp4 0 0 127.0.0.1.9090 *.* LISTEN 0 0 1 1 0\n");
        assert_eq!(kernel_listener_owner(&ownerless, 9090), None);
        let mut failed = table("tcp4 0 0 127.0.0.1.9090 *.* LISTEN 0 0 1 1 a:77 0\n");
        failed.status = 1;
        assert_eq!(kernel_listener_owner(&failed, 9090), None);
        let empty = table("");
        assert_eq!(kernel_listener_owner(&empty, 9090), None);
    }
}
