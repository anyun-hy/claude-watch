//! Event-driven channel supervision coordinator, policy hot-reload engine,
//! independent slow-audit worker, and sequenced monitor state publisher.
//!
//! All environment, process, policy, lease-expiry, and enforcer-receipt events
//! enter one non-blocking event pipeline. Default disposition is cutting off
//! the target application's network channel while preserving its processes
//! (`断流保进程`). Slow probes and `full_audit()` run asynchronously on a
//! background worker; stale async results are discarded if the policy version,
//! session, or risk state changed while the audit was in flight.
use crate::{
    channel_enforcer::ChannelEnforcer,
    config_store::{guard_policy_digest, policy_digest, ConfigStore},
    receipt_store::ReceiptStore,
    session_store::SessionStore,
    storage::StateStore,
};
use claude_watch_core::{
    channel::{
        evaluate_channel_supervision_with_boot_id, verify_channel_recovery_with_vpn_epoch,
        BackendCoverageScope, BoundProcessToken, ChannelEnforcementCommand,
        ChannelEnforcementReceipt, ChannelEnforcementState, ChannelMonitorDisplayState,
        ChannelMonitorEvent, ChannelMonitorSnapshot, ChannelPermit, ChannelPermitState,
        ChannelSupervisionVerdict, ControlledPathEvidence, FamilyChannelMonitorState,
        NetworkBackendKind, PolicySyncState, PolicyVersion, ProcessDispositionIntent, ProcessDispositionReceipt,
        CLOCK_ROLLBACK_TOLERANCE_SECONDS,
        DEFAULT_PERMIT_TTL, MAX_ENFORCEMENT_RECEIPT_AGE,
    },
    config::Config,
    error::{CoreError, Result},
    policy::PolicyCatalog,
    processes::LaunchTarget,
    session::{self, Desktop, Egress, Phase},
    vpn::{compare_vpn, VpnEpoch, VpnExpectation, VpnMatch, VpnObservation},
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

pub const DEFAULT_ASYNC_AUDIT_TIMEOUT_SECONDS: f64 = 10.0;
pub const MAX_ASYNC_AUDIT_RETRIES: u32 = 3;
pub const ASYNC_AUDIT_RETRY_BACKOFF_SECONDS: f64 = 2.0;
pub const MAX_EMITTED_EVENTS: usize = 128;
pub const MAX_PERSISTED_EVENTS: usize = 64;

#[cfg(test)]
mod logging_tests {
    use super::*;
    use crate::{channel_diagnostics::ChannelDiagnostics, events::EventStore, storage::Paths};
    use std::{fs, sync::atomic::{AtomicUsize, Ordering}, time::{Duration, Instant}};

    struct FailingEnforcer(AtomicUsize);
    impl ChannelEnforcer for FailingEnforcer {
        fn boot_id(&self) -> Result<String> { Ok("boot-log-error".into()) }
        fn is_ready(&self) -> Result<bool> { Ok(true) }
        fn apply_command(&self, _: &ChannelEnforcementCommand, _: f64) -> Result<ChannelEnforcementReceipt> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(CoreError::new("fixture_apply_denied", "http://user:secret@proxy/?password=secret"))
        }
        fn receipt_for(&self, _: &str, _: f64) -> Result<Option<ChannelEnforcementReceipt>> { Ok(None) }
        fn enforce_active_deadlines(&self, _: f64, _: bool) -> Result<Vec<ChannelEnforcementReceipt>> { Ok(vec![]) }
    }

    #[test]
    fn execution_error_and_snapshot_failure_remain_visible_without_suppressing_revoke() {
        let root = std::env::temp_dir().join(format!("cw-supervisor-log-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let storage = StateStore::new(Paths::new(&root).unwrap());
        let enforcer = Arc::new(FailingEnforcer(AtomicUsize::new(0)));
        let mut supervisor = ChannelSupervisor::new_with_config(storage.clone(), Config::default(), None,
            Some(enforcer.clone()), None).unwrap();
        let logger = ChannelDiagnostics::new(storage.clone());
        supervisor.set_diagnostics(logger.clone());
        // A directory cannot be atomically replaced by a JSON state file.
        for file in ["channel-permits.json", "channel-supervision.json", "channel-events.json", "vpn-supervision.json"] {
            fs::create_dir_all(storage.paths.watch().join("state").join(file)).unwrap();
        }
        supervisor.handle_event(SupervisionEvent::ProcessInventoryUnavailable {
            family: "claude".into(), observed_at: 1_800_000_000.0,
        }).unwrap();
        assert!(enforcer.0.load(Ordering::SeqCst) > 0, "state logging failure must not suppress the revoke command");
        assert_eq!(supervisor.tracks["claude"].policy_sync_state, PolicySyncState::ApplyFailed);
        assert!(logger.health().state_write_failed >= 4);
        assert!(logger.health_message().unwrap().contains("状态保存失败"));
        let events = EventStore::new(storage);
        let deadline = Instant::now() + Duration::from_secs(5);
        let rows = loop {
            let rows: Vec<_> = events.history().unwrap().events.into_iter().filter_map(|e| e.fields.channel_diagnostic).collect();
            if rows.iter().any(|r| r.stage == "persist_vpn_observation") { break rows; }
            assert!(Instant::now() < deadline); thread::sleep(Duration::from_millis(10));
        };
        let failure = rows.iter().find(|r| r.stage == "command_failed").unwrap();
        assert_eq!(failure.failure.as_ref().unwrap().code, "fixture_apply_denied");
        assert_eq!(failure.executor_boot_id.as_deref(), Some("boot-log-error"));
        assert_eq!(failure.producer_boot_id.as_deref(), Some(supervisor.producer_boot_id.as_str()));
        assert_eq!(failure.command_seq, Some(supervisor.tracks["claude"].command_seq));
        assert!(failure.policy_version.is_some());
        let json = serde_json::to_string(&rows).unwrap();
        assert!(!json.contains("secret") && !json.contains("password="));
    }
}

#[derive(Debug, Clone)]
pub enum AsyncAuditOutcome {
    Succeeded {
        audit: Value,
        egress: Value,
    },
    Failed {
        code: String,
        detail: String,
    },
    TimedOut {
        elapsed_seconds: f64,
    },
}

#[derive(Debug, Clone)]
pub enum SupervisionEvent {
    EnvironmentUpdated {
        egress: Value,
        local_guard: Value,
        observed_at: f64,
    },
    VpnObservationUpdated {
        observation: VpnObservation,
        observed_at: f64,
    },
    VpnObservationUnavailable {
        reason: String,
        observed_at: f64,
    },
    ProcessInventoryUpdated {
        family: String,
        desktops: Vec<(Desktop, bool, String)>,
        processes: Vec<BoundProcessToken>,
        observed_at: f64,
    },
    ProcessInventoryUnavailable {
        family: String,
        observed_at: f64,
    },
    PolicyUpdated {
        config: Config,
        observed_at: f64,
    },
    NetworkContextChanged {
        context_id: String,
        observed_at: f64,
    },
    ExecutorRestarted {
        new_boot_id: String,
        observed_at: f64,
    },
    LeaseExpired {
        observed_at: f64,
        woke_from_sleep: bool,
    },
    EnforcementReceiptArrived {
        receipt: ChannelEnforcementReceipt,
        received_at: f64,
    },
    ProcessReceiptArrived {
        receipt: ProcessDispositionReceipt,
        received_at: f64,
    },
    AsyncAuditCompleted {
        request_id: u64,
        family: String,
        session_id: Option<String>,
        policy_version: PolicyVersion,
        requested_at: f64,
        outcome: AsyncAuditOutcome,
        completed_at: f64,
    },
}

#[derive(Debug, Clone)]
pub struct AsyncAuditRequest {
    pub request_id: u64,
    pub family: String,
    pub target: LaunchTarget,
    pub session_id: Option<String>,
    pub context_id: Option<String>,
    pub policy_version: PolicyVersion,
    pub vpn_epoch: Option<VpnEpoch>,
    pub upstream_endpoint: String,
    pub requested_at: f64,
    pub timeout_seconds: f64,
    pub cancellation: Option<Arc<AtomicBool>>,
}

impl PartialEq for AsyncAuditRequest {
    fn eq(&self, other: &Self) -> bool {
        self.request_id == other.request_id
            && self.family == other.family
            && self.target == other.target
            && self.session_id == other.session_id
            && self.context_id == other.context_id
            && self.policy_version == other.policy_version
            && self.vpn_epoch == other.vpn_epoch
            && self.upstream_endpoint == other.upstream_endpoint
            && self.requested_at == other.requested_at
            && self.timeout_seconds == other.timeout_seconds
    }
}

impl AsyncAuditRequest {
    pub fn is_cancelled(&self) -> bool {
        self.cancellation
            .as_ref()
            .map(|c| c.load(Ordering::Acquire))
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone)]
struct FamilyRuntimeTrack {
    session_id: Option<String>,
    permit_generation: u64,
    command_seq: u64,
    desktops: Vec<(Desktop, bool, String)>,
    processes: Vec<BoundProcessToken>,
    inventory_failed: bool,
    commanded_processes: Vec<BoundProcessToken>,
    current_permit: Option<ChannelPermit>,
    latest_receipt: Option<ChannelEnforcementReceipt>,
    latest_process_receipt: Option<ProcessDispositionReceipt>,
    previous_process_receipts: Vec<ProcessDispositionReceipt>,
    // Issued batches can finish after their authority is cancelled. Keep the
    // original claim separate from the fence authorizing any further signal.
    pending_process_results: BTreeMap<String, (f64, crate::process_disposition::ProcessIntentFence)>,
    process_fence: Option<crate::process_disposition::ProcessIntentFence>,
    process_episode: Option<(String, String)>,
    applied_policy_version: Option<PolicyVersion>,
    policy_sync_state: PolicySyncState,
    verdict: Option<ChannelSupervisionVerdict>,
    revoked_at: Option<f64>,
    last_risk_at: Option<f64>,
    audit_in_flight: Option<AsyncAuditRequest>,
    audit_retry_count: u32,
    audit_retry_not_before: Option<f64>,
    audit_last_failure_code: Option<String>,
}
const MAX_PROCESS_BATCH_RECORDS: usize = 8;

impl FamilyRuntimeTrack {
    fn new() -> Self {
        Self {
            session_id: None,
            permit_generation: 1,
            command_seq: 0,
            desktops: Vec::new(),
            processes: Vec::new(),
            inventory_failed: false,
            commanded_processes: Vec::new(),
            current_permit: None,
            latest_receipt: None,
            latest_process_receipt: None,
            previous_process_receipts: Vec::new(),
            pending_process_results: BTreeMap::new(),
            process_fence: None,
            process_episode: None,
            applied_policy_version: None,
            policy_sync_state: PolicySyncState::PendingApply,
            verdict: None,
            revoked_at: None,
            last_risk_at: None,
            audit_in_flight: None,
            audit_retry_count: 0,
            audit_retry_not_before: None,
            audit_last_failure_code: None,
        }
    }

    fn end_process_authority(&mut self) -> bool {
        let changed = self.process_fence.take().is_some_and(|fence| {
            fence.cancel();
            true
        });
        if let Some(receipt) = self.latest_process_receipt.take() {
            self.record_previous_process_result(receipt);
            return true;
        }
        changed
    }

    fn record_previous_process_result(&mut self, receipt: ProcessDispositionReceipt) {
        self.previous_process_receipts.push(receipt);
        self.previous_process_receipts.sort_by(|a, b| a.observed_at.total_cmp(&b.observed_at));
        let overflow = self.previous_process_receipts.len().saturating_sub(MAX_PROCESS_BATCH_RECORDS);
        self.previous_process_receipts.drain(..overflow);
    }
}

pub struct ChannelSupervisor {
    pub storage: StateStore,
    pub producer_boot_id: String,
    enforcer: Option<Arc<dyn ChannelEnforcer>>,
    inline_receipt_clock: Option<fn() -> f64>,
    diagnostics: Option<crate::channel_diagnostics::ChannelDiagnostics>,
    expected_executor_boot_id: Option<String>,
    audit_tx: Option<Sender<AsyncAuditRequest>>,
    next_audit_request_id: u64,
    config: Config,
    config_blocking_reason: Option<String>,
    saved_policy_version: PolicyVersion,
    latest_egress: BTreeMap<String, Value>,
    latest_local_guard: Value,
    latest_environment_at: Option<f64>,
    process_dispatcher: Option<crate::process_disposition::ProcessDispositionDispatcher>,
    process_registry: Option<Arc<crate::sandbox_launch::SandboxLaunchRegistry>>,
    latest_vpn_observation: Option<VpnObservation>,
    latest_vpn_match: Option<VpnMatch>,
    latest_vpn_unavailable_reason: Option<String>,
    unmanaged_member_pids: BTreeMap<String, Vec<u32>>,
    coverage_scopes: BTreeMap<String, BackendCoverageScope>,
    upstream_endpoint: String,
    tracks: BTreeMap<String, FamilyRuntimeTrack>,
    event_seq: u64,
    emitted_events: Vec<ChannelMonitorEvent>,
    persisted_events: Vec<ChannelMonitorEvent>,
}

impl ChannelSupervisor {
    pub fn new(
        storage: StateStore,
        enforcer: Option<Arc<dyn ChannelEnforcer>>,
        audit_tx: Option<Sender<AsyncAuditRequest>>,
    ) -> Result<Self> {
        let store = ConfigStore {
            storage: storage.clone(),
        };
        let (config, config_blocking_reason) = if storage.paths.config().exists() {
            match store.load() {
                Ok(cfg) => (cfg, None),
                Err(err) => (
                    Config::default_for_new_install(),
                    Some(format!("config_invalid:{}", err.code)),
                ),
            }
        } else {
            (Config::default(), None)
        };
        Self::new_with_config(storage, config, config_blocking_reason, enforcer, audit_tx)
    }

    pub fn new_with_config(
        storage: StateStore,
        config: Config,
        config_blocking_reason: Option<String>,
        enforcer: Option<Arc<dyn ChannelEnforcer>>,
        audit_tx: Option<Sender<AsyncAuditRequest>>,
    ) -> Result<Self> {
        let saved_policy_version = Self::compute_policy_version(&config)?;
        let upstream_endpoint = if let Some(ep) = config
            .vpn_expectation
            .as_ref()
            .filter(|e| e.configured && !e.proxy_url.trim().is_empty())
            .map(|e| &e.proxy_url)
        {
            ep.clone()
        } else {
            config.proxy_url.trim().to_string()
        };
        let expected_executor_boot_id = enforcer
            .as_ref()
            .and_then(|e| e.boot_id().ok())
            .filter(|id| !id.trim().is_empty());
        let mut tracks = BTreeMap::new();
        for family in PolicyCatalog::families() {
            tracks.insert(family.id.to_string(), FamilyRuntimeTrack::new());
        }
        let producer_boot_id = format!(
            "sup-boot-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        Ok(Self {
            storage,
            producer_boot_id,
            enforcer,
            inline_receipt_clock: None,
            diagnostics: None,
            expected_executor_boot_id,
            audit_tx,
            next_audit_request_id: 0,
            config,
            config_blocking_reason,
            saved_policy_version,
            latest_egress: BTreeMap::new(),
            latest_local_guard: Value::Null,
            latest_environment_at: None,
            process_dispatcher: None,
            process_registry: None,
            latest_vpn_observation: None,
            latest_vpn_match: None,
            latest_vpn_unavailable_reason: None,
            unmanaged_member_pids: BTreeMap::new(),
            coverage_scopes: BTreeMap::new(),
            upstream_endpoint,
            tracks,
            event_seq: 0,
            emitted_events: Vec::new(),
            persisted_events: Vec::new(),
        })
    }

    pub fn set_diagnostics(&mut self, diagnostics: crate::channel_diagnostics::ChannelDiagnostics) {
        self.diagnostics = Some(diagnostics);
    }

    /// An inline executor response is received after execution, potentially
    /// well after the triggering event. Queued receipts have their own time.
    pub fn set_inline_receipt_clock(&mut self, clock: fn() -> f64) {
        self.inline_receipt_clock = Some(clock);
    }

    fn diagnostic(&self, family: Option<&str>, stage: &str) -> crate::channel_diagnostics::ChannelDiagnostic {
        let track = family.and_then(|f| self.tracks.get(f));
        crate::channel_diagnostics::ChannelDiagnostic {
            component: "channel_supervisor".into(), stage: stage.into(),
            producer_boot_id: Some(self.producer_boot_id.clone()), executor_boot_id: self.expected_executor_boot_id.clone(),
            family: family.map(str::to_owned), session_id: track.and_then(|t| t.session_id.clone()),
            policy_version: Some(self.saved_policy_version.clone()),
            permit_generation: track.map(|t| t.permit_generation), command_seq: track.map(|t| t.command_seq),
            event_seq: Some(self.event_seq), ..Default::default()
        }
    }

    fn persist_state(&self, file: &str, stage: &str, value: &Value, now: f64) {
        if let Err(error) = self.storage.atomic_json(&self.storage.paths.watch().join(file), value) {
            if let Some(logger) = &self.diagnostics {
                logger.persistence_failed(self.diagnostic(None, stage), &error, now);
            }
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn config_blocking_reason(&self) -> Option<&str> {
        self.config_blocking_reason.as_deref()
    }

    pub fn set_config_blocking_reason(
        &mut self,
        reason: Option<String>,
        now: f64,
    ) -> Result<()> {
        if self.config_blocking_reason != reason {
            self.config_blocking_reason = reason;
            let family_ids: Vec<String> = self.tracks.keys().cloned().collect();
            for family in family_ids {
                self.evaluate_family(&family, now)?;
            }
        }
        Ok(())
    }

    pub fn saved_policy_version(&self) -> &PolicyVersion {
        &self.saved_policy_version
    }

    pub fn upstream_endpoint(&self) -> &str {
        &self.upstream_endpoint
    }

    pub fn latest_vpn_observation(&self) -> Option<&VpnObservation> {
        self.latest_vpn_observation.as_ref()
    }

    pub fn latest_vpn_match(&self) -> Option<&VpnMatch> {
        self.latest_vpn_match.as_ref()
    }

    pub fn set_family_unmanaged_pids(&mut self, family: &str, pids: Vec<u32>, now: f64) {
        self.unmanaged_member_pids.insert(family.to_string(), pids);
        self.refresh_verdict_and_emit(family, now);
    }

    pub fn set_family_coverage_scope(
        &mut self,
        family: &str,
        scope: Option<BackendCoverageScope>,
        now: f64,
    ) {
        if let Some(scope) = scope {
            self.coverage_scopes.insert(family.to_string(), scope);
        } else {
            self.coverage_scopes.remove(family);
        }
        self.refresh_verdict_and_emit(family, now);
    }

    /// Handshakes or updates the expected executor `boot_id`. When an executor
    /// restarts with a new `boot_id`, all tracks advance `permit_generation`
    /// and invalidate prior receipts so pre-restart receipts or reused sequence
    /// numbers cannot impersonate valid state.
    pub fn register_executor_handshake(&mut self, boot_id: impl Into<String>, now: f64) {
        let boot_id = boot_id.into();
        let changed = self.expected_executor_boot_id.as_deref() != Some(boot_id.as_str());
        self.expected_executor_boot_id = Some(boot_id);
        if changed {
            let family_ids: Vec<String> = self.tracks.keys().cloned().collect();
            for family in family_ids {
                if let Some(track) = self.tracks.get_mut(&family) {
                    track.permit_generation = track.permit_generation.saturating_add(1);
                    track.latest_receipt = None;
                    track.end_process_authority();
                    track.policy_sync_state = PolicySyncState::PendingApply;
                }
                self.refresh_verdict_and_emit(&family, now);
            }
        }
    }

    pub fn expected_executor_boot_id(&self) -> Option<&str> {
        self.expected_executor_boot_id.as_deref()
    }

    pub fn install_process_disposition_dispatcher(&mut self, dispatcher: crate::process_disposition::ProcessDispositionDispatcher) {
        self.process_dispatcher = Some(dispatcher);
    }

    pub fn set_process_disposition_registry(&mut self, registry: Arc<crate::sandbox_launch::SandboxLaunchRegistry>) {
        if self.process_registry.as_ref().is_some_and(|old| Arc::ptr_eq(old, &registry)) { return; }
        for track in self.tracks.values_mut() {
            track.end_process_authority();
        }
        self.process_registry = Some(registry);
    }

    fn cancel_process_intent(&mut self, family: &str, now: f64) {
        if let Some(track) = self.tracks.get_mut(family) {
            let changed = track.end_process_authority();
            if changed { self.refresh_verdict_and_emit(family, now); }
        }
    }

    fn update_process_intent(&mut self, family: &str, session: Option<&session::Session>, risk: Option<&str>,
        evidence_deadline: f64, may_reset_episode: bool, now: f64) {
        use crate::process_disposition::{
            ProcessDispositionJob, ProcessIntentFence, INTENT_TTL, MAX_TARGETS, RECEIPT_TTL,
            RESULT_COMPLETION_GRACE,
        };
        let Some(track) = self.tracks.get_mut(family) else { return; };
        let (Some(session), Some(risk)) = (session, risk) else {
            track.end_process_authority();
            if may_reset_episode { track.process_episode = None; }
            return;
        };
        let Some(provider) = PolicyCatalog::family(family).and_then(|spec| spec.providers.first().copied()) else { return; };
        let (Some(dispatcher), Some(registry), Some(executor), Some(permit)) = (
            self.process_dispatcher.as_ref(), self.process_registry.as_ref(), self.expected_executor_boot_id.as_ref(), track.current_permit.as_ref(),
        ) else { return; };
        if !self.config.enabled || !self.config.guard_enabled || self.config_blocking_reason.is_some()
            || self.config.close_action(risk, provider) != "force"
            || permit.state != ChannelPermitState::Revoked || permit.session_id.as_deref() != Some(session.session_id.as_str())
            || permit.policy_version != self.saved_policy_version || permit.permit_generation != track.permit_generation
            || permit.command_seq != track.command_seq || executor.is_empty()
            || !matches!(session.state, Phase::Active | Phase::Locked) || !now.is_finite()
            || self.latest_environment_at.is_none_or(|at| at > now) || now >= evidence_deadline
        { self.cancel_process_intent(family, now); return; }
        let episode = (session.session_id.clone(), risk.to_owned());
        if track.process_episode.as_ref() == Some(&episode) { return; }
        track.pending_process_results.retain(|_, (expires, fence)|
            now <= *expires && fence.may_deliver_result());
        if track.pending_process_results.len() >= MAX_PROCESS_BATCH_RECORDS { return; }
        let verified = registry.verified_family_tokens(family, now);
        let scoped = match SessionStore::channel_processes(session) {
            Ok(Some(tokens)) => tokens,
            Ok(None) => {
                let Ok(desktops) = session.desktop_members() else { return; };
                let instances = registry.instances();
                verified.iter().filter(|token| instances.iter().any(|instance|
                    desktops.iter().any(|desktop| desktop.pid == instance.pid && desktop.start_seconds == instance.start_seconds
                        && desktop.start_microseconds == instance.start_microseconds)
                        && (instance.pid == token.pid || instance.controlled_subtree_pids.contains(&token.pid))))
                    .cloned().collect()
            }
            Err(_) => return,
        };
        let mut target_identities = Vec::new();
        let mut target_executables = BTreeMap::new();
        let mut target_instances = BTreeMap::new();
        let mut targets: Vec<_> = scoped.iter().filter(|token| verified.contains(token) && track.processes.contains(token)).collect();
        // Descendants first, so terminating a parent does not make any
        // not-yet-checked descendant depend on a reparenting race.
        targets.sort_by_key(|token| (token.role != claude_watch_core::processes::ProcessRole::Child, token.pid));
        for token in targets {
            if !token.has_verified_audit_token() || target_executables.contains_key(&token.pid) { continue; }
            let Some(actual) = claude_watch_system::inspect_process_identity(token.pid) else { continue; };
            if !token.matches_process(actual.pid, actual.uid, actual.start_seconds, actual.start_microseconds, Some(&actual.audit_token)) { continue; }
            let Some(instance) = registry.disposition_instance_id(family, token) else { continue; };
            target_instances.insert(token.pid, instance);
            target_executables.insert(token.pid, actual.executable_path);
            target_identities.push(token.clone());
        }
        if target_identities.is_empty() || target_identities.len() > MAX_TARGETS { return; }
        let valid_until = (now + INTENT_TTL).min(evidence_deadline);
        let instance_id = target_instances.values().next().filter(|first|
            target_instances.values().all(|id| id == *first)).cloned();
        let intent = ProcessDispositionIntent {
            intent_id: uuid::Uuid::new_v4().to_string(), family: family.into(), risk_code: risk.into(), action: "force".into(),
            instance_id, session_id: session.session_id.clone(), policy_version: self.saved_policy_version.clone(),
            producer_boot_id: self.producer_boot_id.clone(), executor_boot_id: executor.clone(),
            permit_generation: track.permit_generation, command_seq: track.command_seq, target_identities, target_executables, target_instances,
            created_at: now, valid_until,
        };
        track.end_process_authority();
        let fence = ProcessIntentFence::default();
        if !fence.install(intent.clone()) { return; }
        let intent_id = intent.intent_id.clone();
        let job = ProcessDispositionJob { intent, fence: fence.clone(), registry: registry.clone(),
            deadline: Instant::now() + Duration::from_secs_f64(valid_until - now) };
        if dispatcher.submit(job) {
            track.pending_process_results.insert(intent_id, (valid_until + RESULT_COMPLETION_GRACE + RECEIPT_TTL, fence.clone()));
            track.process_fence = Some(fence);
            track.process_episode = Some(episode);
            self.refresh_verdict_and_emit(family, now);
        }
    }

    pub fn compute_policy_version(config: &Config) -> Result<PolicyVersion> {
        let val = config.value()?;
        Ok(PolicyVersion {
            policy_digest: policy_digest(&val)?,
            guard_policy_digest: guard_policy_digest(config)?,
        })
    }

    /// Spawns an independent background worker that executes slow `full_audit()`
    /// requests without blocking the main supervision event loop.
    ///
    /// Uses an isolated per-request runner and timeout monitor so `timeout_seconds`
    /// takes effect immediately even if `run_audit` is stuck in-flight,
    /// emitting `AsyncAuditOutcome::TimedOut`, clearing `audit_in_flight`, and
    /// never wedging the worker or blocking subsequent retries.
    pub fn spawn_async_audit_worker<F>(
        stop: Arc<AtomicBool>,
        event_tx: Sender<SupervisionEvent>,
        run_audit: F,
    ) -> Result<(Sender<AsyncAuditRequest>, thread::JoinHandle<()>)>
    where
        F: Fn(&AsyncAuditRequest) -> Result<(Value, Value, f64)> + Send + Sync + 'static,
    {
        let (req_tx, req_rx): (Sender<AsyncAuditRequest>, Receiver<AsyncAuditRequest>) =
            mpsc::channel();
        let run_audit = Arc::new(run_audit);
        let handle = thread::Builder::new()
            .name("channel-async-audit-worker".into())
            .spawn(move || {
                let mut retiring: Option<(Arc<AtomicBool>, thread::JoinHandle<()>)> = None;
                while !stop.load(Ordering::Acquire) {
                    if retiring.as_ref().is_some_and(|(_, h)| h.is_finished()) {
                        let (_, handle) = retiring.take().unwrap();
                        let _ = handle.join();
                    }
                    let Ok(req) = req_rx.recv_timeout(std::time::Duration::from_millis(50)) else { continue; };
                    if stop.load(Ordering::Acquire) { break; }
                    let send = |outcome, completed_at| {
                        let _ = event_tx.send(SupervisionEvent::AsyncAuditCompleted {
                            request_id: req.request_id, family: req.family.clone(), session_id: req.session_id.clone(),
                            policy_version: req.policy_version.clone(), requested_at: req.requested_at, outcome, completed_at,
                        });
                    };
                    // Never accumulate abandoned runners. The production runner
                    // cancels and reaps its subprocess group before returning.
                    if retiring.is_some() {
                        send(AsyncAuditOutcome::Failed { code: "audit_cleanup_pending".into(),
                            detail: "前次审计尚未回收，保持断流".into() }, crate::native::now());
                        continue;
                    }
                    let runner = Arc::clone(&run_audit);
                    let (result_tx, result_rx) = mpsc::channel();
                    let cancellation = Arc::new(AtomicBool::new(false));
                    let mut req_clone = req.clone();
                    req_clone.cancellation = Some(cancellation.clone());
                    let started = std::time::Instant::now();
                    let timeout = std::time::Duration::from_secs_f64(
                        if req.timeout_seconds.is_finite() && req.timeout_seconds > 0.0 { req.timeout_seconds } else { 30.0 });
                    let runner_thread = match thread::Builder::new().name("channel-audit-runner".into()).spawn(move || {
                        let _ = result_tx.send(runner(&req_clone));
                    }) {
                        Ok(handle) => handle,
                        Err(_) => { send(AsyncAuditOutcome::Failed { code: "audit_runner_start_failed".into(),
                            detail: "审计工作线程启动失败".into() }, crate::native::now()); continue; }
                    };
                    loop {
                        if stop.load(Ordering::Acquire) || started.elapsed() >= timeout {
                            cancellation.store(true, Ordering::Release);
                            if !stop.load(Ordering::Acquire) {
                                send(AsyncAuditOutcome::TimedOut { elapsed_seconds: started.elapsed().as_secs_f64() }, crate::native::now());
                            }
                            break;
                        }
                        match result_rx.recv_timeout(std::time::Duration::from_millis(20).min(timeout.saturating_sub(started.elapsed()))) {
                            Ok(Ok((audit, egress, completed_at))) => {
                                if completed_at - req.requested_at >= req.timeout_seconds {
                                    send(AsyncAuditOutcome::TimedOut { elapsed_seconds: (completed_at - req.requested_at).max(0.0) }, completed_at);
                                } else { send(AsyncAuditOutcome::Succeeded { audit, egress }, completed_at); }
                                break;
                            }
                            Ok(Err(err)) => {
                                let outcome = if err.code == "audit_cancelled" {
                                    AsyncAuditOutcome::TimedOut { elapsed_seconds: started.elapsed().as_secs_f64() }
                                } else { AsyncAuditOutcome::Failed { code: err.code, detail: err.message } };
                                send(outcome, crate::native::now());
                                break;
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(mpsc::RecvTimeoutError::Disconnected) => {
                                send(AsyncAuditOutcome::Failed { code: "audit_runner_disconnected".into(), detail: "审计工作线程异常结束".into() }, crate::native::now());
                                break;
                            }
                        }
                    }
                    if runner_thread.is_finished() { let _ = runner_thread.join(); }
                    else { retiring = Some((cancellation, runner_thread)); }
                }
                if let Some((cancel, handle)) = retiring {
                    cancel.store(true, Ordering::Release);
                    let cleanup_until = std::time::Instant::now() + std::time::Duration::from_secs(1);
                    while !handle.is_finished() && std::time::Instant::now() < cleanup_until {
                        thread::sleep(std::time::Duration::from_millis(5));
                    }
                    if handle.is_finished() { let _ = handle.join(); }
                }
            })
            .map_err(|_| CoreError::new("async_audit_worker_failed", "异步审计工作线程无法启动"))?;
        Ok((req_tx, handle))
    }

    pub fn drain_emitted_events(&mut self) -> Vec<ChannelMonitorEvent> {
        std::mem::take(&mut self.emitted_events)
    }

    pub fn snapshot(&self, now: f64) -> ChannelMonitorSnapshot {
        let mut families = BTreeMap::new();
        for (family, track) in &self.tracks {
            families.insert(family.clone(), self.build_family_monitor_state(family, track, now));
        }
        ChannelMonitorSnapshot {
            producer_boot_id: self.producer_boot_id.clone(),
            snapshot_seq: self.event_seq,
            captured_at: now,
            saved_policy_version: self.saved_policy_version.clone(),
            families,
        }
    }

    pub fn authoritative_state_for_family(
        &self,
        family: &str,
    ) -> Option<(PolicyVersion, u64, u64, Option<ChannelPermitState>)> {
        self.tracks.get(family).map(|t| {
            (
                self.saved_policy_version.clone(),
                t.command_seq,
                t.permit_generation,
                t.current_permit.as_ref().map(|p| p.state),
            )
        })
    }

    pub fn handle_event(&mut self, event: SupervisionEvent) -> Result<ChannelMonitorSnapshot> {
        self.handle_event_with_delivery_time(event, None)
    }

    /// Queued events keep their original evidence and expiry. Use one
    /// receiver clock for checks and commands caused by their delivery.
    pub fn handle_queued_event(
        &mut self, event: SupervisionEvent, delivered_at: f64,
    ) -> Result<ChannelMonitorSnapshot> {
        self.handle_event_with_delivery_time(event, Some(delivered_at))
    }

    fn handle_event_with_delivery_time(
        &mut self, event: SupervisionEvent, delivered_at: Option<f64>,
    ) -> Result<ChannelMonitorSnapshot> {
        let source_at = match &event {
            SupervisionEvent::EnvironmentUpdated { observed_at, .. }
            | SupervisionEvent::VpnObservationUpdated { observed_at, .. }
            | SupervisionEvent::VpnObservationUnavailable { observed_at, .. }
            | SupervisionEvent::ProcessInventoryUpdated { observed_at, .. }
            | SupervisionEvent::ProcessInventoryUnavailable { observed_at, .. }
            | SupervisionEvent::PolicyUpdated { observed_at, .. }
            | SupervisionEvent::NetworkContextChanged { observed_at, .. }
            | SupervisionEvent::ExecutorRestarted { observed_at, .. }
            | SupervisionEvent::LeaseExpired { observed_at, .. } => *observed_at,
            SupervisionEvent::EnforcementReceiptArrived { received_at, .. }
            | SupervisionEvent::ProcessReceiptArrived { received_at, .. } => *received_at,
            SupervisionEvent::AsyncAuditCompleted { completed_at, .. } => *completed_at,
        };
        let now = delivered_at.unwrap_or(source_at);

        match event {
            SupervisionEvent::VpnObservationUpdated { observation, .. } => {
                if !observation.epoch.is_valid() || observation.sample_seq == 0 {
                    return Ok(self.snapshot(now));
                }
                if let Some(prev) = self.latest_vpn_observation.as_ref() {
                    if prev.epoch.observer_boot_id != observation.epoch.observer_boot_id {
                        return Ok(self.snapshot(now));
                    }
                    if observation.sample_seq <= prev.sample_seq
                        || observation.epoch.change_generation < prev.epoch.change_generation
                    {
                        return Ok(self.snapshot(now));
                    }
                }
                let epoch_changed = match self.latest_vpn_observation.as_ref() {
                    Some(prev) => {
                        prev.epoch != observation.epoch
                            || prev.source_revision != observation.source_revision
                            || !prev.is_fresh(observation.sample_started_at)
                    }
                    None => self.latest_vpn_unavailable_reason.is_some(),
                };
                let matched_now = self
                    .config
                    .vpn_expectation
                    .as_ref()
                    .is_some_and(|exp| compare_vpn(exp, &observation, now).is_matched());
                if matched_now {
                    if let Some(ep) = observation
                        .upstream_endpoint
                        .as_ref()
                        .filter(|ep| !ep.trim().is_empty())
                    {
                        self.upstream_endpoint = ep.clone();
                    }
                }
                self.latest_vpn_observation = Some(observation);
                self.latest_vpn_unavailable_reason = None;
                let family_ids: Vec<String> = self.tracks.keys().cloned().collect();
                for family in family_ids {
                    if let Some(track) = self.tracks.get_mut(&family) {
                        if epoch_changed {
                            track.audit_in_flight = None;
                            track.audit_retry_count = 0;
                            track.audit_retry_not_before = None;
                            track.audit_last_failure_code = None;
                            track.last_risk_at = Some(now);
                        } else if matched_now
                            && track.audit_last_failure_code.as_deref()
                                == Some("async_audit_retries_exhausted")
                        {
                            track.audit_retry_count = 0;
                            track.audit_retry_not_before = None;
                            track.audit_last_failure_code = None;
                        }
                    }
                    self.evaluate_family(&family, now)?;
                }
            }
            SupervisionEvent::VpnObservationUnavailable { reason, .. } => {
                self.latest_vpn_observation = None;
                self.latest_vpn_unavailable_reason = Some(reason);
                let family_ids: Vec<String> = self.tracks.keys().cloned().collect();
                for family in family_ids {
                    if let Some(track) = self.tracks.get_mut(&family) {
                        track.audit_in_flight = None;
                        track.last_risk_at = Some(source_at);
                    }
                    self.evaluate_family(&family, now)?;
                }
            }
            SupervisionEvent::NetworkContextChanged { context_id, .. } => {
                let family_ids: Vec<String> = self.tracks.keys().cloned().collect();
                for family in family_ids {
                    if let Some(track) = self.tracks.get_mut(&family) {
                        track.end_process_authority();
                        track.permit_generation = track.permit_generation.saturating_add(1);
                        track.revoked_at = Some(now);
                        track.last_risk_at = Some(source_at);
                        track.audit_in_flight = None;
                        track.audit_retry_count = 0;
                        track.audit_retry_not_before = None;
                        track.audit_last_failure_code = None;
                        if let Some(permit) = track.current_permit.as_mut() {
                            permit.state = ChannelPermitState::Revoked;
                            permit.reason_code = "network_context_changed".into();
                            permit.context_id = Some(context_id.clone());
                        }
                    }
                    self.evaluate_family(&family, now)?;
                }
            }
            SupervisionEvent::ExecutorRestarted { new_boot_id, .. } => {
                self.register_executor_handshake(new_boot_id, now);
            }
            SupervisionEvent::EnvironmentUpdated {
                egress,
                local_guard,
                ..
            } => {
                let fresh_egress = Egress::fresh(&egress, now, session::GUARD_EGRESS_TTL).is_some();
                let measured_family = egress["family"].as_str().unwrap_or("*");
                if measured_family == "*" {
                    for family in self.tracks.keys() { self.latest_egress.insert(family.clone(), egress.clone()); }
                } else {
                    self.latest_egress.insert(measured_family.to_string(), egress);
                }
                self.latest_local_guard = local_guard;
                self.latest_environment_at = Some(source_at);
                let family_ids: Vec<String> = self.tracks.keys().cloned().collect();
                for family in family_ids {
                    if fresh_egress {
                        if let Some(track) = self.tracks.get_mut(&family) {
                            if track.audit_last_failure_code.as_deref()
                                == Some("async_audit_retries_exhausted")
                            {
                                track.audit_retry_count = 0;
                                track.audit_retry_not_before = None;
                                track.audit_last_failure_code = None;
                            }
                        }
                    }
                    self.evaluate_family(&family, now)?;
                }
            }
            SupervisionEvent::ProcessInventoryUpdated {
                family,
                desktops,
                processes,
                ..
            } => {
                if let Some(spec) = PolicyCatalog::family(&family) {
                    SessionStore::for_family(self.storage.clone(), spec.id)
                        .reconcile_channel_processes(&processes, now)?;
                }
                if let Some(track) = self.tracks.get_mut(&family) {
                    if !track.processes.iter().any(|p| processes.contains(p)) && track.processes != processes {
                        // An audit of a replaced/execed process cannot authorize
                        // the new instance, even if its PID was reused.
                        track.audit_in_flight = None;
                        track.audit_retry_count = 0;
                        track.audit_retry_not_before = None;
                    }
                    track.desktops = desktops;
                    track.processes = processes;
                    track.inventory_failed = false;
                }
                self.evaluate_family(&family, now)?;
            }
            SupervisionEvent::ProcessInventoryUnavailable { family, .. } => {
                if let Some(track) = self.tracks.get_mut(&family) {
                    // Retain managed membership; uncertainty revokes permission.
                    track.inventory_failed = true;
                    track.audit_in_flight = None;
                }
                self.evaluate_family(&family, now)?;
            }
            SupervisionEvent::PolicyUpdated { config, .. } => {
                let new_version = Self::compute_policy_version(&config)?;
                if let Some(ep) = config
                    .vpn_expectation
                    .as_ref()
                    .filter(|e| e.configured && !e.proxy_url.trim().is_empty())
                    .map(|e| &e.proxy_url)
                {
                    self.upstream_endpoint = ep.clone();
                } else if !config.proxy_url.trim().is_empty() {
                    self.upstream_endpoint = config.proxy_url.clone();
                }
                let version_changed = new_version != self.saved_policy_version;
                if version_changed || !config.enabled || !config.guard_enabled {
                    for track in self.tracks.values_mut() {
                        track.end_process_authority();
                    }
                }
                self.config = config;
                self.saved_policy_version = new_version;
                if version_changed && delivered_at.is_some() {
                    if let Some(logger) = &self.diagnostics {
                        let mut diagnostic = self.diagnostic(None, "queued_policy_received");
                        diagnostic.source_observed_at = Some(source_at);
                        logger.record(diagnostic, now);
                    }
                }
                let family_ids: Vec<String> = self.tracks.keys().cloned().collect();
                for family in family_ids {
                    if version_changed {
                        if let Some(track) = self.tracks.get_mut(&family) {
                            track.permit_generation = track.permit_generation.saturating_add(1);
                            track.policy_sync_state = PolicySyncState::PendingApply;
                            // Invalidate any in-flight slow audit started under the old policy
                            track.audit_in_flight = None;
                            track.audit_retry_count = 0;
                            track.audit_retry_not_before = None;
                            track.audit_last_failure_code = None;
                        }
                    }
                    self.evaluate_family(&family, now)?;
                }
            }
            SupervisionEvent::LeaseExpired { woke_from_sleep, .. } => {
                let mut receipt_received_at = now;
                if let Some(enforcer) = &self.enforcer {
                    let receipts = enforcer.enforce_active_deadlines(now, woke_from_sleep)?;
                    receipt_received_at = self.inline_receipt_clock.map_or(now, |clock| clock());
                    for receipt in receipts {
                        self.ingest_receipt(receipt, receipt_received_at)?;
                    }
                }
                let vpn_stale_at_deadline = self
                    .latest_vpn_observation
                    .as_ref()
                    .is_some_and(|obs| !obs.is_fresh(now));
                let family_ids: Vec<String> = self.tracks.keys().cloned().collect();
                for family in family_ids {
                    if vpn_stale_at_deadline {
                        self.evaluate_family(&family, now)?;
                        continue;
                    }
                    if let Some(track) = self.tracks.get_mut(&family) {
                        if let Some(permit) = track.current_permit.as_mut() {
                            let (eff, reason) = permit.effective_state_with_clock(
                                now,
                                None,
                                woke_from_sleep,
                                &self.saved_policy_version,
                            );
                            if eff == ChannelPermitState::Revoked && permit.state != ChannelPermitState::Revoked {
                                permit.state = ChannelPermitState::Revoked;
                                permit.reason_code = reason.into();
                                track.revoked_at = Some(now);
                            }
                        }
                        if let Some(enforcer) = &self.enforcer {
                            if let Ok(Some(r)) = enforcer.receipt_for(&family, receipt_received_at) {
                                track.latest_receipt = Some(r);
                            }
                        }
                    }
                    self.refresh_verdict_and_emit(&family, receipt_received_at);
                }
            }
            SupervisionEvent::EnforcementReceiptArrived { receipt, .. } => {
                self.ingest_receipt(receipt, now)?;
            }
            SupervisionEvent::ProcessReceiptArrived { receipt, .. } => {
                self.ingest_process_receipt(receipt, now)?;
            }
            SupervisionEvent::AsyncAuditCompleted {
                request_id,
                family,
                session_id,
                policy_version,
                requested_at,
                outcome,
                completed_at,
            } => {
                self.handle_async_audit_completed(
                    request_id,
                    &family,
                    session_id,
                    policy_version,
                    requested_at,
                    outcome,
                    completed_at,
                    now,
                )?;
            }
        }

        let snap = self.snapshot(now);
        // Secondary persistence never blocks or rolls back the channel command
        // already executed by the enforcer.
        let mut published = json!(snap);
        published["executor_boot_id"] = json!(self.expected_executor_boot_id);
        published["producer_identity"] = crate::channel_policy_status::current_producer_identity();
        published["authoritative_permits"] = json!(self.tracks.iter()
            .filter_map(|(family, track)| track.current_permit.as_ref().map(|p| (family.clone(), p.clone())))
            .collect::<BTreeMap<_, _>>());
        published["enforcement_receipts"] = json!(self.tracks.iter()
            .filter_map(|(family, track)| track.latest_receipt.as_ref().map(|r| (family.clone(), r.clone())))
            .collect::<BTreeMap<_, _>>());
        published["process_receipts"] = json!(self.tracks.iter()
            .filter_map(|(family, track)| track.latest_process_receipt.as_ref().map(|r| (family.clone(), r.clone())))
            .collect::<BTreeMap<_, _>>());
        self.persist_state("state/channel-supervision.json", "persist_supervision", &published, now);
        self.persist_state("state/channel-events.json", "persist_monitor_events", &json!(self.persisted_events), now);
        let vpn_supervision = json!({
            "captured_at": now,
            "network_backend": self.config.effective_network_backend(),
            "requires_migration": self.config.requires_backend_migration_setup(),
            "expectation": self.config.vpn_expectation,
            "observation": self.latest_vpn_observation,
            "unavailable_reason": self.latest_vpn_unavailable_reason,
            "vpn_match": self.compute_vpn_match(now),
        });
        self.persist_state("state/vpn-supervision.json", "persist_vpn_observation", &vpn_supervision, now);
        crate::native::notify_channel_update();
        Ok(snap)
    }

    fn load_channel_session(&self, family: &'static str, now: f64) -> Result<Option<session::Session>> {
        let current = SessionStore::for_family(self.storage.clone(), family).load(now)?;
        let Some(track) = self.tracks.get(family) else { return Ok(current); };
        if track.inventory_failed { return Ok(current); }
        if let Some(session) = current.as_ref() {
            if session.state == Phase::Ended { return Ok(None); }
            if let Some(bound) = SessionStore::channel_processes(session)? {
                if !bound.iter().any(|p| track.processes.contains(p)) {
                    return Ok(None);
                }
            } else if !track.processes.is_empty() && !session.desktop_members()?.iter().any(|d|
                track.processes.iter().any(|p| p.pid == d.pid && p.start_seconds == d.start_seconds
                    && p.start_microseconds == d.start_microseconds)) {
                // A previous desktop's session is not a newly discovered CLI's
                // permission; establish its own current identity and evidence.
                return Ok(None);
            }
        }
        Ok(current)
    }

    fn compute_vpn_match(&self, now: f64) -> Option<VpnMatch> {
        if let Some(ref reason) = self.config_blocking_reason {
            return Some(VpnMatch::Unknown {
                reasons: vec![reason.clone()],
            });
        }
        let is_sandbox_backend = self.config.effective_network_backend().is_sandbox();
        let vpn_gate_active = is_sandbox_backend
            || self.config.vpn_expectation.is_some()
            || self.latest_vpn_observation.is_some()
            || self.latest_vpn_unavailable_reason.is_some();
        if !vpn_gate_active {
            return None;
        }
        match (
            self.config.vpn_expectation.as_ref(),
            self.latest_vpn_observation.as_ref(),
        ) {
            (Some(exp), Some(obs)) => Some(compare_vpn(exp, obs, now)),
            (None, Some(obs)) => {
                let unconfigured = VpnExpectation::unconfigured();
                Some(compare_vpn(&unconfigured, obs, now))
            }
            (Some(exp), None) => {
                if !exp.configured {
                    let mut reasons = vec!["vpn_expectation_unconfigured".into()];
                    if let Some(ref r) = self.latest_vpn_unavailable_reason {
                        if r != "vpn_expectation_unconfigured" {
                            reasons.push(r.clone());
                        }
                    }
                    Some(VpnMatch::Unknown { reasons })
                } else {
                    let reason = self
                        .latest_vpn_unavailable_reason
                        .clone()
                        .unwrap_or_else(|| "vpn_observation_missing".into());
                    Some(VpnMatch::Unknown {
                        reasons: vec![reason],
                    })
                }
            }
            (None, None) => {
                if is_sandbox_backend {
                    let mut reasons = vec!["vpn_expectation_unconfigured".into()];
                    if let Some(ref r) = self.latest_vpn_unavailable_reason {
                        if r != "vpn_expectation_unconfigured" {
                            reasons.push(r.clone());
                        }
                    }
                    Some(VpnMatch::Unknown { reasons })
                } else {
                    let reason = self
                        .latest_vpn_unavailable_reason
                        .clone()
                        .unwrap_or_else(|| "vpn_observation_unavailable".into());
                    Some(VpnMatch::Unknown {
                        reasons: vec![reason],
                    })
                }
            }
        }
    }

    fn evaluate_family(&mut self, family: &str, now: f64) -> Result<()> {
        let Some(family_spec) = PolicyCatalog::family(family) else {
            return Ok(());
        };
        let sessions = SessionStore::for_family(self.storage.clone(), family_spec.id);
        let receipts_store = ReceiptStore {
            storage: self.storage.clone(),
        };
        let mut session = self.load_channel_session(family_spec.id, now)?;
        if self.tracks.get(family).is_some_and(|t| t.inventory_failed) {
            self.cancel_process_intent(family, now);
            return self.issue_family_command(family, session.as_ref(), ChannelPermitState::Revoked,
                "channel_inventory_incomplete", now);
        }
        let provider = family_spec
            .providers
            .first()
            .copied()
            .unwrap_or(claude_watch_core::processes::Provider::Claude);

        let desktops = self
            .tracks
            .get(family)
            .map(|t| t.desktops.clone())
            .unwrap_or_default();

        let vpn_match = self.compute_vpn_match(now);
        self.latest_vpn_match = vpn_match.clone();

        // Hard VPN Gate: When VPN expectation/observation is active and not Matched,
        // immediately revoke the AI network permit without waiting for egress IP change
        // and without allowing any `warn` policy exemption.
        if let Some(ref vm) = vpn_match {
            if !vm.is_matched() {
                self.cancel_process_intent(family, now);
                let code = vm.reason_code().to_string();
                if let Some(track) = self.tracks.get_mut(family) {
                    track.audit_in_flight = None;
                    track.audit_retry_count = 0;
                    track.audit_retry_not_before = None;
                    track.last_risk_at = Some(now);
                }
                if let Some(s) = session.as_ref() {
                    let _ = sessions.mark_failure(
                        Some(&s.session_id),
                        now,
                        &code,
                        "VPN 实际状态与保存预期不符或观测证据失效，已立即撤销通道放行并保留进程",
                        true,
                    );
                    session = sessions.load(now)?;
                }
                return self.issue_family_command(
                    family,
                    session.as_ref(),
                    ChannelPermitState::Revoked,
                    &code,
                    now,
                );
            }
        }

        let tun_required_by_guard = match self.config.vpn_expectation.as_ref() {
            Some(exp) if exp.configured => exp.require_tun == Some(true),
            _ => true,
        };
        let local_guard_ok = self.latest_local_guard["proxy"] == "ok"
            && (!tun_required_by_guard || self.latest_local_guard["tun"] == "ok");
        let latest_egress = self.latest_egress.get(family).cloned().unwrap_or(Value::Null);
        let fresh_exit = Egress::fresh(&latest_egress, now, session::GUARD_EGRESS_TTL);
        let evidence_valid = fresh_exit
            .as_ref()
            .is_some_and(|exit| exit.observed_at + session::GUARD_EGRESS_TTL > now);
        let path_evidence = serde_json::from_value::<claude_watch_core::channel::ControlledPathEvidence>(latest_egress.clone());
        let expected_vpn_epoch = self
            .latest_vpn_observation
            .as_ref()
            .map(|o| &o.epoch);
        let path_matches_err = match path_evidence {
            Ok(ref ev) => ev.matches_path_with_vpn(
                family,
                &self.upstream_endpoint,
                &self.saved_policy_version,
                session.as_ref().filter(|s| s.state == Phase::Active).map(|s| s.context_id.as_str())
                    .or_else(|| self.latest_local_guard["context_id"].as_str()),
                expected_vpn_epoch,
                now,
                session::GUARD_EGRESS_TTL,
            ).err(),
            Err(_) => Some("evidence_not_from_controlled_path"),
        };
        let audit_context_id = session
            .as_ref()
            .map(|s| s.context_id.clone())
            .or_else(|| {
                latest_egress.get("context_id")
                    .and_then(Value::as_str)
                    .map(|s| s.to_string())
            });

        let had_active_or_permitted = session
            .as_ref()
            .is_some_and(|s| s.state == Phase::Active)
            || self
                .tracks
                .get(family)
                .and_then(|t| t.current_permit.as_ref())
                .is_some_and(|p| p.state == ChannelPermitState::Permitted);

        // Check if there is an active risk on the current session or environment,
        // or if key evidence (egress / local_guard / path) has expired while a session is active.
        let mut risk_code: Option<String> = None;
        let mut evidence_expired_or_missing = false;
        if self.latest_local_guard["proxy"] == "fail"
            || (tun_required_by_guard && self.latest_local_guard["tun"] == "fail")
        {
            risk_code = Some("proxy_or_tun_failed".into());
            // Loss of the required path does not itself establish an
            // independent, current process-force risk.
            evidence_expired_or_missing = true;
        } else if !local_guard_ok && had_active_or_permitted {
            risk_code = Some("local_guard_unverified".into());
            evidence_expired_or_missing = true;
        } else if let Some(path_err) = path_matches_err {
            if had_active_or_permitted {
                risk_code = Some(path_err.into());
                evidence_expired_or_missing = true;
            }
        } else if let Some(exit) = fresh_exit.as_ref() {
            if !evidence_valid && had_active_or_permitted {
                risk_code = Some("egress_evidence_expired".into());
                evidence_expired_or_missing = true;
            } else if exit.country == "CN" {
                risk_code = Some("egress_country_cn".into());
            } else if let Some(s) = session.as_ref() {
                if s.state == Phase::Active && exit.ip != s.baseline.ip {
                    risk_code = Some("egress_ip_changed".into());
                } else if s.state == Phase::Active {
                    let extra = serde_json::to_value(&s.extra).unwrap_or(Value::Null);
                    let drift = receipts_store.probe_drift_risk(&extra, now);
                    if drift["state"] == "risk" {
                        if let Some(c) = drift["reason"]["code"].as_str() {
                            risk_code = Some(c.into());
                        }
                    }
                }
            }
        } else if had_active_or_permitted {
            // Logic Fix 1: Never renew or maintain a Permitted lease when egress
            // evidence is missing or has expired beyond GUARD_EGRESS_TTL!
            risk_code = Some("egress_evidence_expired".into());
            evidence_expired_or_missing = true;
        }

        // Only a current observation can create process authority. A locked
        // session's stored reason may continue a network revocation but cannot
        // start a force action. Independently recheck an already-issued risk.
        let process_evidence_current = local_guard_ok && evidence_valid && path_matches_err.is_none();
        let mut process_risk = risk_code.as_deref().filter(|code|
            !evidence_expired_or_missing && !code.starts_with("vpn_") && PolicyCatalog::criterion_for(code).is_some()).map(str::to_owned);
        if process_risk.is_none() && process_evidence_current {
            if let (Some(exit), Some(s), Some(intent)) = (fresh_exit.as_ref(), session.as_ref(),
                self.tracks.get(family).and_then(|t| t.process_fence.as_ref()).and_then(|fence| fence.current()))
            {
                if intent.session_id == s.session_id {
                    let drift = receipts_store.probe_drift_risk(&serde_json::to_value(&s.extra).unwrap_or(Value::Null), now);
                    let still_observed = match intent.risk_code.as_str() {
                        "egress_ip_changed" => exit.ip != s.baseline.ip,
                        "egress_country_cn" => exit.country == "CN",
                        other => drift["state"] == "risk" && drift["reason"]["code"] == other,
                    };
                    if still_observed { process_risk = Some(intent.risk_code); }
                }
            }
        }
        let process_deadline = self.latest_environment_at.map(|at| at + crate::process_disposition::INTENT_TTL)
            .unwrap_or(0.0).min(fresh_exit.as_ref().map(|exit| exit.observed_at + session::GUARD_EGRESS_TTL).unwrap_or(f64::INFINITY));
        if process_risk.is_none() { self.cancel_process_intent(family, now); }

        // Determine desired permit state without blocking on slow audits
        let (desired_state, reason_code) = if let Some(code) = risk_code {
            let action = if evidence_expired_or_missing || code.starts_with("vpn_") {
                "close".to_string()
            } else {
                self.config.close_action(&code, provider)
            };
            if action == "warn" {
                (ChannelPermitState::Permitted, code)
            } else {
                if let Some(s) = session.as_ref() {
                    let _ = sessions.mark_failure(
                        Some(&s.session_id),
                        now,
                        &code,
                        "通道保护检测到环境或出口风险（或关键证据已过期）；网络与进程的执行结果分别核对",
                        true,
                    );
                    session = sessions.load(now)?;
                }
                if evidence_expired_or_missing {
                    let sid = session.as_ref().map(|s| s.session_id.clone());
                    self.request_async_audit_if_needed(family, sid, audit_context_id.clone(), now);
                }
                (ChannelPermitState::Revoked, code)
            }
        } else if desktops.is_empty() && self.tracks.get(family).is_none_or(|t| t.processes.is_empty()) {
            (ChannelPermitState::PendingVerification, "idle_no_process".into())
        } else if let Some(s) = session.as_ref() {
            let was_revoked = self
                .tracks
                .get(family)
                .and_then(|t| t.current_permit.as_ref())
                .is_some_and(|p| p.state == ChannelPermitState::Revoked);
            if s.state == Phase::Active && !s.group_rechecking() {
                // If previously revoked, do NOT automatically transition back to
                // Permitted without fresh post-revocation recovery verification!
                if was_revoked {
                    self.request_async_audit_if_needed(family, Some(s.session_id.clone()), audit_context_id.clone(), now);
                    (
                        ChannelPermitState::Revoked,
                        "awaiting_recovery_verification".into(),
                    )
                } else if !local_guard_ok || !evidence_valid || path_matches_err.is_some() {
                    self.request_async_audit_if_needed(family, Some(s.session_id.clone()), audit_context_id.clone(), now);
                    let err_code = path_matches_err.unwrap_or("egress_evidence_expired");
                    (
                        ChannelPermitState::Revoked,
                        err_code.into(),
                    )
                } else {
                    (ChannelPermitState::Permitted, "active".into())
                }
            } else if s.state == Phase::Locked {
                let code = s
                    .reason
                    .as_ref()
                    .map(|r| r.code.clone())
                    .unwrap_or_else(|| "session_locked".into());
                if !was_revoked
                    && !code.starts_with("vpn_")
                    && self.config.close_action(&code, provider) == "warn"
                    && local_guard_ok
                    && evidence_valid
                    && path_matches_err.is_none()
                {
                    (ChannelPermitState::Permitted, code)
                } else {
                    self.request_async_audit_if_needed(family, Some(s.session_id.clone()), audit_context_id.clone(), now);
                    (ChannelPermitState::Revoked, code)
                }
            } else {
                self.request_async_audit_if_needed(family, Some(s.session_id.clone()), audit_context_id.clone(), now);
                if self
                    .tracks
                    .get(family)
                    .is_some_and(|t| t.audit_retry_count >= MAX_ASYNC_AUDIT_RETRIES)
                {
                    (
                        ChannelPermitState::Revoked,
                        "async_audit_retries_exhausted".into(),
                    )
                } else {
                    (
                        ChannelPermitState::PendingVerification,
                        "session_rechecking".into(),
                    )
                }
            }
        } else {
            // Running desktop without a verified session: hold channel in
            // PendingVerification and schedule async full_audit() in background!
            self.request_async_audit_if_needed(family, None, audit_context_id.clone(), now);
            if self
                .tracks
                .get(family)
                .is_some_and(|t| t.audit_retry_count >= MAX_ASYNC_AUDIT_RETRIES)
            {
                (
                    ChannelPermitState::Revoked,
                    "async_audit_retries_exhausted".into(),
                )
            } else {
                (
                    ChannelPermitState::PendingVerification,
                    "initial_audit_pending".into(),
                )
            }
        };

        self.issue_family_command(family, session.as_ref(), desired_state, &reason_code, now)?;
        self.update_process_intent(family, session.as_ref(), process_risk.as_deref(), process_deadline, process_evidence_current, now);
        Ok(())
    }

    fn request_async_audit_if_needed(
        &mut self,
        family: &str,
        session_id: Option<String>,
        context_id: Option<String>,
        now: f64,
    ) {
        let current_vpn_epoch = self.latest_vpn_observation.as_ref().map(|o| o.epoch.clone());
        let Some(track) = self.tracks.get_mut(family) else {
            return;
        };
        if let Some(in_flight) = track.audit_in_flight.clone() {
            if in_flight.session_id != session_id
                || in_flight.context_id != context_id
                || in_flight.policy_version != self.saved_policy_version
                || in_flight.vpn_epoch != current_vpn_epoch
            {
                track.audit_in_flight = None;
                track.audit_retry_count = 0;
                track.audit_retry_not_before = None;
                track.audit_last_failure_code = None;
            } else if in_flight.timeout_seconds > 0.0
                && now - in_flight.requested_at >= in_flight.timeout_seconds
            {
                // Logic Fix 4: Timeout cleanup so a hung or lost audit request never
                // wedges `audit_in_flight` forever.
                track.audit_in_flight = None;
                track.audit_retry_count = track.audit_retry_count.saturating_add(1);
                track.audit_last_failure_code = Some("async_audit_timeout".into());
                track.audit_retry_not_before = Some(now + ASYNC_AUDIT_RETRY_BACKOFF_SECONDS);
            } else {
                return;
            }
        }

        if track.audit_retry_count >= MAX_ASYNC_AUDIT_RETRIES {
            track.audit_last_failure_code = Some("async_audit_retries_exhausted".into());
            return;
        }
        if track
            .audit_retry_not_before
            .is_some_and(|not_before| now < not_before)
        {
            return;
        }

        self.next_audit_request_id = self.next_audit_request_id.saturating_add(1);
        let req = AsyncAuditRequest {
            request_id: self.next_audit_request_id,
            family: family.into(),
            target: if track.desktops.is_empty() && !track.processes.is_empty() {
                if family == "claude" { LaunchTarget::ClaudeCli } else { LaunchTarget::CodexCli }
            } else {
                PolicyCatalog::family(family).and_then(PolicyCatalog::guard_target).unwrap_or_default()
            },
            session_id,
            context_id,
            policy_version: self.saved_policy_version.clone(),
            vpn_epoch: current_vpn_epoch,
            upstream_endpoint: self.upstream_endpoint.clone(),
            requested_at: now,
            timeout_seconds: DEFAULT_ASYNC_AUDIT_TIMEOUT_SECONDS,
            cancellation: None,
        };
        if let Some(tx) = &self.audit_tx {
            if tx.send(req.clone()).is_ok() {
                track.audit_in_flight = Some(req);
            } else {
                // Logic Fix 4: Send failure must NOT leave `audit_in_flight` set.
                track.audit_in_flight = None;
                track.audit_retry_count = track.audit_retry_count.saturating_add(1);
                track.audit_last_failure_code = Some("async_audit_channel_closed".into());
                track.audit_retry_not_before = Some(now + ASYNC_AUDIT_RETRY_BACKOFF_SECONDS);
            }
        } else {
            track.audit_in_flight = None;
            track.audit_retry_count = track.audit_retry_count.saturating_add(1);
            track.audit_last_failure_code = Some("async_audit_worker_missing".into());
            track.audit_retry_not_before = Some(now + ASYNC_AUDIT_RETRY_BACKOFF_SECONDS);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_async_audit_completed(
        &mut self,
        request_id: u64,
        family: &str,
        audit_session_id: Option<String>,
        audit_policy: PolicyVersion,
        requested_at: f64,
        outcome: AsyncAuditOutcome,
        completed_at: f64,
        now: f64,
    ) -> Result<()> {
        let Some(family_spec) = PolicyCatalog::family(family) else {
            return Ok(());
        };
        let sessions = SessionStore::for_family(self.storage.clone(), family_spec.id);
        let receipts_store = ReceiptStore {
            storage: self.storage.clone(),
        };
        let current_session = self.load_channel_session(family_spec.id, now)?;
        let current_session_id = current_session.as_ref().map(|s| s.session_id.clone());
        let current_vpn_epoch = self.latest_vpn_observation.as_ref().map(|o| o.epoch.clone());

        // Logic Fix 4: Match `request_id` against `track.audit_in_flight` before
        // clearing `audit_in_flight` or applying the outcome.
        let (matched_in_flight, stale, timeout_limit, audit_target, audit_vpn_epoch) = {
            let Some(track) = self.tracks.get_mut(family) else {
                return Ok(());
            };
            let Some(in_flight) = track.audit_in_flight.as_ref() else {
                return Ok(());
            };
            if in_flight.request_id != request_id {
                return Ok(());
            }
            let timeout_limit = in_flight.timeout_seconds;
            let audit_target = in_flight.target;
            let audit_vpn_epoch = in_flight.vpn_epoch.clone();
            track.audit_in_flight = None;
            let risk_since_request = track
                .last_risk_at
                .is_some_and(|risk_at| risk_at > requested_at);
            let vpn_epoch_changed = current_vpn_epoch.is_some()
                && audit_vpn_epoch != current_vpn_epoch;
            let is_stale = audit_policy != self.saved_policy_version
                || audit_session_id != current_session_id
                || risk_since_request
                || vpn_epoch_changed;
            (true, is_stale, timeout_limit, audit_target, audit_vpn_epoch)
        };
        if !matched_in_flight || stale {
            return Ok(());
        }

        let vpn_match = self.compute_vpn_match(now);
        self.latest_vpn_match = vpn_match.clone();
        if let Some(ref vm) = vpn_match {
            if !vm.is_matched() {
                return self.issue_family_command(
                    family,
                    current_session.as_ref(),
                    ChannelPermitState::Revoked,
                    vm.reason_code(),
                    now,
                );
            }
        }

        let (audit, egress) = match outcome {
            AsyncAuditOutcome::Succeeded { audit, egress } => {
                if session::audit_target(&audit) != audit_target {
                    return self.record_async_audit_failure(family, current_session.as_ref(),
                        "audit_target_changed", now);
                }
                if !now.is_finite() || !requested_at.is_finite() || !completed_at.is_finite() || completed_at < requested_at
                    || completed_at > now + CLOCK_ROLLBACK_TOLERANCE_SECONDS
                    || (timeout_limit > 0.0 && ((completed_at - requested_at) >= timeout_limit
                        || (now - requested_at) >= timeout_limit))
                {
                    return self.record_async_audit_failure(
                        family,
                        current_session.as_ref(),
                        "async_audit_timeout",
                        now,
                    );
                }
                if let Some(track) = self.tracks.get_mut(family) {
                    track.audit_retry_count = 0;
                    track.audit_retry_not_before = None;
                    track.audit_last_failure_code = None;
                }
                (audit, egress)
            }
            AsyncAuditOutcome::Failed { code, .. } => {
                let reason = if code.trim().is_empty() {
                    "async_audit_failed"
                } else {
                    code.as_str()
                };
                return self.record_async_audit_failure(
                    family,
                    current_session.as_ref(),
                    reason,
                    now,
                );
            }
            AsyncAuditOutcome::TimedOut { .. } => {
                return self.record_async_audit_failure(
                    family,
                    current_session.as_ref(),
                    "async_audit_timeout",
                    now,
                );
            }
        };

        // When VPN supervision is active (`current_vpn_epoch` is Some), the audit egress
        // evidence MUST already carry the actual sampled `vpn_epoch` matching both the
        // request epoch and current epoch; never backfill `vpn_epoch` from the request.
        if let Some(ref expected_epoch) = current_vpn_epoch {
            let sampled_epoch = ControlledPathEvidence::parse(&egress).and_then(|ev| ev.vpn_epoch);
            if sampled_epoch.as_ref() != Some(expected_epoch)
                || (audit_vpn_epoch.is_some() && sampled_epoch != audit_vpn_epoch)
            {
                return self.record_async_audit_failure(
                    family,
                    current_session.as_ref(),
                    "recovery_vpn_epoch_mismatch",
                    now,
                );
            }
        }
        if Egress::fresh(&egress, now, session::GUARD_EGRESS_TTL).is_some() {
            self.latest_egress.insert(family.to_string(), egress.clone());
        }

        // Case 1: Recovering an existing revoked channel via `verify_channel_recovery_with_vpn_epoch`
        let was_revoked = self
            .tracks
            .get(family)
            .and_then(|t| t.current_permit.clone())
            .filter(|p| p.state == ChannelPermitState::Revoked && current_session.is_some());

        if let Some(previous_permit) = was_revoked {
            let revoked_at = self
                .tracks
                .get(family)
                .and_then(|t| t.revoked_at)
                .unwrap_or(previous_permit.issued_at);
            let next_gen = self
                .tracks
                .get(family)
                .map(|t| t.permit_generation + 1)
                .unwrap_or(2);
            let next_seq = self
                .tracks
                .get(family)
                .map(|t| t.command_seq + 1)
                .unwrap_or(2);
            // Full AuditStore receipts omit grants_launch_permission; display
            // receipts explicitly set it false. Match the existing launch
            // contract instead of requiring a field the producer never emits.
            let audit_ready = audit["ready"] == true
                && audit["grants_launch_permission"] != false
                && audit["policy"].as_str() == Some(audit_policy.policy_digest.as_str())
                && !matches!(audit["purpose"].as_str(),
                    Some("environment_detection" | "launch_requirements_preview" | "scoped_detection"))
                && audit.pointer("/context_transition/state").and_then(Value::as_str) == Some("stable");
            let audit_observed_at = audit["observed_at"].as_f64().unwrap_or(completed_at);
            let context_id = audit["context_id"].as_str().filter(|s| !s.is_empty()).unwrap_or("");

            match verify_channel_recovery_with_vpn_epoch(
                &previous_permit,
                revoked_at,
                audit_session_id.as_deref(),
                audit_ready,
                audit_observed_at,
                &audit_policy,
                &egress,
                current_session_id.as_deref(),
                &self.saved_policy_version,
                current_vpn_epoch.as_ref(),
                context_id,
                next_gen,
                next_seq,
                now,
                DEFAULT_PERMIT_TTL,
            ) {
                Ok(mut recovered_permit) => {
                    recovered_permit.backend = self.config.effective_network_backend();
                    recovered_permit.coverage_scope = self.coverage_scopes.get(family).cloned();
                    if let Some(obs) = self.latest_vpn_observation.as_ref() {
                        recovered_permit.valid_until =
                            recovered_permit.valid_until.min(obs.valid_until);
                    }
                    if let Some(s) = current_session.as_ref() {
                        if let Some(exit) =
                            Egress::fresh(&egress, now, session::GUARD_EGRESS_TTL)
                        {
                            let mut restored = s.clone();
                            restored.state = Phase::Active;
                            restored.context_id = context_id.to_string();
                            restored.baseline = exit;
                            restored.reason = None;
                            if let Err(error) = self.storage.atomic_json(
                                &self.storage.paths.session_for(family), &json!(restored),
                            ) {
                                if let Some(logger) = &self.diagnostics {
                                logger.persistence_failed(self.diagnostic(Some(family), "persist_recovered_session"), &error, now);
                                }
                            }
                        }
                    }
                    self.apply_permit_to_enforcer(family, recovered_permit, now)?;
                }
                Err(_) => {
                    // Keep channel revoked when recovery verification fails
                    let updated = sessions.load(now)?;
                    self.issue_family_command(
                        family,
                        updated.as_ref(),
                        ChannelPermitState::Revoked,
                        "recovery_verification_failed",
                        now,
                    )?;
                }
            }
            return Ok(());
        }

        // Case 2: One adoption path for desktops, CLIs and retained children.
        if current_session.is_none() {
            let processes = self.tracks.get(family).map(|t| t.processes.clone()).unwrap_or_default();
            if processes.is_empty() { return Ok(()); }
            match sessions.begin_channel_verified(&receipts_store, &audit, &egress, &processes, now) {
                Ok(adopted) => {
                    self.issue_family_command(family, Some(&adopted), ChannelPermitState::Permitted,
                        "session_adopted", now)?;
                    return Ok(());
                }
                Err(_) => return self.record_async_audit_failure(family, None, "initial_audit_rejected", now),
            }
        }

        Ok(())
    }

    fn record_async_audit_failure(
        &mut self,
        family: &str,
        session: Option<&session::Session>,
        failure_code: &str,
        now: f64,
    ) -> Result<()> {
        let (retries_exhausted, was_revoked) = {
            let Some(track) = self.tracks.get_mut(family) else {
                return Ok(());
            };
            track.audit_retry_count = track.audit_retry_count.saturating_add(1);
            track.audit_retry_not_before = Some(now + ASYNC_AUDIT_RETRY_BACKOFF_SECONDS);
            let exhausted = track.audit_retry_count >= MAX_ASYNC_AUDIT_RETRIES;
            let code = if exhausted {
                "async_audit_retries_exhausted"
            } else {
                failure_code
            };
            track.audit_last_failure_code = Some(code.into());
            let was_revoked = track
                .current_permit
                .as_ref()
                .is_some_and(|p| p.state == ChannelPermitState::Revoked);
            (exhausted, was_revoked)
        };
        let (state, reason) = if retries_exhausted {
            (ChannelPermitState::Revoked, "async_audit_retries_exhausted")
        } else if was_revoked {
            (ChannelPermitState::Revoked, failure_code)
        } else {
            (ChannelPermitState::PendingVerification, failure_code)
        };
        self.issue_family_command(family, session, state, reason, now)
    }

    fn issue_family_command(
        &mut self,
        family: &str,
        session: Option<&session::Session>,
        desired_state: ChannelPermitState,
        reason_code: &str,
        now: f64,
    ) -> Result<()> {
        let members = self
                .tracks
                .get(family)
                .map(|t| {
                    t.desktops
                        .iter()
                        .filter(|(_, main, _)| *main)
                        .map(|(d, _, _)| d.clone())
                        .collect()
                })
                .unwrap_or_default();
        let session_id = session.map(|s| s.session_id.clone());
        let context_id = session.map(|s| s.context_id.clone()).filter(|s| !s.is_empty());
        let baseline_ip = session.map(|s| s.baseline.ip.clone()).filter(|s| !s.is_empty());
        let backend = self.config.effective_network_backend();
        let vpn_epoch = self.latest_vpn_observation.as_ref().map(|o| o.epoch.clone());
        let coverage_scope = self.coverage_scopes.get(family).cloned();

        // Logic Fix 1: Cap `valid_until` by key evidence expiration time (and VPN
        // observation expiration when present), and refuse to issue `Permitted` if
        // egress evidence has already expired!
        let (effective_desired_state, effective_reason, valid_until) =
            if desired_state == ChannelPermitState::Permitted {
                match Egress::fresh(self.latest_egress.get(family).unwrap_or(&Value::Null), now, session::GUARD_EGRESS_TTL) {
                    Some(exit) if exit.observed_at + session::GUARD_EGRESS_TTL > now => {
                        let evidence_expires_at = exit.observed_at + session::GUARD_EGRESS_TTL;
                        let mut capped = (now + DEFAULT_PERMIT_TTL).min(evidence_expires_at);
                        if let Some(obs) = self.latest_vpn_observation.as_ref() {
                            capped = capped.min(obs.valid_until);
                        }
                        if capped <= now {
                            (
                                ChannelPermitState::Revoked,
                                "vpn_observation_stale".to_string(),
                                now + DEFAULT_PERMIT_TTL,
                            )
                        } else {
                            (
                                ChannelPermitState::Permitted,
                                reason_code.to_string(),
                                capped,
                            )
                        }
                    }
                    _ => (
                        ChannelPermitState::Revoked,
                        "egress_evidence_expired".to_string(),
                        now + DEFAULT_PERMIT_TTL,
                    ),
                }
            } else {
                (
                    desired_state,
                    reason_code.to_string(),
                    now + DEFAULT_PERMIT_TTL,
                )
            };

        // Do not replace a command on every observation tick: execution receipts
        // need a stable sequence to match. Renew only near lease expiry.
        if self.tracks.get(family).is_some_and(|track| {
            track.current_permit.as_ref().is_some_and(|p| {
                p.state == effective_desired_state && p.reason_code == effective_reason
                    && p.command_seq == track.command_seq && p.permit_generation == track.permit_generation
                    && p.session_id == session_id && p.policy_version == self.saved_policy_version
                    && p.context_id == context_id && p.baseline_ip == baseline_ip
                    && p.members == members && track.processes == track.commanded_processes
                    && p.backend == backend && p.coverage_scope == coverage_scope
                    && (p.state != ChannelPermitState::Permitted || p.vpn_epoch == vpn_epoch)
                    && now >= p.issued_at && (p.state != ChannelPermitState::Permitted
                        || (p.valid_until > now + DEFAULT_PERMIT_TTL / 2.0 && p.valid_until <= valid_until))
            })
        }) { return Ok(()); }

        let (permit_generation, command_seq) = {
            let track = self
                .tracks
                .entry(family.into())
                .or_insert_with(FamilyRuntimeTrack::new);
            track.end_process_authority();
            let session_changed = track.session_id != session_id;
            let state_changed = track
                .current_permit
                .as_ref()
                .is_some_and(|p| p.state != effective_desired_state);
            if session_changed || state_changed {
                track.permit_generation = track.permit_generation.saturating_add(1);
            }
            if effective_desired_state == ChannelPermitState::Revoked && state_changed {
                track.revoked_at = Some(now);
                track.last_risk_at = Some(now);
            }
            track.session_id = session_id.clone();
            track.command_seq = track.command_seq.saturating_add(1);
            (track.permit_generation, track.command_seq)
        };

        let permit = ChannelPermit {
            family: family.into(),
            session_id,
            policy_version: self.saved_policy_version.clone(),
            permit_generation,
            command_seq,
            state: effective_desired_state,
            reason_code: effective_reason,
            issued_at: now,
            valid_until,
            context_id,
            baseline_ip,
            members,
            backend,
            vpn_epoch,
            coverage_scope,
        };
        self.apply_permit_to_enforcer(family, permit, now)
    }

    fn apply_permit_to_enforcer(
        &mut self,
        family: &str,
        permit: ChannelPermit,
        now: f64,
    ) -> Result<()> {
        let allowed_processes = self
            .tracks
            .get(family)
            .map(|t| t.processes.clone())
            .unwrap_or_default();
        let command = ChannelEnforcementCommand {
            family: family.into(),
            session_id: permit.session_id.clone(),
            policy_version: permit.policy_version.clone(),
            permit_generation: permit.permit_generation,
            command_seq: permit.command_seq,
            target_executor_boot_id: self.expected_executor_boot_id.clone(),
            permit: permit.clone(),
            allowed_processes,
            upstream_endpoint: self.upstream_endpoint.clone(),
            issued_at: now,
        };
        if let Some(track) = self.tracks.get_mut(family) {
            track.commanded_processes = command.allowed_processes.clone();
            track.session_id = permit.session_id.clone();
            track.permit_generation = permit.permit_generation;
            track.command_seq = permit.command_seq;
            track.current_permit = Some(permit);
            track.policy_sync_state = PolicySyncState::PendingApply;
            track.latest_receipt = None;
        }
        let mut all_permits: std::collections::BTreeMap<String, ChannelPermit> = std::collections::BTreeMap::new();
        for (fam, tr) in &self.tracks {
            if let Some(ref p) = tr.current_permit {
                all_permits.insert(fam.clone(), p.clone());
            }
        }
        self.persist_state("state/channel-permits.json", "persist_permits", &json!(all_permits), now);
        if let Some(logger) = &self.diagnostics {
            let mut diagnostic = self.diagnostic(Some(family), "command_issued");
            diagnostic.state = serde_json::to_value(command.permit.state).ok().and_then(|v| v.as_str().map(str::to_owned));
            diagnostic.reason_code = Some(command.permit.reason_code.clone());
            logger.record(diagnostic, now);
        }
        if let Some(enforcer) = self.enforcer.clone() {
            match enforcer.apply_command(&command, now) {
                Ok(receipt) => {
                    let received_at = self.inline_receipt_clock.map_or(now, |clock| clock());
                    self.ingest_receipt(receipt, received_at)?;
                    return Ok(());
                }
                Err(error) => {
                    if let Some(logger) = &self.diagnostics {
                        let mut diagnostic = self.diagnostic(Some(family), "command_failed");
                        diagnostic.failure = Some(crate::channel_diagnostics::DiagnosticFailure::from_error(&error));
                        logger.record(diagnostic, now);
                    }
                    if let Some(track) = self.tracks.get_mut(family) {
                        track.policy_sync_state = PolicySyncState::ApplyFailed;
                        track.latest_receipt = None;
                    }
                }
            }
        }
        self.refresh_verdict_and_emit(family, now);
        Ok(())
    }

    fn ingest_receipt(&mut self, receipt: ChannelEnforcementReceipt, receiver_now: f64) -> Result<()> {
        let family = receipt.family.clone();
        let expected_boot_id = self.expected_executor_boot_id.clone();
        let mut autonomous_cutoff = None;
        let receipt_for_log = receipt.clone();
        let changed = self.tracks.get(&family).and_then(|t| t.latest_receipt.as_ref()).is_none_or(|old|
            old.executor_boot_id != receipt.executor_boot_id || old.command_seq != receipt.command_seq
            || old.permit_generation != receipt.permit_generation || old.enforcement_state != receipt.enforcement_state
            || old.error_code != receipt.error_code || old.new_connections_blocked != receipt.new_connections_blocked
            || old.active_flows_count != receipt.active_flows_count);
        let accepted = {
            let Some(track) = self.tracks.get_mut(&family) else {
                return Ok(());
            };
            // Reject stale session, older generation, or out-of-order command receipts
            // so old receipts never overwrite newer state!
            let Some(permit) = track.current_permit.as_ref() else {
                return Ok(());
            };
            if receipt.session_id != permit.session_id
                || receipt.permit_generation < permit.permit_generation
                || receipt.command_seq < permit.command_seq
            {
                false
            } else {
                let boot_id_valid = expected_boot_id
                    .as_deref()
                    .is_none_or(|exp| exp == receipt.executor_boot_id.as_str());
                let timing_valid = receipt.observed_at + CLOCK_ROLLBACK_TOLERANCE_SECONDS
                    >= permit.issued_at
                    && receipt.observed_at <= receiver_now + CLOCK_ROLLBACK_TOLERANCE_SECONDS
                    && (receiver_now - receipt.observed_at) < MAX_ENFORCEMENT_RECEIPT_AGE;
                if boot_id_valid && timing_valid && receipt.policy_version == self.saved_policy_version
                    && receipt.policy_version == permit.policy_version
                    && receipt.command_seq == permit.command_seq && receipt.permit_generation == permit.permit_generation
                    && permit.state == ChannelPermitState::Permitted && receipt.permit_state == ChannelPermitState::Revoked {
                    autonomous_cutoff = Some(receipt.error_code.clone().unwrap_or_else(|| "executor_autonomous_cutoff".into()));
                    track.audit_in_flight = None;
                }
                if receipt.policy_version == self.saved_policy_version
                    && receipt.command_seq == permit.command_seq
                {
                    if boot_id_valid
                        && timing_valid
                        && receipt.enforcement_state != ChannelEnforcementState::Failed
                    {
                        track.applied_policy_version = Some(receipt.policy_version.clone());
                        track.policy_sync_state = PolicySyncState::Applied;
                    } else {
                        track.policy_sync_state = PolicySyncState::ApplyFailed;
                    }
                }
                track.latest_receipt = Some(receipt);
                true
            }
        };
        if changed {
            if let Some(logger) = &self.diagnostics {
                let mut diagnostic = self.diagnostic(Some(&family), if accepted { "receipt_received" } else { "receipt_rejected" });
                diagnostic.executor_boot_id = Some(receipt_for_log.executor_boot_id);
                diagnostic.session_id = receipt_for_log.session_id;
                diagnostic.policy_version = Some(receipt_for_log.policy_version);
                diagnostic.permit_generation = Some(receipt_for_log.permit_generation);
                diagnostic.command_seq = Some(receipt_for_log.command_seq);
                diagnostic.source_observed_at = Some(receipt_for_log.observed_at);
                diagnostic.state = serde_json::to_value(receipt_for_log.enforcement_state).ok().and_then(|v| v.as_str().map(str::to_owned));
                diagnostic.failure = receipt_for_log.error_code.map(|code| crate::channel_diagnostics::DiagnosticFailure::from_error(&CoreError::new(&code, "")));
                logger.record(diagnostic, receiver_now);
            }
        }
        if let Some(reason) = autonomous_cutoff {
            if let Some(spec) = PolicyCatalog::family(&family) {
                let session = self.load_channel_session(spec.id, receiver_now)?;
                // Issue a new authority command and recovery fence. The
                // executor's immutable old command is never edited in place.
                self.issue_family_command(&family, session.as_ref(), ChannelPermitState::Revoked, &reason, receiver_now)?;
                return Ok(());
            }
        }
        if accepted {
            self.refresh_verdict_and_emit(&family, receiver_now);
        }
        Ok(())
    }

    pub fn ingest_process_receipt(
        &mut self,
        receipt: ProcessDispositionReceipt,
        receiver_now: f64,
    ) -> Result<()> {
        use crate::process_disposition::{result_state, RECEIPT_TTL, RESULT_COMPLETION_GRACE};
        let Some(authority) = receipt.authority.as_ref() else { return Ok(()); };
        let family = receipt.family.clone();
        let Some(track) = self.tracks.get_mut(&family) else { return Ok(()); };
        let targets: std::collections::BTreeSet<_> = authority.target_identities.iter().map(|t| t.pid).collect();
        let completed: std::collections::BTreeSet<_> = receipt.target_results.iter().map(|t| t.pid).collect();
        if !track.pending_process_results.get(&receipt.intent_id).is_some_and(|(expires, fence)|
                receiver_now <= *expires && fence.is_claimed(authority))
            || authority.session_id != receipt.session_id || authority.family != family || authority.intent_id != receipt.intent_id
            || authority.producer_boot_id != self.producer_boot_id
            || authority.action != receipt.action || receipt.action != "force"
            || !(receipt.observed_at >= authority.created_at && receipt.observed_at <= authority.valid_until + RESULT_COMPLETION_GRACE
                && (0.0..=RECEIPT_TTL).contains(&(receiver_now - receipt.observed_at)))
            || targets != completed || completed.len() != receipt.target_results.len()
            || receipt.process_execution_state != result_state(&receipt.target_results) || receipt.process_preserved
            || receipt.target_results.iter().any(|r| {
                r.requested_action != "force_quit" || !(authority.created_at..=receipt.observed_at).contains(&r.timestamp)
                    || r.terminated != (r.process_state == "terminated")
                    || matches!(r.process_state.as_str(), "terminated" | "timeout" | "exit_unconfirmed") != r.signal_sent_at.is_some()
                    || r.signal_sent_at.is_some_and(|at| !(authority.created_at..=r.timestamp.min(authority.valid_until)).contains(&at))
            })
        { return Ok(()); }
        let current = track.process_fence.as_ref().and_then(|fence| fence.current()).as_ref() == Some(authority)
            && track.session_id.as_deref() == Some(receipt.session_id.as_str())
            && self.expected_executor_boot_id.as_deref() == Some(authority.executor_boot_id.as_str())
            && authority.policy_version == self.saved_policy_version && authority.command_seq == track.command_seq
            && authority.permit_generation == track.permit_generation;
        // Consumed exactly once. An old result cannot mutate a live command or
        // appear as the current disposition, even when the session is unchanged.
        track.pending_process_results.remove(&receipt.intent_id);
        if current {
            track.latest_process_receipt = Some(receipt);
        } else {
            track.record_previous_process_result(receipt);
        }
        self.refresh_verdict_and_emit(&family, receiver_now);
        Ok(())
    }

    fn refresh_verdict_and_emit(&mut self, family: &str, now: f64) {
        let Some(track) = self.tracks.get_mut(family) else {
            return;
        };
        let Some(permit) = track.current_permit.as_ref() else {
            return;
        };
        let verdict = if track.policy_sync_state == PolicySyncState::ApplyFailed && track.latest_receipt.is_none() {
            ChannelSupervisionVerdict::EnforcementFailed {
                code: "enforcement_command_apply_failed".into(),
                status_label_zh: "通道执行失败，未确认实际断流".into(),
            }
        } else { evaluate_channel_supervision_with_boot_id(
            permit,
            track.latest_receipt.as_ref(),
            &self.saved_policy_version,
            self.expected_executor_boot_id.as_deref(),
            now,
        ) };
        if matches!(verdict, ChannelSupervisionVerdict::EnforcementFailed { .. }) {
            track.policy_sync_state = PolicySyncState::ApplyFailed;
        }
        track.verdict = Some(verdict);
        let local_proxy_port = self.enforcer.as_ref().and_then(|e| e.local_proxy_port());
        let default_backend = self.config.effective_network_backend();
        let latest_vpn_epoch = self.latest_vpn_observation.as_ref().map(|o| o.epoch.clone());
        let latest_vpn_match = self.latest_vpn_match.clone();
        let coverage_scope = self.coverage_scopes.get(family).cloned();
        let unmanaged_pids = self
            .unmanaged_member_pids
            .get(family)
            .cloned()
            .unwrap_or_default();
        let family_state = Self::build_family_monitor_state_from_track(
            &self.producer_boot_id,
            &self.saved_policy_version,
            family,
            track,
            local_proxy_port,
            default_backend,
            latest_vpn_epoch,
            latest_vpn_match,
            coverage_scope,
            unmanaged_pids,
            now,
        );
        self.event_seq = self.event_seq.saturating_add(1);
        let event = ChannelMonitorEvent {
            producer_boot_id: self.producer_boot_id.clone(),
            event_seq: self.event_seq,
            family_state,
        };
        self.emitted_events.push(event.clone());
        if self.emitted_events.len() > MAX_EMITTED_EVENTS {
            let overflow = self.emitted_events.len() - MAX_EMITTED_EVENTS;
            self.emitted_events.drain(0..overflow);
        }
        self.persisted_events.push(event);
        if self.persisted_events.len() > MAX_PERSISTED_EVENTS {
            let drain_count = self.persisted_events.len() - MAX_PERSISTED_EVENTS;
            self.persisted_events.drain(0..drain_count);
        }
    }

    fn build_family_monitor_state(
        &self,
        family: &str,
        track: &FamilyRuntimeTrack,
        now: f64,
    ) -> FamilyChannelMonitorState {
        let local_proxy_port = self.enforcer.as_ref().and_then(|e| e.local_proxy_port());
        let default_backend = self.config.effective_network_backend();
        let latest_vpn_epoch = self.latest_vpn_observation.as_ref().map(|o| o.epoch.clone());
        let latest_vpn_match = self.latest_vpn_match.clone();
        let coverage_scope = self.coverage_scopes.get(family).cloned();
        let unmanaged_pids = self
            .unmanaged_member_pids
            .get(family)
            .cloned()
            .unwrap_or_default();
        Self::build_family_monitor_state_from_track(
            &self.producer_boot_id,
            &self.saved_policy_version,
            family,
            track,
            local_proxy_port,
            default_backend,
            latest_vpn_epoch,
            latest_vpn_match,
            coverage_scope,
            unmanaged_pids,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_family_monitor_state_from_track(
        producer_boot_id: &str,
        saved_policy_version: &PolicyVersion,
        family: &str,
        track: &FamilyRuntimeTrack,
        local_proxy_port: Option<u16>,
        default_backend: NetworkBackendKind,
        latest_vpn_epoch: Option<VpnEpoch>,
        latest_vpn_match: Option<VpnMatch>,
        coverage_scope: Option<BackendCoverageScope>,
        unmanaged_member_pids: Vec<u32>,
        now: f64,
    ) -> FamilyChannelMonitorState {
        let permit_state = track
            .current_permit
            .as_ref()
            .map(|p| p.state)
            .unwrap_or(ChannelPermitState::PendingVerification);
        let reason_code = track
            .current_permit
            .as_ref()
            .map(|p| p.reason_code.clone())
            .unwrap_or_else(|| "uninitialized".into());
        let display_state = track
            .verdict
            .as_ref()
            .map(ChannelSupervisionVerdict::display_state)
            .unwrap_or(match permit_state {
                ChannelPermitState::PendingVerification => {
                    ChannelMonitorDisplayState::PendingVerification
                }
                ChannelPermitState::Permitted | ChannelPermitState::Revoked => {
                    ChannelMonitorDisplayState::Failed
                }
            });
        let display_label_zh = match &track.verdict {
            Some(ChannelSupervisionVerdict::EnforcementFailed {
                status_label_zh, ..
            }) => status_label_zh.clone(),
            _ => display_state.label_zh().to_string(),
        };
        let active_member_pids = track
            .desktops
            .iter()
            .map(|(d, _, _)| d.pid)
            .collect::<Vec<_>>();
        let (
            active_flows_count,
            terminated_flows_count,
            blocked_new_connections,
            local_proxy_ready,
            system_extension_active,
            sandbox_ready,
        ) = track
            .latest_receipt
            .as_ref()
            .map(|r| {
                (
                    r.active_flows_count,
                    r.terminated_flows_count,
                    r.blocked_new_connections,
                    r.local_proxy_ready,
                    r.system_extension_active,
                    r.sandbox_ready,
                )
            })
            .unwrap_or((0, 0, 0, false, false, false));
        let backend = track
            .current_permit
            .as_ref()
            .map(|p| p.backend)
            .unwrap_or(default_backend);
        let vpn_epoch = track
            .current_permit
            .as_ref()
            .and_then(|p| p.vpn_epoch.clone())
            .or(latest_vpn_epoch);
        let effective_coverage_scope = track
            .current_permit
            .as_ref()
            .and_then(|p| p.coverage_scope.clone())
            .or(coverage_scope);

        let process_disposition_receipt = track.latest_process_receipt.as_ref().filter(|receipt|
            (0.0..=crate::process_disposition::RECEIPT_TTL).contains(&(now - receipt.observed_at))).cloned();
        let previous_process_disposition_receipts = track.previous_process_receipts.iter().filter(|receipt|
            (0.0..=crate::process_disposition::RECEIPT_TTL).contains(&(now - receipt.observed_at))).cloned().collect();
        let (process_preserved, process_execution_state, process_disposition_action) =
            if let Some(ref pr) = process_disposition_receipt {
                (
                    pr.process_preserved,
                    Some(pr.process_execution_state.clone()),
                    Some(pr.action.clone()),
                )
            } else if let Some(intent) = track.process_fence.as_ref().and_then(|fence| fence.current()) {
                (false, Some(if now < intent.valid_until { "executing" } else { "unknown" }.into()), Some(intent.action))
            } else {
                (true, None, None)
            };

        FamilyChannelMonitorState {
            producer_boot_id: producer_boot_id.into(),
            family: family.into(),
            session_id: track.session_id.clone(),
            saved_policy_version: saved_policy_version.clone(),
            applied_policy_version: track.applied_policy_version.clone(),
            policy_sync_state: track.policy_sync_state,
            policy_sync_label_zh: track.policy_sync_state.label_zh().into(),
            permit_generation: track.permit_generation,
            command_seq: track.command_seq,
            permit_state,
            display_state,
            display_label_zh,
            reason_code,
            process_preserved,
            process_execution_state,
            process_disposition_action,
            process_disposition_receipt,
            previous_process_disposition_receipts,
            active_member_pids,
            active_members: track.processes.clone(),
            local_proxy_ready,
            system_extension_active,
            active_flows_count,
            terminated_flows_count,
            blocked_new_connections,
            local_proxy_port,
            valid_until: track.current_permit.as_ref().map(|p| p.valid_until),
            updated_at: now,
            backend,
            vpn_epoch,
            vpn_match: latest_vpn_match,
            coverage_scope: effective_coverage_scope.unwrap_or_default(),
            unmanaged_member_pids,
            sandbox_ready,
        }
    }
}
