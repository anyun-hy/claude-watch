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
        evaluate_channel_supervision_with_boot_id, verify_channel_recovery, BoundProcessToken,
        ChannelEnforcementCommand, ChannelEnforcementReceipt, ChannelEnforcementState,
        ChannelMonitorDisplayState, ChannelMonitorEvent, ChannelMonitorSnapshot, ChannelPermit,
        ChannelPermitState, ChannelSupervisionVerdict, FamilyChannelMonitorState, PolicySyncState,
        PolicyVersion, CLOCK_ROLLBACK_TOLERANCE_SECONDS, DEFAULT_PERMIT_TTL,
        MAX_ENFORCEMENT_RECEIPT_AGE,
    },
    config::Config,
    error::{CoreError, Result},
    policy::PolicyCatalog,
    session::{self, Desktop, Egress, Phase},
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
};

pub const DEFAULT_ASYNC_AUDIT_TIMEOUT_SECONDS: f64 = 15.0;
pub const MAX_ASYNC_AUDIT_RETRIES: u32 = 3;
pub const ASYNC_AUDIT_RETRY_BACKOFF_SECONDS: f64 = 2.0;
pub const MAX_EMITTED_EVENTS: usize = 128;
pub const MAX_PERSISTED_EVENTS: usize = 64;

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
    ProcessInventoryUpdated {
        family: String,
        desktops: Vec<(Desktop, bool, String)>,
        processes: Vec<BoundProcessToken>,
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

#[derive(Debug, Clone, PartialEq)]
pub struct AsyncAuditRequest {
    pub request_id: u64,
    pub family: String,
    pub session_id: Option<String>,
    pub policy_version: PolicyVersion,
    pub requested_at: f64,
    pub timeout_seconds: f64,
}

#[derive(Debug, Clone)]
struct FamilyRuntimeTrack {
    session_id: Option<String>,
    permit_generation: u64,
    command_seq: u64,
    desktops: Vec<(Desktop, bool, String)>,
    processes: Vec<BoundProcessToken>,
    current_permit: Option<ChannelPermit>,
    latest_receipt: Option<ChannelEnforcementReceipt>,
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
impl FamilyRuntimeTrack {
    fn new() -> Self {
        Self {
            session_id: None,
            permit_generation: 1,
            command_seq: 0,
            desktops: Vec::new(),
            processes: Vec::new(),
            current_permit: None,
            latest_receipt: None,
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
}

pub struct ChannelSupervisor {
    pub storage: StateStore,
    pub producer_boot_id: String,
    enforcer: Option<Arc<dyn ChannelEnforcer>>,
    expected_executor_boot_id: Option<String>,
    audit_tx: Option<Sender<AsyncAuditRequest>>,
    next_audit_request_id: u64,
    config: Config,
    saved_policy_version: PolicyVersion,
    latest_egress: Value,
    latest_local_guard: Value,
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
        let config = ConfigStore {
            storage: storage.clone(),
        }
        .load()
        .unwrap_or_default();
        let saved_policy_version = Self::compute_policy_version(&config)?;
        let upstream_endpoint = if config.proxy_url.trim().is_empty() {
            "127.0.0.1:7890".to_string()
        } else {
            config.proxy_url.clone()
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
            expected_executor_boot_id,
            audit_tx,
            next_audit_request_id: 0,
            config,
            saved_policy_version,
            latest_egress: json!({"state": "unknown"}),
            latest_local_guard: json!({"proxy": "ok", "tun": "ok"}),
            upstream_endpoint,
            tracks,
            event_seq: 0,
            emitted_events: Vec::new(),
            persisted_events: Vec::new(),
        })
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
                    track.policy_sync_state = PolicySyncState::PendingApply;
                }
                self.refresh_verdict_and_emit(&family, now);
            }
        }
    }

    pub fn expected_executor_boot_id(&self) -> Option<&str> {
        self.expected_executor_boot_id.as_deref()
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
        F: FnMut(&AsyncAuditRequest) -> Result<(Value, Value, f64)> + Send + 'static,
    {
        let (req_tx, req_rx): (Sender<AsyncAuditRequest>, Receiver<AsyncAuditRequest>) =
            mpsc::channel();
        let run_audit = Arc::new(std::sync::Mutex::new(run_audit));
        let handle = thread::Builder::new()
            .name("channel-async-audit-worker".into())
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let Ok(req) = req_rx.recv_timeout(std::time::Duration::from_millis(50)) else {
                        continue;
                    };
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let runner = Arc::clone(&run_audit);
                    let (result_tx, result_rx) = mpsc::channel();
                    let req_clone = req.clone();
                    let start_instant = std::time::Instant::now();
                    let runner_thread = thread::Builder::new()
                        .name("channel-audit-runner".into())
                        .spawn(move || {
                            // Non-blocking try_lock: If previous timed-out runner is still stuck in-flight,
                            // immediately fail without wedging the new runner or queueing on the poisoned lock.
                            let res = match runner.try_lock() {
                                Ok(mut locked) => locked(&req_clone),
                                Err(_) => Err(CoreError::new(
                                    "audit_runner_busy_previous_in_flight",
                                    "上一次慢审计任务仍在运行，本次执行跳过阻塞并立即释放资源",
                                )),
                            };
                            let _ = result_tx.send(res);
                        });

                    let timeout = if req.timeout_seconds > 0.0 {
                        std::time::Duration::from_secs_f64(req.timeout_seconds)
                    } else {
                        std::time::Duration::from_secs(30)
                    };

                    match result_rx.recv_timeout(timeout) {
                        Ok(Ok((audit, egress, completed_at))) => {
                            let elapsed = (completed_at - req.requested_at).max(0.0);
                            let outcome = if req.timeout_seconds > 0.0
                                && elapsed >= req.timeout_seconds
                            {
                                AsyncAuditOutcome::TimedOut {
                                    elapsed_seconds: elapsed,
                                }
                            } else {
                                AsyncAuditOutcome::Succeeded { audit, egress }
                            };
                            let _ = event_tx.send(SupervisionEvent::AsyncAuditCompleted {
                                request_id: req.request_id,
                                family: req.family,
                                session_id: req.session_id,
                                policy_version: req.policy_version,
                                requested_at: req.requested_at,
                                outcome,
                                completed_at,
                            });
                            if let Ok(handle) = runner_thread {
                                let _ = handle.join();
                            }
                        }
                        Ok(Err(err)) => {
                            let elapsed = start_instant.elapsed().as_secs_f64();
                            let completed_at = req.requested_at + elapsed;
                            let _ = event_tx.send(SupervisionEvent::AsyncAuditCompleted {
                                request_id: req.request_id,
                                family: req.family,
                                session_id: req.session_id,
                                policy_version: req.policy_version,
                                requested_at: req.requested_at,
                                outcome: AsyncAuditOutcome::Failed {
                                    code: err.code,
                                    detail: err.message,
                                },
                                completed_at,
                            });
                            if let Ok(handle) = runner_thread {
                                let _ = handle.join();
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            // Immediate timeout without wedging runner or blocking subsequent audits
                            let completed_at = req.requested_at + req.timeout_seconds;
                            let _ = event_tx.send(SupervisionEvent::AsyncAuditCompleted {
                                request_id: req.request_id,
                                family: req.family,
                                session_id: req.session_id,
                                policy_version: req.policy_version,
                                requested_at: req.requested_at,
                                outcome: AsyncAuditOutcome::TimedOut {
                                    elapsed_seconds: req.timeout_seconds,
                                },
                                completed_at,
                            });
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => {}
                    }
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

    pub fn handle_event(&mut self, event: SupervisionEvent) -> Result<ChannelMonitorSnapshot> {
        let now = match &event {
            SupervisionEvent::EnvironmentUpdated { observed_at, .. } => *observed_at,
            SupervisionEvent::ProcessInventoryUpdated { observed_at, .. } => *observed_at,
            SupervisionEvent::PolicyUpdated { observed_at, .. } => *observed_at,
            SupervisionEvent::NetworkContextChanged { observed_at, .. } => *observed_at,
            SupervisionEvent::ExecutorRestarted { observed_at, .. } => *observed_at,
            SupervisionEvent::LeaseExpired { observed_at, .. } => *observed_at,
            SupervisionEvent::EnforcementReceiptArrived { received_at, .. } => *received_at,
            SupervisionEvent::AsyncAuditCompleted { completed_at, .. } => *completed_at,
        };

        match event {
            SupervisionEvent::NetworkContextChanged {
                context_id,
                observed_at,
            } => {
                let family_ids: Vec<String> = self.tracks.keys().cloned().collect();
                for family in family_ids {
                    if let Some(track) = self.tracks.get_mut(&family) {
                        track.permit_generation = track.permit_generation.saturating_add(1);
                        track.revoked_at = Some(observed_at);
                        track.last_risk_at = Some(observed_at);
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
                    self.evaluate_family(&family, observed_at)?;
                }
            }
            SupervisionEvent::ExecutorRestarted {
                new_boot_id,
                observed_at,
            } => {
                self.register_executor_handshake(new_boot_id, observed_at);
            }
            SupervisionEvent::EnvironmentUpdated {
                egress,
                local_guard,
                observed_at,
            } => {
                let fresh_egress =
                    Egress::fresh(&egress, observed_at, session::GUARD_EGRESS_TTL).is_some();
                self.latest_egress = egress;
                self.latest_local_guard = local_guard;
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
                    self.evaluate_family(&family, observed_at)?;
                }
            }
            SupervisionEvent::ProcessInventoryUpdated {
                family,
                desktops,
                processes,
                observed_at,
            } => {
                if let Some(track) = self.tracks.get_mut(&family) {
                    track.desktops = desktops;
                    track.processes = processes;
                }
                self.evaluate_family(&family, observed_at)?;
            }
            SupervisionEvent::PolicyUpdated {
                config,
                observed_at,
            } => {
                let new_version = Self::compute_policy_version(&config)?;
                if !config.proxy_url.trim().is_empty() {
                    self.upstream_endpoint = config.proxy_url.clone();
                }
                let version_changed = new_version != self.saved_policy_version;
                self.config = config;
                self.saved_policy_version = new_version;
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
                    self.evaluate_family(&family, observed_at)?;
                }
            }
            SupervisionEvent::LeaseExpired {
                observed_at,
                woke_from_sleep,
            } => {
                if let Some(enforcer) = &self.enforcer {
                    let receipts =
                        enforcer.enforce_active_deadlines(observed_at, woke_from_sleep)?;
                    for receipt in receipts {
                        self.ingest_receipt(receipt, observed_at)?;
                    }
                }
                let family_ids: Vec<String> = self.tracks.keys().cloned().collect();
                for family in family_ids {
                    if let Some(track) = self.tracks.get_mut(&family) {
                        if let Some(permit) = track.current_permit.as_mut() {
                            let (eff, reason) = permit.effective_state_with_clock(
                                observed_at,
                                None,
                                woke_from_sleep,
                                &self.saved_policy_version,
                            );
                            if eff == ChannelPermitState::Revoked {
                                permit.state = ChannelPermitState::Revoked;
                                permit.reason_code = reason.into();
                                track.revoked_at = Some(observed_at);
                            }
                        }
                        if let Some(enforcer) = &self.enforcer {
                            if let Ok(Some(r)) = enforcer.receipt_for(&family, observed_at) {
                                track.latest_receipt = Some(r);
                            }
                        }
                    }
                    self.refresh_verdict_and_emit(&family, observed_at);
                }
            }
            SupervisionEvent::EnforcementReceiptArrived {
                receipt,
                received_at,
            } => {
                self.ingest_receipt(receipt, received_at)?;
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
                )?;
            }
        }

        let snap = self.snapshot(now);
        // Secondary persistence never blocks or rolls back the channel command
        // already executed by the enforcer.
        let _ = self.storage.atomic_json(
            &self.storage.paths.watch().join("state/channel-supervision.json"),
            &json!(snap),
        );
        let _ = self.storage.atomic_json(
            &self.storage.paths.watch().join("state/channel-events.json"),
            &json!(self.persisted_events),
        );
        Ok(snap)
    }

    fn evaluate_family(&mut self, family: &str, now: f64) -> Result<()> {
        let Some(family_spec) = PolicyCatalog::family(family) else {
            return Ok(());
        };
        let sessions = SessionStore::for_family(self.storage.clone(), family_spec.id);
        let receipts_store = ReceiptStore {
            storage: self.storage.clone(),
        };
        let mut session = sessions.load(now)?;
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

        let local_guard_ok =
            self.latest_local_guard["proxy"] == "ok" && self.latest_local_guard["tun"] == "ok";
        let fresh_exit = Egress::fresh(&self.latest_egress, now, session::GUARD_EGRESS_TTL);
        let evidence_valid = fresh_exit
            .as_ref()
            .is_some_and(|exit| exit.observed_at + session::GUARD_EGRESS_TTL > now);
        let had_active_or_permitted = session
            .as_ref()
            .is_some_and(|s| s.state == Phase::Active)
            || self
                .tracks
                .get(family)
                .and_then(|t| t.current_permit.as_ref())
                .is_some_and(|p| p.state == ChannelPermitState::Permitted);

        // Check if there is an active risk on the current session or environment,
        // or if key evidence (egress / local_guard) has expired while a session is active.
        let mut risk_code: Option<String> = None;
        let mut evidence_expired_or_missing = false;
        if self.latest_local_guard["proxy"] == "fail" || self.latest_local_guard["tun"] == "fail" {
            risk_code = Some("proxy_or_tun_failed".into());
        } else if !local_guard_ok && had_active_or_permitted {
            risk_code = Some("local_guard_unverified".into());
            evidence_expired_or_missing = true;
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

        // Determine desired permit state without blocking on slow audits
        let (desired_state, reason_code) = if let Some(code) = risk_code {
            let action = if evidence_expired_or_missing {
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
                        "通道保护检测到环境或出口风险（或关键证据已过期），已撤销通道放行并保留进程",
                        true,
                    );
                    session = sessions.load(now)?;
                }
                if evidence_expired_or_missing {
                    let sid = session.as_ref().map(|s| s.session_id.clone());
                    self.request_async_audit_if_needed(family, sid, now);
                }
                (ChannelPermitState::Revoked, code)
            }
        } else if desktops.is_empty() {
            (ChannelPermitState::PendingVerification, "idle_no_process".into())
        } else if let Some(s) = session.as_ref() {
            if s.state == Phase::Active && !s.group_rechecking() {
                // If previously revoked, do NOT automatically transition back to
                // Permitted without fresh post-revocation recovery verification!
                let was_revoked = self
                    .tracks
                    .get(family)
                    .and_then(|t| t.current_permit.as_ref())
                    .is_some_and(|p| p.state == ChannelPermitState::Revoked);
                if was_revoked {
                    self.request_async_audit_if_needed(family, Some(s.session_id.clone()), now);
                    (
                        ChannelPermitState::Revoked,
                        "awaiting_recovery_verification".into(),
                    )
                } else if !local_guard_ok || !evidence_valid {
                    self.request_async_audit_if_needed(family, Some(s.session_id.clone()), now);
                    (
                        ChannelPermitState::Revoked,
                        "egress_evidence_expired".into(),
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
                if self.config.close_action(&code, provider) == "warn"
                    && local_guard_ok
                    && evidence_valid
                {
                    (ChannelPermitState::Permitted, code)
                } else {
                    self.request_async_audit_if_needed(family, Some(s.session_id.clone()), now);
                    (ChannelPermitState::Revoked, code)
                }
            } else {
                self.request_async_audit_if_needed(family, Some(s.session_id.clone()), now);
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
            self.request_async_audit_if_needed(family, None, now);
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

        self.issue_family_command(family, session.as_ref(), desired_state, &reason_code, now)
    }

    fn request_async_audit_if_needed(
        &mut self,
        family: &str,
        session_id: Option<String>,
        now: f64,
    ) {
        let Some(track) = self.tracks.get_mut(family) else {
            return;
        };
        if let Some(in_flight) = track.audit_in_flight.clone() {
            if in_flight.session_id != session_id
                || in_flight.policy_version != self.saved_policy_version
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
            session_id,
            policy_version: self.saved_policy_version.clone(),
            requested_at: now,
            timeout_seconds: DEFAULT_ASYNC_AUDIT_TIMEOUT_SECONDS,
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
    ) -> Result<()> {
        let Some(family_spec) = PolicyCatalog::family(family) else {
            return Ok(());
        };
        let sessions = SessionStore::for_family(self.storage.clone(), family_spec.id);
        let receipts_store = ReceiptStore {
            storage: self.storage.clone(),
        };
        let current_session = sessions.load(completed_at)?;
        let current_session_id = current_session.as_ref().map(|s| s.session_id.clone());

        // Logic Fix 4: Match `request_id` against `track.audit_in_flight` before
        // clearing `audit_in_flight` or applying the outcome.
        let (matched_in_flight, stale, timeout_limit) = {
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
            track.audit_in_flight = None;
            let risk_since_request = track
                .last_risk_at
                .is_some_and(|risk_at| risk_at >= requested_at);
            let is_stale = audit_policy != self.saved_policy_version
                || (audit_session_id.is_some() && audit_session_id != current_session_id)
                || risk_since_request;
            (true, is_stale, timeout_limit)
        };
        if !matched_in_flight || stale {
            return Ok(());
        }

        let (audit, egress) = match outcome {
            AsyncAuditOutcome::Succeeded { audit, egress } => {
                if timeout_limit > 0.0 && (completed_at - requested_at) >= timeout_limit {
                    return self.record_async_audit_failure(
                        family,
                        current_session.as_ref(),
                        "async_audit_timeout",
                        completed_at,
                    );
                }
                if let Some(track) = self.tracks.get_mut(family) {
                    track.audit_retry_count = 0;
                    track.audit_retry_not_before = None;
                    track.audit_last_failure_code = None;
                }
                if Egress::fresh(&egress, completed_at, session::GUARD_EGRESS_TTL).is_some() {
                    self.latest_egress = egress.clone();
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
                    completed_at,
                );
            }
            AsyncAuditOutcome::TimedOut { .. } => {
                return self.record_async_audit_failure(
                    family,
                    current_session.as_ref(),
                    "async_audit_timeout",
                    completed_at,
                );
            }
        };

        // Case 1: Recovering an existing revoked channel via `verify_channel_recovery`
        let was_revoked = self
            .tracks
            .get(family)
            .and_then(|t| t.current_permit.clone())
            .filter(|p| p.state == ChannelPermitState::Revoked);

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
            let audit_ready = audit["ready"] == true && audit["grants_launch_permission"] == true;
            let audit_observed_at = audit["observed_at"].as_f64().unwrap_or(completed_at);
            let context_id = audit["context_id"]
                .as_str()
                .or_else(|| previous_permit.context_id.as_deref())
                .unwrap_or("recovered-ctx");

            match verify_channel_recovery(
                &previous_permit,
                revoked_at,
                audit_session_id.as_deref(),
                audit_ready,
                audit_observed_at,
                &audit_policy,
                &egress,
                current_session_id.as_deref(),
                &self.saved_policy_version,
                context_id,
                next_gen,
                next_seq,
                completed_at,
                DEFAULT_PERMIT_TTL,
            ) {
                Ok(recovered_permit) => {
                    if let Some(s) = current_session.as_ref() {
                        if let Some(exit) =
                            Egress::fresh(&egress, completed_at, session::GUARD_EGRESS_TTL)
                        {
                            let mut restored = s.clone();
                            restored.state = Phase::Active;
                            restored.baseline = exit;
                            restored.reason = None;
                            let _ = self.storage.atomic_json(
                                &self.storage.paths.session_for(family),
                                &serde_json::to_value(&restored).unwrap_or(Value::Null),
                            );
                        }
                    }
                    self.apply_permit_to_enforcer(family, recovered_permit, completed_at)?;
                }
                Err(_) => {
                    // Keep channel revoked when recovery verification fails
                    let updated = sessions.load(completed_at)?;
                    self.issue_family_command(
                        family,
                        updated.as_ref(),
                        ChannelPermitState::Revoked,
                        "recovery_verification_failed",
                        completed_at,
                    )?;
                }
            }
            return Ok(());
        }

        // Case 2: Initial adoption of newly opened desktop(s)
        let desktops = self
            .tracks
            .get(family)
            .map(|t| t.desktops.clone())
            .unwrap_or_default();
        let mains: Vec<_> = desktops
            .iter()
            .filter(|(_, main, _)| *main)
            .map(|(d, _, _)| d.clone())
            .collect();
        if current_session.is_none() {
            if mains.len() == 1 {
                let desktop = &mains[0];
                if let Ok(pending) =
                    sessions.begin_verified(&receipts_store, &audit, &egress, completed_at)
                {
                    let id = pending.session_id.clone();
                    if sessions
                        .bind_desktop(&id, desktop.clone(), completed_at)
                        .is_ok()
                    {
                        let _ = sessions.mark_adopted(&id, completed_at);
                        let adopted_session = sessions.load(completed_at)?;
                        self.issue_family_command(
                            family,
                            adopted_session.as_ref(),
                            ChannelPermitState::Permitted,
                            "session_adopted",
                            completed_at,
                        )?;
                        return Ok(());
                    }
                }
                return self.record_async_audit_failure(
                    family,
                    None,
                    "initial_audit_rejected",
                    completed_at,
                );
            } else if mains.len() >= 2 && family == "openai" {
                if let Ok(Some(adopted_group)) = sessions.adopt_desktop_group(
                    &receipts_store,
                    &audit,
                    &egress,
                    mains,
                    &self.config,
                    completed_at,
                ) {
                    self.issue_family_command(
                        family,
                        Some(&adopted_group),
                        ChannelPermitState::Permitted,
                        "session_adopted",
                        completed_at,
                    )?;
                    return Ok(());
                }
                return self.record_async_audit_failure(
                    family,
                    None,
                    "initial_group_audit_rejected",
                    completed_at,
                );
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
        let members = match session {
            Some(s) => s.desktop_members()?,
            None => self
                .tracks
                .get(family)
                .map(|t| {
                    t.desktops
                        .iter()
                        .filter(|(_, main, _)| *main)
                        .map(|(d, _, _)| d.clone())
                        .collect()
                })
                .unwrap_or_default(),
        };
        let session_id = session.map(|s| s.session_id.clone());

        // Logic Fix 1: Cap `valid_until` by key evidence expiration time, and
        // refuse to issue `Permitted` if egress evidence has already expired!
        let (effective_desired_state, effective_reason, valid_until) =
            if desired_state == ChannelPermitState::Permitted {
                match Egress::fresh(&self.latest_egress, now, session::GUARD_EGRESS_TTL) {
                    Some(exit) if exit.observed_at + session::GUARD_EGRESS_TTL > now => {
                        let evidence_expires_at = exit.observed_at + session::GUARD_EGRESS_TTL;
                        (
                            ChannelPermitState::Permitted,
                            reason_code.to_string(),
                            (now + DEFAULT_PERMIT_TTL).min(evidence_expires_at),
                        )
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

        let (permit_generation, command_seq) = {
            let track = self
                .tracks
                .entry(family.into())
                .or_insert_with(FamilyRuntimeTrack::new);
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
            context_id: session
                .map(|s| s.context_id.clone())
                .filter(|s| !s.is_empty()),
            baseline_ip: session
                .map(|s| s.baseline.ip.clone())
                .filter(|s| !s.is_empty()),
            members,
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
            permit: permit.clone(),
            allowed_processes,
            upstream_endpoint: self.upstream_endpoint.clone(),
            issued_at: now,
        };
        if let Some(track) = self.tracks.get_mut(family) {
            track.session_id = permit.session_id.clone();
            track.permit_generation = permit.permit_generation;
            track.command_seq = permit.command_seq;
            track.current_permit = Some(permit);
        }
        if let Some(enforcer) = self.enforcer.clone() {
            match enforcer.apply_command(&command, now) {
                Ok(receipt) => {
                    self.ingest_receipt(receipt, now)?;
                    return Ok(());
                }
                Err(_) => {
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
        if accepted {
            self.refresh_verdict_and_emit(&family, receiver_now);
        }
        Ok(())
    }

    fn refresh_verdict_and_emit(&mut self, family: &str, now: f64) {
        let Some(track) = self.tracks.get_mut(family) else {
            return;
        };
        let Some(permit) = track.current_permit.as_ref() else {
            return;
        };
        let verdict = evaluate_channel_supervision_with_boot_id(
            permit,
            track.latest_receipt.as_ref(),
            &self.saved_policy_version,
            self.expected_executor_boot_id.as_deref(),
            now,
        );
        if matches!(verdict, ChannelSupervisionVerdict::EnforcementFailed { .. }) {
            track.policy_sync_state = PolicySyncState::ApplyFailed;
        }
        track.verdict = Some(verdict);
        let family_state = Self::build_family_monitor_state_from_track(
            &self.producer_boot_id,
            &self.saved_policy_version,
            family,
            track,
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
        Self::build_family_monitor_state_from_track(
            &self.producer_boot_id,
            &self.saved_policy_version,
            family,
            track,
            now,
        )
    }

    fn build_family_monitor_state_from_track(
        producer_boot_id: &str,
        saved_policy_version: &PolicyVersion,
        family: &str,
        track: &FamilyRuntimeTrack,
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
                )
            })
            .unwrap_or((0, 0, 0, false, false));

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
            process_preserved: true,
            active_member_pids,
            active_members: track.processes.clone(),
            local_proxy_ready,
            system_extension_active,
            active_flows_count,
            terminated_flows_count,
            blocked_new_connections,
            updated_at: now,
        }
    }
}
