//! Read-only policy application status from the supervisor's verified receipts.
//! Listener readiness and legacy guard heartbeats are not execution acknowledgements.
use crate::{channel_supervisor::ChannelSupervisor, storage::StateStore};
use claude_watch_core::{
    channel::{
        evaluate_channel_supervision_with_boot_id, ChannelEnforcementReceipt,
        ChannelEnforcementState, ChannelPermit, ChannelSupervisionVerdict, NetworkBackendKind,
        PolicySyncState, PolicyVersion, CLOCK_ROLLBACK_TOLERANCE_SECONDS,
        MAX_ENFORCEMENT_RECEIPT_AGE,
    },
    config::Config,
};
use claude_watch_system::ProcessKernelIdentity;
use serde_json::{json, Value};

pub const FRAME_PATH: &str = "state/channel-supervision.json";

pub fn read_frame(store: &StateStore) -> Value {
    store.read_json(&store.paths.watch().join(FRAME_PATH), Value::Null).unwrap_or(Value::Null)
}

/// One read of the authority frame at a fixed observation time. Each consumer
/// uses the same checked command and execution verdict for this frame.
pub struct FrameEvidence<'a> {
    pub(crate) value: &'a Value,
    pub(crate) config: &'a Config,
    pub(crate) now: f64,
    pub(crate) policy: claude_watch_core::error::Result<PolicyVersion>,
    pub(crate) boot: Option<&'a str>,
    pub(crate) families: Vec<FamilyEvidence<'a>>,
}

pub(crate) struct FamilyEvidence<'a> {
    pub(crate) family: &'a str,
    pub(crate) state: &'a Value,
    pub(crate) permit: Option<ChannelPermit>,
    pub(crate) receipt: Option<ChannelEnforcementReceipt>,
    verdict: Option<ChannelSupervisionVerdict>,
    pub(crate) sync: PolicySyncState,
}

impl<'a> FrameEvidence<'a> {
    pub fn new(value: &'a Value, config: &'a Config, now: f64) -> Self {
        Self::with_producer(value, config, now, producer_is_current)
    }

    pub(crate) fn with_producer(
        value: &'a Value, config: &'a Config, now: f64, producer_current: impl FnOnce(&Value) -> bool,
    ) -> Self {
        let policy = ChannelSupervisor::compute_policy_version(config);
        let version = json!(policy.as_ref().ok());
        let boot = value["executor_boot_id"].as_str().filter(|id| {
            !id.is_empty() && policy.is_ok() && value["saved_policy_version"] == version
                && value["producer_boot_id"].as_str().is_some_and(|id| !id.is_empty())
                && value["captured_at"].as_f64().is_some_and(|at| fresh(at, now))
                && producer_current(value)
        });
        let mut families = Vec::new();
        if let (Some(boot), Ok(policy), Some(rows)) = (boot, &policy, value["families"].as_object()) {
            let backend = config.effective_network_backend();
            for (family, state) in rows {
                if state["producer_boot_id"] != value["producer_boot_id"] || state["saved_policy_version"] != version {
                    continue;
                }
                let permit = serde_json::from_value::<ChannelPermit>(value["authoritative_permits"][family].clone()).ok()
                    .filter(|p| p.family == *family && p.policy_version == *policy && p.backend == backend
                        && state["command_seq"].as_u64() == Some(p.command_seq)
                        && state["permit_generation"].as_u64() == Some(p.permit_generation));
                let receipt = serde_json::from_value::<ChannelEnforcementReceipt>(value["enforcement_receipts"][family].clone()).ok();
                let verdict = permit.as_ref().map(|p|
                    evaluate_channel_supervision_with_boot_id(p, receipt.as_ref(), policy, Some(boot), now));
                // Status and readiness have a tighter receipt clock bound than
                // the executor evaluator. Foreign/stale receipts stay pending.
                let sync = match (&permit, &receipt, &verdict) {
                    (Some(_), None, _) if state["policy_sync_state"] == "apply_failed" => PolicySyncState::ApplyFailed,
                    (Some(p), Some(r), Some(verdict)) if r.family == *family && r.policy_version == *policy
                        && r.backend == backend && r.session_id == p.session_id && r.executor_boot_id == boot
                        && r.command_seq == p.command_seq && r.permit_generation == p.permit_generation
                        && fresh(r.observed_at, now) && r.observed_at + CLOCK_ROLLBACK_TOLERANCE_SECONDS >= p.issued_at => {
                        if r.enforcement_state == ChannelEnforcementState::Failed || state["policy_sync_state"] == "apply_failed"
                            || matches!(verdict, ChannelSupervisionVerdict::EnforcementFailed { .. }) {
                            PolicySyncState::ApplyFailed
                        } else if state["policy_sync_state"] == "applied" && state["applied_policy_version"] == version {
                            PolicySyncState::Applied
                        } else { PolicySyncState::PendingApply }
                    }
                    _ => PolicySyncState::PendingApply,
                };
                families.push(FamilyEvidence { family, state, permit, receipt, verdict, sync });
            }
        }
        Self { value, config, now, policy, boot, families }
    }

    pub(crate) fn family(&self, id: &str) -> Option<&FamilyEvidence<'a>> {
        self.families.iter().find(|evidence| evidence.family == id)
    }

    pub fn value(&self) -> &Value { self.value }

    pub fn policy_sync_state(&self) -> PolicySyncState {
        if self.families.iter().any(|f| f.sync == PolicySyncState::ApplyFailed) {
            PolicySyncState::ApplyFailed
        } else if !self.families.is_empty()
            && self.value["families"].as_object().is_some_and(|rows| rows.len() == self.families.len())
            && self.families.iter().all(|f| f.sync == PolicySyncState::Applied) {
            PolicySyncState::Applied
        } else { PolicySyncState::PendingApply }
    }

    pub fn guard_summary(&self) -> Value {
        use claude_watch_core::{channel::ChannelPermitState, policy::PolicyCatalog};
        if !self.config.enabled || !self.config.guard_enabled {
            return json!({"status":"disabled","action":"observe"});
        }
        let Ok(policy) = &self.policy else {
            return json!({"status":"unknown","action":"observe","code":"guard_policy_unverified"});
        };
        let frame = self.value;
        let rows = PolicyCatalog::families().iter().filter(|spec| PolicyCatalog::guard_target(spec).is_some()).map(|spec| {
            let family = spec.id;
            let pending = |code| json!({"family":family,"time":frame["captured_at"],"status":"unknown","action":"observe",
                "code":code,"session_guard":{"state":"pending_verification","reason":{"code":code}}});
            let Some(FamilyEvidence { state, permit: Some(permit), receipt, verdict: Some(verdict), .. }) = self.family(family) else {
                return pending("execution_evidence_stale_or_mismatched");
            };
            if receipt.is_none() && state["policy_sync_state"] != "apply_failed" {
                return pending("execution_not_confirmed");
            }
            let missing_sample = matches!(permit.reason_code.as_str(), "vpn_observation_unknown" | "vpn_observation_stale"
                | "egress_evidence_expired" | "channel_inventory_incomplete" | "permit_lease_expired"
                | "authority_evidence_unavailable");
            let (status, guard_state, execution_state) = match &verdict {
                ChannelSupervisionVerdict::ForwardingVerified => ("ok", "safe", "forwarding"),
                ChannelSupervisionVerdict::PendingVerification { .. } if permit.reason_code == "idle_no_process" => ("ok", "idle", "pending_verification"),
                ChannelSupervisionVerdict::IsolatedKeepProcess if missing_sample => ("unknown", "pending_verification", "blocked"),
                ChannelSupervisionVerdict::IsolatedKeepProcess => ("protection_triggered", "locked", "blocked"),
                ChannelSupervisionVerdict::PendingIsolation { .. } => ("pending", "pending_verification", "disconnecting"),
                ChannelSupervisionVerdict::PendingVerification { .. } => ("pending", "pending_verification", "pending_verification"),
                ChannelSupervisionVerdict::EnforcementFailed { code, .. } if code == "enforcement_receipt_expired" =>
                    ("pending", "pending_verification", "pending_verification"),
                ChannelSupervisionVerdict::EnforcementFailed { .. } => ("protection_unavailable", "unknown", "failed"),
            };
            let process_state = state["process_execution_state"].as_str();
            let action = match process_state {
                Some("partially_terminated") => "disconnect-and-partial-force-quit",
                Some("confirmed" | "already_exited") if state["process_preserved"] == false => "disconnect-and-force-quit",
                _ if permit.state == ChannelPermitState::Revoked => "disconnect-channel",
                _ => "observe",
            };
            json!({"family":family,"session_id":permit.session_id,"time":frame["captured_at"],
                "status":status,"action":action,"policy":policy.policy_digest,"guard_policy_v1":policy.guard_policy_digest,
                "channel_permit":permit,"channel_receipt":receipt,"channel_supervision":verdict,
                "channel_state":execution_state,"channel_execution_state":execution_state,
                "channel_status_label":verdict.display_state().label_zh(),
                "process_execution_state":process_state,"process_preserved":state["process_preserved"],
                "process_disposition_receipt":state["process_disposition_receipt"],
                "session_guard":{"state":guard_state,"current":frame["egress"][family],
                    "reason":{"code":permit.reason_code,"detail":verdict.display_state().label_zh()}}})
        }).collect();
        fold_guard_receipts(rows)
    }
}

pub fn guard_summary(value: &Value, config: &Config, now: f64) -> Value {
    FrameEvidence::new(value, config, now).guard_summary()
}

pub fn read_guard_summary(store: &StateStore, now: f64) -> Value {
    match (crate::config_store::ConfigStore { storage: store.clone() }).load() {
        Ok(config) => guard_summary(&read_frame(store), &config, now),
        Err(error) => json!({"status":"unknown","action":"observe","code":error.code}),
    }
}

fn identity_value(identity: &ProcessKernelIdentity) -> Value {
    json!({"pid": identity.pid, "uid": identity.uid,
        "start_seconds": identity.start_seconds, "start_microseconds": identity.start_microseconds,
        "executable_path": identity.executable_path, "audit_token": identity.audit_token})
}

pub(crate) fn producer_is_current(value: &Value) -> bool {
    let producer = &value["producer_identity"];
    producer["pid"].as_u64().and_then(|pid| u32::try_from(pid).ok())
        .and_then(claude_watch_system::inspect_process_identity).as_ref().is_some_and(|identity|
            identity.uid == claude_watch_system::effective_uid() && identity_value(identity) == *producer)
}

/// Read-only explanation. It never grants a permit or changes registry state.
pub(crate) fn process_protection(
    store: &StateStore, frame: Option<&FrameEvidence<'_>>, identity: &claude_watch_core::processes::Identity,
    kind: claude_watch_core::processes::Kind, now: f64,
) -> Value {
    use claude_watch_core::{controlled_launch::{ManagedInstanceState, ManagedLaunchInstance}, policy::PolicyCatalog};
    let mut result = json!({"state":"unknown","reason_code":"protection_evidence_unavailable","observed_at":now});
    let Some(live) = claude_watch_system::inspect_process_identity(identity.pid).filter(|live|
        live.uid == identity.uid && live.start_seconds == identity.start_seconds
            && live.start_microseconds == identity.start_microseconds && live.executable_path == identity.executable) else {
        result["reason_code"] = json!("current_process_identity_unverified"); return result;
    };
    let Some(frame) = frame else { return result; };
    let Ok(policy) = &frame.policy else { return result; };
    let Some(family) = PolicyCatalog::family_for(kind.provider()).map(|f| f.id) else { return result; };
    let (Some(boot), Some(evidence)) = (frame.boot, frame.family(family)) else {
        result["reason_code"] = json!("authority_stale_or_mismatched"); return result;
    };
    let value = frame.value;
    let state = evidence.state;
    result["producer_boot_id"] = value["producer_boot_id"].clone();
    result["executor_boot_id"] = json!(boot);
    result["policy_version"] = json!(policy);
    let raw_instances = store.read_json(&store.paths.watch().join("state/managed-launch-instances.json"), Value::Null).unwrap_or(Value::Null);
    let instances = serde_json::from_value::<Vec<ManagedLaunchInstance>>(raw_instances.clone()).ok();
    let Some(instances) = instances else { result["reason_code"] = json!("registry_evidence_unavailable"); return result; };
    let instance = instances.iter().find(|inst| inst.uid == identity.uid &&
        ((inst.pid == identity.pid && inst.start_seconds == identity.start_seconds && inst.start_microseconds == identity.start_microseconds)
            || inst.controlled_subtree_pids.contains(&identity.pid)));
    let Some(inst) = instance else {
        let digest = claude_watch_system::sha256_bytes_hex(live.audit_token.iter().map(u32::to_string).collect::<Vec<_>>().join(":").as_bytes());
        let known_failed_member = raw_instances.as_array().into_iter().flatten().any(|instance|
            instance["executor_boot_id"] == boot && instance["process_visibility"]["observed_at"].as_f64().is_some_and(|at| fresh(at, now))
                && instance["process_visibility"]["members"].as_array().into_iter().flatten().any(|member|
                    member["pid"] == live.pid && member["uid"] == live.uid && member["start_seconds"] == live.start_seconds
                        && member["start_microseconds"] == live.start_microseconds && member["audit_identity_digest"] == digest));
        result["state"] = json!("unprotected");
        result["reason_code"] = json!(if known_failed_member { "member_identity_or_file_evidence_changed" } else { "external_unmanaged_process" }); return result;
    };
    if inst.state == ManagedInstanceState::Failed {
        result["state"] = json!("unprotected");
        result["reason_code"] = json!(inst.error_code.as_deref().unwrap_or("instance_verification_failed")); return result;
    }
    result["state"] = json!("pending_verification");
    let main = inst.pid == identity.pid;
    let sandbox_valid = if main { inst.has_verified_main_protection(boot, policy) }
        else { inst.has_verified_subtree_protection(boot, policy) };
    if !sandbox_valid || !fresh(inst.updated_at, now) {
        result["reason_code"] = json!("sandbox_identity_pending_or_stale"); return result;
    }
    let matched_token = |token: &claude_watch_core::channel::BoundProcessToken|
        token.pid == live.pid && token.uid == live.uid && token.start_seconds == live.start_seconds
            && token.start_microseconds == live.start_microseconds && token.audit_token == Some(live.audit_token);
    let members: Vec<claude_watch_core::channel::BoundProcessToken> = serde_json::from_value(state["active_members"].clone()).unwrap_or_default();
    if !members.iter().any(matched_token) {
        result["reason_code"] = json!("current_member_token_unverified"); return result;
    }
    let audit_identity = live.audit_token.iter().map(u32::to_string).collect::<Vec<_>>().join(":");
    result["audit_identity_digest"] = json!(claude_watch_system::sha256_bytes_hex(audit_identity.as_bytes()));
    let raw_scope = &state["coverage_scope"];
    let scope = serde_json::from_value::<claude_watch_core::channel::BackendCoverageScope>(raw_scope.clone()).ok();
    let complete_scope = ["configured_entries", "protected_pids", "unprotected_pids", "uncovered_boundaries"].iter()
        .all(|key| raw_scope[key].is_array()) && raw_scope["server_identity_verified"].is_boolean();
    if !complete_scope || !scope.as_ref().is_some_and(|scope| scope.backend == NetworkBackendKind::Seatbelt
        && !scope.configured_entries.is_empty() && scope.protected_pids.contains(&identity.pid) && !scope.unprotected_pids.contains(&identity.pid)) {
        result["reason_code"] = json!("coverage_evidence_unverified"); return result;
    }
    let scope = scope.unwrap();
    if !(scope.server_identity_verified || (scope.gateway_endpoint_protection_verified
        && scope.gateway_endpoint_protection_method.as_ref().is_some_and(|s| !s.is_empty()))) {
        result["reason_code"] = json!("gateway_endpoint_proof_missing"); return result;
    }
    let Some(receipt) = &evidence.receipt else { result["reason_code"] = json!("execution_receipt_missing"); return result; };
    let (Some(permit), Some(verdict)) = (&evidence.permit, &evidence.verdict) else {
        result["reason_code"] = json!("current_permit_identity_or_epoch_unverified"); return result;
    };
    if state["vpn_epoch"] != json!(permit.vpn_epoch)
        || (permit.state == claude_watch_core::channel::ChannelPermitState::Permitted && permit.vpn_epoch.is_none()) {
        result["reason_code"] = json!("current_permit_identity_or_epoch_unverified"); return result;
    }
    if state["policy_sync_state"] != "applied" || state["applied_policy_version"] != json!(policy) {
        if state["policy_sync_state"] == "apply_failed" { result["state"] = json!("unprotected"); }
        result["reason_code"] = json!(if state["policy_sync_state"] == "apply_failed" { "execution_failed" } else { "pending_apply" }); return result;
    }
    result["command_seq"] = json!(permit.command_seq);
    result["permit_generation"] = json!(permit.permit_generation);
    result["vpn_epoch"] = json!(permit.vpn_epoch);
    match verdict {
        ChannelSupervisionVerdict::ForwardingVerified | ChannelSupervisionVerdict::IsolatedKeepProcess => {
            // A revoke is not renewed like a forwarding lease. Its confirmed
            // cutoff remains current only while the same identity and actual
            // execution/registry evidence are fresh, independent of that lease.
            let mut deadline = (receipt.observed_at + MAX_ENFORCEMENT_RECEIPT_AGE).min(inst.updated_at + MAX_ENFORCEMENT_RECEIPT_AGE);
            if matches!(verdict, ChannelSupervisionVerdict::ForwardingVerified) {
                let vpn = &value["vpn_supervision"];
                let observation = serde_json::from_value::<claude_watch_core::vpn::VpnObservation>(vpn["observation"].clone()).ok();
                let matched = observation.as_ref().is_some_and(|observation| {
                    vpn["captured_at"] == value["captured_at"] && permit.vpn_epoch.as_ref() == Some(&observation.epoch)
                        && frame.config.vpn_expectation.as_ref().is_some_and(|expected|
                            matches!(claude_watch_core::vpn::compare_vpn(expected, observation, now), claude_watch_core::vpn::VpnMatch::Matched))
                });
                if !matched { result["reason_code"] = json!("current_vpn_path_evidence_unverified"); return result; }
                deadline = deadline.min(permit.valid_until).min(observation.unwrap().valid_until);
            }
            result["state"] = json!("protected");
            result["reason_code"] = json!(if matches!(verdict, ChannelSupervisionVerdict::ForwardingVerified) { "forwarding_verified" } else { "blocked_verified" });
            result["valid_until"] = json!(deadline);
        }
        ChannelSupervisionVerdict::EnforcementFailed { code, .. } => {
            result["state"] = json!("unprotected"); result["reason_code"] = json!(code);
        }
        _ => { result["reason_code"] = json!("execution_pending"); }
    }
    result
}

pub(crate) fn current_producer_identity() -> Value {
    claude_watch_system::inspect_process_identity(std::process::id())
        .as_ref()
        .map(identity_value)
        .unwrap_or(Value::Null)
}

/// Missing, stale or inconsistent evidence always remains pending. A matched
/// failure receipt is reported separately from both pending and applied.
pub fn read_policy_sync_state(store: &StateStore, config: &Config, now: f64) -> PolicySyncState {
    FrameEvidence::new(&read_frame(store), config, now).policy_sync_state()
}

pub(crate) fn fresh(at: f64, now: f64) -> bool {
    at.is_finite()
        && now.is_finite()
        && at <= now + CLOCK_ROLLBACK_TOLERANCE_SECONDS
        && now - at < MAX_ENFORCEMENT_RECEIPT_AGE
}

/// Fold one receipt per supervised family into a single heartbeat. The top
/// level carries the most severe family's receipt verbatim so the existing UI
/// and diagnostics keep reading the fields they know (`status`, `action`,
/// `stop_state`, `session_guard`, `session_id`), while the `families` array
/// keeps every family's full receipt. Adding a service is a new entry in the
/// policy table; nothing here needs to know about it.
fn fold_guard_receipts(receipts: Vec<Value>) -> Value {
    let severity = |status: &str| -> u8 {
        match status {
            "protection_unavailable" => 6,
            "protection_triggered" => 5,
            "unknown" => 4,
            "degraded" | "pending" => 3,
            "ok" => 2,
            "disabled" => 1,
            _ => 0,
        }
    };
    let rank = |receipt: &Value| -> (u8, u8) {
        // A family that actually closed or disconnected outranks one that only reported.
        let acted = u8::from(matches!(
            receipt["action"].as_str(),
            Some("close-desktop" | "disconnect-channel" | "disconnect-and-force-quit")
        ));
        (severity(receipt["status"].as_str().unwrap_or("")), acted)
    };
    let mut primary: Option<Value> = None;
    for receipt in &receipts {
        let take = primary
            .as_ref()
            .is_none_or(|current| rank(receipt) > rank(current));
        if take {
            primary = Some(receipt.clone());
        }
    }
    let mut folded = primary.unwrap_or_else(|| {
        serde_json::json!({"status":"disabled","action":"observe"})
    });
    folded["families"] = serde_json::json!(receipts);
    folded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use claude_watch_core::{channel::BoundProcessToken, controlled_launch::{ManagedInstanceState, ManagedLaunchInstance, SandboxLaunchEvidence}, processes::{Identity, Kind, ProcessRole}};

    fn process_fixture() -> (StateStore, Config, Identity, Value, ManagedLaunchInstance, f64) {
        use crate::{config_store::ConfigStore, storage::Paths};
        let root = std::env::temp_dir().join(format!("cw-process-proof-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        let mut cfg = Config::default_for_new_install(); cfg.proxy_url = "http://127.0.0.1:17890".into(); cfg.proxy_mode = "clash-verge".into();
        let mut expected = claude_watch_core::vpn::VpnExpectation::unconfigured();
        expected.configured = true; expected.proxy_url = cfg.proxy_url.clone(); expected.proxy_mode = "clash-verge".into();
        cfg.vpn_expectation = Some(expected);
        let config = ConfigStore { storage:store.clone() }.save(cfg.value().unwrap()).unwrap();
        let policy = ChannelSupervisor::compute_policy_version(&config).unwrap();
        let live = claude_watch_system::inspect_process_identity(std::process::id()).unwrap();
        let identity = Identity { pid:live.pid, parent:1, uid:live.uid, executable:live.executable_path.clone(),
            start_seconds:live.start_seconds, start_microseconds:live.start_microseconds, start_stamp:"owned-test".into() };
        let token = BoundProcessToken::with_system_identity(live.pid, live.uid, live.start_seconds, live.start_microseconds, ProcessRole::Cli).with_audit_token(live.audit_token);
        let now = crate::native::now(); let (mut value, _) = fixture();
        value["producer_identity"] = current_producer_identity(); value["captured_at"] = json!(now); value["saved_policy_version"] = json!(policy);
        let scope = json!({"backend":"seatbelt","configured_entries":["unit-fixture"],"protected_pids":[live.pid],"unprotected_pids":[],
            "uncovered_boundaries":[],"server_identity_verified":false,"gateway_endpoint_protection_verified":true,"gateway_endpoint_protection_method":"unit-fixture-only"});
        let epoch = json!({"observer_boot_id":"vpn-fixture", "change_generation":1});
        let state = &mut value["families"]["claude"];
        state["saved_policy_version"] = json!(policy); state["applied_policy_version"] = json!(policy);
        state["active_members"] = json!([token.clone()]); state["coverage_scope"] = scope.clone(); state["vpn_epoch"] = epoch.clone();
        let permit = &mut value["authoritative_permits"]["claude"];
        permit["policy_version"] = json!(policy); permit["issued_at"] = json!(now-0.1); permit["valid_until"] = json!(now+30.0);
        permit["vpn_epoch"] = epoch.clone(); permit["coverage_scope"] = scope;
        let receipt = &mut value["enforcement_receipts"]["claude"];
        receipt["policy_version"] = json!(policy); receipt["observed_at"] = json!(now); receipt["vpn_epoch"] = epoch;
        // Synthetic sandbox/endpoint facts exercise projection gates only. This
        // unit does not establish that the test process is sandboxed or I03 works.
        let instance = ManagedLaunchInstance { instance_id:"owned-unit".into(), entry_id:"unit".into(), family:"claude".into(),
            target:claude_watch_core::processes::LaunchTarget::ClaudeCli, launch_nonce:"unit".into(), executor_boot_id:"executor-1".into(),
            helper_identity:Some(token.clone()), expected_executable:identity.executable.clone(), expected_fingerprint:"unit".into(), exec_identity:Some(token.clone()),
            verified_executable:Some(identity.executable.clone()), pid:live.pid, uid:live.uid, start_seconds:live.start_seconds, start_microseconds:live.start_microseconds,
            controlled_subtree_pids:vec![], state:ManagedInstanceState::ExecVerified,
            sandbox_evidence:Some(SandboxLaunchEvidence { applied:true, backend:NetworkBackendKind::Seatbelt, policy_version:policy.clone(),
                allowed_gateway_endpoint:"127.0.0.1:1021".into(), direct_network_blocked:true, unix_relay_blocked:true, verified_helper_origin:true,
                helper_cdhash:"unit-fixture".into(), helper_identity:token, executor_boot_id:"executor-1".into(), applied_at:now-1.0 }),
            updated_at:now, error_code:None, script_entry:None, script_fingerprint:None };
        let registry_path = store.paths.watch().join("state/managed-launch-instances.json");
        store.atomic_json(&registry_path, &json!([instance])).unwrap();
        (store, config, identity, value, instance, now)
    }

    #[test]
    fn process_protection_requires_current_token_registry_boot_policy_and_receipt() {
        let (store, config, identity, value, instance, now) = process_fixture();
        let root = store.paths.home.clone();
        let registry_path = store.paths.watch().join("state/managed-launch-instances.json");
        let live = claude_watch_system::inspect_process_identity(identity.pid).unwrap();
        let project = |v: &Value, i: &Identity, at|
            process_protection(&store, Some(&FrameEvidence::new(v, &config, at)), i, Kind::ClaudeCode, at);
        assert_eq!(project(&value, &identity, now)["state"], "protected");
        assert_eq!(project(&value, &identity, now)["reason_code"], "blocked_verified");
        let mut forward = value.clone();
        forward["authoritative_permits"]["claude"]["state"] = json!("permitted");
        forward["enforcement_receipts"]["claude"]["permit_state"] = json!("permitted");
        forward["enforcement_receipts"]["claude"]["enforcement_state"] = json!("forwarding");
        assert_eq!(project(&forward, &identity, now)["reason_code"], "current_vpn_path_evidence_unverified");
        use claude_watch_core::vpn::{ObservationConsistency, ObservedField, UpstreamProtocol, VpnEpoch, VpnObservation};
        let observation = VpnObservation { source:"clash-verge".into(), source_instance:Some("unit-instance".into()), source_revision:Some("unit-rev".into()),
            upstream_endpoint:Some(config.proxy_url.clone()), upstream_protocol:ObservedField::Known(UpstreamProtocol::MixedHttp),
            running_mode:ObservedField::Known("rule".into()), tun_enabled:ObservedField::Known(false), system_proxy_enabled:ObservedField::Known(false),
            selected_group:ObservedField::Unknown("not_required".into()), selected_node:ObservedField::Unknown("not_required".into()),
            proxy_chain:ObservedField::Unknown("not_required".into()), rules_digest:ObservedField::Unknown("not_required".into()),
            sample_started_at:now, observed_at:now, valid_until:now+3.5, consistency:ObservationConsistency::RevisionVerified, source_error:None,
            sample_seq:1, epoch:VpnEpoch::new("vpn-fixture",1) };
        let vpn = json!({"captured_at":now,"observation":observation}); forward["vpn_supervision"] = vpn.clone();
        assert_eq!(project(&forward, &identity, now)["reason_code"], "forwarding_verified");
        assert_eq!(project(&forward, &identity, now)["valid_until"], json!(now+3.5));
        let mut stale_vpn = vpn.clone(); stale_vpn["observation"]["epoch"]["change_generation"] = json!(2);
        forward["vpn_supervision"] = stale_vpn;
        assert_eq!(project(&forward, &identity, now)["reason_code"], "current_vpn_path_evidence_unverified");
        stale_vpn = vpn.clone(); stale_vpn["observation"]["upstream_endpoint"] = json!("http://127.0.0.1:17891");
        forward["vpn_supervision"] = stale_vpn;
        assert_eq!(project(&forward, &identity, now)["reason_code"], "current_vpn_path_evidence_unverified");
        forward["vpn_supervision"] = vpn;
        assert_eq!(project(&forward, &identity, now+3.5)["reason_code"], "current_vpn_path_evidence_unverified");
        for pointer in ["/executor_boot_id", "/producer_boot_id", "/saved_policy_version/policy_digest",
            "/enforcement_receipts/claude/executor_boot_id", "/enforcement_receipts/claude/policy_version/policy_digest"] {
            let mut stale = value.clone(); *stale.pointer_mut(pointer).unwrap() = json!("old");
            assert_ne!(project(&stale, &identity, now)["state"], "protected", "{pointer}");
        }
        for pointer in ["/families/claude/active_members/0/start_seconds", "/families/claude/active_members/0/audit_token/7",
            "/enforcement_receipts/claude/command_seq", "/families/claude/vpn_epoch/change_generation"] {
            let mut stale = value.clone(); *stale.pointer_mut(pointer).unwrap() = json!(123456789);
            assert_ne!(project(&stale, &identity, now)["state"], "protected", "{pointer}");
        }
        assert_ne!(project(&value, &identity, now+11.0)["state"], "protected");
        let mut reused = identity.clone(); reused.start_microseconds += 1;
        assert_ne!(project(&value, &reused, now)["state"], "protected");
        let mut no_endpoint = value.clone(); no_endpoint["families"]["claude"]["coverage_scope"]["gateway_endpoint_protection_verified"] = json!(false);
        assert_eq!(project(&no_endpoint, &identity, now)["reason_code"], "gateway_endpoint_proof_missing");
        let mut pending = value.clone(); pending["families"]["claude"]["policy_sync_state"] = json!("pending_apply");
        assert_eq!(project(&pending, &identity, now)["reason_code"], "pending_apply");
        pending["families"]["claude"]["policy_sync_state"] = json!("apply_failed");
        assert_eq!(project(&pending, &identity, now)["reason_code"], "execution_failed");
        let mut former_child = json!(instance);
        former_child["pid"] = json!(live.pid + 1000);
        former_child["controlled_subtree_pids"] = json!([]);
        let audit = live.audit_token.iter().map(u32::to_string).collect::<Vec<_>>().join(":");
        former_child["process_visibility"] = json!({"observed_at":now,"members":[{"pid":live.pid,"uid":live.uid,
            "start_seconds":live.start_seconds,"start_microseconds":live.start_microseconds,
            "audit_identity_digest":claude_watch_system::sha256_bytes_hex(audit.as_bytes()),"currently_verified":false}]});
        store.atomic_json(&registry_path, &json!([former_child])).unwrap();
        assert_eq!(project(&value, &identity, now)["reason_code"], "member_identity_or_file_evidence_changed");
        store.atomic_json(&registry_path, &json!([])).unwrap();
        assert_eq!(project(&value, &identity, now)["reason_code"], "external_unmanaged_process");
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn process_protection_separates_block_receipt_freshness_from_forwarding_lease() {
        use claude_watch_core::{channel::FamilyChannelMonitorState, processes::Target};
        let (store, config, identity, mut blocked, instance, now) = process_fixture();
        let registry_path = store.paths.watch().join("state/managed-launch-instances.json");
        // The same revoke command remains in force for a minute. Only the
        // executor/registry observations refresh; no revoke renewal is faked.
        blocked["authoritative_permits"]["claude"]["issued_at"] = json!(now - 60.0);
        blocked["authoritative_permits"]["claude"]["valid_until"] = json!(now - 50.0);
        blocked["enforcement_receipts"]["claude"]["observed_at"] = json!(now - 2.0);
        let mut cases = Vec::new();
        let mut record = |name: &str, authority: &Value, id: &Identity, inst: &ManagedLaunchInstance, at: f64, expected: &str| {
            store.atomic_json(&registry_path, &json!([inst])).unwrap();
            let proof = process_protection(&store, Some(&FrameEvidence::new(authority, &config, at)), id, Kind::ClaudeCode, at);
            let permit: ChannelPermit = serde_json::from_value(authority["authoritative_permits"]["claude"].clone()).unwrap();
            let receipt: ChannelEnforcementReceipt = serde_json::from_value(authority["enforcement_receipts"]["claude"].clone()).unwrap();
            let saved: PolicyVersion = serde_json::from_value(authority["saved_policy_version"].clone()).unwrap();
            let state = &authority["families"]["claude"];
            let display = evaluate_channel_supervision_with_boot_id(&permit, Some(&receipt), &saved,
                authority["executor_boot_id"].as_str(), at).display_state();
            let family = FamilyChannelMonitorState {
                producer_boot_id: state["producer_boot_id"].as_str().unwrap().into(), family: "claude".into(), session_id: permit.session_id.clone(),
                saved_policy_version: serde_json::from_value(state["saved_policy_version"].clone()).unwrap(),
                applied_policy_version: serde_json::from_value(state["applied_policy_version"].clone()).unwrap(),
                policy_sync_state: PolicySyncState::Applied, policy_sync_label_zh: "已应用".into(),
                permit_generation: permit.permit_generation, command_seq: permit.command_seq, permit_state: permit.state,
                display_state: display, display_label_zh: display.label_zh().into(), reason_code: permit.reason_code.clone(), process_preserved: true,
                process_execution_state: None, process_disposition_action: None, process_disposition_receipt: None,
                previous_process_disposition_receipts: Vec::new(),
                active_member_pids: vec![identity.pid], active_members: serde_json::from_value(state["active_members"].clone()).unwrap(),
                local_proxy_ready: receipt.local_proxy_ready, system_extension_active: false,
                active_flows_count: receipt.active_flows_count, terminated_flows_count: receipt.terminated_flows_count,
                blocked_new_connections: receipt.blocked_new_connections, local_proxy_port: None, valid_until: Some(permit.valid_until), updated_at: at,
                backend: permit.backend, vpn_epoch: permit.vpn_epoch.clone(), vpn_match: None,
                coverage_scope: serde_json::from_value(state["coverage_scope"].clone()).unwrap(), unmanaged_member_pids: vec![], sandbox_ready: true,
            };
            let round = crate::sampler::ProcessRound {
                id: "deadline-unit".into(), uid: id.uid, targets: vec![Target { identity: id.clone(), kind: Kind::ClaudeCode }],
                identities: [(id.pid, id.clone())].into(), roles: json!({}), match_evidence: Default::default(),
                unavailable: vec![], diagnostic_reasons: Default::default(), confirmed_exited_count: 0, complete: true, observed_at: at, discovery:None,
            };
            let mut row = crate::monitor_snapshot::process_rows(&round, &[]).remove(0);
            row["protection"] = proof;
            cases.push(json!({"name":name,"now":at,"expected":expected,"process":row,"family":family,
                "executor_boot_id":authority["executor_boot_id"],"receipt_observed_at":receipt.observed_at}));
        };
        record("expired_revoke_fresh_receipt", &blocked, &identity, &instance, now, "blocked_verified");
        let mut refreshed = blocked.clone();
        refreshed["captured_at"] = json!(now + 20.0);
        refreshed["enforcement_receipts"]["claude"]["observed_at"] = json!(now + 20.0);
        let mut refreshed_instance = instance.clone(); refreshed_instance.updated_at = now + 20.0;
        record("same_revoke_new_receipt", &refreshed, &identity, &refreshed_instance, now + 20.0, "blocked_verified");
        for (name, pointer, replacement) in [
            ("expired_receipt", "/enforcement_receipts/claude/observed_at", json!(now - MAX_ENFORCEMENT_RECEIPT_AGE)),
            ("receipt_boot_mismatch", "/enforcement_receipts/claude/executor_boot_id", json!("old")),
            ("executor_boot_mismatch", "/executor_boot_id", json!("old")),
            ("producer_boot_mismatch", "/producer_boot_id", json!("old")),
            ("policy_mismatch", "/enforcement_receipts/claude/policy_version/policy_digest", json!("old")),
            ("member_identity_mismatch", "/families/claude/active_members/0/start_seconds", json!(identity.start_seconds + 1)),
            ("member_audit_mismatch", "/families/claude/active_members/0/audit_token/7", json!(u32::MAX)),
            ("new_connections_not_blocked", "/enforcement_receipts/claude/new_connections_blocked", json!(false)),
            ("flows_not_closed", "/enforcement_receipts/claude/active_flows_closed", json!(false)),
            ("active_flow_remains", "/enforcement_receipts/claude/active_flows_count", json!(1)),
            ("direct_fallback_not_blocked", "/enforcement_receipts/claude/direct_fallback_blocked", json!(false)),
            ("receipt_sequence_mismatch", "/enforcement_receipts/claude/command_seq", json!(2)),
            ("receipt_epoch_mismatch", "/enforcement_receipts/claude/vpn_epoch/change_generation", json!(2)),
        ] {
            let mut invalid = blocked.clone(); *invalid.pointer_mut(pointer).unwrap() = replacement;
            record(name, &invalid, &identity, &instance, now, "unconfirmed");
        }
        let mut old_instance = instance.clone(); old_instance.updated_at = now - MAX_ENFORCEMENT_RECEIPT_AGE;
        record("registry_expired", &blocked, &identity, &old_instance, now, "unconfirmed");
        let mut reused = identity.clone(); reused.start_microseconds += 1;
        record("process_birth_mismatch", &blocked, &reused, &instance, now, "unconfirmed");
        let mut forward = blocked.clone();
        forward["authoritative_permits"]["claude"]["state"] = json!("permitted");
        forward["authoritative_permits"]["claude"]["valid_until"] = json!(now + 2.0);
        forward["enforcement_receipts"]["claude"]["permit_state"] = json!("permitted");
        forward["enforcement_receipts"]["claude"]["enforcement_state"] = json!("forwarding");
        use claude_watch_core::vpn::{ObservationConsistency, ObservedField, UpstreamProtocol, VpnEpoch, VpnObservation};
        let observation = VpnObservation {
            source: "clash-verge".into(), source_instance: Some("unit".into()), source_revision: Some("unit".into()),
            upstream_endpoint: Some(config.proxy_url.clone()), upstream_protocol: ObservedField::Known(UpstreamProtocol::MixedHttp),
            running_mode: ObservedField::Known("rule".into()), tun_enabled: ObservedField::Known(false), system_proxy_enabled: ObservedField::Known(false),
            selected_group: ObservedField::Unknown("not_required".into()), selected_node: ObservedField::Unknown("not_required".into()),
            proxy_chain: ObservedField::Unknown("not_required".into()), rules_digest: ObservedField::Unknown("not_required".into()),
            sample_started_at: now, observed_at: now, valid_until: now + 3.5, consistency: ObservationConsistency::RevisionVerified,
            source_error: None, sample_seq: 1, epoch: VpnEpoch::new("vpn-fixture", 1),
        };
        forward["vpn_supervision"] = json!({"captured_at":now,"observation":observation});
        record("current_forwarding_lease", &forward, &identity, &instance, now, "forwarding_verified");
        record("forwarding_lease_at_expiry", &forward, &identity, &instance, now + 2.0, "unconfirmed");
        forward["authoritative_permits"]["claude"]["valid_until"] = json!(now - 0.5);
        record("expired_forwarding_lease", &forward, &identity, &instance, now, "unconfirmed");
        let wire = json!({"evidence_boundary":"state projection with synthetic sandbox/endpoint/receipt facts, not OS protection acceptance","cases":cases});
        if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
            fs::create_dir_all(&dir).unwrap();
            let path = std::path::Path::new(&dir).join("process-protection-deadlines.json");
            fs::write(&path, serde_json::to_vec_pretty(&wire).unwrap()).unwrap();
            println!("production process protection wire: {}", path.display());
        }
        for case in wire["cases"].as_array().unwrap() {
            let proof = &case["process"]["protection"];
            if case["expected"] == "unconfirmed" {
                assert_ne!(proof["state"], "protected", "{}", case["name"]);
            } else {
                assert_eq!(proof["state"], "protected", "{}", case["name"]);
                assert_eq!(proof["reason_code"], case["expected"], "{}", case["name"]);
                assert!(proof["valid_until"].as_f64().unwrap() > case["now"].as_f64().unwrap(), "{} must have current evidence", case["name"]);
            }
        }
        let first = &wire["cases"][0];
        assert_eq!(first["process"]["protection"]["valid_until"], json!(now - 2.0 + MAX_ENFORCEMENT_RECEIPT_AGE));
        fs::remove_dir_all(&store.paths.home).unwrap();
    }

    fn fixture() -> (Value, Config) {
        let config = Config::default_for_new_install();
        let policy = ChannelSupervisor::compute_policy_version(&config).unwrap();
        let permit = json!({"family":"claude", "session_id":"s", "policy_version":policy,
            "permit_generation":2, "command_seq":3, "state":"revoked", "reason_code":"risk",
            "issued_at":100.0, "valid_until":130.0, "context_id":null,"baseline_ip":null,
            "members":[],"backend":"seatbelt"});
        let receipt = json!({"family":"claude","session_id":"s","policy_version":policy,
            "permit_generation":2,"command_seq":3,"executor_boot_id":"executor-1",
            "permit_state":"revoked","enforcement_state":"blocked","interception_active":true,
            "local_proxy_ready":true,"new_connections_blocked":true,"active_flows_closed":true,
            "direct_fallback_blocked":true,"active_flows_count":0,"terminated_flows_count":1,
            "blocked_new_connections":1,"observed_at":101.0,"backend":"seatbelt","sandbox_ready":true});
        (
            json!({"producer_boot_id":"producer-1","captured_at":102.0,"executor_boot_id":"executor-1",
            "saved_policy_version":policy,"authoritative_permits":{"claude":permit},
            "enforcement_receipts":{"claude":receipt},"families":{"claude":{
                "producer_boot_id":"producer-1","command_seq":3,"permit_generation":2,"saved_policy_version":policy,
                "policy_sync_state":"applied","applied_policy_version":policy}}}),
            config,
        )
    }
    #[test]
    fn policy_application_requires_current_live_producer_policy_boot_command_and_fresh_receipt() {
        let (value, config) = fixture();
        let project = |v: &Value, now, live| {
            FrameEvidence::with_producer(v, &config, now, |_| live).policy_sync_state()
        };
        assert_eq!(project(&value, 103.0, true), PolicySyncState::Applied);
        assert_eq!(project(&value, 103.0, false), PolicySyncState::PendingApply);
        assert_eq!(project(&value, 112.0, true), PolicySyncState::PendingApply);
        for pointer in [
            "/executor_boot_id",
            "/saved_policy_version/policy_digest",
            "/enforcement_receipts/claude/executor_boot_id",
            "/enforcement_receipts/claude/policy_version/policy_digest",
        ] {
            let mut old = value.clone();
            *old.pointer_mut(pointer).unwrap() = json!("old");
            assert_eq!(
                project(&old, 103.0, true),
                PolicySyncState::PendingApply,
                "{pointer}"
            );
        }
        let mut old = value.clone();
        old["enforcement_receipts"]["claude"]["command_seq"] = json!(2);
        assert_eq!(project(&old, 103.0, true), PolicySyncState::PendingApply);
        let mut failed = value.clone();
        failed["enforcement_receipts"]["claude"]["enforcement_state"] = json!("failed");
        assert_eq!(project(&failed, 103.0, true), PolicySyncState::ApplyFailed);
        let mut failed = value.clone();
        failed["enforcement_receipts"]["claude"]["interception_active"] = json!(false);
        assert_eq!(project(&failed, 103.0, true), PolicySyncState::ApplyFailed);
        let mut failed = value.clone();
        failed["enforcement_receipts"] = json!({});
        failed["families"]["claude"]["policy_sync_state"] = json!("apply_failed");
        assert_eq!(project(&failed, 103.0, true), PolicySyncState::ApplyFailed);
        failed["families"]["claude"]["command_seq"] = json!(2);
        assert_eq!(project(&failed, 103.0, true), PolicySyncState::PendingApply);
        // Legacy heartbeat and a locally-written readiness label cannot grant application success.
        assert_eq!(
            project(
                &json!({"time":103.0,"sandbox_ready":true,"applied_policy_version":value["saved_policy_version"]}),
                103.0,
                true
            ),
            PolicySyncState::PendingApply
        );
    }
}
