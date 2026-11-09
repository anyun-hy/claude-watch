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

fn identity_value(identity: &ProcessKernelIdentity) -> Value {
    json!({"pid": identity.pid, "uid": identity.uid,
        "start_seconds": identity.start_seconds, "start_microseconds": identity.start_microseconds,
        "executable_path": identity.executable_path, "audit_token": identity.audit_token})
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
    let Ok(expected_policy) = ChannelSupervisor::compute_policy_version(config) else {
        return PolicySyncState::PendingApply;
    };
    let value = store
        .read_json(
            &store.paths.watch().join("state/channel-supervision.json"),
            Value::Null,
        )
        .unwrap_or(Value::Null);
    let producer = &value["producer_identity"];
    let live = producer["pid"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .and_then(claude_watch_system::inspect_process_identity);
    let producer_valid = live.as_ref().is_some_and(|identity| {
        identity.uid == claude_watch_system::effective_uid()
            && identity_value(identity) == *producer
    });
    project_policy_sync_state(
        &value,
        &expected_policy,
        config.effective_network_backend(),
        now,
        producer_valid,
    )
}

fn fresh(at: f64, now: f64) -> bool {
    at.is_finite()
        && now.is_finite()
        && at <= now + CLOCK_ROLLBACK_TOLERANCE_SECONDS
        && now - at < MAX_ENFORCEMENT_RECEIPT_AGE
}

fn project_policy_sync_state(
    value: &Value,
    expected: &PolicyVersion,
    backend: NetworkBackendKind,
    now: f64,
    producer_valid: bool,
) -> PolicySyncState {
    let version = serde_json::to_value(expected).ok();
    if !producer_valid
        || !value["captured_at"]
            .as_f64()
            .is_some_and(|at| fresh(at, now))
        || value["saved_policy_version"] != version.clone().unwrap_or(Value::Null)
        || value["producer_boot_id"].as_str().is_none_or(str::is_empty)
    {
        return PolicySyncState::PendingApply;
    }
    let Some(boot_id) = value["executor_boot_id"]
        .as_str()
        .filter(|id| !id.is_empty())
    else {
        return PolicySyncState::PendingApply;
    };
    let Some(families) = value["families"].as_object().filter(|f| !f.is_empty()) else {
        return PolicySyncState::PendingApply;
    };
    let mut pending = false;
    let mut failed = false;
    for (family, state) in families {
        let permit =
            serde_json::from_value::<ChannelPermit>(value["authoritative_permits"][family].clone());
        let receipt = serde_json::from_value::<ChannelEnforcementReceipt>(
            value["enforcement_receipts"][family].clone(),
        );
        let Ok(permit) = permit else {
            pending = true;
            continue;
        };
        let command_matched = permit.family == *family
            && permit.backend == backend
            && permit.policy_version == *expected
            && state["saved_policy_version"] == version.clone().unwrap_or(Value::Null)
            && state["command_seq"].as_u64() == Some(permit.command_seq)
            && state["permit_generation"].as_u64() == Some(permit.permit_generation)
            && state["producer_boot_id"] == value["producer_boot_id"];
        let Ok(receipt) = receipt else {
            // apply_command can fail before producing a receipt. The live
            // supervisor's failure is still bound to this exact current command.
            if command_matched && state["policy_sync_state"] == "apply_failed" {
                failed = true;
            } else {
                pending = true;
            }
            continue;
        };
        let matched = command_matched
            && receipt.family == *family
            && receipt.backend == backend
            && receipt.policy_version == *expected
            && receipt.session_id == permit.session_id
            && receipt.executor_boot_id == boot_id
            && receipt.command_seq == permit.command_seq
            && receipt.permit_generation == permit.permit_generation
            && fresh(receipt.observed_at, now)
            && receipt.observed_at + CLOCK_ROLLBACK_TOLERANCE_SECONDS >= permit.issued_at;
        if !matched {
            pending = true;
        } else if receipt.enforcement_state == ChannelEnforcementState::Failed
            || state["policy_sync_state"] == "apply_failed"
            || matches!(
                evaluate_channel_supervision_with_boot_id(
                    &permit,
                    Some(&receipt),
                    expected,
                    Some(boot_id),
                    now
                ),
                ChannelSupervisionVerdict::EnforcementFailed { .. }
            )
        {
            failed = true;
        } else if state["policy_sync_state"] != "applied"
            || state["applied_policy_version"] != version.clone().unwrap_or(Value::Null)
        {
            pending = true;
        }
    }
    if failed {
        PolicySyncState::ApplyFailed
    } else if pending {
        PolicySyncState::PendingApply
    } else {
        PolicySyncState::Applied
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, PolicyVersion) {
        let policy = PolicyVersion {
            policy_digest: "policy".into(),
            guard_policy_digest: "guard".into(),
        };
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
            policy,
        )
    }
    #[test]
    fn policy_application_requires_current_live_producer_policy_boot_command_and_fresh_receipt() {
        let (value, policy) = fixture();
        let project = |v: &Value, now, live| {
            project_policy_sync_state(v, &policy, NetworkBackendKind::Seatbelt, now, live)
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
                &json!({"time":103.0,"sandbox_ready":true,"applied_policy_version":policy}),
                103.0,
                true
            ),
            PolicySyncState::PendingApply
        );
    }
}
