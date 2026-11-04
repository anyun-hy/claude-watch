//! Shared bounded vocabulary for guard event production and validation.
//! This is not an authorization API: logging a reason never requests a stop.
use crate::policy::PolicyCatalog;

pub const STATES: &[&str] = &[
    "idle", "safe", "risk", "locked", "unknown", "missing", "pending",
    "disabled", "active", "rechecking",
];

pub const NON_POLICY_REASONS: &[&str] = &[
    "egress_risk_persist_failed", "evidence_expired", "session_rechecking",
    "session_ended", "session_changed", "session_adopted", "session_resumed",
    "risk_evidence_unavailable", "risk_evidence_missing", "risk_evidence_invalid",
    "invalid_config", "invalid_session", "invalid_native_observation",
    "native_observation_unavailable", "desktop_inventory_incomplete",
    "desktop_identity_unavailable", "process_metadata_unavailable",
    "target_identity_changed", "target_identity_mismatch", "target_already_running",
    "target_start_unconfirmed", "launcher_identity_unavailable", "launcher_context_changed",
    "evidence_context_unconfirmed", "superseded_check", "protected_scope_mismatch",
    "display_receipt_not_authority", "claude_already_running", "pending_cleanup_failed",
    "revalidation_lease_rollback_failed", "backend_unhealthy", "guard_memory_unavailable",
    "guard_encoding_failed", "egress_changed", "state_io_failed", "unsafe_path",
    "home_owner_mismatch", "clock_unavailable", "sampling_failed", "none", "other",
];

pub fn valid_state(value: &str) -> bool { STATES.contains(&value) }
pub fn valid_reason(value: &str) -> bool {
    PolicyCatalog::criterion_for(value).is_some() || NON_POLICY_REASONS.contains(&value)
}
pub fn state(value: Option<&str>) -> &str {
    value.filter(|value| valid_state(value)).unwrap_or("unknown")
}
pub fn reason(value: Option<&str>) -> &str {
    match value {
        None => "none",
        Some(value) if valid_reason(value) => value,
        Some(_) => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn policy_reasons_and_lifecycle_labels_share_one_bounded_vocabulary() {
        for criterion in PolicyCatalog::criteria() {
            for code in criterion.codes {
                assert!(valid_reason(code), "{code}");
                assert_eq!(reason(Some(code)), *code);
            }
        }
        for value in ["active", "rechecking", "pending", "disabled"] {
            assert_eq!(state(Some(value)), value);
        }
        for value in ["session_adopted", "session_resumed", "session_ended"] {
            assert_eq!(reason(Some(value)), value);
        }
    }

    #[test]
    fn arbitrary_values_are_redacted_and_tables_are_unique() {
        for value in ["", "UNKNOWN", "new-unregistered-code", "cookie=secret", "/Users/private/file"] {
            assert_eq!(state(Some(value)), "unknown");
            assert_eq!(reason(Some(value)), "other");
            assert!(!valid_reason(value));
        }
        assert_eq!(STATES.iter().collect::<BTreeSet<_>>().len(), STATES.len());
        assert_eq!(NON_POLICY_REASONS.iter().collect::<BTreeSet<_>>().len(), NON_POLICY_REASONS.len());
        for code in NON_POLICY_REASONS {
            assert!(PolicyCatalog::criterion_for(code).is_none(), "{code}");
        }
    }
}
