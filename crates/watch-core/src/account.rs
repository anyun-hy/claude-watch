#![forbid(unsafe_code)]

//! Pure account ownership and coexistence evaluation.
//! No I/O, no filesystem mutation, no process signaling.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountOwnershipState {
    /// No external switcher is active; active directory matches Watch baseline.
    ExclusiveWatch,
    /// External switcher state matches Watch current slot and metadata anchor.
    AlignedCoexistence,
    /// An external switcher operation lock is active.
    ExternalLocked,
    /// Watch current and external switcher current disagree, or an external
    /// switch occurred between Watch transactions (e.g. A -> B -> A).
    SplitBrainConflict {
        watch_current: Option<String>,
        legacy_current: Option<String>,
    },
    /// Active profile directory was replaced or mutated externally while Claude was idle.
    UntrackedActiveMutation,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LegacySwitcherAnchor {
    pub current: Option<String>,
    pub mtime_ns: Option<u64>,
    pub ino: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AccountOwnershipObservation {
    pub watch_current: Option<String>,
    pub recorded_anchor: Option<LegacySwitcherAnchor>,
    pub current_anchor: Option<LegacySwitcherAnchor>,
    pub external_locked: bool,
    pub active_mutated: bool,
}

/// Evaluates cross-system ownership state between Claude Watch and legacy claude-switcher.
pub fn evaluate_account_ownership(obs: &AccountOwnershipObservation) -> AccountOwnershipState {
    if obs.external_locked {
        return AccountOwnershipState::ExternalLocked;
    }

    match &obs.current_anchor {
        None => {
            if obs.active_mutated {
                AccountOwnershipState::UntrackedActiveMutation
            } else {
                AccountOwnershipState::ExclusiveWatch
            }
        }
        Some(current) => {
            let legacy_str = current.current.as_deref();
            // 1. Reject non-standard slots (e.g. C or D) immediately.
            if !matches!(legacy_str, Some("A" | "B")) {
                return AccountOwnershipState::SplitBrainConflict {
                    watch_current: obs.watch_current.clone(),
                    legacy_current: current.current.clone(),
                };
            }
            // 2. When Watch previously recorded an anchor of ~/.claude-switcher/current,
            // check whether the legacy file changed at all since Watch's last commit.
            // If `prev == current`, the upstream switcher has been completely idle
            // (even if Watch itself moved from A to B while leaving ~/.claude-switcher/current untouched).
            if let Some(prev) = &obs.recorded_anchor {
                if prev.current != current.current
                    || prev.mtime_ns != current.mtime_ns
                    || prev.ino != current.ino
                {
                    return AccountOwnershipState::SplitBrainConflict {
                        watch_current: obs.watch_current.clone(),
                        legacy_current: current.current.clone(),
                    };
                }
            } else {
                // 3. When no anchor was recorded yet (first-ever switch or pre-anchor state),
                // compare against Watch's current slot (or default first-save slot "A").
                let expected_slot = obs.watch_current.as_deref().unwrap_or("A");
                if legacy_str != Some(expected_slot) {
                    return AccountOwnershipState::SplitBrainConflict {
                        watch_current: obs.watch_current.clone(),
                        legacy_current: current.current.clone(),
                    };
                }
            }
            if obs.active_mutated {
                AccountOwnershipState::UntrackedActiveMutation
            } else {
                AccountOwnershipState::AlignedCoexistence
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusive_watch_when_no_legacy() {
        let obs = AccountOwnershipObservation {
            watch_current: Some("A".into()),
            recorded_anchor: None,
            current_anchor: None,
            external_locked: false,
            active_mutated: false,
        };
        assert_eq!(
            evaluate_account_ownership(&obs),
            AccountOwnershipState::ExclusiveWatch
        );
    }

    #[test]
    fn locked_takes_precedence() {
        let obs = AccountOwnershipObservation {
            watch_current: Some("A".into()),
            recorded_anchor: None,
            current_anchor: Some(LegacySwitcherAnchor {
                current: Some("A".into()),
                mtime_ns: Some(100),
                ino: Some(200),
            }),
            external_locked: true,
            active_mutated: false,
        };
        assert_eq!(
            evaluate_account_ownership(&obs),
            AccountOwnershipState::ExternalLocked
        );
    }

    #[test]
    fn slot_mismatch_is_split_brain() {
        let obs = AccountOwnershipObservation {
            watch_current: Some("A".into()),
            recorded_anchor: None,
            current_anchor: Some(LegacySwitcherAnchor {
                current: Some("B".into()),
                mtime_ns: Some(100),
                ino: Some(200),
            }),
            external_locked: false,
            active_mutated: false,
        };
        assert_eq!(
            evaluate_account_ownership(&obs),
            AccountOwnershipState::SplitBrainConflict {
                watch_current: Some("A".into()),
                legacy_current: Some("B".into()),
            }
        );
    }

    #[test]
    fn aba_roundtrip_mtime_change_is_split_brain() {
        let obs = AccountOwnershipObservation {
            watch_current: Some("A".into()),
            recorded_anchor: Some(LegacySwitcherAnchor {
                current: Some("A".into()),
                mtime_ns: Some(100),
                ino: Some(200),
            }),
            current_anchor: Some(LegacySwitcherAnchor {
                current: Some("A".into()),
                mtime_ns: Some(150), // Changed mtime from upstream switch
                ino: Some(200),
            }),
            external_locked: false,
            active_mutated: false,
        };
        assert_eq!(
            evaluate_account_ownership(&obs),
            AccountOwnershipState::SplitBrainConflict {
                watch_current: Some("A".into()),
                legacy_current: Some("A".into()),
            }
        );
    }

    #[test]
    fn aligned_coexistence_when_anchors_match() {
        let obs = AccountOwnershipObservation {
            watch_current: Some("A".into()),
            recorded_anchor: Some(LegacySwitcherAnchor {
                current: Some("A".into()),
                mtime_ns: Some(100),
                ino: Some(200),
            }),
            current_anchor: Some(LegacySwitcherAnchor {
                current: Some("A".into()),
                mtime_ns: Some(100),
                ino: Some(200),
            }),
            external_locked: false,
            active_mutated: false,
        };
        assert_eq!(
            evaluate_account_ownership(&obs),
            AccountOwnershipState::AlignedCoexistence
        );
    }

    #[test]
    fn watch_evolution_with_untouched_legacy_anchor_stays_aligned() {
        let anchor = LegacySwitcherAnchor {
            current: Some("A".into()),
            mtime_ns: Some(100),
            ino: Some(200),
        };
        let obs = AccountOwnershipObservation {
            watch_current: Some("B".into()),
            recorded_anchor: Some(anchor.clone()),
            current_anchor: Some(anchor),
            external_locked: false,
            active_mutated: false,
        };
        assert_eq!(
            evaluate_account_ownership(&obs),
            AccountOwnershipState::AlignedCoexistence
        );
    }

    #[test]
    fn untracked_active_mutation_detected_when_directory_replaced() {
        let obs = AccountOwnershipObservation {
            watch_current: Some("B".into()),
            recorded_anchor: None,
            current_anchor: None,
            external_locked: false,
            active_mutated: true,
        };
        assert_eq!(
            evaluate_account_ownership(&obs),
            AccountOwnershipState::UntrackedActiveMutation
        );
    }
}
