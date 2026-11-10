//! Disposition policy families, declared as data.
//!
//! Every AI service that can be supervised declares one row here: which
//! processes belong to it, which actions it is able to perform, and what to
//! assume when a key is absent. The config keys, their defaults, the
//! validation and the resolution of a risk code all read this table, so
//! adding a service is one entry and never a second copy of the rows.

use crate::processes::Provider;
use std::collections::BTreeMap;

/// One drift criterion of a disposition policy.
pub struct PolicyCriterion {
    /// Suffix of the config key: a family stores `{prefix}_close_{id}`.
    pub id: &'static str,
    /// Risk codes resolved by this criterion's configured action.
    pub codes: &'static [&'static str],
    /// Criteria combined into one code: the strictest configured action of
    /// the parts wins. A criterion with parts owns no config key of its own,
    /// so it is neither defaulted nor validated — it only resolves codes.
    pub combines: &'static [&'static str],
    /// Default action for this criterion, overriding the family default.
    /// A criterion whose historical behaviour was the normal exit keeps that
    /// behaviour even when its family defaults to something stricter.
    pub default_action: Option<&'static str>,
}

/// The criteria every family is configured by, in the order they are shown.
pub const CRITERIA: &[PolicyCriterion] = &[
    PolicyCriterion {
        id: "ip",
        codes: &["egress_ip_changed"],
        combines: &[],
        default_action: None,
    },
    PolicyCriterion {
        id: "cn",
        codes: &["egress_country_cn"],
        combines: &[],
        default_action: None,
    },
    PolicyCriterion {
        id: "dns",
        codes: &["dns_egress_changed", "dns_risk"],
        combines: &[],
        default_action: None,
    },
    PolicyCriterion {
        id: "webrtc",
        codes: &["webrtc_egress_changed", "webrtc_risk"],
        combines: &[],
        default_action: None,
    },
    // Both probe families drifted: one code, resolved from the two criteria
    // that own keys. A leak risk that names no single probe family is judged
    // by both, so it can never be handled more leniently than the strictest
    // configured probe criterion.
    PolicyCriterion {
        id: "probe_drift",
        codes: &["dns_and_webrtc_egress_changed", "network_leak_risk"],
        combines: &["dns", "webrtc"],
        default_action: None,
    },
    // A supervised desktop is running but its protection state could not be
    // confirmed: no session was established, the sampled identity no longer
    // matches, the local proxy/TUN could not be verified, or a sampling round
    // never completed. None of these is a confirmed drift, so they carry their
    // own switch instead of an implicit close. The default stays the
    // historical normal exit — this guard fails closed — but because the row
    // is configurable, a user who prefers a notice can now actually get one
    // instead of being closed by a rule they never saw.
    PolicyCriterion {
        id: "session",
        codes: &[
            // These codes select an action only after the controller receives
            // a risk/locked outcome. Healthy Pending rounds keep observing.
            "session_pending",
            "launch_failed",
            "session_missing",
            "session_identity_unconfirmed",
            "session_identity_changed",
            "session_state_invalid",
            "revalidation_context_changed",
            "guard_sampling_failed",
            "revalidation_timeout",
            "proxy_or_tun_failed",
            "proxy_or_tun_unconfirmed",
            "egress_unconfirmed",
        ],
        combines: &[],
        default_action: Some("close"),
    },
];

/// One AI service's disposition policy.
///
/// Each service declares the actions it can perform; the default is what it
/// assumes when a key is absent. Everything that renders, validates or
/// resolves a policy reads `actions`, so no caller can offer an action the
/// service cannot perform.
pub struct PolicyFamily {
    /// Logical family, matching the panel that edits it.
    pub id: &'static str,
    /// Prefix of this family's config keys. It is the on-disk name and can
    /// differ from the id: the ChatGPT / Codex family is stored as `gpt_*`.
    pub key_prefix: &'static str,
    /// Processes supervised under this family's policy.
    pub providers: &'static [Provider],
    /// Actions this service can perform, most severe first. The last one is
    /// what a stored-but-unperformable value degrades to.
    pub actions: &'static [&'static str],
    /// Action assumed when this family's key is absent.
    pub default_action: &'static str,
}
impl PolicyFamily {
    pub fn key(&self, criterion: &str) -> String {
        format!("{}_close_{criterion}", self.key_prefix)
    }
    /// The action a stored value degrades to when this service cannot perform
    /// it: the mildest one the service can do.
    pub fn fallback(&self) -> &'static str {
        self.actions.last().copied().unwrap_or("warn")
    }
    /// Rank of an action, higher is stricter. An unknown action ranks as the
    /// mildest so it can never win a comparison.
    pub fn severity(&self, action: &str) -> usize {
        self.actions
            .iter()
            .position(|a| *a == action)
            .map(|index| self.actions.len() - 1 - index)
            .unwrap_or(0)
    }
    pub fn performable(&self, action: &str) -> bool {
        self.actions.contains(&action)
    }
}

const CLAUDE: PolicyFamily = PolicyFamily {
    id: "claude",
    key_prefix: "claude",
    providers: &[Provider::Claude],
    actions: &["force", "close", "warn"],
    default_action: "close",
};
const OPENAI: PolicyFamily = PolicyFamily {
    id: "openai",
    key_prefix: "gpt",
    providers: &[Provider::Codex, Provider::Chatgpt, Provider::Openai],
    // Force is available for every supervised family. The helper issues
    // SIGKILL to the process tree it has already identity-verified, so the
    // same bounded force path serves Claude and ChatGPT / Codex alike; the
    // per-product rule lives only in the policy table.
    actions: &["force", "close", "warn"],
    default_action: "close",
};
pub const FAMILIES: &[PolicyFamily] = &[CLAUDE, OPENAI];

/// Lookup over the declared families. Nothing outside this table knows a
/// family's keys or capabilities.
pub struct PolicyCatalog;
impl PolicyCatalog {
    pub const fn families() -> &'static [PolicyFamily] {
        FAMILIES
    }
    pub const fn criteria() -> &'static [PolicyCriterion] {
        CRITERIA
    }
    pub fn family(id: &str) -> Option<&'static PolicyFamily> {
        FAMILIES.iter().find(|family| family.id == id)
    }
    pub fn family_for(provider: Provider) -> Option<&'static PolicyFamily> {
        FAMILIES
            .iter()
            .find(|family| family.providers.contains(&provider))
    }
    /// The representative desktop target a family supervises. The guard's
    /// process scope is derived from `provider()`, not from the specific
    /// desktop kind, so one target per family is enough: `family_desktop_scopes`
    /// expands it to every bundle the family covers. CLI families have no
    /// desktop representative and return `None`.
    pub fn guard_target(family: &PolicyFamily) -> Option<crate::processes::LaunchTarget> {
        match family.id {
            "claude" => Some(crate::processes::LaunchTarget::ClaudeDesktop),
            "openai" => Some(crate::processes::LaunchTarget::CodexDesktop),
            _ => None,
        }
    }
    /// The criteria that own a config key. Combined codes own none.
    pub fn keyed_criteria() -> impl Iterator<Item = &'static PolicyCriterion> {
        CRITERIA.iter().filter(|criterion| criterion.combines.is_empty())
    }
    pub fn criterion_for(code: &str) -> Option<&'static PolicyCriterion> {
        CRITERIA.iter().find(|criterion| criterion.codes.contains(&code))
    }
    pub fn criterion(id: &str) -> Option<&'static PolicyCriterion> {
        CRITERIA.iter().find(|criterion| criterion.id == id)
    }
    /// Action assumed for a key that is absent. A criterion may pin its own
    /// default (the historical normal exit for an unestablished session, for
    /// example); a pinned value the family cannot perform degrades to the
    /// family default so the table can never name an impossible action.
    pub fn fallback_action(family: &PolicyFamily, criterion: &str) -> &'static str {
        Self::criterion(criterion)
            .and_then(|value| value.default_action)
            .filter(|action| family.performable(action))
            .unwrap_or(family.default_action)
    }
    /// Every key a config may carry, with the value assumed when it is
    /// absent. Adding a family extends this without touching any caller.
    pub fn default_actions() -> BTreeMap<String, String> {
        let mut actions = BTreeMap::new();
        for family in FAMILIES {
            for criterion in Self::keyed_criteria() {
                actions.insert(
                    family.key(criterion.id),
                    Self::fallback_action(family, criterion.id).to_string(),
                );
            }
        }
        actions
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthorityConflict {
    pub code: String,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthorityArbitration {
    pub legacy_bodyguard_active: bool,
    pub legacy_tz_active: bool,
    pub effective_proxy_loss_enforcement: String,
    pub conflicts: Vec<AuthorityConflict>,
}

/// Arbitrates authority between Claude Watch policy configuration and legacy background services.
/// Pure policy evaluation: no I/O, no clocks, no process execution.
pub fn arbitrate_legacy_services(
    config: &crate::config::Config,
    legacy_bodyguard_active: bool,
    legacy_tz_active: bool,
) -> AuthorityArbitration {
    let mut conflicts = Vec::new();
    let configured_session_action = config.action("claude", "session");
    let effective_proxy_loss_enforcement = if legacy_bodyguard_active {
        "legacy_root_kill".to_string()
    } else {
        configured_session_action.to_string()
    };

    if legacy_bodyguard_active {
        let has_warn_action = ["ip", "cn", "dns", "webrtc", "session"]
            .iter()
            .any(|crit| config.action("claude", crit) == "warn");

        if config.guard_enabled || has_warn_action {
            conflicts.push(AuthorityConflict {
                code: "legacy_bodyguard_overrides_policy".to_string(),
                title: "原版保镖覆盖策略".to_string(),
                detail: "原版 local.claude-bodyguard 正在运行，在代理或 TUN 异常时会直接终止 Claude，覆盖 Claude Watch 的策略配置。".to_string(),
            });
        }
    }

    if legacy_tz_active && config.timezone_watchdog {
        conflicts.push(AuthorityConflict {
            code: "dual_timezone_writer_conflict".to_string(),
            title: "时区守护双写冲突".to_string(),
            detail: "原版 local.tz-watchdog 与 Claude Watch 时区守护同时启用，两者可能竞争修改系统时区。".to_string(),
        });
    }

    AuthorityArbitration {
        legacy_bodyguard_active,
        legacy_tz_active,
        effective_proxy_loss_enforcement,
        conflicts,
    }
}

#[cfg(test)]
mod legacy_arbitration_tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn clean_state_produces_no_conflicts() {
        let config = Config::default();
        let arb = arbitrate_legacy_services(&config, false, false);
        assert!(!arb.legacy_bodyguard_active);
        assert!(!arb.legacy_tz_active);
        assert_eq!(arb.effective_proxy_loss_enforcement, "close");
        assert!(arb.conflicts.is_empty());
    }

    #[test]
    fn legacy_bodyguard_warn_conflict_detected() {
        let mut config = Config::default();
        config.guard_enabled = false;
        config.policy_actions.insert("claude_close_session".into(), "warn".into());
        let arb = arbitrate_legacy_services(&config, true, false);
        assert!(arb.legacy_bodyguard_active);
        assert_eq!(arb.effective_proxy_loss_enforcement, "legacy_root_kill");
        assert_eq!(arb.conflicts.len(), 1);
        assert_eq!(arb.conflicts[0].code, "legacy_bodyguard_overrides_policy");
    }

    #[test]
    fn dual_timezone_writer_detected() {
        let mut config = Config::default();
        config.timezone_watchdog = true;
        let arb = arbitrate_legacy_services(&config, false, true);
        assert!(arb.legacy_tz_active);
        assert_eq!(arb.conflicts.len(), 1);
        assert_eq!(arb.conflicts[0].code, "dual_timezone_writer_conflict");
    }
}
