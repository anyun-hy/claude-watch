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
}

/// The criteria every family is configured by, in the order they are shown.
pub const CRITERIA: &[PolicyCriterion] = &[
    PolicyCriterion {
        id: "ip",
        codes: &["egress_ip_changed"],
        combines: &[],
    },
    PolicyCriterion {
        id: "cn",
        codes: &["egress_country_cn"],
        combines: &[],
    },
    PolicyCriterion {
        id: "dns",
        codes: &["dns_egress_changed"],
        combines: &[],
    },
    PolicyCriterion {
        id: "webrtc",
        codes: &["webrtc_egress_changed"],
        combines: &[],
    },
    // Both probe families drifted: one code, resolved from the two criteria
    // that own keys.
    PolicyCriterion {
        id: "probe_drift",
        codes: &["dns_and_webrtc_egress_changed"],
        combines: &["dns", "webrtc"],
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
    default_action: "force",
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
    /// Every key a config may carry, with the value assumed when it is
    /// absent. Adding a family extends this without touching any caller.
    pub fn default_actions() -> BTreeMap<String, String> {
        let mut actions = BTreeMap::new();
        for family in FAMILIES {
            for criterion in Self::keyed_criteria() {
                actions.insert(family.key(criterion.id), family.default_action.to_string());
            }
        }
        actions
    }
}
