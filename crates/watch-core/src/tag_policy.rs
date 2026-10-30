use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Global,
    Rule,
    Direct,
    Unknown,
}

impl Mode {
    pub fn from_wire(value: Option<&str>) -> Self {
        match value {
            Some("global") => Self::Global,
            Some("rule") => Self::Rule,
            Some("direct") => Self::Direct,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub api_available: bool,
    pub mode: Mode,
    pub observed_chain: Vec<String>,
    pub required_group: String,
    pub pinned_node: String,
    /// None means the controller's selection could not be resolved.
    pub route_chains: BTreeMap<String, Option<Vec<String>>>,
    pub matched_rule: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Match,
    Mismatch,
    Unconfirmed,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Mismatch => "mismatch",
            Self::Unconfirmed => "unconfirmed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    ModeUnconfirmed,
    DirectOrRejectedPath,
    MissingObservedChain,
    ExplicitGroupMismatch,
    MissingMatchedRule,
    UnresolvedSelection,
    ChainOrPinnedNodeMismatch,
    GlobalMatch,
    RuleMatch,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ModeUnconfirmed => "mode_unconfirmed",
            Self::DirectOrRejectedPath => "direct_or_rejected_path",
            Self::MissingObservedChain => "missing_observed_chain",
            Self::ExplicitGroupMismatch => "explicit_group_mismatch",
            Self::MissingMatchedRule => "missing_matched_rule",
            Self::UnresolvedSelection => "unresolved_selection",
            Self::ChainOrPinnedNodeMismatch => "chain_or_pinned_node_mismatch",
            Self::GlobalMatch => "global_match",
            Self::RuleMatch => "rule_match",
        }
    }

    pub fn detail(self) -> &'static str {
        match self {
            Self::ModeUnconfirmed => "TAG 实际模式未能确认",
            Self::DirectOrRejectedPath => "实测为直连或拒绝路径，未通过代理路径要求",
            Self::MissingObservedChain => "缺少实际代理链",
            Self::ExplicitGroupMismatch => "实际为 GLOBAL 模式，与明确保存的分组要求不同",
            Self::MissingMatchedRule => "规则模式未提供这条连接的命中规则",
            Self::UnresolvedSelection => "未能独立解析当前模式下的分组选择及末端代理节点",
            Self::ChainOrPinnedNodeMismatch => "实际代理链与当前模式的分组选择或已固定节点不一致",
            Self::GlobalMatch => "已按 TAG GLOBAL 模式核对实际代理链与末端节点",
            Self::RuleMatch => "已按 TAG RULE 模式核对实际代理链与末端节点",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub state: State,
    pub reason: Reason,
}

/// Mirrors the validated-input contract of Python `connection_policy`.
/// Deliberately returns no action, launch permit or mutable session state.
pub fn evaluate(evidence: &Evidence) -> Decision {
    use Reason::*;
    use State::*;
    let decision = |state, reason| Decision { state, reason };
    if !evidence.api_available || evidence.mode == Mode::Unknown {
        return decision(Unconfirmed, ModeUnconfirmed);
    }
    if evidence.mode == Mode::Direct
        || evidence.observed_chain.iter().any(|name| {
            matches!(
                name.to_uppercase().as_str(),
                "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS" | "COMPATIBLE"
            )
        })
    {
        return decision(Mismatch, DirectOrRejectedPath);
    }
    let Some(last_hop) = evidence.observed_chain.last() else {
        return decision(Unconfirmed, MissingObservedChain);
    };
    let root = match evidence.mode {
        Mode::Global => {
            if !evidence.required_group.is_empty() && evidence.required_group != "GLOBAL" {
                return decision(Mismatch, ExplicitGroupMismatch);
            }
            "GLOBAL"
        }
        Mode::Rule => {
            if evidence
                .matched_rule
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                return decision(Unconfirmed, MissingMatchedRule);
            }
            if evidence.required_group.is_empty() {
                last_hop
            } else {
                &evidence.required_group
            }
        }
        // These modes are handled before looking at the observed chain.
        Mode::Direct | Mode::Unknown => return decision(Unconfirmed, ModeUnconfirmed),
    };
    let Some(Some(selected)) = evidence.route_chains.get(root) else {
        return decision(Unconfirmed, UnresolvedSelection);
    };
    if selected.is_empty() {
        return decision(Unconfirmed, UnresolvedSelection);
    }
    if evidence.observed_chain != *selected
        || (!evidence.pinned_node.is_empty() && evidence.observed_chain[0] != evidence.pinned_node)
    {
        return decision(Mismatch, ChainOrPinnedNodeMismatch);
    }
    decision(
        Match,
        if evidence.mode == Mode::Global {
            GlobalMatch
        } else {
            RuleMatch
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(mode: Mode) -> Evidence {
        let group = if mode == Mode::Global { "GLOBAL" } else { "AI" };
        let chain = vec!["JP-test".into(), group.into()];
        Evidence {
            api_available: true,
            mode,
            observed_chain: chain.clone(),
            required_group: String::new(),
            pinned_node: String::new(),
            route_chains: BTreeMap::from([(group.into(), Some(chain))]),
            matched_rule: Some("DomainSuffix".into()),
        }
    }

    #[test]
    fn mode_and_complete_chain_are_required() {
        for (mode, reason) in [
            (Mode::Global, Reason::GlobalMatch),
            (Mode::Rule, Reason::RuleMatch),
        ] {
            let mut value = sample(mode);
            assert_eq!(
                evaluate(&value),
                Decision {
                    state: State::Match,
                    reason
                }
            );
            value.observed_chain.insert(1, "unexpected-hop".into());
            assert_eq!(evaluate(&value).reason, Reason::ChainOrPinnedNodeMismatch);
            value.observed_chain.clear();
            assert_eq!(evaluate(&value).reason, Reason::MissingObservedChain);
        }
    }

    #[test]
    fn actual_selection_cannot_replace_an_explicit_pin() {
        let mut value = sample(Mode::Global);
        value.pinned_node = "different-node".into();
        assert_eq!(evaluate(&value).state, State::Mismatch);
        value.pinned_node.clear();
        value.required_group = "AI".into();
        assert_eq!(evaluate(&value).reason, Reason::ExplicitGroupMismatch);
    }

    #[test]
    fn direct_and_unknown_precedence_matches_legacy() {
        let mut value = sample(Mode::Direct);
        value.observed_chain.clear();
        assert_eq!(evaluate(&value).reason, Reason::DirectOrRejectedPath);
        value.api_available = false;
        assert_eq!(evaluate(&value).reason, Reason::ModeUnconfirmed);
        value.api_available = true;
        value.mode = Mode::Unknown;
        value.observed_chain = vec!["DIRECT".into()];
        assert_eq!(evaluate(&value).state, State::Unconfirmed);
    }

    #[test]
    fn incomplete_rule_or_selection_never_matches() {
        let mut value = sample(Mode::Rule);
        for rule in [None, Some("".into()), Some(" \u{3000}".into())] {
            value.matched_rule = rule;
            assert_eq!(evaluate(&value).reason, Reason::MissingMatchedRule);
        }
        value.matched_rule = Some("Match".into());
        for routes in [
            BTreeMap::new(),
            BTreeMap::from([("AI".into(), None)]),
            BTreeMap::from([("AI".into(), Some(vec![]))]),
        ] {
            value.route_chains = routes;
            assert_eq!(evaluate(&value).reason, Reason::UnresolvedSelection);
        }
    }

    #[test]
    fn reserved_hops_never_become_proxy_matches() {
        for label in [
            "DIRECT",
            "direct",
            "Reject",
            "REJECT-DROP",
            "PASS",
            "COMPATIBLE",
        ] {
            let mut value = sample(Mode::Global);
            value.observed_chain[0] = label.into();
            value
                .route_chains
                .insert("GLOBAL".into(), Some(value.observed_chain.clone()));
            assert_eq!(evaluate(&value).reason, Reason::DirectOrRejectedPath);
        }
    }
}
