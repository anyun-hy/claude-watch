use claude_watch_core::{
    cli::Request,
    config::Config,
    processes::Provider,
};
use serde_json::json;

#[test]
fn legacy_openai_force_without_a_matching_grant_resolves_to_close() {
    let config = Config::from_value(json!({
        "gpt_close_ip":"force","gpt_close_dns":"force","gpt_close_webrtc":"warn"
    })).unwrap();
    assert_eq!(config.close_action("egress_ip_changed", Provider::Codex), "close");
    assert_eq!(config.close_action("dns_egress_changed", Provider::Chatgpt), "close");
    assert_eq!(config.close_action("webrtc_egress_changed", Provider::Codex), "warn");
    // Unconfigured Claude defaults to its family contract default (force)
    assert_eq!(config.close_action("egress_ip_changed", Provider::Claude), "force");
    assert_eq!(config.value().unwrap()["gpt_close_ip"], "close");
}

#[test]
fn independent_grants_authorize_only_the_exact_openai_criterion() {
    let config = Config::from_value(json!({
        "gpt_close_ip":"force","gpt_close_dns":"force",
        "gpt_force_approved_v1":["gpt_close_dns"]
    })).unwrap();
    assert_eq!(config.close_action("egress_ip_changed", Provider::Chatgpt), "close");
    assert_eq!(config.close_action("dns_egress_changed", Provider::Codex), "force");
    assert_eq!(config.close_action("webrtc_egress_changed", Provider::Codex), "close");
    assert_eq!(config.close_action("dns_and_webrtc_egress_changed", Provider::Codex), "force");
    assert_eq!(config.gpt_force_approved_v1, ["gpt_close_dns"]);
}

#[test]
fn the_empty_approval_field_does_not_change_legacy_default_serialization() {
    let raw = Config::default().value().unwrap();
    assert!(raw.get("gpt_force_approved_v1").is_none());
    let parsed = Config::from_value(raw.clone()).unwrap();
    assert!(parsed.gpt_force_approved_v1.is_empty());
    assert_eq!(raw, parsed.value().unwrap());
}

#[test]
fn unknown_duplicate_or_malformed_grants_fail_closed() {
    for raw in [
        json!({"gpt_force_approved_v1":["claude_close_ip"]}),
        json!({"gpt_force_approved_v1":["gpt_close_unknown"]}),
        json!({"gpt_force_approved_v1":["gpt_close_ip","gpt_close_ip"]}),
        json!({"gpt_force_approved_v1":"gpt_close_ip"}),
        json!({"gpt_force_approved_v1":[42]}),
    ] {
        assert_eq!(Config::from_value(raw).unwrap_err().code, "invalid_config");
    }
}

#[test]
fn config_set_accepts_only_an_explicit_scoped_force_confirmation_value() {
    let args = ["config", "set", "--apply", "--confirm-force", "gpt_close_ip"]
        .map(String::from);
    let request = Request::parse(&args).unwrap();
    assert_eq!(request.action.as_deref(), Some("set"));
    assert_eq!(request.value("confirm-force"), Some("gpt_close_ip"));
    for args in [
        vec!["config", "show", "--confirm-force", "gpt_close_ip"],
        vec!["config", "enabled", "--apply", "--confirm-force", "gpt_close_ip"],
        vec!["config", "set", "--confirm-force", "gpt_close_ip"],
        vec!["status", "--confirm-force", "gpt_close_ip"],
    ] {
        assert!(Request::parse(&args.into_iter().map(String::from).collect::<Vec<_>>()).is_err());
    }
}

#[test]
fn raw_struct_mutation_cannot_bypass_force_confirmation() {
    let mut config = Config::default();
    config.policy_actions.insert("gpt_close_ip".into(), "force".into());
    assert_eq!(config.close_action("egress_ip_changed", Provider::Codex), "close");
    assert_eq!(config.close_action("egress_ip_changed", Provider::Claude), "force");
    // Explicit close configuration on Claude evaluates to close
    config.policy_actions.insert("claude_close_ip".into(), "close".into());
    assert_eq!(config.close_action("egress_ip_changed", Provider::Claude), "close");
    // Explicit force configuration on Claude evaluates to force
    config.policy_actions.insert("claude_close_ip".into(), "force".into());
    assert_eq!(config.close_action("egress_ip_changed", Provider::Claude), "force");
}
