use claude_watch_runtime::rules::{inspect_rules, inspect_tag_rules, render_rules, BEGIN, END};
use serde_json::json;

#[test]
fn only_owned_block_changes_and_all_thirteen_domains_are_covered() {
    let original = "user: keep\nprepend-rules:\n  - DOMAIN,example.test,DIRECT\n";
    let rendered = render_rules(original, "GLOBAL", false).unwrap();
    assert!(rendered.contains("DOMAIN,example.test,DIRECT"));
    assert!(rendered.contains(BEGIN) && rendered.contains(END));
    assert_eq!(render_rules(&rendered, "GLOBAL", false).unwrap(), rendered);
    let result = inspect_rules("tag", &[], Some("global"), &[]);
    assert_eq!(result["state"], "ok");
    assert_eq!(result["covered_domains"].as_array().unwrap().len(), 13);
}

#[test]
fn bypass_and_ambiguous_markers_are_never_accepted() {
    let result = inspect_rules(
        "tag",
        &["DOMAIN-SUFFIX,claude.ai,DIRECT".into()],
        Some("rule"),
        &[],
    );
    assert_eq!(result["state"], "fail");
    let corrupt = format!("{BEGIN}\n{BEGIN}\n{END}\n");
    assert_eq!(
        render_rules(&corrupt, "GLOBAL", false).unwrap_err().code,
        "ambiguous_rules"
    );
}

#[test]
fn a_rule_pointing_at_a_group_parked_on_direct_is_bypass_not_coverage() {
    let entries = vec![
        "DOMAIN-SUFFIX,claude.ai,海外AI".into(),
        "DOMAIN-SUFFIX,anthropic.com,海外AI".into(),
    ];
    let result = inspect_rules("tag", &entries, Some("rule"), &["海外AI".into()]);
    assert_eq!(result["state"], "fail");
    let bypassed = result["bypass_domains"].as_array().unwrap();
    assert!(bypassed.iter().any(|v| v == "claude.ai"));
    assert!(bypassed.iter().any(|v| v == "anthropic.com"));
    assert!(result["detail"].as_str().unwrap().contains("直连或拒绝"));
    // The same snapshot without the bypassed selection stays covered.
    let parked = inspect_rules("tag", &entries, Some("rule"), &[]);
    assert_eq!(parked["state"], "missing");
    assert!(parked["covered_domains"].as_array().unwrap().iter().any(|v| v == "claude.ai"));
}

#[test]
fn controller_rules_win_and_global_bypass_is_rejected() {
    let runtime = vec!["DOMAIN-SUFFIX,claude.ai,GLOBAL".into()];
    let controller = vec!["DOMAIN-SUFFIX,claude.ai,DIRECT".into()];
    let active = inspect_tag_rules(Some(&controller), &runtime, &json!({"mode":"rule"}));
    assert_eq!(active["state"], "fail");
    let global = inspect_tag_rules(
        None,
        &runtime,
        &json!({"mode":"global","global_node":"DIRECT"}),
    );
    assert_eq!(global["state"], "fail");
}

#[test]
fn a_disabled_rule_is_named_in_detail_and_never_reads_as_coverage() {
    // anthropic.com exists upstream only as a disabled rule, so it never
    // reaches entries; claude.ai is the single effective rule.
    let runtime = vec!["DOMAIN-SUFFIX,claude.ai,AI".into()];
    let api = json!({"mode":"rule","rules":{"disabled_domains":["anthropic.com"]}});
    let result = inspect_tag_rules(None, &runtime, &api);
    assert_eq!(result["state"], "missing");
    assert!(result["missing_domains"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "anthropic.com"));
    assert_eq!(result["disabled_domains"], json!(["anthropic.com"]));
    let detail = result["detail"].as_str().unwrap();
    assert!(detail.contains("anthropic.com"), "{detail}");
    assert!(detail.contains("已被禁用"), "{detail}");
    // The global mode never consults the rule table; the note stays out of it.
    let global = inspect_tag_rules(
        None,
        &runtime,
        &json!({"mode":"global","global_node":"JP","rules":{"disabled_domains":["anthropic.com"]}}),
    );
    assert_eq!(global["state"], "ok");
    assert!(global["detail"].as_str().unwrap().contains("全局模式"));
    assert!(global.get("disabled_domains").is_none());
}
