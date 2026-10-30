mod support;
use claude_watch_core::cli::Request;
use serde_json::{json, Value};
#[test]
fn every_mature_switcher_command_and_flag_shape_matches_the_existing_parser() {
    let cases: Vec<Value> = vec![
        vec!["status"],
        vec!["self-check"],
        vec!["service-status"],
        vec!["protection", "preview"],
        vec!["protection", "apply", "--apply", "--plan-id", "plan"],
        vec!["environment", "--online", "--record"],
        vec!["environment", "--mode=tag"],
        vec!["dns-leak-record", "--apply"],
        vec!["webrtc-risk-record", "--apply"],
        vec!["setup", "inspect"],
        vec!["setup", "detect", "--online"],
        vec!["setup", "preview", "--candidate-id", "candidate"],
        vec![
            "setup",
            "apply",
            "--apply",
            "--candidate-id",
            "c",
            "--plan-id",
            "p",
        ],
        vec!["setup", "recover", "--apply"],
        vec!["check", "--online", "--require-ready", "--no-report"],
        vec!["checkdetail"],
        vec!["config", "show"],
        vec!["config", "set", "--apply"],
        vec!["config", "enabled"],
        vec!["account", "status"],
        vec![
            "account",
            "switch",
            "A",
            "--apply",
            "--ack-unverified-version",
        ],
        vec!["account", "recover", "--apply"],
        vec!["account", "import"],
        vec!["launch", "--apply"],
        vec!["repair"],
        vec!["fix", "--apply", "--plan-id", "p"],
        vec!["set-region", "--allow-country", "CN"],
        vec!["restore-settings", "receipt", "--apply"],
        vec!["guard-tick"],
        vec!["services", "update-on", "--apply"],
        vec!["services", "update-off", "--apply"],
        vec!["services", "disable-legacy", "--apply"],
        vec!["services", "refresh-admin", "--apply"],
        vec!["update"],
        vec!["update", "--auto"],
        vec!["update", "--recover", "--apply"],
        vec!["uninstall"],
        vec![
            "uninstall",
            "--apply",
            "--purge-accounts",
            "--confirm-data-removal",
            "--remove-managed-rules",
        ],
        vec!["logs"],
        vec!["logs", "--export", "/fixture/report.json"],
    ]
    .into_iter()
    .map(|v| json!(v))
    .collect();
    for (c, expected) in cases.iter().zip(support::oracle("cli_parse", &cases)) {
        let args: Vec<String> = serde_json::from_value(c.clone()).unwrap();
        let request = Request::parse(&args).unwrap();
        assert_eq!(json!({"value":request.namespace()}), expected, "{c}");
    }
}
#[test]
fn apply_authorization_is_explicit_and_invalid_flags_cannot_select_a_weaker_mode() {
    for args in [
        vec!["launch"],
        vec!["account", "switch", "A"],
        vec!["setup", "recover"],
        vec!["protection", "apply"],
    ] {
        let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            Request::parse(&args)
                .unwrap()
                .require_apply()
                .unwrap_err()
                .code,
            "explicit_apply_required"
        );
    }
    for args in [
        vec!["launch", "--skip-check"],
        vec!["account", "switch", "C", "--apply"],
        vec!["guard-tick", "--safe"],
        vec!["check", "--online=false"],
        vec!["setup", "invalid"],
        vec!["diagnose-proxy"],
        vec![
            "diagnose-proxy",
            "--proxy",
            "http://127.0.0.1:7890",
            "--stdin-config",
        ],
    ] {
        assert!(Request::parse(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err());
    }
    assert_eq!(
        Request::parse(&["dns-leak-record".into(), "--apply".into()])
            .unwrap()
            .input_limit(),
        768 * 1024
    );
}

#[test]
fn cli_tail_is_opaque_and_cannot_supply_parent_apply_or_leak_into_debug_output() {
    use claude_watch_core::cli::Request;
    let args = [
        "launch",
        "--target",
        "codex-cli",
        "--",
        "--home",
        "--apply",
        "SYNTHETIC_SECRET\n$(literal)",
    ];
    let request = Request::parse(&args.map(str::to_owned)).unwrap();
    assert!(!request.flag("apply"));
    assert_eq!(
        request.child_args,
        vec!["--home", "--apply", "SYNTHETIC_SECRET\n$(literal)"]
    );
    assert!(!request.namespace().to_string().contains("SYNTHETIC_SECRET"));
    assert!(!format!("{request:?}").contains("SYNTHETIC_SECRET"));
    assert!(Request::parse(
        &["launch", "--target", "codex-desktop", "--", "extra"].map(str::to_owned)
    )
    .is_err());
    assert!(Request::parse(&["config", "show", "--", "extra"].map(str::to_owned)).is_err());
    assert!(Request::parse(
        &["launch", "--target", "codex-cli", "--allow-changes", "--"].map(str::to_owned)
    )
    .is_err());
}
