use claude_watch_core::{
    audit::{self, AuditInput},
    config::Config,
    observation, presentation,
    region::ZoneCatalog,
};
mod support;

use serde_json::{json, Value};
use support::oracle;

const NOW: f64 = 1_700_000_000.0;
fn case() -> Value {
    let patterns = json!({"short":"y/MM/dd","medium":"y/MM/dd","long":"y年M月d日"});
    json!({"now":NOW,"zones":{"JP":["Asia/Tokyo"]},"config":{},"history":[],
        "local":{"proxy":"ok","proxy_detail":"entry confirmed","tun":"ok","mode":"tag","context":"ctx","context_id":"ctx",
        "network_identity":{"mode":"tag","entry":"127.0.0.1:7890","selection":"JP-node","tun":"utun4"},
        "context_transition":{"state":"stable"},"timezone":"Asia/Tokyo","locale":"ja_JP","ipv6":"ok","language":"(\"en-JP\")",
        "guard":true,"guard_state":"ok","rules":{"state":"ok","detail":"13/13 已覆盖"},
        "date_format":{"state":"available","configured_locale":"ja_JP","patterns":patterns,
            "reference_patterns":{"ja_JP":patterns},"short_sample":"2023/11/14","reference_samples":{"ja_JP":"2023/11/14"}}},
        "online":{"trace":{"ip":"1.1.1.1","loc":"JP"},"geo":{"ip":"1.1.1.1","country":"JP","timezone":"Asia/Tokyo"},
        "dns":{"state":"ok","detail":"same country","receipt":{"dns":{"countries":["JP"]}}},
        "webrtc":{"state":"ok","observations":[{"kind":"srflx","address":"1.1.1.1","country":"JP"}]},
        "stun":{"complete":true,"started_at":NOW-2.0,"finished_at":NOW,
            "observations":[{"server":"stun.example.test","port":3478,"status":"ok","address":"1.1.1.1",
                "attempts":[{"attempt":1,"status":"timeout","stage":"receive","error":"no reply","error_code":"timed_out","errno":60,"started_at":NOW-2.0,"finished_at":NOW-1.0},
                    {"attempt":2,"status":"ok","started_at":NOW-0.8,"finished_at":NOW}]}]},
        "claude":403,"api":401,"asn":{"number":2516,"organization":"KDDI CORPORATION","registered_country":"JP","result_time":"2023-11-14","registered_queried_at":NOW-3.0},
        "service_responses":{"claude":{"status":"ok","transport_reached":true,"http_status":403,"access":"challenge","source":"https://claude.ai/",
            "challenge":{"provider":"cloudflare","mitigated":"challenge"},"queried_at":NOW-2.0},
            "api":{"status":"ok","transport_reached":true,"http_status":401,"access":"authentication_required","source":"https://api.anthropic.com/v1/models","queried_at":NOW-1.0}}}})
}
fn evaluate(case: &Value) -> Value {
    let config = Config::from_value(case["config"].clone()).unwrap();
    let zones: ZoneCatalog = serde_json::from_value(case["zones"].clone()).unwrap();
    audit::evaluate(
        AuditInput {
            config: &config,
            local: &case["local"],
            online: &case["online"],
            history: case["history"].as_array().unwrap(),
            zones: &zones,
            policy: "test-policy",
            now: case["now"].as_f64().unwrap(),
        },
        |v| format!("T{v:.0}"),
    )
    .unwrap()
}
fn row<'a>(v: &'a Value, id: &str) -> &'a Value {
    v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id)
        .unwrap()
}

#[test]
fn full_fourteen_row_policy_matches_mature_implementation() {
    let good = case();
    let mut cases = vec![good.clone()];
    for (path, value) in [
        ("/local/proxy", json!("unknown")),
        ("/local/tun", json!("fail")),
        ("/local/timezone", json!("America/New_York")),
        ("/local/date_format/patterns/long", json!("MMM d, y")),
        ("/local/language", json!("(\"zh-CN\",\"en-JP\")")),
        ("/local/guard", json!(false)),
        ("/local/guard_state", json!("disabled")),
        ("/local/rules/state", json!("unknown")),
        ("/online/dns/state", json!("unknown")),
        ("/online/stun/complete", json!(false)),
        ("/online/stun/observations/0/address", json!("8.8.8.8")),
        ("/online/stun/observations", json!([])),
        ("/online/asn", json!({})),
        ("/online/service_responses", json!({})),
        ("/online/claude", json!(0)),
        ("/online/trace/loc", json!("CN")),
        ("/online/geo/country", json!("CN")),
        ("/online/geo/ip", json!("8.8.8.8")),
        ("/online/dns/receipt/dns/countries", json!(["JP", "CN"])),
        ("/online/webrtc/state", json!("fail")),
        ("/online/webrtc/observations/0/country", json!("CN")),
        (
            "/local/context_transition",
            json!({"state":"sampling_unavailable","unavailable":["proxy_sampling"]}),
        ),
        (
            "/local/context_transition",
            json!({"state":"sampling_unavailable","unavailable":["timezone"]}),
        ),
        (
            "/history",
            json!([{"time":NOW-10.0,"ip":"8.8.8.8"},{"time":NOW-5.0,"ip":"9.9.9.9"}]),
        ),
    ] {
        let mut candidate = good.clone();
        *candidate.pointer_mut(path).unwrap() = value;
        cases.push(candidate);
    }
    for config in [
        json!({"enabled":false}),
        json!({"require_dns":false,"require_stun":false}),
        json!({"require_pinned_rules":true}),
        json!({"require_ipv6_off":false,"require_english":false}),
    ] {
        let mut candidate = good.clone();
        candidate["config"] = config;
        cases.push(candidate);
    }
    let mut changed = good.clone();
    changed["local"]["context_changed"] = json!(true);
    cases.push(changed);
    let mut asn = good.clone();
    asn["online"]["asn"]["registered_country"] = json!("CN");
    asn["online"]["netcoffee_lookup"] = json!({"data":{"ip":"1.1.1.1"}});
    cases.push(asn);
    let mut error = good.clone();
    error["online"]["geo"] = json!({});
    error["online"]["query_errors"] = json!({"geo":{"source":"Net.Coffee","message":"HTTP 429"}});
    cases.push(error);
    let expected = oracle("audit", &cases);
    for (index, (case, expected)) in cases.iter().zip(expected).enumerate() {
        assert_eq!(evaluate(case), expected, "case {index}: {case}");
    }
}
#[test]
fn sample_failure_is_local_and_recovery_does_not_poison_other_rows() {
    let good = case();
    let initial = evaluate(&good);
    assert_eq!(initial["ready"], true);
    assert_eq!(initial["rows"].as_array().unwrap().len(), 14);
    let mut failed = good.clone();
    failed["online"]["geo"] = json!({});
    failed["online"]["query_errors"] = json!({
        "geo":{"source":"Shared source","message":"HTTP 429"},"asn":{"source":"Shared source","message":"cooldown"}});
    let result = evaluate(&failed);
    assert_eq!(result["ready"], false);
    assert_eq!(row(&result, "egress")["state"], "unknown");
    for id in [
        "proxy",
        "tun",
        "ipv6",
        "dns",
        "stun",
        "language",
        "guard",
        "reachability",
    ] {
        assert_eq!(row(&result, id)["state"], "ok", "{id}");
    }
    assert_eq!(result["source_notices"].as_array().unwrap().len(), 1);
    assert_eq!(row(&result, "asn")["state"], "ok");
    for _ in 0..5 {
        assert_eq!(evaluate(&good)["ready"], true);
        assert_eq!(evaluate(&failed)["ready"], false);
    }
    let mut changed = good.clone();
    changed["local"]["context_changed"] = json!(true);
    let result = evaluate(&changed);
    assert!(!result["ready"].as_bool().unwrap());
    for r in result["rows"].as_array().unwrap() {
        if r["required"] == true {
            assert_eq!(r["state"], "unknown");
        }
    }
}
#[test]
fn dns_and_stun_block_only_when_the_config_requires_them() {
    // Default policy: the probes still run and stay visible as fail rows,
    // but they no longer veto a launch.
    for id in ["dns", "stun"] {
        let mut value = case();
        if id == "dns" {
            value["online"]["dns"]["state"] = json!("fail");
        } else {
            value["online"]["stun"]["observations"][0]["address"] = json!("8.8.8.8");
        }
        let out = evaluate(&value);
        assert_eq!(row(&out, id)["required"], false);
        assert_eq!(row(&out, id)["state"], "fail");
        assert_eq!(out["ready"], true);
    }
    // An explicit require_* config keeps the blocking behaviour for setups
    // that want the probes to gate a launch.
    for (id, key) in [("dns", "require_dns"), ("stun", "require_stun")] {
        let mut value = case();
        value["config"] = json!({key: true});
        if id == "dns" {
            value["online"]["dns"]["state"] = json!("fail");
        } else {
            value["online"]["stun"]["observations"][0]["address"] = json!("8.8.8.8");
        }
        let out = evaluate(&value);
        assert_eq!(row(&out, id)["required"], true);
        assert_eq!(out["ready"], false);
    }
    // Probe sampling failures stay recorded either way.
    let mut value = case();
    value["online"]["dns"]["receipt"]["dns"]["countries"] = json!(["CN"]);
    value["local"]["context_transition"] =
        json!({"state":"sampling_unavailable","unavailable":["controller"]});
    assert_eq!(row(&evaluate(&value), "dns")["state"], "fail");
}
#[test]
fn a_service_card_reports_only_whether_each_endpoint_responded() {
    // The card answers one question. The probe is anonymous by design, so a
    // redirect, a challenge page, a missing API key and a rate limit are all
    // answers — the only failure is silence.
    let answered = |code: i64| {
        json!({"source":"https://claude.ai/","status":"ok","transport_reached":true,"http_status":code})
    };
    for code in [200, 301, 302, 401, 403, 429, 500] {
        let (state, detail, source) =
            presentation::service_response("claude", &answered(code), &Value::Null);
        assert_eq!(state, "ok", "HTTP {code} is a response");
        assert_eq!(detail, format!("已响应 HTTP {code}"));
        assert_eq!(source.as_deref(), Some("https://claude.ai/"));
        assert_eq!(
            presentation::service_label("claude", &answered(code), &Value::Null),
            detail,
            "the label and the detail must never disagree"
        );
    }

    let silent = json!({"source":"https://claude.ai/","status":"unknown",
        "transport_reached":false,"http_status":Value::Null,
        "error":"timeout: connect","error_code":"timeout"});
    let (state, detail, _) = presentation::service_response("claude", &silent, &Value::Null);
    assert_eq!(state, "unknown");
    assert!(detail.starts_with("无响应"), "{detail}");
    assert_eq!(
        presentation::service_label("claude", &silent, &Value::Null),
        "无响应"
    );

    assert_eq!(presentation::http_result(&json!(403)).0, "ok");
    assert_eq!(presentation::http_result(&Value::Null).0, "unknown");
    assert_eq!(evaluate(&case())["ready"], true);
}
#[test]
fn context_transitions_match_original_and_preserve_later_sampling_failures() {
    let local = case()["local"].clone();
    let mut cases = vec![json!({"before":local,"after":local})];
    for (path, value) in [
        ("/timezone", Value::Null),
        ("/timezone", json!("Asia/Shanghai")),
        ("/date_format/state", json!("unknown")),
        ("/proxy", json!("unknown")),
        ("/tun", json!("fail")),
        ("/guard", json!(false)),
        ("/network_identity/selection", json!("other")),
    ] {
        let mut after = local.clone();
        *after.pointer_mut(path).unwrap() = value;
        cases.push(json!({"before":local,"after":after}));
    }
    let mut after = local.clone();
    after["observation_unavailable"] = json!(["controller"]);
    cases.push(json!({"before":local,"after":after}));
    let mut after = local.clone();
    after["app_language"] = json!("en");
    cases.push(json!({"before":local,"after":after}));
    let mut after = local.clone();
    after["guard"] = json!(false);
    after["guard_state"] = json!("disabled");
    cases.push(json!({"before":local,"after":after}));
    for (c, expected) in cases.iter().zip(oracle("reconcile", &cases)) {
        let mut before = c["before"].clone();
        let transition = observation::reconcile(&mut before, &c["after"]);
        assert_eq!(
            json!({"before":before,"transition":transition}),
            expected,
            "{c}"
        );
    }
}

#[test]
fn proxy_and_tun_failures_are_or_conditions_while_unknown_never_creates_a_pass() {
    let base = case()["local"].clone();
    let cases = [
        ("proxy", "fail", "unknown", "fail"),
        ("tun", "fail", "unknown", "fail"),
        ("proxy", "unknown", "ok", "unknown"),
        ("tun", "unknown", "ok", "unknown"),
        ("proxy", "unknown", "fail", "fail"),
    ];
    for (key, before_value, after_value, expected) in cases {
        let mut before = base.clone();
        let mut after = base.clone();
        before[key] = json!(before_value);
        after[key] = json!(after_value);
        let transition = observation::reconcile(&mut before, &after);
        assert_eq!(
            before[key], expected,
            "{key}: {before_value} -> {after_value}"
        );
        if expected == "unknown" {
            assert_eq!(transition["state"], "sampling_unavailable");
            assert!(transition["unavailable"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .any(|value| value == &json!(format!("{key}_sampling")))));
        }
    }
}
#[test]
fn malformed_history_or_identity_never_panics_or_grants_launch_permission() {
    let mut value = case();
    value["history"] = json!([{"time":"NaN","ip":"1.1.1.1"},{"time":NOW+20.0},{"time":null}]);
    assert_eq!(row(&evaluate(&value), "ip_history")["state"], "ok");
    let mut before = value["local"].clone();
    before["network_identity"] = json!("bad");
    let transition = observation::reconcile(&mut before, &value["local"]);
    assert_eq!(transition["state"], "sampling_unavailable");
    value["local"] = before;
    assert_eq!(evaluate(&value)["ready"], false);
}

#[test]
fn observation_targets_share_network_policy_without_claude_specific_requirements() {
    use claude_watch_core::processes::LaunchTarget;
    let mut input = case();
    input["local"]["guard"] = json!(false);
    input["local"]["guard_state"] = json!("disabled");
    input["local"]["language"] = json!("fr-FR");
    input["local"]["backend_healthy"] = json!(true);
    input["local"]["backend_native"] = json!(true);
    input["online"]["service_responses"] = json!({});
    input["online"]["claude"] = json!(503);
    input["online"]["api"] = json!(503);
    let cfg = Config::default();
    let zones: ZoneCatalog = serde_json::from_value(input["zones"].clone()).unwrap();
    let run = |value: &Value, target| {
        audit::evaluate_target(
            AuditInput {
                config: &cfg,
                local: &value["local"],
                online: &value["online"],
                history: &[],
                zones: &zones,
                policy: "test",
                now: NOW,
            },
            target,
            |t| format!("{t}"),
        )
        .unwrap()
    };
    assert_eq!(run(&input, LaunchTarget::ClaudeDesktop)["ready"], false);
    for target in [LaunchTarget::CodexDesktop, LaunchTarget::ChatgptDesktop] {
        let good = run(&input, target);
        assert_eq!(good["ready"], true, "{good}");
        assert_eq!(good["authorization_scope"], "observation");
        assert!(!good["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == "language" || r["id"] == "reachability"));
        let mut old = input.clone();
        old["local"]["backend_native"] = json!(false);
        assert_eq!(run(&old, target)["ready"], false);
        let mut leaking = input.clone();
        leaking["online"]["webrtc"]["state"] = json!("fail");
        assert_eq!(run(&leaking, target)["ready"], false);
        let mut unknown = input.clone();
        unknown["local"]["proxy"] = json!("unknown");
        assert_eq!(run(&unknown, target)["ready"], false);
    }
}

#[test]
fn cli_proxy_overrides_must_match_the_measured_child_endpoint_without_leaking_values() {
    let proxy = "http://127.0.0.1:7890";
    assert_eq!(audit::cli_proxy_state(Some(proxy), &[])["state"], "ok");
    assert_eq!(audit::cli_proxy_state(None, &[])["state"], "unknown");
    assert_eq!(
        audit::cli_proxy_state(
            Some(proxy),
            &[json!({"HTTPS_PROXY":"http://localhost:7890/","NO_PROXY":"localhost,127.0.0.1,::1"})]
        )["state"],
        "ok"
    );
    let other = audit::cli_proxy_state(
        Some(proxy),
        &[json!({"HTTP_PROXY":"http://name:SYNTHETIC_PASSWORD@127.0.0.1:7890"})],
    );
    assert_eq!(other["state"], "fail");
    assert!(!other.to_string().contains("SYNTHETIC_PASSWORD"));
    assert_eq!(
        audit::cli_proxy_state(Some(proxy), &[json!({"NO_PROXY":"*.example.com"})])["state"],
        "unknown"
    );
    assert_eq!(
        audit::cli_proxy_state(Some(proxy), &[json!({"ALL_PROXY":false})])["state"],
        "unknown"
    );
}

/// A partial round with a valid accepted response remains usable; absence of
/// an accepted response is unknown, not evidence that UDP cannot leave.
#[test]
fn stun_requires_a_public_accepted_response_and_preserves_mismatch_risk() {
    assert_eq!(row(&evaluate(&case()), "stun")["state"], "ok");

    let mut partial = case();
    partial["online"]["stun"]["complete"] = json!(false);
    partial["online"]["stun"]["missing"] = json!(1);
    partial["online"]["stun"]["observations"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"server":"stun.cloudflare.com","port":3478,"status":"timeout","address":"",
                   "accepted":false,"deadline_exceeded":true}),
        );
    // One silent server must not veto the servers that answered.
    assert_eq!(row(&evaluate(&partial), "stun")["state"], "ok");
    let detail = row(&evaluate(&partial), "stun")["detail"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        detail.contains("1 / 2 台服务器应答"),
        "coverage is reported, not vetoed: {detail}"
    );

    let mut none = case();
    none["online"]["stun"]["observations"] = json!([]);
    none["online"]["stun"]["complete"] = json!(false);
    assert_eq!(row(&evaluate(&none), "stun")["state"], "unknown");
    // Default policy keeps the row visible without gating a launch.
    assert!(!evaluate(&none)["blocked"]
        .as_array()
        .unwrap()
        .contains(&json!("stun")));
    assert!(row(&evaluate(&none), "stun")["detail"]
        .as_str()
        .unwrap()
        .contains("无法确认 UDP 出口"));
    // An explicit require_stun config keeps the blocking behaviour.
    let mut required = none.clone();
    required["config"] = json!({"require_stun": true});
    assert!(evaluate(&required)["blocked"]
        .as_array()
        .unwrap()
        .contains(&json!("stun")));

    for observation in [
        json!({"status":"timeout","address":""}),
        json!({"status":"ok","address":"10.0.0.1"}),
        json!({"status":"ok","address":"1.1.1.1","accepted":false}),
        json!({"status":"ok","address":"1.1.1.1","deadline_exceeded":true}),
    ] {
        let mut unavailable = case();
        unavailable["online"]["stun"]["observations"] = json!([observation]);
        assert_eq!(row(&evaluate(&unavailable), "stun")["state"], "unknown");
        // Default policy: visible, not blocking. With require_stun the same
        // sample still gates a launch.
        assert!(!evaluate(&unavailable)["blocked"]
            .as_array()
            .unwrap()
            .contains(&json!("stun")));
        let mut gated = unavailable.clone();
        gated["config"] = json!({"require_stun": true});
        assert!(evaluate(&gated)["blocked"]
            .as_array()
            .unwrap()
            .contains(&json!("stun")));
    }

    let mut late_leak = partial.clone();
    late_leak["online"]["stun"]["observations"][1] =
        json!({"status":"ok","address":"8.8.8.8","accepted":false,"deadline_exceeded":true});
    assert_eq!(row(&evaluate(&late_leak), "stun")["state"], "fail");

    let mut leak = case();
    leak["online"]["stun"]["observations"][0]["address"] = json!("8.8.8.8");
    // The strict side survives: an answered address off the reference fails.
    assert_eq!(row(&evaluate(&leak), "stun")["state"], "fail");

    let mut no_reference = case();
    no_reference["online"]["trace"]["ip"] = json!("");
    assert_eq!(row(&evaluate(&no_reference), "stun")["state"], "unknown");
}

#[test]
fn a_non_answering_stun_server_leads_the_detail_instead_of_sitting_below_the_fold() {
    let mut partial = case();
    partial["online"]["stun"]["complete"] = json!(false);
    partial["online"]["stun"]["observations"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"server":"stun.cloudflare.com","port":3478,"status":"timeout","address":"",
                   "accepted":false,"deadline_exceeded":true,
                   "attempts":[{"attempt":1,"status":"timeout","stage":"receive","error":"no reply",
                                "started_at":1.0,"finished_at":2.0}]}),
        );
    let detail = row(&evaluate(&partial), "stun")["detail"]
        .as_str()
        .unwrap()
        .to_string();
    let answered = detail.find("stun.example.test").unwrap();
    let silent = detail.find("stun.cloudflare.com").unwrap();
    assert!(
        silent < answered,
        "the failing server must lead, not hide below the fold: {detail}"
    );
}
