//! Pure JSON/config contracts; no network, process inventory or signals.
use claude_watch_core::{config::Config, processes::Provider, risk::probe_drift};
use serde_json::{json, Value};
const NOW: f64 = 1000.0;
fn dns(country: &str, at: f64) -> Value {
    json!({"finished_at":at,"dns":{"countries":[country]}})
}
fn rtc(ip: &str, at: f64) -> Value {
    json!({"sampled_at":at,"observations":[{"kind":"srflx","address":ip}]})
}
fn verdict(dns: &Value, rtc: &Value) -> Value {
    probe_drift(&["JP".into()], &["1.1.1.1".into()], dns, rtc, NOW)
}

#[test]
fn each_confirmed_drift_survives_an_unavailable_peer() {
    for bad_dns in [Value::Null, json!({}), dns("JP", NOW-301.0), dns("JP", NOW+1.0),
        dns("JP", 0.0), json!({"finished_at":NOW,"dns":{"countries":[]}})] {
        let value = verdict(&bad_dns, &rtc("8.8.8.8", NOW));
        assert_eq!(value["state"], "risk");
        assert_eq!(value["reason"]["code"], "webrtc_egress_changed");
        assert_eq!(value["sources"]["dns"]["state"], "unknown");
        assert_eq!(value["sources"]["webrtc"]["state"], "risk");
    }
    for bad_rtc in [Value::Null, json!({}), rtc("1.1.1.1", NOW-301.0), rtc("1.1.1.1", NOW+1.0),
        rtc("1.1.1.1", 0.0), json!({"sampled_at":NOW,"observations":[]})] {
        let value = verdict(&dns("US", NOW), &bad_rtc);
        assert_eq!(value["state"], "risk");
        assert_eq!(value["reason"]["code"], "dns_egress_changed");
        assert_eq!(value["sources"]["dns"]["state"], "risk");
        assert_eq!(value["sources"]["webrtc"]["state"], "unknown");
    }
}

#[test]
fn missing_peer_baseline_does_not_cancel_a_confirmed_drift() {
    let value = probe_drift(&[], &["1.1.1.1".into()], &dns("US", NOW), &rtc("8.8.8.8", NOW), NOW);
    assert_eq!(value["reason"]["code"], "webrtc_egress_changed");
    assert_eq!(value["sources"]["dns"]["state"], "unknown");
    let value = probe_drift(&["JP".into()], &[], &dns("US", NOW), &rtc("8.8.8.8", NOW), NOW);
    assert_eq!(value["reason"]["code"], "dns_egress_changed");
    assert_eq!(value["sources"]["webrtc"]["state"], "unknown");
}

#[test]
fn a_single_safe_source_never_proves_overall_safety() {
    for value in [verdict(&dns("JP", NOW), &Value::Null), verdict(&Value::Null, &rtc("1.1.1.1", NOW)),
        probe_drift(&[], &["1.1.1.1".into()], &dns("JP", NOW), &rtc("1.1.1.1", NOW), NOW)] {
        assert_eq!(value["state"], "unknown");
        assert!(value["observed_at"].is_null());
    }
}

#[test]
fn combined_code_requires_two_confirmed_changed_sources() {
    let value = verdict(&dns("US", NOW-2.0), &rtc("8.8.8.8", NOW-7.0));
    assert_eq!(value["reason"]["code"], "dns_and_webrtc_egress_changed");
    assert_eq!(value["observed_at"], NOW-7.0);
    assert_eq!(value["reason"]["observed_at"], NOW-7.0);
    assert_eq!(verdict(&dns("US", NOW), &rtc("8.8.8.8", NOW-301.0))["reason"]["code"], "dns_egress_changed");
}

#[test]
fn unavailable_criterion_cannot_lend_force_to_a_warning() {
    let mut config = Config::default();
    config.policy_actions.insert("gpt_close_dns".into(), "warn".into());
    config.policy_actions.insert("gpt_close_webrtc".into(), "force".into());
    // Force is deliberately authorised for only this criterion. A stale
    // pre-migration Force value resolves to ordinary close instead.
    config.gpt_force_approved_v1 = vec!["gpt_close_webrtc".into()];
    let dns_only = verdict(&dns("US", NOW), &Value::Null);
    assert_eq!(config.close_action(dns_only["reason"]["code"].as_str().unwrap(), Provider::Codex), "warn");
    let both = verdict(&dns("US", NOW), &rtc("8.8.8.8", NOW));
    assert_eq!(config.close_action(both["reason"]["code"].as_str().unwrap(), Provider::Codex), "force");
    config.policy_actions.insert("gpt_close_dns".into(), "force".into());
    config.policy_actions.insert("gpt_close_webrtc".into(), "warn".into());
    // Moving the explicit grant does not let the unavailable peer lend Force.
    config.gpt_force_approved_v1 = vec!["gpt_close_dns".into()];
    let rtc_only = verdict(&Value::Null, &rtc("8.8.8.8", NOW));
    assert_eq!(config.close_action(rtc_only["reason"]["code"].as_str().unwrap(), Provider::Codex), "warn");
}

#[test]
fn unusable_samples_never_invent_drift() {
    let empty_dns = dns("?", NOW);
    let private_rtc = rtc("192.168.1.5", NOW);
    let value = verdict(&empty_dns, &private_rtc);
    assert_eq!(value["state"], "unknown");
    assert_eq!(value["reason"]["code"], "probe_sample_empty");
    assert_eq!(value["sources"]["dns"]["state"], "unknown");
    assert_eq!(value["sources"]["webrtc"]["state"], "unknown");
}

#[test]
fn both_unchanged_sources_are_safe_without_renewing_their_sample_time() {
    let value = verdict(&dns("JP", NOW-15.0), &rtc("1.1.1.1", NOW-5.0));
    assert_eq!(value["state"], "safe");
    assert_eq!(value["observed_at"], NOW-15.0);
    assert_eq!(value["sources"]["dns"]["observed_at"], NOW-15.0);
    assert_eq!(value["sources"]["webrtc"]["observed_at"], NOW-5.0);
}

#[test]
fn ttl_boundary_and_invalid_clocks_are_conservative() {
    assert_eq!(verdict(&dns("US", NOW-300.0), &rtc("1.1.1.1", NOW))["state"], "risk");
    assert_eq!(verdict(&dns("US", NOW-300.001), &rtc("1.1.1.1", NOW))["state"], "unknown");
    for now in [0.0, -1.0, f64::INFINITY, f64::NAN] {
        let value = probe_drift(&["JP".into()], &["1.1.1.1".into()], &dns("US", NOW), &rtc("8.8.8.8", NOW), now);
        assert_eq!(value["state"], "unknown");
    }
}
