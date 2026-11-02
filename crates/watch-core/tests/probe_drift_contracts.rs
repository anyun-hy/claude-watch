use claude_watch_core::risk::{probe_drift, probe_fingerprint};
use serde_json::json;

const NOW: f64 = 1000.0;

fn dns_receipt(countries: &[&str], finished_at: f64) -> serde_json::Value {
    json!({
        "finished_at": finished_at,
        "dns": {"countries": countries, "egress_ips": ["111.19.239.31"]},
        "http": {"egress_ips": ["222.10.93.134"]},
    })
}

fn webrtc_receipt(addresses: &[&str], sampled_at: f64) -> serde_json::Value {
    let observations: Vec<_> = addresses
        .iter()
        .map(|a| json!({"kind":"srflx","address":a,"country":"JP"}))
        .chain(std::iter::once(
            json!({"kind":"http","address":"222.10.93.134","country":"JP"}),
        ))
        .collect();
    json!({"sampled_at": sampled_at, "observations": observations})
}

#[test]
fn matching_probe_exits_are_safe_and_stale_ones_are_unknown() {
    let dns = dns_receipt(&["CN", "JP"], NOW - 5.0);
    let rtc = webrtc_receipt(&["222.10.93.134"], NOW - 5.0);
    let baseline = probe_fingerprint(&dns, &rtc);
    let out = probe_drift(&baseline.0, &baseline.1, &dns, &rtc, NOW);
    assert_eq!(out["state"], "safe");

    let stale = probe_drift(&baseline.0, &baseline.1, &dns, &rtc, NOW + 400.0);
    assert_eq!(stale["state"], "unknown");
    assert_eq!(stale["reason"]["code"], "risk_evidence_unavailable");
}

#[test]
fn a_changed_exit_country_or_candidate_set_is_reported_per_source() {
    let baseline_dns = vec!["CN".to_string(), "JP".to_string()];
    let baseline_rtc = vec!["222.10.93.134".to_string()];
    // Both sides moved.
    let out = probe_drift(
        &baseline_dns,
        &baseline_rtc,
        &dns_receipt(&["US"], NOW - 5.0),
        &webrtc_receipt(&["8.8.8.8"], NOW - 5.0),
        NOW,
    );
    assert_eq!(out["state"], "risk");
    assert_eq!(out["reason"]["code"], "dns_and_webrtc_egress_changed");
    // Only the DNS country set moved; rotating one recursive address inside
    // the same country set must not count as drift.
    let rotated = json!({
        "finished_at": NOW - 5.0,
        "dns": {"countries": ["JP", "CN"], "egress_ips": ["111.33.75.149"]},
    });
    let out = probe_drift(
        &baseline_dns,
        &baseline_rtc,
        &rotated,
        &webrtc_receipt(&["222.10.93.134"], NOW - 5.0),
        NOW,
    );
    assert_eq!(out["state"], "safe");
    // Only WebRTC moved.
    let out = probe_drift(
        &baseline_dns,
        &baseline_rtc,
        &dns_receipt(&["CN", "JP"], NOW - 5.0),
        &webrtc_receipt(&["8.8.4.4"], NOW - 5.0),
        NOW,
    );
    assert_eq!(out["state"], "risk");
    assert_eq!(out["reason"]["code"], "webrtc_egress_changed");
}

#[test]
fn a_missing_baseline_or_missing_observations_never_closes() {
    let out = probe_drift(
        &[],
        &["222.10.93.134".to_string()],
        &dns_receipt(&["CN"], NOW - 5.0),
        &webrtc_receipt(&["222.10.93.134"], NOW - 5.0),
        NOW,
    );
    assert_eq!(out["state"], "unknown");
    assert_eq!(out["reason"]["code"], "risk_baseline_missing");

    let out = probe_drift(
        &["CN".to_string()],
        &["222.10.93.134".to_string()],
        &dns_receipt(&["CN"], NOW - 5.0),
        &webrtc_receipt(&[], NOW - 5.0),
        NOW,
    );
    // A fresh sample with zero srflx candidates proves nothing: unknown,
    // never risk.
    assert_eq!(out["state"], "unknown");
    assert_eq!(out["reason"]["code"], "probe_sample_empty");
}
