use claude_watch_core::receipts;
use claude_watch_runtime::{
    receipt_store::ReceiptStore,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use uuid::Uuid;

const NOW: f64 = 1_700_000_000.0;
fn local() -> Value {
    json!({"context":"ctx","context_id":"ctx","proxy":"ok","tun":"ok","tag":{"entry":{"endpoint":"http://127.0.0.1:7890"},"api":{"mode":"global","global_node":"JP-node","selected_node":"JP-node"}}})
}
fn probe(kind: &str, now: f64) -> Value {
    let candidates = if kind == "dns" { "resolver" } else { "srflx" };
    let address = if kind == "dns" { "8.8.8.8" } else { "1.1.1.1" };
    let evidence = if kind == "dns" {
        json!({"session":"a".repeat(40), "dns_servers":{"8.8.8.8":5},
               "http":{"address":"1.1.1.1","country":"JP"},
               "geoip":[{"ip":"8.8.8.8","country_code":"JP"}]})
    } else {
        json!([
            {"kind":"geoip","status":"complete","query":"1.1.1.1","data":{"country_code":"jp"}},
            {"kind":"geoip","status":"complete","query":address,"data":{"country_code":"jp"}}
        ])
    };
    json!({"kind":kind,"status":"complete","startedAt":now-2.0,"finishedAt":now,"contextChanged":false,"errors":[],
        "observations":[{"kind":"http","address":"1.1.1.1","country":"Japan","source":"fixture"},
                        {"kind":candidates,"address":address,"country":"Japan","source":"fixture"}],
        "externalJSON":serde_json::to_string(&evidence).unwrap()})
}
fn oracle(operation: &str, cases: &[Value]) -> Vec<Value> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let mut child = Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(root.join("tools/migration_reference.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&json!({"operation":operation,"cases":cases})).unwrap())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}
struct Fixture {
    home: PathBuf,
    store: ReceiptStore,
}
impl Fixture {
    fn new() -> Self {
        let home = std::env::temp_dir().join(format!("cw-receipts-{}", Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        let store = ReceiptStore {
            storage: StateStore::new(Paths::new(&home).unwrap()),
        };
        Self { home, store }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}

#[test]
fn receipt_generation_matches_mature_dns_and_webrtc_behavior() {
    for kind in ["dns", "webrtc"] {
        let good = json!({"probe":probe(kind,NOW),"local":local(),"now":NOW+1.0});
        let mut cases = vec![good.clone()];
        for (path, value) in [
            ("/probe/status", json!("partial")),
            (
                "/probe/errors",
                json!([{"stage":"dns","code":"timeout","message":"endpoint did not respond"}]),
            ),
            ("/probe/contextChanged", json!(true)),
            ("/probe/finishedAt", json!(NOW - 91.0)),
            ("/probe/externalJSON", json!("invalid")),
            ("/probe/observations", json!([])),
            ("/probe/observations/1/address", json!("192.168.1.1")),
            ("/probe/kind", json!("invalid")),
        ] {
            let mut case = good.clone();
            *case.pointer_mut(path).unwrap() = value;
            cases.push(case);
        }
        let mut cn = good.clone();
        let cn_evidence = if kind == "dns" {
            json!({"session":"a".repeat(40),"dns_servers":{"8.8.8.8":5},"http":{"address":"1.1.1.1","country":"JP"},"geoip":[{"ip":"8.8.8.8","country_code":"CN"}]})
        } else {
            json!([
                {"kind":"geoip","status":"complete","query":"1.1.1.1","data":{"country_code":"JP"}},
                {"kind":"geoip","status":"complete","query":if kind=="dns"{"8.8.8.8"}else{"1.1.1.1"},"data":{"country_code":"CN"}}
            ])
        };
        cn["probe"]["externalJSON"] = json!(serde_json::to_string(&cn_evidence).unwrap());
        cases.push(cn);
        let mut expected = good.clone();
        expected["expected_context"] = json!("wrong");
        cases.push(expected);
        let mut expected = good.clone();
        expected["expected_context"] = json!(receipts::tag_signature(&local()));
        cases.push(expected);
        let mut mismatch = good.clone();
        mismatch["probe"]["observations"][1]["address"] = json!("9.9.9.9");
        cases.push(mismatch);
        let method = if kind == "dns" {
            receipts::record_dns
        } else {
            receipts::record_webrtc
        };
        for (case, expected) in cases.iter().zip(oracle(&format!("{kind}_record"), &cases)) {
            let actual = match method(
                &case["probe"],
                &case["local"],
                case.get("expected_context").and_then(Value::as_str),
                case["now"].as_f64().unwrap(),
            ) {
                Ok(v) => json!({"value":v}),
                Err(e) => json!({"error":e.code}),
            };
            assert_eq!(actual, expected, "kind={kind}, case={case}");
        }
    }
}

#[test]
fn ipleak_evidence_is_bound_to_the_session_and_observed_addresses() {
    let good = probe("dns", NOW);
    let receipt = receipts::record_dns(&good, &local(), None, NOW + 1.0).unwrap();
    assert_eq!(receipt["provider"], "ipleak");
    assert_eq!(receipt["comparison"]["state"], "ok");
    let source: Value = serde_json::from_str(good["externalJSON"].as_str().unwrap()).unwrap();
    for (path, replacement) in [
        ("/session", json!("invalid")),
        ("/dns_servers", json!({"8.8.8.8":0})),
        ("/dns_servers", json!({"9.9.9.9":1})),
        ("/http/address", json!("9.9.9.9")),
        ("/http/country", json!("")),
        ("/geoip/0/country_code", json!("")),
        ("/geoip/0/ip", json!("9.9.9.9")),
    ] {
        let mut raw = source.clone();
        *raw.pointer_mut(path).unwrap() = replacement;
        let mut value = good.clone();
        value["externalJSON"] = json!(raw.to_string());
        assert_ne!(
            receipts::record_dns(&value, &local(), None, NOW + 1.0).unwrap()["comparison"]["state"],
            "ok",
            "{path}"
        );
    }
    let mut omitted = good.clone();
    let mut raw = source.clone();
    raw["dns_servers"]["9.9.9.9"] = json!(1);
    raw["geoip"]
        .as_array_mut()
        .unwrap()
        .push(json!({"ip":"9.9.9.9","country_code":"JP"}));
    omitted["externalJSON"] = json!(raw.to_string());
    assert_eq!(
        receipts::record_dns(&omitted, &local(), None, NOW + 1.0).unwrap()["comparison"]["state"],
        "unknown"
    );
    let mut extra = good.clone();
    extra["observations"]
        .as_array_mut()
        .unwrap()
        .push(json!({"kind":"resolver", "address":"10.0.0.1"}));
    assert_ne!(
        receipts::record_dns(&extra, &local(), None, NOW + 1.0).unwrap()["comparison"]["state"],
        "ok"
    );
    let mut old = receipt.clone();
    old.as_object_mut().unwrap().remove("provider");
    assert_eq!(
        receipts::dns_status(&old, &json!({}), "ctx", true, NOW + 2.0, |v| v.to_string())["state"],
        "unknown"
    );
}

#[test]
fn real_ipleak_collector_payload_reaches_the_backend_gate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let output = Command::new("node")
        .arg(root.join("monitor/tests/test_ipleak_probe.cjs"))
        .arg("--emit-fixture")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let probe: Value = serde_json::from_slice(&output.stdout).unwrap();
    let now = probe["finishedAt"].as_f64().unwrap() + 1.0;
    let receipt = receipts::record_dns(&probe, &local(), None, now).unwrap();
    assert_eq!(receipt["provider"], "ipleak");
    assert_eq!(receipt["comparison"]["state"], "ok");
    assert_eq!(
        receipts::dns_status(&receipt, &json!({}), "ctx", true, now, |v| v.to_string())["state"],
        "ok"
    );
    let mut invalid = probe;
    invalid["contextChanged"] = json!(true);
    assert_ne!(
        receipts::record_dns(&invalid, &local(), None, now).unwrap()["comparison"]["state"],
        "ok"
    );
}
#[test]
fn stored_receipt_status_matches_legacy_ttl_and_history_contract() {
    let good = receipts::record_dns(&probe("dns", NOW), &local(), None, NOW + 1.0).unwrap();
    let mut partial = probe("dns", NOW + 3.0);
    partial["status"] = json!("timeout");
    partial["errors"] = json!([{"stage":"dns","code":"timeout"}]);
    let latest = receipts::record_dns(&partial, &local(), None, NOW + 4.0).unwrap();
    let base = json!({"receipt":good,"last_valid":good,"context":"ctx","now":NOW+2.0});
    let mut cases = vec![base.clone()];
    for (path, value) in [
        ("/now", json!(NOW + 31.0)),
        ("/now", json!(NOW + 301.0)),
        ("/context", json!("changed")),
        ("/receipt", json!({})),
        ("/receipt", latest.clone()),
    ] {
        let mut case = base.clone();
        *case.pointer_mut(path).unwrap() = value;
        cases.push(case);
    }
    cases.push(
        json!({"receipt":latest,"last_valid":good,"context":"ctx","now":NOW+310.0,"launch":true}),
    );
    for (case, expected) in cases.iter().zip(oracle("dns_status", &cases)) {
        assert_eq!(
            receipts::dns_status(
                &case["receipt"],
                &case["last_valid"],
                case["context"].as_str().unwrap(),
                case["launch"].as_bool().unwrap_or(false),
                case["now"].as_f64().unwrap(),
                |v| format!("T{v:.0}")
            ),
            expected,
            "{case}"
        );
    }
    let statuses: Vec<_> = cases
        .iter()
        .map(|c| {
            receipts::dns_status(
                &c["receipt"],
                &c["last_valid"],
                c["context"].as_str().unwrap(),
                c["launch"].as_bool().unwrap_or(false),
                c["now"].as_f64().unwrap(),
                |v| format!("T{v:.0}"),
            )
        })
        .collect();
    for (status, expected) in statuses.iter().zip(oracle("dns_row", &statuses)) {
        assert_eq!(receipts::dns_row(status), expected);
    }
    let rtc = receipts::record_webrtc(&probe("webrtc", NOW), &local(), None, NOW + 1.0).unwrap();
    let cases = vec![
        json!({"receipt":rtc,"context":"ctx","now":NOW+2.0}),
        json!({"receipt":rtc,"context":"ctx","now":NOW+301.0}),
        json!({"receipt":rtc,"context":"other","now":NOW+2.0}),
        json!({"receipt":{},"context":"ctx","now":NOW+2.0}),
    ];
    for (case, expected) in cases.iter().zip(oracle("webrtc_status", &cases)) {
        assert_eq!(
            receipts::webrtc_status(
                &case["receipt"],
                case["context"].as_str().unwrap(),
                case["now"].as_f64().unwrap()
            ),
            expected
        );
    }
}
#[test]
fn unavailable_context_never_becomes_a_pass_or_a_confirmed_change() {
    let good = receipts::record_dns(&probe("dns", NOW), &local(), None, NOW + 1.0).unwrap();
    let mut unknown = probe("dns", NOW + 3.0);
    unknown["errors"] = json!([{"stage":"context","code":"context_unavailable"}]);
    // Even an observed foreign resolver cannot be attributed to an unverified context.
    unknown["externalJSON"] = json!(serde_json::to_string(&json!([
        {"kind":"geoip","status":"complete","query":"1.1.1.1","data":{"country_code":"JP"}},
        {"kind":"geoip","status":"complete","query":"8.8.8.8","data":{"country_code":"US"}}
    ]))
    .unwrap());
    let receipt = receipts::record_dns(&unknown, &local(), None, NOW + 4.0).unwrap();
    assert_eq!(receipt["comparison"]["state"], "unknown");
    assert_eq!(receipt["comparison"]["reason"], "context_unavailable");
    let status = receipts::dns_status(&receipt, &good, "ctx", true, NOW + 5.0, |v| v.to_string());
    assert_eq!(status["state"], "unknown");
    assert_eq!(status["display_cached"], false);
    let mut rtc = probe("webrtc", NOW);
    rtc["errors"] = json!([{"stage":"context","code":"context_unavailable"}]);
    assert_eq!(
        receipts::record_webrtc(&rtc, &local(), None, NOW + 1.0)
            .unwrap_err()
            .code,
        "webrtc_context_unavailable"
    );
}

#[test]
fn dns_history_never_hides_new_mismatch_or_context_change_and_never_authorizes_launch() {
    let f = Fixture::new();
    let now = NOW;
    f.store
        .record_dns(&probe("dns", now), &local(), None, now + 1.0)
        .unwrap();
    let mut timeout = probe("dns", now + 3.0);
    timeout["status"] = json!("timeout");
    timeout["errors"] = json!([{"stage":"dns","code":"timeout"}]);
    f.store
        .record_dns(&timeout, &local(), None, now + 4.0)
        .unwrap();
    let status = f
        .store
        .dns_status("ctx", true, now + 310.0, |v| v.to_string());
    assert_eq!(status["state"], "unknown");
    assert_eq!(status["display_cached"], true);
    assert_eq!(status["last_valid"]["expired"], true);
    timeout["contextChanged"] = json!(true);
    timeout["finishedAt"] = json!(now + 5.0);
    f.store
        .record_dns(&timeout, &local(), None, now + 6.0)
        .unwrap();
    assert_eq!(
        f.store
            .dns_status("ctx", false, now + 7.0, |v| v.to_string())["display_cached"],
        false
    );
    let mut foreign = probe("dns", now + 10.0);
    foreign["externalJSON"] = json!(serde_json::to_string(&json!({
        "session":"a".repeat(40), "dns_servers":{"8.8.8.8":5},
        "http":{"address":"1.1.1.1","country":"JP"},
        "geoip":[{"ip":"8.8.8.8","country_code":"US"}]
    }))
    .unwrap());
    foreign["status"] = json!("partial");
    foreign["errors"] = json!([{"stage":"lookup","code":"timeout"}]);
    f.store
        .record_dns(&foreign, &local(), None, now + 11.0)
        .unwrap();
    let status = f
        .store
        .dns_status("ctx", true, now + 12.0, |v| v.to_string());
    assert_eq!(status["state"], "fail");
    assert_eq!(status["display_cached"], false);
}
#[test]
fn late_probe_cannot_replace_a_newer_risk_and_context_mismatch_leaves_disk_untouched() {
    let f = Fixture::new();
    for kind in ["dns", "webrtc"] {
        let record = |probe: &Value, expected: Option<&str>, now: f64| {
            if kind == "dns" {
                f.store.record_dns(probe, &local(), expected, now)
            } else {
                f.store.record_webrtc(probe, &local(), expected, now)
            }
        };
        let path = f.store.storage.paths.base().join(if kind == "dns" {
            "dns-leak-receipt.json"
        } else {
            "webrtc-risk-receipt.json"
        });
        record(&probe(kind, NOW + 5.0), None, NOW + 6.0).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert_eq!(
            record(&probe(kind, NOW), None, NOW + 8.0).unwrap_err().code,
            "superseded_receipt"
        );
        assert!(record(&probe(kind, NOW + 10.0), Some("wrong"), NOW + 11.0).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}
#[test]
fn malformed_or_oversize_receipts_and_extended_expiry_cannot_produce_a_pass() {
    for kind in ["dns", "webrtc"] {
        let method = if kind == "dns" {
            receipts::record_dns
        } else {
            receipts::record_webrtc
        };
        for (key, value) in [
            ("observations", json!(vec![json!({}); 129])),
            ("errors", json!(vec![json!({}); 33])),
            ("contextChanged", Value::Null),
            ("finishedAt", json!("NaN")),
            ("finishedAt", json!(NOW + 7.0)),
            ("status", json!("available")),
            ("externalJSON", json!("x".repeat(800_000))),
        ] {
            let mut value_probe = probe(kind, NOW);
            value_probe[key] = value;
            assert!(
                method(&value_probe, &local(), None, NOW + 1.0).is_err(),
                "{kind} {key}"
            );
        }
    }
    let mut receipt = receipts::record_dns(&probe("dns", NOW), &local(), None, NOW + 1.0).unwrap();
    receipt["launch_expires_at"] = json!(NOW + 1000.0);
    assert_eq!(
        receipts::dns_status(&receipt, &json!({}), "ctx", true, NOW + 31.0, |v| v
            .to_string())["state"],
        "unknown"
    );
}
#[test]
fn webrtc_country_risk_and_candidate_mismatch_win_over_incomplete_samples() {
    for code in ["CN", "JP"] {
        let mut p = probe("webrtc", NOW);
        p["status"] = json!("partial");
        p["observations"][1]["address"] = json!("8.8.8.8");
        p["externalJSON"] = json!(serde_json::to_string(&json!([
            {"kind":"geoip","status":"complete","query":"8.8.8.8","data":{"country_code":code}}
        ]))
        .unwrap());
        let receipt = receipts::record_webrtc(&p, &local(), None, NOW + 1.0).unwrap();
        assert_eq!(receipt["risk"]["state"], "fail");
        assert_eq!(
            receipts::webrtc_status(&receipt, "ctx", NOW + 2.0)["state"],
            "fail"
        );
    }
    let mut p = probe("webrtc", NOW);
    p["observations"] = json!([
        {"kind":"http","address":"1.1.1.1"},{"kind":"host","address":"192.168.1.1"},
        {"kind":"relay","address":"8.8.8.8","country":"CN"},{"kind":"srflx","address":"1.1.1.1"}
    ]);
    let receipt = receipts::record_webrtc(&p, &local(), None, NOW + 1.0).unwrap();
    assert_eq!(receipt["risk"]["state"], "ok");
    assert_eq!(receipt["observations"].as_array().unwrap().len(), 2);
}

/// A realistic partially-answering round: the domestic servers answer, the
/// overseas one times out.  This is the shape that used to flip the row.
fn stun_probe(now: f64) -> Value {
    json!({"scope":"default","started_at":now-3.0,"finished_at":now,"complete":false,"missing":1,
        "observations":[
            {"server":"stun.miwifi.com","port":3478,"status":"ok","address":"1.1.1.1","accepted":true,
             "attempts":[{"attempt":1,"status":"ok","started_at":now-1.0,"finished_at":now}]},
            {"server":"stun.cloudflare.com","port":3478,"status":"timeout","address":"","accepted":false,
             "deadline_exceeded":true,
             "attempts":[{"attempt":1,"status":"timeout","stage":"receive","error":"no reply",
                          "started_at":now-3.0,"finished_at":now}]}]})
}

#[test]
fn a_stun_round_is_reused_only_while_fresh_and_bound_to_the_same_context() {
    let f = Fixture::new();
    let receipt = f
        .store
        .record_stun(&stun_probe(NOW), "ctx", NOW + 1.0)
        .unwrap();
    assert_eq!(receipt["schema"], 1);
    assert_eq!(receipt["kind"], "stun");
    assert_eq!(receipt["context_id"], "ctx");
    assert_eq!(receipt["sampled_at"], json!(NOW));
    // A fresh same-context round is reused instead of re-probed.
    assert_eq!(
        f.store.stun_fact("ctx", NOW + 60.0),
        Some(receipt["probe"].clone())
    );
    assert!(f.store.stun_fact("ctx", NOW + 300.0).is_some());
    // Past the window the caller must probe again.
    assert!(f.store.stun_fact("ctx", NOW + 300.5).is_none());
    assert!(f.store.stun_fact("ctx", NOW + 900.0).is_none());
    // A different egress context never inherits another context's answer.
    assert!(f.store.stun_fact("other", NOW + 60.0).is_none());
    assert!(f.store.stun_fact("", NOW + 60.0).is_none());
}

#[test]
fn a_missing_or_malformed_stun_receipt_is_never_reused() {
    let f = Fixture::new();
    assert!(f.store.stun_fact("ctx", NOW).is_none());
    for broken in [
        json!({"schema":2,"context_id":"ctx","sampled_at":NOW,"recorded_at":NOW,"probe":stun_probe(NOW)}),
        json!({"schema":1,"context_id":"ctx","sampled_at":NOW,"recorded_at":NOW}),
        json!({"schema":1,"context_id":"ctx","sampled_at":NOW,"recorded_at":NOW,"probe":[]}),
        json!({"schema":1,"context_id":"ctx","sampled_at":NOW,"recorded_at":NOW,"probe":{"observations":[]}}),
        json!({"schema":1,"context_id":"ctx","sampled_at":NOW,"recorded_at":NOW,"probe":{"observations":[1,2]}}),
        json!({"schema":1,"context_id":"ctx","sampled_at":NOW,"recorded_at":NOW-600.0,"probe":stun_probe(NOW)}),
        json!({"schema":1,"context_id":"ctx","recorded_at":NOW,"probe":stun_probe(NOW)}),
    ] {
        f.store
            .storage
            .atomic_json(
                &f.store.storage.paths.base().join("stun-receipt.json"),
                &broken,
            )
            .unwrap();
        assert!(
            f.store.stun_fact("ctx", NOW).is_none(),
            "must not reuse: {broken}"
        );
    }
}

#[test]
fn an_implausible_stun_round_is_refused_instead_of_being_cached() {
    let f = Fixture::new();
    let mut late = stun_probe(NOW);
    late["finished_at"] = json!(NOW - 200.0);
    late["started_at"] = json!(NOW - 203.0);
    assert!(f.store.record_stun(&late, "ctx", NOW).is_err());
    let mut huge = stun_probe(NOW);
    huge["observations"] = json!(vec![json!({"server":"s"}); 200]);
    assert!(f.store.record_stun(&huge, "ctx", NOW).is_err());
    assert!(f.store.record_stun(&json!([]), "ctx", NOW).is_err());
    assert!(f
        .store
        .record_stun(&json!({"started_at":NOW,"finished_at":NOW}), "ctx", NOW)
        .is_err());
    // A probe carrying no usable observation is neither cached nor (per
    // `stun_fact`) ever reused: an empty candidate set would read as zero
    // exposure, so a receipt without evidence must not produce a pass.
    assert!(f
        .store
        .record_stun(
            &json!({"started_at":NOW,"finished_at":NOW,"observations":[]}),
            "ctx",
            NOW
        )
        .is_err());
    assert!(f
        .store
        .record_stun(
            &json!({"started_at":NOW,"finished_at":NOW,"observations":[1,2]}),
            "ctx",
            NOW
        )
        .is_err());
}
