use claude_watch_core::{
    config::Config,
    region::{self, ZoneCatalog},
    risk::{self, SessionRiskInput},
};
use serde_json::{json, Value};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

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
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn stun_ipv4_ipv6_and_invalid_frames_match_legacy() {
    use claude_watch_core::stun;
    let transaction = [7u8; 12];
    let mut packets = Vec::new();
    for address in [
        "8.8.8.8",
        "2001:4860:4860::8888",
        "::ffff:8.8.8.8",
        "192.168.1.1",
    ] {
        for xor in [false, true] {
            let ip = address.parse::<std::net::IpAddr>().unwrap();
            let (family, raw) = match ip {
                std::net::IpAddr::V4(v) => (1, v.octets().to_vec()),
                std::net::IpAddr::V6(v) => (2, v.octets().to_vec()),
            };
            let mut value = vec![0, family, 0, 0];
            let mask: Vec<_> = stun::COOKIE
                .iter()
                .chain(transaction.iter())
                .copied()
                .collect();
            value.extend(
                raw.iter()
                    .enumerate()
                    .map(|(i, v)| if xor { v ^ mask[i] } else { *v }),
            );
            let mut packet = stun::binding_request(transaction).to_vec();
            packet[0] = 1;
            packet[1] = 1;
            packet[2..4].copy_from_slice(&((value.len() + 4) as u16).to_be_bytes());
            packet.extend_from_slice(&(if xor { 0x20u16 } else { 1u16 }).to_be_bytes());
            packet.extend_from_slice(&(value.len() as u16).to_be_bytes());
            packet.extend(value);
            packets.push(packet);
        }
    }
    let mut wrong = packets[0].clone();
    wrong[8] = 8;
    packets.push(wrong);
    let mut truncated = packets[0].clone();
    truncated.push(0);
    packets.push(truncated);
    let mut no_address = stun::binding_request(transaction).to_vec();
    no_address[0] = 1;
    no_address[1] = 1;
    packets.push(no_address);
    let hex = |bytes: &[u8]| bytes.iter().map(|v| format!("{v:02x}")).collect::<String>();
    let cases: Vec<_> = packets
        .iter()
        .map(|v| json!({"packet":hex(v),"transaction":hex(&transaction)}))
        .collect();
    for (packet, expected) in packets.iter().zip(oracle("stun_decode", &cases)) {
        let actual = match stun::decode(packet, &transaction) {
            Ok(value) => json!({"value":value}),
            Err(code) => json!({"error":code}),
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn all_config_fields_match_legacy_defaults_and_normalization() {
    let cases = vec![
        json!({}),
        json!({"enabled":false,"guard_enabled":false}),
        json!({"country":"JP","timezone":"Asia/Tokyo","locale":"ja_JP","proxy_mode":"tag","proxy_url":"http://127.0.0.1:80/"}),
        json!({"country":"US","timezone":"America/Los_Angeles","locale":"en_US","expected_egress":["8.8.8.8","1.1.1.1","8.8.8.8"]}),
        json!({"update_url":"https://example.test/releases?channel=stable","verified_claude_versions":["1.0.0","2.0+test"],"locale":"en_JP@calendar=gregorian"}),
        json!({"enabled":1}),
        json!({"country":"jp"}),
        json!({"unknown":true}),
        json!({"proxy_url":"http://localhost:7890"}),
        json!({"expected_resolvers":["192.168.1.1"]}),
        json!({"expected_egress":["::ffff:8.8.8.8","8.8.8.8"]}),
        json!({"timezone":"../Tokyo"}),
        json!({"locale":"en_US_BAD"}),
    ];
    for (case, expected) in cases.iter().zip(oracle("config", &cases)) {
        let actual = match Config::from_value(case.clone()) {
            Ok(v) => json!({"value":v}),
            Err(e) => json!({"error":e.code}),
        };
        assert_eq!(actual, expected, "case={case}");
    }
}

#[test]
fn measured_region_and_no_fallback_behavior_match_legacy() {
    let zones = json!({"JP":["Asia/Tokyo"],"US":["America/New_York","America/Los_Angeles"]});
    let base = json!({"trace":{"ip":"1.1.1.1","loc":"JP"},"geo":{"ip":"1.1.1.1","country":"JP","timezone":"Asia/Tokyo"},"zones":zones});
    let mut cases = vec![base.clone()];
    for (path, value) in [
        ("/geo/timezone", Value::Null),
        ("/geo/timezone", json!("America/New_York")),
        ("/geo/ip", json!("8.8.8.8")),
        ("/trace/loc", json!("CN")),
    ] {
        let mut value_case = base.clone();
        *value_case.pointer_mut(path).unwrap() = value;
        cases.push(value_case);
    }
    cases.push(json!({"trace":{"ip":"1.1.1.1","loc":"US"},"geo":{"ip":"1.1.1.1","country":"US"},"zones":zones}));
    cases.push(json!({"trace":{},"geo":{},"zones":zones}));
    for (case, expected) in cases.iter().zip(oracle("region", &cases)) {
        let zones: ZoneCatalog = serde_json::from_value(case["zones"].clone()).unwrap();
        assert_eq!(
            region::reference(&case["trace"], &case["geo"], &zones),
            expected,
            "case={case}"
        );
    }
}

#[test]
fn actual_date_patterns_are_required_in_all_styles() {
    let patterns = json!({"short":"y/MM/dd","medium":"y/MM/dd","long":"y年M月d日"});
    let base = json!({"expected":"ja_JP","local":{"locale":"ja_JP","date_format":{"state":"available","configured_locale":"ja_JP","patterns":patterns,"reference_patterns":{"ja_JP":patterns},"short_sample":"2026/10/23","reference_samples":{"ja_JP":"2026/10/23"}}}});
    let mut cases = vec![base.clone()];
    for (path, value) in [
        ("/local/date_format/patterns/long", json!("different")),
        ("/local/date_format/patterns/medium", Value::Null),
        ("/local/date_format/configured_locale", json!("en_US")),
        ("/local/locale", json!("en_US")),
        ("/expected", Value::Null),
    ] {
        let mut value_case = base.clone();
        *value_case.pointer_mut(path).unwrap() = value;
        cases.push(value_case);
    }
    for (case, expected) in cases.iter().zip(oracle("dates", &cases)) {
        let local = &case["local"];
        let locale = case["expected"].as_str();
        assert_eq!(
            json!({"date":region::date_check(local,locale),"locale":region::locale_check(local,locale),"summary":region::date_summary(local),"expected":region::expected_date_summary(local,locale)}),
            expected
        );
    }
}

#[test]
fn china_conflicts_dns_webrtc_and_asn_risks_match_legacy() {
    let base = json!({"measured":{"country":"JP"},"online":{"trace":{"ip":"1.1.1.1","loc":"JP"},"geo":{"ip":"1.1.1.1","country":"JP"}}});
    let mut cases = vec![base.clone()];
    for addition in [
        json!({"trace":{"ip":"1.1.1.1","loc":"CN"}}),
        json!({"geo":{"ip":"8.8.8.8","country":"US"}}),
        json!({"dns":{"receipt":{"dns":{"countries":["JP","CN"]}}}}),
        json!({"webrtc":{"state":"fail","detail":"fixture","observations":[]}}),
        json!({"webrtc":{"state":"fail","observations":[{"country":"CN"}]}}),
        json!({"asn":{"registered_country":"CN"},"netcoffee_lookup":{"data":{"ip":"1.1.1.1"}}}),
        json!({"asn":{"registered_country":"CN"},"netcoffee_lookup":{"data":{"ip":"8.8.8.8"}}}),
        json!({"query_errors":{"egress_consistency":"conflict"}}),
    ] {
        let mut value_case = base.clone();
        value_case["online"]
            .as_object_mut()
            .unwrap()
            .extend(addition.as_object().unwrap().clone());
        cases.push(value_case);
    }
    for (case, expected) in cases.iter().zip(oracle("risks", &cases)) {
        assert_eq!(
            risk::extract_risks(&case["online"], &case["measured"]),
            expected,
            "case={case}"
        );
    }
}

#[test]
fn current_context_and_ip_bound_risk_receipts_match_legacy() {
    let base = json!({"now":1005.0,"context_id":"ctx","current_ip":"1.1.1.1","environment_receipts":[],
        "dns":{"state":"ok","detail":"DNS fixture","receipt":{"finished_at":1000.0,"http":{"egress_ips":["1.1.1.1"]},"dns":{"countries":["JP"]}}},
        "webrtc":{"state":"ok","detail":"RTC fixture","receipt":{"sampled_at":1002.0,"observations":[{"kind":"http","address":"1.1.1.1"}]}}});
    let mut cases = vec![base.clone()];
    for (path, value) in [
        ("/dns/state", json!("fail")),
        ("/dns/receipt/finished_at", json!(500.0)),
        ("/dns/receipt/dns/countries", json!(["CN"])),
        ("/dns/receipt/http/egress_ips", json!(["8.8.8.8"])),
        (
            "/webrtc/receipt/observations",
            json!([{"kind":"http","address":"1.1.1.1"},{"kind":"stun","address":"1.1.1.1","country":"CN"}]),
        ),
    ] {
        let mut value_case = base.clone();
        *value_case.pointer_mut(path).unwrap() = value;
        cases.push(value_case);
    }
    let mut facts = base.clone();
    facts["environment_receipts"] = json!([{"context_id":"ctx","observed_at":1001.0,"facts":{"measured":{"ip":"1.1.1.1"},"risks":[{"id":"cn_asn_registration","source":"asn","reason":"fixture"}]}}]);
    cases.push(facts);
    for (case, expected) in cases.iter().zip(oracle("session_risk", &cases)) {
        let receipts: Vec<Value> =
            serde_json::from_value(case["environment_receipts"].clone()).unwrap();
        let actual = risk::session_risk(&SessionRiskInput {
            dns: &case["dns"],
            webrtc: &case["webrtc"],
            environment_receipts: &receipts,
            context_id: case["context_id"].as_str().unwrap(),
            current_ip: case["current_ip"].as_str(),
            now: case["now"].as_f64().unwrap(),
        });
        assert_eq!(actual, expected, "case={case}");
    }
}
