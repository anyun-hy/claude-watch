mod support;
use claude_watch_core::{
    error::{CoreError, Result},
    tag_flow::{self, CommandEvidence, Flow},
};
use claude_watch_runtime::fakeip_probe::{self, Input, SampledFlow, Source};
use serde_json::{json, Value};
use std::{collections::BTreeMap, time::Duration};
use support::oracle;
const NOW: f64 = 1_700_000_000.0;
fn sample() -> Value {
    let stamp = "Tue Nov 14 22:12:50 2023";
    let owner = json!({"pid":100,"uid":501,"stamp":"Tue Nov 14 22:00:00 2023","executable":"/Applications/TAG.app/Contents/Resources/bin/mihomo-tag"});
    json!({"now":NOW,"process_start":NOW-30.0,"source":"dns:\n  enable: true\n  listen: :5353\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n",
        "entry":{"state":"verified","owners":[owner]},"api":{"state":"available"},"kernel":{"status":0,"stdout":"tcp4 0 0 *.5353 *.* LISTEN 0 0 131072 131072 mihomo:100\n","stderr":"","source":"netstat"},
        "processes":{"100":owner,"77":{"uid":501,"stamp":stamp}},
        "flows":[{"flow":{"pid":77,"protocol":"tcp","local":["198.18.0.1",50000],"peer":["198.18.1.10",443]},"stamp":stamp,"valid":true}],
        "records":[{"id":"conn-1","start":"2023-11-14T22:13:15Z","metadata":{"type":"Tun","sourceIP":"198.18.0.1","sourcePort":"50000","destinationIP":"","destinationPort":"443","network":"tcp","dnsMode":"fake-ip","host":"claude.ai"},"chains":["JP11","AI"],"rule":"DomainSuffix","rulePayload":"claude.ai"}]})
}
struct MockSource {
    case: Value,
    after: bool,
    calls: usize,
    queries: usize,
    listeners: usize,
    mono: Duration,
    deadlines: Vec<Duration>,
}
impl MockSource {
    fn new(case: &Value) -> Self {
        Self {
            case: case.clone(),
            after: false,
            calls: 0,
            queries: 0,
            listeners: 0,
            mono: Duration::ZERO,
            deadlines: Vec::new(),
        }
    }
}
impl Source for MockSource {
    fn now(&self) -> f64 {
        self.case["now"].as_f64().unwrap()
            + if self.after {
                self.case["after_query_elapsed"].as_f64().unwrap_or(0.0)
            } else {
                0.0
            }
    }
    fn monotonic(&mut self) -> Duration {
        self.mono
    }
    fn config(&mut self) -> Result<String> {
        self.calls += 1;
        Ok(if self.after {
            self.case
                .get("current_source")
                .unwrap_or(&self.case["source"])
        } else {
            &self.case["source"]
        }
        .as_str()
        .unwrap()
        .into())
    }
    fn listeners(&mut self) -> Result<CommandEvidence> {
        self.calls += 1;
        self.listeners += 1;
        Ok(serde_json::from_value(
            if self.after {
                self.case
                    .get("after_kernel")
                    .unwrap_or(&self.case["kernel"])
            } else {
                &self.case["kernel"]
            }
            .clone(),
        )
        .unwrap())
    }
    fn route_interface(&mut self, _address: &str) -> Result<String> {
        self.calls += 1;
        Ok(self.case["interface"].as_str().unwrap_or("utun4").into())
    }
    fn query_dns(&mut self, _host: &str, _port: u16, timeout: Duration) -> Result<(String, u32)> {
        self.calls += 1;
        self.queries += 1;
        self.deadlines.push(timeout);
        self.mono +=
            Duration::from_secs_f64(self.case["query_mono_elapsed"].as_f64().unwrap_or(0.0));
        if self.case["query_error"] == true {
            return Err(CoreError::new("fixture_timeout", "fixture"));
        }
        let answer = self
            .case
            .get("answer")
            .cloned()
            .unwrap_or(json!(["198.18.1.10", 1]));
        Ok((
            answer[0].as_str().unwrap().into(),
            answer[1].as_u64().unwrap() as u32,
        ))
    }
    fn connections(&mut self) -> Result<Vec<Value>> {
        self.calls += 1;
        self.after = true;
        Ok(self
            .case
            .get("current_records")
            .unwrap_or(&self.case["records"])
            .as_array()
            .unwrap()
            .clone())
    }
    fn processes(&mut self) -> Result<BTreeMap<u32, Value>> {
        self.calls += 1;
        Ok(serde_json::from_value(
            self.case
                .get("current_processes")
                .unwrap_or(&self.case["processes"])
                .clone(),
        )
        .unwrap())
    }
}
fn collect(c: &Value) -> (fakeip_probe::Collected, MockSource) {
    let flows: Vec<_> = c["flows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| SampledFlow {
            flow: Flow::from_value(s["flow"].clone()).unwrap(),
            stamp: s["stamp"].as_str().unwrap().into(),
            process_start: c["process_start"].as_f64(),
            valid: s["valid"].as_bool().unwrap(),
        })
        .collect();
    let processes = serde_json::from_value(c["processes"].clone()).unwrap();
    let kernel = serde_json::from_value(c["kernel"].clone()).unwrap();
    let mut source = MockSource::new(c);
    let result = fakeip_probe::collect(
        &mut source,
        Input {
            entry: &c["entry"],
            api: &c["api"],
            records: c["records"].as_array().unwrap(),
            flows: &flows,
            processes: &processes,
            listener_snapshot: c["snapshot_at"].as_f64().map(|at| (&kernel, at)),
            uid: 501,
        },
    );
    (result, source)
}
#[test]
fn full_same_core_collection_and_recheck_failures_match_original() {
    let good = sample();
    let mut cases = vec![good.clone()];
    for (path, value) in [
        ("/entry/state", json!("unconfirmed")),
        ("/api/state", json!("unavailable")),
        ("/flows", json!([])),
        ("/flows/0/valid", json!(false)),
        ("/flows/0/flow/peer", json!(["198.19.1.10", 443])),
        ("/records/0/metadata/host", json!("-bad.example")),
        ("/records/0/metadata/destinationPort", json!("444")),
        ("/records/0/metadata/destinationIP", json!("198.18.9.9")),
        (
            "/kernel/stdout",
            json!("tcp4 0 0 *.5353 *.* LISTEN 0 0 other:999\n"),
        ),
        ("/processes/100/stamp", json!("changed")),
    ] {
        let mut c = good.clone();
        *c.pointer_mut(path).unwrap() = value;
        cases.push(c);
    }
    for (key, value) in [
        ("answer", json!(["198.18.1.11", 1])),
        ("answer", json!(["8.8.8.8", 1])),
        ("query_error", json!(true)),
        ("interface", json!("en0")),
        ("current_records", json!([])),
        ("after_query_elapsed", json!(3.0)),
        ("snapshot_at", json!(NOW - 6.0)),
        ("snapshot_at", json!(NOW)),
        (
            "current_source",
            json!(good["source"].as_str().unwrap().replace(":5353", ":5354")),
        ),
    ] {
        let mut c = good.clone();
        c[key] = value;
        cases.push(c);
    }
    for (kind, value) in [
        ("host", json!("other.example")),
        ("destinationPort", json!("444")),
    ] {
        let mut c = good.clone();
        c["current_records"] = good["records"].clone();
        c["current_records"][0]["metadata"][kind] = value;
        cases.push(c);
    }
    for pid in ["100", "77"] {
        let mut c = good.clone();
        c["current_processes"] = good["processes"].clone();
        c["current_processes"][pid]["stamp"] = json!("changed");
        cases.push(c);
    }
    let mut duplicate = good.clone();
    duplicate["records"] = json!([good["records"][0], good["records"][0]]);
    cases.push(duplicate);
    let mut ambiguous = good.clone();
    let mut other = good["records"][0].clone();
    other["id"] = json!("other-id");
    other["metadata"]["host"] = json!("other.example");
    ambiguous["records"] = json!([good["records"][0], other]);
    cases.push(ambiguous);
    for (index, (c, expected)) in cases
        .iter()
        .zip(oracle("tag_fake_collect", &cases))
        .enumerate()
    {
        let (result, source) = collect(c);
        assert_eq!(
            json!({"proofs":result.proofs,"calls":source.queries}),
            expected,
            "case {index}: {c}"
        );
    }
}
#[test]
fn queries_are_capped_at_eight_and_have_one_hard_budget() {
    let mut c = sample();
    let flow = c["flows"][0].clone();
    let record = c["records"][0].clone();
    let mut flows = Vec::new();
    let mut records = Vec::new();
    for i in 0..10 {
        let mut f = flow.clone();
        f["flow"]["local"][1] = json!(50000 + i);
        let mut r = record.clone();
        r["id"] = json!(format!("id-{i}"));
        r["metadata"]["sourcePort"] = json!((50000 + i).to_string());
        r["metadata"]["host"] = json!(format!("h{i}.example"));
        flows.push(f);
        records.push(r);
    }
    c["flows"] = json!(flows);
    c["records"] = json!(records);
    let (result, source) = collect(&c);
    assert_eq!(source.queries, 8);
    assert_eq!(result.proofs.as_object().unwrap().len(), 8);
    assert!(source
        .deadlines
        .iter()
        .all(|d| *d <= Duration::from_millis(350)));
    let expected = oracle("tag_fake_collect", std::slice::from_ref(&c)).remove(0);
    assert_eq!(
        json!({"proofs":result.proofs,"calls":source.queries}),
        expected
    );
    c["query_mono_elapsed"] = json!(2.0);
    let (result, source) = collect(&c);
    assert_eq!(source.queries, 1);
    assert!(result.proofs.as_object().unwrap().is_empty());
    assert_eq!(result.attempts[0]["accepted"], false);
    assert_eq!(result.attempts[0]["state"], "deadline_exceeded");
}
#[test]
fn pid_reuse_with_same_second_stamp_is_rejected_when_native_identity_is_available() {
    for pid in ["100", "77"] {
        let mut c = sample();
        c["processes"][pid]["start_seconds"] = json!(1699999000);
        c["processes"][pid]["start_microseconds"] = json!(10);
        if pid == "100" {
            c["entry"]["owners"][0]["start_seconds"] = json!(1699999000);
            c["entry"]["owners"][0]["start_microseconds"] = json!(10);
        }
        c["current_processes"] = c["processes"].clone();
        c["current_processes"][pid]["start_microseconds"] = json!(11);
        assert!(collect(&c).0.proofs.as_object().unwrap().is_empty());
    }
}
#[test]
fn dns_answer_parser_matches_single_record_identity_ttl_and_error_contract() {
    let good = json!({"stdout":";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 123\nclaude.ai. 4 IN A 198.18.1.10\n","stderr":"","status":0,"host":"claude.ai"});
    let mut cases = vec![good.clone()];
    for (path, value) in [
        ("/stderr", json!("failed")),
        ("/status", json!(1)),
        ("/stdout", json!("")),
        (
            "/stdout",
            json!(";; status: NOERROR\nclaude.ai. 0 IN A 198.18.1.10\n"),
        ),
        (
            "/stdout",
            json!(";; status: NOERROR\nother.example. 1 IN A 198.18.1.10\n"),
        ),
        (
            "/stdout",
            json!(";; status: NOERROR\nclaude.ai. 1 IN CNAME other.example.\n"),
        ),
        ("/stdout", json!(";; status: SERVFAIL\n")),
    ] {
        let mut c = good.clone();
        *c.pointer_mut(path).unwrap() = value;
        cases.push(c);
    }
    let mut dup = good.clone();
    dup["stdout"] = json!(format!(
        "{}claude.ai. 1 IN A 198.18.1.10\n",
        good["stdout"].as_str().unwrap()
    ));
    cases.push(dup);
    for (c, expected) in cases.iter().zip(oracle("tag_dns_answer", &cases)) {
        let actual = match tag_flow::parse_dns_answer(
            c["stdout"].as_str().unwrap(),
            c["stderr"].as_str().unwrap(),
            c["status"].as_i64().unwrap() as i32,
            c["host"].as_str().unwrap(),
        ) {
            Ok(v) => json!({"value":[v.0,v.1]}),
            Err(e) => json!({"error":e.code}),
        };
        assert_eq!(actual, expected, "{c}");
    }
}
#[test]
fn no_fake_flow_or_untrusted_listener_does_not_query_dns_or_read_controller_credentials() {
    let mut c = sample();
    c["flows"] = json!([]);
    let (result, source) = collect(&c);
    assert!(result.proofs.as_object().unwrap().is_empty());
    assert_eq!(source.calls, 0);
    let mut c = sample();
    c["kernel"]["stderr"] = json!("denied");
    let (_, source) = collect(&c);
    assert_eq!(source.queries, 0);
}
