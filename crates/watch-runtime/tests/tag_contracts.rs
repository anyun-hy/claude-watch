mod support;
use claude_watch_core::{
    tag_config as config,
    tag_flow::{self, CommandEvidence, CorrelationInput, Flow},
    time_parse,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use support::oracle;
const NOW: f64 = 1_700_000_000.0;
fn sample() -> Value {
    json!({"flow":{"pid":77,"protocol":"tcp","local":["127.0.0.1",50000],"peer":["127.0.0.1",7890]},
        "stamp":"Tue Nov 14 22:12:50 2023","process_start":NOW-30.0,"now":NOW,"interface":"utun4","group":"AI","expected_node":"JP11",
        "api":{"state":"available","mode":"rule","covers_7890":true,"selected_node":"JP11","global_node":"JP09", "route_chains":{"AI":["JP11","AI"],"GLOBAL":["JP09","GLOBAL"]}},
        "records":[{"id":"connection-1","start":"2023-11-14T22:13:15Z","metadata":{"sourceIP":"127.0.0.1","sourcePort":"50000","network":"tcp",
            "inboundIP":"127.0.0.1","inboundPort":"7890","destinationIP":"8.8.8.8","destinationPort":"443","destinationGeoIP":"jp","type":"HTTP","host":"api.anthropic.com"},
            "chains":["JP11","AI"],"rule":"DomainSuffix","rulePayload":"anthropic.com"}],"proofs":{}})
}
fn fake_sample() -> Value {
    let mut c = sample();
    c["flow"]["local"][0] = json!("198.18.0.1");
    c["flow"]["peer"] = json!(["198.18.1.10", 443]);
    let metadata = &mut c["records"][0]["metadata"];
    metadata["sourceIP"] = json!("198.18.0.1");
    metadata["type"] = json!("Tun");
    metadata["dnsMode"] = json!("fake-ip");
    metadata["destinationIP"] = json!("");
    c["proofs"]["connection-1"] = json!({"kind":"same_core_fakeip_mapping","host":"api.anthropic.com","address":"198.18.1.10","observed_at":NOW-0.5,"expires_at":NOW+0.5,
        "dns_endpoint":"127.0.0.1:5353","dns_owner_pid":100,"dns_owner_started":"Tue Nov 14 22:00:00 2023",
        "source_pid":77,"source_started":c["stamp"],"source":c["flow"]["local"],"peer":c["flow"]["peer"],"protocol":"tcp","connection_start":c["records"][0]["start"]});
    c
}
fn correlate(c: &Value) -> Value {
    let flow = Flow::from_value(c["flow"].clone()).unwrap();
    tag_flow::correlate(CorrelationInput {
        flow: &flow,
        stamp: c["stamp"].as_str().unwrap(),
        process_start: c["process_start"].as_f64(),
        api: &c["api"],
        records: c["records"].as_array().unwrap(),
        group: c["group"].as_str().unwrap(),
        expected_node: c["expected_node"].as_str().unwrap(),
        now: c["now"].as_f64().unwrap(),
        fakeip_evidence: &c["proofs"],
        interface: c["interface"].as_str(),
    })
}
#[test]
fn exact_flow_tuple_and_policy_matrix_match_legacy() {
    let good = sample();
    let mut cases = vec![good.clone()];
    for (path, value) in [
        ("/records/0/metadata/sourceIP", json!("::1")),
        ("/records/0/metadata/sourcePort", json!("50001")),
        ("/records/0/metadata/network", json!("udp")),
        ("/records/0/metadata/inboundPort", json!("7891")),
        ("/records/0/metadata/inboundIP", json!("8.8.8.8")),
        ("/records/0/metadata/type", json!("Tun")),
        ("/records/0/start", json!("2000-01-01T00:00:00Z")),
        ("/records/0/start", json!("2023-11-14T22:13:23Z")),
        ("/records/0/id", json!("")),
        ("/records/0/chains", json!([])),
        ("/records/0/chains", json!(["DIRECT"])),
        ("/records/0/chains", json!(["JP-other", "AI"])),
        ("/records/0/rule", json!("")),
        ("/records/0/metadata/destinationIP", json!("198.18.1.10")),
        ("/records/0/metadata/destinationIP", Value::Null),
        ("/records/0/metadata/destinationIP", json!("4000::1")),
        ("/records/0/metadata/destinationIP", json!("::ffff:8.8.8.8")),
        ("/api/state", json!("unavailable")),
        ("/api/covers_7890", json!(false)),
        ("/api/mode", json!("direct")),
        ("/api/mode", json!("unknown")),
        ("/api/route_chains", json!({})),
        ("/process_start", Value::Null),
        ("/records", json!([])),
        ("/records", json!([{"metadata":null},{"id":[]},"invalid"])),
        ("/flow/peer", json!(["127.0.0.1", 9001])),
    ] {
        let mut c = good.clone();
        *c.pointer_mut(path).unwrap() = value;
        cases.push(c);
    }
    let mut pid = good.clone();
    pid["records"][0]["metadata"]["processID"] = json!(88);
    cases.push(pid);
    let mut duplicate = good.clone();
    duplicate["records"] = json!([good["records"][0], good["records"][0]]);
    cases.push(duplicate.clone());
    let mut ambiguous = duplicate;
    ambiguous["records"][1]["id"] = json!("another");
    cases.push(ambiguous);
    let mut tun = good.clone();
    tun["flow"]["local"][0] = json!("198.18.0.1");
    tun["flow"]["peer"] = json!(["8.8.8.8", 443]);
    tun["records"][0]["metadata"]["sourceIP"] = json!("198.18.0.1");
    tun["records"][0]["metadata"]["type"] = json!("Tun");
    cases.push(tun);
    for (index, (c, expected)) in cases
        .iter()
        .zip(oracle("tag_correlate", &cases))
        .enumerate()
    {
        assert_eq!(correlate(c), expected, "case {index}: {c}");
    }
}
#[test]
fn same_core_fakeip_mapping_never_weakens_original_source_or_policy_checks() {
    let good = fake_sample();
    let mut cases = vec![good.clone()];
    for (path, value) in [
        ("/proofs", json!({})),
        ("/proofs/connection-1/host", json!("other.example")),
        ("/proofs/connection-1/address", json!("198.18.1.11")),
        ("/proofs/connection-1/source_pid", json!(78)),
        ("/proofs/connection-1/source", json!(["198.18.0.1", 50001])),
        ("/proofs/connection-1/source_started", json!("changed")),
        ("/proofs/connection-1/protocol", json!("udp")),
        ("/proofs/connection-1/connection_start", json!("changed")),
        ("/proofs/connection-1/expires_at", json!(NOW - 1.0)),
        ("/proofs/connection-1/observed_at", json!(NOW + 1.0)),
        ("/proofs/connection-1/expires_at", json!(NOW + 30.0)),
        ("/records/0/metadata/sourceIP", json!("198.18.0.2")),
        ("/records/0/metadata/destinationPort", json!("444")),
        ("/records/0/metadata/dnsMode", json!("normal")),
        ("/records/0/metadata/host", json!("other.example")),
        ("/records/0/metadata/destinationIP", json!("198.18.9.9")),
        ("/records/0/metadata/destinationIP", json!("invalid")),
        ("/records/0/metadata/destinationIP", json!("160.79.104.10")),
        ("/records/0/chains", json!(["JP-other", "AI"])),
    ] {
        let mut c = good.clone();
        *c.pointer_mut(path).unwrap() = value;
        cases.push(c);
    }
    for (index, (c, expected)) in cases
        .iter()
        .zip(oracle("tag_correlate", &cases))
        .enumerate()
    {
        assert_eq!(correlate(c), expected, "case {index}: {c}");
    }
    assert_eq!(correlate(&good)["association"], "correlated");
    let mut other = good.clone();
    other["records"][0]["chains"] = json!(["JP-other", "AI"]);
    let r = correlate(&other);
    assert_eq!(r["association"], "correlated");
    assert_eq!(r["policy"], "mismatch");
}
#[test]
fn public_destinations_and_rfc3339_nano_match_legacy_without_host_timezone_fallback() {
    let cases: Vec<_> = [
        "8.8.8.8",
        "198.18.0.1",
        "127.0.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "2001:4860:4860::8888",
        "4000::1",
        "::ffff:8.8.8.8",
        "ff02::1",
        "invalid",
        "",
    ]
    .iter()
    .map(|v| json!({"destinationIP":v,"destinationPort":"443","destinationGeoIP":"jp"}))
    .collect();
    for (case, expected) in cases.iter().zip(oracle("tag_destination", &cases)) {
        assert_eq!(tag_flow::destination_evidence(case), expected, "{case}");
    }
    let timestamps: Vec<_> = [
        "2023-11-14T22:13:15Z",
        "2023-11-14T22:13:15.123456789Z",
        "2023-11-15T07:13:15.999999999+09:00",
        "1970-01-01T00:00:00Z",
        "1969-12-31T23:59:59.5Z",
        "2000-02-29T13:59:59-03:00",
        "2023-02-29T00:00:00Z",
        "invalid",
    ]
    .iter()
    .map(|v| json!(v))
    .collect();
    for (c, expected) in timestamps.iter().zip(oracle("tag_epoch", &timestamps)) {
        assert_eq!(
            json!(time_parse::rfc3339(c.as_str().unwrap())),
            expected,
            "{c}"
        );
    }
}
#[test]
fn resolve_full_selection_chains_and_bounded_public_rule_tables_match_legacy() {
    let proxies = json!({"GLOBAL":{"type":"Selector","now":"AI"},"AI":{"type":"Selector","now":"JP"},"JP":{"type":"Shadowsocks"},"DIRECT":{"type":"Direct"}});
    let mut cases = vec![
        json!({"proxies":proxies,"group":"GLOBAL"}),
        json!({"proxies":proxies,"group":"AI"}),
        json!({"proxies":proxies,"group":"DIRECT"}),
        json!({"proxies":proxies,"group":"missing"}),
    ];
    let mut cycle = proxies.clone();
    cycle["AI"]["now"] = json!("GLOBAL");
    cases.push(json!({"proxies":cycle,"group":"GLOBAL"}));
    let mut absent = proxies.clone();
    absent["AI"] = json!({"type":"Selector","all":[]});
    cases.push(json!({"proxies":absent,"group":"GLOBAL"}));
    for (c, expected) in cases.iter().zip(oracle("tag_chain", &cases)) {
        assert_eq!(
            json!(config::resolve_chain(
                &c["proxies"],
                c["group"].as_str().unwrap()
            )),
            expected
        );
    }
    let rules = vec![
        json!({"rules":["DOMAIN-SUFFIX,claude.ai,GLOBAL","DOMAIN,unrelated.example,DIRECT","MATCH,GLOBAL"]}),
        json!({"rules":[{"type":"DomainSuffix","payload":"+.anthropic.com","proxy":"AI"},{"type":"DomainKeyword","payload":"private-set://TOKEN","proxy":"GLOBAL"},
            {"type":"IPCIDR","payload":"10.0.0.0/8","proxy":"DIRECT"},{"type":"Domain","payload":"user@private.invalid","proxy":"GLOBAL"}]}),
        json!({"rules":vec!["MATCH,GLOBAL";140]}),
    ];
    for (c, expected) in rules.iter().zip(oracle("tag_rules", &rules)) {
        let actual = config::published_rules(c).unwrap();
        assert_eq!(json!({"value":actual}), expected);
        assert!(!actual.to_string().contains("TOKEN"));
    }
    assert!(config::published_rules(&json!({"rules":"invalid"})).is_err());
    assert!(config::published_rules(&json!({"rules":vec!["MATCH,GLOBAL";16_385]})).is_err());
}
#[test]
fn a_disabled_ecosystem_rule_is_named_but_never_counted_as_coverage() {
    let published = config::published_rules(&json!({"rules":[
        {"type":"DomainSuffix","payload":"claude.ai","proxy":"AI"},
        {"type":"DomainSuffix","payload":"anthropic.com","proxy":"AI","extra":{"disabled":true}},
        {"type":"Domain","payload":"stripe.com","proxy":"AI","extra":{"disabled":false}},
        {"type":"Domain","payload":"unrelated.example","proxy":"AI","extra":{"disabled":true}},
    ]}))
    .unwrap();
    let entries: Vec<_> = published["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert!(entries.contains(&"DOMAIN-SUFFIX,claude.ai,AI".to_owned()));
    assert!(entries.contains(&"DOMAIN,stripe.com,AI".to_owned()));
    assert!(!entries.iter().any(|v| v.contains("anthropic")));
    // Only ecosystem domains are named; an unrelated disabled rule is noise.
    assert_eq!(published["disabled_domains"], json!(["anthropic.com"]));
}
#[test]
fn controller_credentials_are_loopback_only_and_never_appear_in_debug() {
    let valid: Vec<_> = [
        "external-controller: \"127.0.0.1:9090\"\nsecret: \"fixture-token\"\n",
        "external-controller: '[::1]:9090'\nsecret: 'quoted''token'\n",
        "external-controller: localhost:9090\nsecret: plain\n",
        "external-controller: LOCALHOST:9090\nsecret: plain\n",
    ]
    .iter()
    .map(|v| json!({"source":v}))
    .collect();
    for (c, expected) in valid.iter().zip(oracle("tag_controller", &valid)) {
        let credentials = config::controller_credentials(c["source"].as_str().unwrap()).unwrap();
        let auth = credentials.authorization().unwrap();
        let secret = auth.strip_prefix("Bearer ").unwrap();
        assert_eq!(json!({"value":[credentials.base(),secret]}), expected);
        assert!(!format!("{credentials:?}").contains(secret));
    }
    for authority in [
        "evil.example:9090",
        "127.1:9090",
        "127.0.0.1:9090/path",
        "user@127.0.0.1:9090",
        "127.0.0.1:0",
        "127.0.0.2:9090",
        "[::1%1]:9090",
    ] {
        assert!(config::controller_credentials(&format!(
            "external-controller: {authority}\nsecret: token\n"
        ))
        .is_err());
    }
    assert_eq!(
        config::controller_credentials(
            "external-controller: 127.0.0.1:9090\nsecret: first\nsecret: second\n"
        )
        .unwrap_err()
        .code,
        "duplicate_controller_field"
    );
    let scalars: Vec<_> = [
        "literal",
        "'quoted''value'",
        "\"space value\"",
        "literal # comment",
        "[invalid]",
        "!tag",
        "two words",
    ]
    .iter()
    .map(|v| json!({"source":v}))
    .collect();
    for (c, expected) in scalars.iter().zip(oracle("tag_scalar", &scalars)) {
        let actual = match config::yaml_scalar(c["source"].as_str().unwrap()) {
            Ok(v) => json!({"value":v}),
            Err(e) => json!({"error":e.code}),
        };
        assert_eq!(actual, expected);
    }
}
#[test]
fn fakeip_dns_config_and_normalized_hosts_preserve_boundaries() {
    let source="mixed-port: 7890\ndns:\n  enable: true\n  listen: :5353\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\nother: value\n";
    let mut cases = vec![json!({"source":source})];
    for (from, to) in [
        (":5353", "8.8.8.8:53"),
        ("198.18.0.1/16", "0.0.0.0/0"),
        ("enhanced-mode: fake-ip", "enhanced-mode: redir-host"),
    ] {
        cases.push(json!({"source":source.replace(from,to)}));
    }
    cases.push(json!({"source":format!("{source}dns:\n  listen: :53\n")}));
    for (c, expected) in cases.iter().zip(oracle("tag_dns_config", &cases)) {
        let actual = match config::fakeip_dns_config(c["source"].as_str().unwrap()) {
            Ok((port, range)) => json!({"value":[port,range.canonical()]}),
            Err(e) => json!({"error":e.code}),
        };
        assert_eq!(actual, expected, "{c}");
    }
    let hosts: Vec<_> = [
        "Claude.AI.",
        "api.anthropic.com",
        "127.0.0.1",
        "-bad.example",
        "a..example",
        "https://claude.ai",
        "claude.ai\nother",
        "a_b.example",
    ]
    .iter()
    .map(|v| json!(v))
    .collect();
    for (c, expected) in hosts.iter().zip(oracle("tag_host", &hosts)) {
        assert_eq!(
            json!(config::normalized_dns_host(c.as_str().unwrap())),
            expected
        );
    }
}
fn owner() -> Value {
    json!({"uid":501,"stamp":"Tue Nov 14 22:00:00 2023","executable":format!("{}mihomo-tag",tag_flow::TAG_BINARY_DIR)})
}
#[test]
fn stable_listener_identity_and_kernel_fallback_never_hide_inspection_errors() {
    let listener =
        json!({"status":0,"stdout":"p100\nn127.0.0.1:7890\n","stderr":"","source":"lsof"});
    let good = json!({"before":{"100":owner()},"after":{"100":owner()},"listener":listener,"reachable":true});
    let mut cases = vec![good.clone()];
    for (path, value) in [
        ("/reachable", json!(false)),
        ("/listener/stdout", json!("")),
        ("/listener/stderr", json!("permission denied")),
        ("/listener/stdout", json!("p100\nn*:7890\n")),
        ("/after/100/stamp", json!("changed")),
        ("/before", json!({})),
        (
            "/before/100/executable",
            json!("/tmp/TAG.app/Contents/Resources/bin/mihomo"),
        ),
    ] {
        let mut c = good.clone();
        *c.pointer_mut(path).unwrap() = value;
        cases.push(c);
    }
    let mut wrong = good.clone();
    wrong["before"]["100"]["executable"] = json!("/usr/bin/python3");
    wrong["after"] = wrong["before"].clone();
    cases.push(wrong);
    for (c, expected) in cases.iter().zip(oracle("tag_inspect", &cases)) {
        assert_eq!(
            tag_flow::inspect_entry(
                &serde_json::from_value(c["before"].clone()).unwrap(),
                &serde_json::from_value(c["after"].clone()).unwrap(),
                &serde_json::from_value(c["listener"].clone()).unwrap(),
                c["reachable"].as_bool().unwrap(),
                501
            ),
            expected,
            "{c}"
        );
    }
    let kernel = json!({"status":0,"stdout":"tcp4 0 0 127.0.0.1.7890 *.* LISTEN 0 0 131072 131072 mihomo:100 00180\n","stderr":"","source":"netstat"});
    let empty = json!({"status":1,"stdout":"","stderr":"","source":"lsof"});
    let mut cases = vec![json!({"lsof":empty,"kernel":kernel})];
    for (path, value) in [
        ("/lsof/stderr", json!("permission denied")),
        (
            "/kernel/stdout",
            json!("tcp4 0 0 127.0.0.1.7890 *.* LISTEN 0 0 unknown:0\n"),
        ),
        ("/kernel/status", json!(1)),
    ] {
        let mut c = cases[0].clone();
        *c.pointer_mut(path).unwrap() = value;
        cases.push(c);
    }
    for (c, expected) in cases.iter().zip(oracle("tag_listener_fallback", &cases)) {
        let kernel = serde_json::from_value(c["kernel"].clone()).unwrap();
        assert_eq!(
            json!(tag_flow::listener_fallback(
                serde_json::from_value(c["lsof"].clone()).unwrap(),
                Some(&kernel)
            )),
            expected
        );
    }
}
#[test]
fn same_core_dns_listener_requires_unique_matching_owner_and_stable_start_identity() {
    let good = json!({"kernel":{"status":0,"stdout":"tcp4 0 0 *.5353 *.* LISTEN 0 0 131072 131072 mihomo:100\n","stderr":"","source":"netstat"},
        "owner":{"pid":100,"uid":501,"stamp":"Tue Nov 14 22:00:00 2023","executable":format!("{}mihomo-tag",tag_flow::TAG_BINARY_DIR)},
        "processes":{"100":owner()},"port":5353});
    let mut cases = vec![good.clone()];
    for (path, value) in [
        ("/kernel/stderr", json!("denied")),
        (
            "/kernel/stdout",
            json!("tcp4 0 0 *.5353 *.* LISTEN 0 0 other:999\n"),
        ),
        ("/processes/100/stamp", json!("changed")),
        ("/port", json!(5354)),
    ] {
        let mut c = good.clone();
        *c.pointer_mut(path).unwrap() = value;
        cases.push(c);
    }
    for (c, expected) in cases.iter().zip(oracle("tag_dns_listener", &cases)) {
        let kernel: CommandEvidence = serde_json::from_value(c["kernel"].clone()).unwrap();
        let processes: BTreeMap<u32, Value> =
            serde_json::from_value(c["processes"].clone()).unwrap();
        assert_eq!(
            json!(tag_flow::dns_listener_matches(
                &kernel,
                c["port"].as_u64().unwrap() as u16,
                &c["owner"],
                &processes,
                501
            )),
            expected
        );
    }
}
#[test]
fn api_snapshot_uses_actual_mode_and_rule_failure_does_not_erase_verified_selection() {
    let base = json!({"group":"AI","/configs":{"mode":"global","mixed-port":7890},"/proxies":{"proxies":{"GLOBAL":{"type":"Selector","now":"JP09"},"AI":{"type":"Selector","now":"JP11"},"JP09":{"type":"Shadowsocks"},"JP11":{"type":"Shadowsocks"}}},"/connections":{"connections":[]},"/rules":{"rules":[]}});
    let mut cases = vec![base.clone()];
    let mut rule = base.clone();
    rule["/configs"]["mode"] = json!("rule");
    cases.push(rule);
    let mut broken = base.clone();
    broken["rules_error"] = json!(404);
    cases.push(broken);
    for (c, expected) in cases.iter().zip(oracle("tag_api_snapshot", &cases)) {
        let rules = if let Some(code) = c["rules_error"].as_u64() {
            json!({"state":"unavailable","reason":format!("控制接口规则表 HTTP {code}"),"entries":[]})
        } else {
            config::published_rules(&c["/rules"]).unwrap()
        };
        let result = config::api_snapshot(
            "http://127.0.0.1:9090",
            c["group"].as_str().unwrap(),
            &c["/configs"],
            &c["/proxies"],
            &c["/connections"],
            rules,
        )
        .unwrap();
        assert_eq!(json!([result.0, result.1]), expected);
    }
}
#[test]
fn a_group_chain_parked_on_a_bypass_target_is_a_direct_group() {
    let configs = json!({"mode":"rule","mixed-port":7890});
    let proxies = json!({"proxies":{
        "GLOBAL":{"type":"Selector","now":"JP"},
        "AI":{"type":"Selector","now":"DIRECT"},
        "外层":{"type":"Selector","now":"内层"},
        "内层":{"type":"Selector","now":"REJECT"},
        "代理组":{"type":"Selector","now":"JP"},
        "JP":{"type":"Shadowsocks"}
    }});
    let result = config::api_snapshot(
        "http://127.0.0.1:9090",
        "AI",
        &configs,
        &proxies,
        &json!({"connections":[]}),
        json!({"state":"available","entries":[]}),
    )
    .unwrap()
    .0;
    assert_eq!(result["direct_groups"], json!(["AI", "内层", "外层"]));
    // A group on a real node is never a direct group, however nested.
    assert!(!result["direct_groups"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "代理组" || v == "GLOBAL"));
}
#[test]
fn endpoints_and_schema_do_not_convert_uncertain_samples_into_a_bypass() {
    assert_eq!(
        tag_flow::parse_endpoint("[fe80::1%utun4]:443 (ESTABLISHED)").unwrap(),
        ("fe80::1".into(), 443)
    );
    for value in [
        "localhost:443",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "unrelated",
    ] {
        assert!(tag_flow::parse_endpoint(value).is_err());
    }
    for (path, value) in [
        ("/pid", json!(1)),
        ("/protocol", json!("sctp")),
        ("/local/0", json!("localhost")),
        ("/peer/1", json!(0)),
    ] {
        let mut c = sample()["flow"].clone();
        *c.pointer_mut(path).unwrap() = value;
        assert!(Flow::from_value(c).is_err());
    }
    let mut duplicate = fake_sample();
    duplicate["records"] = json!([duplicate["records"][0], duplicate["records"][0]]);
    assert_eq!(correlate(&duplicate)["association"], "unconfirmed");
}
fn snapshot(configs: &Value, proxies: &Value) -> Value {
    config::api_snapshot(
        "http://127.0.0.1:9090",
        "",
        configs,
        proxies,
        &json!({"connections":[]}),
        json!({"state":"available","entries":[]}),
    )
    .unwrap()
    .0
}
#[test]
fn a_global_group_without_an_entry_leaves_the_selection_unresolved() {
    let configs = json!({"mode":"global","mixed-port":7890});
    let proxies = json!({"proxies":{
        "node-a":{"type":"Shadowsocks"},
        "node-b":{"type":"Shadowsocks"}
    }});
    let result = snapshot(&configs, &proxies);
    assert!(result["selected_node"].is_null());
    assert!(
        !result["direct_groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "GLOBAL"),
        "组不存在不应被列入 direct_groups"
    );
}
#[test]
fn a_global_group_parked_on_direct_is_null_and_listed() {
    let proxies = json!({"proxies":{
        "GLOBAL":{"type":"Selector","now":"DIRECT"},
        "DIRECT":{"type":"Direct"},
        "node-a":{"type":"Shadowsocks"}
    }});
    let result = snapshot(&json!({"mode":"global","mixed-port":7890}), &proxies);
    assert!(result["selected_node"].is_null(), "直连不产生节点");
    assert!(result["direct_groups"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "GLOBAL"));
}
#[test]
fn a_global_group_parked_on_reject_is_null_and_listed() {
    let proxies = json!({"proxies":{
        "GLOBAL":{"type":"Selector","now":"REJECT"},
        "REJECT":{"type":"Reject"},
        "node-a":{"type":"Shadowsocks"}
    }});
    let result = snapshot(&json!({"mode":"global","mixed-port":7890}), &proxies);
    assert!(result["selected_node"].is_null());
    // 注意：REJECT 是拒绝出站，与 DIRECT 语义相反，却进同一个列表。
    assert!(result["direct_groups"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "GLOBAL"));
}
/// 记录 0B 必须处理的盲点：COMPATIBLE 让 resolve_chain 返回 null，
/// 但 group_is_direct 不认它，于是“null 且不在 direct_groups”出现了反例。
/// 这条只记录当前输出，不代表该输出安全。
#[test]
fn a_global_group_parked_on_compatible_is_null_but_not_listed() {
    let proxies = json!({"proxies":{
        "GLOBAL":{"type":"Selector","now":"COMPATIBLE"},
        "COMPATIBLE":{"type":"Compatible"},
        "node-a":{"type":"Shadowsocks"}
    }});
    let result = snapshot(&json!({"mode":"global","mixed-port":7890}), &proxies);
    assert!(result["selected_node"].is_null());
    assert!(
        !result["direct_groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "GLOBAL"),
        "COMPATIBLE 不在 group_is_direct 的名单里，因此不会被收录"
    );
}
#[test]
fn a_global_group_parked_on_a_real_node_selects_that_node() {
    let proxies = json!({"proxies":{
        "GLOBAL":{"type":"Selector","now":"node-a"},
        "node-a":{"type":"Shadowsocks"},
        "node-b":{"type":"Shadowsocks"}
    }});
    let result = snapshot(&json!({"mode":"global","mixed-port":7890}), &proxies);
    assert_eq!(result["selected_node"], "node-a");
    assert!(!result["direct_groups"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "GLOBAL"));
}

/// 交叉验证：把上面五组夹具原样交给 Python 参考实现，
/// 只比对「选中节点」与「direct_groups」，确认两侧在这五种输入下判断一致。
#[test]
fn global_selection_outputs_match_the_python_reference() {
    let fixtures = [
        json!({"proxies":{
            "node-a":{"type":"Shadowsocks"},
            "node-b":{"type":"Shadowsocks"}
        }}),
        json!({"proxies":{
            "GLOBAL":{"type":"Selector","now":"DIRECT"},
            "DIRECT":{"type":"Direct"},
            "node-a":{"type":"Shadowsocks"}
        }}),
        json!({"proxies":{
            "GLOBAL":{"type":"Selector","now":"REJECT"},
            "REJECT":{"type":"Reject"},
            "node-a":{"type":"Shadowsocks"}
        }}),
        json!({"proxies":{
            "GLOBAL":{"type":"Selector","now":"COMPATIBLE"},
            "COMPATIBLE":{"type":"Compatible"},
            "node-a":{"type":"Shadowsocks"}
        }}),
        json!({"proxies":{
            "GLOBAL":{"type":"Selector","now":"node-a"},
            "node-a":{"type":"Shadowsocks"},
            "node-b":{"type":"Shadowsocks"}
        }}),
    ];
    let cases: Vec<Value> = fixtures
        .iter()
        .map(|proxies| {
            json!({"group":"","/configs":{"mode":"global","mixed-port":7890},
                "/proxies":proxies,"/connections":{"connections":[]},"/rules":{"rules":[]}})
        })
        .collect();
    let reference = oracle("tag_api_snapshot", &cases);
    let groups = |v: &Value| -> Vec<String> {
        let mut names: Vec<String> = v["direct_groups"]
            .as_array()
            .map(|a| a.iter().map(|x| x.as_str().unwrap_or("").to_owned()).collect())
            .unwrap_or_default();
        names.sort();
        names
    };
    for (index, (case, pair)) in cases.iter().zip(reference).enumerate() {
        // 参考实现与 Rust 同形：返回 [快照, 连接表] 二元组。
        let py = &pair[0];
        assert!(
            py.get("error").is_none(),
            "第 {index} 组：Python 参考实现报错 {py}"
        );
        let rust = snapshot(&case["/configs"], &case["/proxies"]);
        assert_eq!(
            rust["selected_node"], py["selected_node"],
            "第 {index} 组选中节点与 Python 参考不一致"
        );
        assert_eq!(
            groups(&rust),
            groups(&py),
            "第 {index} 组 direct_groups 与 Python 参考不一致"
        );
    }
}
