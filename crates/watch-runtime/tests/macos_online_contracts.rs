use claude_watch_core::{
    audit::{self, AuditInput},
    config::Config,
    error::Result,
    region::ZoneCatalog,
};
use claude_watch_runtime::{
    audit_store::AuditSystem,
    commands::{Output, ReadCommand, ReadRunner},
    macos::{Authority, Macos, Mutator},
    network_client::{NetworkClient, Request, Response, Transport, TransportError},
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

struct R;
impl ReadRunner for R {
    fn run(&self, _: ReadCommand, _: &[u8], _: Duration, _: usize) -> Result<Output> {
        Err(claude_watch_core::error::CoreError::new("unused", "unused"))
    }
}

#[derive(Clone, Copy)]
enum Lookup {
    CamelCase,
    /// Same payload as `CamelCase`, but RIPEstat answers with the `AS` prefix.
    RipePrefixed,
    CountryConflict,
    Failed,
    WrongIP,
    MissingIP,
}
struct T {
    lookup: Lookup,
    geo_calls: AtomicUsize,
    service_calls: AtomicUsize,
    chatgpt_calls: AtomicUsize,
}
impl Transport for T {
    fn get(&self, request: &Request) -> std::result::Result<Response, TransportError> {
        if request.url.contains("claude.ai") || request.url.contains("api.anthropic.com") {
            self.service_calls.fetch_add(1, Ordering::SeqCst);
        }
        if request.url.contains("chatgpt.com") || request.url.contains("api.openai.com") {
            self.chatgpt_calls.fetch_add(1, Ordering::SeqCst);
        }
        let ripe_asn = if matches!(self.lookup, Lookup::CountryConflict) {
            4134
        } else {
            13335
        };
        // Real payload shape: `resource` carries no `AS` prefix.
        let ripe_resource = if matches!(self.lookup, Lookup::RipePrefixed) {
            format!("AS{ripe_asn}")
        } else {
            ripe_asn.to_string()
        };
        let ripe_body = format!(
            r#"{{"data":{{"located_resources":[{{"resource":"{ripe_resource}","location":"US"}}],"result_time":"2026-10-27T00:00:00"}}}}"#
        );
        let (status, body, headers) = if request.url.contains("www.cloudflare.com") {
            (200, "ip=1.1.1.1\nloc=JP\n", HashMap::new())
        } else if request.url.contains("/api/ip/lookup/") {
            // Real payload shape: lowercase countryCode, no `timezone`, and no
            // timezone inside `geo_sources`.
            match self.lookup {
                Lookup::CamelCase | Lookup::RipePrefixed => (
                    200,
                    r#"{"ip":"1.1.1.1","country":"Japan","countryCode":"jp","asn":13335,"asOrganization":"Cloudflare, Inc.","geo_sources":[{"src":"g1","country":"Japan","country_code":"jp"}]}"#,
                    HashMap::new(),
                ),
                Lookup::CountryConflict => (
                    200,
                    r#"{"ip":"1.1.1.1","countryCode":"CN","timezone":"Asia/Shanghai","asn":4134,"asOrganization":"China Telecom"}"#,
                    HashMap::new(),
                ),
                Lookup::Failed => (503, "{}", HashMap::new()),
                Lookup::WrongIP => (
                    200,
                    r#"{"ip":"8.8.8.8","countryCode":"JP"}"#,
                    HashMap::new(),
                ),
                Lookup::MissingIP => (200, r#"{"countryCode":"JP"}"#, HashMap::new()),
            }
        } else if request.url.contains("/api/geoip/") {
            // Real payload shape: answers for the IP in the path and carries no
            // `ip` field and no timezone.
            self.geo_calls.fetch_add(1, Ordering::SeqCst);
            (
                200,
                r#"{"country":"Japan","region":"Tokyo","city":"Tokyo","isp":"au one net","country_code":"jp"}"#,
                HashMap::new(),
            )
        } else if request.url.contains("stat.ripe.net") {
            assert_eq!(
                request.url,
                format!(
                    "https://stat.ripe.net/data/rir-stats-country/data.json?resource=AS{ripe_asn}"
                )
            );
            (200, ripe_body.as_str(), HashMap::new())
        } else if request.url.contains("claude.ai") {
            let mut headers = HashMap::new();
            headers.insert("cf-mitigated".into(), "challenge".into());
            (403, "", headers)
        } else {
            (401, "", HashMap::new())
        };
        Ok(Response {
            status,
            headers,
            body: body.as_bytes().to_vec(),
        })
    }
}
struct M;
impl Mutator for M {
    fn apply(&mut self, _: &Value) -> Result<()> {
        Ok(())
    }
    fn restore(&mut self, _: &Value) -> Result<bool> {
        Ok(false)
    }
}

fn online(lookup: Lookup) -> (Value, Arc<T>) {
    online_target(
        lookup,
        claude_watch_core::processes::LaunchTarget::ClaudeDesktop,
    )
}
fn online_target(
    lookup: Lookup,
    target: claude_watch_core::processes::LaunchTarget,
) -> (Value, Arc<T>) {
    let root = std::env::temp_dir().join(format!("mac-online-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let transport = Arc::new(T {
        lookup,
        geo_calls: AtomicUsize::new(0),
        service_calls: AtomicUsize::new(0),
        chatgpt_calls: AtomicUsize::new(0),
    });
    let mut macos = Macos {
        runner: R,
        network: NetworkClient::new(transport.clone(), None).unwrap(),
        storage: StateStore::new(Paths::new(&root).unwrap()),
        authority: Authority::ReadOnly,
        mutator: M,
        probes: Arc::new(|| json!({"complete":false,"observations":[]})),
    };
    let value = AuditSystem::online_for_target(
        &mut macos,
        &Config::default(),
        &json!({"context_id":"ctx"}),
        target,
    )
    .unwrap();
    fs::remove_dir_all(root).unwrap();
    (value, transport)
}

#[test]
fn online_uses_bound_camel_case_lookup_for_geo_asn_and_registered_country() {
    let (out, transport) = online(Lookup::CamelCase);
    assert_eq!(out["trace"]["ip"], "1.1.1.1");
    assert_eq!(out["geo"]["country"], "JP");
    // The real lookup carries no timezone; a single-zone country is resolved
    // from the IANA catalog instead of a fallback round trip.
    assert!(out["geo"]["timezone"].is_null());
    assert_eq!(out["geo"]["country_source"], "Net.Coffee lookup");
    assert_eq!(out["asn"]["number"], 13335);
    assert_eq!(out["asn"]["organization"], "Cloudflare, Inc.");
    assert_eq!(out["asn"]["registered_country"], "US");
    assert!(
        out["query_errors"].get("asn").is_none(),
        "RIPEstat answers with a bare resource number and must still bind"
    );
    assert!(out["query_errors"].get("geo").is_none());
    assert_eq!(
        out["netcoffee_lookup"]["sourceURL"],
        "https://ip.net.coffee/api/ip/lookup/1.1.1.1"
    );
    assert!(out["netcoffee_lookup"].get("source_url").is_none());
    assert!(out["netcoffee_lookup"]["queriedAt"].is_number());
    assert!(out["netcoffee_lookup"]["finishedAt"].is_number());
    assert_eq!(out["netcoffee_lookup"]["httpStatus"], 200);
    assert_eq!(
        transport.geo_calls.load(Ordering::SeqCst),
        0,
        "a single-timezone country must not trigger a geo fallback"
    );
    assert_eq!(out["service_responses"]["claude"]["access"], "challenge");
    assert_eq!(
        out["service_responses"]["api"]["access"],
        "authentication_required"
    );
    let zones: ZoneCatalog = serde_json::from_value(json!({"JP":["Asia/Tokyo"]})).unwrap();
    let audit = audit::evaluate(
        AuditInput {
            config: &Config::default(),
            local: &json!({"proxy":"ok","tun":"ok","timezone":"Asia/Tokyo","locale":"ja_JP","ipv6":"ok","guard":true,"rules":{"state":"ok"},"language":"en","context":"ctx"}),
            online: &out,
            history: &[],
            zones: &zones,
            policy: "test",
            now: 1.0,
        },
        |_| "test".into(),
    )
    .unwrap();
    assert_eq!(
        audit["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == "egress")
            .unwrap()["state"],
        "ok"
    );
}

#[test]
fn registered_country_accepts_a_prefixed_ripe_resource() {
    let (out, _) = online(Lookup::RipePrefixed);
    assert_eq!(out["asn"]["registered_country"], "US");
    assert!(out["query_errors"].get("asn").is_none());
}

#[test]
fn lookup_country_conflict_remains_visible_and_never_uses_fallback() {
    let (out, transport) = online(Lookup::CountryConflict);
    assert_eq!(out["geo"]["country"], "CN");
    assert!(out["query_errors"].get("egress_consistency").is_some());
    assert_eq!(
        transport.geo_calls.load(Ordering::SeqCst),
        0,
        "a confirmed conflict cannot be hidden by geo fallback"
    );
}

#[test]
fn failed_lookup_uses_bound_geo_fallback_without_inventing_an_asn() {
    let (out, transport) = online(Lookup::Failed);
    assert_eq!(out["geo"]["country"], "JP");
    assert_eq!(out["geo"]["country_source"], "Net.Coffee geoip fallback");
    assert!(
        out["query_errors"].get("geo").is_none(),
        "the geoip endpoint returns no `ip`, so provenance comes from the query"
    );
    assert!(out["query_errors"].get("netcoffee").is_some());
    assert!(out["asn"]["number"].is_null());
    assert_eq!(transport.geo_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn missing_fields_are_query_failures_while_real_ip_conflicts_block_fallback() {
    let (missing, transport) = online(Lookup::MissingIP);
    assert!(missing["query_errors"]["egress_consistency"].is_null());
    assert!(missing["query_errors"].get("netcoffee").is_some());
    assert_eq!(missing["geo"]["country"], "JP");
    assert!(missing["query_errors"].get("geo").is_none());
    assert_eq!(transport.geo_calls.load(Ordering::SeqCst), 1);
    let (conflict, transport) = online(Lookup::WrongIP);
    assert!(conflict["query_errors"].get("egress_consistency").is_some());
    assert_eq!(transport.geo_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn observed_target_probes_only_its_own_service() {
    use claude_watch_core::processes::LaunchTarget;
    let (claude, transport) = online_target(Lookup::CamelCase, LaunchTarget::ClaudeDesktop);
    assert_eq!(transport.service_calls.load(Ordering::SeqCst), 2);
    assert!(claude["service_responses"].is_object());
    assert!(
        transport.chatgpt_calls.load(Ordering::SeqCst) == 0,
        "a Claude launch audit must not contact the ChatGPT endpoints"
    );
    for target in [LaunchTarget::CodexDesktop, LaunchTarget::ChatgptDesktop] {
        let (observed, transport) = online_target(Lookup::CamelCase, target);
        assert_eq!(
            transport.service_calls.load(Ordering::SeqCst),
            0,
            "a ChatGPT launch audit must not be decided by Claude's endpoint"
        );
        assert_eq!(
            transport.chatgpt_calls.load(Ordering::SeqCst),
            2,
            "the supervised service is measured on its own two endpoints"
        );
        assert_eq!(observed["trace"]["ip"], claude["trace"]["ip"]);
        assert_eq!(observed["trace"]["loc"], claude["trace"]["loc"]);
        assert_eq!(observed["geo"], claude["geo"]);
        assert!(observed["service_responses"]["chatgpt"].is_object());
        assert!(observed["service_responses"]["openai_api"].is_object());
        assert!(
            observed["service_responses"]["claude"].is_null(),
            "the other family's observation must never be attached"
        );
    }
}

#[test]
fn environment_observes_homepage_challenge_instead_of_trace_status() {
    let (out, _) = online(Lookup::CamelCase);
    let homepage = &out["service_responses"]["claude"];
    assert_eq!(homepage["source"], "https://claude.ai/");
    assert_eq!(homepage["http_status"], 403);
    assert_eq!(homepage["access"], "challenge");
    let (_, detail, _, _) = claude_watch_core::presentation::services(&out);
    // The card reports what the homepage actually answered. It does not
    // narrate a challenge page or a keyless API as a defect.
    assert!(detail.contains("已响应 HTTP 403"), "{detail}");
    assert!(detail.contains("已响应 HTTP 401"), "{detail}");
    assert!(!detail.contains("需要浏览器验证"), "{detail}");
    assert!(!detail.contains("未提供密钥"), "{detail}");
}
