use claude_watch_runtime::network_client::*;
use claude_watch_runtime::storage::{Paths, StateStore};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
struct Fixture {
    calls: AtomicUsize,
    status: u16,
    body: String,
}
impl Transport for Fixture {
    fn get(&self, _: &Request) -> Result<Response, TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Response {
            status: self.status,
            headers: HashMap::new(),
            body: self.body.as_bytes().to_vec(),
        })
    }
}
struct ProcessFixture {
    calls: std::path::PathBuf,
}
impl Transport for ProcessFixture {
    fn get(&self, _: &Request) -> Result<Response, TransportError> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.calls)
            .unwrap();
        file.write_all(b"request\n").unwrap();
        file.sync_all().unwrap();
        thread::sleep(Duration::from_millis(180));
        Ok(Response {
            status: 200,
            headers: HashMap::new(),
            body: br#"{"ip":"1.1.1.1"}"#.to_vec(),
        })
    }
}
fn client(f: Arc<Fixture>) -> NetworkClient<Fixture> {
    NetworkClient::new(f, Some("http://127.0.0.1:7890".into())).unwrap()
}
#[test]
fn metadata_validates_identity_and_reuses_a_shared_singleflight_cache() {
    let f = Arc::new(Fixture {
        calls: AtomicUsize::new(0),
        status: 200,
        body: r#"{"ip":"1.1.1.1","country_code":"JP"}"#.into(),
    });
    let c = client(f.clone());
    let mut joins = vec![];
    for _ in 0..8 {
        let c = c.clone();
        joins.push(thread::spawn(move || c.metadata("lookup", "1.1.1.1")));
    }
    let values: Vec<_> = joins.into_iter().map(|j| j.join().unwrap()).collect();
    assert!(values.iter().all(|r| r.status == "complete"));
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    assert_eq!(c.metadata("lookup", "1.1.1.1").cache_state, "hit");
    let bad = Arc::new(Fixture {
        calls: AtomicUsize::new(0),
        status: 200,
        body: r#"{"ip":"8.8.8.8"}"#.into(),
    });
    assert_eq!(client(bad).metadata("lookup", "1.1.1.1").status, "error");
}
#[test]
fn backoff_retains_history_but_never_reports_stale_success_as_current() {
    let f = Arc::new(Fixture {
        calls: AtomicUsize::new(0),
        status: 429,
        body: "limited".into(),
    });
    let c = client(f.clone());
    let one = c.metadata("geoip", "1.1.1.1");
    assert_eq!(one.status, "error");
    let two = c.metadata("geoip", "1.1.1.1");
    assert_eq!(two.cache_state, "backoff");
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    assert!(two.retry_after.unwrap() > 0.0);
}
#[test]
fn ripe_country_requires_exact_asn_and_one_country() {
    let f=Arc::new(Fixture{calls:AtomicUsize::new(0),status:200,body:r#"{"data":{"located_resources":[{"resource":"AS13335","location":"US"},{"resource":"AS13335x","location":"CN"}]}}"#.into()});
    let r = client(f).ripe_asn(13335);
    assert_eq!(ripe_registered_country(&r, 13335).as_deref(), Some("US"));
    assert!(NetworkClient::new(
        Arc::new(Fixture {
            calls: AtomicUsize::new(0),
            status: 200,
            body: "{}".into()
        }),
        Some("http://example.com:7890".into())
    )
    .is_err());
}
#[test]
fn known_401_and_cloudflare_403_are_metadata_not_successful_login() {
    let api = Receipt {
        kind: "trace".into(),
        query: "".into(),
        source_url: "https://api.anthropic.com/v1/models".into(),
        queried_at: 1.,
        finished_at: 1.,
        status: "error".into(),
        http_status: Some(401),
        raw: String::new(),
        data: None,
        error: Some("HTTP 401".into()),
        context_id: None,
        measurement_at: None,
        response_headers: HashMap::new(),
        transport: String::new(),
        cache_state: "miss".into(),
        cache_age: None,
        retry_after: None,
        last_good: None,
    };
    let c = Receipt {
        http_status: Some(403),
        source_url: "https://claude.ai/cdn-cgi/trace".into(),
        response_headers: HashMap::from([("cf-mitigated".into(), "challenge".into())]),
        ..api.clone()
    };
    assert_eq!(
        service_observation("api", &api)["access"],
        "authentication_required"
    );
    assert_eq!(
        service_observation("claude", &c)["challenge"]["provider"],
        "cloudflare"
    );
}

#[test]
fn homepage_reachability_is_separate_from_the_egress_trace() {
    struct Endpoints(std::sync::Mutex<Vec<Request>>);
    impl Transport for Endpoints {
        fn get(&self, request: &Request) -> Result<Response, TransportError> {
            self.0.lock().unwrap().push(request.clone());
            match request.url.as_str() {
                "https://claude.ai/" => Ok(Response {
                    status: 403,
                    headers: HashMap::from([("cf-mitigated".into(), "challenge".into())]),
                    body: b"page body must not be retained".to_vec(),
                }),
                "https://claude.ai/cdn-cgi/trace" => Ok(Response {
                    status: 200,
                    headers: HashMap::new(),
                    body: b"ip=1.1.1.1\n".to_vec(),
                }),
                _ => panic!("unexpected endpoint"),
            }
        }
    }
    let transport = Arc::new(Endpoints(Default::default()));
    let client = NetworkClient::new(transport.clone(), Some(DEFAULT_PROXY.into())).unwrap();
    let homepage = client.claude_homepage();
    let observed = service_observation("claude", &homepage);
    assert_eq!(homepage.source_url, "https://claude.ai/");
    assert_eq!(homepage.http_status, Some(403));
    assert!(homepage.raw.is_empty());
    assert_eq!(observed["access"], "challenge");
    assert_eq!(observed["challenge"]["provider"], "cloudflare");
    let egress = client.service_metadata("claude");
    assert_eq!(egress.source_url, "https://claude.ai/cdn-cgi/trace");
    assert_eq!(trace_ip(&egress).as_deref(), Some("1.1.1.1"));
    let requests = transport.0.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].max_body, 0);
    assert!(requests[0].safe_headers.is_empty());
    assert_eq!(requests[0].proxy.as_deref(), Some(DEFAULT_PROXY));
    assert!(requests[1].max_body > 0);
}

#[test]
fn homepage_200_needs_no_json_page_body() {
    let transport = Arc::new(Fixture {
        calls: AtomicUsize::new(0),
        status: 200,
        body: "<html>fixture</html>".into(),
    });
    let result = client(transport).claude_homepage();
    assert_eq!(result.status, "complete");
    assert_eq!(result.http_status, Some(200));
    assert!(result.raw.is_empty());
    assert_eq!(
        service_observation("claude", &result)["transport_reached"],
        true
    );
}

#[test]
fn homepage_timeout_stays_unknown() {
    struct Timeout;
    impl Transport for Timeout {
        fn get(&self, _: &Request) -> Result<Response, TransportError> {
            Err(TransportError::new("timeout", "fixture timeout"))
        }
    }
    let client = NetworkClient::new(Arc::new(Timeout), None).unwrap();
    let result = client.claude_homepage();
    let observed = service_observation("claude", &result);
    assert_eq!(result.status, "timeout");
    assert_eq!(observed["transport_reached"], false);
    assert_eq!(observed["status"], "unknown");
    assert_eq!(
        claude_watch_core::presentation::service_response(
            "claude",
            &observed,
            &serde_json::Value::Null
        )
        .0,
        "unknown"
    );
}

#[test]
fn metadata_context_requires_a_current_explicit_egress_measurement() {
    let fixture = Arc::new(Fixture {
        calls: AtomicUsize::new(0),
        status: 200,
        body: r#"{"ip":"1.1.1.1"}"#.into(),
    });
    let client = client(fixture);
    let current = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let receipt = client.metadata_for_context("lookup", "round-42", "1.1.1.1", current);
    assert_eq!(receipt.context_id.as_deref(), Some("round-42"));
    assert_eq!(receipt.measurement_at, Some(current));
    assert_eq!(
        client
            .metadata_for_context("lookup", "round-43", "1.1.1.1", current - 31.0)
            .status,
        "error"
    );
}

#[test]
fn private_state_store_reuses_metadata_between_client_instances() {
    let root = std::env::temp_dir().join(format!("watch-network-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    let store = StateStore::new(Paths::new(&root).unwrap());
    let fixture = Arc::new(Fixture {
        calls: AtomicUsize::new(0),
        status: 200,
        body: r#"{"ip":"1.1.1.1"}"#.into(),
    });
    let first = client(fixture.clone()).with_state_store(store.clone());
    assert_eq!(first.metadata("lookup", "1.1.1.1").cache_state, "miss");
    let second = client(fixture.clone()).with_state_store(store);
    assert_eq!(second.metadata("lookup", "1.1.1.1").cache_state, "hit");
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn durable_failure_cooldown_does_not_extend_or_issue_a_second_request() {
    let root = std::env::temp_dir().join(format!("watch-network-cooldown-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    let store = StateStore::new(Paths::new(&root).unwrap());
    let fixture = Arc::new(Fixture {
        calls: AtomicUsize::new(0),
        status: 429,
        body: String::new(),
    });
    let first = client(fixture.clone())
        .with_state_store(store.clone())
        .metadata("lookup", "1.1.1.1");
    let second = client(fixture.clone())
        .with_state_store(store)
        .metadata("lookup", "1.1.1.1");
    assert_eq!(first.status, "error");
    assert_eq!(second.cache_state, "backoff");
    assert!(second.retry_after.unwrap() > 890.0);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn production_transport_can_read_a_bounded_local_http_response() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0; 512];
        let used = socket.read(&mut request).unwrap();
        let received = std::str::from_utf8(&request[..used]).unwrap();
        let accepts: Vec<_> = received
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.eq_ignore_ascii_case("accept"))
            .map(|(_, value)| value.trim())
            .collect();
        assert_eq!(
            accepts,
            ["application/dns-json"],
            "the real HTTP request must not include a second default Accept header"
        );
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });
    let receipt = UreqTransport
        .get(&Request {
            url: format!("http://{address}/fixture"),
            proxy: None,
            timeout: std::time::Duration::from_secs(1),
            connect_timeout: Some(std::time::Duration::from_millis(200)),
            max_body: 16,
            safe_headers: vec![("Accept".into(), "application/dns-json".into())],
        })
        .unwrap();
    server.join().unwrap();
    assert_eq!(receipt.status, 200);
    assert_eq!(receipt.body, b"ok");
}

#[test]
fn status_only_transport_preserves_403_headers_without_waiting_for_page_body() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (release, wait) = std::sync::mpsc::channel();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0; 512];
        let used = socket.read(&mut request).unwrap();
        let received = std::str::from_utf8(&request[..used]).unwrap();
        let accepts: Vec<_> = received
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.eq_ignore_ascii_case("accept"))
            .map(|(_, value)| value.trim())
            .collect();
        assert_eq!(
            accepts,
            ["application/json, text/plain;q=0.9"],
            "ordinary diagnostic requests retain their default Accept header"
        );
        socket.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 1000000\r\nCF-Mitigated: challenge\r\nConnection: close\r\n\r\n").unwrap();
        let _ = wait.recv_timeout(Duration::from_secs(2));
    });
    let result = UreqTransport.get(&Request {
        url: format!("http://{address}/fixture"),
        proxy: None,
        timeout: Duration::from_secs(1),
        connect_timeout: None,
        max_body: 0,
        safe_headers: vec![],
    });
    let _ = release.send(());
    server.join().unwrap();
    let response = result.unwrap();
    assert_eq!(response.status, 403);
    assert_eq!(
        response.headers.get("cf-mitigated").map(String::as_str),
        Some("challenge")
    );
    assert!(response.body.is_empty());
}

#[test]
fn production_transport_classifies_a_real_global_deadline_as_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0; 512];
        let _ = socket.read(&mut request).unwrap();
        thread::sleep(std::time::Duration::from_millis(250));
    });
    let error = UreqTransport
        .get(&Request {
            url: format!("http://{address}/slow"),
            proxy: None,
            timeout: std::time::Duration::from_millis(50),
            connect_timeout: Some(std::time::Duration::from_millis(50)),
            max_body: 16,
            safe_headers: vec![],
        })
        .unwrap_err();
    server.join().unwrap();
    assert_eq!(error.code, "timeout");
}

#[test]
fn trace_and_collection_keep_service_and_reference_exit_evidence_separate() {
    let trace = Receipt {
        kind: "trace".into(),
        query: String::new(),
        source_url: "https://claude.ai/cdn-cgi/trace".into(),
        queried_at: 1.0,
        finished_at: 1.0,
        status: "complete".into(),
        http_status: Some(200),
        raw: "colo=NRT\nip=1.1.1.1\n".into(),
        data: None,
        error: None,
        context_id: None,
        measurement_at: None,
        response_headers: HashMap::new(),
        transport: String::new(),
        cache_state: "miss".into(),
        cache_age: None,
        retry_after: None,
        last_good: None,
    };
    assert_eq!(trace_ip(&trace).as_deref(), Some("1.1.1.1"));
    assert!(trace_ip(&Receipt {
        raw: "xip=1.1.1.1".into(),
        ..trace
    })
    .is_none());
}

#[test]
fn lookup_asn_requires_an_explicit_valid_prefix() {
    let base = Receipt {
        kind: "lookup".into(),
        query: "1.1.1.1".into(),
        source_url: String::new(),
        queried_at: 0.0,
        finished_at: 0.0,
        status: "complete".into(),
        http_status: Some(200),
        raw: String::new(),
        data: Some(serde_json::json!({"org":"AS13335 Cloudflare"})),
        error: None,
        context_id: None,
        measurement_at: None,
        response_headers: HashMap::new(),
        transport: String::new(),
        cache_state: String::new(),
        cache_age: None,
        retry_after: None,
        last_good: None,
    };
    assert_eq!(lookup_asn(&base), Some(13335));
    assert_eq!(
        lookup_asn(&Receipt {
            data: Some(serde_json::json!({"org":"cloud AS13335"})),
            ..base
        }),
        None
    );
}

#[test]
fn state_store_singleflight_coalesces_independent_processes() {
    if let Ok(root) = std::env::var("WATCH_NETWORK_SINGLEFLIGHT_CHILD") {
        let root = std::path::PathBuf::from(root);
        let store = StateStore::new(Paths::new(&root).unwrap());
        let calls = root.join("calls.log");
        let receipt = NetworkClient::new(
            Arc::new(ProcessFixture { calls }),
            Some("http://127.0.0.1:7890".into()),
        )
        .unwrap()
        .with_timeout(Duration::from_secs(2))
        .with_state_store(store)
        .metadata("lookup", "1.1.1.1");
        assert!(
            matches!(receipt.cache_state.as_str(), "miss" | "hit"),
            "{receipt:?}"
        );
        return;
    }
    let root =
        std::env::temp_dir().join(format!("watch-network-singleflight-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    StateStore::new(Paths::new(&root).unwrap())
        .initialize()
        .unwrap();
    let executable = std::env::current_exe().unwrap();
    let mut children = Vec::new();
    for _ in 0..2 {
        children.push(
            std::process::Command::new(&executable)
                .arg("--exact")
                .arg("state_store_singleflight_coalesces_independent_processes")
                .arg("--nocapture")
                .env("WATCH_NETWORK_SINGLEFLIGHT_CHILD", &root)
                .spawn()
                .unwrap(),
        );
    }
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    let count = std::fs::read_to_string(root.join("calls.log"))
        .unwrap()
        .lines()
        .count();
    std::fs::remove_dir_all(root).unwrap();
    assert_eq!(count, 1, "only the lock holder may issue the first request");
}
#[test]
fn production_transport_keeps_body_deadlines_distinct_from_parse_failures() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut bytes = [0; 512];
        let _ = socket.read(&mut bytes);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n")
            .unwrap();
        thread::sleep(std::time::Duration::from_millis(250));
    });
    let error = UreqTransport
        .get(&Request {
            url: format!("http://{address}/slow-body"),
            proxy: None,
            timeout: std::time::Duration::from_millis(60),
            connect_timeout: None,
            max_body: 32,
            safe_headers: vec![],
        })
        .unwrap_err();
    server.join().unwrap();
    assert_eq!(error.code, "timeout");
}

#[test]
fn fresh_child_route_probe_uses_its_verified_proxy_and_never_the_metadata_cache() {
    struct Route(std::sync::Mutex<Vec<Request>>);
    impl Transport for Route {
        fn get(&self, r: &Request) -> Result<Response, TransportError> {
            self.0.lock().unwrap().push(r.clone());
            Ok(Response {
                status: 200,
                headers: HashMap::new(),
                body: b"ip=1.1.1.1\nloc=JP\n".to_vec(),
            })
        }
    }
    let transport = Arc::new(Route(Default::default()));
    let c = NetworkClient::new(transport.clone(), None).unwrap();
    assert_eq!(c.fast_egress_via(Some(DEFAULT_PROXY)).status, "complete");
    assert_eq!(c.fast_egress_via(Some(DEFAULT_PROXY)).status, "complete");
    assert_eq!(c.fast_egress().status, "complete");
    let calls = transport.0.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].proxy.as_deref(), Some(DEFAULT_PROXY));
    assert_eq!(calls[1].proxy.as_deref(), Some(DEFAULT_PROXY));
    assert_eq!(calls[2].proxy, None);
    assert!(calls.iter().all(|r| r.url == FAST_EGRESS_URL));
    drop(calls);
    assert_eq!(
        c.fast_egress_via(Some("http://remote.invalid:7890")).status,
        "error"
    );
    assert_eq!(transport.0.lock().unwrap().len(), 3);
}
