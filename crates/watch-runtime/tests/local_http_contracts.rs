use claude_watch_core::tag_config::Credentials;
use claude_watch_runtime::local_http::{Client, Error};
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

fn response(status: u16, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} fixture\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}
fn fixture(responses: Vec<Vec<u8>>, delay: Duration) -> (Client, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let until = Instant::now() + Duration::from_secs(4);
        let mut requests = Vec::new();
        for response in responses {
            let mut stream: TcpStream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until =>
                    {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("fixture listener: {e}"),
                }
            };
            // macOS may inherit O_NONBLOCK from the listener.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 2048];
            while !request.ends_with(b"\r\n\r\n") {
                let count = stream.read(&mut buf).unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buf[..count]);
                assert!(request.len() <= 32768);
            }
            requests.push(String::from_utf8(request).unwrap());
            thread::sleep(delay);
            let _ = stream.write_all(&response);
        }
        requests
    });
    let credentials =
        Credentials::from_parts(&endpoint.to_string(), "fixture-token".into()).unwrap();
    (Client::new(credentials), server)
}

#[test]
fn fast_snapshot_shares_deadline_with_closing_consistency_request() {
    let configs = response(200, r#"{"mode":"rule","mixed-port":7890,"revision":"r1"}"#);
    let proxies = response(200, r#"{"proxies":{"AI":{"name":"AI","type":"Selector","now":"US"},"US":{"name":"US","type":"Trojan"}}}"#);
    // Each response fits the 800ms per-request timeout. Together the final
    // consistency check exceeds the 240ms budget and must yield no snapshot.
    let (client, server) = fixture(vec![configs.clone(), proxies, configs], Duration::from_millis(90));
    let started = Instant::now();
    let result = client.with_timeout(Duration::from_millis(800))
        .observe_fast_vpn_state_before("AI", "127.0.0.1", Some(7890), false,
            started + Duration::from_millis(240));
    assert_eq!(result.unwrap_err(), Error::Timeout);
    assert!(started.elapsed() < Duration::from_millis(600));
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[2].starts_with("GET /configs "));
}

#[test]
fn expired_snapshot_budget_issues_no_http_request() {
    let credentials = Credentials::from_parts("127.0.0.1:1", String::new()).unwrap();
    let result = Client::new(credentials).observe_fast_vpn_state_before(
        "AI", "127.0.0.1", Some(7890), true, Instant::now(),
    );
    assert_eq!(result.unwrap_err(), Error::Timeout);
}
#[test]
fn real_loopback_get_is_authenticated_bounded_and_has_no_mutating_method_or_body() {
    let (client, server) = fixture(vec![response(200, r#"{"mode":"rule"}"#)], Duration::ZERO);
    assert_eq!(client.get("/configs").unwrap(), json!({"mode":"rule"}));
    let requests = server.join().unwrap();
    assert!(requests[0].starts_with("GET /configs HTTP/1.1\r\n"));
    let headers = requests[0].to_ascii_lowercase();
    assert!(headers.contains("authorization: bearer fixture-token\r\n"));
    assert!(headers.contains("connection: close\r\n"));
    assert!(!requests[0].contains("Content-Length:"));
    assert!(requests[0].ends_with("\r\n\r\n"));
    for path in [
        "/restart",
        "/configs?force=true",
        "http://evil.invalid/",
        "/cache/dns/flush",
        "/connections/123",
    ] {
        assert_eq!(client.get(path).unwrap_err(), Error::Path);
    }
}
#[test]
fn chunked_and_connection_close_frames_are_decoded_without_redirecting() {
    for wire in [b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"x\":\r\n2;safe=1\r\n1}\r\n0\r\nX-Fixture: value\r\n\r\n".to_vec(),
        b"HTTP/1.0 200 OK\r\n\r\n{\"x\":1}".to_vec()] {
        let(client,server)=fixture(vec![wire],Duration::ZERO);assert_eq!(client.get("/configs").unwrap(),json!({"x":1}));server.join().unwrap();
    }
    let(client,server)=fixture(vec![b"HTTP/1.1 302 Found\r\nLocation: http://evil.invalid/private\r\nContent-Length: 0\r\n\r\n".to_vec()],Duration::ZERO);
    assert_eq!(client.get("/configs").unwrap_err(), Error::Status(302));
    assert_eq!(server.join().unwrap().len(), 1);
}
#[test]
fn ambiguous_framing_duplicate_json_and_oversize_bodies_never_produce_api_evidence() {
    for (wire, error) in [
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nContent-Length: 8\r\n\r\n{\"x\":1}".to_vec(),
            Error::Protocol,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nTransfer-Encoding: chunked\r\n\r\n{\"x\":1}"
                .to_vec(),
            Error::Protocol,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n".to_vec(),
            Error::TooLarge,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\n".to_vec(),
            Error::Transport,
        ),
        (
            response(200, r#"{"mode":"rule","mode":"direct"}"#),
            Error::Json,
        ),
        (response(200, "[]"), Error::Json),
        (response(200, "NaN"), Error::Json),
        (
            b"INVALID/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"x\":1}".to_vec(),
            Error::Protocol,
        ),
        (b"HTTP/1.1 000 Invalid\r\n\r\n".to_vec(), Error::Protocol),
        (
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n".to_vec(),
            Error::Protocol,
        ),
    ] {
        let (client, server) = fixture(vec![wire], Duration::ZERO);
        assert_eq!(client.get("/configs").unwrap_err(), error);
        server.join().unwrap();
    }
    let mut huge = b"HTTP/1.1 200 OK\r\nX-Fixture: ".to_vec();
    huge.extend(vec![b'a'; 33_000]);
    huge.extend(b"\r\n\r\n");
    let (client, server) = fixture(vec![huge], Duration::ZERO);
    assert_eq!(client.get("/configs").unwrap_err(), Error::TooLarge);
    server.join().unwrap();
}
#[test]
fn deadline_is_enforced_and_authentication_error_does_not_echo_response_or_token() {
    let (client, server) = fixture(vec![response(200, "{}")], Duration::from_millis(350));
    let start = Instant::now();
    assert_eq!(
        client
            .with_timeout(Duration::from_millis(100))
            .get("/configs")
            .unwrap_err(),
        Error::Timeout
    );
    assert!(start.elapsed() < Duration::from_millis(320));
    server.join().unwrap();
    let (client, server) = fixture(
        vec![response(401, "private-token-and-response-body")],
        Duration::ZERO,
    );
    let error = client.get("/configs").unwrap_err();
    assert_eq!(error, Error::Status(401));
    assert!(!error.to_string().contains("token"));
    server.join().unwrap();
}
#[test]
fn real_four_endpoint_snapshot_retains_verified_mode_when_rules_endpoint_fails() {
    let (client, server) = fixture(
        vec![
            response(200, r#"{"mode":"global","mixed-port":7890}"#),
            response(
                200,
                r#"{"proxies":{"GLOBAL":{"type":"Selector","now":"JP"},"JP":{"type":"Shadowsocks"}}}"#,
            ),
            response(200, r#"{"connections":[]}"#),
            response(404, "private-error"),
        ],
        Duration::ZERO,
    );
    let (report, records) = client.snapshot("");
    assert_eq!(report["state"], "available");
    assert_eq!(report["mode"], "global");
    assert_eq!(report["selected_node"], "JP");
    assert_eq!(report["rules"]["state"], "unavailable");
    assert!(records.is_empty());
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 4);
    for (request, path) in requests
        .iter()
        .zip(["/configs", "/proxies", "/connections", "/rules"])
    {
        assert!(request.starts_with(&format!("GET {path} ")));
    }
    assert!(!report.to_string().contains("fixture-token"));
    assert!(!report.to_string().contains("private-error"));
}

#[test]
fn streamed_chunked_payload_is_stopped_at_the_actual_four_mib_body_limit() {
    let size = 4 * 1024 * 1024 + 1;
    let mut wire =
        format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size:x}\r\n").into_bytes();
    wire.extend(vec![b'x'; size]);
    wire.extend(b"\r\n0\r\n\r\n");
    let (client, server) = fixture(vec![wire], Duration::ZERO);
    assert_eq!(client.get("/connections").unwrap_err(), Error::TooLarge);
    server.join().unwrap();
}
