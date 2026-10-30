use claude_watch_runtime::stun_probe::{self, Endpoint, NativeRequester, ProbeError, Requester};
use std::{
    net::UdpSocket,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
fn endpoint() -> Endpoint {
    Endpoint {
        host: "fixture".into(),
        port: 3478,
    }
}
struct Retry {
    calls: AtomicUsize,
    invalid: bool,
}
impl Requester for Retry {
    fn request(&self, _: &Endpoint, _: Instant) -> Result<String, ProbeError> {
        let count = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.invalid {
            return Err(ProbeError::new(
                "validation",
                "unexpected_sender",
                "fixture",
            ));
        }
        if count == 0 {
            Err(ProbeError::new("receive", "timeout", "fixture"))
        } else {
            Ok("8.8.8.8".into())
        }
    }
}
#[test]
fn retry_keeps_both_attempts_and_invalid_sender_never_retries() {
    for invalid in [false, true] {
        let client = Arc::new(Retry {
            calls: AtomicUsize::new(0),
            invalid,
        });
        let result = stun_probe::probe_with_delay(
            &[endpoint()],
            client.clone(),
            Duration::from_secs(1),
            Duration::ZERO,
        );
        let row = &result.observations[0];
        assert_eq!(result.complete, !invalid);
        assert_eq!(
            client.calls.load(Ordering::SeqCst),
            if invalid { 1 } else { 2 }
        );
        assert_eq!(row.attempts.len(), if invalid { 1 } else { 2 });
        if !invalid {
            assert_eq!(row.attempts[0].status, "timeout");
            assert_eq!(row.address.as_deref(), Some("8.8.8.8"));
        }
    }
}
#[test]
fn zero_budget_and_empty_server_list_never_report_success() {
    let client = Arc::new(Retry {
        calls: AtomicUsize::new(0),
        invalid: false,
    });
    let servers: Vec<_> = (0..4)
        .map(|i| Endpoint {
            host: format!("fixture-{i}"),
            port: 3478,
        })
        .collect();
    let result = stun_probe::probe(&servers, client.clone(), Duration::ZERO);
    assert!(!result.complete);
    assert_eq!(result.missing, 4);
    assert_eq!(client.calls.load(Ordering::SeqCst), 0);
    assert!(!stun_probe::probe(&[], client, Duration::from_secs(1)).complete);
}
struct Slow {
    calls: AtomicUsize,
    gate: (Mutex<bool>, Condvar),
    fail_first: bool,
}
impl Requester for Slow {
    fn request(&self, _: &Endpoint, _: Instant) -> Result<String, ProbeError> {
        let count = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_first && count == 0 {
            return Err(ProbeError::new("receive", "timeout", "first timeout"));
        }
        let mut gate = self.gate.0.lock().unwrap();
        while !*gate {
            gate = self.gate.1.wait(gate).unwrap();
        }
        Ok("8.8.8.8".into())
    }
}
#[test]
fn late_worker_cannot_retry_or_change_the_returned_receipt() {
    for fail_first in [false, true] {
        let client = Arc::new(Slow {
            calls: AtomicUsize::new(0),
            gate: (Mutex::new(false), Condvar::new()),
            fail_first,
        });
        let result = stun_probe::probe_with_delay(
            &[endpoint()],
            client.clone(),
            Duration::from_millis(120),
            Duration::ZERO,
        );
        let row = &result.observations[0];
        assert!(!result.complete);
        assert_eq!(row.status, "budget_exhausted");
        if fail_first {
            assert_eq!(row.attempts[0].status, "timeout");
            assert_eq!(row.attempts.len(), 2);
        }
        *client.gate.0.lock().unwrap() = true;
        client.gate.1.notify_all();
        thread::sleep(Duration::from_millis(40));
        assert_eq!(
            client.calls.load(Ordering::SeqCst),
            if fail_first { 2 } else { 1 }
        );
        assert_eq!(row.status, "budget_exhausted");
        assert!(row.address.is_none());
    }
}
fn serve(wrong_sender: bool) -> (Endpoint, thread::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let address = socket.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let mut request = [0; 4096];
        let (size, peer) = socket.recv_from(&mut request).unwrap();
        assert_eq!(size, 20);
        let mut packet = request[..20].to_vec();
        packet[0] = 1;
        packet[1] = 1;
        packet[2..4].copy_from_slice(&12u16.to_be_bytes());
        packet.extend_from_slice(&[0, 0x20, 0, 8, 0, 1, 0, 0]);
        let cookie = claude_watch_core::stun::COOKIE;
        packet.extend([8u8; 4].iter().enumerate().map(|(i, v)| v ^ cookie[i]));
        if wrong_sender {
            UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .send_to(&packet, peer)
                .unwrap();
        } else {
            socket.send_to(&packet, peer).unwrap();
        }
    });
    (
        Endpoint {
            host: address.ip().to_string(),
            port: address.port(),
        },
        handle,
    )
}
#[test]
fn native_ipv4_udp_roundtrip_checks_transaction_and_sender() {
    for wrong in [false, true] {
        let (endpoint, server) = serve(wrong);
        let result = NativeRequester.request(&endpoint, Instant::now() + Duration::from_secs(1));
        server.join().unwrap();
        if wrong {
            assert_eq!(result.unwrap_err().code, "unexpected_sender");
        } else {
            assert_eq!(result.unwrap(), "8.8.8.8");
        }
    }
}
#[test]
fn expired_native_request_cannot_send_after_resolution() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let endpoint = Endpoint {
        host: "127.0.0.1".into(),
        port: socket.local_addr().unwrap().port(),
    };
    assert_eq!(
        NativeRequester
            .request(&endpoint, Instant::now())
            .unwrap_err()
            .code,
        "budget_exhausted"
    );
    assert!(socket.recv_from(&mut [0; 32]).is_err());
}
