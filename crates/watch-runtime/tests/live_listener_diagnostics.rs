//! Real kernel collection against an owned temporary listener, not the user's VPN.
use claude_watch_core::tag_flow::{listener_fallback_for_port, CommandEvidence};
use claude_watch_runtime::commands::{ReadCommand, ReadRunner, SystemRunner};
use claude_watch_runtime::sampler::parse_process_table;
use std::collections::BTreeSet;
use std::net::TcpListener;
use std::time::Duration;

#[test]
#[ignore = "requires a macOS host and kernel listener read access; uses an owned temporary port"]
fn system_runner_reports_listener_evidence_without_mutation() {
    let runner = SystemRunner::development().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let control = TcpListener::bind("127.0.0.1:0").unwrap();
    assert_ne!(listener.local_addr().unwrap(), control.local_addr().unwrap());
    let endpoint = listener.local_addr().unwrap();
    let port = endpoint.port();
    let expected_pid = std::process::id();
    let expected_identity = claude_watch_system::inspect_process_identity(expected_pid)
        .expect("owned listener process must have a current kernel identity");
    assert_eq!(runner.run(ReadCommand::LsofTcpListener { port: 0 }, &[], Duration::from_secs(3), 4096)
        .err().expect("zero port must be rejected before running a command").code, "invalid_listener_port");
    let collect = |command, source: &str| {
        let out = runner
            .run(command, &[], Duration::from_secs(3), 4 * 1024 * 1024)
            .unwrap();
        CommandEvidence {
            status: out.status,
            stdout: out.text().unwrap().into(),
            stderr: out.error_text().unwrap().into(),
            source: source.into(),
        }
    };
    let before = collect(ReadCommand::ProcessTable, "ps");
    let kernel = collect(ReadCommand::Listeners, "netstat");
    let lsof = collect(ReadCommand::LsofTcpListener { port }, "lsof");
    let fallback = listener_fallback_for_port(lsof.clone(), Some(&kernel), port);
    let after = collect(ReadCommand::ProcessTable, "ps");
    let line_count = fallback
        .stdout
        .lines()
        .filter(|line| line.starts_with('p'))
        .count();
    eprintln!("netstat status={} bytes={} stderr_bytes={}; lsof status={} bytes={} stderr_bytes={}; combined status={} owners={} source={}; scope=owned_ephemeral_listener",
        kernel.status, kernel.stdout.len(), kernel.stderr.len(), lsof.status, lsof.stdout.len(), lsof.stderr.len(), fallback.status, line_count, fallback.source);
    // Production uses lsof first and netstat only as a fallback. Empty netstat
    // output is not evidence, but must not invalidate a usable lsof result.
    // This checks collection/ownership, not TAG identity or gateway protection.
    assert_eq!(fallback.status, 0, "no successful listener evidence source");
    assert!(fallback.stderr.trim().is_empty(), "listener collection returned an error");
    let mut owners = BTreeSet::new();
    let mut pid = None;
    for line in fallback.stdout.lines() {
        if let Some(raw) = line.strip_prefix('p') {
            pid = raw.parse::<u32>().ok().filter(|value| *value > 1);
        } else if let Some(endpoint) = line.strip_prefix('n') {
            assert_eq!(endpoint, listener.local_addr().unwrap().to_string(), "collector returned a different endpoint");
            if endpoint == format!("127.0.0.1:{port}") {
                owners.insert(pid.expect("listener endpoint has no valid owner PID"));
            }
        }
    }
    assert_eq!(owners, BTreeSet::from([expected_pid]), "listener must belong to the exact owned process");
    for table in [&before, &after] {
        assert_eq!(table.status, 0, "process identity collection failed");
        assert!(table.stderr.trim().is_empty(), "process identity collection returned an error");
    }
    let before = parse_process_table(&before.stdout).unwrap();
    let after = parse_process_table(&after.stdout).unwrap();
    for pid in &owners {
        let first = before.get(pid).expect("listener owner was absent before collection");
        let second = after.get(pid).expect("listener owner exited during collection");
        assert_eq!(first, second, "listener owner identity changed during collection");
        assert_eq!(first["uid"].as_u64(), Some(u64::from(expected_identity.uid)), "listener owner UID differs from kernel identity");
    }
    assert_eq!(claude_watch_system::inspect_process_identity(expected_pid).as_ref(), Some(&expected_identity),
        "listener owner birth/audit identity changed during collection");
    eprintln!("listener_collection=verified source={} stable_owners={}; scope=owned_ephemeral_listener; VPN endpoint, TAG identity and gateway protection are not asserted", fallback.source, owners.len());
}
