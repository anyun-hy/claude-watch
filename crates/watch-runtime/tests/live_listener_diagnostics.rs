//! Read-only, opt-in host diagnostic. No proxy configuration or credentials are read.
use claude_watch_core::tag_flow::{listener_fallback, CommandEvidence};
use claude_watch_runtime::commands::{ReadCommand, ReadRunner, SystemRunner};
use claude_watch_runtime::sampler::parse_process_table;
use std::collections::BTreeSet;
use std::time::Duration;

#[test]
#[ignore = "requires a macOS host and read access to the current listener"]
fn system_runner_reports_listener_evidence_without_mutation() {
    let runner = SystemRunner::development().unwrap();
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
    let direct = std::process::Command::new("/usr/sbin/netstat")
        .args(["-anv", "-p", "tcp"])
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    let clean_env = std::process::Command::new("/usr/sbin/netstat")
        .args(["-anv", "-p", "tcp"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    let through_shell = std::process::Command::new("/bin/sh")
        .args(["-c", "/usr/sbin/netstat -anv -p tcp"])
        .output()
        .unwrap();
    let lsof = collect(ReadCommand::LsofListener, "lsof");
    let fallback = listener_fallback(lsof.clone(), Some(&kernel));
    let after = collect(ReadCommand::ProcessTable, "ps");
    let line_count = fallback
        .stdout
        .lines()
        .filter(|line| line.starts_with('p'))
        .count();
    eprintln!("netstat status={} bytes={} stderr_bytes={}; direct status={:?} bytes={} stderr_bytes={}; clean_env status={:?} bytes={} stderr_bytes={}; shell status={:?} bytes={} stderr_bytes={}; lsof status={} bytes={} stderr_bytes={}; combined status={} owners={} source={}",
        kernel.status, kernel.stdout.len(), kernel.stderr.len(), direct.status.code(), direct.stdout.len(), direct.stderr.len(), clean_env.status.code(), clean_env.stdout.len(), clean_env.stderr.len(), through_shell.status.code(), through_shell.stdout.len(), through_shell.stderr.len(), lsof.status, lsof.stdout.len(), lsof.stderr.len(), fallback.status, line_count, fallback.source);
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
            if ["127.0.0.1:7890", "*:7890", "0.0.0.0:7890", "[::]:7890"].contains(&endpoint) {
                owners.insert(pid.expect("listener endpoint has no valid owner PID"));
            }
        }
    }
    assert!(
        !owners.is_empty(),
        "listener output has no valid owner for a supported endpoint on port 7890"
    );
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
    }
    eprintln!("listener_collection=verified source={} stable_owners={}; TAG identity and gateway protection are not asserted", fallback.source, owners.len());
}
