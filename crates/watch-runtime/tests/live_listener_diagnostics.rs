//! Read-only, opt-in host diagnostic. No proxy configuration or credentials are read.
use claude_watch_core::tag_flow::{listener_fallback, CommandEvidence};
use claude_watch_runtime::commands::{ReadCommand, ReadRunner, SystemRunner};
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
    let line_count = fallback
        .stdout
        .lines()
        .filter(|line| line.starts_with('p'))
        .count();
    eprintln!("netstat status={} bytes={} stderr_bytes={}; direct status={:?} bytes={} stderr_bytes={}; clean_env status={:?} bytes={} stderr_bytes={}; shell status={:?} bytes={} stderr_bytes={}; lsof status={} bytes={} stderr_bytes={}; combined status={} owners={} source={}",
        kernel.status, kernel.stdout.len(), kernel.stderr.len(), direct.status.code(), direct.stdout.len(), direct.stderr.len(), clean_env.status.code(), clean_env.stdout.len(), clean_env.stderr.len(), through_shell.status.code(), through_shell.stdout.len(), through_shell.stderr.len(), lsof.status, lsof.stdout.len(), lsof.stderr.len(), fallback.status, line_count, fallback.source);
    assert_eq!(
        kernel.status, 0,
        "netstat must be readable for this host diagnostic"
    );
    assert!(kernel.stderr.is_empty(), "netstat returned an error");
    assert!(
        !kernel.stdout.trim().is_empty(),
        "netstat returned success with no records; listener identity is not verified"
    );
}
