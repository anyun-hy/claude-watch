use serde_json::Value;
use std::{
    io::Write,
    process::{Command, Stdio},
};
#[test]
fn standalone_diagnostics_do_not_need_home_or_account_config() {
    let out = Command::new(env!("CARGO_BIN_EXE_claude-watch-engine"))
        .env_remove("HOME")
        .args([
            "--home",
            "/no-such-claude-watch-home",
            "diagnose-proxy",
            "--proxy",
            "ftp://127.0.0.1:7890",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["state"], "configuration_error");
}
#[test]
fn oversized_stdin_is_a_diagnostic_configuration_error_before_transport() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_claude-watch-engine"))
        .env_remove("HOME")
        .args(["diagnose-proxy", "--stdin-config"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&vec![b'x'; 65537])
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["state"], "configuration_error");
}
