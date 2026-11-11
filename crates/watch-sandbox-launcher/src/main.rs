//! Dedicated Seatbelt (`nono` capability model) helper binary (`watch-sandbox-launcher`).
//!
//! Execution contract:
//! 1. Validates `ControlledLaunchRequest` and verifies target binary SHA-256 fingerprint on disk.
//! 2. Builds pinned `nono` capabilities allowing ONLY the Watch loopback gateway port
//!    and denying direct network, direct VPN port, DNS, and Unix socket network relays.
//! 3. Connects the registration socket, applies `nono::Sandbox::apply_auto` in this helper
//!    BEFORE `exec`, then registers over the kernel-authenticated Unix socket.
//! 4. Closes registration descriptors, sets `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` (and
//!    optional Electron `--proxy-server` switches), and directly `exec`s the target binary.
//!    Never falls back to an unsandboxed launch if any step fails.

use claude_watch_core::controlled_launch::{ControlledLaunchRequest, ProxyAdaptationKind};
use claude_watch_runtime::sandbox_launch::{
    generate_nono_seatbelt_profile, register_helper_over_connected_stream, NONO_UPSTREAM_GIT_REV,
};
use claude_watch_system::sha256_file_hex;
mod network_policy;
mod node_entry;
use serde_json::json;
use std::{
    net::SocketAddr,
    os::unix::{net::UnixStream, process::CommandExt},
    path::PathBuf,
    process::{Command, ExitCode},
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--version-json") {
        println!(
            "{}",
            json!({
                "binary": "watch-sandbox-launcher",
                "nono_crate_linked": true,
                "seatbelt_engine": "nono",
                "policy_scope": "network_only",
                "nono_reference_git_rev": NONO_UPSTREAM_GIT_REV,
                "backend": "seatbelt",
            })
        );
        return ExitCode::SUCCESS;
    }

    if args.get(1).map(String::as_str) == Some("--dry-run-profile") {
        let Some(gw) = args.get(2).and_then(|s| s.parse::<SocketAddr>().ok()) else {
            eprintln!("invalid_gateway_addr");
            return ExitCode::from(2);
        };
        match generate_nono_seatbelt_profile(gw, &[7890, 7891]) {
            Ok(sbpl) => {
                // The library does not export its generated SBPL; this is
                // Watch's policy specification rather than a profile dump.
                print!(";; Watch network policy specification; applied by pinned nono\n{sbpl}");
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("{}", e.code);
                return ExitCode::from(2);
            }
        }
    }

    if args.get(1).map(String::as_str) != Some("--launch-json") {
        eprintln!("usage: watch-sandbox-launcher --launch-json <request_json> [--registration-socket <path>] [--deny-port <port>]");
        return ExitCode::from(64);
    }

    let Some(req_json) = args.get(2) else {
        eprintln!("missing_launch_json");
        return ExitCode::from(64);
    };

    let mut registration_socket: Option<PathBuf> = None;
    let mut extra_deny_ports: Vec<u16> = Vec::new();
    let mut idx = 3;
    while idx < args.len() {
        match args[idx].as_str() {
            "--registration-socket" => {
                if let Some(p) = args.get(idx + 1) {
                    registration_socket = Some(PathBuf::from(p));
                }
                idx += 2;
            }
            "--deny-port" => {
                if let Some(p) = args.get(idx + 1).and_then(|v| v.parse::<u16>().ok()) {
                    extra_deny_ports.push(p);
                }
                idx += 2;
            }
            _ => {
                idx += 1;
            }
        }
    }

    let req: ControlledLaunchRequest = match serde_json::from_str(req_json) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("invalid_launch_request_json");
            return ExitCode::from(65);
        }
    };
    if let Err(err) = req.validate() {
        eprintln!("{}: {}", err.code, err.message);
        return ExitCode::from(65);
    }

    let canon_target = match std::fs::canonicalize(&req.target_executable) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("target_executable_not_found");
            return ExitCode::from(66);
        }
    };
    let node = if req.script_source.is_some() {
        if registration_socket.is_none() {
            eprintln!("script_registration_required");
            return ExitCode::from(65);
        }
        match node_entry::NodeEntry::capture(&req) {
            Ok(entry) => Some(entry),
            Err(code) => { eprintln!("{code}"); return ExitCode::from(67); }
        }
    } else {
        if claude_watch_runtime::managed_entry::is_script_file(&canon_target) {
            eprintln!("script_launch_contract_required");
            return ExitCode::from(65);
        }
        let Some(actual_sha) = sha256_file_hex(&canon_target) else {
            eprintln!("target_fingerprint_read_failed");
            return ExitCode::from(66);
        };
        if actual_sha != req.target_fingerprint {
            eprintln!("target_fingerprint_mismatch");
            return ExitCode::from(67);
        }
        None
    };

    let gw_addr: SocketAddr = match req.gateway_endpoint.parse() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("invalid_gateway_endpoint");
            return ExitCode::from(65);
        }
    };

    let capabilities = match network_policy::capabilities(gw_addr, &extra_deny_ports) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("invalid_nono_policy: {e}");
            return ExitCode::from(68);
        }
    };
    // Bind the registration evidence to the actual capability input consumed by
    // the pinned library, rather than claiming a handwritten SBPL was applied.
    let policy_description = match serde_json::to_string(&json!({
        "format": "nono-capabilities-v1",
        "nono_git_rev": NONO_UPSTREAM_GIT_REV,
        "network_mode": format!("{:?}", capabilities.network_mode()),
        "dns_enabled": capabilities.dns_enabled(),
        "platform_rules": capabilities.platform_rules(),
    })) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("nono_policy_serialization_failed: {error}");
            return ExitCode::from(68);
        }
    };

    // Connect the Unix registration stream BEFORE `(deny network*)` blocks new AF_UNIX connects,
    // then apply the irreversible nono Seatbelt capabilities, and only after
    // `sandbox_init` succeeds send `sandbox_applied: true` over the connected stream and close it
    // before `exec`. If any step fails, immediately exit non-zero and NEVER exec unsandboxed.
    let reg_stream = match registration_socket {
        Some(ref sock_path) => match UnixStream::connect(sock_path) {
            Ok(s) => Some(s),
            Err(err) => {
                eprintln!("sandbox_daemon_unreachable: {err}");
                return ExitCode::from(72);
            }
        },
        None => None,
    };

    if let Err(err) = network_policy::apply(&capabilities) {
        eprintln!("seatbelt_apply_failed: {err}");
        return ExitCode::from(70);
    }

    if let Some(stream) = reg_stream {
        match register_helper_over_connected_stream(stream, req.clone(), true, &policy_description) {
            Ok(resp) if resp.accepted => {}
            Ok(resp) => {
                eprintln!(
                    "sandbox_registration_rejected: {}",
                    resp.error_code.unwrap_or_else(|| "rejected".into())
                );
                return ExitCode::from(71);
            }
            Err(err) => {
                eprintln!("sandbox_registration_failed: {}", err.code);
                return ExitCode::from(72);
            }
        }
    }

    let proxy_url = format!("http://{}", req.gateway_endpoint);
    let mut cmd = if let Some(ref entry) = node {
        match entry.command() {
            Ok(cmd) => cmd,
            Err(code) => { eprintln!("{code}"); return ExitCode::from(67); }
        }
    } else { Command::new(&canon_target) };
    for (key, _) in std::env::vars_os() {
        if key.to_str().is_some_and(claude_watch_core::controlled_launch::loader_startup_input) {
            cmd.env_remove(key);
        }
    }
    cmd.args(&req.args);
    if let Some(ref cwd) = req.cwd {
        cmd.current_dir(cwd);
    }
    cmd.env("HTTP_PROXY", &proxy_url)
        .env("HTTPS_PROXY", &proxy_url)
        .env("ALL_PROXY", &proxy_url)
        .env("http_proxy", &proxy_url)
        .env("https_proxy", &proxy_url)
        .env("all_proxy", &proxy_url)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .env("CW_CONTROLLED_SANDBOX", "1")
        .env("CW_EXECUTOR_BOOT_ID", &req.executor_boot_id);

    if req.proxy_adaptation == ProxyAdaptationKind::EnvAndElectronSwitches {
        cmd.arg(format!("--proxy-server={proxy_url}"))
            .arg("--proxy-bypass-list=<-loopback>");
    }

    let err = cmd.exec();
    eprintln!("exec_failed: {err}");
    ExitCode::from(73)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nono_seatbelt_profile_allows_only_gateway_port_and_denies_direct_and_vpn_ports() {
        let gw: SocketAddr = "127.0.0.1:18888".parse().unwrap();
        let sbpl = generate_nono_seatbelt_profile(gw, &[7890, 7891]).unwrap();
        assert!(sbpl.contains("(deny network*)"));
        assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:18888\"))"));
        assert!(sbpl.contains("(deny network-outbound (remote tcp \"localhost:7890\"))"));
        assert!(generate_nono_seatbelt_profile(gw, &[18888]).is_err());
    }
}
