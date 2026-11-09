//! Unified desktop wrapper entry (`io.local.watchpanel.entry.<target-id>`) and
//! CLI shim entry (`claude` / `codex`) sharing the same Rust supervision,
//! `nono` Seatbelt launcher (`watch-sandbox-launcher`), and `SandboxLaunchRegistry`.
//!
//! Key invariants:
//! - Never modifies or re-signs the original `.app` bundle or original CLI installation.
//! - If an unmanaged instance of the target is already running (`D02`), returns
//!   `already_running_unmanaged` with `ManagedInstanceState::RunningUnprotected`
//!   and never falsely marks the process as protected or kills it.
//! - Direct `fork`/`exec` children inherit the irreversible Seatbelt profile (`D03`),
//!   Unix domain socket network relays are blocked by `(deny network*)` (`D05`),
//!   and any out-of-tree `NSWorkspace`/`LaunchServices` process not registered in
//!   `SandboxLaunchRegistry` is surfaced as `RunningUnprotected` (`D04`).
//! - CLI shim resolution skips the shim's own directory/executable in `PATH` to
//!   prevent self-recursion (`C01`), preserving arguments, `cwd`, stdio, and exit code.

use crate::sandbox_launch::SandboxLaunchRegistry;
use claude_watch_core::{
    channel::PolicyVersion,
    controlled_launch::{
        ControlledLaunchRequest, ManagedInstanceState, ManagedLaunchInstance, ProxyAdaptationKind,
    },
    error::{CoreError, Result},
    processes::LaunchTarget,
    vpn::VpnEpoch,
};
use claude_watch_system::sha256_file_hex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopManagedEntrySpec {
    pub entry_bundle_id: String,
    pub target: LaunchTarget,
    pub target_bundle_path: PathBuf,
    pub target_bundle_id: String,
    pub target_executable: PathBuf,
    pub target_fingerprint: String,
    pub proxy_adaptation: ProxyAdaptationKind,
}

impl DesktopManagedEntrySpec {
    pub fn entry_bundle_id_for(target: LaunchTarget) -> &'static str {
        match target {
            LaunchTarget::ClaudeDesktop => "io.local.watchpanel.entry.claude-desktop",
            LaunchTarget::CodexDesktop => "io.local.watchpanel.entry.codex-desktop",
            LaunchTarget::ChatgptDesktop => "io.local.watchpanel.entry.chatgpt-desktop",
            LaunchTarget::ClaudeCli => "io.local.watchpanel.entry.claude-cli",
            LaunchTarget::CodexCli => "io.local.watchpanel.entry.codex-cli",
        }
    }

    /// Resolves a desktop `.app` bundle by reading its `Contents/Info.plist`
    /// (`CFBundleIdentifier` and `CFBundleExecutable`) without mutating any file
    /// inside the original `.app`.
    pub fn resolve_from_app_bundle(
        target: LaunchTarget,
        app_bundle: &Path,
        expected_bundle_id: &str,
        cf_bundle_executable: &str,
    ) -> Result<Self> {
        if cf_bundle_executable.trim().is_empty()
            || cf_bundle_executable.contains(['/', '\\'])
            || matches!(cf_bundle_executable, "." | "..")
        {
            return Err(CoreError::new(
                "invalid_bundle_executable",
                "目标 .app 的 CFBundleExecutable 无效",
            ));
        }
        let canon_bundle = fs::canonicalize(app_bundle).map_err(|_| {
            CoreError::new("target_bundle_missing", "目标桌面应用 .app 目录不存在")
        })?;
        let exe_path = canon_bundle
            .join("Contents/MacOS")
            .join(cf_bundle_executable);
        let canon_exe = fs::canonicalize(&exe_path).map_err(|_| {
            CoreError::new("target_executable_missing", "目标桌面应用主程序不存在")
        })?;
        if !canon_exe.starts_with(canon_bundle.join("Contents/MacOS")) {
            return Err(CoreError::new(
                "target_executable_outside_bundle",
                "目标桌面应用主程序不在 Contents/MacOS 范围内",
            ));
        }
        let meta = fs::metadata(&canon_exe).map_err(|_| {
            CoreError::new("target_executable_unreadable", "目标桌面应用主程序无法读取")
        })?;
        if !meta.is_file() || (meta.permissions().mode() & 0o111 == 0) {
            return Err(CoreError::new(
                "target_executable_not_executable",
                "目标桌面应用主程序缺少可执行权限",
            ));
        }
        let fingerprint = sha256_file_hex(&canon_exe).ok_or_else(|| {
            CoreError::new("target_fingerprint_failed", "无法计算目标桌面应用主程序 SHA-256")
        })?;
        let adaptation = match target {
            LaunchTarget::ClaudeDesktop | LaunchTarget::CodexDesktop => {
                ProxyAdaptationKind::EnvAndElectronSwitches
            }
            _ => ProxyAdaptationKind::EnvOnly,
        };
        Ok(Self {
            entry_bundle_id: Self::entry_bundle_id_for(target).to_string(),
            target,
            target_bundle_path: canon_bundle,
            target_bundle_id: expected_bundle_id.to_string(),
            target_executable: canon_exe,
            target_fingerprint: fingerprint,
            proxy_adaptation: adaptation,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunningProcessSnapshot {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub start_seconds: u64,
    pub start_microseconds: u32,
    pub executable: String,
    pub bundle_id: Option<String>,
}

/// Captures a live kernel snapshot of all processes owned by the current effective UID.
pub fn snapshot_running_processes() -> Result<Vec<RunningProcessSnapshot>> {
    let uid = claude_watch_system::effective_uid();
    let mut out = Vec::new();
    for pid in claude_watch_system::list_user_pids(uid) {
        if let Some(info) = claude_watch_system::inspect_process_identity(pid) {
            if info.uid == uid {
                out.push(RunningProcessSnapshot {
                    pid: info.pid,
                    ppid: info.ppid,
                    uid: info.uid,
                    start_seconds: info.start_seconds,
                    start_microseconds: info.start_microseconds,
                    executable: info.executable_path,
                    bundle_id: None,
                });
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum DesktopEntryPreparation {
    /// No unmanaged instance is running; ready to launch through `watch-sandbox-launcher`.
    ReadyToLaunch {
        request: ControlledLaunchRequest,
    },
    /// An unmanaged instance is already running (`D02`).
    /// Must NOT claim protection and must NOT terminate the user's running window.
    AlreadyRunningUnmanaged {
        code: String,
        state: ManagedInstanceState,
        unmanaged_pids: Vec<u32>,
        message: String,
    },
}

/// Evaluates running processes for the target desktop app (`D02`, `D03`, `D04`):
/// - Any running process matching the target bundle/executable that is NOT a
///   verified `ManagedLaunchInstance` (or a direct child in its process tree with
///   matching `executor_boot_id` and `policy_version`) is classified as
///   `ManagedInstanceState::RunningUnprotected`.
/// - If any unmanaged instance is already running, refuses to silently attach
///   and returns `DesktopEntryPreparation::AlreadyRunningUnmanaged` (`already_running_unmanaged`).
pub fn prepare_desktop_managed_launch(
    spec: &DesktopManagedEntrySpec,
    running_processes: &[RunningProcessSnapshot],
    registry: &SandboxLaunchRegistry,
    executor_boot_id: &str,
    policy_version: &PolicyVersion,
    vpn_epoch: Option<VpnEpoch>,
    gateway_addr: SocketAddr,
    args: Vec<String>,
) -> Result<DesktopEntryPreparation> {
    let managed_instances = registry.instances();
    let mut unmanaged_pids = Vec::new();
    let canon_target_str = spec.target_executable.to_string_lossy();

    for proc_info in running_processes {
        let matches_target = proc_info.bundle_id.as_deref() == Some(spec.target_bundle_id.as_str())
            || proc_info.executable == canon_target_str;
        if !matches_target {
            continue;
        }
        let is_verified_managed = managed_instances.iter().any(|inst| {
            inst.has_verified_protection(executor_boot_id, policy_version)
                && ((inst.pid == proc_info.pid
                    && inst.uid == proc_info.uid
                    && inst.start_seconds == proc_info.start_seconds
                    && inst.start_microseconds == proc_info.start_microseconds)
                    || inst.controlled_subtree_pids.contains(&proc_info.pid)
                    || inst.pid == proc_info.ppid)
        });
        if !is_verified_managed {
            unmanaged_pids.push(proc_info.pid);
        }
    }

    if !unmanaged_pids.is_empty() {
        return Ok(DesktopEntryPreparation::AlreadyRunningUnmanaged {
            code: "already_running_unmanaged".into(),
            state: ManagedInstanceState::RunningUnprotected,
            unmanaged_pids,
            message: "检测到未受控的已有应用实例正在运行（running_unprotected）；不会假冒已保护，请先自行退出原实例后再从受控入口启动".into(),
        });
    }

    let req = ControlledLaunchRequest {
        entry_id: spec.entry_bundle_id.clone(),
        target: spec.target,
        target_executable: canon_target_str.into_owned(),
        target_fingerprint: spec.target_fingerprint.clone(),
        args,
        cwd: None,
        proxy_adaptation: spec.proxy_adaptation,
        gateway_endpoint: gateway_addr.to_string(),
        policy_version: policy_version.clone(),
        vpn_epoch,
        launch_nonce: format!("nonce-{}", Uuid::new_v4()),
        executor_boot_id: executor_boot_id.to_string(),
    };
    req.validate()?;
    Ok(DesktopEntryPreparation::ReadyToLaunch { request: req })
}

/// Classifies a discovered process for monitor/truthful reporting (`D02`, `D03`, `D04`):
/// - Direct `fork`/`exec` children of a verified `ManagedLaunchInstance` inherit the
///   Seatbelt sandbox (`ExecVerified`).
/// - Out-of-tree processes (such as `NSWorkspace` / `LaunchServices` launches whose parent
///   is `launchd` PID 1 and which have no verified registration in `SandboxLaunchRegistry`)
///   are reported as `ManagedInstanceState::RunningUnprotected` (`running_unprotected`).
pub fn classify_process_protection_state(
    proc_info: &RunningProcessSnapshot,
    managed_instances: &[ManagedLaunchInstance],
    executor_boot_id: &str,
    policy_version: &PolicyVersion,
) -> ManagedInstanceState {
    for inst in managed_instances {
        if !inst.has_verified_protection(executor_boot_id, policy_version) {
            continue;
        }
        if inst.pid == proc_info.pid
            && inst.uid == proc_info.uid
            && inst.start_seconds == proc_info.start_seconds
            && inst.start_microseconds == proc_info.start_microseconds
        {
            return ManagedInstanceState::ExecVerified;
        }
        // Direct fork/exec child of the sandboxed main process inherits Seatbelt (`D03`),
        // whereas NSWorkspace / LaunchServices spawns under launchd (ppid == 1) and does NOT (`D04`).
        if proc_info.ppid > 1
            && (proc_info.ppid == inst.pid
                || inst.controlled_subtree_pids.contains(&proc_info.ppid)
                || inst.controlled_subtree_pids.contains(&proc_info.pid))
        {
            return ManagedInstanceState::ExecVerified;
        }
    }
    ManagedInstanceState::RunningUnprotected
}

/// Resolves the real CLI executable from `search_paths` (e.g. `PATH`), explicitly
/// skipping `shim_executable` and `shim_dir` so a managed CLI shim placed early in
/// `PATH` never invokes itself recursively (`C01`).
pub fn resolve_real_cli_skipping_shim(
    cli_name: &str,
    shim_executable: &Path,
    search_paths: &[PathBuf],
) -> Result<(PathBuf, String)> {
    let canon_shim = fs::canonicalize(shim_executable).ok();
    let shim_dir = canon_shim
        .as_ref()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .or_else(|| shim_executable.parent().map(Path::to_path_buf));

    for dir in search_paths {
        if let Ok(canon_dir) = fs::canonicalize(dir) {
            if shim_dir.as_ref() == Some(&canon_dir) {
                continue;
            }
        } else if shim_dir.as_deref() == Some(dir.as_path()) {
            continue;
        }
        let candidate = dir.join(cli_name);
        let Ok(canon_cand) = fs::canonicalize(&candidate) else {
            continue;
        };
        if canon_shim.as_ref() == Some(&canon_cand) {
            continue;
        }
        let Ok(meta) = fs::metadata(&canon_cand) else {
            continue;
        };
        if !meta.is_file() || (meta.permissions().mode() & 0o111 == 0) {
            continue;
        }
        let Some(sha) = sha256_file_hex(&canon_cand) else {
            continue;
        };
        return Ok((canon_cand, sha));
    }

    Err(CoreError::new(
        "real_cli_not_found",
        &format!("在排除受控 shim 目录后未找到真实的 {cli_name} 可执行文件"),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliShimExecutionResult {
    pub exit_code: i32,
    pub resolved_executable: PathBuf,
    pub resolved_fingerprint: String,
    pub launch_request: ControlledLaunchRequest,
}

/// Executes a CLI target through `watch-sandbox-launcher`, preserving
/// `args`, `cwd`, `env`, `stdin`/`stdout`/`stderr`, and exit status (`C01`).
pub fn execute_cli_via_sandbox_launcher(
    launcher_binary: &Path,
    registration_socket: Option<&Path>,
    target: LaunchTarget,
    shim_executable: &Path,
    search_paths: &[PathBuf],
    args: &[String],
    cwd: Option<&Path>,
    extra_env: &BTreeMap<String, String>,
    gateway_addr: SocketAddr,
    executor_boot_id: &str,
    policy_version: PolicyVersion,
    vpn_epoch: Option<VpnEpoch>,
    extra_deny_ports: &[u16],
) -> Result<(CliShimExecutionResult, Vec<u8>, Vec<u8>)> {
    execute_cli_via_sandbox_launcher_with_stdin(
        launcher_binary,
        registration_socket,
        target,
        shim_executable,
        search_paths,
        args,
        cwd,
        extra_env,
        None,
        gateway_addr,
        executor_boot_id,
        policy_version,
        vpn_epoch,
        extra_deny_ports,
    )
}

/// Executes a CLI target through `watch-sandbox-launcher` with optional piped `stdin_input`
/// and concurrent streaming readers for `stdout`/`stderr` (never forcing `Stdio::null()`
/// when `stdin_input` is provided, and never blocking streaming output before child exit).
#[allow(clippy::too_many_arguments)]
pub fn execute_cli_via_sandbox_launcher_with_stdin(
    launcher_binary: &Path,
    registration_socket: Option<&Path>,
    target: LaunchTarget,
    shim_executable: &Path,
    search_paths: &[PathBuf],
    args: &[String],
    cwd: Option<&Path>,
    extra_env: &BTreeMap<String, String>,
    stdin_input: Option<&[u8]>,
    gateway_addr: SocketAddr,
    executor_boot_id: &str,
    policy_version: PolicyVersion,
    vpn_epoch: Option<VpnEpoch>,
    extra_deny_ports: &[u16],
) -> Result<(CliShimExecutionResult, Vec<u8>, Vec<u8>)> {
    use std::io::{Read, Write};

    let cli_name = match target {
        LaunchTarget::ClaudeCli => "claude",
        LaunchTarget::CodexCli => "codex",
        _ => {
            return Err(CoreError::new(
                "invalid_cli_target",
                "受控 CLI shim 仅支持 claude-cli 或 codex-cli",
            ))
        }
    };
    let (real_exe, real_sha) =
        resolve_real_cli_skipping_shim(cli_name, shim_executable, search_paths)?;
    let req = ControlledLaunchRequest {
        entry_id: DesktopManagedEntrySpec::entry_bundle_id_for(target).to_string(),
        target,
        target_executable: real_exe.to_string_lossy().into_owned(),
        target_fingerprint: real_sha.clone(),
        args: args.to_vec(),
        cwd: cwd.map(|p| p.to_string_lossy().into_owned()),
        proxy_adaptation: ProxyAdaptationKind::EnvOnly,
        gateway_endpoint: gateway_addr.to_string(),
        policy_version,
        vpn_epoch,
        launch_nonce: format!("cli-nonce-{}", Uuid::new_v4()),
        executor_boot_id: executor_boot_id.to_string(),
    };
    req.validate()?;
    let req_json = serde_json::to_string(&req)
        .map_err(|_| CoreError::new("serialize_launch_request_failed", "序列化受控启动请求失败"))?;

    let mut cmd = Command::new(launcher_binary);
    cmd.arg("--launch-json").arg(&req_json);
    if let Some(sock) = registration_socket {
        cmd.arg("--registration-socket").arg(sock);
    }
    for port in extra_deny_ports {
        cmd.arg("--deny-port").arg(port.to_string());
    }
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|_| {
        CoreError::new(
            "sandbox_launcher_spawn_failed",
            "无法启动 watch-sandbox-launcher",
        )
    })?;

    if let Some(mut child_stdin) = child.stdin.take() {
        if let Some(bytes) = stdin_input {
            let payload = bytes.to_vec();
            std::thread::spawn(move || {
                let _ = child_stdin.write_all(&payload);
                let _ = child_stdin.flush();
            });
        } else {
            drop(child_stdin);
        }
    }

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let stdout_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut out) = stdout_pipe {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = out.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        }
        buf
    });
    let stderr_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut err) = stderr_pipe {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = err.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        }
        buf
    });

    let status = child.wait().map_err(|_| {
        CoreError::new(
            "sandbox_launcher_wait_failed",
            "等待受控 CLI 子进程退出失败",
        )
    })?;
    let stdout_bytes = stdout_handle.join().unwrap_or_default();
    let stderr_bytes = stderr_handle.join().unwrap_or_default();
    let code = status.code().unwrap_or(1);
    Ok((
        CliShimExecutionResult {
            exit_code: code,
            resolved_executable: real_exe,
            resolved_fingerprint: real_sha,
            launch_request: req,
        },
        stdout_bytes,
        stderr_bytes,
    ))
}

/// Runs an interactive CLI session through `watch-sandbox-launcher` with inherited
/// `stdin`, `stdout`, `stderr`, and controlling `TTY` (`Stdio::inherit()`), preserving
/// interactive terminal behavior, streaming output, and exact exit status (`C01`).
#[allow(clippy::too_many_arguments)]
pub fn run_cli_interactive_via_sandbox_launcher(
    launcher_binary: &Path,
    registration_socket: Option<&Path>,
    target: LaunchTarget,
    shim_executable: &Path,
    search_paths: &[PathBuf],
    args: &[String],
    cwd: Option<&Path>,
    extra_env: &BTreeMap<String, String>,
    gateway_addr: SocketAddr,
    executor_boot_id: &str,
    policy_version: PolicyVersion,
    vpn_epoch: Option<VpnEpoch>,
    extra_deny_ports: &[u16],
) -> Result<CliShimExecutionResult> {
    let cli_name = match target {
        LaunchTarget::ClaudeCli => "claude",
        LaunchTarget::CodexCli => "codex",
        _ => {
            return Err(CoreError::new(
                "invalid_cli_target",
                "受控 CLI shim 仅支持 claude-cli 或 codex-cli",
            ))
        }
    };
    let (real_exe, real_sha) =
        resolve_real_cli_skipping_shim(cli_name, shim_executable, search_paths)?;
    let req = ControlledLaunchRequest {
        entry_id: DesktopManagedEntrySpec::entry_bundle_id_for(target).to_string(),
        target,
        target_executable: real_exe.to_string_lossy().into_owned(),
        target_fingerprint: real_sha.clone(),
        args: args.to_vec(),
        cwd: cwd.map(|p| p.to_string_lossy().into_owned()),
        proxy_adaptation: ProxyAdaptationKind::EnvOnly,
        gateway_endpoint: gateway_addr.to_string(),
        policy_version,
        vpn_epoch,
        launch_nonce: format!("cli-nonce-{}", Uuid::new_v4()),
        executor_boot_id: executor_boot_id.to_string(),
    };
    req.validate()?;
    let req_json = serde_json::to_string(&req)
        .map_err(|_| CoreError::new("serialize_launch_request_failed", "序列化受控启动请求失败"))?;

    let mut cmd = Command::new(launcher_binary);
    cmd.arg("--launch-json").arg(&req_json);
    if let Some(sock) = registration_socket {
        cmd.arg("--registration-socket").arg(sock);
    }
    for port in extra_deny_ports {
        cmd.arg("--deny-port").arg(port.to_string());
    }
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let status = cmd.status().map_err(|_| {
        CoreError::new(
            "sandbox_launcher_spawn_failed",
            "无法启动 watch-sandbox-launcher",
        )
    })?;
    Ok(CliShimExecutionResult {
        exit_code: status.code().unwrap_or(1),
        resolved_executable: real_exe,
        resolved_fingerprint: real_sha,
        launch_request: req,
    })
}

/// Stages a managed desktop wrapper `.app` bundle (`io.local.watchpanel.entry.<target>`)
/// in `output_dir` without modifying the original target `.app`.
pub fn stage_desktop_entry_bundle(
    output_dir: &Path,
    spec: &DesktopManagedEntrySpec,
    watch_engine_bin: &Path,
    launcher_bin: &Path,
    controlled_entry_macho: Option<&Path>,
) -> Result<PathBuf> {
    let app_display_name = match spec.target {
        LaunchTarget::ClaudeDesktop => "Claude (Controlled).app",
        LaunchTarget::CodexDesktop => "Codex (Controlled).app",
        LaunchTarget::ChatgptDesktop => "ChatGPT (Controlled).app",
        _ => {
            return Err(CoreError::new(
                "invalid_desktop_entry_target",
                "桌面受控入口仅支持桌面端 AI 目标",
            ))
        }
    };
    let bundle_dir = output_dir.join(app_display_name);
    let macos_dir = bundle_dir.join("Contents/MacOS");
    fs::create_dir_all(&macos_dir)
        .map_err(|_| CoreError::new("stage_entry_mkdir_failed", "无法创建受控桌面入口目录"))?;
    let state_dir = {
        let mut cur = output_dir.to_path_buf();
        let mut found_watch_root = None;
        loop {
            if cur.file_name().and_then(|n| n.to_str()) == Some("entries") {
                found_watch_root = cur.parent().map(|p| p.to_path_buf());
                break;
            }
            if !cur.pop() {
                break;
            }
        }
        if let Some(watch_root) = found_watch_root {
            watch_root.join("state")
        } else if let Some(parent) = output_dir.parent() {
            parent.join("state")
        } else {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
                .join("Library/Application Support/ClaudeWatch/state")
        }
    };
    let info_plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>{}</string>
    <key>CFBundleName</key>
    <string>{}</string>
    <key>CFBundleExecutable</key>
    <string>ControlledEntry</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CWTarget</key>
    <string>{}</string>
    <key>CWTargetBundlePath</key>
    <string>{}</string>
    <key>CWTargetBundleId</key>
    <string>{}</string>
    <key>CWTargetExecutable</key>
    <string>{}</string>
    <key>CWTargetFingerprint</key>
    <string>{}</string>
    <key>CWWatchBin</key>
    <string>{}</string>
    <key>CWSandboxLauncherBin</key>
    <string>{}</string>
    <key>CWWatchStateDirPath</key>
    <string>{}</string>
</dict>
</plist>
"#,
        spec.entry_bundle_id,
        app_display_name.trim_end_matches(".app"),
        spec.target.as_str(),
        spec.target_bundle_path.display(),
        spec.target_bundle_id,
        spec.target_executable.display(),
        spec.target_fingerprint,
        watch_engine_bin.display(),
        launcher_bin.display(),
        state_dir.display(),
    );
    fs::write(bundle_dir.join("Contents/Info.plist"), info_plist)
        .map_err(|_| CoreError::new("stage_entry_plist_failed", "无法写入受控入口 Info.plist"))?;
    let exe_dst = macos_dir.join("ControlledEntry");
    if let Some(macho) = controlled_entry_macho.filter(|p| p.is_file()) {
        fs::copy(macho, &exe_dst)
            .map_err(|_| CoreError::new("stage_entry_copy_failed", "无法复制 ControlledEntry 二进制"))?;
    } else {
        let script = format!(
            "#!/bin/sh\nexport CW_TARGET=\"{}\"\nexport CW_WATCH_BIN=\"{}\"\nexec \"{}\" launch --target \"{}\" --apply \"$@\"\n",
            spec.target.as_str(),
            watch_engine_bin.display(),
            watch_engine_bin.display(),
            spec.target.as_str(),
        );
        fs::write(&exe_dst, script)
            .map_err(|_| CoreError::new("stage_entry_script_failed", "无法写入受控入口启动器"))?;
    }
    let mut perms = fs::metadata(&exe_dst)
        .map_err(|_| CoreError::new("stage_entry_stat_failed", "无法读取受控入口权限"))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&exe_dst, perms)
        .map_err(|_| CoreError::new("stage_entry_chmod_failed", "无法设置受控入口执行权限"))?;
    Ok(bundle_dir)
}

/// Stages a managed CLI shim (`claude` or `codex`) in `bin_dir` that sets
/// `CW_SHIM_EXECUTABLE` (to prevent `PATH` self-recursion) and invokes `watch_engine_bin`.
pub fn stage_cli_entry_shim(
    bin_dir: &Path,
    target: LaunchTarget,
    watch_engine_bin: &Path,
) -> Result<PathBuf> {
    let (cli_name, target_flag) = match target {
        LaunchTarget::ClaudeCli => ("claude", "claude-cli"),
        LaunchTarget::CodexCli => ("codex", "codex-cli"),
        _ => {
            return Err(CoreError::new(
                "invalid_cli_shim_target",
                "CLI 受控入口仅支持 claude-cli 或 codex-cli",
            ))
        }
    };
    fs::create_dir_all(bin_dir)
        .map_err(|_| CoreError::new("stage_shim_mkdir_failed", "无法创建受控 CLI shim 目录"))?;
    let shim_path = bin_dir.join(cli_name);
    let script = format!(
        "#!/bin/sh\nexport CW_SHIM_EXECUTABLE=\"$0\"\nexec \"{}\" launch --target \"{}\" --apply -- \"$@\"\n",
        watch_engine_bin.display(),
        target_flag,
    );
    fs::write(&shim_path, script)
        .map_err(|_| CoreError::new("stage_shim_write_failed", "无法写入受控 CLI shim"))?;
    let mut perms = fs::metadata(&shim_path)
        .map_err(|_| CoreError::new("stage_shim_stat_failed", "无法读取受控 CLI shim 权限"))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&shim_path, perms)
        .map_err(|_| CoreError::new("stage_shim_chmod_failed", "无法设置受控 CLI shim 执行权限"))?;
    Ok(shim_path)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeCodeProcessWrapperPlan {
    pub wrapper_executable: String,
    pub wrapper_args: Vec<String>,
    pub proxy_url: String,
}

/// Builds an optional Claude Code `processWrapper` configuration plan so sub-commands
/// spawned by Claude Code also route through `watch-sandbox-launcher` (`ProxyAdaptationKind::ClaudeCodeProcessWrapper`).
pub fn build_claude_code_process_wrapper_plan(
    launcher_binary: &Path,
    gateway_addr: SocketAddr,
) -> Result<ClaudeCodeProcessWrapperPlan> {
    if !gateway_addr.ip().is_loopback() || gateway_addr.port() == 0 {
        return Err(CoreError::new(
            "invalid_gateway_endpoint",
            "Claude Code processWrapper 仅支持非零回环网关端口",
        ));
    }
    let canon = fs::canonicalize(launcher_binary).map_err(|_| {
        CoreError::new("helper_binary_missing", "watch-sandbox-launcher 二进制不存在")
    })?;
    Ok(ClaudeCodeProcessWrapperPlan {
        wrapper_executable: canon.to_string_lossy().into_owned(),
        wrapper_args: vec!["--launch-json".into()],
        proxy_url: format!("http://{gateway_addr}"),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedManagedEntriesReceipt {
    pub staging_root: String,
    pub desktop_bundles: Vec<String>,
    pub cli_shims: Vec<String>,
    pub watch_engine_bin: String,
    pub launcher_bin: String,
}

/// Stages deliverable desktop wrapper `.app` bundles and CLI shims (`claude`, `codex`)
/// into `staging_root` (`<watch_dir>/entries/{apps,bin}`) and writes `entries-manifest.json`
/// without mutating `/Applications`, global `PATH`, or Dock.
pub fn stage_deliverable_entries(
    staging_root: &Path,
    desktop_specs: &[DesktopManagedEntrySpec],
    watch_engine_bin: &Path,
    launcher_bin: &Path,
    controlled_entry_macho: Option<&Path>,
) -> Result<StagedManagedEntriesReceipt> {
    let apps_dir = staging_root.join("apps");
    let bin_dir = staging_root.join("bin");
    fs::create_dir_all(&apps_dir)
        .map_err(|_| CoreError::new("stage_entries_mkdir_failed", "无法创建受控桌面入口目录"))?;
    fs::create_dir_all(&bin_dir)
        .map_err(|_| CoreError::new("stage_entries_mkdir_failed", "无法创建受控 CLI 入口目录"))?;

    let mut desktop_bundles = Vec::new();
    for spec in desktop_specs {
        let bundle = stage_desktop_entry_bundle(
            &apps_dir,
            spec,
            watch_engine_bin,
            launcher_bin,
            controlled_entry_macho,
        )?;
        desktop_bundles.push(bundle.to_string_lossy().into_owned());
    }

    let mut cli_shims = Vec::new();
    for cli_target in [LaunchTarget::ClaudeCli, LaunchTarget::CodexCli] {
        let shim = stage_cli_entry_shim(&bin_dir, cli_target, watch_engine_bin)?;
        cli_shims.push(shim.to_string_lossy().into_owned());
    }

    let receipt = StagedManagedEntriesReceipt {
        staging_root: staging_root.to_string_lossy().into_owned(),
        desktop_bundles,
        cli_shims,
        watch_engine_bin: watch_engine_bin.to_string_lossy().into_owned(),
        launcher_bin: launcher_bin.to_string_lossy().into_owned(),
    };
    let manifest_json = serde_json::to_vec_pretty(&receipt)
        .map_err(|_| CoreError::new("stage_entries_manifest_failed", "无法序列化受控入口清单"))?;
    fs::write(staging_root.join("entries-manifest.json"), manifest_json)
        .map_err(|_| CoreError::new("stage_entries_manifest_failed", "无法写入受控入口清单"))?;
    Ok(receipt)
}


