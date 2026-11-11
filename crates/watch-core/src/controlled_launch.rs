//! Controlled launch requests, sandbox launch evidence, instance lifecycle states,
//! and live socket attribution context contracts.

use crate::{
    channel::{
        BoundProcessToken, FlowTransportProtocol, NetworkBackendKind, PolicyVersion,
    },
    error::{CoreError, Result},
    processes::LaunchTarget,
    vpn::VpnEpoch,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyAdaptationKind {
    EnvOnly,
    EnvAndElectronSwitches,
    ClaudeCodeProcessWrapper,
}

pub const NODE_ESM_ENTRY_FORMAT: &str = "node_esm_v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptSourceProof {
    pub source_id: String,
    pub source_revision: String,
    pub launcher_format: String,
}

/// Remove only startup inputs that could load code ahead of the approved Node
/// entry or replace the helper/interpreter's loaded libraries.
pub fn script_startup_input(key: &str) -> bool {
    loader_startup_input(key)
        || matches!(key, "NODE_OPTIONS" | "NODE_PATH" | "NODE_COMPILE_CACHE" | "OPENSSL_CONF" | "OPENSSL_MODULES")
}

pub fn loader_startup_input(key: &str) -> bool {
    key.starts_with("DYLD_") || key.starts_with("__XPC_DYLD_") || key.starts_with("LD_")
        || matches!(key, "BASH_ENV" | "ENV")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlledLaunchRequest {
    pub entry_id: String,
    pub target: LaunchTarget,
    pub target_executable: String,
    pub target_fingerprint: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    pub proxy_adaptation: ProxyAdaptationKind,
    pub gateway_endpoint: String,
    pub policy_version: PolicyVersion,
    #[serde(default)]
    pub vpn_epoch: Option<VpnEpoch>,
    pub launch_nonce: String,
    pub executor_boot_id: String,
    /// Optional script file when executing an interpreter-bound script CLI (`N3`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_entry: Option<String>,
    /// SHA-256 fingerprint of `script_entry`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_fingerprint: Option<String>,
    /// Optional verified interpreter binary (e.g. `/usr/local/bin/node` or `/bin/sh`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<String>,
    /// SHA-256 fingerprint of the interpreter
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpreter_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_source: Option<ScriptSourceProof>,
}

impl ControlledLaunchRequest {
    pub fn validate(&self) -> Result<()> {
        if self.entry_id.trim().is_empty()
            || self.entry_id.len() > 128
            || self.entry_id.chars().any(char::is_control)
        {
            return Err(CoreError::new("invalid_launch_request", "受控入口标识无效"));
        }
        if !self.target_executable.starts_with('/')
            || self.target_executable.len() > 1024
            || self.target_executable.chars().any(char::is_control)
        {
            return Err(CoreError::new(
                "invalid_launch_request",
                "目标程序路径必须为有效绝对路径",
            ));
        }
        if self.target_fingerprint.trim().is_empty()
            || self.target_fingerprint.len() > 256
            || self.target_fingerprint.chars().any(char::is_control)
        {
            return Err(CoreError::new("invalid_launch_request", "目标程序指纹无效"));
        }
        match (&self.script_entry, &self.script_fingerprint, &self.interpreter,
               &self.interpreter_fingerprint, &self.script_source) {
            (None, None, None, None, None) => {}
            (Some(script), Some(script_sha), Some(interpreter), Some(interpreter_sha), Some(source))
                if self.target.cli() && self.proxy_adaptation == ProxyAdaptationKind::EnvOnly
                    && script == &self.target_executable && script_sha == &self.target_fingerprint
                    && interpreter != script && interpreter.starts_with('/') && interpreter.len() <= 1024
                    && !interpreter.chars().any(char::is_control)
                    && sha256_text(script_sha) && sha256_text(interpreter_sha)
                    && source.launcher_format == NODE_ESM_ENTRY_FORMAT && sha256_text(&source.source_revision)
                    && !source.source_id.is_empty() && source.source_id.len() <= 2048
                    && !source.source_id.chars().any(char::is_control) => {}
            _ => return Err(CoreError::new("invalid_script_launch_contract", "脚本、解释器、入口形式与来源修订必须完整且互相匹配")),
        }
        if self.launch_nonce.trim().is_empty()
            || self.launch_nonce.len() > 128
            || self.launch_nonce.chars().any(char::is_control)
        {
            return Err(CoreError::new("invalid_launch_request", "受控启动 nonce 无效"));
        }
        if self.executor_boot_id.trim().is_empty()
            || self.executor_boot_id.len() > 128
            || self.executor_boot_id.chars().any(char::is_control)
        {
            return Err(CoreError::new("invalid_launch_request", "目标执行器实例标识无效"));
        }
        if !self.policy_version.valid() {
            return Err(CoreError::new("invalid_launch_request", "受控启动策略摘要无效"));
        }
        let addr: SocketAddr = self.gateway_endpoint.parse().map_err(|_| {
            CoreError::new("invalid_launch_request", "受控网关端点必须为有效回环 SocketAddr")
        })?;
        if !addr.ip().is_loopback() || addr.port() == 0 {
            return Err(CoreError::new(
                "invalid_launch_request",
                "受控网关端点必须为非零端口本机回环地址",
            ));
        }
        Ok(())
    }
}

fn sha256_text(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedInstanceState {
    EntryConfigured,
    Preparing,
    SandboxApplied,
    ExecVerified,
    RunningUnprotected,
    Exited,
    Failed,
}

impl ManagedInstanceState {
    pub fn label_zh(self) -> &'static str {
        match self {
            Self::EntryConfigured => "入口已配置",
            Self::Preparing => "正在准备受控启动",
            Self::SandboxApplied => "沙箱已应用（待核验目标进程）",
            Self::ExecVerified => "受控运行（已核验沙箱与进程身份）",
            Self::RunningUnprotected => "运行中但未受保护",
            Self::Exited => "已退出",
            Self::Failed => "启动或保护失败",
        }
    }

    pub fn is_protected_active(self) -> bool {
        matches!(self, Self::ExecVerified)
    }
}

/// Authoritative evidence produced only after the trusted helper authenticates over the
/// kernel-verified registration channel and applies the irreversible OS sandbox.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxLaunchEvidence {
    pub applied: bool,
    pub backend: NetworkBackendKind,
    pub policy_version: PolicyVersion,
    pub allowed_gateway_endpoint: String,
    pub direct_network_blocked: bool,
    pub unix_relay_blocked: bool,
    pub verified_helper_origin: bool,
    pub helper_cdhash: String,
    pub helper_identity: BoundProcessToken,
    pub executor_boot_id: String,
    pub applied_at: f64,
}

impl SandboxLaunchEvidence {
    pub fn is_trusted(&self, expected_boot_id: &str, current_policy: &PolicyVersion) -> bool {
        let valid_gateway = self
            .allowed_gateway_endpoint
            .parse::<SocketAddr>()
            .is_ok_and(|addr| addr.ip().is_loopback() && addr.port() > 0);
        self.applied
            && self.backend == NetworkBackendKind::Seatbelt
            && self.direct_network_blocked
            && self.unix_relay_blocked
            && self.verified_helper_origin
            && !self.helper_cdhash.trim().is_empty()
            && self.helper_identity.has_verified_audit_token()
            && !expected_boot_id.trim().is_empty()
            && self.executor_boot_id == expected_boot_id
            && current_policy.valid()
            && &self.policy_version == current_policy
            && valid_gateway
            && self.applied_at.is_finite()
            && self.applied_at > 0.0
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManagedLaunchInstance {
    pub instance_id: String,
    pub entry_id: String,
    pub family: String,
    pub target: LaunchTarget,
    pub launch_nonce: String,
    pub executor_boot_id: String,
    pub helper_identity: Option<BoundProcessToken>,
    pub expected_executable: String,
    pub expected_fingerprint: String,
    pub exec_identity: Option<BoundProcessToken>,
    pub verified_executable: Option<String>,
    pub pid: u32,
    pub uid: u32,
    pub start_seconds: u64,
    pub start_microseconds: u32,
    #[serde(default)]
    pub controlled_subtree_pids: Vec<u32>,
    pub state: ManagedInstanceState,
    #[serde(default)]
    pub sandbox_evidence: Option<SandboxLaunchEvidence>,
    pub updated_at: f64,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_entry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_fingerprint: Option<String>,
}

impl ManagedLaunchInstance {
    /// Returns true if the main process of this instance is alive and currently
    /// has verified protection (`ExecVerified`, matching audit token, matching
    /// expected executable, and trusted sandbox evidence).
    pub fn has_verified_main_protection(
        &self,
        expected_boot_id: &str,
        current_policy: &PolicyVersion,
    ) -> bool {
        if self.state != ManagedInstanceState::ExecVerified {
            return false;
        }
        let Some(ref exec_token) = self.exec_identity else {
            return false;
        };
        if !exec_token.has_verified_audit_token()
            || exec_token.pid != self.pid
            || exec_token.uid != self.uid
            || exec_token.start_seconds != self.start_seconds
            || exec_token.start_microseconds != self.start_microseconds
        {
            return false;
        }
        // Reject helper-token reuse: post-exec target executable must match expected target.
        if self.verified_executable.as_deref() != Some(self.expected_executable.as_str()) {
            return false;
        }
        let Some(ref evidence) = self.sandbox_evidence else {
            return false;
        };
        evidence.is_trusted(expected_boot_id, current_policy)
    }

    /// Returns true if the managed sandboxed subtree (including inherited descendant
    /// child processes) remains protected by trusted sandbox evidence.
    ///
    /// macOS Seatbelt restrictions are irreversibly applied to the process and inherited
    /// by all descendant `fork`/`exec` children. Even when the initial main process exits,
    /// verified descendant children in `controlled_subtree_pids` remain bound by Seatbelt
    /// as long as the instance did not fail and evidence is trusted.
    pub fn has_verified_subtree_protection(
        &self,
        expected_boot_id: &str,
        current_policy: &PolicyVersion,
    ) -> bool {
        if self.state == ManagedInstanceState::Failed || self.state == ManagedInstanceState::Exited {
            return false;
        }
        let Some(ref evidence) = self.sandbox_evidence else {
            return false;
        };
        evidence.is_trusted(expected_boot_id, current_policy)
    }

    /// Legacy / main-process verification check.
    pub fn has_verified_protection(
        &self,
        expected_boot_id: &str,
        current_policy: &PolicyVersion,
    ) -> bool {
        self.has_verified_main_protection(expected_boot_id, current_policy)
    }

    pub fn covers_process(&self, pid: u32) -> bool {
        self.pid == pid || self.controlled_subtree_pids.contains(&pid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedScriptCombo {
    pub target: LaunchTarget,
    pub entry_path: String,
    pub script_path: String,
    pub script_fingerprint: String,
    pub package_path: String,
    pub package_fingerprint: String,
    pub interpreter_entry_path: String,
    pub interpreter_path: String,
    pub interpreter_fingerprint: String,
    pub source_id: String,
    pub source_revision: String,
    pub launcher_format: String,
}

impl ApprovedScriptCombo {
    pub fn source_proof(&self) -> ScriptSourceProof {
        ScriptSourceProof { source_id: self.source_id.clone(), source_revision: self.source_revision.clone(),
            launcher_format: self.launcher_format.clone() }
    }
    pub fn matches_request(&self, req: &ControlledLaunchRequest) -> bool {
        self.target == req.target && req.script_entry.as_ref() == Some(&self.script_path)
            && req.script_fingerprint.as_ref() == Some(&self.script_fingerprint)
            && req.interpreter.as_ref() == Some(&self.interpreter_path)
            && req.interpreter_fingerprint.as_ref() == Some(&self.interpreter_fingerprint)
            && req.script_source.as_ref() == Some(&self.source_proof())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcceptedConnectionContext {
    pub connection_id: u64,
    pub protocol: FlowTransportProtocol,
    pub peer_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub listener_boot_id: String,
    pub accepted_at: f64,
    #[serde(skip)]
    pub socket_fd: Option<i32>,
}

impl AcceptedConnectionContext {
    pub fn is_valid_for_listener(&self, expected_listener_boot_id: &str) -> bool {
        self.connection_id > 0
            && !expected_listener_boot_id.trim().is_empty()
            && self.listener_boot_id == expected_listener_boot_id
            && self.peer_addr.ip().is_loopback()
            && self.local_addr.ip().is_loopback()
            && self.peer_addr.port() > 0
            && self.local_addr.port() > 0
            && self.accepted_at.is_finite()
            && self.accepted_at > 0.0
    }
}

