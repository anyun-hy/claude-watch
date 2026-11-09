//! Versioned application channel permits, execution commands, receipts, and
//! monitor subscription contracts.
//!
//! Default disposition is cutting off the supervised application's network
//! channel while keeping its process alive (`断流保进程`). Interception must
//! remain active while a channel is revoked so traffic never falls back to
//! direct routing. Missing or failed enforcement reports `保护不可用／执行失败`
//! and never displays `已阻断` or implicitly invokes legacy process exit.
use crate::{
    error::{CoreError, Result},
    processes::ProcessRole,
    session::{Desktop, Egress, Phase, Session, GUARD_EGRESS_TTL},
    vpn::{VpnEpoch, VpnMatch},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const DEFAULT_PERMIT_TTL: f64 = 10.0;
pub const MAX_ENFORCEMENT_RECEIPT_AGE: f64 = 10.0;
pub const CLOCK_ROLLBACK_TOLERANCE_SECONDS: f64 = 0.05;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkBackendKind {
    #[default]
    #[serde(alias = "network-extension", alias = "ne", alias = "legacy_ne")]
    NetworkExtension,
    #[serde(rename = "seatbelt", alias = "sandbox", alias = "nono")]
    Seatbelt,
}

impl NetworkBackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NetworkExtension => "network_extension",
            Self::Seatbelt => "seatbelt",
        }
    }

    pub fn is_sandbox(self) -> bool {
        matches!(self, Self::Seatbelt)
    }

    pub fn is_network_extension(self) -> bool {
        matches!(self, Self::NetworkExtension)
    }

    pub fn parse_wire(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "network_extension" | "network-extension" | "ne" | "legacy_ne" => {
                Some(Self::NetworkExtension)
            }
            "seatbelt" | "sandbox" | "nono" => Some(Self::Seatbelt),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct BackendCoverageScope {
    pub backend: NetworkBackendKind,
    pub configured_entries: Vec<String>,
    pub protected_pids: Vec<u32>,
    pub unprotected_pids: Vec<u32>,
    pub uncovered_boundaries: Vec<String>,
    pub server_identity_verified: bool,
    #[serde(default)]
    pub gateway_endpoint_protection_verified: bool,
    #[serde(default)]
    pub gateway_endpoint_protection_method: Option<String>,
}

impl BackendCoverageScope {
    pub fn has_unprotected_processes(&self) -> bool {
        !self.unprotected_pids.is_empty()
    }

    pub fn all_discovered_protected(&self) -> bool {
        !self.protected_pids.is_empty() && self.unprotected_pids.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyVersion {
    pub policy_digest: String,
    pub guard_policy_digest: String,
}
impl PolicyVersion {
    pub fn valid(&self) -> bool {
        !self.policy_digest.is_empty()
            && self.policy_digest.len() <= 128
            && !self.policy_digest.chars().any(char::is_control)
            && !self.guard_policy_digest.is_empty()
            && self.guard_policy_digest.len() <= 128
            && !self.guard_policy_digest.chars().any(char::is_control)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelPermitState {
    PendingVerification,
    Permitted,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelEnforcementState {
    PendingVerification,
    Forwarding,
    Disconnecting,
    Blocked,
    Failed,
}
impl ChannelEnforcementState {
    pub fn label_zh(self) -> &'static str {
        match self {
            Self::PendingVerification => "待验证",
            Self::Forwarding => "获准转发",
            Self::Disconnecting => "正在断开",
            Self::Blocked => "已阻断",
            Self::Failed => "执行失败",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelMonitorDisplayState {
    PendingVerification,
    Forwarding,
    Disconnecting,
    Blocked,
    Failed,
}
impl ChannelMonitorDisplayState {
    pub fn label_zh(self) -> &'static str {
        match self {
            Self::PendingVerification => "待验证",
            Self::Forwarding => "获准转发",
            Self::Disconnecting => "正在断开",
            Self::Blocked => "已阻断",
            Self::Failed => "执行失败",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySyncState {
    Applied,
    PendingApply,
    ApplyFailed,
}
impl PolicySyncState {
    pub fn label_zh(self) -> &'static str {
        match self {
            Self::Applied => "执行器已应用",
            Self::PendingApply => "配置已保存（待执行器应用）",
            Self::ApplyFailed => "配置已保存（执行器应用失败）",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowTransportProtocol {
    TcpIpv4,
    TcpIpv6,
    UdpQuic,
    Dns,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolDisposition {
    ForwardViaControlledTunnel,
    ClaimAndBlock,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlledPathEvidence {
    pub family: String,
    pub upstream_endpoint: String,
    pub policy_version: PolicyVersion,
    pub context_id: String,
    pub via_controlled_path: bool,
    pub observed_at: f64,
    #[serde(default)]
    pub backend: NetworkBackendKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_epoch: Option<VpnEpoch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor_boot_id: Option<String>,
}
impl ControlledPathEvidence {
    pub fn parse(value: &Value) -> Option<Self> {
        serde_json::from_value(value.clone()).ok()
    }

    pub fn matches_path(
        &self,
        family: &str,
        expected_upstream: &str,
        current_policy: &PolicyVersion,
        expected_context_id: Option<&str>,
        now: f64,
        ttl: f64,
    ) -> std::result::Result<(), &'static str> {
        self.matches_path_with_vpn(
            family,
            expected_upstream,
            current_policy,
            expected_context_id,
            None,
            now,
            ttl,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn matches_path_with_vpn(
        &self,
        family: &str,
        expected_upstream: &str,
        current_policy: &PolicyVersion,
        expected_context_id: Option<&str>,
        expected_vpn_epoch: Option<&VpnEpoch>,
        now: f64,
        ttl: f64,
    ) -> std::result::Result<(), &'static str> {
        if !self.via_controlled_path {
            return Err("evidence_not_from_controlled_path");
        }
        if !self.family.is_empty() && self.family != "*" && self.family != family {
            return Err("evidence_family_mismatch");
        }
        if expected_upstream.trim().is_empty()
            || self.upstream_endpoint.trim() != expected_upstream.trim()
        {
            return Err("evidence_path_mismatch");
        }
        if !current_policy.valid() || &self.policy_version != current_policy {
            return Err("evidence_policy_version_mismatch");
        }
        if let Some(expected_epoch) = expected_vpn_epoch {
            if !expected_epoch.is_valid() || self.vpn_epoch.as_ref() != Some(expected_epoch) {
                return Err("evidence_vpn_epoch_mismatch");
            }
        }
        if let Some(ctx) = expected_context_id.filter(|s| !s.is_empty()) {
            if self.context_id != ctx {
                return Err("evidence_context_mismatch");
            }
        } else if self.context_id.trim().is_empty() {
            return Err("evidence_context_missing");
        }
        if !self.observed_at.is_finite()
            || !now.is_finite()
            || self.observed_at > now + 1.0
            || now - self.observed_at >= ttl
        {
            return Err("egress_evidence_expired");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundProcessToken {
    pub pid: u32,
    pub uid: u32,
    pub start_seconds: u64,
    pub start_microseconds: u32,
    pub role: ProcessRole,
    #[serde(default)]
    pub audit_token: Option<[u32; 8]>,
}
impl BoundProcessToken {
    pub fn with_system_identity(
        pid: u32,
        uid: u32,
        start_seconds: u64,
        start_microseconds: u32,
        role: ProcessRole,
    ) -> Self {
        Self {
            pid,
            uid,
            start_seconds,
            start_microseconds,
            role,
            audit_token: None,
        }
    }

    pub fn with_audit_token(mut self, audit_token: [u32; 8]) -> Self {
        self.audit_token = Some(audit_token);
        self
    }

    pub fn has_valid_identity(&self) -> bool {
        if self.pid <= 1 || self.uid == 0 || self.start_seconds == 0 {
            return false;
        }
        if let Some(ref token) = self.audit_token {
            // Verify XNU Mach audit_token_t standard layout:
            // token[5] is PID, token[1] is EUID, token[3] is RUID.
            token[5] == self.pid && (token[1] == self.uid || token[3] == self.uid)
        } else {
            true
        }
    }

    pub fn has_verified_audit_token(&self) -> bool {
        self.has_valid_identity() && self.audit_token.is_some()
    }

    pub fn matches_process(
        &self,
        pid: u32,
        uid: u32,
        start_seconds: u64,
        start_microseconds: u32,
        audit_token: Option<&[u32; 8]>,
    ) -> bool {
        if !self.has_valid_identity()
            || uid == 0
            || self.pid != pid
            || self.uid != uid
            || self.start_seconds != start_seconds
            || self.start_microseconds != start_microseconds
        {
            return false;
        }
        match (&self.audit_token, audit_token) {
            (Some(expected), Some(actual)) => expected == actual,
            (Some(_), None) => false,
            (None, Some(actual)) => {
                actual[5] == pid && (actual[1] == uid || actual[3] == uid)
            }
            (None, None) => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelPermit {
    pub family: String,
    pub session_id: Option<String>,
    pub policy_version: PolicyVersion,
    pub permit_generation: u64,
    pub command_seq: u64,
    pub state: ChannelPermitState,
    pub reason_code: String,
    pub issued_at: f64,
    pub valid_until: f64,
    pub context_id: Option<String>,
    pub baseline_ip: Option<String>,
    pub members: Vec<Desktop>,
    #[serde(default)]
    pub backend: NetworkBackendKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_epoch: Option<VpnEpoch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_scope: Option<BackendCoverageScope>,
}
impl ChannelPermit {
    /// Unified expiry and clock check shared across Rust and Swift:
    /// - Policy version mismatch -> `Revoked("policy_version_changed")`
    /// - System wake from sleep -> `Revoked("sleep_wake_reverify_required")`
    /// - Wall-clock rollback (`now < issued_at` or `now < last_wall_now`) -> `Revoked("clock_rollback_detected")`
    /// - Lease deadline reached (`now >= valid_until`, inclusive `>=`) -> `Revoked("permit_lease_expired")`
    pub fn effective_state_with_clock(
        &self,
        now: f64,
        last_wall_now: Option<f64>,
        woke_from_sleep: bool,
        current_policy: &PolicyVersion,
    ) -> (ChannelPermitState, &'static str) {
        self.effective_state_with_vpn_epoch(now, last_wall_now, woke_from_sleep, current_policy, None)
    }

    pub fn effective_state_with_vpn_epoch(
        &self,
        now: f64,
        last_wall_now: Option<f64>,
        woke_from_sleep: bool,
        current_policy: &PolicyVersion,
        current_vpn_epoch: Option<&VpnEpoch>,
    ) -> (ChannelPermitState, &'static str) {
        if !self.policy_version.valid() || &self.policy_version != current_policy {
            return (ChannelPermitState::Revoked, "policy_version_changed");
        }
        if let Some(expected_epoch) = current_vpn_epoch {
            if !expected_epoch.is_valid() || self.vpn_epoch.as_ref() != Some(expected_epoch) {
                return (ChannelPermitState::Revoked, "vpn_epoch_changed");
            }
        }
        if woke_from_sleep {
            return (ChannelPermitState::Revoked, "sleep_wake_reverify_required");
        }
        if !now.is_finite()
            || !self.issued_at.is_finite()
            || !self.valid_until.is_finite()
            || self.valid_until <= self.issued_at
        {
            return (ChannelPermitState::Revoked, "permit_lease_expired");
        }
        if now + CLOCK_ROLLBACK_TOLERANCE_SECONDS < self.issued_at
            || last_wall_now
                .filter(|prev| prev.is_finite())
                .is_some_and(|prev| now + CLOCK_ROLLBACK_TOLERANCE_SECONDS < prev)
        {
            return (ChannelPermitState::Revoked, "clock_rollback_detected");
        }
        // Unified inclusive boundary `now >= valid_until` (matching Swift `>=`).
        if now >= self.valid_until {
            return (ChannelPermitState::Revoked, "permit_lease_expired");
        }
        (self.state, "current_permit")
    }

    pub fn effective_state(
        &self,
        now: f64,
        current_policy: &PolicyVersion,
    ) -> (ChannelPermitState, &'static str) {
        self.effective_state_with_clock(now, None, false, current_policy)
    }

    pub fn from_guard_round(
        family: &str,
        session: Option<&Session>,
        receipt: &Value,
        policy_version: PolicyVersion,
        permit_generation: u64,
        command_seq: u64,
        now: f64,
        ttl: f64,
    ) -> Result<Self> {
        let members = match session {
            Some(s) => s.desktop_members()?,
            None => Vec::new(),
        };
        let guard_state = receipt["session_guard"]["state"].as_str().unwrap_or("");
        let action = receipt["action"].as_str().unwrap_or("observe");
        let reason_code = receipt["session_guard"]["reason"]["code"]
            .as_str()
            .or_else(|| receipt["session_notice"]["code"].as_str())
            .or_else(|| receipt["code"].as_str())
            .unwrap_or(if members.is_empty() { "idle" } else { "active" })
            .to_string();
        let state = if matches!(action, "close-desktop" | "disconnect-channel")
            || matches!(
                receipt["status"].as_str(),
                Some("protection_triggered" | "protection_unavailable")
            )
            || matches!(guard_state, "risk" | "locked")
        {
            ChannelPermitState::Revoked
        } else if matches!(guard_state, "active" | "safe")
            && session.is_some_and(|s| s.state == Phase::Active && !s.group_rechecking())
        {
            ChannelPermitState::Permitted
        } else {
            ChannelPermitState::PendingVerification
        };
        let bounded_ttl = if ttl.is_finite() && ttl > 0.0 {
            ttl
        } else {
            DEFAULT_PERMIT_TTL
        };
        Ok(Self {
            family: family.into(),
            session_id: session.map(|s| s.session_id.clone()),
            policy_version,
            permit_generation: permit_generation.max(1),
            command_seq: command_seq.max(1),
            state,
            reason_code,
            issued_at: now,
            valid_until: now + bounded_ttl,
            context_id: session
                .map(|s| s.context_id.clone())
                .filter(|s| !s.is_empty()),
            baseline_ip: session
                .map(|s| s.baseline.ip.clone())
                .filter(|s| !s.is_empty()),
            members,
            backend: NetworkBackendKind::NetworkExtension,
            vpn_epoch: None,
            coverage_scope: None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelEnforcementCommand {
    pub family: String,
    pub session_id: Option<String>,
    pub policy_version: PolicyVersion,
    pub permit_generation: u64,
    pub command_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_executor_boot_id: Option<String>,
    pub permit: ChannelPermit,
    pub allowed_processes: Vec<BoundProcessToken>,
    pub upstream_endpoint: String,
    pub issued_at: f64,
}

/// Authenticated command envelope binding a `ChannelEnforcementCommand` to a specific
/// `target_executor_boot_id`, backend kind, VPN epoch, and coverage scope at the
/// trusted receiving boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthenticatedCommandEnvelope {
    pub backend: NetworkBackendKind,
    pub target_executor_boot_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_epoch: Option<VpnEpoch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_scope: Option<BackendCoverageScope>,
    pub command: ChannelEnforcementCommand,
}

impl AuthenticatedCommandEnvelope {
    pub fn verify_target_executor(&self, actual_executor_boot_id: &str) -> Result<()> {
        if self.target_executor_boot_id.trim().is_empty()
            || actual_executor_boot_id.trim().is_empty()
            || self.target_executor_boot_id != actual_executor_boot_id
        {
            return Err(CoreError::new(
                "executor_boot_id_mismatch",
                "命令封套的目标执行器实例与当前执行器不匹配，已拒绝旧实例命令",
            ));
        }
        if self.command.permit.backend != self.backend {
            return Err(CoreError::new(
                "backend_kind_mismatch",
                "命令封套后端类型与许可后端类型不一致",
            ));
        }
        if self.vpn_epoch.is_some() && self.command.permit.vpn_epoch != self.vpn_epoch {
            return Err(CoreError::new(
                "vpn_epoch_mismatch",
                "命令封套 VPN epoch 与许可 VPN epoch 不一致",
            ));
        }
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelEnforcementReceipt {
    pub family: String,
    pub session_id: Option<String>,
    pub policy_version: PolicyVersion,
    pub permit_generation: u64,
    pub command_seq: u64,
    pub executor_boot_id: String,
    pub permit_state: ChannelPermitState,
    pub enforcement_state: ChannelEnforcementState,
    /// Must remain true even when the channel is revoked. Turning off proxy
    /// interception on macOS lets connections bypass the tunnel directly.
    pub interception_active: bool,
    #[serde(default)]
    pub local_proxy_ready: bool,
    #[serde(default)]
    pub system_extension_active: bool,
    #[serde(default = "default_true")]
    pub new_connections_blocked: bool,
    pub active_flows_closed: bool,
    pub direct_fallback_blocked: bool,
    pub active_flows_count: u32,
    pub terminated_flows_count: u32,
    pub blocked_new_connections: u32,
    pub observed_at: f64,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub backend: NetworkBackendKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_epoch: Option<VpnEpoch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_scope: Option<BackendCoverageScope>,
    #[serde(default)]
    pub sandbox_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ChannelSupervisionVerdict {
    PendingVerification {
        state: ChannelEnforcementState,
    },
    ForwardingVerified,
    PendingIsolation {
        state: ChannelEnforcementState,
    },
    IsolatedKeepProcess,
    EnforcementFailed {
        code: String,
        status_label_zh: String,
    },
}
impl ChannelSupervisionVerdict {
    pub fn display_state(&self) -> ChannelMonitorDisplayState {
        match self {
            Self::PendingVerification { .. } => ChannelMonitorDisplayState::PendingVerification,
            Self::ForwardingVerified => ChannelMonitorDisplayState::Forwarding,
            Self::PendingIsolation { .. } => ChannelMonitorDisplayState::Disconnecting,
            Self::IsolatedKeepProcess => ChannelMonitorDisplayState::Blocked,
            Self::EnforcementFailed { .. } => ChannelMonitorDisplayState::Failed,
        }
    }
}

pub fn evaluate_channel_supervision(
    permit: &ChannelPermit,
    receipt: Option<&ChannelEnforcementReceipt>,
    current_policy: &PolicyVersion,
    now: f64,
) -> ChannelSupervisionVerdict {
    evaluate_channel_supervision_with_boot_id(permit, receipt, current_policy, None, now)
}

pub fn evaluate_channel_supervision_with_boot_id(
    permit: &ChannelPermit,
    receipt: Option<&ChannelEnforcementReceipt>,
    current_policy: &PolicyVersion,
    expected_executor_boot_id: Option<&str>,
    receiver_now: f64,
) -> ChannelSupervisionVerdict {
    let (effective_permit, permit_reason) = permit.effective_state(receiver_now, current_policy);
    let Some(receipt) = receipt else {
        return ChannelSupervisionVerdict::EnforcementFailed {
            code: "channel_enforcer_unavailable".into(),
            status_label_zh: "保护不可用".into(),
        };
    };
    if receipt.family != permit.family {
        return ChannelSupervisionVerdict::EnforcementFailed {
            code: "enforcement_family_mismatch".into(),
            status_label_zh: "执行失败".into(),
        };
    }
    if !receipt.policy_version.valid() || &receipt.policy_version != current_policy {
        return ChannelSupervisionVerdict::EnforcementFailed {
            code: "stale_policy_version_receipt".into(),
            status_label_zh: "执行失败".into(),
        };
    }
    if receipt.session_id != permit.session_id {
        return ChannelSupervisionVerdict::EnforcementFailed {
            code: "stale_session_receipt".into(),
            status_label_zh: "执行失败".into(),
        };
    }
    if receipt.permit_generation != permit.permit_generation {
        return ChannelSupervisionVerdict::EnforcementFailed {
            code: "stale_permit_generation_receipt".into(),
            status_label_zh: "执行失败".into(),
        };
    }
    if receipt.command_seq != permit.command_seq {
        return ChannelSupervisionVerdict::EnforcementFailed {
            code: "stale_or_out_of_order_command_receipt".into(),
            status_label_zh: "执行失败".into(),
        };
    }
    if receipt.executor_boot_id.trim().is_empty() {
        return ChannelSupervisionVerdict::EnforcementFailed {
            code: "invalid_executor_boot_id".into(),
            status_label_zh: "执行失败".into(),
        };
    }
    if let Some(expected_boot_id) = expected_executor_boot_id {
        if expected_boot_id.trim().is_empty() || receipt.executor_boot_id != expected_boot_id {
            return ChannelSupervisionVerdict::EnforcementFailed {
                code: "executor_boot_id_mismatch".into(),
                status_label_zh: "执行失败".into(),
            };
        }
    }
    if !receipt.observed_at.is_finite()
        || !receiver_now.is_finite()
        || receipt.observed_at > receiver_now + 1.0
        || receiver_now - receipt.observed_at >= MAX_ENFORCEMENT_RECEIPT_AGE
    {
        return ChannelSupervisionVerdict::EnforcementFailed {
            code: "enforcement_receipt_expired".into(),
            status_label_zh: "执行失败".into(),
        };
    }
    if receipt.observed_at + 0.001 < permit.issued_at {
        return ChannelSupervisionVerdict::EnforcementFailed {
            code: "receipt_predates_permit".into(),
            status_label_zh: "执行失败".into(),
        };
    }
    if receipt.backend != permit.backend {
        return ChannelSupervisionVerdict::EnforcementFailed {
            code: "backend_kind_mismatch".into(),
            status_label_zh: "执行失败".into(),
        };
    }
    if permit.backend.is_sandbox() && receipt.system_extension_active {
        return ChannelSupervisionVerdict::EnforcementFailed {
            code: "sandbox_receipt_claims_system_extension".into(),
            status_label_zh: "执行失败".into(),
        };
    }
    if permit.vpn_epoch.is_some() && receipt.vpn_epoch != permit.vpn_epoch {
        return ChannelSupervisionVerdict::EnforcementFailed {
            code: "stale_vpn_epoch_receipt".into(),
            status_label_zh: "执行失败".into(),
        };
    }
    // Critical invariant: disabling interception or returning false in
    // NETransparentProxyProvider allows direct connections and is never valid.
    if !receipt.interception_active || !receipt.direct_fallback_blocked {
        return ChannelSupervisionVerdict::EnforcementFailed {
            code: "interception_inactive_direct_leak_risk".into(),
            status_label_zh: "执行失败".into(),
        };
    }
    if receipt.enforcement_state == ChannelEnforcementState::Failed {
        return ChannelSupervisionVerdict::EnforcementFailed {
            code: receipt
                .error_code
                .clone()
                .unwrap_or_else(|| "enforcement_reported_failure".into()),
            status_label_zh: "执行失败".into(),
        };
    }
    match effective_permit {
        ChannelPermitState::Permitted => {
            if receipt.permit_state == ChannelPermitState::Permitted
                && receipt.enforcement_state == ChannelEnforcementState::Forwarding
            {
                ChannelSupervisionVerdict::ForwardingVerified
            } else if matches!(
                receipt.enforcement_state,
                ChannelEnforcementState::PendingVerification
                    | ChannelEnforcementState::Disconnecting
                    | ChannelEnforcementState::Blocked
            ) {
                ChannelSupervisionVerdict::PendingVerification {
                    state: receipt.enforcement_state,
                }
            } else {
                ChannelSupervisionVerdict::EnforcementFailed {
                    code: "permitted_channel_not_forwarding".into(),
                    status_label_zh: "执行失败".into(),
                }
            }
        }
        ChannelPermitState::PendingVerification => {
            if matches!(
                receipt.enforcement_state,
                ChannelEnforcementState::PendingVerification
                    | ChannelEnforcementState::Disconnecting
                    | ChannelEnforcementState::Blocked
            ) {
                ChannelSupervisionVerdict::PendingVerification {
                    state: receipt.enforcement_state,
                }
            } else {
                ChannelSupervisionVerdict::EnforcementFailed {
                    code: "pending_channel_not_held".into(),
                    status_label_zh: "执行失败".into(),
                }
            }
        }
        ChannelPermitState::Revoked => {
            if receipt.enforcement_state == ChannelEnforcementState::Blocked
                && !receipt.new_connections_blocked
            {
                return ChannelSupervisionVerdict::EnforcementFailed {
                    code: "new_connections_not_blocked".into(),
                    status_label_zh: "执行失败".into(),
                };
            }
            // "已阻断" requires traffic takeover active, new connections prohibited,
            // and all existing connections confirmed closed.
            if receipt.enforcement_state == ChannelEnforcementState::Blocked
                && receipt.new_connections_blocked
                && receipt.active_flows_closed
                && receipt.active_flows_count == 0
            {
                ChannelSupervisionVerdict::IsolatedKeepProcess
            } else if receipt.enforcement_state == ChannelEnforcementState::Disconnecting
                && receipt.new_connections_blocked
                && (permit_reason == "current_permit" || permit_reason == "permit_lease_expired")
            {
                ChannelSupervisionVerdict::PendingIsolation {
                    state: ChannelEnforcementState::Disconnecting,
                }
            } else {
                ChannelSupervisionVerdict::EnforcementFailed {
                    code: "channel_cutoff_incomplete".into(),
                    status_label_zh: "执行失败".into(),
                }
            }
        }
    }
}

/// System extension execution receipt produced by WatchChannelExtension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemExtensionReceipt {
    pub family: String,
    #[serde(default)]
    pub command_binding: String,
    pub executor_boot_id: String,
    pub extension_boot_id: String,
    pub policy_version: PolicyVersion,
    pub command_seq: u64,
    pub permit_generation: u64,
    pub applied_at: f64,
    pub allowed_pids: Vec<u32>,
    #[serde(default)]
    pub local_proxy_port: u16,
    pub permit_state: String,
    pub status: String,
    pub active_flows: usize,
    pub new_connections_blocked: bool,
    pub reason: Option<String>,
}

impl SystemExtensionReceipt {
    pub fn is_fresh(&self, now: f64, max_age_seconds: f64) -> bool {
        self.applied_at.is_finite() && now.is_finite() && max_age_seconds > 0.0
            && self.applied_at > 0.0 && self.applied_at <= now + 1.0
            && now - self.applied_at <= max_age_seconds
    }

    pub fn is_disconnecting(&self) -> bool {
        self.status == "disconnecting"
            || self.permit_state == "disconnecting"
            || (self.status == "revoked" && self.active_flows > 0)
    }

    pub fn is_confirmed_revoked(&self) -> bool {
        self.status == "revoked" && self.permit_state == "revoked"
            && self.active_flows == 0
            && self.new_connections_blocked
    }

    pub fn matches_supervision(
        &self,
        expected_policy_version: &PolicyVersion,
        expected_command_seq: u64,
        expected_generation: u64,
        expected_boot: &str,
        extension_boot: &str,
        issued_at: f64,
        now: f64,
    ) -> bool {
        self.executor_boot_id == expected_boot
            && !extension_boot.is_empty()
            && self.extension_boot_id == extension_boot
            && &self.policy_version == expected_policy_version
            && self.command_seq == expected_command_seq
            && self.permit_generation == expected_generation
            && self.applied_at.is_finite()
            && self.applied_at >= issued_at - CLOCK_ROLLBACK_TOLERANCE_SECONDS
            && self.applied_at <= now + CLOCK_ROLLBACK_TOLERANCE_SECONDS
    }
}

/// Liveness is refreshed independently; an acknowledgement keeps its execution time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemExtensionHeartbeat {
    pub executor_boot_id: String,
    pub extension_boot_id: String,
    pub heartbeat_at: f64,
    pub interception_active: bool,
}
impl SystemExtensionHeartbeat {
    pub fn is_live(&self, executor_boot: &str, now: f64) -> bool {
        self.executor_boot_id == executor_boot && !self.extension_boot_id.is_empty()
            && self.interception_active && self.heartbeat_at.is_finite() && now.is_finite()
            && self.heartbeat_at <= now + CLOCK_ROLLBACK_TOLERANCE_SECONDS
            && now - self.heartbeat_at < 8.0
    }
}

/// Restoring a revoked channel requires fresh evidence sampled strictly after
/// the revocation timestamp under the current session and current policy version.
/// Old probe results or another session's audit can never re-open a blocked channel.
#[allow(clippy::too_many_arguments)]
pub fn verify_channel_recovery(
    previous: &ChannelPermit,
    revoked_at: f64,
    audit_session_id: Option<&str>,
    audit_ready: bool,
    audit_observed_at: f64,
    audit_policy: &PolicyVersion,
    egress: &Value,
    current_session_id: Option<&str>,
    current_policy: &PolicyVersion,
    context_id: &str,
    next_permit_generation: u64,
    next_command_seq: u64,
    now: f64,
    ttl: f64,
) -> Result<ChannelPermit> {
    if !current_policy.valid() || audit_policy != current_policy {
        return Err(CoreError::new(
            "recovery_policy_version_mismatch",
            "恢复证据的策略版本已过期，不能重新放行已阻断通道",
        ));
    }
    if current_session_id.is_none()
        || previous.session_id.as_deref() != current_session_id
        || audit_session_id != current_session_id
    {
        return Err(CoreError::new(
            "recovery_session_mismatch",
            "恢复证据不属于当前受保护会话，不能重新放行已阻断通道",
        ));
    }
    if !audit_ready {
        return Err(CoreError::new(
            "recovery_audit_blocked",
            "环境复核未通过，通道保持阻断",
        ));
    }
    let fence = revoked_at.max(previous.issued_at);
    if !audit_observed_at.is_finite()
        || audit_observed_at <= fence
        || audit_observed_at > now + 1.0
    {
        return Err(CoreError::new(
            "recovery_evidence_stale",
            "恢复证据不晚于上次阻断时刻或时间无效，不能恢复通道",
        ));
    }
    let Some(exit) = Egress::fresh(egress, now, GUARD_EGRESS_TTL) else {
        return Err(CoreError::new(
            "recovery_egress_unconfirmed",
            "当前出口未确认新鲜有效，不能恢复通道",
        ));
    };
    if exit.country == "CN" || exit.observed_at <= fence {
        return Err(CoreError::new(
            "recovery_egress_blocked",
            "当前出口仍处风险区或不晚于阻断时刻，不能恢复通道",
        ));
    }
    let ev: ControlledPathEvidence = serde_json::from_value(egress.clone()).map_err(|_| {
        CoreError::new(
            "evidence_not_from_controlled_path",
            "当前出口证据反序列化失败或缺少受控诊断同路径必要字段，不能恢复通道",
        )
    })?;
    if let Err(err_code) = ev.matches_path(
        &previous.family,
        ev.upstream_endpoint.as_str(),
        current_policy,
        Some(context_id),
        now,
        GUARD_EGRESS_TTL,
    ) {
        return Err(CoreError::new(
            err_code,
            "当前出口证据未通过受控通道同路径验证，不能恢复通道",
        ));
    }
    if context_id.is_empty() {
        return Err(CoreError::new(
            "recovery_context_missing",
            "缺少受控通道上下文标识，不能恢复通道",
        ));
    }
    let bounded_ttl = if ttl.is_finite() && ttl > 0.0 {
        ttl
    } else {
        DEFAULT_PERMIT_TTL
    };
    let evidence_expires_at = exit.observed_at + GUARD_EGRESS_TTL;
    let valid_until = (now + bounded_ttl).min(evidence_expires_at);
    if valid_until <= now {
        return Err(CoreError::new(
            "recovery_egress_unconfirmed",
            "当前出口证据剩余有效期不足，不能恢复通道",
        ));
    }
    Ok(ChannelPermit {
        family: previous.family.clone(),
        session_id: current_session_id.map(str::to_owned),
        policy_version: current_policy.clone(),
        permit_generation: next_permit_generation.max(previous.permit_generation + 1),
        command_seq: next_command_seq.max(previous.command_seq + 1),
        state: ChannelPermitState::Permitted,
        reason_code: "channel_recovered".into(),
        issued_at: now,
        valid_until,
        context_id: Some(context_id.into()),
        baseline_ip: Some(exit.ip),
        members: previous.members.clone(),
        backend: previous.backend,
        vpn_epoch: previous.vpn_epoch.clone(),
        coverage_scope: previous.coverage_scope.clone(),
    })
}

pub fn verify_channel_recovery_with_vpn_epoch(
    previous: &ChannelPermit,
    revoked_at: f64,
    audit_session_id: Option<&str>,
    audit_passed: bool,
    audit_completed_at: f64,
    audit_policy: &PolicyVersion,
    egress: &Value,
    current_session_id: Option<&str>,
    current_policy: &PolicyVersion,
    current_vpn_epoch: Option<&VpnEpoch>,
    context_id: &str,
    next_permit_generation: u64,
    next_command_seq: u64,
    now: f64,
    ttl: f64,
) -> Result<ChannelPermit> {
    let mut recovered = verify_channel_recovery(
        previous,
        revoked_at,
        audit_session_id,
        audit_passed,
        audit_completed_at,
        audit_policy,
        egress,
        current_session_id,
        current_policy,
        context_id,
        next_permit_generation,
        next_command_seq,
        now,
        ttl,
    )?;
    if let Some(expected_epoch) = current_vpn_epoch {
        let controlled = ControlledPathEvidence::parse(egress).ok_or_else(|| {
            CoreError::new("recovery_controlled_path_unconfirmed", "恢复证据缺少受控路径")
        })?;
        let Some(ref observed_epoch) = controlled.vpn_epoch else {
            return Err(CoreError::new(
                "recovery_vpn_epoch_missing",
                "恢复证据缺少当前 VPN epoch 绑定",
            ));
        };
        if observed_epoch != expected_epoch {
            return Err(CoreError::new(
                "recovery_vpn_epoch_mismatch",
                "恢复证据的 VPN epoch 与当前观测不一致",
            ));
        }
        recovered.vpn_epoch = Some(expected_epoch.clone());
    }
    Ok(recovered)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FamilyChannelMonitorState {
    #[serde(default)]
    pub producer_boot_id: String,
    pub family: String,
    pub session_id: Option<String>,
    pub saved_policy_version: PolicyVersion,
    pub applied_policy_version: Option<PolicyVersion>,
    pub policy_sync_state: PolicySyncState,
    pub policy_sync_label_zh: String,
    pub permit_generation: u64,
    pub command_seq: u64,
    pub permit_state: ChannelPermitState,
    pub display_state: ChannelMonitorDisplayState,
    pub display_label_zh: String,
    pub reason_code: String,
    pub process_preserved: bool,
    pub active_member_pids: Vec<u32>,
    #[serde(default)]
    pub active_members: Vec<BoundProcessToken>,
    #[serde(default)]
    pub local_proxy_ready: bool,
    #[serde(default)]
    pub system_extension_active: bool,
    pub active_flows_count: u32,
    pub terminated_flows_count: u32,
    pub blocked_new_connections: u32,
    #[serde(default)]
    pub local_proxy_port: Option<u16>,
    #[serde(default)]
    pub valid_until: Option<f64>,
    pub updated_at: f64,
    #[serde(default)]
    pub backend: NetworkBackendKind,
    #[serde(default)]
    pub vpn_epoch: Option<VpnEpoch>,
    #[serde(default)]
    pub vpn_match: Option<VpnMatch>,
    #[serde(default)]
    pub coverage_scope: BackendCoverageScope,
    #[serde(default)]
    pub unmanaged_member_pids: Vec<u32>,
    #[serde(default)]
    pub sandbox_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelMonitorSnapshot {
    #[serde(default)]
    pub producer_boot_id: String,
    pub snapshot_seq: u64,
    pub captured_at: f64,
    pub saved_policy_version: PolicyVersion,
    pub families: BTreeMap<String, FamilyChannelMonitorState>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelMonitorEvent {
    #[serde(default)]
    pub producer_boot_id: String,
    pub event_seq: u64,
    pub family_state: FamilyChannelMonitorState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionApplyOutcome {
    Applied,
    IgnoredStaleEvent,
    GapDetectedResyncRequired { expected_seq: u64, received_seq: u64 },
}

/// Monitor-side subscriber state machine that enforces monotonic `event_seq`,
/// detects producer restarts via `producer_boot_id`, rejects stale/out-of-order
/// events, and requires a full snapshot resync whenever a sequence gap,
/// producer restart, or reconnect occurs.
#[derive(Debug, Clone)]
pub struct ChannelMonitorSubscriber {
    pub producer_boot_id: Option<String>,
    pub last_event_seq: u64,
    pub needs_resync: bool,
    pub saved_policy_version: Option<PolicyVersion>,
    pub families: BTreeMap<String, FamilyChannelMonitorState>,
}
impl Default for ChannelMonitorSubscriber {
    fn default() -> Self {
        Self {
            producer_boot_id: None,
            last_event_seq: 0,
            needs_resync: true,
            saved_policy_version: None,
            families: BTreeMap::new(),
        }
    }
}
impl ChannelMonitorSubscriber {
    pub fn mark_reconnected(&mut self) {
        self.needs_resync = true;
    }

    pub fn apply_snapshot(&mut self, snapshot: ChannelMonitorSnapshot) -> bool {
        let boot_id_changed = !snapshot.producer_boot_id.is_empty()
            && self
                .producer_boot_id
                .as_deref()
                .is_some_and(|prev| !prev.is_empty() && prev != snapshot.producer_boot_id);
        if snapshot.snapshot_seq < self.last_event_seq && !self.needs_resync && !boot_id_changed {
            return false;
        }
        if !snapshot.producer_boot_id.is_empty() {
            self.producer_boot_id = Some(snapshot.producer_boot_id);
        }
        self.last_event_seq = snapshot.snapshot_seq;
        self.saved_policy_version = Some(snapshot.saved_policy_version);
        self.families = snapshot.families;
        self.needs_resync = false;
        true
    }

    pub fn apply_event(&mut self, event: ChannelMonitorEvent) -> SubscriptionApplyOutcome {
        let event_boot_id = if !event.producer_boot_id.is_empty() {
            event.producer_boot_id.as_str()
        } else {
            event.family_state.producer_boot_id.as_str()
        };
        if !event_boot_id.is_empty()
            && self
                .producer_boot_id
                .as_deref()
                .is_some_and(|prev| !prev.is_empty() && prev != event_boot_id)
        {
            self.needs_resync = true;
            return SubscriptionApplyOutcome::GapDetectedResyncRequired {
                expected_seq: self.last_event_seq + 1,
                received_seq: event.event_seq,
            };
        }
        if self.needs_resync {
            return SubscriptionApplyOutcome::GapDetectedResyncRequired {
                expected_seq: self.last_event_seq + 1,
                received_seq: event.event_seq,
            };
        }
        if event.event_seq <= self.last_event_seq {
            return SubscriptionApplyOutcome::IgnoredStaleEvent;
        }
        if event.event_seq > self.last_event_seq + 1 {
            self.needs_resync = true;
            return SubscriptionApplyOutcome::GapDetectedResyncRequired {
                expected_seq: self.last_event_seq + 1,
                received_seq: event.event_seq,
            };
        }
        if let Some(existing) = self.families.get(&event.family_state.family) {
            if event.family_state.permit_generation < existing.permit_generation
                || (event.family_state.permit_generation == existing.permit_generation
                    && event.family_state.command_seq < existing.command_seq)
            {
                return SubscriptionApplyOutcome::IgnoredStaleEvent;
            }
        }
        if !event_boot_id.is_empty() && self.producer_boot_id.is_none() {
            self.producer_boot_id = Some(event_boot_id.to_string());
        }
        self.last_event_seq = event.event_seq;
        self.saved_policy_version = Some(event.family_state.saved_policy_version.clone());
        self.families
            .insert(event.family_state.family.clone(), event.family_state);
        SubscriptionApplyOutcome::Applied
    }

    /// Returns the display state for `family`, degrading to `PendingVerification`
    /// if the subscriber is disconnected (`needs_resync`) or the state is older
    /// than `max_age` at `now` so stale evidence never continues to display
    /// valid protection.
    pub fn effective_family_state(
        &self,
        family: &str,
        now: f64,
        max_age: f64,
    ) -> Option<FamilyChannelMonitorState> {
        let mut state = self.families.get(family)?.clone();
        let expired = !now.is_finite()
            || !state.updated_at.is_finite()
            || now - state.updated_at > max_age
            || state.updated_at > now + 1.0;
        if self.needs_resync || expired {
            state.display_state = ChannelMonitorDisplayState::PendingVerification;
            state.display_label_zh = "待验证（订阅失联或状态已过期）".into();
            state.reason_code = if self.needs_resync {
                "subscription_resync_required".into()
            } else {
                "monitor_evidence_expired".into()
            };
        }
        Some(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy(v: &str) -> PolicyVersion {
        PolicyVersion {
            policy_digest: format!("policy-{v}"),
            guard_policy_digest: format!("guard-{v}"),
        }
    }

    fn sample_permit(state: ChannelPermitState, p: PolicyVersion) -> ChannelPermit {
        ChannelPermit {
            family: "claude".into(),
            session_id: Some("s1".into()),
            policy_version: p,
            permit_generation: 2,
            command_seq: 5,
            state,
            reason_code: "test".into(),
            issued_at: 1000.0,
            valid_until: 1010.0,
            context_id: Some("ctx-1".into()),
            baseline_ip: Some("1.1.1.1".into()),
            members: vec![Desktop {
                pid: 42,
                start_seconds: 900,
                start_microseconds: 1,
            }],
            backend: NetworkBackendKind::NetworkExtension,
            vpn_epoch: None,
            coverage_scope: None,
        }
    }

    fn sample_receipt(
        permit: &ChannelPermit,
        enforcement_state: ChannelEnforcementState,
        active_flows_closed: bool,
        active_flows_count: u32,
    ) -> ChannelEnforcementReceipt {
        ChannelEnforcementReceipt {
            family: permit.family.clone(),
            session_id: permit.session_id.clone(),
            policy_version: permit.policy_version.clone(),
            permit_generation: permit.permit_generation,
            command_seq: permit.command_seq,
            executor_boot_id: "boot-1".into(),
            permit_state: permit.state,
            enforcement_state,
            interception_active: true,
            local_proxy_ready: true,
            system_extension_active: !permit.backend.is_sandbox(),
            new_connections_blocked: permit.state != ChannelPermitState::Permitted,
            active_flows_closed,
            direct_fallback_blocked: true,
            active_flows_count,
            terminated_flows_count: 1,
            blocked_new_connections: 0,
            observed_at: 1002.0,
            error_code: None,
            backend: permit.backend,
            vpn_epoch: permit.vpn_epoch.clone(),
            coverage_scope: permit.coverage_scope.clone(),
            sandbox_ready: permit.backend.is_sandbox(),
        }
    }

    #[test]
    fn policy_version_change_ttl_expiry_clock_rollback_and_sleep_revoke_fail_closed() {
        let v1 = policy("v1");
        let v2 = policy("v2");
        let permit = sample_permit(ChannelPermitState::Permitted, v1.clone());
        assert_eq!(
            permit.effective_state(1009.999, &v1),
            (ChannelPermitState::Permitted, "current_permit")
        );
        // Inclusive boundary `now >= valid_until`
        assert_eq!(
            permit.effective_state(1010.0, &v1),
            (ChannelPermitState::Revoked, "permit_lease_expired")
        );
        assert_eq!(
            permit.effective_state(1005.0, &v2),
            (ChannelPermitState::Revoked, "policy_version_changed")
        );
        assert_eq!(
            permit.effective_state_with_clock(1004.0, Some(1006.0), false, &v1),
            (ChannelPermitState::Revoked, "clock_rollback_detected")
        );
        assert_eq!(
            permit.effective_state_with_clock(1005.0, Some(1004.0), true, &v1),
            (ChannelPermitState::Revoked, "sleep_wake_reverify_required")
        );
    }

    #[test]
    fn turning_off_interception_or_missing_enforcer_is_never_accepted_as_blocked() {
        let v1 = policy("v1");
        let permit = sample_permit(ChannelPermitState::Revoked, v1.clone());
        assert_eq!(
            evaluate_channel_supervision(&permit, None, &v1, 1003.0),
            ChannelSupervisionVerdict::EnforcementFailed {
                code: "channel_enforcer_unavailable".into(),
                status_label_zh: "保护不可用".into(),
            }
        );
        let mut bad_receipt = sample_receipt(&permit, ChannelEnforcementState::Blocked, true, 0);
        bad_receipt.interception_active = false;
        assert_eq!(
            evaluate_channel_supervision(&permit, Some(&bad_receipt), &v1, 1003.0),
            ChannelSupervisionVerdict::EnforcementFailed {
                code: "interception_inactive_direct_leak_risk".into(),
                status_label_zh: "执行失败".into(),
            }
        );
        let mut unblocked_new_conn =
            sample_receipt(&permit, ChannelEnforcementState::Blocked, true, 0);
        unblocked_new_conn.new_connections_blocked = false;
        assert_eq!(
            evaluate_channel_supervision(&permit, Some(&unblocked_new_conn), &v1, 1003.0),
            ChannelSupervisionVerdict::EnforcementFailed {
                code: "new_connections_not_blocked".into(),
                status_label_zh: "执行失败".into(),
            }
        );
        let good_receipt = sample_receipt(&permit, ChannelEnforcementState::Blocked, true, 0);
        assert_eq!(
            evaluate_channel_supervision(&permit, Some(&good_receipt), &v1, 1003.0),
            ChannelSupervisionVerdict::IsolatedKeepProcess
        );
    }

    #[test]
    fn premature_blocked_without_flow_confirmation_and_stale_session_or_command_are_rejected() {
        let v1 = policy("v1");
        let permit = sample_permit(ChannelPermitState::Revoked, v1.clone());
        // Disconnecting state while 2 flows are still being closed
        let disconnecting =
            sample_receipt(&permit, ChannelEnforcementState::Disconnecting, false, 2);
        assert_eq!(
            evaluate_channel_supervision(&permit, Some(&disconnecting), &v1, 1003.0),
            ChannelSupervisionVerdict::PendingIsolation {
                state: ChannelEnforcementState::Disconnecting,
            }
        );
        // Claims Blocked while active_flows_count > 0 -> rejected!
        let premature_blocked =
            sample_receipt(&permit, ChannelEnforcementState::Blocked, false, 1);
        assert_eq!(
            evaluate_channel_supervision(&permit, Some(&premature_blocked), &v1, 1003.0),
            ChannelSupervisionVerdict::EnforcementFailed {
                code: "channel_cutoff_incomplete".into(),
                status_label_zh: "执行失败".into(),
            }
        );
        // Same policy version v1, but receipt belongs to old session "s0"
        let mut old_session_receipt =
            sample_receipt(&permit, ChannelEnforcementState::Blocked, true, 0);
        old_session_receipt.session_id = Some("s0".into());
        assert_eq!(
            evaluate_channel_supervision(&permit, Some(&old_session_receipt), &v1, 1003.0),
            ChannelSupervisionVerdict::EnforcementFailed {
                code: "stale_session_receipt".into(),
                status_label_zh: "执行失败".into(),
            }
        );
        // Same session and policy, but older command_seq
        let mut old_cmd_receipt =
            sample_receipt(&permit, ChannelEnforcementState::Blocked, true, 0);
        old_cmd_receipt.command_seq = 4;
        assert_eq!(
            evaluate_channel_supervision(&permit, Some(&old_cmd_receipt), &v1, 1003.0),
            ChannelSupervisionVerdict::EnforcementFailed {
                code: "stale_or_out_of_order_command_receipt".into(),
                status_label_zh: "执行失败".into(),
            }
        );
    }

    #[test]
    fn recovery_requires_same_session_current_policy_and_post_revocation_evidence() {
        let v1 = policy("v1");
        let v2 = policy("v2");
        let revoked = sample_permit(ChannelPermitState::Revoked, v1.clone());
        let fresh_egress = json!({
            "ip": "1.1.1.1",
            "country": "JP",
            "observed_at": 1005.0,
            "source": "fixture",
            "via_controlled_path": true,
            "family": "claude",
            "upstream_endpoint": "127.0.0.1:7890",
            "context_id": "ctx-2",
            "policy_version": v2,
        });
        // Wrong session ("s0" vs "s1") rejected
        assert_eq!(
            verify_channel_recovery(
                &revoked,
                1003.0,
                Some("s0"),
                true,
                1005.0,
                &v2,
                &fresh_egress,
                Some("s1"),
                &v2,
                "ctx-2",
                3,
                6,
                1006.0,
                10.0,
            )
            .unwrap_err()
            .code,
            "recovery_session_mismatch"
        );
        // Evidence at 1002.5 <= revoked_at (1003.0) rejected
        assert_eq!(
            verify_channel_recovery(
                &revoked,
                1003.0,
                Some("s1"),
                true,
                1002.5,
                &v2,
                &fresh_egress,
                Some("s1"),
                &v2,
                "ctx-2",
                3,
                6,
                1006.0,
                10.0,
            )
            .unwrap_err()
            .code,
            "recovery_evidence_stale"
        );
        let recovered = verify_channel_recovery(
            &revoked,
            1003.0,
            Some("s1"),
            true,
            1005.0,
            &v2,
            &fresh_egress,
            Some("s1"),
            &v2,
            "ctx-2",
            3,
            6,
            1006.0,
            10.0,
        )
        .unwrap();
        assert_eq!(recovered.state, ChannelPermitState::Permitted);
        assert_eq!(recovered.policy_version, v2);
        assert_eq!(recovered.permit_generation, 3);
        assert_eq!(recovered.command_seq, 6);
    }

    #[test]
    fn monitor_subscriber_rejects_stale_events_and_resyncs_on_sequence_gap_or_producer_restart() {
        let v1 = policy("v1");
        let mut sub = ChannelMonitorSubscriber::default();
        let state1 = FamilyChannelMonitorState {
            producer_boot_id: "daemon-boot-1".into(),
            family: "claude".into(),
            session_id: Some("s1".into()),
            saved_policy_version: v1.clone(),
            applied_policy_version: Some(v1.clone()),
            policy_sync_state: PolicySyncState::Applied,
            policy_sync_label_zh: PolicySyncState::Applied.label_zh().into(),
            permit_generation: 1,
            command_seq: 1,
            permit_state: ChannelPermitState::Permitted,
            display_state: ChannelMonitorDisplayState::Forwarding,
            display_label_zh: ChannelMonitorDisplayState::Forwarding.label_zh().into(),
            reason_code: "active".into(),
            process_preserved: true,
            active_member_pids: vec![42],
            active_members: vec![BoundProcessToken::with_system_identity(
                42,
                501,
                900,
                1,
                ProcessRole::DesktopMain,
            )],
            local_proxy_ready: true,
            system_extension_active: true,
            active_flows_count: 1,
            terminated_flows_count: 0,
            blocked_new_connections: 0,
            local_proxy_port: Some(7890),
            valid_until: Some(1030.0),
            updated_at: 1000.0,
            backend: NetworkBackendKind::NetworkExtension,
            vpn_epoch: None,
            vpn_match: None,
            coverage_scope: BackendCoverageScope::default(),
            unmanaged_member_pids: Vec::new(),
            sandbox_ready: false,
        };
        let mut families = BTreeMap::new();
        families.insert("claude".into(), state1.clone());
        assert!(sub.apply_snapshot(ChannelMonitorSnapshot {
            producer_boot_id: "daemon-boot-1".into(),
            snapshot_seq: 10,
            captured_at: 1000.0,
            saved_policy_version: v1.clone(),
            families,
        }));
        assert!(!sub.needs_resync);
        // Stale event_seq <= 10 from the SAME producer is ignored
        assert_eq!(
            sub.apply_event(ChannelMonitorEvent {
                producer_boot_id: "daemon-boot-1".into(),
                event_seq: 10,
                family_state: state1.clone(),
            }),
            SubscriptionApplyOutcome::IgnoredStaleEvent
        );
        // Event 11 applies cleanly
        let mut state2 = state1.clone();
        state2.command_seq = 2;
        state2.display_state = ChannelMonitorDisplayState::Disconnecting;
        state2.display_label_zh = ChannelMonitorDisplayState::Disconnecting.label_zh().into();
        assert_eq!(
            sub.apply_event(ChannelMonitorEvent {
                producer_boot_id: "daemon-boot-1".into(),
                event_seq: 11,
                family_state: state2.clone(),
            }),
            SubscriptionApplyOutcome::Applied
        );
        // Simulate daemon restart ("daemon-boot-2") where event_seq resets to 1 (< 11):
        // must NOT be ignored as stale! Must trigger resync and accept snapshot_seq = 1.
        let mut restarted_state = state2.clone();
        restarted_state.producer_boot_id = "daemon-boot-2".into();
        restarted_state.permit_generation = 1;
        restarted_state.command_seq = 1;
        assert_eq!(
            sub.apply_event(ChannelMonitorEvent {
                producer_boot_id: "daemon-boot-2".into(),
                event_seq: 1,
                family_state: restarted_state.clone(),
            }),
            SubscriptionApplyOutcome::GapDetectedResyncRequired {
                expected_seq: 12,
                received_seq: 1,
            }
        );
        assert!(sub.needs_resync);
        let mut restarted_families = BTreeMap::new();
        restarted_families.insert("claude".into(), restarted_state.clone());
        assert!(sub.apply_snapshot(ChannelMonitorSnapshot {
            producer_boot_id: "daemon-boot-2".into(),
            snapshot_seq: 1,
            captured_at: 1002.0,
            saved_policy_version: v1.clone(),
            families: restarted_families,
        }));
        assert!(!sub.needs_resync);
        assert_eq!(sub.last_event_seq, 1);
        assert_eq!(sub.producer_boot_id.as_deref(), Some("daemon-boot-2"));

        // Gap (event 3 arrives when 2 was expected) triggers resync
        let mut state3 = restarted_state;
        state3.command_seq = 3;
        assert_eq!(
            sub.apply_event(ChannelMonitorEvent {
                producer_boot_id: "daemon-boot-2".into(),
                event_seq: 3,
                family_state: state3,
            }),
            SubscriptionApplyOutcome::GapDetectedResyncRequired {
                expected_seq: 2,
                received_seq: 3,
            }
        );
        assert!(sub.needs_resync);
        // While needs_resync is true, effective_family_state degrades to PendingVerification
        let degraded = sub.effective_family_state("claude", 1002.5, 30.0).unwrap();
        assert_eq!(
            degraded.display_state,
            ChannelMonitorDisplayState::PendingVerification
        );
    }

    #[test]
    fn delayed_receipt_and_mismatched_executor_boot_id_are_rejected_by_receiver_clock() {
        let v1 = policy("v1");
        let permit = sample_permit(ChannelPermitState::Revoked, v1.clone());
        let receipt = sample_receipt(&permit, ChannelEnforcementState::Blocked, true, 0);
        // Matching boot_id and fresh receiver_now (1003.0 vs observed_at 1002.0) succeeds
        assert_eq!(
            evaluate_channel_supervision_with_boot_id(
                &permit,
                Some(&receipt),
                &v1,
                Some("boot-1"),
                1003.0,
            ),
            ChannelSupervisionVerdict::IsolatedKeepProcess
        );
        // Mismatched executor boot_id (receipt from pre-restart "boot-1" after handshake with "boot-2")
        assert_eq!(
            evaluate_channel_supervision_with_boot_id(
                &permit,
                Some(&receipt),
                &v1,
                Some("boot-2"),
                1003.0,
            ),
            ChannelSupervisionVerdict::EnforcementFailed {
                code: "executor_boot_id_mismatch".into(),
                status_label_zh: "执行失败".into(),
            }
        );
        // Delayed receipt evaluated at receiver_now = 1012.0 (age = 10.0s >= MAX_ENFORCEMENT_RECEIPT_AGE 10.0s)
        assert_eq!(
            evaluate_channel_supervision_with_boot_id(
                &permit,
                Some(&receipt),
                &v1,
                Some("boot-1"),
                1012.0,
            ),
            ChannelSupervisionVerdict::EnforcementFailed {
                code: "enforcement_receipt_expired".into(),
                status_label_zh: "执行失败".into(),
            }
        );
    }

    #[test]
    fn bound_process_token_rejects_zero_uid_or_missing_audit_token() {
        let unverified_token = BoundProcessToken::with_system_identity(
            4100,
            501,
            900,
            1,
            ProcessRole::DesktopMain,
        );
        // Basic process identity is present, but verified audit token is not
        assert!(unverified_token.has_valid_identity());
        assert!(!unverified_token.has_verified_audit_token());
        assert!(unverified_token.matches_process(4100, 501, 900, 1, None));

        let audited_token = unverified_token.clone().with_audit_token([501, 501, 20, 501, 20, 4100, 1000, 0]);
        assert!(audited_token.has_valid_identity());
        assert!(audited_token.has_verified_audit_token());
        assert!(audited_token.matches_process(4100, 501, 900, 1, Some(&[501, 501, 20, 501, 20, 4100, 1000, 0])));
        assert!(!audited_token.matches_process(4100, 501, 900, 1, None));

        let placeholder_token = BoundProcessToken {
            pid: 4100,
            uid: 0,
            start_seconds: 900,
            start_microseconds: 1,
            role: ProcessRole::DesktopMain,
            audit_token: None,
        };
        assert!(!placeholder_token.has_valid_identity());
        assert!(!placeholder_token.matches_process(4100, 0, 900, 1, None));
    }

    #[test]
    fn system_extension_receipt_requires_exact_confirmed_execution() {
        let version = policy("extension");
        let mut receipt = SystemExtensionReceipt {
            family: "claude".into(),
            command_binding: "fixture".into(),
            executor_boot_id: "rust-boot".into(),
            extension_boot_id: "extension-boot".into(),
            policy_version: version.clone(),
            command_seq: 14,
            permit_generation: 5,
            applied_at: 100.0,
            allowed_pids: vec![4100],
            local_proxy_port: 0,
            permit_state: "revoked".into(),
            status: "revoked".into(),
            active_flows: 0,
            new_connections_blocked: true,
            reason: None,
        };
        let matches = |r: &SystemExtensionReceipt, seq, generation, boot: &str| {
            r.matches_supervision(&version, seq, generation, "rust-boot", boot, 99.0, 105.0)
                && r.is_confirmed_revoked()
        };
        assert!(matches(&receipt, 14, 5, "extension-boot"));
        assert!(receipt.is_fresh(105.0, 8.0));
        assert!(!matches(&receipt, 13, 5, "extension-boot"));
        assert!(!matches(&receipt, 14, 4, "extension-boot"));
        assert!(!matches(&receipt, 14, 5, "previous-boot"));
        receipt.status = "failed".into();
        assert!(!matches(&receipt, 14, 5, "extension-boot"));
        receipt.status = "revoked".into();
        receipt.permit_state = "disconnecting".into();
        assert!(!receipt.is_confirmed_revoked());
        receipt.permit_state = "revoked".into();
        receipt.active_flows = 1;
        assert!(!receipt.is_confirmed_revoked());
        receipt.active_flows = 0;
        receipt.new_connections_blocked = false;
        assert!(!receipt.is_confirmed_revoked());
        receipt.applied_at = 110.0;
        assert!(!receipt.is_fresh(100.0, 8.0));
        receipt.applied_at = f64::NAN;
        assert!(!receipt.is_fresh(100.0, 8.0));
    }
}
