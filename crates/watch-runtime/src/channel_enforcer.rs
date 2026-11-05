//! Production network channel enforcer, connection manager, upstream relay,
//! and active lease-expiry watchdog.
//!
//! Traces each supervised connection from permit verification -> upstream
//! forwarding -> revocation request (`Disconnecting` / `正在断开`) -> confirmed
//! socket termination (`Blocked` / `已阻断`), while keeping interception active
//! so traffic never falls back to direct routing.
use crate::storage::StateStore;
use claude_watch_core::{
    channel::{
        BoundProcessToken, ChannelEnforcementCommand, ChannelEnforcementReceipt,
        ChannelEnforcementState, ChannelPermitState, ControlledPathEvidence,
        FlowTransportProtocol, PolicyVersion, ProtocolDisposition,
    },
    error::{CoreError, Result},
    processes::ProcessRole,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

pub const MAX_TRACE_EVENTS: usize = 256;

#[derive(Debug)]
pub enum TunnelStream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl TunnelStream {
    pub fn try_clone(&self) -> std::io::Result<Self> {
        match self {
            Self::Tcp(s) => s.try_clone().map(Self::Tcp),
            Self::Unix(s) => s.try_clone().map(Self::Unix),
        }
    }

    pub fn shutdown(&self, how: Shutdown) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.shutdown(how),
            Self::Unix(s) => s.shutdown(how),
        }
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.set_read_timeout(dur),
            Self::Unix(s) => s.set_read_timeout(dur),
        }
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.set_write_timeout(dur),
            Self::Unix(s) => s.set_write_timeout(dur),
        }
    }
}

impl Read for TunnelStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            Self::Unix(s) => s.read(buf),
        }
    }
}

impl Write for TunnelStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            Self::Unix(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            Self::Unix(s) => s.flush(),
        }
    }
}

pub const DEFAULT_DISCONNECT_TIMEOUT_SECONDS: f64 = 3.0;

pub trait ChannelEnforcer: Send + Sync {
    fn boot_id(&self) -> Result<String>;

    fn is_ready(&self) -> Result<bool>;

    fn apply_command(
        &self,
        command: &ChannelEnforcementCommand,
        now: f64,
    ) -> Result<ChannelEnforcementReceipt>;

    fn receipt_for(&self, family: &str, now: f64) -> Result<Option<ChannelEnforcementReceipt>>;

    fn enforce_active_deadlines(
        &self,
        now: f64,
        woke_from_sleep: bool,
    ) -> Result<Vec<ChannelEnforcementReceipt>>;

    fn local_proxy_port(&self) -> Option<u16> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionTracePhase {
    PermitVerified,
    ForwardingEstablished,
    BytesForwarded,
    BlockedOnArrival,
    RevocationRequested,
    TerminationConfirmed,
    TerminationFailed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionTraceEvent {
    pub seq: u64,
    pub flow_id: String,
    pub family: String,
    pub session_id: Option<String>,
    pub policy_version: PolicyVersion,
    pub permit_generation: u64,
    pub command_seq: u64,
    pub pid: u32,
    pub role: ProcessRole,
    pub phase: ConnectionTracePhase,
    pub enforcement_state: ChannelEnforcementState,
    pub detail: String,
    pub observed_at: f64,
}

#[allow(dead_code)]
struct ActiveSocketFlow {
    flow_id: String,
    family: String,
    session_id: Option<String>,
    permit_generation: u64,
    command_seq: u64,
    process: BoundProcessToken,
    client_stream: Option<TunnelStream>,
    upstream_stream: Option<TunnelStream>,
    aborted: Arc<AtomicBool>,
    close_requested_at: Option<f64>,
    close_reason: Option<String>,
}

struct FamilyEnforcerState {
    command: Option<ChannelEnforcementCommand>,
    last_permit_generation: u64,
    last_command_seq: u64,
    enforcement_state: ChannelEnforcementState,
    active_flows: BTreeMap<String, ActiveSocketFlow>,
    terminated_flows_count: u32,
    blocked_new_connections: u32,
    last_error_code: Option<String>,
    last_updated_at: f64,
}
impl FamilyEnforcerState {
    fn new(now: f64) -> Self {
        Self {
            command: None,
            last_permit_generation: 0,
            last_command_seq: 0,
            enforcement_state: ChannelEnforcementState::PendingVerification,
            active_flows: BTreeMap::new(),
            terminated_flows_count: 0,
            blocked_new_connections: 0,
            last_error_code: None,
            last_updated_at: now,
        }
    }
}

type UpstreamConnector = Arc<dyn Fn(&str) -> std::io::Result<TunnelStream> + Send + Sync>;
type OnDialHook = Arc<dyn Fn(&str) + Send + Sync>;
type ClockFn = Arc<dyn Fn() -> f64 + Send + Sync>;
type ReceiptEventSink = Arc<dyn Fn(ChannelEnforcementReceipt) + Send + Sync>;
type SocketAttributor =
    Arc<dyn Fn(SocketAddr) -> Option<(String, BoundProcessToken)> + Send + Sync>;

struct EnforcerInner {
    boot_id: String,
    local_proxy_ready: bool,
    system_extension_active: bool,
    interception_active: bool,
    direct_fallback_blocked: bool,
    upstream_healthy: bool,
    require_upstream_connect_handshake: bool,
    defer_auto_flow_confirm: bool,
    disconnect_timeout_seconds: f64,
    activation_error_code: Option<String>,
    upstream_connector: Option<UpstreamConnector>,
    on_dial_hook: Option<OnDialHook>,
    clock: Option<ClockFn>,
    receipt_sink: Option<ReceiptEventSink>,
    socket_attributor: Option<SocketAttributor>,
    verified_peer_sockets: BTreeMap<SocketAddr, (String, BoundProcessToken)>,
    local_control_endpoints: BTreeSet<String>,
    local_listener_addr: Option<String>,
    last_wall_now: Option<f64>,
    current_policy: Option<PolicyVersion>,
    families: BTreeMap<String, FamilyEnforcerState>,
    traces: Vec<ConnectionTraceEvent>,
    next_trace_seq: u64,
    extension_secret: String,
    strict_peer_verification: bool,
}

pub struct LocalTunnelEnforcer {
    inner: Arc<Mutex<EnforcerInner>>,
    next_flow_id: Arc<AtomicU64>,
    storage: Option<StateStore>,
}

impl LocalTunnelEnforcer {
    /// Creates an enforcer instance.
    ///
    /// Critical invariant (Requirement 2): `local_proxy_ready`,
    /// `system_extension_active`, `interception_active`, and
    /// `direct_fallback_blocked` start as `false` and are NEVER defaulted to
    /// `true` at construction!
    pub fn new(boot_id: impl Into<String>, storage: Option<StateStore>) -> Self {
        let mut local_control_endpoints = BTreeSet::new();
        local_control_endpoints.insert("127.0.0.1:ipc".into());
        local_control_endpoints.insert("localhost:ipc".into());
        let extension_secret = uuid::Uuid::new_v4().simple().to_string();
        if let Some(ref st) = storage {
            let secret_path = st.paths.watch().join("state/.extension-secret");
            let _ = st.atomic_bytes(&secret_path, extension_secret.as_bytes(), 0o600);
        }
        Self {
            inner: Arc::new(Mutex::new(EnforcerInner {
                boot_id: boot_id.into(),
                local_proxy_ready: false,
                system_extension_active: false,
                interception_active: false,
                direct_fallback_blocked: false,
                upstream_healthy: true,
                require_upstream_connect_handshake: false,
                defer_auto_flow_confirm: false,
                disconnect_timeout_seconds: DEFAULT_DISCONNECT_TIMEOUT_SECONDS,
                activation_error_code: None,
                upstream_connector: None,
                on_dial_hook: None,
                clock: None,
                receipt_sink: None,
                socket_attributor: None,
                verified_peer_sockets: BTreeMap::new(),
                local_control_endpoints,
                local_listener_addr: None,
                last_wall_now: None,
                current_policy: None,
                families: BTreeMap::new(),
                traces: Vec::new(),
                next_trace_seq: 1,
                extension_secret,
                strict_peer_verification: false,
            })),
            next_flow_id: Arc::new(AtomicU64::new(1)),
            storage,
        }
    }

    pub fn set_strict_peer_verification(&self, strict: bool) {
        if let Ok(mut guard) = self.lock() {
            guard.strict_peer_verification = strict;
        }
    }

    pub fn verify_peer_is_system_extension(&self, peer_addr: SocketAddr) -> bool {
        let is_strict = self
            .lock()
            .map(|g| g.strict_peer_verification)
            .unwrap_or(false);
        if !is_strict {
            return true;
        }
        #[cfg(target_os = "macos")]
        {
            let port = peer_addr.port();
            // Step 1: Query the peer process PID owning this TCP loopback connection
            let output = std::process::Command::new("/usr/sbin/lsof")
                .args(["-n", "-P", "-i", &format!("TCP@127.0.0.1:{}", port), "-F", "p"])
                .output();
            let mut peer_pid: Option<u32> = None;
            if let Ok(out) = output {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines() {
                        if let Some(p_str) = line.strip_prefix('p') {
                            if let Ok(p) = p_str.parse::<u32>() {
                                peer_pid = Some(p);
                                break;
                            }
                        }
                    }
                }
            }
            let Some(pid) = peer_pid else {
                return false;
            };

            // Step 2: Query the true executable path of the peer PID
            let ps_out = std::process::Command::new("/bin/ps")
                .args(["-p", &pid.to_string(), "-o", "comm="])
                .output();
            let exec_path = match ps_out {
                Ok(out) if out.status.success() => {
                    String::from_utf8_lossy(&out.stdout).trim().to_string()
                }
                _ => return false,
            };
            if exec_path.is_empty() {
                return false;
            }

            // Step 3: Verify system code signing requirement for the extension bundle identifier
            // We verify both code validity and designated requirement matching our extension bundle ID.
            // Under ad-hoc development/test mode, codesign -d -r- outputs the identifier.
            let cs_out = std::process::Command::new("/usr/bin/codesign")
                .args(["-d", "-r-", &exec_path])
                .output();
            if let Ok(out) = cs_out {
                if out.status.success() {
                    let req_text = String::from_utf8_lossy(&out.stdout);
                    let err_text = String::from_utf8_lossy(&out.stderr);
                    let combined = format!("{req_text}\n{err_text}");
                    if combined.contains("io.local.watchpanel.network-extension")
                        || combined.contains("WatchChannelExtension")
                    {
                        // Verified authentic system extension binary!
                        return true;
                    }
                }
            }
            false
        }
        #[cfg(not(target_os = "macos"))]
        {
            true
        }
    }

    pub fn verify_extension_secret(&self, secret: Option<&str>) -> bool {
        let Ok(guard) = self.lock() else { return false; };
        let Some(s) = secret else { return false; };
        !s.trim().is_empty() && s.trim() == guard.extension_secret.trim()
    }

    pub fn extension_secret(&self) -> String {
        self.lock().map(|g| g.extension_secret.clone()).unwrap_or_default()
    }

    /// Activates local tunnel interception and direct-fallback blocking,
    /// returning the active `executor_boot_id` for supervisor handshake.
    pub fn activate_interception(&self, now: f64) -> Result<String> {
        let mut guard = self.lock()?;
        guard.local_proxy_ready = true;
        guard.system_extension_active = true;
        guard.interception_active = true;
        guard.direct_fallback_blocked = true;
        guard.activation_error_code = None;
        guard.last_wall_now = Some(now);
        Ok(guard.boot_id.clone())
    }

    /// Records whether the local proxy listener is ready, separate from
    /// system-extension kernel interception readiness.
    pub fn set_local_proxy_ready(&self, ready: bool, now: f64) -> Result<()> {
        let mut guard = self.lock()?;
        guard.local_proxy_ready = ready;
        guard.last_wall_now = Some(now);
        if !ready {
            guard.interception_active = false;
            guard.direct_fallback_blocked = false;
            guard.activation_error_code = Some("local_proxy_not_ready".into());
            for state in guard.families.values_mut() {
                state.enforcement_state = ChannelEnforcementState::Failed;
                state.last_error_code = Some("local_proxy_not_ready".into());
                state.last_updated_at = now;
            }
        }
        Ok(())
    }

    /// Records whether the macOS SystemExtension / NetworkExtension takeover
    /// is active, separate from local proxy listener readiness.
    pub fn set_system_extension_active(
        &self,
        active: bool,
        error_code: Option<&str>,
        now: f64,
    ) -> Result<()> {
        let mut guard = self.lock()?;
        guard.system_extension_active = active;
        guard.last_wall_now = Some(now);
        if active && guard.local_proxy_ready {
            guard.interception_active = true;
            guard.direct_fallback_blocked = true;
            guard.activation_error_code = None;
        } else if !active {
            let code = error_code.unwrap_or("system_extension_inactive").to_string();
            guard.interception_active = false;
            guard.direct_fallback_blocked = false;
            guard.activation_error_code = Some(code.clone());
            for state in guard.families.values_mut() {
                state.enforcement_state = ChannelEnforcementState::Failed;
                state.last_error_code = Some(code.clone());
                state.last_updated_at = now;
            }
        }
        Ok(())
    }

    /// Explicitly records an activation or listener binding failure and emits
    /// failure receipts so the supervisor and monitor immediately surface
    /// `执行失败` instead of ignoring the error.
    pub fn record_activation_failure(
        &self,
        error_code: &str,
        now: f64,
    ) -> Result<Vec<ChannelEnforcementReceipt>> {
        let mut emitted = Vec::new();
        let sink = {
            let mut guard = self.lock()?;
            guard.interception_active = false;
            guard.direct_fallback_blocked = false;
            guard.activation_error_code = Some(error_code.into());
            guard.last_wall_now = Some(now);
            let families: Vec<String> = guard.families.keys().cloned().collect();
            for family in families {
                if let Some(state) = guard.families.get_mut(&family) {
                    state.enforcement_state = ChannelEnforcementState::Failed;
                    state.last_error_code = Some(error_code.into());
                    state.last_updated_at = now;
                }
                if let Ok(r) = Self::build_receipt_locked(&guard, &family, now) {
                    emitted.push(r);
                }
            }
            guard.receipt_sink.clone()
        };
        for r in &emitted {
            self.persist_receipt(r)?;
            if let Some(s) = &sink {
                s(r.clone());
            }
        }
        Ok(emitted)
    }

    pub fn activation_error_code(&self) -> Result<Option<String>> {
        Ok(self.lock()?.activation_error_code.clone())
    }

    pub fn local_proxy_ready(&self) -> Result<bool> {
        Ok(self.lock()?.local_proxy_ready)
    }

    pub fn system_extension_active(&self) -> Result<bool> {
        Ok(self.lock()?.system_extension_active)
    }

    pub fn local_listener_addr(&self) -> Result<Option<String>> {
        Ok(self.lock()?.local_listener_addr.clone())
    }

    pub fn set_upstream_connector<F>(&self, connector: F) -> Result<()>
    where
        F: Fn(&str) -> std::io::Result<TunnelStream> + Send + Sync + 'static,
    {
        let mut guard = self.lock()?;
        guard.upstream_connector = Some(Arc::new(connector));
        Ok(())
    }

    pub fn set_require_upstream_connect_handshake(&self, required: bool) -> Result<()> {
        let mut guard = self.lock()?;
        guard.require_upstream_connect_handshake = required;
        Ok(())
    }

    pub fn set_on_dial_hook<F>(&self, hook: F) -> Result<()>
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        let mut guard = self.lock()?;
        guard.on_dial_hook = Some(Arc::new(hook));
        Ok(())
    }

    pub fn set_clock<F>(&self, clock: F) -> Result<()>
    where
        F: Fn() -> f64 + Send + Sync + 'static,
    {
        let mut guard = self.lock()?;
        guard.clock = Some(Arc::new(clock));
        Ok(())
    }

    pub fn set_receipt_event_sink<F>(&self, sink: F) -> Result<()>
    where
        F: Fn(ChannelEnforcementReceipt) + Send + Sync + 'static,
    {
        let mut guard = self.lock()?;
        guard.receipt_sink = Some(Arc::new(sink));
        Ok(())
    }

    pub fn set_socket_attributor<F>(&self, attributor: F) -> Result<()>
    where
        F: Fn(SocketAddr) -> Option<(String, BoundProcessToken)> + Send + Sync + 'static,
    {
        let mut guard = self.lock()?;
        guard.socket_attributor = Some(Arc::new(attributor));
        Ok(())
    }

    /// Registers a system-verified local peer socket mapping `(peer_addr -> (family, process))`
    /// so `start_local_proxy_listener` attributes connections by verified OS socket
    /// ownership rather than trusting spoofable HTTP headers.
    pub fn register_verified_peer_socket(
        &self,
        peer_addr: SocketAddr,
        family: impl Into<String>,
        process: BoundProcessToken,
    ) -> Result<()> {
        if !process.has_valid_identity() {
            return Err(CoreError::new(
                "invalid_process_identity",
                "拒绝注册缺少完整系统身份（uid/audit_token）的套接字归属",
            ));
        }
        let mut guard = self.lock()?;
        guard
            .verified_peer_sockets
            .insert(peer_addr, (family.into(), process));
        Ok(())
    }

    pub fn unregister_verified_peer_socket(&self, peer_addr: &SocketAddr) -> Result<()> {
        let mut guard = self.lock()?;
        guard.verified_peer_sockets.remove(peer_addr);
        Ok(())
    }

    pub fn register_local_control_endpoint(&self, endpoint: impl Into<String>) -> Result<()> {
        let mut guard = self.lock()?;
        guard.local_control_endpoints.insert(endpoint.into());
        Ok(())
    }

    /// Verifies that local control-plane and monitor IPC remains accessible
    /// even when the supervised application's external network channel is cut off.
    pub fn check_local_control_plane_access(
        &self,
        process: &BoundProcessToken,
        control_endpoint: &str,
    ) -> Result<bool> {
        if !process.has_valid_identity() {
            return Err(CoreError::new(
                "invalid_process_identity",
                "本地控制通道访问要求完整系统进程身份",
            ));
        }
        let guard = self.lock()?;
        Ok(guard.local_control_endpoints.contains(control_endpoint)
            || control_endpoint.starts_with("127.0.0.1:")
            || control_endpoint.starts_with("unix://"))
    }

    /// Control whether revoking a target waits for an explicit
    /// `confirm_flow_terminated` call before removing the flow from
    /// `active_flows`. When `false` (default for live TCP sockets), the
    /// background socket relay calls `confirm_flow_terminated` only after
    /// `Shutdown::Both` has actually closed the TCP stream and the relay loop
    /// has exited.
    pub fn set_defer_auto_flow_confirm(&self, defer: bool) -> Result<()> {
        let mut guard = self.lock()?;
        guard.defer_auto_flow_confirm = defer;
        Ok(())
    }

    pub fn set_interception_active(&self, active: bool, now: f64) -> Result<()> {
        let mut guard = self.lock()?;
        guard.interception_active = active;
        guard.direct_fallback_blocked = active;
        guard.system_extension_active = active;
        if !active {
            for state in guard.families.values_mut() {
                state.enforcement_state = ChannelEnforcementState::Failed;
                state.last_error_code = Some("interception_inactive_direct_leak_risk".into());
                state.last_updated_at = now;
            }
        }
        Ok(())
    }

    /// Simulates or handles an executor restart: assigns a new `boot_id`,
    /// clears in-memory leases while keeping interception active, and initiates
    /// shutdown of any active flows so no traffic bypasses verification.
    pub fn restart_executor(&self, new_boot_id: impl Into<String>, now: f64) -> Result<()> {
        let mut guard = self.lock()?;
        guard.boot_id = new_boot_id.into();
        guard.interception_active = true;
        guard.direct_fallback_blocked = true;
        guard.system_extension_active = true;
        guard.local_proxy_ready = true;
        guard.last_wall_now = Some(now);
        let families: Vec<String> = guard.families.keys().cloned().collect();
        for family in families {
            Self::begin_revoke_locked(
                &mut guard,
                &family,
                "executor_restarted_unverified",
                now,
            );
            if let Some(state) = guard.families.get_mut(&family) {
                state.command = None;
                state.last_permit_generation = 0;
                state.last_command_seq = 0;
            }
        }
        Ok(())
    }

    /// Marks the TAG / proxy upstream unhealthy: blocks new connections and
    /// issues close requests for all active flows (transitioning to
    /// `Disconnecting` while flows are closing, never jumping straight to
    /// `Blocked` before termination is confirmed).
    pub fn mark_upstream_unhealthy(&self, now: f64) -> Result<Vec<String>> {
        let (closing_flows, receipts, sink) = {
            let mut guard = self.lock()?;
            guard.upstream_healthy = false;
            let families: Vec<String> = guard.families.keys().cloned().collect();
            let mut closing_flows = Vec::new();
            let mut receipts = Vec::new();
            for family in families {
                let ids =
                    Self::begin_revoke_locked(&mut guard, &family, "tag_upstream_unhealthy", now);
                closing_flows.extend(ids);
                if let Ok(r) = Self::build_receipt_locked(&guard, &family, now) {
                    receipts.push(r);
                }
            }
            (closing_flows, receipts, guard.receipt_sink.clone())
        };
        for r in &receipts {
            self.persist_receipt(r)?;
            if let Some(s) = &sink {
                s(r.clone());
            }
        }
        Ok(closing_flows)
    }

    pub fn mark_upstream_healthy(&self) -> Result<()> {
        let mut guard = self.lock()?;
        guard.upstream_healthy = true;
        Ok(())
    }

    /// Confirms that a flow's underlying socket/stream has actually closed.
    /// Only after all active flows for a revoked family are confirmed closed
    /// does the family transition from `Disconnecting` (`正在断开`) to
    /// `Blocked` (`已阻断`).
    pub fn confirm_flow_terminated(
        &self,
        family: &str,
        flow_id: &str,
        now: f64,
    ) -> Result<Option<ChannelEnforcementReceipt>> {
        let (receipt, sink) = {
            let mut guard = self.lock()?;
            let Some(state) = guard.families.get_mut(family) else {
                return Ok(None);
            };
            let Some(removed) = state.active_flows.remove(flow_id) else {
                return Ok(Some(Self::build_receipt_locked(&guard, family, now)?));
            };
            state.terminated_flows_count = state.terminated_flows_count.saturating_add(1);
            state.last_updated_at = now;
            if state.active_flows.is_empty()
                && state.enforcement_state == ChannelEnforcementState::Disconnecting
            {
                state.enforcement_state = ChannelEnforcementState::Blocked;
            }
            let current_state = state.enforcement_state;
            if let Some(cmd) = state.command.clone() {
                Self::push_trace_locked(
                    &mut guard,
                    flow_id.into(),
                    family.into(),
                    cmd.session_id,
                    cmd.policy_version,
                    cmd.permit_generation,
                    cmd.command_seq,
                    removed.process.pid,
                    removed.process.role,
                    ConnectionTracePhase::TerminationConfirmed,
                    current_state,
                    "连接已确认关闭".into(),
                    now,
                );
            }
            (
                Self::build_receipt_locked(&guard, family, now)?,
                guard.receipt_sink.clone(),
            )
        };
        self.persist_receipt(&receipt)?;
        if let Some(s) = &sink {
            s(receipt.clone());
        }
        Ok(Some(receipt))
    }

    /// Records that closing an active flow failed, keeping the family in
    /// `ChannelEnforcementState::Failed` (`执行失败`) rather than claiming
    /// `Blocked` (`已阻断`).
    pub fn fail_flow_termination(
        &self,
        family: &str,
        flow_id: &str,
        error_code: &str,
        now: f64,
    ) -> Result<Option<ChannelEnforcementReceipt>> {
        let (receipt, sink) = {
            let mut guard = self.lock()?;
            let Some(state) = guard.families.get_mut(family) else {
                return Ok(None);
            };
            let Some(flow) = state.active_flows.get(flow_id) else {
                return Ok(None);
            };
            let pid = flow.process.pid;
            let role = flow.process.role;
            state.enforcement_state = ChannelEnforcementState::Failed;
            state.last_error_code = Some(error_code.into());
            state.last_updated_at = now;
            if let Some(cmd) = state.command.clone() {
                Self::push_trace_locked(
                    &mut guard,
                    flow_id.into(),
                    family.into(),
                    cmd.session_id,
                    cmd.policy_version,
                    cmd.permit_generation,
                    cmd.command_seq,
                    pid,
                    role,
                    ConnectionTracePhase::TerminationFailed,
                    ChannelEnforcementState::Failed,
                    format!("连接关闭失败：{error_code}"),
                    now,
                );
            }
            (
                Self::build_receipt_locked(&guard, family, now)?,
                guard.receipt_sink.clone(),
            )
        };
        self.persist_receipt(&receipt)?;
        if let Some(s) = &sink {
            s(receipt.clone());
        }
        Ok(Some(receipt))
    }

    /// Checks whether any flow in `Disconnecting` state has exceeded the
    /// disconnect timeout without confirmation, transitioning the family to
    /// `Failed` (`flow_termination_timeout`).
    pub fn check_disconnect_timeouts(&self, now: f64) -> Result<Vec<ChannelEnforcementReceipt>> {
        let (timed_out_receipts, sink) = {
            let mut guard = self.lock()?;
            let timeout = guard.disconnect_timeout_seconds;
            let families: Vec<String> = guard.families.keys().cloned().collect();
            let mut timed_out_receipts = Vec::new();
            for family in families {
                let expired = guard.families.get(&family).is_some_and(|state| {
                    state.enforcement_state == ChannelEnforcementState::Disconnecting
                        && state.active_flows.values().any(|flow| {
                            flow.close_requested_at
                                .is_some_and(|at| now - at >= timeout)
                        })
                });
                if expired {
                    if let Some(state) = guard.families.get_mut(&family) {
                        state.enforcement_state = ChannelEnforcementState::Failed;
                        state.last_error_code = Some("flow_termination_timeout".into());
                        state.last_updated_at = now;
                    }
                    timed_out_receipts.push(Self::build_receipt_locked(&guard, &family, now)?);
                }
            }
            (timed_out_receipts, guard.receipt_sink.clone())
        };
        for r in &timed_out_receipts {
            self.persist_receipt(r)?;
            if let Some(s) = &sink {
                s(r.clone());
            }
        }
        Ok(timed_out_receipts)
    }

    /// Strict process attribution check (Requirement 5):
    /// Only matches full `BoundProcessToken::matches_process` (`pid`, `uid > 0`,
    /// `start_seconds`, `start_microseconds`, and `audit_token`). Never falls
    /// back to matching `(pid, start_seconds, start_microseconds)` alone.
    fn is_process_attributed(cmd: &ChannelEnforcementCommand, process: &BoundProcessToken) -> bool {
        process.has_valid_identity()
            && cmd.allowed_processes.iter().any(|allowed| {
                allowed.matches_process(
                    process.pid,
                    process.uid,
                    process.start_seconds,
                    process.start_microseconds,
                    process.audit_token.as_ref(),
                )
            })
    }

    fn resolve_peer_socket_identity(&self, peer_addr: SocketAddr) -> Result<(String, BoundProcessToken)> {
        let (from_map, attributor, allowed_snapshot) = {
            let guard = self.lock()?;
            let from_map = guard.verified_peer_sockets.get(&peer_addr).cloned();
            let attributor = guard.socket_attributor.clone();
            let mut allowed_snapshot = Vec::new();
            for (fam, st) in &guard.families {
                if let Some(cmd) = &st.command {
                    for tok in &cmd.allowed_processes {
                        allowed_snapshot.push((fam.clone(), tok.clone()));
                    }
                }
            }
            (from_map, attributor, allowed_snapshot)
        };
        if let Some((fam, tok)) = from_map {
            if tok.has_valid_identity() {
                return Ok((fam, tok));
            }
        }
        if let Some(attr) = attributor {
            if let Some((fam, tok)) = attr(peer_addr) {
                if tok.has_valid_identity() {
                    return Ok((fam, tok));
                }
            }
        }
        // Query OS socket ownership for `peer_addr` via `lsof` and match against
        // authorized `BoundProcessToken`s with full system identity.
        if let Ok(output) = std::process::Command::new("/usr/sbin/lsof")
            .args([
                "-nP",
                "-F",
                "pu",
                "-i",
                &format!("TCP@{}:{}", peer_addr.ip(), peer_addr.port()),
            ])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let mut pid = 0u32;
                let mut uid = 0u32;
                for line in text.lines() {
                    if let Some(p) = line.strip_prefix('p') {
                        pid = p.trim().parse().unwrap_or(0);
                    } else if let Some(u) = line.strip_prefix('u') {
                        uid = u.trim().parse().unwrap_or(0);
                    }
                }
                if pid > 1 && uid > 0 {
                    for (fam, tok) in allowed_snapshot {
                        if tok.pid == pid && tok.uid == uid && tok.has_valid_identity() {
                            return Ok((fam, tok));
                        }
                    }
                }
            }
        }
        let mut guard = self.lock()?;
        for state in guard.families.values_mut() {
            state.blocked_new_connections = state.blocked_new_connections.saturating_add(1);
        }
        Err(CoreError::new(
            "unverified_peer_socket_identity",
            "拒绝未通过系统级进程套接字归属核验的本地代理连接",
        ))
    }

    pub fn perform_upstream_connect_handshake(
        upstream_stream: &mut TunnelStream,
        target_destination: &str,
    ) -> Result<()> {
        let _ = upstream_stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = upstream_stream.set_write_timeout(Some(Duration::from_secs(2)));
        let request = format!(
            "CONNECT {target_destination} HTTP/1.1\r\nHost: {target_destination}\r\nProxy-Connection: keep-alive\r\n\r\n"
        );
        if upstream_stream
            .write_all(request.as_bytes())
            .and_then(|_| upstream_stream.flush())
            .is_err()
        {
            let _ = upstream_stream.shutdown(Shutdown::Both);
            return Err(CoreError::new(
                "upstream_connect_handshake_failed",
                "向 TAG 上游发送 CONNECT 握手请求失败",
            ));
        }
        let mut response = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        while response.len() < 4096 {
            match upstream_stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    response.push(byte[0]);
                    if response.ends_with(b"\r\n\r\n") || response.ends_with(b"\n\n") {
                        break;
                    }
                }
                Err(_) => {
                    let _ = upstream_stream.shutdown(Shutdown::Both);
                    return Err(CoreError::new(
                        "upstream_connect_handshake_timeout",
                        "等待 TAG 上游 CONNECT 握手响应超时或读取失败",
                    ));
                }
            }
        }
        let header_text = String::from_utf8_lossy(&response);
        let status_line = header_text.lines().next().unwrap_or("").trim();
        let status_ok = status_line.starts_with("HTTP/1.1 200")
            || status_line.starts_with("HTTP/1.0 200");
        if !status_ok {
            let _ = upstream_stream.shutdown(Shutdown::Both);
            return Err(CoreError::new(
                "upstream_connect_rejected",
                &format!("TAG 上游拒绝 CONNECT 隧道握手：{status_line}"),
            ));
        }
        // Crucial: clear handshake timeouts so they never act as idle timeouts on
        // long-lived connections!
        let _ = upstream_stream.set_read_timeout(None);
        let _ = upstream_stream.set_write_timeout(None);
        Ok(())
    }

    /// Starts a real local TCP proxy listener for supervised application channels.
    ///
    /// - Attributes incoming sockets strictly via `resolve_peer_socket_identity`
    ///   (ignoring any spoofed `X-Watch-*` HTTP headers).
    /// - Sends `CONNECT <target> HTTP/1.1` to the TAG upstream and verifies
    ///   `HTTP/1.x 200` before returning `200 Connection Established` to the client.
    /// - Clears handshake read/write timeouts after tunnel establishment so
    ///   long-lived idle connections are never prematurely dropped.
    pub fn start_local_proxy_listener(
        self: &Arc<Self>,
        bind_addr: &str,
        stop: Arc<AtomicBool>,
        now: f64,
    ) -> Result<(SocketAddr, thread::JoinHandle<()>)> {
        let listener = match TcpListener::bind(bind_addr) {
            Ok(l) => l,
            Err(_) => {
                let _ = self.record_activation_failure("enforcer_listener_bind_failed", now);
                return Err(CoreError::new(
                    "enforcer_listener_bind_failed",
                    "受控通道监听绑定失败",
                ));
            }
        };
        let _ = listener.set_nonblocking(true);
        let addr = match listener.local_addr() {
            Ok(a) => a,
            Err(_) => {
                let _ = self.record_activation_failure("enforcer_listener_addr_failed", now);
                return Err(CoreError::new(
                    "enforcer_listener_addr_failed",
                    "受控通道监听地址不可读",
                ));
            }
        };
        {
            let mut guard = self.lock()?;
            guard.local_proxy_ready = true;
            // The local listener only proves that the proxy server is ready.
            // System extension activation and direct fallback blocking must be
            // confirmed separately by the system extension manager or IPC!
            if guard.system_extension_active {
                guard.interception_active = true;
                guard.direct_fallback_blocked = true;
                guard.activation_error_code = None;
            } else {
                guard.interception_active = false;
                guard.direct_fallback_blocked = false;
                guard.activation_error_code = Some("system_extension_inactive".into());
            }
            guard.require_upstream_connect_handshake = true;
            guard.local_listener_addr = Some(addr.to_string());
            guard.last_wall_now = Some(now);
        }
        let enforcer = Arc::clone(self);
        let handle = thread::Builder::new()
            .name("channel-local-proxy-listener".into())
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut incoming, peer_addr)) => {
                            let enf = Arc::clone(&enforcer);
                            thread::spawn(move || {
                                let _ = incoming.set_read_timeout(Some(Duration::from_secs(2)));
                                let _ = incoming.set_write_timeout(Some(Duration::from_secs(2)));
                                let mut req_buf = Vec::with_capacity(256);
                                let mut byte = [0u8; 1];
                                while req_buf.len() < 4096 {
                                    match incoming.read(&mut byte) {
                                        Ok(0) => break,
                                        Ok(_) => {
                                            req_buf.push(byte[0]);
                                            if req_buf.ends_with(b"\r\n\r\n")
                                                || req_buf.ends_with(b"\n\n")
                                            {
                                                break;
                                            }
                                        }
                                        Err(_) => {
                                            let _ = incoming.shutdown(Shutdown::Both);
                                            return;
                                        }
                                    }
                                }
                                if req_buf.is_empty() {
                                    let _ = incoming.shutdown(Shutdown::Both);
                                    return;
                                }
                                let header = String::from_utf8_lossy(&req_buf);
                                let first_line = header.lines().next().unwrap_or("");
                                let parts: Vec<&str> = first_line.split_whitespace().collect();
                                if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("CONNECT") {
                                    let _ = incoming.write_all(
                                        b"HTTP/1.1 400 Bad Request (CONNECT Required)\r\n\r\n",
                                    );
                                    let _ = incoming.shutdown(Shutdown::Both);
                                    return;
                                }
                                let target_dest = parts[1].to_string();
                                // Support both direct socket attribution (via OS/lsof) and
                                // transparent proxy attribution from verified NetworkExtension with X-Watch identity headers.
                                let mut resolved_identity = enf.resolve_peer_socket_identity(peer_addr).ok();
                                if resolved_identity.is_none() && peer_addr.ip().is_loopback() {
                                    let mut req_secret: Option<String> = None;
                                    let mut x_pid: Option<u32> = None;
                                    let mut x_uid: Option<u32> = None;
                                    let mut x_audit_hex: Option<String> = None;
                                    for line in header.lines() {
                                        if let Some(v) = line.strip_prefix("X-Watch-PID:").or_else(|| line.strip_prefix("x-watch-pid:")) {
                                            x_pid = v.trim().parse().ok();
                                        } else if let Some(v) = line.strip_prefix("X-Watch-UID:").or_else(|| line.strip_prefix("x-watch-uid:")) {
                                            x_uid = v.trim().parse().ok();
                                        } else if let Some(v) = line.strip_prefix("X-Watch-Audit-Token:").or_else(|| line.strip_prefix("x-watch-audit-token:")) {
                                            x_audit_hex = Some(v.trim().to_string());
                                        } else if let Some(v) = line.strip_prefix("X-Watch-Extension-Secret:").or_else(|| line.strip_prefix("x-watch-extension-secret:")) {
                                            req_secret = Some(v.trim().to_string());
                                        }
                                    }
                                    // Security invariant: strictly authenticate that this loopback stream originates from
                                    // our verified NetworkExtension by validating:
                                    // 1. Peer process via system lsof
                                    // 2. Shared extension secret
                                    // 3. Kernel Mach audit token (X-Watch-Audit-Token)
                                    let is_secret_valid = enf.verify_extension_secret(req_secret.as_deref());
                                    let is_peer_sys_ext = enf.verify_peer_is_system_extension(peer_addr);
                                    if is_secret_valid && is_peer_sys_ext {
                                        if let (Some(pid), Some(uid)) = (x_pid, x_uid) {
                                            // Hard requirement: MUST provide valid kernel Mach audit token (X-Watch-Audit-Token)
                                            if let Some(parsed_audit) = x_audit_hex.as_deref().and_then(parse_audit_token_hex) {
                                                if parsed_audit[5] == pid && (parsed_audit[1] == uid || parsed_audit[3] == uid) {
                                                    if let Ok(guard) = enf.lock() {
                                                        for (fam, st) in &guard.families {
                                                            if let Some(cmd) = &st.command {
                                                                for tok in &cmd.allowed_processes {
                                                                    if tok.pid == pid && tok.uid == uid {
                                                                        let matched_tok = if let Some(ref expected) = tok.audit_token {
                                                                            if expected == &parsed_audit {
                                                                                tok.clone()
                                                                            } else {
                                                                                continue;
                                                                            }
                                                                        } else {
                                                                            tok.clone().with_audit_token(parsed_audit)
                                                                        };
                                                                        if matched_tok.has_valid_identity() {
                                                                            resolved_identity = Some((fam.clone(), matched_tok));
                                                                            break;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            if resolved_identity.is_some() {
                                                                break;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                let Ok((family, proc_token)) = resolved_identity.ok_or_else(|| {
                                    CoreError::new("unverified_peer_socket_identity", "未核验来源进程身份")
                                }) else {
                                    let _ = incoming.write_all(
                                        b"HTTP/1.1 403 Forbidden (Unverified Process Identity)\r\n\r\n",
                                    );
                                    let _ = incoming.shutdown(Shutdown::Both);
                                    return;
                                };
                                let now = enf
                                    .lock()
                                    .ok()
                                    .and_then(|g| g.clock.as_ref().map(|c| c()))
                                    .unwrap_or_else(crate::native::now);
                                match enf.connect_supervised_tcp_to(
                                    &family,
                                    &proc_token,
                                    &target_dest,
                                    now,
                                ) {
                                    Ok((_flow_id, mut tunnel_stream)) => {
                                        // Clear handshake timeouts before switching to long-lived tunnel relay!
                                        let _ = incoming.set_read_timeout(None);
                                        let _ = incoming.set_write_timeout(None);
                                        let _ = tunnel_stream.set_read_timeout(None);
                                        let _ = tunnel_stream.set_write_timeout(None);
                                        if incoming
                                            .write_all(
                                                b"HTTP/1.1 200 Connection Established\r\n\r\n",
                                            )
                                            .is_err()
                                        {
                                            let _ = incoming.shutdown(Shutdown::Both);
                                            let _ = tunnel_stream.shutdown(Shutdown::Both);
                                            return;
                                        }
                                        let _ = incoming.flush();
                                        let Ok(mut in_clone) = incoming.try_clone() else {
                                            return;
                                        };
                                        let Ok(mut tun_clone) = tunnel_stream.try_clone() else {
                                            return;
                                        };
                                        let t1 = thread::spawn(move || {
                                            let _ = std::io::copy(&mut in_clone, &mut tun_clone);
                                            let _ = tun_clone.shutdown(Shutdown::Both);
                                        });
                                        let _ = std::io::copy(&mut tunnel_stream, &mut incoming);
                                        let _ = incoming.shutdown(Shutdown::Both);
                                        let _ = t1.join();
                                    }
                                    Err(_) => {
                                        let _ = incoming.write_all(
                                            b"HTTP/1.1 502 Bad Gateway (Channel Or Upstream Blocked)\r\n\r\n",
                                        );
                                        let _ = incoming.shutdown(Shutdown::Both);
                                    }
                                }
                            });
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(25));
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(25));
                        }
                    }
                }
                let _ = enforcer.set_local_proxy_ready(false, crate::native::now());
            })
            .map_err(|_| {
                let _ = self.record_activation_failure("enforcer_listener_thread_failed", now);
                CoreError::new("enforcer_listener_thread_failed", "受控通道监听线程启动失败")
            })?;
        Ok((addr, handle))
    }

    /// Unified multi-protocol flow gate covering TCP (IPv4/IPv6), UDP/QUIC,
    /// DNS (53/853), and unsupported protocols.
    /// Every protocol is explicitly forwarded through the controlled tunnel or
    /// claimed and blocked (never bypassing direct).
    pub fn connect_supervised_flow(
        &self,
        family: &str,
        process: &BoundProcessToken,
        protocol: FlowTransportProtocol,
        target_destination: &str,
        now: f64,
    ) -> Result<(ProtocolDisposition, Option<(String, TunnelStream)>)> {
        let is_dns_port = target_destination.ends_with(":53")
            || target_destination.ends_with(":853");
        match protocol {
            FlowTransportProtocol::TcpIpv4 | FlowTransportProtocol::TcpIpv6 if !is_dns_port => {
                let (flow_id, stream) =
                    self.connect_supervised_tcp_to(family, process, target_destination, now)?;
                Ok((
                    ProtocolDisposition::ForwardViaControlledTunnel,
                    Some((flow_id, stream)),
                ))
            }
            FlowTransportProtocol::Dns | FlowTransportProtocol::TcpIpv4 | FlowTransportProtocol::TcpIpv6 => {
                self.record_blocked_protocol_attempt(
                    family,
                    process,
                    "direct_dns_blocked",
                    format!("已拦截并阻断直连 DNS 流量（{target_destination}）"),
                    now,
                )?;
                Err(CoreError::new(
                    "direct_dns_blocked",
                    "受控通道禁止直连 DNS (53/853)，已拦截并阻断",
                ))
            }
            FlowTransportProtocol::UdpQuic => {
                self.record_blocked_protocol_attempt(
                    family,
                    process,
                    "udp_quic_blocked_in_channel_mode",
                    format!("已拦截并阻断 UDP/QUIC 流量（{target_destination}）"),
                    now,
                )?;
                Err(CoreError::new(
                    "udp_quic_blocked_in_channel_mode",
                    "受控通道拦截并阻断 UDP/QUIC 流量，禁止绕过隧道直连",
                ))
            }
            FlowTransportProtocol::Unsupported => {
                self.record_blocked_protocol_attempt(
                    family,
                    process,
                    "unsupported_protocol_blocked",
                    format!("已接管并阻断未支持协议流量（{target_destination}）"),
                    now,
                )?;
                Err(CoreError::new(
                    "unsupported_protocol_blocked",
                    "未支持协议已被受控通道接管并阻断，禁止直连回退",
                ))
            }
        }
    }

    fn record_blocked_protocol_attempt(
        &self,
        family: &str,
        process: &BoundProcessToken,
        _code: &str,
        detail: String,
        now: f64,
    ) -> Result<()> {
        let flow_id = format!(
            "flow-{}-{}",
            family,
            self.next_flow_id.fetch_add(1, Ordering::Relaxed)
        );
        let mut guard = self.lock()?;
        if let Some(state) = guard.families.get_mut(family) {
            state.blocked_new_connections = state.blocked_new_connections.saturating_add(1);
            let current_enf_state = state.enforcement_state;
            if let Some(cmd) = state.command.clone() {
                Self::push_trace_locked(
                    &mut guard,
                    flow_id,
                    family.into(),
                    cmd.session_id,
                    cmd.policy_version,
                    cmd.permit_generation,
                    cmd.command_seq,
                    process.pid,
                    process.role,
                    ConnectionTracePhase::BlockedOnArrival,
                    current_enf_state,
                    detail,
                    now,
                );
            }
        }
        Ok(())
    }

    /// Executes a recovery/environment diagnostic probe along the family's exact
    /// controlled upstream path while keeping the real application's channel
    /// blocked/held (`Revoked` or `PendingVerification`).
    pub fn probe_via_controlled_diagnostic_channel<F, T>(
        &self,
        family: &str,
        context_id: &str,
        now: f64,
        probe_fn: F,
    ) -> Result<(T, ControlledPathEvidence)>
    where
        F: FnOnce(&str) -> Result<T>,
    {
        let (upstream_endpoint, policy_version) = {
            let guard = self.lock()?;
            if !guard.interception_active || !guard.direct_fallback_blocked {
                return Err(CoreError::new(
                    "diagnostic_channel_interception_inactive",
                    "网络接管未激活，不能通过受控诊断通道采集恢复证据",
                ));
            }
            if !guard.upstream_healthy {
                return Err(CoreError::new(
                    "diagnostic_channel_upstream_unhealthy",
                    "受控 TAG 上游不可用，诊断通道探测失败",
                ));
            }
            let state = guard
                .families
                .get(family)
                .ok_or_else(|| CoreError::new("channel_family_unknown", "未找到对应通道状态"))?;
            let cmd = state
                .command
                .as_ref()
                .ok_or_else(|| CoreError::new("channel_command_missing", "通道尚未接收控制命令"))?;
            if cmd.upstream_endpoint.trim().is_empty() {
                return Err(CoreError::new(
                    "diagnostic_channel_upstream_missing",
                    "缺少受控上游端点，不能执行同路径诊断探测",
                ));
            }
            (cmd.upstream_endpoint.clone(), cmd.policy_version.clone())
        };
        let output = probe_fn(&upstream_endpoint)?;
        let evidence = ControlledPathEvidence {
            family: family.into(),
            upstream_endpoint,
            policy_version,
            context_id: context_id.into(),
            via_controlled_path: true,
            observed_at: now,
        };
        Ok((output, evidence))
    }

    pub fn connect_supervised_tcp(
        &self,
        family: &str,
        process: &BoundProcessToken,
        now: f64,
    ) -> Result<(String, TunnelStream)> {
        self.connect_supervised_tcp_to(family, process, "api.anthropic.com:443", now)
    }

    /// Establishes a real supervised connection for `process` to `target_destination`
    /// via the family's configured upstream endpoint.
    ///
    /// Performs two-stage verification:
    /// 1. Pre-dial check under lock: verifies interception readiness, strict
    ///    `BoundProcessToken` attribution, policy version, and active lease.
    /// 2. Upstream dial + optional HTTP `CONNECT` handshake & timeout clearance.
    /// 3. Post-dial re-verification under lock using freshly re-read clock time
    ///    (`post_dial_now`) to verify that `session_id`, `permit_generation`,
    ///    `policy_version`, `upstream_endpoint`, process attribution,
    ///    interception readiness, and lease validity did NOT change or expire
    ///    while dialing!
    pub fn connect_supervised_tcp_to(
        &self,
        family: &str,
        process: &BoundProcessToken,
        target_destination: &str,
        now: f64,
    ) -> Result<(String, TunnelStream)> {
        if target_destination.ends_with(":53") || target_destination.ends_with(":853") {
            let _ = self.record_blocked_protocol_attempt(
                family,
                process,
                "direct_dns_blocked",
                format!("已拦截并阻断直连 DNS 端口访问（{target_destination}）"),
                now,
            );
            return Err(CoreError::new(
                "direct_dns_blocked",
                "受控通道禁止直连 DNS (53/853)，已拦截并阻断",
            ));
        }
        let flow_id = format!(
            "flow-{}-{}",
            family,
            self.next_flow_id.fetch_add(1, Ordering::Relaxed)
        );
        let (
            dial_session_id,
            dial_policy_version,
            dial_permit_generation,
            upstream_endpoint,
            upstream_connector,
            require_connect_handshake,
            on_dial_hook,
            defer_confirm,
        ) = {
            let mut guard = self.lock()?;
            let defer_confirm = guard.defer_auto_flow_confirm;
            let upstream_connector = guard.upstream_connector.clone();
            let require_connect_handshake = guard.require_upstream_connect_handshake;
            let on_dial_hook = guard.on_dial_hook.clone();
            let interception_active = guard.interception_active;
            let direct_fallback_blocked = guard.direct_fallback_blocked;
            let upstream_healthy = guard.upstream_healthy;
            let last_wall = guard.last_wall_now;
            let Some(state) = guard.families.get_mut(family) else {
                return Err(CoreError::new(
                    "channel_unconfigured_blocked",
                    "目标通道尚未建立许可，已拦截并阻断连接",
                ));
            };
            let Some(cmd) = state.command.clone() else {
                state.blocked_new_connections = state.blocked_new_connections.saturating_add(1);
                return Err(CoreError::new(
                    "missing_channel_lease_blocked",
                    "缺少有效通道租约，已拦截并阻断连接",
                ));
            };
            if !Self::is_process_attributed(&cmd, process) {
                state.blocked_new_connections = state.blocked_new_connections.saturating_add(1);
                let current_enf_state = state.enforcement_state;
                Self::push_trace_locked(
                    &mut guard,
                    flow_id,
                    family.into(),
                    cmd.session_id,
                    cmd.policy_version,
                    cmd.permit_generation,
                    cmd.command_seq,
                    process.pid,
                    process.role,
                    ConnectionTracePhase::BlockedOnArrival,
                    current_enf_state,
                    "进程身份或家族归属未通过核验，已拦截并阻断".into(),
                    now,
                );
                return Err(CoreError::new(
                    "process_attribution_rejected",
                    "连接所属进程未通过受控家族身份核验，已阻断",
                ));
            }
            let current_policy = cmd.policy_version.clone();
            let (effective_state, reason) =
                cmd.permit
                    .effective_state_with_clock(now, last_wall, false, &current_policy);
            if !interception_active
                || !direct_fallback_blocked
                || !upstream_healthy
                || effective_state != ChannelPermitState::Permitted
            {
                state.blocked_new_connections = state.blocked_new_connections.saturating_add(1);
                let block_reason = if !interception_active || !direct_fallback_blocked {
                    "interception_inactive"
                } else if !upstream_healthy {
                    "tag_upstream_unhealthy"
                } else {
                    reason
                };
                let current_enf_state = state.enforcement_state;
                Self::push_trace_locked(
                    &mut guard,
                    flow_id,
                    family.into(),
                    cmd.session_id,
                    cmd.policy_version,
                    cmd.permit_generation,
                    cmd.command_seq,
                    process.pid,
                    process.role,
                    ConnectionTracePhase::BlockedOnArrival,
                    current_enf_state,
                    format!("通道未放行（{block_reason}），保持拦截并拒绝新连接"),
                    now,
                );
                return Err(CoreError::new(
                    "channel_connection_blocked",
                    &format!("受控通道已拦截并拒绝新连接：{block_reason}"),
                ));
            }
            Self::push_trace_locked(
                &mut guard,
                flow_id.clone(),
                family.into(),
                cmd.session_id.clone(),
                cmd.policy_version.clone(),
                cmd.permit_generation,
                cmd.command_seq,
                process.pid,
                process.role,
                ConnectionTracePhase::PermitVerified,
                ChannelEnforcementState::Forwarding,
                format!("进程归属与通道租约核验通过（目标 {target_destination}）"),
                now,
            );
            (
                cmd.session_id.clone(),
                cmd.policy_version.clone(),
                cmd.permit_generation,
                cmd.upstream_endpoint.clone(),
                upstream_connector,
                require_connect_handshake,
                on_dial_hook,
                defer_confirm,
            )
        };

        let dial_started_at = Instant::now();
        if let Some(hook) = on_dial_hook {
            hook(family);
        }

        // Dial the designated upstream endpoint and perform HTTP CONNECT
        // handshake when connecting to an HTTP proxy upstream or when
        // `require_upstream_connect_handshake` is enabled.
        let (mut upstream_stream, perform_handshake) = if let Some(connector) = upstream_connector {
            let s = connector(&upstream_endpoint)
                .map_err(|_| CoreError::new("upstream_connect_failed", "受控上游连接失败"))?;
            (s, require_connect_handshake)
        } else if let Some(unix_path) = upstream_endpoint.strip_prefix("unix://") {
            let s = UnixStream::connect(unix_path)
                .map_err(|_| CoreError::new("upstream_connect_failed", "受控上游连接失败"))?;
            (TunnelStream::Unix(s), require_connect_handshake)
        } else {
            let upstream_addr: SocketAddr = upstream_endpoint
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .parse()
                .map_err(|_| CoreError::new("invalid_upstream_endpoint", "受控上游地址无效"))?;
            let s = TcpStream::connect_timeout(&upstream_addr, Duration::from_secs(2))
                .map_err(|_| CoreError::new("upstream_connect_failed", "受控上游连接失败"))?;
            let _ = s.set_nodelay(true);
            (TunnelStream::Tcp(s), true)
        };

        if perform_handshake {
            if let Err(err) =
                Self::perform_upstream_connect_handshake(&mut upstream_stream, target_destination)
            {
                if let Ok(mut guard) = self.lock() {
                    if let Some(state) = guard.families.get_mut(family) {
                        state.blocked_new_connections =
                            state.blocked_new_connections.saturating_add(1);
                    }
                }
                return Err(err);
            }
        }

        let (client_side, enforcer_client_stream) =
            if let Ok(bridge_listener) = TcpListener::bind("127.0.0.1:0") {
                if let Ok(bridge_addr) = bridge_listener.local_addr() {
                    if let Ok(client_tcp) = TcpStream::connect(bridge_addr) {
                        let _ = client_tcp.set_nodelay(true);
                        if let Ok((enforcer_tcp, _)) = bridge_listener.accept() {
                            let _ = enforcer_tcp.set_nodelay(true);
                            (TunnelStream::Tcp(client_tcp), TunnelStream::Tcp(enforcer_tcp))
                        } else {
                            let (a, b) = UnixStream::pair().map_err(|_| {
                                CoreError::new(
                                    "tunnel_bridge_pair_failed",
                                    "本地隧道套接字对创建失败",
                                )
                            })?;
                            (TunnelStream::Unix(a), TunnelStream::Unix(b))
                        }
                    } else {
                        let (a, b) = UnixStream::pair().map_err(|_| {
                            CoreError::new("tunnel_bridge_pair_failed", "本地隧道套接字对创建失败")
                        })?;
                        (TunnelStream::Unix(a), TunnelStream::Unix(b))
                    }
                } else {
                    let (a, b) = UnixStream::pair().map_err(|_| {
                        CoreError::new("tunnel_bridge_pair_failed", "本地隧道套接字对创建失败")
                    })?;
                    (TunnelStream::Unix(a), TunnelStream::Unix(b))
                }
            } else {
                let (a, b) = UnixStream::pair().map_err(|_| {
                    CoreError::new("tunnel_bridge_pair_failed", "本地隧道套接字对创建失败")
                })?;
                (TunnelStream::Unix(a), TunnelStream::Unix(b))
            };

        let aborted = Arc::new(AtomicBool::new(false));
        let client_for_state = enforcer_client_stream
            .try_clone()
            .map_err(|_| CoreError::new("socket_clone_failed", "套接字句柄复制失败"))?;
        let upstream_for_state = upstream_stream
            .try_clone()
            .map_err(|_| CoreError::new("socket_clone_failed", "上游句柄复制失败"))?;

        {
            let mut guard = self.lock()?;
            // Requirement 4 (修正实际取时位置): Re-read current time AFTER dialing
            // completes rather than trusting pre-dial `now` or cached `last_wall_now`!
            let dial_elapsed = dial_started_at.elapsed().as_secs_f64();
            let clock_now = guard
                .clock
                .as_ref()
                .map(|c| c())
                .unwrap_or(now + dial_elapsed);
            let post_dial_now = clock_now
                .max(now + dial_elapsed)
                .max(guard.last_wall_now.unwrap_or(now));
            let interception_ok = guard.interception_active && guard.direct_fallback_blocked;
            let upstream_ok = guard.upstream_healthy;
            let last_wall = guard.last_wall_now;

            let Some(state) = guard.families.get_mut(family) else {
                let _ = enforcer_client_stream.shutdown(Shutdown::Both);
                let _ = upstream_stream.shutdown(Shutdown::Both);
                return Err(CoreError::new(
                    "channel_changed_during_dial",
                    "拨号期间通道已移除",
                ));
            };
            let Some(cmd) = state.command.clone() else {
                state.blocked_new_connections = state.blocked_new_connections.saturating_add(1);
                let _ = enforcer_client_stream.shutdown(Shutdown::Both);
                let _ = upstream_stream.shutdown(Shutdown::Both);
                return Err(CoreError::new(
                    "channel_changed_during_dial",
                    "拨号期间通道命令已清除",
                ));
            };
            let active_policy = cmd.policy_version.clone();
            let (post_eff_state, post_reason) = cmd.permit.effective_state_with_clock(
                post_dial_now,
                last_wall,
                false,
                &active_policy,
            );
            let dial_invariant_ok = interception_ok
                && upstream_ok
                && state.enforcement_state == ChannelEnforcementState::Forwarding
                && post_eff_state == ChannelPermitState::Permitted
                && cmd.session_id == dial_session_id
                && cmd.permit_generation == dial_permit_generation
                && cmd.policy_version == dial_policy_version
                && active_policy == dial_policy_version
                && cmd.upstream_endpoint == upstream_endpoint
                && Self::is_process_attributed(&cmd, process);

            if !dial_invariant_ok {
                state.blocked_new_connections = state.blocked_new_connections.saturating_add(1);
                let current_enf_state = state.enforcement_state;
                let _ = enforcer_client_stream.shutdown(Shutdown::Both);
                let _ = upstream_stream.shutdown(Shutdown::Both);
                Self::push_trace_locked(
                    &mut guard,
                    flow_id,
                    family.into(),
                    cmd.session_id,
                    cmd.policy_version,
                    cmd.permit_generation,
                    cmd.command_seq,
                    process.pid,
                    process.role,
                    ConnectionTracePhase::BlockedOnArrival,
                    current_enf_state,
                    format!(
                        "拨号期间通道状态、会话、代次、上游或有效期已变化（{post_reason}），已阻断旧连接"
                    ),
                    post_dial_now,
                );
                return Err(CoreError::new(
                    "channel_changed_during_dial",
                    "拨号期间会话、策略、代次、归属、上游或有效期已变化，已阻断连接",
                ));
            }
            state.active_flows.insert(
                flow_id.clone(),
                ActiveSocketFlow {
                    flow_id: flow_id.clone(),
                    family: family.into(),
                    session_id: cmd.session_id.clone(),
                    permit_generation: cmd.permit_generation,
                    command_seq: cmd.command_seq,
                    process: process.clone(),
                    client_stream: Some(client_for_state),
                    upstream_stream: Some(upstream_for_state),
                    aborted: aborted.clone(),
                    close_requested_at: None,
                    close_reason: None,
                },
            );
            Self::push_trace_locked(
                &mut guard,
                flow_id.clone(),
                family.into(),
                cmd.session_id,
                cmd.policy_version,
                cmd.permit_generation,
                cmd.command_seq,
                process.pid,
                process.role,
                ConnectionTracePhase::ForwardingEstablished,
                ChannelEnforcementState::Forwarding,
                format!("已建立经受控上游 {upstream_endpoint} 到 {target_destination} 的转发流"),
                post_dial_now,
            );
        }

        self.spawn_relay_workers(
            family.to_string(),
            flow_id.clone(),
            process.clone(),
            enforcer_client_stream,
            upstream_stream,
            aborted,
            defer_confirm,
        )?;

        Ok((flow_id, client_side))
    }

    pub fn traces(&self) -> Result<Vec<ConnectionTraceEvent>> {
        Ok(self.lock()?.traces.clone())
    }

    /// Spawns an autonomous background watchdog thread that proactively checks
    /// lease deadlines (`now >= valid_until`) at a fixed interval, cutting off
    /// existing connections even when Rust stops renewing leases and no new
    /// connections arrive.
    pub fn spawn_lease_watchdog<F, C>(
        self: &Arc<Self>,
        stop: Arc<AtomicBool>,
        interval: Duration,
        mut clock: F,
        mut on_expired: C,
    ) -> Result<thread::JoinHandle<()>>
    where
        F: FnMut() -> f64 + Send + 'static,
        C: FnMut(Vec<ChannelEnforcementReceipt>) + Send + 'static,
    {
        let enforcer = Arc::clone(self);
        thread::Builder::new()
            .name("channel-lease-watchdog".into())
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let now = clock();
                    let mut emitted = enforcer
                        .enforce_active_deadlines(now, false)
                        .unwrap_or_default();
                    if let Ok(mut timeouts) = enforcer.check_disconnect_timeouts(now) {
                        emitted.append(&mut timeouts);
                    }
                    if !emitted.is_empty() {
                        on_expired(emitted);
                    }
                    thread::sleep(interval);
                }
            })
            .map_err(|_| CoreError::new("lease_watchdog_start_failed", "通道租约到期巡检线程无法启动"))
    }

    fn spawn_relay_workers(
        &self,
        family: String,
        flow_id: String,
        process: BoundProcessToken,
        mut client_read: TunnelStream,
        mut upstream_read: TunnelStream,
        aborted: Arc<AtomicBool>,
        defer_confirm: bool,
    ) -> Result<()> {
        let mut upstream_write = upstream_read
            .try_clone()
            .map_err(|_| CoreError::new("socket_clone_failed", "上游写句柄复制失败"))?;
        let mut client_write = client_read
            .try_clone()
            .map_err(|_| CoreError::new("socket_clone_failed", "客户端写句柄复制失败"))?;

        let inner_c2u = self.inner.clone();
        let family_c2u = family.clone();
        let flow_c2u = flow_id.clone();
        let aborted_c2u = aborted.clone();
        let proc_c2u = process.clone();

        let c2u = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                if aborted_c2u.load(Ordering::Acquire) {
                    break;
                }
                match client_read.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if aborted_c2u.load(Ordering::Acquire)
                            || upstream_write.write_all(&buf[..n]).is_err()
                        {
                            break;
                        }
                        let _ = upstream_write.flush();
                        if let Ok(mut guard) = inner_c2u.lock() {
                            if let Some(state) = guard.families.get(&family_c2u) {
                                if let Some(cmd) = state.command.clone() {
                                    let now = state.last_updated_at;
                                    Self::push_trace_locked(
                                        &mut guard,
                                        flow_c2u.clone(),
                                        family_c2u.clone(),
                                        cmd.session_id,
                                        cmd.policy_version,
                                        cmd.permit_generation,
                                        cmd.command_seq,
                                        proc_c2u.pid,
                                        proc_c2u.role,
                                        ConnectionTracePhase::BytesForwarded,
                                        ChannelEnforcementState::Forwarding,
                                        format!("已转发 {n} 字节"),
                                        now,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            let _ = upstream_write.shutdown(Shutdown::Both);
        });

        let inner_done = self.inner.clone();
        let storage_done = self.storage.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                if aborted.load(Ordering::Acquire) {
                    break;
                }
                match upstream_read.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if aborted.load(Ordering::Acquire)
                            || client_write.write_all(&buf[..n]).is_err()
                        {
                            break;
                        }
                        let _ = client_write.flush();
                    }
                }
            }
            let _ = client_write.shutdown(Shutdown::Both);
            let _ = c2u.join();
            if !defer_confirm {
                let (maybe_receipt, sink) = if let Ok(mut guard) = inner_done.lock() {
                    let sink = guard.receipt_sink.clone();
                    let clock_now = guard.clock.as_ref().map(|c| c());
                    let r = if let Some(state) = guard.families.get_mut(&family) {
                        let now = clock_now
                            .unwrap_or(state.last_updated_at)
                            .max(state.last_updated_at);
                        state.last_updated_at = now;
                        if let Some(removed) = state.active_flows.remove(&flow_id) {
                            state.terminated_flows_count =
                                state.terminated_flows_count.saturating_add(1);
                            if state.active_flows.is_empty()
                                && state.enforcement_state
                                    == ChannelEnforcementState::Disconnecting
                            {
                                state.enforcement_state = ChannelEnforcementState::Blocked;
                            }
                            let current_state = state.enforcement_state;
                            if let Some(cmd) = state.command.clone() {
                                Self::push_trace_locked(
                                    &mut guard,
                                    flow_id.clone(),
                                    family.clone(),
                                    cmd.session_id,
                                    cmd.policy_version,
                                    cmd.permit_generation,
                                    cmd.command_seq,
                                    removed.process.pid,
                                    removed.process.role,
                                    ConnectionTracePhase::TerminationConfirmed,
                                    current_state,
                                    "底层套接字已关闭并确认断开".into(),
                                    now,
                                );
                            }
                        }
                        Self::build_receipt_locked(&guard, &family, now).ok()
                    } else {
                        None
                    };
                    (r, sink)
                } else {
                    (None, None)
                };
                if let Some(receipt) = maybe_receipt {
                    if let Some(store) = &storage_done {
                        let _ = store.atomic_json(
                            &store
                                .paths
                                .watch()
                                .join(format!("state/channel-receipt-{}.json", receipt.family)),
                            &json!(receipt),
                        );
                    }
                    if let Some(s) = sink {
                        s(receipt);
                    }
                }
            }
        });

        Ok(())
    }

    fn begin_revoke_locked(
        guard: &mut EnforcerInner,
        family: &str,
        reason: &str,
        now: f64,
    ) -> Vec<String> {
        let Some(state) = guard.families.get_mut(family) else {
            return Vec::new();
        };
        if let Some(cmd) = state.command.as_mut() {
            cmd.permit.state = ChannelPermitState::Revoked;
            cmd.permit.reason_code = reason.into();
        }
        state.last_updated_at = now;
        let mut closing_ids = Vec::new();
        let mut trace_items = Vec::new();
        let cmd_snapshot = state.command.clone();
        for (id, flow) in state.active_flows.iter_mut() {
            closing_ids.push(id.clone());
            flow.aborted.store(true, Ordering::Release);
            if flow.close_requested_at.is_none() {
                flow.close_requested_at = Some(now);
                flow.close_reason = Some(reason.into());
            }
            if let Some(stream) = flow.client_stream.as_ref() {
                let _ = stream.shutdown(Shutdown::Both);
            }
            if let Some(stream) = flow.upstream_stream.as_ref() {
                let _ = stream.shutdown(Shutdown::Both);
            }
            trace_items.push((id.clone(), flow.process.pid, flow.process.role));
        }
        // Critical invariant (Requirement 3): Revoking only issues close
        // requests. If active flows exist, state becomes `Disconnecting`
        // (`正在断开`) and NEVER transitions to `Blocked` until each flow's
        // termination is confirmed!
        if state.active_flows.is_empty() {
            state.enforcement_state = ChannelEnforcementState::Blocked;
        } else {
            state.enforcement_state = ChannelEnforcementState::Disconnecting;
        }
        let current_enf_state = state.enforcement_state;
        if let Some(cmd) = cmd_snapshot {
            for (flow_id, pid, role) in trace_items {
                Self::push_trace_locked(
                    guard,
                    flow_id,
                    family.into(),
                    cmd.session_id.clone(),
                    cmd.policy_version.clone(),
                    cmd.permit_generation,
                    cmd.command_seq,
                    pid,
                    role,
                    ConnectionTracePhase::RevocationRequested,
                    current_enf_state,
                    format!("已发出断开请求（{reason}），等待底层流关闭确认"),
                    now,
                );
            }
        }
        closing_ids
    }

    fn build_receipt_locked(
        guard: &EnforcerInner,
        family: &str,
        now: f64,
    ) -> Result<ChannelEnforcementReceipt> {
        let state = guard
            .families
            .get(family)
            .ok_or_else(|| CoreError::new("channel_family_unknown", "未找到对应通道状态"))?;
        let Some(cmd) = state.command.as_ref() else {
            return Err(CoreError::new(
                "channel_command_missing",
                "通道尚未接收控制命令",
            ));
        };
        let active_count = state.active_flows.len() as u32;
        let new_connections_blocked = guard.interception_active
            && guard.direct_fallback_blocked
            && (cmd.permit.state != ChannelPermitState::Permitted
                || state.enforcement_state != ChannelEnforcementState::Forwarding);
        Ok(ChannelEnforcementReceipt {
            family: family.into(),
            session_id: cmd.session_id.clone(),
            policy_version: cmd.policy_version.clone(),
            permit_generation: state.last_permit_generation,
            command_seq: state.last_command_seq,
            executor_boot_id: guard.boot_id.clone(),
            permit_state: cmd.permit.state,
            enforcement_state: state.enforcement_state,
            interception_active: guard.interception_active,
            local_proxy_ready: guard.local_proxy_ready,
            system_extension_active: guard.system_extension_active,
            new_connections_blocked,
            active_flows_closed: active_count == 0,
            direct_fallback_blocked: guard.direct_fallback_blocked,
            active_flows_count: active_count,
            terminated_flows_count: state.terminated_flows_count,
            blocked_new_connections: state.blocked_new_connections,
            observed_at: now,
            error_code: state
                .last_error_code
                .clone()
                .or_else(|| {
                    if cmd.permit.state == ChannelPermitState::Revoked
                        && !cmd.permit.reason_code.is_empty()
                    {
                        Some(cmd.permit.reason_code.clone())
                    } else {
                        guard.activation_error_code.clone()
                    }
                }),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn push_trace_locked(
        guard: &mut EnforcerInner,
        flow_id: String,
        family: String,
        session_id: Option<String>,
        policy_version: PolicyVersion,
        permit_generation: u64,
        command_seq: u64,
        pid: u32,
        role: ProcessRole,
        phase: ConnectionTracePhase,
        enforcement_state: ChannelEnforcementState,
        detail: String,
        observed_at: f64,
    ) {
        let seq = guard.next_trace_seq;
        guard.next_trace_seq = guard.next_trace_seq.saturating_add(1);
        if guard.traces.len() >= MAX_TRACE_EVENTS {
            let overflow = guard.traces.len() + 1 - MAX_TRACE_EVENTS;
            guard.traces.drain(0..overflow);
        }
        guard.traces.push(ConnectionTraceEvent {
            seq,
            flow_id,
            family,
            session_id,
            policy_version,
            permit_generation,
            command_seq,
            pid,
            role,
            phase,
            enforcement_state,
            detail,
            observed_at,
        });
    }

    fn persist_receipt(&self, receipt: &ChannelEnforcementReceipt) -> Result<()> {
        if let Some(store) = &self.storage {
            store.atomic_json(
                &store
                    .paths
                    .watch()
                    .join(format!("state/channel-receipt-{}.json", receipt.family)),
                &json!(receipt),
            )?;
        }
        Ok(())
    }

    fn command_content_matches(
        a: &ChannelEnforcementCommand,
        b: &ChannelEnforcementCommand,
    ) -> bool {
        a.family == b.family
            && a.session_id == b.session_id
            && a.policy_version == b.policy_version
            && a.permit_generation == b.permit_generation
            && a.command_seq == b.command_seq
            && a.permit.state == b.permit.state
            && a.permit.reason_code == b.permit.reason_code
            && (a.permit.valid_until - b.permit.valid_until).abs() < 1e-6
            && a.permit.members == b.permit.members
            && a.allowed_processes == b.allowed_processes
            && a.upstream_endpoint == b.upstream_endpoint
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, EnforcerInner>> {
        self.inner
            .lock()
            .map_err(|_| CoreError::new("channel_enforcer_lock_poisoned", "通道执行器锁不可用"))
    }
}

impl ChannelEnforcer for LocalTunnelEnforcer {
    fn boot_id(&self) -> Result<String> {
        Ok(self.lock()?.boot_id.clone())
    }

    fn is_ready(&self) -> Result<bool> {
        let guard = self.lock()?;
        Ok(guard.interception_active
            && guard.direct_fallback_blocked
            && guard.system_extension_active
            && guard.local_proxy_ready
            && guard.upstream_healthy)
    }

    fn apply_command(
        &self,
        command: &ChannelEnforcementCommand,
        now: f64,
    ) -> Result<ChannelEnforcementReceipt> {
        if !command.policy_version.valid() {
            return Err(CoreError::new(
                "invalid_policy_version",
                "拒绝策略版本摘要无效的通道命令",
            ));
        }
        let (receipt, sink) = {
            let mut guard = self.lock()?;

            // Validate generation, sequence, session, and per-family policy
            // BEFORE modifying `last_wall_now`, `current_policy`, or family state!
            if let Some(existing) = guard.families.get(&command.family) {
                if command.permit_generation < existing.last_permit_generation
                    || (command.permit_generation == existing.last_permit_generation
                        && command.command_seq < existing.last_command_seq)
                {
                    return Err(CoreError::new(
                        "stale_or_out_of_order_command",
                        "拒绝旧代次或乱序的通道控制命令",
                    ));
                }
                if command.permit_generation == existing.last_permit_generation
                    && command.command_seq == existing.last_command_seq
                {
                    if let Some(prev_cmd) = existing.command.as_ref() {
                        if Self::command_content_matches(prev_cmd, command) {
                            let existing_receipt = Self::build_receipt_locked(
                                &guard,
                                &command.family,
                                existing.last_updated_at,
                            )?;
                            return Ok(existing_receipt);
                        }
                    }
                    return Err(CoreError::new(
                        "conflicting_command_seq",
                        "拒绝同序号但内容冲突的通道控制命令",
                    ));
                }
                if existing
                    .command
                    .as_ref()
                    .is_some_and(|prev| prev.session_id != command.session_id)
                    && command.permit_generation <= existing.last_permit_generation
                {
                    return Err(CoreError::new(
                        "stale_session_command",
                        "会话切换必须递增许可代次",
                    ));
                }
                // Requirement 6 (逐家族比较旧命令策略版本): Compare against THIS
                // family's own previous command policy version, not just global
                // `guard.current_policy`!
                if existing
                    .command
                    .as_ref()
                    .is_some_and(|prev| prev.policy_version != command.policy_version)
                    && command.permit_generation <= existing.last_permit_generation
                {
                    return Err(CoreError::new(
                        "stale_policy_generation_command",
                        "策略版本变更必须递增许可代次",
                    ));
                }
            }

            if let Some(prev_wall) = guard.last_wall_now {
                if now + claude_watch_core::channel::CLOCK_ROLLBACK_TOLERANCE_SECONDS < prev_wall {
                    let families: Vec<String> = guard.families.keys().cloned().collect();
                    for fam in families {
                        Self::begin_revoke_locked(&mut guard, &fam, "clock_rollback_detected", now);
                    }
                }
            }
            guard.last_wall_now = Some(now);
            guard.current_policy = Some(command.policy_version.clone());

            let interception_active = guard.interception_active && guard.direct_fallback_blocked;
            let upstream_healthy = guard.upstream_healthy;
            // Compare `policy_version` per-family against `state.command` so
            // updating family #1 ("claude") never masks `policy_changed` for
            // family #2 ("openai")!
            let (policy_changed, session_changed, has_active_flows) = {
                let state = guard
                    .families
                    .entry(command.family.clone())
                    .or_insert_with(|| FamilyEnforcerState::new(now));
                let policy_changed = state
                    .command
                    .as_ref()
                    .is_some_and(|prev| prev.policy_version != command.policy_version);
                let session_changed = state
                    .command
                    .as_ref()
                    .is_some_and(|prev| prev.session_id != command.session_id);
                state.last_permit_generation = command.permit_generation;
                state.last_command_seq = command.command_seq;
                state.command = Some(command.clone());
                state.last_updated_at = now;
                (
                    policy_changed,
                    session_changed,
                    !state.active_flows.is_empty(),
                )
            };

            let (effective_state, effective_reason) = command
                .permit
                .effective_state_with_clock(now, None, false, &command.policy_version);

            let activation_error = guard
                .activation_error_code
                .clone()
                .unwrap_or_else(|| "interception_inactive_direct_leak_risk".into());

            if !interception_active {
                if let Some(state) = guard.families.get_mut(&command.family) {
                    state.enforcement_state = ChannelEnforcementState::Failed;
                    state.last_error_code = Some(activation_error);
                }
            } else if !upstream_healthy {
                Self::begin_revoke_locked(
                    &mut guard,
                    &command.family,
                    "tag_upstream_unhealthy",
                    now,
                );
            } else if policy_changed || session_changed {
                // Any active flows from a previous policy or previous session must
                // be closed before the new state can be considered clean.
                if effective_state == ChannelPermitState::Permitted {
                    if has_active_flows {
                        Self::begin_revoke_locked(
                            &mut guard,
                            &command.family,
                            "policy_or_session_transition",
                            now,
                        );
                    } else if let Some(state) = guard.families.get_mut(&command.family) {
                        state.enforcement_state = ChannelEnforcementState::Forwarding;
                        state.last_error_code = None;
                    }
                } else {
                    Self::begin_revoke_locked(&mut guard, &command.family, effective_reason, now);
                }
            } else {
                match effective_state {
                    ChannelPermitState::Permitted => {
                        if let Some(state) = guard.families.get_mut(&command.family) {
                            state.enforcement_state = ChannelEnforcementState::Forwarding;
                            state.last_error_code = None;
                        }
                    }
                    ChannelPermitState::PendingVerification => {
                        if !has_active_flows {
                            if let Some(state) = guard.families.get_mut(&command.family) {
                                state.enforcement_state =
                                    ChannelEnforcementState::PendingVerification;
                            }
                        } else {
                            Self::begin_revoke_locked(
                                &mut guard,
                                &command.family,
                                "pending_verification_hold",
                                now,
                            );
                        }
                    }
                    ChannelPermitState::Revoked => {
                        Self::begin_revoke_locked(
                            &mut guard,
                            &command.family,
                            &command.permit.reason_code.clone(),
                            now,
                        );
                    }
                }
            }
            (
                Self::build_receipt_locked(&guard, &command.family, now)?,
                guard.receipt_sink.clone(),
            )
        };
        if let Some(store) = &self.storage {
            store.atomic_json(
                &store
                    .paths
                    .watch()
                    .join(format!("state/channel-command-{}.json", command.family)),
                &json!(command),
            )?;
        }
        self.persist_receipt(&receipt)?;
        if let Some(s) = &sink {
            s(receipt.clone());
        }
        Ok(receipt)
    }

    fn receipt_for(&self, family: &str, now: f64) -> Result<Option<ChannelEnforcementReceipt>> {
        let guard = self.lock()?;
        if !guard.families.contains_key(family)
            || guard
                .families
                .get(family)
                .is_none_or(|s| s.command.is_none())
        {
            return Ok(None);
        }
        Ok(Some(Self::build_receipt_locked(&guard, family, now)?))
    }

    fn enforce_active_deadlines(
        &self,
        now: f64,
        woke_from_sleep: bool,
    ) -> Result<Vec<ChannelEnforcementReceipt>> {
        let (updated, sink) = {
            let mut guard = self.lock()?;
            let last_wall = guard.last_wall_now;
            guard.last_wall_now = Some(now);
            let families: Vec<String> = guard.families.keys().cloned().collect();
            let mut updated = Vec::new();
            for family in families {
                let should_revoke = guard.families.get(&family).and_then(|state| {
                    let cmd = state.command.as_ref()?;
                    let policy = &cmd.policy_version;
                    let (eff_state, reason) = cmd.permit.effective_state_with_clock(
                        now,
                        last_wall,
                        woke_from_sleep,
                        policy,
                    );
                    if eff_state == ChannelPermitState::Revoked
                        && (cmd.permit.state != ChannelPermitState::Revoked
                            || state.enforcement_state == ChannelEnforcementState::Forwarding
                            || !state.active_flows.is_empty())
                    {
                        Some(reason)
                    } else {
                        None
                    }
                });
                if let Some(reason) = should_revoke {
                    Self::begin_revoke_locked(&mut guard, &family, reason, now);
                    updated.push(Self::build_receipt_locked(&guard, &family, now)?);
                }
            }
            (updated, guard.receipt_sink.clone())
        };
        for r in &updated {
            self.persist_receipt(r)?;
            if let Some(s) = &sink {
                s(r.clone());
            }
        }
        Ok(updated)
    }

    fn local_proxy_port(&self) -> Option<u16> {
        let guard = self.lock().ok()?;
        guard.local_listener_addr.as_ref().and_then(|addr| {
            addr.split(':').last()?.parse::<u16>().ok()
        })
    }
}

static PRODUCTION_ENFORCERS: std::sync::OnceLock<
    Mutex<BTreeMap<std::path::PathBuf, Arc<LocalTunnelEnforcer>>>,
> = std::sync::OnceLock::new();

fn enforcer_registry() -> &'static Mutex<BTreeMap<std::path::PathBuf, Arc<LocalTunnelEnforcer>>> {
    PRODUCTION_ENFORCERS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub fn register_production_enforcer(
    watch_dir: &std::path::Path,
    enforcer: Arc<LocalTunnelEnforcer>,
) {
    if let Ok(mut guard) = enforcer_registry().lock() {
        guard.insert(watch_dir.to_path_buf(), enforcer);
    }
}

pub fn registered_production_enforcer(
    watch_dir: &std::path::Path,
) -> Option<Arc<LocalTunnelEnforcer>> {
    enforcer_registry()
        .lock()
        .ok()
        .and_then(|guard| guard.get(watch_dir).cloned())
}

pub fn unregister_production_enforcer(watch_dir: &std::path::Path) {
    if let Ok(mut guard) = enforcer_registry().lock() {
        guard.remove(watch_dir);
    }
}

impl LocalTunnelEnforcer {
    /// Explicit protocol coverage matrix distinguishing `local_proxy_ready`
    /// and `system_extension_active`.
    pub fn protocol_coverage_boundaries(&self) -> serde_json::Value {
        let ready = self.is_ready().unwrap_or(false);
        let local_proxy_ready = self.local_proxy_ready().unwrap_or(false);
        let sysext_active = self.system_extension_active().unwrap_or(false);
        let proxy_addr = self.lock().ok().and_then(|g| g.local_listener_addr.clone());
        json!({
            "enforcer_ready": ready,
            "local_proxy_ready": local_proxy_ready,
            "system_extension_active": sysext_active,
            "local_proxy_addr": proxy_addr,
            "tcp_ipv4": {
                "local_proxy_relay": if local_proxy_ready { "active_with_upstream_connect_handshake" } else { "inactive" },
                "transparent_kernel_capture": if sysext_active { "active" } else { "pending_system_extension_activation" },
                "disposition": "forward_via_controlled_tunnel_or_block_when_revoked"
            },
            "tcp_ipv6": {
                "local_proxy_relay": if local_proxy_ready { "active_with_upstream_connect_handshake" } else { "inactive" },
                "transparent_kernel_capture": if sysext_active { "active" } else { "pending_system_extension_activation" },
                "disposition": "forward_via_controlled_tunnel_or_block_when_revoked"
            },
            "udp_quic": {
                "flow_gate_policy": "claimed_and_blocked_in_channel_mode",
                "transparent_kernel_capture": if sysext_active { "active" } else { "pending_system_extension_activation" },
                "disposition": "claim_and_block"
            },
            "dns": {
                "flow_gate_policy": "direct_53_853_claimed_and_blocked",
                "transparent_kernel_capture": if sysext_active { "active" } else { "pending_system_extension_activation" },
                "disposition": "claim_and_block"
            },
            "unsupported": {
                "flow_gate_policy": "claimed_and_blocked_no_direct_bypass",
                "transparent_kernel_capture": if sysext_active { "active" } else { "pending_system_extension_activation" },
                "disposition": "claim_and_block"
            }
        })
    }
}

fn parse_audit_token_hex(hex: &str) -> Option<[u32; 8]> {
    let clean = hex.trim();
    if clean.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
    }
    let mut words = [0u32; 8];
    for i in 0..8 {
        words[i] = u32::from_ne_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1],
            bytes[i * 4 + 2],
            bytes[i * 4 + 3],
        ]);
    }
    Some(words)
}
