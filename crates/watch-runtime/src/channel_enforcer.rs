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
        FlowTransportProtocol, NetworkBackendKind, PolicyVersion, ProtocolDisposition,
    },
    controlled_launch::AcceptedConnectionContext,
    error::{CoreError, Result},
    processes::ProcessRole,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    os::unix::{net::{UnixStream, UnixListener}, fs::{DirBuilderExt, PermissionsExt}},
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
    local_revoke_reason: Option<String>,
    requires_supervisor_revocation: bool,
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
            local_revoke_reason: None,
            requires_supervisor_revocation: false,
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
#[derive(Default)]
struct ReceiptPublication {
    pending: VecDeque<(ChannelEnforcementReceipt, ReceiptEventSink)>,
    dispatching: bool,
}
type SocketAttributor =
    Arc<dyn Fn(SocketAddr) -> Option<(String, BoundProcessToken)> + Send + Sync>;
type ContextSocketAttributor = Arc<
    dyn Fn(&AcceptedConnectionContext) -> Option<(String, BoundProcessToken)> + Send + Sync,
>;

struct EnforcerInner {
    boot_id: String,
    backend: NetworkBackendKind,
    sandbox_ready: bool,
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
    context_socket_attributor: Option<ContextSocketAttributor>,
    verified_peer_sockets: BTreeMap<SocketAddr, (String, BoundProcessToken)>,
    local_control_endpoints: BTreeSet<String>,
    local_listener_addr: Option<String>,
    gateway_endpoint_protection: Option<claude_watch_system::launchd_gateway::GatewayEndpointProtection>,
    last_wall_now: Option<f64>,
    current_policy: Option<PolicyVersion>,
    families: BTreeMap<String, FamilyEnforcerState>,
    traces: Vec<ConnectionTraceEvent>,
    next_trace_seq: u64,
    strict_peer_verification: bool,
    extension_socket_path: Option<String>,
    extension_receipts: BTreeMap<String, claude_watch_core::channel::SystemExtensionReceipt>,
    extension_heartbeat: Option<claude_watch_core::channel::SystemExtensionHeartbeat>,
}

pub struct LocalTunnelEnforcer {
    inner: Arc<Mutex<EnforcerInner>>,
    receipt_publication: Arc<Mutex<ReceiptPublication>>,
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
        Self {
            inner: Arc::new(Mutex::new(EnforcerInner {
                boot_id: boot_id.into(),
                backend: NetworkBackendKind::NetworkExtension,
                sandbox_ready: false,
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
                context_socket_attributor: None,
                verified_peer_sockets: BTreeMap::new(),
                local_control_endpoints,
                local_listener_addr: None,
                gateway_endpoint_protection: None,
                last_wall_now: None,
                current_policy: None,
                families: BTreeMap::new(),
                traces: Vec::new(),
                next_trace_seq: 1,
                strict_peer_verification: false,
                extension_socket_path: None,
                extension_receipts: BTreeMap::new(),
                extension_heartbeat: None,
            })),
            next_flow_id: Arc::new(AtomicU64::new(1)),
            receipt_publication: Arc::new(Mutex::new(ReceiptPublication::default())),
            storage,
        }
    }

    pub fn set_strict_peer_verification(&self, strict: bool) {
        if let Ok(mut guard) = self.lock() {
            guard.strict_peer_verification = strict;
        }
    }

    pub fn backend_kind(&self) -> Result<NetworkBackendKind> {
        Ok(self.lock()?.backend)
    }

    pub fn sandbox_ready(&self) -> Result<bool> {
        Ok(self.lock()?.sandbox_ready)
    }

    /// Configures Seatbelt (`nono`) sandbox backend state without pretending
    /// that a macOS SystemExtension (`NETransparentProxyProvider`) is active.
    pub fn configure_seatbelt_backend(&self, sandbox_ready: bool, now: f64) -> Result<String> {
        let mut guard = self.lock()?;
        guard.backend = NetworkBackendKind::Seatbelt;
        guard.sandbox_ready = sandbox_ready;
        guard.system_extension_active = false;
        guard.interception_active = sandbox_ready && guard.local_proxy_ready;
        guard.direct_fallback_blocked = sandbox_ready;
        guard.last_wall_now = Some(now);
        if sandbox_ready && guard.local_proxy_ready {
            guard.activation_error_code = None;
        } else if !sandbox_ready && guard.activation_error_code.is_none() {
            guard.activation_error_code = Some("sandbox_backend_not_ready".into());
        }
        Ok(guard.boot_id.clone())
    }

    /// Production Seatbelt (`nono`) backend gate: evaluates `SandboxGatewayIdentityReport::can_enable_production_backend()`
    /// and keeps `sandbox_ready = false` (recording the exact blocker code such as `gateway_server_identity_unverified_i03`)
    /// whenever any of `I01`–`I04` is unverified.
    pub fn configure_seatbelt_backend_with_identity_gate(
        &self,
        report: &crate::sandbox_launch::SandboxGatewayIdentityReport,
        now: f64,
    ) -> Result<bool> {
        let can_enable = report.can_enable_production_backend();
        let mut guard = self.lock()?;
        guard.backend = NetworkBackendKind::Seatbelt;
        guard.sandbox_ready = can_enable;
        guard.system_extension_active = false;
        guard.interception_active = can_enable && guard.local_proxy_ready;
        guard.direct_fallback_blocked = can_enable;
        guard.last_wall_now = Some(now);
        if can_enable && guard.local_proxy_ready {
            guard.activation_error_code = None;
        } else if !can_enable {
            guard.activation_error_code = Some(
                report
                    .blocker_code
                    .clone()
                    .unwrap_or_else(|| "sandbox_identity_gate_blocked".into()),
            );
        }
        Ok(can_enable)
    }

    pub fn start_extension_gateway(self: &Arc<Self>, stop: Arc<AtomicBool>) -> Result<()> {
        let dir = std::path::PathBuf::from("/tmp")
            .join(format!("cw-channel-{}", uuid::Uuid::new_v4().simple()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir)
            .map_err(|_| CoreError::new("extension_gateway_unavailable", "扩展网关目录创建失败"))?;
        let path = dir.join("gateway.sock");
        let listener = UnixListener::bind(&path)
            .map_err(|_| CoreError::new("extension_gateway_unavailable", "扩展网关绑定失败"))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| CoreError::new("extension_gateway_unavailable", "扩展网关权限设置失败"))?;
        listener.set_nonblocking(true)
            .map_err(|_| CoreError::new("extension_gateway_unavailable", "扩展网关监听设置失败"))?;
        self.lock()?.extension_socket_path = Some(path.to_string_lossy().into_owned());
        let enforcer = self.clone();
        thread::Builder::new().name("channel-extension-gateway".into()).spawn(move || {
            while !stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let enforcer = enforcer.clone();
                        thread::spawn(move || {
                            if crate::channel_extension::is_authenticated_extension(&stream) {
                                Self::serve_gateway_connection(enforcer, TunnelStream::Unix(stream), None, true);
                            } else {
                                let _ = stream.shutdown(Shutdown::Both);
                            }
                        });
                    }
                    Err(_) => thread::sleep(Duration::from_millis(25)),
                }
            }
            drop(listener);
            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_dir(dir);
        }).map_err(|_| CoreError::new("extension_gateway_unavailable", "扩展网关线程创建失败"))?;
        Ok(())
    }

    /// Read only root-authored observations. Every unavailable/invalid path
    /// clears prior success; the UI's activation cache is never evidence here.
    pub fn refresh_system_extension(&self, now: f64) -> Result<()> {
        use claude_watch_core::channel::{SystemExtensionHeartbeat, SystemExtensionReceipt};
        if !self.lock()?.strict_peer_verification { return Ok(()); }
        let Some(store) = &self.storage else { return Ok(()); };
        let heartbeat = crate::channel_extension::read_observation::<SystemExtensionHeartbeat>(store, "system-extension-heartbeat.json").ok();
        let receipts = crate::channel_extension::read_observation::<Vec<SystemExtensionReceipt>>(store, "system-extension-receipt.json").unwrap_or_default();
        self.observe_system_extension(heartbeat, receipts, now)
    }

    pub fn observe_system_extension(
        &self,
        heartbeat: Option<claude_watch_core::channel::SystemExtensionHeartbeat>,
        receipts: Vec<claude_watch_core::channel::SystemExtensionReceipt>,
        now: f64,
    ) -> Result<()> {
        let updates = {
            let mut guard = self.lock()?;
            let live = heartbeat.as_ref().is_some_and(|h| h.is_live(&guard.boot_id, now));
            let receipt_map = receipts.into_iter().map(|r| (r.family.clone(), r)).collect::<BTreeMap<_, _>>();
            if guard.extension_heartbeat == heartbeat && guard.extension_receipts == receipt_map
                && guard.system_extension_active == live { return Ok(()); }
            let lost = guard.system_extension_active && !live;
            let changed = guard.extension_heartbeat.as_ref().map(|h| &h.extension_boot_id)
                != heartbeat.as_ref().map(|h| &h.extension_boot_id);
            guard.extension_heartbeat = heartbeat;
            guard.extension_receipts = receipt_map;
            guard.system_extension_active = live;
            guard.interception_active = live && guard.local_proxy_ready;
            guard.direct_fallback_blocked = live;
            guard.activation_error_code = if live { None } else { Some("system_extension_liveness_unconfirmed".into()) };
            let families: Vec<_> = guard.families.keys().cloned().collect();
            if lost || changed {
                for family in &families {
                    Self::begin_autonomous_revoke_locked(&mut guard, family, "extension_control_lost_or_restarted", now);
                }
            }
            for family in &families {
                let reason = guard.families.get(family).filter(|s|
                    s.command.as_ref().is_some_and(|c| c.permit.state == ChannelPermitState::Permitted)
                        && s.local_revoke_reason.is_none())
                    .and_then(|_| Self::matching_extension_receipt(&guard, family, now))
                    .filter(|r| r.new_connections_blocked && (r.is_confirmed_revoked()
                        || r.is_disconnecting() || r.status == "failed"))
                    .map(|r| r.reason.clone().unwrap_or_else(|| "extension_autonomous_cutoff".into()));
                if let Some(reason) = reason {
                    // Mirror the extension's actual cutoff into our own relay
                    // before reporting it; neither half can reopen on its own.
                    Self::begin_autonomous_revoke_locked(&mut guard, family, &reason, now);
                }
            }
            let updates = families.iter().filter_map(|f| Self::build_receipt_locked(&guard, f, now).ok()).collect::<Vec<_>>();
            updates
        };
        for receipt in updates {
            self.publish_current_receipt(&receipt)?;
        }
        Ok(())
    }

    pub fn extension_commands(&self) -> Result<serde_json::Value> {
        Ok({
            let guard = self.lock()?;
            let commands = guard.families.iter().filter_map(|(family, state)| {
                let cmd = state.command.as_ref()?;
                Some(json!({
                    "family": family,
                    "policy_version": cmd.policy_version,
                    "command_seq": cmd.command_seq,
                    "permit_generation": cmd.permit_generation,
                    "issued_at": cmd.issued_at,
                    "valid_until": cmd.permit.valid_until,
                    "permit_state": cmd.permit.state,
                    "allowed_pids": cmd.allowed_processes.iter().map(|p| p.pid).collect::<Vec<_>>(),
                    "allowed_processes": cmd.allowed_processes,
                    "session_id": cmd.session_id,
                    "command_binding": crate::channel_extension::command_binding(cmd),
                    "reason": cmd.permit.reason_code,
                }))
            }).collect::<Vec<_>>();
            json!({"executor_boot_id": guard.boot_id,
                "extension_boot_id": guard.extension_heartbeat.as_ref().map(|h| h.extension_boot_id.as_str()),
                "gateway_socket": guard.extension_socket_path,
                "control_home": self.storage.as_ref().map(|s| &s.paths.home), "commands": commands})
        })
    }

    fn publish_extension_commands(&self) -> Result<()> {
        let Some(store) = &self.storage else { return Ok(()); };
        if !self.lock()?.strict_peer_verification { return Ok(()); }
        let snapshot = self.extension_commands()?;
        let value = json!({"gateway_socket": snapshot["gateway_socket"], "executor_boot_id": snapshot["executor_boot_id"]});
        // Discovery and wakeup only. The extension obtains authority from our
        // authenticated Unix CONTROL endpoint, never the contents of this file.
        store.atomic_json(&store.paths.watch().join("state/system-extension-command.json"), &value)
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
            guard.gateway_endpoint_protection = None;
            if guard.backend.is_sandbox() { guard.sandbox_ready = false; }
            guard.interception_active = false;
            guard.direct_fallback_blocked = false;
            guard.activation_error_code = Some("local_proxy_not_ready".into());
            for state in guard.families.values_mut() {
                state.enforcement_state = ChannelEnforcementState::Failed;
                state.last_error_code = Some("local_proxy_not_ready".into());
                state.last_updated_at = now;
            }
        } else if guard.backend.is_sandbox() && guard.sandbox_ready {
            guard.system_extension_active = false;
            guard.interception_active = true;
            guard.direct_fallback_blocked = true;
            guard.activation_error_code = None;
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
        {
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
        }
        emitted.iter().map(|r| self.publish_current_receipt(r)).collect()
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

    pub fn set_accepted_connection_attributor<F>(&self, attributor: F) -> Result<()>
    where
        F: Fn(&AcceptedConnectionContext) -> Option<(String, BoundProcessToken)>
            + Send
            + Sync
            + 'static,
    {
        let mut guard = self.lock()?;
        guard.context_socket_attributor = Some(Arc::new(attributor));
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
            Self::begin_autonomous_revoke_locked(
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
        let (closing_flows, receipts) = {
            let mut guard = self.lock()?;
            guard.upstream_healthy = false;
            let families: Vec<String> = guard.families.keys().cloned().collect();
            let mut closing_flows = Vec::new();
            let mut receipts = Vec::new();
            for family in families {
                let ids =
                    Self::begin_autonomous_revoke_locked(&mut guard, &family, "tag_upstream_unhealthy", now);
                closing_flows.extend(ids);
                if let Ok(r) = Self::build_receipt_locked(&guard, &family, now) {
                    receipts.push(r);
                }
            }
            (closing_flows, receipts)
        };
        for r in &receipts {
            self.publish_current_receipt(r)?;
        }
        Ok(closing_flows)
    }

    pub fn mark_upstream_healthy(&self) -> Result<()> {
        let mut guard = self.lock()?;
        guard.upstream_healthy = true;
        Ok(())
    }

    /// Autonomous family cutoff (e.g., on daemon shutdown or emergency VPN/gateway cutoff):
    /// immediately blocks new connections and closes all active flows for `family` while
    /// keeping the supervised processes alive.
    pub fn revoke_family(&self, family: &str, reason: &str, now: f64) -> Result<Option<ChannelEnforcementReceipt>> {
        let receipt = {
            let mut guard = self.lock()?;
            if !guard.families.contains_key(family) {
                return Ok(None);
            }
            Self::begin_autonomous_revoke_locked(&mut guard, family, reason, now);
            Self::build_receipt_locked(&guard, family, now)?
        };
        let receipt = self.publish_current_receipt(&receipt)?;
        Ok(Some(receipt))
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
        let receipt = {
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
            Self::build_receipt_locked(&guard, family, now)?
        };
        let receipt = self.publish_current_receipt(&receipt)?;
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
        let receipt = {
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
            Self::build_receipt_locked(&guard, family, now)?
        };
        let receipt = self.publish_current_receipt(&receipt)?;
        Ok(Some(receipt))
    }

    /// Checks whether any flow in `Disconnecting` state has exceeded the
    /// disconnect timeout without confirmation, transitioning the family to
    /// `Failed` (`flow_termination_timeout`).
    pub fn check_disconnect_timeouts(&self, now: f64) -> Result<Vec<ChannelEnforcementReceipt>> {
        let timed_out_receipts = {
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
            timed_out_receipts
        };
        timed_out_receipts.iter().map(|r| self.publish_current_receipt(r)).collect()
    }

    /// Strict process attribution check (Requirement 5):
    /// Only matches full `BoundProcessToken::matches_process` (`pid`, `uid > 0`,
    /// `start_seconds`, `start_microseconds`, and `audit_token`). Never falls
    /// back to matching `(pid, start_seconds, start_microseconds)` alone.
    fn is_process_attributed(cmd: &ChannelEnforcementCommand, process: &BoundProcessToken, strict: bool) -> bool {
        process.has_valid_identity()
            && (!strict || process.has_verified_audit_token())
            && cmd.allowed_processes.iter().any(|allowed| {
                (!strict || allowed.has_verified_audit_token()) && allowed.matches_process(
                    process.pid,
                    process.uid,
                    process.start_seconds,
                    process.start_microseconds,
                    process.audit_token.as_ref(),
                )
            })
    }

    fn resolve_peer_socket_identity(&self, peer_addr: SocketAddr) -> Result<(String, BoundProcessToken)> {
        let conn_id = self.next_flow_id.fetch_add(1, Ordering::Relaxed);
        let (from_map, attributor, ctx_attributor, boot_id, now, local_addr_opt, allowed_snapshot) = {
            let guard = self.lock()?;
            let from_map = guard.verified_peer_sockets.get(&peer_addr).cloned();
            let attributor = guard.socket_attributor.clone();
            let ctx_attributor = guard.context_socket_attributor.clone();
            let boot_id = guard.boot_id.clone();
            let now = guard
                .clock
                .as_ref()
                .map(|c| c())
                .unwrap_or_else(crate::native::now);
            let local_addr_opt = guard
                .local_listener_addr
                .as_deref()
                .and_then(|s| s.parse::<SocketAddr>().ok());
            let mut allowed_snapshot = Vec::new();
            for (fam, st) in &guard.families {
                if let Some(cmd) = &st.command {
                    for tok in &cmd.allowed_processes {
                        allowed_snapshot.push((fam.clone(), tok.clone()));
                    }
                }
            }
            (
                from_map,
                attributor,
                ctx_attributor,
                boot_id,
                now,
                local_addr_opt,
                allowed_snapshot,
            )
        };
        if let Some((fam, tok)) = from_map {
            if tok.has_valid_identity() {
                return Ok((fam, tok));
            }
        }
        if let (Some(ctx_attr), Some(local_addr)) = (ctx_attributor, local_addr_opt) {
            let ctx = AcceptedConnectionContext {
                connection_id: conn_id,
                protocol: FlowTransportProtocol::TcpIpv4,
                peer_addr,
                local_addr,
                listener_boot_id: boot_id,
                accepted_at: now,
                socket_fd: None,
            };
            if let Some((fam, tok)) = ctx_attr(&ctx) {
                if tok.has_valid_identity() {
                    return Ok((fam, tok));
                }
            }
            let mut guard = self.lock()?;
            for state in guard.families.values_mut() {
                state.blocked_new_connections = state.blocked_new_connections.saturating_add(1);
            }
            return Err(CoreError::new(
                "unverified_peer_socket_identity",
                "拒绝未通过 AcceptedConnectionContext 实时内核套接字归属核验的本地代理连接",
            ));
        }
        if let Some(attr) = attributor {
            if let Some((fam, tok)) = attr(peer_addr) {
                if tok.has_valid_identity() {
                    return Ok((fam, tok));
                }
            }
        }
        // Kernel socket attribution via `proc_pidinfo(PROC_PIDLISTFDS)` + `PROC_PIDFDSOCKETINFO`
        // matched against authorized `BoundProcessToken`s with full kernel identity.
        if let Some(local_addr) = local_addr_opt {
            let candidate_pids: Vec<u32> = allowed_snapshot.iter().map(|(_, t)| t.pid).collect();
            if let Some(kernel_id) =
                claude_watch_system::attribute_loopback_tcp_peer(peer_addr, local_addr, &candidate_pids)
            {
                for (fam, tok) in &allowed_snapshot {
                    if tok.matches_process(
                        kernel_id.pid,
                        kernel_id.uid,
                        kernel_id.start_seconds,
                        kernel_id.start_microseconds,
                        Some(&kernel_id.audit_token),
                    ) {
                        let matched_tok = if tok.audit_token.is_some() {
                            tok.clone()
                        } else {
                            tok.clone().with_audit_token(kernel_id.audit_token)
                        };
                        if matched_tok.has_valid_identity() {
                            return Ok((fam.clone(), matched_tok));
                        }
                    }
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
        self.start_proxy_on_listener(listener, None, stop, now)
    }

    /// Production Seatbelt ingress accepts only a listener transferred by the
    /// authenticated, system-installed launchd broker. There is deliberately
    /// no local bind fallback when that service is absent or untrusted.
    pub fn start_launchd_proxy_listener(
        self: &Arc<Self>, stop: Arc<AtomicBool>, now: f64,
    ) -> Result<(SocketAddr, thread::JoinHandle<()>)> {
        let verified = claude_watch_system::launchd_gateway::acquire_gateway_listener()
            .map_err(|error| CoreError::new("gateway_endpoint_unverified_i03", &format!("系统托管网关不可用：{error}")))?;
        let (listener, protection) = verified.into_parts();
        self.start_proxy_on_listener(listener, Some(protection), stop, now)
    }

    pub fn gateway_endpoint_protection(&self) -> Result<Option<claude_watch_system::launchd_gateway::GatewayEndpointProtection>> {
        let guard = self.lock()?;
        Ok(if guard.local_proxy_ready { guard.gateway_endpoint_protection.clone() } else { None })
    }

    fn start_proxy_on_listener(
        self: &Arc<Self>, listener: TcpListener,
        protection: Option<claude_watch_system::launchd_gateway::GatewayEndpointProtection>,
        stop: Arc<AtomicBool>, now: f64,
    ) -> Result<(SocketAddr, thread::JoinHandle<()>)> {
        listener.set_nonblocking(true).map_err(|error| CoreError::new("enforcer_listener_mode_failed", &error.to_string()))?;
        let bound_addr = match listener.local_addr() {
            Ok(a) => a,
            Err(_) => {
                let _ = self.record_activation_failure("enforcer_listener_addr_failed", now);
                return Err(CoreError::new(
                    "enforcer_listener_addr_failed",
                    "受控通道监听地址不可读",
                ));
            }
        };
        // System reservations cover all local addresses, because Seatbelt's
        // localhost filter is broader than the literal 127.0.0.1. Advertise
        // only the intended loopback endpoint; never expose a wildcard proxy
        // address in launch requests or diagnostic path evidence.
        let addr = protection.as_ref().map(|proof| proof.endpoint()).unwrap_or(bound_addr);
        {
            let mut guard = self.lock()?;
            guard.local_proxy_ready = true;
            guard.gateway_endpoint_protection = protection;
            // The local listener only proves that the proxy server is ready.
            // System extension activation and direct fallback blocking must be
            // confirmed separately by the system extension manager or IPC!
            if guard.backend.is_sandbox() && guard.sandbox_ready {
                guard.system_extension_active = false;
                guard.interception_active = true;
                guard.direct_fallback_blocked = true;
                guard.activation_error_code = None;
            } else if guard.system_extension_active {
                guard.interception_active = true;
                guard.direct_fallback_blocked = true;
                guard.activation_error_code = None;
            } else {
                guard.interception_active = false;
                guard.direct_fallback_blocked = false;
                guard.activation_error_code = Some(if guard.backend.is_sandbox() {
                    "sandbox_backend_not_ready".into()
                } else {
                    "system_extension_inactive".into()
                });
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
                        Ok((incoming, peer_addr)) => {
                            if !peer_addr.ip().is_loopback() {
                                let _ = incoming.shutdown(Shutdown::Both);
                                continue;
                            }
                            let _ = incoming.set_nonblocking(false);
                            let enf = Arc::clone(&enforcer);
                            thread::spawn(move || {
                                Self::serve_gateway_connection(enf, TunnelStream::Tcp(incoming), Some(peer_addr), false);
                            });
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(25));
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
                // A failed accept loop must not leave existing relays alive.
                let families = enforcer.lock().map(|g| g.families.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
                for family in families { let _ = enforcer.revoke_family(&family, "gateway_listener_stopped", crate::native::now()); }
                let _ = enforcer.set_local_proxy_ready(false, crate::native::now());
                let _ = enforcer.record_activation_failure("gateway_listener_stopped", crate::native::now());
            })
            .map_err(|_| {
                let _ = self.set_local_proxy_ready(false, now);
                let _ = self.record_activation_failure("enforcer_listener_thread_failed", now);
                CoreError::new("enforcer_listener_thread_failed", "受控通道监听线程启动失败")
            })?;
        Ok((addr, handle))
    }

    fn read_chunked_http_body<R: Read>(
        reader: &mut R,
        max_bytes: usize,
    ) -> std::result::Result<Vec<u8>, &'static str> {
        // Bound payload and framing separately: many tiny chunks with long extensions must
        // not turn the payload limit into an unbounded allocation of raw wire bytes.
        const MAX_CHUNK_METADATA_BYTES: usize = 64 * 1024;
        let mut total_bytes = 0usize;
        let mut metadata_bytes = 0usize;
        let mut raw_chunked_payload = Vec::new();
        loop {
            let mut line = Vec::new();
            let mut b = [0u8; 1];
            while line.len() < 1024 {
                match reader.read(&mut b) {
                    Ok(1) => {
                        line.push(b[0]);
                        if line.ends_with(b"\r\n") {
                            break;
                        }
                    }
                    _ => return Err("incomplete_chunk_header"),
                }
            }
            if !line.ends_with(b"\r\n") {
                return Err("chunk_header_too_long");
            }
            metadata_bytes = metadata_bytes.checked_add(line.len()).ok_or("too_large")?;
            if metadata_bytes > MAX_CHUNK_METADATA_BYTES {
                return Err("too_large");
            }
            raw_chunked_payload.extend_from_slice(&line);
            let line_str = std::str::from_utf8(&line[..line.len() - 2])
                .map_err(|_| "invalid_chunk_header_encoding")?;
            let size_str = line_str.split(';').next().unwrap_or("");
            if size_str.is_empty()
                || !size_str.bytes().all(|b| b.is_ascii_hexdigit())
                || line_str.bytes().any(|b| b.is_ascii_control() && b != b'\t')
            {
                return Err("invalid_chunk_size_hex");
            }
            let chunk_size =
                usize::from_str_radix(size_str, 16).map_err(|_| "invalid_chunk_size_hex")?;
            if chunk_size == 0 {
                let mut trailer = Vec::new();
                let mut trailer_complete = false;
                while trailer.len() < 4096 {
                    match reader.read(&mut b) {
                        Ok(1) => {
                            trailer.push(b[0]);
                            if trailer.ends_with(b"\r\n\r\n") || trailer == b"\r\n" {
                                trailer_complete = true;
                                break;
                            }
                        }
                        _ => return Err("incomplete_chunk_trailer"),
                    }
                }
                if !trailer_complete {
                    return Err("trailer_too_long_or_unterminated");
                }
                let trailer_text =
                    std::str::from_utf8(&trailer).map_err(|_| "invalid_chunk_trailer")?;
                for field in trailer_text.split("\r\n").filter(|line| !line.is_empty()) {
                    let (name, value) = field.split_once(':').ok_or("invalid_chunk_trailer")?;
                    if name.is_empty()
                        || !name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
                        || value.bytes().any(|b| b.is_ascii_control() && b != b'\t')
                        || [
                            "content-length",
                            "transfer-encoding",
                            "host",
                            "connection",
                            "upgrade",
                            "trailer",
                        ]
                        .iter()
                        .any(|blocked| name.eq_ignore_ascii_case(blocked))
                    {
                        return Err("invalid_chunk_trailer");
                    }
                }
                metadata_bytes = metadata_bytes
                    .checked_add(trailer.len())
                    .ok_or("too_large")?;
                if metadata_bytes > MAX_CHUNK_METADATA_BYTES {
                    return Err("too_large");
                }
                raw_chunked_payload.extend_from_slice(&trailer);
                break;
            }
            total_bytes = total_bytes.checked_add(chunk_size).ok_or("too_large")?;
            if total_bytes > max_bytes {
                return Err("too_large");
            }
            metadata_bytes = metadata_bytes.checked_add(2).ok_or("too_large")?;
            if metadata_bytes > MAX_CHUNK_METADATA_BYTES {
                return Err("too_large");
            }
            let mut chunk_data = vec![0u8; chunk_size];
            reader
                .read_exact(&mut chunk_data)
                .map_err(|_| "incomplete_chunk_data")?;
            raw_chunked_payload.extend_from_slice(&chunk_data);
            let mut crlf = [0u8; 2];
            reader
                .read_exact(&mut crlf)
                .map_err(|_| "missing_chunk_crlf")?;
            if &crlf != b"\r\n" {
                return Err("invalid_chunk_crlf");
            }
            raw_chunked_payload.extend_from_slice(&crlf);
        }
        Ok(raw_chunked_payload)
    }

    fn serve_gateway_connection(enf: Arc<Self>, mut incoming: TunnelStream, peer_addr: Option<SocketAddr>, authenticated_extension: bool) {
        const MAX_HTTP_HEADER_BYTES: usize = 16384;
        const MAX_HTTP_BODY_BYTES: usize = 16 * 1024 * 1024;

        // Production NetworkExtension identity comes from the authenticated extension socket.
        // Seatbelt (`nono`) sandboxed clients connect via loopback TCP and are attributed
        // via kernel `PROC_PIDFDSOCKETINFO` + `BoundProcessToken` verification.
        if !authenticated_extension
            && enf
                .lock()
                .map_or(true, |g| g.strict_peer_verification && !g.backend.is_sandbox())
        {
            let _ = incoming.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            let _ = incoming.shutdown(Shutdown::Both);
            return;
        }

        let mut bound_keepalive_authority: Option<String> = None;
        loop {
            let _ = incoming.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = incoming.set_write_timeout(Some(Duration::from_secs(2)));
            let mut req_buf = Vec::with_capacity(512);
            let mut byte = [0u8; 1];
            let mut header_complete = false;
            while req_buf.len() < MAX_HTTP_HEADER_BYTES {
                match incoming.read(&mut byte) {
                    Ok(0) => break,
                    Ok(_) => {
                        req_buf.push(byte[0]);
                        if req_buf.ends_with(b"\r\n\r\n") || req_buf.ends_with(b"\n\n") {
                            header_complete = true;
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
            if !header_complete {
                let _ = incoming.write_all(
                    b"HTTP/1.1 400 Bad Request (Incomplete Or Oversized HTTP Headers)\r\n\r\n",
                );
                let _ = incoming.shutdown(Shutdown::Both);
                return;
            }
            let Ok(header) = std::str::from_utf8(&req_buf) else {
                let _ = incoming.write_all(
                    b"HTTP/1.1 400 Bad Request (Invalid UTF-8 In HTTP Headers)\r\n\r\n",
                );
                let _ = incoming.shutdown(Shutdown::Both);
                return;
            };
            let first_line = header.lines().next().unwrap_or("").trim_end_matches('\r');
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.first() == Some(&"WATCH-CONTROL") {
                if authenticated_extension
                    && parts.len() == 3
                    && uuid::Uuid::parse_str(parts[1]).is_ok()
                    && parts[2] == "HTTP/1.1"
                {
                    if let Ok(envelope) = enf.extension_commands() {
                        if let Ok(bytes) = serde_json::to_vec(&json!({"nonce": parts[1], "envelope": envelope})) {
                            if bytes.len() <= 1_048_576 {
                                let _ = incoming.write_all(&(bytes.len() as u32).to_be_bytes());
                                let _ = incoming.write_all(&bytes);
                            }
                        }
                    }
                }
                let _ = incoming.shutdown(Shutdown::Both);
                return;
            }
            let is_connect = parts.len() == 3
                && parts[0].eq_ignore_ascii_case("CONNECT")
                && matches!(parts[2], "HTTP/1.1" | "HTTP/1.0");
            let is_http_forward = parts.len() == 3
                && matches!(
                    parts[0].to_ascii_uppercase().as_str(),
                    "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH"
                )
                && matches!(parts[2], "HTTP/1.1" | "HTTP/1.0");
            if !is_connect && !is_http_forward {
                let _ = incoming.write_all(
                    b"HTTP/1.1 400 Bad Request (CONNECT Or HTTP Proxy Request Required)\r\n\r\n",
                );
                let _ = incoming.shutdown(Shutdown::Both);
                return;
            }

            let mut host_values = Vec::new();
            let mut content_length_values = Vec::new();
            let mut transfer_encoding_values = Vec::new();
            let mut has_transfer_encoding = false;
            let mut upgrade_websocket = false;
            let mut connection_upgrade = false;
            let mut client_wants_close = parts[2] == "HTTP/1.0";

            for raw_line in header.lines().skip(1) {
                let line = raw_line.trim_end_matches('\r');
                if line.is_empty() {
                    break;
                }
                let Some((name, val)) = line.split_once(':') else {
                    let _ = incoming.write_all(
                        b"HTTP/1.1 400 Bad Request (Malformed HTTP Header Line)\r\n\r\n",
                    );
                    let _ = incoming.shutdown(Shutdown::Both);
                    return;
                };
                if name.chars().any(char::is_whitespace) || name.is_empty() {
                    let _ = incoming.write_all(
                        b"HTTP/1.1 400 Bad Request (Invalid HTTP Header Name)\r\n\r\n",
                    );
                    let _ = incoming.shutdown(Shutdown::Both);
                    return;
                }
                let val = val.trim();
                if name.eq_ignore_ascii_case("host") {
                    host_values.push(val);
                } else if name.eq_ignore_ascii_case("content-length") {
                    content_length_values.push(val);
                } else if name.eq_ignore_ascii_case("transfer-encoding") {
                    has_transfer_encoding = true;
                    transfer_encoding_values.push(val);
                } else if name.eq_ignore_ascii_case("upgrade") && val.eq_ignore_ascii_case("websocket") {
                    upgrade_websocket = true;
                } else if name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("proxy-connection") {
                    if val.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")) {
                        connection_upgrade = true;
                    }
                    if val.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")) {
                        client_wants_close = true;
                    } else if val.split(',').any(|t| t.trim().eq_ignore_ascii_case("keep-alive")) {
                        client_wants_close = false;
                    }
                }
            }

            if host_values.len() > 1 {
                let _ = incoming.write_all(
                    b"HTTP/1.1 400 Bad Request (Duplicate Host Header)\r\n\r\n",
                );
                let _ = incoming.shutdown(Shutdown::Both);
                return;
            }

            let is_chunked = if has_transfer_encoding {
                if !content_length_values.is_empty() {
                    let _ = incoming.write_all(
                        b"HTTP/1.1 400 Bad Request (Conflicting Content-Length And Transfer-Encoding)\r\n\r\n",
                    );
                    let _ = incoming.shutdown(Shutdown::Both);
                    return;
                }
                if transfer_encoding_values.len() > 1 {
                    let _ = incoming.write_all(
                        b"HTTP/1.1 400 Bad Request (Multiple Transfer-Encoding Headers)\r\n\r\n",
                    );
                    let _ = incoming.shutdown(Shutdown::Both);
                    return;
                }
                let te_val = transfer_encoding_values[0].trim();
                if te_val.contains(',') || !te_val.eq_ignore_ascii_case("chunked") {
                    let _ = incoming.write_all(
                        b"HTTP/1.1 501 Not Implemented (Unsupported Transfer-Encoding)\r\n\r\n",
                    );
                    let _ = incoming.shutdown(Shutdown::Both);
                    return;
                }
                true
            } else {
                false
            };

            if content_length_values.len() > 1 {
                let _ = incoming.write_all(
                    b"HTTP/1.1 400 Bad Request (Duplicate Content-Length)\r\n\r\n",
                );
                let _ = incoming.shutdown(Shutdown::Both);
                return;
            }
            let content_length = if let Some(cl_raw) = content_length_values.first() {
                let Ok(cl) = cl_raw.parse::<usize>() else {
                    let _ = incoming.write_all(
                        b"HTTP/1.1 400 Bad Request (Invalid Content-Length)\r\n\r\n",
                    );
                    let _ = incoming.shutdown(Shutdown::Both);
                    return;
                };
                if cl > MAX_HTTP_BODY_BYTES {
                    let _ = incoming.write_all(
                        b"HTTP/1.1 413 Payload Too Large\r\n\r\n",
                    );
                    let _ = incoming.shutdown(Shutdown::Both);
                    return;
                }
                cl
            } else {
                0
            };

            let host_hdr = host_values.first().copied().unwrap_or("");
            let target_dest = if is_connect {
                let raw = parts[1].trim();
                if raw.is_empty()
                    || raw.contains('/')
                    || raw.chars().any(char::is_whitespace)
                    || raw.chars().any(char::is_control)
                {
                    let _ = incoming.write_all(
                        b"HTTP/1.1 400 Bad Request (Invalid CONNECT Authority)\r\n\r\n",
                    );
                    let _ = incoming.shutdown(Shutdown::Both);
                    return;
                }
                let authority = if raw.contains(':') {
                    raw.to_string()
                } else {
                    format!("{raw}:443")
                };
                if !host_hdr.is_empty() {
                    let norm_host = if host_hdr.contains(':') {
                        host_hdr.to_string()
                    } else {
                        format!("{host_hdr}:443")
                    };
                    if !norm_host.eq_ignore_ascii_case(&authority)
                        && !host_hdr.eq_ignore_ascii_case(raw)
                    {
                        let _ = incoming.write_all(
                            b"HTTP/1.1 400 Bad Request (CONNECT Authority And Host Mismatch)\r\n\r\n",
                        );
                        let _ = incoming.shutdown(Shutdown::Both);
                        return;
                    }
                }
                authority
            } else {
                let uri = parts[1].trim();
                if uri.starts_with("http://") || uri.starts_with("ws://") {
                    let Ok(parsed) = url::Url::parse(uri) else {
                        let _ = incoming.write_all(
                            b"HTTP/1.1 400 Bad Request (Invalid Proxy URI)\r\n\r\n",
                        );
                        let _ = incoming.shutdown(Shutdown::Both);
                        return;
                    };
                    let Some(host) = parsed.host_str().filter(|h| !h.is_empty()) else {
                        let _ = incoming.write_all(
                            b"HTTP/1.1 400 Bad Request (Missing URI Host)\r\n\r\n",
                        );
                        let _ = incoming.shutdown(Shutdown::Both);
                        return;
                    };
                    let port = parsed.port_or_known_default().unwrap_or(80);
                    let uri_authority = format!("{host}:{port}");
                    if !host_hdr.is_empty() {
                        let norm_hdr = if host_hdr.contains(':') {
                            host_hdr.to_string()
                        } else {
                            format!("{host_hdr}:{port}")
                        };
                        if !norm_hdr.eq_ignore_ascii_case(&uri_authority) {
                            let _ = incoming.write_all(
                                b"HTTP/1.1 400 Bad Request (URI And Host Header Mismatch)\r\n\r\n",
                            );
                            let _ = incoming.shutdown(Shutdown::Both);
                            return;
                        }
                    }
                    uri_authority
                } else if uri.starts_with('/') {
                    if host_hdr.is_empty()
                        || host_hdr.contains('/')
                        || host_hdr.chars().any(char::is_whitespace)
                    {
                        let _ = incoming.write_all(b"HTTP/1.1 400 Bad Request (Missing Host)\r\n\r\n");
                        let _ = incoming.shutdown(Shutdown::Both);
                        return;
                    }
                    if host_hdr.contains(':') {
                        host_hdr.to_string()
                    } else {
                        format!("{host_hdr}:80")
                    }
                } else {
                    let _ = incoming.write_all(
                        b"HTTP/1.1 400 Bad Request (Unsupported Proxy Target Scheme)\r\n\r\n",
                    );
                    let _ = incoming.shutdown(Shutdown::Both);
                    return;
                }
            };

            if let Some(ref prev_auth) = bound_keepalive_authority {
                if !prev_auth.eq_ignore_ascii_case(&target_dest) {
                    let _ = incoming.write_all(
                        b"HTTP/1.1 400 Bad Request (Host Switch Not Allowed On Keep-Alive Connection)\r\n\r\n",
                    );
                    let _ = incoming.shutdown(Shutdown::Both);
                    return;
                }
            } else {
                bound_keepalive_authority = Some(target_dest.clone());
            }

            let req_body = if is_chunked {
                match Self::read_chunked_http_body(&mut incoming, MAX_HTTP_BODY_BYTES) {
                    Ok(b) => b,
                    Err("too_large") => {
                        let _ = incoming.write_all(
                            b"HTTP/1.1 413 Payload Too Large\r\n\r\n",
                        );
                        let _ = incoming.shutdown(Shutdown::Both);
                        return;
                    }
                    Err(_) => {
                        let _ = incoming.write_all(
                            b"HTTP/1.1 400 Bad Request (Malformed Chunked Body)\r\n\r\n",
                        );
                        let _ = incoming.shutdown(Shutdown::Both);
                        return;
                    }
                }
            } else {
                let mut b = vec![0u8; content_length];
                if content_length > 0 && incoming.read_exact(&mut b).is_err() {
                    let _ = incoming.write_all(
                        b"HTTP/1.1 400 Bad Request (Incomplete Request Body)\r\n\r\n",
                    );
                    let _ = incoming.shutdown(Shutdown::Both);
                    return;
                }
                b
            };

            // Support both direct socket attribution (via kernel PROC_PIDFDSOCKETINFO / lsof) and
            // transparent proxy attribution from verified NetworkExtension with X-Watch identity headers.
            let mut resolved_identity = peer_addr.and_then(|peer| enf.resolve_peer_socket_identity(peer).ok());
            if resolved_identity.is_none() && authenticated_extension {
                let mut x_pid: Option<u32> = None;
                let mut x_uid: Option<u32> = None;
                let mut x_start: Option<u64> = None;
                let mut x_micros: Option<u32> = None;
                let mut x_audit_hex: Option<String> = None;
                for line in header.lines() {
                    let line = line.trim_end_matches('\r');
                    if let Some(v) = line.strip_prefix("X-Watch-PID:").or_else(|| line.strip_prefix("x-watch-pid:")) {
                        x_pid = v.trim().parse().ok();
                    } else if let Some(v) = line.strip_prefix("X-Watch-UID:").or_else(|| line.strip_prefix("x-watch-uid:")) {
                        x_uid = v.trim().parse().ok();
                    } else if let Some(v) = line.strip_prefix("X-Watch-Audit-Token:").or_else(|| line.strip_prefix("x-watch-audit-token:")) {
                        x_audit_hex = Some(v.trim().to_string());
                    } else if let Some(v) = line.strip_prefix("X-Watch-Start-Seconds:") {
                        x_start = v.trim().parse().ok();
                    } else if let Some(v) = line.strip_prefix("X-Watch-Start-Micros:") {
                        x_micros = v.trim().parse().ok();
                    }
                }
                if let (Some(pid), Some(uid)) = (x_pid, x_uid) {
                    if let Some(parsed_audit) = x_audit_hex.as_deref().and_then(parse_audit_token_hex) {
                        if parsed_audit[5] == pid && parsed_audit[1] == uid {
                            if let Ok(guard) = enf.lock() {
                                for (fam, st) in &guard.families {
                                    if let Some(cmd) = &st.command {
                                        for tok in &cmd.allowed_processes {
                                            if tok.pid == pid
                                                && tok.uid == uid
                                                && Some(tok.start_seconds) == x_start
                                                && Some(tok.start_microseconds) == x_micros
                                            {
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

            match enf.connect_supervised_tcp_to_with_handshake(
                &family,
                &proc_token,
                &target_dest,
                Some(is_connect),
                now,
            ) {
                Ok((_flow_id, mut tunnel_stream)) => {
                    let _ = incoming.set_read_timeout(None);
                    let _ = incoming.set_write_timeout(None);
                    let _ = tunnel_stream.set_read_timeout(None);
                    let _ = tunnel_stream.set_write_timeout(None);
                    if is_connect {
                        if incoming
                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .and_then(|_| incoming.flush())
                            .is_err()
                        {
                            let _ = incoming.shutdown(Shutdown::Both);
                            let _ = tunnel_stream.shutdown(Shutdown::Both);
                            return;
                        }
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
                        return;
                    } else if upgrade_websocket && connection_upgrade {
                        // This is an HTTP proxy, not a WebSocket endpoint: validate the HTTP
                        // upgrade boundary here; the client validates Sec-WebSocket-Accept
                        // against its key. WSS remains opaque TLS inside CONNECT.
                        if tunnel_stream
                            .write_all(&req_buf)
                            .and_then(|_| tunnel_stream.write_all(&req_body))
                            .and_then(|_| tunnel_stream.flush())
                            .is_err()
                        {
                            let _ = incoming.shutdown(Shutdown::Both);
                            let _ = tunnel_stream.shutdown(Shutdown::Both);
                            return;
                        }
                        let _ = tunnel_stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut resp_hdr = Vec::with_capacity(256);
                        let mut b = [0u8; 1];
                        while resp_hdr.len() < MAX_HTTP_HEADER_BYTES {
                            match tunnel_stream.read(&mut b) {
                                Ok(0) => break,
                                Ok(_) => {
                                    resp_hdr.push(b[0]);
                                    if resp_hdr.ends_with(b"\r\n\r\n") || resp_hdr.ends_with(b"\n\n") {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        let _ = tunnel_stream.set_read_timeout(None);
                        let is_terminated = resp_hdr.ends_with(b"\r\n\r\n") || resp_hdr.ends_with(b"\n\n");
                        if !is_terminated {
                            let _ = incoming.shutdown(Shutdown::Both);
                            let _ = tunnel_stream.shutdown(Shutdown::Both);
                            return;
                        }
                        let resp_line = String::from_utf8_lossy(&resp_hdr);
                        let mut lines = resp_line.lines();
                        let mut proto_ok = false;
                        let mut code_ok = false;
                        if let Some(status_line) = lines.next() {
                            let mut status_parts = status_line.trim().split_whitespace();
                            proto_ok = status_parts.next().is_some_and(|p| p == "HTTP/1.1");
                            code_ok = status_parts.next().is_some_and(|c| c == "101");
                        }
                        let mut has_exact_upgrade_ws = false;
                        let mut has_connection_upgrade = false;
                        for l in lines {
                            let l = l.trim();
                            if l.is_empty() {
                                break;
                            }
                            if let Some((k, v)) = l.split_once(':') {
                                let k = k.trim();
                                let v = v.trim();
                                if k.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket") {
                                    has_exact_upgrade_ws = true;
                                } else if k.eq_ignore_ascii_case("connection") {
                                    if v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")) {
                                        has_connection_upgrade = true;
                                    }
                                }
                            }
                        }
                        if !proto_ok || !code_ok || !has_exact_upgrade_ws || !has_connection_upgrade {
                            let _ = incoming.write_all(&resp_hdr);
                            let _ = incoming.shutdown(Shutdown::Both);
                            let _ = tunnel_stream.shutdown(Shutdown::Both);
                            return;
                        }
                        if incoming.write_all(&resp_hdr).and_then(|_| incoming.flush()).is_err() {
                            let _ = incoming.shutdown(Shutdown::Both);
                            let _ = tunnel_stream.shutdown(Shutdown::Both);
                            return;
                        }
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
                        return;
                    } else {
                        // Ordinary HTTP request (`GET`, `POST`, etc.): rewrite Connection: close
                        // on the upstream hop so the upstream proxy closes after the single HTTP
                        // response, preventing raw stream smuggling while allowing the next request
                        // on `incoming` to be parsed and validated per-request (`R4.2`).
                        let mut rewritten_req = String::new();
                        rewritten_req.push_str(first_line);
                        rewritten_req.push_str("\r\n");
                        for raw_line in header.lines().skip(1) {
                            let line = raw_line.trim_end_matches('\r');
                            if line.is_empty() {
                                break;
                            }
                            if let Some((name, _)) = line.split_once(':') {
                                if name.eq_ignore_ascii_case("connection")
                                    || name.eq_ignore_ascii_case("proxy-connection")
                                {
                                    continue;
                                }
                            }
                            rewritten_req.push_str(line);
                            rewritten_req.push_str("\r\n");
                        }
                        rewritten_req.push_str("Connection: close\r\nProxy-Connection: close\r\n\r\n");
                        if tunnel_stream
                            .write_all(rewritten_req.as_bytes())
                            .and_then(|_| tunnel_stream.write_all(&req_body))
                            .and_then(|_| tunnel_stream.flush())
                            .is_err()
                        {
                            let _ = incoming.shutdown(Shutdown::Both);
                            let _ = tunnel_stream.shutdown(Shutdown::Both);
                            return;
                        }
                        let _ = std::io::copy(&mut tunnel_stream, &mut incoming);
                        let _ = incoming.flush();
                        let _ = tunnel_stream.shutdown(Shutdown::Both);
                        if client_wants_close {
                            let _ = incoming.shutdown(Shutdown::Both);
                            return;
                        }
                    }
                }
                Err(_) => {
                    let _ = incoming.write_all(
                        b"HTTP/1.1 502 Bad Gateway (Channel Or Upstream Blocked)\r\n\r\n",
                    );
                    let _ = incoming.shutdown(Shutdown::Both);
                    return;
                }
            }
        }
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
        let started = std::time::Instant::now();
        let output = probe_fn(&upstream_endpoint)?;
        let observed_at = now + started.elapsed().as_secs_f64();
        let (evidence_family, backend, vpn_epoch, executor_boot_id) = {
            let guard = self.lock()?;
            let unchanged = guard.interception_active && guard.direct_fallback_blocked && guard.upstream_healthy
                && guard.families.get(family).and_then(|s| s.command.as_ref()).is_some_and(|c|
                    c.policy_version == policy_version && c.upstream_endpoint == upstream_endpoint);
            if !unchanged { return Err(CoreError::new("diagnostic_path_changed", "探针期间策略或受控通道变化，结果作废")); }
            let cmd = guard
                .families
                .get(family)
                .and_then(|s| s.command.as_ref())
                .ok_or_else(|| CoreError::new("channel_command_missing", "通道尚未接收控制命令"))?;
            let fam = if guard.families.values().filter_map(|s| s.command.as_ref()).all(|c|
                c.policy_version == policy_version && c.upstream_endpoint == upstream_endpoint) { "*" } else { family };
            (
                fam,
                cmd.permit.backend,
                cmd.permit.vpn_epoch.clone(),
                Some(guard.boot_id.clone()),
            )
        };
        let evidence = ControlledPathEvidence {
            family: evidence_family.into(),
            upstream_endpoint,
            policy_version,
            context_id: context_id.into(),
            via_controlled_path: true,
            observed_at,
            backend,
            vpn_epoch,
            executor_boot_id,
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
        self.connect_supervised_tcp_to_with_handshake(
            family,
            process,
            target_destination,
            None,
            now,
        )
    }

    pub fn connect_supervised_tcp_to_with_handshake(
        &self,
        family: &str,
        process: &BoundProcessToken,
        target_destination: &str,
        handshake_override: Option<bool>,
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
            dial_vpn_epoch,
            upstream_endpoint,
            upstream_connector,
            require_connect_handshake,
            on_dial_hook,
            defer_confirm,
        ) = {
            let mut guard = self.lock()?;
            if guard.strict_peer_verification
                && !guard.backend.is_sandbox()
                && Self::build_receipt_locked(&guard, family, now)?.enforcement_state
                    != ChannelEnforcementState::Forwarding
            {
                return Err(CoreError::new("extension_permit_unconfirmed", "系统扩展尚未确认当前许可，连接保持阻断"));
            }
            let defer_confirm = guard.defer_auto_flow_confirm;
            let upstream_connector = guard.upstream_connector.clone();
            let require_connect_handshake =
                handshake_override.unwrap_or(guard.require_upstream_connect_handshake);
            let on_dial_hook = guard.on_dial_hook.clone();
            let interception_active = guard.interception_active;
            let direct_fallback_blocked = guard.direct_fallback_blocked;
            let upstream_healthy = guard.upstream_healthy;
            let last_wall = guard.last_wall_now;
            let strict = guard.strict_peer_verification;
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
            if !Self::is_process_attributed(&cmd, process, strict) {
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
                || state.local_revoke_reason.is_some()
                || state.enforcement_state != ChannelEnforcementState::Forwarding
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
                cmd.permit.vpn_epoch.clone(),
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
            (TunnelStream::Tcp(s), require_connect_handshake)
        };

        // Clients already configured for TAG speak CONNECT themselves. Their
        // intercepted connection still belongs to this managed relay; avoid
        // asking TAG to tunnel back to its own proxy port.
        let is_explicit_proxy_connection = {
            let url = if upstream_endpoint.contains("://") { upstream_endpoint.clone() } else { format!("http://{upstream_endpoint}") };
            url::Url::parse(&url).ok().is_some_and(|u| {
                u.host_str().zip(u.port_or_known_default()).is_some_and(|(host, port)|
                    target_destination == format!("{host}:{port}"))
            })
        };
        if perform_handshake && !is_explicit_proxy_connection {
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
            let interception_ok = guard.interception_active && guard.direct_fallback_blocked
                && (!guard.strict_peer_verification || guard.backend.is_sandbox() || Self::build_receipt_locked(&guard, family, post_dial_now)
                    .is_ok_and(|r| r.enforcement_state == ChannelEnforcementState::Forwarding));
            let upstream_ok = guard.upstream_healthy;
            let last_wall = guard.last_wall_now;
            let strict = guard.strict_peer_verification;

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
            let (post_eff_state, post_reason) = cmd.permit.effective_state_with_vpn_epoch(
                post_dial_now,
                last_wall,
                false,
                &active_policy,
                dial_vpn_epoch.as_ref(),
            );
            let dial_invariant_ok = interception_ok
                && upstream_ok
                && state.enforcement_state == ChannelEnforcementState::Forwarding
                && post_eff_state == ChannelPermitState::Permitted
                && cmd.session_id == dial_session_id
                && cmd.permit_generation == dial_permit_generation
                && cmd.policy_version == dial_policy_version
                && active_policy == dial_policy_version
                && cmd.permit.vpn_epoch == dial_vpn_epoch
                && cmd.upstream_endpoint == upstream_endpoint
                && Self::is_process_attributed(&cmd, process, strict);

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
        let publication_done = self.receipt_publication.clone();
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
                let maybe_receipt = if let Ok(mut guard) = inner_done.lock() {
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
                    r
                } else {
                    None
                };
                if let Some(receipt) = maybe_receipt {
                    let _ = Self::publish_current_receipt_shared(
                        &inner_done, &publication_done, storage_done.as_ref(), &receipt,
                    );
                }
            }
        });

        Ok(())
    }

    fn begin_autonomous_revoke_locked(guard: &mut EnforcerInner, family: &str, reason: &str, now: f64) -> Vec<String> {
        if let Some(state) = guard.families.get_mut(family) {
            state.requires_supervisor_revocation = true;
        }
        Self::begin_revoke_locked(guard, family, reason, now)
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
        // The executor may tighten enforcement but cannot rewrite the
        // supervisor's versioned command under an unchanged sequence.
        state.local_revoke_reason = Some(reason.into());
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

    fn matching_extension_receipt<'a>(
        guard: &'a EnforcerInner, family: &str, now: f64,
    ) -> Option<&'a claude_watch_core::channel::SystemExtensionReceipt> {
        let cmd = guard.families.get(family)?.command.as_ref()?;
        let live = guard.extension_heartbeat.as_ref().filter(|h| h.is_live(&guard.boot_id, now))?;
        guard.extension_receipts.get(family).filter(|r|
            r.matches_supervision(&cmd.policy_version, cmd.command_seq, cmd.permit_generation,
                &guard.boot_id, &live.extension_boot_id, cmd.issued_at, now)
                && r.allowed_pids.iter().copied().collect::<BTreeSet<_>>()
                    == cmd.allowed_processes.iter().map(|p| p.pid).collect::<BTreeSet<_>>()
                && crate::channel_extension::command_binding(cmd).as_ref() == Some(&r.command_binding))
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
        let mut receipt = ChannelEnforcementReceipt {
            family: family.into(),
            session_id: cmd.session_id.clone(),
            policy_version: cmd.policy_version.clone(),
            permit_generation: state.last_permit_generation,
            command_seq: state.last_command_seq,
            executor_boot_id: guard.boot_id.clone(),
            permit_state: if state.local_revoke_reason.is_some() { ChannelPermitState::Revoked } else { cmd.permit.state },
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
                .or_else(|| state.local_revoke_reason.clone())
                .or_else(|| {
                    if cmd.permit.state == ChannelPermitState::Revoked
                        && !cmd.permit.reason_code.is_empty()
                    {
                        Some(cmd.permit.reason_code.clone())
                    } else {
                        guard.activation_error_code.clone()
                    }
                }),
            backend: cmd.permit.backend,
            vpn_epoch: cmd.permit.vpn_epoch.clone(),
            coverage_scope: cmd.permit.coverage_scope.clone(),
            sandbox_ready: guard.sandbox_ready,
        };
        if cmd.permit.backend.is_sandbox() || guard.backend.is_sandbox() {
            receipt.backend = NetworkBackendKind::Seatbelt;
            receipt.system_extension_active = false;
            receipt.sandbox_ready = guard.sandbox_ready;
            receipt.interception_active = guard.sandbox_ready && guard.local_proxy_ready;
            receipt.direct_fallback_blocked = guard.sandbox_ready;
            if !receipt.interception_active || !receipt.direct_fallback_blocked {
                receipt.enforcement_state = ChannelEnforcementState::Failed;
                receipt.new_connections_blocked = false;
                if receipt.error_code.is_none() {
                    receipt.error_code = Some(
                        if !guard.sandbox_ready {
                            "sandbox_backend_not_ready"
                        } else {
                            "local_proxy_not_ready"
                        }
                        .into(),
                    );
                }
            }
        } else if guard.strict_peer_verification {
            let live = guard.extension_heartbeat.as_ref().filter(|h| h.is_live(&guard.boot_id, now));
            let extension = Self::matching_extension_receipt(guard, family, now);
            receipt.system_extension_active = live.is_some();
            receipt.interception_active = live.is_some() && guard.local_proxy_ready;
            receipt.direct_fallback_blocked = live.is_some();
            // Rust closes its relay, the extension closes the application's flow.
            // Neither half alone is a successful isolation receipt.
            match extension {
                Some(ext) if ext.status == "failed" => {
                    receipt.enforcement_state = ChannelEnforcementState::Failed;
                    receipt.error_code = Some(ext.reason.clone().unwrap_or_else(|| "extension_execution_failed".into()));
                    receipt.active_flows_closed = false;
                }
                Some(ext) => {
                    receipt.active_flows_count = receipt.active_flows_count.max(ext.active_flows.min(u32::MAX as usize) as u32);
                    receipt.new_connections_blocked &= ext.new_connections_blocked;
                    receipt.active_flows_closed &= ext.is_confirmed_revoked();
                    if receipt.permit_state == ChannelPermitState::Permitted {
                        if ext.status != "ok" || ext.permit_state != "permitted" {
                            receipt.enforcement_state = ChannelEnforcementState::Failed;
                            receipt.error_code = Some("extension_permit_not_applied".into());
                        }
                    } else if ext.is_disconnecting() || !receipt.active_flows_closed {
                        receipt.enforcement_state = ChannelEnforcementState::Disconnecting;
                    } else if receipt.new_connections_blocked && receipt.interception_active {
                        receipt.enforcement_state = ChannelEnforcementState::Blocked;
                    }
                }
                None => {
                    receipt.enforcement_state = ChannelEnforcementState::Failed;
                    receipt.new_connections_blocked = false;
                    receipt.active_flows_closed = false;
                    receipt.error_code = Some(if live.is_some() { "extension_receipt_pending_or_invalid" } else { "system_extension_liveness_unconfirmed" }.into());
                }
            }
        }
        Ok(receipt)
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

    fn publish_current_receipt(&self, prior: &ChannelEnforcementReceipt) -> Result<ChannelEnforcementReceipt> {
        Self::publish_current_receipt_shared(&self.inner, &self.receipt_publication, self.storage.as_ref(), prior)
    }

    fn publish_current_receipt_shared(
        inner: &Arc<Mutex<EnforcerInner>>,
        publication: &Arc<Mutex<ReceiptPublication>>,
        storage: Option<&StateStore>,
        prior: &ChannelEnforcementReceipt,
    ) -> Result<ChannelEnforcementReceipt> {
        // A watchdog snapshot can become stale before it reaches disk or its
        // callback: the relay may already have confirmed actual socket closure.
        // Serialize publication and re-read authority inside that ordering.
        // Never hold the authority lock while doing I/O or calling a sink.
        let (receipt, persisted, dispatch) = {
            let mut publisher = publication.lock().map_err(|_| CoreError::new(
                "receipt_publication_poisoned", "通道回执发布锁不可用"))?;
            let (receipt, sink) = {
                let guard = inner.lock().map_err(|_| CoreError::new(
                    "enforcer_poisoned", "通道执行器状态锁不可用"))?;
                // A real clock sample must stay truthful even if it moved
                // backwards; consumers must see and reject that condition.
                // Clockless fixtures retain their caller-driven timeline.
                let now = guard.clock.as_ref().map(|clock| clock()).unwrap_or_else(||
                    prior.observed_at.max(guard.families.get(&prior.family)
                        .map(|s| s.last_updated_at).unwrap_or(prior.observed_at)));
                (Self::build_receipt_locked(&guard, &prior.family, now)?, guard.receipt_sink.clone())
            };
            let persisted = if let Some(store) = storage { store.atomic_json(
                &store
                    .paths
                    .watch()
                    .join(format!("state/channel-receipt-{}.json", receipt.family)),
                &json!(receipt),
            ) } else { Ok(()) };
            if let Some(sink) = sink { publisher.pending.push_back((receipt.clone(), sink)); }
            let dispatch = !publisher.dispatching && !publisher.pending.is_empty();
            if dispatch { publisher.dispatching = true; }
            (receipt, persisted, dispatch)
        };
        if dispatch {
            loop {
                let next = {
                    let mut publisher = publication.lock().map_err(|_| CoreError::new(
                        "receipt_publication_poisoned", "通道回执发布锁不可用"))?;
                    match publisher.pending.pop_front() {
                        Some(item) => Some(item),
                        None => { publisher.dispatching = false; None }
                    }
                };
                let Some((event, sink)) = next else { break };
                // Dispatch in order outside both locks. Reentrant callbacks
                // may read or mutate the enforcer and enqueue the next event.
                sink(event);
            }
        }
        persisted?;
        Ok(receipt)
    }

    fn command_content_matches(
        a: &ChannelEnforcementCommand,
        b: &ChannelEnforcementCommand,
    ) -> bool {
        a == b
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
        let backend_ready = if guard.backend.is_sandbox() {
            guard.sandbox_ready
        } else {
            guard.system_extension_active
        };
        Ok(guard.interception_active
            && guard.direct_fallback_blocked
            && backend_ready
            && guard.local_proxy_ready
            && guard.upstream_healthy)
    }

    fn apply_command(
        &self,
        command: &ChannelEnforcementCommand,
        now: f64,
    ) -> Result<ChannelEnforcementReceipt> {
        if !command.policy_version.valid() || !command.permit.policy_version.valid() {
            return Err(CoreError::new(
                "invalid_policy_version",
                "拒绝策略版本摘要无效的通道命令",
            ));
        }
        if command.policy_version != command.permit.policy_version {
            return Err(CoreError::new(
                "policy_version_envelope_mismatch",
                "命令策略版本与许可策略版本不一致，已拒绝",
            ));
        }
        let receipt = {
            let mut guard = self.lock()?;

            // Validate target executor boot_id (`I04`) at the command receiving boundary!
            if let Some(ref target_boot) = command.target_executor_boot_id {
                if target_boot.trim().is_empty() || target_boot != &guard.boot_id {
                    return Err(CoreError::new(
                        "executor_boot_id_mismatch",
                        "拒绝目标执行器 boot_id 不匹配的旧实例或重放命令",
                    ));
                }
            } else if guard.strict_peer_verification {
                return Err(CoreError::new(
                    "executor_boot_id_missing",
                    "生产模式通道命令必须绑定目标执行器 boot_id",
                ));
            }

            // Validate generation, sequence, session, and per-family policy
            // BEFORE modifying `last_wall_now`, `current_policy`, or family state!
            if let Some(existing) = guard.families.get(&command.family) {
                if command.permit_generation < existing.last_permit_generation
                    || command.command_seq < existing.last_command_seq
                    || (command.permit_generation > existing.last_permit_generation
                        && command.command_seq == existing.last_command_seq)
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
                        Self::begin_autonomous_revoke_locked(&mut guard, &fam, "clock_rollback_detected", now);
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
                if command.permit.state == ChannelPermitState::Revoked {
                    state.requires_supervisor_revocation = false;
                }
                if !state.requires_supervisor_revocation { state.local_revoke_reason = None; }
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
            } else if guard.families.get(&command.family).is_some_and(|s| s.requires_supervisor_revocation) {
                let reason = guard.families[&command.family].local_revoke_reason.clone()
                    .unwrap_or_else(|| "executor_autonomous_cutoff".into());
                Self::begin_revoke_locked(&mut guard, &command.family, &reason, now);
            } else if !upstream_healthy {
                Self::begin_autonomous_revoke_locked(
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
            Self::build_receipt_locked(&guard, &command.family, now)?
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
        self.publish_extension_commands()?;
        let receipt = self.publish_current_receipt(&receipt)?;
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
        let updated = {
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
                        && (state.local_revoke_reason.is_none()
                            || state.enforcement_state == ChannelEnforcementState::Forwarding
                            || !state.active_flows.is_empty())
                    {
                        Some(reason)
                    } else {
                        None
                    }
                });
                if let Some(reason) = should_revoke {
                    Self::begin_autonomous_revoke_locked(&mut guard, &family, reason, now);
                    updated.push(Self::build_receipt_locked(&guard, &family, now)?);
                }
            }
            updated
        };
        updated.iter().map(|r| self.publish_current_receipt(r)).collect()
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

#[cfg(test)]
mod control_rpc_contracts {
    use super::*;

    fn publication_command() -> ChannelEnforcementCommand {
        use claude_watch_core::channel::ChannelPermit;
        let policy = PolicyVersion { policy_digest: "publication".into(), guard_policy_digest: "publication-guard".into() };
        ChannelEnforcementCommand {
            family: "claude".into(), session_id: Some("publication-session".into()),
            policy_version: policy.clone(), permit_generation: 1, command_seq: 1,
            target_executor_boot_id: Some("publication-boot".into()),
            upstream_endpoint: "127.0.0.1:17890".into(), issued_at: 100.,
            allowed_processes: vec![BoundProcessToken::with_system_identity(1234, 501, 50, 1, ProcessRole::Cli)
                .with_audit_token([501, 501, 20, 501, 20, 1234, 0, 9])],
            permit: ChannelPermit {
                family: "claude".into(), session_id: Some("publication-session".into()),
                policy_version: policy, permit_generation: 1, command_seq: 1,
                state: ChannelPermitState::Permitted, reason_code: "fixture".into(),
                issued_at: 100., valid_until: 200., context_id: Some("fixture".into()),
                baseline_ip: Some("1.1.1.1".into()), members: vec![],
                backend: NetworkBackendKind::NetworkExtension, vpn_epoch: None, coverage_scope: None,
            },
        }
    }

    #[test]
    fn delayed_disconnect_publication_cannot_overwrite_confirmed_socket_closure() {
        use crate::storage::Paths;
        use std::sync::mpsc;
        let dir = std::env::temp_dir().join(format!("cw-publication-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let store = StateStore::new(Paths::new(&dir).unwrap());
        let enforcer = Arc::new(LocalTunnelEnforcer::new("publication-boot", Some(store.clone())));
        enforcer.activate_interception(100.).unwrap();
        enforcer.set_defer_auto_flow_confirm(true).unwrap();
        enforcer.set_clock(|| 101.).unwrap();
        let (event_tx, event_rx) = mpsc::channel();
        enforcer.set_receipt_event_sink(move |r| { event_tx.send(r).unwrap(); }).unwrap();
        let (upstream, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let upstream = Mutex::new(Some(upstream));
        enforcer.set_upstream_connector(move |_| Ok(TunnelStream::Unix(upstream.lock().unwrap().take().unwrap()))).unwrap();
        let command = publication_command();
        enforcer.apply_command(&command, 100.).unwrap();
        let (flow, mut client) = enforcer.connect_supervised_tcp("claude", &command.allowed_processes[0], 101.).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        client.write_all(b"p").unwrap();
        let mut byte = [0];
        peer.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [b'p']);
        let old = enforcer.revoke_family("claude", "fixture_cutoff", 101.).unwrap().unwrap();
        assert_eq!(old.enforcement_state, ChannelEnforcementState::Disconnecting);
        assert_eq!(old.active_flows_count, 1);
        assert!(!old.active_flows_closed);
        assert_eq!(client.read(&mut byte).unwrap(), 0, "real client must reach EOF before closure confirmation");
        assert_eq!(peer.read(&mut byte).unwrap(), 0, "real upstream must reach EOF too");

        let (release_tx, release_rx) = mpsc::channel();
        let late_enforcer = enforcer.clone();
        let delayed = thread::spawn(move || {
            release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            late_enforcer.publish_current_receipt(&old).unwrap()
        });
        let confirmed = enforcer.confirm_flow_terminated("claude", &flow, 101.).unwrap().unwrap();
        assert!(confirmed.active_flows_closed);
        release_tx.send(()).unwrap();
        let late = delayed.join().unwrap();
        assert_eq!(late.enforcement_state, ChannelEnforcementState::Blocked);
        assert!(late.active_flows_closed);
        let events: Vec<_> = event_rx.try_iter().collect();
        let terminal = events.iter().position(|r| r.enforcement_state == ChannelEnforcementState::Blocked).unwrap();
        assert!(events[terminal..].iter().all(|r| r.active_flows_closed && r.active_flows_count == 0));
        let persisted = store.read_json(&store.paths.watch().join("state/channel-receipt-claude.json"), json!(null)).unwrap();
        assert_eq!(persisted["active_flows_closed"], true);
        assert_eq!(persisted["active_flows_count"], 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn receipt_callback_can_reenter_without_deadlock_or_notification_reordering() {
        use std::sync::mpsc;
        let enforcer = Arc::new(LocalTunnelEnforcer::new("publication-boot", None));
        enforcer.activate_interception(100.).unwrap();
        let weak = Arc::downgrade(&enforcer);
        let first = AtomicBool::new(true);
        let (event_tx, event_rx) = mpsc::channel();
        enforcer.set_receipt_event_sink(move |receipt| {
            event_tx.send(receipt).unwrap();
            let enforcer = weak.upgrade().unwrap();
            assert!(enforcer.receipt_for("claude", 101.).unwrap().is_some());
            if first.swap(false, Ordering::AcqRel) {
                enforcer.revoke_family("claude", "reentrant_fixture", 101.).unwrap();
            }
        }).unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || { done_tx.send(enforcer.apply_command(&publication_command(), 100.)).unwrap(); });
        done_rx.recv_timeout(Duration::from_secs(2)).expect("sink mutation must not deadlock publication").unwrap();
        worker.join().unwrap();
        let events: Vec<_> = event_rx.try_iter().collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].enforcement_state, ChannelEnforcementState::Forwarding);
        assert_eq!(events[1].enforcement_state, ChannelEnforcementState::Blocked);
    }

    #[test]
    fn receipt_publication_reports_the_real_clock_even_when_it_moves_backwards() {
        let enforcer = LocalTunnelEnforcer::new("publication-boot", None);
        enforcer.activate_interception(100.).unwrap();
        let old = enforcer.apply_command(&publication_command(), 100.).unwrap();
        enforcer.set_clock(|| 90.).unwrap();
        let published = enforcer.publish_current_receipt(&old).unwrap();
        assert_eq!(published.observed_at, 90., "a queued receipt cannot conceal clock rollback with max(old_time)");
    }

    #[test]
    fn chunked_body_bounds_framing_checks_overflow_and_leaves_the_next_request_unread() {
        use std::io::Cursor;
        let body = b"4;note=ok\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Fixture: yes\r\n\r\n";
        let mut wire = body.to_vec();
        wire.extend_from_slice(b"GET /next HTTP/1.1\r\n\r\n");
        let mut source = Cursor::new(wire);
        assert_eq!(
            LocalTunnelEnforcer::read_chunked_http_body(&mut source, 9).unwrap(),
            body
        );
        assert_eq!(source.position() as usize, body.len());
        let overflow = format!("1\r\nx\r\n{:x}\r\n", usize::MAX);
        assert_eq!(
            LocalTunnelEnforcer::read_chunked_http_body(&mut Cursor::new(overflow), 16 * 1024 * 1024),
            Err("too_large")
        );
        let mut metadata = Vec::new();
        for _ in 0..70 {
            metadata.extend_from_slice(format!("1;note={}\r\nx\r\n", "a".repeat(1000)).as_bytes());
        }
        metadata.extend_from_slice(b"0\r\n\r\n");
        assert_eq!(
            LocalTunnelEnforcer::read_chunked_http_body(&mut Cursor::new(metadata), 16 * 1024 * 1024),
            Err("too_large")
        );
        let unterminated = format!("0\r\n{}", "a".repeat(4096));
        assert_eq!(
            LocalTunnelEnforcer::read_chunked_http_body(&mut Cursor::new(unterminated), 100),
            Err("trailer_too_long_or_unterminated")
        );
        for invalid in [
            b"+1\r\nx\r\n0\r\n\r\n".as_slice(),
            b"0\r\nContent-Length: 7\r\n\r\n",
            b"0\r\nnot-a-field\r\n\r\n",
        ] {
            assert!(
                LocalTunnelEnforcer::read_chunked_http_body(&mut Cursor::new(invalid), 100).is_err()
            );
        }
    }

    #[test]
    fn control_rpc_requires_authentication_and_returns_a_fresh_bound_memory_snapshot() {
        fn exchange(authenticated: bool, nonce: &str) -> Vec<u8> {
            let enforcer = Arc::new(LocalTunnelEnforcer::new("live-boot", None));
            enforcer.set_strict_peer_verification(true);
            let (mut client, server) = UnixStream::pair().unwrap();
            client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            // Fixture exercises the transport AFTER the OS authentication
            // decision; it does not claim a genuine signed extension login.
            let worker = thread::spawn(move || LocalTunnelEnforcer::serve_gateway_connection(
                enforcer, TunnelStream::Unix(server), None, authenticated));
            client.write_all(format!("WATCH-CONTROL {nonce} HTTP/1.1\r\n\r\n").as_bytes()).unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).unwrap();
            worker.join().unwrap();
            response
        }
        let nonce = uuid::Uuid::new_v4().to_string();
        let bytes = exchange(true, &nonce);
        let size = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        assert_eq!(size, bytes.len() - 4);
        let value: serde_json::Value = serde_json::from_slice(&bytes[4..]).unwrap();
        assert_eq!(value["nonce"], nonce);
        assert_eq!(value["envelope"]["executor_boot_id"], "live-boot");
        assert!(exchange(false, &nonce).starts_with(b"HTTP/1.1 403"));
        assert!(exchange(true, "invalid").is_empty());
    }
}
