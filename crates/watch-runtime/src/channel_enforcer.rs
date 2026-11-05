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
        ChannelEnforcementState, ChannelPermitState, PolicyVersion,
    },
    error::{CoreError, Result},
    processes::ProcessRole,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

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

struct EnforcerInner {
    boot_id: String,
    interception_active: bool,
    direct_fallback_blocked: bool,
    upstream_healthy: bool,
    defer_auto_flow_confirm: bool,
    disconnect_timeout_seconds: f64,
    upstream_connector: Option<UpstreamConnector>,
    on_dial_hook: Option<OnDialHook>,
    local_listener_addr: Option<String>,
    last_wall_now: Option<f64>,
    current_policy: Option<PolicyVersion>,
    families: BTreeMap<String, FamilyEnforcerState>,
    traces: Vec<ConnectionTraceEvent>,
    next_trace_seq: u64,
}

pub struct LocalTunnelEnforcer {
    inner: Arc<Mutex<EnforcerInner>>,
    next_flow_id: Arc<AtomicU64>,
    storage: Option<StateStore>,
}

impl LocalTunnelEnforcer {
    /// Creates an enforcer instance.
    ///
    /// Critical invariant (Requirement 2): `interception_active` and
    /// `direct_fallback_blocked` start as `false` and are NEVER defaulted to
    /// `true` at construction! They only become `true` when interception is
    /// explicitly activated via `activate_interception()` or
    /// `start_local_proxy_listener()`.
    pub fn new(boot_id: impl Into<String>, storage: Option<StateStore>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(EnforcerInner {
                boot_id: boot_id.into(),
                interception_active: false,
                direct_fallback_blocked: false,
                upstream_healthy: true,
                defer_auto_flow_confirm: false,
                disconnect_timeout_seconds: DEFAULT_DISCONNECT_TIMEOUT_SECONDS,
                upstream_connector: None,
                on_dial_hook: None,
                local_listener_addr: None,
                last_wall_now: None,
                current_policy: None,
                families: BTreeMap::new(),
                traces: Vec::new(),
                next_trace_seq: 1,
            })),
            next_flow_id: Arc::new(AtomicU64::new(1)),
            storage,
        }
    }

    /// Activates local tunnel interception and direct-fallback blocking,
    /// returning the active `executor_boot_id` for supervisor handshake.
    pub fn activate_interception(&self, now: f64) -> Result<String> {
        let mut guard = self.lock()?;
        guard.interception_active = true;
        guard.direct_fallback_blocked = true;
        guard.last_wall_now = Some(now);
        Ok(guard.boot_id.clone())
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

    pub fn set_on_dial_hook<F>(&self, hook: F) -> Result<()>
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        let mut guard = self.lock()?;
        guard.on_dial_hook = Some(Arc::new(hook));
        Ok(())
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
        let mut guard = self.lock()?;
        guard.upstream_healthy = false;
        let families: Vec<String> = guard.families.keys().cloned().collect();
        let mut closing_flows = Vec::new();
        for family in families {
            let ids = Self::begin_revoke_locked(&mut guard, &family, "tag_upstream_unhealthy", now);
            closing_flows.extend(ids);
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
        self.persist_receipt(&receipt)?;
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
        self.persist_receipt(&receipt)?;
        Ok(Some(receipt))
    }

    /// Checks whether any flow in `Disconnecting` state has exceeded the
    /// disconnect timeout without confirmation, transitioning the family to
    /// `Failed` (`flow_termination_timeout`).
    pub fn check_disconnect_timeouts(&self, now: f64) -> Result<Vec<ChannelEnforcementReceipt>> {
        let mut timed_out_receipts = Vec::new();
        {
            let mut guard = self.lock()?;
            let timeout = guard.disconnect_timeout_seconds;
            let families: Vec<String> = guard.families.keys().cloned().collect();
            for family in families {
                let expired = guard
                    .families
                    .get(&family)
                    .is_some_and(|state| {
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
        }
        for r in &timed_out_receipts {
            self.persist_receipt(r)?;
        }
        Ok(timed_out_receipts)
    }

    /// Establishes a real TCP connection from a supervised process through this
    /// enforcer to the family's configured upstream endpoint.
    ///
    /// Verifies:
    /// 1. The connecting process (`process`) matches an authorized member or
    ///    helper/child in `allowed_processes` for `family`.
    /// 2. The family's permit is currently `Permitted` under `current_policy`
    ///    and has not reached `valid_until` (`now < valid_until`).
    /// 3. Interception and the upstream tunnel are healthy.
    ///
    /// Returns `(flow_id, client_side_stream)` when permitted and connected to
    /// upstream. When blocked/revoked/pending, interception still claims the
    /// attempt and immediately aborts it (`Err`), never falling back to direct.
    fn is_process_attributed(cmd: &ChannelEnforcementCommand, process: &BoundProcessToken) -> bool {
        cmd.allowed_processes.iter().any(|allowed| {
            allowed.matches_process(
                process.pid,
                process.uid,
                process.start_seconds,
                process.start_microseconds,
                process.audit_token.as_ref(),
            )
        }) || cmd.permit.members.iter().any(|member| {
            member.pid == process.pid
                && member.start_seconds == process.start_seconds
                && member.start_microseconds == process.start_microseconds
        })
    }

    /// Starts a real local TCP proxy listener for supervised application channels.
    ///
    /// Protocol coverage boundaries:
    /// - `LocalTunnelEnforcer` (local TCP listener / socket relay): covers TCP
    ///   (IPv4/IPv6 target endpoints via HTTP CONNECT or stream relay).
    /// - `NetworkChannelFlowGate` (`NETransparentProxyProvider` +
    ///   `NEFilterDataProvider`): covers TCP, UDP/QUIC, IPv4, IPv6, and DNS
    ///   (53/853) flows at the macOS NetworkExtension layer once signed and
    ///   activated on a host machine.
    pub fn start_local_proxy_listener(
        self: &Arc<Self>,
        bind_addr: &str,
        stop: Arc<AtomicBool>,
        now: f64,
    ) -> Result<(SocketAddr, thread::JoinHandle<()>)> {
        let listener = TcpListener::bind(bind_addr)
            .map_err(|_| CoreError::new("enforcer_listener_bind_failed", "受控通道监听绑定失败"))?;
        let _ = listener.set_nonblocking(true);
        let addr = listener
            .local_addr()
            .map_err(|_| CoreError::new("enforcer_listener_addr_failed", "受控通道监听地址不可读"))?;
        {
            let mut guard = self.lock()?;
            guard.interception_active = true;
            guard.direct_fallback_blocked = true;
            guard.local_listener_addr = Some(addr.to_string());
            guard.last_wall_now = Some(now);
        }
        let enforcer = Arc::clone(self);
        let handle = thread::Builder::new()
            .name("channel-local-proxy-listener".into())
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut incoming, _)) => {
                            let enf = Arc::clone(&enforcer);
                            thread::spawn(move || {
                                let _ = incoming.set_read_timeout(Some(Duration::from_secs(2)));
                                let mut header_buf = [0u8; 512];
                                let Ok(n) = incoming.read(&mut header_buf) else {
                                    let _ = incoming.shutdown(Shutdown::Both);
                                    return;
                                };
                                if n == 0 {
                                    let _ = incoming.shutdown(Shutdown::Both);
                                    return;
                                }
                                let header = String::from_utf8_lossy(&header_buf[..n]);
                                let mut family = "claude".to_string();
                                let mut target_dest = "api.anthropic.com:443".to_string();
                                let mut pid = 0u32;
                                let mut start_sec = 0u64;
                                let mut start_usec = 0u32;
                                for (idx, line) in header.lines().enumerate() {
                                    if idx == 0 {
                                        let parts: Vec<&str> = line.split_whitespace().collect();
                                        if parts.len() >= 2 && parts[0].eq_ignore_ascii_case("CONNECT") {
                                            target_dest = parts[1].to_string();
                                        }
                                    } else if let Some(val) = line.strip_prefix("X-Watch-Family:") {
                                        family = val.trim().to_string();
                                    } else if let Some(val) = line.strip_prefix("X-Watch-Pid:") {
                                        pid = val.trim().parse().unwrap_or(0);
                                    } else if let Some(val) = line.strip_prefix("X-Watch-Start:") {
                                        let mut sp = val.trim().split(':');
                                        start_sec = sp.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                                        start_usec = sp.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                                    }
                                }
                                let proc_token = BoundProcessToken {
                                    pid,
                                    uid: 0,
                                    start_seconds: start_sec,
                                    start_microseconds: start_usec,
                                    role: ProcessRole::DesktopMain,
                                    audit_token: None,
                                };
                                let now = crate::native::now();
                                match enf.connect_supervised_tcp_to(
                                    &family,
                                    &proc_token,
                                    &target_dest,
                                    now,
                                ) {
                                    Ok((_flow_id, mut tunnel_stream)) => {
                                        if incoming
                                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
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
                                            b"HTTP/1.1 403 Forbidden (Channel Blocked)\r\n\r\n",
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
                let _ = enforcer.set_interception_active(false, crate::native::now());
            })
            .map_err(|_| CoreError::new("enforcer_listener_thread_failed", "受控通道监听线程启动失败"))?;
        Ok((addr, handle))
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
    /// 1. Pre-dial check under lock: verifies interception readiness, process
    ///    attribution, policy version, and active lease (`now < valid_until`).
    /// 2. Post-dial re-verification under lock (Logic Fix 2): re-verifies that
    ///    `session_id`, `permit_generation`, `policy_version`, `upstream_endpoint`,
    ///    process attribution, interception readiness, and lease validity did NOT
    ///    change while dialing the upstream socket!
    pub fn connect_supervised_tcp_to(
        &self,
        family: &str,
        process: &BoundProcessToken,
        target_destination: &str,
        now: f64,
    ) -> Result<(String, TunnelStream)> {
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
            on_dial_hook,
            defer_confirm,
        ) = {
            let mut guard = self.lock()?;
            let defer_confirm = guard.defer_auto_flow_confirm;
            let upstream_connector = guard.upstream_connector.clone();
            let on_dial_hook = guard.on_dial_hook.clone();
            let interception_active = guard.interception_active;
            let direct_fallback_blocked = guard.direct_fallback_blocked;
            let upstream_healthy = guard.upstream_healthy;
            let last_wall = guard.last_wall_now;
            let current_policy_opt = guard.current_policy.clone();
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
            let current_policy = current_policy_opt.unwrap_or_else(|| cmd.policy_version.clone());
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
                on_dial_hook,
                defer_confirm,
            )
        };

        if let Some(hook) = on_dial_hook {
            hook(family);
        }

        // Dial the designated upstream endpoint (TCP `http://host:port` / `host:port`
        // or custom kernel socket connector) and create a local socket
        // pair bridged by the enforcer so the enforcer owns the real socket handles
        // and can forcibly shut them down on revocation or lease expiry.
        let upstream_stream = if let Some(connector) = upstream_connector {
            connector(&upstream_endpoint)
                .map_err(|_| CoreError::new("upstream_connect_failed", "受控上游连接失败"))?
        } else if let Some(unix_path) = upstream_endpoint.strip_prefix("unix://") {
            let s = UnixStream::connect(unix_path)
                .map_err(|_| CoreError::new("upstream_connect_failed", "受控上游连接失败"))?;
            TunnelStream::Unix(s)
        } else {
            let upstream_addr: SocketAddr = upstream_endpoint
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .parse()
                .map_err(|_| CoreError::new("invalid_upstream_endpoint", "受控上游地址无效"))?;
            let s = TcpStream::connect_timeout(&upstream_addr, Duration::from_secs(2))
                .map_err(|_| CoreError::new("upstream_connect_failed", "受控上游连接失败"))?;
            let _ = s.set_nodelay(true);
            TunnelStream::Tcp(s)
        };

        let (client_side, enforcer_client_stream) = if let Ok(bridge_listener) =
            TcpListener::bind("127.0.0.1:0")
        {
            if let Ok(bridge_addr) = bridge_listener.local_addr() {
                if let Ok(client_tcp) = TcpStream::connect(bridge_addr) {
                    let _ = client_tcp.set_nodelay(true);
                    if let Ok((enforcer_tcp, _)) = bridge_listener.accept() {
                        let _ = enforcer_tcp.set_nodelay(true);
                        (TunnelStream::Tcp(client_tcp), TunnelStream::Tcp(enforcer_tcp))
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
            let post_dial_now = guard.last_wall_now.unwrap_or(now).max(now);
            let interception_ok = guard.interception_active && guard.direct_fallback_blocked;
            let upstream_ok = guard.upstream_healthy;
            let current_policy_opt = guard.current_policy.clone();
            let last_wall = guard.last_wall_now;

            // Logic Fix 2: Re-verify under lock that session, permit_generation,
            // policy_version, upstream_endpoint, process attribution, and lease
            // validity did NOT change while dialing!
            let Some(state) = guard.families.get_mut(family) else {
                let _ = enforcer_client_stream.shutdown(Shutdown::Both);
                let _ = upstream_stream.shutdown(Shutdown::Both);
                return Err(CoreError::new("channel_changed_during_dial", "拨号期间通道已移除"));
            };
            let Some(cmd) = state.command.clone() else {
                state.blocked_new_connections = state.blocked_new_connections.saturating_add(1);
                let _ = enforcer_client_stream.shutdown(Shutdown::Both);
                let _ = upstream_stream.shutdown(Shutdown::Both);
                return Err(CoreError::new("channel_changed_during_dial", "拨号期间通道命令已清除"));
            };
            let active_policy = current_policy_opt.unwrap_or_else(|| cmd.policy_version.clone());
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
                    format!("拨号期间通道状态、会话、代次、上游或有效期已变化（{post_reason}），已阻断旧连接"),
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
                let maybe_receipt = if let Ok(mut guard) = inner_done.lock() {
                    if let Some(state) = guard.families.get_mut(&family) {
                        let now = state.last_updated_at;
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
                    }
                } else {
                    None
                };
                if let (Some(store), Some(receipt)) = (&storage_done, &maybe_receipt) {
                    let _ = store.atomic_json(
                        &store
                            .paths
                            .watch()
                            .join(format!("state/channel-receipt-{}.json", receipt.family)),
                        &json!(receipt),
                    );
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
            active_flows_closed: active_count == 0,
            direct_fallback_blocked: guard.direct_fallback_blocked,
            active_flows_count: active_count,
            terminated_flows_count: state.terminated_flows_count,
            blocked_new_connections: state.blocked_new_connections,
            observed_at: now,
            error_code: state.last_error_code.clone(),
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

    fn command_content_matches(a: &ChannelEnforcementCommand, b: &ChannelEnforcementCommand) -> bool {
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
        Ok(guard.interception_active && guard.direct_fallback_blocked && guard.upstream_healthy)
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
        let receipt = {
            let mut guard = self.lock()?;

            // Logic Fix 3: Validate generation, sequence, session, and policy
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
                if guard
                    .current_policy
                    .as_ref()
                    .is_some_and(|p| p != &command.policy_version)
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
            let policy_changed = guard
                .current_policy
                .as_ref()
                .is_some_and(|p| p != &command.policy_version);
            guard.current_policy = Some(command.policy_version.clone());

            let interception_active = guard.interception_active && guard.direct_fallback_blocked;
            let upstream_healthy = guard.upstream_healthy;
            let (session_changed, has_active_flows) = {
                let state = guard
                    .families
                    .entry(command.family.clone())
                    .or_insert_with(|| FamilyEnforcerState::new(now));
                let session_changed = state
                    .command
                    .as_ref()
                    .is_some_and(|prev| prev.session_id != command.session_id);
                state.last_permit_generation = command.permit_generation;
                state.last_command_seq = command.command_seq;
                state.command = Some(command.clone());
                state.last_updated_at = now;
                (session_changed, !state.active_flows.is_empty())
            };

            let (effective_state, effective_reason) =
                command
                    .permit
                    .effective_state_with_clock(now, None, false, &command.policy_version);

            if !interception_active {
                if let Some(state) = guard.families.get_mut(&command.family) {
                    state.enforcement_state = ChannelEnforcementState::Failed;
                    state.last_error_code = Some("interception_inactive_direct_leak_risk".into());
                }
            } else if !upstream_healthy {
                Self::begin_revoke_locked(&mut guard, &command.family, "tag_upstream_unhealthy", now);
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
        self.persist_receipt(&receipt)?;
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
        let mut updated = Vec::new();
        {
            let mut guard = self.lock()?;
            let last_wall = guard.last_wall_now;
            guard.last_wall_now = Some(now);
            let families: Vec<String> = guard.families.keys().cloned().collect();
            for family in families {
                let should_revoke = guard.families.get(&family).and_then(|state| {
                    let cmd = state.command.as_ref()?;
                    let policy = guard
                        .current_policy
                        .as_ref()
                        .unwrap_or(&cmd.policy_version);
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
        }
        for r in &updated {
            self.persist_receipt(r)?;
        }
        Ok(updated)
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
    /// Explicit protocol coverage matrix so unimplemented kernel-level capture
    /// (UDP/QUIC, transparent IPv6, direct port 53/853 DNS) is reported as
    /// blocked or pending SystemExtension activation, never falsely claimed as
    /// protected.
    pub fn protocol_coverage_boundaries(&self) -> serde_json::Value {
        let ready = self.is_ready().unwrap_or(false);
        let proxy_addr = self.lock().ok().and_then(|g| g.local_listener_addr.clone());
        json!({
            "enforcer_ready": ready,
            "local_proxy_addr": proxy_addr,
            "tcp_ipv4": {
                "local_proxy_relay": if ready { "active" } else { "inactive" },
                "transparent_kernel_capture": "pending_system_extension_activation",
                "claimed_protected": false
            },
            "tcp_ipv6": {
                "local_proxy_relay": if ready { "supported_via_proxy_endpoint" } else { "inactive" },
                "transparent_kernel_capture": "pending_system_extension_activation",
                "claimed_protected": false
            },
            "udp_quic": {
                "flow_gate_policy": "blocked_in_channel_mode",
                "transparent_kernel_capture": "pending_system_extension_activation",
                "claimed_protected": false
            },
            "dns": {
                "flow_gate_policy": "direct_53_853_blocked_in_gate",
                "transparent_kernel_capture": "pending_system_extension_activation",
                "claimed_protected": false
            }
        })
    }
}
