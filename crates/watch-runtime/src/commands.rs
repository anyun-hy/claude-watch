//! Fixed read-only utilities and a bounded, deadlock-free subprocess transport.
use claude_watch_core::{
    error::{CoreError, Result},
    tag_config::normalized_dns_host,
};
use std::{
    ffi::OsString,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};
use subprocess::{Exec, Job, Redirection};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserverAction {
    Inventory,
    Arguments,
    Sockets,
    Identities,
    Environment,
}
impl ObserverAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Inventory => "inventory",
            Self::Arguments => "arguments",
            Self::Sockets => "sockets",
            Self::Identities => "identities",
            Self::Environment => "environment",
        }
    }
}
#[derive(Clone, Debug)]
pub enum ReadCommand {
    Observer(ObserverAction),
    ProcessTable,
    Interfaces,
    Plist(PathBuf),
    Listeners,
    LsofListener,
    /// Read the owner of one caller-selected TCP listening port, never mutate it.
    LsofTcpListener { port: u16 },
    /// Fixed-pid file-descriptor sampling.  The caller must discard names before
    /// publishing; lsof paths are intentionally never a presentation contract.
    LsofFiles {
        pids: Vec<u32>,
    },
    /// One bounded nettop counter batch (at most twenty PIDs).
    NettopBytes {
        pids: Vec<u32>,
    },
    /// Candidate labels only.  `launchctl list` does not establish ownership.
    LaunchctlList,
    Route(IpAddr),
    DnsA {
        host: String,
        port: u16,
    },
    /// Fixed `dig` query through the system resolver configuration; this is
    /// deliberately not a caller-provided DNS host or command string.
    DnsProbeWhoamiTxt,
    ScutilDns,
    ScutilProxy,
    RouteDefaultV4,
    RouteDefaultV6,
    ReadlinkLocaltime,
    Iso8601Date,
    ClaudeSettings {
        home: PathBuf,
        managed: bool,
    },
    ClaudeSettingsExists {
        home: PathBuf,
        managed: bool,
    },
    NetstatRouteV6,
    LaunchctlSystem {
        label: ServiceLabel,
    },
    AdminHelperStatus,
    LaunchctlGuiUpdater {
        uid: u32,
    },
    LaunchctlGuiAgent {
        uid: u32,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceLabel {
    Timezone,
    LegacyBodyguard,
    LegacyTimezone,
    LegacyUpdate,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    Observer(ObserverAction),
    ProcessTable,
    Interfaces,
    Plist,
    Listeners,
    LsofListener,
    LsofFiles,
    NettopBytes,
    LaunchctlList,
    Route,
    DnsA,
    DnsProbeWhoamiTxt,
    ScutilDns,
    ScutilProxy,
    RouteDefaultV4,
    RouteDefaultV6,
    ReadlinkLocaltime,
    Iso8601Date,
    ClaudeSettings,
    ClaudeSettingsExists,
    NetstatRouteV6,
    LaunchctlSystem,
    AdminHelperStatus,
    LaunchctlGuiUpdater,
    LaunchctlGuiAgent,
}
impl ReadCommand {
    fn key(&self) -> Key {
        match self {
            Self::Observer(action) => Key::Observer(*action),
            Self::ProcessTable => Key::ProcessTable,
            Self::Interfaces => Key::Interfaces,
            Self::Plist(_) => Key::Plist,
            Self::Listeners => Key::Listeners,
            Self::LsofListener => Key::LsofListener,
            Self::LsofTcpListener { .. } => Key::LsofListener,
            Self::LsofFiles { .. } => Key::LsofFiles,
            Self::NettopBytes { .. } => Key::NettopBytes,
            Self::LaunchctlList => Key::LaunchctlList,
            Self::Route(_) => Key::Route,
            Self::DnsA { .. } => Key::DnsA,
            Self::DnsProbeWhoamiTxt => Key::DnsProbeWhoamiTxt,
            Self::ScutilDns => Key::ScutilDns,
            Self::ScutilProxy => Key::ScutilProxy,
            Self::RouteDefaultV4 => Key::RouteDefaultV4,
            Self::RouteDefaultV6 => Key::RouteDefaultV6,
            Self::ReadlinkLocaltime => Key::ReadlinkLocaltime,
            Self::Iso8601Date => Key::Iso8601Date,
            Self::ClaudeSettings { .. } => Key::ClaudeSettings,
            Self::ClaudeSettingsExists { .. } => Key::ClaudeSettingsExists,
            Self::NetstatRouteV6 => Key::NetstatRouteV6,
            Self::LaunchctlSystem { .. } => Key::LaunchctlSystem,
            Self::AdminHelperStatus => Key::AdminHelperStatus,
            Self::LaunchctlGuiUpdater { .. } => Key::LaunchctlGuiUpdater,
            Self::LaunchctlGuiAgent { .. } => Key::LaunchctlGuiAgent,
        }
    }
    fn spec(&self, observer: &Path) -> Result<(PathBuf, Vec<OsString>)> {
        let (program, args) = match self {
            Self::Observer(action) => (observer.to_path_buf(), vec![action.as_str().into()]),
            Self::ProcessTable => (
                "/bin/ps".into(),
                ["-ww", "-axo", "pid=,ppid=,uid=,lstart=,comm="]
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            ),
            Self::Interfaces => ("/sbin/ifconfig".into(), vec![]),
            Self::Plist(path) => {
                if !path.is_absolute() || path.extension().is_none_or(|v| v != "plist") {
                    return Err(CoreError::new("invalid_plist_path", "系统定义文件路径无效"));
                }
                (
                    "/usr/bin/plutil".into(),
                    vec![
                        "-convert".into(),
                        "json".into(),
                        "-o".into(),
                        "-".into(),
                        "--".into(),
                        path.as_os_str().into(),
                    ],
                )
            }
            Self::Listeners => (
                "/usr/sbin/netstat".into(),
                ["-anv", "-p", "tcp"].into_iter().map(Into::into).collect(),
            ),
            Self::LsofListener => return Self::LsofTcpListener { port: 7890 }.spec(observer),
            Self::LsofTcpListener { port } => {
                if *port == 0 {
                    return Err(CoreError::new("invalid_listener_port", "监听端口必须非零"));
                }
                ("/usr/sbin/lsof".into(), vec!["-nP".into(), "-a".into(),
                    format!("-iTCP:{port}").into(), "-sTCP:LISTEN".into(), "-Fpn".into()])
            }
            Self::LsofFiles { pids } => {
                let pid_list = bounded_pid_list(pids, 1024)?;
                (
                    "/usr/sbin/lsof".into(),
                    vec![
                        "-nP".into(),
                        "-a".into(),
                        "-p".into(),
                        pid_list.into(),
                        "-Fpfan".into(),
                    ],
                )
            }
            Self::NettopBytes { pids } => {
                let pids = bounded_pid_list(pids, 20)?;
                let mut args: Vec<OsString> = vec![
                    "-n".into(),
                    "-P".into(),
                    "-L".into(),
                    "1".into(),
                    "-x".into(),
                    "-J".into(),
                    "bytes_in,bytes_out".into(),
                ];
                for pid in pids.split(',') {
                    args.push("-p".into());
                    args.push(pid.into());
                }
                ("/usr/bin/nettop".into(), args)
            }
            Self::LaunchctlList => ("/bin/launchctl".into(), vec!["list".into()]),
            Self::Route(address) => {
                let mut args: Vec<OsString> = vec!["-n".into(), "get".into()];
                if address.is_ipv6() {
                    args.push("-inet6".into())
                }
                args.push(address.to_string().into());
                ("/sbin/route".into(), args)
            }
            Self::DnsA { host, port } => {
                if normalized_dns_host(host).as_deref() != Some(host) || *port == 0 {
                    return Err(CoreError::new("invalid_dns_query", "本机 DNS 查询参数无效"));
                }
                (
                    "/usr/bin/dig".into(),
                    vec![
                        "@127.0.0.1".into(),
                        "-p".into(),
                        port.to_string().into(),
                        "+tcp".into(),
                        "+time=1".into(),
                        "+tries=1".into(),
                        "+nosearch".into(),
                        "+noall".into(),
                        "+answer".into(),
                        "+comments".into(),
                        "+nocmd".into(),
                        host.into(),
                        "A".into(),
                    ],
                )
            }
            Self::DnsProbeWhoamiTxt => (
                "/usr/bin/dig".into(),
                [
                    "+time=3",
                    "+tries=1",
                    "+short",
                    "whoami.ds.akahelp.net",
                    "TXT",
                ]
                .into_iter()
                .map(Into::into)
                .collect(),
            ),
            Self::ScutilDns => ("/usr/sbin/scutil".into(), vec!["--dns".into()]),
            Self::ScutilProxy => ("/usr/sbin/scutil".into(), vec!["--proxy".into()]),
            Self::RouteDefaultV4 => (
                "/sbin/route".into(),
                ["-n", "get", "-inet", "default"]
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            ),
            Self::RouteDefaultV6 => (
                "/sbin/route".into(),
                ["-n", "get", "-inet6", "default"]
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            ),
            Self::ReadlinkLocaltime => ("/usr/bin/readlink".into(), vec!["/etc/localtime".into()]),
            Self::Iso8601Date => ("/bin/date".into(), vec!["+%Y-%m-%dT%H:%M:%S%z".into()]),
            Self::ClaudeSettings { home, managed } => {
                let path = if *managed {
                    PathBuf::from("/Library/Application Support/ClaudeCode/managed-settings.json")
                } else {
                    if !home.is_absolute()
                        || home
                            .components()
                            .any(|part| matches!(part, std::path::Component::ParentDir))
                    {
                        return Err(CoreError::new("invalid_home", "Claude 设置目录无效"));
                    }
                    home.join(".claude/settings.json")
                };
                (
                    "/usr/bin/plutil".into(),
                    vec![
                        "-convert".into(),
                        "json".into(),
                        "-o".into(),
                        "-".into(),
                        "--".into(),
                        path.into_os_string(),
                    ],
                )
            }
            Self::ClaudeSettingsExists { home, managed } => {
                let path = if *managed {
                    PathBuf::from("/Library/Application Support/ClaudeCode/managed-settings.json")
                } else {
                    if !home.is_absolute()
                        || home
                            .components()
                            .any(|part| matches!(part, std::path::Component::ParentDir))
                    {
                        return Err(CoreError::new("invalid_home", "Claude 设置目录无效"));
                    }
                    home.join(".claude/settings.json")
                };
                (
                    "/usr/bin/test".into(),
                    vec!["-f".into(), path.into_os_string()],
                )
            }
            Self::NetstatRouteV6 => (
                "/usr/sbin/netstat".into(),
                ["-rn", "-f", "inet6"].into_iter().map(Into::into).collect(),
            ),
            Self::LaunchctlSystem { label } => {
                let label = match label {
                    ServiceLabel::Timezone => "io.local.claudewatch.timezone",
                    ServiceLabel::LegacyBodyguard => "local.claude-bodyguard",
                    ServiceLabel::LegacyTimezone => "local.tz-watchdog",
                    ServiceLabel::LegacyUpdate => "local.claude-update",
                };
                (
                    "/bin/launchctl".into(),
                    vec!["print".into(), format!("system/{label}").into()],
                )
            }
            Self::AdminHelperStatus => (
                "/Library/Application Support/ClaudeWatch/claude-watch-admin.sh".into(),
                vec!["status".into()],
            ),
            Self::LaunchctlGuiUpdater { uid } if *uid > 0 => (
                "/bin/launchctl".into(),
                vec![
                    "print".into(),
                    format!("gui/{uid}/io.local.claudewatch.update").into(),
                ],
            ),
            Self::LaunchctlGuiAgent { uid } if *uid > 0 => (
                "/bin/launchctl".into(),
                vec![
                    "print".into(),
                    format!("gui/{uid}/io.local.claudewatch.agent").into(),
                ],
            ),
            Self::LaunchctlGuiUpdater { .. } | Self::LaunchctlGuiAgent { .. } => {
                return Err(CoreError::new("invalid_uid", "GUI 后台读取 UID 无效"))
            }
        };
        Ok((program, args))
    }
}
fn bounded_pid_list(pids: &[u32], maximum: usize) -> Result<String> {
    if pids.is_empty() || pids.len() > maximum || pids.iter().any(|pid| *pid <= 1) {
        return Err(CoreError::new(
            "invalid_pid_list",
            "只读采样进程列表无效或超过上限",
        ));
    }
    let mut unique = pids.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != pids.len() {
        return Err(CoreError::new(
            "invalid_pid_list",
            "只读采样进程列表包含重复项",
        ));
    }
    Ok(unique
        .into_iter()
        .map(|pid| pid.to_string())
        .collect::<Vec<_>>()
        .join(","))
}
impl<R: ReadRunner + ?Sized> ReadRunner for &R {
    fn run(&self, c: ReadCommand, i: &[u8], t: Duration, l: usize) -> Result<Output> {
        (*self).run(c, i, t, l)
    }
}
impl<R: ReadRunner + ?Sized> ReadRunner for std::sync::Arc<R> {
    fn run(&self, c: ReadCommand, i: &[u8], t: Duration, l: usize) -> Result<Output> {
        self.as_ref().run(c, i, t, l)
    }
}
// Do not derive Debug: argument observations may contain private argv prefixes in memory.
pub struct Output {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}
impl Output {
    pub fn text(&self) -> Result<&str> {
        std::str::from_utf8(&self.stdout)
            .map_err(|_| CoreError::new("invalid_command_encoding", "系统采样输出不是有效UTF-8"))
    }
    pub fn error_text(&self) -> Result<&str> {
        std::str::from_utf8(&self.stderr).map_err(|_| {
            CoreError::new("invalid_command_encoding", "系统采样错误输出不是有效UTF-8")
        })
    }
}
pub trait ReadRunner {
    fn run(
        &self,
        command: ReadCommand,
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> Result<Output>;
}
pub struct SystemRunner {
    observer: PathBuf,
    pending: Mutex<Vec<(Key, Job)>>,
    listeners: Option<std::sync::Arc<crate::native_listener::ListenerStream>>,
    listener_cache: Option<crate::storage::StateStore>,
}
/// launchctl also prints nested coalitions with their own `state` field.
/// Only the service's root fields establish its process identity.
pub fn loaded_agent_identity(text: &str) -> Option<(&str, u32)> {
    let scoped = text.lines().any(|s| s.trim_end().ends_with(" = {"));
    let mut depth = 0usize;
    let mut state = None;
    let mut pid = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line == "}" {
            depth = depth.saturating_sub(1);
            continue;
        }
        if (!scoped && depth == 0) || (scoped && depth == 1) {
            if let Some(v) = line.strip_prefix("state = ") {
                if state.replace(v.trim()).is_some() {
                    return None;
                }
            }
            if let Some(v) = line.strip_prefix("pid = ") {
                if pid
                    .replace(v.trim().parse::<u32>().ok().filter(|v| *v > 1)?)
                    .is_some()
                {
                    return None;
                }
            }
        }
        if line.ends_with(" = {") {
            depth += 1;
        }
    }
    state.zip(pid)
}
impl SystemRunner {
    pub fn development() -> Result<Self> {
        Self::new(Path::new(env!("CW_NATIVE_OBSERVER_BUILD_PATH")))
    }
    pub fn new(observer: &Path) -> Result<Self> {
        let meta = std::fs::symlink_metadata(observer)
            .map_err(|_| CoreError::new("native_observer_missing", "缺少macOS原生采样组件"))?;
        if !meta.is_file() || meta.file_type().is_symlink() || !observer.is_absolute() {
            return Err(CoreError::new(
                "invalid_observer_path",
                "原生采样组件路径无效",
            ));
        }
        Ok(Self {
            observer: observer.into(),
            pending: Mutex::new(Vec::new()),
            listeners: None,
            listener_cache: None,
        })
    }
    pub fn with_listener_stream(
        mut self,
        stream: std::sync::Arc<crate::native_listener::ListenerStream>,
    ) -> Self {
        self.listeners = Some(stream);
        self
    }
    pub fn with_listener_cache(mut self, store: crate::storage::StateStore) -> Self {
        self.listener_cache = Some(store);
        self
    }
    pub fn publish_listeners(&self, store: &crate::storage::StateStore) -> Result<()> {
        if let Some(stream) = &self.listeners {
            stream.publish(store, self)
        } else {
            Ok(())
        }
    }
    pub fn listener_channel_finished(&self) -> bool {
        self.listeners.as_ref().is_some_and(|s| s.is_finished())
    }
    fn reap_or_block(&self, key: Key) -> Result<()> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| CoreError::new("command_state_unavailable", "采样进程状态不可读取"))?;
        pending.retain(|(_, job)| job.poll().is_none());
        if pending.iter().any(|(active, _)| *active == key) {
            return Err(CoreError::new(
                "command_still_running",
                "上一次只读采样子进程尚未退出，未重复启动",
            ));
        }
        Ok(())
    }
    fn stop_owned_child(&self, key: Key, job: Job) {
        let _ = job.kill();
        if !matches!(job.wait_timeout(Duration::from_millis(500)), Ok(Some(_))) {
            job.detach();
            if let Ok(mut pending) = self.pending.lock() {
                pending.push((key, job));
            }
        }
    }
}
impl ReadRunner for SystemRunner {
    fn run(
        &self,
        command: ReadCommand,
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> Result<Output> {
        if timeout.is_zero()
            || timeout > Duration::from_secs(10)
            || limit == 0
            || limit > 8 * 1024 * 1024
            || input.len() > 1_048_576
            || (!matches!(command, ReadCommand::Observer(_)) && !input.is_empty())
        {
            return Err(CoreError::new(
                "invalid_command_limits",
                "系统采样参数或资源上限无效",
            ));
        }
        let key = command.key();
        if matches!(command, ReadCommand::Listeners) {
            if let Some(stream) = &self.listeners {
                return stream.read(self);
            }
            // The published cache is a hardened path, never the only source.
            // A stale frame, a rejected frame boundary or a changed sampling
            // origin must fall through to the plain netstat read below; other-
            // wise only the daemon (which owns the live stream) can verify the
            // listener, and every UI-spawned engine stays "unconfirmed".
            if let Some(store) = &self.listener_cache {
                if crate::native_listener::cache_exists(store) {
                    if let Ok(output) = crate::native_listener::read_cached(store, self) {
                        return Ok(output);
                    }
                }
            }
        }
        self.reap_or_block(key)?;
        let (program, args) = command.spec(&self.observer)?;
        let started = Instant::now();
        let mut job = Exec::cmd(program)
            .args(&args)
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(input.to_vec())
            .stdout(Redirection::Pipe)
            .stderr(Redirection::Pipe)
            .start()
            .map_err(|_| CoreError::new("command_unavailable", "系统只读采样组件无法启动"))?;
        let communication = job.communicate();
        let result = match communication {
            Ok(comm) => comm
                .limit_time(
                    timeout
                        .saturating_sub(started.elapsed())
                        .max(Duration::from_millis(1)),
                )
                .limit_size(limit + 1)
                .read(),
            Err(error) => Err(error),
        };
        let (stdout, stderr) = match result {
            Ok(value) => value,
            Err(error) => {
                self.stop_owned_child(key, job);
                return Err(CoreError::new(
                    if error.kind() == std::io::ErrorKind::TimedOut {
                        "command_timeout"
                    } else {
                        "command_io_failed"
                    },
                    "系统只读采样超时或通信失败",
                ));
            }
        };
        if stdout.len() + stderr.len() > limit {
            self.stop_owned_child(key, job);
            return Err(CoreError::new(
                "command_output_oversize",
                "系统采样输出超过资源上限",
            ));
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        let status = if remaining.is_zero() {
            None
        } else {
            match job.wait_timeout(remaining) {
                Ok(value) => value,
                Err(_) => {
                    self.stop_owned_child(key, job);
                    return Err(CoreError::new(
                        "command_wait_failed",
                        "系统采样退出状态不可读取",
                    ));
                }
            }
        };
        let Some(status) = status else {
            self.stop_owned_child(key, job);
            return Err(CoreError::new(
                "command_timeout",
                "系统采样子进程未在时限内退出",
            ));
        };
        Ok(Output {
            status: status.code().map(|v| v as i32).unwrap_or(-1),
            stdout,
            stderr,
        })
    }
}

#[cfg(test)]
mod agent_identity_tests {
    use super::loaded_agent_identity;
    #[test]
    fn nested_coalition_state_cannot_replace_service_identity() {
        let live="gui/501/io.local.claudewatch.agent = {\n\tstate = running\n\tpid = 123\n\tresource coalition = {\n\t\tstate = active\n\t\tpid = 999\n\t}\n}\n";
        assert_eq!(loaded_agent_identity(live), Some(("running", 123)));
        assert_eq!(
            loaded_agent_identity("state = running\npid = 123\n"),
            Some(("running", 123))
        );
        assert!(loaded_agent_identity(
            "gui/501/example = {\nstate = running\nresource coalition = {\npid = 999\n}\n}\n"
        )
        .is_none());
        assert!(loaded_agent_identity("state = running\npid = 123\npid = 456\n").is_none());
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_route_tests {
    use super::{ReadCommand, ReadRunner, SystemRunner};
    use std::time::Duration;

    #[test]
    fn default_route_readers_can_launch_on_macos() {
        let runner = SystemRunner::development().expect("native observer is available");
        for command in [ReadCommand::RouteDefaultV4, ReadCommand::RouteDefaultV6] {
            // An absent default route is a legitimate nonzero exit; the check
            // here is that each reader can actually launch the system tool.
            runner
                .run(command, &[], Duration::from_secs(5), 32 * 1024)
                .expect("default route command must be executable");
        }
    }
}
