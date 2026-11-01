//! Native desktop operations. The Rust controller owns when and why an operation is allowed.
use crate::{
    audit_store::{AuditStore, AuditSystem},
    commands::ReadRunner,
    config_store::ConfigStore,
    controlled::{CliProcess, DesktopSystem},
    macos::Authority,
    native::{self, Observer},
    network_client::{NetworkClient, Transport},
    region_catalog::load_system_catalog,
    services::ServiceSystem,
    storage::StateStore,
};
use claude_watch_core::{
    error::{CoreError, Result},
    processes::{Identity as ProcessIdentity, Kind, LaunchTarget, Target},
    session::{Desktop, Launcher},
};
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use subprocess::unix::JobExt;
use subprocess::{Exec, Job, Redirection};

fn execute_output(program: &Path, args: &[&str], timeout: Duration) -> Result<Vec<u8>> {
    let started = Instant::now();
    let mut job = Exec::cmd(program)
        .args(args)
        .stdin(Redirection::Null)
        .stdout(Redirection::Pipe)
        .stderr(Redirection::Pipe)
        .env("LC_ALL", "C")
        .start()
        .map_err(|_| CoreError::new("desktop_component_unavailable", "原生应用执行组件无法启动"))?;
    let result = job
        .communicate()
        .and_then(|c| c.limit_time(timeout).limit_size(65537).read());
    let mut reaped = false;
    let outcome = match result {
        Ok((out, error)) if out.len() + error.len() <= 65536 => {
            match job.wait_timeout(timeout.saturating_sub(started.elapsed())) {
                Ok(Some(s)) if s.success() => {
                    reaped = true;
                    Ok(out)
                }
                Ok(Some(_)) => {
                    reaped = true;
                    Err(CoreError::new(
                        "desktop_operation_failed",
                        "原生应用操作未完成",
                    ))
                }
                _ => Err(CoreError::new(
                    "desktop_operation_failed",
                    "原生应用操作未完成",
                )),
            }
        }
        Ok(_) => Err(CoreError::new(
            "desktop_output_oversize",
            "应用执行组件输出过大",
        )),
        Err(_) => Err(CoreError::new(
            "desktop_operation_timeout",
            "应用执行组件通信失败或超时",
        )),
    };
    if outcome.is_err() && !reaped {
        let _ = job.kill();
        if !matches!(job.wait_timeout(Duration::from_millis(500)), Ok(Some(_))) {
            job.detach();
        }
    }
    outcome
}
fn execute(program: &Path, args: &[&str], timeout: Duration) -> Result<()> {
    execute_output(program, args, timeout).map(|_| ())
}
pub struct NativeDesktop<R: ReadRunner> {
    pub runner: R,
    helper: PathBuf,
    pub authority: Authority,
    target: LaunchTarget,
    selected: Option<SelectedApplication>,
    applications: PathBuf,
    cask_roots: Vec<PathBuf>,
    cli: Option<SelectedCli>,
}
#[derive(Clone, PartialEq, Eq)]
struct SelectedApplication {
    path: PathBuf,
    bundle: PathBuf,
    executable: PathBuf,
    bundle_id: String,
    kind: Kind,
}
struct SelectedCli {
    path: PathBuf,
    fingerprint: (u64, u64, u64, i64, i64),
}
fn cli_fingerprint(path: &Path) -> Result<(u64, u64, u64, i64, i64)> {
    let m = fs::symlink_metadata(path)
        .map_err(|_| CoreError::new("cli_unavailable", "CLI可执行文件无法读取"))?;
    if !m.is_file() || m.file_type().is_symlink() || m.permissions().mode() & 0o111 == 0 {
        return Err(CoreError::new("cli_unavailable", "CLI不是可执行的普通文件"));
    }
    Ok((m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec()))
}
pub struct NativeCliState {
    proxy: Option<String>,
    flag: Arc<AtomicUsize>,
    handlers: Vec<signal_hook::SigId>,
}
impl NativeCliState {
    fn new(proxy: Option<String>) -> Self {
        Self {
            proxy,
            flag: Arc::new(AtomicUsize::new(0)),
            handlers: Vec::new(),
        }
    }
    fn prepare(&mut self) -> Result<()> {
        if !self.handlers.is_empty() {
            return Ok(());
        }
        for (signal, code) in [
            (signal_hook::consts::SIGINT, 130),
            (signal_hook::consts::SIGTERM, 143),
        ] {
            match signal_hook::flag::register_usize(signal, self.flag.clone(), code) {
                Ok(id) => self.handlers.push(id),
                Err(_) => {
                    for id in self.handlers.drain(..) {
                        signal_hook::low_level::unregister(id);
                    }
                    return Err(CoreError::new(
                        "cli_signal_unavailable",
                        "无法准备CLI中断处理，未启动",
                    ));
                }
            }
        }
        Ok(())
    }
}
impl Drop for NativeCliState {
    fn drop(&mut self) {
        for id in self.handlers.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}
struct NativeCliProcess {
    job: Job,
    flag: Arc<AtomicUsize>,
}
impl CliProcess for NativeCliProcess {
    fn wait(&mut self) -> Result<i32> {
        loop {
            let code = self.flag.load(Ordering::SeqCst);
            if code != 0 {
                let signal = if code == 143 {
                    signal_hook::consts::SIGTERM
                } else {
                    signal_hook::consts::SIGINT
                };
                let _ = self.job.send_signal(signal);
                if !matches!(self.job.wait_timeout(Duration::from_secs(2)), Ok(Some(_))) {
                    let _ = self.job.kill();
                    if !matches!(
                        self.job.wait_timeout(Duration::from_millis(500)),
                        Ok(Some(_))
                    ) {
                        self.job.detach();
                    }
                }
                return Ok(code as i32);
            }
            match self.job.wait_timeout(Duration::from_millis(50)) {
                Ok(Some(status)) => {
                    return status
                        .code()
                        .map(|c| c as i32)
                        .or_else(|| status.signal().map(|s| 128 + s))
                        .ok_or_else(|| {
                            CoreError::new(
                                "cli_exit_unavailable",
                                "CLI退出状态无法确认；已撤销观察关联",
                            )
                        })
                }
                Ok(None) => {}
                Err(_) => {
                    self.job.detach();
                    return Err(CoreError::new(
                        "cli_wait_failed",
                        "CLI等待失败；撤销观察关联，不自动结束应用",
                    ));
                }
            }
        }
    }
}
impl Drop for NativeCliProcess {
    fn drop(&mut self) {
        if self.job.poll().is_none() {
            self.job.detach();
        }
    }
}
impl<R: ReadRunner> NativeDesktop<R> {
    pub fn new(runner: R, helper: PathBuf, authority: Authority) -> Result<Self> {
        let m = fs::symlink_metadata(&helper)
            .map_err(|_| CoreError::new("process_component_missing", "缺少原生应用执行组件"))?;
        if !helper.is_absolute()
            || !m.is_file()
            || m.file_type().is_symlink()
            || helper.file_name().and_then(|s| s.to_str()) != Some("watch-process-control")
        {
            return Err(CoreError::new(
                "invalid_process_component",
                "应用执行组件路径无效",
            ));
        }
        Ok(Self {
            runner,
            helper,
            authority,
            target: LaunchTarget::ClaudeDesktop,
            selected: None,
            applications: "/Applications".into(),
            cask_roots: vec![
                "/opt/homebrew/Caskroom".into(),
                "/usr/local/Caskroom".into(),
            ],
            cli: None,
        })
    }
    pub fn target(&self) -> LaunchTarget {
        self.target
    }
    pub fn select_target(&mut self, target: LaunchTarget) -> Result<()> {
        self.selected = if target.protected() {
            None
        } else {
            Some(self.resolve_target(target)?)
        };
        self.target = target;
        Ok(())
    }
    pub fn select_cli(&mut self, target: LaunchTarget, home: &Path) -> Result<()> {
        let mut env = std::collections::BTreeMap::new();
        for key in ["PATH", "CLAUDE_CODE_BIN", "CODEX_CLI_BIN"] {
            match std::env::var(key) {
                Ok(value) => {
                    env.insert(key.into(), value);
                }
                Err(std::env::VarError::NotPresent) => {}
                Err(_) => {
                    return Err(CoreError::new(
                        "cli_environment_invalid",
                        "CLI定位环境不是有效UTF-8，未启动",
                    ))
                }
            }
        }
        self.select_cli_environment(target, home, &env)
    }
    fn select_cli_environment(
        &mut self,
        target: LaunchTarget,
        home: &Path,
        env: &std::collections::BTreeMap<String, String>,
    ) -> Result<()> {
        if !target.cli() {
            return Err(CoreError::new("invalid_target", "目标不是CLI"));
        }
        let (name, key) = if target == LaunchTarget::ClaudeCli {
            ("claude", "CLAUDE_CODE_BIN")
        } else {
            ("codex", "CODEX_CLI_BIN")
        };
        let paths = crate::storage::Paths::new(home)?;
        let home = paths.home.as_path();
        let trusted = crate::sampler::cli_paths(&paths);
        let mut bundled = std::collections::BTreeSet::new();
        if target == LaunchTarget::CodexCli {
            for request in [LaunchTarget::CodexDesktop, LaunchTarget::ChatgptDesktop] {
                if let Ok(app) = self.resolve_target(request) {
                    for relative in [
                        "Contents/Resources/codex",
                        "Contents/Resources/codex-cli/bin/codex",
                        "Contents/Resources/CodexCLI.app/Contents/MacOS/codex",
                        "Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex",
                    ] {
                        if let Ok(path) = fs::canonicalize(app.bundle.join(relative)) {
                            if path.starts_with(&app.bundle) {
                                bundled.insert(path);
                            }
                        }
                    }
                }
            }
        }
        let mut candidates = Vec::new();
        if let Some(value) = env.get(key).filter(|v| !v.is_empty()) {
            let p = PathBuf::from(value);
            if !p.is_absolute() {
                return Err(CoreError::new(
                    "cli_source_unverified",
                    "CLI覆盖路径必须为已识别来源的绝对路径",
                ));
            }
            candidates.push(p);
        } else {
            if let Some(path) = env.get("PATH").and_then(|v| {
                std::env::split_paths(v).map(|p| p.join(name)).find(|p| {
                    fs::metadata(p)
                        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                })
            }) {
                candidates.push(path);
            } else {
                candidates.extend(if target == LaunchTarget::ClaudeCli {
                    vec![
                        home.join(".local/bin/claude"),
                        home.join(".claude/local/claude"),
                        "/opt/homebrew/bin/claude".into(),
                        "/usr/local/bin/claude".into(),
                    ]
                } else {
                    vec![
                        "/opt/homebrew/bin/codex".into(),
                        "/usr/local/bin/codex".into(),
                    ]
                });
            }
        }
        if !env.get(key).is_some_and(|v| !v.is_empty()) {
            candidates.extend(bundled.iter().cloned());
        }
        for path in candidates {
            let Ok(path) = fs::canonicalize(path) else {
                continue;
            };
            if !bundled.contains(&path)
                && !path.to_str().is_some_and(|p| {
                    claude_watch_core::process_roots::cli_kind(p, home, &trusted)
                        .is_some_and(|kind| target.accepts(kind))
                })
            {
                return Err(CoreError::new(
                    "cli_source_unverified",
                    "同名CLI来源未通过现有进程身份规则，未启动",
                ));
            }
            let fingerprint = cli_fingerprint(&path)?;
            self.cli = Some(SelectedCli { path, fingerprint });
            self.selected = None;
            self.target = target;
            return Ok(());
        }
        Err(CoreError::new(
            "cli_unavailable",
            "没有找到受支持来源的CLI可执行文件",
        ))
    }
    fn spawn_cli(&self, args: &[String], state: &NativeCliState) -> Result<Box<dyn CliProcess>> {
        if self.authority != Authority::ExplicitPermit || !self.target.cli() {
            return Err(CoreError::new(
                "write_not_authorized",
                "只读或桌面入口不能执行CLI",
            ));
        }
        let selected = self
            .cli
            .as_ref()
            .ok_or_else(|| CoreError::new("cli_unavailable", "CLI目标尚未绑定"))?;
        if cli_fingerprint(&selected.path)? != selected.fingerprint {
            return Err(CoreError::new(
                "cli_install_changed",
                "预检期间CLI文件发生变化，未启动",
            ));
        }
        let proxy = state
            .proxy
            .as_deref()
            .filter(|p| claude_watch_core::config::valid_loopback_proxy(p))
            .ok_or_else(|| CoreError::new("cli_route_unconfirmed", "本次子进程代理入口未确认"))?;
        if state.handlers.len() != 2 {
            return Err(CoreError::new(
                "cli_signal_unavailable",
                "CLI中断处理尚未就绪",
            ));
        }
        let mut command = Exec::cmd(&selected.path).args(args);
        for key in [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
        ] {
            command = command.env_remove(key);
        }
        for key in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"] {
            command = command.env(key, proxy);
        }
        for key in ["NO_PROXY", "no_proxy"] {
            command = command.env(key, "localhost,127.0.0.1,::1");
        }
        let job = command.start().map_err(|_| {
            CoreError::new(
                "cli_spawn_failed",
                "CLI子进程无法启动；未执行shell或更改当前登录",
            )
        })?;
        Ok(Box::new(NativeCliProcess {
            job,
            flag: state.flag.clone(),
        }))
    }
    fn resolve_target(&self, target: LaunchTarget) -> Result<SelectedApplication> {
        let names: &[&str] = match target {
            LaunchTarget::CodexDesktop => &["Codex.app", "ChatGPT.app"],
            LaunchTarget::ChatgptDesktop => &["ChatGPT.app"],
            _ => return Err(CoreError::new("invalid_target", "目标使用现有Claude适配器")),
        };
        let mut reasons = Vec::new();
        for name in names {
            let path = self.applications.join(name);
            let Ok(bundle) = fs::canonicalize(&path) else {
                reasons.push(format!("{name} 不存在"));
                continue;
            };
            let standard =
                fs::canonicalize(&self.applications).is_ok_and(|root| bundle == root.join(name));
            let cask = self
                .cask_roots
                .iter()
                .any(|root| fs::canonicalize(root).is_ok_and(|root| bundle.starts_with(root)))
                && bundle.file_name().is_some_and(|actual| actual == *name);
            if !standard && !cask {
                reasons.push(format!("{name} 安装链接不在应用目录或已知Homebrew安装范围"));
                continue;
            }
            let info = self
                .runner
                .run(
                    crate::commands::ReadCommand::Plist(path.join("Contents/Info.plist")),
                    &[],
                    Duration::from_secs(3),
                    128 * 1024,
                )
                .ok()
                .filter(|o| o.status == 0)
                .and_then(|o| crate::storage::strict_json(&o.stdout).ok());
            let Some(info) = info else {
                reasons.push(format!("{name} 元数据无法读取"));
                continue;
            };
            let id = info["CFBundleIdentifier"].as_str().unwrap_or("");
            let kind = claude_watch_core::process_roots::desktop_kind(name, id, true);
            let Some(kind) = kind.filter(|kind| target.accepts(*kind)) else {
                reasons.push(format!("{name} bundle标识与目标不符"));
                continue;
            };
            let exe = info["CFBundleExecutable"].as_str().unwrap_or("");
            if exe.is_empty()
                || exe.len() > 256
                || exe.contains(['/', '\\'])
                || matches!(exe, "." | "..")
                || exe.chars().any(char::is_control)
            {
                reasons.push(format!("{name} 可执行文件名称无效"));
                continue;
            }
            let executable = bundle.join("Contents/MacOS").join(exe);
            let Ok(executable) = fs::canonicalize(executable) else {
                reasons.push(format!("{name} 可执行文件不存在"));
                continue;
            };
            if !executable.starts_with(bundle.join("Contents/MacOS"))
                || !fs::metadata(&executable)
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            {
                reasons.push(format!("{name} 可执行文件范围或权限无效"));
                continue;
            }
            return Ok(SelectedApplication {
                path,
                bundle,
                executable,
                bundle_id: id.into(),
                kind,
            });
        }
        Err(CoreError::new(
            "target_app_unavailable",
            &format!("未找到经验证的目标应用：{}", reasons.join("；")),
        ))
    }
    pub fn observation_owner(&self) -> Result<ProcessIdentity> {
        let inventory = Observer {
            runner: &self.runner,
        }
        .inventory()?;
        inventory
            .processes
            .get(&std::process::id())
            .filter(|p| p.identity.uid == inventory.uid && p.identity.valid())
            .map(|p| p.identity.clone())
            .ok_or_else(|| {
                CoreError::new(
                    "launcher_identity_unavailable",
                    "当前启动器的原生身份未确认",
                )
            })
    }
    pub fn observation_roots(&self) -> Result<Vec<Target>> {
        let selected = self
            .selected
            .as_ref()
            .ok_or_else(|| CoreError::new("target_adapter_unavailable", "尚未绑定观察目标"))?;
        let inventory = Observer {
            runner: &self.runner,
        }
        .inventory()?;
        if !inventory.complete {
            return Err(CoreError::new(
                "target_inventory_incomplete",
                "进程清单不完整，未假定目标已关闭",
            ));
        }
        let mut roots = Vec::new();
        for p in inventory.processes.values() {
            if p.identity.uid != inventory.uid
                || p.bundle_id.as_deref() != Some(&selected.bundle_id)
            {
                continue;
            }
            let Some(bundle) = &p.bundle_path else {
                continue;
            };
            if !p
                .identity
                .executable
                .starts_with(&format!("{bundle}/Contents/MacOS/"))
            {
                continue;
            }
            if claude_watch_core::process_roots::desktop_kind(bundle, &selected.bundle_id, true)
                != Some(selected.kind)
            {
                continue;
            }
            let path = fs::canonicalize(&p.identity.executable).map_err(|_| {
                CoreError::new("target_identity_unavailable", "目标可执行文件无法复核")
            })?;
            if path != selected.executable
                || fs::canonicalize(bundle).ok().as_ref() != Some(&selected.bundle)
            {
                return Err(CoreError::new(
                    "target_running_elsewhere",
                    "同类目标正在其他安装位置运行，未补登记",
                ));
            }
            roots.push(Target {
                identity: p.identity.clone(),
                kind: selected.kind,
            });
        }
        Ok(roots)
    }
    pub fn development(runner: R, authority: Authority) -> Result<Self> {
        Self::new(
            runner,
            native::built_process_control_path()
                .ok_or_else(|| CoreError::new("unsupported_platform", "缺少arm64 macOS执行组件"))?
                .into(),
            authority,
        )
    }
    pub fn desktops(&self) -> Result<Vec<(Desktop, bool, String)>> {
        let inventory = Observer {
            runner: &self.runner,
        }
        .inventory()?;
        let mut result = Vec::new();
        for record in inventory.processes.values() {
            if record.bundle_id.as_deref() != Some("com.anthropic.claudefordesktop") {
                continue;
            }
            let Some(bundle) = &record.bundle_path else {
                continue;
            };
            let main = record
                .identity
                .executable
                .starts_with(&format!("{bundle}/Contents/MacOS/"));
            result.push((
                Desktop {
                    pid: record.identity.pid,
                    start_seconds: record.identity.start_seconds,
                    start_microseconds: record.identity.start_microseconds,
                },
                main,
                record.identity.start_stamp.clone(),
            ));
        }
        if !inventory.complete {
            return Err(CoreError::new(
                "desktop_inventory_incomplete",
                "原生进程清单未完整确认，未假定Claude已退出",
            ));
        }
        Ok(result)
    }

    pub fn desktop_alive(&self, expected: &Desktop) -> Result<bool> {
        let inventory = Observer {
            runner: &self.runner,
        }
        .inventory()?;
        if !inventory.complete {
            return Err(CoreError::new(
                "desktop_inventory_incomplete",
                "进程清单不完整，无法确认旧进程是否退出",
            ));
        }
        Ok(inventory
            .processes
            .get(&expected.pid)
            .is_some_and(|record| {
                record.identity.start_seconds == expected.start_seconds
                    && record.identity.start_microseconds == expected.start_microseconds
            }))
    }

    pub fn desktop_tree_running(&self) -> Result<bool> {
        let inventory = Observer {
            runner: &self.runner,
        }
        .inventory()?;
        if !inventory.complete {
            return Err(CoreError::new(
                "desktop_inventory_incomplete",
                "进程清单不完整，无法确认 Claude 是否完全退出",
            ));
        }
        Ok(inventory.processes.values().any(|record| {
            record.bundle_id.as_deref() == Some("com.anthropic.claudefordesktop")
                || record
                    .identity
                    .executable
                    .starts_with("/Applications/Claude.app/Contents/")
        }))
    }
    pub fn launcher(&self) -> Result<Launcher> {
        let inventory = Observer {
            runner: &self.runner,
        }
        .inventory()?;
        let identity = inventory
            .processes
            .get(&std::process::id())
            .ok_or_else(|| CoreError::new("launcher_identity_unavailable", "启动器身份未能确认"))?;
        Ok(Launcher {
            pid: identity.identity.pid,
            start: identity.identity.start_stamp.clone(),
        })
    }
    pub fn launcher_matches(&self, launcher: &Launcher) -> Result<bool> {
        let inventory = Observer {
            runner: &self.runner,
        }
        .inventory()?;
        Ok(inventory
            .processes
            .get(&launcher.pid)
            .is_some_and(|p| p.identity.start_stamp == launcher.start))
    }
    pub fn open(&self) -> Result<()> {
        if self.authority != Authority::ExplicitPermit {
            return Err(CoreError::new(
                "write_not_authorized",
                "只读运行入口不启动应用",
            ));
        }
        if !self.target.protected() {
            let selected = self
                .selected
                .as_ref()
                .ok_or_else(|| CoreError::new("target_identity_unavailable", "目标尚未绑定"))?;
            if &self.resolve_target(self.target)? != selected {
                return Err(CoreError::new(
                    "target_install_changed",
                    "预检期间目标应用安装身份变化，未启动",
                ));
            }
            return execute(
                Path::new("/usr/bin/open"),
                &[
                    "-a",
                    selected
                        .path
                        .to_str()
                        .ok_or_else(|| CoreError::new("invalid_target_path", "目标路径编码无效"))?,
                ],
                Duration::from_secs(15),
            );
        }
        let env = Observer {
            runner: &self.runner,
        }
        .environment()?;
        if env.pointer("/claude_app/bundle_id").and_then(Value::as_str)
            != Some("com.anthropic.claudefordesktop")
        {
            return Err(CoreError::new(
                "claude_identity_unavailable",
                "Claude应用安装身份未验证",
            ));
        }
        execute(
            Path::new("/usr/bin/open"),
            &["-a", "/Applications/Claude.app"],
            Duration::from_secs(15),
        )
    }
    fn require_quit_authority(&self) -> Result<()> {
        if !self.target.protected() {
            return Err(CoreError::new(
                "protected_scope_mismatch",
                "观察目标不能通过Claude退出入口关闭",
            ));
        }
        if self.authority != Authority::ExplicitPermit {
            return Err(CoreError::new(
                "write_not_authorized",
                "只读运行入口不关闭应用",
            ));
        }
        Ok(())
    }
    pub fn quit(&self) -> Result<()> {
        self.require_quit_authority()?;
        let request = execute(&self.helper, &["close-desktop"], Duration::from_secs(20));
        if !self.desktop_tree_running()? {
            return Ok(());
        }
        request?;
        Err(CoreError::new("claude_still_running", "Claude尚未完全退出"))
    }
    /// Only the confirmed IP-risk path requests the bounded force fallback.
    /// The actual process tree decides success even if another guard closed it.
    pub fn quit_for_confirmed_ip_risk(&self, forced: &mut Option<u32>) -> Result<()> {
        *forced = None;
        self.require_quit_authority()?;
        let request = execute_output(
            &self.helper,
            &["guard-close-desktop"],
            Duration::from_secs(20),
        );
        *forced = request
            .as_ref()
            .ok()
            .and_then(|bytes| crate::storage::strict_json(bytes).ok())
            .filter(|value| matches!(value["status"].as_str(), Some("ok" | "error")))
            .and_then(|value| value.get("force_requested").and_then(Value::as_u64))
            .and_then(|count| u32::try_from(count).ok())
            .filter(|count| *count <= 4096);
        if self.desktop_tree_running()? {
            request?;
            return Err(CoreError::new("claude_still_running", "Claude尚未完全退出"));
        }
        Ok(())
    }
}
pub struct DesktopRuntime<'a, R: ReadRunner, T: Transport, S: AuditSystem + ServiceSystem> {
    pub desktop: &'a NativeDesktop<R>,
    pub system: &'a mut S,
    pub network: NetworkClient<T>,
    pub storage: StateStore,
    pub started: Instant,
    pub cli: Option<NativeCliState>,
}
impl<R: ReadRunner, T: Transport, S: AuditSystem + ServiceSystem> DesktopRuntime<'_, R, T, S> {
    /// The first screen renders its environment rows from `last-audit.json`.
    /// A fresh install, or any policy change, leaves that file missing or
    /// bound to the previous digest, so `status` reports `audit: null` and
    /// every row reads "未取得" until someone presses the check button.
    /// The guard loop only publishes `guard-heartbeat.json`; nothing fills
    /// this baseline in the background. Collect it once after the daemon
    /// starts and let the UI pick it up on its next poll.
    ///
    /// `online` follows the stored policy so the rows match what an explicit
    /// check would produce. `launch` stays false: this is a baseline
    /// observation, never a launch grant.
    ///
    /// Returns `Ok(true)` when a baseline was collected, `Ok(false)` when the
    /// stored audit already matches the current policy (or the target cannot
    /// persist an observation).
    pub fn ensure_baseline_audit(&mut self) -> Result<bool> {
        let config = ConfigStore {
            storage: self.storage.clone(),
        }
        .load()?;
        let policy = crate::config_store::policy_digest(&config.value()?)?;
        let path = self.storage.paths.base().join("last-audit.json");
        let stored = self.storage.read_json(&path, Value::Null)?;
        if crate::audit_store::audit_matches_policy(&stored, &policy) {
            return Ok(false);
        }
        let audit = crate::audit_store::AuditStore::new(self.storage.clone()).collect_target(
            self.system,
            &load_system_catalog(),
            self.desktop.target(),
            crate::audit_store::AuditOptions {
                online: config.online_enabled,
                persist: true,
                launch: false,
            },
        )?;
        // `collect_target` silently skips persistence for a target it may not
        // observe; report that as "nothing to do" instead of looping.
        Ok(crate::audit_store::audit_matches_policy(&audit, &policy))
    }
}
impl<R: ReadRunner, T: Transport, S: AuditSystem + ServiceSystem> DesktopSystem
    for DesktopRuntime<'_, R, T, S>
{
    fn prepare_cli(&mut self) -> Result<()> {
        self.cli
            .as_mut()
            .ok_or_else(|| CoreError::new("cli_route_unconfirmed", "CLI路由尚未准备"))?
            .prepare()
    }
    fn cli_interrupted(&self) -> Option<i32> {
        self.cli
            .as_ref()
            .map(|s| s.flag.load(Ordering::SeqCst))
            .filter(|v| *v != 0)
            .map(|v| v as i32)
    }
    fn spawn_cli(&mut self, args: &[String]) -> Result<Box<dyn CliProcess>> {
        self.desktop.spawn_cli(
            args,
            self.cli
                .as_ref()
                .ok_or_else(|| CoreError::new("cli_route_unconfirmed", "CLI路由尚未准备"))?,
        )
    }
    fn launch_target(&self) -> LaunchTarget {
        self.desktop.target()
    }
    fn observation_roots(&mut self) -> Result<Vec<Target>> {
        self.desktop.observation_roots()
    }
    fn observation_owner(&mut self) -> Result<ProcessIdentity> {
        self.desktop.observation_owner()
    }
    fn now(&self) -> f64 {
        native::now()
    }
    fn monotonic(&self) -> Duration {
        self.started.elapsed()
    }
    fn wait(&mut self, d: Duration) {
        std::thread::sleep(d)
    }
    fn desktops(&mut self) -> Result<Vec<(Desktop, bool, String)>> {
        self.desktop.desktops()
    }
    fn desktop_alive(&mut self, desktop: &Desktop) -> Result<bool> {
        self.desktop.desktop_alive(desktop)
    }
    fn desktop_tree_running(&mut self) -> Result<bool> {
        self.desktop.desktop_tree_running()
    }
    fn launcher(&mut self) -> Result<Launcher> {
        self.desktop.launcher()
    }
    fn full_audit(&mut self) -> Result<Value> {
        let audit = AuditStore::new(self.storage.clone()).collect_target(
            self.system,
            &load_system_catalog(),
            self.desktop.target(),
            crate::audit_store::AuditOptions {
                online: true,
                persist: true,
                launch: true,
            },
        )?;
        if self.desktop.target().cli() {
            self.cli = Some(NativeCliState::new(
                audit
                    .pointer("/display_facts/local/verified_proxy_url")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            ));
        }
        Ok(audit)
    }
    fn egress(&mut self) -> Value {
        let receipt = if self.desktop.target().cli() {
            let Some(proxy) = self.cli.as_ref().and_then(|s| s.proxy.as_deref()) else {
                return serde_json::json!({"state":"unknown","error":"CLI入口未确认"});
            };
            self.network.fast_egress_via(Some(proxy))
        } else {
            self.network.fast_egress()
        };
        receipt.data.unwrap_or_else(||serde_json::json!({"state":"unknown","error":receipt.error,"observed_at":native::now(),"source":"Cloudflare trace（系统TUN，未缓存）"}))
    }
    fn local_guard(&mut self) -> Result<Value> {
        let config = ConfigStore {
            storage: self.storage.clone(),
        }
        .load()?;
        AuditSystem::local(self.system, &config)
    }
    fn backend_healthy(&mut self) -> Result<bool> {
        Ok(ServiceSystem::backend_healthy(self.system))
    }
    fn guard_backend_healthy(&mut self) -> Result<bool> {
        Ok(ServiceSystem::guard_backend_healthy(self.system))
    }
    fn launcher_matches(&mut self, l: &Launcher) -> Result<bool> {
        self.desktop.launcher_matches(l)
    }
    fn open_desktop(&mut self) -> Result<()> {
        self.desktop.open()
    }
    fn quit_desktop(&mut self) -> Result<()> {
        self.desktop.quit()
    }
    fn quit_for_confirmed_ip_risk(&mut self, forced: &mut Option<u32>) -> Result<()> {
        self.desktop.quit_for_confirmed_ip_risk(forced)
    }
}

#[cfg(test)]
mod target_contracts {
    use super::*;
    use crate::commands::{Output, ReadCommand};
    struct Reader;
    impl ReadRunner for Reader {
        fn run(&self, command: ReadCommand, _: &[u8], _: Duration, _: usize) -> Result<Output> {
            let ReadCommand::Plist(path) = command else {
                panic!("metadata-only target selection must not control processes")
            };
            Ok(Output {
                status: 0,
                stdout: fs::read(path).unwrap(),
                stderr: vec![],
            })
        }
    }
    fn app(root: &Path, name: &str, id: &str, exe: &str) {
        let bundle = root.join(name);
        fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
        fs::write(
            bundle.join("Contents/Info.plist"),
            serde_json::to_vec(
                &serde_json::json!({"CFBundleIdentifier":id,"CFBundleExecutable":exe}),
            )
            .unwrap(),
        )
        .unwrap();
        if !exe.contains('/') {
            let file = bundle.join("Contents/MacOS").join(exe);
            fs::write(&file, b"fixture executable").unwrap();
            fs::set_permissions(file, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    #[test]
    fn known_openai_bundles_are_bound_to_real_executables_and_readonly_never_opens() {
        let root = std::env::temp_dir().join(format!("cw-app-targets-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let helper = root.join("watch-process-control");
        fs::write(&helper, b"fixture").unwrap();
        app(&root, "ChatGPT.app", "com.openai.codex", "ChatGPT");
        app(&root, "Codex.app", "com.openai.codex", "Codex");
        let mut desktop = NativeDesktop::new(Reader, helper, Authority::ReadOnly).unwrap();
        desktop.applications = root.clone();
        desktop.select_target(LaunchTarget::CodexDesktop).unwrap();
        assert_eq!(desktop.selected.as_ref().unwrap().kind, Kind::CodexMain);
        fs::remove_dir_all(root.join("Codex.app")).unwrap();
        desktop.select_target(LaunchTarget::CodexDesktop).unwrap();
        assert_eq!(desktop.selected.as_ref().unwrap().kind, Kind::OpenaiMain);
        desktop.select_target(LaunchTarget::ChatgptDesktop).unwrap();
        assert_eq!(desktop.selected.as_ref().unwrap().kind, Kind::OpenaiMain);
        assert_eq!(desktop.open().unwrap_err().code, "write_not_authorized");
        assert_eq!(desktop.quit().unwrap_err().code, "protected_scope_mismatch");
        app(&root, "ChatGPT.app", "com.other.spoof", "ChatGPT");
        assert_eq!(
            desktop
                .select_target(LaunchTarget::ChatgptDesktop)
                .unwrap_err()
                .code,
            "target_app_unavailable"
        );
        app(&root, "ChatGPT.app", "com.openai.chat", "../escape");
        assert_eq!(
            desktop
                .select_target(LaunchTarget::ChatgptDesktop)
                .unwrap_err()
                .code,
            "target_app_unavailable"
        );
        use std::os::unix::fs::symlink;
        fs::remove_dir_all(root.join("ChatGPT.app")).unwrap();
        let outside = root.join("outside");
        app(&outside, "ChatGPT.app", "com.openai.chat", "ChatGPT");
        symlink(outside.join("ChatGPT.app"), root.join("ChatGPT.app")).unwrap();
        assert_eq!(
            desktop
                .select_target(LaunchTarget::ChatgptDesktop)
                .unwrap_err()
                .code,
            "target_app_unavailable"
        );
        fs::remove_file(root.join("ChatGPT.app")).unwrap();
        let cask = root.join("Caskroom");
        let version = cask.join("chatgpt/1");
        app(&version, "ChatGPT.app", "com.openai.chat", "ChatGPT");
        desktop.cask_roots = vec![cask];
        symlink(version.join("ChatGPT.app"), root.join("ChatGPT.app")).unwrap();
        desktop.select_target(LaunchTarget::ChatgptDesktop).unwrap();
        assert_eq!(desktop.selected.as_ref().unwrap().kind, Kind::ChatgptMain);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn packaged_codex_cli_requires_a_verified_app_catalog_binding() {
        let root = std::env::temp_dir().join(format!("bundled-cli-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let helper = root.join("watch-process-control");
        fs::write(&helper, b"fixture").unwrap();
        app(&root, "ChatGPT.app", "com.openai.codex", "ChatGPT");
        let mut desktop = NativeDesktop::new(Reader, helper, Authority::ReadOnly).unwrap();
        desktop.applications = root.clone();
        for relative in [
            "Contents/Resources/codex-cli/bin/codex",
            "Contents/Resources/CodexCLI.app/Contents/MacOS/codex",
            "Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex",
        ] {
            let program = root.join("ChatGPT.app").join(relative);
            fs::create_dir_all(program.parent().unwrap()).unwrap();
            fs::write(&program, b"fixture CLI").unwrap();
            fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
            let env = std::collections::BTreeMap::from([(
                "CODEX_CLI_BIN".into(),
                program.to_str().unwrap().into(),
            )]);
            desktop
                .select_cli_environment(LaunchTarget::CodexCli, &root, &env)
                .unwrap();
            assert_eq!(
                desktop.cli.as_ref().unwrap().path,
                fs::canonicalize(&program).unwrap()
            );
            let state = NativeCliState::new(Some(crate::network_client::DEFAULT_PROXY.into()));
            assert_eq!(
                desktop.spawn_cli(&[], &state).err().unwrap().code,
                "write_not_authorized"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod cli_process_contracts {
    use super::*;
    use crate::commands::{Output, ReadCommand};
    use std::{
        collections::BTreeMap,
        io::{BufRead, BufReader, Write},
        process::{Command, Stdio},
        sync::mpsc,
    };
    struct Reader;
    impl ReadRunner for Reader {
        fn run(&self, _: ReadCommand, _: &[u8], _: Duration, _: usize) -> Result<Output> {
            panic!("fixture CLI does not need app metadata or network")
        }
    }
    fn desktop(root: &Path) -> (NativeDesktop<Reader>, PathBuf) {
        let helper = root.join("watch-process-control");
        fs::write(&helper, b"fixture").unwrap();
        let mut desktop = NativeDesktop::new(Reader, helper, Authority::ExplicitPermit).unwrap();
        desktop.applications = root.join("no-apps");
        let program = root.join(".local/share/claude/versions/fixture-cli");
        fs::create_dir_all(program.parent().unwrap()).unwrap();
        (desktop, program)
    }
    #[test]
    fn cli_fixture_helper() {
        let Ok(root) = std::env::var("CW_NATIVE_CLI_FIXTURE_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let (mut desktop, program) = desktop(&root);
        let mode = std::env::var("CW_NATIVE_CLI_FIXTURE_MODE").unwrap();
        let script = if mode == "io" {
            "#!/bin/sh\nprintf 'ARG:%s\\n' \"$@\"\nIFS= read -r input\nprintf 'INPUT:%s\\n' \"$input\"\nprintf 'PROXY:%s|%s|%s|%s\\n' \"$HTTP_PROXY\" \"$HTTPS_PROXY\" \"${ALL_PROXY-unset}\" \"$NO_PROXY\"\nexit 7\n"
        } else {
            "#!/bin/sh\ntrap 'exit 0' INT TERM\nprintf 'READY:%s\\n' \"$$\"\nfor n in 1 2 3 4 5 6 7 8 9 10; do /bin/sleep 1; done\n"
        };
        fs::write(&program, script).unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        let env = BTreeMap::from([("CLAUDE_CODE_BIN".into(), program.to_str().unwrap().into())]);
        desktop
            .select_cli_environment(LaunchTarget::ClaudeCli, &root, &env)
            .unwrap();
        let mut state = NativeCliState::new(Some(crate::network_client::DEFAULT_PROXY.into()));
        state.prepare().unwrap();
        let args = if mode == "io" {
            vec!["--home".into(), "$(not-a-shell)\nsecond line".into()]
        } else {
            Vec::new()
        };
        let before = std::env::vars_os()
            .filter(|(k, _)| {
                ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"]
                    .iter()
                    .any(|v| k == *v)
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut child = desktop.spawn_cli(&args, &state).unwrap();
        let code = child.wait().unwrap();
        let after = std::env::vars_os()
            .filter(|(k, _)| {
                ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"]
                    .iter()
                    .any(|v| k == *v)
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(before, after);
        let expected = match mode.as_str() {
            "io" => 7,
            "int" => 130,
            _ => 143,
        };
        assert_eq!(code, expected);
        eprintln!("WRAPPED={code}");
    }
    #[test]
    fn native_cli_keeps_stdio_arguments_exit_and_only_changes_child_proxy_env() {
        let root = std::env::temp_dir().join(format!("cli-io-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let parent_proxy = std::env::var_os("HTTP_PROXY");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "desktop_native::cli_process_contracts::cli_fixture_helper",
                "--nocapture",
            ])
            .env("CW_NATIVE_CLI_FIXTURE_ROOT", &root)
            .env("CW_NATIVE_CLI_FIXTURE_MODE", "io")
            .env("ALL_PROXY", "http://bad.invalid:1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"fixture input\n")
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let stdout = String::from_utf8(result.stdout).unwrap();
        assert!(stdout.contains("ARG:--home\n"));
        assert!(stdout.contains("ARG:$(not-a-shell)\nsecond line\n"));
        assert!(stdout.contains("INPUT:fixture input"));
        assert!(stdout.contains(
            "PROXY:http://127.0.0.1:7890|http://127.0.0.1:7890|unset|localhost,127.0.0.1,::1"
        ));
        assert!(String::from_utf8_lossy(&result.stderr).contains("WRAPPED=7"));
        assert_eq!(std::env::var_os("HTTP_PROXY"), parent_proxy);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn native_cli_interrupts_forward_to_the_owned_fixture_child() {
        for (mode, signal, expected) in [("int", 2, 130), ("term", 15, 143)] {
            let root = std::env::temp_dir().join(format!("cli-signal-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            let mut helper = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "desktop_native::cli_process_contracts::cli_fixture_helper",
                    "--nocapture",
                ])
                .env("CW_NATIVE_CLI_FIXTURE_ROOT", &root)
                .env("CW_NATIVE_CLI_FIXTURE_MODE", mode)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let stdout = helper.stdout.take().unwrap();
            let (tx, rx) = mpsc::channel();
            let reader = std::thread::spawn(move || {
                let mut captured = String::new();
                for line in BufReader::new(stdout).lines() {
                    let line = line.unwrap();
                    captured.push_str(&line);
                    captured.push('\n');
                    if line.contains("READY:") {
                        let _ = tx.send(());
                    }
                }
                captured
            });
            if rx.recv_timeout(Duration::from_secs(8)).is_err() {
                let _ = helper.kill();
                let _ = helper.wait();
                let _ = reader.join();
                panic!("fixture child did not become ready");
            }
            assert!(Command::new("/bin/kill")
                .args([format!("-{signal}"), helper.id().to_string()])
                .status()
                .unwrap()
                .success());
            let until = Instant::now() + Duration::from_secs(5);
            let status = loop {
                if let Some(status) = helper.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() >= until {
                    let _ = helper.kill();
                    let _ = helper.wait();
                    panic!("fixture signal forwarding timed out");
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            let mut stderr = String::new();
            use std::io::Read;
            helper
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            assert!(status.success(), "{stderr}");
            assert!(stderr.contains(&format!("WRAPPED={expected}")), "{stderr}");
            reader.join().unwrap();
            fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn changed_or_untrusted_cli_files_are_refused_without_execution() {
        let root = std::env::temp_dir().join(format!("cli-identity-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let (mut desktop, program) = desktop(&root);
        fs::write(&program, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        let mut env =
            BTreeMap::from([("CLAUDE_CODE_BIN".into(), program.to_str().unwrap().into())]);
        desktop
            .select_cli_environment(LaunchTarget::ClaudeCli, &root, &env)
            .unwrap();
        let mut state = NativeCliState::new(Some(crate::network_client::DEFAULT_PROXY.into()));
        state.prepare().unwrap();
        fs::write(&program, b"changed executable").unwrap();
        assert_eq!(
            desktop.spawn_cli(&[], &state).err().unwrap().code,
            "cli_install_changed"
        );
        let other = root.join("untrusted");
        fs::write(&other, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o700)).unwrap();
        env.insert("CLAUDE_CODE_BIN".into(), other.to_str().unwrap().into());
        assert_eq!(
            desktop
                .select_cli_environment(LaunchTarget::ClaudeCli, &root, &env)
                .unwrap_err()
                .code,
            "cli_source_unverified"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
