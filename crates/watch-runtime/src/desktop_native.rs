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
    policy::PolicyCatalog,
    processes::{Identity as ProcessIdentity, Kind, LaunchTarget, Provider, Target},
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

mod close_receipt;

fn channel_process_tokens(targets: &[Target], provider: Provider) -> Vec<claude_watch_core::channel::BoundProcessToken> {
    use claude_watch_core::{channel::BoundProcessToken, processes::ProcessRole};
    let family = PolicyCatalog::family_for(provider).map(|f| f.id);
    targets.iter().filter(|t| t.identity.valid() && t.identity.uid > 0
        && t.kind.role() != ProcessRole::Launcher
        && PolicyCatalog::family_for(t.kind.provider()).map(|f| f.id) == family)
        .map(|t| BoundProcessToken::with_system_identity(t.identity.pid, t.identity.uid,
            t.identity.start_seconds, t.identity.start_microseconds, t.kind.role())).collect()
}

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
    cli: Option<SelectedCli>,
    channel_tracked: Vec<Target>,
    discovery: std::sync::Mutex<Option<crate::target_discovery::DiscoveryHandle>>,
}
#[derive(Clone, PartialEq, Eq)]
struct SelectedApplication {
    path: PathBuf,
    bundle: PathBuf,
    executable: PathBuf,
    bundle_id: String,
    kind: Kind,
    source_id: String,
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
        let applications = std::env::var_os("CW_APPLICATIONS_DIR")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute() && p.is_dir())
            .unwrap_or_else(|| "/Applications".into());
        Ok(Self {
            runner,
            helper,
            authority,
            target: LaunchTarget::ClaudeDesktop,
            selected: None,
            applications,
            cli: None,
            channel_tracked: Vec::new(),
            discovery: std::sync::Mutex::new(None),
        })
    }
    pub fn target(&self) -> LaunchTarget {
        self.target
    }
    pub fn set_applications_dir(&mut self, dir: PathBuf) {
        self.applications = dir.clone();
        let mut inputs = crate::target_discovery::DiscoveryInputs::for_home(&dir);
        inputs.application_roots = vec![dir]; inputs.query_registry = false; inputs.prefixes.clear();
        self.set_discovery(crate::target_discovery::DiscoveryHandle::new(inputs));
    }
    pub fn sandbox_launcher_binary(&self) -> Result<PathBuf> {
        if let Some(override_bin) = std::env::var_os("CW_SANDBOX_LAUNCHER_BIN") {
            let p = PathBuf::from(override_bin);
            if p.is_absolute() && p.is_file() {
                return Ok(p);
            }
        }
        let candidate = self
            .helper
            .parent()
            .map(|d| d.join("watch-sandbox-launcher"))
            .ok_or_else(|| {
                CoreError::new("sandbox_launcher_missing", "无法定位 watch-sandbox-launcher")
            })?;
        let m = fs::symlink_metadata(&candidate).map_err(|_| {
            CoreError::new("sandbox_launcher_missing", "缺少 watch-sandbox-launcher 组件")
        })?;
        if !candidate.is_absolute() || !m.is_file() || m.file_type().is_symlink() {
            return Err(CoreError::new(
                "invalid_sandbox_launcher",
                "watch-sandbox-launcher 组件路径或类型无效",
            ));
        }
        Ok(candidate)
    }
    pub fn selected_cli_path(&self) -> Option<&Path> {
        self.cli.as_ref().map(|c| c.path.as_path())
    }
    pub fn set_discovery(&mut self, discovery: crate::target_discovery::DiscoveryHandle) {
        *self.discovery.lock().unwrap() = Some(discovery);
    }
    fn discovery_for(&self, home: Option<&Path>) -> crate::target_discovery::DiscoveryHandle {
        let mut current = self.discovery.lock().unwrap();
        if let Some(handle) = current.as_ref() { return handle.clone(); }
        let home = home.map(Path::to_path_buf).or_else(||std::env::var_os("HOME").map(PathBuf::from)).unwrap_or_else(||self.applications.clone());
        let handle = crate::target_discovery::DiscoveryHandle::for_home(&home);
        *current = Some(handle.clone()); handle
    }
    pub fn build_managed_entry_spec(&self) -> Result<crate::managed_entry::DesktopManagedEntrySpec> {
        let discovery = self.discovery_for(None);
        let snapshot = discovery.refresh(&self.runner, native::now());
        let record = snapshot.select(self.target, self.selected.as_ref().map(|s|s.source_id.as_str()))?;
        discovery.managed_spec(&snapshot, record, self.target)
    }
    pub fn refresh_approved_targets_in_registry(
        &mut self, home: &Path, registry: &crate::sandbox_launch::SandboxLaunchRegistry,
    ) -> Vec<crate::managed_entry::DesktopManagedEntrySpec> {
        let discovery = self.discovery_for(Some(home));
        let snapshot = discovery.refresh(&self.runner, native::now());
        let Ok(manifest) = discovery.approved_manifest(&snapshot) else { return Vec::new(); };
        let invalidated=registry.replace_approved_targets_with_cli_sources(manifest.targets, manifest.children, manifest.cli_sources);
        registry.queue_inventory_invalidations(invalidated);
        manifest.desktop_specs
    }

    pub fn discover_bundle_child_paths(bundle_root: &Path) -> Result<Vec<PathBuf>> {
        let mut results = Vec::new();
        let frameworks_dir = bundle_root.join("Contents/Frameworks");
        if let Ok(entries) = fs::read_dir(&frameworks_dir) {
            for (index, entry) in entries.enumerate() {
                if index >= 256 { return Err(CoreError::new("discovery_budget_exhausted", "应用辅助程序目录超过发现预算")); }
                let Ok(entry) = entry else { continue };
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("app") {
                    let macos_dir = path.join("Contents/MacOS");
                    if let Ok(bins) = fs::read_dir(&macos_dir) {
                        for (index, bin_entry) in bins.enumerate() {
                            if index >= 256 { return Err(CoreError::new("discovery_budget_exhausted", "应用辅助程序目录超过发现预算")); }
                            let Ok(bin_entry) = bin_entry else { continue };
                            if let Ok(canon) = fs::canonicalize(bin_entry.path()) {
                                if canon.starts_with(bundle_root)
                                    && fs::metadata(&canon).is_ok_and(|m| {
                                        m.is_file() && (m.permissions().mode() & 0o111 != 0)
                                    })
                                {
                                    results.push(canon);
                                }
                            }
                        }
                    }
                }
            }
        }
        for rel in [
            "Contents/Resources/codex",
            "Contents/Resources/codex-cli/bin/codex",
            "Contents/Resources/CodexCLI.app/Contents/MacOS/codex",
            "Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex",
        ] {
            if let Ok(canon) = fs::canonicalize(bundle_root.join(rel)) {
                if canon.starts_with(bundle_root)
                    && fs::metadata(&canon)
                        .is_ok_and(|m| m.is_file() && (m.permissions().mode() & 0o111 != 0))
                {
                    results.push(canon);
                }
            }
        }
        results.sort(); results.dedup(); Ok(results)
    }
    pub fn discover_bundle_child_executables(bundle_root: &Path) -> Vec<(PathBuf, String)> {
        Self::discover_bundle_child_paths(bundle_root).unwrap_or_default().into_iter().filter_map(|path|
            claude_watch_system::sha256_file_hex(&path).map(|sha|(path,sha))).collect()
    }
    pub fn select_target(&mut self, target: LaunchTarget) -> Result<()> {
        self.selected = Some(self.resolve_target(target)?);
        self.target = target;
        Ok(())
    }
    /// Explicit source selection is separate from discovery and must still pass
    /// current metadata/content, registry, sandbox and permit gates.
    pub fn select_target_source(&mut self, target: LaunchTarget, path: &Path) -> Result<()> {
        let discovery = self.discovery_for(None);
        discovery.refresh(&self.runner, native::now());
        discovery.desktop_source(target,path);
        let snapshot = discovery.refresh(&self.runner, native::now());
        let record = snapshot.targets.iter().find(|r|r.entry_path == path && r.valid() && r.kind().is_some_and(|kind|target.accepts(kind)))
            .ok_or_else(||CoreError::new("selected_source_unavailable", "指定应用来源尚未验证"))?;
        discovery.choose_source(target, &record.source_id);
        if self.authority==Authority::ExplicitPermit { discovery.publish_caller_hint(target)?; }
        self.selected = Some(SelectedApplication { path:record.entry_path.clone(),bundle:record.bundle.clone().unwrap(),
            executable:record.executable.clone().unwrap(),bundle_id:record.bundle_id.clone().unwrap(),kind:record.kind().unwrap(),source_id:record.source_id.clone() });
        self.target = target; Ok(())
    }
    /// Point the guard's supervised family at a target without resolving or
    /// binding an application. The guard's observation and exit paths derive
    /// their bundle scope from `target.provider()` alone; they never read the
    /// launch-time `selected` binding, so a family may be supervised before
    /// (or without) its app being installed. Launch-time binding still goes
    /// through `select_target`, which verifies the app exists.
    pub fn set_guard_target(&mut self, target: LaunchTarget) {
        self.target = target;
    }
    pub fn select_cli(&mut self, target: LaunchTarget, home: &Path) -> Result<()> {
        let mut env = std::collections::BTreeMap::new();
        for key in [
            "PATH",
            "CLAUDE_CODE_BIN",
            "CODEX_CLI_BIN",
            "CW_SHIM_EXECUTABLE",
        ] {
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
        let discovery = self.discovery_for(Some(home));
        let (_, record) = discovery.select_cli(&self.runner, target, env, native::now())?;
        if self.authority == Authority::ExplicitPermit { discovery.publish_caller_hint(target)?; }
        let path = record.executable.unwrap();
        let fingerprint = cli_fingerprint(&path)?;
        self.cli = Some(SelectedCli { path, fingerprint });
        self.selected = None; self.target = target; Ok(())
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
    #[allow(clippy::too_many_arguments)]
    fn spawn_cli_via_sandbox_launcher(
        &self,
        args: &[String],
        state: &NativeCliState,
        launcher_bin: &Path,
        registration_socket: &Path,
        gateway_endpoint: &str,
        executor_boot_id: &str,
        policy_version: claude_watch_core::channel::PolicyVersion,
        vpn_epoch: Option<claude_watch_core::vpn::VpnEpoch>,
    ) -> Result<Box<dyn CliProcess>> {
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
        if state.handlers.len() != 2 {
            return Err(CoreError::new(
                "cli_signal_unavailable",
                "CLI中断处理尚未就绪",
            ));
        }
        let target_sha = claude_watch_system::sha256_file_hex(&selected.path)
            .ok_or_else(|| CoreError::new("cli_unavailable", "无法计算CLI可执行文件哈希"))?;
        let cwd = std::env::current_dir()
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        let req = claude_watch_core::controlled_launch::ControlledLaunchRequest {
            entry_id: crate::managed_entry::DesktopManagedEntrySpec::entry_bundle_id_for(
                self.target,
            )
            .to_string(),
            target: self.target,
            target_executable: selected.path.to_string_lossy().into_owned(),
            target_fingerprint: target_sha,
            args: args.to_vec(),
            cwd,
            proxy_adaptation: claude_watch_core::controlled_launch::ProxyAdaptationKind::EnvOnly,
            gateway_endpoint: gateway_endpoint.to_string(),
            policy_version,
            vpn_epoch,
            launch_nonce: format!("cli-nonce-{}", uuid::Uuid::new_v4()),
            executor_boot_id: executor_boot_id.to_string(),
        };
        req.validate()?;
        let req_json = serde_json::to_string(&req).map_err(|_| {
            CoreError::new("serialize_launch_request_failed", "序列化CLI受控启动请求失败")
        })?;
        let command = Exec::cmd(launcher_bin)
            .arg("--launch-json")
            .arg(&req_json)
            .arg("--registration-socket")
            .arg(registration_socket);
        let job = command.start().map_err(|_| {
            CoreError::new(
                "cli_spawn_failed",
                "受控沙箱启动器无法启动CLI子进程",
            )
        })?;
        Ok(Box::new(NativeCliProcess {
            job,
            flag: state.flag.clone(),
        }))
    }
    fn resolve_target(&self, target: LaunchTarget) -> Result<SelectedApplication> {
        if target.cli() { return Err(CoreError::new("invalid_target", "CLI 使用独立受控入口")); }
        let discovery = self.discovery_for(None);
        let snapshot = discovery.refresh(&self.runner, native::now());
        let source = if self.target == target { self.selected.as_ref().map(|s|s.source_id.as_str()) } else { None };
        let record = snapshot.select(target, source)?;
        discovery.choose_source(target, &record.source_id);
        Ok(SelectedApplication { path:record.entry_path.clone(),bundle:record.bundle.clone().unwrap(),executable:record.executable.clone().unwrap(),
            bundle_id:record.bundle_id.clone().unwrap(),kind:record.kind().unwrap(),source_id:record.source_id.clone() })
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
        let catalog = self.catalog_for_inventory(&inventory);
        let mut roots = Vec::new();
        for process in inventory.processes.values() {
            let installed=catalog.targets.iter().filter(|r|r.valid() && !r.target.cli() && r.bundle_id.as_deref()==Some(selected.bundle_id.as_str()))
                .find(|r|r.executable.as_ref().is_some_and(|exe|exe==Path::new(&process.identity.executable)));
            if let Some(installed)=installed {
                if installed.bundle.as_ref()!=Some(&selected.bundle) || installed.executable.as_ref()!=Some(&selected.executable) {
                    return Err(CoreError::new("target_running_elsewhere", "同类目标正在其他安装位置运行，未补登记"));
                }
                roots.push(Target { identity:process.identity.clone(), kind:selected.kind });
            } else if process.bundle_id.as_deref()==Some(selected.bundle_id.as_str()) && process.bundle_path.as_ref().is_some_and(|bundle|
                process.identity.executable.starts_with(&format!("{bundle}/Contents/MacOS/"))) {
                return Err(CoreError::new("target_identity_unavailable", "已有目标安装身份待确认，未重复启动"));
            }
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
        // Which desktops belong to this target is decided by its policy
        // family, not by a hardcoded bundle: the supervised service is
        // whatever the configuration supervises.
        let (bundle_ids, _) =
            claude_watch_core::process_roots::family_desktop_scopes(self.target.provider());
        let catalog = self.catalog_for_inventory(&inventory);
        let mut result = Vec::new();
        for record in inventory.processes.values() {
            let installed=catalog.targets.iter().filter(|r|!r.target.cli() && r.valid() && r.bundle_id.as_deref().is_some_and(|id|bundle_ids.contains(&id)))
                .find(|r|r.bundle.as_ref().is_some_and(|bundle|Path::new(&record.identity.executable).starts_with(bundle.join("Contents"))));
            if let Some(installed)=installed {
                result.push((Desktop { pid:record.identity.pid,start_seconds:record.identity.start_seconds,start_microseconds:record.identity.start_microseconds },
                    installed.executable.as_ref().is_some_and(|exe|exe==Path::new(&record.identity.executable)),record.identity.start_stamp.clone()));
            } else if record.bundle_id.as_deref().is_some_and(|id|bundle_ids.contains(&id)) {
                return Err(CoreError::new("desktop_installation_pending", "已有应用的安装身份待确认，未假定其已退出"));
            }
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
                "进程清单不完整，无法确认目标是否完全退出",
            ));
        }
        let catalog=self.catalog_for_inventory(&inventory);
        let (bundle_ids, _) = claude_watch_core::process_roots::family_desktop_scopes(self.target.provider());
        Ok(inventory.processes.values().any(|record|record.bundle_id.as_deref().is_some_and(|id|bundle_ids.contains(&id))
            || catalog.targets.iter().any(|r|!r.target.cli() && r.valid() && r.bundle_id.as_deref().is_some_and(|id|bundle_ids.contains(&id))
                && r.bundle.as_ref().is_some_and(|bundle|Path::new(&record.identity.executable).starts_with(bundle.join("Contents"))))))
    }
    fn catalog_for_inventory(&self,inventory:&crate::native::Inventory)->std::sync::Arc<crate::target_discovery::DiscoverySnapshot> {
        let discovery=self.discovery_for(None);
        discovery.observed_process_bundles(inventory.processes.values().filter_map(|process|
            process.bundle_path.as_ref().map(PathBuf::from).or_else(||process.identity.executable.split_once(".app/Contents/")
                .map(|(prefix,_)|PathBuf::from(format!("{prefix}.app")))).map(|path|(path,process.bundle_id.clone()))));
        discovery.refresh(&self.runner,native::now())
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
        let selected = self.selected.as_ref().ok_or_else(||CoreError::new("target_identity_unavailable", "目标尚未绑定"))?;
        if &self.resolve_target(self.target)? != selected {
            return Err(CoreError::new("target_install_changed", "预检期间目标应用安装身份变化，未启动"));
        }
        execute(Path::new("/usr/bin/open"), &["-a",selected.path.to_str().ok_or_else(||CoreError::new("invalid_target_path", "目标路径编码无效"))?],Duration::from_secs(15))
    }
    pub fn open_via_sandbox_launcher(
        &self,
        launcher_bin: &Path,
        registration_socket: &Path,
        gateway_endpoint: &str,
        executor_boot_id: &str,
        policy_version: claude_watch_core::channel::PolicyVersion,
        vpn_epoch: Option<claude_watch_core::vpn::VpnEpoch>,
    ) -> Result<()> {
        if self.authority != Authority::ExplicitPermit {
            return Err(CoreError::new(
                "write_not_authorized",
                "只读运行入口不启动应用",
            ));
        }
        if let Some(selected) = self.selected.as_ref() {
            if &self.resolve_target(self.target)? != selected {
                return Err(CoreError::new("target_install_changed", "预检期间目标应用安装身份变化，未启动"));
            }
        }
        let spec = self.build_managed_entry_spec()?;
        let req = claude_watch_core::controlled_launch::ControlledLaunchRequest {
            entry_id: spec.entry_bundle_id.clone(),
            target: spec.target,
            target_executable: spec.target_executable.to_string_lossy().into_owned(),
            target_fingerprint: spec.target_fingerprint.clone(),
            args: Vec::new(),
            cwd: None,
            proxy_adaptation: spec.proxy_adaptation,
            gateway_endpoint: gateway_endpoint.to_string(),
            policy_version,
            vpn_epoch,
            launch_nonce: format!("desktop-nonce-{}", uuid::Uuid::new_v4()),
            executor_boot_id: executor_boot_id.to_string(),
        };
        req.validate()?;
        let req_json = serde_json::to_string(&req).map_err(|_| {
            CoreError::new("serialize_launch_request_failed", "序列化桌面受控启动请求失败")
        })?;
        let mut child = std::process::Command::new(launcher_bin)
            .arg("--launch-json")
            .arg(&req_json)
            .arg("--registration-socket")
            .arg(registration_socket)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|_| {
                CoreError::new(
                    "sandbox_launcher_spawn_failed",
                    "无法启动 watch-sandbox-launcher",
                )
            })?;
        std::thread::sleep(Duration::from_millis(120));
        if let Ok(Some(status)) = child.try_wait() {
            if !status.success() {
                return Err(CoreError::new(
                    "sandbox_launch_rejected",
                    &format!(
                        "watch-sandbox-launcher 拒绝或中止了桌面应用启动 (exit={})",
                        status.code().unwrap_or(1)
                    ),
                ));
            }
        }
        Ok(())
    }
    /// The launch target this desktop adapter supervises; the policy family
    /// and every provider-specific decision derive from it.
    pub fn provider(&self) -> Provider {
        self.target.provider()
    }
    fn require_quit_authority(&self) -> Result<()> {
        // Which targets this entry may close is declared by the policy table:
        // a target outside every family is nobody's supervised service.
        if PolicyCatalog::family_for(self.target.provider()).is_none() {
            return Err(CoreError::new(
                "protected_scope_mismatch",
                "观察目标不属于受监督的服务，不能通过退出入口关闭",
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
        self.request_quit(false, &mut None)
    }
    /// Force remains an explicit upstream decision. Completion covers the
    /// helper's original identities and newly observed family members.
    pub fn quit_for_confirmed_ip_risk(&self, forced: &mut Option<u32>) -> Result<()> {
        self.request_quit(true, forced)
    }
    fn request_quit(&self, allow_force: bool, forced: &mut Option<u32>) -> Result<()> {
        *forced = None;
        self.require_quit_authority()?;
        let family = PolicyCatalog::family_for(self.target.provider()).ok_or_else(|| {
            CoreError::new("protected_scope_mismatch", "观察目标不属于受监督的服务，不能通过退出入口关闭")
        })?;
        if allow_force && !family.performable("force") {
            return Err(CoreError::new("protected_scope_mismatch", "该服务未声明强制退出能力"));
        }
        let command = if allow_force { "guard-close-desktop" } else { "close-desktop" };
        let request = execute_output(&self.helper, &[command, family.id], Duration::from_secs(20));
        close_receipt::finish(request, family.id, allow_force, forced, || self.desktop_tree_running())
    }

}
pub struct DesktopRuntime<'a, R: ReadRunner, T: Transport, S: AuditSystem + ServiceSystem> {
    pub desktop: &'a mut NativeDesktop<R>,
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

    fn resolve_seatbelt_launch_context(
        &self,
        config: &claude_watch_core::config::Config,
    ) -> Result<(
        PathBuf,
        PathBuf,
        String,
        String,
        claude_watch_core::channel::PolicyVersion,
        Option<claude_watch_core::vpn::VpnEpoch>,
    )> {
        let launcher_bin = self.desktop.sandbox_launcher_binary()?;
        let rt_path = self
            .storage
            .paths
            .watch()
            .join("state/seatbelt-runtime.json");
        let rt = self.storage.read_json(&rt_path, Value::Null)?;
        if rt.is_null() {
            return Err(CoreError::new(
                "seatbelt_daemon_unavailable",
                "Seatbelt 监管后台尚未就绪，拒绝绕过沙箱直接启动目标",
            ));
        }
        if rt["sandbox_ready"] != Value::Bool(true) {
            return Err(CoreError::new(
                "seatbelt_identity_gate_blocked",
                "Seatbelt 生产身份门禁未通过（如 I03 服务端身份未就绪），拒绝启用沙箱启动",
            ));
        }
        let gw_endpoint = rt["gateway_endpoint"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                CoreError::new("seatbelt_gateway_unavailable", "Seatbelt 受控网关地址未就绪")
            })?
            .to_string();
        let reg_sock = rt["registration_socket"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| {
                CoreError::new(
                    "seatbelt_registration_socket_unavailable",
                    "Seatbelt 注册通道地址未就绪",
                )
            })?;
        let boot_id = rt["executor_boot_id"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                CoreError::new(
                    "seatbelt_boot_id_unavailable",
                    "Seatbelt 执行器 boot_id 未就绪",
                )
            })?
            .to_string();
        let policy_version = claude_watch_core::channel::PolicyVersion {
            policy_digest: crate::config_store::policy_digest(&config.value()?)?,
            guard_policy_digest: crate::config_store::guard_policy_digest(config)?,
        };
        let obs_path = self.storage.paths.base().join("vpn-observation.json");
        let vpn_epoch = self
            .storage
            .read_json(&obs_path, Value::Null)
            .ok()
            .and_then(|v| {
                serde_json::from_value::<claude_watch_core::vpn::VpnObservation>(v).ok()
            })
            .filter(|obs| obs.is_fresh(native::now()) && obs.epoch.is_valid())
            .map(|obs| obs.epoch);
        Ok((
            launcher_bin,
            reg_sock,
            gw_endpoint,
            boot_id,
            policy_version,
            vpn_epoch,
        ))
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
        let config = ConfigStore {
            storage: self.storage.clone(),
        }
        .load()?;
        let cli_state = self
            .cli
            .as_ref()
            .ok_or_else(|| CoreError::new("cli_route_unconfirmed", "CLI路由尚未准备"))?;
        if config.effective_network_backend().is_sandbox() {
            let (launcher_bin, reg_sock, gw_endpoint, boot_id, policy_version, vpn_epoch) =
                self.resolve_seatbelt_launch_context(&config)?;
            return self.desktop.spawn_cli_via_sandbox_launcher(
                args,
                cli_state,
                &launcher_bin,
                &reg_sock,
                &gw_endpoint,
                &boot_id,
                policy_version,
                vpn_epoch,
            );
        }
        self.desktop.spawn_cli(args, cli_state)
    }
    fn launch_target(&self) -> LaunchTarget {
        self.desktop.target()
    }
    fn set_family(&mut self, family_id: &str) -> Result<()> {
        let target = claude_watch_core::policy::PolicyCatalog::family(family_id)
            .and_then(claude_watch_core::policy::PolicyCatalog::guard_target)
            .ok_or_else(|| CoreError::new("unknown_family", "策略表未声明该监督对象"))?;
        // Supervision scope is derived from the target's provider, not from a
        // resolved app bundle, so pointing the guard at a family never fails
        // when its app is not yet installed. Launch-time binding still goes
        // through `select_target`.
        self.desktop.set_guard_target(target);
        Ok(())
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
    fn supervised_processes(&mut self) -> Result<Vec<claude_watch_core::channel::BoundProcessToken>> {
        // Reuse the monitor's native root/CLI/descendant classification. A
        // desktop-only fallback would silently lose Code and orphan children.
        let mut sampler = crate::sampler::Sampler::new(&self.desktop.runner, self.storage.paths.clone());
        sampler.set_discovery(self.desktop.discovery_for(Some(&self.storage.paths.home)));
        sampler.retain_channel_targets(&self.desktop.channel_tracked);
        let round = sampler.processes()?;
        if !round.complete {
            return Err(CoreError::new("channel_inventory_incomplete", "通道进程归属尚未完整确认"));
        }
        self.desktop.channel_tracked = round.targets.clone();
        let mut tokens = channel_process_tokens(&round.targets, self.desktop.target.provider());
        for token in &mut tokens {
            let target = round.targets.iter().find(|t| t.identity.pid == token.pid)
                .ok_or_else(|| CoreError::new("channel_identity_unavailable", "通道进程身份丢失"))?;
            token.audit_token = Some(claude_watch_system::process_audit_token(token.pid, token.uid,
                token.start_seconds, token.start_microseconds, &target.identity.executable)
                .ok_or_else(|| CoreError::new("channel_identity_unavailable", "未取得当前进程的原始系统身份，通道保持阻断"))?);
        }
        Ok(tokens)
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
        let enforcer = crate::channel_enforcer::registered_production_enforcer(&self.storage.paths.watch());
        let now = native::now();
        let family_id = PolicyCatalog::family_for(self.desktop.target().provider())
            .map(|f| f.id)
            .unwrap_or("claude");

        // Bind fast diagnostics to the environment actually sampled this round.
        // Failure on a controlled path must not turn into a direct fallback.
        if let Some(ref enf) = enforcer {
            let probe: Result<Value> = (|| {
                let configs = ConfigStore { storage: self.storage.clone() };
                let config = configs.load()?;
                let local = self.system.local_for_target(&config, self.desktop.target())?;
                let context = local["context_id"].as_str().filter(|s| !s.is_empty())
                    .ok_or_else(|| CoreError::new("missing_context_id", "当前环境上下文无法确认"))?;
                let (mut data, evidence) = enf.probe_via_controlled_diagnostic_channel(family_id, context, now, |proxy| {
                    self.network.fast_egress_via(Some(proxy)).data
                        .ok_or_else(|| CoreError::new("controlled_probe_failed", "受控出口采样失败"))
                })?;
                let latest = configs.load()?;
                let after = self.system.local_for_target(&latest, self.desktop.target())?;
                if config.value()? != latest.value()? || after["context_id"].as_str() != Some(context) {
                    return Err(CoreError::new("audit_context_changed", "出口采样期间环境变化"));
                }
                data["via_controlled_path"] = serde_json::json!(true);
                data["family"] = serde_json::json!(evidence.family);
                data["upstream_endpoint"] = serde_json::json!(evidence.upstream_endpoint);
                data["context_id"] = serde_json::json!(evidence.context_id);
                data["policy_version"] = serde_json::json!(evidence.policy_version);
                data["observed_at"] = serde_json::json!(evidence.observed_at);
                Ok(data)
            })();
            return probe.unwrap_or_else(|error| serde_json::json!({
                "state":"unknown", "error":error.code, "via_controlled_path":false, "observed_at":native::now()
            }));
        }

        // Direct proxy fallback for CLI or direct config without active enforcer.
        // This is an unverified fallback path and MUST NOT be marked as via_controlled_path!
        let controlled_proxy = if self.desktop.target().cli() {
            self.cli.as_ref().and_then(|s| s.proxy.clone())
        } else {
            ConfigStore {
                storage: self.storage.clone(),
            }
            .load()
            .ok()
            .map(|c| c.proxy_url.clone())
            .filter(|p| !p.trim().is_empty())
        };

        if let Some(ref proxy) = controlled_proxy {
            let receipt = self.network.fast_egress_via(Some(proxy.as_str()));
            if let Some(mut data) = receipt.data {
                data["via_controlled_path"] = serde_json::json!(false);
                data["upstream_endpoint"] = serde_json::json!(proxy);
                return data;
            }
        }

        // Standard exit fallback: explicitly marks via_controlled_path as false
        let receipt = self.network.fast_egress();
        let mut data = receipt.data.unwrap_or_else(|| {
            serde_json::json!({
                "state": "unknown",
                "error": receipt.error,
                "observed_at": now,
                "source": "Cloudflare trace（直连未受控）"
            })
        });
        data["via_controlled_path"] = serde_json::json!(false);
        data
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
        let config = ConfigStore {
            storage: self.storage.clone(),
        }
        .load()?;
        if config.effective_network_backend().is_sandbox() {
            let (launcher_bin, reg_sock, gw_endpoint, boot_id, policy_version, vpn_epoch) =
                self.resolve_seatbelt_launch_context(&config)?;
            return self.desktop.open_via_sandbox_launcher(
                &launcher_bin,
                &reg_sock,
                &gw_endpoint,
                &boot_id,
                policy_version,
                vpn_epoch,
            );
        }
        self.desktop.open()
    }
    fn quit_desktop(&mut self) -> Result<()> {
        self.desktop.quit()
    }
    fn quit_for_confirmed_ip_risk(&mut self, forced: &mut Option<u32>) -> Result<()> {
        self.desktop.quit_for_confirmed_ip_risk(forced)
    }
    fn channel_mode(&self) -> bool {
        true
    }
    fn delegates_slow_audit_to_worker(&self) -> bool {
        crate::channel_enforcer::registered_production_enforcer(&self.storage.paths.watch())
            .is_some()
    }
    fn enforce_channel(
        &mut self,
        command: &claude_watch_core::channel::ChannelEnforcementCommand,
    ) -> Result<Option<claude_watch_core::channel::ChannelEnforcementReceipt>> {
        if let Some(enforcer) =
            crate::channel_enforcer::registered_production_enforcer(&self.storage.paths.watch())
        {
            use crate::channel_enforcer::ChannelEnforcer;
            let receipt = enforcer.apply_command(command, self.now())?;
            return Ok(Some(receipt));
        }
        let cmd_path = self
            .storage
            .paths
            .watch()
            .join(format!("state/channel-command-{}.json", command.family));
        self.storage
            .atomic_json(&cmd_path, &serde_json::to_value(command).unwrap_or(Value::Null))?;
        self.channel_receipt(&command.family)
    }
    fn channel_receipt(
        &mut self,
        family: &str,
    ) -> Result<Option<claude_watch_core::channel::ChannelEnforcementReceipt>> {
        if let Some(enforcer) =
            crate::channel_enforcer::registered_production_enforcer(&self.storage.paths.watch())
        {
            use crate::channel_enforcer::ChannelEnforcer;
            if let Some(receipt) = enforcer.receipt_for(family, self.now())? {
                return Ok(Some(receipt));
            }
        }
        let receipt_path = self
            .storage
            .paths
            .watch()
            .join(format!("state/channel-receipt-{family}.json"));
        let raw = self.storage.read_json(&receipt_path, Value::Null)?;
        if raw.is_null() {
            return Ok(None);
        }
        Ok(serde_json::from_value(raw).ok())
    }
}

#[cfg(test)]
mod target_contracts {
    use super::*;
    use crate::commands::{Output, ReadCommand};
    #[test]
    fn channel_inventory_includes_cli_and_children_without_cross_family_or_launcher() {
        use claude_watch_core::processes::ProcessRole;
        let target = |pid, kind| Target { kind, identity: ProcessIdentity {
            pid, parent: 1, uid: 501, executable: format!("/fixture/{pid}"),
            start_seconds: 100, start_microseconds: pid, start_stamp: String::new(),
        }};
        let targets = vec![target(10, Kind::ClaudeCode), target(11, Kind::ClaudeChild),
            target(12, Kind::ClaudeLauncher), target(13, Kind::CodexCli), target(14, Kind::ChatgptMain)];
        let claude = channel_process_tokens(&targets, Provider::Claude);
        assert_eq!(claude.iter().map(|p| p.pid).collect::<Vec<_>>(), [10, 11]);
        assert_eq!(claude[0].role, ProcessRole::Cli);
        assert_eq!(claude[1].role, ProcessRole::Child);
        assert_eq!(claude[0].start_microseconds, 10);
        assert_eq!(channel_process_tokens(&targets, Provider::Openai).iter().map(|p| p.pid).collect::<Vec<_>>(), [13, 14]);
    }
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
        desktop.set_applications_dir(root.clone());
        assert_eq!(desktop.select_target(LaunchTarget::CodexDesktop).unwrap_err().code,"ambiguous_source");
        desktop.select_target_source(LaunchTarget::CodexDesktop,&root.join("Codex.app")).unwrap();
        assert_eq!(desktop.selected.as_ref().unwrap().kind, Kind::CodexMain);
        fs::remove_dir_all(root.join("Codex.app")).unwrap();
        assert_eq!(desktop.select_target(LaunchTarget::CodexDesktop).unwrap_err().code,"selected_source_unavailable");
        desktop.select_target_source(LaunchTarget::CodexDesktop,&root.join("ChatGPT.app")).unwrap();
        assert_eq!(desktop.selected.as_ref().unwrap().kind, Kind::OpenaiMain);
        desktop.select_target(LaunchTarget::ChatgptDesktop).unwrap();
        assert_eq!(desktop.selected.as_ref().unwrap().kind, Kind::OpenaiMain);
        assert_eq!(desktop.open().unwrap_err().code, "write_not_authorized");
        // The target belongs to a supervised family, so the exit entry accepts
        // it in principle; only the read-only authority refuses the action.
        assert_eq!(desktop.quit().unwrap_err().code, "write_not_authorized");
        app(&root, "ChatGPT.app", "com.other.spoof", "ChatGPT");
        assert_eq!(
            desktop
                .select_target(LaunchTarget::ChatgptDesktop)
                .unwrap_err()
                .code,
            "selected_source_unavailable"
        );
        app(&root, "ChatGPT.app", "com.openai.chat", "../escape");
        assert_eq!(
            desktop
                .select_target(LaunchTarget::ChatgptDesktop)
                .unwrap_err()
                .code,
            "selected_source_unavailable"
        );
        use std::os::unix::fs::symlink;
        fs::remove_dir_all(root.join("ChatGPT.app")).unwrap();
        let outside = root.join("outside");
        app(&outside, "ChatGPT.app", "com.openai.chat", "ChatGPT");
        symlink(outside.join("ChatGPT.app"), root.join("ChatGPT.app")).unwrap();
        // A symlink to a custom installation is a candidate; its supported
        // actual ID and executable containment, rather than a prefix, decide.
        assert_eq!(desktop.select_target(LaunchTarget::ChatgptDesktop).unwrap_err().code,"selected_source_unavailable");
        desktop.select_target_source(LaunchTarget::ChatgptDesktop,&root.join("ChatGPT.app")).unwrap();
        assert_eq!(desktop.selected.as_ref().unwrap().bundle,fs::canonicalize(outside.join("ChatGPT.app")).unwrap());
        fs::remove_file(root.join("ChatGPT.app")).unwrap();
        let cask = root.join("Caskroom");
        let version = cask.join("chatgpt/1");
        app(&version, "ChatGPT.app", "com.openai.chat", "ChatGPT");
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
        desktop.set_applications_dir(root.clone());
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
        // The launcher intentionally rejects scripts. Keep these stdio/signal
        // contracts using an owned native image, without relaxing discovery.
        let source=root.join("native-cli.c");
        fs::write(&source,r#"#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static const char *env(const char *key) { const char *v=getenv(key);return v?v:"unset"; }
int main(int argc,char **argv) {
 if (FIXTURE_IO) {
  for(int i=1;i<argc;i++) printf("ARG:%s\n",argv[i]);
  char line[1024];if(!fgets(line,sizeof(line),stdin))return 99;printf("INPUT:%s",line);
  printf("PROXY:%s|%s|%s|%s\n",env("HTTP_PROXY"),env("HTTPS_PROXY"),env("ALL_PROXY"),env("NO_PROXY"));return 7;
 }
 printf("READY:%d\n",getpid());fflush(stdout);for(;;)pause();
}
"#).unwrap();
        let compiled=Command::new("xcrun").args(["clang","-Wall","-Werror"]).arg(if mode=="io"{"-DFIXTURE_IO=1"}else{"-DFIXTURE_IO=0"})
            .arg(&source).arg("-o").arg(&program).output().unwrap();
        assert!(compiled.status.success(),"{}",String::from_utf8_lossy(&compiled.stderr));
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
        fs::write(&program, b"private native discovery image; never executed").unwrap();
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
