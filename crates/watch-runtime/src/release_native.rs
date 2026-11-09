//! Native, fixed-command release adapters.  This module owns no account,
//! proxy, or guard data; it only validates and replaces the product bundle.
use crate::{
    app_lifecycle::{AppIdentity, LifecycleOs, APP_NAME, BUNDLE_ID},
    update::UpdateOs,
};
use claude_watch_core::error::{CoreError, Result};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
use subprocess::{Exec, Redirection};

const ADMIN: &str = "/Library/Application Support/ClaudeWatch/claude-watch-admin.sh";
const AGENT: &str = "io.local.claudewatch.agent";

fn error(code: &str, detail: &str) -> CoreError {
    CoreError::new(code, detail)
}
fn failed(detail: &str) -> CoreError {
    error("release_command_failed", detail)
}

/// A command is deliberately data-only, bounded, and emitted only by this
/// module.  Tests provide a recording executor; production uses `SystemExecutor`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub timeout: Duration,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}
pub trait FixedCommandExecutor {
    fn run(&mut self, command: FixedCommand) -> Result<FixedOutput>;
}
pub struct SystemExecutor;
/// `bootout` removes registration before the old process has necessarily died.
/// Replacements must observe both conditions, then repeat the observation.
pub(crate) fn stop_user_agent<E: FixedCommandExecutor>(executor: &mut E, uid: u32) -> Result<bool> {
    let job = format!("gui/{uid}/{AGENT}");
    let mut call = |program: &str, args: Vec<String>| {
        executor.run(FixedCommand {
            program: program.into(),
            args,
            timeout: Duration::from_secs(5),
        })
    };
    let initial = call("/bin/launchctl", vec!["print".into(), job.clone()])?;
    if initial.status != 0 {
        return if initial.stderr.contains("Could not find service") {
            Ok(false)
        } else {
            Err(error(
                "agent_state_unavailable",
                "后台状态读取失败，未当作未安装",
            ))
        };
    }
    let pid = initial
        .stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("pid = ")?.parse::<u32>().ok());
    if call("/bin/launchctl", vec!["bootout".into(), job.clone()])?.status != 0 {
        return Err(error("agent_stop_failed", "旧后台注销失败，未替换程序"));
    }
    let until = Instant::now() + Duration::from_secs(20);
    let mut missing_since = None;
    while Instant::now() < until {
        let registered = call("/bin/launchctl", vec!["print".into(), job.clone()])?;
        if registered.status != 0 && !registered.stderr.contains("Could not find service") {
            return Err(error("agent_state_unavailable", "旧后台退出状态无法读取"));
        }
        let processes = call("/bin/ps", vec!["-axo".into(), "pid=".into()])?;
        if processes.status != 0 || processes.stdout.trim().is_empty() {
            return Err(error(
                "agent_state_unavailable",
                "旧后台进程退出状态无法读取",
            ));
        }
        let alive = pid.is_some_and(|pid| {
            processes
                .stdout
                .lines()
                .any(|line| line.trim().parse::<u32>() == Ok(pid))
        });
        if registered.status != 0 && !alive {
            let missing = missing_since.get_or_insert_with(Instant::now);
            if missing.elapsed() >= Duration::from_secs(1) {
                return Ok(true);
            }
        } else {
            missing_since = None;
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err(error(
        "agent_stop_timeout",
        "旧后台尚未完全退出，未加载新后台",
    ))
}
/// A launchd entry can disappear before its process exits. Wait for any
/// current-user process using this exact managed runtime path; never signal an
/// unregistered process merely because its name matches.
pub(crate) fn stop_agent_for_runtime<E: FixedCommandExecutor>(
    executor: &mut E,
    uid: u32,
    runtime: &Path,
) -> Result<()> {
    stop_user_agent(executor, uid)?;
    let expected = runtime.join("watch-engine").to_string_lossy().into_owned();
    for attempt in 0..6 {
        let out = executor.run(FixedCommand {
            program: "/bin/ps".into(),
            args: vec!["-axo".into(), "pid=,uid=,comm=".into()],
            timeout: Duration::from_secs(5),
        })?;
        if out.status != 0 || out.stdout.trim().is_empty() {
            return Err(error("agent_state_unavailable", "无法确认后台进程是否退出"));
        }
        let alive = out.stdout.lines().any(|line| {
            let Some((_, rest)) = line.trim_start().split_once(char::is_whitespace) else {
                return false;
            };
            let Some((owner, exe)) = rest.trim_start().split_once(char::is_whitespace) else {
                return false;
            };
            owner.parse::<u32>() == Ok(uid) && exe.trim_start() == expected
        });
        if !alive {
            return Ok(());
        }
        if attempt < 5 {
            thread::sleep(Duration::from_millis(200));
        }
    }
    Err(error(
        "agent_process_still_running",
        "后台进程尚未退出；已保留组件及恢复记录",
    ))
}
impl FixedCommandExecutor for SystemExecutor {
    fn run(&mut self, command: FixedCommand) -> Result<FixedOutput> {
        if !command.program.is_absolute()
            || command.timeout.is_zero()
            || command.timeout > Duration::from_secs(125)
            || command
                .args
                .iter()
                .any(|x| x.len() > 4096 || x.contains(['\0', '\n', '\r']))
        {
            return Err(error("invalid_release_command", "固定系统命令参数无效"));
        }
        let started = Instant::now();
        let mut job = Exec::cmd(&command.program)
            .args(&command.args)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdout(Redirection::Pipe)
            .stderr(Redirection::Pipe)
            .start()
            .map_err(|e| {
                error(
                    "release_command_unavailable",
                    &format!("受权发布命令无法启动：{}（{e}）", command.program.display()),
                )
            })?;
        let output = match job.communicate() {
            Ok(communicator) => communicator
                .limit_time(command.timeout)
                .limit_size(1024 * 1024 + 1)
                .read(),
            Err(_) => {
                let _ = job.kill();
                if !matches!(job.wait_timeout(Duration::from_millis(500)), Ok(Some(_))) {
                    job.detach();
                }
                return Err(failed("发布命令通信失败"));
            }
        };
        let (out, err) = match output {
            Ok(output) => output,
            Err(_) => {
                // `job` is the child this executor started.  Do not leave it
                // running (or as a zombie) when the bounded read fails.
                let _ = job.kill();
                if !matches!(job.wait_timeout(Duration::from_millis(500)), Ok(Some(_))) {
                    job.detach();
                }
                return Err(error("release_command_timeout", "发布命令超时或输出过大"));
            }
        };
        if out.len().saturating_add(err.len()) > 1024 * 1024 {
            let _ = job.kill();
            if !matches!(job.wait_timeout(Duration::from_millis(500)), Ok(Some(_))) {
                job.detach();
            }
            return Err(error("release_command_timeout", "发布命令输出过大"));
        }
        let remaining = command.timeout.saturating_sub(started.elapsed());
        let waited = job.wait_timeout(remaining);
        let status = match waited {
            Err(_) => {
                let _ = job.kill();
                if !matches!(job.wait_timeout(Duration::from_millis(500)), Ok(Some(_))) {
                    job.detach();
                }
                return Err(failed("发布命令状态不可读取"));
            }
            Ok(Some(status)) => status,
            Ok(None) => {
                let _ = job.kill();
                if !matches!(job.wait_timeout(Duration::from_millis(500)), Ok(Some(_))) {
                    job.detach();
                }
                return Err(error("release_command_timeout", "发布命令未在时限内退出"));
            }
        };
        Ok(FixedOutput {
            status: status.code().map(|x| x as i32).unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out).into(),
            stderr: String::from_utf8_lossy(&err).into(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct NativeReleasePaths {
    pub base: PathBuf,
    pub watch: PathBuf,
    pub backend: PathBuf,
}
impl NativeReleasePaths {
    pub fn derive(home: &Path) -> Self {
        let base = home.join("Library/Application Support/ClaudeWatch");
        Self {
            watch: base.join("switcher"),
            backend: base.join("claude-watch.sh"),
            base,
        }
    }
}
pub struct NativeRelease<E> {
    pub executor: E,
    pub paths: NativeReleasePaths,
    pub uid: u32,
    restart_observation: Option<Option<String>>,
}
impl NativeRelease<SystemExecutor> {
    /// Concrete engine construction for an eventually authorized desktop run.
    /// Construction is side-effect free.
    pub fn production(home: &Path, desktop_uid: u32) -> Self {
        Self::new(
            SystemExecutor,
            NativeReleasePaths::derive(home),
            desktop_uid,
        )
    }
}
impl<E> NativeRelease<E> {
    pub fn new(executor: E, paths: NativeReleasePaths, uid: u32) -> Self {
        Self {
            executor,
            paths,
            uid,
            restart_observation: None,
        }
    }
}
impl<E: FixedCommandExecutor> NativeRelease<E> {
    fn run(&mut self, program: &str, args: &[String], timeout: Duration) -> Result<FixedOutput> {
        self.executor.run(FixedCommand {
            program: program.into(),
            args: args.to_vec(),
            timeout,
        })
    }
    fn require(
        &mut self,
        program: &str,
        args: &[String],
        timeout: Duration,
    ) -> Result<FixedOutput> {
        let out = self.run(program, args, timeout)?;
        if out.status == 0 {
            Ok(out)
        } else {
            Err(failed("固定发布命令返回失败"))
        }
    }
    fn job(&self) -> String {
        format!("gui/{}/{}", self.uid, AGENT)
    }
    fn plist_json(&mut self, path: &Path) -> Result<Value> {
        let out = self.require(
            "/usr/bin/plutil",
            &[
                "-convert".into(),
                "json".into(),
                "-o".into(),
                "-".into(),
                path.display().to_string(),
            ],
            Duration::from_secs(10),
        )?;
        serde_json::from_str(&out.stdout)
            .map_err(|_| error("invalid_app_bundle", "应用元数据格式无效"))
    }
    fn plist_value(&mut self, path: &Path, key: &str) -> Result<String> {
        self.plist_json(path)?
            .as_object()
            .and_then(|dict| dict.get(key))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 256)
            .map(str::to_owned)
            .ok_or_else(|| error("invalid_app_bundle", "应用元数据缺少必需字段"))
    }
    fn process_rows(&mut self) -> Result<Vec<(u32, u32, String, String)>> {
        let out = self.require(
            "/bin/ps",
            &[
                "-ww".into(),
                "-axo".into(),
                "pid=,ppid=,uid=,lstart=,comm=".into(),
            ],
            Duration::from_secs(5),
        )?;
        Ok(crate::sampler::parse_process_table(&out.stdout)?
            .into_iter()
            .filter_map(|(pid, v)| {
                Some((
                    pid,
                    u32::try_from(v["uid"].as_u64()?).ok()?,
                    v["stamp"].as_str()?.into(),
                    v["executable"].as_str()?.into(),
                ))
            })
            .collect())
    }
    fn exact_app_executable(app: &Path) -> PathBuf {
        app.join("Contents/MacOS/ClaudeWatchMonitor")
    }
    fn accessibility(&mut self, app: &Path, bundle: &str) -> Result<()> {
        if bundle != BUNDLE_ID || app != Path::new("/Applications").join(APP_NAME) {
            return Err(error(
                "invalid_app_path",
                "仅允许重置产品标准安装路径的辅助功能权限",
            ));
        }
        self.require(
            "/usr/bin/tccutil",
            &["reset".into(), "Accessibility".into(), BUNDLE_ID.into()],
            Duration::from_secs(15),
        )?;
        let _ = self.run(
            "/usr/bin/defaults",
            &[
                "delete".into(),
                BUNDLE_ID.into(),
                "accessibilityPromptedBuild".into(),
            ],
            Duration::from_secs(10),
        )?;
        Ok(())
    }
    fn agent_registered(&mut self) -> Result<bool> {
        let out = self.run(
            "/bin/launchctl",
            &["print".into(), self.job()],
            Duration::from_secs(10),
        )?;
        if out.status == 0 {
            Ok(true)
        } else if out.stderr.contains("Could not find service") {
            Ok(false)
        } else {
            Err(error(
                "agent_state_unavailable",
                "后台状态读取失败，未当作未安装",
            ))
        }
    }
    fn heartbeat(&self) -> Option<String> {
        let path = self.paths.base.join("state/heartbeat");
        let meta = fs::symlink_metadata(&path).ok()?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 4096 {
            return None;
        }
        fs::read_to_string(path).ok()
    }
    fn healthy_generation(&mut self, previous: &str) -> Result<bool> {
        let Some(raw) = self.heartbeat() else {
            return Ok(false);
        };
        let fields = raw.trim().split('|').collect::<Vec<_>>();
        if fields.len() != 5
            || fields[3] != "ok"
            || format!("{}|{}", fields[0], fields[1]) == previous
        {
            return Ok(false);
        }
        let Some(pid) = fields[0].parse::<u32>().ok() else {
            return Ok(false);
        };
        let Some(sampled) = fields[2].parse::<f64>().ok() else {
            return Ok(false);
        };
        if !(0.0..=30.0).contains(&(crate::native::now() - sampled)) {
            return Ok(false);
        }
        let job = self.run(
            "/bin/launchctl",
            &["print".into(), self.job()],
            Duration::from_secs(5),
        )?;
        let observed_job = crate::commands::loaded_agent_identity(&job.stdout);
        let job_pid = observed_job.map(|(_, pid)| pid);
        if job.status != 0 || observed_job.map(|(state, _)| state) != Some("running") {
            return Ok(false);
        }
        let snapshot_path = self.paths.base.join("state/runtime-snapshot.json");
        let metadata = match fs::symlink_metadata(&snapshot_path) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > 8 * 1024 * 1024
        {
            return Ok(false);
        }
        let snapshot = crate::storage::strict_json(
            &fs::read(snapshot_path).map_err(|_| error("agent_read_failed", "后台快照不可读取"))?,
        )?;
        let expected: claude_watch_core::processes::Identity =
            serde_json::from_value(snapshot["producer"].clone())
                .map_err(|_| error("agent_identity_invalid", "后台身份回执无效"))?;
        let observer = self.paths.base.join("runtime/watch-native-observer");
        let sent = crate::native::now();
        let observed = self.run(
            observer
                .to_str()
                .ok_or_else(|| error("invalid_runtime", "观察组件路径无效"))?,
            &["inventory".into()],
            Duration::from_secs(5),
        )?;
        if observed.status != 0 {
            return Ok(false);
        }
        let inventory = crate::native::decode_inventory(
            &crate::storage::strict_json(observed.stdout.as_bytes())?,
            sent,
            crate::native::now(),
        )?;
        let verified_worker = expected.pid == pid
            && expected.uid == self.uid
            && expected.start_stamp == fields[1]
            && expected.executable
                == self
                    .paths
                    .base
                    .join("runtime/watch-engine")
                    .to_string_lossy()
            && inventory
                .processes
                .get(&pid)
                .is_some_and(|p| p.identity.same_process(&expected));
        if !verified_worker {
            return Ok(false);
        }
        if job_pid == Some(pid) {
            return Ok(true);
        }
        // The same production snapshot verifier authenticates the supervised
        // worker relationship; release checks must not invent a weaker rule.
        let home = self
            .paths
            .base
            .ancestors()
            .nth(3)
            .ok_or_else(|| error("invalid_install_path", "后台安装根目录无效"))?
            .to_path_buf();
        let engine = self.paths.base.join("runtime/watch-engine");
        let out = self.run(
            engine
                .to_str()
                .ok_or_else(|| error("invalid_runtime", "运行组件路径无效"))?,
            &[
                "--home".into(),
                home.to_string_lossy().into_owned(),
                "snapshot".into(),
            ],
            Duration::from_secs(15),
        )?;
        if out.status != 0 {
            return Ok(false);
        }
        let receipt = crate::storage::strict_json(out.stdout.as_bytes())?;
        Ok(receipt["health"]["state"] == "running"
            && receipt["health"]["pid"] == pid
            && receipt["health"]["started"] == expected.start_stamp)
    }
    fn wait_native_publication(&mut self) -> Result<()> {
        let home = self
            .paths
            .base
            .ancestors()
            .nth(3)
            .ok_or_else(|| error("invalid_install_path", "后台安装根目录无效"))?
            .to_path_buf();
        let engine = self.paths.base.join("runtime/watch-engine");
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut detail = "后台尚未发布原生采样".to_string();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let result = self.executor.run(FixedCommand {
                program: engine.clone(),
                args: vec![
                    "--home".into(),
                    home.to_string_lossy().into_owned(),
                    "snapshot".into(),
                ],
                timeout: remaining.min(Duration::from_secs(5)),
            });
            match result {
                Ok(out) => {
                    if let Ok(value) = crate::storage::strict_json(out.stdout.as_bytes()) {
                        let current = value["capturedAt"].as_f64().is_some_and(|at| {
                            at.is_finite() && (0.0..=30.0).contains(&(crate::native::now() - at))
                        });
                        if out.status == 0
                            && current
                            && value["backendVersion"] == crate::monitor_snapshot::VERSION
                            && matches!(
                                value["health"]["state"].as_str(),
                                Some("running" | "degraded")
                            )
                            && value["health"]["pid"].as_u64().is_some_and(|p| p > 1)
                        {
                            return Ok(());
                        }
                        detail = value["health"]["detail"]
                            .as_str()
                            .or(value["message"].as_str())
                            .unwrap_or("后台尚未发布有效身份回执")
                            .chars()
                            .take(180)
                            .collect();
                    }
                }
                Err(e) => detail = e.message.chars().take(180).collect(),
            }
            thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(250)),
            );
        }
        Err(error(
            "agent_publication_unconfirmed",
            &format!("新后台未在启动时限内发布可信采样：{detail}"),
        ))
    }
}
impl<E: FixedCommandExecutor> LifecycleOs for NativeRelease<E> {
    fn inspect_installed(&mut self, path: &Path) -> Result<AppIdentity> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| error("invalid_app_bundle", "旧应用不可读取"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(error("invalid_app_bundle", "旧应用不是普通目录"));
        }
        let info = self.plist_json(&path.join("Contents/Info.plist"))?;
        if info["CFBundleIdentifier"] != BUNDLE_ID
            || info["CFBundleExecutable"] != "ClaudeWatchMonitor"
        {
            return Err(error(
                "release_identity_mismatch",
                "旧应用身份不匹配，未执行删除",
            ));
        }
        Ok(AppIdentity {
            bundle_id: BUNDLE_ID.into(),
            executable: "ClaudeWatchMonitor".into(),
            version: info["CFBundleShortVersionString"]
                .as_str()
                .unwrap_or("unknown")
                .into(),
            build: info["CFBundleVersion"].as_str().unwrap_or("unknown").into(),
            architecture: "unknown".into(),
        })
    }
    fn retire_agent(&mut self, trash: &Path) -> Result<()> {
        let home = self
            .paths
            .base
            .ancestors()
            .nth(3)
            .ok_or_else(|| error("invalid_install_path", "用户安装根路径无效"))?;
        let store = crate::storage::StateStore::new(crate::storage::Paths::new(home)?);
        let path = home.join("Library/LaunchAgents/io.local.claudewatch.agent.plist");
        store.guarded(&path)?;
        store.guarded(trash)?;
        if path.exists() {
            let definition = self.plist_json(&path)?;
            if definition["Label"] != AGENT {
                return Err(error(
                    "agent_identity_mismatch",
                    "任务定义身份不匹配，未删除",
                ));
            }
            let destination = trash.join("io.local.claudewatch.agent.plist");
            if destination.exists() {
                return Err(error("trash_conflict", "任务回收位置已经存在"));
            }
            fs::rename(path, destination)
                .map_err(|_| error("agent_retire_failed", "主后台任务定义移除失败"))?;
        }
        Ok(())
    }
    fn validate_bundle(&mut self, path: &Path) -> Result<AppIdentity> {
        let meta = fs::symlink_metadata(path)
            .map_err(|_| error("invalid_app_bundle", "应用路径不可读取"))?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(error("invalid_app_bundle", "应用路径不是普通目录"));
        }
        let get = |value: &Value, key: &str| -> Result<String> {
            value[key]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 256)
                .map(str::to_owned)
                .ok_or_else(|| error("invalid_app_bundle", "应用元数据缺少必需字段"))
        };
        let info = self.plist_json(&path.join("Contents/Info.plist"))?;
        let bundle_id = get(&info, "CFBundleIdentifier")?;
        let executable = get(&info, "CFBundleExecutable")?;
        let version = get(&info, "CFBundleShortVersionString")?;
        let build = get(&info, "CFBundleVersion")?;
        if bundle_id != BUNDLE_ID || executable != "ClaudeWatchMonitor" {
            return Err(error("release_identity_mismatch", "应用身份不匹配"));
        }
        self.require(
            "/usr/bin/codesign",
            &[
                "--verify".into(),
                "--deep".into(),
                "--strict".into(),
                path.display().to_string(),
            ],
            Duration::from_secs(30),
        )?;
        let resources = path.join("Contents/Resources");
        for binary in [
            Self::exact_app_executable(path),
            resources.join("watch-process-control"),
            resources.join("watch-engine"),
            resources.join("watch-native-observer"),
        ] {
            let out = self.require(
                "/usr/bin/lipo",
                &["-archs".into(), binary.display().to_string()],
                Duration::from_secs(10),
            )?;
            if out.stdout.split_whitespace().collect::<Vec<_>>() != ["arm64"] {
                return Err(error("release_identity_mismatch", "应用组件不是 arm64"));
            }
        }
        let manifest = self.plist_json(&resources.join("BuildInfo.plist"))?;
        if manifest["Architecture"] != "arm64"
            || manifest["ProductVersion"] != version
            || manifest["BackendVariant"] != "rust-candidate"
            || manifest["RuntimeSchema"] != 2
        {
            return Err(error(
                "release_identity_mismatch",
                "原生构建清单与应用不匹配",
            ));
        }
        let hashes = manifest["RuntimeHashes"]
            .as_object()
            .ok_or_else(|| error("invalid_app_bundle", "缺少原生组件清单"))?;
        let mut required = vec![
            "watch-engine",
            "watch-native-observer",
            "watch-process-control",
            "watch-admin.sh",
            "watch-native-collector.zsh",
        ];
        if crate::background_evidence::supported_manifest(&manifest)? {
            required.extend_from_slice(crate::background_evidence::extra_files(&manifest)?);
            let out = self.require(
                "/usr/bin/lipo",
                &[
                    "-archs".into(),
                    resources
                        .join(crate::background_evidence::WORKER)
                        .display()
                        .to_string(),
                ],
                Duration::from_secs(10),
            )?;
            if out.stdout.split_whitespace().collect::<Vec<_>>() != ["arm64"] {
                return Err(error("release_identity_mismatch", "后台检测组件不是arm64"));
            }
        }
        for component in ["watch-sandbox-launcher", "watch-gateway-broker"] {
            if manifest["NetworkBackend"] != "seatbelt" && !hashes.contains_key(component) {
                continue;
            }
            required.push(component);
            let out = self.require(
                "/usr/bin/lipo",
                &[
                    "-archs".into(),
                    resources
                        .join(component)
                        .display()
                        .to_string(),
                ],
                Duration::from_secs(10),
            )?;
            if out.stdout.split_whitespace().collect::<Vec<_>>() != ["arm64"] {
                return Err(error("release_identity_mismatch", "受控网络组件不是arm64"));
            }
        }
        if hashes.contains_key("ControlledEntry") {
            required.push("ControlledEntry");
            let out = self.require(
                "/usr/bin/lipo",
                &[
                    "-archs".into(),
                    resources
                        .join("ControlledEntry")
                        .display()
                        .to_string(),
                ],
                Duration::from_secs(10),
            )?;
            if out.stdout.split_whitespace().collect::<Vec<_>>() != ["arm64"] {
                return Err(error("release_identity_mismatch", "受控入口组件不是arm64"));
            }
        }
        if hashes.len() != required.len() || required.iter().any(|key| !hashes.contains_key(*key)) {
            return Err(error(
                "release_identity_mismatch",
                "原生组件清单不完整或含旧业务依赖",
            ));
        }
        for name in required {
            let candidate = resources.join(name);
            let meta = fs::symlink_metadata(&candidate)
                .map_err(|_| error("release_identity_mismatch", "原生组件缺失"))?;
            let expected = hashes[name].as_str().unwrap_or("");
            if !meta.is_file()
                || meta.file_type().is_symlink()
                || meta.len() > 128 * 1024 * 1024
                || expected.len() != 64
                || !expected.bytes().all(|x| x.is_ascii_hexdigit())
            {
                return Err(error("release_identity_mismatch", "原生组件清单无效"));
            }
            let actual = crate::storage::sha256(
                &fs::read(candidate)
                    .map_err(|_| error("release_identity_mismatch", "原生组件不可读取"))?,
            );
            if actual != expected {
                return Err(error("release_identity_mismatch", "原生组件校验失败"));
            }
        }
        Ok(AppIdentity {
            bundle_id,
            executable,
            version,
            build,
            architecture: "arm64".into(),
        })
    }
    fn outstanding_transaction(&mut self) -> Result<bool> {
        Ok([
            self.paths.watch.join("transaction.json"),
            self.paths.watch.join("setup-transaction.json"),
            self.paths.watch.join("update-transaction.json"),
            self.paths.watch.join("service-transaction.json"),
            self.paths.base.join("agent-install-transaction.json"),
            self.paths.base.join(".runtime.previous"),
        ]
        .iter()
        .any(|p| p.exists()))
    }
    fn stop_app(&mut self, installed: &Path) -> Result<()> {
        let target = Self::exact_app_executable(installed).display().to_string();
        for (pid, uid, stamp, executable) in self.process_rows()? {
            if uid == self.uid && executable == target {
                if !self
                    .process_rows()?
                    .iter()
                    .any(|r| r.0 == pid && r.1 == uid && r.2 == stamp && r.3 == executable)
                {
                    continue;
                }
                self.require(
                    "/bin/kill",
                    &["-TERM".into(), pid.to_string()],
                    Duration::from_secs(5),
                )?;
            }
        }
        let until = Instant::now() + Duration::from_secs(15);
        while Instant::now() < until {
            if !self
                .process_rows()?
                .iter()
                .any(|(_, uid, _, x)| *uid == self.uid && x == &target)
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(200));
        }
        Err(error("app_stop_timeout", "监控界面未退出，未替换程序"))
    }
    fn stop_agent(&mut self) -> Result<bool> {
        stop_user_agent(&mut self.executor, self.uid)
    }
    fn install_agent(&mut self, installed: &Path) -> Result<()> {
        self.validate_bundle(installed)?;
        let home = self
            .paths
            .base
            .ancestors()
            .nth(3)
            .ok_or_else(|| error("invalid_install_path", "原生后台安装根目录无效"))?
            .to_path_buf();
        let store = crate::storage::StateStore::new(crate::storage::Paths::new(&home)?);
        if store.paths.watch() != self.paths.base {
            return Err(error(
                "invalid_install_path",
                "原生后台安装路径不属于本用户",
            ));
        }
        crate::agent_install::install_deferred(
            &store,
            &installed.join("Contents/Resources"),
            self.uid,
            &mut self.executor,
        )?;
        self.wait_native_publication()
    }
    fn commit_agent_install(&mut self) -> Result<()> {
        let home = self
            .paths
            .base
            .ancestors()
            .nth(3)
            .ok_or_else(|| error("invalid_install_path", "安装根目录无效"))?;
        let store = crate::storage::StateStore::new(crate::storage::Paths::new(home)?);
        crate::agent_install::commit(&store, self.uid, &mut self.executor)?;
        Ok(())
    }
    fn rollback_agent_install(&mut self) -> Result<()> {
        let home = self
            .paths
            .base
            .ancestors()
            .nth(3)
            .ok_or_else(|| error("invalid_install_path", "安装根目录无效"))?;
        let store = crate::storage::StateStore::new(crate::storage::Paths::new(home)?);
        crate::agent_install::recover(&store, self.uid, &mut self.executor)?;
        Ok(())
    }
    fn resume_agent(&mut self, _installed: &Path) -> Result<()> {
        if self.agent_registered()? {
            return Ok(());
        }
        let home = self
            .paths
            .base
            .ancestors()
            .nth(3)
            .ok_or_else(|| error("invalid_install_path", "安装根目录无效"))?;
        let plist = home.join("Library/LaunchAgents/io.local.claudewatch.agent.plist");
        self.require(
            "/bin/launchctl",
            &[
                "bootstrap".into(),
                format!("gui/{}", self.uid),
                plist.display().to_string(),
            ],
            Duration::from_secs(20),
        )?;
        Ok(())
    }
    fn reset_product_accessibility(&mut self) -> Result<()> {
        self.accessibility(&Path::new("/Applications").join(APP_NAME), BUNDLE_ID)
    }
}
impl<E: FixedCommandExecutor> UpdateOs for NativeRelease<E> {
    fn architecture(&mut self) -> Result<String> {
        let out = self.require("/usr/bin/uname", &["-m".into()], Duration::from_secs(5))?;
        if out.stdout.trim() == "arm64" {
            Ok("arm64".into())
        } else {
            Err(error("architecture_mismatch", "当前设备不是 arm64"))
        }
    }
    fn verify_app(&mut self, path: &Path, version: &str) -> Result<()> {
        let app = self.validate_bundle(path)?;
        if app.version == version {
            Ok(())
        } else {
            Err(error(
                "release_identity_mismatch",
                "应用版本与签名清单不匹配",
            ))
        }
    }
    fn health(&mut self) -> Result<()> {
        let program = self.paths.base.join("runtime/watch-engine");
        let out = self.require(
            program
                .to_str()
                .ok_or_else(|| error("invalid_runtime", "运行组件路径无效"))?,
            &["self-check".into()],
            Duration::from_secs(15),
        )?;
        let receipt = crate::storage::strict_json(out.stdout.as_bytes())?;
        if receipt["status"] == "ok"
            && receipt["engine"] == "rust"
            && receipt["component_integrity"] == true
        {
            Ok(())
        } else {
            Err(error("update_health_failed", "原生运行组件自检未通过"))
        }
    }
    fn installed_version(&mut self, app: &Path) -> Result<String> {
        self.plist_value(
            &app.join("Contents/Info.plist"),
            "CFBundleShortVersionString",
        )
    }
    fn macos_version(&mut self) -> Result<(u64, u64)> {
        let out = self.require(
            "/usr/bin/sw_vers",
            &["-productVersion".into()],
            Duration::from_secs(5),
        )?;
        let mut p = out.stdout.trim().split('.');
        Ok((
            p.next()
                .and_then(|x| x.parse().ok())
                .ok_or_else(|| error("os_version_invalid", "macOS版本无效"))?,
            p.next().and_then(|x| x.parse().ok()).unwrap_or(0),
        ))
    }
    fn app_running(&mut self, app: &Path) -> Result<bool> {
        let target = Self::exact_app_executable(app).display().to_string();
        Ok(self
            .process_rows()?
            .iter()
            .any(|(_, uid, _, x)| *uid == self.uid && x == &target))
    }
    fn root_helper_hash(&mut self) -> Result<Option<String>> {
        let p = Path::new(ADMIN);
        if !p.exists() {
            return Ok(None);
        };
        let m = fs::symlink_metadata(p)
            .map_err(|_| error("root_helper_invalid", "系统组件不可读取"))?;
        if m.file_type().is_symlink() || !m.is_file() {
            return Err(error("root_helper_invalid", "系统组件不是普通文件"));
        }
        let bytes = fs::read(p).map_err(|_| error("root_helper_invalid", "系统组件不可读取"))?;
        Ok(Some(crate::storage::sha256(&bytes)))
    }
    fn reset_accessibility(&mut self, app: &Path, bundle: &str) -> Result<()> {
        self.accessibility(app, bundle)
    }
    fn restart_agent(&mut self) -> Result<()> {
        if !self.agent_registered()? {
            self.restart_observation = Some(None);
            return Ok(());
        }
        let previous = self
            .heartbeat()
            .map(|v| v.trim().split('|').take(2).collect::<Vec<_>>().join("|"))
            .unwrap_or_default();
        self.restart_observation = Some(Some(previous));
        self.require(
            "/bin/launchctl",
            &["kickstart".into(), "-k".into(), self.job()],
            Duration::from_secs(15),
        )?;
        Ok(())
    }
    fn agent_healthy(&mut self) -> Result<bool> {
        match self.restart_observation.clone() {
            // Preserve an explicitly observed unloaded agent, as the mature updater does.
            Some(None) => Ok(!self.agent_registered()?),
            Some(Some(previous)) => {
                let deadline = Instant::now() + Duration::from_secs(15);
                while Instant::now() < deadline {
                    if self.healthy_generation(&previous)? {
                        return Ok(true);
                    }
                    thread::sleep(Duration::from_millis(250));
                }
                Ok(false)
            }
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod startup_publication_tests {
    use super::*;
    struct Publisher {
        calls: Vec<FixedCommand>,
    }
    impl FixedCommandExecutor for Publisher {
        fn run(&mut self, c: FixedCommand) -> Result<FixedOutput> {
            self.calls.push(c);
            let attempt = self.calls.len();
            let at = crate::native::now();
            let value = match attempt {
                1 => {
                    serde_json::json!({"capturedAt":at,"backendVersion":crate::monitor_snapshot::VERSION,"health":{"state":"unavailable","detail":"publisher pending","pid":0}})
                }
                2 => {
                    serde_json::json!({"capturedAt":at-60.0,"backendVersion":crate::monitor_snapshot::VERSION,"health":{"state":"running","pid":22}})
                }
                _ => {
                    serde_json::json!({"capturedAt":at,"backendVersion":crate::monitor_snapshot::VERSION,"health":{"state":"degraded","pid":22}})
                }
            };
            Ok(FixedOutput {
                status: 0,
                stdout: value.to_string(),
                stderr: String::new(),
            })
        }
    }
    #[test]
    fn install_waits_for_fresh_trusted_publication_without_calling_it_launch_permission() {
        let home = Path::new("/fixture/user");
        let mut release = NativeRelease::new(
            Publisher { calls: vec![] },
            NativeReleasePaths::derive(home),
            501,
        );
        release.wait_native_publication().unwrap();
        assert_eq!(release.executor.calls.len(), 3);
        for c in &release.executor.calls {
            assert_eq!(
                c.program,
                home.join("Library/Application Support/ClaudeWatch/runtime/watch-engine")
            );
            assert_eq!(c.args, ["--home", "/fixture/user", "snapshot"]);
            assert!(c.timeout <= Duration::from_secs(5));
        }
    }
}
