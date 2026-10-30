//! Fixed macOS mutations and conflict-safe restoration.
//!
//! This module owns the only write-side command vocabulary.  Callers hand it
//! a previewed action, never a program name or shell fragment.  The runner is
//! injectable so the transaction contract is testable without touching macOS.
#![forbid(unsafe_code)]

use crate::macos::Mutator;
use claude_watch_core::error::{CoreError, Result};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use subprocess::{Exec, Job, Redirection};

const ADMIN: &str = "/Library/Application Support/ClaudeWatch/claude-watch-admin.sh";
const UPDATE_LABEL: &str = "io.local.claudewatch.update";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const ADMIN_TIMEOUT: Duration = Duration::from_secs(185);
const COMMAND_OUTPUT_LIMIT: usize = 64 * 1024;

fn err(code: &str, message: &str) -> CoreError {
    CoreError::new(code, message)
}

fn bounded_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.contains(['\n', '\r', '\0'])
}

fn zone(value: &str) -> bool {
    bounded_text(value)
        && value.contains('/')
        && !value.starts_with('/')
        && !value.contains("..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'+' | b'-'))
}

fn locale(value: &str) -> bool {
    bounded_text(value)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'@' | b'=' | b'.'))
}

fn service(value: &str) -> bool {
    bounded_text(value) && value.len() <= 128
}

fn language(value: &str) -> bool {
    let mut segments = value.split(['-', '_']);
    matches!(segments.next(), Some(first) if first.len() >= 2 && first.len() <= 3)
        && segments.all(|part| {
            !part.is_empty() && part.len() <= 8 && part.bytes().all(|b| b.is_ascii_alphanumeric())
        })
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminCommand {
    Timezone(String),
    Ipv6Off(String),
    Ipv6Automatic(String),
    FlushDns,
    Watchdog(Option<String>),
    /// Explicit maintenance operations.  They are deliberately not reachable
    /// from the repair mutator, but keep the native vocabulary aligned with
    /// the fixed root helper.
    Status,
    LegacyStop,
    Uninstall,
}

/// A fully fixed administrator request.  Exposing this value lets contract
/// tests inspect the privilege boundary without ever invoking `osascript`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAuthorizationPlan {
    pub program: String,
    pub args: Vec<String>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultsCommand {
    Locale(String),
    Languages(Vec<String>),
    DeleteLanguages,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateRead {
    Timezone,
    Locale,
    Languages,
    Ipv6(String),
    Watchdog,
    Updater,
}

/// The bounded command interface used by the mutator.  Implementations never
/// receive a shell program or unvalidated argv from a plan.
pub trait MutationRunner: Send {
    fn admin(&mut self, command: AdminCommand) -> Result<()>;
    fn defaults(&mut self, command: DefaultsCommand) -> Result<()>;
    fn updater(&mut self, enabled: bool) -> Result<()>;
    fn read(&mut self, state: StateRead) -> Result<Value>;
}

#[derive(Debug, Clone)]
pub struct MutationPaths {
    pub home: PathBuf,
    pub watch: PathBuf,
}

impl MutationPaths {
    pub fn new(home: PathBuf, watch: PathBuf) -> Result<Self> {
        if !home.is_absolute() || !watch.is_absolute() {
            return Err(err("invalid_mutation_paths", "系统变更路径必须是绝对路径"));
        }
        Ok(Self { home, watch })
    }

    fn updater_plist(&self) -> PathBuf {
        self.home
            .join("Library/LaunchAgents/io.local.claudewatch.update.plist")
    }
}

/// Native implementation.  It launches only absolute, fixed binaries and
/// writes a fixed launchd definition whose variable path is supplied by the
/// trusted application host, not by an action payload.
pub struct NativeMutationRunner {
    paths: MutationPaths,
}

impl NativeMutationRunner {
    pub fn new(paths: MutationPaths) -> Self {
        Self { paths }
    }
    fn registered(&self, label: &str) -> Result<bool> {
        use crate::release_native::FixedCommandExecutor;
        let out =
            crate::release_native::SystemExecutor.run(crate::release_native::FixedCommand {
                program: "/bin/launchctl".into(),
                args: vec!["print".into(), label.into()],
                timeout: COMMAND_TIMEOUT,
            })?;
        if out.status == 0 {
            Ok(true)
        } else if out.stderr.contains("Could not find service") {
            Ok(false)
        } else {
            Err(err("mutation_read_failed", "后台状态读取失败，未当作停用"))
        }
    }

    fn stop_owned_child(job: Job) {
        let _ = job.kill();
        if !matches!(job.wait_timeout(Duration::from_millis(500)), Ok(Some(_))) {
            job.detach();
        }
    }

    /// Execute a fixed native command with bounded I/O and lifetime.  A timed
    /// out command is killed and reaped (or detached only if reaping fails),
    /// so a failed mutation cannot leave a synchronously-owned child behind.
    fn execute(program: &str, args: &[String]) -> Result<(bool, Vec<u8>)> {
        Self::execute_input_timeout(program, args, Vec::new(), COMMAND_TIMEOUT)
    }

    fn execute_input(program: &str, args: &[String], input: Vec<u8>) -> Result<(bool, Vec<u8>)> {
        Self::execute_input_timeout(program, args, input, COMMAND_TIMEOUT)
    }

    fn execute_input_timeout(
        program: &str,
        args: &[String],
        input: Vec<u8>,
        timeout: Duration,
    ) -> Result<(bool, Vec<u8>)> {
        let started = Instant::now();
        let mut job = Exec::cmd(program)
            .args(args)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(input)
            .stdout(Redirection::Pipe)
            .stderr(Redirection::Pipe)
            .start()
            .map_err(|_| err("mutation_unavailable", "受权系统操作无法启动"))?;
        let result = job.communicate().and_then(|comm| {
            comm.limit_time(timeout)
                .limit_size(COMMAND_OUTPUT_LIMIT + 1)
                .read()
        });
        let (stdout, stderr) = match result {
            Ok(value) if value.0.len() + value.1.len() <= COMMAND_OUTPUT_LIMIT => value,
            Ok(_) => {
                Self::stop_owned_child(job);
                return Err(err("mutation_output_oversize", "系统操作输出超过资源上限"));
            }
            Err(_) => {
                Self::stop_owned_child(job);
                return Err(err("mutation_timeout", "系统操作超时或通信失败"));
            }
        };
        let remaining = timeout.saturating_sub(started.elapsed());
        let status = match job.wait_timeout(remaining) {
            Ok(Some(status)) => status,
            Ok(None) => {
                Self::stop_owned_child(job);
                return Err(err("mutation_timeout", "系统操作未在时限内退出"));
            }
            Err(_) => {
                Self::stop_owned_child(job);
                return Err(err("mutation_wait_failed", "系统操作退出状态不可读取"));
            }
        };
        let _ = stderr; // Fixed commands do not surface untrusted diagnostic text.
        Ok((status.success(), stdout))
    }

    fn status(program: &str, args: &[String]) -> Result<()> {
        if Self::execute(program, args)?.0 {
            Ok(())
        } else {
            Err(err("mutation_failed", "受权系统操作失败"))
        }
    }

    fn output(program: &str, args: &[String]) -> Result<String> {
        let (success, stdout) = Self::execute(program, args)?;
        if success {
            String::from_utf8(stdout).map_err(|_| err("mutation_read_failed", "系统状态不是 UTF-8"))
        } else {
            Err(err("mutation_read_failed", "系统状态读取失败"))
        }
    }

    fn uid(&self) -> Result<String> {
        let uid = Self::output("/usr/bin/id", &["-u".into()])?;
        let uid = uid.trim();
        if uid.is_empty() || !uid.bytes().all(|b| b.is_ascii_digit()) {
            return Err(err("mutation_read_failed", "当前用户身份不可用"));
        }
        Ok(uid.into())
    }

    fn updater_xml(&self) -> Result<String> {
        let engine = self.paths.watch.join("runtime/watch-engine");
        if !engine.is_file() {
            return Err(err("runtime_missing", "先安装完整后台运行组件"));
        }
        let engine = engine
            .to_str()
            .filter(|v| !v.contains(['&', '<', '>', '\0']))
            .ok_or_else(|| err("invalid_mutation_paths", "后台路径不可用于固定服务定义"))?;
        Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>{UPDATE_LABEL}</string><key>ProgramArguments</key><array><string>{engine}</string><string>update</string><string>--auto</string><string>--apply</string></array><key>StartInterval</key><integer>43200</integer><key>RunAtLoad</key><false/></dict></plist>"))
    }

    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\\"'\\\"'"))
    }

    fn admin_args(command: AdminCommand) -> Result<Vec<String>> {
        let args = match command {
            AdminCommand::Timezone(value) if zone(&value) => vec!["timezone".into(), value],
            AdminCommand::Ipv6Off(value) if service(&value) => {
                vec!["ipv6".into(), value, "off".into()]
            }
            AdminCommand::Ipv6Automatic(value) if service(&value) => {
                vec!["ipv6".into(), value, "automatic".into()]
            }
            AdminCommand::FlushDns => vec!["flush-dns".into()],
            AdminCommand::Watchdog(Some(value)) if zone(&value) => vec!["watchdog".into(), value],
            AdminCommand::Watchdog(None) => vec!["watchdog".into(), "off".into()],
            AdminCommand::Status => vec!["status".into()],
            AdminCommand::LegacyStop => vec!["legacy-stop".into()],
            AdminCommand::Uninstall => vec!["uninstall".into()],
            _ => return Err(err("invalid_admin_action", "无效管理员操作")),
        };
        Ok(args)
    }

    fn bundled_helper(&self) -> Option<PathBuf> {
        // Installed Rust runtime is the normal source.  A bundled application
        // may invoke the binary directly before the runtime is installed.
        let installed = self.paths.watch.join("runtime/watch-admin.sh");
        if installed.is_file() {
            return Some(installed);
        }
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|p| p.join("watch-admin.sh")))
            .filter(|p| p.is_file())
    }

    fn trusted_root_helper() -> Result<Option<String>> {
        let target = Path::new(ADMIN);
        let meta = match fs::symlink_metadata(target) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(err("unsafe_admin_helper", "系统辅助组件不可读取")),
        };
        if !meta.is_file()
            || meta.file_type().is_symlink()
            || meta.uid() != 0
            || (meta.mode() & 0o022) != 0
        {
            return Err(err(
                "unsafe_admin_helper",
                "系统辅助组件不是受信任的 root 文件",
            ));
        }
        let hash = crate::storage::sha256(
            &fs::read(target).map_err(|_| err("unsafe_admin_helper", "系统辅助组件不可读取"))?,
        );
        Ok(Some(hash))
    }

    fn compile_admin_script(
        args: Vec<String>,
        source: Option<&Path>,
        install: bool,
    ) -> Result<AdminAuthorizationPlan> {
        let verb = args
            .first()
            .ok_or_else(|| err("invalid_admin_action", "无效管理员操作"))?
            .clone();
        let target = Self::shell_quote(ADMIN);
        let mut commands = vec!["cd /private/tmp".into()];
        if install {
            let source = source
                .and_then(Path::to_str)
                .ok_or_else(|| err("invalid_mutation_paths", "系统辅助组件路径无效"))?;
            let parent = Self::shell_quote("/Library/Application Support/ClaudeWatch");
            let incoming = Self::shell_quote(&format!("{ADMIN}.incoming"));
            let expected =
                crate::storage::sha256(include_bytes!("../../../monitor/Resources/watch-admin.sh"));
            commands.extend([
                format!("test ! -L {parent}"), format!("/usr/bin/install -d -o root -g wheel -m 755 {parent}"),
                format!("test ! -L {target} && test ! -L {incoming}"),
                format!("/usr/bin/install -o root -g wheel -m 755 {} {incoming}", Self::shell_quote(source)),
                format!("test \"$(/usr/bin/shasum -a 256 {incoming} | /usr/bin/awk '{{print $1}}')\" = {expected}"), format!("/bin/mv -f {incoming} {target}"),
            ]);
        }
        let helper_args = std::iter::once(ADMIN.to_owned())
            .chain(args)
            .map(|v| Self::shell_quote(&v))
            .collect::<Vec<_>>()
            .join(" ");
        commands.push(format!("/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash --noprofile --norc {helper_args}"));
        let prompt = if install || verb == "status" {
            "Claude Watch：安装或升级固定系统组件并执行已确认操作"
        } else {
            "Claude Watch：应用已预览的系统配置变更"
        };
        let script = format!("with timeout of 180 seconds\n do shell script {} with prompt {} with administrator privileges\nend timeout", serde_json::to_string(&commands.join(" && ")).expect("fixed string"), serde_json::to_string(prompt).expect("fixed string"));
        Ok(AdminAuthorizationPlan {
            program: "/usr/bin/osascript".into(),
            args: vec!["-e".into(), script],
            timeout: ADMIN_TIMEOUT,
        })
    }

    /// Builds, but does not execute, the fixed AppleScript request.  The
    /// bundled bytes are a compile-time pin; a locally modified runtime helper
    /// cannot be promoted to root even when its path is otherwise trusted.
    pub fn admin_authorization_plan(
        &self,
        command: AdminCommand,
    ) -> Result<AdminAuthorizationPlan> {
        let args = Self::admin_args(command)?;
        let verb = args[0].clone();
        let current = Self::trusted_root_helper()?;
        let source = self.bundled_helper();
        let expected =
            crate::storage::sha256(include_bytes!("../../../monitor/Resources/watch-admin.sh"));
        if let Some(source) = source.as_ref() {
            let meta = fs::symlink_metadata(source)
                .map_err(|_| err("admin_helper_missing", "缺少系统辅助组件"))?;
            if !meta.is_file()
                || meta.file_type().is_symlink()
                || crate::storage::sha256(
                    &fs::read(source)
                        .map_err(|_| err("admin_helper_missing", "缺少系统辅助组件"))?,
                ) != expected
            {
                return Err(err(
                    "admin_helper_untrusted",
                    "随附系统辅助组件未通过完整性校验",
                ));
            }
        } else if verb != "uninstall" {
            return Err(err("admin_helper_missing", "缺少系统辅助组件"));
        }
        // A mismatch is never silently replaced.  `status` is the explicit
        // refresh operation, matching the mature UI's "refresh-admin" path.
        if current.as_deref().is_some_and(|hash| hash != expected)
            && !matches!(verb.as_str(), "status" | "uninstall")
        {
            return Err(err(
                "admin_update_required",
                "系统组件版本不同；请先明确选择升级系统辅助组件",
            ));
        }
        Self::compile_admin_script(
            args,
            source.as_deref(),
            current.is_none() || verb == "status",
        )
    }
}

impl MutationRunner for NativeMutationRunner {
    fn admin(&mut self, command: AdminCommand) -> Result<()> {
        let plan = self.admin_authorization_plan(command)?;
        // Emit only after validating the fixed helper and immediately before
        // the actual macOS administrator request, never during egress reads.
        crate::setup_progress::emit(crate::setup_progress::Phase::RequestAdministrator);
        if Self::execute_input_timeout(&plan.program, &plan.args, Vec::new(), plan.timeout)?.0 {
            Ok(())
        } else {
            Err(err("mutation_failed", "受权系统操作失败"))
        }
    }

    fn defaults(&mut self, command: DefaultsCommand) -> Result<()> {
        let args: Vec<String> = match command {
            DefaultsCommand::Locale(locale) => {
                vec!["write".into(), "-g".into(), "AppleLocale".into(), locale]
            }
            DefaultsCommand::Languages(languages) => {
                let mut out = vec![
                    "write".into(),
                    "com.anthropic.claudefordesktop".into(),
                    "AppleLanguages".into(),
                    "-array".into(),
                ];
                out.extend(languages);
                out
            }
            DefaultsCommand::DeleteLanguages => vec![
                "delete".into(),
                "com.anthropic.claudefordesktop".into(),
                "AppleLanguages".into(),
            ],
        };
        Self::status("/usr/bin/defaults", &args)
    }

    fn updater(&mut self, enabled: bool) -> Result<()> {
        let uid = self.uid()?;
        let domain = format!("gui/{uid}");
        let label = format!("{domain}/{UPDATE_LABEL}");
        let plist = self.paths.updater_plist();
        let plist_text = plist
            .to_str()
            .ok_or_else(|| err("invalid_mutation_paths", "更新任务路径无效"))?;
        let store = crate::storage::StateStore::new(crate::storage::Paths::new(&self.paths.home)?);
        store.guarded(&plist)?;
        let definition = if enabled {
            Some(self.updater_xml()?)
        } else {
            None
        };
        if self.registered(&label)? {
            Self::status("/bin/launchctl", &["bootout".into(), label.clone()])?;
        }
        if enabled {
            store.atomic_bytes(&plist, definition.as_ref().unwrap().as_bytes(), 0o600)?;
            Self::status(
                "/bin/launchctl",
                &["bootstrap".into(), domain, plist_text.into()],
            )
        } else if plist.exists() {
            fs::remove_file(&plist).map_err(|_| err("mutation_failed", "无法移除更新任务定义"))
        } else {
            Ok(())
        }
    }

    fn read(&mut self, state: StateRead) -> Result<Value> {
        match state {
            StateRead::Timezone => {
                let target = Self::output("/usr/bin/readlink", &["/etc/localtime".into()])?;
                Ok(json!(target
                    .trim()
                    .strip_prefix("/var/db/timezone/zoneinfo/")
                    .unwrap_or("")))
            }
            StateRead::Locale => Ok(json!(Self::output(
                "/usr/bin/defaults",
                &["read".into(), "-g".into(), "AppleLocale".into()]
            )?
            .trim())),
            StateRead::Languages => {
                // `defaults read` is a display format, not a typed contract: a
                // one-element array may be emitted as only a quoted line. Export
                // the domain and let fixed `plutil` produce JSON instead. A
                // missing domain/key is represented as null, never as an
                // invented default or an empty array.
                let (exported, plist) = Self::execute(
                    "/usr/bin/defaults",
                    &[
                        "export".into(),
                        "com.anthropic.claudefordesktop".into(),
                        "-".into(),
                    ],
                )?;
                if !exported {
                    return Ok(Value::Null);
                }
                let (found, raw) = Self::execute_input(
                    "/usr/bin/plutil",
                    &[
                        "-extract".into(),
                        "AppleLanguages".into(),
                        "json".into(),
                        "-o".into(),
                        "-".into(),
                        "-".into(),
                    ],
                    plist,
                )?;
                if !found {
                    return Ok(Value::Null);
                }
                let values: Value = serde_json::from_slice(&raw)
                    .map_err(|_| err("mutation_read_failed", "应用语言状态不是 JSON"))?;
                let valid = values.as_array().is_some_and(|items| {
                    items.iter().all(|item| item.as_str().is_some_and(language))
                });
                if !valid {
                    return Err(err("mutation_read_failed", "应用语言状态无效"));
                }
                Ok(values)
            }
            StateRead::Ipv6(service) => {
                let raw = Self::output("/usr/sbin/networksetup", &["-getinfo".into(), service])?;
                let value = raw
                    .lines()
                    .find_map(|line| line.trim().strip_prefix("IPv6:").map(str::trim))
                    .unwrap_or("");
                Ok(json!(if value.eq_ignore_ascii_case("automatic") {
                    "automatic"
                } else if value.eq_ignore_ascii_case("off") {
                    "off"
                } else {
                    "unknown"
                }))
            }
            StateRead::Watchdog => {
                let target =
                    fs::read_to_string("/Library/Application Support/ClaudeWatch/timezone.target")
                        .ok()
                        .map(|v| v.trim().to_owned())
                        .filter(|v| zone(v));
                Ok(json!(target))
            }
            StateRead::Updater => {
                let uid = self.uid()?;
                let label = format!("gui/{uid}/{UPDATE_LABEL}");
                let registered = self.registered(&label)?;
                Ok(json!(registered))
            }
        }
    }
}

pub struct FixedMacosMutator<R: MutationRunner = NativeMutationRunner> {
    runner: R,
}

impl FixedMacosMutator<NativeMutationRunner> {
    /// Creates the production mutator.  This is inert until `apply` is called.
    pub fn native(home: PathBuf, watch: PathBuf) -> Result<Self> {
        Ok(Self {
            runner: NativeMutationRunner::new(MutationPaths::new(home, watch)?),
        })
    }
}

impl<R: MutationRunner> FixedMacosMutator<R> {
    pub fn administrative(&mut self, command: AdminCommand) -> Result<()> {
        self.runner.admin(command)
    }
    pub fn with_runner(runner: R) -> Self {
        Self { runner }
    }

    fn before_zone(action: &Value) -> Result<String> {
        action["before"]
            .as_str()
            .filter(|v| zone(v))
            .map(str::to_owned)
            .ok_or_else(|| err("invalid_action", "原时区不可安全恢复"))
    }

    fn languages(value: &Value) -> Result<Option<Vec<String>>> {
        if value.is_null() {
            return Ok(None);
        }
        let values = value
            .as_array()
            .ok_or_else(|| err("invalid_action", "原应用语言记录无效"))?
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| err("invalid_action", "原应用语言记录无效"))?;
        if values.iter().any(|v| !language(v)) {
            return Err(err("invalid_action", "原应用语言记录无效"));
        }
        Ok(Some(values.into_iter().map(str::to_owned).collect()))
    }

    fn action_id(action: &Value) -> Result<&str> {
        action
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| err("invalid_action", "缺少受权操作类型"))
    }

    fn applied_state(action: &Value) -> Result<Option<(StateRead, Value)>> {
        match Self::action_id(action)? {
            "timezone" => Ok(Some((StateRead::Timezone, action["after"].clone()))),
            "locale" => Ok(Some((StateRead::Locale, action["after"].clone()))),
            "language" => Ok(Some((StateRead::Languages, json!(["en-US"])))),
            "ipv6" => Ok(Some((
                StateRead::Ipv6(action["after"].as_str().unwrap_or_default().into()),
                json!("off"),
            ))),
            "watchdog" => Ok(Some((StateRead::Watchdog, action["after"].clone()))),
            "updater" => Ok(Some((StateRead::Updater, action["after"].clone()))),
            // DNS cache state has no stable, queryable value; it is intentionally
            // not journaled as a restorable setting.
            "flush_dns" => Ok(None),
            _ => Err(err(
                "unsupported_action",
                "macOS写入器拒绝未列入白名单的操作",
            )),
        }
    }

    fn require_readback(
        &mut self,
        state: StateRead,
        expected: Value,
        code: &str,
        message: &str,
    ) -> Result<()> {
        if self.runner.read(state)? == expected {
            Ok(())
        } else {
            Err(err(code, message))
        }
    }

    fn confirm_applied(&mut self, action: &Value) -> Result<()> {
        if let Some((state, expected)) = Self::applied_state(action)? {
            crate::setup_progress::emit(crate::setup_progress::Phase::VerifySettings);
            self.require_readback(
                state,
                expected,
                "mutation_unconfirmed",
                "系统操作未能回读确认",
            )?;
        }
        Ok(())
    }
}

impl<R: MutationRunner> Mutator for FixedMacosMutator<R> {
    fn apply(&mut self, action: &Value) -> Result<()> {
        match Self::action_id(action)? {
            "timezone" => {
                let after = action["after"]
                    .as_str()
                    .filter(|v| zone(v))
                    .ok_or_else(|| err("invalid_action", "时区操作参数无效"))?;
                self.runner.admin(AdminCommand::Timezone(after.into()))?
            }
            "locale" => {
                let after = action["after"]
                    .as_str()
                    .filter(|v| locale(v))
                    .ok_or_else(|| err("invalid_action", "地区操作参数无效"))?;
                self.runner
                    .defaults(DefaultsCommand::Locale(after.into()))?
            }
            "language" => {
                if action["after"] != "en-US" {
                    return Err(err("invalid_action", "语言目标必须是 en-US"));
                }
                // Validate before writing: a journal without an exact original is
                // not reversible and must not claim it is.
                Self::languages(&action["before"])?;
                self.runner
                    .defaults(DefaultsCommand::Languages(vec!["en-US".into()]))?
            }
            "ipv6" => {
                if action["before"] != "automatic" {
                    return Err(err("invalid_action", "IPv6 原状态必须为 automatic"));
                }
                let service = action["after"]
                    .as_str()
                    .filter(|v| service(v))
                    .ok_or_else(|| err("invalid_action", "IPv6服务参数无效"))?;
                self.runner.admin(AdminCommand::Ipv6Off(service.into()))?
            }
            "flush_dns" if action["before"].is_null() && action["after"].is_null() => {
                self.runner.admin(AdminCommand::FlushDns)?
            }
            "watchdog" => {
                let after = if action["after"].is_null() {
                    None
                } else {
                    Some(
                        action["after"]
                            .as_str()
                            .filter(|v| zone(v))
                            .ok_or_else(|| err("invalid_action", "守护时区参数无效"))?
                            .to_owned(),
                    )
                };
                if !action["before"].is_null() {
                    Self::before_zone(action)?;
                }
                self.runner.admin(AdminCommand::Watchdog(after))?
            }
            "updater" => {
                let enabled = action["after"]
                    .as_bool()
                    .ok_or_else(|| err("invalid_action", "更新任务参数无效"))?;
                if action["before"].as_bool().is_none() {
                    return Err(err("invalid_action", "更新任务原状态无效"));
                }
                self.runner.updater(enabled)?
            }
            _ => {
                return Err(err(
                    "unsupported_action",
                    "macOS写入器拒绝未列入白名单的操作",
                ))
            }
        };
        self.confirm_applied(action)
    }

    fn restore(&mut self, action: &Value) -> Result<bool> {
        match Self::action_id(action)? {
            "timezone" => {
                let before = Self::before_zone(action)?;
                let after = action["after"]
                    .as_str()
                    .filter(|v| zone(v))
                    .ok_or_else(|| err("invalid_action", "时区操作参数无效"))?;
                if self.runner.read(StateRead::Timezone)? != json!(after) {
                    return Ok(false);
                }
                self.runner.admin(AdminCommand::Timezone(before.clone()))?;
                self.require_readback(
                    StateRead::Timezone,
                    json!(before),
                    "mutation_restore_unconfirmed",
                    "系统恢复未能回读确认",
                )?;
                Ok(true)
            }
            "locale" => {
                let before = action["before"]
                    .as_str()
                    .filter(|v| locale(v))
                    .ok_or_else(|| err("invalid_action", "原地区设置无效"))?;
                let after = action["after"]
                    .as_str()
                    .filter(|v| locale(v))
                    .ok_or_else(|| err("invalid_action", "地区操作参数无效"))?;
                if self.runner.read(StateRead::Locale)? != json!(after) {
                    return Ok(false);
                }
                self.runner
                    .defaults(DefaultsCommand::Locale(before.into()))?;
                self.require_readback(
                    StateRead::Locale,
                    json!(before),
                    "mutation_restore_unconfirmed",
                    "系统恢复未能回读确认",
                )?;
                Ok(true)
            }
            "language" => {
                if action["after"] != "en-US" {
                    return Err(err("invalid_action", "语言目标必须是 en-US"));
                }
                let before = Self::languages(&action["before"])?;
                if self.runner.read(StateRead::Languages)? != json!(["en-US"]) {
                    return Ok(false);
                }
                let expected = before.clone().map_or(Value::Null, Value::from);
                match before {
                    Some(values) => self.runner.defaults(DefaultsCommand::Languages(values))?,
                    None => self.runner.defaults(DefaultsCommand::DeleteLanguages)?,
                }
                self.require_readback(
                    StateRead::Languages,
                    expected,
                    "mutation_restore_unconfirmed",
                    "系统恢复未能回读确认",
                )?;
                Ok(true)
            }
            "ipv6" => {
                if action["before"] != "automatic" {
                    return Err(err("invalid_action", "IPv6 原状态必须为 automatic"));
                }
                let service = action["after"]
                    .as_str()
                    .filter(|v| service(v))
                    .ok_or_else(|| err("invalid_action", "IPv6服务参数无效"))?;
                if self.runner.read(StateRead::Ipv6(service.into()))? != json!("off") {
                    return Ok(false);
                }
                self.runner
                    .admin(AdminCommand::Ipv6Automatic(service.into()))?;
                self.require_readback(
                    StateRead::Ipv6(service.into()),
                    json!("automatic"),
                    "mutation_restore_unconfirmed",
                    "系统恢复未能回读确认",
                )?;
                Ok(true)
            }
            "watchdog" => {
                let before = if action["before"].is_null() {
                    None
                } else {
                    Some(Self::before_zone(action)?)
                };
                let after = action["after"].clone();
                if self.runner.read(StateRead::Watchdog)? != after {
                    return Ok(false);
                }
                self.runner.admin(AdminCommand::Watchdog(before.clone()))?;
                self.require_readback(
                    StateRead::Watchdog,
                    json!(before),
                    "mutation_restore_unconfirmed",
                    "系统恢复未能回读确认",
                )?;
                Ok(true)
            }
            "updater" => {
                let before = action["before"]
                    .as_bool()
                    .ok_or_else(|| err("invalid_action", "更新任务原状态无效"))?;
                let after = action["after"]
                    .as_bool()
                    .ok_or_else(|| err("invalid_action", "更新任务参数无效"))?;
                if self.runner.read(StateRead::Updater)? != json!(after) {
                    return Ok(false);
                }
                self.runner.updater(before)?;
                self.require_readback(
                    StateRead::Updater,
                    json!(before),
                    "mutation_restore_unconfirmed",
                    "系统恢复未能回读确认",
                )?;
                Ok(true)
            }
            // DNS flushing is intentionally not reversible.
            "flush_dns" => Ok(false),
            _ => Err(err(
                "unsupported_action",
                "macOS写入器拒绝未列入白名单的操作",
            )),
        }
    }
}

#[cfg(test)]
mod admin_plan_tests {
    use super::*;

    #[test]
    fn generated_admin_script_is_fixed_quoted_and_uses_authorization_timeout() {
        let args =
            NativeMutationRunner::admin_args(AdminCommand::Ipv6Off("Wi-Fi;$(whoami)".into()))
                .unwrap();
        let plan = NativeMutationRunner::compile_admin_script(
            args,
            Some(Path::new("/bundle/watch-admin.sh")),
            true,
        )
        .unwrap();
        assert_eq!(plan.program, "/usr/bin/osascript");
        assert_eq!(plan.timeout, Duration::from_secs(185));
        assert!(plan.args[1].contains("with timeout of 180 seconds"));
        assert!(plan.args[1].contains("with administrator privileges"));
        assert!(plan.args[1].contains("'Wi-Fi;$(whoami)'"));
        assert!(plan.args[1].contains("/usr/bin/install -o root -g wheel -m 755"));
    }
}
