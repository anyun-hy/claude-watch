//! The destructive state machine. Every stage re-checks the promises of the
//! previous one: a machine that is not exactly where the flow left it stops
//! before the next irreversible step.
use crate::layout::Layout;
use crate::plist;
use crate::runner::{RunMode, Runner};
use crate::blocked;
use claude_watch_core::error::Result;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

const REMOVED_PREFIX: &str = "ClaudeWatch-removed-";
const ALLOWED_SYSTEM_ENTRIES: [&str; 3] = [
    "claude-watch-admin.sh",
    "timezone.target",
    "timezone.last-success",
];

/// What the preflight learned about the machine, re-checked verbatim after the
/// user confirms so a concurrent change cannot be executed against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayoutPlan {
    pub old_identity: Option<(String, String)>,
    pub old_engine_hash: Option<String>,
    pub helper_hash: Option<String>,
}

pub fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(blocked(message))
    }
}

/// Cargo is reached through the rustup shim, which is a symlink, so this
/// check follows links the way the shell would have.
fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|info| info.is_file() && info.mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn is_hex32(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn is_removed_directory(name: &str) -> bool {
    name.strip_prefix(REMOVED_PREFIX)
        .map(is_hex32)
        .unwrap_or(false)
}

fn is_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|info| info.is_dir())
        .unwrap_or(false)
}

pub fn path_is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|info| info.file_type().is_symlink())
        .unwrap_or(false)
}

/// Rejects anything outside the user's home, reached through a symlink, or
/// owned by somebody else before it is touched.
pub fn safe_user_path(path: &Path, home: &Path, uid: u32) -> Result<()> {
    require(
        path.strip_prefix(home).is_ok(),
        &format!("路径不在当前用户目录内：{}", path.display()),
    )?;
    for part in path.ancestors() {
        if part == home {
            break;
        }
        if path_is_symlink(part) {
            return Err(blocked(format!("路径或其父目录是符号链接：{}", part.display())));
        }
    }
    if exists(path) {
        let info = std::fs::symlink_metadata(path)
            .map_err(|_| blocked(format!("无法读取路径信息：{}", path.display())))?;
        require(
            info.uid() == uid && (info.is_file() || info.is_dir()),
            &format!("路径归属或类型不匹配：{}", path.display()),
        )?;
    }
    Ok(())
}

pub fn digest(path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut file = std::fs::File::open(path)
        .map_err(|_| blocked(format!("无法校验文件：{}", path.display())))?;
    let mut block = [0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut block)
            .map_err(|_| blocked(format!("无法校验文件：{}", path.display())))?;
        if read == 0 {
            break;
        }
        hasher.update(&block[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn loaded(runner: &dyn Runner, label: &str) -> Result<bool> {
    let output = runner.run(
        &[
            "/bin/launchctl".to_string(),
            "print".to_string(),
            label.to_string(),
        ],
        None,
        RunMode::Capture,
    )?;
    match output.status {
        0 => Ok(true),
        113 => Ok(false),
        code => Err(blocked(format!(
            "无法确认后台任务状态：{label}（退出码 {code}）"
        ))),
    }
}

fn process_rows(runner: &dyn Runner, uid: u32) -> Result<Vec<String>> {
    let output = runner.run(
        &[
            "/bin/ps".to_string(),
            "-axo".to_string(),
            "uid=,command=".to_string(),
        ],
        None,
        RunMode::Capture,
    )?;
    require(output.success(), "无法检查当前进程。")?;
    let mut rows = Vec::new();
    for line in output.stdout.lines() {
        let line = line.trim();
        let mut fields = line.splitn(2, char::is_whitespace);
        if let (Some(owner), Some(command)) = (fields.next(), fields.next()) {
            if owner == uid.to_string() && !command.trim().is_empty() {
                rows.push(command.trim().to_string());
            }
        }
    }
    Ok(rows)
}

fn check_no_conflicting_work(runner: &dyn Runner, uid: u32) -> Result<()> {
    for command in process_rows(runner, uid)? {
        if command.contains("/Claude.app/Contents/MacOS/Claude") {
            return Err(blocked("请先正常退出 Claude，再执行完整重置。"));
        }
        for name in [
            "monitor/package-dmg.sh",
            "monitor/build.sh",
            "tools/build-rust-components.sh",
        ] {
            if command.contains(name) {
                return Err(blocked("发现其他打包或编译操作正在进行，请等它完成。"));
            }
        }
    }
    Ok(())
}

fn check_transactions(layout: &Layout) -> Result<()> {
    for name in [
        "transaction.json",
        "setup-transaction.json",
        "update-transaction.json",
        "service-transaction.json",
    ] {
        if exists(&layout.base().join("switcher").join(name)) {
            return Err(blocked(format!("发现未完成的 Watch 事务：{name}")));
        }
    }
    for name in ["agent-install-transaction.json", ".runtime.previous"] {
        if exists(&layout.base().join(name)) {
            return Err(blocked(format!("发现未完成的后台事务：{name}")));
        }
    }
    Ok(())
}

fn check_helper(layout: &Layout, runner: &dyn Runner, app_present: bool) -> Result<Option<String>> {
    let job_loaded = loaded(runner, &layout.helper_label())?;
    let system_paths = [&layout.system_root, &layout.helper(), &layout.system_plist];
    for path in system_paths {
        for part in path.ancestors() {
            if path_is_symlink(part) {
                return Err(blocked("Watch 系统辅助组件路径是符号链接。"));
            }
        }
    }
    if !exists(&layout.system_root) && !exists(&layout.system_plist) && !job_loaded {
        return Ok(None);
    }
    require(
        app_present && is_directory(&layout.system_root) && layout.helper().is_file(),
        "Watch 系统辅助组件不完整，请先检查残留。",
    )?;
    let root_info = std::fs::symlink_metadata(&layout.system_root)
        .map_err(|_| blocked("Watch 系统辅助目录无法读取。"))?;
    let helper_info = std::fs::symlink_metadata(layout.helper())
        .map_err(|_| blocked("Watch 系统辅助程序无法读取。"))?;
    require(
        root_info.uid() == layout.system_uid && root_info.mode() & 0o022 == 0,
        "Watch 系统辅助目录的归属或权限异常。",
    )?;
    require(
        helper_info.uid() == layout.system_uid && helper_info.mode() & 0o777 == 0o755,
        "Watch 系统辅助程序的归属或权限异常。",
    )?;
    let entries = std::fs::read_dir(&layout.system_root)
        .map_err(|_| blocked("Watch 系统辅助目录无法读取。"))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| blocked("Watch 系统辅助目录无法读取。"))?;
    let names: Vec<String> = entries
        .iter()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    require(
        names
            .iter()
            .all(|name| ALLOWED_SYSTEM_ENTRIES.contains(&name.as_str())),
        "Watch 系统辅助目录包含未知文件，请先检查。",
    )?;
    for entry in &entries {
        let info = std::fs::symlink_metadata(entry.path())
            .map_err(|_| blocked("Watch 系统辅助目录中有无法确认的文件。"))?;
        if info.file_type().is_symlink() || info.uid() != layout.system_uid || !info.is_file() {
            return Err(blocked("Watch 系统辅助目录中有无法确认的文件。"));
        }
    }
    let bundled = layout.app.join("Contents/Resources/watch-admin.sh");
    if path_is_symlink(&bundled) || !bundled.is_file() || digest(&bundled)? != digest(&layout.helper())?
    {
        return Err(blocked("系统辅助程序与已安装应用不一致。"));
    }
    if exists(&layout.system_plist) {
        let info = std::fs::symlink_metadata(&layout.system_plist)
            .map_err(|_| blocked("Watch 系统时区任务无法读取。"))?;
        let value = plist::read(runner, &layout.system_plist)?;
        let expected = vec![
            "/usr/bin/env".to_string(),
            "-i".to_string(),
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin".to_string(),
            "/bin/bash".to_string(),
            "--noprofile".to_string(),
            "--norc".to_string(),
            layout.helper().display().to_string(),
            "tick".to_string(),
        ];
        let matching = info.uid() == layout.system_uid
            && info.mode() & 0o022 == 0
            && plist::string(&value, "Label").as_deref() == Some("io.local.claudewatch.timezone")
            && plist::strings(&value, "ProgramArguments").as_deref() == Some(expected.as_slice());
        require(matching, "Watch 系统时区任务身份不匹配。")?;
    } else if job_loaded {
        return Err(blocked("Watch 系统时区任务已加载，但定义文件缺失。"));
    }
    Ok(Some(digest(&layout.helper())?))
}

pub fn app_identity(app: &Path) -> Result<(String, String)> {
    app_identity_with(&crate::SystemRunner, app)
}

/// Identity check through the injected runner so contracts can answer plutil.
pub fn app_identity_with(runner: &dyn Runner, app: &Path) -> Result<(String, String)> {
    if path_is_symlink(app) || !app.is_dir() {
        return Err(blocked("已安装应用不是普通目录。"));
    }
    let info = plist::read(runner, &app.join("Contents/Info.plist"))?;
    let manifest = plist::read(runner, &app.join("Contents/Resources/BuildInfo.plist"))?;
    let identity = plist::string(&info, "CFBundleIdentifier");
    let executable = plist::string(&info, "CFBundleExecutable");
    require(
        identity.as_deref() == Some("io.local.watchpanel")
            && executable.as_deref() == Some("ClaudeWatchMonitor"),
        "已安装应用身份不匹配。",
    )?;
    require(
        plist::string(&manifest, "BackendVariant").as_deref() == Some("rust-candidate")
            && plist::string(&manifest, "Architecture").as_deref() == Some("arm64"),
        "此流程只支持 arm64 Rust 候选版，请先检查当前应用。",
    )?;
    let version = plist::string(&info, "CFBundleShortVersionString");
    let build = plist::string(&info, "CFBundleVersion").filter(|value| !value.is_empty());
    match (version, build) {
        (Some(version), Some(build)) => Ok((version, build)),
        _ => Err(blocked("无法确认已安装应用的版本和构建号。")),
    }
}

fn json_command(runner: &dyn Runner, args: &[String]) -> Result<Value> {
    let output = runner.run(args, None, RunMode::Capture)?;
    if !output.stdout.is_empty() {
        println!("{}", output.stdout.trim_end());
    }
    if !output.stderr.is_empty() {
        eprintln!("{}", output.stderr.trim_end());
    }
    if !output.success() {
        let name = Path::new(&args[0])
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| args[0].clone());
        return Err(blocked(format!(
            "{name} 执行失败（退出码 {}）。",
            output.status
        )));
    }
    let value: Value = serde_json::from_str(&output.stdout)
        .map_err(|_| blocked("安装组件返回了无法识别的结果。"))?;
    require(value.is_object(), "安装组件返回格式无效。")?;
    Ok(value)
}

fn preflight(layout: &Layout, runner: &dyn Runner, uid: u32) -> Result<LayoutPlan> {
    let home_info = std::fs::symlink_metadata(&layout.home)
        .map_err(|_| blocked("当前用户目录的归属或类型不匹配。"))?;
    require(
        !home_info.file_type().is_symlink() && home_info.is_dir() && home_info.uid() == uid,
        "当前用户目录的归属或类型不匹配。",
    )?;
    let mut guarded = layout.data_paths();
    guarded.push(layout.agent());
    guarded.push(layout.updater());
    guarded.push(layout.trash());
    for path in &guarded {
        safe_user_path(path, &layout.home, uid)?;
    }
    check_transactions(layout)?;
    check_no_conflicting_work(runner, uid)?;
    if exists(&layout.updater()) || loaded(runner, &layout.updater_label(uid))? {
        return Err(blocked("发现 Watch 更新任务；请先检查是否有更新正在进行。"));
    }
    let app_present = exists(&layout.app);
    let mut old_identity = None;
    let mut engine_hash = None;
    if app_present {
        if exists(&layout.trash()) && !is_directory(&layout.trash()) {
            return Err(blocked("废纸篓不是普通目录。"));
        }
        let identity = app_identity_with(runner, &layout.app)?;
        let app_info = std::fs::symlink_metadata(&layout.app)
            .map_err(|_| blocked("已安装应用无法读取。"))?;
        require(app_info.uid() == uid, "已安装应用不属于当前用户，请先核对。")?;
        let engine = layout.app.join("Contents/Resources/watch-engine");
        require(is_executable(&engine), "已安装应用的卸载组件无效。")?;
        let verified = runner.run(
            &[
                "/usr/bin/codesign".to_string(),
                "--verify".to_string(),
                "--deep".to_string(),
                "--strict".to_string(),
                layout.app.display().to_string(),
            ],
            None,
            RunMode::Inherit,
        )?;
        require(verified.success(), "已安装应用签名校验失败。")?;
        let preview = json_command(
            runner,
            &[engine.display().to_string(), "app-uninstall".to_string()],
        )?;
        let matching = preview.get("status").and_then(Value::as_str) == Some("preview")
            && preview.get("action").and_then(Value::as_str) == Some("app-uninstall")
            && preview.get("installed").and_then(Value::as_str)
                == Some(layout.app.display().to_string().as_str());
        require(matching, "卸载预览与目标应用不一致。")?;
        engine_hash = Some(digest(&engine)?);
        old_identity = Some(identity);
    } else {
        let mut residual = layout.data_paths();
        residual.push(layout.agent());
        if residual.iter().any(|path| exists(path)) {
            return Err(blocked(
                "应用已不存在，但 Watch 数据或后台任务仍有残留；请先检查。",
            ));
        }
    }
    if !app_present && loaded(runner, &layout.agent_label(uid))? {
        return Err(blocked("应用已不存在，但 Watch 主后台仍在运行。"));
    }
    if !app_present && is_directory(&layout.trash()) {
        let mut found = false;
        if let Ok(entries) = std::fs::read_dir(layout.trash()) {
            for entry in entries.flatten() {
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(REMOVED_PREFIX)
                {
                    found = true;
                    break;
                }
            }
        }
        require(!found, "废纸篓中有 Watch 卸载目录；请先核查归属。")?;
    }
    let helper_hash = check_helper(layout, runner, app_present)?;
    Ok(LayoutPlan {
        old_identity,
        old_engine_hash: engine_hash,
        helper_hash,
    })
}

fn cleanup_trashed_app(
    layout: &Layout,
    runner: &dyn Runner,
    uid: u32,
    previous: &str,
    old_identity: &(String, String),
) -> Result<PathBuf> {
    let app = PathBuf::from(previous);
    let parent = app
        .parent()
        .ok_or_else(|| blocked("本次卸载返回的废纸篓路径不匹配。"))?
        .to_path_buf();
    let name_ok = app.file_name().map(|value| value == "Claude Watch Monitor.app") == Some(true);
    let root_ok = parent.parent() == Some(layout.trash().as_path());
    let dir_ok = parent
        .file_name()
        .map(|value| is_removed_directory(&value.to_string_lossy()))
        == Some(true);
    require(name_ok && root_ok && dir_ok, "本次卸载返回的废纸篓路径不匹配。")?;
    safe_user_path(&parent, &layout.home, uid)?;
    safe_user_path(&app, &layout.home, uid)?;
    let info = plist::read(runner, &app.join("Contents/Info.plist"))?;
    let identity = (
        plist::string(&info, "CFBundleShortVersionString").unwrap_or_default(),
        plist::string(&info, "CFBundleVersion").unwrap_or_default(),
    );
    require(
        plist::string(&info, "CFBundleIdentifier").as_deref() == Some("io.local.watchpanel")
            && plist::string(&info, "CFBundleExecutable").as_deref() == Some("ClaudeWatchMonitor")
            && &identity == old_identity,
        "废纸篓中应用的身份或版本不匹配。",
    )?;
    let entries = std::fs::read_dir(&parent)
        .map_err(|_| blocked("本次卸载目录包含未知内容。"))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| blocked("本次卸载目录包含未知内容。"))?;
    let allowed = ["Claude Watch Monitor.app", "io.local.claudewatch.agent.plist"];
    for entry in &entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        require(
            allowed.contains(&name.as_str()),
            "本次卸载目录包含未知内容。",
        )?;
    }
    let agent = parent.join("io.local.claudewatch.agent.plist");
    if exists(&agent) {
        safe_user_path(&agent, &layout.home, uid)?;
        let value = plist::read(runner, &agent)?;
        require(
            plist::string(&value, "Label").as_deref() == Some("io.local.claudewatch.agent"),
            "废纸篓中的 Watch 后台任务标签不匹配。",
        )?;
    }
    Ok(parent)
}

fn wait_for_watch_exit(
    layout: &Layout,
    runner: &dyn Runner,
    uid: u32,
    old: Option<&Path>,
    sleep: &dyn Fn(Duration),
) -> Result<()> {
    let mut needles = vec![
        format!("{}/", layout.base().join("runtime").display()),
        format!("{}/Contents/", layout.app.display()),
    ];
    if let Some(old) = old {
        needles.push(format!("{}/Contents/", old.display()));
    }
    for attempt in 0..11 {
        let rows = process_rows(runner, uid)?;
        if !rows
            .iter()
            .any(|row| needles.iter().any(|needle| row.contains(needle)))
        {
            return Ok(());
        }
        if attempt < 10 {
            sleep(Duration::from_secs(1));
        }
    }
    Err(blocked("Watch 进程尚未退出，未清理数据。"))
}

fn clean_data(
    layout: &Layout,
    runner: &dyn Runner,
    uid: u32,
    trashed: Option<&Path>,
    sleep: &dyn Fn(Duration),
) -> Result<()> {
    if exists(&layout.app) || exists(&layout.system_root) || exists(&layout.system_plist) {
        return Err(blocked("应用或系统辅助组件尚未完全卸载。"));
    }
    let labels = [
        layout.agent_label(uid),
        layout.updater_label(uid),
        layout.helper_label(),
    ];
    for label in &labels {
        if loaded(runner, label)? {
            return Err(blocked(format!("后台任务仍在运行：{label}")));
        }
    }
    check_transactions(layout)?;
    if exists(&layout.agent()) || exists(&layout.updater()) {
        return Err(blocked("Watch 后台任务文件仍存在。"));
    }
    let trashed_app = trashed.map(|path| path.join("Claude Watch Monitor.app"));
    wait_for_watch_exit(layout, runner, uid, trashed_app.as_deref(), sleep)?;
    let paths = layout.data_paths();
    for path in &paths {
        safe_user_path(path, &layout.home, uid)?;
    }
    if let Some(path) = trashed {
        safe_user_path(path, &layout.home, uid)?;
    }
    let prefs = layout
        .home
        .join("Library/Preferences/io.local.watchpanel.plist");
    let read = runner.run(
        &[
            "/usr/bin/defaults".to_string(),
            "read".to_string(),
            "io.local.watchpanel".to_string(),
        ],
        None,
        RunMode::Capture,
    )?;
    if read.success() {
        let deleted = runner.run(
            &[
                "/usr/bin/defaults".to_string(),
                "delete".to_string(),
                "io.local.watchpanel".to_string(),
            ],
            None,
            RunMode::Capture,
        )?;
        require(deleted.success(), "无法清理 Watch 偏好设置。")?;
    } else if exists(&prefs) || !read.key_missing() {
        return Err(blocked("无法确认 Watch 偏好设置状态。"));
    }
    for path in &paths {
        remove_if_present(path)?;
    }
    if let Some(path) = trashed {
        remove_if_present(path)?;
    }
    let mut residue = paths.clone();
    if let Some(path) = trashed {
        residue.push(path.to_path_buf());
    }
    if residue.iter().any(|path| exists(path)) {
        return Err(blocked("仍有 Watch 数据未能清理。"));
    }
    let after = runner.run(
        &[
            "/usr/bin/defaults".to_string(),
            "read".to_string(),
            "io.local.watchpanel".to_string(),
        ],
        None,
        RunMode::Capture,
    )?;
    if !after.key_missing() {
        return Err(blocked("无法确认 Watch 偏好设置已清理。"));
    }
    for label in &labels {
        if loaded(runner, label)? {
            return Err(blocked(format!("清理后后台任务仍在运行：{label}")));
        }
    }
    wait_for_watch_exit(layout, runner, uid, None, sleep)
}

fn remove_if_present(path: &Path) -> Result<()> {
    if !exists(path) {
        return Ok(());
    }
    let is_dir = is_directory(path);
    let removed = if is_dir {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    removed.map_err(|_| blocked(format!("无法清理：{}", path.display())))
}

fn acquire_lock(layout: &Layout, uid: u32) -> Result<std::fs::File> {
    let path = layout
        .temporary
        .join(format!("claude-watch-reinstall-{uid}.lock"));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|_| blocked("无法取得重装锁。"))?;
    let info = file
        .metadata()
        .map_err(|_| blocked("重装锁文件归属或类型异常。"))?;
    require(
        info.uid() == uid && info.is_file() && info.mode() & 0o077 == 0,
        "重装锁文件归属或类型异常。",
    )?;
    let locked = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_EX | libc::LOCK_NB) };
    if locked != 0 {
        let kind = std::io::Error::last_os_error();
        if kind.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(blocked("另一个重装流程正在运行。"));
        }
        return Err(blocked("无法取得重装锁。"));
    }
    Ok(file)
}

fn validate_arguments(version: &str, build: &str) -> Result<()> {
    let parts: Vec<&str> = version.split('.').collect();
    let version_ok = version.len() <= 32
        && parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    require(version_ok, "应用版本应为数字格式，例如 3.0.0。")?;
    let build_ok = !build.is_empty()
        && build.len() <= 9
        && build.as_bytes()[0].is_ascii_digit()
        && build.as_bytes()[0] != b'0'
        && build.bytes().all(|b| b.is_ascii_digit());
    require(build_ok, "build 编号必须是正整数。")?;
    Ok(())
}

fn check_build_inputs(layout: &Layout, runner: &dyn Runner, cargo: &Path) -> Result<Vec<PathBuf>> {
    let required = [
        "monitor/package-dmg.sh",
        "monitor/build.sh",
        "tools/build-rust-components.sh",
        "Cargo.toml",
        "Cargo.lock",
        "monitor/Resources/AppIcon.icns",
        "monitor/macos-minimum.txt",
    ];
    let paths: Vec<PathBuf> = required.iter().map(|name| layout.project.join(name)).collect();
    let present = paths
        .iter()
        .all(|path| !path_is_symlink(path) && path.is_file());
    require(
        present && is_executable(cargo),
        "未找到打包脚本或可执行的 Cargo。",
    )?;
    let mut tools = Vec::new();
    for name in [
        "xcrun",
        "xcode-select",
        "hdiutil",
        "shasum",
        "plutil",
        "python3",
    ] {
        match runner.locate(name) {
            Some(path) => tools.push(path),
            None => return Err(blocked("缺少 Xcode 或打包所需的系统工具。")),
        }
    }
    let compiler = runner.run(
        &[tools[0].display().to_string(), "--find".to_string(), "swiftc".to_string()],
        None,
        RunMode::Capture,
    )?;
    let sdk = runner.run(
        &[
            tools[0].display().to_string(),
            "--sdk".to_string(),
            "macosx".to_string(),
            "--show-sdk-path".to_string(),
        ],
        None,
        RunMode::Capture,
    )?;
    require(
        compiler.success()
            && !compiler.stdout.trim().is_empty()
            && sdk.success()
            && !sdk.stdout.trim().is_empty(),
        "无法确认 Swift 编译器或 macOS SDK。",
    )?;
    for directory in [layout.project.join("monitor/build"), layout.project.join("monitor/dist")] {
        if path_is_symlink(&directory) || (exists(&directory) && !is_directory(&directory)) {
            return Err(blocked(format!(
                "构建目录不是普通目录：{}",
                directory.display()
            )));
        }
        let existing = if directory.exists() {
            directory.clone()
        } else {
            directory
                .parent()
                .map(Path::to_path_buf)
                .ok_or_else(|| blocked("构建目录不可写。"))?
        };
        let writable = unsafe {
            libc::access(
                std::ffi::CString::new(existing.display().to_string())
                    .map_err(|_| blocked("构建目录不可写。"))?
                    .as_ptr(),
                libc::W_OK | libc::X_OK,
            ) == 0
        };
        require(
            writable,
            &format!("构建目录不可写：{}", existing.display()),
        )?;
    }
    Ok(tools)
}

fn tag(runner: &dyn Runner) -> Result<String> {
    let stamp = runner.run(
        &["/bin/date".to_string(), "+%Y%m%d-%H%M%S".to_string()],
        None,
        RunMode::Capture,
    )?;
    let trimmed = stamp.stdout.trim().to_string();
    require(stamp.success() && !trimmed.is_empty(), "无法取得打包时间戳。")?;
    let unique = uuid::Uuid::new_v4().simple().to_string();
    Ok(format!("{trimmed}-{}", &unique[..8]))
}

fn package_environment(
    version: &str,
    build: &str,
    app_out: &Path,
    dmg_name: &str,
) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = std::env::vars().collect();
    for (key, value) in [
        ("APP_VERSION", version.to_string()),
        ("BUILD_NUMBER", build.to_string()),
        ("CW_BUILD_ARCH", "arm64".to_string()),
        ("CW_BACKEND_VARIANT", "rust-candidate".to_string()),
        ("CW_CARGO_BIN", "cargo".to_string()),
        ("CW_APP_OUTPUT", app_out.display().to_string()),
        ("DMG_NAME", dmg_name.to_string()),
    ] {
        env.insert(key.to_string(), value);
    }
    env
}

fn checksum_matches(sha_file: &Path, dmg: &Path) -> Result<bool> {
    let text = std::fs::read_to_string(sha_file)
        .map_err(|_| blocked("DMG 校验文件无法读取，未执行安装。"))?;
    let token = text.split_whitespace().next().unwrap_or_default();
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Ok(false);
    }
    Ok(digest(dmg)? == token)
}

fn verify_signature(runner: &dyn Runner, app: &Path) -> Result<bool> {
    let output = runner.run(
        &[
            "/usr/bin/codesign".to_string(),
            "--verify".to_string(),
            "--deep".to_string(),
            "--strict".to_string(),
            app.display().to_string(),
        ],
        None,
        RunMode::Inherit,
    )?;
    Ok(output.success())
}

/// What the flow actually did. A cancelled run is not a successful install,
/// and the caller must be able to say so instead of reporting success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Installed,
    DryRun,
    Cancelled,
}

/// Runs the full flow. `sleep` is injected so contract tests never wait.
pub fn perform(
    layout: &Layout,
    runner: &dyn Runner,
    version: &str,
    build: &str,
    dry_run: bool,
    confirm: &mut dyn FnMut(&str) -> Result<String>,
    uid: u32,
    cargo: &Path,
    sleep: &dyn Fn(Duration),
) -> Result<Outcome> {
    validate_arguments(version, build)?;
    check_build_inputs(layout, runner, cargo)?;
    let stamp = tag(runner)?;
    let app_out = layout.project.join("monitor/build").join(format!(
        "Claude Watch Monitor build{build}-{stamp}.app"
    ));
    let dmg_name = format!("Claude-Watch-{version}-build{build}-{stamp}-arm64.dmg");
    let dmg = layout.project.join("monitor/dist").join(&dmg_name);
    let sha = PathBuf::from(format!("{}.sha256", dmg.display()));
    if [&app_out, &dmg, &sha].iter().any(|path| exists(path)) {
        return Err(blocked("本次输出路径已存在，未覆盖。"));
    }
    // The plan is printed before preflight on purpose: a preflight that stops
    // the flow must never look like "nothing happened, no idea what this
    // command does". Target and phases are known before any check runs.
    println!("Watch 重装：目标 {version} / build {build}（arm64 Rust 候选版）");
    println!("流程：卸载已安装应用 → 清理 Watch 专属数据 → 打包 DMG → 校验 → 安装");
    let _ = std::io::stdout().flush();
    let plan = preflight(layout, runner, uid).map_err(|error| {
        println!(
            "预检未通过：{}；没有卸载、删除、打包或安装。",
            error.message
        );
        let _ = std::io::stdout().flush();
        error
    })?;
    let old = plan
        .old_identity
        .as_ref()
        .map(|(version, build)| format!("{version} / build {build}"))
        .unwrap_or_else(|| "当前未安装".into());
    println!("已安装：{old}");
    println!("将永久删除 Claude Watch 的设置、日志、A/B 快照及其自有后台；保留 Claude 登录、TAG 配置和独立原版工具。");
    println!("流程先卸载再打包；如果打包失败，旧应用已卸载，请保留输出并检查当前状态。");
    // The confirmation prompt writes to stderr; without flushing stdout the
    // preview can stay in the pipe buffer and the prompt looks like it came
    // out of nowhere (or, when the output is captured, from nowhere at all).
    let _ = std::io::stdout().flush();
    if dry_run {
        println!("预演通过：没有卸载、删除、打包或安装。");
        let _ = std::io::stdout().flush();
        return Ok(Outcome::DryRun);
    }
    if confirm("输入 y/N 重置并安装继续，其他输入取消：")?
        .trim()
        .to_lowercase()
        != "y"
    {
        println!("已取消，没有执行重置。");
        let _ = std::io::stdout().flush();
        return Ok(Outcome::Cancelled);
    }
    let _lock = acquire_lock(layout, uid)?;
    let current = preflight(layout, runner, uid)?;
    if current != plan {
        return Err(blocked("确认后安装状态发生变化；未执行卸载。"));
    }
    let mut trashed: Option<PathBuf> = None;
    if plan.old_identity.is_some() {
        println!("[1/4] 卸载已安装应用（移入废纸篓，可恢复）。");
        let _ = std::io::stdout().flush();
        let engine = layout.app.join("Contents/Resources/watch-engine");
        let result = json_command(
            runner,
            &[
                engine.display().to_string(),
                "app-uninstall".to_string(),
                "--apply".to_string(),
            ],
        )?;
        let previous = result.get("previous").and_then(Value::as_str);
        let confirmed = result.get("status").and_then(Value::as_str) == Some("ok")
            && result.get("action").and_then(Value::as_str) == Some("app-uninstall")
            && previous.is_some();
        require(confirmed, "卸载结果未确认；请检查当前状态。")?;
        trashed = Some(cleanup_trashed_app(
            layout,
            runner,
            uid,
            previous.unwrap_or_default(),
            plan.old_identity.as_ref().expect("checked"),
        )?);
    }
    if let Some(hash) = plan.helper_hash.as_ref() {
        if path_is_symlink(&layout.helper())
            || !layout.helper().is_file()
            || &digest(&layout.helper())? != hash
        {
            return Err(blocked("系统辅助组件已变化；未继续清理。"));
        }
        println!("正在卸载 Watch 系统辅助组件；可能需要管理员密码。");
        let uninstalled = runner.run(
            &[
                "/usr/bin/sudo".to_string(),
                layout.helper().display().to_string(),
                "uninstall".to_string(),
            ],
            None,
            RunMode::Inherit,
        )?;
        require(
            uninstalled.success(),
            "系统辅助组件卸载未完成；本地数据保留。",
        )?;
    }
    clean_data(layout, runner, uid, trashed.as_deref(), sleep)?;
    println!("Watch 卸载与数据清理完成。");
    if [&app_out, &dmg, &sha].iter().any(|path| exists(path)) {
        return Err(blocked("本次输出路径已存在，未覆盖。"));
    }
    let env = package_environment(version, build, &app_out, &dmg_name);
    println!("正在打包 {version} / build {build}。");
    let packaged = runner.run(
        &[
            "/bin/bash".to_string(),
            layout.project.join("monitor/package-dmg.sh").display().to_string(),
        ],
        Some(&env),
        RunMode::Inherit,
    )?;
    require(packaged.success(), "打包失败，未执行安装。")?;
    let produced = app_identity_with(runner, &app_out)?;
    let artifacts_ok = !path_is_symlink(&dmg) && !path_is_symlink(&sha) && dmg.is_file() && sha.is_file();
    require(
        produced == (version.to_string(), build.to_string()) && artifacts_ok,
        "打包产物或版本不匹配，未执行安装。",
    )?;
    require(
        checksum_matches(&sha, &dmg)?,
        "DMG 校验不匹配，未执行安装。",
    )?;
    require(
        verify_signature(runner, &app_out)?,
        "新应用签名校验失败，未执行安装。",
    )?;
    // A user or another process may have installed or restarted Watch while
    // the build ran. Never replace that new state silently.
    check_no_conflicting_work(runner, uid)?;
    check_transactions(layout)?;
    let mut changed = layout.data_paths();
    changed.push(layout.app.clone());
    changed.push(layout.agent());
    changed.push(layout.updater());
    changed.push(layout.system_root.clone());
    changed.push(layout.system_plist.clone());
    if changed.iter().any(|path| exists(path)) {
        return Err(blocked("打包期间 Watch 安装或数据状态发生变化，未执行安装。"));
    }
    for label in [
        layout.agent_label(uid),
        layout.updater_label(uid),
        layout.helper_label(),
    ] {
        if loaded(runner, &label)? {
            return Err(blocked(format!(
                "打包期间后台任务重新出现，未执行安装：{label}"
            )));
        }
    }
    wait_for_watch_exit(layout, runner, uid, None, sleep)?;
    let engine = app_out.join("Contents/Resources/watch-engine");
    let source = app_out.display().to_string();
    let preview = json_command(
        runner,
        &[
            engine.display().to_string(),
            "app-install".to_string(),
            "--source".to_string(),
            source.clone(),
        ],
    )?;
    let preview_ok = preview.get("status").and_then(Value::as_str) == Some("preview")
        && preview.get("source").and_then(Value::as_str) == Some(source.as_str())
        && preview.get("installed").and_then(Value::as_str)
            == Some(layout.app.display().to_string().as_str());
    require(preview_ok, "安装预览不匹配，未执行安装。")?;
    let installed = json_command(
        runner,
        &[
            engine.display().to_string(),
            "app-install".to_string(),
            "--source".to_string(),
            source,
            "--apply".to_string(),
        ],
    )?;
    let installed_ok = installed.get("status").and_then(Value::as_str) == Some("ok")
        && installed.get("version").and_then(Value::as_str) == Some(version)
        && installed.get("build").and_then(Value::as_str) == Some(build)
        && installed.get("architecture").and_then(Value::as_str) == Some("arm64");
    require(installed_ok, "安装结果未通过版本核对，请检查实际安装状态。")?;
    require(
        app_identity_with(runner, &layout.app)? == (version.to_string(), build.to_string())
            && verify_signature(runner, &layout.app)?,
        "已安装应用的身份、版本或签名未通过核对。",
    )?;
    require(
        loaded(runner, &layout.agent_label(uid))?,
        "应用已安装，但主后台注册状态未确认。",
    )?;
    let opened = runner.run(
        &[
            "/usr/bin/open".to_string(),
            "-a".to_string(),
            layout.app.display().to_string(),
        ],
        None,
        RunMode::Inherit,
    )?;
    require(opened.success(), "应用已安装，但未能自动打开。")?;
    println!("已安装 {version} / build {build}；安装包：{}", dmg.display());
    println!("请按 macOS 提示授权；实际后台和保护功能仍需打开应用后核验。");
    Ok(Outcome::Installed)
}
