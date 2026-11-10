//! Transactional installation of the native per-user runtime and fixed agent.
//! Accounts, environment references, and the independent original bodyguard are
//! outside this module's write set.
use crate::{
    release_native::{FixedCommand, FixedCommandExecutor},
    storage::{sha256, strict_json, StateStore},
};
use claude_watch_core::error::{CoreError, Result};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path},
    thread,
    time::{Duration, Instant},
};
const LABEL: &str = "io.local.claudewatch.agent";
const COMPONENTS: [&str; 5] = [
    "watch-engine",
    "watch-native-observer",
    "watch-process-control",
    "watch-admin.sh",
    "watch-native-collector.zsh",
];
#[cfg(target_os = "macos")]
const NOFOLLOW: i32 = 0x0100;
#[cfg(not(target_os = "macos"))]
const NOFOLLOW: i32 = 0x20000;
struct StageCleanup {
    path: std::path::PathBuf,
    preserve: bool,
}
impl Drop for StageCleanup {
    fn drop(&mut self) {
        if !self.preserve && self.path.exists() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
fn err(code: &str, message: &str) -> CoreError {
    CoreError::new(code, message)
}
fn run<E: FixedCommandExecutor>(
    executor: &mut E,
    program: &str,
    args: Vec<String>,
) -> Result<crate::release_native::FixedOutput> {
    executor.run(FixedCommand {
        program: program.into(),
        args,
        timeout: Duration::from_secs(20),
    })
}
fn require<E: FixedCommandExecutor>(
    executor: &mut E,
    program: &str,
    args: Vec<String>,
) -> Result<()> {
    let output = run(executor, program, args)?;
    if output.status == 0 {
        Ok(())
    } else {
        Err(err("agent_command_failed", "原生后台操作未成功"))
    }
}
fn definition(engine: &Path) -> Result<Vec<u8>> {
    let logs = engine
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| err("invalid_runtime", "运行目录无效"))?
        .join("logs");
    definition_inner(engine, true, Some(&logs))
}
fn definition_for(engine: &Path, supervised: bool) -> Result<Vec<u8>> {
    definition_inner(engine, supervised, None)
}
fn definition_inner(engine: &Path, supervised: bool, logs: Option<&Path>) -> Result<Vec<u8>> {
    let collector = engine
        .parent()
        .ok_or_else(|| err("invalid_runtime", "运行目录无效"))?
        .join(crate::native_listener::SCRIPT);
    let path = (if supervised {
        collector.as_path()
    } else {
        engine
    })
    .to_str()
    .ok_or_else(|| err("invalid_runtime", "运行组件路径编码无效"))?;
    let escaped = path
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let prefix = if supervised {
        "<string>/bin/zsh</string><string>-f</string>"
    } else {
        ""
    };
    let logs = logs
        .map(|dir| {
            let out = dir.join("native-agent.out.log");
            let err_path = dir.join("native-agent.err.log");
            let out = out.to_str().ok_or_else(|| err("invalid_runtime", "日志路径编码无效"))?;
            let err_path = err_path.to_str().ok_or_else(|| err("invalid_runtime", "日志路径编码无效"))?;
            Ok(format!("<key>StandardOutPath</key><string>{}</string><key>StandardErrorPath</key><string>{}</string>", out.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;"), err_path.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")))
        })
        .transpose()?
        .unwrap_or_default();
    Ok(format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Label</key><string>{LABEL}</string><key>ProgramArguments</key><array>{prefix}<string>{escaped}</string><string>daemon</string><string>--apply</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>5</integer><key>ProcessType</key><string>Background</string>{logs}</dict></plist>\n").into_bytes())
}

fn ensure_agent_logs(store: &StateStore, uid: u32) -> Result<()> {
    let logs = store.paths.watch().join("logs");
    store.guarded(&logs)?;
    store.private_dir(&logs)?;
    for name in ["native-agent.out.log", "native-agent.err.log"] {
        let path = logs.join(name);
        store.guarded(&path)?;
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if !meta.is_file()
                    || meta.file_type().is_symlink()
                    || meta.uid() != uid
                    || meta.mode() & 0o022 != 0
                {
                    return Err(err("unsafe_agent_log", "原生日志路径或权限无效"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(NOFOLLOW)
                    .open(&path)
                    .map_err(|_| err("agent_log_create_failed", "无法创建原生日志文件"))?;
            }
            Err(_) => return Err(err("agent_log_create_failed", "无法读取原生日志路径")),
        }
    }
    Ok(())
}

fn agent_status_summary(text: &str) -> (String, String) {
    let scoped = text.lines().any(|line| line.trim_end().ends_with(" = {"));
    let mut depth = 0usize;
    let mut state = None;
    let mut exit = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line == "}" {
            depth = depth.saturating_sub(1);
            continue;
        }
        if (!scoped && depth == 0) || (scoped && depth == 1) {
            if let Some(value) = line.strip_prefix("state = ") {
                if value.len() <= 64
                    && value
                        .bytes()
                        .all(|v| v.is_ascii_alphanumeric() || b"_- ".contains(&v))
                {
                    state = Some(value.to_owned());
                }
            }
            if let Some(value) = line.strip_prefix("last exit code = ") {
                if value.len() <= 64
                    && value
                        .bytes()
                        .all(|v| v.is_ascii_alphanumeric() || b"_-() ".contains(&v))
                {
                    exit = Some(value.to_owned());
                }
            }
        }
        if line.ends_with(" = {") {
            depth += 1;
        }
    }
    (
        state.unwrap_or_else(|| "unknown".into()),
        exit.unwrap_or_else(|| "unknown".into()),
    )
}

fn wait_for_agent<E: FixedCommandExecutor>(executor: &mut E, label: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let output = executor.run(FixedCommand {
            program: "/bin/launchctl".into(),
            args: vec!["print".into(), label.into()],
            timeout: Duration::from_secs(3),
        })?;
        let (final_state, final_exit) = agent_status_summary(&output.stdout);
        if output.status == 0
            && crate::commands::loaded_agent_identity(&output.stdout)
                .is_some_and(|(state, _)| state == "running")
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(err(
                "agent_install_failed",
                &format!("新后台未在15秒内进入running（最终状态：{final_state}；last exit code：{final_exit}）"),
            ));
        }
        thread::sleep(Duration::from_millis(250));
    }
}
pub(crate) fn tree(root: &Path) -> Result<BTreeMap<String, String>> {
    fn visit(
        base: &Path,
        path: &Path,
        out: &mut BTreeMap<String, String>,
        total: &mut u64,
    ) -> Result<()> {
        if out.len() > 100000 {
            return Err(err("runtime_limit", "运行组件文件过多"));
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| err("runtime_read_failed", "运行组件不可读取"))?;
        if metadata.file_type().is_symlink() {
            return Err(err("unsafe_runtime", "运行组件包含符号链接"));
        }
        if metadata.is_dir() {
            for entry in
                fs::read_dir(path).map_err(|_| err("runtime_read_failed", "运行目录不可读取"))?
            {
                visit(
                    base,
                    &entry
                        .map_err(|_| err("runtime_read_failed", "运行目录项不可读取"))?
                        .path(),
                    out,
                    total,
                )?;
            }
            return Ok(());
        }
        if !metadata.is_file() || metadata.len() > 128 * 1024 * 1024 {
            return Err(err("unsafe_runtime", "运行组件不是大小受限的普通文件"));
        }
        *total = total.saturating_add(metadata.len());
        if *total > 2 * 1024 * 1024 * 1024 {
            return Err(err("runtime_limit", "运行组件总大小超限"));
        }
        let bytes = fs::read(path).map_err(|_| err("runtime_read_failed", "运行组件不可读取"))?;
        out.insert(
            path.strip_prefix(base)
                .map_err(|_| err("unsafe_runtime", "运行组件路径越界"))?
                .to_string_lossy()
                .into_owned(),
            sha256(&bytes),
        );
        Ok(())
    }
    let mut value = BTreeMap::new();
    visit(root, root, &mut value, &mut 0)?;
    Ok(value)
}
fn source_bytes(path: &Path) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| err("runtime_missing", "运行组件缺失"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 128 * 1024 * 1024
    {
        return Err(err("unsafe_runtime", "运行组件不是大小受限的普通文件"));
    }
    #[cfg(target_os = "macos")]
    const NOFOLLOW: i32 = 0x100;
    #[cfg(not(target_os = "macos"))]
    const NOFOLLOW: i32 = 0x20000;
    let mut bytes = Vec::new();
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW)
        .open(path)
        .and_then(|f| f.take(128 * 1024 * 1024 + 1).read_to_end(&mut bytes))
        .map_err(|_| err("runtime_read_failed", "运行组件读取失败"))?;
    if bytes.len() > 128 * 1024 * 1024 {
        return Err(err("runtime_limit", "运行组件超限"));
    }
    Ok(bytes)
}
pub fn install<E: FixedCommandExecutor>(
    store: &StateStore,
    resources: &Path,
    uid: u32,
    executor: &mut E,
) -> Result<Value> {
    install_mode(store, resources, uid, executor, false, &mut |_, _| Ok(()))
}
pub fn install_deferred<E: FixedCommandExecutor>(
    store: &StateStore,
    resources: &Path,
    uid: u32,
    executor: &mut E,
) -> Result<Value> {
    install_mode(store, resources, uid, executor, true, &mut |_, _| Ok(()))
}
/// Run a release preparation step against the final signed runtime before
/// bootstrap. A failed hook follows the existing runtime rollback path.
pub fn install_deferred_with_runtime_hook<E: FixedCommandExecutor>(
    store: &StateStore, resources: &Path, uid: u32, executor: &mut E,
    before_bootstrap: &mut dyn FnMut(&Path, &mut E) -> Result<()>,
) -> Result<Value> {
    install_mode(store, resources, uid, executor, true, before_bootstrap)
}
fn install_mode<E: FixedCommandExecutor>(
    store: &StateStore,
    resources: &Path,
    uid: u32,
    executor: &mut E,
    deferred: bool,
    before_bootstrap: &mut dyn FnMut(&Path, &mut E) -> Result<()>,
) -> Result<Value> {
    if uid == 0
        || fs::metadata(&store.paths.home)
            .map_err(|_| err("invalid_home", "用户目录不可读取"))?
            .uid()
            != uid
    {
        return Err(err("invalid_install_uid", "后台安装用户身份不匹配"));
    }
    let _lock = store.lock("agent-install", None)?;
    let runtime = store.paths.watch().join("runtime");
    let previous = store.paths.watch().join(".runtime.previous");
    let journal = store.paths.watch().join("agent-install-transaction.json");
    for path in [&runtime, &previous, &journal] {
        store.guarded(path)?;
    }
    if previous.exists() || journal.exists() {
        return Err(err("recovery_required", "原生后台安装事务尚未恢复"));
    }
    let output = run(
        executor,
        "/usr/bin/plutil",
        vec![
            "-convert".into(),
            "json".into(),
            "-o".into(),
            "-".into(),
            "--".into(),
            resources.join("BuildInfo.plist").display().to_string(),
        ],
    )?;
    if output.status != 0 {
        return Err(err("invalid_runtime_manifest", "运行组件清单无法解析"));
    }
    let manifest = strict_json(output.stdout.as_bytes())?;
    let hashes = manifest["RuntimeHashes"]
        .as_object()
        .ok_or_else(|| err("invalid_runtime_manifest", "缺少运行组件哈希表"))?;
    if manifest["Architecture"] != "arm64"
        || manifest["BackendVariant"] != "rust-candidate"
        || manifest["RuntimeSchema"] != 2
    {
        return Err(err("invalid_runtime_manifest", "需要 arm64 原生运行组件"));
    }
    for name in COMPONENTS {
        if !hashes.contains_key(name) {
            return Err(err("runtime_missing", "缺少原生运行组件校验项"));
        }
    }
    if crate::background_evidence::supported_manifest(&manifest)? {
        for &name in crate::background_evidence::extra_files(&manifest)? {
            if !hashes.contains_key(name) {
                return Err(err("runtime_missing", "缺少后台DNS/WebRTC检测组件校验项"));
            }
        }
    }
    if manifest["NetworkBackend"] == "seatbelt" && !hashes.contains_key("watch-sandbox-launcher") {
        return Err(err("runtime_missing", "缺少沙盒启动组件校验项"));
    }
    if manifest["NetworkBackend"] == "seatbelt" && !hashes.contains_key("watch-gateway-broker") {
        return Err(err("runtime_missing", "缺少系统托管网关组件校验项（安装运行组件不等于加载系统服务）"));
    }
    let stage = store
        .paths
        .watch()
        .join(format!(".runtime-stage-{}", uuid::Uuid::new_v4().simple()));
    store.private_dir(&stage)?;
    let mut cleanup = StageCleanup {
        path: stage.clone(),
        preserve: false,
    };
    let prepared = (|| {
        for (name, expected) in hashes {
            let rel = Path::new(name);
            if rel.is_absolute() || rel.components().any(|c| !matches!(c, Component::Normal(_))) {
                return Err(err("unsafe_runtime", "运行清单路径越界"));
            }
            let bytes = source_bytes(&resources.join(rel))?;
            if expected.as_str() != Some(sha256(&bytes).as_str()) {
                return Err(err("runtime_hash_mismatch", "运行组件哈希不匹配"));
            }
            store.atomic_bytes(
                &stage.join(rel),
                &bytes,
                if COMPONENTS.contains(&name.as_str())
                    || name == crate::background_evidence::WORKER
                    || name == "watch-sandbox-launcher"
                    || name == "watch-gateway-broker"
                    || name == "ControlledEntry"
                {
                    0o700
                } else {
                    0o600
                },
            )?;
        }
        store.atomic_bytes(
            &stage.join("BuildInfo.plist"),
            &source_bytes(&resources.join("BuildInfo.plist"))?,
            0o600,
        )?;
        tree(&stage)
    })();
    let expected = match prepared {
        Ok(v) => v,
        Err(error) => {
            let _ = fs::remove_dir_all(stage);
            return Err(error);
        }
    };
    let plist = store
        .paths
        .home
        .join(format!("Library/LaunchAgents/{LABEL}.plist"));
    let old_plist = store.read_bytes(&plist, 256 * 1024)?;
    let label = format!("gui/{uid}/{LABEL}");
    let job = run(
        executor,
        "/bin/launchctl",
        vec!["print".into(), label.clone()],
    )?;
    let loaded = if job.status == 0 {
        true
    } else if job.stderr.contains("Could not find service") {
        false
    } else {
        return Err(err("agent_state_unavailable", "旧后台任务状态未确认"));
    };
    if loaded && old_plist.is_none() {
        return Err(err(
            "agent_definition_missing",
            "旧后台正在运行但任务定义缺失，无法保证恢复",
        ));
    }
    let mut transaction = json!({"schema":1,"phase":"prepared","stage":stage,"runtime":runtime,"previous":previous,"previous_plist":old_plist,"expected":expected,"had_runtime":runtime.exists(),"had_agent":loaded});
    store.atomic_json(&journal, &transaction)?;
    cleanup.preserve = true;
    let had_runtime = runtime.exists();
    let outcome = (|| {
        if loaded {
            crate::release_native::stop_user_agent(executor, uid)?;
        }
        if had_runtime {
            fs::rename(&runtime, &previous)
                .map_err(|_| err("runtime_replace_failed", "旧运行组件无法暂存"))?;
        }
        fs::rename(&stage, &runtime)
            .map_err(|_| err("runtime_replace_failed", "新运行组件无法提交"))?;
        ensure_agent_logs(store, uid)?;
        let check = run(
            executor,
            runtime
                .join("watch-engine")
                .to_str()
                .ok_or_else(|| err("invalid_runtime", "运行组件路径编码无效"))?,
            vec![
                "self-check".into(),
                "--home".into(),
                store.paths.home.display().to_string(),
            ],
        )?;
        let receipt = strict_json(check.stdout.as_bytes())?;
        if check.status != 0
            || receipt["status"] != "ok"
            || receipt["engine"] != "rust"
            || receipt["component_integrity"] != true
        {
            return Err(err("runtime_self_check_failed", "新运行组件自检失败"));
        }
        before_bootstrap(&runtime, executor)?;
        store.atomic_bytes(&plist, &definition(&runtime.join("watch-engine"))?, 0o600)?;
        require(
            executor,
            "/bin/launchctl",
            vec![
                "bootstrap".into(),
                format!("gui/{uid}"),
                plist.display().to_string(),
            ],
        )?;
        wait_for_agent(executor, &label)?;
        Ok(())
    })();
    if let Err(error) = outcome {
        if runtime.exists() && tree(&runtime)? != expected && (previous.exists() || !had_runtime) {
            return Err(err(
                "runtime_rollback_conflict",
                "运行组件被外部修改，保留安装事务以恢复",
            ));
        }
        let actual_plist = store.read_bytes(&plist, 256 * 1024)?;
        let intended_plist = definition(&runtime.join("watch-engine"))?;
        if actual_plist != old_plist && actual_plist.as_deref() != Some(intended_plist.as_slice()) {
            return Err(err(
                "runtime_rollback_conflict",
                "任务定义被外部修改，保留安装事务",
            ));
        }
        crate::release_native::stop_agent_for_runtime(executor, uid, &runtime)?;
        if previous.exists() {
            if runtime.exists() {
                fs::remove_dir_all(&runtime)
                    .map_err(|_| err("runtime_rollback_failed", "无法撤回新运行组件"))?;
            }
            fs::rename(&previous, &runtime)
                .map_err(|_| err("runtime_rollback_failed", "无法恢复旧运行组件"))?;
        } else if !had_runtime && runtime.exists() {
            fs::remove_dir_all(&runtime)
                .map_err(|_| err("runtime_rollback_failed", "无法撤回新运行组件"))?;
        }
        match old_plist {
            Some(bytes) => store.atomic_bytes(&plist, &bytes, 0o600)?,
            None => {
                if plist.exists() {
                    fs::remove_file(&plist)
                        .map_err(|_| err("runtime_rollback_failed", "无法恢复旧任务定义"))?;
                }
            }
        }
        if loaded {
            require(
                executor,
                "/bin/launchctl",
                vec![
                    "bootstrap".into(),
                    format!("gui/{uid}"),
                    plist.display().to_string(),
                ],
            )?;
        }
        if stage.exists() {
            let _ = fs::remove_dir_all(&stage);
        }
        fs::remove_file(&journal)
            .map_err(|_| err("runtime_rollback_failed", "无法结束回滚事务"))?;
        return Err(error);
    }
    if deferred {
        transaction["phase"] = json!("verified");
        store.atomic_json(&journal, &transaction)?;
        return Ok(json!({"status":"verified","commit_required":true}));
    }
    transaction["phase"] = json!("committed");
    store.atomic_json(&journal, &transaction)?;
    if previous.exists() {
        fs::remove_dir_all(previous)
            .map_err(|_| err("runtime_cleanup_failed", "旧运行组件清理未完成"))?;
    }
    fs::remove_file(journal).map_err(|_| err("runtime_cleanup_failed", "安装事务清理未完成"))?;
    Ok(
        json!({"status":"ok","runtime":runtime,"agent":LABEL,"engine":"rust","accounts_preserved":true}),
    )
}

/// Resume only the exact fixed-path transaction created by install(). A runtime
/// changed by another writer is preserved for inspection rather than removed.
pub fn recover<E: FixedCommandExecutor>(
    store: &StateStore,
    uid: u32,
    executor: &mut E,
) -> Result<Value> {
    if uid == 0
        || fs::metadata(&store.paths.home)
            .map_err(|_| err("invalid_home", "用户目录不可读取"))?
            .uid()
            != uid
    {
        return Err(err("invalid_install_uid", "后台恢复用户不匹配"));
    }
    let _lock = store.lock("agent-install", None)?;
    let journal = store.paths.watch().join("agent-install-transaction.json");
    let record = store.read_json(&journal, Value::Null)?;
    if record.is_null() {
        return Ok(json!({"status":"ok","recovered":false}));
    }
    let runtime = store.paths.watch().join("runtime");
    let previous = store.paths.watch().join(".runtime.previous");
    let stage = record["stage"]
        .as_str()
        .map(std::path::PathBuf::from)
        .ok_or_else(|| err("invalid_install_journal", "安装暂存路径无效"))?;
    let stage_name = stage.file_name().and_then(|v| v.to_str()).unwrap_or("");
    let suffix = stage_name.strip_prefix(".runtime-stage-").unwrap_or("");
    if record["schema"] != 1
        || record["runtime"] != runtime.to_string_lossy().as_ref()
        || record["previous"] != previous.to_string_lossy().as_ref()
        || stage.parent() != Some(store.paths.watch().as_path())
        || suffix.len() != 32
        || !suffix.bytes().all(|v| v.is_ascii_hexdigit())
    {
        return Err(err(
            "invalid_install_journal",
            "安装恢复记录越过固定路径边界",
        ));
    }
    for path in [&runtime, &previous, &stage] {
        store.guarded(path)?;
    }
    let expected: BTreeMap<String, String> = serde_json::from_value(record["expected"].clone())
        .map_err(|_| err("invalid_install_journal", "安装清单无效"))?;
    if !record["had_runtime"].is_boolean()
        || !record["had_agent"].is_boolean()
        || !matches!(
            record["phase"].as_str(),
            Some("prepared" | "verified" | "committed")
        )
        || expected.len() > 100000
        // Four-component journals were written before the system collector
        // existed. Recovery recognizes that exact older layout, not a new install.
        || COMPONENTS[..4].iter().any(|name| !expected.contains_key(*name))
        || expected.iter().any(|(path, hash)| {
            Path::new(path)
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
                || hash.len() != 64
                || !hash.bytes().all(|v| v.is_ascii_hexdigit())
        })
    {
        return Err(err("invalid_install_journal", "安装恢复字段无效"));
    }
    let previous_plist: Option<Vec<u8>> = serde_json::from_value(record["previous_plist"].clone())
        .map_err(|_| err("invalid_install_journal", "旧任务定义无效"))?;
    if previous_plist
        .as_ref()
        .is_some_and(|v| v.len() > 256 * 1024)
        || (record["had_agent"] == true && previous_plist.is_none())
    {
        return Err(err("invalid_install_journal", "旧任务定义不完整"));
    }
    let plist = store
        .paths
        .home
        .join(format!("Library/LaunchAgents/{LABEL}.plist"));
    let actual_plist = store.read_bytes(&plist, 256 * 1024)?;
    let legacy_new_plist = definition_for(
        &runtime.join("watch-engine"),
        expected.contains_key(crate::native_listener::SCRIPT),
    )?;
    let logged_new_plist = if expected.contains_key(crate::native_listener::SCRIPT) {
        Some(definition(&runtime.join("watch-engine"))?)
    } else {
        None
    };
    if actual_plist != previous_plist
        && actual_plist.as_deref() != Some(legacy_new_plist.as_slice())
        && logged_new_plist
            .as_deref()
            .is_none_or(|definition| actual_plist.as_deref() != Some(definition))
    {
        return Err(err(
            "runtime_rollback_conflict",
            "任务定义被外部修改，未覆盖",
        ));
    }
    let committed = record["phase"] == "committed";
    let new_runtime =
        previous.exists() || record["had_runtime"] == false || (!stage.exists() && committed);
    if runtime.exists() && new_runtime && tree(&runtime)? != expected {
        return Err(err(
            "runtime_rollback_conflict",
            "运行组件被外部修改，未覆盖",
        ));
    }
    if !committed {
        crate::release_native::stop_agent_for_runtime(executor, uid, &runtime)?;
        if previous.exists() {
            if runtime.exists() {
                fs::remove_dir_all(&runtime)
                    .map_err(|_| err("runtime_rollback_failed", "无法移除本次新组件"))?;
            }
            fs::rename(&previous, &runtime)
                .map_err(|_| err("runtime_rollback_failed", "旧组件恢复失败"))?;
        } else if record["had_runtime"] == false && runtime.exists() {
            fs::remove_dir_all(&runtime)
                .map_err(|_| err("runtime_rollback_failed", "新组件恢复失败"))?;
        } else if record["had_runtime"] == true && !stage.exists() {
            return Err(err(
                "runtime_rollback_failed",
                "旧运行组件缺失，保留恢复记录",
            ));
        }
        if let Some(bytes) = previous_plist {
            store.atomic_bytes(&plist, &bytes, 0o600)?;
        } else if plist.exists() {
            fs::remove_file(&plist)
                .map_err(|_| err("runtime_rollback_failed", "任务定义恢复失败"))?;
        }
        if record["had_agent"] == true {
            require(
                executor,
                "/bin/launchctl",
                vec![
                    "bootstrap".into(),
                    format!("gui/{uid}"),
                    plist.display().to_string(),
                ],
            )?;
        }
    } else if previous.exists() {
        fs::remove_dir_all(&previous)
            .map_err(|_| err("runtime_cleanup_failed", "旧组件清理失败"))?;
    }
    if stage.exists() {
        fs::remove_dir_all(stage).map_err(|_| err("runtime_cleanup_failed", "暂存组件清理失败"))?;
    }
    fs::remove_file(journal).map_err(|_| err("runtime_cleanup_failed", "恢复记录清理失败"))?;
    Ok(json!({"status":"ok","recovered":true,"committed":committed}))
}

pub fn commit<E: FixedCommandExecutor>(
    store: &StateStore,
    uid: u32,
    executor: &mut E,
) -> Result<Value> {
    let lock = store.lock("agent-install", None)?;
    let journal = store.paths.watch().join("agent-install-transaction.json");
    let mut record = store.read_json(&journal, Value::Null)?;
    let runtime = store.paths.watch().join("runtime");
    if record["schema"] != 1
        || record["phase"] != "verified"
        || record["runtime"] != runtime.to_string_lossy().as_ref()
    {
        return Err(err("invalid_install_journal", "没有可以提交的原生安装事务"));
    }
    let expected: BTreeMap<String, String> = serde_json::from_value(record["expected"].clone())
        .map_err(|_| err("invalid_install_journal", "组件清单无效"))?;
    if tree(&runtime)? != expected {
        return Err(err("runtime_rollback_conflict", "提交前运行组件已被改变"));
    }
    record["phase"] = json!("committed");
    store.atomic_json(&journal, &record)?;
    drop(lock);
    // Once committed, a cleanup error must not trigger an app-only rollback
    // after the old runtime has already been partially removed.
    match recover(store, uid, executor) {
        Ok(value) => Ok(value),
        Err(error) => Ok(json!({"status":"ok","cleanup_pending":true,"cleanup_error":error.code})),
    }
}
