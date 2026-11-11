//! Product commands for opt-in, user-owned controlled entry files.
use crate::runtime;
use claude_watch_core::{
    cli::Request,
    error::{CoreError, Result},
    processes::LaunchTarget,
};
use claude_watch_runtime::{
    commands::{ReadCommand, ReadRunner},
    managed_entry_activation::{
        observe_entry, EntryActivity, EntryShell, EntrySource, ManagedEntryActivationManager,
    },
    native,
    sampler::Sampler,
    storage::{sha256, strict_json, StateStore},
    target_discovery::DiscoveryHandle,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

fn verify_components(
    runner: &impl ReadRunner,
    engine: &Path,
    target: LaunchTarget,
) -> Result<Option<Vec<u8>>> {
    let root = engine
        .parent()
        .ok_or_else(|| CoreError::new("runtime_incomplete", "运行组件目录不存在"))?;
    let dir = claude_watch_system::anchored_files::Dir::absolute(root, false)
        .map_err(|_| CoreError::new("runtime_incomplete", "运行组件目录不安全"))?;
    let out = runner.run(
        ReadCommand::Plist(root.join("BuildInfo.plist")),
        &[],
        Duration::from_secs(5),
        1024 * 1024,
    )?;
    if out.status != 0 {
        return Err(CoreError::new(
            "runtime_incomplete",
            "缺少可读的运行组件清单",
        ));
    }
    let manifest = strict_json(&out.stdout)?;
    if manifest["Architecture"] != "arm64" || manifest["NetworkBackend"] != "seatbelt" {
        return Err(CoreError::new(
            "entry_backend_unavailable",
            "入口须使用当前 arm64 nono/Seatbelt 安装",
        ));
    }
    if engine.file_name().and_then(|n| n.to_str()) != Some("watch-engine") {
        return Err(CoreError::new(
            "entry_component_mismatch",
            "当前运行程序不是清单中的 watch-engine",
        ));
    }
    let mut result = None;
    let components = if target.cli() {
        &["watch-engine", "watch-sandbox-launcher"][..]
    } else {
        &[
            "watch-engine",
            "watch-sandbox-launcher",
            "watch-process-control",
            "ControlledEntry",
        ][..]
    };
    for component in components {
        let error = || {
            CoreError::new(
                "entry_component_unverified",
                &format!("运行组件缺失或无法校验：{component}"),
            )
        };
        let file = dir.read(component).map_err(|_| error())?;
        let metadata = file.metadata().map_err(|_| error())?;
        const LIMIT: u64 = 128 * 1024 * 1024;
        if !metadata.is_file()
            || metadata.len() > LIMIT
            || metadata.permissions().mode() & 0o111 == 0
        {
            return Err(error());
        }
        let mut bytes = Vec::new();
        file.take(LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| error())?;
        if bytes.len() as u64 != metadata.len()
            || manifest["RuntimeHashes"][*component] != sha256(&bytes)
        {
            return Err(error());
        }
        if *component == "ControlledEntry" {
            result = Some(bytes);
        }
    }
    Ok(result)
}

fn resolve(
    request: &Request,
    target: LaunchTarget,
    store: &StateStore,
    manager: &ManagedEntryActivationManager,
    discovery: &DiscoveryHandle,
    runner: &impl ReadRunner,
) -> Result<EntrySource> {
    let now = native::now();
    if target.cli() {
        if request.value("target-bundle").is_some() {
            return Err(CoreError::new(
                "entry_bundle_requires_desktop",
                "CLI 入口不能选择应用包",
            ));
        }
        let mut env = BTreeMap::new();
        for key in ["PATH", "CLAUDE_CODE_BIN", "CODEX_CLI_BIN"] {
            if let Some(value) = std::env::var_os(key) {
                let value = value
                    .into_string()
                    .map_err(|_| CoreError::new("cli_environment_invalid", "CLI 来源环境无效"))?;
                env.insert(key.to_owned(), value);
            }
        }
        // Only filters our requested destination during selection. This value
        // is never used as evidence of invocation, activation or protection.
        env.insert(
            "CW_SHIM_EXECUTABLE".into(),
            manager.destination(target)?.to_string_lossy().into_owned(),
        );
        let (_, record) = discovery.select_cli(runner, target, &env, now)?;
        let kind = record
            .kind()
            .ok_or_else(|| CoreError::new("entry_target_unverified", "CLI 安装身份尚未核验"))?;
        let executable = record
            .executable
            .ok_or_else(|| CoreError::new("entry_target_unverified", "未找到 CLI 执行文件"))?;
        let sha256 = claude_watch_system::sha256_file_hex(&executable)
            .ok_or_else(|| CoreError::new("entry_target_unverified", "CLI 执行文件内容无法核验"))?;
        return Ok(EntrySource::Cli {
            entry_path: record.entry_path,
            executable,
            sha256,
            kind,
            script: record.script_entry.is_some(),
        });
    }
    let (snapshot, record) = if let Some(path) = request.value("target-bundle") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(CoreError::new(
                "entry_invalid_path",
                "指定应用包必须是绝对路径",
            ));
        }
        let path = std::fs::canonicalize(path)
            .map_err(|_| CoreError::new("selected_source_unavailable", "指定应用包不可访问"))?;
        discovery.desktop_source(target, &path);
        let snapshot = discovery.refresh(runner, now);
        let record = snapshot
            .targets
            .iter()
            .find(|r| {
                r.entry_path == path
                    && r.valid()
                    && r.kind().is_some_and(|kind| target.accepts(kind))
            })
            .cloned()
            .ok_or_else(|| {
                CoreError::new("selected_source_unavailable", "指定应用包尚未通过来源核验")
            })?;
        (snapshot, record)
    } else {
        discovery.select_desktop(runner, target, now)?
    };
    let _ = store;
    let kind = record
        .kind()
        .ok_or_else(|| CoreError::new("entry_target_unverified", "应用身份未核验"))?;
    Ok(EntrySource::Desktop {
        spec: discovery.managed_spec(&snapshot, &record, target)?,
        kind,
    })
}

pub(crate) fn dispatch(request: &Request, storage: StateStore) -> Result<Value> {
    let target = request
        .value("target")
        .or(request.target.as_deref())
        .and_then(LaunchTarget::parse)
        .ok_or_else(|| CoreError::new("invalid_target", "请明确选择受控入口目标"))?;
    let action = request.action.as_deref().unwrap_or("preview");
    if matches!(action, "activate" | "deactivate") {
        request.require_apply()?;
    }
    let engine = std::env::current_exe()
        .map_err(|_| CoreError::new("runtime_incomplete", "无法定位当前 watch-engine"))?;
    let launcher = engine.with_file_name("watch-sandbox-launcher");
    let controlled_entry = if action == "activate" {
        verify_components(runtime::runner()?.as_ref(), &engine, target)?
    } else {
        None
    };
    let mut manager =
        ManagedEntryActivationManager::new(storage.clone(), engine, launcher, controlled_entry);
    if let Some(s) = request.value("shims-dir") {
        manager.set_shims_dir(s.into());
    }
    if let Some(a) = request.value("applications-dir") {
        manager.set_applications_dir(a.into());
    }
    if let Some(s) = request.value("shell") {
        if !target.cli() {
            return Err(CoreError::new(
                "entry_shell_requires_cli",
                "桌面入口不修改 shell",
            ));
        }
        manager.set_shell(EntryShell::parse(s)?);
    }
    if action == "deactivate" {
        return Ok(json!({"status":"ok", "result": manager.deactivate(target)?}));
    }

    let runner = runtime::runner()?;
    let discovery = DiscoveryHandle::for_home(&storage.paths.home);
    let source = resolve(
        request,
        target,
        &storage,
        &manager,
        &discovery,
        runner.as_ref(),
    );
    match action {
        "preview" => Ok(json!({"status":"ok", "preview":manager.preview(target, &source?)?})),
        "activate" | "status" => {
            let (activity, source_issue) = match &source {
                Ok(source) => {
                    let mut targets = vec![];
                    if matches!(source, EntrySource::Cli { script: true, .. }) {
                        let mut sampler = Sampler::new(runner.clone(), storage.paths.clone());
                        sampler.set_discovery(discovery);
                        let round = sampler.processes()?;
                        if !round.complete && action == "activate" {
                            return Err(CoreError::new(
                                "entry_inventory_pending",
                                "脚本进程身份尚未核验，未启用入口",
                            ));
                        }
                        targets = round.targets;
                    }
                    (
                        observe_entry(&storage, target, source, &targets, native::now())?,
                        None,
                    )
                }
                Err(e) if action == "status" => (EntryActivity::default(), Some(e.code.clone())),
                Err(e) => return Err(e.clone()),
            };
            if action == "activate" {
                Ok(json!({"status":"ok", "result":manager.activate(target, &source?, &activity)?}))
            } else {
                Ok(
                    json!({"status":"ok", "status_report":manager.status(target, activity)?, "source_issue":source_issue}),
                )
            }
        }
        _ => Err(CoreError::new("invalid_entry_action", "未知的入口操作")),
    }
}
