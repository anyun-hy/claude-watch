mod ai_dispatch;
mod channel_audit;
mod coffee_dispatch;
mod daemon_run;
mod evidence_run;
mod diagnostics_dispatch;
mod diagnostic_queue;
mod dns_dispatch;
mod install_dispatch;
mod maintenance_dispatch;
mod reference_dispatch;
mod reinstall_dispatch;
mod runtime;
mod setup_dispatch;
mod update_dispatch;
use claude_watch_core::error::{CoreError, Result};
use claude_watch_runtime::{
    commands::SystemRunner,
    sampler::{pinned_node, Sampler},
    storage::Paths,
};
use serde_json::{json, Value};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

struct ReadOnlyAccounts;
impl claude_watch_runtime::accounts::AccountOs for ReadOnlyAccounts {
    fn claude_version(&mut self) -> Result<Option<String>> {
        Ok(None)
    }
    fn quit_claude(&mut self) -> Result<()> {
        Err(CoreError::new("read_only", "只读入口不控制Claude"))
    }
    fn claude_running(&mut self) -> Result<bool> {
        Err(CoreError::new("read_only", "此入口只读取本地槽位"))
    }
    fn launch_claude(&mut self) -> Result<()> {
        Err(CoreError::new("read_only", "只读入口不启动Claude"))
    }
    fn preflight(&mut self) -> Result<()> {
        Err(CoreError::new("read_only", "只读入口不授予启动许可"))
    }
}
fn bounded_input(limit: usize) -> Result<Value> {
    let mut data = Vec::new();
    std::io::stdin()
        .take(limit as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| CoreError::new("input_unavailable", "输入不可读取"))?;
    if data.len() > limit {
        return Err(CoreError::new("oversize_input", "输入超过资源上限"));
    }
    claude_watch_runtime::storage::strict_json(&data)
}
fn export_new(path: &Path, data: &[u8]) -> Result<()> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| CoreError::new("export_failed", "导出目录不可读取"))?
            .join(path)
    };
    for ancestor in path.ancestors() {
        if std::fs::symlink_metadata(ancestor).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(CoreError::new("unsafe_export_path", "拒绝通过符号链接导出"));
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| CoreError::new("export_failed", "导出目标已存在或不可写"))?;
    file.write_all(data)
        .and_then(|_| file.sync_all())
        .map_err(|_| CoreError::new("export_failed", "导出未完成"))
}
fn local_command(request: &claude_watch_core::cli::Request, paths: Paths) -> Result<Option<Value>> {
    use claude_watch_runtime::{
        accounts::AccountStore, config_store::ConfigStore, events::EventStore, storage::StateStore,
    };
    let storage = StateStore::new(paths);
    let config = ConfigStore {
        storage: storage.clone(),
    };
    match (request.command.as_str(), request.action.as_deref()) {
        ("config", Some("show")) => Ok(Some(config.load()?.value()?)),
        ("config", Some("enabled")) => Ok(Some(
            json!({"status":"ok","enabled":config.load()?.enabled}),
        )),
        ("config", Some("set")) => {
            request.require_apply()?;
            let saved = config.save_with_force_confirmation(
                bounded_input(request.input_limit())?,
                request.value("confirm-force"),
            )?;
            Ok(Some(json!({"status":"ok","config":saved.value()?})))
        }
        ("account", Some("status")) => Ok(Some(
            AccountStore::new(storage, ReadOnlyAccounts)
                .status()?
                .value(),
        )),
        ("logs", _) => {
            let events = EventStore::new(storage);
            let data = events.export(100)?;
            if let Some(path) = request.value("export") {
                let encoded = serde_json::to_vec(&data)
                    .map_err(|_| CoreError::new("export_failed", "记录无法编码"))?;
                export_new(Path::new(path), &encoded)?;
                Ok(Some(
                    json!({"status":"ok","message":"操作记录已导出，不含账号资料"}),
                ))
            } else {
                Ok(Some(
                    json!({"status":"ok","events":data,"message":serde_json::to_string(&events.recent(100)?).map_err(|_|CoreError::new("event_encoding_failed","记录无法编码"))?}),
                ))
            }
        }
        ("event-history", _) => {
            let input = bounded_input(request.input_limit())?;
            let query: claude_watch_runtime::monitor_snapshot::EventHistoryQuery =
                serde_json::from_value(input)
                    .map_err(|_| CoreError::new("invalid_event_query", "事件筛选条件无效"))?;
            Ok(Some(claude_watch_runtime::monitor_snapshot::event_history(
                &storage, &query,
            )?))
        }
        ("event-diagnostic", _) => {
            request.require_apply()?;
            let input = bounded_input(request.input_limit())?;
            let input: claude_watch_runtime::events::DiagnosticEventInput =
                serde_json::from_value(input)
                    .map_err(|_| CoreError::new("invalid_event", "诊断日志格式无效"))?;
            let recorded = EventStore::new(storage)
                .record_diagnostic(&input, claude_watch_runtime::native::now())?;
            Ok(Some(json!({"status":"ok","recorded":recorded})))
        }
        ("receipt-diagnostic", _) => {
            request.require_apply()?;
            let input: claude_watch_runtime::events::ReceiptDiagnosticInput = serde_json::from_value(bounded_input(request.input_limit())?).map_err(|_| CoreError::new("invalid_event", "回执诊断格式无效"))?;
            let recorded = EventStore::new(storage).record_receipt_diagnostic(&input, claude_watch_runtime::native::now())?;
            Ok(Some(json!({"status":"ok","recorded":recorded})))
        }
        ("guard-diagnostic", _) => {
            request.require_apply()?;
            let input: claude_watch_runtime::guard_diagnostics::GuardRound =
                serde_json::from_value(bounded_input(request.input_limit())?)
                    .map_err(|_| CoreError::new("invalid_guard_diagnostic", "保护心跳诊断格式无效"))?;
            let recorded = EventStore::new(storage)
                .record_guard_diagnostic(&input, claude_watch_runtime::native::now())?;
            Ok(Some(json!({"status":"ok","recorded":recorded})))
        }
        _ => Ok(None),
    }
}

fn result_code(value: &Value) -> i32 {
    if matches!(value["status"].as_str(), Some("error" | "partial")) {
        4
    } else {
        0
    }
}
enum EngineOutput {
    Receipt(Value, i32),
    Cli(claude_watch_runtime::controlled::CliOutcome),
}
impl EngineOutput {
    fn json(value: Value, code: i32) -> Self {
        Self::Receipt(value, code)
    }
}
fn command_arguments(args: &[String]) -> Result<(Option<PathBuf>, Vec<String>)> {
    let mut home = std::env::var_os("HOME").map(PathBuf::from);
    let mut filtered = Vec::new();
    let mut index = 0;
    let mut opaque = false;
    while index < args.len() {
        if args[index] == "--" {
            opaque = true;
        }
        if !opaque && args[index] == "--home" {
            index += 1;
            home = Some(PathBuf::from(args.get(index).ok_or_else(|| {
                CoreError::new("invalid_arguments", "缺少用户数据目录")
            })?));
        } else {
            filtered.push(args[index].clone());
        }
        index += 1;
    }
    Ok((home, filtered))
}
fn run() -> Result<EngineOutput> {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|value| {
            value.into_string().map_err(|_| {
                CoreError::new("invalid_arguments", "命令接口要求UTF-8参数，未启动程序")
            })
        })
        .collect::<Result<_>>()?;
    if args.first().map(String::as_str) == Some("--channel-audit-worker") {
        if args.len() != 2 { return Err(CoreError::new("invalid_audit_request", "审计组件参数无效")); }
        let value = channel_audit::worker(&args[1], bounded_input(4096)?)?;
        return Ok(EngineOutput::json(value, 0));
    }
    if args == ["--version"] {
        return Ok(EngineOutput::json(
            json!({"schema":1,"status":"ok","engine":"rust","version":env!("CARGO_PKG_VERSION"),"backend_version":claude_watch_runtime::monitor_snapshot::VERSION,"runtime_schema":2,"migration_complete":false}),
            0,
        ));
    }
    if args == ["--component-paths"] {
        return Ok(EngineOutput::json(
            json!({"native_observer":claude_watch_runtime::native::built_observer_path(),"process_control":claude_watch_runtime::native::built_process_control_path()}),
            0,
        ));
    }
    let Some(_) = args.first().map(String::as_str) else {
        return Err(CoreError::new("command_required", "需要明确的命令"));
    };
    let (home, filtered) = command_arguments(&args)?;
    let request = claude_watch_core::cli::Request::parse(&filtered)?.execution();
    if request.command == "diagnose-proxy" {
        let data = if request.flag("stdin-config") {
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(65537)
                .read_to_end(&mut bytes)
                .map_err(|_| CoreError::new("input_unavailable", "配置输入不可读取"))?;
            Some(bytes)
        } else {
            None
        };
        return diagnostics_dispatch::dispatch(&request, data)?
            .map(|(value, code)| EngineOutput::json(value, code))
            .ok_or_else(|| CoreError::new("invalid_arguments", "诊断请求无效"));
    }
    let uid = {
        use claude_watch_runtime::release_native::{
            FixedCommand, FixedCommandExecutor, SystemExecutor,
        };
        let identity = SystemExecutor.run(FixedCommand {
            program: "/usr/bin/id".into(),
            args: vec!["-u".into()],
            timeout: std::time::Duration::from_secs(2),
        })?;
        let uid = identity
            .stdout
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|uid| *uid > 0);
        if identity.status != 0 || uid.is_none() {
            return Err(CoreError::new(
                "user_required",
                "普通运行组件必须以登录用户运行，请勿使用 sudo",
            ));
        }
        uid.unwrap()
    };
    if request.command == "reinstall" {
        let value = reinstall_dispatch::dispatch(&request, uid)?;
        return Ok(EngineOutput::json(value.unwrap_or(serde_json::Value::Null), 0));
    }
    runtime::require_apply(&request)?;
    let paths = Paths::new(
        home.ok_or_else(|| CoreError::new("home_unavailable", "当前用户目录不可读取"))?,
    )?;
    paths.require_owner(uid)?;
    runtime::initialize_native_listener(&request)?;
    if let Some(value) = install_dispatch::dispatch(&request, paths.clone(), uid)? {
        return Ok(EngineOutput::json(value, 0));
    }
    if request.command == "daemon" {
        return Ok(EngineOutput::json(daemon_run::run(&request, paths)?, 0));
    }
    if request.command == "dns-probe" {
        use claude_watch_runtime::network_client::{NetworkClient, UreqTransport, DEFAULT_PROXY};
        let runner = runtime::runner()?;
        let network = NetworkClient::new(
            std::sync::Arc::new(UreqTransport),
            Some(DEFAULT_PROXY.into()),
        )
        .map_err(|e| CoreError::new(&e.code, &e.detail))?;
        return Ok(EngineOutput::json(
            dns_dispatch::dispatch(&request, runner.as_ref(), &network)?.unwrap(),
            0,
        ));
    }
    if let Some(value) = ai_dispatch::dispatch(&request)? {
        // A partial/timeout observation is still a valid JSON receipt for the
        // GUI, matching the Python collector's zero exit behaviour.
        return Ok(EngineOutput::json(value, 0));
    }
    if let Some(value) = reference_dispatch::dispatch(&request)? {
        return Ok(EngineOutput::json(value, 0));
    }
    if let Some(value) = coffee_dispatch::dispatch(&request, paths.clone())? {
        return Ok(EngineOutput::json(value, 0));
    }
    if let Some(value) = maintenance_dispatch::dispatch(&request, paths.clone())? {
        let code = result_code(&value);
        return Ok(EngineOutput::json(value, code));
    }
    if let Some(value) = local_command(&request, paths.clone())? {
        let code = if request.command == "config"
            && request.action.as_deref() == Some("enabled")
            && value["enabled"] == false
        {
            3
        } else {
            result_code(&value)
        };
        return Ok(EngineOutput::json(value, code));
    }
    if let Some(value) = runtime::dispatch_read(&request, paths.clone())? {
        let code = if matches!(request.command.as_str(), "proxy-check" | "dns-check") {
            if value["state"] == "fail" {
                4
            } else if value["state"] == "unknown"
                || !value["evidence"]["dns_refresh"]["error"].is_null()
            {
                3
            } else {
                0
            }
        } else if matches!(request.command.as_str(), "check" | "checkdetail")
            && request.flag("require-ready")
            && value["ready"] != true
        {
            4
        } else {
            0
        };
        return Ok(EngineOutput::json(value, code));
    }
    if let Some(value) = setup_dispatch::dispatch(&request, paths.clone())? {
        let code = result_code(&value);
        return Ok(EngineOutput::json(value, code));
    }
    if let Some(value) = update_dispatch::dispatch(&request, paths.clone())? {
        let code = result_code(&value);
        return Ok(EngineOutput::json(value, code));
    }
    if let Some(value) = runtime::dispatch_operations(&request, paths.clone())? {
        return Ok(match value {
            runtime::OperationOutcome::Receipt(value) => {
                let code = result_code(&value);
                EngineOutput::json(value, code)
            }
            runtime::OperationOutcome::CliExit(outcome) => EngineOutput::Cli(outcome),
        });
    }
    if request.command != "observe" {
        return Err(CoreError::new(
            "unsupported_command",
            "该命令的原生运行链正在迁移，未执行任何系统动作",
        ));
    }
    let executable = std::env::current_exe()
        .map_err(|_| CoreError::new("executable_unavailable", "无法定位运行组件"))?;
    let packaged = executable
        .parent()
        .ok_or_else(|| CoreError::new("invalid_executable", "运行组件目录无效"))?
        .join("watch-native-observer");
    let runner = if packaged.is_file() {
        SystemRunner::new(&packaged)?
    } else if cfg!(debug_assertions) {
        SystemRunner::development()?
    } else {
        return Err(CoreError::new(
            "native_observer_missing",
            "缺少已打包的原生采样组件",
        ));
    };
    let mut sampler = Sampler::new(runner, paths);
    let processes = sampler.processes()?;
    let sockets = sampler.sockets(&processes)?;
    let pin = pinned_node(&sampler.paths, "");
    let tag = sampler.tag_report(&processes, &sockets, "", &pin);
    Ok(EngineOutput::json(
        json!({"schema":1,"status":"ok","mode":"read_only","grants_launch_permission":false,"engine":"rust","processes":processes.public_value(),"tag":tag}),
        0,
    ))
}
fn emit(output: EngineOutput, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    match output {
        EngineOutput::Receipt(value, code) => {
            if writeln!(out, "{value}").is_err() {
                4
            } else {
                code
            }
        }
        EngineOutput::Cli(result) => {
            if let Some(message) = result.diagnostic {
                let _ = writeln!(err, "{message}");
            }
            result.exit_code
        }
    }
}
fn main() {
    match run() {
        Ok(output) => {
            let code = emit(output, &mut std::io::stdout(), &mut std::io::stderr());
            if code != 0 {
                std::process::exit(code);
            }
        }
        Err(error) => {
            let code = if ["invalid_arguments", "unknown_command", "command_required"]
                .contains(&error.code.as_str())
            {
                2
            } else {
                4
            };
            println!(
                "{}",
                json!({"schema":1,"status":"error","code":error.code,"message":error.message,"grants_launch_permission":false})
            );
            std::process::exit(code)
        }
    }
}

#[cfg(test)]
mod output_contracts {
    use super::*;
    #[test]
    fn child_home_apply_and_secrets_are_not_parent_arguments() {
        let args = [
            "--home",
            "/tmp/parent",
            "launch",
            "--target",
            "codex-cli",
            "--",
            "--home",
            "/tmp/child",
            "--apply",
            "SYNTHETIC_PROMPT",
        ]
        .map(str::to_owned);
        let (home, control) = command_arguments(&args).unwrap();
        assert_eq!(home, Some(PathBuf::from("/tmp/parent")));
        let request = claude_watch_core::cli::Request::parse(&control).unwrap();
        assert!(!request.flag("apply"));
        assert_eq!(
            request.child_args,
            vec!["--home", "/tmp/child", "--apply", "SYNTHETIC_PROMPT"]
        );
    }
    #[test]
    fn cli_output_does_not_append_rpc_json_or_change_child_exit() {
        let mut stdout = b"{\"child\":true}\n".to_vec();
        let mut stderr = Vec::new();
        let code = emit(
            EngineOutput::Cli(claude_watch_runtime::controlled::CliOutcome {
                exit_code: 7,
                diagnostic: Some("cleanup warning".into()),
            }),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 7);
        assert_eq!(stdout, b"{\"child\":true}\n");
        assert_eq!(stderr, b"cleanup warning\n");
        let code = emit(
            EngineOutput::json(json!({"stdout_forwarded":true}), 0),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0);
        assert!(stdout.ends_with(b"{\"stdout_forwarded\":true}\n"));
    }
}
