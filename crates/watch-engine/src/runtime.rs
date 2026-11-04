//! Command dispatch policy shared by the executable and isolated contracts.
use claude_watch_core::{
    cli::Request,
    error::{CoreError, Result},
};
use claude_watch_runtime::{
    accounts::AccountStore,
    audit_store::{AuditOptions, AuditScope, AuditStore},
    commands::SystemRunner,
    config_store::{policy_digest, ConfigStore},
    desktop_native::NativeDesktop,
    macos::{Authority, Macos},
    monitor_snapshot, native,
    network_client::{NetworkClient, UreqTransport},
    platform_mutator::NativePlatformMutator,
    region_catalog::load_system_catalog,
    services,
    session_store::SessionStore,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc};
static LISTENER_STREAM: std::sync::OnceLock<
    Arc<claude_watch_runtime::native_listener::ListenerStream>,
> = std::sync::OnceLock::new();
pub type Host = Macos<Arc<SystemRunner>, UreqTransport, NativePlatformMutator>;
/// Commands which may mutate local or system state always require the parser's
/// explicit `--apply` acknowledgement before an adapter is invoked.
pub fn require_apply(request: &Request) -> Result<()> {
    let writes = matches!(
        (request.command.as_str(), request.action.as_deref()),
        ("config", Some("set"))
            | ("account", Some("switch" | "recover"))
            | ("setup", Some("apply" | "recover"))
            | ("protection", Some("apply"))
    ) || matches!(
        request.command.as_str(),
        "restore-settings" | "services" | "launch" | "dns-leak-record" | "webrtc-risk-record"
    ) || (request.command == "update" && request.flag("recover"));
    if writes {
        request.require_apply()
    } else {
        Ok(())
    }
}
pub fn runner() -> Result<Arc<SystemRunner>> {
    let executable = std::env::current_exe()
        .map_err(|_| CoreError::new("executable_unavailable", "无法定位运行组件"))?;
    let packaged = executable
        .parent()
        .ok_or_else(|| CoreError::new("invalid_executable", "运行组件目录无效"))?
        .join("watch-native-observer");
    let mut runner = if packaged.is_file() {
        SystemRunner::new(&packaged)?
    } else if cfg!(debug_assertions) {
        SystemRunner::development()?
    } else {
        return Err(CoreError::new(
            "native_observer_missing",
            "缺少已打包的原生采样组件",
        ));
    };
    if let Some(stream) = LISTENER_STREAM.get() {
        runner = runner.with_listener_stream(stream.clone());
    }
    Ok(Arc::new(runner))
}
pub fn initialize_native_listener(request: &Request) -> Result<()> {
    match std::env::var("CW_NATIVE_LISTENER_STREAM") {
        Err(std::env::VarError::NotPresent) => return Ok(()),
        Ok(v) if v == "1" && matches!(request.command.as_str(), "daemon" | "proxy-check") => {}
        _ => {
            return Err(CoreError::new(
                "native_listener_arguments",
                "系统采样管道仅用于固定后台或只读代理检查",
            ))
        }
    }
    let runner = runner()?;
    let exe = std::env::current_exe()
        .map_err(|_| CoreError::new("executable_unavailable", "无法定位原生组件"))?;
    let stream =
        claude_watch_runtime::native_listener::ListenerStream::start(runner.as_ref(), &exe)?;
    LISTENER_STREAM
        .set(stream)
        .map_err(|_| CoreError::new("native_listener_already_initialized", "采样管道已初始化"))
}
pub fn host(paths: Paths, authority: Authority) -> Result<Host> {
    let storage = StateStore::new(paths);
    let network = NetworkClient::new(Arc::new(UreqTransport), None)
        .map_err(|e| CoreError::new(&e.code, &e.detail))?
        .with_state_store(storage.clone());
    let mutator = NativePlatformMutator::new(storage.clone())?;
    Ok(Macos {
        runner: Arc::new(
            Arc::try_unwrap(runner()?)
                .map_err(|_| CoreError::new("runner_shared", "采样器初始化冲突"))?
                .with_listener_cache(storage.clone()),
        ),
        network,
        storage,
        authority,
        mutator,
        probes: Arc::new(claude_watch_runtime::online_probes::NativeProbes),
    })
}
pub(crate) fn process_component() -> Result<PathBuf> {
    let executable = std::env::current_exe()
        .map_err(|_| CoreError::new("executable_unavailable", "无法定位运行组件"))?;
    let candidate = executable.parent().unwrap().join("watch-process-control");
    if candidate.is_file() {
        Ok(candidate)
    } else if cfg!(debug_assertions) {
        native::built_process_control_path()
            .map(Into::into)
            .ok_or_else(|| CoreError::new("process_component_missing", "缺少原生进程组件"))
    } else {
        Err(CoreError::new(
            "process_component_missing",
            "缺少原生进程组件",
        ))
    }
}
fn project_session_heartbeat(
    status: &mut Value,
    session_id: &str,
    running: Option<bool>,
    heartbeat: &Value,
) {
    let matching = heartbeat["session_id"].as_str() == Some(session_id);
    let applicable = matching && heartbeat["stop_state"] != "session_changed";
    if status["phase"] != "ended"
        && applicable
        && heartbeat["persistence_error"] == "state_io_failed"
        && heartbeat["session_guard"]["reason"]["code"] == "egress_risk_persist_failed"
    {
        status["state"] = json!("locked");
        status["phase"] = json!("locked");
        status["reason"] = heartbeat["session_guard"]["reason"].clone();
    }
    if status["state"] == "locked" {
        if running == Some(false) {
            status["stop_state"] = json!("confirmed");
        } else if applicable {
            if heartbeat["stop_state"] != "confirmed" {
                status["stop_state"] = heartbeat["stop_state"].clone();
                status["stop_error"] = heartbeat["stop_error"].clone();
            }
        }
    }
}

pub fn session_view(host: &Host) -> Value {
    let session = SessionStore::new(host.storage.clone()).load(native::now());
    let ended_session = session
        .as_ref()
        .ok()
        .and_then(|v| v.as_ref())
        .is_some_and(|s| s.state == claude_watch_core::session::Phase::Ended);
    let running = NativeDesktop::new(
        host.runner.clone(),
        process_component().unwrap_or_default(),
        Authority::ReadOnly,
    )
    .ok()
    .and_then(|d| {
        let processes = d.desktops().ok()?;
        if processes.is_empty() && ended_session {
            d.desktop_tree_running().ok()
        } else {
            Some(!processes.is_empty())
        }
    });
    match session {
        Ok(Some(s)) => {
            let mut status = claude_watch_core::session::status(&s, native::now(), running);
            let heartbeat = host
                .storage
                .read_json(
                    &host.storage.paths.base().join("guard-heartbeat.json"),
                    Value::Null,
                )
                .unwrap_or(Value::Null);
            project_session_heartbeat(&mut status, &s.session_id, running, &heartbeat);
            status
        }
        Ok(None) => {
            json!({"state":if running==Some(false){"idle"}else{"missing"},"detail":if running==Some(false){"后台保护待命，无需操作"}else{"尚无受控启动会话"}})
        }
        Err(e) => json!({"state":"unknown","reason":{"code":e.code,"detail":e.message}}),
    }
}
fn background(host: &Host) -> Result<Value> {
    let config = ConfigStore {
        storage: host.storage.clone(),
    }
    .load()?;
    let mut value = services::service_status(host, &config)?;
    let at = value["observed_at"].clone();
    for row in value["services"].as_array_mut().into_iter().flatten() {
        let detail = match (
            row["id"].as_str().unwrap_or(""),
            row["state"].as_str().unwrap_or(""),
        ) {
            ("guard", "running") => "保护心跳与后台身份已确认",
            (_, "inactive") => "该后台任务已停用",
            ("updater", "unavailable") => "尚未配置本项目发布源或固定公钥",
            (_, "scheduled") => "任务已注册并按计划运行",
            (_, "mismatch") => "实际后台状态与已保存意愿不同",
            (_, "error") => "实际后台健康未通过核对",
            _ => "尚未取得完整后台运行证据",
        };
        row["detail"] = json!(detail);
        row["last_checked"] = at.clone();
    }
    value["session_guard"] = session_view(host);
    Ok(value)
}
pub fn dispatch_read(request: &Request, paths: Paths) -> Result<Option<Value>> {
    if ![
        "self-check",
        "snapshot",
        "status",
        "service-status",
        "check",
        "checkdetail",
        "environment",
        "proxy-check",
        "dns-check",
    ]
    .contains(&request.command.as_str())
    {
        return Ok(None);
    }
    let mut host = host(paths, Authority::ReadOnly)?;
    match request.command.as_str() {
        "self-check" => {
            use claude_watch_runtime::commands::{ReadCommand, ReadRunner};
            use std::time::Duration;
            let current = std::env::current_exe()
                .map_err(|_| CoreError::new("runtime_incomplete", "无法定位运行组件"))?;
            let resources = current
                .parent()
                .ok_or_else(|| CoreError::new("runtime_incomplete", "运行组件路径无效"))?;
            let out = host.runner.run(
                ReadCommand::Plist(resources.join("BuildInfo.plist")),
                &[],
                Duration::from_secs(5),
                1024 * 1024,
            )?;
            if out.status != 0 {
                return Err(CoreError::new("runtime_incomplete", "缺少运行组件校验清单"));
            }
            let manifest = claude_watch_runtime::storage::strict_json(&out.stdout)?;
            if manifest["Architecture"] != "arm64" {
                return Err(CoreError::new(
                    "architecture_mismatch",
                    "运行组件不是 arm64",
                ));
            }
            let mut required = vec![
                "watch-engine",
                "watch-native-observer",
                "watch-process-control",
                "watch-admin.sh",
                "watch-native-collector.zsh",
            ];
            if claude_watch_runtime::background_evidence::supported_manifest(&manifest)? {
                required.extend_from_slice(claude_watch_runtime::background_evidence::extra_files(
                    &manifest,
                )?);
            }
            for name in required {
                let path = resources.join(name);
                let metadata = std::fs::symlink_metadata(&path)
                    .map_err(|_| CoreError::new("runtime_incomplete", "缺少原生运行组件"))?;
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.len() > 128 * 1024 * 1024
                {
                    return Err(CoreError::new("runtime_incomplete", "原生组件文件格式无效"));
                }
                let bytes = std::fs::read(path)
                    .map_err(|_| CoreError::new("runtime_incomplete", "原生运行组件不可读取"))?;
                if manifest["RuntimeHashes"][name] != claude_watch_runtime::storage::sha256(&bytes)
                {
                    return Err(CoreError::new(
                        "runtime_hash_mismatch",
                        "原生组件校验未通过",
                    ));
                }
            }
            ConfigStore {
                storage: host.storage.clone(),
            }
            .load()?;
            AccountStore::new(host.storage.clone(), super::ReadOnlyAccounts).status()?;
            Ok(Some(
                json!({"status":"ok","schema":1,"engine":"rust","component_integrity":true,"checks":14,"grants_launch_permission":false}),
            ))
        }
        "snapshot" => {
            let at = native::now();
            Ok(Some(
                monitor_snapshot::read(&host.storage, host.runner.as_ref())
                    .unwrap_or_else(|e| monitor_snapshot::empty(&host.storage, at, &e.message)),
            ))
        }
        "service-status" => Ok(Some(background(&host)?)),
        "status" => {
            let config_store = ConfigStore {
                storage: host.storage.clone(),
            };
            let config = config_store.load()?;
            let legacy_openai_force_review = config_store.legacy_force_pending()?;
            let mut audit = host.storage.read_json(
                &host.storage.paths.base().join("last-audit.json"),
                Value::Null,
            )?;
            if audit["policy"] != policy_digest(&config.value()?)? {
                audit = Value::Null
            }
            let accounts = AccountStore::new(host.storage.clone(), super::ReadOnlyAccounts)
                .status()?
                .value();
            let env = host.environment().ok();
            Ok(Some(
                json!({"status":"ok","config":config.value()?,"legacy_openai_force_review":legacy_openai_force_review,"accounts":accounts,"audit":audit,"service_status":background(&host)?,"netcoffee_lookup":audit["netcoffee_lookup"],"source_notices":audit.get("source_notices").unwrap_or(&json!([])),
                "repair":host.storage.read_json(&host.storage.paths.base().join("last-repair.json"),Value::Null)?,"guard":host.storage.read_json(&host.storage.paths.base().join("guard-heartbeat.json"),Value::Null)?,
                "update_recovery_required":host.storage.paths.base().join("update-transaction.json").exists(),"setup_recovery_required":host.storage.paths.base().join("setup-transaction.json").exists()||host.storage.paths.base().join("service-transaction.json").exists()||host.storage.paths.watch().join("agent-install-transaction.json").exists(),"proxy_groups":[],
                "claude_version":env.as_ref().and_then(|v|v.pointer("/claude_app/version")).and_then(Value::as_str).unwrap_or("")}),
            ))
        }
        "check" | "checkdetail" | "environment" | "proxy-check" | "dns-check" => {
            let environment = request.command == "environment";
            let scope = match request.command.as_str() {
                "proxy-check" => AuditScope::Proxy,
                "dns-check" => AuditScope::Dns,
                _ => AuditScope::Full,
            };
            let persist = if environment {
                request.flag("record")
            } else {
                !request.flag("no-report")
            };
            let zones = if scope == AuditScope::Full {
                load_system_catalog()
            } else {
                Default::default()
            };
            let store = AuditStore::new(host.storage.clone());
            let options = AuditOptions {
                online: request.flag("online"),
                persist,
                launch: false,
            };
            // The same stage announcements the launch path uses, so a launch
            // requirements preview shows which part of the check is running
            // rather than sitting still until the whole audit finishes.
            if !environment && scope == AuditScope::Full {
                claude_watch_runtime::setup_progress::emit(
                    claude_watch_runtime::setup_progress::Phase::CollectEvidence,
                );
            }
            let (mut audit, guard_diagnostics) = if environment {
                store.collect_environment(&mut host, &zones, request.launch_target(), options)?
            } else if scope == AuditScope::Full {
                (
                    store.collect_target(&mut host, &zones, request.launch_target(), options)?,
                    None,
                )
            } else {
                (
                    store.collect_scope(&mut host, &zones, scope, options)?,
                    None,
                )
            };
            if !environment && scope == AuditScope::Full {
                claude_watch_runtime::setup_progress::emit(
                    claude_watch_runtime::setup_progress::Phase::VerifyLaunchConditions,
                );
            }
            audit["grants_launch_permission"] = json!(false);
            if !environment && scope == AuditScope::Full {
                audit["purpose"] = json!("launch_requirements_preview");
            }
            Ok(Some(if environment {
                let mut receipt = claude_watch_runtime::environment_display::receipt(
                    &host.storage,
                    audit,
                    session_view(&host),
                    persist,
                )?;
                if let Some(trace) = guard_diagnostics {
                    if let Ok(value) = serde_json::to_value(trace) {
                        receipt["guard_diagnostics"] = value;
                    }
                }
                receipt
            } else {
                audit
            }))
        }
        _ => unreachable!(),
    }
}

/// One recovery entry coordinates the existing component services. It does
/// not invent a second transaction format or override account/update recovery.
pub fn recover_maintenance(request: &Request, paths: Paths) -> Result<Value> {
    request.require_apply()?;
    let mut host = host(paths, Authority::ExplicitPermit)?;
    let storage = host.storage.clone();
    let mut restored = Vec::new();
    if storage
        .paths
        .watch()
        .join("agent-install-transaction.json")
        .exists()
    {
        // Only the coordinated recovery entry holds this internal capability.
        // Account/update recovery may not cross an unfinished agent install.
        let _operation = storage.lock("operation", Some("maintenance"))?;
        let uid = host.environment()?["uid"]
            .as_u64()
            .and_then(|u| u32::try_from(u).ok())
            .filter(|u| *u > 0)
            .ok_or_else(|| CoreError::new("uid_unavailable", "当前用户身份未确认"))?;
        let value = claude_watch_runtime::agent_install::recover(
            &storage,
            uid,
            &mut claude_watch_runtime::release_native::SystemExecutor,
        )?;
        if value["status"] == "partial" {
            return Ok(value);
        }
        restored.push(json!({"component":"agent","result":value}));
    }
    if storage
        .paths
        .base()
        .join("service-transaction.json")
        .exists()
    {
        let value = services::recover(&storage, &mut host)?;
        if value["status"] == "partial" {
            return Ok(value);
        }
        restored.push(json!({"component":"services","result":value}));
    }
    if storage.paths.base().join("setup-transaction.json").exists() {
        let value = claude_watch_runtime::onboarding::recover(&storage, &mut host)?;
        if value["status"] == "partial" {
            return Ok(value);
        }
        restored.push(json!({"component":"setup","result":value}));
    }
    Ok(
        json!({"status":"ok","recovered":restored,"message":"已检查并恢复环境、服务和原生后台安装事务"}),
    )
}

/// Native command boundary. Parsing and explicit apply checks happen before
/// constructing any adapter capable of controlling the desktop.
pub enum OperationOutcome {
    Receipt(Value),
    CliExit(claude_watch_runtime::controlled::CliOutcome),
}
pub fn dispatch_operations(request: &Request, paths: Paths) -> Result<Option<OperationOutcome>> {
    use claude_watch_runtime::{
        account_native::AccountRuntimeHost, audit_store::AuditSystem, controlled::Controller,
        desktop_native::DesktopRuntime, receipt_store::ReceiptStore,
    };
    use std::time::Instant;
    let account_action = request.command == "account"
        && matches!(
            request.action.as_deref(),
            Some("switch" | "recover" | "import")
        );
    if !account_action
        && !matches!(
            request.command.as_str(),
            "launch" | "guard-tick" | "dns-leak-record" | "webrtc-risk-record"
        )
    {
        return Ok(None);
    }
    if request.command != "guard-tick"
        && !(request.command == "account" && request.action.as_deref() == Some("import"))
    {
        request.require_apply()?;
    }
    let mut host = host(paths, Authority::ExplicitPermit)?;
    let storage = host.storage.clone();
    if matches!(
        request.command.as_str(),
        "dns-leak-record" | "webrtc-risk-record"
    ) {
        let value = super::bounded_input(request.input_limit())?;
        let probe = value.get("probe").unwrap_or(&value);
        let expected = value.get("expected_context").and_then(Value::as_str);
        let config = ConfigStore {
            storage: storage.clone(),
        }
        .load()?;
        let local = AuditSystem::local(&host, &config)?;
        let receipts = ReceiptStore { storage };
        if request.command == "dns-leak-record" {
            let receipt = receipts.record_dns(probe, &local, expected, native::now())?;
            let context = receipt["context"].as_str().unwrap_or("");
            let current =
                receipts.dns_status(context, false, native::now(), |at| format!("{at:.0}"));
            return Ok(Some(OperationOutcome::Receipt(
                json!({"status":"ok","context_id":receipt["context"],"sampled_at":receipt["finished_at"],"dns_row":claude_watch_core::receipts::dns_row(&current),"receipt":receipt}),
            )));
        }
        return Ok(Some(OperationOutcome::Receipt(
            json!({"status":"ok","receipt":receipts.record_webrtc(probe,&local,expected,native::now())?}),
        )));
    }
    let authority = if request.flag("apply") || request.command == "guard-tick" {
        Authority::ExplicitPermit
    } else {
        Authority::ReadOnly
    };
    let mut desktop = NativeDesktop::new(host.runner.clone(), process_component()?, authority)?;
    if request.command == "launch" {
        if request.launch_target().cli() {
            desktop.select_cli(request.launch_target(), &storage.paths.home)?;
        } else {
            desktop.select_target(request.launch_target())?;
        }
    }
    if account_action {
        let config = ConfigStore {
            storage: storage.clone(),
        }
        .load()?;
        let legacy = storage.paths.home.join(".claude-switcher");
        let native = AccountRuntimeHost {
            storage: storage.clone(),
            controller: Controller::new(storage.clone()),
            desktop,
            network: host.network.clone(),
            system: host,
        };
        let mut accounts = AccountStore::new(storage, native);
        return Ok(Some(OperationOutcome::Receipt(
            match request.action.as_deref() {
                Some("switch") => accounts
                    .switch(
                        request
                            .target
                            .as_deref()
                            .ok_or_else(|| CoreError::new("invalid_account", "需要账号 A 或 B"))?,
                        &config,
                        request.flag("ack-unverified-version"),
                    )?
                    .value(),
                Some("recover") => {
                    accounts.recover()?;
                    json!({"status":"ok","accounts":accounts.status()?.value()})
                }
                Some("import") => accounts
                    .import_legacy(&legacy, request.flag("apply"))?
                    .value(),
                _ => unreachable!(),
            },
        )));
    }
    let mut desktop_runtime = DesktopRuntime {
        desktop: &mut desktop,
        network: host.network.clone(),
        system: &mut host,
        storage: storage.clone(),
        started: Instant::now(),
        cli: None,
    };
    let controller = Controller::new(storage.clone());
    if request.command == "launch" {
        if request.launch_target().cli() {
            return Ok(Some(OperationOutcome::CliExit(
                controller.launch_cli(&mut desktop_runtime, &request.child_args)?,
            )));
        }
        let _operation = storage.lock("operation", None)?;
        Ok(Some(OperationOutcome::Receipt(
            controller.launch(&mut desktop_runtime)?,
        )))
    } else {
        Ok(Some(OperationOutcome::Receipt(
            controller.guard_tick(&mut desktop_runtime)?,
        )))
    }
}

#[cfg(test)]
mod session_heartbeat_projection_tests {
    use super::*;
    fn heartbeat(id: &str, stop: &str) -> Value {
        json!({"session_id":id,"persistence_error":"state_io_failed", "stop_state":stop,
            "stop_error":"quit_failed", "session_guard":{"reason":{"code":"egress_risk_persist_failed","detail":"risk"}}})
    }
    #[test]
    fn projection_binds_risk_and_stop_to_current_session_and_observation() {
        let safe = json!({"state":"safe"});
        let mut other = safe.clone();
        project_session_heartbeat(&mut other, "new", Some(true), &heartbeat("old", "failed"));
        assert_eq!(other, safe);
        let mut superseded = safe.clone();
        project_session_heartbeat(
            &mut superseded,
            "same",
            Some(true),
            &heartbeat("same", "session_changed"),
        );
        assert_eq!(superseded, safe);
        let mut failed = safe.clone();
        project_session_heartbeat(
            &mut failed,
            "same",
            Some(true),
            &heartbeat("same", "failed"),
        );
        assert_eq!(failed["state"], "locked");
        assert_eq!(failed["stop_state"], "failed");
        for running in [Some(true), None] {
            let mut current = safe.clone();
            project_session_heartbeat(
                &mut current,
                "same",
                running,
                &heartbeat("same", "confirmed"),
            );
            assert_eq!(current["state"], "locked");
            assert!(current.get("stop_state").is_none());
        }
        let mut stopped = safe.clone();
        project_session_heartbeat(
            &mut stopped,
            "same",
            Some(false),
            &heartbeat("same", "confirmed"),
        );
        assert_eq!(stopped["stop_state"], "confirmed");
        let mut ended = json!({"state":"idle","phase":"ended"});
        project_session_heartbeat(
            &mut ended,
            "same",
            Some(false),
            &heartbeat("same", "failed"),
        );
        assert_eq!(
            ended["state"], "idle",
            "a stale failure cannot resurrect an ended session"
        );
    }
}
