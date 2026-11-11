use claude_watch_core::{
    cli::Request,
    error::{CoreError, Result},
};
use claude_watch_runtime::{
    events::{AlertOutcome, EventStore},
    lease_store::LeaseStore,
    macos::{Authority, Mutator},
    macos_mutations::AdminCommand,
    native,
    native_notifications::NativeNotifier,
    release_native::{FixedCommand, FixedCommandExecutor, SystemExecutor},
    services::ServiceSystem,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::time::Duration;
pub fn dispatch(request: &Request, paths: Paths) -> Result<Option<Value>> {
    if matches!(
        request.command.as_str(),
        "arm" | "pause" | "snooze" | "test-alert"
    ) {
        let storage = StateStore::new(paths);
        let events = EventStore::new(storage.clone());
        let now = native::now();
        let result = match request.command.as_str() {
            "arm" => {
                LeaseStore { storage }.revoke_all()?;
                let mode = events.arm(
                    &format!("cli-{}-{}", std::process::id(), now.to_bits()),
                    now,
                )?;
                json!({"status":"ok","mode":mode,"message":"恢复警戒通知；撤销观察会话关联，不退出应用或关闭 IP 保护"})
            }
            "pause" => {
                json!({"status":"ok","mode":events.pause(now)?,"message":"通知已静默，采样和保护继续运行"})
            }
            "snooze" => {
                let minutes = request
                    .value("minutes")
                    .and_then(|v| v.parse::<u16>().ok())
                    .ok_or_else(|| CoreError::new("invalid_arguments", "需要 1–1440 分钟"))?;
                json!({"status":"ok","mode":events.snooze(minutes,now)?,"message":"通知已定时静默，采样和保护继续运行"})
            }
            _ => {
                let result = events.test_alert(&NativeNotifier::system(), now)?;
                json!({"status":if matches!(result,AlertOutcome::Failed(_)){"error"}else{"ok"},"outcome":format!("{result:?}"),"message":"测试通知请求已处理；不代表通知中心已允许显示"})
            }
        };
        return Ok(Some(result));
    }
    if request.command == "uninstall" {
        if !request.flag("apply") {
            return Ok(Some(
                json!({"status":"preview","keep_accounts":!request.flag("purge-accounts"),"message":"停止新增保护和更新任务；现有 Claude 数据目录不删除"}),
            ));
        }
        request.require_apply()?;
        if request.flag("remove-managed-rules") {
            return Err(CoreError::new(
                "vpn_managed_externally",
                "VPN 与代理规则由外部客户端管理，Watch 不再修改外部规则文件；请在代理客户端中管理规则",
            ));
        }
        let options = claude_watch_runtime::uninstall::Options {
            purge_accounts: request.flag("purge-accounts"),
            confirm_data_removal: request.flag("confirm-data-removal"),
            remove_managed_rules: request.flag("remove-managed-rules"),
        };
        if options.purge_accounts && !options.confirm_data_removal {
            return Err(CoreError::new(
                "data_confirmation_required",
                "清理账号库需明确指定 --confirm-data-removal",
            ));
        }
        let mut host = crate::runtime::host(paths, Authority::ExplicitPermit)?;
        let storage = host.storage.clone();
        return claude_watch_runtime::uninstall::apply(&storage, options, || {
            let state = host.service_job("updater")?;
            let before = state["registered"].as_bool().ok_or_else(|| {
                CoreError::new("service_unknown", "更新任务状态无法确认，未删除数据")
            })?;
            host.mutator
                .apply(&json!({"id":"updater","before":before,"after":false}))?;
            if std::path::Path::new(
                "/Library/Application Support/ClaudeWatch/claude-watch-admin.sh",
            )
            .exists()
            {
                host.mutator.administrative(AdminCommand::Uninstall)?;
            }
            Ok(())
        })
        .map(Some);
    }
    if request.command != "services" {
        return Ok(None);
    }
    request.require_apply()?;
    if request.action.as_deref() == Some("recover") {
        return crate::runtime::recover_maintenance(request, paths).map(Some);
    }
    let mut host = crate::runtime::host(paths, Authority::ExplicitPermit)?;
    let storage = host.storage.clone();
    match request.action.as_deref() {
        Some("update-on" | "update-off") => {
            let _lock = storage.lock("operation", None)?;
            let enabled = request.action.as_deref() == Some("update-on");
            let state = host.service_job("updater")?;
            let before = state["registered"].as_bool().ok_or_else(|| {
                CoreError::new("service_unknown", "更新任务状态未确认，未执行变更")
            })?;
            host.mutator
                .apply(&json!({"id":"updater","before":before,"after":enabled}))?;
            Ok(Some(json!({"status":"ok","enabled":enabled})))
        }
        Some("refresh-admin") => {
            let _lock = storage.lock("operation", None)?;
            host.mutator.administrative(AdminCommand::Status)?;
            let state = host.admin_helper_status()?;
            if state["trusted"] != true {
                return Err(CoreError::new("admin_unconfirmed", "系统组件未能回读确认"));
            }
            Ok(Some(
                json!({"status":"ok","message":"系统辅助组件已通过身份校验"}),
            ))
        }
        Some("disable-legacy") => {
            let _lock = storage.lock("operation", None)?;
            let uid = uid(&host)?;
            let label = format!("gui/{uid}/local.claude-update");
            let mut executor = SystemExecutor;
            let state = executor.run(FixedCommand {
                program: "/bin/launchctl".into(),
                args: vec!["print".into(), label.clone()],
                timeout: Duration::from_secs(5),
            })?;
            if state.status == 0 {
                let output = executor.run(FixedCommand {
                    program: "/bin/launchctl".into(),
                    args: vec!["bootout".into(), label],
                    timeout: Duration::from_secs(15),
                })?;
                if output.status != 0 {
                    return Err(CoreError::new(
                        "legacy_stop_failed",
                        "旧用户更新任务未能停用",
                    ));
                }
            } else if !state.stderr.contains("Could not find service") {
                return Err(CoreError::new(
                    "legacy_state_unknown",
                    "旧用户任务状态不可读取",
                ));
            }
            host.mutator.administrative(AdminCommand::LegacyStop)?;
            let orig = host.service_job("original")?;
            let leg_tz = host.service_job("legacy_watchdog")?;
            if orig["registered"] != json!(false) || leg_tz["registered"] != json!(false) {
                return Err(CoreError::new(
                    "legacy_stop_unconfirmed",
                    "原版系统守护未能确认停用",
                ));
            }
            Ok(Some(
                json!({"status":"ok","message":"已按明确命令停用旧后台；原应用与账号资料保留"}),
            ))
        }
        _ => Err(CoreError::new("invalid_arguments", "未知后台管理动作")),
    }
}
fn uid(host: &crate::runtime::Host) -> Result<u32> {
    host.environment()?["uid"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v > 0)
        .ok_or_else(|| CoreError::new("uid_unavailable", "当前用户身份未确认"))
}
