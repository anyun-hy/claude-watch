//! Release-only integration for the root-owned gateway. The subprocess probe
//! runs as the final user engine and proves the actual socket handoff before
//! the daemon can start. This module is never called by ordinary sampling.
use crate::release_native::{FixedCommand, FixedCommandExecutor, FixedOutput};
use claude_watch_core::error::{CoreError, Result};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
fn error(code: &str, detail: &str) -> CoreError {
    CoreError::new(code, detail)
}
#[derive(Clone)]
pub(crate) struct GatewayTransaction {
    broker: PathBuf,
    engine: PathBuf,
    uid: u32,
    id: String,
    previous_config: String,
}
fn run<E: FixedCommandExecutor>(
    executor: &mut E,
    program: &Path,
    args: Vec<String>,
) -> Result<FixedOutput> {
    let output = executor.run(FixedCommand {
        program: program.into(),
        args,
        timeout: Duration::from_secs(120),
    })?;
    if output.status != 0 {
        let receipt: Value = serde_json::from_str(&output.stdout).unwrap_or(Value::Null);
        let detail = receipt["error"]["message"]
            .as_str()
            .or_else(|| receipt["message"].as_str())
            .filter(|v| !v.is_empty())
            .unwrap_or(output.stderr.trim());
        let code = receipt["error"]["code"]
            .as_str()
            .or_else(|| receipt["code"].as_str())
            .unwrap_or("gateway_install_failed");
        return Err(error(
            code,
            &format!(
                "系统托管网关操作失败（{}）：{}",
                output.status,
                detail.chars().take(1200).collect::<String>()
            ),
        ));
    }
    Ok(output)
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
fn administrator<E: FixedCommandExecutor>(
    executor: &mut E,
    program: &Path,
    args: Vec<String>,
) -> Result<FixedOutput> {
    let mut parts = vec![quote(&program.display().to_string())];
    parts.extend(args.iter().map(|s| quote(s)));
    run(
        executor,
        Path::new("/usr/bin/osascript"),
        vec![
            "-e".into(),
            "on run argv".into(),
            "-e".into(),
            "do shell script (item 1 of argv) with administrator privileges".into(),
            "-e".into(),
            "end run".into(),
            "--".into(),
            parts.join(" "),
        ],
    )
}
fn json(output: FixedOutput) -> Result<Value> {
    serde_json::from_str(&output.stdout)
        .map_err(|_| error("gateway_receipt_invalid", "网关安装返回格式不正确"))
}
pub(crate) fn prepare_and_verify<E: FixedCommandExecutor>(
    executor: &mut E,
    broker: &Path,
    runtime: &Path,
    uid: u32,
    state: &mut Option<GatewayTransaction>,
) -> Result<()> {
    let engine = runtime.join("watch-engine");
    let scope = vec![
        "--uid".into(),
        uid.to_string(),
        "--engine".into(),
        engine.display().to_string(),
    ];
    let preview = json(run(
        executor,
        broker,
        [vec!["--service-preview".into()], scope].concat(),
    )?)?;
    let port = preview["gateway_port"]
        .as_u64()
        .filter(|v| (1..1024).contains(v))
        .ok_or_else(|| error("gateway_preview_invalid", "网关安装预演缺少受保护端口"))?;
    if preview["status"] != "preview"
        || preview["administrator_required"] != true
        || !matches!(preview["action"].as_str(), Some("install" | "upgrade"))
    {
        return Err(error(
            "gateway_preview_invalid",
            "网关安装预演未确认服务归属",
        ));
    }
    let previous_config = preview["previous_config"]
        .as_str()
        .filter(|v| *v == "absent" || (v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())))
        .ok_or_else(|| error("gateway_preview_invalid", "网关安装预演缺少原身份凭据"))?
        .to_string();
    let id = uuid::Uuid::new_v4().simple().to_string();
    let prepared = runtime
        .parent()
        .ok_or_else(|| error("gateway_install_failed", "运行路径无父目录"))?
        .join(format!(".gateway-prepare-{id}"));
    run(
        executor,
        broker,
        vec![
            "--prepare".into(),
            "--output".into(),
            prepared.display().to_string(),
            "--engine".into(),
            engine.display().to_string(),
            "--uid".into(),
            uid.to_string(),
            "--port".into(),
            port.to_string(),
        ],
    )?;
    *state = Some(GatewayTransaction {
        broker: broker.into(),
        engine: engine.clone(),
        uid,
        id: id.clone(),
        previous_config,
    });
    let install = administrator(
        executor,
        broker,
        vec![
            "--service-install".into(),
            "--prepared".into(),
            prepared.display().to_string(),
            "--transaction".into(),
            id.clone(),
        ],
    );
    // Only this invocation's unprivileged preparation directory is cleaned.
    if prepared.is_dir() {
        let _ = fs::remove_dir_all(&prepared);
    }
    let receipt = json(install?)?;
    if receipt["status"] != "prepared" || receipt["transaction"] != id {
        return Err(error(
            "gateway_receipt_invalid",
            "网关安装事务未确认；请检查管理员安装记录",
        ));
    }
    let checked = json(run(
        executor,
        &engine,
        vec!["gateway-endpoint-check".into()],
    )?)?;
    if checked["status"] != "ok"
        || checked["gateway_endpoint"] != format!("127.0.0.1:{port}")
        || checked["ipv4_verified"] != true
        || checked["ipv6_verified"] != true
    {
        return Err(error(
            "gateway_endpoint_unverified_i03",
            "网关监听句柄或真实端点尚未验证，未启动后台",
        ));
    }
    Ok(())
}
pub(crate) fn finish<E: FixedCommandExecutor>(
    executor: &mut E,
    state: &mut Option<GatewayTransaction>,
    rollback: bool,
) -> Result<()> {
    let Some(transaction) = state.as_ref() else {
        return Ok(());
    };
    let action = if rollback {
        "--service-rollback"
    } else {
        "--service-commit"
    };
    let mut args = vec![
        action.into(),
        "--uid".into(),
        transaction.uid.to_string(),
        "--engine".into(),
        transaction.engine.display().to_string(),
        "--transaction".into(),
        transaction.id.clone(),
    ];
    if rollback {
        args.extend([
            "--previous-config".into(),
            transaction.previous_config.clone(),
        ]);
    }
    let receipt = json(administrator(executor, &transaction.broker, args).map_err(
        |mut error| {
            error
                .message
                .push_str(&format!("；待核对的网关事务 {}", transaction.id));
            error
        },
    )?)
    .map_err(|mut error| {
        error
            .message
            .push_str(&format!("；待核对的网关事务 {}", transaction.id));
        error
    })?;
    if receipt["status"] != "ok"
        || receipt["transaction"] != transaction.id
        || receipt["action"] != action
    {
        return Err(error("gateway_receipt_invalid", "系统网关事务结果未确认"));
    }
    *state = None;
    Ok(())
}

pub(crate) fn commit_after_runtime<E: FixedCommandExecutor>(
    executor: &mut E,
    state: &mut Option<GatewayTransaction>,
    commit: impl FnOnce(&mut E) -> Result<()>,
) -> Result<Option<String>> {
    commit(executor)?;
    Ok(finish(executor, state, false).err().map(|error| {
        format!(
            "网关与运行组件已提交；网关事务清理待处理：{}",
            error.message
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    struct Fake {
        calls: Vec<FixedCommand>,
        lost_install_receipt: bool,
        wrong_endpoint: bool,
        fail_commit: bool,
    }
    impl FixedCommandExecutor for Fake {
        fn run(&mut self, c: FixedCommand) -> Result<FixedOutput> {
            crate::release_native::validate_fixed_command(&c)?;
            let mut status = 0;
            let value = if c.args.first().map(String::as_str) == Some("--service-preview") {
                json!({"status":"preview","action":"install","gateway_port":1023,"administrator_required":true,"previous_config":"absent"})
            } else if c.args.first().map(String::as_str) == Some("--prepare") {
                json!({"prepared":true})
            } else if c.args.first().map(String::as_str) == Some("gateway-endpoint-check") {
                json!({"status":"ok","gateway_endpoint":if self.wrong_endpoint {"127.0.0.1:7890"}else{"127.0.0.1:1023"},"ipv4_verified":true,"ipv6_verified":true})
            } else if c.program == Path::new("/usr/bin/osascript") {
                let shell = c.args.last().unwrap();
                let parts: Vec<_> = shell.split('\'').collect();
                let id = parts
                    .iter()
                    .position(|v| *v == "--transaction")
                    .map(|i| parts[i + 2])
                    .unwrap();
                if shell.contains("--service-install") {
                    if self.lost_install_receipt {
                        status = 1;
                    }
                    json!({"status":"prepared","transaction":id})
                } else {
                    let action = if shell.contains("--service-rollback") {
                        "--service-rollback"
                    } else {
                        "--service-commit"
                    };
                    if self.fail_commit && action == "--service-commit" {
                        status = 1;
                    }
                    json!({"status":"ok","action":action,"transaction":id})
                }
            } else {
                panic!("unexpected external command: {c:?}")
            };
            self.calls.push(c);
            Ok(FixedOutput {
                status,
                stdout: value.to_string(),
                stderr: if status == 0 {
                    String::new()
                } else {
                    "fixture lost reply".into()
                },
            })
        }
    }
    fn fake() -> Fake {
        Fake {
            calls: vec![],
            lost_install_receipt: false,
            wrong_endpoint: false,
            fail_commit: false,
        }
    }
    #[test]
    fn final_engine_receives_actual_endpoint_check_before_install_is_accepted() {
        let mut executor = fake();
        let mut state = None;
        prepare_and_verify(
            &mut executor,
            Path::new("/fixture/app/watch-gateway-broker"),
            Path::new("/fixture/runtime"),
            501,
            &mut state,
        )
        .unwrap();
        assert_eq!(
            executor.calls.last().unwrap().program,
            Path::new("/fixture/runtime/watch-engine")
        );
        assert_eq!(
            executor.calls.last().unwrap().args,
            vec!["gateway-endpoint-check"]
        );
        finish(&mut executor, &mut state, false).unwrap();
        assert!(state.is_none());
    }
    #[test]
    fn lost_admin_receipt_retains_transaction_for_verified_rollback() {
        let mut executor = fake();
        executor.lost_install_receipt = true;
        let mut state = None;
        assert!(prepare_and_verify(
            &mut executor,
            Path::new("/fixture/broker"),
            Path::new("/fixture/runtime"),
            501,
            &mut state
        )
        .is_err());
        assert!(state.is_some());
        finish(&mut executor, &mut state, true).unwrap();
        let recovery = executor.calls.last().unwrap().args.last().unwrap();
        assert!(recovery.contains("--service-rollback"));
        assert!(recovery.contains("--previous-config' 'absent"));
        assert!(!executor
            .calls
            .iter()
            .any(|c| c.args.first().map(String::as_str) == Some("gateway-endpoint-check")));
    }
    #[test]
    fn wrong_endpoint_cannot_start_daemon_and_failed_cleanup_retains_recovery() {
        let mut executor = fake();
        executor.wrong_endpoint = true;
        let mut state = None;
        assert_eq!(
            prepare_and_verify(
                &mut executor,
                Path::new("/fixture/broker"),
                Path::new("/fixture/runtime"),
                501,
                &mut state
            )
            .unwrap_err()
            .code,
            "gateway_endpoint_unverified_i03"
        );
        assert!(state.is_some());
        executor.fail_commit = true;
        assert!(finish(&mut executor, &mut state, false).is_err());
        assert!(state.is_some());
        finish(&mut executor, &mut state, true).unwrap();
    }
    #[test]
    fn runtime_commit_failure_keeps_root_rollback_available() {
        let mut executor = fake();
        let mut state = None;
        prepare_and_verify(
            &mut executor,
            Path::new("/fixture/broker"),
            Path::new("/fixture/runtime"),
            501,
            &mut state,
        )
        .unwrap();
        let before = executor.calls.len();
        assert!(
            commit_after_runtime(&mut executor, &mut state, |_| Err(error(
                "fixture_commit_failed",
                "runtime commit failed"
            )))
            .is_err()
        );
        assert_eq!(executor.calls.len(), before);
        assert!(state.is_some());
        finish(&mut executor, &mut state, true).unwrap();
    }
    #[test]
    fn cleanup_failure_after_runtime_commit_is_reported_without_rollback() {
        let mut executor = fake();
        let mut state = None;
        prepare_and_verify(
            &mut executor,
            Path::new("/fixture/broker"),
            Path::new("/fixture/runtime"),
            501,
            &mut state,
        )
        .unwrap();
        executor.fail_commit = true;
        let warning = commit_after_runtime(&mut executor, &mut state, |_| Ok(()))
            .unwrap()
            .unwrap();
        assert!(warning.contains("清理待处理"));
        assert!(state.is_some());
        assert!(!executor.calls.iter().any(|c| c
            .args
            .last()
            .is_some_and(|a| a.contains("--service-rollback"))));
    }
    #[test]
    fn endpoint_json_error_keeps_actual_reason_and_code() {
        struct Failure;
        impl FixedCommandExecutor for Failure {
            fn run(&mut self, c: FixedCommand) -> Result<FixedOutput> {
                crate::release_native::validate_fixed_command(&c)?;
                Ok(FixedOutput{status:1,stderr:String::new(),stdout:json!({"status":"error","error":{"code":"gateway_endpoint_unverified_i03","message":"broker live identity mismatch"}}).to_string()})
            }
        }
        let failed = run(
            &mut Failure,
            Path::new("/fixture/watch-engine"),
            vec!["gateway-endpoint-check".into()],
        )
        .unwrap_err();
        assert_eq!(failed.code, "gateway_endpoint_unverified_i03");
        assert!(failed.message.contains("broker live identity mismatch"));
    }
}
