//! Release-only integration for the root-owned gateway. The subprocess probe
//! runs as the final user engine and proves the actual socket handoff before
//! the daemon can start. This module is never called by ordinary sampling.
use crate::release_native::{FixedCommand, FixedCommandExecutor, FixedOutput};
use claude_watch_core::error::{CoreError, Result};
use claude_watch_system::launchd_gateway::{GatewayInstallConfig, TRANSACTION_DIR};
use serde_json::Value;
use std::{
    fs,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
fn error(code: &str, detail: &str) -> CoreError {
    CoreError::new(code, detail)
}
#[derive(Clone)]
pub(crate) struct GatewayTransaction {
    broker: PathBuf,
    broker_sha: String,
    engine: PathBuf,
    uid: u32,
    id: String,
    previous_config: String,
    approval_generation: u64,
}
#[derive(Clone)]
pub(crate) struct GatewayComponentPins {
    pub engine_sha: String,
    pub broker_sha: String,
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
const BOOTSTRAP: &str = include_str!("release_gateway_bootstrap.pl");
const ADMIN_SCRIPT: &[&str] = &[
    "on run argv",
    "set commandText to \"/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/perl\"",
    "repeat with argumentValue in argv",
    "set commandText to commandText & \" \" & quoted form of (contents of argumentValue)",
    "end repeat",
    "do shell script commandText with administrator privileges",
    "end run",
];
fn bootstrap_args(request: &[String]) -> Vec<String> {
    let mut args: Vec<_> = BOOTSTRAP.lines().map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .flat_map(|line| ["-e".into(), line.to_owned()])
        .collect();
    args.push("--".into());
    args.extend_from_slice(request);
    args
}
fn administrator<E: FixedCommandExecutor>(
    executor: &mut E,
    transaction: &GatewayTransaction,
    action: &str,
    prepared: Option<(&Path, &str)>,
) -> Result<FixedOutput> {
    let (prepared, config_sha) = prepared.map_or((String::new(), String::new()), |(p, sha)| {
        (p.display().to_string(), sha.to_owned())
    });
    let request = [
        action.into(), transaction.broker.display().to_string(), transaction.broker_sha.clone(),
        prepared, config_sha, format!("{TRANSACTION_DIR}/next/watch-gateway-broker"),
        transaction.id.clone(), transaction.uid.to_string(), transaction.engine.display().to_string(),
        transaction.previous_config.clone(),
        transaction.approval_generation.to_string(),
    ];
    let mut args: Vec<_> = ADMIN_SCRIPT.iter().flat_map(|line| ["-e".into(), (*line).into()]).collect();
    args.push("--".into());
    args.extend(bootstrap_args(&request));
    run(executor, Path::new("/usr/bin/osascript"), args)
}
fn regular_path(path: &Path) -> Result<PathBuf> {
    if !fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file()) {
        return Err(error("gateway_authorization_mismatch", "批准的网关文件不是普通文件"));
    }
    fs::canonicalize(path).map_err(|_| error("gateway_authorization_mismatch", "批准的网关路径不可读取"))
}
fn prepared_config(path: &Path) -> Result<(GatewayInstallConfig, String)> {
    const LIMIT: u64 = 16 * 1024;
    let rejected = || error("gateway_authorization_mismatch", "网关准备配置不可核验");
    let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path).map_err(|_| rejected())?;
    if !file.metadata().is_ok_and(|m| m.is_file() && m.len() <= LIMIT) { return Err(rejected()); }
    let mut raw = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut raw).map_err(|_| rejected())?;
    if raw.len() as u64 > LIMIT { return Err(rejected()); }
    let cfg: GatewayInstallConfig = crate::storage::strict_json(&raw)
        .and_then(|v| serde_json::from_value(v).map_err(|_| rejected()))?;
    cfg.validate().map_err(|_| rejected())?;
    Ok((cfg, crate::storage::sha256(&raw)))
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
    pins: &GatewayComponentPins,
    state: &mut Option<GatewayTransaction>,
) -> Result<()> {
    let broker = regular_path(broker)?;
    let engine = regular_path(&runtime.join("watch-engine"))?;
    if claude_watch_system::sha256_file_hex(&broker).as_deref() != Some(pins.broker_sha.as_str())
        || claude_watch_system::sha256_file_hex(&engine).as_deref() != Some(pins.engine_sha.as_str())
    {
        return Err(error("gateway_authorization_mismatch", "待批准文件与已核验发行清单不符"));
    }
    let scope = vec![
        "--uid".into(),
        uid.to_string(),
        "--engine".into(),
        engine.display().to_string(),
    ];
    let preview = json(run(
        executor,
        &broker,
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
    let approval_generation = preview["approval_generation"].as_u64()
        .ok_or_else(|| error("gateway_preview_invalid", "网关安装预演缺少授权代次"))?;
    let id = uuid::Uuid::new_v4().simple().to_string();
    let prepared = runtime
        .parent()
        .ok_or_else(|| error("gateway_install_failed", "运行路径无父目录"))?
        .join(format!(".gateway-prepare-{id}"));
    run(
        executor,
        &broker,
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
    let captured = (|| {
        if !fs::symlink_metadata(&prepared).is_ok_and(|m| m.is_dir()) {
            return Err(error("gateway_authorization_mismatch", "网关准备路径不是普通目录"));
        }
        let (config, config_sha) = prepared_config(&prepared.join("config.json"))?;
        if config.engine_uid != uid || Path::new(&config.engine_executable) != engine
            || u64::from(config.gateway_port) != port || config.engine_sha256 != pins.engine_sha
            || config.broker_sha256 != pins.broker_sha
        {
            return Err(error("gateway_authorization_mismatch", "准备配置与批准的用户、端口或发行组件不符"));
        }
        Ok((fs::canonicalize(&prepared).map_err(|_| error("gateway_authorization_mismatch", "准备路径不可核验"))?, config_sha))
    })();
    let (prepared_canonical, config_sha) = match captured {
        Ok(v) => v,
        Err(e) => { let _ = fs::remove_dir_all(&prepared); return Err(e); }
    };
    *state = Some(GatewayTransaction {
        broker,
        broker_sha: pins.broker_sha.clone(),
        engine: engine.clone(),
        uid,
        id: id.clone(),
        previous_config,
        approval_generation,
    });
    let install = administrator(executor, state.as_ref().unwrap(), "install", Some((&prepared_canonical, &config_sha)));
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
    let receipt = json(administrator(executor, transaction, if rollback { "rollback" } else { "commit" }, None).map_err(
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
    struct FixtureRoot(PathBuf);
    impl Drop for FixtureRoot {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }
    fn root() -> FixtureRoot {
        let dir = std::env::temp_dir().canonicalize().unwrap().join(format!("cw-approval-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir(&dir).unwrap();
        FixtureRoot(dir)
    }
    struct Fake {
        root: FixtureRoot,
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
                json!({"status":"preview","action":"install","gateway_port":1023,"administrator_required":true,"previous_config":"absent","approval_generation":42})
            } else if c.args.first().map(String::as_str) == Some("--prepare") {
                let prepared = Path::new(&c.args[2]);
                let engine = Path::new(&c.args[4]);
                fs::create_dir(prepared).unwrap();
                fs::copy(&c.program, prepared.join("watch-gateway-broker")).unwrap();
                fs::write(prepared.join("config.json"), json!({
                    "schema_version":1,"gateway_port":1023,"engine_uid":501,"engine_executable":engine,
                    "engine_sha256":claude_watch_system::sha256_file_hex(engine).unwrap(),"engine_cdhash":"1".repeat(40),
                    "broker_sha256":claude_watch_system::sha256_file_hex(&c.program).unwrap(),"broker_cdhash":"2".repeat(40),
                }).to_string()).unwrap();
                json!({"prepared":true})
            } else if c.args.first().map(String::as_str) == Some("gateway-endpoint-check") {
                json!({"status":"ok","gateway_endpoint":if self.wrong_endpoint {"127.0.0.1:7890"}else{"127.0.0.1:1023"},"ipv4_verified":true,"ipv6_verified":true})
            } else if c.program == Path::new("/usr/bin/osascript") {
                let request = &c.args[c.args.len() - 11..];
                let id = &request[6];
                assert_eq!(request[2], claude_watch_system::sha256_file_hex(Path::new(&request[1])).unwrap());
                assert_eq!(request[10], "42");
                if request[0] == "install" {
                    if self.lost_install_receipt {
                        status = 1;
                    }
                    json!({"status":"prepared","transaction":id})
                } else {
                    let action = format!("--service-{}", request[0]);
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
        let root = root();
        fs::create_dir(root.0.join("runtime")).unwrap();
        fs::write(root.0.join("broker"), b"broker fixture").unwrap();
        fs::write(root.0.join("runtime/watch-engine"), b"engine fixture").unwrap();
        Fake {
            root,
            calls: vec![],
            lost_install_receipt: false,
            wrong_endpoint: false,
            fail_commit: false,
        }
    }
    fn fixture_prepare(executor: &mut Fake, state: &mut Option<GatewayTransaction>) -> Result<()> {
        let broker = executor.root.0.join("broker");
        let runtime = executor.root.0.join("runtime");
        let pins = GatewayComponentPins {
            engine_sha: claude_watch_system::sha256_file_hex(&runtime.join("watch-engine")).unwrap(),
            broker_sha: claude_watch_system::sha256_file_hex(&broker).unwrap(),
        };
        prepare_and_verify(executor, &broker, &runtime, 501, &pins, state)
    }
    #[test]
    fn fixed_bootstrap_executes_only_preapproved_private_snapshot() {
        use std::os::unix::fs::symlink;
        let dir = root();
        let prepared = dir.0.join("prepared");
        fs::create_dir(&prepared).unwrap();
        let source = dir.0.join("broker");
        let recovery = dir.0.join("saved");
        let payload = prepared.join("watch-gateway-broker");
        let config = prepared.join("config.json");
        let bytes = b"#!/bin/sh\ncase \"$0\" in /private/tmp/.cw-gateway-*/watch-gateway-broker) ;; *) exit 77;; esac\ncase \"$(umask)\" in 0022|022) ;; *) exit 76;; esac\nif [ \"$1\" = --service-install ]; then [ \"${12}\" = --approval-generation ] && [ \"${13}\" = 42 ] || exit 75; fi\nprintf '%s\\n' \"$1\"\n";
        let raw = b"{\"broker\":\"approved\"}";
        let pin = crate::storage::sha256(bytes);
        let cfg = crate::storage::sha256(raw);
        let exec = |mode: &str| {
            let request = [
                mode.into(), source.display().to_string(), pin.clone(), prepared.display().to_string(),
                cfg.clone(), recovery.display().to_string(), "c".repeat(32), "501".into(),
                dir.0.join("engine").display().to_string(), "absent".into(), "42".into(),
            ];
            std::process::Command::new("/usr/bin/perl").env_clear()
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .args(bootstrap_args(&request)).current_dir(&dir.0).output().unwrap()
        };
        fs::write(&source, bytes).unwrap();
        fs::write(&payload, bytes).unwrap();
        fs::write(&config, raw).unwrap();
        let clean = exec("install");
        assert!(clean.status.success(), "{}", String::from_utf8_lossy(&clean.stderr));
        assert_eq!(clean.stdout, b"--service-install\n");
        let reject = |label| {
            let result = exec("install");
            assert!(!result.status.success() && result.stdout.is_empty(), "{label}");
            assert!(String::from_utf8_lossy(&result.stderr).contains("gateway_authorization_mismatch"), "{label}");
            println!("{label}: rejected before fixture execution");
        };
        fs::write(&source, b"changed executable data").unwrap();
        reject("source changed after authorization");
        fs::write(&source, bytes).unwrap();
        fs::write(&payload, b"changed payload data").unwrap();
        fs::write(&config, json!({"broker":crate::storage::sha256(b"changed payload data")}).to_string()).unwrap();
        reject("payload and its self-reported pin changed together");
        fs::write(&payload, bytes).unwrap();
        reject("config alone changed");
        fs::write(&config, raw).unwrap();
        fs::remove_file(&payload).unwrap();
        symlink(&source, &payload).unwrap();
        reject("symbolic link to otherwise correct payload");
        fs::write(&recovery, bytes).unwrap();
        fs::remove_file(&source).unwrap();
        for (mode, expected) in [("commit", b"--service-commit\n".as_slice()), ("rollback", b"--service-rollback\n".as_slice())] {
            let output = exec(mode);
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
            assert_eq!(output.stdout, expected);
        }
    }
    #[test]
    fn final_engine_receives_actual_endpoint_check_before_install_is_accepted() {
        let mut executor = fake();
        let mut state = None;
        fixture_prepare(&mut executor, &mut state)
        .unwrap();
        assert_eq!(
            executor.calls.last().unwrap().program,
            executor.root.0.join("runtime/watch-engine")
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
        assert!(fixture_prepare(&mut executor, &mut state)
        .is_err());
        assert!(state.is_some());
        finish(&mut executor, &mut state, true).unwrap();
        let args = &executor.calls.last().unwrap().args;
        assert_eq!(args[args.len() - 11], "rollback");
        assert_eq!(args[args.len() - 2], "absent");
        assert_eq!(args.last().unwrap(), "42");
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
            fixture_prepare(&mut executor, &mut state)
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
        fixture_prepare(&mut executor, &mut state)
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
        fixture_prepare(&mut executor, &mut state)
        .unwrap();
        executor.fail_commit = true;
        let warning = commit_after_runtime(&mut executor, &mut state, |_| Ok(()))
            .unwrap()
            .unwrap();
        assert!(warning.contains("清理待处理"));
        assert!(state.is_some());
        assert!(!executor.calls.iter().any(|c| c.program == Path::new("/usr/bin/osascript")
            && c.args[c.args.len() - 11] == "rollback"));
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
