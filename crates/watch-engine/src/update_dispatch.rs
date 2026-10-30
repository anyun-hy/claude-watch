use claude_watch_core::{
    cli::Request,
    error::{CoreError, Result},
};
use claude_watch_runtime::{
    config_store::ConfigStore,
    native::Observer,
    release_native::NativeRelease,
    storage::{Paths, StateStore},
    update::{UpdatePaths, Updater, UreqTransport},
};
use serde_json::{json, Value};
pub fn dispatch(request: &Request, paths: Paths) -> Result<Option<Value>> {
    if request.command != "update" {
        return Ok(None);
    }
    let storage = StateStore::new(paths.clone());
    let config = ConfigStore {
        storage: storage.clone(),
    }
    .load()?;
    if !request.flag("recover") {
        if request.flag("auto") && !config.auto_update {
            return Ok(Some(
                json!({"status":"disabled","message":"自动更新未启用"}),
            ));
        }
        if config.update_url.is_empty() || config.update_public_key.is_empty() {
            return Ok(Some(
                json!({"status":"unavailable","message":"尚未配置本项目发布源和固定公钥；未发起下载"}),
            ));
        }
    }
    let runner = crate::runtime::runner()?;
    let environment = Observer {
        runner: runner.as_ref(),
    }
    .environment()?;
    let uid = environment["uid"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v > 0)
        .ok_or_else(|| CoreError::new("uid_unavailable", "当前用户身份未确认"))?;
    let mut updater = Updater {
        paths: UpdatePaths {
            base: paths.base(),
            app: "/Applications/Claude Watch Monitor.app".into(),
            watch: paths.watch(),
            backend: paths.watch().join("claude-watch.sh"),
        },
        os: NativeRelease::production(&paths.home, uid),
        transport: UreqTransport,
    };
    if request.flag("recover") {
        request.require_apply()?;
        let _operation = storage.lock("operation", Some("update"))?;
        let reauthorization = updater.recover()?;
        return Ok(Some(if reauthorization {
            json!({"status":"partial","reauthorization_required":true,"message":"应用和后台已恢复；辅助功能授权可能已被清除，请在系统提示中重新授权。"})
        } else {
            json!({"status":"ok","reauthorization_required":false,"message":"已恢复更新事务"})
        }));
    }
    let _operation = if request.flag("apply") {
        Some(storage.lock("operation", None)?)
    } else {
        None
    };
    Ok(Some(updater.check(
        &config.update_url,
        &config.update_public_key,
        request.flag("apply"),
    )?))
}
