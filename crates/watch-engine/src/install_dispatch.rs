//! User-invoked application replacement. Preview is read-only; only --apply
//! reaches the native lifecycle adapter. Background-only install is separate.
use claude_watch_core::{
    cli::Request,
    error::{CoreError, Result},
};
use claude_watch_runtime::{
    app_lifecycle::{AppLifecycle, LifecyclePaths, APP_NAME},
    release_native::NativeRelease,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::path::PathBuf;

pub fn dispatch(request: &Request, paths: Paths, uid: u32) -> Result<Option<Value>> {
    if request.command == "install" {
        request.require_apply()?;
        let source = request
            .value("source")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(PathBuf::from))
            })
            .ok_or_else(|| CoreError::new("invalid_source", "无法定位原生运行组件来源"))?;
        let store = StateStore::new(paths);
        let _operation = store.lock("operation", None)?;
        let value = claude_watch_runtime::agent_install::install(
            &store,
            &source,
            uid,
            &mut claude_watch_runtime::release_native::SystemExecutor,
        )?;
        return Ok(Some(value));
    }
    if !matches!(request.command.as_str(), "app-install" | "app-uninstall") {
        return Ok(None);
    }
    let source = request.value("source").map(PathBuf::from);
    if source.as_ref().is_some_and(|p| !p.is_absolute()) {
        return Err(CoreError::new("invalid_source", "安装来源必须是绝对路径"));
    }
    let store = StateStore::new(paths.clone());
    let mut lifecycle = AppLifecycle {
        paths: LifecyclePaths {
            installed: PathBuf::from("/Applications").join(APP_NAME),
            trash: paths.home.join(".Trash"),
            protected_data: paths.watch(),
        },
        os: NativeRelease::production(&paths.home, uid),
    };
    if !request.flag("apply") {
        let plan = lifecycle.plan(source.as_deref())?;
        return Ok(Some(json!({"status":"preview", "engine":"rust",
            "action":request.command,"source":plan.source,"installed":plan.installed,
            "reset_accessibility":plan.reset_accessibility,"preserves_account_and_policy_data":true,
            "grants_launch_permission":false})));
    }
    let _operation = store.lock("operation", None)?;
    let result = if let Some(source) = source {
        let identity = lifecycle.apply(&source)?;
        json!({"status":"ok","engine":"rust","action":"app-install",
            "version":identity.version,"build":identity.build,"architecture":identity.architecture,
            "message":"应用与自有后台已更新；账号、代理和保护设置保留。打开新版后按 macOS 提示重新授权。"})
    } else {
        let previous = lifecycle.uninstall()?;
        json!({"status":"ok","engine":"rust","action":"app-uninstall","previous":previous,
            "message":"应用与自有后台任务已移入废纸篓；账号、配置和原版保镖保留。"})
    };
    Ok(Some(result))
}
