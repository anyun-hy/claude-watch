//! User-run full reset and install. The whole state machine lives in the
//! installer crate; this module only adapts the command line to it.
use claude_watch_core::{
    cli::Request,
    error::{CoreError, Result},
};
use claude_watch_installer::{Layout, Outcome, SystemRunner};
use serde_json::{json, Value};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

fn prompt_confirm(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);
    match read {
        Ok(0) | Err(_) => Ok(String::new()),
        Ok(_) => Ok(line),
    }
}

pub fn dispatch(request: &Request, uid: u32) -> Result<Option<Value>> {
    if request.command != "reinstall" {
        return Ok(None);
    }
    let version = request
        .value("version")
        .ok_or_else(|| CoreError::new("invalid_arguments", "重装需要 --version"))?;
    let build = request
        .value("build")
        .ok_or_else(|| CoreError::new("invalid_arguments", "重装需要 --build"))?;
    let project = request
        .value("project")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    if !project.is_absolute() {
        return Err(CoreError::new("invalid_arguments", "--project 必须是绝对路径"));
    }
    let dry_run = request.flag("dry-run");
    // The flow removes the installed app, so it is only ever allowed to run
    // with a human at the keyboard. Reading stdin from a pipe or /dev/null
    // returns end-of-file, which would silently look like "cancelled" and
    // leave the caller (and the user) unsure whether anything happened.
    if !dry_run && !std::io::stdin().is_terminal() {
        return Err(CoreError::new(
            "confirmation_unavailable",
            "重装需要交互确认，请在终端里直接运行 monitor/reinstall.sh；只想看预演请加 --dry-run。",
        ));
    }
    let layout = Layout::for_current_user(project, uid);
    let cargo = std::env::var_os("CW_CARGO_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| layout.home.join(".cargo/bin/cargo"));
    let outcome = claude_watch_installer::perform(
        &layout,
        &SystemRunner,
        &version,
        &build,
        dry_run,
        &mut prompt_confirm,
        uid,
        &cargo,
        &|duration: Duration| std::thread::sleep(duration),
    )?;
    let _ = std::io::stdout().flush();
    let value = match outcome {
        Outcome::Installed => json!({
            "status": "ok",
            "action": "reinstall",
            "engine": "rust",
            "installed": true,
            "version": version,
            "build": build,
        }),
        Outcome::DryRun => json!({
            "status": "preview",
            "action": "reinstall",
            "engine": "rust",
            "installed": false,
            "version": version,
            "build": build,
            "message": "预演通过；没有卸载、删除、打包或安装。",
        }),
        Outcome::Cancelled => json!({
            "status": "cancelled",
            "action": "reinstall",
            "engine": "rust",
            "installed": false,
            "version": version,
            "build": build,
            "message": "已取消；没有卸载、删除、打包或安装。",
        }),
    };
    Ok(Some(value))
}
