//! User-run full reset and install. The whole state machine lives in the
//! installer crate; this module only adapts the command line to it.
use claude_watch_core::{
    cli::Request,
    error::{CoreError, Result},
};
use claude_watch_installer::{Layout, SystemRunner};
use serde_json::{json, Value};
use std::io::Write;
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
    let layout = Layout::for_current_user(project, uid);
    let cargo = std::env::var_os("CW_CARGO_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| layout.home.join(".cargo/bin/cargo"));
    claude_watch_installer::perform(
        &layout,
        &SystemRunner,
        &version,
        &build,
        request.flag("dry-run"),
        &mut prompt_confirm,
        uid,
        &cargo,
        &|duration: Duration| std::thread::sleep(duration),
    )?;
    Ok(Some(json!({
        "status": "ok",
        "action": "reinstall",
        "engine": "rust",
        "version": version,
        "build": build,
    })))
}
