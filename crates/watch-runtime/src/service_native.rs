//! Read-only validation of fixed launchd definitions, independently of loaded state.
use crate::{
    commands::{ReadCommand, ReadRunner},
    storage::{sha256, strict_json, StateStore},
};
use claude_watch_core::error::{CoreError, Result};
use serde_json::{json, Value};
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    time::Duration,
};
fn fixed(store: &StateStore, name: &str) -> Option<(PathBuf, &'static str)> {
    match name {
        "original" => Some((
            "/Library/LaunchDaemons/local.claude-bodyguard.plist".into(),
            "local.claude-bodyguard",
        )),
        "watchdog" => Some((
            "/Library/LaunchDaemons/io.local.claudewatch.timezone.plist".into(),
            "io.local.claudewatch.timezone",
        )),
        "updater" => Some((
            store
                .paths
                .home
                .join("Library/LaunchAgents/io.local.claudewatch.update.plist"),
            "io.local.claudewatch.update",
        )),
        _ => None,
    }
}
fn valid_arguments(store: &StateStore, name: &str, value: &Value) -> bool {
    let args = &value["ProgramArguments"];
    if !value["Program"].is_null() {
        return false;
    }
    match name {
        "original" => {
            args == &json!([
                "/bin/bash",
                "/Library/Application Support/claude-switcher/claude-bodyguard.sh"
            ])
        }
        "watchdog" => {
            args == &json!([
                "/usr/bin/env",
                "-i",
                "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                "/bin/bash",
                "--noprofile",
                "--norc",
                "/Library/Application Support/ClaudeWatch/claude-watch-admin.sh",
                "tick"
            ]) && value["StartInterval"] == 3600
        }
        "updater" => {
            args == &json!([
                store.paths.watch().join("runtime/watch-engine"),
                "update",
                "--auto",
                "--apply"
            ]) && value["StartInterval"] == 43200
                && value["RunAtLoad"] == false
        }
        _ => false,
    }
}
pub fn read_job_definition<R: ReadRunner>(
    store: &StateStore,
    name: &str,
    runner: &R,
) -> Result<Value> {
    let (path, label) =
        fixed(store, name).ok_or_else(|| CoreError::new("invalid_service", "未知固定后台名称"))?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({"trusted":false,"definition":null,"definition_present":false}))
        }
        Err(_) => return Err(CoreError::new("service_read_failed", "后台定义不可读取")),
    };
    if name == "updater" {
        store.guarded(&path)?;
    }
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 256 * 1024 {
        return Err(CoreError::new(
            "unsafe_service_definition",
            "后台定义不是大小受限的普通文件",
        ));
    }
    let owner = if name == "updater" {
        fs::metadata(&store.paths.home)
            .map_err(|_| CoreError::new("service_read_failed", "无法核对用户目录属主"))?
            .uid()
    } else {
        0
    };
    if metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
        return Ok(
            json!({"trusted":false,"definition":null,"definition_present":true,"reason":"后台定义属主或权限不符合要求"}),
        );
    }
    #[cfg(target_os = "macos")]
    const NOFOLLOW: i32 = 0x100;
    #[cfg(not(target_os = "macos"))]
    const NOFOLLOW: i32 = 0x20000;
    let mut bytes = Vec::new();
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW)
        .open(&path)
        .and_then(|file| file.take(256 * 1024 + 1).read_to_end(&mut bytes))
        .map_err(|_| CoreError::new("service_read_failed", "后台定义读取失败"))?;
    if bytes.len() > 256 * 1024 {
        return Err(CoreError::new(
            "oversize_service_definition",
            "后台定义过大",
        ));
    }
    let parsed = runner.run(
        ReadCommand::Plist(path.clone()),
        &[],
        Duration::from_secs(3),
        256 * 1024,
    )?;
    if parsed.status != 0 {
        return Err(CoreError::new(
            "invalid_service_definition",
            "后台 plist 解析失败",
        ));
    }
    let value = strict_json(&parsed.stdout)?;
    let after = fs::symlink_metadata(&path)
        .map_err(|_| CoreError::new("service_changed", "后台定义在读取期间变化"))?;
    let same = after.is_file()
        && !after.file_type().is_symlink()
        && after.dev() == metadata.dev()
        && after.ino() == metadata.ino()
        && after.uid() == metadata.uid()
        && after.mode() == metadata.mode()
        && after.mtime() == metadata.mtime()
        && after.mtime_nsec() == metadata.mtime_nsec()
        && after.len() == metadata.len();
    let trusted = same && value["Label"] == label && valid_arguments(store, name, &value);
    Ok(
        json!({"trusted":trusted,"definition":sha256(&bytes),"definition_present":true,"label":label,"interval":value["StartInterval"].as_u64().filter(|v|*v>0)}),
    )
}
