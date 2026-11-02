//! Property-list reading through the system `plutil`.
//!
//! Info.plist and launchd definitions are XML or binary plists; `plutil`
//! normalises both to JSON, which keeps this crate free of a bundle-format
//! parser while still validating the file before any decision uses it.
use crate::blocked;
use crate::runner::{RunMode, Runner};
use claude_watch_core::error::Result;
use serde_json::Value;
use std::path::Path;

pub fn read(runner: &dyn Runner, path: &Path) -> Result<Value> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| {
        blocked(format!("信息文件不存在或不是普通文件：{}", path.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(blocked(format!(
            "信息文件不存在或不是普通文件：{}",
            path.display()
        )));
    }
    let args = vec![
        "/usr/bin/plutil".to_string(),
        "-convert".to_string(),
        "json".to_string(),
        "-o".to_string(),
        "-".to_string(),
        path.display().to_string(),
    ];
    let output = runner.run(&args, None, RunMode::Capture)?;
    if !output.success() {
        return Err(blocked(format!(
            "信息文件无法读取：{}",
            path.display()
        )));
    }
    let value: Value = serde_json::from_str(&output.stdout)
        .map_err(|_| blocked(format!("信息文件无法读取：{}", path.display())))?;
    if !value.is_object() {
        return Err(blocked(format!(
            "信息文件格式无效：{}",
            path.display()
        )));
    }
    Ok(value)
}

/// The string under `key`, or `None` when it is absent or not a string.
pub fn string(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_owned)
}

/// The arguments list of a launchd definition as plain strings.
pub fn strings(value: &Value, key: &str) -> Option<Vec<String>> {
    let items = value.get(key)?.as_array()?;
    items
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}
