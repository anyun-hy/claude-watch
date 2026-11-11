use claude_watch_core::controlled_launch::{script_startup_input, ControlledLaunchRequest};
use claude_watch_system::{
    anchored_files::{inherit_across_exec, unlinked_read_only_bytes, Dir},
    sha256_bytes_hex, sha256_file_hex,
};
use serde_json::json;
use std::{
    fs::{File, Metadata},
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

type Stamp = (u64, u64, u64, i64, i64, i64, i64, u32);
fn stamp(meta: &Metadata) -> Stamp {
    (
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
        meta.mode(),
    )
}
fn file_stamp(path: &Path) -> Option<Stamp> {
    let m = std::fs::symlink_metadata(path).ok()?;
    m.is_file().then(|| stamp(&m))
}

pub struct NodeEntry {
    source: File,
    script: PathBuf,
    script_stamp: Stamp,
    script_sha: String,
    interpreter: PathBuf,
    interpreter_stamp: Stamp,
}

impl NodeEntry {
    pub fn capture(req: &ControlledLaunchRequest) -> Result<Self, &'static str> {
        let path = PathBuf::from(req.script_entry.as_ref().ok_or("script_entry_missing")?);
        if std::fs::canonicalize(&path).ok().as_deref() != Some(path.as_path()) {
            return Err("script_path_not_canonical");
        }
        let file = Dir::absolute(path.parent().ok_or("script_entry_missing")?, false)
            .and_then(|dir| {
                dir.read(
                    path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default(),
                )
            })
            .map_err(|_| "script_entry_open_failed")?;
        let meta = file.metadata().map_err(|_| "script_entry_stat_failed")?;
        const MAX_SCRIPT_BYTES: u64 = 64 * 1024 * 1024;
        if !meta.is_file() || meta.len() > MAX_SCRIPT_BYTES {
            return Err("script_entry_format_invalid");
        }
        let expected = req
            .script_fingerprint
            .as_ref()
            .ok_or("script_fingerprint_missing")?;
        let mut bytes = Vec::new();
        file.take(MAX_SCRIPT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "script_entry_read_failed")?;
        let script_stamp = stamp(&meta);
        if bytes.len() as u64 != meta.len()
            || file_stamp(&path) != Some(script_stamp)
            || sha256_bytes_hex(&bytes) != *expected
        {
            return Err("script_fingerprint_mismatch");
        }
        let shebang = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
        if shebang.strip_suffix(b"\r").unwrap_or(shebang) != b"#!/usr/bin/env node" {
            return Err("script_shebang_unsupported");
        }
        let source = unlinked_read_only_bytes(&bytes).map_err(|_| "script_snapshot_failed")?;
        let interpreter = PathBuf::from(req.interpreter.as_ref().ok_or("interpreter_missing")?);
        if std::fs::canonicalize(&interpreter).ok().as_deref() != Some(interpreter.as_path())
            || std::fs::metadata(&interpreter)
                .ok()
                .is_none_or(|m| m.permissions().mode() & 0o111 == 0)
        {
            return Err("interpreter_path_invalid");
        }
        let interpreter_stamp = file_stamp(&interpreter).ok_or("interpreter_not_found")?;
        if sha256_file_hex(&interpreter).as_ref() != req.interpreter_fingerprint.as_ref()
            || file_stamp(&interpreter) != Some(interpreter_stamp)
        {
            return Err("interpreter_fingerprint_mismatch");
        }
        Ok(Self {
            source,
            script: path,
            script_stamp,
            script_sha: expected.clone(),
            interpreter,
            interpreter_stamp,
        })
    }

    pub fn command(&self) -> Result<Command, &'static str> {
        if file_stamp(&self.script) != Some(self.script_stamp) {
            return Err("script_source_changed_before_exec");
        }
        if file_stamp(&self.interpreter) != Some(self.interpreter_stamp) {
            return Err("interpreter_changed_before_exec");
        }
        let fd = inherit_across_exec(&self.source).map_err(|_| "script_snapshot_inherit_failed")?;
        let path = self.script.to_str().ok_or("script_entry_path_invalid")?;
        let prefix = format!(
            "const approved = {};\n",
            json!({ "path":path, "fd":fd, "sha":self.script_sha })
        );
        let boot = prefix + include_str!("node_entry_bootstrap.mjs");
        let import = format!(
            "data:text/javascript,{}",
            percent_encode(boot.as_bytes(), false)
        );
        let entry = format!("file://{}", percent_encode(path.as_bytes(), true));
        let mut cmd = Command::new(&self.interpreter);
        for (key, _) in std::env::vars_os() {
            if key.to_str().is_some_and(script_startup_input) {
                cmd.env_remove(key);
            }
        }
        cmd.env("NODE_DISABLE_COMPILE_CACHE", "1").args([
            "--import",
            &import,
            "--entry-url",
            "--",
            &entry,
        ]);
        Ok(cmd)
    }
}

fn percent_encode(bytes: &[u8], slash: bool) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len());
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) || slash && byte == b'/' {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}
