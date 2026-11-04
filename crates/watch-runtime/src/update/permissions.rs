//! Permissions are derived from fixed signed file roles, never copied from
//! arbitrary ZIP mode bits. Hash validation must finish before execution bits
//! are granted. This module never executes the extracted files.
use super::*;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

pub(super) fn validate_entry(is_dir: bool, mode: Option<u32>) -> Result<()> {
    if let Some(mode) = mode {
        let kind = mode & 0o170000;
        let expected = if is_dir { 0o040000 } else { 0o100000 };
        if mode & 0o7000 != 0 || (kind != 0 && kind != expected) {
            return Err(err("unsafe_archive", "更新包包含链接、特殊文件或特殊权限"));
        }
    }
    Ok(())
}

fn executable(name: &str) -> bool {
    if name == "app/Claude Watch Monitor.app/Contents/MacOS/ClaudeWatchMonitor" { return true; }
    let component = name.strip_prefix("runtime/")
        .or_else(|| name.strip_prefix("app/Claude Watch Monitor.app/Contents/Resources/"));
    matches!(component, Some("watch-engine" | "watch-native-observer" | "watch-process-control"
        | "watch-admin.sh" | "watch-leak-worker" | "watch-native-collector.zsh"))
}

/// Only traverse normal directories inside the extraction destination. An
/// existing destination/parent symlink must not redirect writes or chmod.
pub(super) fn prepare_parent(destination: &Path, name: &str) -> Result<PathBuf> {
    match fs::symlink_metadata(destination) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
        Ok(_) => return Err(err("unsafe_archive", "解包目标不是普通目录")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new().recursive(true).mode(0o700).create(destination).map_err(io)?;
        }
        Err(e) => return Err(io(e)),
    }
    let relative = Path::new(name);
    let parent = relative.parent().ok_or_else(|| err("unsafe_archive", "解包路径缺少父目录"))?;
    let mut path = destination.to_path_buf();
    for part in parent.components() {
        let Component::Normal(part) = part else { return Err(err("unsafe_archive", "解包路径无效")) };
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
            Ok(_) => return Err(err("unsafe_archive", "解包父路径不是普通目录")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(0o700).create(&path).map_err(io)?;
            }
            Err(e) => return Err(io(e)),
        }
    }
    Ok(destination.join(relative))
}

pub(super) fn apply(destination: &Path, release: &Release) -> Result<()> {
    for name in release.files.keys() {
        let path = prepare_parent(destination, name)?;
        let meta = fs::symlink_metadata(&path).map_err(io)?;
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err(err("unsafe_archive", "已校验文件被替换，未授予执行权限"));
        }
        let mode = if executable(name) { 0o700 } else { 0o600 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_types_and_privileged_mode_bits_are_rejected() {
        for mode in [0o120777, 0o010600, 0o020600, 0o060600, 0o140600,
            0o104755, 0o102755, 0o101755] {
            assert_eq!(validate_entry(false, Some(mode)).unwrap_err().code, "unsafe_archive");
        }
        assert!(validate_entry(true, Some(0o041777)).is_err());
        assert!(validate_entry(false, Some(0o040755)).is_err());
        assert!(validate_entry(true, Some(0o100644)).is_err());
    }

    #[test]
    fn ordinary_zip_modes_do_not_require_unix_metadata() {
        for mode in [None, Some(0), Some(0o644), Some(0o100755), Some(0o100777)] {
            validate_entry(false, mode).unwrap();
        }
        for mode in [None, Some(0), Some(0o755), Some(0o040755)] {
            validate_entry(true, mode).unwrap();
        }
    }

    #[test]
    fn execution_roles_are_exact_paths_not_names_or_extensions() {
        for name in ["runtime/watch-engine", "runtime/watch-leak-worker",
            "app/Claude Watch Monitor.app/Contents/MacOS/ClaudeWatchMonitor",
            "app/Claude Watch Monitor.app/Contents/Resources/watch-admin.sh"] {
            assert!(executable(name), "{name}");
        }
        for name in ["runtime/extra/watch-engine", "runtime/arbitrary.sh", "runtime/BuildInfo.plist",
            "app/Other.app/Contents/MacOS/ClaudeWatchMonitor",
            "app/Claude Watch Monitor.app/Contents/MacOS/Other",
            "app/Claude Watch Monitor.app/Contents/Resources/nested/watch-admin.sh"] {
            assert!(!executable(name), "{name}");
        }
    }
}
