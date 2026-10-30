//! Shared private storage and operation locks. All paths are anchored to an explicit home.
use claude_watch_core::error::{CoreError, Result};
use serde::{de, Deserialize, Deserializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

#[cfg(target_os = "macos")]
const NOFOLLOW: i32 = 0x0100;
#[cfg(target_os = "linux")]
const NOFOLLOW: i32 = 0x20000;

fn io_error(_error: std::io::Error) -> CoreError {
    CoreError::new("state_io_failed", "受管理状态文件操作失败")
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub home: PathBuf,
}
impl Paths {
    pub fn require_owner(&self, uid: u32) -> Result<()> {
        let metadata = fs::symlink_metadata(&self.home).map_err(io_error)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != uid {
            return Err(CoreError::new(
                "home_owner_mismatch",
                "数据根目录不属于当前登录用户，未读取账号或启动程序",
            ));
        }
        Ok(())
    }
    pub fn new(home: impl AsRef<Path>) -> Result<Self> {
        let home = fs::canonicalize(home).map_err(io_error)?;
        if !home.is_dir() {
            return Err(CoreError::new("invalid_home", "用户数据目录不存在"));
        }
        Ok(Self { home })
    }
    pub fn watch(&self) -> PathBuf {
        self.home.join("Library/Application Support/ClaudeWatch")
    }
    pub fn base(&self) -> PathBuf {
        self.watch().join("switcher")
    }
    pub fn config(&self) -> PathBuf {
        self.base().join("config.json")
    }
    pub fn accounts(&self) -> PathBuf {
        self.base().join("accounts")
    }
    pub fn active(&self) -> PathBuf {
        self.home.join("Library/Application Support/Claude")
    }
    pub fn journal(&self) -> PathBuf {
        self.base().join("transaction.json")
    }
    pub fn session(&self) -> PathBuf {
        self.base().join("session-guard.json")
    }
}

#[derive(Debug, Clone)]
pub struct StateStore {
    pub paths: Paths,
}
pub struct OperationLock {
    _file: File,
}
impl Drop for OperationLock {
    fn drop(&mut self) {
        // Forked OS helpers can briefly retain a duplicate of the descriptor.
        // Release this transaction's lock now, rather than waiting for the last
        // inherited descriptor to close after the owner has finished.
        let _ = self._file.unlock();
    }
}
impl StateStore {
    pub fn new(paths: Paths) -> Self {
        Self { paths }
    }
    pub fn guarded(&self, path: &Path) -> Result<PathBuf> {
        if !path.is_absolute()
            || path.components().any(|c| matches!(c, Component::ParentDir))
            || !path.starts_with(&self.paths.home)
        {
            return Err(CoreError::new(
                "path_outside_home",
                "路径不属于当前用户的数据范围",
            ));
        }
        let mut cursor = path;
        loop {
            match fs::symlink_metadata(cursor) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(CoreError::new(
                        "unsafe_path",
                        "拒绝通过符号链接访问受管理数据",
                    ))
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(error)),
            }
            if cursor == self.paths.home {
                break;
            }
            cursor = cursor
                .parent()
                .ok_or_else(|| CoreError::new("unsafe_path", "无效的状态文件路径"))?;
        }
        Ok(path.into())
    }
    pub fn private_dir(&self, path: &Path) -> Result<()> {
        self.guarded(path)?;
        let relative = path
            .strip_prefix(&self.paths.home)
            .map_err(|_| CoreError::new("unsafe_path", "无效的目录边界"))?;
        let mut current = self.paths.home.clone();
        for part in relative.components() {
            if !matches!(part, Component::Normal(_)) {
                return Err(CoreError::new("unsafe_path", "无效的目录组件"));
            }
            current.push(part);
            match fs::symlink_metadata(&current) {
                Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() => {
                    return Err(CoreError::new("unsafe_path", "受管理目录不是普通目录"))
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::DirBuilder::new()
                        .mode(0o700)
                        .create(&current)
                        .map_err(io_error)?;
                }
                Err(error) => return Err(io_error(error)),
            }
        }
        // Do not change permissions on unrelated existing ancestors such as ~/Library.
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)
    }
    pub fn initialize(&self) -> Result<()> {
        for path in [self.paths.watch(), self.paths.base(), self.paths.accounts()] {
            self.private_dir(&path)?;
        }
        Ok(())
    }
    pub fn read_bytes(&self, path: &Path, limit: usize) -> Result<Option<Vec<u8>>> {
        self.guarded(path)?;
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
        };
        if !file.metadata().map_err(io_error)?.is_file() {
            return Err(CoreError::new("unsafe_path", "状态文件不是普通文件"));
        }
        let mut data = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut data)
            .map_err(io_error)?;
        if data.len() > limit {
            return Err(CoreError::new("oversize_state", "状态文件过大"));
        }
        Ok(Some(data))
    }
    pub fn read_json(&self, path: &Path, default: Value) -> Result<Value> {
        let Some(data) = self.read_bytes(path, 2_000_000)? else {
            return Ok(default);
        };
        strict_json(&data)
    }
    pub fn atomic_bytes(&self, path: &Path, data: &[u8], mode: u32) -> Result<()> {
        self.guarded(path)?;
        let parent = path
            .parent()
            .ok_or_else(|| CoreError::new("unsafe_path", "状态文件缺少父目录"))?;
        if parent.exists() && !parent.starts_with(self.paths.watch()) {
            self.guarded(parent)?;
            if !parent.is_dir() {
                return Err(CoreError::new("unsafe_path", "文件父路径不是目录"));
            }
        } else {
            self.private_dir(parent)?;
        }
        if let Ok(meta) = fs::symlink_metadata(path) {
            if !meta.is_file() {
                return Err(CoreError::new("unsafe_path", "目标不是普通文件"));
            }
        }
        let temp = parent.join(format!(
            ".{}.{}",
            path.file_name().and_then(|s| s.to_str()).unwrap_or("state"),
            Uuid::new_v4()
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .custom_flags(NOFOLLOW)
                .open(&temp)
                .map_err(io_error)?;
            file.set_permissions(fs::Permissions::from_mode(mode))
                .map_err(io_error)?;
            file.write_all(data).map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
            self.guarded(path)?;
            fs::rename(&temp, path).map_err(io_error)?;
            File::open(parent)
                .and_then(|f| f.sync_all())
                .map_err(io_error)
        })();
        if temp.exists() {
            let _ = fs::remove_file(temp);
        }
        result
    }
    pub fn atomic_json(&self, path: &Path, value: &Value) -> Result<()> {
        let mut data = serde_json::to_vec(value)
            .map_err(|_| CoreError::new("invalid_state", "状态无法序列化"))?;
        data.push(b'\n');
        self.atomic_bytes(path, &data, 0o600)
    }
    pub fn lock(&self, name: &str, recovery: Option<&str>) -> Result<OperationLock> {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
        {
            return Err(CoreError::new("invalid_lock", "无效的操作锁名称"));
        }
        self.initialize()?;
        let path = self.paths.base().join(format!("{name}.lock"));
        self.guarded(&path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(NOFOLLOW)
            .open(path)
            .map_err(io_error)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(CoreError::new("busy", "已有切换、修复或升级操作正在进行"))
            }
            Err(TryLockError::Error(error)) => return Err(io_error(error)),
        }
        if name == "operation" {
            let agent_journal = self.paths.watch().join("agent-install-transaction.json");
            self.guarded(&agent_journal)?;
            if agent_journal.exists() && recovery != Some("maintenance") {
                return Err(CoreError::new(
                    "recovery_required",
                    "先恢复未完成的原生后台安装",
                ));
            }
            for (file, kind, detail) in [
                (
                    "setup-transaction.json",
                    "setup",
                    "先恢复未完成的环境初始化",
                ),
                (
                    "update-transaction.json",
                    "update",
                    "先恢复未完成的整包更新",
                ),
                ("transaction.json", "account", "先恢复未完成的账号切换"),
                (
                    "service-transaction.json",
                    "service",
                    "先恢复未完成的后台设置",
                ),
            ] {
                let path = self.paths.base().join(file);
                self.guarded(&path)?;
                if path.exists() && recovery != Some(kind) && recovery != Some("maintenance") {
                    return Err(CoreError::new("recovery_required", detail));
                }
            }
        }
        Ok(OperationLock { _file: file })
    }
}

pub fn sha256(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in Sha256::digest(data).iter() {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 15) as usize] as char);
    }
    text
}

/// Duplicate keys or non-finite JSON numbers cannot silently replace a state field.
pub fn strict_json(data: &[u8]) -> Result<Value> {
    struct Strict(Value);
    impl<'de> Deserialize<'de> for Strict {
        fn deserialize<D: Deserializer<'de>>(
            deserializer: D,
        ) -> std::result::Result<Self, D::Error> {
            struct Visitor;
            impl<'de> de::Visitor<'de> for Visitor {
                type Value = Strict;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("JSON with unique object keys")
                }
                fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                    Ok(Strict(Value::Bool(v)))
                }
                fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                    Ok(Strict(v.into()))
                }
                fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                    Ok(Strict(v.into()))
                }
                fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Strict, E> {
                    serde_json::Number::from_f64(v)
                        .map(|v| Strict(Value::Number(v)))
                        .ok_or_else(|| E::custom("non-finite number"))
                }
                fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                    Ok(Strict(v.into()))
                }
                fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Strict, E> {
                    Ok(Strict(v.into()))
                }
                fn visit_none<E: de::Error>(self) -> std::result::Result<Strict, E> {
                    Ok(Strict(Value::Null))
                }
                fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                    Ok(Strict(Value::Null))
                }
                fn visit_seq<A: de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> std::result::Result<Strict, A::Error> {
                    let mut values = Vec::new();
                    while let Some(Strict(v)) = seq.next_element()? {
                        values.push(v);
                    }
                    Ok(Strict(Value::Array(values)))
                }
                fn visit_map<A: de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> std::result::Result<Strict, A::Error> {
                    let mut values = Map::new();
                    while let Some((key, Strict(v))) = map.next_entry::<String, Strict>()? {
                        if values.insert(key, v).is_some() {
                            return Err(de::Error::custom("duplicate key"));
                        }
                    }
                    Ok(Strict(Value::Object(values)))
                }
            }
            deserializer.deserialize_any(Visitor)
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(data);
    let Strict(value) = Strict::deserialize(&mut decoder)
        .map_err(|_| CoreError::new("invalid_state", "状态文件损坏；未覆盖原文件"))?;
    decoder
        .end()
        .map_err(|_| CoreError::new("invalid_state", "状态文件包含多余内容"))?;
    Ok(value)
}

#[cfg(test)]
mod lock_lifetime_tests {
    use super::*;
    #[test]
    fn inherited_descriptor_does_not_extend_a_finished_transaction() {
        let home = std::env::temp_dir().join(format!("cw-lock-lifetime-{}", Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        let store = StateStore::new(Paths::new(&home).unwrap());
        let first = store.lock("session-guard", None).unwrap();
        let inherited = first._file.try_clone().unwrap();
        drop(first);
        let second = store.lock("session-guard", None).unwrap();
        drop(inherited);
        assert_eq!(
            store.lock("session-guard", None).err().unwrap().code,
            "busy"
        );
        drop(second);
        assert!(store.lock("session-guard", None).is_ok());
        fs::remove_dir_all(home).unwrap();
    }
}
