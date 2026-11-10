//! Conflict-safe, fixed-scope Clash Verge repair mutations.
//!
//! The read helper deliberately returns configuration text only to the local
//! planner.  It must not be serialized into an audit receipt or UI response:
//! proxy profiles may contain credentials.
#![forbid(unsafe_code)]

use crate::{
    macos::Mutator,
    rules,
    storage::{sha256, StateStore},
};
use claude_watch_core::error::{CoreError, Result};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use subprocess::{Exec, Redirection};
use uuid::Uuid;

const CONFIG_LIMIT: usize = 2_000_000;
const COMMAND_LIMIT: usize = 64 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const APP_CONFIG_DIR: &str =
    "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev";

fn err(code: &str, message: &str) -> CoreError {
    CoreError::new(code, message)
}

/// Only application identities with an exact, vendor-controlled bundle path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProvider {
    Tag,
    ClashVerge,
    Shadowrocket,
    SingBox,
    ClashX,
    Surge,
}

impl ProxyProvider {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "tag" => Self::Tag,
            "clash-verge" => Self::ClashVerge,
            "shadowrocket" => Self::Shadowrocket,
            "sing-box" => Self::SingBox,
            "clashx" => Self::ClashX,
            "surge" => Self::Surge,
            _ => return None,
        })
    }
    fn bundle(self) -> &'static str {
        match self {
            Self::Tag => "/Applications/TAG.app",
            Self::ClashVerge => "/Applications/Clash Verge.app",
            Self::Shadowrocket => "/Applications/Shadowrocket.app",
            Self::SingBox => "/Applications/sing-box.app",
            Self::ClashX => "/Applications/ClashX.app",
            Self::Surge => "/Applications/Surge.app",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyCommand {
    Open(ProxyProvider),
    QuitClashVerge,
}

/// Injection point for the two process-control operations.  It never accepts a
/// caller-controlled binary, script, or argument list.
pub trait ProxyCommandExecutor: Send {
    fn execute(&mut self, command: ProxyCommand) -> Result<()>;
}

pub struct NativeProxyCommandExecutor;
impl NativeProxyCommandExecutor {
    fn run(program: &str, args: &[&str]) -> Result<()> {
        let mut child = Exec::cmd(program)
            .args(args)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdout(Redirection::Pipe)
            .stderr(Redirection::Pipe)
            .start()
            .map_err(|_| err("mutation_unavailable", "受权代理操作无法启动"))?;
        let started = Instant::now();
        let output = child.communicate().and_then(|comm| {
            comm.limit_time(COMMAND_TIMEOUT)
                .limit_size(COMMAND_LIMIT + 1)
                .read()
        });
        let (stdout, stderr) = match output {
            Ok(value) if value.0.len() + value.1.len() <= COMMAND_LIMIT => value,
            Ok(_) => {
                let _ = child.kill();
                return Err(err("mutation_output_oversize", "代理操作输出超过资源上限"));
            }
            Err(_) => {
                let _ = child.kill();
                return Err(err("mutation_timeout", "代理操作超时或通信失败"));
            }
        };
        let status = match child.wait_timeout(COMMAND_TIMEOUT.saturating_sub(started.elapsed())) {
            Ok(Some(status)) => status,
            Ok(None) => {
                let _ = child.kill();
                return Err(err("mutation_timeout", "代理操作未在时限内退出"));
            }
            Err(_) => return Err(err("mutation_wait_failed", "代理操作退出状态不可读取")),
        };
        let _ = (stdout, stderr);
        status
            .success()
            .then_some(())
            .ok_or_else(|| err("mutation_failed", "受权代理操作失败"))
    }
}
impl ProxyCommandExecutor for NativeProxyCommandExecutor {
    fn execute(&mut self, command: ProxyCommand) -> Result<()> {
        match command {
            ProxyCommand::Open(provider) => Self::run("/usr/bin/open", &[provider.bundle()]),
            ProxyCommand::QuitClashVerge => Self::run(
                "/usr/bin/osascript",
                &["-e", "tell application \"Clash Verge\" to quit"],
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyConfigFacts {
    pub clash_verge_config: Option<String>,
    pub merge_text: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProxyMutationPaths {
    root: PathBuf,
    verge: PathBuf,
    merge: PathBuf,
}
impl ProxyMutationPaths {
    pub fn from_store(store: &StateStore) -> Self {
        let root = store.paths.home.join(APP_CONFIG_DIR);
        Self {
            verge: root.join("verge.yaml"),
            merge: root.join("profiles/Merge.yaml"),
            root,
        }
    }
    fn path(&self, kind: &str) -> Result<&Path> {
        match kind {
            "enable_tun" => Ok(&self.verge),
            "rules" => Ok(&self.merge),
            _ => Err(err(
                "unsupported_action",
                "代理写入器拒绝未列入白名单的操作",
            )),
        }
    }
    fn valid(&self, store: &StateStore, path: &Path) -> Result<()> {
        if !path.starts_with(&self.root) || !self.root.starts_with(&store.paths.home) {
            return Err(err("path_outside_home", "代理配置路径不属于固定应用目录"));
        }
        store.guarded(path)?;
        Ok(())
    }
}

fn read_text(store: &StateStore, paths: &ProxyMutationPaths, path: &Path) -> Result<String> {
    paths.valid(store, path)?;
    let bytes = store
        .read_bytes(path, CONFIG_LIMIT)
        .map_err(|_| err("config_read_failed", "代理配置读取失败"))?
        .unwrap_or_default();
    String::from_utf8(bytes).map_err(|_| err("config_read_failed", "代理配置不是 UTF-8"))
}

/// Read only; callers must keep these strings in-process and never publish
/// them as macOS facts, logs, receipts, or diagnostics.
pub fn read_clash_verge_config_facts(store: &StateStore) -> Result<ProxyConfigFacts> {
    let paths = ProxyMutationPaths::from_store(store);
    Ok(ProxyConfigFacts {
        clash_verge_config: Some(read_text(store, &paths, &paths.verge)?),
        merge_text: Some(read_text(store, &paths, &paths.merge)?),
    })
}

fn action_text<'a>(action: &'a Value, field: &str) -> Result<&'a str> {
    action
        .get(field)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 256 && !v.contains(['\n', '\r', '\0']))
        .ok_or_else(|| err("invalid_action", "代理操作参数无效"))
}
fn expected_hash(action: &Value) -> Result<&str> {
    action
        .get("before")
        .and_then(Value::as_str)
        .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| err("invalid_action", "代理配置摘要无效"))
}
fn replacement_tun(text: &str) -> Result<String> {
    let mut matched = 0usize;
    let mut output = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let ending = if line.ends_with('\n') { "\n" } else { "" };
        let body = line.strip_suffix('\n').unwrap_or(line);
        if let Some(rest) = body.strip_prefix("enable_tun_mode:") {
            let trimmed = rest.trim_start();
            if let Some(tail) = trimmed.strip_prefix("false") {
                let tail = tail.trim_start();
                if tail.is_empty() || tail.starts_with('#') {
                    matched += 1;
                    output.push_str("enable_tun_mode: true");
                    output.push_str(if tail.is_empty() { "" } else { " " });
                    output.push_str(tail);
                    output.push_str(ending);
                    continue;
                }
            }
        }
        output.push_str(line);
    }
    if matched != 1 {
        return Err(err("ambiguous_config", "TUN 配置键缺失或不唯一"));
    }
    Ok(output)
}

fn write_text(
    store: &StateStore,
    paths: &ProxyMutationPaths,
    path: &Path,
    text: &str,
) -> Result<()> {
    paths.valid(store, path)?;
    let parent = path
        .parent()
        .ok_or_else(|| err("unsafe_path", "代理配置缺少目录"))?;
    paths.valid(store, parent)?;
    if !parent.is_dir() {
        return Err(err("config_write_failed", "固定代理配置目录不存在"));
    }
    let temp = parent.join(format!(".claude-watch-{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|_| err("config_write_failed", "无法创建代理配置临时文件"))?;
        file.write_all(text.as_bytes())
            .map_err(|_| err("config_write_failed", "无法写入代理配置"))?;
        file.sync_all()
            .map_err(|_| err("config_write_failed", "无法同步代理配置"))?;
        paths.valid(store, path)?;
        fs::rename(&temp, path).map_err(|_| err("config_write_failed", "无法提交代理配置"))?;
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| err("config_write_failed", "无法同步代理配置目录"))?;
        let readback = read_text(store, paths, path)?;
        if readback != text {
            return Err(err("mutation_unconfirmed", "代理配置写入后未能回读确认"));
        }
        Ok(())
    })();
    if temp.exists() {
        let _ = fs::remove_file(temp);
    }
    result
}

pub struct ProxyMutationAdapter<E: ProxyCommandExecutor = NativeProxyCommandExecutor> {
    store: StateStore,
    paths: ProxyMutationPaths,
    executor: E,
}
impl ProxyMutationAdapter<NativeProxyCommandExecutor> {
    pub fn native(store: StateStore) -> Self {
        let paths = ProxyMutationPaths::from_store(&store);
        Self {
            store,
            paths,
            executor: NativeProxyCommandExecutor,
        }
    }
}
impl<E: ProxyCommandExecutor> ProxyMutationAdapter<E> {
    pub fn with_executor(store: StateStore, executor: E) -> Self {
        let paths = ProxyMutationPaths::from_store(&store);
        Self {
            store,
            paths,
            executor,
        }
    }
    fn journal_path(&self) -> PathBuf {
        self.store.paths.base().join("proxy-repair.json")
    }
    fn action_id(action: &Value) -> Result<&str> {
        action
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| err("invalid_action", "缺少代理操作类型"))
    }
    fn journal_before(&self, action: &Value, path: &Path, before: &str, after: &str) -> Result<()> {
        let context = action_text(action, "context")?;
        let journal_path = self.journal_path();
        let mut journal = self
            .store
            .read_json(&journal_path, json!({"schema":1,"records":[]}))?;
        let records = journal
            .get_mut("records")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| err("invalid_transaction", "代理恢复记录无效"))?;
        records.push(json!({"id":Self::action_id(action)?,"context":context,"path":path.file_name().and_then(|n|n.to_str()).unwrap_or(""),"action_before":action["before"],"action_after":action["after"],"before":before,"after_hash":sha256(after.as_bytes())}));
        self.store.atomic_json(&journal_path, &journal)
    }
    fn apply_file(&mut self, action: &Value) -> Result<()> {
        let id = Self::action_id(action)?;
        let path = self.paths.path(id)?.to_path_buf();
        let old = read_text(&self.store, &self.paths, &path)?;
        if sha256(old.as_bytes()) != expected_hash(action)? {
            return Err(err("config_changed", "代理配置已变化；请重新预览"));
        }
        let new = match id {
            "enable_tun" if action["after"] == true => replacement_tun(&old)?,
            "rules" => rules::render_rules(&old, action_text(action, "after")?, false)?,
            _ => return Err(err("invalid_action", "代理配置操作参数无效")),
        };
        self.journal_before(action, &path, &old, &new)?;
        write_text(&self.store, &self.paths, &path, &new)
    }
    fn ensure_mutations_permitted(&self) -> Result<()> {
        #[cfg(test)]
        if !self.store.paths.config().exists() {
            return Ok(());
        }
        if let Ok(config) = (crate::config_store::ConfigStore {
            storage: self.store.clone(),
        })
        .load()
        {
            verify_vpn_write_allowed(&config, "")?;
        }
        Ok(())
    }
}

pub fn verify_vpn_write_allowed(config: &claude_watch_core::config::Config, _action: &str) -> Result<()> {
    if config.vpn_is_read_only() {
        return Err(err(
            "vpn_managed_externally",
            "VPN 与代理配置由外部客户端管理，Watch 仅执行只读观测与通道断流",
        ));
    }
    Ok(())
}
impl<E: ProxyCommandExecutor> Mutator for ProxyMutationAdapter<E> {
    fn apply(&mut self, action: &Value) -> Result<()> {
        self.ensure_mutations_permitted()?;
        match Self::action_id(action)? {
            "start_proxy" => self.executor.execute(ProxyCommand::Open(
                ProxyProvider::parse(action_text(action, "after")?)
                    .ok_or_else(|| err("invalid_action", "未知代理客户端"))?,
            )),
            "reload_proxy" => {
                if action_text(action, "before")? != "clash-verge"
                    || action_text(action, "after")? != "clash-verge"
                {
                    return Err(err("invalid_action", "重载目标必须是 Clash Verge"));
                }
                self.executor.execute(ProxyCommand::QuitClashVerge)?;
                self.executor
                    .execute(ProxyCommand::Open(ProxyProvider::ClashVerge))
            }
            "enable_tun" | "rules" => self.apply_file(action),
            _ => Err(err(
                "unsupported_action",
                "代理写入器拒绝未列入白名单的操作",
            )),
        }
    }
    fn restore(&mut self, action: &Value) -> Result<bool> {
        self.ensure_mutations_permitted()?;
        let id = Self::action_id(action)?;
        if !matches!(id, "enable_tun" | "rules") {
            return Ok(false);
        }
        let journal = self.store.read_json(&self.journal_path(), Value::Null)?;
        let Some(record) = journal
            .get("records")
            .and_then(Value::as_array)
            .and_then(|records| {
                records.iter().rev().find(|record| {
                    record["id"] == id
                        && record["context"] == action["context"]
                        && record["action_before"] == action["before"]
                        && record["action_after"] == action["after"]
                })
            })
        else {
            return Ok(false);
        };
        let path = self.paths.path(id)?.to_path_buf();
        let current = read_text(&self.store, &self.paths, &path)?;
        let after = record["after_hash"]
            .as_str()
            .ok_or_else(|| err("invalid_transaction", "代理恢复记录无效"))?;
        let before = record["before"]
            .as_str()
            .ok_or_else(|| err("invalid_transaction", "代理恢复记录无效"))?;
        if sha256(current.as_bytes()) != after {
            return Ok(false);
        }
        write_text(&self.store, &self.paths, &path, before)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Paths;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Fake(Arc<Mutex<Vec<ProxyCommand>>>);
    impl ProxyCommandExecutor for Fake {
        fn execute(&mut self, command: ProxyCommand) -> Result<()> {
            self.0.lock().unwrap().push(command);
            Ok(())
        }
    }
    fn fixture() -> (PathBuf, StateStore) {
        let home = std::env::temp_dir().join(format!("cw-proxy-{}", Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        let store = StateStore::new(Paths::new(&home).unwrap());
        (home, store)
    }
    fn paths(home: &Path) -> (PathBuf, PathBuf) {
        let root = home.join(APP_CONFIG_DIR);
        fs::create_dir_all(root.join("profiles")).unwrap();
        (root.join("verge.yaml"), root.join("profiles/Merge.yaml"))
    }
    fn action(id: &str, before: &str, after: Value) -> Value {
        json!({"id":id,"before":before,"after":after,"context":"stable-context"})
    }
    #[test]
    fn scoped_writes_preserve_unrelated_content_and_restore_only_unchanged_after() {
        let (home, store) = fixture();
        let (verge, merge) = paths(&home);
        fs::write(
            &verge,
            "foo: keep\nenable_tun_mode: false # user note\nbar: keep\n",
        )
        .unwrap();
        fs::write(&merge, "port: 7890\n").unwrap();
        let old_verge = fs::read_to_string(&verge).unwrap();
        let old_merge = fs::read_to_string(&merge).unwrap();
        let mut adapter = ProxyMutationAdapter::with_executor(store.clone(), Fake::default());
        let tun = action("enable_tun", &sha256(old_verge.as_bytes()), json!(true));
        adapter.apply(&tun).unwrap();
        let changed = fs::read_to_string(&verge).unwrap();
        assert!(changed.contains("foo: keep\nenable_tun_mode: true # user note\nbar: keep"));
        let rules = action("rules", &sha256(old_merge.as_bytes()), json!("GLOBAL"));
        adapter.apply(&rules).unwrap();
        let changed = fs::read_to_string(&merge).unwrap();
        assert!(changed.starts_with("port: 7890\nprepend-rules:"));
        assert!(adapter.restore(&rules).unwrap());
        assert_eq!(fs::read_to_string(&merge).unwrap(), old_merge);
        assert!(adapter.restore(&tun).unwrap());
        assert_eq!(fs::read_to_string(&verge).unwrap(), old_verge);
        let rules = action("rules", &sha256(old_merge.as_bytes()), json!("GLOBAL"));
        adapter.apply(&rules).unwrap();
        fs::write(&merge, "external change\n").unwrap();
        assert!(!adapter.restore(&rules).unwrap());
        let _ = fs::remove_dir_all(home);
    }
    #[test]
    fn rejects_stale_hash_ambiguous_tun_and_missing_context_before_write() {
        let (home, store) = fixture();
        let (verge, _) = paths(&home);
        fs::write(&verge, "enable_tun_mode: false\nenable_tun_mode: false\n").unwrap();
        let old = fs::read_to_string(&verge).unwrap();
        let mut adapter = ProxyMutationAdapter::with_executor(store, Fake::default());
        let a = action("enable_tun", &sha256(old.as_bytes()), json!(true));
        assert_eq!(adapter.apply(&a).unwrap_err().code, "ambiguous_config");
        let mut stale = a.clone();
        stale["before"] = json!("0".repeat(64));
        assert_eq!(adapter.apply(&stale).unwrap_err().code, "config_changed");
        fs::write(&verge, "enable_tun_mode: false\n").unwrap();
        let valid = fs::read_to_string(&verge).unwrap();
        let mut missing = action("enable_tun", &sha256(valid.as_bytes()), json!(true));
        missing.as_object_mut().unwrap().remove("context");
        assert_eq!(adapter.apply(&missing).unwrap_err().code, "invalid_action");
        assert_eq!(fs::read_to_string(&verge).unwrap(), valid);
        let _ = fs::remove_dir_all(home);
    }
    #[test]
    fn fixed_commands_are_injected_and_reject_unknown_provider() {
        let (home, store) = fixture();
        let fake = Fake::default();
        let seen = fake.0.clone();
        let mut adapter = ProxyMutationAdapter::with_executor(store, fake);
        adapter
            .apply(&json!({"id":"start_proxy","before":false,"after":"clash-verge"}))
            .unwrap();
        adapter
            .apply(&json!({"id":"reload_proxy","before":"clash-verge","after":"clash-verge"}))
            .unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                ProxyCommand::Open(ProxyProvider::ClashVerge),
                ProxyCommand::QuitClashVerge,
                ProxyCommand::Open(ProxyProvider::ClashVerge)
            ]
        );
        assert_eq!(
            adapter
                .apply(&json!({"id":"start_proxy","after":"/tmp/no"}))
                .unwrap_err()
                .code,
            "invalid_action"
        );
        let _ = fs::remove_dir_all(home);
    }
}
