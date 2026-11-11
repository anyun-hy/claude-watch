//! Conflict-safe, fixed-scope Clash Verge repair mutations.
//!
//! The read helper deliberately returns configuration text only to the local
//! planner.  It must not be serialized into an audit receipt or UI response:
//! proxy profiles may contain credentials.
#![forbid(unsafe_code)]

use crate::{
    macos::Mutator,
    storage::StateStore,
};
use claude_watch_core::error::{CoreError, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

const CONFIG_LIMIT: usize = 2_000_000;
const APP_CONFIG_DIR: &str =
    "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev";

fn err(code: &str, message: &str) -> CoreError {
    CoreError::new(code, message)
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

pub struct ProxyMutationAdapter {
    _store: StateStore,
    _paths: ProxyMutationPaths,
}
impl ProxyMutationAdapter {
    pub fn native(store: StateStore) -> Self {
        let paths = ProxyMutationPaths::from_store(&store);
        Self {
            _store: store,
            _paths: paths,
        }
    }
    pub fn new(store: StateStore) -> Self {
        Self::native(store)
    }
}

impl Mutator for ProxyMutationAdapter {
    fn apply(&mut self, _action: &Value) -> Result<()> {
        Err(err(
            "vpn_managed_externally",
            "VPN 与代理配置由外部客户端管理，Watch 仅执行只读观测与通道断流",
        ))
    }
    fn restore(&mut self, _action: &Value) -> Result<bool> {
        Err(err(
            "vpn_managed_externally",
            "VPN 与代理配置由外部客户端管理，Watch 仅执行只读观测与通道断流",
        ))
    }
}

/// Check if VPN write actions are allowed. Under the current architecture,
/// VPN and proxy configuration mutations are retired and strictly rejected.
pub fn verify_vpn_write_allowed(
    _config: &claude_watch_core::config::Config,
    _action: &str,
) -> Result<()> {
    Err(err(
        "vpn_managed_externally",
        "VPN 与代理配置由外部客户端管理，Watch 仅执行只读观测与通道断流",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Paths;
    use serde_json::json;
    use std::fs;
    use uuid::Uuid;

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

    #[test]
    fn proxy_mutation_actions_and_restores_are_strictly_rejected() {
        let (home, store) = fixture();
        let (verge, merge) = paths(&home);
        let initial_verge = "foo: keep\nenable_tun_mode: false # user note\nbar: keep\n";
        let initial_merge = "port: 7890\n";
        fs::write(&verge, initial_verge).unwrap();
        fs::write(&merge, initial_merge).unwrap();

        let mut adapter = ProxyMutationAdapter::native(store.clone());

        for action_id in ["start_proxy", "reload_proxy", "enable_tun", "rules"] {
            let action = json!({
                "id": action_id,
                "context": "stable-context",
                "before": "clash-verge",
                "after": "clash-verge"
            });
            let err = adapter.apply(&action).unwrap_err();
            assert_eq!(err.code, "vpn_managed_externally", "action {action_id} must be rejected");

            let err = adapter.restore(&action).unwrap_err();
            assert_eq!(err.code, "vpn_managed_externally", "restore {action_id} must be rejected");
        }

        // Assert files remained untouched
        assert_eq!(fs::read_to_string(&verge).unwrap(), initial_verge);
        assert_eq!(fs::read_to_string(&merge).unwrap(), initial_merge);

        // Read-only inspection facts still work correctly
        let facts = read_clash_verge_config_facts(&store).unwrap();
        assert_eq!(facts.clash_verge_config.as_deref(), Some(initial_verge));
        assert_eq!(facts.merge_text.as_deref(), Some(initial_merge));

        let _ = fs::remove_dir_all(home);
    }
}
