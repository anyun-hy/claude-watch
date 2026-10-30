//! The switcher-level uninstall contract. Removing the GUI/collector uses the
//! separate app lifecycle; the active Claude profile is never a removal target.
use crate::{config_store::ConfigStore, rules, storage::StateStore};
use claude_watch_core::error::{CoreError, Result};
use serde_json::{json, Value};
use std::fs;
#[derive(Clone, Copy, Default)]
pub struct Options {
    pub purge_accounts: bool,
    pub confirm_data_removal: bool,
    pub remove_managed_rules: bool,
}
pub fn apply(
    store: &StateStore,
    options: Options,
    mut stop_services: impl FnMut() -> Result<()>,
) -> Result<Value> {
    if options.purge_accounts && !options.confirm_data_removal {
        return Err(CoreError::new(
            "data_confirmation_required",
            "清理账号库需明确指定 --confirm-data-removal",
        ));
    }
    let _lock = store.lock("operation", None)?;
    let config = ConfigStore {
        storage: store.clone(),
    }
    .load()?;
    let mut desired = config.value()?;
    for key in [
        "enabled",
        "guard_enabled",
        "auto_update",
        "timezone_watchdog",
    ] {
        desired[key] = json!(false);
    }
    // Stop new automatic actions first, as in the mature implementation. If an
    // OS task refuses to stop, no account library or user rules are removed.
    store.atomic_json(&store.paths.config(), &desired)?;
    if let Err(error) = stop_services() {
        return Ok(
            json!({"status":"partial","accounts_removed":false,"automatic_actions_disabled":true,
            "code":error.code,"message":error.message}),
        );
    }
    if options.remove_managed_rules {
        let path=store.paths.home.join("Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/profiles/Merge.yaml");
        if let Some(before) = store.read_bytes(&path, 8_000_000)? {
            let text = std::str::from_utf8(&before)
                .map_err(|_| CoreError::new("invalid_rules", "规则文件编码无效"))?;
            let after = rules::remove_block(text)?;
            if store.read_bytes(&path, 8_000_000)?.as_ref() != Some(&before) {
                return Err(CoreError::new(
                    "external_change",
                    "规则已被其他程序更改，未覆盖",
                ));
            }
            if after.as_bytes() != before {
                store.atomic_bytes(&path, after.as_bytes(), 0o600)?;
            }
        }
    }
    if options.purge_accounts {
        for path in [
            store.paths.accounts(),
            store.paths.base().join("ip-history.json"),
            store.paths.base().join("accounts.json"),
        ] {
            store.guarded(&path)?;
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_dir() => fs::remove_dir_all(&path),
                Ok(meta) if meta.is_file() => fs::remove_file(&path),
                Ok(_) => return Err(CoreError::new("unsafe_path", "账号库路径类型无效，未清理")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => Err(e),
            }
            .map_err(|_| {
                CoreError::new(
                    "account_cleanup_failed",
                    "工具账号库清理未完成；当前 Claude 登录目录保留",
                )
            })?;
        }
    }
    Ok(
        json!({"status":"ok","accounts_removed":options.purge_accounts,
        "message":"新增保护和更新任务已停止；当前 Claude 资料保留"}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Paths;
    #[test]
    fn purge_requires_separate_ack_and_never_removes_active_claude_profile() {
        let root = std::env::temp_dir().join(format!("cw-uninstall-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        let active = store.paths.active().join("Cookies");
        store
            .atomic_bytes(&active, b"current-login", 0o600)
            .unwrap();
        let slot = store.paths.accounts().join("A/profile/Cookies");
        store.atomic_bytes(&slot, b"saved-A", 0o600).unwrap();
        let result = apply(
            &store,
            Options {
                purge_accounts: true,
                ..Default::default()
            },
            || panic!("must not invoke OS"),
        );
        assert_eq!(result.unwrap_err().code, "data_confirmation_required");
        assert!(!store.paths.config().exists());
        let result = apply(
            &store,
            Options {
                purge_accounts: true,
                confirm_data_removal: true,
                ..Default::default()
            },
            || Err(CoreError::new("service_refused", "fixture")),
        )
        .unwrap();
        assert_eq!(result["status"], "partial");
        assert!(slot.exists());
        assert!(
            !ConfigStore {
                storage: store.clone()
            }
            .load()
            .unwrap()
            .enabled
        );
        let result = apply(
            &store,
            Options {
                purge_accounts: true,
                confirm_data_removal: true,
                ..Default::default()
            },
            || Ok(()),
        )
        .unwrap();
        assert_eq!(result["accounts_removed"], true);
        assert!(!slot.exists());
        assert_eq!(fs::read(active).unwrap(), b"current-login");
        fs::remove_dir_all(root).unwrap();
    }
}
