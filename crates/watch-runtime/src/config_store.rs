use crate::storage::{sha256, StateStore};
use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
};
use serde_json::Value;
use std::collections::BTreeSet;

pub struct ConfigStore {
    pub storage: StateStore,
}
impl ConfigStore {
    pub fn load(&self) -> Result<Config> {
        Config::from_value(
            self.storage
                .read_json(&self.storage.paths.config(), serde_json::json!({}))?,
        )
    }
    pub fn save(&self, value: Value) -> Result<Config> {
        self.save_with_force_confirmation(value, None)
    }

    /// Read-only migration disclosure for the UI. Loading never edits the
    /// legacy document; the effective config is already downgraded to close.
    pub fn legacy_force_pending(&self) -> Result<Vec<String>> {
        let raw = self.storage.read_json(
            &self.storage.paths.config(), serde_json::json!({}),
        )?;
        let config = Config::from_value(raw.clone())?;
        let openai = claude_watch_core::policy::PolicyCatalog::family("openai")
            .ok_or_else(|| CoreError::new("invalid_config", "OpenAI 策略目录不可用"))?;
        Ok(claude_watch_core::policy::PolicyCatalog::keyed_criteria()
            .filter_map(|criterion| {
                let key = openai.key(criterion.id);
                (raw.get(&key).and_then(Value::as_str) == Some("force")
                    && config.action("openai", criterion.id) != "force")
                    .then_some(key)
            })
            .collect())
    }

    /// A new OpenAI Force grant is a specific, explicit per-key transition.
    /// The ordinary full-document save must never re-authorize a stale force
    /// string, even if an older GUI echoes the raw value during another edit.
    /// The grant and the effective policy are committed in one atomic JSON.
    pub fn save_with_force_confirmation(
        &self,
        mut value: Value,
        confirmation: Option<&str>,
    ) -> Result<Config> {
        let _lock = self.storage.lock("operation", None)?;
        let raw_before = self.storage.read_json(
            &self.storage.paths.config(), serde_json::json!({}),
        )?;
        let previous = match Config::from_value(raw_before.clone()) {
            Ok(config) => config,
            Err(error) if confirmation.is_none() => {
                // Keep the original ability to repair invalid stored config
                // without allowing a new Force grant while authority is unknown.
                let _ = error;
                Config::default()
            }
            Err(error) => return Err(error),
        };
        let incoming = value.as_object_mut().ok_or_else(|| {
            CoreError::new("invalid_config", "配置必须是对象")
        })?;
        if incoming.get("gpt_force_approved_v1")
            .is_some_and(|v| v != &serde_json::json!(previous.gpt_force_approved_v1))
        {
            return Err(CoreError::new(
                "force_confirmation_invalid", "Force 授权记录不能由配置请求直接修改",
            ));
        }
        let openai = claude_watch_core::policy::PolicyCatalog::family("openai")
            .ok_or_else(|| CoreError::new("invalid_config", "OpenAI 策略目录不可用"))?;
        let allowed = claude_watch_core::policy::PolicyCatalog::keyed_criteria()
            .map(|criterion| openai.key(criterion.id))
            .collect::<BTreeSet<_>>();
        let mut approved = previous.gpt_force_approved_v1.iter()
            .cloned().collect::<BTreeSet<_>>();
        if let Some(raw) = confirmation {
            if raw.is_empty() || raw.len() > 512 {
                return Err(CoreError::new("force_confirmation_invalid", "Force 确认参数无效"));
            }
            let mut selected = BTreeSet::new();
            for key in raw.split(',') {
                if !allowed.contains(key)
                    || !selected.insert(key.to_string())
                    || incoming.get(key).and_then(Value::as_str) != Some("force")
                {
                    return Err(CoreError::new(
                        "force_confirmation_invalid", "Force 确认项与本次选择不一致",
                    ));
                }
            }
            approved.extend(selected);
        }
        // A newly requested Force without the explicit CLI confirmation is
        // rejected rather than silently accepted or displayed as successful.
        // A pre-migration, already-stored Force string is the sole exception:
        // it is downgraded to ordinary close when the document is next saved.
        for key in &allowed {
            if incoming.get(key).and_then(Value::as_str) == Some("force")
                && !approved.contains(key)
                && raw_before.get(key).and_then(Value::as_str) != Some("force")
            {
                return Err(CoreError::new(
                    "force_confirmation_required", "新选择的 Force 需要逐项明确确认",
                ));
            }
        }
        // An old, unconfirmed Force value is never inherited. A legitimate
        // existing approval persists only while that exact key stays Force.
        approved.retain(|key| incoming.get(key).and_then(Value::as_str) == Some("force"));
        incoming.insert(
            "gpt_force_approved_v1".into(),
            serde_json::json!(approved.into_iter().collect::<Vec<_>>()),
        );
        let validated = Config::from_value(value)?;
        self.storage
            .atomic_json(&self.storage.paths.config(), &validated.value()?)?;
        Ok(validated)
    }
}

/// Python json.dumps(sort_keys=True, ensure_ascii=False), for configuration/plan values.
/// Float formatting is normalized to the Python JSON exponent convention.
pub fn canonical_policy_json(value: &Value) -> Result<String> {
    match value {
        Value::Null => Ok("null".into()),
        Value::Bool(v) => Ok(v.to_string()),
        Value::Number(v) if v.is_i64() || v.is_u64() => Ok(v.to_string()),
        Value::Number(value) => {
            let value = value
                .as_f64()
                .filter(|v| v.is_finite())
                .ok_or_else(|| CoreError::new("invalid_policy_digest", "策略数值必须有限"))?;
            let text = format!("{value:?}");
            if let Some((mantissa, exponent)) = text.split_once('e') {
                let exponent = exponent
                    .parse::<i32>()
                    .map_err(|_| CoreError::new("invalid_policy_digest", "数值指数格式无效"))?;
                Ok(format!(
                    "{mantissa}e{}{:02}",
                    if exponent < 0 { '-' } else { '+' },
                    exponent.abs()
                ))
            } else {
                Ok(text)
            }
        }
        Value::String(v) => serde_json::to_string(v)
            .map_err(|_| CoreError::new("invalid_policy_digest", "策略字符串无法序列化")),
        Value::Array(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(canonical_policy_json)
                .collect::<Result<Vec<_>>>()?
                .join(", ")
        )),
        Value::Object(values) => {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            let fields = keys
                .into_iter()
                .map(|key| {
                    Ok(format!(
                        "{}: {}",
                        canonical_policy_json(&Value::String(key.clone()))?,
                        canonical_policy_json(&values[key])?
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("{{{}}}", fields.join(", ")))
        }
    }
}
pub fn policy_digest(value: &Value) -> Result<String> {
    Ok(sha256(canonical_policy_json(value)?.as_bytes()))
}

/// Bind a guard heartbeat to the policy used by the running guard. The
/// timezone service and its saved geographic target are independent of the
/// guard's local proxy/TUN checks and session risk checks. Changing only those
/// three fields must not invalidate a still-fresh guard observation. Full
/// audits, launch authorization and service transactions continue to bind the
/// complete policy with `policy_digest`.
pub fn guard_policy_digest(config: &Config) -> Result<String> {
    let mut policy = config.value()?;
    let fields = policy
        .as_object_mut()
        .ok_or_else(|| CoreError::new("invalid_policy_digest", "保护策略格式无效"))?;
    for key in ["timezone_watchdog", "country", "timezone"] {
        fields.remove(key);
    }
    policy_digest(&policy)
}

/// Old heartbeats have only the full policy digest. New heartbeats explicitly
/// carry the scoped digest; never fall back if that field is present but bad.
pub fn guard_heartbeat_policy_matches(heartbeat: &Value, config: &Config) -> Option<bool> {
    if let Some(actual) = heartbeat.get("guard_policy_v1") {
        return guard_policy_digest(config)
            .ok()
            .map(|expected| actual == &expected);
    }
    let actual = heartbeat.get("policy")?.as_str()?;
    config
        .value()
        .and_then(|v| policy_digest(&v))
        .ok()
        .map(|expected| actual == expected)
}

/// Read only proxy-related CLI settings. Other environment values (including
/// authentication secrets) never leave this local read adapter.
pub(crate) fn cli_proxy_overrides<R: crate::commands::ReadRunner>(
    runner: &R,
    home: &std::path::Path,
) -> Result<Vec<Value>> {
    use crate::commands::ReadCommand;
    let mut sets = Vec::new();
    for managed in [false, true] {
        let path = if managed {
            std::path::PathBuf::from(
                "/Library/Application Support/ClaudeCode/managed-settings.json",
            )
        } else {
            home.join(".claude/settings.json")
        };
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(claude_watch_core::error::CoreError::new(
                    "cli_settings_unavailable",
                    "CLI用户或管理设置无法读取",
                ))
            }
            Ok(_) => {}
        }
        let output = runner.run(
            ReadCommand::ClaudeSettings {
                home: home.into(),
                managed,
            },
            &[],
            std::time::Duration::from_secs(3),
            256 * 1024,
        )?;
        let value = if output.status == 0 {
            crate::storage::strict_json(&output.stdout)?
        } else {
            return Err(claude_watch_core::error::CoreError::new(
                "cli_settings_unavailable",
                "CLI用户或管理设置读取失败",
            ));
        };
        if !value.is_object() {
            return Err(claude_watch_core::error::CoreError::new(
                "cli_settings_unavailable",
                "CLI设置不是有效对象",
            ));
        }
        let mut selected = serde_json::Map::new();
        if let Some(env) = value.get("env") {
            let env = env.as_object().ok_or_else(|| {
                claude_watch_core::error::CoreError::new(
                    "cli_settings_unavailable",
                    "CLI设置环境字段格式无效",
                )
            })?;
            for key in [
                "https_proxy",
                "HTTPS_PROXY",
                "http_proxy",
                "HTTP_PROXY",
                "ALL_PROXY",
                "all_proxy",
                "NO_PROXY",
                "no_proxy",
            ] {
                if let Some(v) = env.get(key) {
                    selected.insert(key.into(), v.clone());
                }
            }
        }
        sets.push(Value::Object(selected));
    }
    Ok(sets)
}

#[cfg(test)]
mod cli_settings_contracts {
    use super::*;
    struct Reader;
    impl crate::commands::ReadRunner for Reader {
        fn run(
            &self,
            command: crate::commands::ReadCommand,
            _: &[u8],
            _: std::time::Duration,
            _: usize,
        ) -> Result<crate::commands::Output> {
            let crate::commands::ReadCommand::ClaudeSettings { home, managed } = command else {
                panic!("unexpected read")
            };
            let stdout = if managed {
                b"{}".to_vec()
            } else {
                std::fs::read(home.join(".claude/settings.json")).unwrap()
            };
            Ok(crate::commands::Output {
                status: 0,
                stdout,
                stderr: vec![],
            })
        }
    }
    #[test]
    fn default_policy_digest_is_pinned_so_a_field_reorder_cannot_break_heartbeats() {
        // Heartbeats already on disk carry these digests. Adding, renaming or
        // reordering a config field would invalidate every live heartbeat, so
        // the default document's digest is pinned here. The 2026-11 pin moved
        // when the ChatGPT / Codex family gained the ordinary close action, and
        // again when the unestablished-session criterion gained its own switch.
        let config = Config::default();
        assert_eq!(
            policy_digest(&config.value().unwrap()).unwrap(),
            "460959ad0e5f9d406f38cc8ee2109f403517730559b6215beb4ef88c84920c36"
        );
        assert_eq!(
            guard_policy_digest(&config).unwrap(),
            "820b249fb027c2f719dc7d1b433cfecf9c6895e5dc4034f1ca2c37b0edd4ff5e"
        );
    }
    #[test]
    fn cli_proxy_read_filters_auth_values_and_never_updates_settings() {
        let root = std::env::temp_dir().join(format!("cli-settings-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join(".claude")).unwrap();
        let path = root.join(".claude/settings.json");
        let before=br#"{"env":{"HTTP_PROXY":"http://127.0.0.1:7890","ANTHROPIC_API_KEY":"SYNTHETIC_KEY"}}"#;
        std::fs::write(&path, before).unwrap();
        let values = cli_proxy_overrides(&Reader, &root).unwrap();
        let out = serde_json::to_string(&values).unwrap();
        assert!(!out.contains("SYNTHETIC_KEY"));
        assert_eq!(values[0]["HTTP_PROXY"], "http://127.0.0.1:7890");
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_dir_all(root).unwrap();
    }
}
