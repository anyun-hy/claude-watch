//! Command contract shared by the native engine and thin compatibility launchers.
use crate::error::{CoreError, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    pub command: String,
    pub action: Option<String>,
    pub target: Option<String>,
    pub flags: BTreeSet<String>,
    pub values: BTreeMap<String, String>,
    pub receipt_id: Option<String>,
    /// Opaque child arguments are not included in namespace or logs.
    pub child_args: Vec<String>,
}
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("command", &self.command)
            .field("action", &self.action)
            .field("target", &self.target)
            .field("flags", &self.flags)
            .field("value_keys", &self.values.keys().collect::<Vec<_>>())
            .field("child_argument_count", &self.child_args.len())
            .finish()
    }
}
fn invalid() -> CoreError {
    CoreError::new("invalid_arguments", "命令或参数无效")
}
impl Request {
    pub fn parse(arguments: &[String]) -> Result<Self> {
        let delimiter = arguments.iter().position(|v| v == "--");
        let (arguments, child) = delimiter
            .map(|i| (&arguments[..i], &arguments[i + 1..]))
            .unwrap_or((arguments, &[]));
        if child.len() > 128 || child.iter().any(|v| v.len() > 16384 || v.contains('\0')) {
            return Err(invalid());
        }
        if arguments.is_empty()
            || arguments.len() > 64
            || arguments
                .iter()
                .any(|v| v.len() > 16384 || v.chars().any(char::is_control))
        {
            return Err(invalid());
        }
        let command = arguments[0].as_str();
        let (actions, flags, values): (&[&str], &[&str], &[&str]) = match command {
            "status" | "self-check" | "service-status" | "guard-tick" => (&[], &[], &[]),
            "protection" => (&["preview", "apply"], &["apply"], &["plan-id"]),
            "environment" => (&[], &["online", "record"], &["mode"]),
            "dns-leak-record" | "webrtc-risk-record" => (&[], &["apply"], &[]),
            "launch" => (&[], &["apply"], &["target"]),
            "setup" => (
                &["inspect", "detect", "preview", "apply", "recover"],
                &["online", "apply"],
                &["mode", "candidate-id", "plan-id"],
            ),
            "check" | "checkdetail" => {
                (&[], &["online", "require-ready", "no-report"], &["target"])
            }
            "config" => (&["show", "set", "enabled"], &["apply"], &[]),
            "account" => (
                &["status", "switch", "recover", "import"],
                &["apply", "ack-unverified-version"],
                &[],
            ),
            "repair" | "fix" | "set-region" => (&[], &["apply"], &["plan-id", "allow-country"]),
            "restore-settings" => (&[], &["apply"], &[]),
            "services" => (
                &[
                    "update-on",
                    "update-off",
                    "disable-legacy",
                    "refresh-admin",
                    "recover",
                ],
                &["apply"],
                &[],
            ),
            "update" => (&[], &["apply", "auto", "recover"], &[]),
            "app-install" => (&[], &["apply"], &["source"]),
            "app-uninstall" => (&[], &["apply"], &[]),
            "install" => (&[], &["apply"], &["source"]),
            "preflight" | "audit" => (&[], &["online", "require-ready", "no-report"], &["target"]),
            "proxy-check" => (&[], &[], &[]),
            "dns-check" => (&[], &["online"], &[]),
            "launch-desktop" => (&[], &["apply"], &[]),
            "uninstall" => (
                &[],
                &[
                    "apply",
                    "purge-accounts",
                    "confirm-data-removal",
                    "remove-managed-rules",
                ],
                &[],
            ),
            "logs" => (&[], &[], &["export"]),
            "event-history" => (&[], &[], &[]),
            "event-diagnostic" => (&[], &["apply"], &[]),
            "guard-diagnostic" => (&[], &["apply"], &[]),
            "diagnose-proxy" => (&[], &["stdin-config"], &["proxy", "config"]),
            "observe" => (&[], &["json"], &["home"]),
            "snapshot" => (&[], &["full"], &[]),
            "ai-probe" => (&[], &[], &["service"]),
            "dns-probe" => (&[], &[], &[]),
            "server-reference" => (&[], &[], &["host", "ip"]),
            "coffee" => (
                &["lookup", "geoip", "risk", "dns", "trace"],
                &[],
                &["record-har"],
            ),
            "daemon" => (&[], &["apply", "once", "observe-only"], &[]),
            "arm" | "pause" | "test-alert" => (&[], &[], &[]),
            "snooze" => (&[], &[], &["minutes"]),
            _ => return Err(CoreError::new("unknown_command", "未知操作")),
        };
        let mut request = Self {
            command: command.into(),
            action: None,
            target: None,
            flags: BTreeSet::new(),
            values: BTreeMap::new(),
            receipt_id: None,
            child_args: child.to_vec(),
        };
        let mut positionals = Vec::new();
        let mut index = 1;
        while index < arguments.len() {
            let token = &arguments[index];
            if let Some(option) = token.strip_prefix("--") {
                let (key, inline) = option
                    .split_once('=')
                    .map(|(k, v)| (k, Some(v)))
                    .unwrap_or((option, None));
                if flags.contains(&key) {
                    if inline.is_some() {
                        return Err(invalid());
                    }
                    request.flags.insert(key.into());
                } else if values.contains(&key) {
                    let value = if let Some(value) = inline {
                        value
                    } else {
                        index += 1;
                        arguments
                            .get(index)
                            .filter(|s| !s.starts_with("--"))
                            .ok_or_else(invalid)?
                    };
                    request.values.insert(key.into(), value.into());
                } else {
                    return Err(invalid());
                }
            } else if token.starts_with('-') {
                return Err(invalid());
            } else {
                positionals.push(token.clone());
            }
            index += 1;
        }
        if !actions.is_empty() {
            let action = positionals
                .first()
                .filter(|v| actions.contains(&v.as_str()))
                .ok_or_else(invalid)?;
            request.action = Some(action.clone());
            positionals.remove(0);
        }
        if command == "account" {
            if let Some(target) = positionals.first() {
                if !["A", "B"].contains(&target.as_str()) {
                    return Err(invalid());
                }
                request.target = Some(target.clone());
                positionals.remove(0);
            }
        }
        if command == "coffee" {
            if let Some(query) = positionals.first() {
                request.target = Some(query.clone());
                positionals.remove(0);
            }
            if request.action.as_deref() == Some("trace") {
                if request.target.as_deref().is_some_and(|v| !v.is_empty()) {
                    return Err(invalid());
                }
            } else if request.target.as_deref().is_none_or(str::is_empty) {
                return Err(invalid());
            }
        }
        if command == "snooze" && request.value("minutes").is_none() && positionals.len() == 1 {
            request
                .values
                .insert("minutes".into(), positionals.remove(0));
        }
        if command == "restore-settings" {
            request.receipt_id = Some(positionals.first().ok_or_else(invalid)?.clone());
            positionals.remove(0);
        }
        if !positionals.is_empty() {
            return Err(invalid());
        }
        if command == "ai-probe" && !matches!(request.value("service"), Some("claude" | "gpt")) {
            return Err(invalid());
        }
        if command == "server-reference" && request.value("host").is_none() {
            return Err(invalid());
        }
        if command == "app-install" && request.value("source").is_none() {
            return Err(invalid());
        }
        if request
            .value("target")
            .is_some_and(|value| crate::processes::LaunchTarget::parse(value).is_none())
        {
            return Err(invalid());
        }
        if delimiter.is_some() && (command != "launch" || !request.launch_target().cli()) {
            return Err(invalid());
        }
        if matches!(command, "setup" | "environment") {
            request.values.entry("mode".into()).or_insert("auto".into());
        }
        if request
            .values
            .get("allow-country")
            .is_some_and(|v| v != "CN")
        {
            return Err(invalid());
        }
        if command == "diagnose-proxy"
            && usize::from(request.values.contains_key("proxy"))
                + usize::from(request.values.contains_key("config"))
                + usize::from(request.flags.contains("stdin-config"))
                != 1
        {
            return Err(invalid());
        }
        Ok(request)
    }
    /// Command names select a view of the same services; they do not own an
    /// alternate baseline, policy evaluator, network probe or launch gate.
    pub fn execution(mut self) -> Self {
        match self.command.as_str() {
            "preflight" => {
                self.command = "checkdetail".into();
                self.flags.extend(["online".into(), "require-ready".into()]);
            }
            "audit" => {
                self.command = "checkdetail".into();
                self.flags.insert("online".into());
            }
            "launch-desktop" => self.command = "launch".into(),
            _ => {}
        }
        self
    }
    pub fn flag(&self, key: &str) -> bool {
        self.flags.contains(key)
    }
    pub fn value(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
    pub fn launch_target(&self) -> crate::processes::LaunchTarget {
        self.value("target")
            .and_then(crate::processes::LaunchTarget::parse)
            .unwrap_or_default()
    }
    pub fn require_apply(&self) -> Result<()> {
        if self.flag("apply") {
            Ok(())
        } else {
            Err(CoreError::new(
                "explicit_apply_required",
                "此操作需要明确的--apply，预览不会执行",
            ))
        }
    }
    pub fn input_limit(&self) -> usize {
        if matches!(
            self.command.as_str(),
            "dns-leak-record" | "webrtc-risk-record"
        ) {
            768 * 1024
        } else {
            64 * 1024
        }
    }
    pub fn namespace(&self) -> Value {
        let mut value = json!({"command":self.command});
        if let Some(action) = &self.action {
            value["action"] = json!(action)
        }
        if self.command == "account" {
            value["target"] = json!(self.target)
        }
        if let Some(id) = &self.receipt_id {
            value["receipt_id"] = json!(id)
        }
        if let Some(target) = self.value("target") {
            value["target"] = json!(target);
        }
        let boolean_defaults: &[&str] = match self.command.as_str() {
            "protection" | "dns-leak-record" | "webrtc-risk-record" | "config" | "launch"
            | "restore-settings" | "services" => &["apply"],
            "environment" => &["online", "record"],
            "setup" => &["online", "apply"],
            "check" | "checkdetail" => &["online", "require-ready", "no-report"],
            "account" => &["apply", "ack-unverified-version"],
            "repair" | "fix" | "set-region" => &["apply"],
            "update" => &["apply", "auto", "recover"],
            "uninstall" => &[
                "apply",
                "purge-accounts",
                "confirm-data-removal",
                "remove-managed-rules",
            ],
            _ => &[],
        };
        for key in boolean_defaults {
            value[key.replace('-', "_")] = json!(self.flag(key));
        }
        let optional: &[&str] = match self.command.as_str() {
            "protection" => &["plan-id"],
            "setup" => &["mode", "candidate-id", "plan-id"],
            "environment" => &["mode"],
            "repair" | "fix" | "set-region" => &["plan-id", "allow-country"],
            "logs" => &["export"],
            _ => &[],
        };
        for key in optional {
            value[key.replace('-', "_")] = json!(self.value(key));
        }
        value
    }
}

#[cfg(test)]
mod cli_target_contracts {
    use super::*;
    #[test]
    fn opaque_tail_keeps_parent_authorization_and_debug_separate() {
        let request = Request::parse(
            &[
                "launch",
                "--target",
                "claude-cli",
                "--",
                "--apply",
                "SYNTHETIC_SECRET\nline",
            ]
            .map(str::to_owned),
        )
        .unwrap();
        assert!(!request.flag("apply"));
        assert_eq!(request.child_args.len(), 2);
        assert!(!format!("{request:?}").contains("SYNTHETIC_SECRET"));
    }
}
