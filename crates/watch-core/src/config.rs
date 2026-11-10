use crate::channel::NetworkBackendKind;
use crate::error::{CoreError, Result};
use crate::network::public_unicast;
use crate::policy::PolicyCatalog;
use crate::processes::Provider;
use crate::vpn::VpnExpectation;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub schema: u32,
    pub enabled: bool,
    pub proxy_mode: String,
    pub proxy_group: String,
    pub proxy_url: String,
    pub country: String,
    pub timezone: String,
    pub locale: String,
    pub network_service: String,
    pub online_enabled: bool,
    pub require_ipv6_off: bool,
    pub require_english: bool,
    pub require_stun: bool,
    pub require_dns: bool,
    pub require_pinned_rules: bool,
    pub guard_enabled: bool,
    pub timezone_watchdog: bool,
    pub auto_update: bool,
    pub auto_check_on_open: bool,
    pub return_to_overview_after_launch: bool,
    pub expected_egress: Vec<String>,
    pub expected_resolvers: Vec<String>,
    /// Legacy prelaunch history policy. It never permits changing a running session's IP.
    pub allow_ip_change: bool,
    /// Per-criterion disposition keyed by each AI service family's own
    /// `{prefix}_close_{criterion}` keys, declared in `PolicyCatalog`.
    ///
    /// Flattened so the on-disk shape is one flat object: a family added to
    /// the catalog extends this map without a new field. Unknown keys are
    /// rejected in `from_value`, which checks every incoming key against the
    /// default document, so flattening silently collecting them is not
    /// reachable.
    #[serde(flatten)]
    pub policy_actions: BTreeMap<String, String>,
    /// The exact OpenAI policy keys explicitly re-approved for Force.
    /// Absence means a pre-migration Force string cannot grant SIGKILL.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gpt_force_approved_v1: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_backend: Option<NetworkBackendKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_expectation: Option<VpnExpectation>,
    pub update_url: String,
    pub update_public_key: String,
    pub verified_claude_versions: Vec<String>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            schema: 1,
            enabled: true,
            proxy_mode: "auto".into(),
            proxy_group: String::new(),
            proxy_url: String::new(),
            country: String::new(),
            timezone: String::new(),
            locale: String::new(),
            network_service: "Wi-Fi".into(),
            online_enabled: true,
            require_ipv6_off: true,
            require_english: true,
            require_stun: false,
            require_dns: false,
            require_pinned_rules: false,
            guard_enabled: false,
            timezone_watchdog: false,
            auto_update: false,
            auto_check_on_open: true,
            return_to_overview_after_launch: false,
            expected_egress: Vec::new(),
            expected_resolvers: Vec::new(),
            allow_ip_change: true,
            policy_actions: PolicyCatalog::default_actions(),
            gpt_force_approved_v1: Vec::new(),
            network_backend: None,
            vpn_expectation: None,
            update_url: String::new(),
            update_public_key: String::new(),
            verified_claude_versions: Vec::new(),
        }
    }
}
fn invalid(detail: &str) -> CoreError {
    CoreError::new("invalid_config", detail)
}

impl Config {
    pub fn default_for_new_install() -> Self {
        Self {
            schema: 2,
            network_backend: Some(NetworkBackendKind::Seatbelt),
            ..Self::default()
        }
    }

    pub fn effective_network_backend(&self) -> NetworkBackendKind {
        if let Some(backend) = self.network_backend {
            backend
        } else if self.schema >= 2 {
            NetworkBackendKind::Seatbelt
        } else {
            NetworkBackendKind::NetworkExtension
        }
    }

    pub fn requires_backend_migration_setup(&self) -> bool {
        self.schema < 2 && self.network_backend.is_none()
    }

    pub fn vpn_is_read_only(&self) -> bool {
        self.effective_network_backend().is_sandbox()
            || self
                .vpn_expectation
                .as_ref()
                .is_some_and(|exp| exp.configured)
    }

    pub fn from_value(value: Value) -> Result<Self> {
        let incoming = value.as_object().ok_or_else(|| invalid("配置必须是对象"))?;
        let mut defaults =
            serde_json::to_value(Self::default()).map_err(|_| invalid("无法构造默认配置"))?;
        let merged = defaults
            .as_object_mut()
            .ok_or_else(|| invalid("默认配置格式无效"))?;
        // The approval and schema-2 fields are intentionally omitted from the
        // empty default document, keeping legacy policy digests stable.
        merged.insert("gpt_force_approved_v1".into(), serde_json::json!([]));
        merged.insert("network_backend".into(), Value::Null);
        merged.insert("vpn_expectation".into(), Value::Null);
        if incoming.keys().any(|k| !merged.contains_key(k)) {
            return Err(invalid("配置包含未知字段"));
        }
        for (key, value) in incoming {
            let default = &merged[key];
            if default.is_boolean() && !value.is_boolean() {
                return Err(invalid(&format!("{key} 必须是布尔值")));
            }
            if default.is_string() && value.as_str().is_none_or(|s| s.chars().count() > 16_384) {
                return Err(invalid(&format!("{key} 格式错误")));
            }
        }
        merged.extend(incoming.iter().map(|(k, v)| (k.clone(), v.clone())));
        for key in ["expected_egress", "expected_resolvers"] {
            let addresses = merged[key]
                .as_array()
                .filter(|v| v.len() <= 32)
                .ok_or_else(|| invalid("预期地址必须为 IP 列表"))?;
            let addresses = addresses
                .iter()
                .map(|v| {
                    v.as_str()
                        .and_then(public_unicast)
                        .ok_or_else(|| invalid("预期地址必须是有效公网 IP"))
                })
                .collect::<Result<BTreeSet<_>>>()?;
            merged.insert(
                key.into(),
                serde_json::to_value(addresses).map_err(|_| invalid("预期地址格式错误"))?,
            );
        }
        let versions = merged["verified_claude_versions"]
            .as_array()
            .filter(|v| v.len() <= 100)
            .ok_or_else(|| invalid("账号兼容性版本列表无效"))?;
        if versions.iter().any(|v| {
            v.as_str().is_none_or(|s| {
                s.is_empty()
                    || s.len() > 80
                    || !s
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"._+-".contains(&c))
            })
        }) {
            return Err(invalid("账号兼容性版本列表无效"));
        }
        let mut result: Self =
            serde_json::from_value(defaults).map_err(|_| invalid("配置字段类型无效"))?;
        if !matches!(result.schema, 1 | 2)
            || !matches!(
                result.proxy_mode.as_str(),
                "tag" | "clash-verge" | "shadowrocket" | "sing-box" | "clashx" | "surge" | "auto"
            )
        {
            return Err(invalid("不支持的配置版本或代理类型"));
        }
        if result.schema == 2 && result.network_backend.is_none() {
            result.network_backend = Some(NetworkBackendKind::Seatbelt);
        }
        if let Some(ref mut expectation) = result.vpn_expectation {
            if expectation.proxy_url.is_empty() && !result.proxy_url.is_empty() {
                expectation.proxy_url = result.proxy_url.clone();
            } else if result.proxy_url.is_empty() && !expectation.proxy_url.is_empty() {
                result.proxy_url = expectation.proxy_url.clone();
            }
            if expectation.proxy_mode.is_empty() && !result.proxy_mode.is_empty() {
                expectation.proxy_mode = result.proxy_mode.clone();
            }
            if expectation.proxy_group.is_empty() && !result.proxy_group.is_empty() {
                expectation.proxy_group = result.proxy_group.clone();
            }
            expectation.bind_top_level_authority(
                &result.proxy_mode,
                &result.proxy_url,
                &result.proxy_group,
            )?;
        }
        if !result.country.is_empty()
            && (result.country.len() != 2
                || !result.country.bytes().all(|c| c.is_ascii_uppercase()))
        {
            return Err(invalid("国家必须为两位大写代码"));
        }
        if !result.timezone.is_empty() {
            let parts: Vec<_> = result.timezone.split('/').collect();
            if parts.len() < 2
                || parts.iter().any(|v| {
                    v.is_empty()
                        || !v
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"_+-".contains(&c))
                })
            {
                return Err(invalid("无效时区"));
            }
        }
        if !result.locale.is_empty() && !valid_locale(&result.locale) {
            return Err(invalid("无效地区格式"));
        }
        for name in [&result.proxy_group, &result.network_service] {
            if name.chars().count() > 256 || name.chars().any(|c| matches!(c, '\n' | '\r' | '\0')) {
                return Err(invalid("代理组或网络服务名称无效"));
            }
        }
        if !result.update_url.is_empty() && !valid_https(&result.update_url) {
            return Err(invalid("更新源必须为不含凭据的 HTTPS 地址"));
        }
        if !result.proxy_url.is_empty() && !valid_loopback_proxy(&result.proxy_url) {
            return Err(invalid("诊断代理必须为数字回环 HTTP 入口"));
        }
        // Each family is validated against the actions it declared, so a
        // service is never configured to perform something it cannot do, and
        // a family added to the catalog is validated without an edit here.
        for family in PolicyCatalog::families() {
            for criterion in PolicyCatalog::keyed_criteria() {
                let key = family.key(criterion.id);
                let value = result.action(family.id, criterion.id);
                if !family.performable(&value) {
                    return Err(invalid(&format!("{key} 必须为 {}", family.actions.join("、"))));
                }
            }
        }
        // Old schema-1 files could already contain gpt_close_*=force before
        // this consent protocol existed. Those strings have no execution
        // authority; normalize their effective values to ordinary close.
        let openai = PolicyCatalog::family("openai")
            .ok_or_else(|| invalid("OpenAI 策略目录不可用"))?;
        let keys = PolicyCatalog::keyed_criteria()
            .map(|criterion| openai.key(criterion.id))
            .collect::<BTreeSet<_>>();
        let mut seen = BTreeSet::new();
        if result.gpt_force_approved_v1.len() > keys.len()
            || result.gpt_force_approved_v1.iter().any(|key| {
                !keys.contains(key) || !seen.insert(key.clone())
            })
        {
            return Err(invalid("历史 Force 确认记录无效"));
        }
        result.gpt_force_approved_v1.retain(|key| {
            result.policy_actions.get(key).is_some_and(|action| action == "force")
        });
        result.gpt_force_approved_v1.sort();
        let approved = result.gpt_force_approved_v1.iter().cloned().collect::<BTreeSet<_>>();
        for key in &keys {
            if result.policy_actions.get(key).is_some_and(|value| value == "force")
                && !approved.contains(key)
            {
                result.policy_actions.insert(key.clone(), "close".into());
            }
        }
        Ok(result)
    }
    /// Actions a service can be configured to take, from the family that
    /// supervises it. The services are not the same shape, and the shape is
    /// declared in the catalog: anything that renders or validates a policy
    /// reads this instead of assuming one service's set.
    pub fn allowed_actions(provider: Provider) -> &'static [&'static str] {
        PolicyCatalog::family_for(provider)
            .map(|family| family.actions)
            .unwrap_or(&["warn"])
    }
    /// Configured action of one family and criterion, defaulting to the
    /// action the criterion (or its family) declared for a missing key.
    pub fn action(&self, family: &str, criterion: &str) -> String {
        let Some(family) = PolicyCatalog::family(family) else {
            return String::new();
        };
        let key = family.key(criterion);
        let selected = self.policy_actions
            .get(&key)
            .cloned()
            .unwrap_or_else(|| PolicyCatalog::fallback_action(family, criterion).to_string());
        // Also guard manually constructed Config values, which bypass parsing.
        if family.id == "openai" && selected == "force"
            && !self.gpt_force_approved_v1.contains(&key)
        {
            "close".to_string()
        } else {
            selected
        }
    }
    /// Configured action for a confirmed risk code within one service's own
    /// policy family. Families are kept separate, so an action is always
    /// resolved against the service being supervised and one service's policy
    /// can never be read from the other's keys. Codes without a config key
    /// keep the historical normal-exit path.
    pub fn close_action(&self, code: &str, provider: Provider) -> String {
        // A service or a code this table does not describe cannot be mapped to
        // a key, so nothing was configured for it. Falling back to `close`
        // here would let a code the user never saw bypass every policy they
        // did set, which is exactly the "I changed it and it still closed"
        // failure. An unmapped code therefore only ever reports.
        let Some(family) = PolicyCatalog::family_for(provider) else {
            return "warn".to_string();
        };
        let Some(criterion) = PolicyCatalog::criterion_for(code) else {
            return "warn".to_string();
        };
        // A stored value the service cannot perform (a policy written before
        // a capability existed) degrades to that service's mildest action
        // instead of being performed as written.
        let performable = |value: String| -> String {
            if family.performable(&value) {
                value
            } else {
                family.fallback().to_string()
            }
        };
        if criterion.combines.is_empty() {
            return performable(self.action(family.id, criterion.id));
        }
        // A code spanning several criteria: apply the strictest configured
        // action so a wider drift can never be handled more leniently than a
        // single-criterion drift.
        let mut strictest = String::new();
        for part in criterion.combines {
            let value = self.action(family.id, part);
            if strictest.is_empty() || family.severity(&value) > family.severity(&strictest) {
                strictest = value;
            }
        }
        performable(strictest)
    }
    pub fn value(&self) -> Result<Value> {
        serde_json::to_value(self).map_err(|_| invalid("配置无法序列化"))
    }
}

fn valid_locale(value: &str) -> bool {
    let (base, options) = value
        .split_once('@')
        .map_or((value, None), |(base, options)| (base, Some(options)));
    if options.is_some_and(|v| {
        v.is_empty()
            || !v
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_=;".contains(&c))
    }) {
        return false;
    }
    let Some((language, country)) = base.split_once('_') else {
        return false;
    };
    (2..=3).contains(&language.len())
        && language.bytes().all(|c| c.is_ascii_lowercase())
        && country.len() == 2
        && country.bytes().all(|c| c.is_ascii_uppercase())
}
pub fn valid_https(value: &str) -> bool {
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    let Some((scheme, authority)) = value.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("https")
        || authority.is_empty()
        || authority.starts_with('/')
        || authority.contains('\\')
    {
        return false;
    }
    Url::parse(value).is_ok_and(|u| {
        u.scheme() == "https"
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none()
    })
}
pub fn valid_loopback_proxy(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if url.scheme() != "http"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    let Some((_, authority_path)) = value.split_once("://") else {
        return false;
    };
    let (authority, path) = authority_path
        .split_once('/')
        .map_or((authority_path, ""), |(a, p)| (a, p));
    if !path.is_empty() || authority.contains('@') {
        return false;
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    let host = host
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(host);
    port.parse::<u16>().is_ok_and(|port| port > 0)
        && host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn defaults_and_explicit_disable_survive_roundtrip() {
        let default = Config::from_value(json!({})).unwrap();
        assert!(default.enabled && default.online_enabled);
        assert!(!default.guard_enabled && !default.timezone_watchdog);
        assert_eq!(default.proxy_mode, "auto");
        assert!(default.country.is_empty());
        let disabled = Config::from_value(json!({"enabled":false,"guard_enabled":false})).unwrap();
        assert!(!disabled.enabled && !disabled.guard_enabled);
        assert_eq!(
            Config::from_value(disabled.value().unwrap()).unwrap(),
            disabled
        );
    }
    #[test]
    fn types_names_and_regions_are_validated() {
        for bad in [
            json!({"unknown":true}),
            json!({"schema":true}),
            json!({"schema":1.0}),
            json!({"enabled":1}),
            json!({"country":"jp"}),
            json!({"timezone":"../Tokyo"}),
            json!({"locale":"ja_jp"}),
            json!({"network_service":"Wi-Fi\nother"}),
            json!({"verified_claude_versions":["bad version"]}),
        ] {
            assert_eq!(Config::from_value(bad).unwrap_err().code, "invalid_config");
        }
        assert!(Config::from_value(
            json!({"country":"JP","timezone":"Asia/Tokyo","locale":"en_JP@calendar=gregorian"})
        )
        .is_ok());
    }
    #[test]
    fn proxy_must_be_explicit_numeric_loopback() {
        for good in [
            "http://127.0.0.1:7890",
            "http://127.0.0.1:80/",
            "http://[::1]:7890/",
        ] {
            assert!(valid_loopback_proxy(good), "{good}");
        }
        for bad in [
            "http://localhost:7890",
            "http://127.1:7890",
            "http://0x7f000001:7890",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:7890/./",
            "http://user@127.0.0.1:7890",
            "socks5://127.0.0.1:7890",
        ] {
            assert!(!valid_loopback_proxy(bad), "{bad}");
        }
    }
    #[test]
    fn addresses_are_deduplicated_and_multicast_is_not_an_exit() {
        let good =
            Config::from_value(json!({"expected_egress":["8.8.8.8","1.1.1.1","8.8.8.8"]})).unwrap();
        assert_eq!(good.expected_egress, ["1.1.1.1", "8.8.8.8"]);
        for value in ["224.0.0.1", "192.168.1.1", "ff02::1"] {
            assert!(Config::from_value(json!({"expected_resolvers":[value]})).is_err());
        }
    }
    #[test]
    fn https_requires_a_real_authority_and_no_credentials() {
        for good in [
            "https://example.test/releases",
            "https://example.test/releases?channel=stable",
        ] {
            assert!(valid_https(good));
        }
        for bad in [
            "http://example.test",
            "https:///example.test",
            "https:example.test",
            "https://user:secret@example.test",
            "https://example.test/#fragment",
            "https://example.test/\npath",
        ] {
            assert!(!valid_https(bad), "{bad}");
        }
    }
}

#[cfg(test)]
mod protection_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn probe_blocking_defaults_to_off_and_policy_defaults_to_force() {
        let config = Config::from_value(json!({})).unwrap();
        assert!(!config.require_dns && !config.require_stun);
        for criterion in ["ip", "cn", "dns", "webrtc"] {
            // Claude defaults to "force" as declared by its policy family contract.
            // OpenAI defaults to "close" (preserve process & disconnect channel).
            assert_eq!(config.action("claude", criterion), "force");
            assert_eq!(config.action("openai", criterion), "close");
        }

        // Explicit user configuration requesting close on Claude is respected
        let explicit_close = Config::from_value(json!({
            "claude_close_ip": "close",
            "claude_close_cn": "warn"
        })).unwrap();
        assert_eq!(explicit_close.action("claude", "ip"), "close");
        assert_eq!(explicit_close.action("claude", "cn"), "warn");
        assert_eq!(explicit_close.action("claude", "dns"), "force"); // unconfigured remains default force
    }
    #[test]
    fn close_actions_accept_only_the_three_documented_values() {
        let warn = Config::from_value(json!({
            "claude_close_ip":"warn","claude_close_cn":"close",
            "claude_close_dns":"warn","claude_close_webrtc":"close"
        }))
        .unwrap();
        assert_eq!(warn.action("claude", "ip"), "warn");
        assert_eq!(warn.action("claude", "cn"), "close");
        for bad in [
            json!({"claude_close_ip":"kill"}),
            json!({"claude_close_dns":"FORCE"}),
            json!({"claude_close_webrtc":true}),
        ] {
            assert_eq!(Config::from_value(bad).unwrap_err().code, "invalid_config");
        }
    }
    #[test]
    fn gpt_policy_closes_by_default_and_is_configured_independently() {
        let config = Config::from_value(json!({})).unwrap();
        for code in [
            "egress_ip_changed",
            "egress_country_cn",
            "dns_egress_changed",
            "webrtc_egress_changed",
        ] {
            assert_eq!(config.close_action(code, Provider::Codex), "close");
            assert_eq!(config.close_action(code, Provider::Chatgpt), "close");
            assert_eq!(config.close_action(code, Provider::Claude), "force");
        }
        // Each service reads only its own family: setting one never moves
        // the other.
        let split = Config::from_value(json!({"claude_close_cn":"warn","gpt_close_ip":"warn"})).unwrap();
        assert_eq!(split.close_action("egress_country_cn", Provider::Claude), "warn");
        assert_eq!(split.close_action("egress_ip_changed", Provider::Chatgpt), "warn");
        assert_eq!(split.close_action("egress_ip_changed", Provider::Claude), "force");
        assert_eq!(split.close_action("egress_country_cn", Provider::Codex), "close");

        // When Claude is explicitly configured for close, it returns close
        let explicit_claude_close = Config::from_value(json!({
            "claude_close_ip": "close",
            "claude_close_cn": "warn"
        })).unwrap();
        assert_eq!(explicit_claude_close.close_action("egress_ip_changed", Provider::Claude), "close");
        assert_eq!(explicit_claude_close.close_action("egress_country_cn", Provider::Claude), "warn");
        assert_eq!(explicit_claude_close.close_action("egress_ip_changed", Provider::Chatgpt), "close");
        // Codes are resolved inside the family, and the stricter of two
        // drifting probe families wins.
        let strict =
            Config::from_value(json!({"claude_close_dns":"warn","claude_close_webrtc":"close"}))
                .unwrap();
        assert_eq!(
            strict.close_action("dns_and_webrtc_egress_changed", Provider::Claude),
            "close"
        );
        // A legacy OpenAI Force value is not new explicit consent.
        let legacy =
            Config::from_value(json!({"gpt_close_cn":"force","gpt_close_ip":"close"})).unwrap();
        assert_eq!(legacy.close_action("egress_country_cn", Provider::Codex), "close");
        let forced = Config::from_value(json!({
            "gpt_close_cn":"force","gpt_close_ip":"close",
            "gpt_force_approved_v1":["gpt_close_cn"]
        })).unwrap();
        assert_eq!(forced.close_action("egress_country_cn", Provider::Codex), "force");
        assert_eq!(forced.close_action("egress_ip_changed", Provider::Chatgpt), "close");
        for bad in [
            json!({"gpt_close_ip":"kill"}),
            json!({"gpt_close_cn":true}),
            json!({"gpt_close_cn":"FORCE"}),
        ] {
            assert_eq!(Config::from_value(bad).unwrap_err().code, "invalid_config");
        }
        // Even a manually constructed stale configuration has no OpenAI
        // Force authority without its per-key grant.
        let mut stale = Config::default();
        stale
            .policy_actions
            .insert("gpt_close_webrtc".into(), "force".into());
        assert_eq!(stale.close_action("webrtc_egress_changed", Provider::Codex), "close");
        assert_eq!(stale.close_action("webrtc_egress_changed", Provider::Claude), "force");
    }
    #[test]
    fn a_family_added_to_the_catalog_is_validated_and_resolved_without_an_edit() {
        // The catalog is the single declaration: every family in it is
        // defaulted, validated against its own actions, and resolvable.
        for family in PolicyCatalog::families() {
            for criterion in PolicyCatalog::keyed_criteria() {
                let config = Config::from_value(json!({})).unwrap();
                // A criterion may pin its own default (an unestablished
                // session keeps the historical normal exit even where the
                // family defaults to something stricter), so the declared
                // fallback — not the family default alone — is the contract.
                assert_eq!(
                    config.action(family.id, criterion.id),
                    PolicyCatalog::fallback_action(family, criterion.id)
                );
                for action in family.actions {
                    let key = family.key(criterion.id);
                    let stored = Config::from_value(json!({ key: action })).unwrap();
                    assert_eq!(
                        stored.action(family.id, criterion.id),
                        if family.id == "openai" && *action == "force" { "close" } else { *action }
                    );
                }
                let rejected = family.key(criterion.id);
                assert_eq!(
                    Config::from_value(json!({ rejected: "kill" })).unwrap_err().code,
                    "invalid_config"
                );
            }
        }
        // An undeclared family's key is not a config field at all.
        assert_eq!(
            Config::from_value(json!({"gemini_close_ip": "warn"}))
                .unwrap_err()
                .code,
            "invalid_config"
        );
    }
    #[test]
    fn saved_configuration_preserves_explicit_actions_and_does_not_revert_to_default_close() {
        let original = Config::from_value(json!({
            "claude_close_ip": "force",
            "claude_close_cn": "close",
            "gpt_close_cn": "warn"
        })).unwrap();

        let serialized = original.value().unwrap();
        assert_eq!(serialized["claude_close_ip"], "force");
        assert_eq!(serialized["claude_close_cn"], "close");
        assert_eq!(serialized["gpt_close_cn"], "warn");

        let reloaded = Config::from_value(serialized).unwrap();
        assert_eq!(reloaded.action("claude", "ip"), "force");
        assert_eq!(reloaded.action("claude", "cn"), "close");
        assert_eq!(reloaded.action("openai", "cn"), "warn");
        // Unconfigured fields remain their family default ("force" for Claude, "close" for OpenAI)
        assert_eq!(reloaded.action("claude", "dns"), "force");
        assert_eq!(reloaded.action("openai", "ip"), "close");
    }
}
