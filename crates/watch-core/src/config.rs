use crate::error::{CoreError, Result};
use crate::network::public_unicast;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, net::IpAddr};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
    /// Per-criterion action for a running Claude session: force | close | warn.
    /// Empty or unknown values fall back to the documented default (force).
    pub claude_close_ip: String,
    pub claude_close_cn: String,
    pub claude_close_dns: String,
    pub claude_close_webrtc: String,
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
            claude_close_ip: "force".into(),
            claude_close_cn: "force".into(),
            claude_close_dns: "force".into(),
            claude_close_webrtc: "force".into(),
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
    pub fn from_value(value: Value) -> Result<Self> {
        let incoming = value.as_object().ok_or_else(|| invalid("配置必须是对象"))?;
        let mut defaults =
            serde_json::to_value(Self::default()).map_err(|_| invalid("无法构造默认配置"))?;
        let merged = defaults
            .as_object_mut()
            .ok_or_else(|| invalid("默认配置格式无效"))?;
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
        let result: Self =
            serde_json::from_value(defaults).map_err(|_| invalid("配置字段类型无效"))?;
        if result.schema != 1
            || !matches!(
                result.proxy_mode.as_str(),
                "tag" | "clash-verge" | "shadowrocket" | "sing-box" | "clashx" | "surge" | "auto"
            )
        {
            return Err(invalid("不支持的配置版本或代理类型"));
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
        for (key, value) in [
            ("claude_close_ip", &result.claude_close_ip),
            ("claude_close_cn", &result.claude_close_cn),
            ("claude_close_dns", &result.claude_close_dns),
            ("claude_close_webrtc", &result.claude_close_webrtc),
        ] {
            if !matches!(value.as_str(), "force" | "close" | "warn") {
                return Err(invalid(&format!("{key} 必须为 force、close 或 warn")));
            }
        }
        Ok(result)
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
        assert_eq!(config.claude_close_ip, "force");
        assert_eq!(config.claude_close_cn, "force");
        assert_eq!(config.claude_close_dns, "force");
        assert_eq!(config.claude_close_webrtc, "force");
    }
    #[test]
    fn close_actions_accept_only_the_three_documented_values() {
        let warn = Config::from_value(json!({
            "claude_close_ip":"warn","claude_close_cn":"close",
            "claude_close_dns":"warn","claude_close_webrtc":"close"
        }))
        .unwrap();
        assert_eq!(warn.claude_close_ip, "warn");
        assert_eq!(warn.claude_close_cn, "close");
        for bad in [
            json!({"claude_close_ip":"kill"}),
            json!({"claude_close_dns":"FORCE"}),
            json!({"claude_close_webrtc":true}),
        ] {
            assert_eq!(Config::from_value(bad).unwrap_err().code, "invalid_config");
        }
    }
}
