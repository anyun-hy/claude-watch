//! Read-only local environment capture used by the onboarding transaction.
//! The format-2 storage encoding is retained for existing recovery records.
//! This module owns no command, policy comparison, or launch authorization.

use crate::{
    commands::{ReadCommand, ReadRunner},
    storage::sha256,
};
use claude_watch_core::error::{CoreError, Result};
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

const TIMEOUT: Duration = Duration::from_secs(3);
const LIMIT: usize = 256 * 1024;
const PROXY_KEYS: [&str; 6] = [
    "https_proxy",
    "HTTPS_PROXY",
    "http_proxy",
    "HTTP_PROXY",
    "NO_PROXY",
    "no_proxy",
];
const CLI_PROXY_KEYS: [&str; 8] = [
    "https_proxy",
    "HTTPS_PROXY",
    "http_proxy",
    "HTTP_PROXY",
    "NO_PROXY",
    "no_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// Explicit inputs keep the collector deterministic under tests.  Production
/// callers pass their state-store home and a snapshot of `std::env::vars()`.
#[derive(Clone, Debug, Default)]
pub struct EnvironmentInput {
    pub home: PathBuf,
    pub environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentFacts {
    pub timezone: String,
    pub ipv4_route: String,
    pub ipv6_route: String,
    pub dns: String,
    pub dns_sig: String,
    pub sys_proxy: String,
    pub sys_proxy_sig: String,
    pub cli_proxy: String,
    pub cli_proxy_sig: String,
    pub settings_proxy: String,
    pub settings_proxy_sig: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentCapture {
    /// The complete, newline-terminated `format=2` text written by onboarding.
    pub data: String,
    /// The measured inputs that produced `data`; no route or proxy is invented.
    pub measured: EnvironmentFacts,
}

fn command_text<R: ReadRunner>(runner: &R, command: ReadCommand) -> Option<String> {
    let output = runner.run(command, &[], TIMEOUT, LIMIT).ok()?;
    (output.status == 0)
        .then(|| output.text().ok().map(str::to_owned))
        .flatten()
}

fn command_output<R: ReadRunner>(
    runner: &R,
    command: ReadCommand,
) -> Option<(i32, String, String)> {
    let output = runner.run(command, &[], TIMEOUT, LIMIT).ok()?;
    Some((
        output.status,
        output.text().ok()?.to_owned(),
        output.error_text().ok()?.to_owned(),
    ))
}

fn route<R: ReadRunner>(runner: &R, v6: bool) -> String {
    let command = if v6 {
        ReadCommand::RouteDefaultV6
    } else {
        ReadCommand::RouteDefaultV4
    };
    let Some((status, stdout, stderr)) = command_output(runner, command) else {
        return "unavailable".into();
    };
    let output = format!("{stdout}{stderr}");
    let lower = output.to_ascii_lowercase();
    if ["not in table", "no route", "not found"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        return "absent".into();
    }
    if status != 0 {
        return "unavailable".into();
    }
    let mut interface = None;
    let mut gateway = "";
    for line in output.lines() {
        let trimmed = line.trim_start();
        if let Some(value) = trimmed.strip_prefix("interface:") {
            interface = value.split_whitespace().next();
        }
        if let Some(value) = trimmed.strip_prefix("gateway:") {
            gateway = value.split_whitespace().next().unwrap_or("");
        }
    }
    interface
        .map(|v| format!("{v} gateway={gateway}"))
        .unwrap_or_else(|| "unavailable".into())
}

fn timezone<R: ReadRunner>(runner: &R) -> String {
    let Some(value) = command_text(runner, ReadCommand::ReadlinkLocaltime) else {
        return "unavailable".into();
    };
    value
        .trim_end_matches(['\r', '\n'])
        .rsplit("zoneinfo/")
        .next()
        .filter(|v| !v.is_empty())
        .unwrap_or("unavailable")
        .to_owned()
}

fn selected_dns(text: &str) -> String {
    let mut values = text
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.len() >= 3 && fields[0].starts_with("nameserver[") && fields[0].ends_with(']'))
                .then(|| fields[2].to_owned())
        })
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    if values.is_empty() {
        "unavailable".into()
    } else {
        values.join(",")
    }
}

fn dns_signature(text: &str) -> String {
    let lines = text
        .lines()
        .filter(|line| {
            ["resolver #", "domain", "nameserver[", "if_index", "flags"]
                .iter()
                .any(|needle| line.contains(needle))
        })
        .collect::<Vec<_>>();
    let selected = if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    };
    sha256(selected.as_bytes())
}

fn safe_proxy_value(value: &str) -> String {
    let value = value.rsplit('@').next().unwrap_or("");
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '_' | '-'))
        .collect()
}

fn system_proxy_display(text: &str) -> String {
    let names = [
        "HTTPEnable",
        "HTTPSEnable",
        "SOCKSEnable",
        "HTTPProxy",
        "HTTPSProxy",
        "SOCKSProxy",
        "HTTPPort",
        "HTTPSPort",
        "SOCKSPort",
        "ProxyAutoConfigEnable",
    ];
    let values = text
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.len() >= 3 && names.contains(&fields[0]))
                .then(|| format!("{}={}", fields[0], safe_proxy_value(fields[2])))
        })
        .collect::<Vec<_>>();
    if values.is_empty() {
        "unavailable".into()
    } else {
        values.join(",")
    }
}

fn redact_proxy(proxy: &str) -> String {
    if proxy.is_empty() {
        return "none".into();
    }
    let Some((scheme, rest)) = proxy.split_once("://") else {
        return "[configured; unrecognized format]".into();
    };
    if !matches!(
        scheme,
        "http" | "https" | "socks" | "socks4" | "socks5" | "socks5h"
    ) {
        return "[configured; unrecognized format]".into();
    }
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    let sanitized: String = authority
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '[' | ']' | '/' | '_' | '%' | '-')
        })
        .collect();
    format!("{scheme}://{sanitized}")
}

fn settings_values<R: ReadRunner>(runner: &R, input: &EnvironmentInput) -> String {
    let mut values = String::new();
    for managed in [false, true] {
        let exists = command_output(
            runner,
            ReadCommand::ClaudeSettingsExists {
                home: input.home.clone(),
                managed,
            },
        )
        .is_some_and(|(status, _, _)| status == 0);
        if !exists {
            continue;
        }
        let Some((status, text, _)) = command_output(
            runner,
            ReadCommand::ClaudeSettings {
                home: input.home.clone(),
                managed,
            },
        ) else {
            values.push_str("invalid-json\n");
            continue;
        };
        let Ok(value) = (status == 0)
            .then_some(text)
            .ok_or(())
            .and_then(|text| serde_json::from_str::<Value>(&text).map_err(|_| ()))
        else {
            values.push_str("invalid-json\n");
            continue;
        };
        let name = if managed {
            "managed-settings.json"
        } else {
            "settings.json"
        };
        for key in PROXY_KEYS {
            if let Some(value) = value
                .pointer(&format!("/env/{key}"))
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
            {
                values.push_str(&format!("{name}:{key}={value}\n"));
            }
        }
    }
    values
}

/// Port of `claude-watch.sh`'s local collector.  A command failure is an
/// unavailable fact; it is never converted to an absent route or disabled
/// proxy.
pub fn collect<R: ReadRunner>(runner: &R, input: &EnvironmentInput) -> EnvironmentFacts {
    let timezone = timezone(runner);
    let ipv4_route = route(runner, false);
    let ipv6_route = route(runner, true);
    let dns_text = command_text(runner, ReadCommand::ScutilDns).unwrap_or_default();
    let proxy_text = command_text(runner, ReadCommand::ScutilProxy).unwrap_or_default();
    let dns = selected_dns(&dns_text);
    let dns_sig = dns_signature(&dns_text);
    let sys_proxy_sig = sha256(proxy_text.as_bytes());
    let sys_proxy = system_proxy_display(&proxy_text);
    let cli_proxy_raw = ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"]
        .iter()
        .find_map(|key| input.environment.get(*key))
        .map(String::as_str)
        .unwrap_or("");
    let cli_proxy = redact_proxy(cli_proxy_raw);
    let mut signature = Vec::new();
    for key in CLI_PROXY_KEYS {
        signature.extend_from_slice(
            input
                .environment
                .get(key)
                .map(String::as_bytes)
                .unwrap_or_default(),
        );
        signature.push(0);
    }
    let cli_proxy_sig = sha256(&signature);
    let settings = settings_values(runner, input);
    let settings_proxy_sig = sha256(settings.as_bytes());
    let settings_proxy = if settings.is_empty() {
        "none".into()
    } else if settings.contains("invalid-json") {
        "unreadable-json".into()
    } else {
        "configured; effective per-session proxy must be verified".into()
    };
    let fingerprint = sha256(
        format!("{timezone}\n{ipv4_route}\n{ipv6_route}\n{dns_sig}\n{sys_proxy_sig}\n").as_bytes(),
    );
    EnvironmentFacts {
        timezone,
        ipv4_route,
        ipv6_route,
        dns,
        dns_sig,
        sys_proxy,
        sys_proxy_sig,
        cli_proxy,
        cli_proxy_sig,
        settings_proxy,
        settings_proxy_sig,
        fingerprint,
    }
}

pub fn capture<R: ReadRunner>(runner: &R, input: &EnvironmentInput) -> Result<EnvironmentCapture> {
    let measured = collect(runner, input);
    if [
        &measured.ipv4_route,
        &measured.ipv6_route,
        &measured.dns,
        &measured.sys_proxy,
        &measured.timezone,
    ]
    .iter()
    .any(|value| value.as_str() == "unavailable")
    {
        return Err(CoreError::new(
            "baseline_incomplete",
            "环境读取不完整，未生成基线。",
        ));
    }
    if measured.ipv4_route == "absent" && measured.ipv6_route == "absent" {
        return Err(CoreError::new(
            "baseline_incomplete",
            "没有默认路由，未生成基线。",
        ));
    }
    let created = command_text(runner, ReadCommand::Iso8601Date)
        .map(|v| v.trim_end_matches(['\r', '\n']).to_owned())
        .filter(|v| !v.is_empty() && !v.contains(['\r', '\n']))
        .ok_or_else(|| CoreError::new("baseline_incomplete", "本机时间读取失败，未生成基线。"))?;
    let values = [
        ("timezone", &measured.timezone),
        ("ipv4_route", &measured.ipv4_route),
        ("ipv6_route", &measured.ipv6_route),
        ("dns", &measured.dns),
        ("dns_sig", &measured.dns_sig),
        ("sys_proxy_sig", &measured.sys_proxy_sig),
        ("cli_proxy_sig", &measured.cli_proxy_sig),
        ("settings_proxy_sig", &measured.settings_proxy_sig),
    ];
    if values.iter().any(|(_, value)| value.contains(['\r', '\n'])) {
        return Err(CoreError::new(
            "baseline_incomplete",
            "环境读取包含无效换行，未生成基线。",
        ));
    }
    let mut data = format!("format=2\ncreated={created}\nonline=no\n");
    for (key, value) in values {
        data.push_str(&format!("{key}={value}\n"));
    }
    Ok(EnvironmentCapture { data, measured })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::Output;
    use std::sync::Mutex;

    struct Fixture {
        route6_absent: bool,
        settings_invalid: bool,
        calls: Mutex<Vec<String>>,
    }
    fn output(text: &str) -> Result<Output> {
        Ok(Output {
            status: 0,
            stdout: text.as_bytes().to_vec(),
            stderr: vec![],
        })
    }
    impl ReadRunner for Fixture {
        fn run(&self, command: ReadCommand, _: &[u8], _: Duration, _: usize) -> Result<Output> {
            let name = match &command {
                ReadCommand::RouteDefaultV4 => "route4",
                ReadCommand::RouteDefaultV6 => "route6",
                ReadCommand::ReadlinkLocaltime => "timezone",
                ReadCommand::Iso8601Date => "date",
                ReadCommand::ScutilDns => "dns",
                ReadCommand::ScutilProxy => "proxy",
                ReadCommand::ClaudeSettingsExists { managed, .. } => {
                    if *managed {
                        "managed-exists"
                    } else {
                        "user-exists"
                    }
                }
                ReadCommand::ClaudeSettings { managed, .. } => {
                    if *managed {
                        "managed-settings"
                    } else {
                        "user-settings"
                    }
                }
                _ => panic!("unexpected command"),
            };
            self.calls.lock().unwrap().push(name.into());
            match command {
                ReadCommand::RouteDefaultV4 => output("    gateway: 192.0.2.1\n  interface: en0\n"),
                ReadCommand::RouteDefaultV6 if self.route6_absent => Ok(Output { status: 0, stdout: b"route: writing to routing socket: not in table\n".to_vec(), stderr: vec![] }),
                ReadCommand::RouteDefaultV6 => output("    gateway: fe80::1%en0\n  interface: en0\n"),
                ReadCommand::ReadlinkLocaltime => output("/var/db/timezone/zoneinfo/Asia/Tokyo\n"),
                ReadCommand::Iso8601Date => output("2026-10-27T12:34:56+0900\n"),
                ReadCommand::ScutilDns => output("resolver #1\n  nameserver[0] : 1.1.1.1\n  nameserver[1] : 8.8.8.8\n  flags    : Request A records\n"),
                ReadCommand::ScutilProxy => output("<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : user:secret@proxy.example:8080\n  ProxyAutoConfigEnable : 0\n}\n"),
                ReadCommand::ClaudeSettingsExists { managed: false, .. } => Ok(Output { status: 0, stdout: vec![], stderr: vec![] }),
                ReadCommand::ClaudeSettingsExists { managed: true, .. } => Ok(Output { status: 1, stdout: vec![], stderr: vec![] }),
                ReadCommand::ClaudeSettings { managed: false, .. } if self.settings_invalid => output("not json"),
                ReadCommand::ClaudeSettings { managed: false, .. } => output(r#"{"env":{"https_proxy":"https://name:password@settings.example:443/path","NO_PROXY":"private.internal"}}"#),
                _ => unreachable!(),
            }
        }
    }
    fn input() -> EnvironmentInput {
        EnvironmentInput {
            home: PathBuf::from("/fixture/home"),
            environment: BTreeMap::from([
                (
                    "HTTPS_PROXY".into(),
                    "https://cli:token@terminal.example:8443/a?token=x".into(),
                ),
                ("NO_PROXY".into(), "localhost,private.internal".into()),
            ]),
        }
    }

    #[test]
    fn collector_preserves_legacy_hash_inputs_and_redacts_displays() {
        let fixture = Fixture {
            route6_absent: true,
            settings_invalid: false,
            calls: Mutex::new(vec![]),
        };
        let facts = collect(&fixture, &input());
        assert_eq!(facts.timezone, "Asia/Tokyo");
        assert_eq!(facts.ipv4_route, "en0 gateway=192.0.2.1");
        assert_eq!(facts.ipv6_route, "absent");
        assert_eq!(facts.dns, "1.1.1.1,8.8.8.8");
        assert_eq!(
            facts.sys_proxy,
            "HTTPEnable=1,HTTPProxy=proxy.example:8080,ProxyAutoConfigEnable=0"
        );
        assert_eq!(facts.cli_proxy, "https://terminal.example:8443");
        assert!(!facts.sys_proxy.contains("secret") && !facts.cli_proxy.contains("token"));
        assert_eq!(
            facts.settings_proxy,
            "configured; effective per-session proxy must be verified"
        );
        let expected_settings = "settings.json:https_proxy=https://name:password@settings.example:443/path\nsettings.json:NO_PROXY=private.internal\n";
        assert_eq!(
            facts.settings_proxy_sig,
            sha256(expected_settings.as_bytes())
        );
        let expected_cli = b"\0https://cli:token@terminal.example:8443/a?token=x\0\0\0localhost,private.internal\0\0\0\0";
        assert_eq!(facts.cli_proxy_sig, sha256(expected_cli));
    }

    #[test]
    fn onboarding_environment_capture_is_complete_and_readonly() {
        let fixture = Fixture {
            route6_absent: true,
            settings_invalid: false,
            calls: Mutex::new(vec![]),
        };
        let baseline = capture(&fixture, &input()).unwrap();
        assert!(baseline
            .data
            .starts_with("format=2\ncreated=2026-10-27T12:34:56+0900\nonline=no\n"));
        assert!(baseline.data.contains("settings_proxy_sig="));
        assert!(baseline.data.ends_with('\n'));
        assert!(baseline.data.contains("ipv6_route=absent\n"));
        assert_eq!(baseline.measured.timezone, "Asia/Tokyo");
    }

    #[test]
    fn invalid_settings_stays_unknown_rather_than_disabled() {
        let fixture = Fixture {
            route6_absent: false,
            settings_invalid: true,
            calls: Mutex::new(vec![]),
        };
        let facts = collect(&fixture, &input());
        assert_eq!(facts.settings_proxy, "unreadable-json");
        assert_eq!(facts.settings_proxy_sig, sha256(b"invalid-json\n"));
    }
}
