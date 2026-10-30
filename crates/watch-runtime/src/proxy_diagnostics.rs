//! Read-only, proxy-only transport diagnostics.
//!
//! This module deliberately has no dependency on account state, configuration
//! stores, launch policy, or mutable runtime state.  The sole OS boundary is a
//! fixed `/usr/bin/curl` invocation; proxy credentials are supplied on stdin.
use claude_watch_core::error::{CoreError, Result};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    net::IpAddr,
    path::Path,
    time::{Duration, Instant},
};
use subprocess::{Exec, Job, Redirection};
use url::Url;

pub const MAX_CONFIG: usize = 64 * 1024;
const MAX_PROXY: usize = 16 * 1024;
const TARGETS: [(&str, &str); 2] = [
    ("anthropic_api", "https://api.anthropic.com/v1/models"),
    ("claude_web", "https://claude.ai/"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxySource {
    Argument(String),
    ConfigFile(String),
    StdinConfig(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurlOutput {
    pub status: i32,
    pub stdout: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurlFailure {
    Timeout,
    Unavailable,
    Io,
}

/// Injectable boundary for tests. Implementations receive only fixed targets
/// and fixed curl options; the proxy URL is passed as curl config stdin.
pub trait CurlExecutor: Sync {
    fn execute(
        &self,
        args: &[String],
        config_stdin: &str,
        environment: &BTreeMap<String, String>,
    ) -> std::result::Result<CurlOutput, CurlFailure>;
}

pub struct SystemCurl;

/// Never leave a diagnostic child in an unbounded wait path.  A failed kill or
/// delayed exit is detached only after the bounded reap attempt.
fn stop_curl_child(job: &mut Job) {
    let _ = job.kill();
    let _ = job.wait_timeout(Duration::from_millis(500));
    job.detach();
}

impl CurlExecutor for SystemCurl {
    fn execute(
        &self,
        args: &[String],
        config_stdin: &str,
        environment: &BTreeMap<String, String>,
    ) -> std::result::Result<CurlOutput, CurlFailure> {
        let started = Instant::now();
        let mut command = Exec::cmd("/usr/bin/curl");
        command = command
            .args(args)
            .env_clear()
            .env_extend(environment.iter())
            .stdin(config_stdin.as_bytes().to_vec())
            .stdout(Redirection::Pipe)
            .stderr(Redirection::Pipe);
        let mut job = command.start().map_err(|_| CurlFailure::Unavailable)?;
        const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
        const OUTPUT_LIMIT: usize = 8 * 1024;
        let communication = match job.communicate() {
            Ok(value) => value,
            Err(_) => {
                stop_curl_child(&mut job);
                return Err(CurlFailure::Io);
            }
        };
        let (stdout, stderr) = match communication
            .limit_time(
                TOTAL_TIMEOUT
                    .saturating_sub(started.elapsed())
                    .max(Duration::from_millis(1)),
            )
            .limit_size(OUTPUT_LIMIT + 1)
            .read()
        {
            Ok(value) => value,
            Err(error) => {
                stop_curl_child(&mut job);
                return Err(if error.kind() == std::io::ErrorKind::TimedOut {
                    CurlFailure::Timeout
                } else {
                    CurlFailure::Io
                });
            }
        };
        if stdout.len() + stderr.len() > OUTPUT_LIMIT {
            stop_curl_child(&mut job);
            return Err(CurlFailure::Io);
        }
        let remaining = TOTAL_TIMEOUT.saturating_sub(started.elapsed());
        let status = if remaining.is_zero() {
            None
        } else {
            match job.wait_timeout(remaining) {
                Ok(value) => value,
                Err(_) => {
                    stop_curl_child(&mut job);
                    return Err(CurlFailure::Io);
                }
            }
        };
        let Some(status) = status else {
            stop_curl_child(&mut job);
            return Err(CurlFailure::Timeout);
        };
        Ok(CurlOutput {
            status: status.code().map(|value| value as i32).unwrap_or(1),
            stdout: String::from_utf8(stdout).map_err(|_| CurlFailure::Io)?,
        })
    }
}

fn configuration_error() -> CoreError {
    CoreError::new("invalid_or_missing_proxy", "代理配置无效或缺失")
}

fn read_limited(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|_| configuration_error())?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| configuration_error())?;
    if bytes.len() > MAX_CONFIG {
        return Err(configuration_error());
    }
    Ok(bytes)
}

fn config_proxy(bytes: &[u8]) -> Result<String> {
    if bytes.len() > MAX_CONFIG {
        return Err(configuration_error());
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| configuration_error())?;
    value
        .as_object()
        .and_then(|object| object.get("proxy_url"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(configuration_error)
}

fn selected(source: ProxySource) -> Result<(String, &'static str)> {
    match source {
        ProxySource::Argument(value) => Ok((value, "argument")),
        ProxySource::ConfigFile(path) => {
            Ok((config_proxy(&read_limited(Path::new(&path))?)?, "config"))
        }
        ProxySource::StdinConfig(bytes) => Ok((config_proxy(&bytes)?, "stdin")),
    }
}

fn public_proxy(value: String, source: &'static str) -> Result<(String, Value)> {
    if value.len() > MAX_PROXY
        || value.trim().is_empty()
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(configuration_error());
    }
    let value = value.trim().to_owned();
    let url = Url::parse(&value).map_err(|_| configuration_error())?;
    // `Url` normalizes an explicitly supplied default port away.  Preserve the
    // command contract's explicit-port requirement from the original spelling.
    let authority = value
        .split_once("://")
        .map(|(_, rest)| {
            rest.split('/')
                .next()
                .unwrap_or(rest)
                .rsplit('@')
                .next()
                .unwrap_or(rest)
        })
        .ok_or_else(configuration_error)?;
    let explicit_port = authority
        .rsplit_once(':')
        .and_then(|(_, port)| (!port.is_empty()).then_some(port))
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .ok_or_else(configuration_error)?;
    if !matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h")
        || url.host().is_none()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(configuration_error());
    }
    let port = explicit_port;
    let loopback = url.host_str().is_some_and(|host| {
        let host = host.trim_matches(['[', ']']);
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    Ok((
        value,
        json!({"scheme":url.scheme(),"port":port,"host_scope":if loopback{"loopback"}else{"remote"},"authentication_configured":!url.username().is_empty(),"source":source}),
    ))
}

fn curl_args(target: &str) -> Vec<String> {
    [
        "--disable",
        "--config",
        "-",
        "--silent",
        "--show-error",
        "--output",
        "/dev/null",
        "--proto",
        "=https",
        "--noproxy",
        "",
        "--connect-timeout",
        "6",
        "--max-time",
        "12",
        "--write-out",
        "%{http_code}\t%{http_connect}\t%{ssl_verify_result}\t%{time_appconnect}\t%{time_total}",
        target,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn clean_environment(environ: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    [
        "PATH",
        "HOME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "CURL_CA_BUNDLE",
    ]
    .into_iter()
    .filter_map(|key| {
        environ
            .get(key)
            .map(|value| (key.to_owned(), value.clone()))
    })
    .collect()
}

fn probe(
    name: &str,
    target: &str,
    proxy: &str,
    environment: &BTreeMap<String, String>,
    executor: &dyn CurlExecutor,
) -> Value {
    let mut result = json!({"name":name,"url":target,"transport_reached":false,"access":"unknown"});
    let config = format!(
        "proxy = {}\n",
        serde_json::to_string(proxy).expect("string encodes")
    );
    match executor.execute(&curl_args(target), &config, &clean_environment(environment)) {
        Err(CurlFailure::Timeout) => result["error"] = json!("probe_timeout"),
        Err(CurlFailure::Unavailable) => result["error"] = json!("curl_unavailable"),
        Err(CurlFailure::Io) => result["error"] = json!("invalid_probe_output"),
        Ok(output) => {
            let fields: Vec<&str> = output.stdout.split_whitespace().collect();
            let parsed = (|| {
                if fields.len() != 5 {
                    return None;
                }
                let status = fields[0].parse::<u16>().ok()?;
                let connect = fields[1].parse::<u16>().ok()?;
                let verify = fields[2].parse::<i32>().ok()?;
                let tls = fields[3].parse::<f64>().ok()?;
                let elapsed = fields[4].parse::<f64>().ok()?;
                if status > 599
                    || connect > 599
                    || verify < 0
                    || !tls.is_finite()
                    || !elapsed.is_finite()
                    || tls < 0.0
                    || elapsed < 0.0
                {
                    return None;
                }
                Some((status, connect, verify, tls, elapsed))
            })();
            if let Some((status, connect, verify, tls, elapsed)) = parsed {
                let reached = output.status == 0 && status >= 100 && verify == 0 && tls > 0.0;
                let access = if status == 401 {
                    "unauthenticated"
                } else if matches!(status, 403 | 407) {
                    "access_restricted"
                } else if status >= 500 {
                    "server_error"
                } else {
                    "http_response"
                };
                result = json!({"name":name,"url":target,"transport_reached":reached,"access":if reached {access} else {"unknown"},"curl_exit":output.status,"http_status":status,"proxy_connect_status":connect,"tls_verified":reached,"elapsed_seconds":elapsed});
            } else {
                result["error"] = json!("invalid_probe_output");
            }
        }
    }
    result
}

/// Produces the stable receipt and its CLI exit code (0, 1, or 2).
pub fn diagnose(
    source: ProxySource,
    environment: &BTreeMap<String, String>,
    executor: &dyn CurlExecutor,
) -> (Value, i32) {
    let mut report = json!({"schema_version":1,"mode":"proxy_diagnostics","scope":"unauthenticated_transport_only","account_status":"not_evaluated","leak_protection":"not_evaluated","launch_allowed":Value::Null,"application_started":false,"system_modified":false,"checks":[]});
    let Ok((raw, source)) =
        selected(source).and_then(|(value, source)| public_proxy(value, source))
    else {
        report["status"] = json!("error");
        report["state"] = json!("configuration_error");
        report["error"] = json!("invalid_or_missing_proxy");
        report["message"] = json!("请明确提供带端口的 HTTP/HTTPS/SOCKS5/SOCKS5H 代理；认证信息可通过私有 JSON 或标准输入提供。");
        return (report, 2);
    };
    let (first, second) = std::thread::scope(|scope| {
        let a = scope.spawn(|| probe(TARGETS[0].0, TARGETS[0].1, &raw, environment, executor));
        let b = scope.spawn(|| probe(TARGETS[1].0, TARGETS[1].1, &raw, environment, executor));
        (
            a.join().expect("probe thread"),
            b.join().expect("probe thread"),
        )
    });
    let checks = vec![first, second];
    let reached = checks
        .iter()
        .all(|check| check["transport_reached"] == true);
    report["status"] = json!(if reached { "ok" } else { "partial" });
    report["proxy"] = source;
    report["checks"] = json!(checks);
    report["state"] = json!(if reached {
        "transport_reached"
    } else {
        "transport_failed"
    });
    report["message"] = json!(if reached {
        "两个目标均收到 TLS 验证后的 HTTP 响应；认证与访问限制见逐项结果。"
    } else {
        "部分传输未完成；失败或未知项没有被视为通过。"
    });
    (report, if reached { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        output: std::result::Result<CurlOutput, CurlFailure>,
    }
    impl CurlExecutor for Fake {
        fn execute(
            &self,
            args: &[String],
            stdin: &str,
            environment: &BTreeMap<String, String>,
        ) -> std::result::Result<CurlOutput, CurlFailure> {
            assert_eq!(args[0], "--disable");
            assert!(args.iter().any(|v| v == "--noproxy"));
            assert!(stdin.starts_with("proxy = \""));
            assert!(!environment.contains_key("HTTPS_PROXY"));
            self.output.clone()
        }
    }
    fn environment() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("PATH".into(), "/usr/bin".into()),
            ("HTTPS_PROXY".into(), "secret".into()),
        ])
    }
    fn success() -> Fake {
        Fake {
            output: Ok(CurlOutput {
                status: 0,
                stdout: "200 200 0 0.1 0.2".into(),
            }),
        }
    }
    #[test]
    fn explicit_credentials_are_redacted_and_fixed_targets_are_used() {
        let (report, code) = diagnose(
            ProxySource::Argument("socks5h://alice:secret@127.0.0.1:1080".into()),
            &environment(),
            &success(),
        );
        assert_eq!(code, 0);
        assert_eq!(report["proxy"]["host_scope"], "loopback");
        assert_eq!(report["proxy"]["authentication_configured"], true);
        assert!(!report.to_string().contains("secret"));
        assert_eq!(report["checks"][0]["url"], TARGETS[0].1);
    }
    #[test]
    fn stdin_config_is_accepted_but_conflicting_or_bad_proxy_is_not() {
        let (report, code) = diagnose(
            ProxySource::StdinConfig(br#"{"proxy_url":"https://proxy.example:443"}"#.to_vec()),
            &environment(),
            &success(),
        );
        assert_eq!(code, 0);
        assert_eq!(report["proxy"]["source"], "stdin");
        let (report, code) = diagnose(
            ProxySource::Argument("http://example.test/nope".into()),
            &environment(),
            &success(),
        );
        assert_eq!(code, 2);
        assert_eq!(report["error"], "invalid_or_missing_proxy");
    }
    #[test]
    fn private_config_file_is_read_bounded_and_its_path_is_not_reported() {
        let path =
            std::env::temp_dir().join(format!("proxy-diagnostic-{}.json", std::process::id()));
        std::fs::write(&path, br#"{"proxy_url":"http://[::1]:7890"}"#).unwrap();
        let (report, code) = diagnose(
            ProxySource::ConfigFile(path.display().to_string()),
            &environment(),
            &success(),
        );
        let _ = std::fs::remove_file(&path);
        assert_eq!(code, 0);
        assert_eq!(report["proxy"]["source"], "config");
        assert_eq!(report["proxy"]["host_scope"], "loopback");
        assert!(!report.to_string().contains(&path.display().to_string()));
    }
    #[test]
    fn tls_failure_is_partial_and_never_claims_reachability() {
        let fake = Fake {
            output: Ok(CurlOutput {
                status: 0,
                stdout: "403 200 60 0.1 0.2".into(),
            }),
        };
        let (report, code) = diagnose(
            ProxySource::Argument("http://localhost:7890".into()),
            &environment(),
            &fake,
        );
        assert_eq!(code, 1);
        assert_eq!(report["status"], "partial");
        assert_eq!(report["checks"][0]["transport_reached"], false);
    }
}
