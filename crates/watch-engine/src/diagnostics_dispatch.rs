//! Dispatch for standalone proxy diagnostics, before account/config runtime setup.
use claude_watch_core::{
    cli::Request,
    error::{CoreError, Result},
};
use claude_watch_runtime::proxy_diagnostics::{self, ProxySource, SystemCurl};
use serde_json::Value;
use std::collections::BTreeMap;

/// `stdin` must already be bounded by the executable at 64 KiB + one byte.
/// Parser-enforced mutual exclusion guarantees a diagnostic source is selected.
pub fn dispatch(request: &Request, stdin: Option<Vec<u8>>) -> Result<Option<(Value, i32)>> {
    if request.command != "diagnose-proxy" {
        return Ok(None);
    }
    let source = match (
        request.value("proxy"),
        request.value("config"),
        request.flag("stdin-config"),
    ) {
        (Some(value), None, false) => ProxySource::Argument(value.to_owned()),
        (None, Some(path), false) => ProxySource::ConfigFile(path.to_owned()),
        (None, None, true) => ProxySource::StdinConfig(
            stdin.ok_or_else(|| CoreError::new("input_unavailable", "代理配置输入不可读取"))?,
        ),
        _ => return Err(CoreError::new("invalid_arguments", "代理诊断参数无效")),
    };
    let environment = std::env::vars().collect::<BTreeMap<_, _>>();
    let (receipt, code) = proxy_diagnostics::diagnose(source, &environment, &SystemCurl);
    Ok(Some((receipt, code)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn non_diagnostic_requests_are_not_claimed() {
        let request = Request::parse(&["status".into()]).unwrap();
        assert!(dispatch(&request, None).unwrap().is_none());
    }
    #[test]
    fn parser_rejects_conflicting_diagnostic_sources() {
        assert!(Request::parse(&[
            "diagnose-proxy".into(),
            "--proxy".into(),
            "http://localhost:1".into(),
            "--stdin-config".into()
        ])
        .is_err());
    }
}
