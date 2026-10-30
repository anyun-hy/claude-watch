//! Read-only dispatch for the monitor's Rust-candidate AI probe.
use claude_watch_core::{
    cli::Request,
    error::{CoreError, Result},
};
use claude_watch_runtime::{
    ai_probe,
    network_client::{NetworkClient, UreqTransport},
};
use serde_json::Value;
use std::{sync::Arc, time::Duration};

/// The parser owns the public `ai-probe --service <claude|gpt>` grammar.  This
/// dispatch layer only accepts that already-bounded value and never consumes a
/// user URL, credentials, proxy setting, or mutation flag.
pub fn dispatch(request: &Request) -> Result<Option<Value>> {
    if request.command != "ai-probe" {
        return Ok(None);
    }
    let service = request
        .value("service")
        .ok_or_else(|| CoreError::new("invalid_arguments", "AI 诊断需要 --service"))?;
    if !matches!(service, "claude" | "gpt") {
        return Err(CoreError::new("invalid_arguments", "AI 诊断服务无效"));
    }
    let client = NetworkClient::new(Arc::new(UreqTransport), Some(ai_probe::PROXY.into()))
        .map_err(|error| CoreError::new(&error.code, &error.detail))?
        .with_timeout(Duration::from_secs(6));
    Ok(Some(ai_probe::production(client, service)))
}
