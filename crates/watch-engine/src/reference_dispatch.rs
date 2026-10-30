//! Read-only server-reference command adapter.
use claude_watch_core::{
    cli::Request,
    error::{CoreError, Result},
};
use claude_watch_runtime::{
    network_client::UreqTransport,
    server_reference::{LookupRequest, ServerReferenceClient},
};
use serde_json::{to_value, Value};
use std::sync::Arc;

pub fn dispatch(request: &Request) -> Result<Option<Value>> {
    if request.command != "server-reference" {
        return Ok(None);
    }
    let host = request
        .value("host")
        .ok_or_else(|| CoreError::new("invalid_arguments", "缺少服务器域名"))?;
    let client = ServerReferenceClient::new(Arc::new(UreqTransport));
    to_value(client.lookup(LookupRequest {
        host: host.into(),
        observed_ip: request.value("ip").map(Into::into),
    }))
    .map(Some)
    .map_err(|_| CoreError::new("reference_encoding_failed", "服务器参考结果无法编码"))
}
