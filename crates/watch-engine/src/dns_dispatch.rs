//! GUI-compatible native DNS receipt command.
use claude_watch_core::{
    cli::Request,
    error::{CoreError, Result},
};
use claude_watch_runtime::{
    commands::ReadRunner,
    dns_probe,
    network_client::{NetworkClient, Transport},
};
use serde_json::Value;

/// The parser accepts only `dns-probe`; there are no caller-selected programs,
/// hostnames or endpoints on this native collector path.
pub fn dispatch<R: ReadRunner, T: Transport>(
    request: &Request,
    runner: &R,
    network: &NetworkClient<T>,
) -> Result<Option<Value>> {
    if request.command != "dns-probe" {
        return Ok(None);
    }
    if request.action.is_some()
        || request.target.is_some()
        || !request.flags.is_empty()
        || !request.values.is_empty()
    {
        return Err(CoreError::new(
            "invalid_arguments",
            "DNS 检测不接受附加参数",
        ));
    }
    Ok(Some(dns_probe::collect(runner, network)))
}
