//! The extension writes root-owned observations into the explicitly configured
//! user's private state directory. Commands go the other way. No HOME guessing.
use crate::storage::{strict_json, StateStore};
use claude_watch_core::error::{CoreError, Result};
use serde::de::DeserializeOwned;
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
};

pub fn read_observation<T: DeserializeOwned>(store: &StateStore, name: &str) -> Result<T> {
    if !matches!(
        name,
        "system-extension-heartbeat.json" | "system-extension-receipt.json"
    ) {
        return Err(CoreError::new(
            "invalid_extension_observation",
            "扩展回执名称无效",
        ));
    }
    let path = store.guarded(&store.paths.watch().join("state").join(name))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| CoreError::new("extension_observation_unavailable", "系统扩展回执不可读取"))?;
    let meta = file
        .metadata()
        .map_err(|_| CoreError::new("extension_observation_unavailable", "回执身份不可读取"))?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.nlink() != 1 {
        return Err(CoreError::new(
            "untrusted_extension_observation",
            "拒绝非系统扩展身份写入的回执",
        ));
    }
    let mut bytes = Vec::new();
    file.take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| CoreError::new("extension_observation_unavailable", "回执读取失败"))?;
    if bytes.len() > 65536 {
        return Err(CoreError::new(
            "extension_observation_oversize",
            "扩展回执过大",
        ));
    }
    serde_json::from_value(strict_json(&bytes)?)
        .map_err(|_| CoreError::new("invalid_extension_observation", "扩展回执契约不匹配"))
}

pub use claude_watch_system::{is_authenticated_extension, ObservationSignal};

/// Echoed by the authenticated executor: binds the full session, original
/// process identities, policy and permission, not just a reusable list of PIDs.
pub fn command_binding(command: &claude_watch_core::channel::ChannelEnforcementCommand) -> Option<String> {
    use sha2::{Digest, Sha256};
    // Local diagnostic reasons may change without a new authority command.
    // They are not a permission; bind every authorization-relevant field.
    let value = serde_json::json!({
        "family": command.family, "session_id": command.session_id,
        "policy_version": command.policy_version, "command_seq": command.command_seq,
        "permit_generation": command.permit_generation, "issued_at": command.issued_at,
        "valid_until": command.permit.valid_until, "permit_state": command.permit.state,
        "context_id": command.permit.context_id, "upstream_endpoint": command.upstream_endpoint,
        "allowed_processes": command.allowed_processes,
    });
    Some(Sha256::digest(serde_json::to_vec(&value).ok()?).iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn extension_peer_rejects_an_ordinary_user_even_with_a_valid_socket() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(!super::is_authenticated_extension(&a));
    }
}
