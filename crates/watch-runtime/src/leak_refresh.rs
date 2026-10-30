//! Bounded native WebView refresh request and receipt handoff.
//! A ready reply acknowledges collection only; audit/session still validate the actual receipt.
use crate::storage::StateStore;
use claude_watch_core::error::{CoreError, Result};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::MetadataExt,
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    NotRequested,
    AlreadyFresh,
    Refreshed,
}
pub fn refresh_for_launch(
    store: &StateStore,
    uid: u32,
    token: Option<&str>,
    timeout: Duration,
) -> Result<Outcome> {
    let Some(token) = token.filter(|s| !s.is_empty()) else {
        return Ok(Outcome::NotRequested);
    };
    if token.len() != 32
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CoreError::new("dns_refresh_invalid", "DNS更新请求标识无效"));
    }
    let directory = store.paths.base().join(format!(".dns-refresh-{token}"));
    store.guarded(&directory)?;
    let meta = fs::symlink_metadata(&directory)
        .map_err(|_| CoreError::new("dns_refresh_unavailable", "DNS检测协作通道不可用"))?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != uid
        || meta.mode() & 0o077 != 0
    {
        return Err(CoreError::new(
            "dns_refresh_unavailable",
            "DNS检测协作通道身份或权限无效",
        ));
    }
    let receipt = store
        .read_json(&store.paths.base().join("dns-leak-receipt.json"), json!({}))
        .unwrap_or(json!({}));
    if receipt["provider"] == "ipleak"
        && receipt["finished_at"]
            .as_f64()
            .is_some_and(|v| v.is_finite() && (0.0..=8.0).contains(&(crate::native::now() - v)))
    {
        return Ok(Outcome::AlreadyFresh);
    }
    let request = directory.join("request.json");
    let reply = directory.join("reply.json");
    store.guarded(&request)?;
    store.guarded(&reply)?;
    let id = Uuid::new_v4().simple().to_string();
    store.atomic_json(&request, &json!({"schema":1,"id":id}))?;
    let deadline = Instant::now() + timeout.min(Duration::from_secs(85));
    while Instant::now() < deadline {
        let response = store.read_json(&reply, json!({})).unwrap_or(json!({}));
        if response["schema"] == 1 && response["id"] == id {
            return if response["ready"] == true {
                Ok(Outcome::Refreshed)
            } else {
                Err(CoreError::new(
                    "dns_refresh_failed",
                    "DNS检测未完成或上下文变化，未放行",
                ))
            };
        }
        thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(150)),
        );
    }
    Err(CoreError::new(
        "dns_refresh_timeout",
        "等待原生DNS检测超时，未放行",
    ))
}
