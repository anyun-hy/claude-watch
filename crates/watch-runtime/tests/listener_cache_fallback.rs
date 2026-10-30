//! A published listener frame is a hardened path, not the only source.
//!
//! The daemon owns the live collector stream; an engine spawned by the UI reads
//! the published cache instead. When that cache is stale, rejected or reported
//! unavailable, the engine must still be able to read the plain netstat table --
//! otherwise every UI refresh reports "listener identity unconfirmed" while the
//! daemon itself is healthy.
use claude_watch_runtime::{
    commands::{ReadCommand, ReadRunner, SystemRunner},
    native,
    storage::{Paths, StateStore},
};
use serde_json::json;
use std::{fs, path::PathBuf, time::Duration};

struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("cw-fallback-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn identity(pid: u32) -> serde_json::Value {
    json!({
        "pid": pid,
        "parent": 1,
        "uid": 501,
        "executable": "/bin/zsh",
        "start_seconds": 1,
        "start_microseconds": 1,
        "start_stamp": "Mon Oct 26 01:02:03 2026"
    })
}

fn observer() -> PathBuf {
    native::built_observer_path()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/bin/true"))
}

#[test]
fn stale_published_frame_falls_through_to_netstat() {
    let home = Home::new();
    let paths = Paths::new(&home.0).unwrap();
    let store = StateStore::new(paths.clone());
    let state = paths.watch().join("state");
    fs::create_dir_all(&state).unwrap();
    // Exactly what a client without a live stream sees a few seconds after the
    // daemon published a frame and then judged that same frame stale.
    fs::write(
        state.join("native-listener.json"),
        json!({
            "schema": 2,
            "published_at": native::now(),
            "actor": {
                "root": paths.watch().join("runtime"),
                "supervisor": identity(1),
                "worker": identity(1)
            },
            "listener": null,
            "error": {
                "code": "native_listener_stale",
                "message": "系统监听采样已过期或来源不匹配"
            }
        })
        .to_string(),
    )
    .unwrap();

    let runner = SystemRunner::new(&observer())
        .unwrap()
        .with_listener_cache(store);
    let out = runner
        .run(
            ReadCommand::Listeners,
            &[],
            Duration::from_secs(3),
            4 * 1024 * 1024,
        )
        .expect("a stale published frame must not remove the netstat path");
    // Whether netstat itself can see listener owners depends on the signing
    // identity of the caller, so only the routing is asserted here: the cache
    // failure must not surface as the command result.
    assert_eq!(out.status, 0);
    assert!(
        out.stderr.is_empty(),
        "netstat stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn an_unreadable_published_frame_also_falls_through() {
    let home = Home::new();
    let paths = Paths::new(&home.0).unwrap();
    let store = StateStore::new(paths.clone());
    let state = paths.watch().join("state");
    fs::create_dir_all(&state).unwrap();
    // A truncated or foreign-schema cache must not be fatal either.
    fs::write(state.join("native-listener.json"), b"{\"schema\":2,").unwrap();

    let runner = SystemRunner::new(&observer())
        .unwrap()
        .with_listener_cache(store);
    let out = runner
        .run(
            ReadCommand::Listeners,
            &[],
            Duration::from_secs(3),
            4 * 1024 * 1024,
        )
        .expect("an unreadable cache must not remove the netstat path");
    assert_eq!(out.status, 0);
}
