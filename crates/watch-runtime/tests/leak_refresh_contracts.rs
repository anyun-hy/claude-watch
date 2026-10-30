use claude_watch_runtime::{
    leak_refresh::{self, Outcome},
    native,
    storage::{Paths, StateStore},
};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    process::Command,
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;
struct Fixture {
    home: PathBuf,
    store: StateStore,
    token: String,
}
impl Fixture {
    fn new() -> Self {
        let home = std::env::temp_dir().join(format!("cw-leak-refresh-{}", Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        let store = StateStore::new(Paths::new(&home).unwrap());
        let token = Uuid::new_v4().simple().to_string();
        store
            .private_dir(&store.paths.base().join(format!(".dns-refresh-{token}")))
            .unwrap();
        Self { home, store, token }
    }
    fn uid(&self) -> u32 {
        fs::metadata(&self.home).unwrap().uid()
    }
    fn dir(&self) -> PathBuf {
        self.store
            .paths
            .base()
            .join(format!(".dns-refresh-{}", self.token))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}
#[test]
fn responder_child() {
    let Some(home) = std::env::var_os("CW_REFRESH_TEST_HOME") else {
        return;
    };
    let token = std::env::var("CW_REFRESH_TEST_TOKEN").unwrap();
    let store = StateStore::new(Paths::new(PathBuf::from(home)).unwrap());
    let dir = store.paths.base().join(format!(".dns-refresh-{token}"));
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let request = store
            .read_json(&dir.join("request.json"), json!({}))
            .unwrap();
        if request["schema"] == 1 && request["id"].is_string() {
            store
                .atomic_json(
                    &dir.join("reply.json"),
                    &json!({"schema":1,"id":request["id"],"ready":true}),
                )
                .unwrap();
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("test refresh request missing")
}
#[test]
fn native_protocol_cross_process_reply_is_only_an_acknowledgment_and_preserves_receipts() {
    let f = Fixture::new();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "responder_child", "--nocapture"])
        .env("CW_REFRESH_TEST_HOME", &f.home)
        .env("CW_REFRESH_TEST_TOKEN", &f.token)
        .spawn()
        .unwrap();
    assert_eq!(
        leak_refresh::refresh_for_launch(&f.store, f.uid(), Some(&f.token), Duration::from_secs(2))
            .unwrap(),
        Outcome::Refreshed
    );
    assert!(child.wait().unwrap().success());
    assert!(!f.store.paths.base().join("dns-leak-receipt.json").exists());
}
#[test]
fn stale_response_timeout_invalid_uid_and_missing_token_do_not_grant_permission() {
    let f = Fixture::new();
    assert_eq!(
        leak_refresh::refresh_for_launch(&f.store, f.uid(), None, Duration::ZERO).unwrap(),
        Outcome::NotRequested
    );
    assert_eq!(
        leak_refresh::refresh_for_launch(&f.store, f.uid(), Some("invalid"), Duration::ZERO)
            .unwrap_err()
            .code,
        "dns_refresh_invalid"
    );
    assert_eq!(
        leak_refresh::refresh_for_launch(&f.store, f.uid() + 1, Some(&f.token), Duration::ZERO)
            .unwrap_err()
            .code,
        "dns_refresh_unavailable"
    );
    f.store
        .atomic_json(
            &f.dir().join("reply.json"),
            &json!({"schema":1,"id":"older","ready":true}),
        )
        .unwrap();
    assert_eq!(
        leak_refresh::refresh_for_launch(
            &f.store,
            f.uid(),
            Some(&f.token),
            Duration::from_millis(40)
        )
        .unwrap_err()
        .code,
        "dns_refresh_timeout"
    );
    f.store
        .atomic_json(
            &f.store.paths.base().join("dns-leak-receipt.json"),
            &json!({"provider":"ipleak","finished_at":native::now()}),
        )
        .unwrap();
    assert_eq!(
        leak_refresh::refresh_for_launch(&f.store, f.uid(), Some(&f.token), Duration::from_secs(1))
            .unwrap(),
        Outcome::AlreadyFresh
    );
}
