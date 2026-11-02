use claude_watch_runtime::{
    sampler::{pinned_node, selection_drift},
    storage::{Paths, StateStore},
};
use std::{fs, path::PathBuf};
use uuid::Uuid;

struct Home {
    path: PathBuf,
}
impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("cw-node-pin-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
    fn paths(&self) -> Paths {
        Paths::new(&self.path).unwrap()
    }
    fn write_baseline(&self, text: &str) {
        self.write_baseline_bytes(text.as_bytes());
    }
    fn write_baseline_bytes(&self, bytes: &[u8]) {
        let paths = self.paths();
        let store = StateStore::new(paths.clone());
        // Build fixture paths from the canonicalized home: on macOS the
        // temp dir (/var/...) is a symlink to /private/var/..., and the
        // store rejects non-canonical paths with path_outside_home.
        let dir = paths.watch().join("state");
        fs::create_dir_all(&dir).unwrap();
        store
            .atomic_bytes(&dir.join("baseline.conf"), bytes, 0o600)
            .unwrap();
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn a_matching_baseline_pins_the_session_node() {
    let home = Home::new();
    home.write_baseline("format=2\ntimezone=Asia/Tokyo\ntag_group=GLOBAL\ntag_node=node-a\n");
    assert_eq!(pinned_node(&home.paths(), "GLOBAL"), "node-a");
}

#[test]
fn a_group_mismatch_never_pins() {
    let home = Home::new();
    home.write_baseline("format=2\ntag_group=PROXY\ntag_node=node-a\n");
    assert_eq!(pinned_node(&home.paths(), "GLOBAL"), "");
}

#[test]
fn a_missing_baseline_yields_no_pin() {
    let home = Home::new();
    assert_eq!(pinned_node(&home.paths(), "GLOBAL"), "");
}

#[test]
fn a_baseline_without_tag_keys_yields_no_pin() {
    // The real machine's state on 2026-11-02: format=2 exists, tag keys do not
    // (tag mode was enabled after the baseline was created).
    let home = Home::new();
    home.write_baseline("format=2\ntimezone=Asia/Tokyo\n");
    assert_eq!(pinned_node(&home.paths(), "GLOBAL"), "");
}

#[test]
fn an_empty_request_group_matches_the_global_pin() {
    let home = Home::new();
    home.write_baseline("format=2\ntag_group=GLOBAL\ntag_node=node-a\n");
    assert_eq!(pinned_node(&home.paths(), ""), "node-a");
}

#[test]
fn invalid_utf8_yields_no_pin() {
    let home = Home::new();
    home.write_baseline_bytes(&[0xff, 0xfe, 0x00]);
    assert_eq!(pinned_node(&home.paths(), "GLOBAL"), "");
}

#[test]
fn drift_requires_both_a_pin_and_a_resolved_selection() {
    // Same node: no drift.
    assert!(!selection_drift("node-a", "node-a"));
    // A real drift: both sides name a real node and they differ.
    assert!(selection_drift("node-a", "node-b"));
    // Guard rail against the historical false-kill path: a pinned expectation
    // with an unresolvable (null) selection is unknown, never a change.
    assert!(!selection_drift("node-a", ""));
    // Without a pin there is nothing to compare against.
    assert!(!selection_drift("", "node-b"));
    assert!(!selection_drift("", ""));
}
