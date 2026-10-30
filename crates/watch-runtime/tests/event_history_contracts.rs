use claude_watch_runtime::{
    events::{DiagnosticEventInput, EventFields, EventStore},
    monitor_snapshot::{self, EventHistoryQuery},
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};

struct Fixture {
    root: PathBuf,
    store: StateStore,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("cw-event-history-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        Self { root, store }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn query(store: &StateStore, filter: &str, term: &str, offset: usize) -> Value {
    monitor_snapshot::event_history(
        store,
        &EventHistoryQuery {
            filter: filter.into(),
            query: term.into(),
            offset,
        },
    )
    .unwrap()
}

#[test]
fn filters_cover_previous_history_before_paging_and_old_traffic_cannot_hide_warnings() {
    let f = Fixture::new();
    let dir = f.store.paths.base();
    fs::create_dir_all(&dir).unwrap();
    let mut old = String::new();
    for index in 0..130 {
        old.push_str(&format!(
            "{}\n",
            json!({"id":format!("warning-{index}"),"time":index + 1,
            "category":"activity-unavailable","status":"partial"})
        ));
    }
    fs::write(dir.join("events.previous.jsonl"), old).unwrap();
    let mut current = format!(
        "{}\n",
        json!({"id":"current-warning","time":500,
        "category":"activity-unavailable","status":"partial"})
    );
    for index in 0..5000 {
        current.push_str(&format!(
            "{}\n",
            json!({"id":format!("sample-{index}"),"time":1000 + index,
            "category":"traffic-counter","pid":10000 + index,"bytes_in":index})
        ));
    }
    fs::write(dir.join("events.jsonl"), current).unwrap();
    EventStore::new(f.store.clone())
        .append(
            "traffic-counter",
            EventFields {
                pid: Some(456),
                bytes_in: Some(22),
                ..Default::default()
            },
            7000.0,
        )
        .unwrap();

    let first = query(&f.store, "attention", "", 0);
    assert_eq!(first["total"], 131);
    assert_eq!(first["events"].as_array().unwrap().len(), 100);
    assert_eq!(first["hasMore"], true);
    let second = query(&f.store, "attention", "", 100);
    assert_eq!(second["events"].as_array().unwrap().len(), 31);
    assert_eq!(second["hasMore"], false);
    let sample = query(&f.store, "sample", "PID 14999", 0);
    assert_eq!(sample["total"], 1);
    assert_eq!(sample["events"][0]["id"], "sample-4999");
    assert_eq!(query(&f.store, "sample", "", 0)["total"], 5001);
    assert_eq!(
        monitor_snapshot::events(&f.store).unwrap()[0]["id"],
        "current-warning"
    );
    assert!(dir.join("traffic-events.jsonl").is_file());
}

#[test]
fn diagnostic_stream_is_minimal_deduplicated_and_rejects_untrusted_fields() {
    let f = Fixture::new();
    let events = EventStore::new(f.store.clone());
    let mut input = DiagnosticEventInput {
        kind: "dns".into(),
        source: "ipleak".into(),
        outcome: "incomplete".into(),
        reason: "timeout".into(),
        stage: Some("dns".into()),
        elapsed_seconds: Some(2.0),
    };
    assert!(events.record_diagnostic(&input, 1000.0).unwrap());
    assert!(!events.record_diagnostic(&input, 1001.0).unwrap());
    input.stage = Some("geoip".into());
    assert!(events.record_diagnostic(&input, 1002.0).unwrap());
    input.stage = Some("geoip:203.0.113.9".into());
    assert!(events.record_diagnostic(&input, 1003.0).is_err());
    assert!(
        serde_json::from_value::<DiagnosticEventInput>(json!({"kind":"dns","source":"ipleak",
        "outcome":"incomplete","reason":"timeout","stage":"dns","elapsed_seconds":2,
        "message":"secret-token-123"}))
        .is_err()
    );
    let raw = fs::read_to_string(f.store.paths.base().join("diagnostic-events.jsonl")).unwrap();
    assert!(!raw.contains("203.0.113.9"));
    assert!(!raw.contains("secret-token-123"));
    assert!(!raw.contains(":null"));
    assert!(!f.store.paths.base().join("events.jsonl").exists());
    let view = query(&f.store, "attention", "超时", 0);
    assert_eq!(view["total"], 2);
    assert_eq!(view["events"][0]["title"], "DNS 检测");
    assert_eq!(view["events"][0]["severity"], "warning");
}

#[test]
fn dns_deadline_stages_are_specific_but_cannot_carry_addresses_or_tokens() {
    let f = Fixture::new();
    let events = EventStore::new(f.store.clone());
    let mut input = DiagnosticEventInput { kind:"dns".into(), source:"netcoffee".into(),
        outcome:"incomplete".into(), reason:"timeout".into(), stage:None, elapsed_seconds:Some(69.0) };
    for (index,stage) in ["dns_images", "dns_records"].iter().enumerate() {
        input.stage=Some((*stage).into());
        assert!(events.record_diagnostic(&input,1000.0+index as f64).unwrap());
    }
    input.stage=Some("dns_records:private-token".into());
    assert!(events.record_diagnostic(&input,1002.).is_err());
    let view=query(&f.store,"attention","",0);
    assert_eq!(view["total"],2);
    assert!(view.to_string().contains("DNS 记录读取"));
    assert!(!view.to_string().contains("private-token"));
}

#[test]
fn malformed_complete_lines_and_unreadable_logs_are_not_presented_as_empty_success() {
    let f = Fixture::new();
    let dir = f.store.paths.base();
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("events.jsonl"), b"{bad}\n{partial").unwrap();
    assert_eq!(query(&f.store, "all", "", 0)["invalidRecords"], 1);
    fs::remove_file(dir.join("events.jsonl")).unwrap();
    fs::create_dir(dir.join("events.jsonl")).unwrap();
    let request = EventHistoryQuery {
        filter: "all".into(),
        query: "".into(),
        offset: 0,
    };
    assert!(monitor_snapshot::event_history(&f.store, &request).is_err());
    assert_eq!(
        monitor_snapshot::empty(&f.store, 1000.0, "fixture")["eventError"],
        "事件日志不可读取"
    );
}

#[test]
fn error_status_is_not_hidden_by_an_unrecognized_event_category() {
    let f = Fixture::new();
    EventStore::new(f.store.clone())
        .append(
            "new-error-category",
            EventFields {
                status: Some("failed".into()),
                code: Some("test_failure".into()),
                ..Default::default()
            },
            1000.0,
        )
        .unwrap();
    let page = query(&f.store, "attention", "new-error-category", 0);
    assert_eq!(page["total"], 1);
    assert_eq!(page["events"][0]["severity"], "error");
}
