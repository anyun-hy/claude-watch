use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
    session::{Desktop, Identity},
};
use claude_watch_runtime::{
    background_evidence::{self, EvidenceSystem, ProbeKind},
    receipt_store::ReceiptStore,
    session_store::SessionStore,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};

struct Fixture {
    root: PathBuf,
    store: StateStore,
}

#[test]
fn failed_worker_persists_only_validated_lifecycle_diagnostics() {
    use claude_watch_runtime::{
        background_evidence::{ProbeExecutor, WORKER},
        release_native::{FixedCommand, FixedCommandExecutor},
    };
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{atomic::AtomicBool, Arc},
        time::Duration,
    };
    let f = Fixture::new();
    let script = f.root.join(WORKER);
    fs::write(
        &script,
        r##"#!/bin/sh
printf '%s\n' '{"cw_trace":"navigation_finished","attached":true,"elapsed_ms":40}' >&2
printf '%s\n' '{"cw_trace":"dns_retry","attached":true,"elapsed_ms":45}' >&2
printf '%s\n' '{"cw_trace":"secret-203.0.113.9","attached":true,"elapsed_ms":50}' >&2
printf '%s\n' 'unstructured secret-token' >&2
printf '%s\n' '{"status":"timeout"}'
"##,
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let output = ProbeExecutor::new(Arc::new(AtomicBool::new(false)))
        .with_diagnostics(f.store.clone())
        .run(FixedCommand {
            program: script,
            args: vec!["--dns".into()],
            timeout: Duration::from_secs(3),
        })
        .unwrap();
    assert!(
        output.stderr.is_empty(),
        "raw stderr never crosses the output contract"
    );
    let log = fs::read_to_string(f.store.paths.base().join("diagnostic-events.jsonl")).unwrap();
    assert!(log.contains("navigation_finished"));
    assert!(log.contains("dns_retry"));
    assert!(log.contains("background-leak-trace"));
    assert!(!log.contains("203.0.113.9") && !log.contains("secret-token"));
    assert_eq!(log.lines().count(), 2);

    let script = f.root.join(WORKER);
    fs::write(&script, "#!/bin/sh\nprintf '%s\\n' '{\"cw_trace\":\"phase_dns\",\"attached\":true,\"elapsed_ms\":40}' >&2\n/bin/sleep 5\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let timeout = ProbeExecutor::new(Arc::new(AtomicBool::new(false)))
        .with_diagnostics(f.store.clone())
        .run(FixedCommand {
            program: script,
            args: vec!["--dns".into()],
            timeout: Duration::from_secs(1),
        })
        .unwrap_err();
    assert_eq!(timeout.code, "evidence_probe_timeout");
    let log = fs::read_to_string(f.store.paths.base().join("diagnostic-events.jsonl")).unwrap();
    assert!(
        log.contains("phase_dns"),
        "phase evidence survives the supervisor timeout"
    );
}

#[test]
fn recovered_worker_retains_only_bounded_http_retry_diagnostic() {
    use claude_watch_runtime::{
        background_evidence::{ProbeExecutor, WORKER},
        release_native::{FixedCommand, FixedCommandExecutor},
    };
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{atomic::AtomicBool, Arc},
        time::Duration,
    };
    let f = Fixture::new();
    let script = f.root.join(WORKER);
    fs::write(
        &script,
        r##"#!/bin/sh
printf '%s\n' '{"cw_trace":"navigation_finished","attached":true,"elapsed_ms":40}' >&2
printf '%s\n' '{"cw_trace":"http_retry","attached":true,"elapsed_ms":45}' >&2
printf '%s\n' '{"cw_trace":"secret-203.0.113.9","attached":true,"elapsed_ms":50}' >&2
printf '%s\n' '{"status":"complete"}'
"##,
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let output = ProbeExecutor::new(Arc::new(AtomicBool::new(false)))
        .with_diagnostics(f.store.clone())
        .run(FixedCommand {
            program: script,
            args: vec!["--webrtc".into()],
            timeout: Duration::from_secs(3),
        })
        .unwrap();
    assert!(output.stderr.is_empty());
    let log = fs::read_to_string(f.store.paths.base().join("diagnostic-events.jsonl")).unwrap();
    assert!(log.contains("http_retry"));
    assert!(!log.contains("navigation_finished") && !log.contains("203.0.113.9"));
    assert_eq!(log.lines().count(), 1);
}

impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("cw-background-evidence-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        store
            .atomic_json(
                &store.paths.config(),
                &Config {
                    guard_enabled: true,
                    ..Default::default()
                }
                .value()
                .unwrap(),
            )
            .unwrap();
        Self { root, store }
    }
    fn active(&self, now: f64) {
        let receipts = ReceiptStore {
            storage: self.store.clone(),
        };
        receipts
            .record_dns(&probe(ProbeKind::Dns, now, "JP"), &local("ctx"), None, now)
            .unwrap();
        receipts
            .record_webrtc(
                &probe(ProbeKind::WebRtc, now, "JP"),
                &local("ctx"),
                None,
                now,
            )
            .unwrap();
        let sessions = SessionStore::new(self.store.clone());
        let audit = json!({"ready":true,"observed_at":now,"expires_at":now+30.,"context_id":"ctx","observation_id":"round","context_transition":{"state":"stable"},"egress_reference":{"ip":"1.1.1.1","country":"JP","checked_at":now,"context":"ctx","source":"fixture"}});
        let session = sessions
            .begin_verified(&receipts, &audit, &egress(now), now)
            .unwrap();
        sessions
            .bind_desktop(
                &session.session_id,
                Desktop {
                    pid: 77,
                    start_seconds: 100,
                    start_microseconds: 1,
                },
                now + 0.1,
            )
            .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn local(ctx: &str) -> Value {
    json!({"context":ctx,"context_id":ctx,"proxy":"ok","tun":"ok","observation_unavailable":[]})
}
fn egress(now: f64) -> Value {
    json!({"ip":"1.1.1.1","country":"JP","observed_at":now,"source":"fixture"})
}
fn probe(kind: ProbeKind, now: f64, country: &str) -> Value {
    let mut value = json!({"kind":kind.label(),"status":"complete","contextChanged":false,"startedAt":now-1.,"finishedAt":now,"errors":[],"observations":[{"kind":"http","address":"1.1.1.1","country":"JP"}]});
    value["observations"].as_array_mut().unwrap().push(match kind {
        ProbeKind::Dns => json!({"kind":"resolver","address":"8.8.8.8","country":country}),
        ProbeKind::WebRtc => json!({"kind":"srflx","address":if country=="CN"{"8.8.8.8"}else{"1.1.1.1"},"country":country}),
    });
    if kind == ProbeKind::Dns {
        value["externalJSON"] = json!(serde_json::to_string(&json!({
            "session":"a".repeat(40),"dns_servers":{"8.8.8.8":5},
            "http":{"address":"1.1.1.1","country":"JP"},
            "geoip":[{"ip":"8.8.8.8","country_code":country}]
        }))
        .unwrap());
    }
    value
}
struct Fake {
    now: f64,
    calls: usize,
    local_calls: usize,
    change_after: bool,
    fail: bool,
    timeout_receipt: bool,
    running: bool,
    country: &'static str,
    mutate: Option<StateStore>,
}
impl Default for Fake {
    fn default() -> Self {
        Self {
            now: 1001.,
            calls: 0,
            local_calls: 0,
            change_after: false,
            fail: false,
            timeout_receipt: false,
            running: true,
            country: "JP",
            mutate: None,
        }
    }
}
impl EvidenceSystem for Fake {
    fn now(&self) -> f64 {
        self.now
    }
    fn local(&mut self, _: &Config) -> Result<Value> {
        self.local_calls += 1;
        Ok(local(if self.change_after && self.calls > 0 {
            "different"
        } else {
            "ctx"
        }))
    }
    fn desktop_matches(&mut self, _: &Desktop) -> Result<bool> {
        Ok(self.running)
    }
    fn collect(&mut self, kind: ProbeKind) -> Result<Value> {
        self.calls += 1;
        self.now += 1.;
        if let Some(store) = self.mutate.take() {
            store.atomic_json(&store.paths.config(), &Config::default().value().unwrap())?;
        }
        if self.fail {
            Err(CoreError::new("fixture_timeout", "fixture"))
        } else if self.timeout_receipt {
            Ok(
                json!({"kind":kind.label(),"status":"timeout","startedAt":self.now-1.,"finishedAt":self.now,
                "contextChanged":false,"observations":[],"errors":[{"stage":"collector","code":"timeout","message":"fixture"}]}),
            )
        } else {
            Ok(probe(kind, self.now, self.country))
        }
    }
}

#[test]
fn a_saved_timeout_receipt_remains_incomplete_and_does_not_renew_safe_evidence() {
    let f = Fixture::new();
    f.active(1000.);
    let mut system = Fake {
        now: 1070.,
        timeout_receipt: true,
        ..Default::default()
    };
    let result = background_evidence::refresh_active_session(&f.store, &mut system).unwrap();
    assert_eq!(result["status"], "incomplete");
    assert_eq!(result["failed_probes"], json!(["dns", "webrtc"]));
    let last_valid = f
        .store
        .read_json(
            &f.store.paths.base().join("dns-leak-last-valid.json"),
            Value::Null,
        )
        .unwrap();
    assert_eq!(last_valid["finished_at"], 1000.);
    assert_eq!(
        SessionStore::new(f.store.clone())
            .load(system.now)
            .unwrap()
            .unwrap()
            .risk_evidence["observed_at"],
        1000.
    );
}

#[test]
fn ui_absent_background_keeps_session_evidence_fresh_beyond_five_minutes() {
    let f = Fixture::new();
    f.active(1000.);
    let sessions = SessionStore::new(f.store.clone());
    let receipts = ReceiptStore {
        storage: f.store.clone(),
    };
    let mut system = Fake::default();
    let original = sessions.load(1001.).unwrap().unwrap();
    // No GUI or GUI heartbeat exists. Only the independent worker refreshes.
    for now in [1065., 1130., 1195., 1260., 1325., 1390.] {
        system.now = now;
        let refreshed = background_evidence::refresh_active_session(&f.store, &mut system).unwrap();
        assert_eq!(refreshed["count"], 2);
        let checked = sessions
            .check_verified(
                &receipts,
                Some(&original.session_id),
                system.now + 0.1,
                false,
                Identity::Matches,
                egress(system.now),
            )
            .unwrap();
        assert_eq!(checked.state, "safe");
        assert_eq!(checked.session.unwrap().baseline, original.baseline);
    }
    assert_eq!(system.calls, 12);
    assert!(!f.store.paths.base().join("last-guard-stop.json").exists());
}

#[test]
fn gui_fresh_receipts_are_reused_without_duplicate_requests_or_renewing_timestamps() {
    let f = Fixture::new();
    f.active(1000.);
    let path = f.store.paths.base().join("dns-leak-receipt.json");
    let before = fs::read(&path).unwrap();
    let mut system = Fake::default();
    assert_eq!(
        background_evidence::refresh_active_session(&f.store, &mut system).unwrap()["count"],
        0
    );
    assert_eq!(system.calls, 0);
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn dns_refreshes_before_its_thirty_second_gate_while_webrtc_remains_fresh() {
    let f = Fixture::new();
    f.active(1000.);
    let mut system = Fake {
        now: 1021.,
        ..Default::default()
    };
    assert_eq!(
        background_evidence::refresh_active_session(&f.store, &mut system).unwrap()["count"],
        1
    );
    assert_eq!(system.calls, 1);
    assert_eq!(
        f.store
            .read_json(
                &f.store.paths.base().join("webrtc-risk-receipt.json"),
                Value::Null
            )
            .unwrap()["sampled_at"],
        1000.
    );
    assert_eq!(
        ReceiptStore {
            storage: f.store.clone()
        }
        .dns_status("ctx", true, system.now, |t| format!("{t}"))["state"],
        "ok"
    );
}

#[test]
fn dns_refresh_begins_at_ten_seconds_without_renewing_the_old_receipt() {
    let f = Fixture::new();
    f.active(1000.);
    let path = f.store.paths.base().join("dns-leak-receipt.json");
    let original = fs::read(&path).unwrap();
    let mut system = Fake {
        now: 1009.0,
        ..Default::default()
    };
    assert_eq!(
        background_evidence::refresh_active_session(&f.store, &mut system).unwrap()["count"],
        0
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    system.now = 1010.0;
    assert_eq!(
        background_evidence::refresh_active_session(&f.store, &mut system).unwrap()["count"],
        1
    );
    let updated: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(updated["finished_at"], json!(1011.0));
    assert_eq!(updated["provider"], "ipleak");
}

#[test]
fn cancelled_probe_reaps_its_owned_process_group_and_releases_child_lock() {
    use claude_watch_runtime::{
        background_evidence::{ProbeExecutor, WORKER},
        release_native::{FixedCommand, FixedCommandExecutor},
    };
    use std::{
        io::Write,
        os::unix::fs::PermissionsExt,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };
    let f = Fixture::new();
    let script = f.root.join(WORKER);
    let ready = f.root.join("ready");
    let held = f.root.join("child-lock");
    let body=format!("#!/bin/sh\n/usr/bin/python3 -c 'import fcntl,time; f=open(\"{}\",\"w\"); fcntl.flock(f,fcntl.LOCK_EX); open(\"{}\",\"w\").write(\"ready\"); time.sleep(60)' &\nwait\n",held.display(),ready.display());
    fs::File::create(&script)
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let cancel = stop.clone();
    let worker = std::thread::spawn(move || {
        ProbeExecutor::new(stop).run(FixedCommand {
            program: script,
            args: vec!["--dns".into()],
            timeout: Duration::from_secs(30),
        })
    });
    let wait = Instant::now();
    while !ready.exists() && wait.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    cancel.store(true, Ordering::Release);
    let joined = worker.join().unwrap();
    assert!(ready.exists(), "isolated child must have acquired its lock");
    assert_eq!(joined.unwrap_err().code, "evidence_cancelled");
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(held)
        .unwrap();
    assert!(
        file.try_lock().is_ok(),
        "cancelled child must release the lock"
    );
}

#[test]
fn missing_or_disabled_session_does_not_start_background_network_queries() {
    let f = Fixture::new();
    let mut system = Fake::default();
    assert_eq!(
        background_evidence::refresh_active_session(&f.store, &mut system).unwrap()["status"],
        "idle"
    );
    f.active(1000.);
    system.now = 1070.;
    system.running = false;
    assert_eq!(
        background_evidence::refresh_active_session(&f.store, &mut system).unwrap()["status"],
        "idle"
    );
    system.running = true;
    f.store
        .atomic_json(&f.store.paths.config(), &Config::default().value().unwrap())
        .unwrap();
    assert_eq!(
        background_evidence::refresh_active_session(&f.store, &mut system).unwrap()["status"],
        "idle"
    );
    assert_eq!(system.calls, 0);
}

#[test]
fn context_or_policy_change_discards_late_results() {
    for change_context in [true, false] {
        let f = Fixture::new();
        f.active(1000.);
        let path = f.store.paths.base().join("dns-leak-receipt.json");
        let before = fs::read(&path).unwrap();
        let mut system = Fake {
            now: 1070.,
            change_after: change_context,
            mutate: (!change_context).then(|| f.store.clone()),
            ..Default::default()
        };
        let error = background_evidence::refresh_active_session(&f.store, &mut system).unwrap_err();
        assert_eq!(
            error.code,
            if change_context {
                "evidence_context_changed"
            } else {
                "evidence_policy_changed"
            }
        );
        assert_eq!(fs::read(path).unwrap(), before);
    }
}

#[test]
fn collector_failure_never_refreshes_old_safe_time_and_real_dns_risk_still_blocks() {
    let f = Fixture::new();
    f.active(1000.);
    let mut system = Fake {
        now: 1070.,
        fail: true,
        ..Default::default()
    };
    assert_eq!(
        background_evidence::refresh_active_session(&f.store, &mut system).unwrap()["status"],
        "incomplete"
    );
    let receipts = ReceiptStore {
        storage: f.store.clone(),
    };
    let sessions = SessionStore::new(f.store.clone());
    let active = sessions.load(system.now).unwrap().unwrap();
    let expired = sessions
        .check_verified(
            &receipts,
            Some(&active.session_id),
            1301.,
            false,
            Identity::Matches,
            egress(1301.),
        )
        .unwrap();
    assert_eq!(expired.state, "risk");
    assert_eq!(expired.reason.unwrap().code, "evidence_expired");

    let f = Fixture::new();
    f.active(1000.);
    let mut system = Fake {
        now: 1070.,
        country: "CN",
        ..Default::default()
    };
    background_evidence::refresh_active_session(&f.store, &mut system).unwrap();
    let sessions = SessionStore::new(f.store.clone());
    let active = sessions.load(system.now).unwrap().unwrap();
    let risk = sessions
        .check_verified(
            &ReceiptStore {
                storage: f.store.clone(),
            },
            Some(&active.session_id),
            system.now + 0.1,
            false,
            Identity::Matches,
            egress(system.now),
        )
        .unwrap();
    assert_eq!(risk.state, "risk");
    assert!(risk.reason.unwrap().code.contains("dns"));
}
