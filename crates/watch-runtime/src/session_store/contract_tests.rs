use crate as claude_watch_runtime;
use claude_watch_core::session::{self, CheckInput, Desktop, Identity, Launcher, Phase};
use claude_watch_runtime::config_store::{canonical_policy_json, policy_digest, ConfigStore};
use claude_watch_runtime::{
    session_store::SessionStore,
    storage::{strict_json, Paths, StateStore},
};
use serde_json::{json, Value};
use std::io::Write;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
    process::Command,
};
use uuid::Uuid;

struct Fixture {
    home: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let home = std::env::temp_dir().join(format!("cw-runtime-{}", Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        Self { home }
    }
    fn storage(&self) -> StateStore {
        StateStore::new(Paths::new(&self.home).unwrap())
    }
    fn sessions(&self) -> SessionStore {
        SessionStore::new(self.storage())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}

#[test]
fn config_store_preserves_defaults_and_blocks_unfinished_transactions() {
    let fixture = Fixture::new();
    let storage = fixture.storage();
    let store = ConfigStore {
        storage: storage.clone(),
    };
    assert!(store.load().unwrap().enabled);
    assert!(!storage.paths.config().exists());
    let config=store.save(json!({"enabled":false,"guard_enabled":false,"country":"JP","timezone":"Asia/Tokyo","locale":"ja_JP"})).unwrap();
    assert_eq!(store.load().unwrap(), config);
    let bytes = fs::read(storage.paths.config()).unwrap();
    storage
        .atomic_json(&storage.paths.journal(), &json!({"schema":3}))
        .unwrap();
    assert_eq!(store.save(json!({})).unwrap_err().code, "recovery_required");
    assert_eq!(fs::read(storage.paths.config()).unwrap(), bytes);
}

#[test]
fn policy_canonical_json_and_hash_match_python() {
    let input = json!({"日本":"value","array":[true,false,null,1,-2,0.0,-0.0,1.0,1e-7,1e-5,1e16,1e20,5e-324],"nested":{"b":2,"a":"\n"}});
    let mut child=Command::new("python3").args(["-c","import json,sys,hashlib\nv=json.load(sys.stdin)\ns=json.dumps(v,sort_keys=True,ensure_ascii=False)\nprint(s)\nprint(hashlib.sha256(s.encode()).hexdigest())"]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&input).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(canonical_policy_json(&input).unwrap(), lines[0]);
    assert_eq!(policy_digest(&input).unwrap(), lines[1]);
}
fn egress(ip: &str, country: &str, now: f64) -> Value {
    json!({"ip":ip,"country":country,"observed_at":now,"source":"fixture"})
}
fn audit(now: f64) -> Value {
    json!({"ready":true,"observed_at":now,"expires_at":now+30.0,"context_id":"ctx","observation_id":"round",
    "context_transition":{"state":"stable"},"egress_reference":{"ip":"1.1.1.1","country":"JP","checked_at":now,"context":"ctx","source":"fixture"}})
}
fn risk(now: f64) -> Value {
    json!({"state":"safe","observed_at":now})
}
fn input(now: f64) -> CheckInput {
    CheckInput {
        now,
        launcher_live: false,
        identity: Identity::Matches,
        egress: egress("1.1.1.1", "JP", now),
        risk: risk(now),
    }
}
fn active(store: &SessionStore, now: f64) -> session::Session {
    let value = store
        .begin(&audit(now), &egress("1.1.1.1", "JP", now), &risk(now), now)
        .unwrap();
    store
        .bind_desktop(
            &value.session_id,
            Desktop {
                pid: 77,
                start_seconds: 10,
                start_microseconds: 20,
            },
            now + 0.1,
        )
        .unwrap()
}

#[test]
fn private_atomic_state_and_corruption_preservation() {
    let fixture = Fixture::new();
    let store = fixture.storage();
    let path = store.paths.base().join("example.json");
    store
        .atomic_json(&path, &json!({"round":1,"data":"a"}))
        .unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    store
        .atomic_json(&path, &json!({"round":2,"data":"b"}))
        .unwrap();
    assert_eq!(store.read_json(&path, Value::Null).unwrap()["round"], 2);
    let broken = b"{\"state\":\"safe\",\"state\":\"locked\"}";
    fs::write(&path, broken).unwrap();
    assert_eq!(
        store.read_json(&path, Value::Null).unwrap_err().code,
        "invalid_state"
    );
    assert_eq!(fs::read(&path).unwrap(), broken);
    assert!(strict_json(b"{\"nested\":{\"x\":1,\"x\":2}}").is_err());
    assert!(strict_json(b"{\"x\":NaN}").is_err());
    assert!(strict_json(b"{}{}").is_err());
    assert!(fs::read_dir(path.parent().unwrap()).unwrap().all(|v| !v
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".example")));
}

#[test]
fn path_boundaries_and_symlink_targets_are_rejected() {
    let fixture = Fixture::new();
    let outside = Fixture::new();
    let store = fixture.storage();
    store.initialize().unwrap();
    let secret = outside.home.join("outside.json");
    fs::write(&secret, b"preserved").unwrap();
    let link = store.paths.base().join("linked.json");
    symlink(&secret, &link).unwrap();
    assert_eq!(
        store.atomic_json(&link, &json!({})).unwrap_err().code,
        "unsafe_path"
    );
    assert!(store.read_json(&link, Value::Null).is_err());
    assert_eq!(fs::read(&secret).unwrap(), b"preserved");
    assert_eq!(
        store.atomic_json(&secret, &json!({})).unwrap_err().code,
        "path_outside_home"
    );
    assert!(store
        .guarded(&store.paths.base().join("../config.json"))
        .is_err());
    let directory = store.paths.base().join("linked-directory");
    symlink(&outside.home, &directory).unwrap();
    assert!(store
        .atomic_json(&directory.join("child.json"), &json!({}))
        .is_err());
    assert!(!outside.home.join("child.json").exists());
}

#[test]
fn lock_is_nonblocking_and_compatible_with_legacy_python() {
    let fixture = Fixture::new();
    let store = fixture.storage();
    let held = store.lock("session-guard", None).unwrap();
    assert!(matches!(store.lock("session-guard",None),Err(e) if e.code=="busy"));
    let code="import fcntl,sys\nf=open(sys.argv[1],'r+b')\ntry: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(3)\nsys.exit(0)";
    let output = Command::new("python3")
        .args(["-c", code])
        .arg(store.paths.base().join("session-guard.lock"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    drop(held);
    assert!(store.lock("session-guard", None).is_ok());
}

#[test]
fn unfinished_transactions_only_allow_the_matching_recovery() {
    let fixture = Fixture::new();
    let store = fixture.storage();
    store.initialize().unwrap();
    for (file, kind) in [
        ("setup-transaction.json", "setup"),
        ("update-transaction.json", "update"),
        ("transaction.json", "account"),
    ] {
        let path = store.paths.base().join(file);
        store.atomic_json(&path, &json!({"fixture":true})).unwrap();
        assert!(matches!(store.lock("operation",None),Err(e) if e.code=="recovery_required"));
        assert!(store.lock("operation", Some(kind)).is_ok());
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn launch_requires_current_audit_risk_and_egress() {
    let fixture = Fixture::new();
    let store = fixture.sessions();
    let now = 1000.0;
    let mut old = audit(now);
    old["ready"] = false.into();
    assert_eq!(
        store
            .begin(&old, &egress("1.1.1.1", "JP", now), &risk(now), now)
            .unwrap_err()
            .code,
        "preflight_blocked"
    );
    assert_eq!(
        store
            .begin(&audit(now), &egress("8.8.8.8", "JP", now), &risk(now), now)
            .unwrap_err()
            .code,
        "egress_changed"
    );
    // Leak evidence no longer vetoes a launch: an unknown or stale probe
    // sample is recorded with the session, and drift comparison judges it
    // while the session runs. Only the audit, the egress agreement and the
    // CN check still block a launch.
    let unknown = store
        .begin(
            &audit(now),
            &egress("1.1.1.1", "JP", now),
            &json!({"state":"unknown"}),
            now,
        )
        .unwrap();
    assert_eq!(unknown.risk_evidence.get("state"), Some(&json!("unknown")));
    let stale = store
        .begin(
            &audit(now),
            &egress("1.1.1.1", "JP", now),
            &risk(5000.0),
            now,
        )
        .unwrap();
    assert_eq!(stale.state, Phase::Pending);
    let mut cn = audit(now);
    cn["egress_reference"]["country"] = "CN".into();
    assert_eq!(
        store
            .begin(&cn, &egress("1.1.1.1", "CN", now), &risk(now), now)
            .unwrap_err()
            .code,
        "egress_country_cn"
    );
    // The refused CN launch must not replace or clear the session that the
    // stale-evidence launch legitimately created.
    assert_eq!(
        store.load(now).unwrap().unwrap().session_id,
        stale.session_id
    );
}

#[test]
fn active_baseline_never_moves_on_safe_or_changed_ip() {
    let fixture = Fixture::new();
    let store = fixture.sessions();
    let value = active(&store, 1000.0);
    for now in [1001.0, 1002.0, 1003.0] {
        assert_eq!(
            store
                .apply_check(Some(&value.session_id), &input(now))
                .unwrap()
                .state,
            "safe"
        );
    }
    assert_eq!(
        store.load(1003.0).unwrap().unwrap().baseline,
        value.baseline
    );
    let mut changed = input(1004.0);
    changed.egress = egress("8.8.8.8", "JP", 1004.0);
    let out = store
        .apply_check(Some(&value.session_id), &changed)
        .unwrap();
    assert_eq!(out.reason.unwrap().code, "egress_ip_changed");
    let locked = store.load(1004.0).unwrap().unwrap();
    assert_eq!(locked.baseline, value.baseline);
    assert_eq!(locked.state, Phase::Locked);
    assert_eq!(
        store
            .apply_check(Some(&value.session_id), &input(1005.0))
            .unwrap()
            .state,
        "locked"
    );
}

#[test]
fn unknown_samples_require_a_sustained_fifteen_second_streak_without_claiming_ip_change() {
    let fixture = Fixture::new();
    let store = fixture.sessions();
    let value = active(&store, 1000.0);
    let mut failed = input(1001.0);
    failed.egress = json!({"error":"timeout"});
    assert_eq!(
        store
            .apply_check(Some(&value.session_id), &failed)
            .unwrap()
            .state,
        "unknown"
    );
    failed.now = 1002.0;
    let out = store.apply_check(Some(&value.session_id), &failed).unwrap();
    assert_eq!(out.state, "unknown");
    failed.now = 1016.0;
    let out = store.apply_check(Some(&value.session_id), &failed).unwrap();
    assert_eq!(out.state, "risk");
    assert_eq!(out.reason.unwrap().code, "egress_unconfirmed");
    let value = active(&store, 1003.0);
    let mut unavailable = input(1004.0);
    unavailable.identity = Identity::Unavailable;
    assert_eq!(
        store
            .apply_check(Some(&value.session_id), &unavailable)
            .unwrap()
            .state,
        "unknown"
    );
    unavailable.now = 1005.0;
    assert_eq!(
        store
            .apply_check(Some(&value.session_id), &unavailable)
            .unwrap()
            .state,
        "unknown"
    );
    unavailable.now = 1019.0;
    let out = store
        .apply_check(Some(&value.session_id), &unavailable)
        .unwrap();
    assert_eq!(out.reason.unwrap().detail, "主进程身份连续未能复核");
}

#[test]
fn successful_check_clears_unknown_streak_and_invalid_clock_marker_cannot_extend_it() {
    let fixture = Fixture::new();
    let store = fixture.sessions();
    let value = active(&store, 1000.0);
    let mut unknown = input(1001.0);
    unknown.egress = json!({"error":"timeout"});
    assert_eq!(
        store
            .apply_check(Some(&value.session_id), &unknown)
            .unwrap()
            .state,
        "unknown"
    );
    let saved = store.load(1001.0).unwrap().unwrap();
    assert_eq!(saved.unknown_since, Some(1001.0));
    assert_eq!(
        store
            .apply_check(Some(&value.session_id), &input(1002.0))
            .unwrap()
            .state,
        "safe"
    );
    let saved = store.load(1002.0).unwrap().unwrap();
    assert_eq!(saved.unknown_count, 0);
    assert_eq!(saved.unknown_since, None);

    let mut corrupted = saved.clone();
    corrupted.unknown_count = 1;
    corrupted.unknown_since = Some(2000.0);
    store
        .storage
        .atomic_json(
            &store.storage.paths.session(),
            &serde_json::to_value(&corrupted).unwrap(),
        )
        .unwrap();
    let mut again = input(1003.0);
    again.egress = json!({"error":"timeout"});
    let out = store.apply_check(Some(&value.session_id), &again).unwrap();
    assert_eq!(out.state, "risk");
    assert_eq!(out.reason.unwrap().code, "egress_unconfirmed");
}

#[test]
fn china_identity_and_dns_risk_remain_immediate_stops() {
    let fixture = Fixture::new();
    let store = fixture.sessions();
    for scenario in ["country", "identity", "dns"] {
        let value = active(&store, 1000.0);
        let mut probe = input(1001.0);
        let expected = match scenario {
            "country" => {
                probe.egress = egress("1.1.1.1", "CN", 1001.0);
                "egress_country_cn"
            }
            "identity" => {
                probe.identity = Identity::Changed;
                "session_identity_changed"
            }
            _ => {
                probe.risk = json!({"state":"risk","observed_at":1001,"reason":{"code":"dns_risk","detail":"DNS fixture"}});
                "dns_risk"
            }
        };
        let out = store.apply_check(Some(&value.session_id), &probe).unwrap();
        assert_eq!(out.state, "risk");
        assert_eq!(out.reason.unwrap().code, expected);
    }
}

#[test]
fn unknown_risk_never_renews_safe_evidence_and_invalid_time_expires() {
    let fixture = Fixture::new();
    let store = fixture.sessions();
    let value = active(&store, 1000.0);
    let mut probe = input(1010.0);
    probe.risk = json!({"state":"unknown"});
    assert_eq!(
        store
            .apply_check(Some(&value.session_id), &probe)
            .unwrap()
            .state,
        "unknown"
    );
    assert_eq!(
        store.load(1010.0).unwrap().unwrap().risk_evidence,
        value.risk_evidence
    );
    // Stale evidence is recorded as an unknown gap, it no longer locks the
    // session: the probe measures its own path and the egress baseline check
    // above keeps guarding on its own TTL.
    probe.now = 1301.0;
    probe.egress = egress("1.1.1.1", "JP", 1301.0);
    let stale = store.apply_check(Some(&value.session_id), &probe).unwrap();
    assert_eq!(stale.state, "unknown");
    let stored = stale.session.unwrap();
    assert_eq!(stored.state, Phase::Active);
    assert_eq!(stored.risk_evidence["reason"]["code"], "evidence_expired");
    for invalid in [json!("NaN"), json!(5000), Value::Null] {
        let mut value = active(&store, 1000.0);
        value.risk_evidence["observed_at"] = invalid;
        store
            .storage
            .atomic_json(
                &store.storage.paths.session(),
                &serde_json::to_value(&value).unwrap(),
            )
            .unwrap();
        let mut probe = input(1001.0);
        probe.risk = json!({"state":"unknown"});
        let stale = store.apply_check(Some(&value.session_id), &probe).unwrap();
        assert_eq!(stale.state, "unknown");
        assert_eq!(
            stale.session.unwrap().risk_evidence["reason"]["code"],
            "evidence_expired"
        );
    }
}

#[test]
fn old_pending_timeout_cannot_lock_or_close_new_session() {
    let fixture = Fixture::new();
    let store = fixture.sessions();
    let old = store
        .begin(
            &audit(1000.0),
            &egress("1.1.1.1", "JP", 1000.0),
            &risk(1000.0),
            1000.0,
        )
        .unwrap();
    let new = store
        .begin(
            &audit(1010.0),
            &egress("1.1.1.1", "JP", 1010.0),
            &risk(1010.0),
            1010.0,
        )
        .unwrap();
    assert_eq!(
        store
            .apply_check(Some(&old.session_id), &input(1020.0))
            .unwrap()
            .reason
            .unwrap()
            .code,
        "session_changed"
    );
    assert!(store
        .close_if_current::<()>(Some(&old.session_id), 1020.0, || {
            panic!("stale closer executed")
        })
        .unwrap()
        .is_none());
    assert_eq!(
        store.load(1020.0).unwrap().unwrap().session_id,
        new.session_id
    );
    let bound = store
        .bind_desktop(
            &new.session_id,
            Desktop {
                pid: 77,
                start_seconds: 10,
                start_microseconds: 20,
            },
            1021.0,
        )
        .unwrap();
    assert_eq!(bound.state, Phase::Active);
}

#[test]
fn pending_launcher_grace_and_idle_projection_are_explicit() {
    let fixture = Fixture::new();
    let store = fixture.sessions();
    let value = store
        .begin(
            &audit(1000.0),
            &egress("1.1.1.1", "JP", 1000.0),
            &risk(1000.0),
            1000.0,
        )
        .unwrap();
    store
        .bind_launcher(
            &value.session_id,
            Launcher {
                pid: 55,
                start: "fixture-start".into(),
            },
            1001.0,
        )
        .unwrap();
    let mut probe = input(1002.0);
    probe.launcher_live = true;
    assert_eq!(
        store
            .apply_check(Some(&value.session_id), &probe)
            .unwrap()
            .reason
            .unwrap()
            .code,
        "session_pending"
    );
    probe.now = 1016.0;
    assert_eq!(
        store
            .apply_check(Some(&value.session_id), &probe)
            .unwrap()
            .state,
        "risk"
    );
    let value = active(&store, 1020.0);
    let out = store
        .apply_check(Some(&value.session_id), &input(1021.0))
        .unwrap();
    let value = out.session.unwrap();
    assert_eq!(session::status(&value, 1022.0, Some(true))["state"], "safe");
    assert_eq!(
        session::status(&value, 1022.0, Some(false))["state"],
        "idle"
    );
    assert_eq!(
        session::status(&value, 1040.0, Some(true))["state"],
        "unknown"
    );
}

#[test]
fn confirmed_identity_and_leak_risks_precede_missing_egress() {
    let fixture = Fixture::new();
    let session = active(&fixture.sessions(), 1000.0);
    let mut probe = input(1001.0);
    probe.egress = json!({"error":"offline"});
    probe.identity = Identity::Changed;
    let result = session::check(&session, &probe);
    assert_eq!(result.state, "risk");
    assert_eq!(result.reason.unwrap().code, "session_identity_changed");
    probe.identity = Identity::Unavailable;
    probe.risk = json!({"state":"risk","observed_at":1001.0,"reason":{"code":"dns_risk","detail":"fixture"}});
    let result = session::check(&session, &probe);
    assert_eq!(result.state, "risk");
    assert_eq!(result.reason.unwrap().code, "dns_risk");
    assert_eq!(result.baseline.unwrap().ip, "1.1.1.1");
    assert!(result.current.is_none());
}

#[test]
fn failed_probe_cannot_close_replacement_session() {
    let fixture = Fixture::new();
    let store = fixture.sessions();
    let old = active(&store, 1000.0);
    let new = active(&store, 1002.0);
    let mut closed = false;
    let result = store
        .close_if_current_before(Some(&old.session_id), 1003.0, 1001.0, || {
            closed = true;
            Ok(())
        })
        .unwrap();
    assert!(result.is_none());
    assert!(!closed);
    assert_ne!(old.session_id, new.session_id);
}
