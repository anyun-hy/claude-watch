//! Temporary state + a mock EvidenceSystem only. No helper, network or signals.
use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
    policy::PolicyCatalog,
    processes::Provider,
    session::{Desktop, Phase, Reason, Session},
};
use claude_watch_runtime::{
    background_evidence::{self, EvidenceSystem, ProbeKind},
    config_store::{policy_digest, ConfigStore},
    receipt_store::ReceiptStore,
    session_store::SessionStore,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};

struct Fixture { root: PathBuf, store: StateStore }
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("cw-evidence-regression-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        store.atomic_json(&store.paths.config(), &Config { guard_enabled: true, ..Default::default() }.value().unwrap()).unwrap();
        Self { root, store }
    }
    fn receipts(&self) -> ReceiptStore { ReceiptStore { storage: self.store.clone() } }
    fn seed(&self, now: f64, context: &str) {
        self.receipts().record_dns(&probe(ProbeKind::Dns, now), &local(context), None, now).unwrap();
        self.receipts().record_webrtc(&probe(ProbeKind::WebRtc, now), &local(context), None, now).unwrap();
    }
    fn policy(&self, family: &str, criterion: &str, action: &str) {
        let config = ConfigStore { storage: self.store.clone() };
        let mut value = config.load().unwrap().value().unwrap();
        value[PolicyCatalog::family(family).unwrap().key(criterion)] = json!(action);
        config.save(value).unwrap();
    }
    fn sessions(&self, family: &'static str) -> SessionStore {
        SessionStore::for_family(self.store.clone(), family)
    }
    fn active(&self, family: &'static str) -> Session {
        self.seed(1000., "ctx");
        let sessions = self.sessions(family);
        let audit = audit(&self.store, family, 1000.);
        let pending = sessions.begin_verified(&self.receipts(), &audit, &egress(1000.), 1000.).unwrap();
        sessions.bind_desktop(&pending.session_id, desktop(family, 100), 1000.1).unwrap()
    }
    fn warning(&self, family: &'static str) -> Session {
        self.policy(family, "dns", "warn");
        let active = self.active(family);
        self.sessions(family).mark_failure(Some(&active.session_id), 1001.,
            "dns_egress_changed", "fixture notice", true).unwrap().session.unwrap()
    }
    fn rechecking(&self, family: &'static str) -> Session {
        let active = self.active(family);
        let sessions = self.sessions(family);
        sessions.end_desktop(&active.session_id, active.desktop.as_ref().unwrap(), 1002., true).unwrap();
        sessions.begin_recheck(&active.session_id, desktop(family, 200), 1003.).unwrap().unwrap()
    }
    fn mock(&self, family: &'static str) -> Mock {
        Mock { store: self.store.clone(), family, now: 1100., calls: vec![], selected: vec![], mutation: None,
            cancelled: false, wrong_audit: false, revalidations: 0 }
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); } }
fn desktop(family: &str, start_seconds: u64) -> Desktop {
    Desktop { pid: if family == "claude" { 77 } else { 88 }, start_seconds, start_microseconds: 1 }
}
fn local(context: &str) -> Value {
    json!({"context":context,"context_id":context,"proxy":"ok","tun":"ok","observation_unavailable":[]})
}
fn egress(now: f64) -> Value {
    json!({"ip":"1.1.1.1","country":"JP","observed_at":now,"source":"fixture"})
}
fn audit(store: &StateStore, family: &str, now: f64) -> Value {
    let config = ConfigStore { storage: store.clone() }.load().unwrap();
    let mut value = json!({"ready":true,"observed_at":now,"expires_at":now+30.,"context_id":"ctx",
        "observation_id":"fixture-round","context_transition":{"state":"stable"},
        "policy":policy_digest(&config.value().unwrap()).unwrap(),
        "egress_reference":{"ip":"1.1.1.1","country":"JP","checked_at":now,"context":"ctx","source":"fixture"}});
    if family == "openai" {
        value["launch_target"] = json!("codex-desktop");
        value["authorization_scope"] = json!("observation");
    }
    value
}
fn probe(kind: ProbeKind, now: f64) -> Value {
    let mut value = json!({"kind":kind.label(),"status":"complete","contextChanged":false,
        "startedAt":now-1.,"finishedAt":now,"errors":[],
        "observations":[{"kind":"http","address":"1.1.1.1","country":"JP"}]});
    value["observations"].as_array_mut().unwrap().push(match kind {
        ProbeKind::Dns => json!({"kind":"resolver","address":"8.8.8.8","country":"JP"}),
        ProbeKind::WebRtc => json!({"kind":"srflx","address":"1.1.1.1","country":"JP"}),
    });
    if kind == ProbeKind::Dns {
        value["externalJSON"] = json!(json!({"session":"a".repeat(40),"dns_servers":{"8.8.8.8":5},
            "http":{"address":"1.1.1.1","country":"JP"},
            "geoip":[{"ip":"8.8.8.8","country_code":"JP"}]}).to_string());
    }
    value
}
enum Mutation { Policy, StrictLock, Replacement }
struct Mock {
    store: StateStore,
    family: &'static str,
    now: f64,
    calls: Vec<(String, ProbeKind)>,
    selected: Vec<String>,
    mutation: Option<Mutation>,
    cancelled: bool,
    wrong_audit: bool,
    revalidations: usize,
}
impl EvidenceSystem for Mock {
    fn now(&self) -> f64 { self.now }
    fn local(&mut self, _: &Config) -> Result<Value> { Ok(local("ctx")) }
    fn desktop_matches(&mut self, expected: &Desktop) -> Result<bool> {
        Ok(expected.pid == desktop(self.family, 100).pid)
    }
    fn desktop_unique_stamp(&mut self, expected: &Desktop) -> Result<Option<String>> {
        Ok(self.desktop_matches(expected)?.then(|| "fixture-start".to_string()))
    }
    fn supervised_provider(&self) -> Provider {
        if self.family == "claude" { Provider::Claude } else { Provider::Codex }
    }
    fn set_family(&mut self, family: &str) -> Result<()> {
        self.family = match family { "claude" => "claude", "openai" => "openai",
            _ => return Err(CoreError::new("unknown_family", "fixture")) };
        self.selected.push(family.to_string());
        Ok(())
    }
    fn cancelled(&self) -> bool { self.cancelled }
    fn collect(&mut self, kind: ProbeKind) -> Result<Value> {
        self.calls.push((self.family.into(), kind));
        match self.mutation.take() {
            Some(Mutation::Policy) => {
                let config = ConfigStore { storage: self.store.clone() };
                let mut value = config.load()?.value()?;
                value[PolicyCatalog::family(self.family).unwrap().key("dns")] = json!("close");
                config.save(value)?;
            }
            Some(change) => {
                let sessions = SessionStore::for_family(self.store.clone(), self.family);
                let mut session = sessions.load(self.now)?.unwrap();
                match change {
                    Mutation::StrictLock => {
                        session.state = Phase::Locked;
                        session.reason = Some(Reason::new("egress_country_cn", "new mandatory stop", self.now));
                    }
                    Mutation::Replacement => session.session_id = uuid::Uuid::new_v4().to_string(),
                    Mutation::Policy => unreachable!(),
                }
                self.store.atomic_json(&self.store.paths.session_for(self.family), &serde_json::to_value(session).unwrap())?;
            }
            None => {}
        }
        Ok(probe(kind, self.now))
    }
    fn revalidate(&mut self) -> Result<(Value, Value)> {
        self.revalidations += 1;
        Ok((audit(&self.store, if self.wrong_audit { "claude" } else { self.family }, self.now), egress(self.now)))
    }
}

#[test]
fn openai_only_session_refreshes_without_a_claude_record() {
    let f = Fixture::new(); let before = f.active("openai"); let mut system = f.mock("claude");
    let out = background_evidence::refresh_supervised_sessions(&f.store, &mut system).unwrap();
    assert_eq!(out["status"], "ok"); assert_eq!(out["count"], 2);
    assert!(system.calls.iter().all(|(family, _)| family == "openai"));
    assert!(!f.store.paths.session_for("claude").exists());
    assert_eq!(f.sessions("openai").load(system.now).unwrap().unwrap(), before);
}
#[test]
fn warn_locked_sessions_refresh_but_do_not_resume_or_rewrite_the_baseline() {
    for family in ["claude", "openai"] {
        let f = Fixture::new(); let before = f.warning(family); let mut system = f.mock(family);
        let out = background_evidence::refresh_active_session(&f.store, &mut system).unwrap();
        assert_eq!(out["count"], 2); assert_eq!(system.revalidations, 0);
        assert_eq!(f.sessions(family).load(system.now).unwrap().unwrap(), before);
    }
}
#[test]
fn mandatory_locked_sessions_do_not_collect_or_unlock() {
    let f = Fixture::new(); let current = f.active("openai");
    let locked = f.sessions("openai").mark_failure(Some(&current.session_id), 1001.,
        "egress_country_cn", "fixture", true).unwrap().session.unwrap();
    let mut system = f.mock("openai");
    assert_eq!(background_evidence::refresh_active_session(&f.store, &mut system).unwrap()["status"], "idle");
    assert!(system.calls.is_empty()); assert_eq!(f.sessions("openai").load(system.now).unwrap().unwrap(), locked);
}
#[test]
fn one_damaged_family_does_not_starve_another() {
    let f = Fixture::new(); f.active("openai");
    fs::write(f.store.paths.session_for("claude"), b"{damaged").unwrap();
    let mut system = f.mock("claude");
    let out = background_evidence::refresh_supervised_sessions(&f.store, &mut system).unwrap();
    assert_eq!(out["status"], "incomplete"); assert_eq!(out["count"], 2);
    assert_eq!(out["families"][0]["family"], "claude");
    assert_eq!(out["families"][1]["status"], "ok");
}
#[test]
fn current_context_receipts_are_reused_across_families_without_duplicate_probes() {
    let f = Fixture::new(); f.active("claude"); f.active("openai");
    let mut system = f.mock("claude");
    let out = background_evidence::refresh_supervised_sessions(&f.store, &mut system).unwrap();
    assert_eq!(out["count"], 2); assert_eq!(system.calls.len(), 2);
    assert_eq!(out["families"][1]["count"], 0);
}
#[test]
fn a_policy_change_discards_the_inflight_probe() {
    let f = Fixture::new(); f.warning("openai");
    let before = f.receipts().probe_receipts(); let mut system = f.mock("openai");
    system.mutation = Some(Mutation::Policy);
    assert_eq!(background_evidence::refresh_active_session(&f.store, &mut system).unwrap_err().code, "evidence_policy_changed");
    assert_eq!(f.receipts().probe_receipts(), before);
}
#[test]
fn newer_mandatory_lock_and_replacement_both_discard_inflight_evidence() {
    for mutation in [Mutation::StrictLock, Mutation::Replacement] {
        let f = Fixture::new(); f.warning("openai"); let before = f.receipts().probe_receipts();
        let mut system = f.mock("openai"); system.mutation = Some(mutation);
        assert_eq!(background_evidence::refresh_active_session(&f.store, &mut system).unwrap_err().code, "evidence_session_changed");
        assert_eq!(f.receipts().probe_receipts(), before);
    }
}
#[test]
fn successful_openai_recheck_preserves_new_probe_baselines() {
    let f = Fixture::new(); let current = f.rechecking("openai"); let mut system = f.mock("openai");
    let out = background_evidence::refresh_active_session(&f.store, &mut system).unwrap();
    assert_eq!(out["status"], "ok"); assert_eq!(system.revalidations, 1);
    let verified = f.sessions("openai").load(system.now).unwrap().unwrap();
    assert_eq!(verified.state, Phase::Active); assert_eq!(verified.session_id, current.session_id);
    assert_eq!(verified.extra["baseline_dns_countries"], json!(["JP"]));
    assert_eq!(verified.extra["baseline_webrtc_addresses"], json!(["1.1.1.1"]));
    assert!(!f.store.paths.session_for("claude").exists());
}
#[test]
fn recheck_cannot_accept_a_different_family_audit() {
    let f = Fixture::new(); let current = f.rechecking("openai"); let mut system = f.mock("openai");
    system.wrong_audit = true;
    assert_eq!(background_evidence::refresh_active_session(&f.store, &mut system).unwrap_err().code, "launch_target_mismatch");
    assert_eq!(f.sessions("openai").load(system.now).unwrap().unwrap().state, Phase::Rechecking);
    assert_eq!(f.sessions("openai").load(system.now).unwrap().unwrap().session_id, current.session_id);
    assert!(!f.store.paths.watch().join("state/sessions/rust-88.session").exists());
}
#[test]
fn creation_rejects_cross_family_cli_and_malformed_explicit_targets() {
    let f = Fixture::new(); let receipts = f.receipts();
    for target in [json!("codex-desktop"), json!("claude-cli"), json!("unknown"), json!(null), json!(true)] {
        let mut value = audit(&f.store, "claude", 1000.); value["launch_target"] = target;
        assert_eq!(f.sessions("claude").begin_verified(&receipts, &value, &egress(1000.), 1000.).unwrap_err().code,
            "launch_target_mismatch");
    }
    assert!(!f.store.paths.session_for("claude").exists());
}
#[test]
fn recheck_provider_must_belong_to_the_same_store_family() {
    let f = Fixture::new(); let current = f.rechecking("openai");
    let before = fs::read(f.store.paths.session_for("openai")).unwrap();
    assert_eq!(f.sessions("openai").complete_recheck(&current.session_id, current.desktop.as_ref().unwrap(),
        "fixture", &audit(&f.store, "openai", 1100.), &egress(1100.), 1100., Provider::Claude)
        .unwrap_err().code, "launch_target_mismatch");
    assert_eq!(fs::read(f.store.paths.session_for("openai")).unwrap(), before);
}
#[test]
fn a_different_context_cannot_seed_a_new_sessions_probe_baseline() {
    let f = Fixture::new(); f.seed(1000., "other-context");
    let pending = f.sessions("openai").begin_verified(&f.receipts(), &audit(&f.store, "openai", 1000.),
        &egress(1000.), 1000.).unwrap();
    assert_eq!(pending.extra["baseline_dns_countries"], json!([]));
    assert_eq!(pending.extra["baseline_webrtc_addresses"], json!([]));
    assert_eq!(f.sessions("openai").load(1000.).unwrap().unwrap(), pending);
}
#[test]
fn cancellation_starts_no_family_collection() {
    let f = Fixture::new(); f.active("openai"); let mut system = f.mock("claude"); system.cancelled = true;
    let out = background_evidence::refresh_supervised_sessions(&f.store, &mut system).unwrap();
    assert_eq!(out["status"], "idle"); assert!(system.selected.is_empty()); assert!(system.calls.is_empty());
}
