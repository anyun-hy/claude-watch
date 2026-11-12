//! Isolated multi-main contracts: temporary files and mock native observations.
//! No child process, network, native helper, app launch or signal is used.
use claude_watch_core::{
    config::Config, error::{CoreError, Result}, processes::Provider,
    session::{self, Desktop, Phase, Session, GROUP_CONTINUITY_KEY, GROUP_KEY, GROUP_RECHECK_KEY},
};
use claude_watch_runtime::{
    background_evidence::{self, EvidenceSystem, ProbeKind},
    config_store::{ConfigStore, policy_digest},
    receipt_store::ReceiptStore,
    session_store::{SessionStore, desktop_groups::{
        canonical_desktops, desktop_members, group_rechecking, group_stamps,
    }},
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};

fn desktop(pid: u32, start: u64) -> Desktop {
    Desktop { pid, start_seconds: start, start_microseconds: 1 }
}
fn local() -> Value {
    json!({"context":"ctx","context_id":"ctx","proxy":"ok","tun":"ok",
        "guard_backend_healthy":true,"observation_unavailable":[]})
}
fn egress(now: f64, ip: &str, country: &str) -> Value {
    json!({"ip":ip,"country":country,"observed_at":now,"source":"fixture"})
}
fn audit(store: &StateStore, now: f64, openai: bool, ip: &str, country: &str) -> Value {
    let config = ConfigStore { storage: store.clone() }.load().unwrap();
    let mut value = json!({"ready":true,"observed_at":now,"expires_at":now+30.,
        "context_id":"ctx","observation_id":"fixture","context_transition":{"state":"stable"},
        "policy":policy_digest(&config.value().unwrap()).unwrap(),
        "egress_reference":{"ip":ip,"country":country,"checked_at":now,"context":"ctx","source":"fixture"}});
    if openai { value["launch_target"] = json!("codex-desktop"); value["authorization_scope"] = json!("observation"); }
    value
}
fn probe(kind: ProbeKind, now: f64, dns_country: &str) -> Value {
    let mut value = json!({"kind":kind.label(),"status":"complete","contextChanged":false,
        "startedAt":now-1.,"finishedAt":now,"errors":[],
        "observations":[{"kind":"http","address":"1.1.1.1","country":"JP"}]});
    value["observations"].as_array_mut().unwrap().push(match kind {
        ProbeKind::Dns => json!({"kind":"resolver","address":"8.8.8.8","country":dns_country}),
        ProbeKind::WebRtc => json!({"kind":"srflx","address":"1.1.1.1","country":"JP"}),
    });
    if kind == ProbeKind::Dns {
        value["externalJSON"] = json!(json!({"session":"a".repeat(40),"dns_servers":{"8.8.8.8":5},
            "http":{"address":"1.1.1.1","country":"JP"},
            "geoip":[{"ip":"8.8.8.8","country_code":dns_country}]}).to_string());
    }
    value
}
struct Fixture { root: PathBuf, store: StateStore }
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("cw-multi-main-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        store.atomic_json(&store.paths.config(), &Config { guard_enabled: true, ..Default::default() }.value().unwrap()).unwrap();
        let f = Self { root, store };
        f.seed(1000., "JP");
        f
    }
    fn seed(&self, now: f64, country: &str) {
        let receipts = ReceiptStore { storage: self.store.clone() };
        receipts.record_dns(&probe(ProbeKind::Dns, now, country), &local(), None, now).unwrap();
        receipts.record_webrtc(&probe(ProbeKind::WebRtc, now, country), &local(), None, now).unwrap();
    }
    fn sessions(&self) -> SessionStore { SessionStore::for_family(self.store.clone(), "openai") }
    fn session(&self, now: f64) -> Session { self.sessions().load(now).unwrap().unwrap() }

    // Seed an existing group record. The evidence worker still performs the
    // real identity, policy, context, receipt and commit checks.
    fn pending_join(&self) -> (Mock, Session) {
        let system = Mock {
            store: self.store.clone(), family: "openai", now: 1002.,
            mains: vec![desktop(77, 900), desktop(78, 900)], ip: "1.1.1.1", country: "JP",
            support_group: true, change_on_revalidate: false, lock_on_revalidate: false,
        };
        let initial = 1000.0;
        let egress = egress(initial, system.ip, system.country);
        let audit = audit(&self.store, initial, true, system.ip, system.country);
        let risk = (ReceiptStore { storage: self.store.clone() }).session_risk("ctx", Some(system.ip), initial);
        let mut value = session::begin(&audit, &egress, &risk, "fixture-pending-group", initial).unwrap();
        value.state = Phase::Rechecking;
        value.created_at = system.now;
        value.pending_deadline = system.now + session::RISK_EVIDENCE_TTL;
        value.desktop = system.mains.first().cloned();
        value.bound_at = Some(system.now);
        value.extra.insert(GROUP_KEY.into(), json!(system.mains));
        value.extra.insert(GROUP_RECHECK_KEY.into(), json!(true));
        value.extra.insert(GROUP_CONTINUITY_KEY.into(), json!(true));
        value.extra.insert("baseline_dns_countries".into(), json!(["JP"]));
        self.store.atomic_json(&self.store.paths.session_for("openai"), &json!(value)).unwrap();
        (system, value)
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); } }

struct Mock {
    store: StateStore, family: &'static str, now: f64,
    mains: Vec<Desktop>, ip: &'static str, country: &'static str,
    support_group: bool, change_on_revalidate: bool, lock_on_revalidate: bool,
}
impl Mock {
    fn rows(&self) -> Vec<(Desktop, bool, String)> {
        self.mains.iter().map(|d| (d.clone(), true, format!("fixture-{}-{}", d.pid, d.start_seconds))).collect()
    }
}
impl EvidenceSystem for Mock {
    fn now(&self) -> f64 { self.now }
    fn local(&mut self, _: &Config) -> Result<Value> { Ok(local()) }
    fn desktop_matches(&mut self, expected: &Desktop) -> Result<bool> { Ok(self.mains.contains(expected)) }
    fn desktop_unique_stamp(&mut self, expected: &Desktop) -> Result<Option<String>> {
        Ok(group_stamps(&[expected.clone()], &self.rows())?.and_then(|v| v.into_iter().next().map(|(_, s)| s)))
    }
    fn desktop_group_stamps(&mut self, expected: &[Desktop]) -> Result<Option<Vec<(Desktop, String)>>> {
        if !self.support_group { return Err(CoreError::new("evidence_identity_unknown", "fixture")); }
        group_stamps(expected, &self.rows())
    }
    fn supervised_provider(&self) -> Provider { if self.family == "openai" { Provider::Codex } else { Provider::Claude } }
    fn set_family(&mut self, family: &str) -> Result<()> {
        self.family = match family { "openai" => "openai", "claude" => "claude", _ => return Err(CoreError::new("unknown_family", "fixture")) };
        Ok(())
    }
    fn collect(&mut self, kind: ProbeKind) -> Result<Value> { Ok(probe(kind, self.now, "JP")) }
    fn revalidate(&mut self) -> Result<(Value, Value)> {
        let sessions = SessionStore::for_family(self.store.clone(), "openai");
        if self.change_on_revalidate {
            self.change_on_revalidate = false;
            self.mains.push(desktop(99, 902));
            self.now += 1.;
            let mut newer = sessions.load(self.now)?.unwrap();
            newer.session_id = "fixture-newer-group".into();
            newer.extra.insert(GROUP_KEY.into(), json!(self.mains));
            self.store.atomic_json(&self.store.paths.session_for("openai"), &json!(newer))?;
        }
        if self.lock_on_revalidate {
            self.lock_on_revalidate = false;
            self.now += 1.;
            let current = sessions.load(self.now)?.unwrap();
            sessions.mark_failure(Some(&current.session_id), self.now, "egress_country_cn", "newer risk", true)?;
        }
        Ok((audit(&self.store, self.now, self.family == "openai", self.ip, self.country),
            egress(self.now, self.ip, self.country)))
    }
}
#[test]
fn background_recheck_verifies_every_member_without_rebasing_continuous_work() {
    let f = Fixture::new(); let (mut system, before) = f.pending_join(); system.now += 2.;
    let out = background_evidence::refresh_active_session(&f.store, &mut system).unwrap();
    assert_eq!(out["status"], "ok"); let after = f.session(system.now);
    assert_eq!(after.state, Phase::Active); assert!(!group_rechecking(&after));
    assert_eq!(after.session_id, before.session_id); assert_eq!(after.baseline, before.baseline);
    assert_eq!(after.extra["baseline_dns_countries"], before.extra["baseline_dns_countries"]);
    assert_eq!(desktop_members(&after).unwrap(), system.mains);
    assert_eq!(after.extra["guard_checked_at"], json!(system.now));
}
#[test]
fn completion_refuses_missing_duplicate_or_wrong_members() {
    let f = Fixture::new(); let (mut system, pending) = f.pending_join(); system.now += 2.; f.seed(system.now, "JP");
    let audit = audit(&f.store, system.now, true, system.ip, system.country);
    for members in [vec![desktop(77,900)], vec![desktop(77,900),desktop(77,900)], vec![desktop(77,900),desktop(78,901)]] {
        let bindings: Vec<_> = members.into_iter().map(|d| (d, "fixture".to_string())).collect();
        assert!(f.sessions().complete_group_recheck(&pending, &bindings, &audit,
            &egress(system.now,system.ip,system.country), system.now,Provider::Codex).is_err());
        assert_eq!(f.session(system.now).state, Phase::Rechecking);
    }
}
#[test]
fn the_legacy_single_desktop_recheck_cannot_drop_group_members() {
    let f = Fixture::new(); let (mut system, pending) = f.pending_join(); system.now += 2.; f.seed(system.now, "JP");
    assert!(f.sessions().complete_recheck(&pending.session_id,pending.desktop.as_ref().unwrap(),"fixture",
        &audit(&f.store,system.now,true,system.ip,system.country),&egress(system.now,system.ip,system.country),
        system.now,Provider::Codex).unwrap().is_none());
    assert_eq!(f.session(system.now), pending);
}
#[test]
fn malformed_group_data_is_not_silently_read_as_a_single_main() {
    let f = Fixture::new();
    let (system, pending) = f.pending_join();
    let mut raw = json!(pending);
    raw[GROUP_KEY] = json!([desktop(77,900),desktop(77,900)]);
    let path = f.store.paths.session_for("openai");
    f.store.atomic_json(&path, &raw).unwrap();
    let bytes = fs::read(&path).unwrap();
    assert!(f.sessions().load(system.now).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
}
#[test]
fn a_late_audit_cannot_overwrite_a_newer_membership_revision() {
    let f = Fixture::new(); let (mut system, before) = f.pending_join(); system.now += 2.; system.change_on_revalidate = true;
    assert_eq!(background_evidence::refresh_active_session(&f.store,&mut system).unwrap_err().code,"evidence_session_changed");
    let after = f.session(system.now); assert_ne!(after.session_id,before.session_id);
    assert_eq!(desktop_members(&after).unwrap().len(),3); assert_eq!(after.state,Phase::Rechecking);
}
#[test]
fn a_late_audit_cannot_unlock_a_new_mandatory_risk() {
    let f = Fixture::new(); let (mut system, _) = f.pending_join(); system.now += 2.; system.lock_on_revalidate = true;
    assert_eq!(background_evidence::refresh_active_session(&f.store,&mut system).unwrap_err().code,"evidence_session_changed");
    let after = f.session(system.now); assert_eq!(after.state,Phase::Locked);
    assert_eq!(after.reason.unwrap().code,"egress_country_cn");
}
#[test]
fn invalid_or_duplicate_native_members_are_rejected() {
    for rows in [vec![desktop(1,900)],vec![desktop(77,0)],vec![desktop(77,900),desktop(77,901)],
        (0..33).map(|i|desktop(100+i,900)).collect()] { assert!(canonical_desktops(rows).is_err()); }
}
#[test]
fn native_group_binding_requires_the_exact_main_set_and_valid_stamps() {
    let roots=vec![desktop(77,900),desktop(78,900)];
    let mut rows=vec![(roots[0].clone(),true,"a".into()),(roots[1].clone(),true,"b".into())];
    assert!(group_stamps(&roots[..1],&rows).unwrap().is_none());
    rows.push((desktop(99,900),false,"helper".into())); assert_eq!(group_stamps(&roots,&rows).unwrap().unwrap().len(),2);
    rows[1].2="bad|stamp".into(); assert!(group_stamps(&roots,&rows).is_err());
    rows[1].2="b".into(); rows[1].1=false; assert!(group_stamps(&roots,&rows).unwrap().is_none());
}
#[test]
fn an_adapter_without_group_identity_support_cannot_promote_it() {
    let f=Fixture::new(); let (mut system,before)=f.pending_join(); system.now+=2.; system.support_group=false;
    assert_eq!(background_evidence::refresh_active_session(&f.store,&mut system).unwrap_err().code,"evidence_identity_unknown");
    assert_eq!(f.session(system.now),before);
}
#[test]
fn recheck_cannot_commit_a_different_network_context() {
    let f = Fixture::new(); let (mut system, pending) = f.pending_join();
    system.now += 2.; f.seed(system.now, "JP");
    let bindings = group_stamps(&desktop_members(&pending).unwrap(), &system.rows()).unwrap().unwrap();
    let mut wrong = audit(&f.store, system.now, true, system.ip, system.country);
    wrong["context_id"] = json!("other-context");
    wrong["egress_reference"]["context"] = json!("other-context");
    assert_eq!(f.sessions().complete_group_recheck(&pending, &bindings, &wrong,
        &egress(system.now, system.ip, system.country), system.now, Provider::Codex)
        .unwrap_err().code, "revalidation_context_changed");
    assert_eq!(f.session(system.now), pending);
}
#[test]
fn group_recheck_rejects_another_familys_audit_without_writing_leases() {
    let f = Fixture::new(); let (mut system, pending) = f.pending_join();
    system.now += 2.; f.seed(system.now, "JP");
    let bindings = group_stamps(&desktop_members(&pending).unwrap(), &system.rows()).unwrap().unwrap();
    assert_eq!(f.sessions().complete_group_recheck(&pending, &bindings,
        &audit(&f.store, system.now, false, system.ip, system.country),
        &egress(system.now, system.ip, system.country), system.now, Provider::Codex)
        .unwrap_err().code, "launch_target_mismatch");
    assert_eq!(f.session(system.now), pending);
    assert!(!f.store.paths.watch().join("state/sessions/rust-78.session").exists());
}
