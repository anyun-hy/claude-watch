//! Isolated multi-main contracts: temporary files and mock native observations.
//! No child process, network, native helper, app launch or signal is used.
use claude_watch_core::{
    config::Config, error::{CoreError, Result}, processes::{LaunchTarget, Provider},
    session::{Desktop, Launcher, Phase, Session},
};
use claude_watch_runtime::{
    background_evidence::{self, EvidenceSystem, ProbeKind},
    config_store::{ConfigStore, policy_digest}, controlled::{Controller, DesktopSystem},
    receipt_store::ReceiptStore,
    session_store::{SessionStore, desktop_groups::{
        canonical_desktops, desktop_members, group_rechecking, group_stamps,
    }},
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{fs, path::PathBuf, time::Duration};

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
struct Fixture { root: PathBuf, store: StateStore, controller: Controller }
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("cw-multi-main-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        store.atomic_json(&store.paths.config(), &Config { guard_enabled: true, ..Default::default() }.value().unwrap()).unwrap();
        let f = Self { root, controller: Controller::new(store.clone()), store };
        f.seed(1000., "JP"); f
    }
    fn seed(&self, now: f64, country: &str) {
        let receipts = ReceiptStore { storage: self.store.clone() };
        receipts.record_dns(&probe(ProbeKind::Dns, now, country), &local(), None, now).unwrap();
        receipts.record_webrtc(&probe(ProbeKind::WebRtc, now, country), &local(), None, now).unwrap();
    }
    fn sessions(&self) -> SessionStore { SessionStore::for_family(self.store.clone(), "openai") }
    fn session(&self, now: f64) -> Session { self.sessions().load(now).unwrap().unwrap() }
    fn config(&self, key: &str, value: Value) {
        let store = ConfigStore { storage: self.store.clone() };
        let mut config = store.load().unwrap().value().unwrap(); config[key] = value;
        store.save(config).unwrap();
    }
    fn mock(&self, count: usize) -> Mock {
        Mock { store: self.store.clone(), family: "openai", now: 1001.,
            mains: (0..count).map(|i| desktop(77 + i as u32, 900)).collect(), claude: vec![],
            hidden: vec![], helper: false, ip: "1.1.1.1", country: "JP", dns_country: "JP",
            closes: 0, forces: 0, audits: 0, fail_quit: false, support_group: true,
            change_on_audit: false, change_on_revalidate: false, lock_on_revalidate: false }
    }
    fn tick(&self, system: &mut Mock) -> Value {
        self.controller.guard_tick(system).unwrap()["families"].as_array().unwrap()
            .iter().find(|v| v["family"] == "openai").unwrap().clone()
    }
    fn pending_join(&self) -> (Mock, Session) {
        let mut system = self.mock(1); self.tick(&mut system); system.now += 1.;
        system.mains.push(desktop(78, 900)); self.tick(&mut system);
        let value = self.session(system.now); assert_eq!(value.state, Phase::Rechecking);
        (system, value)
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); } }

struct Mock {
    store: StateStore, family: &'static str, now: f64,
    mains: Vec<Desktop>, claude: Vec<Desktop>, hidden: Vec<u32>, helper: bool,
    ip: &'static str, country: &'static str, dns_country: &'static str,
    closes: usize, forces: usize, audits: usize, fail_quit: bool, support_group: bool,
    change_on_audit: bool, change_on_revalidate: bool, lock_on_revalidate: bool,
}
impl Mock {
    fn roots(&self) -> &[Desktop] { if self.family == "openai" { &self.mains } else { &self.claude } }
    fn rows(&self) -> Vec<(Desktop, bool, String)> {
        let mut rows: Vec<_> = self.roots().iter().map(|d| (d.clone(), !self.hidden.contains(&d.pid), format!("fixture-{}-{}", d.pid, d.start_seconds))).collect();
        if self.helper && self.family == "openai" { rows.push((desktop(199, 901), false, "fixture-helper".into())); }
        rows
    }
    fn stop(&mut self) -> Result<()> {
        if self.fail_quit { return Err(CoreError::new("fixture_quit_failed", "fixture")); }
        if self.family == "openai" { self.mains.clear(); self.helper = false; } else { self.claude.clear(); }
        Ok(())
    }
}
impl DesktopSystem for Mock {
    fn launch_target(&self) -> LaunchTarget { if self.family == "openai" { LaunchTarget::CodexDesktop } else { LaunchTarget::ClaudeDesktop } }
    fn set_family(&mut self, family: &str) -> Result<()> {
        self.family = match family { "openai" => "openai", "claude" => "claude", _ => return Err(CoreError::new("unknown_family", "fixture")) }; Ok(())
    }
    fn now(&self) -> f64 { self.now }
    fn monotonic(&self) -> Duration { Duration::from_secs_f64(self.now) }
    fn wait(&mut self, duration: Duration) { self.now += duration.as_secs_f64(); }
    fn desktops(&mut self) -> Result<Vec<(Desktop, bool, String)>> { Ok(self.rows()) }
    fn desktop_alive(&mut self, expected: &Desktop) -> Result<bool> { Ok(self.roots().contains(expected)) }
    fn desktop_tree_running(&mut self) -> Result<bool> { Ok(!self.roots().is_empty() || (self.helper && self.family == "openai")) }
    fn launcher(&mut self) -> Result<Launcher> { Ok(Launcher { pid: 90, start: "fixture".into() }) }
    fn full_audit(&mut self) -> Result<Value> {
        self.audits += 1;
        if self.change_on_audit { self.change_on_audit = false; self.mains.push(desktop(99, 901)); }
        Ok(audit(&self.store, self.now, self.family == "openai", self.ip, self.country))
    }
    fn egress(&mut self) -> Value { egress(self.now, self.ip, self.country) }
    fn local_guard(&mut self) -> Result<Value> { Ok(local()) }
    fn backend_healthy(&mut self) -> Result<bool> { Ok(true) }
    fn launcher_matches(&mut self, _: &Launcher) -> Result<bool> { Ok(true) }
    fn open_desktop(&mut self) -> Result<()> { panic!("these tests must never open an app") }
    fn quit_desktop(&mut self) -> Result<()> { self.closes += 1; self.stop() }
    fn quit_for_confirmed_ip_risk(&mut self, forced: &mut Option<u32>) -> Result<()> {
        self.forces += 1; *forced = Some(self.roots().len() as u32); self.stop()
    }
}
impl EvidenceSystem for Mock {
    fn now(&self) -> f64 { self.now }
    fn local(&mut self, _: &Config) -> Result<Value> { Ok(local()) }
    fn desktop_matches(&mut self, expected: &Desktop) -> Result<bool> {
        Ok(self.rows().iter().any(|(d, main, _)| *main && d == expected))
    }
    fn desktop_unique_stamp(&mut self, expected: &Desktop) -> Result<Option<String>> {
        Ok(group_stamps(&[expected.clone()], &self.rows())?.and_then(|v| v.into_iter().next().map(|(_, s)| s)))
    }
    fn desktop_group_stamps(&mut self, expected: &[Desktop]) -> Result<Option<Vec<(Desktop, String)>>> {
        if !self.support_group { return Err(CoreError::new("evidence_identity_unknown", "fixture")); }
        group_stamps(expected, &self.rows())
    }
    fn supervised_provider(&self) -> Provider { DesktopSystem::launch_target(self).provider() }
    fn set_family(&mut self, family: &str) -> Result<()> { DesktopSystem::set_family(self, family) }
    fn collect(&mut self, kind: ProbeKind) -> Result<Value> { Ok(probe(kind, self.now, self.dns_country)) }
    fn revalidate(&mut self) -> Result<(Value, Value)> {
        if self.change_on_revalidate {
            self.change_on_revalidate = false; self.mains.push(desktop(99, 902)); self.now += 1.;
            Controller::new(self.store.clone()).guard_tick(self)?;
        }
        if self.lock_on_revalidate {
            self.lock_on_revalidate = false; self.now += 1.;
            let sessions = SessionStore::for_family(self.store.clone(), "openai");
            let current = sessions.load(self.now)?.unwrap();
            sessions.mark_failure(Some(&current.session_id), self.now, "egress_country_cn", "newer risk", true)?;
        }
        Ok((DesktopSystem::full_audit(self)?, DesktopSystem::egress(self)))
    }
}

#[test]
fn two_mains_are_bound_without_a_missing_session_stop() {
    let f = Fixture::new(); let mut system = f.mock(2); let receipt = f.tick(&mut system);
    assert_eq!(receipt["session_guard"]["reason"]["code"], "session_adopted");
    assert_eq!(receipt["desktop_count"], 2); assert_eq!((system.closes, system.forces), (0, 0));
    let value = f.session(system.now); assert_eq!(value.state, Phase::Active);
    assert_eq!(desktop_members(&value).unwrap(), system.mains);
    for pid in [77, 78] { assert!(f.store.paths.watch().join(format!("state/sessions/rust-{pid}.session")).exists()); }
}
#[test]
fn inventory_order_and_helpers_do_not_rebind_a_group() {
    let f = Fixture::new(); let mut system = f.mock(2); f.tick(&mut system);
    let old = f.session(system.now); system.mains.reverse(); system.helper = true; system.now += 1.; f.tick(&mut system);
    assert_eq!(f.session(system.now).session_id, old.session_id);
    assert_eq!(desktop_members(&f.session(system.now)).unwrap().len(), 2);
    assert_eq!((system.closes, system.forces), (0, 0));
}
#[test]
fn either_member_can_exit_without_resetting_the_survivors_baseline() {
    for index in [0, 1] {
        let f = Fixture::new(); let mut system = f.mock(2); f.tick(&mut system); let old = f.session(system.now);
        system.mains.remove(index); system.now += 1.; f.tick(&mut system);
        let now = f.session(system.now); assert_eq!(now.state, Phase::Active);
        assert_eq!(desktop_members(&now).unwrap(), system.mains); assert_eq!(now.baseline, old.baseline);
        assert_eq!((system.closes, system.forces), (0, 0));
    }
}
#[test]
fn joining_main_is_provisional_without_a_slow_audit_on_the_guard() {
    let f = Fixture::new(); let (system, value) = f.pending_join();
    assert!(group_rechecking(&value)); assert_eq!(desktop_members(&value).unwrap().len(), 2);
    assert_eq!(system.audits, 1); assert_eq!((system.closes, system.forces), (0, 0));
    assert_eq!(value.baseline.observed_at, 1001.);
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
fn a_non_anchor_metadata_gap_is_not_a_confirmed_exit() {
    let f = Fixture::new(); let mut system = f.mock(2); f.tick(&mut system); let old = f.session(system.now);
    system.hidden.push(78); system.now += 1.; f.tick(&mut system);
    let now = f.session(system.now); assert_eq!(desktop_members(&now).unwrap().len(), 2);
    assert_eq!(now.session_id, old.session_id); assert_eq!(now.state, Phase::Active);
    assert_eq!((system.closes, system.forces), (0, 0));
}
#[test]
fn reused_pid_requires_a_new_membership_audit() {
    let f = Fixture::new(); let mut system = f.mock(2); f.tick(&mut system); let old = f.session(system.now);
    system.mains[1].start_microseconds += 1; system.now += 1.; f.tick(&mut system);
    let now = f.session(system.now); assert_ne!(now.session_id, old.session_id);
    assert_eq!(now.state, Phase::Rechecking); assert_eq!(now.baseline, old.baseline);
    assert_eq!((system.closes, system.forces), (0, 0));
}
#[test]
fn confirmed_exit_risk_is_not_delayed_by_group_rechecking() {
    for cn in [false, true] {
        let f = Fixture::new(); let (mut system, _) = f.pending_join();
        system.now += 1.; if cn { system.country = "CN"; } else { system.ip = "8.8.8.8"; }
        let receipt = f.tick(&mut system); assert_eq!(receipt["action"], "close-desktop");
        assert_eq!(receipt["stop_action"], "close"); assert_eq!(system.audits, 1);
        assert_eq!((system.closes, system.forces), (1, 0));
    }
}
#[test]
fn a_required_failed_stop_cannot_be_cancelled_by_a_new_member() {
    let f = Fixture::new(); let mut system = f.mock(2); f.tick(&mut system);
    system.now += 1.; system.ip = "8.8.8.8"; system.fail_quit = true; f.tick(&mut system);
    let locked = f.session(system.now); system.mains.push(desktop(99, 902));
    system.ip = "1.1.1.1"; system.fail_quit = false; system.now += 1.; let receipt = f.tick(&mut system);
    assert_eq!(receipt["stop_state"], "confirmed"); assert_eq!(system.closes, 2);
    assert_eq!(f.session(system.now).session_id, locked.session_id);
}
#[test]
fn a_confirmed_empty_family_can_start_a_fresh_group_baseline() {
    let f = Fixture::new(); let mut system = f.mock(2); f.tick(&mut system);
    system.mains.clear(); system.now += 1.; f.tick(&mut system);
    assert_eq!(f.session(system.now).state, Phase::Ended);
    system.mains = vec![desktop(87, 910), desktop(88, 910)]; system.ip = "8.8.8.8";
    system.now += 1.; f.tick(&mut system);
    let current = f.session(system.now); assert_eq!(current.state, Phase::Rechecking);
    assert_eq!(current.baseline.ip, "8.8.8.8"); assert_eq!((system.closes, system.forces), (0, 0));
}
#[test]
fn a_warn_latch_survives_join_and_audit_until_the_guard_recovers_it() {
    let f = Fixture::new(); f.config("gpt_close_dns", json!("warn")); let mut system = f.mock(2);
    f.tick(&mut system); system.now += 1.; f.seed(system.now, "US"); f.tick(&mut system);
    assert_eq!(f.session(system.now).state, Phase::Locked);
    system.mains.push(desktop(99, 902)); system.now += 1.; f.tick(&mut system);
    assert!(group_rechecking(&f.session(system.now))); assert_eq!(f.session(system.now).state, Phase::Locked);
    system.now += 2.; background_evidence::refresh_active_session(&f.store, &mut system).unwrap();
    let audited = f.session(system.now); assert_eq!(audited.state, Phase::Locked);
    assert!(!group_rechecking(&audited)); system.now += 1.; let receipt = f.tick(&mut system);
    assert_eq!(receipt["stop_state"], "recovered"); assert_eq!(f.session(system.now).state, Phase::Active);
    assert_eq!((system.closes, system.forces), (0, 0));
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
    let f = Fixture::new(); f.config("gpt_close_session",json!("warn")); let mut system = f.mock(2); f.tick(&mut system);
    let mut raw = serde_json::to_value(f.session(system.now)).unwrap(); raw["desktop_group_v1"] = json!([desktop(77,900),desktop(77,900)]);
    f.store.atomic_json(&f.store.paths.session_for("openai"),&raw).unwrap();
    let bytes = fs::read(f.store.paths.session_for("openai")).unwrap(); system.now += 1.; f.tick(&mut system);
    assert!(f.sessions().load(system.now).is_err()); assert_eq!((system.closes,system.forces),(0,0));
    assert_eq!(fs::read(f.store.paths.session_for("openai")).unwrap(),bytes);
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
fn repeated_joins_do_not_extend_the_original_recheck_deadline() {
    let f = Fixture::new(); f.config("gpt_close_session",json!("warn")); let (mut system, before) = f.pending_join();
    system.now = before.pending_deadline - 1.; system.mains.push(desktop(99,910)); f.tick(&mut system);
    assert_eq!(f.session(system.now).pending_deadline,before.pending_deadline);
    system.now = before.pending_deadline; f.tick(&mut system); let after=f.session(system.now);
    assert_eq!(after.state,Phase::Locked); assert_eq!(after.reason.unwrap().code,"revalidation_timeout");
    assert_eq!((system.closes,system.forces),(0,0));
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
fn disabled_or_unreadable_policy_cannot_modify_group_membership() {
    for corrupt in [false,true] {
        let f=Fixture::new(); let mut system=f.mock(2); f.tick(&mut system);
        let before=fs::read(f.store.paths.session_for("openai")).unwrap();
        if corrupt { fs::write(f.store.paths.config(),b"{broken").unwrap(); }
        else { f.config("guard_enabled",json!(false)); }
        system.mains.push(desktop(99,902)); system.now+=1.; let out=f.tick(&mut system);
        assert_eq!(out["action"],"observe"); assert_eq!((system.closes,system.forces),(0,0));
        assert_eq!(fs::read(f.store.paths.session_for("openai")).unwrap(),before);
    }
}
#[test]
fn an_adapter_without_group_identity_support_cannot_promote_it() {
    let f=Fixture::new(); let (mut system,before)=f.pending_join(); system.now+=2.; system.support_group=false;
    assert_eq!(background_evidence::refresh_active_session(&f.store,&mut system).unwrap_err().code,"evidence_identity_unknown");
    assert_eq!(f.session(system.now),before);
}
#[test]
fn warning_recovery_checks_every_bound_main_not_only_the_anchor() {
    let f=Fixture::new(); f.config("gpt_close_dns",json!("warn")); let mut system=f.mock(2); f.tick(&mut system);
    system.now+=1.; f.seed(system.now,"US"); f.tick(&mut system);
    system.now+=1.; f.seed(system.now,"JP"); system.hidden.push(78); let out=f.tick(&mut system);
    assert_eq!(f.session(system.now).state,Phase::Locked); assert_ne!(out["stop_state"],"recovered");
    assert_eq!((system.closes,system.forces),(0,0));
}
#[test]
fn membership_change_during_initial_audit_is_not_adopted_or_stopped() {
    let f=Fixture::new(); let mut system=f.mock(2); system.change_on_audit=true;
    let out=f.tick(&mut system); assert_eq!(out["stop_state"],"session_changed");
    assert!(f.sessions().load(system.now).unwrap().is_none()); assert_eq!((system.closes,system.forces),(0,0));
    system.now+=1.; f.tick(&mut system); assert_eq!(desktop_members(&f.session(system.now)).unwrap().len(),3);
}
#[test]
fn an_openai_group_does_not_replace_a_claude_session() {
    let f=Fixture::new(); let receipts=ReceiptStore{storage:f.store.clone()}; let claude=SessionStore::new(f.store.clone());
    let pending=claude.begin_verified(&receipts,&audit(&f.store,1000.,false,"1.1.1.1","JP"),&egress(1000.,"1.1.1.1","JP"),1000.).unwrap();
    let old=claude.bind_desktop(&pending.session_id,desktop(177,900),1000.1).unwrap();
    let mut system=f.mock(2); system.claude.push(desktop(177,900)); f.tick(&mut system);
    let current=claude.load(system.now).unwrap().unwrap(); assert_eq!(current.session_id,old.session_id);
    assert_eq!(current.baseline,old.baseline); assert_eq!(current.desktop,old.desktop);
    assert!(!current.extra.contains_key("desktop_group_v1")); assert_eq!(desktop_members(&f.session(system.now)).unwrap().len(),2);
}

#[test]
fn ending_a_provisional_family_does_not_poison_the_next_lifetimes_deadline() {
    let f = Fixture::new(); let (mut system, pending) = f.pending_join();
    system.mains.clear(); system.now += 1.; f.tick(&mut system);
    assert_eq!(f.session(system.now).state, Phase::Ended);
    system.now = pending.pending_deadline + 10.;
    system.mains = vec![desktop(87, 910), desktop(88, 910)]; system.ip = "8.8.8.8";
    f.tick(&mut system); let current = f.session(system.now);
    assert_eq!(current.state, Phase::Rechecking);
    assert_eq!(current.baseline.ip, "8.8.8.8");
    assert!(current.pending_deadline > system.now);
    assert_eq!((system.closes, system.forces), (0, 0));
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
fn explicit_force_and_warn_remain_distinct_for_a_multi_main_family() {
    for action in ["force", "warn"] {
        let f = Fixture::new(); f.config("gpt_close_ip", json!(action));
        let mut system = f.mock(2); f.tick(&mut system);
        system.ip = "8.8.8.8"; system.now += 1.; let receipt = f.tick(&mut system);
        assert_eq!(system.closes, 0);
        assert_eq!(system.forces, usize::from(action == "force"));
        assert_eq!(receipt["stop_state"], if action == "force" { "confirmed" } else { "skipped_warn_only" });
        assert_eq!(system.mains.len(), if action == "force" { 0 } else { 2 });
    }
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
