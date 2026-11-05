//! Isolated warning/fault regressions: temp state and mock observations only.
//! Never launches a native helper, reads real applications, networks or signals.
use super::*;
use claude_watch_core::{config::Config, session::{Phase, Session}};
use crate::storage::Paths;
use std::{fs, path::PathBuf};

struct Fixture {
    home: PathBuf,
    store: StateStore,
    controller: Controller,
    family: &'static str,
}
impl Fixture {
    fn new(family: &'static str) -> Self {
        let home = std::env::temp_dir().join(format!("cw-warning-recovery-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        let store = StateStore::new(Paths::new(&home).unwrap());
        let mut config = Config { guard_enabled: true, ..Default::default() };
        for action in config.policy_actions.values_mut() { *action = "warn".into(); }
        store.atomic_json(&store.paths.config(), &config.value().unwrap()).unwrap();
        Self { controller: Controller::new(store.clone()), home, store, family }
    }
    fn sessions(&self) -> SessionStore { SessionStore::for_family(self.store.clone(), self.family) }
    fn policy(&self, criterion: &str, action: &str) {
        let mut config = ConfigStore { storage: self.store.clone() }.load().unwrap();
        let key = PolicyCatalog::family(self.family).unwrap().key(criterion);
        config.gpt_force_approved_v1.retain(|v| v != &key);
        if self.family == "openai" && action == "force" {
            config.gpt_force_approved_v1.push(key.clone());
        }
        config.policy_actions.insert(key, action.into());
        self.store.atomic_json(&self.store.paths.config(), &config.value().unwrap()).unwrap();
    }
    fn locked(&self, code: &str) -> Session {
        let mut audit = json!({"ready":true,"observed_at":1000.,"expires_at":1030.,
            "context_id":"fixture","context_transition":{"state":"stable"},
            "egress_reference":{"ip":"1.1.1.1","country":"JP","checked_at":1000.,"context":"fixture"}});
        if self.family == "openai" {
            audit["launch_target"] = json!("codex-desktop");
            audit["authorization_scope"] = json!("observation");
        }
        let mut value = session::begin(&audit, &exit(1000., "1.1.1.1"), &json!({"state":"unknown"}),
            &uuid::Uuid::new_v4().to_string(), 1000.).unwrap();
        value.state = Phase::Active;
        value.desktop = Some(desktop()); value.bound_at = Some(1000.);
        value.extra.insert("baseline_dns_countries".into(), json!(["JP"]));
        value.extra.insert("baseline_webrtc_addresses".into(), json!(["1.1.1.1"]));
        let value = session::lock(value, code, "fixture warning", 1001., None, None);
        self.save(&value);
        value
    }
    fn save(&self, value: &Session) {
        self.store.atomic_json(&self.store.paths.session_for(self.family), &serde_json::to_value(value).unwrap()).unwrap();
    }
    fn raw(&self) -> Vec<u8> { fs::read(self.store.paths.session_for(self.family)).unwrap() }
    fn probes(&self, dns_time: f64, rtc_time: f64, context: &str) {
        self.store.atomic_json(&self.store.paths.base().join("dns-leak-receipt.json"),
            &json!({"status":"complete","finished_at":dns_time,"context":context,"dns":{"countries":["JP"]}})).unwrap();
        self.store.atomic_json(&self.store.paths.base().join("webrtc-risk-receipt.json"),
            &json!({"status":"complete","sampled_at":rtc_time,"context_id":context,
                "observations":[{"kind":"srflx","address":"1.1.1.1"}]})).unwrap();
    }
    fn recover(&self, system: &mut Mock, expected: &Session) -> Value {
        let mut receipt = json!({"action":"observe","stop_state":"skipped_warn_only"});
        self.controller.resume_warning(system, &self.sessions(), self.family, expected, &mut receipt).unwrap();
        assert_eq!((system.closes, system.forces), (0, 0));
        receipt
    }
    fn tick(&self, system: &mut Mock) -> Value {
        self.controller
            .guard_tick_family(system, self.family, true)
            .unwrap()
            .into_value()
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.home); } }
fn desktop() -> Desktop { Desktop { pid:77, start_seconds:900, start_microseconds:1 } }
fn exit(at: f64, ip: &str) -> Value { json!({"ip":ip,"country":"JP","observed_at":at,"source":"fixture"}) }
struct Mock {
    target: LaunchTarget, now: f64, local: Value, egress: Value,
    main: Option<Desktop>, backend: bool, closes: usize, forces: usize, reads: usize,
    on_egress: Option<Box<dyn FnOnce()>>,
    change_second_main: bool,
}
impl Mock {
    fn new(family: &str) -> Self {
        Self { target: if family == "openai" { LaunchTarget::CodexDesktop } else { LaunchTarget::ClaudeDesktop },
            now:1003., local:json!({"proxy":"ok","tun":"ok"}), egress:exit(1003., "1.1.1.1"),
            main:Some(desktop()), backend:true, closes:0, forces:0, reads:0,
            on_egress:None, change_second_main:false }
    }
}
impl DesktopSystem for Mock {
    fn channel_mode(&self) -> bool { false }
    fn launch_target(&self) -> LaunchTarget { self.target }
    fn now(&self) -> f64 { self.now }
    fn monotonic(&self) -> Duration { Duration::from_secs_f64(self.now) }
    fn wait(&mut self, d: Duration) { self.now += d.as_secs_f64(); }
    fn desktops(&mut self) -> Result<Vec<(Desktop, bool, String)>> {
        self.reads += 1;
        if self.change_second_main && self.reads == 2 { self.main = None; }
        Ok(self.main.clone().into_iter().map(|d| (d, true, "fixture".into())).collect())
    }
    fn desktop_alive(&mut self, value: &Desktop) -> Result<bool> { Ok(self.main.as_ref() == Some(value)) }
    fn desktop_tree_running(&mut self) -> Result<bool> { Ok(self.main.is_some()) }
    fn launcher(&mut self) -> Result<Launcher> { panic!("no launch in this fixture") }
    fn full_audit(&mut self) -> Result<Value> { panic!("no audit or network in this fixture") }
    fn egress(&mut self) -> Value {
        if let Some(change) = self.on_egress.take() { change(); }
        self.egress.clone()
    }
    fn local_guard(&mut self) -> Result<Value> { Ok(self.local.clone()) }
    fn backend_healthy(&mut self) -> Result<bool> { Ok(self.backend) }
    fn launcher_matches(&mut self, _: &Launcher) -> Result<bool> { Ok(true) }
    fn open_desktop(&mut self) -> Result<()> { panic!("no application may be opened") }
    fn quit_desktop(&mut self) -> Result<()> { self.closes += 1; Ok(()) }
    fn quit_for_confirmed_ip_risk(&mut self, forced: &mut Option<u32>) -> Result<()> {
        self.forces += 1; *forced = Some(1); Ok(())
    }
}

#[test]
fn unreadable_policy_never_invents_stop_authority_or_changes_session() {
    for family in ["claude", "openai"] {
        for action in ["warn", "close", "force"] {
            let f = Fixture::new(family); f.policy("session", action);
            f.locked("guard_sampling_failed"); let before = f.raw();
            fs::write(f.store.paths.config(), b"{broken").unwrap();
            let mut system = Mock::new(family);
            for at in [1003., 1020., 1500.] {
                system.now = at;
                let receipt = f.tick(&mut system);
                assert_eq!(receipt["status"], "unknown"); assert_eq!(receipt["action"], "observe");
                assert_eq!(receipt["policy_state"], "unavailable");
                assert_eq!(receipt["stop_state"], "skipped_warn_only");
                assert!(receipt["code"].is_string()); assert_eq!(f.raw(), before);
            }
            assert_eq!((system.closes, system.forces, system.reads), (0, 0, 0));
            assert!(!f.store.paths.base().join("last-guard-stop.json").exists());
        }
    }
}
#[test]
fn corrupt_policy_and_session_are_left_intact_without_a_stop() {
    let f = Fixture::new("openai"); f.locked("guard_sampling_failed");
    fs::write(f.store.paths.session_for(f.family), b"{broken-session").unwrap();
    fs::write(f.store.paths.config(), b"{broken-config").unwrap();
    let mut system = Mock::new(f.family); let receipt = f.tick(&mut system);
    assert_eq!(receipt["policy_state"], "unavailable"); assert_eq!(system.closes+system.forces, 0);
    assert_eq!(f.raw(), b"{broken-session");
}
#[test]
fn unreadable_policy_at_final_gate_preserves_pending_risk_for_later() {
    let f = Fixture::new("openai"); let session = f.locked("egress_country_cn");
    f.policy("cn", "force"); f.controller.remember_risk(f.family, Some(&session.session_id), "egress_country_cn").unwrap();
    let good = fs::read(f.store.paths.config()).unwrap();
    fs::write(f.store.paths.config(), b"{broken").unwrap();
    let mut system = Mock::new(f.family);
    let mut receipt = json!({"session_id":session.session_id,"persistence_risk_code":"egress_country_cn",
        "session_guard":{"reason":{"code":"egress_risk_persist_failed"}}});
    assert_eq!(f.controller.timed_guard_quit(&mut system, &mut receipt).unwrap(), StopOutcome::SkippedWarn);
    assert_eq!(receipt["policy_state"], "unavailable"); assert!(receipt["policy_error"].is_string());
    assert!(f.controller.pending_risk(f.family, Some(&session.session_id)).unwrap().is_some());
    assert_eq!(system.closes+system.forces, 0);
    fs::write(f.store.paths.config(), good).unwrap();
    assert_eq!(f.tick(&mut system)["stop_action"], "force"); assert_eq!(system.forces, 1);
}
#[test]
fn disabling_guard_or_policy_before_execution_revokes_stop_authority() {
    for key in ["enabled", "guard_enabled"] {
        let f = Fixture::new("openai"); f.policy("cn", "force");
        let mut value = ConfigStore { storage:f.store.clone() }.load().unwrap().value().unwrap();
        value[key] = json!(false); f.store.atomic_json(&f.store.paths.config(), &value).unwrap();
        let mut system = Mock::new(f.family);
        let mut receipt = json!({"session_guard":{"reason":{"code":"egress_country_cn"}}});
        assert_eq!(f.controller.timed_guard_quit(&mut system, &mut receipt).unwrap(), StopOutcome::SkippedWarn);
        assert_eq!(system.closes+system.forces, 0);
    }
}
#[test]
fn valid_explicit_actions_remain_distinct() {
    for (action, closes, forces) in [("warn",0,0), ("close",1,0), ("force",0,1)] {
        let f = Fixture::new("openai"); f.policy("cn", action); let mut system = Mock::new(f.family);
        let mut receipt = json!({"session_guard":{"reason":{"code":"egress_country_cn"}}});
        f.controller.timed_guard_quit(&mut system, &mut receipt).unwrap();
        assert_eq!(receipt["stop_action"], action); assert_eq!((system.closes,system.forces),(closes,forces));
    }
}
#[test]
fn healthy_probes_do_not_recover_a_failed_or_unknown_proxy() {
    for state in ["fail", "unknown"] {
        let f = Fixture::new("openai"); let session = f.locked("proxy_or_tun_failed");
        f.probes(1002.,1002.,"fixture"); let before = f.raw(); let mut system = Mock::new(f.family);
        system.local["proxy"] = json!(state);
        assert_ne!(f.tick(&mut system)["stop_state"], "recovered");
        assert_eq!(f.raw(),before); assert_eq!(system.closes+system.forces,0);
        assert_ne!(f.recover(&mut system,&session)["stop_state"], "recovered");
    }
}
#[test]
fn local_warning_recovers_from_verified_local_state_without_probe_substitution() {
    for family in ["claude","openai"] {
        let f = Fixture::new(family); let session = f.locked("proxy_or_tun_unconfirmed");
        let mut system = Mock::new(family);
        assert_eq!(f.tick(&mut system)["stop_state"], "recovered");
        let value = f.sessions().load(system.now).unwrap().unwrap();
        assert_eq!(value.state,Phase::Active); assert_eq!(value.baseline,session.baseline);
        assert_eq!(value.extra["baseline_dns_countries"],session.extra["baseline_dns_countries"]);
        assert_eq!(system.closes+system.forces,0);
    }
}
#[test]
fn healthy_probes_cannot_substitute_for_the_expected_main_identity() {
    let f = Fixture::new("openai"); let session = f.locked("session_identity_unconfirmed");
    f.probes(1002.,1002.,"fixture"); let before = f.raw();
    for main in [None,Some(Desktop { pid:78, ..desktop() })] {
        let mut system = Mock::new(f.family); system.main = main;
        assert_ne!(f.recover(&mut system,&session)["stop_state"], "recovered"); assert_eq!(f.raw(),before);
    }
    let mut system=Mock::new(f.family);
    assert_eq!(f.recover(&mut system,&session)["stop_state"], "recovered");
}
#[test]
fn unhealthy_guard_or_stale_or_changed_http_exit_blocks_recovery() {
    for case in ["backend","stale","changed","cn","before-warning"] {
        let f = Fixture::new("openai"); let session=f.locked("proxy_or_tun_failed"); let before=f.raw();
        let mut system=Mock::new(f.family);
        match case {
            "backend" => system.backend=false,
            "stale" => system.egress=exit(980.,"1.1.1.1"),
            "changed" => system.egress=exit(1003.,"8.8.8.8"),
            "cn" => system.egress["country"]=json!("CN"),
            _ => system.egress=exit(1000.,"1.1.1.1"),
        }
        assert_ne!(f.recover(&mut system,&session)["stop_state"], "recovered", "{case}"); assert_eq!(f.raw(),before);
    }
}
#[test]
fn creation_revalidation_and_unknown_reasons_are_not_blessed_by_safe_probes() {
    for code in ["session_missing","session_pending","launch_failed","revalidation_timeout",
        "revalidation_context_changed","session_state_invalid","dns_risk","network_leak_risk","unmapped"] {
        let f=Fixture::new("openai"); let session=f.locked(code); f.probes(1002.,1002.,"fixture");
        let before=f.raw(); let mut system=Mock::new(f.family);
        assert_ne!(f.recover(&mut system,&session)["stop_state"],"recovered", "{code}"); assert_eq!(f.raw(),before);
    }
}
#[test]
fn one_recovered_probe_does_not_require_an_unrelated_missing_probe() {
    for (code,dns_at,rtc_at) in [("dns_egress_changed",1002.,0.),("webrtc_egress_changed",0.,1002.)] {
        let f=Fixture::new("openai"); let session=f.locked(code); f.probes(dns_at,rtc_at,"fixture");
        let mut system=Mock::new(f.family);
        assert_eq!(f.recover(&mut system,&session)["stop_state"],"recovered");
    }
}
#[test]
fn combined_drift_recovery_needs_both_sources_and_post_warning_context() {
    for (dns_at,rtc_at,context) in [(1002.,0.,"fixture"),(0.,1002.,"fixture"),
        (1000.,1002.,"fixture"),(1002.,1000.,"fixture"),(1002.,1002.,"other")] {
        let f=Fixture::new("openai"); let session=f.locked("dns_and_webrtc_egress_changed");
        f.probes(dns_at,rtc_at,context); let before=f.raw(); let mut system=Mock::new(f.family);
        assert_ne!(f.recover(&mut system,&session)["stop_state"],"recovered"); assert_eq!(f.raw(),before);
    }
    let f=Fixture::new("openai"); let session=f.locked("dns_and_webrtc_egress_changed");
    f.probes(1002.,1002.,"fixture"); let mut system=Mock::new(f.family);
    assert_eq!(f.recover(&mut system,&session)["stop_state"],"recovered");
}
#[test]
fn a_newer_session_reason_or_checkpoint_cannot_be_cleared_by_recovery() {
    for case in ["replacement","new-reason","checkpoint"] {
        let f=Fixture::new("openai"); let session=f.locked("dns_egress_changed"); f.probes(1002.,1002.,"fixture");
        let mut newer=session.clone();
        match case {
            "replacement" => newer.session_id=uuid::Uuid::new_v4().to_string(),
            "new-reason" => newer=session::lock(newer,"egress_country_cn","new risk",1003.,None,None),
            _ => { newer.extra.insert("guard_checked_at".into(),json!(1004.)); }
        }
        let store=f.store.clone(); let expected_newer=newer.clone(); let family=f.family;
        let mut system=Mock::new(f.family);
        system.on_egress=Some(Box::new(move || {
            store.atomic_json(&store.paths.session_for(family), &serde_json::to_value(newer).unwrap()).unwrap();
        }));
        assert_eq!(f.recover(&mut system,&session)["stop_state"],"session_changed");
        assert_eq!(f.sessions().load(1005.).unwrap().unwrap(),expected_newer);
    }
}
#[test]
fn changed_policy_or_receipt_during_recovery_cannot_unlock_the_old_snapshot() {
    for policy in [false,true] {
        let f=Fixture::new("openai"); let session=f.locked("dns_egress_changed"); f.probes(1002.,1002.,"fixture");
        let before=f.raw(); let store=f.store.clone(); let mut system=Mock::new(f.family);
        system.on_egress=Some(Box::new(move || {
            if policy {
                let mut config=ConfigStore{storage:store.clone()}.load().unwrap().value().unwrap();
                config["gpt_close_dns"]=json!("force");
                config["gpt_force_approved_v1"]=json!(["gpt_close_dns"]);
                store.atomic_json(&store.paths.config(), &config).unwrap();
            } else {
                store.atomic_json(&store.paths.base().join("dns-leak-receipt.json"),
                    &json!({"finished_at":1003.,"context":"fixture","dns":{"countries":["US"]}})).unwrap();
            }
        }));
        assert_eq!(f.recover(&mut system,&session)["stop_state"],"session_changed"); assert_eq!(f.raw(),before);
    }
}
#[test]
fn identity_is_rechecked_at_the_recovery_commit_boundary() {
    let f=Fixture::new("openai"); let session=f.locked("session_identity_unconfirmed");
    let before=f.raw(); let mut system=Mock::new(f.family); system.change_second_main=true;
    assert_eq!(f.recover(&mut system,&session)["stop_state"],"session_changed"); assert_eq!(f.raw(),before);
}
#[test]
fn dns_force_still_applies_when_webrtc_is_unavailable_in_a_warning_round() {
    let f=Fixture::new("openai"); f.policy("dns","force"); f.locked("egress_ip_changed");
    f.store.atomic_json(&f.store.paths.base().join("dns-leak-receipt.json"),
        &json!({"finished_at":1002.,"dns":{"countries":["US"]}})).unwrap();
    let mut system=Mock::new(f.family); system.egress=exit(1003.,"8.8.8.8");
    let result=f.tick(&mut system);
    assert_eq!(result["stop_action"],"force"); assert_eq!(result["stop_reason_code"],"dns_egress_changed");
    assert_eq!((system.closes,system.forces),(0,1));
}
