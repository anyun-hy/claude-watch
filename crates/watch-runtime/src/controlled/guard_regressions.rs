//! No-signal guard regressions. Only a private temporary home and a mock
//! DesktopSystem are used: no native helper, network or child process runs.
use super::*;
use claude_watch_core::{config::Config, session::{Phase, Session}};
use crate::storage::Paths;
use std::{fs, path::PathBuf};

struct Fixture {
    home: PathBuf,
    storage: StateStore,
    controller: Controller,
    family: &'static str,
}
impl Fixture {
    fn new(family: &'static str, actions: &[(&str, &str)]) -> Self {
        let home = std::env::temp_dir().join(format!("cw-guard-disposition-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        let storage = StateStore::new(Paths::new(&home).unwrap());
        let mut config = Config { guard_enabled: true, ..Default::default() };
        for (key, value) in actions {
            config.policy_actions.insert((*key).into(), (*value).into());
            if key.starts_with("gpt_close_") && *value == "force" {
                config.gpt_force_approved_v1.push((*key).into());
            }
        }
        storage.atomic_json(&storage.paths.config(), &config.value().unwrap()).unwrap();
        Self { controller: Controller::new(storage.clone()), home, storage, family }
    }
    fn active(&self) -> Session {
        let now = 1000.0;
        let mut audit = json!({"ready":true,"observed_at":now,"expires_at":now+30.0,
            "context_id":"fixture-context","observation_id":"fixture-round",
            "context_transition":{"state":"stable"},
            "egress_reference":{"ip":"1.1.1.1","country":"JP","checked_at":now,
                "context":"fixture-context","source":"fixture"}});
        if self.family == "openai" {
            audit["launch_target"] = json!("codex-desktop");
            audit["authorization_scope"] = json!("observation");
        }
        let exit = json!({"ip":"1.1.1.1","country":"JP","observed_at":now,"source":"fixture"});
        let mut value = session::begin(&audit, &exit, &json!({"state":"unknown"}),
            &uuid::Uuid::new_v4().to_string(), now).unwrap();
        value.state = Phase::Active;
        value.desktop = Some(Desktop { pid: 77, start_seconds: 900, start_microseconds: 1 });
        value.bound_at = Some(now);
        value.extra.insert("baseline_dns_countries".into(), json!(["JP"]));
        value.extra.insert("baseline_webrtc_addresses".into(), json!(["1.1.1.1"]));
        self.save(&value);
        value
    }
    fn locked(&self, code: &str) -> Session {
        let value = session::lock(self.active(), code, "fixture finding", 1001.0, None, None);
        self.save(&value);
        value
    }
    fn save(&self, session: &Session) {
        self.storage.atomic_json(&self.storage.paths.session_for(self.family),
            &serde_json::to_value(session).unwrap()).unwrap();
    }
    fn load(&self) -> Session {
        SessionStore::for_family(self.storage.clone(), self.family).load(1003.0).unwrap().unwrap()
    }
    fn probes(&self, country: &str, rtc: &str) {
        self.storage.atomic_json(&self.storage.paths.base().join("dns-leak-receipt.json"),
            &json!({"status":"complete","finished_at":1002.0,"context":"fixture-context",
                "dns":{"countries":[country]}})).unwrap();
        self.storage.atomic_json(&self.storage.paths.base().join("webrtc-risk-receipt.json"),
            &json!({"status":"complete","sampled_at":1002.0,"context_id":"fixture-context",
                "observations":[{"kind":"srflx","address":rtc}]})).unwrap();
    }
    fn tick(&self, system: &mut Mock) -> Value {
        self.controller
            .guard_tick_family(system, self.family, true)
            .unwrap()
            .into_value()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.home); }
}

struct Mock {
    target: LaunchTarget,
    now: f64,
    running: bool,
    ip: &'static str,
    country: &'static str,
    age: f64,
    closes: usize,
    forces: usize,
    egress_calls: usize,
    fail_quit: bool,
    replace_on_egress: Option<(StateStore, &'static str, Session)>,
    config_on_egress: Option<(StateStore, Value)>,
}
impl Mock {
    fn new(family: &str) -> Self {
        Self {
            target: if family == "openai" { LaunchTarget::CodexDesktop } else { LaunchTarget::ClaudeDesktop },
            now: 1002.0, running: true, ip: "1.1.1.1", country: "JP", age: 0.0,
            closes: 0, forces: 0, egress_calls: 0, fail_quit: false,
            replace_on_egress: None, config_on_egress: None,
        }
    }
}
impl DesktopSystem for Mock {
    fn channel_mode(&self) -> bool { false }
    fn launch_target(&self) -> LaunchTarget { self.target }
    fn set_family(&mut self, family: &str) -> Result<()> {
        self.target = PolicyCatalog::family(family).and_then(PolicyCatalog::guard_target)
            .ok_or_else(|| CoreError::new("unknown_family", "fixture"))?;
        Ok(())
    }
    fn now(&self) -> f64 { self.now }
    fn monotonic(&self) -> Duration { Duration::from_secs_f64(self.now) }
    fn wait(&mut self, duration: Duration) { self.now += duration.as_secs_f64(); }
    fn desktops(&mut self) -> Result<Vec<(Desktop, bool, String)>> {
        Ok(if self.running {
            vec![(Desktop { pid:77, start_seconds:900, start_microseconds:1 }, true, "fixture-start".into())]
        } else { vec![] })
    }
    fn desktop_alive(&mut self, expected: &Desktop) -> Result<bool> {
        Ok(self.running && expected.pid == 77 && expected.start_seconds == 900 && expected.start_microseconds == 1)
    }
    fn desktop_tree_running(&mut self) -> Result<bool> { Ok(self.running) }
    fn launcher(&mut self) -> Result<Launcher> { Ok(Launcher { pid:88, start:"fixture-owner".into() }) }
    fn full_audit(&mut self) -> Result<Value> { panic!("these tests never launch or adopt an application") }
    fn egress(&mut self) -> Value {
        self.egress_calls += 1;
        if let Some((storage, family, value)) = self.replace_on_egress.take() {
            storage.atomic_json(&storage.paths.session_for(family), &serde_json::to_value(value).unwrap()).unwrap();
        }
        if let Some((storage, value)) = self.config_on_egress.take() {
            storage.atomic_json(&storage.paths.config(), &value).unwrap();
        }
        json!({"ip":self.ip,"country":self.country,"observed_at":self.now-self.age,"source":"fixture"})
    }
    fn local_guard(&mut self) -> Result<Value> {
        Ok(json!({"proxy":"ok","tun":"ok","guard_backend_healthy":true}))
    }
    fn backend_healthy(&mut self) -> Result<bool> { Ok(true) }
    fn launcher_matches(&mut self, _: &Launcher) -> Result<bool> { Ok(true) }
    fn open_desktop(&mut self) -> Result<()> { panic!("no real application may be opened") }
    fn quit_desktop(&mut self) -> Result<()> {
        self.closes += 1;
        if self.fail_quit { return Err(CoreError::new("fixture_quit_failed", "fixture")); }
        self.running = false;
        Ok(())
    }
    fn quit_for_confirmed_ip_risk(&mut self, forced: &mut Option<u32>) -> Result<()> {
        self.forces += 1;
        *forced = Some(1);
        if self.fail_quit { return Err(CoreError::new("fixture_quit_failed", "fixture")); }
        self.running = false;
        Ok(())
    }
}

#[test]
fn warn_returns_a_distinct_outcome_without_requesting_a_stop() {
    let f = Fixture::new("openai", &[("gpt_close_dns", "warn")]);
    let mut system = Mock::new("openai");
    let mut receipt = json!({"session_guard":{"reason":{"code":"dns_egress_changed"}}});
    assert_eq!(f.controller.timed_guard_quit(&mut system, &mut receipt).unwrap(), StopOutcome::SkippedWarn);
    assert_eq!(receipt["action"], "observe");
    assert_eq!(receipt["stop_state"], "skipped_warn_only");
    assert!(receipt["stop_completed_at"].is_number());
    assert_eq!((system.closes, system.forces), (0, 0));
}

#[test]
fn corrupt_session_warn_is_not_relabelled_as_a_successful_close() {
    let f = Fixture::new("openai", &[("gpt_close_session", "warn")]);
    f.active();
    fs::write(f.storage.paths.session_for("openai"), b"{corrupt").unwrap();
    let mut system = Mock::new("openai");
    let receipt = f.tick(&mut system);
    assert_eq!(receipt["action"], "observe");
    assert_eq!(receipt["stop_state"], "skipped_warn_only");
    assert_eq!((system.closes, system.forces), (0, 0));
    assert!(!f.storage.paths.base().join("last-guard-stop.json").exists());
}

#[test]
fn a_failed_ip_write_cannot_borrow_force_from_the_cn_policy() {
    for action in ["warn", "close"] {
        let f = Fixture::new("openai", &[("gpt_close_ip", action), ("gpt_close_cn", "force")]);
        let session = f.active();
        f.controller.remember_risk("openai", Some(&session.session_id), "egress_ip_changed").unwrap();
        let mut system = Mock::new("openai");
        let receipt = f.tick(&mut system);
        assert_eq!(receipt["stop_action"], action);
        assert_eq!(receipt["stop_reason_code"], "egress_ip_changed");
        assert_eq!(system.forces, 0);
        assert_eq!(system.closes, usize::from(action == "close"));
        if action == "warn" {
            assert_eq!(receipt["stop_state"], "skipped_warn_only");
            assert_eq!(receipt["action"], "observe");
            assert!(f.controller.pending_risk("openai", Some(&session.session_id)).unwrap().is_none());
            // A skipped persistence stop must not mask the next confirmed CN exit.
            system.country = "CN";
            system.now += 1.0;
            let next = f.tick(&mut system);
            assert_eq!(next["stop_action"], "force");
            assert_eq!(system.forces, 1);
        }
    }
}

#[test]
fn a_confirmed_cn_write_failure_keeps_its_own_force_action() {
    let f = Fixture::new("openai", &[("gpt_close_ip", "warn"), ("gpt_close_cn", "force")]);
    let session = f.active();
    f.controller.remember_risk("openai", Some(&session.session_id), "egress_country_cn").unwrap();
    let mut system = Mock::new("openai");
    let receipt = f.tick(&mut system);
    assert_eq!(receipt["stop_action"], "force");
    assert_eq!(receipt["stop_reason_code"], "egress_country_cn");
    assert_eq!((system.closes, system.forces), (0, 1));
}

#[test]
fn a_persistence_error_without_an_original_reason_cannot_authorise_force() {
    let f = Fixture::new("claude", &[]);
    let mut system = Mock::new("claude");
    let mut receipt = json!({"session_guard":{"reason":{"code":"egress_risk_persist_failed"}}});
    assert_eq!(f.controller.timed_guard_quit(&mut system, &mut receipt).unwrap(), StopOutcome::SkippedWarn);
    assert_eq!((system.closes, system.forces), (0, 0));
}

#[test]
fn persistence_latches_never_cross_family_or_session_boundaries() {
    let f = Fixture::new("openai", &[]);
    f.controller.remember_risk("openai", Some("old-openai"), "egress_ip_changed").unwrap();
    f.controller.remember_risk("claude", Some("claude"), "egress_country_cn").unwrap();
    assert!(f.controller.pending_risk("openai", Some("replacement")).unwrap().is_none());
    assert_eq!(f.controller.pending_risk("claude", Some("claude")).unwrap().unwrap().code, "egress_country_cn");
    assert!(f.controller.pending_risk("openai", None).unwrap().is_none());
}

#[test]
fn dns_warn_does_not_hide_a_new_confirmed_cn_force() {
    let f = Fixture::new("openai", &[("gpt_close_dns", "warn"), ("gpt_close_cn", "force")]);
    f.locked("dns_egress_changed");
    f.probes("US", "1.1.1.1");
    let mut system = Mock::new("openai");
    system.country = "CN";
    let receipt = f.tick(&mut system);
    assert_eq!(receipt["session_guard"]["reason"]["code"], "egress_country_cn");
    assert_eq!(receipt["stop_state"], "confirmed");
    assert_eq!(receipt["stop_action"], "force");
    assert_eq!((system.closes, system.forces), (0, 1));
    assert_eq!(f.load().reason.unwrap().code, "egress_country_cn");
}

#[test]
fn ip_warn_does_not_hide_an_independent_dns_force() {
    let f = Fixture::new("openai", &[("gpt_close_ip", "warn"), ("gpt_close_dns", "force")]);
    f.locked("egress_ip_changed");
    f.probes("US", "1.1.1.1");
    let mut system = Mock::new("openai");
    system.ip = "8.8.8.8";
    let receipt = f.tick(&mut system);
    assert_eq!(receipt["session_guard"]["reason"]["code"], "dns_egress_changed");
    assert_eq!(receipt["stop_action"], "force");
    assert_eq!(system.forces, 1);
}

#[test]
fn warn_only_rows_remain_non_terminating_on_later_rounds() {
    let f = Fixture::new("openai", &[("gpt_close_ip", "warn"), ("gpt_close_cn", "warn"),
        ("gpt_close_dns", "warn"), ("gpt_close_webrtc", "warn")]);
    f.locked("dns_egress_changed");
    f.probes("US", "8.8.8.8");
    let mut system = Mock::new("openai");
    system.ip = "8.8.4.4";
    system.country = "CN";
    for _ in 0..2 {
        let receipt = f.tick(&mut system);
        assert_eq!(receipt["action"], "observe");
        assert_eq!(receipt["stop_state"], "skipped_warn_only");
        system.now += 1.0;
    }
    assert_eq!((system.closes, system.forces), (0, 0));
    assert!(system.running);
}

#[test]
fn stale_exit_does_not_invent_an_actionable_risk() {
    let f = Fixture::new("openai", &[("gpt_close_dns", "warn"), ("gpt_close_cn", "force")]);
    f.locked("dns_egress_changed");
    f.probes("US", "1.1.1.1");
    let mut system = Mock::new("openai");
    system.country = "CN";
    system.age = 20.0;
    let receipt = f.tick(&mut system);
    assert_eq!(receipt["stop_state"], "skipped_warn_only");
    assert_eq!((system.closes, system.forces), (0, 0));
}

#[test]
fn a_replacement_session_during_warning_sampling_is_never_stopped() {
    let f = Fixture::new("openai", &[("gpt_close_dns", "warn"), ("gpt_close_cn", "force")]);
    let mut replacement = f.locked("dns_egress_changed");
    replacement.session_id = uuid::Uuid::new_v4().to_string();
    replacement.state = Phase::Active;
    replacement.reason = None;
    replacement.locked_at = None;
    let replacement_id = replacement.session_id.clone();
    let mut system = Mock::new("openai");
    system.country = "CN";
    system.replace_on_egress = Some((f.storage.clone(), "openai", replacement));
    let receipt = f.tick(&mut system);
    assert_eq!(receipt["stop_state"], "session_changed");
    assert_eq!((system.closes, system.forces), (0, 0));
    assert_eq!(f.load().session_id, replacement_id);
}

#[test]
fn changed_policy_during_warning_sampling_is_not_overwritten() {
    let f = Fixture::new("openai", &[("gpt_close_dns", "warn"), ("gpt_close_cn", "force")]);
    f.locked("dns_egress_changed");
    let mut config = ConfigStore { storage: f.storage.clone() }.load().unwrap().value().unwrap();
    config["gpt_close_cn"] = json!("warn");
    let mut system = Mock::new("openai");
    system.country = "CN";
    system.config_on_egress = Some((f.storage.clone(), config));
    let receipt = f.tick(&mut system);
    assert_eq!(receipt["stop_state"], "session_changed");
    assert_eq!((system.closes, system.forces), (0, 0));
    assert_eq!(f.load().reason.unwrap().code, "dns_egress_changed");
}

#[test]
fn a_failed_escalated_stop_stays_latched_until_the_target_exits() {
    let f = Fixture::new("openai", &[("gpt_close_dns", "warn"), ("gpt_close_cn", "force")]);
    f.locked("dns_egress_changed");
    let mut system = Mock::new("openai");
    system.country = "CN";
    system.fail_quit = true;
    let first = f.tick(&mut system);
    assert_eq!(first["stop_state"], "failed");
    assert_eq!(f.load().reason.unwrap().code, "egress_country_cn");
    let calls = system.egress_calls;
    system.country = "JP";
    system.fail_quit = false;
    system.now += 1.0;
    let second = f.tick(&mut system);
    assert_eq!(second["stop_state"], "confirmed");
    assert_eq!(system.forces, 2);
    assert_eq!(system.egress_calls, calls, "a mandatory stop must not be erased by a newer safe sample");
}

#[test]
fn original_egress_reason_is_exact_and_requires_fresh_evidence() {
    let f = Fixture::new("openai", &[]);
    let mut session = f.active();
    let changed = json!({"ip":"8.8.8.8","country":"JP","observed_at":1002.0});
    assert_eq!(confirmed_egress_code(&session, &changed, 1002.0), Some("egress_ip_changed"));
    let cn = json!({"ip":"8.8.8.8","country":"CN","observed_at":1002.0});
    assert_eq!(confirmed_egress_code(&session, &cn, 1002.0), Some("egress_country_cn"));
    assert_eq!(confirmed_egress_code(&session, &cn, 1020.0), None);
    session.state = Phase::Rechecking;
    session.created_at = 1003.0;
    assert_eq!(confirmed_egress_code(&session, &cn, 1003.0), None);
    session.created_at = 1001.0;
    session.extra.insert("recheck_baseline_pending".into(), json!(true));
    assert_eq!(confirmed_egress_code(&session, &changed, 1002.0), None);
}

#[test]
fn a_later_guard_checkpoint_cannot_be_replaced_by_an_older_warning_sample() {
    let f = Fixture::new("openai", &[("gpt_close_dns", "warn"), ("gpt_close_cn", "force")]);
    let mut session = f.locked("dns_egress_changed");
    session.extra.insert("guard_checked_at".into(), json!(1005.0));
    f.save(&session);
    let mut system = Mock::new("openai");
    system.country = "CN";
    let receipt = f.tick(&mut system);
    assert_eq!(receipt["stop_state"], "session_changed");
    assert_eq!((system.closes, system.forces), (0, 0));
    assert_eq!(f.load().extra["guard_checked_at"], json!(1005.0));
}

#[test]
fn a_post_stop_log_failure_does_not_turn_an_actual_stop_into_a_warning() {
    let f = Fixture::new("openai", &[("gpt_close_dns", "warn"), ("gpt_close_cn", "force")]);
    f.locked("dns_egress_changed");
    fs::create_dir(f.storage.paths.base().join("last-guard-stop.json")).unwrap();
    let mut system = Mock::new("openai");
    system.country = "CN";
    let receipt = f.tick(&mut system);
    assert_eq!(receipt["action"], "close-desktop");
    assert_eq!(receipt["stop_state"], "confirmed");
    assert!(receipt["stop_log_error"].is_string());
    assert_eq!(system.forces, 1);
}
