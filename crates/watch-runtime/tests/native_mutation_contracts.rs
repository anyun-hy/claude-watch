use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
};
use claude_watch_runtime::{
    macos::Mutator,
    macos_mutations::{
        AdminCommand, DefaultsCommand, FixedMacosMutator, MutationRunner, StateRead,
    },
    repair,
};
use serde_json::{json, Value};

#[derive(Default)]
struct FakeRunner {
    timezone: Value,
    locale: Value,
    languages: Value,
    ipv6: Value,
    watchdog: Value,
    updater: Value,
    calls: Vec<String>,
    fail: bool,
    write_changes_state: bool,
}

impl FakeRunner {
    fn fail_if_requested(&self) -> Result<()> {
        if self.fail {
            Err(CoreError::new("fake_failure", "injected failure"))
        } else {
            Ok(())
        }
    }

    fn record(&mut self, call: &str) {
        self.calls.push(call.into());
    }
}

impl MutationRunner for FakeRunner {
    fn admin(&mut self, command: AdminCommand) -> Result<()> {
        self.fail_if_requested()?;
        match command {
            AdminCommand::Timezone(v) => {
                if self.write_changes_state {
                    self.timezone = json!(v);
                }
                self.record("timezone");
            }
            AdminCommand::Ipv6Off(_) => {
                if self.write_changes_state {
                    self.ipv6 = json!("off");
                }
                self.record("ipv6-off");
            }
            AdminCommand::Ipv6Automatic(_) => {
                if self.write_changes_state {
                    self.ipv6 = json!("automatic");
                }
                self.record("ipv6-auto");
            }
            AdminCommand::FlushDns => self.record("flush-dns"),
            AdminCommand::Watchdog(v) => {
                if self.write_changes_state {
                    self.watchdog = json!(v);
                }
                self.record("watchdog");
            }
            AdminCommand::Status => self.record("status"),
            AdminCommand::LegacyStop => self.record("legacy-stop"),
            AdminCommand::Uninstall => self.record("uninstall"),
        }
        Ok(())
    }

    fn defaults(&mut self, command: DefaultsCommand) -> Result<()> {
        self.fail_if_requested()?;
        match command {
            DefaultsCommand::Locale(v) => {
                if self.write_changes_state {
                    self.locale = json!(v);
                }
                self.record("locale");
            }
            DefaultsCommand::Languages(v) => {
                if self.write_changes_state {
                    self.languages = json!(v);
                }
                self.record("languages");
            }
            DefaultsCommand::DeleteLanguages => {
                if self.write_changes_state {
                    self.languages = Value::Null;
                }
                self.record("delete-languages");
            }
        }
        Ok(())
    }

    fn updater(&mut self, enabled: bool) -> Result<()> {
        self.fail_if_requested()?;
        if self.write_changes_state {
            self.updater = json!(enabled);
        }
        self.record("updater");
        Ok(())
    }

    fn read(&mut self, state: StateRead) -> Result<Value> {
        Ok(match state {
            StateRead::Timezone => self.timezone.clone(),
            StateRead::Locale => self.locale.clone(),
            StateRead::Languages => self.languages.clone(),
            StateRead::Ipv6(_) => self.ipv6.clone(),
            StateRead::Watchdog => self.watchdog.clone(),
            StateRead::Updater => self.updater.clone(),
        })
    }
}

fn mutator(runner: FakeRunner) -> FixedMacosMutator<FakeRunner> {
    FixedMacosMutator::with_runner(runner)
}

#[test]
fn applies_only_fixed_action_shapes_and_restores_exact_original_values() {
    let runner = FakeRunner {
        timezone: json!("America/New_York"),
        locale: json!("en_US"),
        languages: json!(["zh-CN", "en-US"]),
        ipv6: json!("automatic"),
        watchdog: Value::Null,
        updater: json!(false),
        write_changes_state: true,
        ..Default::default()
    };
    let mut m = mutator(runner);
    let timezone = json!({"id":"timezone", "before":"America/New_York", "after":"Asia/Tokyo"});
    let locale = json!({"id":"locale", "before":"en_US", "after":"ja_JP"});
    let language = json!({"id":"language", "before":["zh-CN", "en-US"], "after":"en-US"});
    let ipv6 = json!({"id":"ipv6", "before":"automatic", "after":"Wi-Fi"});
    let watchdog = json!({"id":"watchdog", "before":null, "after":"Asia/Tokyo"});
    let updater = json!({"id":"updater", "before":false, "after":true});
    for action in [&timezone, &locale, &language, &ipv6, &watchdog, &updater] {
        m.apply(action).unwrap();
    }
    for action in [&updater, &watchdog, &ipv6, &language, &locale, &timezone] {
        assert!(m.restore(action).unwrap());
    }
}

#[test]
fn external_change_is_preserved_and_reported_as_unrestored() {
    let runner = FakeRunner {
        locale: json!("fr_FR"),
        write_changes_state: true,
        ..Default::default()
    };
    let mut m = mutator(runner);
    let action = json!({"id":"locale", "before":"en_US", "after":"ja_JP"});
    assert!(!m.restore(&action).unwrap());
    assert!(!m.restore(&action).unwrap());
}

#[test]
fn successful_command_without_apply_readback_is_an_error() {
    let runner = FakeRunner {
        timezone: json!("America/New_York"),
        write_changes_state: false,
        ..Default::default()
    };
    let mut m = mutator(runner);
    let action = json!({"id":"timezone", "before":"America/New_York", "after":"Asia/Tokyo"});
    assert_eq!(m.apply(&action).unwrap_err().code, "mutation_unconfirmed");
}

#[test]
fn successful_command_without_restore_readback_is_an_error() {
    let runner = FakeRunner {
        timezone: json!("Asia/Tokyo"),
        write_changes_state: false,
        ..Default::default()
    };
    let mut m = mutator(runner);
    let action = json!({"id":"timezone", "before":"America/New_York", "after":"Asia/Tokyo"});
    assert_eq!(
        m.restore(&action).unwrap_err().code,
        "mutation_restore_unconfirmed"
    );
}

#[test]
fn make_plan_emits_actions_that_the_native_mutator_can_restore() {
    let config = Config::default();
    let local = json!({
        "timezone":"",
        "locale":"",
        "ipv6":"fail",
        "ipv6_method":"automatic",
        "app_language":["zh-CN", "en-US"]
    });
    let plan = repair::make_plan(&config, &local, None).unwrap();
    let actions = plan["actions"].as_array().unwrap();
    let language = actions
        .iter()
        .find(|action| action["id"] == "language")
        .unwrap();
    let ipv6 = actions
        .iter()
        .find(|action| action["id"] == "ipv6")
        .unwrap();
    assert_eq!(language["before"], json!(["zh-CN", "en-US"]));
    assert_eq!(ipv6["before"], "automatic");

    let runner = FakeRunner {
        languages: json!(["zh-CN", "en-US"]),
        ipv6: json!("automatic"),
        write_changes_state: true,
        ..Default::default()
    };
    let mut m = mutator(runner);
    m.apply(language).unwrap();
    m.apply(ipv6).unwrap();
    assert!(m.restore(ipv6).unwrap());
    assert!(m.restore(language).unwrap());
}

#[test]
fn english_native_app_language_does_not_create_a_redundant_action() {
    let local = json!({"ipv6":"ok", "app_language":["en-US"]});
    let plan = repair::make_plan(&Config::default(), &local, None).unwrap();
    assert!(plan["actions"]
        .as_array()
        .unwrap()
        .iter()
        .all(|action| action["id"] != "language"));
}

#[test]
fn plan_refuses_an_ipv6_mode_the_fixed_helper_cannot_restore() {
    let local = json!({"ipv6":"fail", "ipv6_method":"manual", "app_language":["en-US"]});
    assert_eq!(
        repair::make_plan(&Config::default(), &local, None)
            .unwrap_err()
            .code,
        "ipv6_restore_unsupported"
    );
}

#[test]
fn injected_failure_does_not_claim_apply_or_restore_success() {
    let runner = FakeRunner {
        fail: true,
        timezone: json!("Asia/Tokyo"),
        ..Default::default()
    };
    let mut m = mutator(runner);
    let action = json!({"id":"timezone", "before":"America/New_York", "after":"Asia/Tokyo"});
    assert_eq!(m.apply(&action).unwrap_err().code, "fake_failure");
    assert_eq!(m.restore(&action).unwrap_err().code, "fake_failure");
}

#[test]
fn rejects_legacy_placeholder_before_values_instead_of_guessing_a_rollback() {
    let runner = FakeRunner::default();
    let mut m = mutator(runner);
    assert!(m
        .apply(&json!({"id":"language", "before":"application-default", "after":"en-US"}))
        .is_err());
    assert!(m
        .apply(&json!({"id":"ipv6", "before":"enabled", "after":"Wi-Fi"}))
        .is_err());
}

#[test]
fn administrative_maintenance_verbs_remain_typed_and_cannot_carry_shell_arguments() {
    // This fake runner is the contract boundary: native admin calls accept an
    // enum, not a caller-provided program, shell string, or argv vector.
    let mut runner = FakeRunner::default();
    runner.admin(AdminCommand::Status).unwrap();
    runner.admin(AdminCommand::LegacyStop).unwrap();
    runner.admin(AdminCommand::Uninstall).unwrap();
    assert_eq!(runner.calls, ["status", "legacy-stop", "uninstall"]);
}
