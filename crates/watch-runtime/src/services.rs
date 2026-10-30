//! Native service lifecycle, health and protection installation transactions.
//! All operating-system interaction is supplied by `ServiceSystem`; these
//! functions only validate, bind previews, journal intent and verify readback.
use crate::{
    config_store::{policy_digest, ConfigStore},
    storage::StateStore,
};
use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
};
use serde_json::{json, Value};

pub const UPDATE_LABEL: &str = "io.local.claudewatch.update";
pub const TIMEZONE_LABEL: &str = "io.local.claudewatch.timezone";
const UPDATE_INTERVAL: u64 = 43_200;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendHealthSnapshot {
    pub sampling_healthy: bool,
    pub guard_backend_healthy: bool,
    pub guard_healthy: bool,
}
fn err(code: &str, msg: &str) -> CoreError {
    CoreError::new(code, msg)
}
fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
fn service_path(store: &StateStore) -> std::path::PathBuf {
    store.paths.base().join("service-transaction.json")
}

pub fn update_task_definition(runtime: &str) -> Result<Value> {
    if runtime.is_empty() || runtime.contains(['\n', '\r', '\0']) {
        return Err(err("invalid_runtime", "更新运行组件路径无效"));
    }
    Ok(
        json!({"label":UPDATE_LABEL,"program_arguments":[runtime,"update","--auto","--apply"],"start_interval":UPDATE_INTERVAL,"run_at_load":false,"environment_path":"/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"}),
    )
}

/// Dispatcher-facing form: the entrypoint is derived from the managed runtime,
/// never supplied by a UI preference or arbitrary caller string.
pub fn installed_update_task_definition(store: &StateStore) -> Result<Value> {
    let entry = store.paths.watch().join("runtime/watch-engine");
    if !entry.is_file() {
        return Err(err("runtime_missing", "先安装完整后台运行组件"));
    }
    update_task_definition(
        entry
            .to_str()
            .ok_or_else(|| err("invalid_runtime", "更新运行组件路径无效"))?,
    )
}

pub fn require_admin_helper(facts: &Value) -> Result<()> {
    if facts["trusted"] != true || facts["abi"] != 1 {
        return Err(err(
            "admin_update_required",
            "系统辅助组件身份或 ABI 未确认；请先明确升级",
        ));
    }
    Ok(())
}

/// Native implementation must obtain facts from launchd/helper itself.  It
/// must not derive `registered` or `guard` from config intent.
pub trait ServiceSystem {
    fn now(&self) -> f64;
    /// Strict per-round monitoring quality. This remains false for an
    /// incomplete socket/activity sample even if the daemon process lives.
    fn backend_healthy(&self) -> bool;
    /// Liveness used by the session guard. A verified native daemon may keep
    /// guarding during a transient non-protection sampling gap.
    fn guard_backend_healthy(&self) -> bool {
        self.backend_healthy()
    }
    fn guard_status(&self, config: &Config) -> Result<bool>;
    /// Read strict sampling quality, guard liveness, and guard heartbeat from
    /// one observation when the platform can provide one. The default keeps
    /// simple fakes and non-macOS adapters source-compatible.
    fn backend_health_snapshot(&self, config: &Config) -> Result<BackendHealthSnapshot> {
        Ok(BackendHealthSnapshot {
            sampling_healthy: self.backend_healthy(),
            guard_backend_healthy: self.guard_backend_healthy(),
            guard_healthy: self.guard_status(config)?,
        })
    }
    fn service_job(&self, name: &str) -> Result<Value>;
    fn watchdog_state(&self) -> Result<Value>;
    /// Verified root-owned helper metadata (`trusted`, ABI `1`).
    fn admin_helper_status(&self) -> Result<Value>;
    fn runtime_present(&self) -> bool;
    fn apply_service(&mut self, action: &Value) -> Result<()>;
    /// Return true only after a compare-and-restore of the exact action.
    fn restore_service(&mut self, _action: &Value) -> Result<bool> {
        Ok(false)
    }
}

pub fn policy_issues(config: &Config) -> Value {
    let mut issues = Vec::new();
    if !config.enabled {
        issues.push(json!({"id":"policy","title":"启动策略尚未启用","detail":"确认环境并开启 Claude Watch 保护后，再运行启动前检查。"}));
    }
    if !config.online_enabled {
        issues.push(json!({"id":"online","title":"受控启动的联网预检未允许","detail":"此选项只控制启动预检；环境状态页的手动检测会单独请求网络。"}));
    }
    if !config.guard_enabled {
        issues.push(json!({"id":"guard","title":"Claude Watch 断线保护未启用","detail":"受控启动要求本工具保护后台具有有效心跳。"}));
    }
    Value::Array(issues)
}
fn job<S: ServiceSystem>(system: &S, name: &str) -> Value {
    system
        .service_job(name)
        .unwrap_or_else(|_| json!({"registered":null,"trusted":false}))
}
pub fn service_status<S: ServiceSystem>(system: &S, config: &Config) -> Result<Value> {
    let health = system
        .backend_health_snapshot(config)
        .unwrap_or(BackendHealthSnapshot {
            sampling_healthy: false,
            guard_backend_healthy: false,
            guard_healthy: false,
        });
    let helper = system
        .admin_helper_status()
        .unwrap_or_else(|_| json!({"trusted":false,"abi":null}));
    let watchdog = system
        .watchdog_state()
        .unwrap_or_else(|_| json!({"registered":null,"target":null}));
    let original = job(system, "original");
    let update = job(system, "updater");
    let clock = job(system, "watchdog");
    let ready = !config.update_url.is_empty() && !config.update_public_key.is_empty();
    let guard_state = if health.guard_healthy {
        "running"
    } else if !config.guard_enabled {
        "inactive"
    } else {
        "error"
    };
    let original_state = if original["registered"].is_null()
        || (original["registered"] == true && original["trusted"] != true)
    {
        "unknown"
    } else if original["registered"] == false {
        "inactive"
    } else if original["last_exit"].as_i64().is_some_and(|x| x != 0) {
        "error"
    } else {
        "scheduled"
    };
    let desired_target = if config.timezone_watchdog {
        Value::String(config.timezone.clone())
    } else {
        Value::Null
    };
    let watchdog_state = if clock["registered"].is_null() || watchdog["registered"].is_null() {
        "unknown"
    } else if !desired_target.is_null()
        && watchdog["registered"] == true
        && watchdog["target"] == desired_target
    {
        "scheduled"
    } else if desired_target.is_null() && watchdog["registered"] == false {
        "inactive"
    } else {
        "mismatch"
    };
    let update_state = if !ready {
        "unavailable"
    } else if update["registered"].is_null() {
        "unknown"
    } else if config.auto_update && update["registered"] == true && update["trusted"] == true {
        "scheduled"
    } else if !config.auto_update && update["registered"] == false {
        "inactive"
    } else {
        "mismatch"
    };
    Ok(
        json!({"status":"ok","observed_at":system.now(),"backend_healthy":health.sampling_healthy,"guard_backend_healthy":health.guard_backend_healthy,"backend_sampling_state":if health.sampling_healthy{"complete"}else{"incomplete"},"admin_helper":helper,"update_source_ready":ready,"policy_issues":policy_issues(config),"services":[
          {"id":"guard","title":"Claude Watch 保镖","state":guard_state,"desired":config.guard_enabled,"source":"本工具保护心跳 / 后台进程身份"},
          {"id":"original","title":"原版 Claude切换器保镖","state":original_state,"desired":null,"source":"system/local.claude-bodyguard / 原版任务定义"},
          {"id":"watchdog","title":"时区守护","state":watchdog_state,"desired":config.timezone_watchdog,"actual_target":watchdog["target"],"accepted_target":desired_target,"source":"时区任务注册 / root 管理的目标文件"},
          {"id":"updater","title":"自动更新","state":update_state,"desired":config.auto_update,"interval_seconds":UPDATE_INTERVAL,"source":"本项目发布配置 / 用户更新任务"}
        ]}),
    )
}
fn watchdog_reference(store: &StateStore, now: f64) -> Result<(String, String)> {
    for name in ["last-environment-detection.json", "last-audit.json"] {
        let r = store.read_json(&store.paths.base().join(name), Value::Null)?;
        let refv = &r["egress_reference"];
        let age = now - refv["checked_at"].as_f64().unwrap_or(-1.);
        let country = text(refv, "country");
        let timezone = text(refv, "timezone");
        let stable = r
            .pointer("/context_transition/state")
            .and_then(Value::as_str)
            == Some("stable");
        let safe = r["ready"] == true
            || ["proxy", "tun", "egress", "timezone"].iter().all(|id| {
                r["rows"].as_array().is_some_and(|rows| {
                    rows.iter()
                        .any(|x| text(x, "id") == *id && text(x, "state") == "ok")
                })
            });
        if stable
            && safe
            && (0.0..=300.0).contains(&age)
            && country != "CN"
            && !country.is_empty()
            && timezone.contains('/')
        {
            return Ok((country.into(), timezone.into()));
        }
    }
    Err(err(
        "reference_required",
        "本轮出口时区尚未检测完整，重新检测后即可自动生成时区守护预览",
    ))
}
pub fn protection_preview<S: ServiceSystem>(
    store: &StateStore,
    system: &S,
    changes: &Value,
) -> Result<Value> {
    let obj = changes
        .as_object()
        .filter(|v| v.len() == 1)
        .ok_or_else(|| err("invalid_service_change", "每次只预览一个明确的后台开关"))?;
    let (key, value) = obj.iter().next().unwrap();
    if !matches!(
        key.as_str(),
        "guard_enabled" | "timezone_watchdog" | "auto_update"
    ) || !value.is_boolean()
    {
        return Err(err(
            "invalid_service_change",
            "每次只预览一个明确的后台开关",
        ));
    }
    let cfg = ConfigStore {
        storage: store.clone(),
    }
    .load()?;
    let mut desired = cfg.value()?;
    desired[key] = value.clone();
    if key == "guard_enabled" && value == true {
        if !system.runtime_present() {
            return Err(err("runtime_missing", "先安装完整后台，再启用保护"));
        }
        desired["enabled"] = json!(true);
        desired["online_enabled"] = json!(true);
    }
    if key == "auto_update"
        && value == true
        && (cfg.update_url.is_empty() || cfg.update_public_key.is_empty())
    {
        return Err(err(
            "update_source_missing",
            "发布源与固定公钥未配置，自动更新不可启用",
        ));
    }
    let mut context = Value::Object(Default::default());
    let mut actions = Vec::new();
    if key == "guard_enabled" {
        actions.push(json!({"id":"guard","title":if value==true {"启用 Claude Watch 断线保护"}else{"停用 Claude Watch 断线保护"},"scope":"watch","before":cfg.guard_enabled&&cfg.enabled,"after":value,"detail":"原版保镖保持独立运行。"}));
    } else if key == "timezone_watchdog" {
        // The fixed root helper is installed by the same administrator
        // authorization that applies this change (the mutation runner
        // verifies the bundled hash before installing).  A preview therefore
        // must not require the helper to pre-exist: that would deadlock a
        // fresh install, where nothing can install it before the first apply.
        let helper = system.admin_helper_status()?;
        let helper_ready = helper["trusted"] == true && helper["abi"] == 1;
        let previous = system.watchdog_state()?;
        let j = job(system, "watchdog");
        if j["registered"].is_null() {
            return Err(err(
                "service_unknown",
                "无法确认时区任务注册状态，未生成变更",
            ));
        }
        if !previous["target"].is_null() && previous["registered"] != true {
            return Err(err(
                "service_inconsistent",
                "时区目标文件与注册状态不一致，请先核对后台",
            ));
        }
        if value == true {
            let (country, zone) = watchdog_reference(store, system.now())?;
            desired["country"] = json!(country);
            desired["timezone"] = json!(zone);
        }
        context = json!({"job":{"registered":j["registered"],"definition":j["definition"]},"target":previous["target"]});
        actions.push(json!({"id":"watchdog","title":if value==true {"启用时区守护"}else{"停用时区守护"},"scope":"administrator","before":previous["target"],"after":if value==true {desired["timezone"].clone()}else{Value::Null},
            "admin_helper_required":!helper_ready,
            "detail":if helper_ready {"原版保镖保持独立运行。"}else{"应用时先安装或升级固定系统组件（需管理员授权）。"}}));
    } else {
        let j = job(system, "updater");
        if j["registered"].is_null() {
            return Err(err(
                "service_inconsistent",
                "更新任务加载状态未能核对，请先检查后台",
            ));
        }
        context = json!({"registered":j["registered"],"definition":j["definition"]});
        actions.push(json!({"id":"updater","title":if value==true {"启用每 12 小时更新"}else{"停用自动更新"},"scope":"watch","before":j["registered"],"before_definition":j["definition"],"after":value,"interval_seconds":UPDATE_INTERVAL,"detail":"原版保镖保持并行。"}));
    }
    let desired = Config::from_value(desired)?;
    let mut plan = json!({"schema":1,"purpose":"protection_change","changes":changes,"actions":actions,"desired_config":desired.value()?,"config_hash":policy_digest(&cfg.value()?)?,"context":context});
    plan["id"] = json!(policy_digest(&plan)?);
    Ok(plan)
}
pub fn protection_apply<S: ServiceSystem>(
    store: &StateStore,
    system: &mut S,
    changes: &Value,
    plan_id: &str,
) -> Result<Value> {
    let _lock = store.lock("operation", None)?;
    let plan = protection_preview(store, system, changes)?;
    if text(&plan, "id") != plan_id {
        return Err(err("stale_plan", "后台或设置发生变化，请重新预览"));
    }
    let before = ConfigStore {
        storage: store.clone(),
    }
    .load()?;
    let desired = Config::from_value(plan["desired_config"].clone())?;
    let mut journal = json!({"schema":1,"id":plan_id,"origin":"protection","desired_config":desired.value()?,"config_before":before.value()?,"config_after":desired.value()?,"actions":[]});
    store.atomic_json(&service_path(store), &journal)?;
    let outcome = (|| -> Result<Value> {
        for action in plan["actions"].as_array().unwrap() {
            if text(action, "id") == "guard" {
                continue;
            }
            journal["actions"]
                .as_array_mut()
                .unwrap()
                .push(json!({"action":action,"state":"pending"}));
            store.atomic_json(&service_path(store), &journal)?;
            system.apply_service(action)?;
            journal["actions"]
                .as_array_mut()
                .unwrap()
                .last_mut()
                .unwrap()["state"] = json!("applied");
            store.atomic_json(&service_path(store), &journal)?;
            let ok = match text(action, "id") {
                "watchdog" => {
                    let x = system.watchdog_state()?;
                    // Applying this action is what installs (or upgrades) the
                    // fixed root helper; confirm the installed identity rather
                    // than trusting that the authorization step succeeded.
                    let helper = system.admin_helper_status()?;
                    x["target"] == action["after"]
                        && x["registered"] == (!action["after"].is_null())
                        && require_admin_helper(&helper).is_ok()
                }
                "updater" => job(system, "updater")["registered"] == action["after"],
                _ => true,
            };
            if !ok {
                return Err(err("service_unconfirmed", "后台变更未能回读确认"));
            }
        }
        if (ConfigStore {
            storage: store.clone(),
        })
        .load()?
            != before
        {
            return Err(err("external_change", "配置被其他操作更改，未覆盖"));
        }
        store.atomic_json(&store.paths.config(), &desired.value()?)?;
        std::fs::remove_file(service_path(store))
            .map_err(|_| err("state_io_failed", "无法完成服务事务"))?;
        Ok(
            json!({"status":"ok","config":desired.value()?,"message":"后台变更已完成；原版保镖保持并行。"}),
        )
    })();
    if let Err(error) = outcome {
        drop(_lock);
        let restored = recover(store, system)?;
        if restored["status"] == "partial" {
            return Ok(restored);
        }
        return Err(err(
            "protection_rolled_back",
            &format!("后台变更未完成，已恢复原设置：{}", error.message),
        ));
    }
    outcome
}
pub fn recover<S: ServiceSystem>(store: &StateStore, system: &mut S) -> Result<Value> {
    let _lock = store.lock("operation", Some("service"))?;
    let path = service_path(store);
    let mut j = store.read_json(&path, Value::Null)?;
    if j.is_null() {
        return Ok(json!({"status":"ok","message":"没有待恢复的服务事务"}));
    }
    if j["schema"] != 1
        || j["origin"] != "protection"
        || !j["actions"].is_array()
        || !j["config_before"].is_object()
        || !j["config_after"].is_object()
    {
        return Err(err("invalid_transaction", "服务恢复记录无效"));
    }
    let config_before = Config::from_value(j["config_before"].clone())?;
    let config_after = Config::from_value(j["config_after"].clone())?;
    let mut skipped = Vec::new();
    for i in (0..j["actions"].as_array().unwrap().len()).rev() {
        let a = j["actions"][i]["action"].clone();
        if !matches!(text(&a, "id"), "watchdog" | "updater")
            || !matches!(
                j["actions"][i]["state"].as_str(),
                Some("pending" | "applied" | "restored")
            )
        {
            return Err(err("invalid_transaction", "服务恢复动作无效"));
        }
        let already_restored = match text(&a, "id") {
            "watchdog" => {
                let state = system.watchdog_state()?;
                state["target"] == a["before"] && state["registered"] == (!a["before"].is_null())
            }
            "updater" => {
                let current = system.service_job("updater")?;
                current["registered"] == a["before"]
                    && a.get("before_definition")
                        .is_some_and(|hash| current["definition"] == *hash)
            }
            _ => false,
        };
        if already_restored || system.restore_service(&a)? {
            j["actions"][i]["state"] = json!("restored");
            store.atomic_json(&path, &j)?;
        } else {
            skipped.push(text(&a, "id").to_owned());
        }
    }
    if !skipped.is_empty() {
        return Ok(json!({"status":"partial","recovery_required":true,"skipped":skipped}));
    }
    let current = ConfigStore {
        storage: store.clone(),
    }
    .load()?;
    if current != config_after && current != config_before {
        return Ok(json!({"status":"partial","recovery_required":true,"skipped":["config"]}));
    }
    if current != config_before {
        store.atomic_json(&store.paths.config(), &config_before.value()?)?;
    }
    std::fs::remove_file(path).map_err(|_| err("state_io_failed", "无法完成服务恢复"))?;
    Ok(json!({"status":"ok","recovery_required":false}))
}
