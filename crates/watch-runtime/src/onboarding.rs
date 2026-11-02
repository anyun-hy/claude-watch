//! Automatic environment discovery and context-bound setup transactions.
//! First-run discovery and explicit setup transactions.
//!
//! Detection only measures through `OnboardingSystem`.  It neither invents an
//! egress value after an error nor mutates a system.  Applying a preview is
//! compare-and-bind: candidate, policy, context and plan hashes must all still
//! match immediately before writes.
use crate::{
    config_store::{policy_digest, ConfigStore},
    repair::{self, RepairSystem},
    setup_progress::Phase,
    storage::StateStore,
};
use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
    region,
};
use serde_json::{json, Value};
use uuid::Uuid;
pub const TTL: f64 = 300.0;
pub const OPTIONS: [&str; 5] = [
    "apply_environment",
    "enable_policy",
    "guard_enabled",
    "timezone_watchdog",
    "auto_update",
];
fn err(c: &str, m: &str) -> CoreError {
    CoreError::new(c, m)
}
fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

pub trait OnboardingSystem: RepairSystem {
    fn network(&self) -> Result<Value>;
    fn now(&self) -> f64;
    fn baseline_data(&self) -> Result<String>;
    fn progress(&self, phase: Phase) {
        crate::setup_progress::emit(phase);
    }
}
/// Detection and confirmation must use identical country/timezone rules.
/// A missing timezone can resolve only through a unique authoritative zone;
/// malformed, conflicting or ambiguous metadata never creates a reference.
pub fn normalized_reference(egress: &Value, zones: &region::ZoneCatalog) -> Result<Value> {
    let measured = region::reference(&egress["trace"], &egress["geo"], zones);
    if ["ip", "country", "timezone", "locale"]
        .iter()
        .any(|key| text(&measured, key).is_empty())
    {
        return Err(err(
            "region_inconsistent",
            "出口 IP、国家、对应时区或地区格式未能确认，请重新检测",
        ));
    }
    Ok(measured)
}
pub fn confirm_reference(
    values: &Value,
    egress: &Value,
    zones: &region::ZoneCatalog,
) -> Result<()> {
    // Positive IP/country differences remain changes even when another
    // metadata field is missing. Missing data alone is an incomplete check.
    let ip_changed = [&egress["trace"]["ip"], &egress["geo"]["ip"]]
        .into_iter()
        .filter_map(|v| {
            v.as_str()
                .and_then(claude_watch_core::network::public_unicast)
        })
        .any(|ip| Some(ip.as_str()) != values["ip"].as_str());
    let country_changed = [&egress["trace"]["loc"], &egress["geo"]["country"]]
        .into_iter()
        .filter_map(Value::as_str)
        .filter(|v| v.len() == 2 && v.bytes().all(|b| b.is_ascii_uppercase()))
        .any(|country| Some(country) != values["country"].as_str());
    if ip_changed || country_changed {
        return Err(err("egress_changed", "确认时出口发生变化，请重新检测"));
    }
    let measured = normalized_reference(egress, zones).map_err(|_| {
        err(
            "egress_unconfirmed",
            "出口复核未取得完整且一致的资料，未执行变更；请重新检测",
        )
    })?;
    if ["ip", "country", "timezone", "locale"]
        .iter()
        .any(|key| measured[*key] != values[*key])
    {
        return Err(err(
            "egress_changed",
            "确认时出口或地区要求发生变化，请重新检测",
        ));
    }
    Ok(())
}
fn context(network: &Value, local: &Value) -> Result<String> {
    policy_digest(
        &json!({"network":network.get("service"),"interface":network.get("interface"),"context":local.get("context"),"timezone":local.get("timezone"),"locale":local.get("locale"),"date_format":local.get("date_format"),"language":local.get("language"),"ipv6":local.get("ipv6")}),
    )
}
fn candidate_path(store: &StateStore) -> std::path::PathBuf {
    store.paths.base().join("environment-candidate.json")
}
fn setup_path(store: &StateStore) -> std::path::PathBuf {
    store.paths.base().join("setup-transaction.json")
}
fn managed_paths(store: &StateStore) -> [(&'static str, std::path::PathBuf); 3] {
    [
        ("config", store.paths.config()),
        ("baseline", store.paths.watch().join("state/baseline.conf")),
        (
            "confirmation",
            store.paths.base().join("confirmed-environment.json"),
        ),
    ]
}
fn file_text(store: &StateStore, path: &std::path::Path) -> Result<Option<String>> {
    store
        .read_bytes(path, 2_000_000)?
        .map(|v| String::from_utf8(v).map_err(|_| err("invalid_state", "受管理文本不是 UTF-8")))
        .transpose()
}
fn put_text(store: &StateStore, path: &std::path::Path, text: &str) -> Result<()> {
    store.atomic_bytes(path, text.as_bytes(), 0o600)
}
fn options_ok(v: &Value) -> bool {
    let Some(o) = v.as_object() else { return false };
    o.len() == OPTIONS.len()
        && OPTIONS
            .iter()
            .all(|k| o.get(*k).and_then(Value::as_bool).is_some())
}
pub fn current_values(network: &Value, local: &Value) -> Value {
    let verified = require_transport(local).is_ok();
    json!({"proxy_mode":local.get("mode"),"proxy_url":if verified {Some("http://127.0.0.1:7890")}else{None},"proxy_group":if verified {local.pointer("/tag/expected_group")}else{None},"node":if verified {local.pointer("/tag/api/selected_node")}else{None},"network_service":network.get("service"),"timezone":local.get("timezone"),"locale":local.get("locale"),"language":local.get("language")})
}

/// Fail closed before any online candidate creation.  TAG evidence must bind
/// the private listener to a currently observed owner and its control API.
pub fn require_transport(local: &Value) -> Result<()> {
    if text(local, "proxy") != "ok" {
        return Err(err(
            "proxy_unverified",
            "代理身份或本轮必要证据未确认；未联网",
        ));
    }
    if text(local, "mode") == "tag" {
        let entry = &local["tag"]["entry"];
        let api = &local["tag"]["api"];
        if text(entry, "state") != "verified"
            || entry["public_listener"] == true
            || text(api, "state") != "available"
            || api["covers_7890"] != true
            || !matches!(text(api, "mode"), "rule" | "global")
        {
            return Err(err(
                "proxy_unverified",
                "TAG 回环入口、控制接口或覆盖范围未确认；未联网",
            ));
        }
        let owners = entry["owners"]
            .as_array()
            .ok_or_else(|| err("proxy_unverified", "TAG 监听者身份未确认；未联网"))?;
        let processes = local["processes"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if owners.is_empty()
            || owners.iter().any(|owner| {
                !processes.iter().any(|p| {
                    p["pid"] == owner["pid"]
                        && p["executable"] == owner["executable"]
                        && p["uid"] == owner["uid"]
                        && (owner["stamp"].is_null() || p["start_stamp"] == owner["stamp"])
                })
            })
        {
            return Err(err(
                "proxy_unverified",
                "监听者与当前运行进程身份不一致；未联网",
            ));
        }
    }
    if text(local, "tun") != "ok" {
        return Err(err("proxy_unverified", "TUN 网卡或路由未确认；未联网"));
    }
    // The same native daemon liveness used by service-status and first-run
    // step 2: fresh heartbeat + matching PID/start identity + launchd/worker
    // identity + native runtime path. Complete monitoring of unrelated sockets
    // is a separate fact and cannot veto this transport-specific prerequisite.
    // Missing/unknown liveness fails closed; strict sampling is never a fallback.
    if local["guard_backend_healthy"] != true {
        return Err(err(
            "proxy_unverified",
            "采集后台的原生进程身份或有效心跳未确认；未联网",
        ));
    }
    Ok(())
}
pub fn detect<S: OnboardingSystem>(
    store: &StateStore,
    system: &S,
    mode: &str,
    online: bool,
    zones: &region::ZoneCatalog,
) -> Result<Value> {
    if !matches!(
        mode,
        "tag" | "clash-verge" | "shadowrocket" | "sing-box" | "clashx" | "surge" | "auto"
    ) {
        return Err(err("invalid_mode", "请选择已识别的代理类型"));
    }
    if !online {
        return Err(err(
            "online_consent_required",
            "生成候选需要本次明确允许联网检测",
        ));
    }
    let cfg = ConfigStore {
        storage: store.clone(),
    }
    .load()?;
    let net = system.network()?;
    let local = system.local(&cfg)?;
    if text(&net, "service").is_empty() {
        return Err(err("network_unknown", "活动网络服务未确认"));
    }
    require_transport(&local)?;
    let egress = system.egress_reference(&cfg)?;
    let measured = normalized_reference(&egress, zones)?;
    if text(&measured, "country") == "CN" {
        return Err(err(
            "region_confirmation_required",
            "检测到 CN 出口，自动初始化不接受此地区",
        ));
    }
    let after_cfg = ConfigStore {
        storage: store.clone(),
    }
    .load()?;
    let after_net = system.network()?;
    let after = system.local(&after_cfg)?;
    require_transport(&after)?;
    if policy_digest(&cfg.value()?)? != policy_digest(&after_cfg.value()?)?
        || context(&net, &local)? != context(&after_net, &after)?
    {
        return Err(err(
            "context_changed",
            "检测期间环境或目标配置变化，请重新检测",
        ));
    }
    let mut values = current_values(&net, &local);
    values["country"] = measured["country"].clone();
    values["ip"] = measured["ip"].clone();
    values["timezone"] = measured["timezone"].clone();
    values["locale"] = measured["locale"].clone();
    if cfg.require_english {
        values["language"] = json!("English");
    }
    let now = system.now();
    let body = json!({"schema":1,"observed_at":now,"expires_at":now+TTL,"mode":mode,"policy":policy_digest(&cfg.value()?)?,"context":context(&net,&local)?,"values":values,"sources":{"country":"cross-checked egress","ip":"cross-checked egress","timezone":"egress region","locale":"egress country convention","language":"independent English preference"}});
    let mut out = body;
    out["id"] = json!(policy_digest(&out)?);
    store.atomic_json(&candidate_path(store), &out)?;
    Ok(out)
}
pub fn checked_candidate<S: OnboardingSystem>(
    store: &StateStore,
    system: &S,
    id: &str,
) -> Result<(Value, Config, Value, Value)> {
    let c = store.read_json(&candidate_path(store), Value::Null)?;
    if text(&c, "id") != id
        || system.now() - c["observed_at"].as_f64().unwrap_or(-1.0) > TTL
        || system.now() < c["observed_at"].as_f64().unwrap_or(0.0)
    {
        return Err(err(
            "candidate_expired",
            "候选不存在或已超过 5 分钟，请重新检测",
        ));
    }
    let mut body = c.clone();
    body.as_object_mut().unwrap().remove("id");
    if policy_digest(&body)? != id {
        return Err(err("invalid_candidate", "候选校验失败，请重新检测"));
    }
    let cfg = ConfigStore {
        storage: store.clone(),
    }
    .load()?;
    let net = system.network()?;
    let local = system.local(&cfg)?;
    require_transport(&local)?;
    if text(&c, "policy") != policy_digest(&cfg.value()?)?
        || text(&c, "context") != context(&net, &local)?
    {
        return Err(err(
            "stale_candidate",
            "当前值、代理或已保存目标变化，请重新检测",
        ));
    }
    Ok((c, cfg, net, local))
}
pub fn preview<S: OnboardingSystem>(
    store: &StateStore,
    system: &S,
    id: &str,
    options: &Value,
    merge: Option<&str>,
) -> Result<Value> {
    if !options_ok(options) {
        return Err(err("invalid_options", "请明确选择环境与后台选项"));
    }
    let (c, cfg, _net, local) = checked_candidate(store, system, id)?;
    let mut desired = cfg.value()?;
    for k in [
        "country",
        "timezone",
        "locale",
        "proxy_mode",
        "proxy_url",
        "proxy_group",
        "network_service",
    ] {
        if let Some(v) = c["values"].get(k) {
            // A measured absence (for example an unverified TAG selection) is
            // display data, not a request to replace a validated string field
            // with JSON null.
            if !v.is_null() {
                desired[k] = v.clone();
            }
        }
    }
    desired["enabled"] = json!(options["enable_policy"].as_bool().unwrap());
    desired["online_enabled"] =
        json!(options["enable_policy"].as_bool().unwrap() || cfg.online_enabled);
    desired["guard_enabled"] = options["guard_enabled"].clone();
    desired["timezone_watchdog"] = options["timezone_watchdog"].clone();
    desired["auto_update"] = options["auto_update"].clone();
    let desired = Config::from_value(desired)?;
    if desired.guard_enabled && !desired.enabled {
        return Err(err("policy_required", "启用断线保护时也需启用受控环境策略"));
    }
    let repair = repair::make_plan(&desired, &local, merge)?;
    let actions: Vec<Value> = repair["actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| {
            matches!(text(a, "id"), "watchdog" | "updater")
                || (options["apply_environment"] == Value::Bool(true)
                    && matches!(text(a, "id"), "timezone" | "locale" | "language" | "ipv6"))
        })
        .cloned()
        .collect();
    let mut out = json!({"schema":1,"candidate_id":id,"options":options,"actions":actions,"desired_config":desired.value()?,"policy":c["policy"],"context":c["context"],"values":c["values"],"observed_at":c["observed_at"],"expires_at":c["expires_at"]});
    out["id"] = json!(policy_digest(&out)?);
    Ok(out)
}
fn apply_inner<S: OnboardingSystem>(
    store: &StateStore,
    system: &mut S,
    candidate_id: &str,
    options: &Value,
    plan_id: &str,
    merge: Option<&str>,
    transaction_id: &str,
) -> Result<Value> {
    let plan = preview(store, system, candidate_id, options, merge)?;
    if text(&plan, "id") != plan_id {
        return Err(err("stale_plan", "预览选项或环境变化，请重新预览"));
    }
    let (c, before, network, local) = checked_candidate(store, system, candidate_id)?;
    let desired = Config::from_value(plan["desired_config"].clone())?;
    system.progress(Phase::VerifyEgress);
    let reread = system.egress_reference(&before)?;
    confirm_reference(
        &c["values"],
        &reread,
        &crate::region_catalog::load_system_catalog(),
    )?;
    // Permission dialogs and writes must not begin on a context or candidate
    // that changed/expired while the network reference was being rechecked.
    checked_candidate(store, system, candidate_id)?;
    if setup_path(store).exists() {
        return Err(err("recovery_required", "已有初始化事务待恢复，未覆盖"));
    }
    let mut files = serde_json::Map::new();
    for (key, path) in managed_paths(store) {
        files.insert(
            key.into(),
            json!({"before":file_text(store,&path)?,"after":null}),
        );
    }
    let mut journal = json!({"schema":1,"id":plan_id,"transaction_id":transaction_id,"desired_config":desired.value()?,"actions":[],"files":files});
    store.atomic_json(&setup_path(store), &journal)?;
    for action in plan["actions"].as_array().unwrap() {
        if matches!(text(action, "id"), "guard" | "reference") {
            continue;
        }
        journal["actions"]
            .as_array_mut()
            .unwrap()
            .push(json!({"action":action,"state":"pending"}));
        store.atomic_json(&setup_path(store), &journal)?;
        system.progress(Phase::ApplySettings);
        system.apply(action)?;
        journal["actions"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap()["state"] = json!("applied");
        store.atomic_json(&setup_path(store), &journal)?;
    }
    // Time and locale changes are expected; the transport identity and saved
    // policy must nevertheless still be the one bound to the preview.
    system.progress(Phase::VerifySettings);
    let final_network = system.network()?;
    let final_local = system.local(&desired)?;
    require_transport(&final_local)?;
    let current = ConfigStore {
        storage: store.clone(),
    }
    .load()?;
    if text(&local, "context") != text(&final_local, "context")
        || network != final_network
        || text(&c, "policy") != policy_digest(&current.value()?)?
    {
        return Err(err("context_changed", "应用期间网络或目标设置变化"));
    }
    for a in plan["actions"].as_array().unwrap() {
        let k = text(a, "id");
        if matches!(k, "timezone" | "locale") && final_local.get(k) != a.get("after") {
            return Err(err("setting_unconfirmed", "系统设置应用后未能确认"));
        }
        if k == "language"
            && claude_watch_core::audit::preferred_language(&final_local["app_language"]).as_deref()
                != Some("en-US")
        {
            return Err(err("setting_unconfirmed", "Claude 英文语言应用后未能确认"));
        }
        if k == "ipv6" && text(&final_local, "ipv6") != "ok" {
            return Err(err("setting_unconfirmed", "IPv6 关闭状态未能确认"));
        }
        if k == "watchdog"
            && (final_local["watchdog"]["target"] != a["after"]
                || final_local["watchdog"]["registered"] != (!a["after"].is_null()))
        {
            return Err(err("setting_unconfirmed", "时区守护注册未能确认"));
        }
    }
    if options["apply_environment"] == true
        && claude_watch_core::region::date_check(&final_local, Some(&desired.locale)) != "ok"
    {
        return Err(err("setting_unconfirmed", "应用后的日期格式未能核对"));
    }
    system.progress(Phase::SaveBaseline);
    let mut baseline = system.baseline_data()?;
    let end_network = system.network()?;
    let end_local = system.local(&desired)?;
    require_transport(&end_local)?;
    if context(&final_network, &final_local)? != context(&end_network, &end_local)?
        || final_network != end_network
    {
        return Err(err("context_changed", "基线读取期间代理或网络变化"));
    }
    if !baseline.lines().any(|x| x == "format=2")
        || !baseline
            .lines()
            .any(|x| x == format!("timezone={}", end_local["timezone"].as_str().unwrap_or("")))
    {
        return Err(err("baseline_incomplete", "基线与最终本机时区未能核对"));
    }
    // Pin the observed TAG node, not the requested CLI mode: auto detection
    // must still record the baseline photo when the machine really runs a
    // TAG-transport client (values.proxy_mode is the observed transport).
    if text(&c["values"], "proxy_mode") == "tag" {
        let group = c["values"]["proxy_group"].as_str().unwrap_or("");
        let node = c["values"]["node"].as_str().unwrap_or("");
        if [group, node]
            .iter()
            .any(|value| value.contains(['\n', '\r', '\0']))
        {
            return Err(err("invalid_proxy_reference", "代理参考名称含无效控制字符"));
        }
        if !baseline.ends_with('\n') {
            baseline.push('\n');
        }
        baseline.push_str(&format!("tag_group={group}\ntag_node={node}\n"));
    }
    let confirmation = json!({"schema":1,"confirmed_at":system.now(),"observed_at":c["observed_at"],"policy":policy_digest(&desired.value()?)?,"values":c["values"],"sources":c["sources"]});
    let outputs = [
        (
            "config",
            serde_json::to_string(&desired.value()?).unwrap() + "\n",
        ),
        ("baseline", baseline),
        (
            "confirmation",
            serde_json::to_string(&confirmation).unwrap() + "\n",
        ),
    ];
    for (key, after) in outputs {
        let path = managed_paths(store)
            .into_iter()
            .find(|x| x.0 == key)
            .unwrap()
            .1;
        let current = file_text(store, &path)?;
        let before: Option<String> =
            serde_json::from_value(journal["files"][key]["before"].clone())
                .map_err(|_| err("invalid_transaction", "初始化文件记录无效"))?;
        if current != before {
            return Err(err("external_change", "保存期间文件被其他操作更改；未覆盖"));
        }
        journal["files"][key]["after"] = json!(after);
        store.atomic_json(&setup_path(store), &journal)?;
        put_text(
            store,
            &path,
            journal["files"][key]["after"].as_str().unwrap(),
        )?;
    }
    std::fs::remove_file(setup_path(store))
        .map_err(|_| err("state_io_failed", "无法完成初始化事务"))?;
    Ok(json!({"status":"ok","config":desired.value()?,"candidate":c["id"]}))
}

/// Apply is deliberately a two-phase wrapper.  The operation lock is dropped
/// before automatic recovery, and recovery is permitted only when the journal
/// still names this invocation's fresh transaction id.  Thus a stale or
/// concurrent journal can never be rolled back by the wrong caller.
pub fn apply<S: OnboardingSystem>(
    store: &StateStore,
    system: &mut S,
    candidate_id: &str,
    options: &Value,
    plan_id: &str,
    merge: Option<&str>,
) -> Result<Value> {
    let transaction_id = Uuid::new_v4().to_string();
    let result = {
        let _lock = store.lock("operation", None)?;
        apply_inner(
            store,
            system,
            candidate_id,
            options,
            plan_id,
            merge,
            &transaction_id,
        )
    };
    let Err(failure) = result else { return result };
    let recovery = {
        let _lock = store.lock("operation", Some("setup"))?;
        recover_inner(store, system, Some(&transaction_id))
    };
    match recovery {
        Ok(value) if value["status"] == "partial" => Ok(value),
        Ok(_) => Err(err(
            "setup_rolled_back",
            &format!("初始化未完成，已恢复原设置。{}", failure.message),
        )),
        // Preserve the original failure when our journal has already gone
        // away or belongs to another transaction; no unbound recovery ran.
        Err(recovery_error) if recovery_error.code == "transaction_changed" => Err(failure),
        Err(recovery_error) => Err(recovery_error),
    }
}
fn recover_inner<S: OnboardingSystem>(
    store: &StateStore,
    system: &mut S,
    expected_transaction: Option<&str>,
) -> Result<Value> {
    let path = setup_path(store);
    let mut journal = store.read_json(&path, Value::Null)?;
    if journal.is_null() {
        if expected_transaction.is_some() {
            return Err(err("transaction_changed", "本次初始化事务已不再可恢复"));
        }
        return Ok(json!({"status":"ok","message":"没有待恢复的初始化事务"}));
    }
    if let Some(expected) = expected_transaction {
        if journal["transaction_id"].as_str() != Some(expected) {
            return Err(err("transaction_changed", "初始化事务已由其他操作接管"));
        }
    }
    if journal["schema"] != 1
        || !journal["desired_config"].is_object()
        || !journal["actions"].is_array()
        || journal["actions"].as_array().is_some_and(|a| a.len() > 8)
        || !journal["files"].is_object()
        || journal["files"].as_object().is_some_and(|f| {
            f.len() != 3
                || !["config", "baseline", "confirmation"]
                    .iter()
                    .all(|k| f.contains_key(*k))
        })
    {
        return Err(err(
            "invalid_transaction",
            "初始化事务格式不完整，未猜测恢复内容",
        ));
    }
    let _ = Config::from_value(journal["desired_config"].clone())?;
    system.progress(Phase::RestoreSettings);
    let mut skipped = Vec::new();
    let action_count = journal["actions"].as_array().unwrap().len();
    for index in (0..action_count).rev() {
        let action = journal["actions"][index]
            .get("action")
            .cloned()
            .ok_or_else(|| err("invalid_transaction", "初始化动作记录无效，未执行恢复"))?;
        if !matches!(
            text(&action, "id"),
            "timezone" | "locale" | "language" | "ipv6" | "watchdog" | "updater"
        ) {
            return Err(err("invalid_transaction", "初始化动作类型无效，未执行恢复"));
        }
        if !matches!(
            journal["actions"][index]
                .get("state")
                .and_then(Value::as_str),
            Some("pending" | "applied" | "restored")
        ) {
            return Err(err("invalid_transaction", "初始化动作状态无效，未执行恢复"));
        }
        if journal["actions"][index]["state"] == "restored" {
            continue;
        }
        if system.restore(&action)? {
            journal["actions"][index]["state"] = json!("restored");
            store.atomic_json(&path, &journal)?;
        } else {
            skipped.push(text(&action, "id").to_owned());
        }
    }
    if !skipped.is_empty() {
        return Ok(json!({"status":"partial","recovery_required":true,"skipped":skipped}));
    }
    for (key, path) in managed_paths(store) {
        let record = &journal["files"][key];
        let before: Option<String> = serde_json::from_value(record["before"].clone())
            .map_err(|_| err("invalid_transaction", "初始化文件记录无效"))?;
        let after: Option<String> = serde_json::from_value(record["after"].clone())
            .map_err(|_| err("invalid_transaction", "初始化文件记录无效"))?;
        let current = file_text(store, &path)?;
        if current == before {
            continue;
        }
        if current != after {
            return Ok(json!({"status":"partial","recovery_required":true,"skipped":[key]}));
        }
        match before {
            Some(value) => put_text(store, &path, &value)?,
            None => {
                if path.exists() {
                    std::fs::remove_file(&path)
                        .map_err(|_| err("state_io_failed", "无法恢复初始化文件"))?;
                }
            }
        }
    }
    std::fs::remove_file(&path).map_err(|_| err("state_io_failed", "无法完成恢复事务"))?;
    Ok(json!({"status":"ok","recovery_required":false}))
}

pub fn recover<S: OnboardingSystem>(store: &StateStore, system: &mut S) -> Result<Value> {
    let _lock = store.lock("operation", Some("setup"))?;
    recover_inner(store, system, None)
}
