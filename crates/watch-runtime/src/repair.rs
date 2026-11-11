//! Previewed environment repair and conflict-safe restoration.
//! Preview-bound repair executor.  System changes are delegated to an adapter;
//! this crate deliberately contains no defaults/networksetup/launchctl calls.
use crate::{
    config_store::policy_digest,
    storage::StateStore,
};
use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
    region,
};
use serde_json::{json, Value};

pub trait RepairSystem {
    fn local(&self, config: &Config) -> Result<Value>;
    fn apply(&mut self, action: &Value) -> Result<()>;
    fn egress_reference(&self, config: &Config) -> Result<Value>;
    /// Restore is compare-and-restore: `true` means the adapter proved the
    /// current state was still our `after` value and restored `before`.
    /// `false` preserves the journal for human review; it must never guess.
    fn restore(&mut self, _action: &Value) -> Result<bool> {
        Ok(false)
    }
}
fn err(c: &str, m: &str) -> CoreError {
    CoreError::new(c, m)
}
fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn app_language(value: &Value) -> Result<Option<&str>> {
    if value.is_null() {
        return Ok(None);
    }
    let languages = value
        .as_array()
        .ok_or_else(|| err("invalid_local_state", "应用语言原生状态无效"))?;
    if languages.iter().any(|item| {
        item.as_str().is_none_or(|language| {
            let mut parts = language.split(['-', '_']);
            !matches!(parts.next(), Some(first) if (2..=3).contains(&first.len()) && first.bytes().all(|b| b.is_ascii_alphabetic()))
                || parts.any(|part| part.is_empty() || part.len() > 8 || !part.bytes().all(|b| b.is_ascii_alphanumeric()))
        })
    }) {
        return Err(err("invalid_local_state", "应用语言原生状态无效"));
    }
    Ok(languages.first().and_then(Value::as_str))
}
pub fn config_hash(config: &Config) -> Result<String> {
    policy_digest(&config.value()?)
}
pub fn make_plan(config: &Config, local: &Value, _merge_text: Option<&str>) -> Result<Value> {
    let accepted_locale = local["accepted_locale"]
        .as_str()
        .unwrap_or(&config.locale)
        .to_owned();
    let saved_hash = local["saved_config_hash"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or(config_hash(config)?);
    let mut normalized = config.clone();
    if let Some(locale) = region::locale_for(&config.country) {
        normalized.locale = locale.into();
    }
    let config = &normalized;
    if local["date_format"]["has_custom_formats"] == true
        && region::date_check(local, Some(&config.locale)) == "fail"
    {
        return Err(err(
            "custom_date_format",
            "自定义日期模板与出口地区不一致；未擅自清空自定义格式",
        ));
    }
    let mut actions = Vec::new();
    let add = |actions: &mut Vec<Value>, id, title, scope, before: Value, after: Value| {
        actions.push(json!({"id":id,"title":title,"scope":scope,"before":before,"after":after}))
    };
    if !config.timezone.is_empty() && text(local, "timezone") != config.timezone {
        add(
            &mut actions,
            "timezone",
            "设置系统时区",
            "administrator",
            json!(text(local, "timezone")),
            json!(config.timezone),
        );
    }
    if config.require_ipv6_off && text(local, "ipv6") == "fail" {
        let method = text(local, "ipv6_method");
        if method != "automatic" {
            return Err(err(
                "ipv6_restore_unsupported",
                "当前 IPv6 模式无法由固定辅助组件精确恢复；未生成不可恢复的关闭操作",
            ));
        }
        add(
            &mut actions,
            "ipv6",
            "关闭选定网络服务的 IPv6",
            "administrator",
            json!(method),
            json!(config.network_service),
        );
    }
    if !config.locale.is_empty() && text(local, "locale") != config.locale {
        add(
            &mut actions,
            "locale",
            "设置地区与日期格式（保留界面语言）",
            "preferences",
            json!(text(local, "locale")),
            json!(config.locale),
        );
    }
    let app_languages = local.get("app_language").unwrap_or(&Value::Null);
    let app_preferred = app_language(app_languages)?;
    let system_preferred = claude_watch_core::audit::preferred_language(&local["language"]);
    let app_preferred = app_preferred.or(system_preferred.as_deref());
    if config.require_english
        && !app_preferred.is_some_and(|language| language.split(['-', '_']).next() == Some("en"))
    {
        add(
            &mut actions,
            "language",
            "单独将 Claude 客户端语言设为英文",
            "preferences",
            app_languages.clone(),
            json!("en-US"),
        );
    }
    // The adapter reports service state as facts.  Planning it here keeps
    if accepted_locale != config.locale {
        add(
            &mut actions,
            "reference",
            "更新已接受的地区格式参考",
            "watch",
            json!(accepted_locale),
            json!(config.locale),
        );
    }
    // registration changes explicit and makes a stale preview visible.
    let watchdog_target = local
        .pointer("/watchdog/target")
        .cloned()
        .unwrap_or(Value::Null);
    let desired_watchdog = if config.timezone_watchdog {
        Value::String(config.timezone.clone())
    } else {
        Value::Null
    };
    if watchdog_target != desired_watchdog
        || (config.timezone_watchdog
            && !local
                .pointer("/watchdog/registered")
                .and_then(Value::as_bool)
                .unwrap_or(false))
    {
        add(
            &mut actions,
            "watchdog",
            "设置时区守护",
            "administrator",
            watchdog_target,
            desired_watchdog,
        );
    }
    let updater_registered = local
        .pointer("/updater/registered")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if updater_registered != config.auto_update {
        add(
            &mut actions,
            "updater",
            "设置每 12 小时自动更新任务",
            "watch",
            json!(updater_registered),
            json!(config.auto_update),
        );
    }
    if actions
        .iter()
        .any(|x| matches!(text(x, "id"), "enable_tun" | "rules" | "ipv6"))
    {
        add(
            &mut actions,
            "flush_dns",
            "刷新系统 DNS 缓存",
            "administrator",
            Value::Null,
            Value::Null,
        );
    }
    for action in &mut actions {
        if matches!(text(action, "id"), "enable_tun" | "rules") {
            action["context"] = local["context"].clone();
        }
    }
    let base = json!({"schema":1,"actions":actions,"desired_config":config.value()?,"config_hash":saved_hash,"context":local.get("context").cloned().unwrap_or(Value::Null),"note":"未列出的设置不会改变"});
    let mut out = base;
    out["id"] = json!(policy_digest(&out)?);
    Ok(out)
}
pub fn region_plan<S: RepairSystem>(
    system: &S,
    config: &Config,
    zones: &region::ZoneCatalog,
    allow_country: Option<&str>,
    merge: Option<&str>,
) -> Result<Value> {
    if !config.online_enabled {
        return Err(err("online_disabled", "请先明确启用在线检查"));
    }
    let local = system.local(config)?;
    let tun_required = config
        .vpn_expectation
        .as_ref()
        .and_then(|e| e.require_tun)
        .unwrap_or(!config.vpn_is_read_only());
    if text(&local, "proxy") != "ok" || (tun_required && text(&local, "tun") != "ok") {
        return Err(err("proxy_unverified", "代理与 TUN 未确认；未发起地区探测"));
    }
    let mut probe = config.clone();
    if config.proxy_mode == "auto" {
        let selected = text(&local, "mode");
        if !matches!(
            selected,
            "tag" | "clash-verge" | "shadowrocket" | "sing-box" | "clashx" | "surge"
        ) {
            return Err(err(
                "proxy_ambiguous",
                "当前客户端未能唯一确认；请核对运行进程与实际入口后重新检测",
            ));
        }
        probe.proxy_mode = selected.into();
    }
    let refv = system.egress_reference(&probe)?;
    let measured = region::reference(&refv["trace"], &refv["geo"], zones);
    let country = text(&measured, "country");
    if country.is_empty()
        || text(&measured, "timezone").is_empty()
        || text(&measured, "locale").is_empty()
    {
        return Err(err(
            "region_inconsistent",
            "两个来源的出口 IP/国家未能交叉确认",
        ));
    }
    if country == "CN" && allow_country != Some("CN") {
        return Err(err(
            "region_confirmation_required",
            "当前出口为 CN；默认不应用，例外需明确指定",
        ));
    }
    let mut v = config.value()?;
    v["country"] = json!(country);
    v["timezone"] = measured["timezone"].clone();
    v["locale"] = measured["locale"].clone();
    let desired = Config::from_value(v)?;
    let local = system.local(&desired)?;
    make_plan(&desired, &local, merge)
}
pub fn apply_plan<S: RepairSystem>(
    store: &StateStore,
    system: &mut S,
    config: &Config,
    expected_id: &str,
    merge: Option<&str>,
) -> Result<Value> {
    let _lock = store.lock("operation", None)?;
    let before = crate::config_store::ConfigStore {
        storage: store.clone(),
    }
    .load()?;
    let local = system.local(config)?;
    let plan = make_plan(config, &local, merge)?;
    if text(&plan, "id") != expected_id {
        return Err(err("stale_plan", "当前环境或配置已变化，请重新预览"));
    }
    let mut receipt = json!({"schema":1,"id":expected_id,"status":"running","actions":[],"desired_config":config.value()?});
    for a in plan["actions"].as_array().unwrap() {
        match if a["id"] == "reference" {
            Ok(())
        } else {
            system.apply(a)
        } {
            Ok(()) => receipt["actions"]
                .as_array_mut()
                .unwrap()
                .push(json!({"action":a,"status":"ok"})),
            Err(e) => {
                receipt["status"] = json!("partial");
                receipt["actions"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"action":a,"status":"failed","code":e.code}));
                store.atomic_json(&store.paths.base().join("last-repair.json"), &receipt)?;
                return Ok(receipt);
            }
        }
    }
    if (crate::config_store::ConfigStore {
        storage: store.clone(),
    })
    .load()?
        != before
    {
        receipt["status"] = json!("partial");
        receipt["code"] = json!("external_change");
        store.atomic_json(&store.paths.base().join("last-repair.json"), &receipt)?;
        return Ok(receipt);
    }
    let desired = Config::from_value(plan["desired_config"].clone())?;
    store.atomic_json(&store.paths.config(), &desired.value()?)?;
    receipt["status"] = json!("ok");
    store.atomic_json(&store.paths.base().join("last-repair.json"), &receipt)?;
    Ok(receipt)
}
pub fn restore_settings<S: RepairSystem>(
    store: &StateStore,
    system: &mut S,
    receipt_id: &str,
    config: &Config,
) -> Result<Value> {
    let _l = store.lock("operation", None)?;
    let receipt = store.read_json(&store.paths.base().join("last-repair.json"), Value::Null)?;
    if text(&receipt, "id") != receipt_id {
        return Err(err("receipt_missing", "未找到对应变更记录"));
    }
    let local = system.local(config)?;
    let mut restored = Vec::new();
    let mut skipped = Vec::new();
    for item in receipt["actions"].as_array().into_iter().flatten().rev() {
        let a = &item["action"];
        let id = text(a, "id");
        if matches!(id, "timezone" | "locale") && local.get(id) == a.get("after") {
            let mut rollback = a.clone();
            rollback["before"] = a["after"].clone();
            rollback["after"] = a["before"].clone();
            system.apply(&rollback)?;
            restored.push(id);
        } else {
            skipped.push(id);
        }
    }
    Ok(json!({"status":"ok","restored":restored,"skipped":skipped}))
}
