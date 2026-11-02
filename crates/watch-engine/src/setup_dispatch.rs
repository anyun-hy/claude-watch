//! Setup, repair, and protection command adapter.
//!
//! Reads use the normal observation host; write paths construct an explicitly
//! permitted host only after the request has acknowledged `--apply`.
use crate::runtime::{host, require_apply, Host};
use claude_watch_core::{
    cli::Request,
    config::Config,
    error::{CoreError, Result},
};
use claude_watch_runtime::{
    config_store::{policy_digest, ConfigStore},
    macos::Authority,
    onboarding::{self, OnboardingSystem},
    region_catalog::load_system_catalog,
    repair::{self, RepairSystem},
    services,
    storage::Paths,
};
use serde_json::{json, Value};

const VALUE_IDS: [(&str, &str); 11] = [
    ("proxy_mode", "代理客户端"),
    ("runtime_mode", "运行模式"),
    ("proxy_url", "HTTP 入口"),
    ("proxy_group", "代理组"),
    ("node", "当前节点"),
    ("network_service", "活动网络服务"),
    ("country", "出口国家"),
    ("ip", "出口 IP"),
    ("timezone", "系统时区"),
    ("locale", "地区格式"),
    ("language", "Claude 语言"),
];

fn missing<'a>(
    value: Option<&'a str>,
    code: &'static str,
    message: &'static str,
) -> Result<&'a str> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CoreError::new(code, message))
}
fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}
fn display(value: &Value, fallback: &str) -> String {
    value
        .as_str()
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_owned()
}
/// Observed controller mode is a read-only fact; render it in the same
/// Chinese wording used by the proxy detail panel.
fn runtime_mode_label(value: &Value) -> String {
    match value.as_str().unwrap_or("") {
        "rule" => "规则模式".into(),
        "global" => "全局模式".into(),
        "direct" => "直连模式".into(),
        _ => "未知".into(),
    }
}
fn local(host: &Host, config: &Config) -> Result<Value> {
    RepairSystem::local(host, config)
}
fn network(host: &Host) -> Result<Value> {
    OnboardingSystem::network(host)
}
fn source(id: &str, local: &Value, network: &Value, candidate: bool) -> String {
    match id {
        "proxy_mode" => "运行进程身份 / 本机网络状态".into(),
        "proxy_url" => "后台监听者身份样本（非默认端口猜测）".into(),
        "proxy_group" | "node" | "runtime_mode" => "TAG 控制接口".into(),
        "network_service" => text(network, "source").if_empty("scutil / networksetup"),
        "country" | "ip" if candidate => "Cloudflare + Net.Coffee 本轮交叉确认".into(),
        "country" | "ip" => "未联网检测".into(),
        "timezone" => "/etc/localtime".into(),
        "locale" => "defaults AppleLocale / Foundation 日期模板".into(),
        "language" if !text(local, "app_language").is_empty() => "Claude AppleLanguages".into(),
        "language" => "系统 AppleLanguages（Claude 未单独设置）".into(),
        _ => String::new(),
    }
}
trait EmptyFallback {
    fn if_empty(self, fallback: &str) -> String;
}
impl EmptyFallback for String {
    fn if_empty(self, fallback: &str) -> String {
        if self.is_empty() {
            fallback.into()
        } else {
            self
        }
    }
}

fn value_rows(
    host: &Host,
    config: &Config,
    mode: Option<&str>,
    proposed: Option<&Value>,
) -> Result<Vec<Value>> {
    let net = network(host)?;
    let mut probe = config.clone();
    if let Some(mode) = mode.filter(|mode| !mode.is_empty()) {
        probe.proxy_mode = mode.into();
    }
    let facts = local(host, &probe)?;
    let current = onboarding::current_values(&net, &facts);
    let confirmed = host.storage.read_json(
        &host.storage.paths.base().join("confirmed-environment.json"),
        Value::Null,
    )?;
    let confirmed_matches = confirmed["policy"] == policy_digest(&config.value()?)?;
    let candidate = proposed.is_some();
    Ok(VALUE_IDS.into_iter().map(|(id, title)| {
        let actual = match id {
            "country" | "ip" if candidate => proposed.unwrap()[id].clone(),
            "runtime_mode" => json!(runtime_mode_label(&current[id])),
            _ => current[id].clone(),
        };
        let target = match id {
            "language" => json!(if config.require_english { "English" } else { "未限定" }),
            "runtime_mode" => json!("只读实测，无需配置"),
            "node" if confirmed_matches => confirmed["values"][id].clone(),
            "ip" if !config.expected_egress.is_empty() => json!(config.expected_egress.join(", ")),
            "ip" if config.allow_ip_change => json!("检测历史变化仅提示；受控会话固定本次基准"),
            "ip" => json!("按历史检测变化"),
            _ => config.value().ok().and_then(|v| v.get(id).cloned()).unwrap_or(Value::Null),
        };
        let target_source = if confirmed_matches { text(&confirmed["sources"], id) } else { "".into() };
        let proposed_text = match proposed {
            Some(values) if id == "runtime_mode" => match values[id].as_str().unwrap_or("") {
                "" => String::new(),
                _ => runtime_mode_label(&values[id]),
            },
            Some(values) => values[id].as_str().unwrap_or("").to_owned(),
            None => String::new(),
        };
        json!({"id":id,"title":title,"current":display(&actual,"未知"),"target":display(&target,"未配置"),"proposed":proposed_text,"source":source(id,&facts,&net,candidate),"target_source":if target_source.is_empty() { "已保存设置（手动或旧版，检测来源未记录）".to_owned() } else { target_source },"proposed_source":proposed.map(|v| text(&v["sources"],id)).unwrap_or_default()})
    }).collect())
}

fn unsupported_actions(plan: &mut Value) {
    let unsupported: Vec<Value> = plan["actions"].as_array().into_iter().flatten().filter_map(|action| {
        if !matches!(action["id"].as_str(), Some("timezone" | "locale" | "language" | "ipv6" | "watchdog" | "updater" | "flush_dns" | "start_proxy" | "reload_proxy" | "enable_tun" | "rules" | "reference")) {
            Some(json!({"id":action["id"],"detail":"当前原生写入器尚未支持此动作；确认执行会拒绝，未放宽验收。"}))
        } else { None }
    }).collect();
    if !unsupported.is_empty() {
        plan["unsupported_actions"] = json!(unsupported);
    }
}

fn setup_inspect(paths: Paths, mode: &str) -> Result<Value> {
    let host = host(paths, Authority::ReadOnly)?;
    let config = ConfigStore {
        storage: host.storage.clone(),
    }
    .load()?;
    let facts = local(&host, &config)?;
    let confirmed = host.storage.read_json(
        &host.storage.paths.base().join("confirmed-environment.json"),
        Value::Null,
    )?;
    Ok(
        json!({"status":"ok","observed_at":OnboardingSystem::now(&host),"initialized":host.storage.paths.config().is_file()&&!config.country.is_empty()&&!config.timezone.is_empty(),"rows":value_rows(&host,&config,Some(mode),None)?,"candidates":facts["candidates"].as_array().cloned().unwrap_or_default(),"message":text(&facts,"proxy_detail").if_empty("本机读取完成；尚未联网检测"),"confirmed_at":if confirmed["policy"]==policy_digest(&config.value()?)? {confirmed["confirmed_at"].clone()} else {Value::Null},"recovery_required":host.storage.paths.base().join("setup-transaction.json").is_file()}),
    )
}

fn setup_detect(paths: Paths, request: &Request) -> Result<Value> {
    let host = host(paths, Authority::ReadOnly)?;
    let mode = request.value("mode").unwrap_or("auto");
    let mut candidate = onboarding::detect(
        &host.storage,
        &host,
        mode,
        request.flag("online"),
        &load_system_catalog(),
    )?;
    let config = ConfigStore {
        storage: host.storage.clone(),
    }
    .load()?;
    candidate["rows"] = json!(value_rows(
        &host,
        &config,
        Some(mode),
        Some(&candidate["values"])
    )?);
    candidate["message"] = json!("本轮实测候选；确认前不会保存环境基线或修改系统设置。");
    Ok(candidate)
}

fn setup_preview(paths: Paths, request: &Request) -> Result<Value> {
    let host = host(paths, Authority::ReadOnly)?;
    let id = missing(
        request.value("candidate-id"),
        "candidate_required",
        "请先完成环境检测",
    )?;
    let options = crate::bounded_input(request.input_limit())?;
    let mut plan = onboarding::preview(&host.storage, &host, id, &options, None)?;
    let config = ConfigStore {
        storage: host.storage.clone(),
    }
    .load()?;
    plan["rows"] = json!(value_rows(&host, &config, None, Some(&plan["values"]))?);
    unsupported_actions(&mut plan);
    Ok(plan)
}

fn setup_apply(paths: Paths, request: &Request) -> Result<Value> {
    require_apply(request)?;
    let mut host = host(paths, Authority::ExplicitPermit)?;
    let candidate = missing(
        request.value("candidate-id"),
        "candidate_required",
        "请先完成环境检测",
    )?;
    let plan = missing(
        request.value("plan-id"),
        "plan_required",
        "请先预览并提交对应 plan-id",
    )?;
    let options = crate::bounded_input(request.input_limit())?;
    onboarding::apply(
        &host.storage.clone(),
        &mut host,
        candidate,
        &options,
        plan,
        None,
    )
}

fn repair_dispatch(paths: Paths, request: &Request) -> Result<Value> {
    let mut host = host(
        paths,
        if request.flag("apply") {
            Authority::ExplicitPermit
        } else {
            Authority::ReadOnly
        },
    )?;
    let config = ConfigStore {
        storage: host.storage.clone(),
    }
    .load()?;
    let plan = if request.command == "set-region" {
        repair::region_plan(
            &host,
            &config,
            &load_system_catalog(),
            request.value("allow-country"),
            None,
        )?
    } else {
        repair::make_plan(&config, &local(&host, &config)?, None)?
    };
    if !request.flag("apply") {
        let mut plan = plan;
        unsupported_actions(&mut plan);
        return Ok(plan);
    }
    require_apply(request)?;
    let id = missing(
        request.value("plan-id"),
        "plan_required",
        "先预览并提交对应 plan-id",
    )?;
    let desired = Config::from_value(plan["desired_config"].clone())?;
    repair::apply_plan(&host.storage.clone(), &mut host, &desired, id, None)
}

pub fn dispatch(request: &Request, paths: Paths) -> Result<Option<Value>> {
    match (request.command.as_str(), request.action.as_deref()) {
        ("setup", Some("inspect")) => Ok(Some(setup_inspect(
            paths,
            request.value("mode").unwrap_or("auto"),
        )?)),
        ("setup", Some("detect")) => Ok(Some(setup_detect(paths, request)?)),
        ("setup", Some("preview")) => Ok(Some(setup_preview(paths, request)?)),
        ("setup", Some("apply")) => Ok(Some(setup_apply(paths, request)?)),
        ("setup", Some("recover")) => crate::runtime::recover_maintenance(request, paths).map(Some),
        ("protection", Some("preview")) => {
            let host = host(paths, Authority::ReadOnly)?;
            Ok(Some(services::protection_preview(
                &host.storage,
                &host,
                &crate::bounded_input(request.input_limit())?,
            )?))
        }
        ("protection", Some("apply")) => {
            require_apply(request)?;
            let mut host = host(paths, Authority::ExplicitPermit)?;
            let changes = crate::bounded_input(request.input_limit())?;
            let id = missing(
                request.value("plan-id"),
                "plan_required",
                "先预览具体后台变更",
            )?;
            Ok(Some(services::protection_apply(
                &host.storage.clone(),
                &mut host,
                &changes,
                id,
            )?))
        }
        ("repair" | "fix" | "set-region", _) => Ok(Some(repair_dispatch(paths, request)?)),
        ("restore-settings", _) => {
            require_apply(request)?;
            let mut host = host(paths, Authority::ExplicitPermit)?;
            let config = ConfigStore {
                storage: host.storage.clone(),
            }
            .load()?;
            Ok(Some(repair::restore_settings(
                &host.storage.clone(),
                &mut host,
                missing(
                    request.receipt_id.as_deref(),
                    "receipt_required",
                    "需要对应修复回执",
                )?,
                &config,
            )?))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::runtime_mode_label;
    use serde_json::json;

    #[test]
    fn runtime_mode_labels_match_proxy_detail_wording() {
        assert_eq!(runtime_mode_label(&json!("rule")), "规则模式");
        assert_eq!(runtime_mode_label(&json!("global")), "全局模式");
        assert_eq!(runtime_mode_label(&json!("direct")), "直连模式");
        assert_eq!(runtime_mode_label(&json!("script")), "未知");
        assert_eq!(runtime_mode_label(&serde_json::Value::Null), "未知");
    }
}
