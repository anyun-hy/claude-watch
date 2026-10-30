//! Production macOS facts and explicitly authorized OS adapters.
#![forbid(unsafe_code)]

use crate::{
    audit_store::AuditSystem,
    commands::{ReadCommand, ReadRunner, ServiceLabel},
    native::{self, Observer},
    network_client::{NetworkClient, Transport},
    onboarding::OnboardingSystem,
    repair::RepairSystem,
    sampler::{ProcessRound, Sampler, SocketRound},
    services::ServiceSystem,
    storage::{sha256, StateStore},
};
use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, os::unix::fs::MetadataExt, time::Duration};

/// Match complete executable prefixes, never a display name or command argument.
fn proxy_mode(executable: &str) -> Option<&'static str> {
    for (mode, prefixes) in [
        ("tag", &["/Applications/TAG.app/Contents/"][..]),
        (
            "clash-verge",
            &[
                "/Applications/Clash Verge.app/Contents/",
                "/Library/PrivilegedHelperTools/io.github.clash-verge",
            ][..],
        ),
        ("shadowrocket", &["/Applications/Shadowrocket.app/"][..]),
        (
            "sing-box",
            &[
                "/opt/homebrew/Cellar/sing-box/",
                "/usr/local/Cellar/sing-box/",
                "/usr/local/bin/sing-box",
            ][..],
        ),
        (
            "clashx",
            &[
                "/Applications/ClashX.app/",
                "/Library/PrivilegedHelperTools/com.west2online.ClashX",
            ][..],
        ),
        (
            "surge",
            &[
                "/Applications/Surge.app/",
                "/Library/PrivilegedHelperTools/com.nssurge.",
            ][..],
        ),
    ] {
        if prefixes.iter().any(|prefix| executable.starts_with(prefix))
            && (!matches!(mode, "tag" | "clash-verge")
                || executable
                    .rsplit('/')
                    .next()
                    .unwrap_or("")
                    .contains("mihomo"))
        {
            return Some(mode);
        }
    }
    None
}

fn route_interface(route: &str) -> Option<&str> {
    route
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
        .filter(|v| !v.is_empty())
}

fn fake_ip_interface(interfaces: &str, wanted: &str) -> bool {
    let mut current = "";
    for line in interfaces.lines() {
        if !line.starts_with(char::is_whitespace) {
            current = line.split(':').next().unwrap_or("");
        } else if current == wanted {
            let mut fields = line.split_whitespace();
            if fields.next() == Some("inet")
                && fields.next().is_some_and(|ip| {
                    ip.parse::<std::net::Ipv4Addr>()
                        .is_ok_and(|ip| ip.octets()[0] == 198 && matches!(ip.octets()[1], 18 | 19))
                })
            {
                return true;
            }
        }
    }
    false
}

pub use crate::macos_mutations::FixedMacosMutator;

/// Writes are impossible unless the host explicitly hands this adapter a
/// permit. The desktop's normal read-only construction uses `ReadOnly`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    ReadOnly,
    ExplicitPermit,
}
pub trait Mutator: Send {
    fn apply(&mut self, action: &Value) -> Result<()>;
    fn restore(&mut self, action: &Value) -> Result<bool>;
}
pub struct Macos<R: ReadRunner, T: Transport, M: Mutator> {
    pub runner: R,
    pub network: NetworkClient<T>,
    pub storage: StateStore,
    pub authority: Authority,
    pub mutator: M,
    pub probes: std::sync::Arc<dyn crate::online_probes::OnlineProbes>,
}

struct BackendFacts {
    sampling_healthy: bool,
    guard_healthy: bool,
    sampling_native: bool,
    guard_native: bool,
    sampling_detail: &'static str,
    guard_detail: &'static str,
    diagnostics: Value,
}

/// A fresh observation and independently verified backend are both required;
/// a matching policy alone never makes an unhealthy guard ready.
pub fn guard_heartbeat_confirmed(
    config: &Config,
    backend: bool,
    now: f64,
    heartbeat: &Value,
) -> bool {
    let age = heartbeat["time"].as_f64().map(|time| now - time);
    config.enabled
        && config.guard_enabled
        && backend
        && age.is_some_and(|age| (0.0..=35.0).contains(&age))
        && heartbeat["status"] == "ok"
        && crate::config_store::guard_heartbeat_policy_matches(heartbeat, config) == Some(true)
}
impl<R: ReadRunner, T: Transport, M: Mutator> Macos<R, T, M> {
    pub fn environment(&self) -> Result<Value> {
        Observer {
            runner: &self.runner,
        }
        .environment()
    }
    fn read(&self, command: ReadCommand) -> Option<String> {
        let output = self
            .runner
            .run(command, &[], Duration::from_secs(3), 256 * 1024)
            .ok()?;
        (output.status == 0)
            .then(|| output.text().ok().map(str::to_owned))
            .flatten()
    }
    fn helper(&self) -> Value {
        let path =
            std::path::Path::new("/Library/Application Support/ClaudeWatch/claude-watch-admin.sh");
        let meta = fs::symlink_metadata(path).ok();
        let parent = path.parent().and_then(|p| fs::symlink_metadata(p).ok());
        let root = meta.as_ref().is_some_and(|m| {
            m.is_file()
                && !m.file_type().is_symlink()
                && m.uid() == 0
                && (m.mode() & 0o022) == 0
                && m.len() <= 1024 * 1024
        }) && parent.is_some_and(|m| {
            m.is_dir() && !m.file_type().is_symlink() && m.uid() == 0 && m.mode() & 0o022 == 0
        });
        let hash = if root {
            fs::read(path).ok().map(|b| sha256(&b))
        } else {
            None
        };
        let expected = sha256(include_bytes!("../../../monitor/Resources/watch-admin.sh"));
        // This pinned source implements ABI 1. Reading its exact hash needs no
        // administrator prompt; executing its root-only `status` as a normal
        // user would falsely label every installed helper unavailable.
        let trusted = root && hash.as_deref() == Some(expected.as_str());
        json!({"trusted":trusted,"abi":if trusted{Some(1)}else{None},"root_owned":root,"sha256":hash,"expected_sha256":expected,"source":"root-owned helper / exact bundled ABI 1 hash"})
    }
    fn job(&self, label: ServiceLabel) -> Value {
        self.job_observation(ReadCommand::LaunchctlSystem { label })
    }
    fn job_observation(&self, command: ReadCommand) -> Value {
        match self
            .runner
            .run(command, &[], Duration::from_secs(3), 256 * 1024)
        {
            Ok(out) if out.status == 0 => {
                let text = out.text().unwrap_or("");
                let field = |name: &str| {
                    text.lines()
                        .find_map(|line| line.trim().strip_prefix(name).map(str::trim))
                };
                json!({"registered":true,"trusted":false,"state":field("state =").unwrap_or("unknown"),"last_exit":field("last exit code =").and_then(|v|v.parse::<i32>().ok()),"pid":field("pid =").and_then(|v|v.parse::<u32>().ok()),"definition":null,"detail":"已读取任务；定义文件仍需独立验证"})
            }
            Ok(out)
                if out
                    .error_text()
                    .ok()
                    .is_some_and(|v| v.contains("Could not find service")) =>
            {
                json!({"registered":false,"trusted":false,"state":"absent","definition":null})
            }
            _ => {
                json!({"registered":null,"trusted":false,"state":"unknown","definition":null,"detail":"系统任务状态读取失败，不能判定为已停止"})
            }
        }
    }
    fn gui_updater(&self) -> Value {
        let uid = self
            .environment()
            .ok()
            .and_then(|v| v["uid"].as_u64())
            .and_then(|v| u32::try_from(v).ok())
            .filter(|v| *v > 0);
        uid.map(|uid| self.job_observation(ReadCommand::LaunchctlGuiUpdater { uid }))
            .unwrap_or_else(
                || json!({"registered":null,"trusted":false,"state":"unknown","definition":null}),
            )
    }
    fn backend_facts(&self) -> BackendFacts {
        let mut diagnostics = json!({"reason":"unavailable","observed_at":native::now()});
        let unavailable = |reason, detail, mut diagnostics: Value| {
            diagnostics["reason"] = json!(reason);
            diagnostics["detail"] = json!(detail);
            BackendFacts {
                sampling_healthy: false,
                guard_healthy: false,
                sampling_native: false,
                guard_native: false,
                sampling_detail: detail,
                guard_detail: detail,
                diagnostics,
            }
        };
        let bytes = match self
            .storage
            .read_bytes(&self.storage.paths.watch().join("state/heartbeat"), 4096)
        {
            Ok(Some(bytes)) => {
                diagnostics["heartbeat_present"] = json!(true);
                bytes
            }
            Ok(None) => {
                diagnostics["heartbeat_present"] = json!(false);
                return unavailable("heartbeat_missing", "未找到或无法读取采集后台心跳", diagnostics);
            }
            Err(e) => {
                diagnostics["source_error_code"] = json!(e.code);
                return unavailable("heartbeat_unreadable", "未找到或无法读取采集后台心跳", diagnostics);
            }
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return unavailable("heartbeat_encoding", "后台心跳编码无效", diagnostics);
        };
        let fields: Vec<_> = text.trim().split('|').collect();
        if fields.len() != 5 || !matches!(fields[3], "ok" | "error") {
            return unavailable("heartbeat_format", "心跳质量状态无效", diagnostics);
        }
        let sampling_healthy = fields[3] == "ok";
        let Ok(pid) = fields[0].parse::<u32>() else {
            return unavailable("pid_invalid", "心跳 PID 无效", diagnostics);
        };
        diagnostics["heartbeat_pid"] = json!(pid);
        diagnostics["heartbeat_status"] = json!(fields[3]);
        let Ok(sampled) = fields[2].parse::<f64>() else {
            return unavailable("time_invalid", "心跳时间字段无效", diagnostics);
        };
        let age = native::now() - sampled;
        diagnostics["heartbeat_age_seconds"] = json!(age.is_finite().then_some(age));
        if !(0.0..=30.0).contains(&age) {
            return unavailable("heartbeat_stale", "后台心跳已过期或时间异常", diagnostics);
        }
        let sampler = Sampler::new(&self.runner, self.storage.paths.clone());
        let table = match sampler.process_table() {
            Ok(table) => table,
            Err(e) => {
                diagnostics["source_error_code"] = json!(e.code);
                return unavailable("process_sample_failed", "系统进程采样失败", diagnostics);
            }
        };
        diagnostics["process_found"] = json!(table.contains_key(&pid));
        let Some(process) = table.get(&pid) else {
            return unavailable("pid_unconfirmed", "心跳 PID 已退出或无法确认", diagnostics);
        };
        let Some(uid) = process["uid"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .filter(|v| *v > 0)
        else {
            return unavailable("uid_invalid", "采集后台用户身份无效", diagnostics);
        };
        let same_stamp = process["stamp"]
            .as_str()
            .is_some_and(|v| v.split_whitespace().eq(fields[1].split_whitespace()));
        let job = self.job_observation(ReadCommand::LaunchctlGuiAgent { uid });
        diagnostics["start_identity_matches"] = json!(same_stamp);
        diagnostics["launchd_registered"] = job["registered"].clone();
        diagnostics["launchd_state"] = job["state"].clone();
        diagnostics["launchd_pid"] = job["pid"].clone();
        let direct_job = job["registered"] == true && job["state"] == "running" && job["pid"] == pid;
        let worker = if same_stamp && !direct_job {
            let result = crate::native_listener::registered_worker_result(&self.storage, &self.runner, pid);
            diagnostics["worker_verified"] = json!(result.is_ok());
            if let Err(ref e) = result {
                diagnostics["worker_error_code"] = json!(e.code);
            }
            result.is_ok()
        } else {
            false
        };
        let identity_healthy = same_stamp && (direct_job || worker);
        let guard_native = identity_healthy
            && process["executable"].as_str()
                == self
                    .storage
                    .paths
                    .watch()
                    .join("runtime/watch-engine")
                    .to_str();
        let guard_detail = if !same_stamp {
            "心跳 PID 的启动身份不匹配"
        } else if !identity_healthy {
            "launchd 任务、PID 或运行状态未通过核对"
        } else if !guard_native {
            "当前采集后台为旧组件，不支持原生观察租约"
        } else if !sampling_healthy {
            "原生采集后台身份已核对；本轮监控采样未完整"
        } else {
            "原生采集后台身份与心跳已核对"
        };
        diagnostics["native_path_matches"] = json!(process["executable"].as_str() == self.storage.paths.watch().join("runtime/watch-engine").to_str());
        diagnostics["reason"] = json!(if !same_stamp { "identity_mismatch" } else if !identity_healthy { "job_unconfirmed" } else if !guard_native { "native_path_mismatch" } else { "confirmed" });
        diagnostics["detail"] = json!(guard_detail);
        BackendFacts {
            // Preserve the strict historical monitor verdict: sampling health
            // binds heartbeat quality and daemon identity, but does not make a
            // path mismatch look like a complete monitoring round.
            sampling_healthy: sampling_healthy && identity_healthy,
            guard_healthy: guard_native,
            sampling_native: sampling_healthy && guard_native,
            guard_native,
            sampling_detail: if sampling_healthy {
                guard_detail
            } else {
                "心跳未报告完整监控采样"
            },
            guard_detail,
            diagnostics,
        }
    }
    fn guard_heartbeat(&self, config: &Config, backend: bool) -> bool {
        let heartbeat = self
            .storage
            .read_json(
                &self.storage.paths.base().join("guard-heartbeat.json"),
                Value::Null,
            )
            .ok();
        heartbeat.is_some_and(|v| guard_heartbeat_confirmed(config, backend, native::now(), &v))
    }
    fn local_facts(&self, c: &Config) -> Result<Value> {
        let env = self.environment()?;
        let uid = env["uid"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| CoreError::new("invalid_native_observation", "未取得当前用户身份"))?;
        let sampler = Sampler::new(&self.runner, self.storage.paths.clone());
        let table = sampler.process_table();
        let native_inventory = Observer {
            runner: &self.runner,
        }
        .inventory();
        let mut identity_unavailable = !native_inventory.as_ref().is_ok_and(|v| v.uid == uid);
        let mut candidates = BTreeMap::<&str, Vec<Value>>::new();
        if let Ok(table) = &table {
            for (pid, process) in table {
                if process["uid"] != 0 && process["uid"] != uid {
                    continue;
                }
                if let Some(mode) = proxy_mode(process["executable"].as_str().unwrap_or("")) {
                    if c.proxy_mode == "auto" || c.proxy_mode == mode {
                        let mut identity = process.clone();
                        identity["pid"] = json!(pid);
                        identity["start_stamp"] = identity["stamp"].clone();
                        if process["uid"] == uid {
                            if let Some(record) = native_inventory
                                .as_ref()
                                .ok()
                                .and_then(|v| v.processes.get(pid))
                                .filter(|record| {
                                    record.identity.uid == uid
                                        && record.identity.executable
                                            == process["executable"].as_str().unwrap_or("")
                                        && claude_watch_core::processes::normalized_stamp(
                                            &record.identity.start_stamp,
                                        ) == claude_watch_core::processes::normalized_stamp(
                                            process["stamp"].as_str().unwrap_or(""),
                                        )
                                })
                            {
                                identity["start_seconds"] = json!(record.identity.start_seconds);
                                identity["start_microseconds"] =
                                    json!(record.identity.start_microseconds);
                                identity["native_identity"] = json!(true);
                            } else {
                                identity_unavailable = true;
                            }
                        }
                        candidates.entry(mode).or_default().push(identity);
                    }
                }
            }
        }
        let selected = if candidates.len() == 1 {
            candidates.keys().next().copied().unwrap_or("")
        } else {
            ""
        };
        let mut unavailable: Vec<&str> = Vec::new();
        let mut proxy = if table.is_err() || candidates.len() > 1 || identity_unavailable {
            "unknown"
        } else if selected.is_empty() {
            "fail"
        } else {
            "ok"
        };
        let mut detail = if proxy == "ok" {
            format!("已识别 {selected}")
        } else {
            "代理未运行、身份不完整或存在多个候选".into()
        };
        let route = self.read(ReadCommand::Route(std::net::IpAddr::from([198, 18, 0, 1])));
        let interfaces = self.read(ReadCommand::Interfaces);
        let interface = route.as_deref().and_then(route_interface).unwrap_or("");
        let tun = match (&route, &interfaces) {
            (Some(_), Some(interfaces))
                if !selected.is_empty() && fake_ip_interface(interfaces, interface) =>
            {
                "ok"
            }
            (Some(_), Some(_)) => "fail",
            _ => "unknown",
        };
        if tun == "unknown" {
            unavailable.push("tun_sampling");
        }
        let mut tag = json!({});
        if selected == "tag" {
            // Environment checks need the controller identity, not all AI app sockets.
            let round = ProcessRound {
                id: uuid::Uuid::new_v4().to_string(),
                uid,
                targets: vec![],
                identities: BTreeMap::new(),
                roles: json!({}),
                unavailable: vec![],
                complete: true,
                observed_at: native::now(),
            };
            let sockets = SocketRound {
                flows: vec![],
                receipt: json!({}),
            };
            tag = sampler.tag_report(&round, &sockets, &c.proxy_group, "");
            if tag["entry"]["state"] != "verified"
                || tag["api"]["state"] != "available"
                || tag["api"]["covers_7890"] != true
            {
                proxy = "unknown";
                detail = "TAG 7890 监听者、控制接口或该入口覆盖范围未确认".into();
                unavailable.push("tag_snapshot");
            } else if tag["selection_changed"] == true {
                proxy = "fail";
                detail = "TAG 分组或节点偏离已确认的预期".into();
            }
        }
        if proxy == "unknown" && unavailable.is_empty() {
            unavailable.push("proxy_sampling");
        }
        let processes: Vec<_> = candidates.values().flatten().cloned().collect();
        // Preserve the mature digest contract. Parent PID, collection source
        // and network-service metadata are not proxy identity. The old native
        // inventory supplied microseconds but no display start_stamp; its root
        // ps supplement supplied only start_stamp, never invented precision.
        let mut context_processes=processes.iter().map(|p|json!({"pid":p["pid"],"uid":p["uid"],"executable":p["executable"],"start_stamp":if p["native_identity"]==true{Value::Null}else{p["start_stamp"].clone()},"start_seconds":p["start_seconds"],"start_microseconds":p["start_microseconds"]})).collect::<Vec<_>>();
        context_processes
            .sort_by_key(|p| (p["pid"].as_u64().unwrap_or(0), p["start_stamp"].to_string()));
        let mut identity =
            json!({"mode":selected,"tun":tun,"interface":interface,"processes":context_processes});
        if selected == "tag" {
            identity["selection"] = json!({"mode":tag["api"]["mode"],"selected_node":tag["api"]["selected_node"],"global_node":tag["api"]["global_node"]});
            identity["group"] = tag["expected_group"].clone();
        }
        let context = crate::config_store::policy_digest(&identity)?;
        let backend = self.backend_facts();
        let guard = self.guard_heartbeat(c, backend.guard_healthy);
        let mut out = json!({"proxy":proxy,"proxy_detail":detail,"tun":tun,"mode":selected,"candidates":candidates.keys().collect::<Vec<_>>(),"context":context,"context_id":context,"timezone":env.get("timezone"),"locale":env.get("locale"),"language":env.get("language"),"app_language":env.get("app_language"),"date_format":env.get("date_format"),"ipv6":env.get("ipv6"),"ipv6_method":env.get("ipv6_method"),"network":env.get("network"),"network_identity":identity,"service":env.pointer("/network/service"),"interface":interface,"processes":processes,"tag":tag,"observation_unavailable":unavailable,"backend_healthy":backend.sampling_healthy,"backend_native":backend.sampling_native,"backend_detail":backend.sampling_detail,"guard_backend_healthy":backend.guard_healthy,"guard_backend_native":backend.guard_native,"guard_backend_detail":backend.guard_detail,"guard":guard,"guard_state":if guard{"ok"}else if !c.guard_enabled{"disabled"}else{"unknown"},"guard_detail":if guard{"保护心跳已确认"}else if !c.guard_enabled{"保护策略已禁用"}else{"保护心跳或后台身份未能确认"}});
        out["verified_proxy_url"] = if selected == "tag"
            && proxy == "ok"
            && tag["entry"]["state"] == "verified"
            && tag["api"]["covers_7890"] == true
        {
            json!(crate::network_client::DEFAULT_PROXY)
        } else {
            Value::Null
        };
        let entries = tag
            .pointer("/rules/entries")
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            });
        out["rules"] = if selected == "tag" && tag["api"]["state"] == "available" {
            crate::rules::inspect_tag_rules(entries.as_deref(), &[], &tag["api"])
        } else {
            json!({"state":"unknown","detail":"未取得当前代理的实际规则证据"})
        };
        Ok(out)
    }
    fn online_facts(&self, _: &Config, local: &Value, include_claude: bool) -> Result<Value> {
        let context = local
            .get("context_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let egress = self.network.fast_egress();
        let raw_trace = egress.data.clone().unwrap_or(Value::Null);
        let trace = json!({"ip":raw_trace["ip"],"loc":raw_trace["country"],"observed_at":raw_trace["observed_at"]});
        let ip = trace.get("ip").and_then(Value::as_str).unwrap_or("");
        let measured_at = trace
            .get("observed_at")
            .and_then(Value::as_f64)
            .unwrap_or(0.);
        let lookup_receipt = (!ip.is_empty()).then(|| {
            self.network
                .metadata_for_context("lookup", context, ip, measured_at)
        });
        let lookup = lookup_receipt
            .as_ref()
            .map(crate::network_client::Receipt::display_value)
            .unwrap_or(Value::Null);
        let mut query_errors = if egress.status == "complete" {
            json!({})
        } else {
            json!({"egress":{"source":egress.source_url,"message":egress.error}})
        };
        let mut geo = json!({"ip":ip,"country":Value::Null,"timezone":Value::Null});
        let mut geo_sampled_at = None;
        let lookup_data = lookup_receipt.as_ref().and_then(|receipt| {
            (receipt.status == "complete" && receipt.http_status == Some(200))
                .then_some(receipt.data.as_ref())
                .flatten()
                .filter(|data| data.is_object())
        });
        let lookup_bound = lookup_data.is_some_and(|data| {
            lookup_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.query == ip)
                && data
                    .get("ip")
                    .and_then(Value::as_str)
                    .and_then(claude_watch_core::network::public_unicast)
                    .as_deref()
                    == Some(ip)
        });
        let mut conflict = false;
        if let Some(data) = lookup_data.filter(|_| lookup_bound) {
            let country = data
                .get("countryCode")
                .or_else(|| data.get("country_code"))
                .and_then(Value::as_str)
                .map(|country| country.to_ascii_uppercase())
                .filter(|country| {
                    country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_uppercase())
                });
            let timezone = data
                .get("timezone")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| {
                    let zones = data
                        .get("geo_sources")?
                        .as_array()?
                        .iter()
                        .filter_map(|row| row.get("timezone").and_then(Value::as_str))
                        .collect::<std::collections::BTreeSet<_>>();
                    (zones.len() == 1).then(|| zones.into_iter().next().unwrap().to_owned())
                });
            if country
                .as_deref()
                .is_some_and(|country| country != trace["loc"].as_str().unwrap_or(""))
            {
                conflict = true;
                query_errors["egress_consistency"] = json!({"source":"Cloudflare trace / Net.Coffee","message":"Cloudflare 与 Net.Coffee 出口国家不一致"});
            }
            geo = json!({"ip":ip,"country":country,"timezone":timezone,
                "country_source":"Net.Coffee lookup","timezone_source":"Net.Coffee lookup"});
            geo_sampled_at = lookup_receipt.as_ref().map(|value| value.finished_at);
        } else if lookup_receipt.is_some() {
            // A positive mismatch rejected by NetworkClient must not disappear
            // when the display data is cleared; malformed fields are different.
            let returned = lookup_receipt
                .as_ref()
                .filter(|r| r.http_status == Some(200))
                .and_then(|r| crate::storage::strict_json(r.raw.as_bytes()).ok());
            let other_ip = lookup_data
                .or(returned.as_ref())
                .and_then(|data| data["ip"].as_str())
                .and_then(claude_watch_core::network::public_unicast);
            let actual_conflict = other_ip.as_deref().is_some_and(|other| other != ip);
            let (source, message) = if actual_conflict {
                (
                    "Cloudflare trace / Net.Coffee",
                    "Cloudflare 与 Net.Coffee 出口 IP 不一致",
                )
            } else {
                ("Net.Coffee lookup", "Net.Coffee 查询未完成")
            };
            query_errors[if actual_conflict {
                "egress_consistency"
            } else {
                "netcoffee"
            }] = json!({"source":source,"message":message});
            conflict = actual_conflict;
        }
        // A valid primary lookup is authoritative. Only genuinely absent geo
        // fields may use the cached geoip fallback; a known IP/country conflict
        // remains visible and cannot be overwritten by another source.
        // A country with exactly one IANA zone already resolves the timezone
        // (same rule as 2.9.5), so a missing `timezone` there is not a gap and
        // must not trigger a fallback.
        let single_zone_country = geo["country"].as_str().is_some_and(|country| {
            crate::region_catalog::system_catalog()
                .get(country)
                .is_some_and(|zones| zones.len() == 1)
        });
        if !ip.is_empty()
            && !conflict
            && (geo["country"].is_null() || (geo["timezone"].is_null() && !single_zone_country))
        {
            let fallback = self
                .network
                .metadata_for_context("geoip", context, ip, measured_at);
            if let Some(data) = fallback.data.as_ref().filter(|data| data.is_object()) {
                // `/api/geoip/` answers for the IP in the path and returns no
                // `ip` field, so provenance comes from the receipt query.  A
                // returned `ip` still has to match when the source provides it.
                let returned_ip = data
                    .get("ip")
                    .and_then(Value::as_str)
                    .and_then(claude_watch_core::network::public_unicast);
                let ip_bound = match returned_ip.as_deref() {
                    Some(value) => value == ip,
                    None => fallback.query == ip,
                };
                let bound =
                    fallback.status == "complete" && fallback.http_status == Some(200) && ip_bound;
                // `/api/geoip/` reports the full country name in `country` and
                // the ISO code in `country_code`, so the code wins; a
                // name-shaped value must never be read as a country code.
                let country = ["countryCode", "country_code", "country"]
                    .iter()
                    .filter_map(|key| data.get(*key).and_then(Value::as_str))
                    .map(|country| country.trim().to_ascii_uppercase())
                    .find(|country| {
                        country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_uppercase())
                    });
                if bound && country.as_deref() == trace["loc"].as_str() {
                    geo = json!({"ip":ip,"country":country,"timezone":data.get("timezone").cloned().unwrap_or(Value::Null),
                        "country_source":"Net.Coffee geoip fallback","timezone_source":"Net.Coffee geoip fallback"});
                    geo_sampled_at = Some(fallback.finished_at);
                } else if country.is_some() && returned_ip.is_some() {
                    query_errors["egress_consistency"] = json!({"source":"Cloudflare trace / Net.Coffee geoip","message":"Cloudflare 与 Net.Coffee 备用出口资料不一致"});
                } else {
                    query_errors["geo"] = json!({"source":"Net.Coffee geoip","message":"备用地理响应缺少有效 IP 或国家字段"});
                }
            } else {
                query_errors["geo"] =
                    json!({"source":"Net.Coffee geoip","message":"备用地理查询未完成"});
            }
        }
        let asn = lookup_receipt
            .as_ref()
            .filter(|_| lookup_bound)
            .and_then(crate::network_client::lookup_asn);
        let organization = lookup_data
            .filter(|_| lookup_bound)
            .and_then(|data| {
                data.get("asOrganization")
                    .or_else(|| data.get("asn_org"))
                    .or_else(|| data.get("org"))
            })
            .and_then(Value::as_str)
            .unwrap_or("");
        let mut asn_value =
            json!({"number":asn,"organization":organization,"source":"Net.Coffee lookup"});
        if let Some(receipt) = lookup_receipt.as_ref().filter(|_| asn.is_some()) {
            asn_value["queried_at"] = json!(receipt.finished_at);
            let number = asn.unwrap();
            let registration = self.network.ripe_asn(number);
            if let Some(country) =
                crate::network_client::ripe_registered_country(&registration, number)
            {
                asn_value["registered_country"] = json!(country);
                asn_value["registered_queried_at"] = json!(registration.finished_at);
                asn_value["result_time"] = json!(registration
                    .data
                    .as_ref()
                    .and_then(|v| v.pointer("/data/result_time"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .chars()
                    .take(80)
                    .collect::<String>());
            } else {
                query_errors["asn"] = json!({"source":"RIPEstat ASN","message":registration.error.unwrap_or_else(||"ASN 注册国家没有返回完整结果".into())});
            }
        }
        let services = include_claude.then(|| {
            (
                self.network.service_metadata("claude"),
                self.network.service_metadata("api"),
            )
        });
        let stun = self.stun_fact(context);
        let mut result = json!({"stun":stun,"trace":trace,"geo":geo,"asn":asn_value,"netcoffee_lookup":lookup,"query_errors":query_errors,
            "source_times":{"trace":egress.finished_at,"geo":geo_sampled_at,"asn":asn_value.get("registered_queried_at").or_else(||asn_value.get("queried_at"))}});
        if let Some((claude, api)) = services {
            result["source_times"]["claude"] = json!(claude.queried_at);
            result["source_times"]["api"] = json!(api.queried_at);
            result["service_responses"] = json!({"claude":crate::network_client::service_observation("claude",&claude),"api":crate::network_client::service_observation("api",&api)});
        }
        Ok(result)
    }

    /// The UDP/STUN probe is the one online fact that used to be re-run every
    /// round, so a single server's packet loss flipped the whole row.  It now
    /// reuses a context-bound receipt for `STUN_RECEIPT_TTL` — the same shape
    /// as the DNS/WebRTC receipts — and probes only when no fresh receipt
    /// exists.  `refresh_stun` (launch only) writes a fresh receipt first, so
    /// the launch gate never judges a cached round.
    fn stun_fact(&self, context: &str) -> Value {
        let store = crate::receipt_store::ReceiptStore {
            storage: self.storage.clone(),
        };
        let now = native::now();
        if let Some(fact) = store.stun_fact(context, now) {
            return fact;
        }
        let probe = self.probes.stun();
        // Persisting keeps the periodic view stable for the next window; a
        // failed write must not lose the observation we already paid for.
        let _ = store.record_stun(&probe, context, now);
        probe
    }
    fn write(&mut self, a: &Value) -> Result<()> {
        if self.authority != Authority::ExplicitPermit {
            return Err(CoreError::new(
                "write_not_authorized",
                "macOS 适配器处于只读模式",
            ));
        }
        self.mutator.apply(a)
    }
}
impl<R: ReadRunner, T: Transport, M: Mutator> AuditSystem for Macos<R, T, M> {
    fn now(&self) -> f64 {
        native::now()
    }
    fn network(&self) -> Result<Value> {
        let e = self.environment()?;
        Ok(
            json!({"service":e.pointer("/network/service"),"interface":e.pointer("/network/interface"),"service_id":e.pointer("/network/service_id")}),
        )
    }
    fn local(&self, c: &Config) -> Result<Value> {
        self.local_facts(c)
    }
    fn local_for_target(
        &self,
        c: &Config,
        target: claude_watch_core::processes::LaunchTarget,
    ) -> Result<Value> {
        let mut local = self.local_facts(c)?;
        if target.cli() {
            let overrides = if target == claude_watch_core::processes::LaunchTarget::ClaudeCli {
                crate::config_store::cli_proxy_overrides(&self.runner, &self.storage.paths.home)
            } else {
                Ok(Vec::new())
            };
            local["cli_proxy"] = match overrides {
                Ok(values) => claude_watch_core::audit::cli_proxy_state(
                    local["verified_proxy_url"].as_str(),
                    &values,
                ),
                Err(e) => json!({"state":"unknown","detail":e.message}),
            };
        }
        Ok(local)
    }
    fn online(&mut self, c: &Config, l: &Value) -> Result<Value> {
        self.online_facts(c, l, true)
    }
    fn online_for_target(
        &mut self,
        c: &Config,
        l: &Value,
        target: claude_watch_core::processes::LaunchTarget,
    ) -> Result<Value> {
        self.online_facts(c, l, target.protected())
    }
    fn refresh_dns(&mut self) -> Result<Option<Value>> {
        let token = std::env::var("CLAUDE_WATCH_DNS_REFRESH_TOKEN").ok();
        if token.is_none() {
            return Ok(None);
        }
        let env = self.environment()?;
        let uid = env["uid"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| CoreError::new("invalid_native_observation", "当前用户身份未确认"))?;
        crate::leak_refresh::refresh_for_launch(
            &self.storage,
            uid,
            token.as_deref(),
            Duration::from_secs(85),
        )?;
        // The GUI records the result through the receipt command. Revalidate the
        // persisted receipt in AuditStore; an acknowledgement cannot grant launch.
        Ok(None)
    }
    fn refresh_stun(&mut self, context: &str) -> Result<Option<Value>> {
        // A launch gate must judge a fresh round, so probe now and persist the
        // receipt; `online_facts` then reads this just-written observation.
        let probe = crate::online_probes::default_stun_value();
        let store = crate::receipt_store::ReceiptStore {
            storage: self.storage.clone(),
        };
        store.record_stun(&probe, context, native::now())?;
        Ok(Some(probe))
    }
}
impl<R: ReadRunner, T: Transport, M: Mutator> RepairSystem for Macos<R, T, M> {
    fn local(&self, c: &Config) -> Result<Value> {
        let mut facts = self.local_facts(c)?;
        let saved = crate::config_store::ConfigStore {
            storage: self.storage.clone(),
        }
        .load()?;
        facts["accepted_locale"] = json!(saved.locale);
        facts["saved_config_hash"] = json!(crate::config_store::policy_digest(&saved.value()?)?);
        facts["watchdog"] = self.watchdog_state()?;
        facts["updater"] = self.service_job("updater")?;
        if facts["mode"] == "clash-verge" || c.proxy_mode == "clash-verge" {
            let proxy = crate::proxy_mutations::read_clash_verge_config_facts(&self.storage)?;
            // Repair-only inputs. AuditSystem::local deliberately excludes
            // these credential-bearing configuration strings from UI receipts.
            facts["clash_verge_config"] = json!(proxy.clash_verge_config);
            facts["merge_text"] = json!(proxy.merge_text);
        }
        Ok(facts)
    }
    fn apply(&mut self, a: &Value) -> Result<()> {
        self.write(a)
    }
    fn egress_reference(&self, c: &Config) -> Result<Value> {
        let local = self.local_facts(c)?;
        let online = self.online_facts(c, &local, true)?;
        let trace = &online["trace"];
        Ok(json!({"trace":{"ip":trace["ip"],"loc":trace["loc"]},"geo":online["geo"]}))
    }
    fn restore(&mut self, a: &Value) -> Result<bool> {
        if self.authority != Authority::ExplicitPermit {
            return Ok(false);
        }
        self.mutator.restore(a)
    }
}
impl<R: ReadRunner, T: Transport, M: Mutator> OnboardingSystem for Macos<R, T, M> {
    fn network(&self) -> Result<Value> {
        AuditSystem::network(self)
    }
    fn now(&self) -> f64 {
        native::now()
    }
    fn baseline_data(&self) -> Result<String> {
        let input = crate::environment_capture::EnvironmentInput {
            home: self.storage.paths.home.clone(),
            environment: std::env::vars().collect(),
        };
        Ok(crate::environment_capture::capture(&self.runner, &input)?.data)
    }
}
impl<R: ReadRunner, T: Transport, M: Mutator> ServiceSystem for Macos<R, T, M> {
    fn now(&self) -> f64 {
        native::now()
    }
    fn backend_healthy(&self) -> bool {
        self.backend_facts().sampling_healthy
    }
    fn guard_backend_healthy(&self) -> bool {
        self.backend_facts().guard_healthy
    }
    fn guard_status(&self, config: &Config) -> Result<bool> {
        Ok(self.guard_heartbeat(config, self.guard_backend_healthy()))
    }
    fn backend_health_snapshot(
        &self,
        config: &Config,
    ) -> Result<crate::services::BackendHealthSnapshot> {
        let facts = self.backend_facts();
        Ok(crate::services::BackendHealthSnapshot {
            sampling_healthy: facts.sampling_healthy,
            guard_backend_healthy: facts.guard_healthy,
            guard_healthy: self.guard_heartbeat(config, facts.guard_healthy),
            diagnostics: facts.diagnostics,
        })
    }
    fn service_job(&self, name: &str) -> Result<Value> {
        let mut observation = match name {
            "watchdog" => self.job(ServiceLabel::Timezone),
            "original" => self.job(ServiceLabel::LegacyBodyguard),
            "updater" => self.gui_updater(),
            _ => json!({"registered":null,"trusted":false}),
        };
        match crate::service_native::read_job_definition(&self.storage, name, &self.runner) {
            Ok(value) => {
                for key in [
                    "trusted",
                    "definition",
                    "definition_present",
                    "label",
                    "interval",
                ] {
                    observation[key] = value[key].clone();
                }
            }
            Err(error) => {
                observation["trusted"] = json!(false);
                observation["definition_error"] = json!(error.message);
            }
        }
        Ok(observation)
    }
    fn watchdog_state(&self) -> Result<Value> {
        let job = self.service_job("watchdog")?;
        let target =
            std::path::Path::new("/Library/Application Support/ClaudeWatch/timezone.target");
        let value = fs::symlink_metadata(target)
            .ok()
            .filter(|m| {
                m.is_file()
                    && !m.file_type().is_symlink()
                    && m.uid() == 0
                    && m.mode() & 0o022 == 0
                    && m.len() < 1024
            })
            .and_then(|_| fs::read_to_string(target).ok())
            .map(|v| v.trim().to_owned());
        Ok(
            json!({"registered":job["registered"],"target":value,"trusted":job["trusted"],"source":"root timezone target and fixed launchd definition"}),
        )
    }
    fn admin_helper_status(&self) -> Result<Value> {
        Ok(self.helper())
    }
    fn runtime_present(&self) -> bool {
        self.storage
            .paths
            .home
            .join("Library/Application Support/ClaudeWatch/runtime/watch-engine")
            .is_file()
    }
    fn apply_service(&mut self, a: &Value) -> Result<()> {
        self.write(a)
    }
    fn restore_service(&mut self, a: &Value) -> Result<bool> {
        if self.authority != Authority::ExplicitPermit {
            return Ok(false);
        }
        self.mutator.restore(a)
    }
}
