//! Current-user process ownership, native socket sampling and TAG correlation in one round.
use crate::fakeip_probe::Source as _;
use crate::{
    commands::{ReadCommand, ReadRunner},
    fakeip_probe::{self, SampledFlow},
    local_http::Client,
    native::{self, Arguments, Observer},
    storage::{Paths, StateStore},
};
use claude_watch_core::{
    error::{CoreError, Result},
    process_roots::{self, Classification, RootEvidence, TrustedCliPaths},
    processes::{self, Identity, McpSpec, Target},
    tag_config,
    tag_flow::{self, CommandEvidence, CorrelationInput},
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use uuid::Uuid;

fn canonical(path: &Path) -> Option<PathBuf> {
    fs::canonicalize(path).ok()
}
fn command_path(command: &str, cwd: Option<&str>) -> Option<String> {
    let path = Path::new(command);
    let path = if path.is_absolute() || command.contains('/') {
        process_roots::lexical_path(command, cwd)?
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|p| p.join(command))
            .find(|p| p.is_file())?
    };
    canonical(&path).map(|p| p.to_string_lossy().into_owned())
}
pub(crate) fn cli_paths(paths: &Paths) -> TrustedCliPaths {
    let mut known = TrustedCliPaths::default();
    for (file, claude) in [
        (paths.home.join(".local/bin/claude"), true),
        (paths.home.join(".claude/local/claude"), true),
        (PathBuf::from("/opt/homebrew/bin/claude"), true),
        (PathBuf::from("/usr/local/bin/claude"), true),
        (PathBuf::from("/opt/homebrew/bin/codex"), false),
        (PathBuf::from("/usr/local/bin/codex"), false),
    ] {
        if let Some(path) = canonical(&file) {
            let path = path.to_string_lossy().into_owned();
            if claude {
                known.claude.insert(path);
            } else {
                known.codex.insert(path);
            }
        }
    }
    known
}
fn load_mcp_specs(paths: &Paths) -> Vec<McpSpec> {
    let store = StateStore::new(paths.clone());
    let mut result = Vec::new();
    for (path, toml) in [
        (paths.home.join(".codex/config.toml"), true),
        (
            paths
                .home
                .join("Library/Application Support/Claude/claude_desktop_config.json"),
            false,
        ),
        (paths.home.join(".claude.json"), false),
    ] {
        let Ok(Some(bytes)) = store.read_bytes(&path, 2 * 1024 * 1024) else {
            continue;
        };
        let data = if toml {
            std::str::from_utf8(&bytes)
                .ok()
                .and_then(|s| toml::from_str::<toml::Value>(s).ok())
                .and_then(|v| serde_json::to_value(v).ok())
        } else {
            crate::storage::strict_json(&bytes).ok()
        };
        let Some(data) = data else { continue };
        let key = if toml { "mcp_servers" } else { "mcpServers" };
        for (name, entry) in data[key].as_object().into_iter().flatten() {
            let Some(command) = entry["command"].as_str() else {
                continue;
            };
            let args = entry.get("args").cloned().unwrap_or(json!([]));
            let Ok(args) = serde_json::from_value::<Vec<String>>(args) else {
                continue;
            };
            if let Some(spec) = McpSpec::from_config(command, &args, name, |s| {
                command_path(s, Some(paths.home.to_string_lossy().as_ref()))
            }) {
                result.push(spec)
            }
        }
    }
    result
}
pub struct ProcessRound {
    pub id: String,
    pub uid: u32,
    pub targets: Vec<Target>,
    pub identities: BTreeMap<u32, Identity>,
    pub roles: Value,
    pub unavailable: Vec<Value>,
    pub diagnostic_reasons: BTreeMap<String, u32>,
    pub confirmed_exited_count: u32,
    pub complete: bool,
    pub observed_at: f64,
}
impl ProcessRound {
    pub fn public_value(&self) -> Value {
        json!({"schema":1,"round_id":self.id,"uid":self.uid,"state":if self.complete{"ok"}else{"partial"},"observed_at":self.observed_at,
        "targets":self.targets,"roles":self.roles,"unavailable":self.unavailable})
    }
}
pub struct SocketRound {
    pub flows: Vec<SampledFlow>,
    pub receipt: Value,
}
pub struct Sampler<R: ReadRunner> {
    pub runner: R,
    pub paths: Paths,
    tracked: Vec<Target>,
    trusted: TrustedCliPaths,
    #[cfg(test)]
    fixture_tag: bool,
}
impl<R: ReadRunner> Sampler<R> {
    pub fn new(runner: R, paths: Paths) -> Self {
        let trusted = cli_paths(&paths);
        Self {
            runner,
            paths,
            tracked: Vec::new(),
            trusted,
            #[cfg(test)]
            fixture_tag: false,
        }
    }
    #[cfg(test)]
    pub(crate) fn use_fixture_tag(&mut self) { self.fixture_tag = true; }
    pub fn processes(&mut self) -> Result<ProcessRound> {
        let observer = Observer {
            runner: &self.runner,
        };
        let inventory = observer.inventory()?;
        let id = Uuid::new_v4().to_string();
        let identities: BTreeMap<_, _> = inventory
            .processes
            .iter()
            .map(|(pid, p)| (*pid, p.identity.clone()))
            .collect();
        let leases = crate::lease_store::LeaseStore {
            storage: StateStore::new(self.paths.clone()),
        };
        let mut seeds = crate::lease_store::LeaseStore::launcher_targets(&leases.load(
            &identities,
            inventory.uid,
            false,
        )?);
        if self.tracked.is_empty() {
            self.tracked = leases.tracked()?;
        }
        let mut need_args = BTreeSet::new();
        let mut unavailable = inventory.unavailable.clone();
        let evidence = |pid: u32, args: Option<&Arguments>| {
            let record = &inventory.processes[&pid];
            process_roots::classify(
                RootEvidence {
                    identity: &record.identity,
                    bundle_path: record.bundle_path.as_deref(),
                    bundle_id: record.bundle_id.as_deref(),
                    arguments: args.map(|a| a.tokens.as_slice()),
                    cwd: args.map(|a| a.cwd.as_str()),
                },
                &self.paths.home,
                &self.trusted,
                canonical,
            )
        };
        for (pid, record) in &inventory.processes {
            match evidence(*pid, None) {
                Classification::Root(kind) => seeds.push(Target {
                    identity: record.identity.clone(),
                    kind,
                }),
                Classification::NeedArguments => {
                    need_args.insert(*pid);
                }
                Classification::NotTarget => {
                    if [
                        "/Claude.app/Contents/",
                        "/Codex.app/Contents/",
                        "/ChatGPT.app/Contents/",
                    ]
                    .iter()
                    .any(|s| record.identity.executable.contains(s))
                        && record.bundle_id.as_deref().is_none_or(str::is_empty)
                    {
                        unavailable.push(json!({"pid":pid,"code":"bundle_identity_unavailable"}));
                    }
                }
            }
        }
        let protected = BTreeSet::from([std::process::id()]);
        let preliminary = processes::targets(
            &identities,
            &seeds,
            &self.tracked,
            inventory.uid,
            &protected,
        );
        let requested: BTreeSet<_> = need_args
            .iter()
            .copied()
            .chain(preliminary.iter().map(|p| p.identity.pid))
            .collect();
        let requested: Vec<_> = requested
            .into_iter()
            .filter_map(|pid| identities.get(&pid).cloned())
            .take(2048)
            .collect();
        let arguments = observer.arguments(&requested, &id)?;
        for pid in need_args {
            let Some(args) = arguments.get(&pid) else {
                unavailable.push(json!({"pid":pid,"code":"root_arguments_unavailable"}));
                continue;
            };
            if let Classification::Root(kind) = evidence(pid, Some(args)) {
                seeds.push(Target {
                    identity: identities[&pid].clone(),
                    kind,
                });
            }
        }
        let targets = processes::targets(
            &identities,
            &seeds,
            &self.tracked,
            inventory.uid,
            &protected,
        );
        let specs = load_mcp_specs(&self.paths);
        let mut roles = serde_json::Map::new();
        let target_ids: BTreeSet<_> = targets.iter().map(|p| p.identity.pid).collect();
        for (pid, args) in &arguments {
            if !target_ids.contains(pid) {
                continue;
            }
            if let Some(role) =
                processes::classify_role(&args.tokens, &args.identity.executable, &specs, |s| {
                    command_path(s, Some(&args.cwd))
                })
            {
                let mut value = serde_json::to_value(role)
                    .map_err(|_| CoreError::new("role_encoding_failed", "组件角色无法编码"))?;
                value["started"] = json!(args.identity.start_stamp);
                roles.insert(pid.to_string(), value);
            }
        }
        for target in &targets {
            let mut current = target.identity.pid;
            let mut seen = BTreeSet::new();
            for _ in 0..32 {
                if !seen.insert(current) {
                    break;
                }
                let Some(parent) = identities.get(&current) else {
                    break;
                };
                if let Some(role) = roles
                    .get(&current.to_string())
                    .filter(|v| v["runtimeRole"] == "mcp")
                {
                    if current != target.identity.pid {
                        let mut role = role.clone();
                        role["roleEvidence"] = json!("configured_mcp_descendant");
                        roles.insert(target.identity.pid.to_string(), role);
                    }
                    break;
                }
                current = parent.parent;
            }
        }
        let mut diagnostic_reasons = inventory.diagnostic_reasons.clone();
        for row in unavailable.iter().skip(inventory.unavailable.len()) {
            let key = match row["code"].as_str() { Some("bundle_identity_unavailable") => "bundle_identity_unavailable", Some("root_arguments_unavailable") => "root_arguments_unavailable", _ => "other" };
            let count = diagnostic_reasons.entry(key.into()).or_default(); *count = count.saturating_add(1);
        }
        let complete = inventory.complete && unavailable.is_empty();
        if complete {
            self.tracked = targets.clone();
        }
        Ok(ProcessRound {
            id,
            uid: inventory.uid,
            targets,
            identities,
            roles: Value::Object(roles),
            unavailable,
            diagnostic_reasons,
            confirmed_exited_count: inventory.confirmed_exited_count,
            complete,
            observed_at: native::now(),
        })
    }
    pub fn sockets(&self, round: &ProcessRound) -> Result<SocketRound> {
        if round.targets.is_empty() {
            return Ok(SocketRound {
                flows: Vec::new(),
                receipt: json!({"schema":1,"round_id":round.id,"observed_at":native::now(),"collector_state":if round.complete{"no_targets"}else{"unknown"},"target_count":0,"confirmed_exited_count":0,"process_reason_counts":round.diagnostic_reasons,"process_confirmed_exited_count":round.confirmed_exited_count,"parsed_count":0,"accepted_count":0,"correlated_count":0,"unconfirmed_count":0,"dropped":{},"detail":"没有已确认的受监控目标；未读取套接字"}),
            });
        }
        let ids: Vec<_> = round.targets.iter().map(|p| p.identity.clone()).collect();
        let result = Observer {
            runner: &self.runner,
        }
        .sockets(&ids, &round.id)?;
        let complete = round.complete && result.complete;
        let flows: Vec<_> = result
            .flows
            .into_iter()
            .map(|flow| {
                let identity = &round.identities[&flow.pid];
                SampledFlow {
                    flow,
                    stamp: identity.start_stamp.clone(),
                    process_start: Some(
                        identity.start_seconds as f64
                            + f64::from(identity.start_microseconds) / 1_000_000.0,
                    ),
                    valid: true,
                }
            })
            .collect();
        let state = if !complete {
            "partial"
        } else if flows.is_empty() {
            "empty"
        } else {
            "ok"
        };
        let receipt = json!({"schema":1,"round_id":round.id,"observed_at":result.observed_at,"collector_state":state,"target_count":ids.len(),"parsed_count":result.parsed_count,"accepted_count":result.accepted_count,
            "correlated_count":0,"unconfirmed_count":0,"confirmed_exited_count":result.confirmed_exited_count,"process_reason_counts":round.diagnostic_reasons,"process_confirmed_exited_count":round.confirmed_exited_count,"dropped":result.dropped,"detail":if complete{"已按进程启动身份读取本轮可见套接字；空样本不证明没有网络活动"}else{"本轮部分原生采样未完成；未判定为网络变化"}});
        Ok(SocketRound { flows, receipt })
    }
    pub fn tag_report(
        &self,
        processes: &ProcessRound,
        sockets: &SocketRound,
        group: &str,
        pin: &str,
    ) -> Value {
        #[cfg(test)]
        if self.fixture_tag {
            return json!({"schema":1,"observed_epoch":sockets.receipt["observed_at"],"entry":{},"api":{},"flows":[],"connection_observation":sockets.receipt});
        }
        let captured = native::now();
        let mut report = json!({"schema":1,"observed_epoch":captured.floor(),"round_id":processes.id,"expected_group":group,"expected_node":pin,"pinned":!pin.is_empty(),"flows":[],"cli":{"state":"unconfirmed","detail":"连接证据来自原生套接字，不读取或修改shell代理变量"}});
        let before = self.process_table();
        let kernel =
            self.command_evidence(ReadCommand::Listeners, Duration::from_secs(3), "netstat");
        let listener =
            self.command_evidence(ReadCommand::LsofListener, Duration::from_secs(3), "lsof");
        let listener = listener.map(|v| tag_flow::listener_fallback(v, kernel.as_ref().ok()));
        let reachable = TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], 7890)),
            Duration::from_millis(500),
        )
        .is_ok();
        let after = self.process_table();
        let mut entry = match (&before, &after, &listener) {
            (Ok(before), Ok(after), Ok(listener)) => {
                tag_flow::inspect_entry(before, after, listener, reachable, processes.uid)
            }
            _ => {
                let failure = before
                    .as_ref()
                    .err()
                    .or(after.as_ref().err())
                    .or(listener.as_ref().err());
                json!({"state":"unconfirmed","reason":failure.map(|e|e.message.as_str()).unwrap_or("无法验证7890监听者"),"code":failure.map(|e|e.code.as_str()),"owners":[]})
            }
        };
        if entry["state"] != "verified" {
            let summary = |value: &Result<CommandEvidence>| match value {
                Ok(v) => {
                    json!({"status":v.status,"stdout_bytes":v.stdout.len(),"stderr_bytes":v.stderr.len(),"source":v.source})
                }
                Err(e) => json!({"code":e.code,"message":e.message}),
            };
            entry["collection"] = json!({"kernel":summary(&kernel),"listener":summary(&listener)});
        }
        report["entry"] = entry.clone();
        let config_path = self
            .paths
            .home
            .join("Library/Application Support/com.tag.lab/mihomo/runtime.yaml");
        let config = if entry["state"] == "verified" {
            StateStore::new(self.paths.clone())
                .read_bytes(&config_path, tag_config::CONFIG_LIMIT)
                .ok()
                .flatten()
                .and_then(|b| String::from_utf8(b).ok())
        } else {
            None
        };
        let client = config
            .as_deref()
            .and_then(|s| tag_config::controller_credentials(s).ok())
            .map(Client::new);
        let(mut api,records)=client.as_ref().map(|c|c.snapshot(group)).unwrap_or_else(||(json!({"state":"unavailable","reason":"入口或控制接口配置未验证，未取得控制器证据","rules":{"state":"unavailable","reason":"控制接口未验证","entries":[]}}),Vec::new()));
        report["rules"] = api
            .as_object_mut()
            .and_then(|v| v.remove("rules"))
            .unwrap_or(json!({"state":"unavailable","entries":[]}));
        report["api"] = api.clone();
        let effective_group = if group.is_empty() && api["mode"] == "global" {
            "GLOBAL"
        } else {
            group
        };
        report["expected_group"] = json!(effective_group);
        let node = if pin.is_empty() {
            api["selected_node"].as_str().unwrap_or("")
        } else {
            pin
        };
        report["expected_node"] = json!(node);
        report["selection_changed"] = json!(!pin.is_empty() && api["selected_node"] != pin);
        let mut native_processes = after.unwrap_or_default();
        for (pid, identity) in &processes.identities {
            native_processes.entry(*pid).and_modify(|p| {
                if p["stamp"] == identity.start_stamp
                    && p["uid"] == identity.uid
                    && p["executable"] == identity.executable
                {
                    p["start_seconds"] = json!(identity.start_seconds);
                    p["start_microseconds"] = json!(identity.start_microseconds);
                }
            });
        }
        let mut source = TagSource {
            sampler: self,
            client: client.as_ref(),
            config_path,
            started: Instant::now(),
            routes: BTreeMap::new(),
            expected: processes
                .targets
                .iter()
                .map(|p| p.identity.clone())
                .collect(),
            round_id: processes.id.clone(),
        };
        let mapping = fakeip_probe::collect(
            &mut source,
            fakeip_probe::Input {
                entry: &entry,
                api: &api,
                records: &records,
                flows: &sockets.flows,
                processes: &native_processes,
                listener_snapshot: kernel.as_ref().ok().map(|k| (k, captured)),
                uid: processes.uid,
            },
        );
        let mut observation = sockets.receipt.clone();
        let mut correlated = 0u64;
        let mut unknown = 0u64;
        let mut flows = Vec::new();
        for sample in &sockets.flows {
            let interface = source.route_interface(&sample.flow.peer.0).ok();
            let flow = tag_flow::correlate(CorrelationInput {
                flow: &sample.flow,
                stamp: &sample.stamp,
                process_start: sample.process_start,
                api: &api,
                records: &records,
                group: effective_group,
                expected_node: node,
                now: native::now(),
                fakeip_evidence: &mapping.proofs,
                interface: interface.as_deref(),
            });
            if flow["association"] == "correlated" {
                correlated += 1
            } else {
                unknown += 1
            }
            flows.push(flow);
        }
        observation["correlated_count"] = json!(correlated);
        observation["unconfirmed_count"] = json!(unknown);
        report["flows"] = json!(flows);
        report["connection_observation"] = observation;
        report["fakeip_probe"] = json!({"detail":mapping.reason,"attempts":mapping.attempts});
        report
    }
    pub fn command_evidence(
        &self,
        command: ReadCommand,
        timeout: Duration,
        source: &str,
    ) -> Result<CommandEvidence> {
        let out = self.runner.run(command, &[], timeout, 4 * 1024 * 1024)?;
        Ok(CommandEvidence {
            status: out.status,
            stdout: out.text()?.into(),
            stderr: out.error_text()?.into(),
            source: source.into(),
        })
    }
    pub fn process_table(&self) -> Result<BTreeMap<u32, Value>> {
        let out = self.runner.run(
            ReadCommand::ProcessTable,
            &[],
            Duration::from_secs(3),
            4 * 1024 * 1024,
        )?;
        if out.status != 0 || !out.stderr.is_empty() {
            return Err(CoreError::new(
                "process_metadata_unavailable",
                "系统进程补充采样不可读取",
            ));
        }
        parse_process_table(out.text()?)
    }
}
pub fn parse_process_table(text: &str) -> Result<BTreeMap<u32, Value>> {
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let mut remaining = line.trim_start();
        let mut fields = Vec::new();
        for _ in 0..8 {
            let Some(index) = remaining.find(char::is_whitespace) else {
                break;
            };
            fields.push(&remaining[..index]);
            remaining = remaining[index..].trim_start();
        }
        if fields.len() != 8 || remaining.is_empty() {
            continue;
        }
        let (Ok(pid), Ok(parent), Ok(uid)) = (
            fields[0].parse::<u32>(),
            fields[1].parse::<u32>(),
            fields[2].parse::<u32>(),
        ) else {
            continue;
        };
        if pid <= 1 {
            continue;
        }
        let executable = fs::canonicalize(remaining)
            .unwrap_or_else(|_| PathBuf::from(remaining))
            .to_string_lossy()
            .into_owned();
        let stamp = fields[3..8].join(" ");
        if result
            .insert(
                pid,
                json!({"uid":uid,"parent":parent,"stamp":stamp,"executable":executable}),
            )
            .is_some()
        {
            return Err(CoreError::new(
                "duplicate_process_identity",
                "系统进程采样包含重复身份",
            ));
        }
    }
    if result.is_empty() {
        return Err(CoreError::new(
            "process_metadata_unavailable",
            "没有可核对的系统进程元数据",
        ));
    }
    Ok(result)
}
struct TagSource<'a, R: ReadRunner> {
    sampler: &'a Sampler<R>,
    client: Option<&'a Client>,
    config_path: PathBuf,
    started: Instant,
    routes: BTreeMap<String, String>,
    expected: Vec<Identity>,
    round_id: String,
}
impl<R: ReadRunner> fakeip_probe::Source for TagSource<'_, R> {
    fn now(&self) -> f64 {
        native::now()
    }
    fn monotonic(&mut self) -> Duration {
        self.started.elapsed()
    }
    fn config(&mut self) -> Result<String> {
        let bytes = StateStore::new(self.sampler.paths.clone())
            .read_bytes(&self.config_path, tag_config::CONFIG_LIMIT)?
            .ok_or_else(|| CoreError::new("tag_config_unavailable", "TAG运行配置不存在"))?;
        String::from_utf8(bytes)
            .map_err(|_| CoreError::new("tag_config_encoding", "TAG运行配置编码无效"))
    }
    fn listeners(&mut self) -> Result<CommandEvidence> {
        self.sampler
            .command_evidence(ReadCommand::Listeners, Duration::from_secs(3), "netstat")
    }
    fn route_interface(&mut self, address: &str) -> Result<String> {
        if let Some(value) = self.routes.get(address) {
            return Ok(value.clone());
        }
        let ip = address
            .parse()
            .map_err(|_| CoreError::new("invalid_route_address", "路由目标必须是明确IP"))?;
        let out = self.sampler.runner.run(
            ReadCommand::Route(ip),
            &[],
            Duration::from_secs(2),
            32 * 1024,
        )?;
        let value = if out.status == 0 {
            out.text()?
                .lines()
                .find_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
                .unwrap_or("unavailable")
                .to_owned()
        } else {
            "unavailable".into()
        };
        self.routes.insert(address.into(), value.clone());
        Ok(value)
    }
    fn query_dns(&mut self, host: &str, port: u16, timeout: Duration) -> Result<(String, u32)> {
        let out = self.sampler.runner.run(
            ReadCommand::DnsA {
                host: host.into(),
                port,
            },
            &[],
            timeout,
            64 * 1024,
        )?;
        tag_flow::parse_dns_answer(out.text()?, out.error_text()?, out.status, host)
    }
    fn connections(&mut self) -> Result<Vec<Value>> {
        let response = self
            .client
            .ok_or_else(|| CoreError::new("controller_unavailable", "控制接口不可用"))?
            .get("/connections")
            .map_err(|_| CoreError::new("controller_query_failed", "控制器连接复核失败"))?;
        response["connections"]
            .as_array()
            .cloned()
            .ok_or_else(|| CoreError::new("controller_schema_invalid", "控制器连接表无效"))
    }
    fn processes(&mut self) -> Result<BTreeMap<u32, Value>> {
        let mut table = self.sampler.process_table()?;
        let current = Observer {
            runner: &self.sampler.runner,
        }
        .identities(&self.expected, &self.round_id)?;
        for expected in &self.expected {
            if let Some(identity) = current.get(&expected.pid) {
                if let Some(row) = table.get_mut(&expected.pid) {
                    if row["stamp"] == identity.start_stamp
                        && row["uid"] == identity.uid
                        && row["executable"] == identity.executable
                    {
                        row["start_seconds"] = json!(identity.start_seconds);
                        row["start_microseconds"] = json!(identity.start_microseconds);
                    } else {
                        table.remove(&expected.pid);
                    }
                }
            } else {
                table.remove(&expected.pid);
            }
        }
        Ok(table)
    }
}
