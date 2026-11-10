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
    processes::{self, Identity, MatchEvidence, McpSpec, Target},
    tag_config,
    tag_flow::{self, CommandEvidence, CorrelationInput},
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{SocketAddr, TcpStream},
    os::unix::fs::MetadataExt,
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
#[cfg(test)]
fn cli_paths(paths: &Paths) -> TrustedCliPaths {
    cli_alias_snapshot(paths, cli_alias_signature).map(|snapshot| snapshot.trusted).unwrap_or_default()
}

type CliAliasSignature = Vec<(PathBuf, bool, Vec<i128>, Option<PathBuf>)>;

struct CliAliasSnapshot {
    signature: CliAliasSignature,
    trusted: TrustedCliPaths,
}

fn trusted_cli_paths(signature: &CliAliasSignature) -> TrustedCliPaths {
    let mut known = TrustedCliPaths::default();
    for (_, claude, _, resolved) in signature {
        if let Some(path) = resolved {
            let path = path.to_string_lossy().into_owned();
            if *claude {
                known.claude.insert(path);
            } else {
                known.codex.insert(path);
            }
        }
    }
    known
}

fn cli_alias_snapshot(paths: &Paths, mut read: impl FnMut(&Paths) -> CliAliasSignature) -> Option<CliAliasSnapshot> {
    // Equal consecutive observations bind link/target metadata and canonical
    // resolution to the SAME trusted set. Bound retries under active upgrades;
    // an unstable result is pending and must not retain cached alias success.
    let mut signature = read(paths);
    for _ in 0..3 {
        let next = read(paths);
        if signature == next {
            let trusted = trusted_cli_paths(&next);
            return Some(CliAliasSnapshot { signature: next, trusted });
        }
        signature = next;
    }
    None
}

// Watch only the supported aliases, including both link and target identity.
// No directory-tree scan or process arguments are needed to invalidate this cache.
fn cli_alias_signature(paths: &Paths) -> CliAliasSignature {
    process_roots::cli_aliases(&paths.home).into_iter().map(|(path, claude)| {
        let mut facts = Vec::new();
        for metadata in [fs::symlink_metadata(&path), fs::metadata(&path)] {
            if let Ok(m) = metadata {
                facts.extend([m.dev() as i128, m.ino() as i128, m.len() as i128,
                    m.mtime() as i128, m.mtime_nsec() as i128, m.ctime() as i128,
                    m.ctime_nsec() as i128, m.mode() as i128]);
            } else { facts.push(-1); }
        }
        let resolved = canonical(&path);
        (path, claude, facts, resolved)
    }).collect()
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
    pub match_evidence: BTreeMap<u32, MatchEvidence>,
    pub unavailable: Vec<Value>,
    pub diagnostic_reasons: BTreeMap<String, u32>,
    pub confirmed_exited_count: u32,
    pub complete: bool,
    pub observed_at: f64,
    pub discovery: Option<Value>,
}
impl ProcessRound {
    pub fn public_value(&self) -> Value {
        json!({"schema":1,"round_id":self.id,"uid":self.uid,"state":if self.complete{"ok"}else{"partial"},"observed_at":self.observed_at,
        "targets":self.targets,"roles":self.roles,"unavailable":self.unavailable,"discovery":self.discovery})
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
    aliases: Option<CliAliasSnapshot>,
    discovery: crate::target_discovery::DiscoveryHandle,
    #[cfg(test)]
    fixture_tag: bool,
}
/// The session pin comes from the confirmed environment baseline — the same
/// source the legacy flow reads (`tag_node` in `state/baseline.conf`).
/// A missing file, missing keys, unreadable text, or a baseline whose
/// `tag_group` does not match the requested policy group all mean "no pin":
/// the caller then reports an unpinned observation, and never treats an
/// unresolvable selection as a confirmed drift.
pub fn pinned_node(paths: &Paths, group: &str) -> String {
    let path = paths.watch().join("state/baseline.conf");
    let bytes = match StateStore::new(paths.clone()).read_bytes(&path, 2_000_000) {
        Ok(Some(bytes)) => bytes,
        _ => return String::new(),
    };
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return String::new(),
    };
    let mut node = String::new();
    let mut group_ok = false;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("tag_group=") {
            // An empty requested group resolves to GLOBAL inside tag_report;
            // the baseline pin applies to that same effective group.
            group_ok = group == value || (group.is_empty() && value == "GLOBAL");
        } else if let Some(value) = line.strip_prefix("tag_node=") {
            node = value.to_string();
        }
    }
    if group_ok && !node.is_empty() {
        node
    } else {
        String::new()
    }
}

/// Drift is only confirmable when the pinned expectation and the observed
/// selection both name a real node. A `null` selection has several causes
/// (missing group, DIRECT, REJECT, COMPATIBLE) and none of them is evidence
/// that the node changed — an unresolved observation must never become a
/// confirmed drift (and must never trigger the proxy-fail protection path).
pub fn selection_drift(pin: &str, observed: &str) -> bool {
    !pin.is_empty() && !observed.is_empty() && observed != pin
}

impl<R: ReadRunner> Sampler<R> {
    pub fn new(runner: R, paths: Paths) -> Self {
        Self::new_with_alias_reader(runner, paths, cli_alias_signature)
    }
    fn new_with_alias_reader(runner: R, paths: Paths, read: impl FnMut(&Paths) -> CliAliasSignature) -> Self {
        let aliases = cli_alias_snapshot(&paths, read);
        let discovery = crate::target_discovery::DiscoveryHandle::for_home(&paths.home);
        Self {
            runner,
            paths,
            tracked: Vec::new(),
            aliases,
            discovery,
            #[cfg(test)]
            fixture_tag: false,
        }
    }
    #[cfg(test)]
    pub(crate) fn use_fixture_tag(&mut self) { self.fixture_tag = true; }
    pub fn set_discovery(&mut self,discovery:crate::target_discovery::DiscoveryHandle) { self.discovery=discovery; }
    pub fn discovery(&self)->crate::target_discovery::DiscoveryHandle { self.discovery.clone() }
    pub fn processes(&mut self) -> Result<ProcessRound> {
        self.processes_with_alias_reader(cli_alias_signature)
    }
    fn processes_with_alias_reader(&mut self, read: impl FnMut(&Paths) -> CliAliasSignature) -> Result<ProcessRound> {
        let snapshot = cli_alias_snapshot(&self.paths, read);
        if snapshot.as_ref().map(|s| &s.signature) != self.aliases.as_ref().map(|s| &s.signature) {
            self.aliases = snapshot;
        }
        let observer = Observer {
            runner: &self.runner,
        };
        let inventory = observer.inventory()?;
        self.discovery.observed_process_bundles(inventory.processes.values().filter_map(|p|p.bundle_path.as_ref().map(PathBuf::from)
            .or_else(||p.identity.executable.split_once(".app/Contents/").map(|(prefix,_)|PathBuf::from(format!("{prefix}.app")))).map(|path|(path,p.bundle_id.clone()))));
        let mut discovery_snapshot=self.discovery.observation_snapshot(&self.runner,native::now());
        let merge_aliases=|snapshot:&crate::target_discovery::DiscoverySnapshot| {
            let accepted=snapshot.cli_paths();let mut trusted=snapshot.process_paths(true);
            if let Some(aliases)=&self.aliases {
                // The P2 stability guard cannot add a path absent from the
                // shared accepted revision used by staging and selection.
                trusted.claude.extend(aliases.trusted.claude.intersection(&accepted.claude).cloned());
                trusted.codex.extend(aliases.trusted.codex.intersection(&accepted.codex).cloned());
            }
            trusted
        };
        let mut trusted=merge_aliases(&discovery_snapshot);
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
        let mut match_evidence = BTreeMap::new();
        let mut need_args = BTreeSet::new();
        let mut unavailable = inventory.unavailable.clone();
        if self.aliases.is_none() {
            unavailable.push(json!({"code":"cli_alias_snapshot_unstable"}));
        }
        let evidence = |pid: u32, args: Option<&Arguments>, trusted:&TrustedCliPaths| {
            let record = &inventory.processes[&pid];
            process_roots::classify_with_evidence(
                RootEvidence {
                    identity: &record.identity,
                    bundle_path: record.bundle_path.as_deref(),
                    bundle_id: record.bundle_id.as_deref(),
                    arguments: args.map(|a| a.tokens.as_slice()),
                    cwd: args.map(|a| a.cwd.as_str()),
                },
                &self.paths.home,
                trusted,
                canonical,
            )
        };
        for (pid, record) in &inventory.processes {
            let classified = evidence(*pid, None, &trusted);
            match classified.classification {
                Classification::Root(kind) => {
                    match_evidence.insert(*pid, MatchEvidence::direct(&record.identity, classified.reason.unwrap()));
                    seeds.push(Target { identity: record.identity.clone(), kind });
                },
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
        let entries=arguments.values().filter(|args|Path::new(&args.identity.executable).file_name().is_some_and(|n|n=="node" || n=="nodejs" || n=="bun"))
            .filter_map(|args|process_roots::node_script_entry(&args.tokens,Some(&args.cwd)))
            .filter_map(|path| {
                let text=path.to_string_lossy();
                if text.ends_with("/node_modules/@anthropic-ai/claude-code/cli.js") { Some((processes::LaunchTarget::ClaudeCli,path)) }
                else if text.ends_with("/node_modules/@openai/codex/bin/codex.js") { Some((processes::LaunchTarget::CodexCli,path)) }
                else { None }
            }).collect::<Vec<_>>();
        if !entries.is_empty() {
            self.discovery.observe_interpreters(arguments.values().filter(|args|Path::new(&args.identity.executable).file_name().is_some_and(|n|n=="node" || n=="nodejs" || n=="bun"))
                .filter_map(|args|process_roots::node_script_entry(&args.tokens,Some(&args.cwd)).map(|script|(script,PathBuf::from(&args.identity.executable)))));
            self.discovery.observe_cli_entries(entries);
            discovery_snapshot=self.discovery.observation_snapshot(&self.runner,native::now());
            trusted=merge_aliases(&discovery_snapshot);
        }
        for pid in need_args {
            let Some(args) = arguments.get(&pid) else {
                unavailable.push(json!({"pid":pid,"code":"root_arguments_unavailable"}));
                continue;
            };
            let classified = evidence(pid, Some(args), &trusted);
            if let Classification::Root(kind) = classified.classification {
                match_evidence.insert(pid, MatchEvidence::direct(&identities[&pid], classified.reason.unwrap()));
                seeds.push(Target {
                    identity: identities[&pid].clone(),
                    kind,
                });
            }
        }
        let (targets, match_evidence) = processes::targets_with_evidence(
            &identities,
            &seeds,
            &self.tracked,
            inventory.uid,
            &protected,
            &match_evidence,
        );
        let specs = load_mcp_specs(&self.paths);
        let mut roles = serde_json::Map::new();
        let target_ids: BTreeSet<_> = targets.iter().map(|p| p.identity.pid).collect();
        for (pid, args) in &arguments {
            if !target_ids.contains(pid) {
                continue;
            }
            // Presentation hint only: keep the existing process/lease kind and
            // connection sampling unchanged. Never infer a client from the daemon.
            if process_roots::managed_codex_app_server(&args.identity.executable, &self.paths.home)
                && matches!(evidence(*pid, Some(args), &trusted).classification, Classification::Root(processes::Kind::CodexCli))
            {
                roles.insert(pid.to_string(), json!({"runtimeRole":"codex_managed", "serviceName":"Codex 托管后台", "roleEvidence":"managed_app_server", "started":args.identity.start_stamp}));
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
        // A retained target whose managed-path arguments could not be read is
        // not evidence of an independent CLI, even during an incomplete round.
        for target in &targets {
            let pid = target.identity.pid;
            if !arguments.contains_key(&pid)
                && process_roots::managed_codex_app_server(&target.identity.executable, &self.paths.home)
            {
                roles.insert(pid.to_string(), json!({"runtimeRole":"codex_managed_unconfirmed", "serviceName":"Codex 后台（身份待确认）", "roleEvidence":"managed_path_only", "started":target.identity.start_stamp}));
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
            let key = match row["code"].as_str() { Some("bundle_identity_unavailable") => "bundle_identity_unavailable", Some("root_arguments_unavailable") => "root_arguments_unavailable", Some("cli_alias_snapshot_unstable") => "cli_alias_snapshot_unstable", _ => "other" };
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
            match_evidence,
            unavailable,
            diagnostic_reasons,
            confirmed_exited_count: inventory.confirmed_exited_count,
            complete,
            observed_at: inventory.finished_at,
            discovery: Some(json!({"revision":discovery_snapshot.revision,"complete":discovery_snapshot.complete,"issues":discovery_snapshot.issues})),
        })
    }
    pub(crate) fn retain_channel_targets(&mut self, tracked: &[Target]) {
        self.tracked = tracked.to_vec();
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
        let observed = api["selected_node"].as_str().unwrap_or("");
        let saved_vpn_exp = crate::config_store::ConfigStore {
            storage: StateStore::new(self.paths.clone()),
        }
        .load()
        .ok()
        .and_then(|c| c.vpn_expectation);
        let configured_node = saved_vpn_exp
            .as_ref()
            .filter(|e| e.configured)
            .and_then(|e| e.expected_node.as_deref())
            .unwrap_or("");
        let effective_pin = if !pin.is_empty() {
            pin
        } else {
            configured_node
        };
        let node = if !effective_pin.is_empty() {
            effective_pin
        } else if saved_vpn_exp.as_ref().is_some_and(|e| e.configured) {
            ""
        } else {
            observed
        };
        report["expected_node"] = json!(node);
        report["selection_observed"] = json!(!observed.is_empty());
        report["selection_changed"] = json!(selection_drift(effective_pin, observed));
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

#[cfg(test)]
mod alias_snapshot_tests {
    use super::*;
    use crate::commands::{ObserverAction, Output};
    use claude_watch_core::processes::MatchReason;
    use std::os::unix::fs::symlink;

    struct FixtureInventory { records: Vec<Identity> }
    impl ReadRunner for FixtureInventory {
        fn run(&self, command: ReadCommand, input: &[u8], _: Duration, _: usize) -> Result<Output> {
            let at = native::now();
            let mut value = json!({"schema":1,"status":"ok","uid":501,"started_at":at,"finished_at":at});
            match command {
                ReadCommand::Plist(_) => return Ok(Output { status:1, stdout:vec![], stderr:vec![] }),
                ReadCommand::Observer(ObserverAction::Inventory) => {
                    value["state"] = json!("ok"); value["truncated"] = json!(false);
                    value["requested_count"] = json!(self.records.len()); value["processes"] = json!(self.records);
                    value["unavailable"] = json!([]); value["exited"] = json!([]);
                }
                ReadCommand::Observer(ObserverAction::Arguments) => {
                    let request: Value = serde_json::from_slice(input).unwrap();
                    value["round_id"] = request["round_id"].clone();
                    value["argument_prefixes"] = json!(self.records.iter().filter(|r|
                        request["targets"].as_array().unwrap().iter().any(|p| p["pid"] == r.pid)).map(|r|
                        json!({"pid":r.pid,"state":"ok","identity":r,"arguments":[r.executable,"/ordinary/script.js","/node_modules/@openai/codex/bin/codex.js"],"cwd":"/fixture","truncated":false})).collect::<Vec<_>>());
                }
                _ => panic!("unexpected alias fixture command"),
            }
            Ok(Output { status:0, stdout:serde_json::to_vec(&value).unwrap(), stderr:vec![] })
        }
    }

    struct AliasFixture { paths: Paths, alias: PathBuf, a: PathBuf, b: PathBuf }
    impl AliasFixture {
        fn new() -> Self {
            let home = PathBuf::from("/private/tmp").join(format!("cw-alias-snapshot-{}", Uuid::new_v4()));
            fs::create_dir_all(home.join(".local/bin")).unwrap();
            fs::create_dir_all(home.join("ordinary")).unwrap();
            let a = home.join("opaque-image-a"); let b = home.join("opaque-image-b");
            for p in [&a, &b, &home.join("ordinary/codex")] {
                fs::write(p, b"private discovery fixture, never executed").unwrap();
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(p,fs::Permissions::from_mode(0o755)).unwrap();
            }
            let alias = home.join(".local/bin/codex"); symlink(&a, &alias).unwrap();
            Self { paths: Paths::new(&home).unwrap(), alias, a, b }
        }
        fn retarget(&self, path: &Path) { fs::remove_file(&self.alias).unwrap(); symlink(path, &self.alias).unwrap(); }
        fn runner(&self) -> FixtureInventory {
            let records = [self.a.clone(), self.b.clone(), "/usr/local/bin/node".into(), "/usr/bin/python3".into(),
                "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal".into(), self.paths.home.join("ordinary/codex")]
                .into_iter().enumerate().map(|(index, path)| Identity { pid:7000+index as u32, parent:1, uid:501,
                    executable:path.to_string_lossy().into_owned(), start_seconds:100, start_microseconds:1, start_stamp:"owned-fixture".into() }).collect();
            FixtureInventory { records }
        }
    }
    impl Drop for AliasFixture { fn drop(&mut self) { fs::remove_dir_all(&self.paths.home).unwrap(); } }

    #[test]
    fn sampler_initial_alias_retarget_uses_one_stable_snapshot() {
        let fixture = AliasFixture::new();
        let mut reads = 0;
        let mut sampler = Sampler::new_with_alias_reader(fixture.runner(), fixture.paths.clone(), |paths| {
            let observed = cli_alias_signature(paths);
            // Exact seam: A has been read, but validation/signature acquisition
            // has not. B has no known installation layout or AI file name.
            if reads == 0 { fixture.retarget(&fixture.b); }
            reads += 1;
            observed
        });
        let round = sampler.processes().unwrap();
        assert_eq!(round.targets.iter().map(|t| t.identity.pid).collect::<Vec<_>>(), [7001], "B must be discovered; ordinary programs and independent A must not");
        assert_eq!(round.match_evidence[&7001].reason, MatchReason::SupportedCliAlias);
        assert_eq!(reads, 3, "A, B, B is a bounded deterministic reread, not a timing race");
        assert!(cli_paths(&fixture.paths).codex.contains(fixture.b.to_str().unwrap()));
        println!("initial alias snapshot: A -> B -> B; opaque B discovered; A, Node, Python, Terminal and unrelated codex excluded");
    }

    #[test]
    fn sampler_unstable_alias_snapshot_is_pending_and_retries_next_round() {
        let fixture = AliasFixture::new();
        let mut reads = 0;
        let mut unstable = |paths: &Paths| {
            let observed = cli_alias_signature(paths);
            fixture.retarget(if reads % 2 == 0 { &fixture.b } else { &fixture.a });
            reads += 1; observed
        };
        let mut sampler = Sampler::new_with_alias_reader(fixture.runner(), fixture.paths.clone(), &mut unstable);
        assert!(sampler.aliases.is_none(), "unstable initialization must not cache success");
        let pending = sampler.processes_with_alias_reader(&mut unstable).unwrap();
        assert!(!pending.complete && pending.targets.is_empty());
        assert_eq!(pending.diagnostic_reasons.get("cli_alias_snapshot_unstable"), Some(&1));
        let receipt = sampler.sockets(&pending).unwrap().receipt;
        assert_eq!(receipt["collector_state"], "unknown");
        assert_eq!(crate::monitor_snapshot::connection_observation(&receipt, receipt["observed_at"].as_f64().unwrap())["processReasonCounts"]["cli_alias_snapshot_unstable"], 1);
        drop(unstable);
        assert_eq!(reads, 8, "initialization and refresh must each stop after four observations");
        let recovered = sampler.processes().unwrap();
        assert!(recovered.complete); assert_eq!(recovered.targets.len(), 1);
        assert_eq!(recovered.match_evidence[&7000].reason, MatchReason::SupportedCliAlias);
        // A later unstable refresh also drops the old alias success. New
        // process lifetimes cannot inherit its cached discovery or tracking.
        for record in &mut sampler.runner.records { record.start_seconds += 1; }
        let mut refresh_reads = 0;
        let pending = sampler.processes_with_alias_reader(|paths| {
            let observed = cli_alias_signature(paths);
            fixture.retarget(if refresh_reads % 2 == 0 { &fixture.b } else { &fixture.a });
            refresh_reads += 1; observed
        }).unwrap();
        assert_eq!(refresh_reads, 4); assert!(sampler.aliases.is_none());
        assert!(pending.targets.is_empty() && !pending.complete);
        let recovered = sampler.processes().unwrap();
        assert!(recovered.complete && recovered.targets.len() == 1);
        println!("unstable snapshots: four reads per attempt, pending/unknown without cached success, recovered on stable next round");
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
