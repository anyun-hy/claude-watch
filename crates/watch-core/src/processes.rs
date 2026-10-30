//! Identity-bound process ownership and authorization. Names/arguments alone never authorize actions.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub pid: u32,
    pub parent: u32,
    pub uid: u32,
    pub executable: String,
    pub start_seconds: u64,
    pub start_microseconds: u32,
    #[serde(default)]
    pub start_stamp: String,
}
impl Identity {
    pub fn valid(&self) -> bool {
        self.pid > 1
            && self.pid <= i32::MAX as u32
            && self.start_seconds > 0
            && self.start_microseconds < 1_000_000
            && self.executable.starts_with('/')
            && self.executable.len() <= 16_384
            && !self.executable.chars().any(char::is_control)
    }
    pub fn same_process(&self, other: &Self) -> bool {
        self.valid()
            && other.valid()
            && self.pid == other.pid
            && self.uid == other.uid
            && self.executable == other.executable
            && self.start_seconds == other.start_seconds
            && self.start_microseconds == other.start_microseconds
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Claude,
    Codex,
    Chatgpt,
    Openai,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum LaunchTarget {
    #[default]
    ClaudeDesktop,
    CodexDesktop,
    ChatgptDesktop,
    ClaudeCli,
    CodexCli,
}
impl LaunchTarget {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "claude-desktop" => Some(Self::ClaudeDesktop),
            "codex-desktop" => Some(Self::CodexDesktop),
            "chatgpt-desktop" => Some(Self::ChatgptDesktop),
            "claude-cli" => Some(Self::ClaudeCli),
            "codex-cli" => Some(Self::CodexCli),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeDesktop => "claude-desktop",
            Self::CodexDesktop => "codex-desktop",
            Self::ChatgptDesktop => "chatgpt-desktop",
            Self::ClaudeCli => "claude-cli",
            Self::CodexCli => "codex-cli",
        }
    }
    pub fn protected(self) -> bool {
        self == Self::ClaudeDesktop
    }
    pub fn cli(self) -> bool {
        matches!(self, Self::ClaudeCli | Self::CodexCli)
    }
    pub fn cli_provider(self) -> Option<Provider> {
        match self {
            Self::ClaudeCli => Some(Provider::Claude),
            Self::CodexCli => Some(Provider::Codex),
            _ => None,
        }
    }
    pub fn accepts(self, kind: Kind) -> bool {
        match self {
            Self::ClaudeDesktop => kind == Kind::ClaudeMain,
            Self::CodexDesktop => matches!(kind, Kind::CodexMain | Kind::OpenaiMain),
            Self::ChatgptDesktop => matches!(kind, Kind::ChatgptMain | Kind::OpenaiMain),
            Self::ClaudeCli => kind == Kind::ClaudeCode,
            Self::CodexCli => kind == Kind::CodexCli,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    #[serde(rename = "desktop-main")]
    ClaudeMain,
    #[serde(rename = "desktop-helper")]
    ClaudeHelper,
    #[serde(rename = "code")]
    ClaudeCode,
    #[serde(rename = "child")]
    ClaudeChild,
    #[serde(rename = "claude-launcher", alias = "launcher")]
    ClaudeLauncher,
    #[serde(rename = "codex-desktop-main")]
    CodexMain,
    #[serde(rename = "codex-desktop-helper")]
    CodexHelper,
    #[serde(rename = "codex-cli")]
    CodexCli,
    #[serde(rename = "codex-child")]
    CodexChild,
    #[serde(rename = "codex-launcher")]
    CodexLauncher,
    #[serde(rename = "chatgpt-desktop-main")]
    ChatgptMain,
    #[serde(rename = "chatgpt-desktop-helper")]
    ChatgptHelper,
    #[serde(rename = "chatgpt-child")]
    ChatgptChild,
    #[serde(rename = "chatgpt-launcher")]
    ChatgptLauncher,
    #[serde(rename = "openai-desktop-main")]
    OpenaiMain,
    #[serde(rename = "openai-desktop-helper")]
    OpenaiHelper,
    #[serde(rename = "openai-child")]
    OpenaiChild,
    #[serde(rename = "openai-launcher")]
    OpenaiLauncher,
}
impl Kind {
    pub fn provider(self) -> Provider {
        match self {
            Self::ClaudeMain
            | Self::ClaudeHelper
            | Self::ClaudeCode
            | Self::ClaudeChild
            | Self::ClaudeLauncher => Provider::Claude,
            Self::CodexMain
            | Self::CodexHelper
            | Self::CodexCli
            | Self::CodexChild
            | Self::CodexLauncher => Provider::Codex,
            Self::ChatgptMain
            | Self::ChatgptHelper
            | Self::ChatgptChild
            | Self::ChatgptLauncher => Provider::Chatgpt,
            _ => Provider::Openai,
        }
    }
    pub fn child(self) -> Self {
        match self.provider() {
            Provider::Claude => Self::ClaudeChild,
            Provider::Codex => Self::CodexChild,
            Provider::Chatgpt => Self::ChatgptChild,
            Provider::Openai => Self::OpenaiChild,
        }
    }
    pub fn launcher(self) -> bool {
        matches!(
            self,
            Self::ClaudeLauncher
                | Self::CodexLauncher
                | Self::ChatgptLauncher
                | Self::OpenaiLauncher
        )
    }
    pub fn desktop(self) -> bool {
        matches!(
            self,
            Self::ClaudeMain
                | Self::ClaudeHelper
                | Self::CodexMain
                | Self::CodexHelper
                | Self::ChatgptMain
                | Self::ChatgptHelper
                | Self::OpenaiMain
                | Self::OpenaiHelper
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub identity: Identity,
    pub kind: Kind,
}
pub fn normalized_stamp(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}
pub fn descendant(pid: u32, root: u32, inventory: &BTreeMap<u32, Identity>) -> bool {
    let mut current = pid;
    let mut visited = BTreeSet::new();
    for _ in 0..64 {
        if current <= 1 || !visited.insert(current) {
            return false;
        }
        if current == root {
            return true;
        }
        let Some(value) = inventory.get(&current) else {
            return false;
        };
        current = value.parent;
    }
    false
}
pub fn targets(
    inventory: &BTreeMap<u32, Identity>,
    seeds: &[Target],
    tracked: &[Target],
    uid: u32,
    protected: &BTreeSet<u32>,
) -> Vec<Target> {
    let owned: BTreeMap<_, _> = inventory
        .iter()
        .filter(|(pid, p)| **pid == p.pid && p.uid == uid && p.valid() && !protected.contains(pid))
        .map(|(pid, p)| (*pid, p))
        .collect();
    let mut kinds = BTreeMap::new();
    // A stale tracked record must never overwrite a fresh independently classified root.
    for seed in seeds.iter().chain(tracked) {
        if let Some(current) = owned.get(&seed.identity.pid) {
            if current.same_process(&seed.identity) {
                kinds.entry(seed.identity.pid).or_insert(seed.kind);
            }
        }
    }
    let mut changes = Vec::new();
    for (&pid, &kind) in &kinds {
        if kind != Kind::CodexCli {
            continue;
        }
        let mut current = owned[&pid].parent;
        let mut visited = BTreeSet::new();
        for _ in 0..64 {
            if !visited.insert(current) {
                break;
            }
            let Some(parent) = owned.get(&current) else {
                break;
            };
            if let Some(&k) = kinds.get(&current) {
                if k.desktop() && k.provider() != Provider::Claude {
                    changes.push((pid, k.child()));
                    break;
                }
            }
            current = parent.parent;
        }
    }
    kinds.extend(changes);
    for _ in 0..64 {
        let next: Vec<_> = owned
            .iter()
            .filter(|(pid, _)| !kinds.contains_key(pid))
            .filter_map(|(pid, p)| kinds.get(&p.parent).map(|k| (*pid, k.child())))
            .collect();
        if next.is_empty() {
            break;
        }
        kinds.extend(next);
    }
    kinds
        .into_iter()
        .filter(|(_, k)| !k.launcher())
        .map(|(pid, kind)| Target {
            identity: owned[&pid].clone(),
            kind,
        })
        .collect()
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub provider: Provider,
    pub root: Identity,
    pub owner: Option<Identity>,
    pub cli: bool,
}
impl Lease {
    pub fn valid(&self, inventory: &BTreeMap<u32, Identity>, uid: u32) -> bool {
        let matches = |value: &Identity| {
            value.uid == uid
                && inventory
                    .get(&value.pid)
                    .is_some_and(|current| current.same_process(value))
        };
        matches(&self.root) && (!self.cli || self.owner.as_ref().is_some_and(matches))
    }
}
pub fn authorization(
    targets: &[Target],
    leases: &[Lease],
    inventory: &BTreeMap<u32, Identity>,
    uid: u32,
) -> Value {
    let valid: Vec<_> = leases.iter().filter(|v| v.valid(inventory, uid)).collect();
    let mut active = Vec::new();
    let mut unauthorized = Vec::new();
    for target in targets {
        let bound = inventory
            .get(&target.identity.pid)
            .is_some_and(|p| p.uid == uid && p.same_process(&target.identity));
        if bound
            && valid.iter().any(|lease| {
                target.kind.provider() == lease.provider
                    && descendant(target.identity.pid, lease.root.pid, inventory)
            })
        {
            active.push(target.identity.pid);
        } else {
            unauthorized.push(target.identity.pid);
        }
    }
    json!({"active_pids":active,"unauthorized_pids":unauthorized,"mode":if active.is_empty(){"GUARD"}else{"ACTIVE"}})
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpSpec {
    pub executable: String,
    pub arguments: Vec<String>,
    pub name: String,
}
impl McpSpec {
    pub fn from_config(
        command: &str,
        arguments: &[String],
        name: &str,
        resolve: impl Fn(&str) -> Option<String>,
    ) -> Option<Self> {
        if arguments.len() > 128 || arguments.iter().any(|v| v.len() > 16_384) {
            return None;
        }
        let mut tokens = vec![command.to_owned()];
        tokens.extend_from_slice(arguments);
        if arguments.is_empty()
            && ["node", "nodejs", "bun", "python", "python3", "uvx", "npx"]
                .contains(&basename(command))
        {
            return None;
        }
        // Normalize interpreter + script together, rather than comparing a script against its interpreter.
        let (entry, args) = entrypoint(&tokens)?;
        Some(Self {
            executable: resolve(entry)?,
            arguments: args.to_vec(),
            name: name.chars().filter(|v| !v.is_control()).take(64).collect(),
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    pub runtime_role: String,
    pub service_name: String,
    pub role_evidence: String,
}
fn role(name: &str, label: &str, evidence: &str) -> Role {
    Role {
        runtime_role: name.into(),
        service_name: label.into(),
        role_evidence: evidence.into(),
    }
}
fn basename(value: &str) -> &str {
    Path::new(value)
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("")
}
pub fn entrypoint(tokens: &[String]) -> Option<(&str, &[String])> {
    let first = tokens.first()?;
    let name = basename(first).to_lowercase();
    if ["node", "nodejs", "bun"].contains(&name.as_str()) || name.starts_with("python") {
        let mut index = 1;
        while tokens.get(index).is_some_and(|v| {
            ["--no-warnings", "--enable-source-maps", "-u", "-B", "--"].contains(&v.as_str())
        }) {
            index += 1;
        }
        let script = tokens.get(index)?;
        if script.starts_with('-') {
            None
        } else {
            Some((script, &tokens[index + 1..]))
        }
    } else {
        Some((first, &tokens[1..]))
    }
}
pub fn classify_role(
    tokens: &[String],
    executable: &str,
    specs: &[McpSpec],
    resolve: impl Fn(&str) -> Option<String>,
) -> Option<Role> {
    if let Some((entry, args)) = entrypoint(tokens) {
        if let Some(entry) = resolve(entry) {
            for spec in specs {
                if spec.executable == entry && args.starts_with(&spec.arguments) {
                    return Some(role("mcp", &spec.name, "configured_mcp_entry"));
                }
            }
        }
    }
    for (flag, name, label) in [
        (
            "--utility-sub-type=network.mojom.NetworkService",
            "chromium_network",
            "Chromium 网络服务",
        ),
        ("--type=renderer", "chromium_renderer", "Chromium 渲染器"),
        ("--type=gpu-process", "chromium_gpu", "Chromium GPU 组件"),
    ] {
        if tokens.iter().any(|s| s == flag) {
            return Some(role(name, label, "runtime_component"));
        }
    }
    if basename(executable) == "chrome_crashpad_handler" {
        return Some(role(
            "chromium_crashpad",
            "Chromium 崩溃报告",
            "runtime_component",
        ));
    }
    None
}
/// The result is display-only. Full command arguments and executable paths are not emitted.
pub fn role_hints(
    requested: &BTreeMap<u32, String>,
    before: &BTreeMap<u32, Identity>,
    after: &BTreeMap<u32, Identity>,
    commands: &BTreeMap<u32, Vec<String>>,
    specs: &[McpSpec],
    resolve: impl Fn(&str) -> Option<String>,
) -> Value {
    let mut roles = BTreeMap::<u32, Role>::new();
    for (pid, tokens) in commands {
        if let Some(identity) = before.get(pid) {
            if requested
                .get(pid)
                .is_some_and(|s| normalized_stamp(s) == normalized_stamp(&identity.start_stamp))
            {
                if let Some(role) = classify_role(tokens, &identity.executable, specs, &resolve) {
                    roles.insert(*pid, role);
                }
            }
        }
    }
    for pid in before.keys() {
        let mut current = *pid;
        let mut visited = BTreeSet::new();
        for _ in 0..32 {
            if !visited.insert(current) {
                break;
            }
            let Some(identity) = before.get(&current) else {
                break;
            };
            if let Some(role) = roles.get(&current) {
                if role.runtime_role == "mcp" {
                    if *pid != current {
                        let mut inherited = role.clone();
                        inherited.role_evidence = "configured_mcp_descendant".into();
                        roles.insert(*pid, inherited);
                    }
                    break;
                }
            }
            current = identity.parent;
        }
    }
    let mut result = serde_json::Map::new();
    for (pid, role) in roles {
        let Some(identity) = before.get(&pid) else {
            continue;
        };
        if after.get(&pid) != Some(identity)
            || !requested
                .get(&pid)
                .is_some_and(|s| normalized_stamp(s) == normalized_stamp(&identity.start_stamp))
        {
            continue;
        }
        let mut value = serde_json::to_value(role).unwrap_or(json!({}));
        value["started"] = json!(normalized_stamp(&identity.start_stamp));
        result.insert(pid.to_string(), value);
    }
    Value::Object(result)
}

/// POSIX word parsing for `ps args` observations only; this never executes a shell.
pub fn command_tokens(command: &str, executable: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut chars = command.chars().peekable();
    let mut word = String::new();
    let mut state = None;
    let mut began = false;
    if !executable.is_empty()
        && command.starts_with(executable)
        && command[executable.len()..]
            .chars()
            .next()
            .is_some_and(char::is_whitespace)
    {
        result.push(executable.into());
        chars = command[executable.len()..].chars().peekable();
    }
    while let Some(c) = chars.next() {
        match state {
            Some('\'') => {
                if c == '\'' {
                    state = None
                } else {
                    word.push(c)
                }
            }
            Some('"') => {
                if c == '"' {
                    state = None
                } else if c == '\\' {
                    let Some(next) = chars.next() else {
                        return Vec::new();
                    };
                    if next != '"' && next != '\\' {
                        word.push('\\')
                    }
                    word.push(next)
                } else {
                    word.push(c)
                }
            }
            _ => {
                if [' ', '\t', '\r', '\n'].contains(&c) {
                    if began {
                        result.push(std::mem::take(&mut word));
                        began = false
                    }
                } else if c == '\'' || c == '"' {
                    state = Some(c);
                    began = true
                } else if c == '\\' {
                    let Some(next) = chars.next() else {
                        return Vec::new();
                    };
                    word.push(next);
                    began = true
                } else {
                    word.push(c);
                    began = true
                }
            }
        }
    }
    if state.is_some() {
        return Vec::new();
    }
    if began {
        result.push(word)
    }
    result
}
