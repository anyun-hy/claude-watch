//! Activation is opt-in. Owned files, shell configuration, and verified
//! controlled invocations are separate facts.
use crate::{
    channel_policy_status::{process_protection, producer_is_current},
    channel_supervisor::ChannelSupervisor,
    config_store::ConfigStore,
    managed_entry::{desktop_entry_plist, snapshot_running_processes, DesktopManagedEntrySpec},
    managed_entry_transaction::{commit, err, Change, Leaf, Object, Stamp},
    storage::{strict_json, StateStore},
};
use claude_watch_core::{
    channel::BoundProcessToken,
    controlled_launch::{ManagedInstanceState, ManagedLaunchInstance},
    error::Result,
    policy::PolicyCatalog,
    processes::{Identity, Kind, LaunchTarget, ProcessRole, Target},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedEntryKind {
    DesktopWrapper,
    CliShim,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryShell {
    Zsh,
    Bash,
}

impl EntryShell {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "zsh" => Ok(Self::Zsh),
            "bash" => Ok(Self::Bash),
            _ => Err(err(
                "unsupported_entry_shell",
                "只支持显式选择 zsh 或 Bash 交互配置",
            )),
        }
    }
    fn rc(self) -> &'static str {
        match self {
            Self::Zsh => ".zshrc",
            Self::Bash => ".bashrc",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedEntryPreview {
    pub target: LaunchTarget,
    pub kind: ManagedEntryKind,
    pub entry_id: String,
    pub destination_path: PathBuf,
    pub target_executable: Option<PathBuf>,
    pub target_bundle_path: Option<PathBuf>,
    pub target_fingerprint: Option<String>,
    pub conflict_detected: bool,
    pub conflict_reason: Option<String>,
    pub shell_config_path: Option<PathBuf>,
    pub shell_snippet: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedEntryActivationResult {
    pub target: LaunchTarget,
    pub entry_id: String,
    pub installed_path: PathBuf,
    pub status: String,
    pub activation_configured: bool,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedEntryStatusReport {
    pub target: LaunchTarget,
    pub entry_id: String,
    pub entry_path: PathBuf,
    pub entry_generated: bool,
    pub activation_configured: bool,
    pub current_invocation_verified: bool,
    pub shell_resolution: String,
    pub state: ManagedInstanceState,
    pub active_managed_count: usize,
    pub protected_instance_count: usize,
    pub unmanaged_pids: Vec<u32>,
    pub pending_pids: Vec<u32>,
    pub status_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedEntryDeactivationResult {
    pub target: LaunchTarget,
    pub entry_id: String,
    pub removed_path: PathBuf,
    pub was_present: bool,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct EntryActivity {
    managed: usize,
    protected: usize,
    unmanaged: Vec<u32>,
    pending: Vec<u32>,
}

pub enum EntrySource {
    Cli {
        entry_path: PathBuf,
        executable: PathBuf,
        sha256: String,
        kind: Kind,
        script: bool,
    },
    Desktop {
        spec: DesktopManagedEntrySpec,
        kind: Kind,
    },
}
impl EntrySource {
    fn executable(&self) -> &Path {
        match self {
            Self::Cli { executable, .. } => executable,
            Self::Desktop { spec, .. } => &spec.target_executable,
        }
    }
    fn fingerprint(&self) -> &str {
        match self {
            Self::Cli { sha256, .. } => sha256,
            Self::Desktop { spec, .. } => &spec.target_fingerprint,
        }
    }
    fn kind(&self) -> Kind {
        match self {
            Self::Cli { kind, .. } | Self::Desktop { kind, .. } => *kind,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedShell {
    shell: EntryShell,
    fragment: Stamp,
    rc_originally_present: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    schema: u32,
    target: LaunchTarget,
    destination: PathBuf,
    entry: Stamp,
    shell: Option<OwnedShell>,
}

pub struct ManagedEntryActivationManager {
    storage: StateStore,
    applications_dir: PathBuf,
    shims_dir: Option<PathBuf>,
    watch_engine_bin: PathBuf,
    launcher_bin: PathBuf,
    controlled_entry: Option<Vec<u8>>,
    shell: Option<EntryShell>,
}

impl ManagedEntryActivationManager {
    pub fn new(
        storage: StateStore,
        watch_engine_bin: PathBuf,
        launcher_bin: PathBuf,
        controlled_entry: Option<Vec<u8>>,
    ) -> Self {
        Self {
            applications_dir: storage.paths.home.join("Applications"),
            storage,
            shims_dir: None,
            watch_engine_bin,
            launcher_bin,
            controlled_entry,
            shell: None,
        }
    }
    pub fn set_shims_dir(&mut self, dir: PathBuf) {
        self.shims_dir = Some(dir);
    }
    pub fn set_applications_dir(&mut self, dir: PathBuf) {
        self.applications_dir = dir;
    }
    pub fn set_shell(&mut self, shell: EntryShell) {
        self.shell = Some(shell);
    }

    pub fn desktop_app_name(target: LaunchTarget) -> Result<&'static str> {
        match target {
            LaunchTarget::ClaudeDesktop => Ok("Claude (Controlled).app"),
            LaunchTarget::CodexDesktop => Ok("Codex (Controlled).app"),
            LaunchTarget::ChatgptDesktop => Ok("ChatGPT (Controlled).app"),
            _ => Err(err("invalid_desktop_target", "该目标不属于桌面受控入口")),
        }
    }

    pub fn cli_name(target: LaunchTarget) -> Result<&'static str> {
        match target {
            LaunchTarget::ClaudeCli => Ok("claude"),
            LaunchTarget::CodexCli => Ok("codex"),
            _ => Err(err("invalid_cli_target", "该目标不属于受控 CLI 入口")),
        }
    }

    pub fn destination(&self, target: LaunchTarget) -> Result<PathBuf> {
        if target.cli() {
            let dir = self.shims_dir.clone().unwrap_or_else(|| {
                self.storage
                    .paths
                    .watch()
                    .join("shims")
                    .join(target.as_str())
            });
            Ok(dir.join(Self::cli_name(target)?))
        } else {
            Ok(self.applications_dir.join(Self::desktop_app_name(target)?))
        }
    }

    fn record_path(&self, target: LaunchTarget) -> PathBuf {
        self.storage
            .paths
            .watch()
            .join("entry-ownership")
            .join(format!("{}.json", target.as_str()))
    }
    fn fragment_path(&self, target: LaunchTarget) -> PathBuf {
        self.storage
            .paths
            .watch()
            .join("entry-ownership")
            .join(format!("{}.sh", target.as_str()))
    }
    fn rc_path(&self, shell: EntryShell) -> PathBuf {
        self.storage.paths.home.join(shell.rc())
    }
    fn rc_block(&self, target: LaunchTarget) -> Result<String> {
        let t = target.as_str();
        Ok(format!("\n# BEGIN CLAUDE WATCH MANAGED CLI ({t})\n. {}\n# END CLAUDE WATCH MANAGED CLI ({t})\n",
            shell_path(&self.fragment_path(target))?))
    }

    fn ownership(&self, target: LaunchTarget, dest: &Path) -> Result<Option<(Ownership, Stamp)>> {
        let Some((bytes, stamp)) = Leaf::read_bytes(&self.record_path(target), 32_768)? else {
            if Leaf::read_stamp(dest)?.is_some() {
                return Err(err(
                    "entry_conflict",
                    format!("非受控文件或目录已存在：{}", dest.display()),
                ));
            }
            return Ok(None);
        };
        if stamp.mode != 0o600 {
            return Err(err("entry_ownership_invalid", "入口所有权记录权限无效"));
        }
        let record: Ownership = serde_json::from_value(strict_json(&bytes)?)
            .map_err(|_| err("entry_ownership_invalid", "入口所有权记录无效"))?;
        if record.schema != 1
            || record.target != target
            || record.destination != dest
            || record.shell.is_some() && !target.cli()
            || Leaf::read_stamp(dest)?.as_ref() != Some(&record.entry)
        {
            return Err(err(
                "entry_conflict",
                "入口目标、所有权或内容已改变，保留现有文件",
            ));
        }
        if let Some(shell) = &record.shell {
            if Leaf::read_stamp(&self.fragment_path(target))?.as_ref() != Some(&shell.fragment) {
                return Err(err("entry_conflict", "受控 shell 片段已改变，保留现有文件"));
            }
        }
        Ok(Some((record, stamp)))
    }

    fn shell_for(
        &self,
        target: LaunchTarget,
        record: Option<&Ownership>,
    ) -> Result<Option<EntryShell>> {
        if !target.cli() && self.shell.is_some() {
            return Err(err("entry_shell_requires_cli", "桌面入口不修改 shell"));
        }
        let prior = record.and_then(|r| r.shell.as_ref()).map(|s| s.shell);
        if self.shell.zip(prior).is_some_and(|(a, b)| a != b) {
            return Err(err(
                "entry_shell_conflict",
                "先停用已配置的 shell 引用再切换 shell",
            ));
        }
        Ok(self.shell.or(prior))
    }

    fn shell_state(
        &self,
        target: LaunchTarget,
        shell: EntryShell,
        expected: bool,
    ) -> Result<(PathBuf, Option<(Vec<u8>, Stamp)>)> {
        let rc = self.rc_path(shell);
        let current = Leaf::read_bytes(&rc, 1024 * 1024)?;
        let data = current
            .as_ref()
            .map_or(&[][..], |(bytes, _)| bytes.as_slice());
        let block = self.rc_block(target)?;
        let marker = format!("CLAUDE WATCH MANAGED CLI ({})", target.as_str());
        if expected {
            if find_once(data, block.as_bytes()).is_none()
                || count_bytes(data, marker.as_bytes()) != 2
            {
                return Err(err(
                    "entry_shell_conflict",
                    "受控 shell 引用已改变或丢失，保留原配置",
                ));
            }
        } else if count_bytes(data, marker.as_bytes()) != 0 {
            return Err(err(
                "entry_shell_conflict",
                "shell 中已有未获所有权的同名入口标记",
            ));
        }
        Ok((rc, current))
    }

    pub fn preview(
        &self,
        target: LaunchTarget,
        source: &EntrySource,
    ) -> Result<ManagedEntryPreview> {
        let destination_path = self.destination(target)?;
        let target_bundle_path = match source {
            EntrySource::Desktop { spec, .. } => Some(spec.target_bundle_path.clone()),
            _ => None,
        };
        let mut shell_config_path = None;
        let mut shell_snippet = None;
        let check = (|| {
            if target_bundle_path
                .as_ref()
                .is_some_and(|bundle| &destination_path == bundle)
            {
                return Err(err("cannot_overwrite_original", "不能覆盖原版应用"));
            }
            let ownership = self.ownership(target, &destination_path)?;
            let record = ownership.as_ref().map(|(r, _)| r);
            if let Some(shell) = self.shell_for(target, record)? {
                shell_config_path = Some(self.rc_path(shell));
                shell_snippet = Some(self.rc_block(target)?);
                self.shell_state(target, shell, record.is_some_and(|r| r.shell.is_some()))?;
            }
            Ok(())
        })();
        Ok(ManagedEntryPreview {
            target,
            kind: if target.cli() {
                ManagedEntryKind::CliShim
            } else {
                ManagedEntryKind::DesktopWrapper
            },
            entry_id: DesktopManagedEntrySpec::entry_bundle_id_for(target).into(),
            destination_path,
            target_executable: Some(source.executable().into()),
            target_fingerprint: Some(source.fingerprint().into()),
            target_bundle_path,
            conflict_detected: check.is_err(),
            conflict_reason: check.err().map(|e| e.message),
            shell_config_path,
            shell_snippet,
        })
    }

    fn entry_object(
        &self,
        target: LaunchTarget,
        source: &EntrySource,
        dest: &Path,
    ) -> Result<Object> {
        match source {
            EntrySource::Cli { entry_path, .. } if target.cli() && target.accepts(source.kind()) => Ok(Object::File(format!(
                "#!/bin/sh\n# CLAUDE WATCH MANAGED CLI ENTRY SHIM v2\nexport CW_SHIM_EXECUTABLE=\"$0\"\nexport {}={}\nexec {} launch --home {} --target {} --apply -- \"$@\"\n",
                if target == LaunchTarget::ClaudeCli { "CLAUDE_CODE_BIN" } else { "CODEX_CLI_BIN" },
                shell_path(entry_path)?, shell_path(&self.watch_engine_bin)?, shell_path(&self.storage.paths.home)?, target.as_str()
            ).into_bytes(), 0o755)),
            EntrySource::Desktop { spec, .. } if !target.cli() && spec.target == target => {
                if dest == spec.target_bundle_path || dest.starts_with(&spec.target_bundle_path) {
                    return Err(err("cannot_overwrite_original", "不能覆盖原版应用"));
                }
                let executable = self.controlled_entry.as_ref().filter(|bytes| {
                    // Thin arm64 Mach-O, MH_EXECUTE, as built by monitor/build.sh.
                    bytes.len() >= 32 && bytes[..8] == [0xcf,0xfa,0xed,0xfe,0x0c,0,0,1] && bytes[12..16] == [2,0,0,0]
                }).ok_or_else(|| err("controlled_entry_binary_missing", "缺少已校验的原生 ControlledEntry arm64 组件"))?;
                let plist = desktop_entry_plist(spec, Self::desktop_app_name(target)?, &self.watch_engine_bin,
                    &self.launcher_bin, &self.storage.paths.watch().join("state"), Some(&self.storage.paths.home));
                Ok(Object::Desktop { plist: plist.into_bytes(), executable: executable.clone() })
            }
            _ => Err(err("entry_source_mismatch", "入口与已核验来源不匹配")),
        }
    }

    pub fn activate(
        &self,
        target: LaunchTarget,
        source: &EntrySource,
        activity: &EntryActivity,
    ) -> Result<ManagedEntryActivationResult> {
        if !activity.unmanaged.is_empty() || !activity.pending.is_empty() {
            return Err(err(
                "already_running_unmanaged",
                "已有同一来源的未受控或待验证实例，保留进程，未启用入口",
            ));
        }
        let dest = self.destination(target)?;
        let object = self.entry_object(target, source, &dest)?;
        let _lock = self.storage.lock("managed-entry", None)?;
        if claude_watch_system::sha256_file_hex(source.executable()).as_deref()
            != Some(source.fingerprint())
        {
            return Err(err(
                "entry_source_changed",
                "准备启用期间，已核验的入口来源发生变化",
            ));
        }
        let ownership = self.ownership(target, &dest)?;
        let prior = ownership.as_ref().map(|(r, _)| r);
        let shell = self.shell_for(target, prior)?;
        let entry = Change::prepare(&dest, prior.map(|r| r.entry.clone()), Some(object))?;
        let entry_stamp = entry.new.clone().unwrap();
        let mut changes = vec![entry];
        let mut owned_shell = None;
        if let Some(shell) = shell {
            let prior_shell = prior.and_then(|r| r.shell.as_ref());
            let (rc, current) = self.shell_state(target, shell, prior_shell.is_some())?;
            let rc_originally_present =
                prior_shell.map_or(current.is_some(), |s| s.rc_originally_present);
            let fragment_path = self.fragment_path(target);
            let fragment = Change::prepare(
                &fragment_path,
                prior_shell.map(|s| s.fragment.clone()),
                Some(Object::File(
                    format!(
                        "# Claude Watch managed entry: {}\nexport PATH={}:\"$PATH\"\n",
                        target.as_str(),
                        shell_path(dest.parent().unwrap())?
                    )
                    .into_bytes(),
                    0o600,
                )),
            )?;
            owned_shell = Some(OwnedShell {
                shell,
                fragment: fragment.new.clone().unwrap(),
                rc_originally_present,
            });
            changes.push(fragment);
            if prior_shell.is_none() {
                let (mut bytes, old) = current.map_or((vec![], None), |(b, s)| (b, Some(s)));
                let mode = old.as_ref().map_or(0o600, |s| s.mode);
                bytes.extend_from_slice(self.rc_block(target)?.as_bytes());
                changes.push(Change::prepare(&rc, old, Some(Object::File(bytes, mode)))?);
            }
        }
        let record = Ownership {
            schema: 1,
            target,
            destination: dest.clone(),
            entry: entry_stamp,
            shell: owned_shell,
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|_| err("entry_ownership_invalid", "无法记录入口所有权"))?;
        changes.push(Change::prepare(
            &self.record_path(target),
            ownership.map(|(_, stamp)| stamp),
            Some(Object::File(bytes, 0o600)),
        )?);
        commit(changes)?;
        Ok(ManagedEntryActivationResult {
            target,
            entry_id: DesktopManagedEntrySpec::entry_bundle_id_for(target).into(),
            installed_path: dest,
            status: "activated".into(),
            activation_configured: !target.cli() || shell.is_some(),
            message: if shell.is_some() {
                "入口与选定的 shell 引用已写入；当前 shell 是否加载仍待确认".into()
            } else {
                "受控入口已生成；实际启动与保护须分别核验".into()
            },
        })
    }

    pub fn status(
        &self,
        target: LaunchTarget,
        activity: EntryActivity,
    ) -> Result<ManagedEntryStatusReport> {
        let path = self.destination(target)?;
        let ownership = self.ownership(target, &path)?;
        let record = ownership.as_ref().map(|(r, _)| r);
        let generated = record.is_some();
        let configured = if let Some(shell) = record.and_then(|r| r.shell.as_ref()) {
            self.shell_state(target, shell.shell, true)?;
            true
        } else {
            generated && !target.cli()
        };
        let shell_resolution = if !target.cli() {
            "not_applicable"
        } else if !configured {
            "not_configured"
        } else if first_executable(Self::cli_name(target)?)
            .as_deref()
            .is_some_and(|p| p != path)
        {
            "earlier_path_candidate"
        } else {
            "current_shell_unconfirmed"
        };
        let (state, status_label) = if !activity.unmanaged.is_empty() {
            (
                ManagedInstanceState::RunningUnprotected,
                "检测到未受控的来源实例",
            )
        } else if activity.protected > 0 {
            (
                ManagedInstanceState::ExecVerified,
                "已核验受控实例与当前网关回执",
            )
        } else if activity.managed > 0 || !activity.pending.is_empty() {
            (ManagedInstanceState::Preparing, "实例已发现，保护待验证")
        } else if generated {
            (
                ManagedInstanceState::EntryConfigured,
                "入口已生成，等待实际调用",
            )
        } else {
            (ManagedInstanceState::Exited, "受控入口未生成")
        };
        Ok(ManagedEntryStatusReport {
            target,
            entry_id: DesktopManagedEntrySpec::entry_bundle_id_for(target).into(),
            entry_path: path,
            entry_generated: generated,
            activation_configured: configured,
            current_invocation_verified: activity.managed > 0,
            shell_resolution: shell_resolution.into(),
            state,
            active_managed_count: activity.managed,
            protected_instance_count: activity.protected,
            unmanaged_pids: activity.unmanaged,
            pending_pids: activity.pending,
            status_label: status_label.into(),
        })
    }

    pub fn deactivate(&self, target: LaunchTarget) -> Result<ManagedEntryDeactivationResult> {
        let dest = self.destination(target)?;
        let result = |was_present| ManagedEntryDeactivationResult {
            target,
            entry_id: DesktopManagedEntrySpec::entry_bundle_id_for(target).into(),
            removed_path: dest.clone(),
            was_present,
            message: if was_present {
                "已移除与所有权记录相符的入口及 shell 引用".into()
            } else {
                "入口未部署".into()
            },
        };
        if self.ownership(target, &dest)?.is_none() {
            return Ok(result(false));
        }
        let _lock = self.storage.lock("managed-entry", None)?;
        let Some((record, stamp)) = self.ownership(target, &dest)? else {
            return Ok(result(false));
        };
        let mut changes = Vec::new();
        if let Some(shell) = record.shell {
            let (rc, current) = self.shell_state(target, shell.shell, true)?;
            let (mut bytes, old) =
                current.ok_or_else(|| err("entry_shell_conflict", "原配置已丢失"))?;
            let block = self.rc_block(target)?;
            let start = find_once(&bytes, block.as_bytes())
                .ok_or_else(|| err("entry_shell_conflict", "原配置引用已改变"))?;
            bytes.drain(start..start + block.len());
            let replacement = if bytes.is_empty() && !shell.rc_originally_present {
                None
            } else {
                Some(Object::File(bytes, old.mode))
            };
            changes.push(Change::prepare(&rc, Some(old), replacement)?);
            changes.push(Change::prepare(
                &self.fragment_path(target),
                Some(shell.fragment),
                None,
            )?);
        }
        changes.push(Change::prepare(&dest, Some(record.entry), None)?);
        changes.push(Change::prepare(
            &self.record_path(target),
            Some(stamp),
            None,
        )?);
        commit(changes)?;
        Ok(result(true))
    }
}

fn count_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}
fn find_once(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if count_bytes(haystack, needle) != 1 {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
fn shell_path(path: &Path) -> Result<String> {
    let raw = path
        .to_str()
        .filter(|v| path.is_absolute() && !v.chars().any(char::is_control))
        .ok_or_else(|| err("entry_invalid_path", "入口路径必须为不含控制字符的绝对路径"))?;
    Ok(format!("'{}'", raw.replace('\'', "'\\''")))
}
fn first_executable(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .take(128)
        .map(|dir| dir.join(name))
        .find(|p| fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

#[derive(Deserialize)]
struct EntryRegistryRow {
    #[serde(flatten)]
    instance: ManagedLaunchInstance,
    #[serde(default)]
    process_visibility: Option<EntryRegistryVisibility>,
}

#[derive(Deserialize)]
struct EntryRegistryVisibility {
    observed_at: f64,
    members: Vec<EntryRegistryMember>,
}

#[derive(Deserialize)]
struct EntryRegistryMember {
    pid: u32,
    uid: u32,
    start_seconds: u64,
    start_microseconds: u32,
    audit_identity_digest: String,
    currently_verified: bool,
    #[serde(default)]
    verified_executable: Option<String>,
}

/// Only live identity, current producer/boot and the normal verified registry
/// can prove a controlled invocation. Shell aliases, functions, hashes and the
/// calling shell's loaded state cannot be inferred from PATH or an environment flag.
pub fn observe_entry(
    storage: &StateStore,
    target: LaunchTarget,
    source: &EntrySource,
    observed_targets: &[Target],
    now: f64,
) -> Result<EntryActivity> {
    let authority = storage.read_json(
        &storage.paths.watch().join("state/channel-supervision.json"),
        Value::Null,
    )?;
    let policy = ChannelSupervisor::compute_policy_version(
        &(ConfigStore {
            storage: storage.clone(),
        })
        .load()?,
    )?;
    let family = PolicyCatalog::family_for(source.kind().provider()).map(|f| f.id).unwrap_or_default();
    let state = &authority["families"][family];
    let policy_wire = serde_json::json!(policy);
    let fresh = |at| (0.0..10.0).contains(&(now - at));
    let boot = authority["executor_boot_id"].as_str().filter(|id| {
        !id.is_empty()
            && producer_is_current(&authority)
            && authority["producer_boot_id"].as_str().is_some_and(|boot| !boot.is_empty())
            && authority["saved_policy_version"] == policy_wire
            && state["producer_boot_id"] == authority["producer_boot_id"]
            && state["saved_policy_version"] == policy_wire
            && authority["captured_at"].as_f64().is_some_and(fresh)
    });
    let child_tokens: Vec<BoundProcessToken> = if boot.is_some() {
        serde_json::from_value(state["active_members"].clone()).unwrap_or_default()
    } else {
        Vec::new()
    };
    let instances: Vec<EntryRegistryRow> = storage
        .read_json(
            &storage
                .paths
                .watch()
                .join("state/managed-launch-instances.json"),
            Value::Null,
        )
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    let mut activity = EntryActivity::default();
    let mut managed = BTreeMap::new();
    let mut pending_instances = BTreeSet::new();
    for p in snapshot_running_processes()? {
        let matches = Path::new(&p.executable) == source.executable()
            || match source {
                EntrySource::Desktop { spec, .. } => {
                    Path::new(&p.executable).starts_with(spec.target_bundle_path.join("Contents"))
                }
                EntrySource::Cli { script: true, .. } => observed_targets.iter().any(|t| {
                    t.kind == source.kind()
                        && t.identity.pid == p.pid
                        && t.identity.uid == p.uid
                        && t.identity.start_seconds == p.start_seconds
                        && t.identity.start_microseconds == p.start_microseconds
                        && t.identity.executable == p.executable
                }),
                _ => false,
            };
        let desktop_member = matches && matches!(source, EntrySource::Desktop { .. });
        let mut candidates = instances.iter().filter_map(|row| {
            let i = &row.instance;
            if i.target != target || i.family != family || i.uid != p.uid
                || !(Path::new(&i.expected_executable) == source.executable()
                    || i.script_entry.as_deref().is_some_and(|s| Path::new(s) == source.executable())) {
                return None;
            }
            if i.pid == p.pid && i.start_seconds == p.start_seconds && i.start_microseconds == p.start_microseconds {
                return Some((i, None));
            }
            let visibility = row.process_visibility.as_ref().filter(|_| desktop_member && i.pid != p.pid)?;
            let member = visibility.members.iter().find(|m| m.pid == p.pid && m.uid == p.uid
                && m.start_seconds == p.start_seconds && m.start_microseconds == p.start_microseconds)?;
            Some((i, Some((visibility.observed_at, member))))
        });
        let instance = candidates.next();
        if !matches && instance.is_none() {
            continue;
        }
        let identity = Identity {
            pid: p.pid,
            parent: p.ppid,
            uid: p.uid,
            executable: p.executable,
            start_seconds: p.start_seconds,
            start_microseconds: p.start_microseconds,
            start_stamp: String::new(),
        };
        let competing = candidates.next();
        let ambiguous = competing.is_some();
        let verified = !ambiguous && boot.zip(instance).is_some_and(|(boot, (i, child))| {
            let source_hash = i.script_fingerprint.as_deref().unwrap_or(&i.expected_fingerprint);
            if i.executor_boot_id != boot || !fresh(i.updated_at) || source_hash != source.fingerprint() { return false; }
            let Some(live) = claude_watch_system::inspect_process_identity(identity.pid).filter(|live|
                live.uid == identity.uid && live.start_seconds == identity.start_seconds
                    && live.start_microseconds == identity.start_microseconds && live.executable_path == identity.executable)
            else { return false; };
            let matches_live = |token: &BoundProcessToken| token.has_verified_audit_token()
                && token.matches_process(live.pid, live.uid, live.start_seconds, live.start_microseconds, Some(&live.audit_token));
            if let Some((at, member)) = child {
                let audit = live.audit_token.iter().map(u32::to_string).collect::<Vec<_>>().join(":");
                i.state == ManagedInstanceState::ExecVerified && i.has_verified_subtree_protection(boot, &policy)
                    && fresh(at) && i.controlled_subtree_pids.contains(&live.pid) && member.currently_verified
                    && member.verified_executable.as_deref() == Some(live.executable_path.as_str())
                    && member.audit_identity_digest == claude_watch_system::sha256_bytes_hex(audit.as_bytes())
                    && child_tokens.iter().any(|token| token.role == ProcessRole::Child && matches_live(token))
            } else {
                i.has_verified_main_protection(boot, &policy)
                    && i.verified_executable.as_deref() == Some(live.executable_path.as_str())
                    && i.exec_identity.as_ref().is_some_and(matches_live)
            }
        });
        if verified {
            let id = &instance.unwrap().0.instance_id;
            let protected = process_protection(storage, &authority, &identity, source.kind(), now)["state"] == "protected";
            managed.entry(id).and_modify(|all| *all &= protected).or_insert(protected);
        } else if let Some((i, _)) = instance {
            pending_instances.insert(&i.instance_id);
            if let Some((other, _)) = competing {
                pending_instances.insert(&other.instance_id);
                pending_instances.extend(candidates.map(|(other, _)| &other.instance_id));
            }
            activity.pending.push(identity.pid);
        } else {
            activity.unmanaged.push(identity.pid);
        }
    }
    activity.managed = managed.len();
    activity.protected = managed.into_iter().filter(|(id, protected)| *protected && !pending_instances.contains(id)).count();
    Ok(activity)
}
