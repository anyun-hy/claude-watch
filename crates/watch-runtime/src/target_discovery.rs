//! Installation discovery is a source of candidates, never network authority.
//! All consumers use this catalog; content approval stays in the existing registry.
use crate::{
    commands::{ReadCommand, ReadRunner},
    storage::{Paths, StateStore},
};
use claude_watch_core::{
    error::{CoreError, Result},
    process_roots::{self, TrustedCliPaths},
    processes::{Kind, LaunchTarget},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex, OnceLock, Weak},
    time::Duration,
};

pub const DESKTOP_IDS: [(&str, LaunchTarget); 3] = [
    (
        "com.anthropic.claudefordesktop",
        LaunchTarget::ClaudeDesktop,
    ),
    ("com.openai.codex", LaunchTarget::CodexDesktop),
    ("com.openai.chat", LaunchTarget::ChatgptDesktop),
];
pub const BUNDLED_CLI_ENTRIES: [&str; 4] = [
    "Contents/Resources/codex",
    "Contents/Resources/codex-cli/bin/codex",
    "Contents/Resources/CodexCLI.app/Contents/MacOS/codex",
    "Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex",
];
pub trait ApplicationRegistry: Send + Sync {
    fn locations(
        &self,
        id: &str,
    ) -> Result<claude_watch_system::application_locations::ApplicationLocations>;
}
pub struct SystemApplicationRegistry;
impl ApplicationRegistry for SystemApplicationRegistry {
    fn locations(
        &self,
        id: &str,
    ) -> Result<claude_watch_system::application_locations::ApplicationLocations> {
        claude_watch_system::application_locations::registered_applications(id)
            .map_err(|_| CoreError::new("application_registry_unavailable", "系统应用登记暂不可读"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredTarget {
    pub target: LaunchTarget,
    pub source_kind: String,
    pub source_id: String,
    pub entry_path: PathBuf,
    pub bundle: Option<PathBuf>,
    pub bundle_id: Option<String>,
    pub executable: Option<PathBuf>,
    pub script_entry: Option<PathBuf>,
    pub interpreter: Option<PathBuf>,
    pub launcher_supported: bool,
    #[serde(default)]
    pub child_executables: Vec<PathBuf>,
    pub error_code: Option<String>,
}
impl DiscoveredTarget {
    pub fn valid(&self) -> bool {
        self.error_code.is_none() && self.executable.is_some()
    }
    pub fn kind(&self) -> Option<Kind> {
        if self.target.cli() {
            return Some(if self.target == LaunchTarget::ClaudeCli {
                Kind::ClaudeCode
            } else {
                Kind::CodexCli
            });
        }
        process_roots::desktop_kind(
            self.bundle.as_ref()?.to_str()?,
            self.bundle_id.as_deref()?,
            true,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoverySnapshot {
    pub revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_revision: Option<String>,
    pub complete: bool,
    pub targets: Vec<DiscoveredTarget>,
    pub issues: Vec<String>,
    pub preferred_sources: BTreeMap<String, String>,
}
impl DiscoverySnapshot {
    pub fn select(&self, target: LaunchTarget, source: Option<&str>) -> Result<&DiscoveredTarget> {
        let accepts =
            |record: &&DiscoveredTarget| record.kind().is_some_and(|kind| target.accepts(kind));
        if let Some(id) = source.or_else(|| {
            self.preferred_sources
                .get(target.as_str())
                .map(String::as_str)
        }) {
            return self
                .targets
                .iter()
                .find(|r| r.source_id == id && accepts(&r))
                .filter(|r| r.valid())
                .ok_or_else(|| {
                    CoreError::new(
                        "selected_source_unavailable",
                        "已选安装来源失效，未切换到其他安装",
                    )
                });
        }
        let records: Vec<_> = self
            .targets
            .iter()
            .filter(accepts)
            .filter(|r| r.valid())
            .collect();
        let files: BTreeSet<_> = records
            .iter()
            .filter_map(|r| r.executable.as_ref())
            .collect();
        if files.len() > 1 {
            return Err(CoreError::new(
                "ambiguous_source",
                "存在多个有效安装，尚未选定来源",
            ));
        }
        records
            .first()
            .copied()
            .ok_or_else(|| CoreError::new("target_app_unavailable", "未找到经安装证据验证的目标"))
    }
    pub fn cli_paths(&self) -> TrustedCliPaths {
        self.process_paths(false)
    }
    pub fn process_paths(&self, omit_aliases: bool) -> TrustedCliPaths {
        let mut trusted = TrustedCliPaths::default();
        trusted.exact_cli_catalog = true;
        trusted.desktop_catalog = Some(
            self.targets
                .iter()
                .filter(|r| r.valid() && !r.target.cli())
                .filter_map(|r| {
                    Some((
                        r.bundle.clone()?,
                        r.bundle_id.clone()?,
                        r.executable.clone()?,
                    ))
                })
                .collect(),
        );
        trusted.pending_desktops = self
            .targets
            .iter()
            .filter(|r| !r.valid() && !r.target.cli())
            .filter_map(|r| Some((r.bundle.clone()?, r.bundle_id.clone()?)))
            .collect();
        for r in self.targets.iter().filter(|r| {
            r.valid() && r.target.cli() && !(omit_aliases && r.source_kind == "supported_alias")
        }) {
            if let Some(path) = r
                .script_entry
                .as_ref()
                .or(r.executable.as_ref())
                .and_then(|p| p.to_str())
            {
                if r.target == LaunchTarget::ClaudeCli {
                    trusted.claude.insert(path.into());
                } else {
                    trusted.codex.insert(path.into());
                }
                use claude_watch_core::processes::MatchReason;
                let reason = if r.source_kind == "verified_bundle_cli" {
                    MatchReason::VerifiedBundleComponent
                } else if r.source_kind == "supported_alias"
                    || r.executable.as_ref().is_some_and(|p| *p != r.entry_path)
                {
                    MatchReason::SupportedCliAlias
                } else {
                    MatchReason::KnownCliLayout
                };
                let current = trusted.cli_reasons.entry(path.into()).or_insert(reason);
                if matches!(
                    reason,
                    MatchReason::SupportedCliAlias | MatchReason::VerifiedBundleComponent
                ) {
                    *current = reason;
                }
            }
        }
        trusted
    }
}

#[derive(Clone, Debug)]
pub struct DiscoveryInputs {
    pub home: PathBuf,
    pub application_roots: Vec<PathBuf>,
    pub prefixes: Vec<PathBuf>,
    pub daemon_path: Vec<PathBuf>,
    pub caller_path: Vec<PathBuf>,
    pub caller_paths: BTreeMap<String, Vec<PathBuf>>,
    pub desktop_sources: BTreeMap<String, PathBuf>,
    pub overrides: BTreeMap<String, PathBuf>,
    pub observed_bundles: Vec<PathBuf>,
    pub observed_bundle_ids: BTreeMap<PathBuf, String>,
    pub observed_cli_entries: Vec<(LaunchTarget, PathBuf)>,
    pub observed_interpreters: BTreeMap<PathBuf, PathBuf>,
    pub query_registry: bool,
    pub entry_budget: usize,
    pub input_issues: BTreeSet<String>,
}
pub fn isolated_home(home: &Path) -> bool {
    [
        "/tmp/",
        "/private/tmp/",
        "/var/folders/",
        "/private/var/folders/",
    ]
    .iter()
    .any(|p| home.to_string_lossy().starts_with(p))
}
impl DiscoveryInputs {
    pub fn for_home(home: &Path) -> Self {
        let resolved = fs::canonicalize(home).unwrap_or_else(|_| home.into());
        let home = resolved.as_path();
        let isolated = isolated_home(home);
        let mut input_issues = BTreeSet::new();
        let daemon_path = if isolated {
            vec![]
        } else {
            let paths = search_path_entries(&std::env::var_os("PATH").unwrap_or_default())
                .unwrap_or_else(|_| {
                    input_issues.insert("daemon_path_unavailable".into());
                    vec![]
                });
            if paths.len() > 128 {
                input_issues.insert("daemon_path_partial".into());
            }
            paths.into_iter().take(128).collect()
        };
        let mut application_roots = vec![home.join("Applications")];
        if let Some(path) = std::env::var_os("CW_APPLICATIONS_DIR") {
            application_roots.insert(0, path.into());
        }
        if !isolated {
            application_roots.push("/Applications".into());
        }
        Self {
            home: home.into(),
            application_roots,
            prefixes: if isolated {
                vec![]
            } else {
                vec!["/opt/homebrew".into(), "/usr/local".into()]
            },
            daemon_path,
            caller_path: vec![],
            caller_paths: BTreeMap::new(),
            desktop_sources: BTreeMap::new(),
            overrides: ["CLAUDE_CODE_BIN", "CODEX_CLI_BIN"]
                .into_iter()
                .filter_map(|key| std::env::var_os(key).map(|value| (key.into(), value.into())))
                .collect(),
            observed_bundles: vec![],
            observed_bundle_ids: BTreeMap::new(),
            observed_cli_entries: vec![],
            observed_interpreters: BTreeMap::new(),
            query_registry: !isolated,
            entry_budget: 1024,
            input_issues,
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct DiscoveryCounters {
    pub registry_queries: u64,
    pub directory_queries: u64,
    pub directory_entries: u64,
    pub plist_reads: u64,
    pub scans: u64,
    pub fingerprint_reads: u64,
}
type Signature = Vec<(PathBuf, Vec<i128>, Option<PathBuf>)>;
#[derive(Clone)]
struct DirectoryBatch {
    stamp: (Vec<i128>, Option<PathBuf>),
    offset: usize,
    paths: Vec<PathBuf>,
    more: bool,
    error: bool,
}
fn stamp(path: &Path) -> (Vec<i128>, Option<PathBuf>) {
    let mut facts = Vec::new();
    for value in [fs::symlink_metadata(path), fs::metadata(path)] {
        match value {
            Ok(m) => facts.extend([
                m.dev() as i128,
                m.ino() as i128,
                m.len() as i128,
                m.mtime() as i128,
                m.mtime_nsec() as i128,
                m.ctime() as i128,
                m.ctime_nsec() as i128,
                m.mode() as i128,
            ]),
            Err(e) => facts.extend([-1, e.raw_os_error().unwrap_or(0) as i128]),
        }
    }
    (facts, fs::canonicalize(path).ok())
}

pub struct DiscoveryCache {
    pub inputs: DiscoveryInputs,
    pub counters: DiscoveryCounters,
    snapshot: Option<Arc<DiscoverySnapshot>>,
    signature: Signature,
    registered: BTreeMap<String, Vec<PathBuf>>,
    registry_issues: Vec<String>,
    last_registry_at: Option<f64>,
    dirty: bool,
    hint_stamp: Option<(Vec<i128>, Option<PathBuf>)>,
    bound_sources: BTreeMap<String, String>,
    fingerprints: BTreeMap<PathBuf, (crate::executable_verification::FileIdentity, String)>,
    directory_offsets: BTreeMap<PathBuf, usize>,
    next_directory_offsets: BTreeMap<PathBuf, usize>,
    base_overrides: BTreeMap<String, PathBuf>,
    hint_issues: Vec<String>,
    directories: BTreeMap<PathBuf, DirectoryBatch>,
    cancellation: Option<Arc<AtomicBool>>,
}
impl DiscoveryCache {
    pub fn new(inputs: DiscoveryInputs) -> Self {
        let base_overrides = inputs.overrides.clone();
        Self {
            inputs,
            counters: DiscoveryCounters::default(),
            snapshot: None,
            signature: vec![],
            registered: BTreeMap::new(),
            registry_issues: vec![],
            last_registry_at: None,
            dirty: true,
            hint_stamp: None,
            bound_sources: BTreeMap::new(),
            fingerprints: BTreeMap::new(),
            directory_offsets: BTreeMap::new(),
            next_directory_offsets: BTreeMap::new(),
            base_overrides,
            hint_issues: vec![],
            directories: BTreeMap::new(),
            cancellation: None,
        }
    }
    fn input_issue(&mut self, code: &str, present: bool) {
        let changed = if present {
            self.inputs.input_issues.insert(code.into())
        } else {
            self.inputs.input_issues.remove(code)
        };
        self.dirty |= changed;
    }
    pub fn refresh<R: ReadRunner + ?Sized>(
        &mut self,
        reader: &R,
        registry: &dyn ApplicationRegistry,
        now: f64,
    ) -> Arc<DiscoverySnapshot> {
        if self.cancelled() { return self.pending_snapshot("target_discovery_cancelled"); }
        let store = StateStore::new(Paths {
            home: self.inputs.home.clone(),
        });
        let hint_path = store
            .paths
            .watch()
            .join("state/target-discovery-hints.json");
        let hint_stamp = stamp(&hint_path);
        if self.hint_stamp.as_ref() != Some(&hint_stamp) {
            self.hint_stamp = Some(hint_stamp);
            self.hint_issues.clear();
            self.dirty = true;
            match store.read_bytes(&hint_path, 128 * 1024) {
                Ok(Some(bytes)) => {
                    if let Ok(hints) = crate::storage::strict_json(&bytes) {
                        if let Ok(paths) =
                            serde_json::from_value::<Vec<PathBuf>>(hints["caller_path"].clone())
                        {
                            if paths.len() > 128 || paths.iter().any(|p| !p.is_absolute()) {
                                self.hint_issues.push("caller_path_partial".into());
                            }
                            self.inputs.caller_path = paths
                                .into_iter()
                                .filter(|p| p.is_absolute())
                                .take(128)
                                .collect();
                            self.dirty = true;
                        } else {
                            self.hint_issues.push("discovery_hint_invalid".into());
                        }
                        if let Ok(paths) = serde_json::from_value::<BTreeMap<String, Vec<PathBuf>>>(
                            hints["caller_paths"].clone(),
                        ) {
                            let mut scoped = BTreeMap::new();
                            for (target, paths) in paths {
                                if !LaunchTarget::parse(&target).is_some_and(LaunchTarget::cli) {
                                    self.hint_issues.push("discovery_hint_invalid".into());
                                    continue;
                                }
                                if paths.len() > 128 || paths.iter().any(|p| !p.is_absolute()) {
                                    self.hint_issues.push("caller_path_partial".into());
                                }
                                let paths = paths
                                    .into_iter()
                                    .filter(|p| p.is_absolute())
                                    .take(128)
                                    .collect::<Vec<_>>();
                                if self.inputs.caller_paths.get(&target) != Some(&paths) {
                                    self.bound_sources.remove(&target);
                                }
                                scoped.insert(target, paths);
                            }
                            self.inputs.caller_paths = scoped;
                        }
                        if let Ok(sources) = serde_json::from_value::<BTreeMap<String, PathBuf>>(
                            hints["desktop_sources"].clone(),
                        ) {
                            let mut accepted = BTreeMap::new();
                            for (target, path) in sources {
                                if !LaunchTarget::parse(&target).is_some_and(|t| !t.cli())
                                    || !path.is_absolute()
                                {
                                    self.hint_issues.push("discovery_hint_invalid".into());
                                    continue;
                                }
                                if self.inputs.desktop_sources.get(&target) != Some(&path) {
                                    self.bound_sources.remove(&target);
                                }
                                accepted.insert(target, path);
                            }
                            self.inputs.desktop_sources = accepted;
                        }
                        // Hints go through normal source verification, never deserialize approvals.
                        self.inputs.overrides = self.base_overrides.clone();
                        for key in ["CLAUDE_CODE_BIN", "CODEX_CLI_BIN"] {
                            if let Some(path) = hints["overrides"][key]
                                .as_str()
                                .map(PathBuf::from)
                                .filter(|p| p.is_absolute())
                            {
                                self.inputs.overrides.insert(key.into(), path);
                                self.dirty = true;
                            }
                        }
                    } else {
                        self.hint_issues.push("discovery_hint_invalid".into());
                    }
                }
                Ok(None) => {}
                Err(_) => self.hint_issues.push("discovery_hint_unreadable".into()),
            }
        }
        if self.inputs.query_registry
            && self
                .last_registry_at
                .is_none_or(|at| !now.is_finite() || now < at || now - at >= 30.0)
        {
            let prior_issues = self.registry_issues.clone();
            self.registry_issues.clear();
            for (id, _) in DESKTOP_IDS {
                if self.cancelled() { return self.pending_snapshot("target_discovery_cancelled"); }
                self.counters.registry_queries += 1;
                match registry.locations(id) {
                    Ok(mut batch) => {
                        if !batch.complete || batch.paths.len() > 512 {
                            self.registry_issues
                                .push("application_registry_partial".into());
                        }
                        batch.paths.truncate(512);
                        if self.registered.get(id) != Some(&batch.paths) {
                            self.registered.insert(id.into(), batch.paths);
                            self.dirty = true;
                        }
                    }
                    Err(error) => {
                        self.registry_issues.push(error.code);
                        self.dirty = true;
                    }
                }
            }
            if prior_issues != self.registry_issues {
                self.dirty = true;
            }
            self.last_registry_at = Some(now);
        }
        if !self.dirty
            && self.snapshot.is_some()
            && self
                .signature
                .iter()
                .all(|(path, facts, canonical)| stamp(path) == (facts.clone(), canonical.clone()))
        {
            return self.snapshot.as_ref().unwrap().clone();
        }
        let mut previous = None;
        self.directory_offsets.retain(|path, _| {
            self.signature
                .iter()
                .find(|(p, _, _)| p == path)
                .is_some_and(|(_, facts, canonical)| {
                    stamp(path) == (facts.clone(), canonical.clone())
                })
        });
        for _ in 0..4 {
            let (mut snapshot, signature) = self.scan(reader);
            if self.cancelled() { return self.pending_snapshot("target_discovery_cancelled"); }
            if !signature
                .iter()
                .all(|(path, facts, canonical)| stamp(path) == (facts.clone(), canonical.clone()))
            {
                previous = None;
                continue;
            }
            let evidence=serde_json::to_vec(&json!({"targets":snapshot.targets,"preferred":snapshot.preferred_sources,"issues":snapshot.issues})).unwrap();
            if previous.as_ref() == Some(&(signature.clone(), evidence.clone())) {
                snapshot.issues.extend(self.registry_issues.clone());
                snapshot
                    .issues
                    .extend(self.inputs.input_issues.iter().cloned());
                snapshot.issues.extend(self.hint_issues.clone());
                snapshot.issues.sort();
                snapshot.issues.dedup();
                snapshot.complete &= snapshot.issues.is_empty();
                snapshot.revision = crate::storage::sha256(
                    &serde_json::to_vec(&json!({"signature":signature,"targets":snapshot.targets,
                    "preferred":snapshot.preferred_sources,"issues":snapshot.issues}))
                    .unwrap(),
                );
                self.signature = signature;
                self.dirty = !snapshot.complete;
                self.directories
                    .retain(|path, _| self.signature.iter().any(|(p, _, _)| p == path));
                self.directory_offsets = self.next_directory_offsets.clone();
                let snapshot = Arc::new(snapshot);
                self.snapshot = Some(snapshot.clone());
                return snapshot;
            }
            previous = Some((signature, evidence));
        }
        // An unstable scan never becomes a successful cached signature. Keep
        // only still-readable previous evidence for unrelated sources.
        self.pending_snapshot("target_discovery_unstable")
    }
    fn cancelled(&self) -> bool {
        self.cancellation.as_ref().is_some_and(|stop| stop.load(Ordering::Acquire))
    }
    fn pending_snapshot(&mut self, reason: &str) -> Arc<DiscoverySnapshot> {
        let mut snapshot = self
            .snapshot
            .as_deref()
            .cloned()
            .unwrap_or(DiscoverySnapshot {
                revision: String::new(),
                prior_revision: None,
                complete: false,
                targets: vec![],
                issues: vec![],
                preferred_sources: BTreeMap::new(),
            });
        snapshot.complete = false;
        snapshot.issues = vec![reason.into()];
        snapshot
            .targets
            .retain(|r| self.record_is_current(r) && self.source_is_configured(r));
        snapshot.prior_revision = Some(snapshot.revision.clone());
        snapshot.revision = crate::storage::sha256(
            &serde_json::to_vec(
                &json!({"pending_from":snapshot.prior_revision,"targets":snapshot.targets,"reason":reason}),
            )
            .unwrap(),
        );
        self.dirty = true;
        Arc::new(snapshot)
    }
    fn record_is_current(&self, record: &DiscoveredTarget) -> bool {
        let Some(executable) = &record.executable else {
            return false;
        };
        let mut paths = vec![record.entry_path.clone(), executable.clone()];
        paths.extend(record.child_executables.clone());
        if let Some(bundle) = &record.bundle {
            paths.push(bundle.join("Contents/Info.plist"));
        }
        for parent in executable.ancestors().take(8) {
            if parent.ends_with("node_modules/@openai/codex")
                || parent.ends_with("node_modules/@anthropic-ai/claude-code")
            {
                paths.push(parent.join("package.json"));
            }
        }
        paths.iter().all(|p| {
            self.signature
                .iter()
                .find(|(path, _, _)| path == p)
                .is_some_and(|(_, facts, canonical)| stamp(p) == (facts.clone(), canonical.clone()))
        })
    }
    fn scan<R: ReadRunner + ?Sized>(&mut self, reader: &R) -> (DiscoverySnapshot, Signature) {
        self.counters.scans += 1;
        let retained = self
            .snapshot
            .as_ref()
            .map(|s| {
                s.targets
                    .iter()
                    .filter(|r| self.record_is_current(r) && self.source_is_configured(r))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut scan = Scan {
            reader,
            inputs: &self.inputs,
            counters: &mut self.counters,
            watched: BTreeMap::new(),
            targets: vec![],
            issues: vec![],
            remaining: self.inputs.entry_budget.saturating_mul(8).clamp(512, 4096),
            preferred: BTreeMap::new(),
            offsets: &self.directory_offsets,
            next_offsets: BTreeMap::new(),
            batched: BTreeSet::new(),
            directories: &mut self.directories,
            cancellation: self.cancellation.clone(),
        };
        for root in &self.inputs.application_roots {
            for path in scan.entries(root) {
                if path.extension().is_some_and(|e| e == "app") {
                    scan.desktop(path, "applications_root", None);
                }
            }
        }
        for (id, paths) in &self.registered {
            for path in paths {
                let record = scan.desktop(path.clone(), "registered_application", Some(id));
                if let Some(record) = record.filter(|r| r.valid()) {
                    scan.preferred
                        .entry(record.target.as_str().into())
                        .or_insert(record.source_id);
                }
            }
        }
        for path in &self.inputs.observed_bundles {
            scan.desktop(
                path.clone(),
                "observed_bundle",
                self.inputs
                    .observed_bundle_ids
                    .get(path)
                    .map(String::as_str),
            );
        }
        for (target, path) in &self.inputs.desktop_sources {
            let record = scan.desktop(path.clone(), "explicit_desktop", None);
            scan.preferred.insert(
                target.clone(),
                record
                    .map(|r| r.source_id)
                    .unwrap_or_else(|| format!("{target}:unavailable:{}", path.display())),
            );
        }
        scan.cli_sources();
        for (target, path) in &self.inputs.observed_cli_entries {
            scan.cli(path.clone(), *target, "observed_entry", false);
        }
        for record in retained {
            let budget_pending = scan
                .issues
                .iter()
                .any(|v| v == "discovery_source_budget_exhausted");
            if (scan
                .batched
                .iter()
                .any(|root| record.entry_path.starts_with(root))
                || budget_pending)
                && !scan.targets.iter().any(|r| r.source_id == record.source_id)
            {
                // Earlier bounded batches remain discovery evidence only while
                // their exact entry, metadata and executable still match.
                for (path, (facts, canonical)) in self.signature.iter().map(|(p, f, c)| (p, (f, c)))
                {
                    if path == &record.entry_path
                        || record.executable.as_ref() == Some(path)
                        || record.child_executables.contains(path)
                        || record
                            .bundle
                            .as_ref()
                            .is_some_and(|b| path == &b.join("Contents/Info.plist"))
                        || (path.file_name().is_some_and(|v| v == "package.json")
                            && record.executable.as_ref().is_some_and(|exe| {
                                path.parent().is_some_and(|p| exe.starts_with(p))
                            }))
                    {
                        scan.watched
                            .entry(path.clone())
                            .or_insert((facts.clone(), canonical.clone()));
                    }
                }
                scan.targets.push(record);
            }
        }
        scan.choose_cli_preferences();
        scan.preferred.extend(self.bound_sources.clone());
        scan.targets.sort_by(|a, b| a.source_id.cmp(&b.source_id));
        scan.targets.dedup_by(|a, b| a.source_id == b.source_id);
        self.next_directory_offsets = scan.next_offsets;
        let signature = scan
            .watched
            .into_iter()
            .map(|(p, (facts, c))| (p, facts, c))
            .collect();
        (
            DiscoverySnapshot {
                revision: String::new(),
                prior_revision: None,
                complete: scan.issues.is_empty(),
                targets: scan.targets,
                issues: scan.issues,
                preferred_sources: scan.preferred,
            },
            signature,
        )
    }
    fn fingerprint(&mut self, path: &Path) -> Result<String> {
        use crate::executable_verification::{fingerprint_file, FileIdentity};
        let text = path
            .to_str()
            .ok_or_else(|| CoreError::new("target_path_encoding", "安装路径编码无效"))?;
        if let Some((identity, sha)) = self.fingerprints.get(path) {
            if FileIdentity::read(text).as_ref() == Some(identity) {
                return Ok(sha.clone());
            }
        }
        self.counters.fingerprint_reads += 1;
        let proof = fingerprint_file(text)
            .ok_or_else(|| CoreError::new("target_fingerprint_failed", "安装文件变化或无法读取"))?;
        let sha = proof.1.clone();
        self.fingerprints.insert(path.into(), proof);
        Ok(sha)
    }
    fn source_is_configured(&self, r: &DiscoveredTarget) -> bool {
        match r.source_kind.as_str() {
            "registered_application" => self
                .registered
                .values()
                .any(|paths| paths.contains(&r.entry_path)),
            "applications_root" => self
                .inputs
                .application_roots
                .iter()
                .any(|root| r.entry_path.parent() == Some(root.as_path())),
            "observed_bundle" => self.inputs.observed_bundles.contains(&r.entry_path),
            "explicit_desktop" => self
                .inputs
                .desktop_sources
                .values()
                .any(|p| p == &r.entry_path),
            "observed_entry" => self
                .inputs
                .observed_cli_entries
                .contains(&(r.target, r.entry_path.clone())),
            "caller_path" => self
                .inputs
                .caller_path
                .iter()
                .chain(self.inputs.caller_paths.values().flatten())
                .any(|root| r.entry_path.parent() == Some(root.as_path())),
            "daemon_path" => self
                .inputs
                .daemon_path
                .iter()
                .any(|root| r.entry_path.parent() == Some(root.as_path())),
            "explicit_path" => self.inputs.overrides.values().any(|p| p == &r.entry_path),
            "homebrew" => self
                .inputs
                .prefixes
                .iter()
                .any(|root| r.entry_path.starts_with(root)),
            "verified_bundle_cli" => self.snapshot.as_ref().is_some_and(|s| {
                s.targets.iter().any(|parent| {
                    !parent.target.cli()
                        && parent.bundle == r.bundle
                        && parent.valid()
                        && self.record_is_current(parent)
                        && self.source_is_configured(parent)
                })
            }),
            _ => true,
        }
    }
}

struct Scan<'a, R: ReadRunner + ?Sized> {
    reader: &'a R,
    inputs: &'a DiscoveryInputs,
    counters: &'a mut DiscoveryCounters,
    watched: BTreeMap<PathBuf, (Vec<i128>, Option<PathBuf>)>,
    targets: Vec<DiscoveredTarget>,
    issues: Vec<String>,
    remaining: usize,
    preferred: BTreeMap<String, String>,
    offsets: &'a BTreeMap<PathBuf, usize>,
    next_offsets: BTreeMap<PathBuf, usize>,
    batched: BTreeSet<PathBuf>,
    directories: &'a mut BTreeMap<PathBuf, DirectoryBatch>,
    cancellation: Option<Arc<AtomicBool>>,
}
impl<R: ReadRunner + ?Sized> Scan<'_, R> {
    fn cancelled(&self) -> bool {
        self.cancellation.as_ref().is_some_and(|stop| stop.load(Ordering::Acquire))
    }
    fn watch(&mut self, path: &Path) {
        self.watched
            .entry(path.into())
            .or_insert_with(|| stamp(path));
    }
    fn entries(&mut self, path: &Path) -> Vec<PathBuf> {
        if self.cancelled() { return vec![]; }
        if path.to_str().is_none() {
            self.issues.push("discovery_path_encoding".into());
            return vec![];
        }
        self.watch(path);
        let observed = self.watched[path].clone();
        let offset = self.offsets.get(path).copied().unwrap_or(0);
        if let Some(batch) = self
            .directories
            .get(path)
            .filter(|batch| !batch.error && batch.stamp == observed && batch.offset == offset)
        {
            if offset > 0 || batch.more {
                self.batched.insert(path.into());
            }
            if batch.more {
                self.issues.push("discovery_budget_exhausted".into());
                self.next_offsets.insert(
                    path.into(),
                    offset + self.inputs.entry_budget.clamp(1, 1024),
                );
            }
            if batch.error {
                self.issues.push("discovery_directory_unreadable".into());
            }
            return batch.paths.clone();
        }
        self.counters.directory_queries += 1;
        let entries = match fs::read_dir(path) {
            Ok(v) => v,
            Err(e) => {
                let error = e.kind() != std::io::ErrorKind::NotFound;
                if error {
                    self.issues.push("discovery_directory_unreadable".into());
                }
                self.directories.insert(
                    path.into(),
                    DirectoryBatch {
                        stamp: observed,
                        offset,
                        paths: vec![],
                        more: false,
                        error,
                    },
                );
                return vec![];
            }
        };
        let mut out = Vec::new();
        let limit = self.inputs.entry_budget.clamp(1, 1024);
        if offset > 4096 {
            self.issues.push("discovery_budget_exhausted".into());
            self.batched.insert(path.into());
            return out;
        }
        if offset > 0 {
            self.batched.insert(path.into());
        }
        let mut consumed = 0;
        let mut failed = false;
        for (index, item) in entries.take(offset + limit + 1).enumerate() {
            if self.cancelled() { break; }
            self.counters.directory_entries += 1;
            if index < offset {
                continue;
            }
            if consumed == limit {
                self.issues.push("discovery_budget_exhausted".into());
                self.batched.insert(path.into());
                self.next_offsets.insert(path.into(), offset + limit);
                break;
            }
            consumed += 1;
            match item {
                Ok(entry) => {
                    if entry.path().to_str().is_some() {
                        out.push(entry.path());
                    } else {
                        failed = true;
                        self.issues.push("discovery_path_encoding".into());
                    }
                }
                Err(_) => {
                    failed = true;
                    self.issues.push("discovery_entry_unreadable".into());
                }
            }
        }
        out.sort();
        self.directories.insert(
            path.into(),
            DirectoryBatch {
                stamp: observed,
                offset,
                paths: out.clone(),
                more: self.next_offsets.contains_key(path),
                error: failed,
            },
        );
        out
    }
    fn record(&self, target: LaunchTarget, path: PathBuf, source: &str) -> DiscoveredTarget {
        DiscoveredTarget {
            target,
            source_kind: source.into(),
            source_id: format!("{}:{source}:{}", target.as_str(), path.to_string_lossy()),
            entry_path: path,
            bundle: None,
            bundle_id: None,
            executable: None,
            script_entry: None,
            interpreter: None,
            launcher_supported: false,
            child_executables: vec![],
            error_code: None,
        }
    }
    fn desktop(
        &mut self,
        path: PathBuf,
        source: &str,
        expected: Option<&str>,
    ) -> Option<DiscoveredTarget> {
        if self.cancelled() { return None; }
        if path.to_str().is_none() {
            self.issues.push("discovery_path_encoding".into());
            return None;
        }
        if self.remaining == 0 {
            self.issues.push("discovery_source_budget_exhausted".into());
            return None;
        }
        self.remaining -= 1;
        self.watch(&path);
        let plist = path.join("Contents/Info.plist");
        self.watch(&plist);
        if !plist.is_file() {
            self.issues.push("bundle_metadata_unavailable".into());
            return self.pending_desktop(path, source, expected);
        }
        self.counters.plist_reads += 1;
        let info = self
            .reader
            .run(
                ReadCommand::Plist(plist),
                &[],
                Duration::from_secs(3),
                128 * 1024,
            )
            .ok()
            .filter(|v| v.status == 0 && v.stderr.is_empty())
            .and_then(|v| crate::storage::strict_json(&v.stdout).ok());
        let Some(info) = info else {
            self.issues.push("bundle_metadata_unreadable".into());
            return self.pending_desktop(path, source, expected);
        };
        let id = info["CFBundleIdentifier"].as_str().unwrap_or("");
        let Some((_, target)) = DESKTOP_IDS.iter().find(|(known, _)| *known == id) else {
            return None;
        };
        let mut record = self.record(*target, path.clone(), source);
        let exe = info["CFBundleExecutable"].as_str().unwrap_or("");
        let resolved = fs::canonicalize(&path).ok();
        let executable = resolved
            .as_ref()
            .map(|bundle| bundle.join("Contents/MacOS").join(exe));
        if let Some(p) = &executable {
            self.watch(p);
        }
        let canonical = executable.as_ref().and_then(|p| fs::canonicalize(p).ok());
        if let Some(p) = &canonical {
            self.watch(p);
        }
        if expected.is_some_and(|v| v != id)
            || exe.is_empty()
            || exe.len() > 256
            || exe.contains(['/', '\\'])
            || matches!(exe, "." | "..")
            || exe.chars().any(char::is_control)
        {
            record.error_code = Some("invalid_bundle_metadata".into());
        } else if !canonical
            .as_ref()
            .zip(resolved.as_ref())
            .is_some_and(|(p, b)| p.starts_with(b.join("Contents/MacOS")) && executable_file(p))
        {
            record.error_code = Some("target_executable_outside_bundle_or_unavailable".into());
        } else {
            record.executable = canonical;
            record.launcher_supported = true;
        }
        record.bundle = resolved;
        record.bundle_id = Some(id.into());
        if record.valid() {
            let bundle = record.bundle.as_ref().unwrap();
            self.watch(&bundle.join("Contents/Info.plist"));
            for helper in self.entries(&bundle.join("Contents/Frameworks")) {
                if self.remaining == 0 {
                    self.issues.push("discovery_source_budget_exhausted".into());
                    break;
                }
                self.remaining -= 1;
                if helper.extension().is_some_and(|v| v == "app") {
                    for file in self.entries(&helper.join("Contents/MacOS")) {
                        if self.remaining == 0 {
                            self.issues.push("discovery_source_budget_exhausted".into());
                            break;
                        }
                        self.remaining -= 1;
                        self.watch(&file);
                        if let Ok(file) = fs::canonicalize(file) {
                            self.watch(&file);
                            if file.starts_with(bundle) && executable_file(&file) {
                                record.child_executables.push(file);
                            }
                        }
                    }
                }
            }
            for relative in BUNDLED_CLI_ENTRIES {
                let file = bundle.join(relative);
                self.watch(&file);
                if let Ok(child) = fs::canonicalize(&file) {
                    self.watch(&child);
                    if child.starts_with(bundle) && executable_file(&child) {
                        record.child_executables.push(child);
                    }
                }
                if id != "com.anthropic.claudefordesktop"
                    && fs::canonicalize(&file).is_ok_and(|p| p.starts_with(bundle))
                {
                    let before = self.targets.len();
                    self.cli(file, LaunchTarget::CodexCli, "verified_bundle_cli", true);
                    if self.targets.len() > before {
                        let cli = self.targets.last_mut().unwrap();
                        cli.bundle = Some(bundle.clone());
                        cli.bundle_id = Some(id.into());
                    }
                }
            }
        }
        self.targets.push(record.clone());
        Some(record)
    }
    fn pending_desktop(
        &mut self,
        path: PathBuf,
        source: &str,
        expected: Option<&str>,
    ) -> Option<DiscoveredTarget> {
        let (id, target) = DESKTOP_IDS.iter().find(|(id, _)| Some(*id) == expected)?;
        let mut record = self.record(*target, path.clone(), source);
        record.bundle = fs::canonicalize(path).ok();
        record.bundle_id = Some((*id).into());
        record.error_code = Some("bundle_metadata_unreadable".into());
        self.targets.push(record.clone());
        Some(record)
    }
    fn cli(&mut self, path: PathBuf, target: LaunchTarget, source: &str, known_alias: bool) {
        if self.cancelled() { return; }
        if path.to_str().is_none() {
            self.issues.push("discovery_path_encoding".into());
            return;
        }
        self.watch(&path);
        let Ok(canonical) = fs::canonicalize(&path) else {
            return;
        };
        if self.remaining == 0 {
            self.issues.push("discovery_source_budget_exhausted".into());
            return;
        }
        self.remaining -= 1;
        self.watch(&canonical);
        let mut record = self.record(target, path.clone(), source);
        let package = package_evidence(&canonical, target, |p| self.watch(p));
        let bundle_cli = self
            .targets
            .iter()
            .find(|r| {
                r.source_kind == "verified_bundle_cli"
                    && r.target == target
                    && r.valid()
                    && r.executable.as_ref() == Some(&canonical)
            })
            .map(|r| (r.bundle.clone(), r.bundle_id.clone()));
        if !executable_file(&canonical)
            && !package
                .as_ref()
                .is_some_and(|(_, script)| *script && canonical.is_file())
        {
            return;
        }
        let native = self.inputs.home.join(".local/share/claude/versions");
        let homebrew = self.inputs.prefixes.iter().any(|p| {
            canonical.starts_with(
                p.join("Caskroom")
                    .join(if target == LaunchTarget::CodexCli {
                        "codex"
                    } else {
                        "claude-code"
                    }),
            ) || canonical.starts_with(p.join("Cellar").join(if target == LaunchTarget::CodexCli {
                "codex"
            } else {
                "claude-code"
            }))
        });
        if !(known_alias
            || bundle_cli.is_some()
            || package.is_some()
            || (target == LaunchTarget::ClaudeCli && canonical.starts_with(native))
            || homebrew)
        {
            record.error_code = Some("cli_source_unverified".into());
        }
        let script = package.as_ref().is_some_and(|(_, script)| *script) || is_script(&canonical);
        record.executable = Some(canonical.clone());
        if let Some((bundle, id)) = bundle_cli {
            record.bundle = bundle;
            record.bundle_id = id;
        }
        record.launcher_supported = !script;
        if script {
            record.interpreter = self
                .inputs
                .observed_interpreters
                .get(&canonical)
                .cloned()
                .or_else(|| {
                    script_interpreter(
                        &canonical,
                        self.inputs
                            .caller_paths
                            .get(target.as_str())
                            .unwrap_or(&self.inputs.caller_path),
                        &self.inputs.daemon_path,
                    )
                });
            if let Some(interpreter) = &record.interpreter {
                self.watch(interpreter);
            }
            record.script_entry = Some(canonical);
        }
        self.targets.push(record);
    }
    fn choose_cli_preferences(&mut self) {
        for (target, key, name) in [
            (LaunchTarget::ClaudeCli, "CLAUDE_CODE_BIN", "claude"),
            (LaunchTarget::CodexCli, "CODEX_CLI_BIN", "codex"),
        ] {
            let entry = self
                .inputs
                .overrides
                .get(key)
                .cloned()
                .or_else(|| {
                    self.inputs
                        .caller_paths
                        .get(target.as_str())
                        .unwrap_or(&self.inputs.caller_path)
                        .iter()
                        .chain(&self.inputs.daemon_path)
                        .map(|p| p.join(name))
                        .find(|p| executable_file(p) && !is_watch_shim(p, &self.inputs.home, None))
                })
                .or_else(|| {
                    process_roots::cli_aliases(&self.inputs.home)
                        .into_iter()
                        .filter(|(_, claude)| *claude == (target == LaunchTarget::ClaudeCli))
                        .map(|(p, _)| p)
                        .find(|p| executable_file(p))
                });
            if let Some(entry) = entry {
                // Preserve even a failed preferred entry. A different valid
                // copy must not silently replace the user's first actual one.
                let id = self
                    .targets
                    .iter()
                    .find(|r| r.target == target && r.entry_path == entry)
                    .map(|r| r.source_id.clone())
                    .unwrap_or_else(|| {
                        format!("{}:unavailable:{}", target.as_str(), entry.display())
                    });
                self.preferred.insert(target.as_str().into(), id);
            }
        }
    }
    fn cli_sources(&mut self) {
        let mut dirs: Vec<(PathBuf, &str)> = self
            .inputs
            .caller_path
            .iter()
            .cloned()
            .map(|p| (p, "caller_path"))
            .chain(
                self.inputs
                    .caller_paths
                    .values()
                    .flatten()
                    .cloned()
                    .map(|p| (p, "caller_path")),
            )
            .chain(
                self.inputs
                    .daemon_path
                    .iter()
                    .cloned()
                    .map(|p| (p, "daemon_path")),
            )
            .collect();
        let watch = Paths {
            home: self.inputs.home.clone(),
        }
        .watch();
        for (entry, claude) in process_roots::cli_aliases(&self.inputs.home) {
            if !isolated_home(&self.inputs.home) || entry.starts_with(&self.inputs.home) {
                self.cli(
                    entry,
                    if claude {
                        LaunchTarget::ClaudeCli
                    } else {
                        LaunchTarget::CodexCli
                    },
                    "supported_alias",
                    true,
                );
            }
        }
        for prefix in &self.inputs.prefixes {
            dirs.push((prefix.join("bin"), "homebrew"));
        }
        // Only known version roots and fixed relative bin/package entries.
        let roots = [
            (self.inputs.home.join(".nvm/versions/node"), "nvm", "bin"),
            (
                self.inputs.home.join(".local/share/fnm/node-versions"),
                "fnm",
                "installation/bin",
            ),
            (
                self.inputs
                    .home
                    .join("Library/Application Support/fnm/node-versions"),
                "fnm",
                "installation/bin",
            ),
            (
                self.inputs.home.join(".volta/tools/image/node"),
                "volta",
                "bin",
            ),
        ];
        for (root, source, relative) in roots {
            for version in self.entries(&root) {
                dirs.push((version.join(relative), source));
            }
        }
        dirs.push((self.inputs.home.join(".volta/bin"), "volta"));
        for (directory, source) in dirs {
            if !directory.is_absolute()
                || directory == watch.join("bin")
                || directory == watch.join("entries/bin")
            {
                continue;
            }
            self.watch(&directory);
            for (name, target) in [
                ("claude", LaunchTarget::ClaudeCli),
                ("codex", LaunchTarget::CodexCli),
            ] {
                let path = directory.join(name);
                if fs::canonicalize(&path).ok().is_some_and(|p| {
                    p.starts_with(watch.join("bin")) || p.starts_with(watch.join("entries/bin"))
                }) {
                    continue;
                }
                self.cli(path, target, source, false);
                let package = directory
                    .parent()
                    .unwrap_or(&directory)
                    .join("lib/node_modules")
                    .join(if target == LaunchTarget::ClaudeCli {
                        "@anthropic-ai/claude-code/cli.js"
                    } else {
                        "@openai/codex/bin/codex.js"
                    });
                self.cli(package, target, "npm", false);
            }
        }
        for version in self.entries(&self.inputs.home.join(".local/share/claude/versions")) {
            self.cli(version, LaunchTarget::ClaudeCli, "claude_native", false);
        }
        for (scope, name, target) in [
            ("@openai/codex", "codex", LaunchTarget::CodexCli),
            (
                "@anthropic-ai/claude-code",
                "claude",
                LaunchTarget::ClaudeCli,
            ),
        ] {
            for version in self.entries(
                &self
                    .inputs
                    .home
                    .join(".volta/tools/image/packages")
                    .join(scope),
            ) {
                self.cli(
                    version.join("bin").join(name),
                    target,
                    "volta_package",
                    false,
                );
                self.cli(
                    version.join("lib/node_modules").join(scope).join(
                        if target == LaunchTarget::ClaudeCli {
                            "cli.js"
                        } else {
                            "bin/codex.js"
                        },
                    ),
                    target,
                    "volta_package",
                    false,
                );
            }
        }
        for (key, target) in [
            ("CLAUDE_CODE_BIN", LaunchTarget::ClaudeCli),
            ("CODEX_CLI_BIN", LaunchTarget::CodexCli),
        ] {
            if let Some(path) = self.inputs.overrides.get(key) {
                self.cli(path.clone(), target, "explicit_path", false);
            }
        }
    }
}
fn executable_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0)
}
fn search_path_entries(value: &std::ffi::OsStr) -> std::io::Result<Vec<PathBuf>> {
    let mut paths = std::env::split_paths(value).take(129).collect::<Vec<_>>();
    if paths.iter().any(|p| !p.is_absolute()) {
        let cwd = std::env::current_dir()?;
        for path in &mut paths {
            if !path.is_absolute() {
                *path = cwd.join(&*path);
            }
        }
    }
    Ok(paths)
}
fn is_script(path: &Path) -> bool {
    let mut bytes = [0; 2];
    fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_ok()
        && bytes == *b"#!"
        || path
            .extension()
            .is_some_and(|v| v == "js" || v == "mjs" || v == "cjs")
}
fn script_interpreter(path: &Path, caller: &[PathBuf], daemon: &[PathBuf]) -> Option<PathBuf> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(512)
        .read_to_end(&mut bytes)
        .ok()?;
    let line = std::str::from_utf8(&bytes)
        .ok()?
        .lines()
        .next()?
        .strip_prefix("#!")?
        .trim();
    let mut words = line.split_whitespace();
    let first = words.next()?;
    let name = if first == "/usr/bin/env" {
        words.next()?
    } else {
        first
    };
    if !["node", "nodejs", "bun"].contains(&Path::new(name).file_name()?.to_str()?) {
        return None;
    }
    let candidate = if Path::new(name).is_absolute() {
        PathBuf::from(name)
    } else {
        caller
            .iter()
            .chain(daemon)
            .map(|p| p.join(name))
            .find(|p| executable_file(p))?
    };
    fs::canonicalize(candidate).ok()
}
fn package_evidence(
    path: &Path,
    target: LaunchTarget,
    mut watch: impl FnMut(&Path),
) -> Option<(PathBuf, bool)> {
    let name = if target == LaunchTarget::ClaudeCli {
        "@anthropic-ai/claude-code"
    } else {
        "@openai/codex"
    };
    for root in path.ancestors().skip(1).take(7) {
        if !root
            .to_string_lossy()
            .ends_with(&format!("/node_modules/{name}"))
        {
            continue;
        }
        let file = root.join("package.json");
        watch(&file);
        let mut bytes = Vec::new();
        fs::File::open(file)
            .ok()?
            .take(128 * 1024 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() > 128 * 1024 {
            return None;
        }
        let value = crate::storage::strict_json(&bytes).ok()?;
        if value["name"] != name {
            return None;
        }
        let script = if target == LaunchTarget::ClaudeCli {
            path == root.join("cli.js")
        } else {
            path == root.join("bin/codex.js")
        };
        if script
            || (target == LaunchTarget::CodexCli
                && path.file_name().is_some_and(|v| v == "codex")
                && path.starts_with(root.join("vendor")))
        {
            return Some((root.into(), script));
        }
    }
    None
}

fn is_watch_shim(path: &Path, home: &Path, shim: Option<&Path>) -> bool {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.into());
    let root = Paths { home: home.into() }.watch();
    canonical.starts_with(root.join("bin"))
        || canonical.starts_with(root.join("entries/bin"))
        || shim
            .and_then(|p| fs::canonicalize(p).ok())
            .is_some_and(|p| p == canonical)
}

/// In-process shared cache, scoped to an explicit home. It carries no permits.
#[derive(Clone)]
pub struct DiscoveryHandle(pub Arc<Mutex<DiscoveryCache>>, Arc<dyn ApplicationRegistry>);

pub struct ApprovedDiscoveryManifest {
    pub revision: String,
    pub desktop_specs: Vec<crate::managed_entry::DesktopManagedEntrySpec>,
    pub targets: BTreeMap<String, String>,
    pub children: BTreeMap<String, String>,
    pub cli_sources: Vec<crate::sandbox_launch::ApprovedCliSource>,
    pub selection_issues: Vec<String>,
    pub needs_verification_retry: bool,
}
impl DiscoveryHandle {
    pub fn new(inputs: DiscoveryInputs) -> Self {
        Self::with_registry(inputs, Arc::new(SystemApplicationRegistry))
    }
    pub fn with_registry(inputs: DiscoveryInputs, registry: Arc<dyn ApplicationRegistry>) -> Self {
        Self(Arc::new(Mutex::new(DiscoveryCache::new(inputs))), registry)
    }
    pub fn for_home(home: &Path) -> Self {
        static CACHES: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Mutex<DiscoveryCache>>>>> =
            OnceLock::new();
        let resolved = fs::canonicalize(home).unwrap_or_else(|_| home.into());
        let home = resolved.as_path();
        let mut caches = CACHES
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap();
        caches.retain(|_, weak| weak.strong_count() > 0);
        if let Some(cache) = caches.get(home).and_then(Weak::upgrade) {
            return Self(cache, Arc::new(SystemApplicationRegistry));
        }
        let cache = Arc::new(Mutex::new(DiscoveryCache::new(DiscoveryInputs::for_home(
            home,
        ))));
        caches.insert(home.into(), Arc::downgrade(&cache));
        Self(cache, Arc::new(SystemApplicationRegistry))
    }
    pub fn refresh<R: ReadRunner + ?Sized>(&self, reader: &R, now: f64) -> Arc<DiscoverySnapshot> {
        self.0.lock().unwrap().refresh(reader, self.1.as_ref(), now)
    }
    /// The daemon's stop flag bounds cold discovery between system reads.
    /// Cancellation publishes no successful revision and grants no authority.
    pub fn cancel_pending_when(&self, stop: Arc<AtomicBool>) {
        self.0.lock().unwrap().cancellation = Some(stop);
    }
    pub fn managed_spec(
        &self,
        snapshot: &DiscoverySnapshot,
        record: &DiscoveredTarget,
        target: LaunchTarget,
    ) -> Result<crate::managed_entry::DesktopManagedEntrySpec> {
        let mut cache = self.0.lock().unwrap();
        ensure_current(&cache, snapshot, record)?;
        make_spec(&mut cache, record, target)
    }
    pub fn select_desktop<R: ReadRunner + ?Sized>(
        &self,
        reader: &R,
        target: LaunchTarget,
        now: f64,
    ) -> Result<(Arc<DiscoverySnapshot>, DiscoveredTarget)> {
        let snapshot = self.refresh(reader, now);
        let record = snapshot.select(target, None)?.clone();
        self.bind_source(target, &record.source_id);
        let snapshot = self.refresh(reader, now);
        let record = snapshot.select(target, Some(&record.source_id))?.clone();
        Ok((snapshot, record))
    }
    fn bind_source(&self, target: LaunchTarget, source: &str) {
        let mut cache = self.0.lock().unwrap();
        if cache.snapshot.as_ref().is_some_and(|s| {
            s.preferred_sources
                .get(target.as_str())
                .is_none_or(|v| v != source)
        }) {
            cache.dirty = true;
        }
        cache
            .bound_sources
            .insert(target.as_str().into(), source.into());
    }
    pub fn choose_source(&self, target: LaunchTarget, source: &str) {
        self.bind_source(target, source);
    }
    pub fn select_cli<R: ReadRunner + ?Sized>(
        &self,
        reader: &R,
        target: LaunchTarget,
        env: &BTreeMap<String, String>,
        now: f64,
    ) -> Result<(Arc<DiscoverySnapshot>, DiscoveredTarget)> {
        if !target.cli() {
            return Err(CoreError::new("invalid_target", "目标不是 CLI"));
        }
        self.refresh(reader, now); // Load candidate hints before this caller's authoritative PATH choice.
        let caller_paths = self.caller_environment(target, env)?;
        let snapshot = self.refresh(reader, now);
        let (name, key) = if target == LaunchTarget::ClaudeCli {
            ("claude", "CLAUDE_CODE_BIN")
        } else {
            ("codex", "CODEX_CLI_BIN")
        };
        let home = self.0.lock().unwrap().inputs.home.clone();
        let shim = env.get("CW_SHIM_EXECUTABLE").map(Path::new);
        let selected_entry = if let Some(value) = env.get(key).filter(|v| !v.is_empty()) {
            let path = PathBuf::from(value);
            if !path.is_absolute() || !executable_file(&path) || is_watch_shim(&path, &home, shim) {
                return Err(CoreError::new(
                    "cli_source_unverified",
                    "显式 CLI 来源无效，未回退其他安装",
                ));
            }
            Some(path)
        } else {
            env.get("PATH").and_then(|_| {
                caller_paths
                    .iter()
                    .take(128)
                    .map(|p| p.join(name))
                    .find(|p| {
                        p.is_absolute() && executable_file(p) && !is_watch_shim(p, &home, shim)
                    })
            })
        };
        if selected_entry.is_none() && caller_paths.len() > 128 {
            return Err(CoreError::new(
                "discovery_pending",
                "调用方 PATH 超过预算，未确认实际首个入口",
            ));
        }
        let record = if let Some(entry) = selected_entry {
            snapshot
                .targets
                .iter()
                .find(|r| r.target == target && r.entry_path == entry && r.valid())
                .cloned()
                .ok_or_else(|| {
                    CoreError::new(
                        "cli_source_unverified",
                        "首个实际 CLI 入口未经来源验证，未跳过它启动其他副本",
                    )
                })?
        } else {
            snapshot.select(target, None)?.clone()
        };
        if !record.launcher_supported {
            return Err(CoreError::new(
                "unsupported_launcher",
                "已发现官方脚本或版本管理器入口，当前沙箱启动器不支持此形式",
            ));
        }
        self.bind_source(target, &record.source_id);
        let snapshot = self.refresh(reader, now);
        let record = snapshot.select(target, Some(&record.source_id))?.clone();
        if !record.launcher_supported {
            return Err(CoreError::new(
                "unsupported_launcher",
                "来源变化后为不支持的脚本启动形式",
            ));
        }
        Ok((snapshot, record))
    }
    /// Materialize only selected current installs. Discovered historical
    /// versions never become general approvals merely by appearing in a scan.
    pub fn approved_manifest(
        &self,
        snapshot: &DiscoverySnapshot,
    ) -> Result<ApprovedDiscoveryManifest> {
        let mut cache = self.0.lock().unwrap();
        // A stale whole revision is not a set of individual installation
        // failures: leave the current approvals alone and retry discovery.
        ensure_snapshot_current(&cache, snapshot)?;
        let mut manifest = ApprovedDiscoveryManifest {
            revision: snapshot.revision.clone(),
            desktop_specs: vec![],
            targets: BTreeMap::new(),
            children: BTreeMap::new(),
            cli_sources: vec![],
            selection_issues: vec![],
            needs_verification_retry: false,
        };
        for target in [
            LaunchTarget::ClaudeDesktop,
            LaunchTarget::CodexDesktop,
            LaunchTarget::ChatgptDesktop,
            LaunchTarget::ClaudeCli,
            LaunchTarget::CodexCli,
        ] {
            let record = match snapshot.select(target, None) {
                Ok(r) => r,
                Err(error) => {
                    manifest
                        .selection_issues
                        .push(format!("{}:{}", target.as_str(), error.code));
                    continue;
                }
            };
            if !record.launcher_supported {
                manifest
                    .selection_issues
                    .push(format!("{}:unsupported_launcher", target.as_str()));
                continue;
            }
            // Verify into target-local values first. A bad helper must not
            // leave its main executable approved or abort other families.
            let prepared = (|| {
                ensure_current(&cache, snapshot, record)?;
                let path = record.executable.as_ref().unwrap();
                let sha = cache.fingerprint(path)?;
                let spec = if target.cli() { None } else {
                    Some(make_spec(&mut cache, record, target)?)
                };
                let mut children = BTreeMap::new();
                for child in &record.child_executables {
                    children.insert(child.to_string_lossy().into_owned(), cache.fingerprint(child)?);
                }
                ensure_current(&cache, snapshot, record)?;
                Ok::<_, CoreError>((path.to_string_lossy().into_owned(), sha, spec, children))
            })();
            let (text, sha, spec, children) = match prepared {
                Ok(values) => values,
                Err(error) => {
                    manifest.selection_issues.push(format!("{}:{}", target.as_str(), error.code));
                    manifest.needs_verification_retry = true;
                    continue;
                }
            };
            manifest.targets.insert(text.clone(), sha.clone());
            manifest.children.insert(text.clone(), sha.clone());
            if target.cli() {
                manifest
                    .cli_sources
                    .push(crate::sandbox_launch::ApprovedCliSource {
                        entry_path: record.entry_path.to_string_lossy().into_owned(),
                        target,
                        executable: text,
                        fingerprint: sha,
                    });
            } else if let Some(spec) = spec {
                manifest.desktop_specs.push(spec);
                manifest.children.extend(children);
            }
            cache
                .bound_sources
                .insert(target.as_str().into(), record.source_id.clone());
        }
        cache.fingerprints.retain(|path, _| {
            manifest
                .targets
                .contains_key(path.to_string_lossy().as_ref())
                || manifest
                    .children
                    .contains_key(path.to_string_lossy().as_ref())
        });
        Ok(manifest)
    }
    pub fn observe_bundles(&self, bundles: impl IntoIterator<Item = PathBuf>) {
        let mut cache = self.0.lock().unwrap();
        let bundles = bundles.into_iter().take(257).collect::<Vec<_>>();
        if bundles.len() > 256 {
            cache.input_issue("observed_bundles_partial", true);
        }
        for bundle in bundles.into_iter().take(256) {
            if !cache.inputs.observed_bundles.contains(&bundle)
                && cache.inputs.observed_bundles.len() == 256
            {
                cache.input_issue("observed_bundles_partial", true);
            }
            if !cache.inputs.observed_bundles.contains(&bundle)
                && cache.inputs.observed_bundles.len() < 256
            {
                cache.inputs.observed_bundles.push(bundle);
                cache.dirty = true;
            }
        }
    }
    pub fn observed_process_bundles(
        &self,
        bundles: impl IntoIterator<Item = (PathBuf, Option<String>)>,
    ) {
        let mut paths = BTreeSet::new();
        let mut ids = BTreeMap::new();
        let bundles = bundles.into_iter().take(257).collect::<Vec<_>>();
        let partial = bundles.len() > 256;
        for (path, id) in bundles.into_iter().take(256) {
            if let Some(id) = id.filter(|id| DESKTOP_IDS.iter().any(|(known, _)| *known == id)) {
                ids.insert(path.clone(), id);
            }
            paths.insert(path);
        }
        let paths = paths.into_iter().collect::<Vec<_>>();
        let mut cache = self.0.lock().unwrap();
        cache.input_issue("observed_bundles_partial", partial);
        if cache.inputs.observed_bundles != paths || cache.inputs.observed_bundle_ids != ids {
            cache.inputs.observed_bundles = paths;
            cache.inputs.observed_bundle_ids = ids;
            cache.dirty = true;
        }
    }
    pub fn observe_cli_entries(&self, entries: impl IntoIterator<Item = (LaunchTarget, PathBuf)>) {
        let mut cache = self.0.lock().unwrap();
        let entries = entries.into_iter().take(257).collect::<Vec<_>>();
        if entries.len() > 256 {
            cache.input_issue("observed_cli_entries_partial", true);
        }
        for entry in entries.into_iter().take(256) {
            if !cache.inputs.observed_cli_entries.contains(&entry)
                && cache.inputs.observed_cli_entries.len() == 256
            {
                cache.input_issue("observed_cli_entries_partial", true);
            }
            if !cache.inputs.observed_cli_entries.contains(&entry)
                && cache.inputs.observed_cli_entries.len() < 256
            {
                cache.inputs.observed_cli_entries.push(entry);
                cache.dirty = true;
            }
        }
    }
    pub fn observe_interpreters(&self, entries: impl IntoIterator<Item = (PathBuf, PathBuf)>) {
        let mut cache = self.0.lock().unwrap();
        let entries = entries.into_iter().take(257).collect::<Vec<_>>();
        if entries.len() > 256 {
            cache.input_issue("observed_interpreters_partial", true);
        }
        for (script, interpreter) in entries.into_iter().take(256) {
            let (Ok(script), Ok(interpreter)) =
                (fs::canonicalize(script), fs::canonicalize(interpreter))
            else {
                continue;
            };
            if !cache.inputs.observed_interpreters.contains_key(&script)
                && cache.inputs.observed_interpreters.len() == 256
            {
                cache.input_issue("observed_interpreters_partial", true);
            }
            if cache.inputs.observed_interpreters.get(&script) != Some(&interpreter)
                && (cache.inputs.observed_interpreters.contains_key(&script)
                    || cache.inputs.observed_interpreters.len() < 256)
            {
                cache
                    .inputs
                    .observed_interpreters
                    .insert(script, interpreter);
                cache.dirty = true;
            }
        }
    }
    pub fn desktop_source(&self, target: LaunchTarget, path: &Path) {
        let mut cache = self.0.lock().unwrap();
        if cache
            .inputs
            .desktop_sources
            .get(target.as_str())
            .map(PathBuf::as_path)
            != Some(path)
        {
            cache
                .inputs
                .desktop_sources
                .insert(target.as_str().into(), path.into());
            cache.bound_sources.remove(target.as_str());
            cache.dirty = true;
        }
    }
    pub fn caller_environment(
        &self,
        target: LaunchTarget,
        env: &BTreeMap<String, String>,
    ) -> Result<Vec<PathBuf>> {
        let mut cache = self.0.lock().unwrap();
        let mut paths = env
            .get("PATH")
            .map(|v| search_path_entries(std::ffi::OsStr::new(v)))
            .transpose()
            .map_err(|_| {
                CoreError::new(
                    "cli_environment_invalid",
                    "无法确认调用方相对 PATH，未选择其他副本",
                )
            })?
            .unwrap_or_default();
        let caller_paths = paths.clone();
        cache.input_issue(
            &format!("{}:caller_path_partial", target.as_str()),
            paths.len() > 128,
        );
        paths.truncate(128);
        if cache.inputs.caller_paths.get(target.as_str()) != Some(&paths) {
            cache
                .inputs
                .caller_paths
                .insert(target.as_str().into(), paths);
            cache.dirty = true;
        }
        let before = cache.inputs.overrides.clone();
        for key in [if target == LaunchTarget::ClaudeCli {
            "CLAUDE_CODE_BIN"
        } else {
            "CODEX_CLI_BIN"
        }] {
            cache.inputs.overrides.remove(key);
            if let Some(base) = cache.base_overrides.get(key).cloned() {
                cache.inputs.overrides.insert(key.into(), base);
            }
            if let Some(value) = env.get(key).filter(|v| !v.is_empty()) {
                let path = PathBuf::from(value);
                if cache.inputs.overrides.get(key) != Some(&path) {
                    cache.inputs.overrides.insert(key.into(), path);
                    cache.dirty = true;
                }
            }
        }
        if before != cache.inputs.overrides {
            cache.dirty = true;
        }
        Ok(caller_paths)
    }
    pub fn publish_caller_hint(&self, target: LaunchTarget) -> Result<()> {
        // Copy only this request's scope, then release the in-process mutex
        // before waiting for another process's short file transaction.
        let (home, paths, bundle, override_path) = {
            let cache = self.0.lock().unwrap();
            let key = if target == LaunchTarget::ClaudeCli { "CLAUDE_CODE_BIN" } else { "CODEX_CLI_BIN" };
            (cache.inputs.home.clone(), cache.inputs.caller_paths.get(target.as_str()).cloned(),
                cache.inputs.desktop_sources.get(target.as_str()).cloned(), cache.inputs.overrides.get(key).cloned())
        };
        let store = StateStore::new(Paths { home });
        let path = store.paths.watch().join("state/target-discovery-hints.json");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let _transaction = loop {
            match store.lock("target-discovery-hints", None) {
                Ok(lock) => break lock,
                Err(error) if error.code == "busy" && std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        };
        // Atomic rename alone does not protect read-modify-write. Re-read
        // under the cross-process lock and merge only the requested target.
        let mut hints = match store.read_bytes(&path, 128 * 1024)? {
            Some(bytes) => crate::storage::strict_json(&bytes)?,
            None => json!({"caller_path":[],"caller_paths":{},"desktop_sources":{},"overrides":{}}),
        };
        if target.cli() {
            let scoped = hint_object(&mut hints, "caller_paths")?;
            if let Some(paths) = paths { scoped.insert(target.as_str().into(), json!(paths)); }
            else { scoped.remove(target.as_str()); }
            let overrides = hint_object(&mut hints, "overrides")?;
            let key = if target == LaunchTarget::ClaudeCli { "CLAUDE_CODE_BIN" } else { "CODEX_CLI_BIN" };
            if let Some(value) = override_path { overrides.insert(key.into(), json!(value)); }
            else { overrides.remove(key); }
        } else {
            let scoped = hint_object(&mut hints, "desktop_sources")?;
            if let Some(bundle) = bundle { scoped.insert(target.as_str().into(), json!(bundle)); }
            else { scoped.remove(target.as_str()); }
        }
        store.atomic_json(&path, &hints)
    }
}

fn hint_object<'a>(hints: &'a mut serde_json::Value, key: &str) -> Result<&'a mut serde_json::Map<String, serde_json::Value>> {
    hints.as_object_mut().and_then(|object| {
        object.entry(key).or_insert_with(|| json!({})).as_object_mut()
    }).ok_or_else(|| CoreError::new("discovery_hint_invalid", "来源提示结构损坏，未覆盖其他目标的记录"))
}

fn ensure_snapshot_current(cache: &DiscoveryCache, snapshot: &DiscoverySnapshot) -> Result<()> {
    if cache.snapshot.as_ref().is_none_or(|s| {
        s.revision != snapshot.revision && snapshot.prior_revision.as_ref() != Some(&s.revision)
    }) {
        return Err(CoreError::new("discovery_snapshot_changed", "发现修订已变化，等待重新构造批准清单"));
    }
    Ok(())
}

fn ensure_current(
    cache: &DiscoveryCache,
    snapshot: &DiscoverySnapshot,
    record: &DiscoveredTarget,
) -> Result<()> {
    ensure_snapshot_current(cache, snapshot)?;
    if !record.valid() || !cache.record_is_current(record) {
        return Err(CoreError::new(
            "discovery_snapshot_changed",
            "发现来源已变化，等待新修订，未批准或启动",
        ));
    }
    Ok(())
}
fn make_spec(
    cache: &mut DiscoveryCache,
    record: &DiscoveredTarget,
    target: LaunchTarget,
) -> Result<crate::managed_entry::DesktopManagedEntrySpec> {
    use crate::managed_entry::DesktopManagedEntrySpec as Spec;
    use claude_watch_core::controlled_launch::ProxyAdaptationKind;
    let executable = record
        .executable
        .as_ref()
        .ok_or_else(|| CoreError::new("target_executable_missing", "安装文件缺失"))?;
    Ok(Spec {
        entry_bundle_id: Spec::entry_bundle_id_for(target).into(),
        target,
        target_bundle_path: record
            .bundle
            .clone()
            .ok_or_else(|| CoreError::new("target_bundle_missing", "应用包缺失"))?,
        target_bundle_id: record.bundle_id.clone().unwrap_or_default(),
        target_executable: executable.clone(),
        target_fingerprint: cache.fingerprint(executable)?,
        proxy_adaptation: if matches!(
            target,
            LaunchTarget::ClaudeDesktop | LaunchTarget::CodexDesktop
        ) {
            ProxyAdaptationKind::EnvAndElectronSwitches
        } else {
            ProxyAdaptationKind::EnvOnly
        },
    })
}
