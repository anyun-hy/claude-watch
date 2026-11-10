#[path = "support/fixture_inventory.rs"]
mod fixture_inventory;
use claude_watch_core::{
    error::Result,
    processes::{Identity, LaunchTarget},
};
use claude_watch_runtime::{
    commands::{Output, ReadCommand, ReadRunner, SystemRunner},
    desktop_native::NativeDesktop,
    macos::Authority,
    native,
    sampler::Sampler,
    storage::{Paths, StateStore},
    target_discovery::*,
};
use claude_watch_system::application_locations::ApplicationLocations;
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

#[derive(Default)]
struct Registry {
    urls: Mutex<BTreeMap<String, Vec<PathBuf>>>,
    calls: AtomicUsize,
}

#[test]
fn shutdown_cancels_cold_discovery_between_reads_without_accepting_partial_success() {
    let fixture = Fixture::new();
    for index in 0..24 {
        let id = if index == 0 { "com.anthropic.claudefordesktop" } else { "example.ordinary" };
        fixture.app(&fixture.home.join(format!("Applications/Private {index:02}.app")), id, "PrivateMain");
    }
    struct StopAfterRead<'a> { inner: &'a SystemRunner, stop: Arc<AtomicBool>, reads: AtomicUsize }
    impl ReadRunner for StopAfterRead<'_> {
        fn run(&self, command: ReadCommand, input: &[u8], timeout: Duration, limit: usize) -> Result<Output> {
            let plist = matches!(&command, ReadCommand::Plist(_));
            let output = self.inner.run(command, input, timeout, limit);
            if plist {
                self.reads.fetch_add(1, Ordering::SeqCst);
                self.stop.store(true, Ordering::Release);
            }
            output
        }
    }
    let stop = Arc::new(AtomicBool::new(false));
    let handle = fixture.handle();
    handle.cancel_pending_when(stop.clone());
    let reader = StopAfterRead { inner: &fixture.reader, stop: stop.clone(), reads: AtomicUsize::new(0) };
    let pending = handle.refresh(&reader, native::now());
    assert_eq!(reader.reads.load(Ordering::SeqCst), 1, "must not finish all remaining app reads after shutdown");
    assert!(!pending.complete);
    assert_eq!(pending.issues, ["target_discovery_cancelled"]);
    assert!(handle.approved_manifest(&pending).is_err(), "an interrupted scan is not accepted authority");
    stop.store(false, Ordering::Release);
    let recovered = handle.refresh(&fixture.reader, native::now());
    assert!(recovered.complete, "cancellation must not cache incomplete discovery as success");
    assert_eq!(recovered.targets.iter().filter(|record| record.valid()).count(), 1);
}
impl ApplicationRegistry for Registry {
    fn locations(&self, id: &str) -> Result<ApplicationLocations> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ApplicationLocations {
            paths: self
                .urls
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .unwrap_or_default(),
            complete: true,
        })
    }
}
struct Fixture {
    root: PathBuf,
    home: PathBuf,
    reader: SystemRunner,
    registry: Arc<Registry>,
}
impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from("/private/tmp").join(format!("cw-m5-{}", uuid::Uuid::new_v4()));
        let home = root.join("home");
        fs::create_dir_all(home.join("Applications")).unwrap();
        Self {
            root,
            home,
            reader: SystemRunner::new(native::built_observer_path().unwrap()).unwrap(),
            registry: Arc::new(Registry::default()),
        }
    }
    fn inputs(&self) -> DiscoveryInputs {
        let mut i = DiscoveryInputs::for_home(&self.home);
        i.query_registry = true;
        i
    }
    fn handle(&self) -> DiscoveryHandle {
        DiscoveryHandle::with_registry(self.inputs(), self.registry.clone())
    }
    fn app(&self, path: &Path, id: &str, exe: &str) -> PathBuf {
        fs::create_dir_all(path.join("Contents/MacOS")).unwrap();
        fs::write(path.join("Contents/Info.plist"),format!(r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>{id}</string><key>CFBundleExecutable</key><string>{exe}</string></dict></plist>"#)).unwrap();
        let executable = path.join("Contents/MacOS").join(exe);
        Self::image(&executable);
        executable
    }
    fn image(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            b"\xcf\xfa\xed\xfe private discovery fixture; never executed",
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fn helper(&self) -> PathBuf {
        let p = self.root.join("watch-process-control");
        Self::image(&p);
        p
    }
    fn package(&self, prefix: &Path, target: LaunchTarget, script: bool) -> PathBuf {
        let name = if target == LaunchTarget::ClaudeCli {
            "@anthropic-ai/claude-code"
        } else {
            "@openai/codex"
        };
        let package = prefix.join("lib/node_modules").join(name);
        fs::create_dir_all(&package).unwrap();
        fs::write(
            package.join("package.json"),
            json!({"name":name}).to_string(),
        )
        .unwrap();
        let executable = package.join(if script {
            if target == LaunchTarget::ClaudeCli {
                "cli.js"
            } else {
                "bin/codex.js"
            }
        } else {
            "vendor/aarch64-apple-darwin/codex/codex"
        });
        Self::image(&executable);
        if script {
            fs::write(
                &executable,
                b"#!/usr/bin/env node\n// private package fixture\n",
            )
            .unwrap();
        }
        fs::create_dir_all(prefix.join("bin")).unwrap();
        symlink(
            &executable,
            prefix
                .join("bin")
                .join(if target == LaunchTarget::ClaudeCli {
                    "claude"
                } else {
                    "codex"
                }),
        )
        .unwrap();
        executable
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn renamed_registered_desktops_share_native_selection_and_sampler_revision() {
    use fixture_inventory::{FixtureInventory, FixtureProcess};
    let f = Fixture::new();
    let handle = f.handle();
    let mut records = Vec::new();
    let mut expected = Vec::new();
    for (index, (id, target)) in DESKTOP_IDS.into_iter().enumerate() {
        let bundle = if index == 1 {
            f.home.join("Applications/Renamed Editor.app")
        } else {
            f.root.join(format!("custom-{index}/A Different Name.app"))
        };
        let executable = f.app(&bundle, id, &format!("UnusualExecutable{index}"));
        f.registry
            .urls
            .lock()
            .unwrap()
            .insert(id.into(), vec![bundle.clone()]);
        records.push(FixtureProcess {
            identity: Identity {
                pid: 4100 + index as u32,
                parent: 1,
                uid: 501,
                executable: executable.to_string_lossy().into_owned(),
                start_seconds: 100,
                start_microseconds: 1,
                start_stamp: "private-m5".into(),
            },
            bundle: Some((bundle.to_string_lossy().into_owned(), id.into())),
            arguments: vec!["PRIVATE_DO_NOT_EMIT".into()],
        });
        expected.push((target, executable));
    }
    let mut desktop = NativeDesktop::new(&f.reader, f.helper(), Authority::ReadOnly).unwrap();
    desktop.set_discovery(handle.clone());
    for (target, executable) in &expected {
        desktop.select_target(*target).unwrap();
        let spec = desktop.build_managed_entry_spec().unwrap();
        assert_eq!(&spec.target_executable, executable);
        assert_eq!(spec.target, *target);
    }
    let inventory = FixtureInventory(Arc::new(Mutex::new(records)));
    let mut sampler = Sampler::new(inventory, Paths::new(&f.home).unwrap());
    sampler.set_discovery(handle.clone());
    let round = sampler.processes().unwrap();
    assert_eq!(round.targets.len(), 3);
    let snapshot = handle.refresh(&f.reader, native::now());
    assert_eq!(
        round.discovery.as_ref().unwrap()["revision"],
        snapshot.revision
    );
    assert_eq!(f.registry.calls.load(Ordering::SeqCst), 3);
    let manifest = handle.approved_manifest(&snapshot).unwrap();
    assert_eq!(manifest.desktop_specs.len(), 3);
    let reads = handle.0.lock().unwrap().counters.fingerprint_reads;
    assert_eq!(reads, 3);
    handle.approved_manifest(&snapshot).unwrap();
    assert_eq!(handle.0.lock().unwrap().counters.fingerprint_reads, reads);
    let store = StateStore::new(Paths::new(&f.home).unwrap());
    let producer = Identity {
        pid: 4000,
        parent: 1,
        uid: 501,
        executable: "/fixture/watch-engine".into(),
        start_seconds: 100,
        start_microseconds: 1,
        start_stamp: "fixture".into(),
    };
    let monitor = claude_watch_runtime::monitor_snapshot::assemble(
        &store,
        &round,
        &json!({}),
        &producer,
        "fixture",
        false,
        native::now(),
    );
    assert!(monitor["processes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["matchReason"] == "verified_bundle" && r["protection"]["state"] != "protected"));
    assert!(!monitor.to_string().contains("PRIVATE_DO_NOT_EMIT"));
    if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            Path::new(&dir).join("target-discovery-wire.json"),
            serde_json::to_vec_pretty(&json!({"discovery":snapshot.as_ref(),"monitor":monitor}))
                .unwrap(),
        )
        .unwrap();
    }
    println!("M5: all three renamed/custom desktop IDs share selection, process classification and accepted revision; stable fingerprints {reads}->{reads}");
}

#[test]
fn desktop_negative_metadata_and_ambiguous_copies_never_select_by_name() {
    let f = Fixture::new();
    let handle = f.handle();
    let a = f.home.join("Applications/Claude.app");
    f.app(&a, "com.other.ordinary", "Claude");
    let b = f.home.join("Applications/One.app");
    f.app(&b, "com.openai.codex", "Different");
    let c = f.home.join("Applications/Two.app");
    f.app(&c, "com.openai.codex", "Other");
    let escape = f.home.join("Applications/Escape.app");
    let exe = f.app(&escape, "com.openai.chat", "Escaped");
    let outside = f.root.join("outside");
    Fixture::image(&outside);
    fs::remove_file(&exe).unwrap();
    symlink(&outside, &exe).unwrap();
    let snapshot = handle.refresh(&f.reader, native::now());
    assert_eq!(
        snapshot
            .select(LaunchTarget::CodexDesktop, None)
            .unwrap_err()
            .code,
        "ambiguous_source"
    );
    assert!(!snapshot
        .targets
        .iter()
        .any(|r| r.target == LaunchTarget::ClaudeDesktop));
    assert!(snapshot
        .targets
        .iter()
        .filter(|r| r.target == LaunchTarget::ChatgptDesktop)
        .all(|r| !r.valid()));
    let mut desktop = NativeDesktop::new(&f.reader, f.helper(), Authority::ReadOnly).unwrap();
    desktop.set_discovery(handle.clone());
    desktop
        .select_target_source(LaunchTarget::CodexDesktop, &b)
        .unwrap();
    fs::remove_dir_all(&b).unwrap();
    assert_eq!(
        desktop
            .select_target(LaunchTarget::CodexDesktop)
            .unwrap_err()
            .code,
        "selected_source_unavailable"
    );
    let snapshot = handle.refresh(&f.reader, native::now());
    let manifest = handle.approved_manifest(&snapshot).unwrap();
    assert!(
        manifest.targets.is_empty(),
        "must not silently approve Two.app after selected One.app disappears"
    );
    fs::write(c.join("Contents/Info.plist"), b"corrupt").unwrap();
    let snapshot = handle.refresh(&f.reader, native::now());
    assert!(!snapshot.complete);
    assert!(snapshot
        .issues
        .contains(&"bundle_metadata_unreadable".into()));
}

#[test]
fn cli_sources_cover_version_managers_and_keep_script_launchers_explicit() {
    let f = Fixture::new();
    let mut inputs = f.inputs();
    let hb = f.home.join("homebrew-arm");
    inputs.prefixes = vec![hb.clone(), f.home.join("homebrew-intel")];
    let brew_image = hb.join("Caskroom/codex/1/bin/codex");
    Fixture::image(&brew_image);
    fs::create_dir_all(hb.join("bin")).unwrap();
    symlink(&brew_image, hb.join("bin/codex")).unwrap();
    let intel = f.home.join("homebrew-intel");
    let intel_codex = intel.join("Caskroom/codex/2/bin/codex");
    let intel_claude = intel.join("Caskroom/claude-code/1/claude");
    Fixture::image(&intel_codex);
    Fixture::image(&intel_claude);
    fs::create_dir_all(intel.join("bin")).unwrap();
    symlink(&intel_codex, intel.join("bin/codex")).unwrap();
    symlink(&intel_claude, intel.join("bin/claude")).unwrap();
    let prefixes = [
        f.home.join("npm"),
        f.home.join(".nvm/versions/node/v22"),
        f.home
            .join(".local/share/fnm/node-versions/v23/installation"),
        f.home.join(".volta/tools/image/packages/@openai/codex/1"),
    ];
    let mut native_paths = vec![brew_image, intel_codex];
    for prefix in &prefixes {
        native_paths.push(f.package(prefix, LaunchTarget::CodexCli, false));
        f.package(prefix, LaunchTarget::ClaudeCli, true);
    }
    inputs.daemon_path = vec![prefixes[0].join("bin")];
    let handle = DiscoveryHandle::with_registry(inputs, f.registry.clone());
    let snapshot = handle.refresh(&f.reader, native::now());
    assert!(snapshot
        .targets
        .iter()
        .any(|r| r.target == LaunchTarget::ClaudeCli
            && r.valid()
            && r.executable.as_ref() == Some(&intel_claude)));
    for path in &native_paths {
        assert!(
            snapshot
                .targets
                .iter()
                .any(|r| r.valid() && r.executable.as_ref() == Some(path)),
            "{}",
            path.display()
        );
    }
    assert!(snapshot
        .targets
        .iter()
        .any(|r| r.valid() && r.source_kind == "nvm"));
    assert!(snapshot
        .targets
        .iter()
        .any(|r| r.valid() && r.source_kind == "fnm"));
    assert!(snapshot
        .targets
        .iter()
        .any(|r| r.valid() && r.source_kind == "volta_package"));
    let env = BTreeMap::from([(
        "PATH".into(),
        prefixes[1].join("bin").to_string_lossy().into_owned(),
    )]);
    let (_, record) = handle
        .select_cli(&f.reader, LaunchTarget::CodexCli, &env, native::now())
        .unwrap();
    assert_eq!(record.executable.as_ref(), Some(&native_paths[3]));
    assert_eq!(
        handle
            .select_cli(&f.reader, LaunchTarget::ClaudeCli, &env, native::now())
            .unwrap_err()
            .code,
        "unsupported_launcher"
    );
    let env = BTreeMap::from([(
        "PATH".into(),
        intel.join("bin").to_string_lossy().into_owned(),
    )]);
    assert_eq!(
        handle
            .select_cli(&f.reader, LaunchTarget::ClaudeCli, &env, native::now())
            .unwrap()
            .1
            .executable
            .as_ref(),
        Some(&intel_claude)
    );
    println!("M5 CLI sources: Homebrew, npm, nvm, fnm, Volta official packages found; official JS discovered with unsupported launcher, no interpreter-wide approval");
}

#[test]
fn caller_path_first_entry_overrides_and_watch_shims_do_not_promote_ordinary_programs() {
    let f = Fixture::new();
    let known = f.home.join("known");
    let good = f.package(&known, LaunchTarget::CodexCli, false);
    let bad = f.home.join("ordinary/bin");
    Fixture::image(&bad.join("codex"));
    let handle = f.handle();
    let paths = std::env::join_paths([bad.clone(), known.join("bin")])
        .unwrap()
        .into_string()
        .unwrap();
    let env = BTreeMap::from([("PATH".into(), paths)]);
    assert_eq!(
        handle
            .select_cli(&f.reader, LaunchTarget::CodexCli, &env, native::now())
            .unwrap_err()
            .code,
        "cli_source_unverified"
    );
    let cwd = std::env::current_dir().unwrap();
    let mut up = PathBuf::new();
    for part in cwd.components() {
        if matches!(part, std::path::Component::Normal(_)) {
            up.push("..");
        }
    }
    let relative_bad = up.join(bad.strip_prefix("/").unwrap());
    let relative = BTreeMap::from([(
        "PATH".into(),
        std::env::join_paths([relative_bad, known.join("bin")])
            .unwrap()
            .into_string()
            .unwrap(),
    )]);
    assert_eq!(
        handle
            .select_cli(&f.reader, LaunchTarget::CodexCli, &relative, native::now())
            .unwrap_err()
            .code,
        "cli_source_unverified",
        "relative ordinary entry must not be skipped"
    );
    let relative_good = up.join(known.strip_prefix("/").unwrap()).join("bin");
    let relative = BTreeMap::from([("PATH".into(), relative_good.to_string_lossy().into_owned())]);
    let (snapshot, record) = handle
        .select_cli(&f.reader, LaunchTarget::CodexCli, &relative, native::now())
        .unwrap();
    assert_eq!(record.executable.as_ref(), Some(&good));
    assert_eq!(snapshot.preferred_sources["codex-cli"], record.source_id);
    let mut invalid = BTreeMap::from([
        (
            "PATH".into(),
            known.join("bin").to_string_lossy().into_owned(),
        ),
        (
            "CODEX_CLI_BIN".into(),
            f.home.join("missing").to_string_lossy().into_owned(),
        ),
    ]);
    assert_eq!(
        handle
            .select_cli(&f.reader, LaunchTarget::CodexCli, &invalid, native::now())
            .unwrap_err()
            .code,
        "cli_source_unverified"
    );
    invalid.remove("CODEX_CLI_BIN");
    let shim = Paths::new(&f.home)
        .unwrap()
        .watch()
        .join("entries/bin/codex");
    Fixture::image(&shim);
    invalid.insert(
        "PATH".into(),
        std::env::join_paths([shim.parent().unwrap().to_path_buf(), known.join("bin")])
            .unwrap()
            .into_string()
            .unwrap(),
    );
    invalid.insert(
        "CW_SHIM_EXECUTABLE".into(),
        shim.to_string_lossy().into_owned(),
    );
    let (_, selected) = handle
        .select_cli(&f.reader, LaunchTarget::CodexCli, &invalid, native::now())
        .unwrap();
    assert_eq!(selected.executable.as_ref(), Some(&good));
    assert!(selected.valid() && !selected.entry_path.starts_with(shim.parent().unwrap()));
}

#[test]
fn incremental_refresh_queries_on_budget_and_hashes_only_changed_selected_files() {
    let f = Fixture::new();
    let app = f.home.join("Applications/Claude Custom.app");
    f.app(&app, DESKTOP_IDS[0].0, "Different");
    f.registry
        .urls
        .lock()
        .unwrap()
        .insert(DESKTOP_IDS[0].0.into(), vec![app]);
    let handle = f.handle();
    let first = handle.refresh(&f.reader, 100.0);
    handle.approved_manifest(&first).unwrap();
    let before = handle.0.lock().unwrap().counters.clone();
    for now in [101.0, 110.0, 129.0] {
        assert_eq!(handle.refresh(&f.reader, now).revision, first.revision);
    }
    let stable = handle.0.lock().unwrap().counters.clone();
    assert_eq!(
        (
            stable.registry_queries,
            stable.directory_queries,
            stable.directory_entries,
            stable.plist_reads,
            stable.fingerprint_reads
        ),
        (
            before.registry_queries,
            before.directory_queries,
            before.directory_entries,
            before.plist_reads,
            before.fingerprint_reads
        )
    );
    let added = f.app(
        &f.home.join("Applications/New Codex.app"),
        DESKTOP_IDS[1].0,
        "ChangedName",
    );
    let next = handle.refresh(&f.reader, 129.5);
    assert_ne!(next.revision, first.revision);
    handle.approved_manifest(&next).unwrap();
    let after_add = handle.0.lock().unwrap().counters.clone();
    assert_eq!(
        handle.0.lock().unwrap().counters.fingerprint_reads,
        before.fingerprint_reads + 1
    );
    fs::write(&added, b"changed private native image").unwrap();
    let changed = handle.refresh(&f.reader, 129.6);
    handle.approved_manifest(&changed).unwrap();
    let after = handle.0.lock().unwrap().counters.clone();
    assert_eq!(after.fingerprint_reads, before.fingerprint_reads + 2);
    assert_eq!(
        after.directory_queries, after_add.directory_queries,
        "changing only a file must reuse all unchanged directory enumerations"
    );
    assert_eq!(after.registry_queries, 3);
    handle.refresh(&f.reader, 130.0);
    assert_eq!(handle.0.lock().unwrap().counters.registry_queries, 6);
    let counts = |c: &DiscoveryCounters| {
        json!({"registry_queries":c.registry_queries,"directory_queries":c.directory_queries,
        "directory_entries":c.directory_entries,"plist_reads":c.plist_reads,"scans":c.scans,"fingerprint_reads":c.fingerprint_reads})
    };
    let measured = json!({"initial":counts(&before),"stable":counts(&stable),"one_added":counts(&after_add),"one_changed":counts(&after),
        "at_30s":counts(&handle.0.lock().unwrap().counters)});
    println!("M5 measured counters: {measured}");
    if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            Path::new(&dir).join("target-discovery-counters.json"),
            serde_json::to_vec_pretty(&measured).unwrap(),
        )
        .unwrap();
    }
    println!("M5 counters: stable dirs/plist/SHA unchanged; adding and changing one selected file each hashes exactly once; registered lookups 3 before 30s, 6 at 30s");
}

#[test]
fn bounded_directory_batches_remain_partial_until_all_sources_are_observed() {
    let f = Fixture::new();
    for i in 0..7 {
        f.app(
            &f.home.join(format!("Applications/Copy {i}.app")),
            DESKTOP_IDS[0].0,
            &format!("Executable{i}"),
        );
    }
    let mut inputs = f.inputs();
    inputs.entry_budget = 2;
    let handle = DiscoveryHandle::with_registry(inputs, f.registry.clone());
    let mut snapshot = handle.refresh(&f.reader, 100.0);
    assert!(!snapshot.complete);
    assert_eq!(snapshot.targets.len(), 2);
    let mut rounds = 1;
    while !snapshot.complete && rounds < 5 {
        rounds += 1;
        snapshot = handle.refresh(&f.reader, 100.0 + rounds as f64);
    }
    assert_eq!(rounds, 4);
    assert!(snapshot.complete);
    assert_eq!(snapshot.targets.len(), 7);
    assert!(
        snapshot.select(LaunchTarget::ClaudeDesktop, None).is_err(),
        "completion never guesses among multiple installs"
    );
    let counters = handle.0.lock().unwrap().counters.clone();
    assert!(counters.directory_entries < 100);
    println!("M5 bounded batches: 2 entries per directory batch, 4 accepted rounds -> 7 copies, partial until final batch, {} counted directory entries",counters.directory_entries);
}

struct ChangingPlistReader<'a> {
    inner: &'a SystemRunner,
    alias: PathBuf,
    a: PathBuf,
    b: PathBuf,
    calls: AtomicUsize,
    changes: usize,
}
impl ReadRunner for ChangingPlistReader<'_> {
    fn run(
        &self,
        command: ReadCommand,
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> Result<Output> {
        let output = self.inner.run(command, input, timeout, limit)?;
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call < self.changes {
            let current = fs::canonicalize(&self.alias).unwrap();
            fs::remove_file(&self.alias).unwrap();
            symlink(
                if current == self.a { &self.b } else { &self.a },
                &self.alias,
            )
            .unwrap();
        }
        Ok(output)
    }
}

#[test]
fn discovery_snapshot_rereads_internal_retarget_and_never_caches_unstable_success() {
    let f = Fixture::new();
    let a = f.root.join("external/A.app");
    let b = f.root.join("external/B.app");
    f.app(&a, DESKTOP_IDS[1].0, "ImageA");
    let b_image = f.app(&b, DESKTOP_IDS[1].0, "ImageB");
    let alias = f.home.join("Applications/Stable Name.app");
    symlink(&a, &alias).unwrap();
    let mut inputs = f.inputs();
    inputs.query_registry = false;
    let mut cache = DiscoveryCache::new(inputs.clone());
    let one = ChangingPlistReader {
        inner: &f.reader,
        alias: alias.clone(),
        a: a.clone(),
        b: b.clone(),
        calls: AtomicUsize::new(0),
        changes: 1,
    };
    let snapshot = cache.refresh(&one, f.registry.as_ref(), 100.0);
    assert_eq!(
        snapshot
            .select(LaunchTarget::CodexDesktop, None)
            .unwrap()
            .executable
            .as_ref(),
        Some(&b_image)
    );
    assert_eq!(
        one.calls.load(Ordering::SeqCst),
        3,
        "A read, retarget, B, B; no random scheduling"
    );
    let mut cache = DiscoveryCache::new(inputs);
    let changing = ChangingPlistReader {
        inner: &f.reader,
        alias,
        a,
        b,
        calls: AtomicUsize::new(0),
        changes: usize::MAX,
    };
    let pending = cache.refresh(&changing, f.registry.as_ref(), 100.0);
    assert!(!pending.complete && pending.targets.is_empty());
    assert!(pending.issues.contains(&"target_discovery_unstable".into()));
    assert_eq!(changing.calls.load(Ordering::SeqCst), 4);
    let recovered = cache.refresh(&f.reader, f.registry.as_ref(), 101.0);
    assert!(recovered.complete && recovered.select(LaunchTarget::CodexDesktop, None).is_ok());
    println!("M5 snapshot seam: internal A->B accepted after B,B; four continuous changes remain pending, next stable read recovers");
}

#[test]
fn official_script_entries_are_discovered_without_promoting_ordinary_interpreters() {
    use fixture_inventory::{FixtureInventory, FixtureProcess};
    let f = Fixture::new();
    let prefix = f.home.join(".nvm/versions/node/v22");
    let script = f.package(&prefix, LaunchTarget::ClaudeCli, true);
    fs::set_permissions(&script, fs::Permissions::from_mode(0o644)).unwrap();
    let node = prefix.join("bin/node");
    Fixture::image(&node);
    let bun = f.home.join("custom-runtime/bun");
    Fixture::image(&bun);
    let codex_script = f.package(&f.home.join("custom-package"), LaunchTarget::CodexCli, true);
    let process = |pid, exe: &Path, args: Vec<String>| FixtureProcess {
        identity: Identity {
            pid,
            parent: 1,
            uid: 501,
            executable: exe.to_string_lossy().into_owned(),
            start_seconds: 100,
            start_microseconds: 1,
            start_stamp: "script-fixture".into(),
        },
        bundle: None,
        arguments: args,
    };
    let records = vec![
        process(
            6100,
            &node,
            vec![
                node.to_string_lossy().into_owned(),
                script.to_string_lossy().into_owned(),
            ],
        ),
        process(
            6101,
            &node,
            vec![
                node.to_string_lossy().into_owned(),
                "/ordinary/script.js".into(),
                script.to_string_lossy().into_owned(),
            ],
        ),
        process(
            6102,
            Path::new("/usr/bin/python3"),
            vec!["python3".into(), script.to_string_lossy().into_owned()],
        ),
        process(
            6103,
            &bun,
            vec![
                bun.to_string_lossy().into_owned(),
                codex_script.to_string_lossy().into_owned(),
            ],
        ),
        process(
            6104,
            &bun,
            vec![
                bun.to_string_lossy().into_owned(),
                "-e".into(),
                "console.log('ordinary')".into(),
                codex_script.to_string_lossy().into_owned(),
            ],
        ),
    ];
    let handle = f.handle();
    let mut sampler = Sampler::new(
        FixtureInventory(Arc::new(Mutex::new(records))),
        Paths::new(&f.home).unwrap(),
    );
    sampler.set_discovery(handle.clone());
    let round = sampler.processes().unwrap();
    assert_eq!(
        round
            .targets
            .iter()
            .map(|r| r.identity.pid)
            .collect::<Vec<_>>(),
        vec![6100, 6103]
    );
    let snapshot = handle.refresh(&f.reader, native::now());
    assert!(snapshot.targets.iter().any(|r| r.valid()
        && r.script_entry.as_ref() == Some(&script)
        && r.interpreter.as_ref() == Some(&node)
        && !r.launcher_supported));
    assert!(snapshot.targets.iter().any(|r| r.valid()
        && r.script_entry.as_ref() == Some(&codex_script)
        && r.interpreter.as_ref() == Some(&bun)
        && !r.launcher_supported));
    assert_eq!(
        round.match_evidence[&6103].reason,
        claude_watch_core::processes::MatchReason::ScriptEntry
    );
    assert!(
        handle
            .approved_manifest(&snapshot)
            .unwrap()
            .targets
            .is_empty(),
        "no Node executable or script enters general native-launch approval"
    );
}

#[test]
fn caller_hints_are_revalidated_and_do_not_replace_another_familys_sources() {
    let f = Fixture::new();
    let claude = f.home.join(".local/share/claude/versions/current");
    Fixture::image(&claude);
    let claude_bin = f.home.join("caller-claude/bin");
    fs::create_dir_all(&claude_bin).unwrap();
    symlink(&claude, claude_bin.join("claude")).unwrap();
    let codex_prefix = f.home.join("caller-codex");
    let codex = f.package(&codex_prefix, LaunchTarget::CodexCli, false);
    let first = f.handle();
    first
        .select_cli(
            &f.reader,
            LaunchTarget::ClaudeCli,
            &BTreeMap::from([("PATH".into(), claude_bin.to_string_lossy().into_owned())]),
            native::now(),
        )
        .unwrap();
    first.publish_caller_hint(LaunchTarget::ClaudeCli).unwrap();
    let daemon = f.handle();
    let snapshot = daemon.refresh(&f.reader, native::now());
    assert!(snapshot.complete, "new scoped hints must preserve the complete discovery schema: {:?}", snapshot.issues);
    assert!(daemon
        .approved_manifest(&snapshot)
        .unwrap()
        .targets
        .contains_key(claude.to_str().unwrap()));
    let second = f.handle();
    second
        .select_cli(
            &f.reader,
            LaunchTarget::CodexCli,
            &BTreeMap::from([(
                "PATH".into(),
                codex_prefix.join("bin").to_string_lossy().into_owned(),
            )]),
            native::now(),
        )
        .unwrap();
    second.publish_caller_hint(LaunchTarget::CodexCli).unwrap();
    let snapshot = daemon.refresh(&f.reader, native::now());
    let manifest = daemon.approved_manifest(&snapshot).unwrap();
    assert!(
        manifest.targets.contains_key(claude.to_str().unwrap())
            && manifest.targets.contains_key(codex.to_str().unwrap())
    );
    let ordinary = f.home.join("ordinary/bin");
    Fixture::image(&ordinary.join("codex"));
    let store = StateStore::new(Paths::new(&f.home).unwrap());
    let hint_path = store.paths.watch().join("state/target-discovery-hints.json");
    let mut shared = store.read_json(&hint_path, serde_json::Value::Null).unwrap();
    shared["overrides"] = json!({"CLAUDE_CODE_BIN":claude,"CODEX_CLI_BIN":codex});
    store.atomic_json(&hint_path, &shared).unwrap();
    first.publish_caller_hint(LaunchTarget::ClaudeCli).unwrap();
    let merged = store.read_json(&hint_path, serde_json::Value::Null).unwrap();
    assert!(merged["overrides"].get("CLAUDE_CODE_BIN").is_none(), "clear only this caller's removed override");
    assert_eq!(merged["overrides"]["CODEX_CLI_BIN"], json!(codex), "stale Claude writer must preserve the newer Codex override");
    assert!(merged["caller_paths"].get("codex-cli").is_some());
    store.atomic_json(&store.paths.watch().join("state/target-discovery-hints.json"),&json!({
        "caller_path":[],"caller_paths":{"claude-cli":[claude_bin],"codex-cli":[ordinary]},"desktop_sources":{},"overrides":{},
        "approved_targets":{codex.to_string_lossy():"pretend-approved"}})).unwrap();
    let snapshot = daemon.refresh(&f.reader, native::now());
    let manifest = daemon.approved_manifest(&snapshot).unwrap();
    assert!(
        manifest.targets.contains_key(claude.to_str().unwrap()),
        "unrelated Claude source must survive bad Codex hint"
    );
    assert!(!manifest.targets.contains_key(codex.to_str().unwrap()));
    assert!(
        !manifest.targets.keys().any(|p| p.contains("ordinary")),
        "candidate hints never deserialize or create approvals"
    );
    let app = f.root.join("outside-home/Explicit Renamed.app");
    let executable = f.app(&app, DESKTOP_IDS[2].0, "A Different Main");
    let mut desktop = NativeDesktop::new(&f.reader, f.helper(), Authority::ExplicitPermit).unwrap();
    desktop.set_discovery(f.handle());
    desktop
        .select_target_source(LaunchTarget::ChatgptDesktop, &app)
        .unwrap();
    let snapshot = daemon.refresh(&f.reader, native::now());
    let manifest = daemon.approved_manifest(&snapshot).unwrap();
    assert!(manifest.targets.contains_key(executable.to_str().unwrap()));
    assert!(manifest.targets.contains_key(claude.to_str().unwrap()));
    println!("M5 cross-process-style hints: caller/daemon PATH differs, each CLI preserves the other family; ordinary/forged approval hint rejected; explicit renamed desktop revalidated");
}

#[test]
fn m5_review_concurrent_stale_hint_writers_preserve_each_targets_source() {
    use std::{process::Command, time::Instant};
    const CHILD: &str = "CW_DISCOVERY_HINT_WRITER";
    if let Ok(target) = std::env::var(CHILD) {
        let target = LaunchTarget::parse(&target).unwrap();
        let home = PathBuf::from(std::env::var_os("CW_DISCOVERY_HINT_HOME").unwrap());
        let barrier = home.parent().unwrap();
        let reader = SystemRunner::new(native::built_observer_path().unwrap()).unwrap();
        let handle = DiscoveryHandle::new(DiscoveryInputs::for_home(&home));
        handle.select_cli(&reader, target, &BTreeMap::from([(
            "PATH".into(), home.join(target.as_str()).join("bin").to_string_lossy().into_owned(),
        )]), native::now()).unwrap();
        fs::write(barrier.join(format!("ready-{}", target.as_str())), b"ready").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !barrier.join("publish").exists() {
            assert!(Instant::now() < deadline, "parent did not release hint writers");
            std::thread::sleep(Duration::from_millis(10));
        }
        handle.publish_caller_hint(target).unwrap();
        return;
    }
    let f = Fixture::new();
    let claude = f.home.join(".local/share/claude/versions/current");
    Fixture::image(&claude);
    let claude_bin = f.home.join("claude-cli/bin");
    fs::create_dir_all(&claude_bin).unwrap();
    symlink(&claude, claude_bin.join("claude")).unwrap();
    let codex = f.package(&f.home.join("codex-cli"), LaunchTarget::CodexCli, false);
    let app = f.root.join("previous/Client.app");
    let store = StateStore::new(Paths::new(&f.home).unwrap());
    let hint = store.paths.watch().join("state/target-discovery-hints.json");
    store.atomic_json(&hint, &json!({"caller_path":[],"caller_paths":{},
        "desktop_sources":{"chatgpt-desktop":app},"overrides":{}})).unwrap();
    let mut children = Vec::new();
    for target in [LaunchTarget::ClaudeCli, LaunchTarget::CodexCli] {
        children.push(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "m5_review_concurrent_stale_hint_writers_preserve_each_targets_source", "--nocapture"])
            .env(CHILD, target.as_str()).env("CW_DISCOVERY_HINT_HOME", &f.home)
            .spawn().unwrap());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let ready = loop {
        if ["claude-cli", "codex-cli"].iter().all(|t| f.root.join(format!("ready-{t}")).exists()) {
            break true;
        }
        if Instant::now() >= deadline { break false; }
        std::thread::sleep(Duration::from_millis(10));
    };
    fs::write(f.root.join("publish"), b"go").unwrap();
    let statuses: Vec<_> = children.iter_mut().map(|child| child.wait().unwrap()).collect();
    assert!(ready && statuses.iter().all(|s| s.success()), "hint writers did not complete: {statuses:?}");
    let saved = store.read_json(&hint, serde_json::Value::Null).unwrap();
    assert_eq!(saved["caller_paths"]["claude-cli"], json!([claude_bin]), "stale Codex writer erased Claude");
    assert_eq!(saved["caller_paths"]["codex-cli"], json!([f.home.join("codex-cli/bin")]), "stale Claude writer erased Codex");
    assert_eq!(saved["desktop_sources"]["chatgpt-desktop"], json!(app));
    let daemon = f.handle();
    let snapshot = daemon.refresh(&f.reader, native::now());
    let manifest = daemon.approved_manifest(&snapshot).unwrap();
    assert!(manifest.targets.contains_key(claude.to_str().unwrap()));
    assert!(manifest.targets.contains_key(codex.to_str().unwrap()));
    println!("Two independent stale processes preserved both CLI hints and the unrelated desktop source");
}

#[test]
fn m5_review_fingerprint_failures_isolate_targets_and_do_not_block_other_source_removals() {
    for child_failure in [false, true] {
        let f = Fixture::new();
        let bundle = f.home.join("Applications/Client.app");
        let main = f.app(&bundle, DESKTOP_IDS[0].0, "Main");
        let child = bundle.join("Contents/Frameworks/Helper.app/Contents/MacOS/Helper");
        Fixture::image(&child);
        let codex_prefix = f.home.join("codex-prefix");
        let codex = f.package(&codex_prefix, LaunchTarget::CodexCli, false);
        let old = f.home.join(".local/share/claude/versions/old");
        Fixture::image(&old);
        let alias = f.home.join(".local/bin/claude");
        fs::create_dir_all(alias.parent().unwrap()).unwrap();
        symlink(&old, &alias).unwrap();
        let mut inputs = f.inputs();
        inputs.daemon_path = vec![codex_prefix.join("bin")];
        let handle = DiscoveryHandle::with_registry(inputs, f.registry.clone());
        let before = handle.refresh(&f.reader, 100.0);
        assert_eq!(handle.approved_manifest(&before).unwrap().targets.len(), 3);
        let unreadable = if child_failure { &child } else { &main };
        fs::set_permissions(unreadable, fs::Permissions::from_mode(0o111)).unwrap();
        assert!(fs::File::open(unreadable).is_err(), "fixture requires the unprivileged file-read failure");
        fs::remove_file(alias).unwrap();
        fs::write(&codex, b"new private native image; never executed").unwrap();
        let snapshot = handle.refresh(&f.reader, 101.0);
        assert!(snapshot.targets.iter().any(|r| r.target == LaunchTarget::ClaudeDesktop && r.valid()));
        let manifest = handle.approved_manifest(&snapshot)
            .expect("one unreadable image must not abort unrelated manifest updates");
        assert_eq!(manifest.targets.len(), 1);
        assert_eq!(manifest.targets[codex.to_str().unwrap()], claude_watch_system::sha256_file_hex(&codex).unwrap());
        assert!(!manifest.targets.contains_key(old.to_str().unwrap()), "removed source must not retain approval");
        assert!(!manifest.children.contains_key(main.to_str().unwrap()));
        assert!(!manifest.children.contains_key(child.to_str().unwrap()));
        assert!(manifest.desktop_specs.is_empty(), "failed helper must not leave a partial desktop approval");
        assert!(manifest.selection_issues.iter().any(|s| s == "claude-desktop:target_fingerprint_failed"));
        assert!(manifest.needs_verification_retry, "temporary reads must not cache a fully staged revision");
        assert!(handle.approved_manifest(&before).is_err(), "stale whole snapshot still fails as a whole");
    }
    println!("Unreadable main/helper isolates the entire affected target; other updates and removals remain applicable");
}

struct UnreadablePlist<'a> {
    inner: &'a SystemRunner,
    blocked: PathBuf,
}
impl ReadRunner for UnreadablePlist<'_> {
    fn run(
        &self,
        command: ReadCommand,
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> Result<Output> {
        if matches!(&command,ReadCommand::Plist(path) if path==&self.blocked) {
            return Ok(Output {
                status: 1,
                stdout: vec![],
                stderr: b"fixture permission denied".to_vec(),
            });
        }
        self.inner.run(command, input, timeout, limit)
    }
}

#[test]
fn unreadable_known_install_stays_pending_without_withdrawing_unrelated_family() {
    use fixture_inventory::{FixtureInventory, FixtureProcess};
    let f = Fixture::new();
    let claude = f.root.join("observed/Custom Client.app");
    let executable = f.app(&claude, DESKTOP_IDS[0].0, "Unusual");
    let codex = f.home.join("Applications/Editor.app");
    let unrelated = f.app(&codex, DESKTOP_IDS[1].0, "Editor");
    let handle = f.handle();
    let before = handle.refresh(&f.reader, 100.0);
    handle.approved_manifest(&before).unwrap();
    handle.observed_process_bundles([(claude.clone(), Some(DESKTOP_IDS[0].0.into()))]);
    let denied = UnreadablePlist {
        inner: &f.reader,
        blocked: claude.join("Contents/Info.plist"),
    };
    let pending = handle.refresh(&denied, 101.0);
    assert!(!pending.complete);
    assert!(pending
        .targets
        .iter()
        .any(|r| r.bundle.as_ref() == Some(&claude) && !r.valid()));
    let manifest = handle.approved_manifest(&pending).unwrap();
    assert_eq!(
        manifest.targets.keys().collect::<Vec<_>>(),
        vec![unrelated.to_str().unwrap()]
    );
    let records = vec![FixtureProcess {
        identity: Identity {
            pid: 6200,
            parent: 1,
            uid: 501,
            executable: executable.to_string_lossy().into_owned(),
            start_seconds: 100,
            start_microseconds: 1,
            start_stamp: "pending-fixture".into(),
        },
        bundle: Some((
            claude.to_string_lossy().into_owned(),
            DESKTOP_IDS[0].0.into(),
        )),
        arguments: vec![],
    }];
    // Missing metadata is also deterministic for the production sampler reader.
    fs::remove_file(claude.join("Contents/Info.plist")).unwrap();
    let mut sampler = Sampler::new(
        FixtureInventory(Arc::new(Mutex::new(records))),
        Paths::new(&f.home).unwrap(),
    );
    sampler.set_discovery(handle.clone());
    let round = sampler.processes().unwrap();
    assert_eq!(round.targets.len(), 1);
    assert_eq!(
        round.match_evidence[&6200].reason,
        claude_watch_core::processes::MatchReason::InstallationPending
    );
    let producer = Identity {
        pid: 4000,
        parent: 1,
        uid: 501,
        executable: "/fixture/watch-engine".into(),
        start_seconds: 100,
        start_microseconds: 1,
        start_stamp: "fixture".into(),
    };
    let monitor = claude_watch_runtime::monitor_snapshot::assemble(
        &StateStore::new(Paths::new(&f.home).unwrap()),
        &round,
        &json!({}),
        &producer,
        "fixture",
        false,
        native::now(),
    );
    assert_eq!(
        monitor["processes"][0]["matchReason"],
        "installation_pending"
    );
    assert_ne!(monitor["processes"][0]["protection"]["state"], "protected");
    if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            Path::new(&dir).join("target-discovery-pending.json"),
            serde_json::to_vec_pretty(&monitor).unwrap(),
        )
        .unwrap();
    }
    println!("M5 unreadable/missing known installation: visible pending only, no approval; unrelated Codex remains selected and content-approved");
}

#[test]
fn unstable_refresh_drops_only_changed_evidence_and_publishes_a_new_pending_revision() {
    let f = Fixture::new();
    let a = f.root.join("external/A.app");
    let b = f.root.join("external/B.app");
    f.app(&a, DESKTOP_IDS[1].0, "ImageA");
    f.app(&b, DESKTOP_IDS[1].0, "ImageB");
    let alias = f.home.join("Applications/Moving.app");
    symlink(&a, &alias).unwrap();
    let unrelated = f.home.join(".local/share/claude/versions/current");
    Fixture::image(&unrelated);
    let cli = f.home.join(".local/bin/claude");
    fs::create_dir_all(cli.parent().unwrap()).unwrap();
    symlink(&unrelated, &cli).unwrap();
    let handle = f.handle();
    let before = handle.refresh(&f.reader, 100.0);
    assert_eq!(handle.approved_manifest(&before).unwrap().targets.len(), 2);
    fs::remove_file(&alias).unwrap();
    symlink(&b, &alias).unwrap();
    let changing = ChangingPlistReader {
        inner: &f.reader,
        alias,
        a,
        b,
        calls: AtomicUsize::new(0),
        changes: usize::MAX,
    };
    let pending = handle.refresh(&changing, 101.0);
    assert!(!pending.complete);
    assert_ne!(pending.revision, before.revision);
    assert_eq!(
        pending.prior_revision.as_deref(),
        Some(before.revision.as_str())
    );
    let manifest = handle.approved_manifest(&pending).unwrap();
    assert_eq!(
        manifest.targets.keys().collect::<Vec<_>>(),
        vec![unrelated.to_str().unwrap()]
    );
    assert_eq!(changing.calls.load(Ordering::SeqCst), 4);
    println!("M5 unstable refresh: changed source removed in a distinct pending revision, unchanged family retains current content proof");
}

#[test]
fn dangling_nonexecutable_and_bounded_inputs_never_report_verified_success() {
    let f = Fixture::new();
    let broken = f.home.join("Applications/Broken.app");
    symlink(f.root.join("missing"), &broken).unwrap();
    let app = f.home.join("Applications/No Exec.app");
    let exe = f.app(&app, DESKTOP_IDS[2].0, "Disabled");
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o644)).unwrap();
    let handle = f.handle();
    let snapshot = handle.refresh(&f.reader, 100.0);
    assert!(!snapshot.complete);
    assert!(handle
        .approved_manifest(&snapshot)
        .unwrap()
        .targets
        .is_empty());
    let env = BTreeMap::from([(
        "PATH".into(),
        std::env::join_paths((0..129).map(|i| f.home.join(format!("empty-{i}"))))
            .unwrap()
            .into_string()
            .unwrap(),
    )]);
    handle
        .caller_environment(LaunchTarget::CodexCli, &env)
        .unwrap();
    handle.observed_process_bundles(
        (0..257).map(|i| (f.home.join(format!("unknown-{i}.app")), None)),
    );
    let pending = handle.refresh(&f.reader, 101.0);
    assert!(!pending.complete);
    assert!(pending
        .issues
        .contains(&"codex-cli:caller_path_partial".into()));
    assert!(pending.issues.contains(&"observed_bundles_partial".into()));
    assert!(handle
        .approved_manifest(&pending)
        .unwrap()
        .targets
        .is_empty());
    println!("M5 negative boundaries: dangling bundle, nonexecutable image and truncated PATH/inventory remain unapproved and partial");
}

#[test]
fn registered_preference_move_and_explicit_reselection_keep_monitoring_separate() {
    use fixture_inventory::{FixtureInventory, FixtureProcess};
    let f = Fixture::new();
    let ordinary = f.root.join("registered/Ordinary.app");
    f.app(&ordinary, "com.example.other", "Ordinary");
    let preferred = f.root.join("registered/Preferred.app");
    f.app(&preferred, DESKTOP_IDS[1].0, "Agent");
    let other = f.home.join("Applications/Other Copy.app");
    f.app(&other, DESKTOP_IDS[1].0, "Other");
    f.registry.urls.lock().unwrap().insert(
        DESKTOP_IDS[1].0.into(),
        vec![ordinary, preferred.clone(), other],
    );
    let handle = f.handle();
    let (_, selected) = handle
        .select_desktop(&f.reader, LaunchTarget::CodexDesktop, 100.0)
        .unwrap();
    assert_eq!(
        selected.bundle.as_ref(),
        Some(&preferred),
        "first valid OS-registered copy takes precedence"
    );
    let moved = f.root.join("relocated/New Display Name.app");
    fs::create_dir_all(moved.parent().unwrap()).unwrap();
    fs::rename(&preferred, &moved).unwrap();
    let lost = handle.refresh(&f.reader, 101.0);
    assert_eq!(
        lost.select(LaunchTarget::CodexDesktop, None)
            .unwrap_err()
            .code,
        "selected_source_unavailable"
    );
    assert!(handle.approved_manifest(&lost).unwrap().targets.is_empty());
    let executable = moved.join("Contents/MacOS/Agent");
    let record = FixtureProcess {
        identity: Identity {
            pid: 6300,
            parent: 1,
            uid: 501,
            executable: executable.to_string_lossy().into_owned(),
            start_seconds: 100,
            start_microseconds: 1,
            start_stamp: "moved-fixture".into(),
        },
        bundle: Some((
            moved.to_string_lossy().into_owned(),
            DESKTOP_IDS[1].0.into(),
        )),
        arguments: vec![],
    };
    let mut sampler = Sampler::new(
        FixtureInventory(Arc::new(Mutex::new(vec![record]))),
        Paths::new(&f.home).unwrap(),
    );
    sampler.set_discovery(handle.clone());
    let round = sampler.processes().unwrap();
    assert_eq!(round.targets.len(), 1);
    assert_eq!(
        round.targets[0].identity.executable,
        executable.to_string_lossy()
    );
    let snapshot = handle.refresh(&f.reader, native::now());
    assert!(
        handle
            .approved_manifest(&snapshot)
            .unwrap()
            .targets
            .is_empty(),
        "observing a moved process cannot silently replace its selected launch source"
    );
    let mut desktop = NativeDesktop::new(&f.reader, f.helper(), Authority::ReadOnly).unwrap();
    desktop.set_discovery(handle);
    desktop
        .select_target_source(LaunchTarget::CodexDesktop, &moved)
        .unwrap();
    assert_eq!(
        desktop
            .build_managed_entry_spec()
            .unwrap()
            .target_executable,
        executable
    );
    println!("M5 selection: OS first valid registered copy; moving it withdraws approval without fallback, observed process remains discovered, explicit new source revalidates");
}

#[test]
fn canonical_home_alias_and_registry_failure_reuse_current_evidence_conservatively() {
    let f = Fixture::new();
    let alias = f.root.join("home-alias");
    symlink(&f.home, &alias).unwrap();
    assert_eq!(DiscoveryInputs::for_home(&alias).home, f.home);
    let one = DiscoveryHandle::for_home(&alias);
    let two = DiscoveryHandle::for_home(&f.home);
    assert!(Arc::ptr_eq(&one.0, &two.0));
    let image = f.home.join(".local/share/claude/versions/native");
    Fixture::image(&image);
    let env = BTreeMap::from([(
        "CLAUDE_CODE_BIN".into(),
        alias
            .join(".local/share/claude/versions/native")
            .to_string_lossy()
            .into_owned(),
    )]);
    assert_eq!(
        one.select_cli(&f.reader, LaunchTarget::ClaudeCli, &env, 100.0)
            .unwrap()
            .1
            .executable
            .as_ref(),
        Some(&image)
    );
    struct Query {
        path: PathBuf,
        fail: std::sync::atomic::AtomicBool,
    }
    impl ApplicationRegistry for Query {
        fn locations(&self, id: &str) -> Result<ApplicationLocations> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(claude_watch_core::error::CoreError::new(
                    "application_registry_unavailable",
                    "fixture read failure",
                ));
            }
            Ok(ApplicationLocations {
                paths: if id == DESKTOP_IDS[2].0 {
                    vec![self.path.clone()]
                } else {
                    vec![]
                },
                complete: true,
            })
        }
    }
    let app = f.root.join("external/Chat.app");
    let executable = f.app(&app, DESKTOP_IDS[2].0, "Client");
    let query = Arc::new(Query {
        path: app,
        fail: std::sync::atomic::AtomicBool::new(false),
    });
    let handle = DiscoveryHandle::with_registry(f.inputs(), query.clone());
    let first = handle.refresh(&f.reader, 100.0);
    assert!(first.complete);
    query.fail.store(true, Ordering::SeqCst);
    let partial = handle.refresh(&f.reader, 130.0);
    assert!(
        !partial.complete
            && partial
                .issues
                .contains(&"application_registry_unavailable".into())
    );
    assert_ne!(partial.revision, first.revision);
    assert!(
        handle
            .approved_manifest(&partial)
            .unwrap()
            .targets
            .contains_key(executable.to_str().unwrap()),
        "query failure does not invalidate separately current known files"
    );
    println!("M5 canonical home alias: shared cache and explicit native source agree; failed registry query becomes partial while current known installation remains usable under existing gates");
}
