use claude_watch_core::error::Result;
use claude_watch_runtime::{
    background_evidence::{collect_native, ProbeKind, ASSETS, WORKER},
    commands::{Output, ReadCommand, ReadRunner},
    release_native::{FixedCommand, FixedCommandExecutor, FixedOutput},
    storage::{sha256, Paths, StateStore},
};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
    time::Duration,
};
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
    store: StateStore,
    manifest: Value,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("cw-worker-integrity-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let home = root.join("home");
        fs::create_dir(&home).unwrap();
        let store = StateStore::new(Paths::new(&home).unwrap());
        let runtime = store.paths.watch().join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        let mut hashes = serde_json::Map::new();
        for name in [WORKER, "watch-engine", ASSETS[0], ASSETS[1], ASSETS[2]] {
            let path = runtime.join(name);
            fs::write(&path, name.as_bytes()).unwrap();
            let mode = if matches!(name, WORKER | "watch-engine") {
                0o700
            } else {
                0o600
            };
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            hashes.insert(name.into(), json!(sha256(name.as_bytes())));
        }
        fs::write(runtime.join("BuildInfo.plist"), b"fixture").unwrap();
        Self {
            root,
            store,
            manifest: json!({
                "Architecture":"arm64", "BackendVariant":"rust-candidate",
                "RuntimeSchema":2, "BackgroundEvidenceSchema":1,
                "RuntimeHashes":hashes,
            }),
        }
    }
    fn runtime(&self) -> PathBuf {
        self.store.paths.watch().join("runtime")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Reader(Value);
impl ReadRunner for Reader {
    fn run(&self, command: ReadCommand, _: &[u8], _: Duration, _: usize) -> Result<Output> {
        assert!(matches!(command, ReadCommand::Plist(_)));
        Ok(Output {
            status: 0,
            stdout: self.0.to_string().into_bytes(),
            stderr: vec![],
        })
    }
}

struct Executor {
    output: FixedOutput,
    calls: Vec<FixedCommand>,
}
impl FixedCommandExecutor for Executor {
    fn run(&mut self, command: FixedCommand) -> Result<FixedOutput> {
        self.calls.push(command);
        Ok(self.output.clone())
    }
}

fn probe(kind: ProbeKind) -> String {
    json!({"kind":kind.label(),"status":"complete","contextChanged":false,
        "startedAt":1000.0,"finishedAt":1001.0,"errors":[],"observations":[]})
    .to_string()
}
fn executor(kind: ProbeKind) -> Executor {
    Executor {
        output: FixedOutput {
            status: 0,
            stdout: probe(kind),
            stderr: String::new(),
        },
        calls: vec![],
    }
}

#[test]
fn verified_runtime_executes_only_the_fixed_worker_and_probe_argument() {
    let fixture = Fixture::new();
    let mut commands = executor(ProbeKind::Dns);
    let value = collect_native(
        &fixture.store,
        &Reader(fixture.manifest.clone()),
        &mut commands,
        ProbeKind::Dns,
    )
    .unwrap();
    assert_eq!(value["kind"], "dns");
    assert_eq!(commands.calls.len(), 1);
    assert_eq!(commands.calls[0].program, fixture.runtime().join(WORKER));
    assert_eq!(commands.calls[0].args, ["--dns"]);
    assert_eq!(commands.calls[0].timeout, Duration::from_secs(80));
}

#[test]
fn missing_hash_or_changed_asset_rejects_before_worker_execution() {
    let fixture = Fixture::new();
    let mut missing = fixture.manifest.clone();
    missing["RuntimeHashes"]
        .as_object_mut()
        .unwrap()
        .remove(ASSETS[1]);
    let mut commands = executor(ProbeKind::Dns);
    assert_eq!(
        collect_native(
            &fixture.store,
            &Reader(missing),
            &mut commands,
            ProbeKind::Dns
        )
        .unwrap_err()
        .code,
        "evidence_runtime_invalid"
    );
    assert!(commands.calls.is_empty());

    fs::write(fixture.runtime().join(ASSETS[1]), b"changed").unwrap();
    let mut commands = executor(ProbeKind::Dns);
    assert_eq!(
        collect_native(
            &fixture.store,
            &Reader(fixture.manifest.clone()),
            &mut commands,
            ProbeKind::Dns,
        )
        .unwrap_err()
        .code,
        "evidence_runtime_invalid"
    );
    assert!(commands.calls.is_empty());
}

#[test]
fn absent_symlink_or_non_executable_worker_is_rejected_before_execution() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.runtime().join(WORKER)).unwrap();
    let mut commands = executor(ProbeKind::Dns);
    assert_eq!(
        collect_native(
            &fixture.store,
            &Reader(fixture.manifest.clone()),
            &mut commands,
            ProbeKind::Dns,
        )
        .unwrap_err()
        .code,
        "evidence_worker_missing"
    );
    assert!(commands.calls.is_empty());

    fs::write(fixture.runtime().join(WORKER), WORKER).unwrap();
    fs::set_permissions(
        fixture.runtime().join(WORKER),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mut commands = executor(ProbeKind::Dns);
    assert_eq!(
        collect_native(
            &fixture.store,
            &Reader(fixture.manifest.clone()),
            &mut commands,
            ProbeKind::Dns,
        )
        .unwrap_err()
        .code,
        "evidence_runtime_invalid"
    );
    assert!(commands.calls.is_empty());

    fs::remove_file(fixture.runtime().join(WORKER)).unwrap();
    symlink(fixture.root.join("outside"), fixture.runtime().join(WORKER)).unwrap();
    let mut commands = executor(ProbeKind::Dns);
    assert!(collect_native(
        &fixture.store,
        &Reader(fixture.manifest.clone()),
        &mut commands,
        ProbeKind::Dns,
    )
    .is_err());
    assert!(commands.calls.is_empty());
}

#[test]
fn bad_worker_reply_never_becomes_a_receipt() {
    let fixture = Fixture::new();
    for output in [
        FixedOutput {
            status: 0,
            stdout: probe(ProbeKind::WebRtc),
            stderr: String::new(),
        },
        FixedOutput {
            status: 0,
            stdout: "{bad".into(),
            stderr: String::new(),
        },
        FixedOutput {
            status: 1,
            stdout: probe(ProbeKind::Dns),
            stderr: String::new(),
        },
        FixedOutput {
            status: 0,
            stdout: "x".repeat(1_048_577),
            stderr: String::new(),
        },
    ] {
        let mut commands = Executor {
            output,
            calls: vec![],
        };
        assert!(collect_native(
            &fixture.store,
            &Reader(fixture.manifest.clone()),
            &mut commands,
            ProbeKind::Dns,
        )
        .is_err());
        assert_eq!(commands.calls.len(), 1);
    }
}

#[test]
fn legacy_manifest_stays_recognizable_but_cannot_start_background_worker() {
    let fixture = Fixture::new();
    let mut legacy = fixture.manifest.clone();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("BackgroundEvidenceSchema");
    let mut commands = executor(ProbeKind::Dns);
    assert_eq!(
        collect_native(
            &fixture.store,
            &Reader(legacy),
            &mut commands,
            ProbeKind::Dns
        )
        .unwrap_err()
        .code,
        "evidence_runtime_invalid"
    );
    assert!(commands.calls.is_empty());
}
