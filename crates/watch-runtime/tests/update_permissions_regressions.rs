//! Real ZIP/file operations in temporary directories; extracted bytes are
//! never executed. Installation, health and network adapters are mocked.
use claude_watch_core::error::{CoreError, Result};
use claude_watch_runtime::{storage::sha256, update::*};
use std::{collections::BTreeMap, fs, io::Write, os::unix::fs::{symlink, PermissionsExt}, path::{Path, PathBuf}};

const APP: &str = "app/Claude Watch Monitor.app";
const BIN: &str = "app/Claude Watch Monitor.app/Contents/MacOS/ClaudeWatchMonitor";
const COMPONENTS: &[&str] = &["watch-engine", "watch-native-observer", "watch-process-control",
    "watch-admin.sh", "watch-native-collector.zsh", "watch-leak-worker"];
struct Fixture { root: PathBuf }
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("cw-zip-permissions-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        Self { root: fs::canonicalize(root).unwrap() }
    }
    fn archive(&self, contents: &BTreeMap<String, Vec<u8>>, mode: u32) -> (PathBuf, Release) {
        let archive = self.root.join("release.zip");
        let mut writer = zip::ZipWriter::new(fs::File::create(&archive).unwrap());
        for (name, bytes) in contents {
            writer.start_file(name, zip::write::SimpleFileOptions::default().unix_permissions(mode)).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
        let release = Release { version: "3.0.0".into(), architecture: "arm64".into(),
            archive_url: "https://fixture.invalid/release.zip".into(),
            archive_sha256: archive_hash(&archive).unwrap(),
            files: contents.iter().map(|(n, b)| (n.clone(), sha256(b))).collect() };
        (archive, release)
    }
    fn destination(&self) -> PathBuf { self.root.join("payload") }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); } }
fn contents() -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    files.insert(format!("{APP}/Contents/Info.plist"), b"fixture app metadata".to_vec());
    files.insert(BIN.into(), b"fixture main executable; never executed".to_vec());
    for name in COMPONENTS.iter().copied().chain(["BuildInfo.plist", "netcoffee_probe.js", "unknown.sh"]) {
        for prefix in ["runtime/".to_string(), format!("{APP}/Contents/Resources/")] {
            files.insert(format!("{prefix}{name}"), format!("fixture {name}").into_bytes());
        }
    }
    files.insert(format!("{APP}/Contents/Resources/nested/watch-engine"), b"data, not a component".to_vec());
    files
}
fn mode(path: &Path) -> u32 { fs::metadata(path).unwrap().permissions().mode() & 0o7777 }
fn put(path: &Path, bytes: &[u8], permissions: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap(); fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(permissions)).unwrap();
}
fn no_execute(path: &Path) {
    if !path.exists() { return; }
    if path.is_dir() {
        for item in fs::read_dir(path).unwrap() { no_execute(&item.unwrap().path()); }
    } else { assert_eq!(mode(path) & 0o111, 0, "{}", path.display()); }
}

#[test]
fn signed_component_roles_get_execute_bits_even_when_zip_modes_lost_them() {
    let f = Fixture::new(); let files = contents(); let (archive, release) = f.archive(&files, 0o644);
    verify_extract(&archive, &f.destination(), &release).unwrap();
    assert_eq!(mode(&f.destination().join(BIN)), 0o700);
    for name in COMPONENTS {
        for prefix in ["runtime/".to_string(), format!("{APP}/Contents/Resources/")] {
            assert_eq!(mode(&f.destination().join(format!("{prefix}{name}"))), 0o700);
        }
    }
    for (name, bytes) in files { assert_eq!(fs::read(f.destination().join(name)).unwrap(), bytes); }
}
#[test]
fn gateway_broker_update_requires_matching_pair_and_grants_only_exact_execution_roles() {
    const RUNTIME: &str = "runtime/watch-gateway-broker";
    const BUNDLED: &str = "app/Claude Watch Monitor.app/Contents/Resources/watch-gateway-broker";
    const NESTED: &str = "app/Claude Watch Monitor.app/Contents/Resources/nested/watch-gateway-broker";
    for case in ["absent", "matching", "runtime_only", "app_only", "mismatched"] {
        let fixture = Fixture::new();
        let mut files = contents();
        files.insert(NESTED.into(), b"ordinary resource, never executed".to_vec());
        if case != "absent" {
            files.insert(RUNTIME.into(), b"broker fixture, never executed".to_vec());
            files.insert(BUNDLED.into(), b"broker fixture, never executed".to_vec());
        }
        match case {
            "runtime_only" => { files.remove(BUNDLED); }
            "app_only" => { files.remove(RUNTIME); }
            "mismatched" => { files.insert(BUNDLED.into(), b"different broker bytes".to_vec()); }
            _ => {}
        }
        let (archive, release) = fixture.archive(&files, 0o755);
        let result = verify_extract(&archive, &fixture.destination(), &release);
        if matches!(case, "absent" | "matching") {
            result.unwrap();
            assert_eq!(mode(&fixture.destination().join(NESTED)), 0o600);
            if case == "matching" {
                for path in [RUNTIME, BUNDLED] {
                    assert_eq!(mode(&fixture.destination().join(path)), 0o700);
                    assert_eq!(fs::read(fixture.destination().join(path)).unwrap(), files[path]);
                }
            }
        } else {
            assert_eq!(result.unwrap_err().code, "release_component_mismatch", "{case}");
            no_execute(&fixture.destination());
        }
    }
}
#[test]
fn arbitrary_archive_execute_bits_do_not_turn_resources_into_programs() {
    let f = Fixture::new(); let (archive, release) = f.archive(&contents(), 0o777);
    verify_extract(&archive, &f.destination(), &release).unwrap();
    for name in ["runtime/BuildInfo.plist", "runtime/netcoffee_probe.js", "runtime/unknown.sh",
        "app/Claude Watch Monitor.app/Contents/Info.plist",
        "app/Claude Watch Monitor.app/Contents/Resources/nested/watch-engine"] {
        assert_eq!(mode(&f.destination().join(name)), 0o600, "{name}");
    }
    assert_eq!(mode(&f.destination().join("runtime/watch-engine")), 0o700);
}
#[test]
fn a_late_hash_failure_grants_no_execution_permissions() {
    let f = Fixture::new(); let mut files = contents(); files.insert("runtime/zzz-corrupt".into(), b"fixture".to_vec());
    let (archive, mut release) = f.archive(&files, 0o755);
    release.files.insert("runtime/zzz-corrupt".into(), "0".repeat(64));
    assert_eq!(verify_extract(&archive, &f.destination(), &release).unwrap_err().code, "release_hash_mismatch");
    assert!(f.destination().join("runtime/watch-engine").exists()); no_execute(&f.destination());
}
#[test]
fn incomplete_or_mismatched_components_never_become_executable() {
    for mismatch in [false, true] {
        let f = Fixture::new(); let mut files = contents();
        if mismatch { files.insert("runtime/watch-engine".into(), b"different bytes".to_vec()); }
        else { files.remove("runtime/watch-native-observer"); }
        let (archive, release) = f.archive(&files, 0o755);
        assert_eq!(verify_extract(&archive, &f.destination(), &release).unwrap_err().code,
            if mismatch { "release_component_mismatch" } else { "release_incomplete" });
        no_execute(&f.destination());
    }
}
#[test]
fn aliased_members_cannot_bypass_the_fixed_execution_roles() {
    for path in ["runtime/./watch-engine", "runtime//watch-engine", "runtime/../watch-engine"] {
        let f = Fixture::new(); let mut files = contents(); files.insert(path.into(), b"aliased".to_vec());
        let (archive, release) = f.archive(&files, 0o755);
        assert_eq!(verify_extract(&archive, &f.destination(), &release).unwrap_err().code, "unsafe_archive");
        no_execute(&f.destination());
    }
}
#[test]
fn a_symlink_destination_or_parent_never_receives_payload_or_chmod() {
    for nested in [false, true] {
        let f = Fixture::new(); let outside = f.root.join("preserve"); fs::create_dir(&outside).unwrap();
        put(&outside.join("sentinel"), b"unchanged", 0o640);
        if nested {
            fs::create_dir(f.destination()).unwrap(); symlink(&outside, f.destination().join("app")).unwrap();
        } else { symlink(&outside, f.destination()).unwrap(); }
        let (archive, release) = f.archive(&contents(), 0o755);
        assert_eq!(verify_extract(&archive, &f.destination(), &release).unwrap_err().code, "unsafe_archive");
        assert_eq!(mode(&outside.join("sentinel")), 0o640);
        assert_eq!(fs::read_dir(outside).unwrap().count(), 1);
    }
}
#[test]
fn a_preexisting_leaf_is_never_overwritten_or_granted_execute_permission() {
    let f = Fixture::new(); let target = f.destination().join(BIN);
    put(&target, b"existing data", 0o640);
    let (archive, release) = f.archive(&contents(), 0o755);
    assert!(verify_extract(&archive, &f.destination(), &release).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"existing data"); assert_eq!(mode(&target), 0o640);
}
#[test]
fn zero_archive_permissions_are_normalized_by_signed_file_role() {
    let f = Fixture::new(); let (archive, release) = f.archive(&contents(), 0);
    verify_extract(&archive, &f.destination(), &release).unwrap();
    assert_eq!(mode(&f.destination().join("runtime/watch-engine")), 0o700);
    assert_eq!(mode(&f.destination().join("runtime/BuildInfo.plist")), 0o600);
}

struct NoNetwork;
impl Transport for NoNetwork {
    fn get(&mut self, _: &str, _: u64) -> Result<Vec<u8>> { panic!("fixture must not use the network") }
}
struct MockOs { engine: PathBuf, fail_health: bool, checks: usize, restarts: usize }
impl UpdateOs for MockOs {
    fn architecture(&mut self) -> Result<String> { Ok("arm64".into()) }
    fn verify_app(&mut self, app: &Path, _: &str) -> Result<()> {
        assert_eq!(mode(&app.join("Contents/MacOS/ClaudeWatchMonitor")), 0o700); Ok(())
    }
    fn health(&mut self) -> Result<()> {
        self.checks += 1; assert_eq!(mode(&self.engine), 0o700);
        if self.fail_health { Err(CoreError::new("fixture_health_failed", "fixture")) } else { Ok(()) }
    }
    fn restart_agent(&mut self) -> Result<()> { self.restarts += 1; Ok(()) }
    fn agent_healthy(&mut self) -> Result<bool> { Ok(true) }
}
fn updater(f: &Fixture, fail_health: bool) -> Updater<MockOs, NoNetwork> {
    let watch = f.root.join("installed-watch"); fs::create_dir(&watch).unwrap();
    Updater { paths: UpdatePaths { base: f.root.join("update-state"), app: f.root.join("installed.app"),
        watch: watch.clone(), backend: f.root.join("untouched-legacy") },
        os: MockOs { engine: watch.join("runtime/watch-engine"), fail_health, checks: 0, restarts: 0 },
        transport: NoNetwork }
}
#[test]
fn extraction_permissions_survive_real_staging_copy_without_execution() {
    let f = Fixture::new(); let (archive, release) = f.archive(&contents(), 0o644);
    verify_extract(&archive, &f.destination(), &release).unwrap();
    let mut update = updater(&f, false); update.apply_payload(&f.destination(), &release).unwrap();
    assert_eq!((update.os.checks, update.os.restarts), (1, 1));
    assert_eq!(mode(&update.paths.watch.join("runtime/watch-engine")), 0o700);
    assert_eq!(mode(&update.paths.watch.join("runtime/BuildInfo.plist")), 0o600);
    assert!(!update.paths.base.join("update-transaction.json").exists());
}
#[test]
fn failed_mock_health_restores_old_bytes_and_permissions() {
    let f = Fixture::new(); let (archive, release) = f.archive(&contents(), 0o644);
    verify_extract(&archive, &f.destination(), &release).unwrap();
    let mut update = updater(&f, true);
    let engine = update.paths.watch.join("runtime/watch-engine");
    let main = update.paths.app.join("Contents/MacOS/ClaudeWatchMonitor");
    put(&engine, b"old engine", 0o750); put(&main, b"old main", 0o750);
    put(&update.paths.backend, b"legacy untouched", 0o640);
    assert_eq!(update.apply_payload(&f.destination(), &release).unwrap_err().code, "fixture_health_failed");
    assert_eq!(fs::read(&engine).unwrap(), b"old engine"); assert_eq!(mode(&engine), 0o750);
    assert_eq!(fs::read(&main).unwrap(), b"old main"); assert_eq!(mode(&main), 0o750);
    assert_eq!(fs::read(&update.paths.backend).unwrap(), b"legacy untouched");
    assert!(!update.paths.base.join("update-transaction.json").exists());
}
