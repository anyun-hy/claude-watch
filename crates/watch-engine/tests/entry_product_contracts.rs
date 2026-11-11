#![cfg(target_os = "macos")]
use claude_watch_runtime::{
    native,
    storage::{Paths, StateStore},
};
use claude_watch_system::{inspect_process_identity, sha256_file_hex};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Output},
    time::{Duration, Instant},
};

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path =
            PathBuf::from("/private/tmp").join(format!("cw-v2-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn show(label: &str, result: &Output) {
    println!(
        "{label}: {}\nstdout: {}\nstderr: {}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
fn response(label: &str, result: Output) -> Value {
    show(label, &result);
    serde_json::from_slice(&result.stdout).unwrap_or_else(|_| panic!("{label} returned no JSON"))
}
fn write_plist(path: &Path, data: Value) {
    let temporary = path.with_extension("fixture-json");
    fs::write(&temporary, serde_json::to_vec(&data).unwrap()).unwrap();
    let out = Command::new("/usr/bin/plutil")
        .args(["-convert", "xml1", "-o"])
        .arg(path)
        .arg(&temporary)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    fs::remove_file(temporary).unwrap();
}
fn manifest(resources: &Path, components: &[&str]) {
    let hashes = components
        .iter()
        .map(|name| (*name, sha256_file_hex(&resources.join(name)).unwrap()))
        .collect::<std::collections::BTreeMap<_, _>>();
    write_plist(
        &resources.join("BuildInfo.plist"),
        json!({"Architecture":"arm64","NetworkBackend":"seatbelt","RuntimeHashes":hashes}),
    );
}

#[test]
fn v2_product_entry_uses_selected_source_and_native_component_with_no_system_writes() {
    let root = Root::new();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let home = root.0.join("home");
    let resources = root.0.join("Runtime");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&resources).unwrap();
    let engine = resources.join("watch-engine");
    fs::copy(env!("CARGO_BIN_EXE_claude-watch-engine"), &engine).unwrap();
    let helper = repo.join("target/debug/watch-sandbox-launcher");
    fs::copy(helper, resources.join("watch-sandbox-launcher")).unwrap();
    fs::copy(
        native::built_observer_path().unwrap(),
        resources.join("watch-native-observer"),
    )
    .unwrap();
    fs::copy(
        native::built_process_control_path().unwrap(),
        resources.join("watch-process-control"),
    )
    .unwrap();
    let core_components = [
        "watch-engine",
        "watch-sandbox-launcher",
        "watch-process-control",
    ];
    manifest(&resources, &core_components);

    let originals = home.join("Applications");
    let app = originals.join("Claude.app");
    let exe = app.join("Contents/MacOS/Claude");
    fs::create_dir_all(exe.parent().unwrap()).unwrap();
    let source = root.0.join("original-fixture.c");
    fs::write(
        &source,
        b"#include <unistd.h>\nint main(void){for(;;)pause();}\n",
    )
    .unwrap();
    let compile = Command::new("xcrun")
        .args(["clang", "-O0", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&exe)
        .output()
        .unwrap();
    show("private original application executable", &compile);
    assert!(compile.status.success());
    let original_bytes = fs::read(&exe).unwrap();
    write_plist(
        &app.join("Contents/Info.plist"),
        json!({"CFBundleIdentifier":"com.anthropic.claudefordesktop",
        "CFBundleName":"Claude","CFBundleExecutable":"Claude","CFBundlePackageType":"APPL"}),
    );
    let bin = home.join(".local/bin");
    let version = home.join(".local/share/claude/versions/fixture");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(version.parent().unwrap()).unwrap();
    fs::copy("/bin/sleep", &version).unwrap();
    std::os::unix::fs::symlink(&version, bin.join("claude")).unwrap();
    let rc = home.join(".zshrc");
    let original_rc = b"# private user bytes\n";
    fs::write(&rc, original_rc).unwrap();
    let output_apps = home.join("Private Entries");
    let entry = |action: &str, target: &str, extra: &[&str]| -> Output {
        let mut command = Command::new(&engine);
        command
            .env_clear()
            .env("HOME", &home)
            .env(
                "PATH",
                std::env::join_paths([bin.as_path(), Path::new("/usr/bin"), Path::new("/bin")])
                    .unwrap(),
            )
            .args(["entry", action, "--home"])
            .arg(&home)
            .args(["--target", target]);
        if target.ends_with("-desktop") {
            command.arg("--applications-dir").arg(&output_apps);
            if action != "deactivate" {
                command.arg("--target-bundle").arg(&app);
            }
        }
        command.args(extra).output().unwrap()
    };

    let preview = response(
        "real CLI preview",
        entry("preview", "claude-cli", &["--shell", "zsh"]),
    );
    assert_eq!(preview["status"], "ok");
    assert_eq!(
        preview["preview"]["target_executable"],
        version.to_str().unwrap()
    );
    assert_eq!(
        preview["preview"]["shell_config_path"],
        rc.to_str().unwrap()
    );
    let shim = PathBuf::from(preview["preview"]["destination_path"].as_str().unwrap());
    assert!(!shim.exists());
    assert!(!home.join("Library").exists(), "preview must be read-only");
    assert_eq!(fs::read(&rc).unwrap(), original_rc);
    let preview_desktop = response(
        "real desktop preview",
        entry("preview", "claude-desktop", &[]),
    );
    assert_eq!(
        preview_desktop["preview"]["target_bundle_path"],
        app.to_str().unwrap()
    );
    assert!(!output_apps.exists());

    let missing = response(
        "missing real ControlledEntry",
        entry("activate", "claude-desktop", &["--apply"]),
    );
    assert_eq!(missing["code"], "entry_component_unverified");
    assert!(!output_apps.exists());
    let unapproved = response(
        "activation requires explicit apply",
        entry("activate", "claude-cli", &["--shell", "zsh"]),
    );
    assert_ne!(unapproved["status"], "ok");
    assert!(!shim.exists());

    let generated = response(
        "CLI generation without shell opt-in",
        entry("activate", "claude-cli", &["--apply"]),
    );
    assert_eq!(generated["result"]["activation_configured"], false);
    assert_eq!(fs::read(&rc).unwrap(), original_rc);
    let active = response(
        "CLI opt-in with zsh reference",
        entry("activate", "claude-cli", &["--apply", "--shell", "zsh"]),
    );
    assert_eq!(active["result"]["activation_configured"], true);
    let status = response(
        "current PATH points to original first",
        entry("status", "claude-cli", &[]),
    );
    assert_eq!(
        status["status_report"]["shell_resolution"],
        "earlier_path_candidate"
    );
    assert_eq!(
        status["status_report"]["current_invocation_verified"],
        false
    );

    // A private interactive-shell configuration can be loaded while a
    // higher-priority function still wins. Product status cannot infer it.
    let shell = Command::new("/bin/zsh")
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .args([
            "-dfc",
            "source \"$1\"; claude() { print private-function; }; whence -w claude; claude",
            "fixture",
        ])
        .arg(&rc)
        .output()
        .unwrap();
    show("isolated zsh function precedence", &shell);
    assert!(
        shell.status.success()
            && String::from_utf8_lossy(&shell.stdout).contains("claude: function")
    );

    // Simulate a second caller while the same operation lock is held.
    let store = StateStore::new(Paths::new(&home).unwrap());
    let lock = store.lock("managed-entry", None).unwrap();
    let before = fs::read(&shim).unwrap();
    let busy = response(
        "concurrent entry operation",
        entry("activate", "claude-cli", &["--apply"]),
    );
    assert_eq!(busy["code"], "busy");
    assert_eq!(fs::read(&shim).unwrap(), before);
    drop(lock);

    // Execute the generated shim with only fixture state. The real product
    // must stop before launch while its collection backend is absent.
    let refused = Command::new(&shim)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .arg("private argument")
        .output()
        .unwrap();
    show("generated CLI reaches guarded product launch", &refused);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stdout).contains("backend_unhealthy")
            || String::from_utf8_lossy(&refused.stderr).contains("backend_unhealthy")
    );
    assert_eq!(
        response(
            "CLI deactivation",
            entry("deactivate", "claude-cli", &["--apply"])
        )["result"]["was_present"],
        true
    );
    assert_eq!(fs::read(&rc).unwrap(), original_rc);
    assert!(!shim.exists());

    let wrapper_component = resources.join("ControlledEntry");
    let compiled = Command::new("xcrun")
        .args([
            "--sdk",
            "macosx",
            "swiftc",
            "-parse-as-library",
            "-target",
            "arm64-apple-macosx26.0",
            "-module-cache-path",
        ])
        .arg(root.0.join("swift-cache"))
        .arg(repo.join("monitor/ControlledEntry/ControlledEntryApp.swift"))
        .arg(repo.join("monitor/Sources/BoundedDiagnosticLog.swift"))
        .arg("-o")
        .arg(&wrapper_component)
        .output()
        .unwrap();
    show("production AppKit component compile", &compiled);
    assert!(compiled.status.success());
    manifest(
        &resources,
        &[
            "watch-engine",
            "watch-sandbox-launcher",
            "watch-process-control",
            "ControlledEntry",
        ],
    );

    let mut original = OwnedChild(Command::new(&exe).arg("20").spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if inspect_process_identity(original.0.id())
            .is_some_and(|p| Path::new(&p.executable_path) == exe)
        {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let refused = response(
        "unmanaged original stays running",
        entry("activate", "claude-desktop", &["--apply"]),
    );
    assert_eq!(refused["code"], "already_running_unmanaged");
    assert!(original.0.try_wait().unwrap().is_none());
    drop(original);

    let activation = response(
        "native desktop entry activation",
        entry("activate", "claude-desktop", &["--apply"]),
    );
    assert_eq!(activation["status"], "ok");
    let wrapper = output_apps.join("Claude (Controlled).app");
    let wrapper_exe = wrapper.join("Contents/MacOS/ControlledEntry");
    assert_eq!(
        fs::read(&wrapper_exe).unwrap(),
        fs::read(&wrapper_component).unwrap()
    );
    let plist = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-"])
        .arg(wrapper.join("Contents/Info.plist"))
        .output()
        .unwrap();
    assert!(plist.status.success());
    let plist: Value = serde_json::from_slice(&plist.stdout).unwrap();
    assert_eq!(plist["CWWatchHomePath"], home.to_str().unwrap());
    assert_eq!(
        plist["CWWatchStateDirPath"],
        store.paths.watch().join("state").to_str().unwrap()
    );
    assert_eq!(plist["CWWatchBin"], engine.to_str().unwrap());
    assert_eq!(plist["CWTargetBundlePath"], app.to_str().unwrap());

    let ordinary_exe = root.0.join("ordinary-owned-process");
    fs::copy(&exe, &ordinary_exe).unwrap();
    let mut ordinary = OwnedChild(Command::new(&ordinary_exe).spawn().unwrap());
    let wrapper_run = Command::new(&wrapper_exe)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .arg("--reopen")
        .output()
        .unwrap();
    show(
        "native wrapper invokes real engine and stops at missing backend",
        &wrapper_run,
    );
    assert!(!wrapper_run.status.success());
    assert!(
        String::from_utf8_lossy(&wrapper_run.stdout).contains("backend_unhealthy")
            || String::from_utf8_lossy(&wrapper_run.stderr).contains("backend_unhealthy")
    );
    assert!(ordinary.0.try_wait().unwrap().is_none());
    assert!(claude_watch_runtime::managed_entry::snapshot_running_processes().unwrap()
        .iter().all(|process| Path::new(&process.executable) != exe));
    assert!(!store.paths.watch().join("state/managed-launch-instances.json").exists());
    assert_eq!(
        response(
            "desktop deactivation",
            entry("deactivate", "claude-desktop", &["--apply"])
        )["result"]["was_present"],
        true
    );
    assert!(!wrapper.exists());
    assert_eq!(fs::read(&exe).unwrap(), original_bytes);
    if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            Path::new(&dir).join("entry-product-wire.json"),
            serde_json::to_vec_pretty(&json!({
                "preview":preview_desktop,"activation":activation,"plist":plist,
                "isolated_wrapper_exit":wrapper_run.status.code(),"original_unchanged":true,
            }))
            .unwrap(),
        )
        .unwrap();
    }
}
