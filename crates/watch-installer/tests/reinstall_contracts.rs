//! Contract tests ported one-for-one from the retired `reinstall_clean.py`
//! suite: every guard that protected the destructive steps must still hold.
use claude_watch_core::error::{CoreError, Result};
use claude_watch_installer::{flow, Layout, Output, RunMode, Runner};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn fixture_root() -> PathBuf {
    let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
    let root = PathBuf::from("/private/tmp").join(format!(
        "cw-reinstall-{}-{unique}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("fixture root");
    root
}

fn write_plist(path: &Path, value: Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("plist parent");
    }
    std::fs::write(path, serde_json::to_vec(&value).expect("plist body")).expect("plist write");
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("fixture read")).expect("fixture json")
}

fn make_app(path: &Path, version: &str, build: &str) {
    write_plist(
        &path.join("Contents/Info.plist"),
        json!({
            "CFBundleIdentifier": "io.local.watchpanel",
            "CFBundleExecutable": "ClaudeWatchMonitor",
            "CFBundleShortVersionString": version,
            "CFBundleVersion": build,
        }),
    );
    write_plist(
        &path.join("Contents/Resources/BuildInfo.plist"),
        json!({"BackendVariant": "rust-candidate", "Architecture": "arm64"}),
    );
    let engine = path.join("Contents/Resources/watch-engine");
    std::fs::write(&engine, b"fixture engine").expect("engine");
    set_mode(&engine, 0o700);
    std::fs::write(
        path.join("Contents/Resources/watch-admin.sh"),
        b"fixture helper",
    )
    .expect("helper");
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path).expect("mode metadata").permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(path, permissions).expect("mode set");
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("copy root");
    for entry in std::fs::read_dir(from).expect("copy read") {
        let entry = entry.expect("copy entry");
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy file");
            let mode = std::fs::metadata(entry.path()).expect("copy mode").permissions();
            std::fs::set_permissions(&target, mode).expect("copy chmod");
        }
    }
}

fn digest(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(std::fs::read(path).expect("digest read"));
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct Fake {
    layout: Layout,
    uid: u32,
    cargo: PathBuf,
    calls: RefCell<Vec<Vec<String>>>,
    prefs: Cell<bool>,
    fail: RefCell<String>,
    process_output: RefCell<String>,
    jobs: RefCell<BTreeMap<String, bool>>,
}

impl Fake {
    fn new(root: &Path) -> Self {
        let uid = unsafe { libc::getuid() };
        let home = root.join("home");
        std::fs::create_dir_all(&home).expect("home");
        let layout = Layout::new(
            home,
            root.join("Applications/Claude Watch Monitor.app"),
            root.join("Library/Application Support/ClaudeWatch"),
            root.join("Library/LaunchDaemons/io.local.claudewatch.timezone.plist"),
            root.join("project"),
            root.join("temp"),
            uid,
        );
        let fake = Self {
            layout,
            uid,
            cargo: root.join("cargo"),
            calls: RefCell::new(Vec::new()),
            prefs: Cell::new(true),
            fail: RefCell::new(String::new()),
            process_output: RefCell::new(String::new()),
            jobs: RefCell::new(BTreeMap::new()),
        };
        fake.seed();
        fake
    }

    fn seed(&self) {
        std::fs::create_dir_all(&self.layout.temporary).expect("temp");
        std::fs::create_dir_all(self.layout.trash()).expect("trash");
        std::fs::write(self.layout.trash().join("unrelated-user-file"), "keep trash")
            .expect("other trash");
        make_app(&self.layout.app, "3.0.0", "313");
        write_plist(
            &self.layout.agent(),
            json!({"Label": "io.local.claudewatch.agent"}),
        );
        std::fs::create_dir_all(&self.layout.system_root).expect("system root");
        std::fs::write(self.layout.helper(), b"fixture helper").expect("helper");
        set_mode(&self.layout.helper(), 0o755);
        std::fs::write(self.layout.system_root.join("timezone.target"), "Asia/Tokyo")
            .expect("timezone target");
        write_plist(
            &self.layout.system_plist,
            json!({
                "Label": "io.local.claudewatch.timezone",
                "ProgramArguments": [
                    "/usr/bin/env", "-i", "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                    "/bin/bash", "--noprofile", "--norc",
                    self.layout.helper().display().to_string(), "tick"
                ],
            }),
        );
        std::fs::create_dir_all(self.layout.base().join("switcher")).expect("base");
        std::fs::write(
            self.layout.base().join("switcher/config.json"),
            "watch settings",
        )
        .expect("settings");
        let prefs = self
            .layout
            .home
            .join("Library/Preferences/io.local.watchpanel.plist");
        if let Some(parent) = prefs.parent() {
            std::fs::create_dir_all(parent).expect("prefs parent");
        }
        std::fs::write(&prefs, "watch prefs").expect("prefs");
        for (relative, body) in [
            ("Library/Application Support/Claude/Cookies", "keep Claude login"),
            (".claude/credentials", "keep Claude CLI"),
            ("Library/Application Support/TAG/config.yaml", "keep TAG config"),
            (".claude-switcher/data", "keep original"),
        ] {
            let path = self.layout.home.join(relative);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("keep parent");
            std::fs::write(path, body).expect("keep file");
        }
        let service = self
            .layout
            .project
            .parent()
            .expect("project parent")
            .join("Library/LaunchDaemons/local.claude-bodyguard.plist");
        std::fs::create_dir_all(service.parent().expect("service parent")).expect("service dir");
        std::fs::write(service, "keep original service").expect("service");
        for relative in [
            "monitor/package-dmg.sh",
            "monitor/build.sh",
            "monitor/network-backend.sh",
            "tools/build-rust-components.sh",
            "target/aarch64-apple-darwin/release/watch-gateway-broker",
            "Cargo.toml",
            "Cargo.lock",
            "monitor/Resources/AppIcon.icns",
            "monitor/macos-minimum.txt",
        ] {
            let path = self.layout.project.join(relative);
            std::fs::create_dir_all(path.parent().expect("build parent")).expect("build dir");
            std::fs::write(path, "fixture build input").expect("build input");
        }
        set_mode(&self.layout.project.join("target/aarch64-apple-darwin/release/watch-gateway-broker"),0o700);
        std::fs::write(&self.cargo, "fixture cargo").expect("cargo");
        set_mode(&self.cargo, 0o700);
        let mut jobs = self.jobs.borrow_mut();
        jobs.insert(self.layout.agent_label(self.uid), true);
        jobs.insert(self.layout.updater_label(self.uid), false);
        jobs.insert(self.layout.helper_label(), true);
    }

    fn set_job(&self, label: &str, value: bool) {
        self.jobs.borrow_mut().insert(label.to_string(), value);
    }

    fn set_fail(&self, value: &str) {
        *self.fail.borrow_mut() = value.to_string();
    }

    fn calls(&self) -> Vec<Vec<String>> {
        self.calls.borrow().clone()
    }

    fn identity(&self, app: &Path) -> (String, String) {
        let info = read_json(&app.join("Contents/Info.plist"));
        (
            info["CFBundleShortVersionString"]
                .as_str()
                .unwrap_or_default()
                .into(),
            info["CFBundleVersion"].as_str().unwrap_or_default().into(),
        )
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.layout.home);
    }
}

fn result(status: i32, out: &str, err: &str) -> Output {
    Output {
        status,
        stdout: out.into(),
        stderr: err.into(),
    }
}

impl Runner for Fake {
    fn locate(&self, name: &str) -> Option<PathBuf> {
        if *self.fail.borrow() == "toolchain" {
            return None;
        }
        Some(PathBuf::from("/fixture").join(name))
    }

    fn run(
        &self,
        args: &[String],
        env: Option<&BTreeMap<String, String>>,
        _mode: RunMode,
    ) -> Result<Output> {
        self.calls.borrow_mut().push(args.to_vec());
        let command = args[0].as_str();
        let fail = self.fail.borrow().clone();
        match command {
            "/bin/ps" => Ok(result(0, &self.process_output.borrow(), "")),
            "/bin/date" => Ok(result(0, "20261103-010101\n", "")),
            "/fixture/xcrun" => Ok(result(
                0,
                if args.get(1).map(String::as_str) == Some("--find") {
                    "/fixture/swiftc\n"
                } else {
                    "/fixture/macos-sdk\n"
                },
                "",
            )),
            "/bin/launchctl" => {
                let sub = args.get(1).map(String::as_str).unwrap_or_default();
                let label = args.get(2).map(String::as_str).unwrap_or_default().to_string();
                if sub == "bootout" {
                    // A real bootout stops the job, so later reads must agree.
                    self.jobs.borrow_mut().insert(label, false);
                    return Ok(result(0, "", ""));
                }
                let loaded = self.jobs.borrow().get(&label).copied().unwrap_or(false);
                Ok(result(if loaded { 0 } else { 113 }, "", ""))
            }
            "/usr/bin/plutil" => {
                let path = args.last().expect("plutil path");
                match std::fs::read_to_string(path) {
                    Ok(body) => Ok(result(0, &body, "")),
                    Err(_) => Ok(result(1, "", "No such file")),
                }
            }
            "/usr/bin/codesign" => Ok(result(
                if fail == "codesign" { 1 } else { 0 },
                "",
                "",
            )),
            "/usr/bin/defaults" => {
                if args.get(1).map(String::as_str) == Some("read") {
                    if self.prefs.get() {
                        Ok(result(0, "", ""))
                    } else {
                        Ok(result(1, "", "Error: Domain not found."))
                    }
                } else {
                    self.prefs.set(false);
                    Ok(result(0, "", ""))
                }
            }
            "/usr/bin/sudo" => {
                if fail == "admin" {
                    return Ok(result(1, "", ""));
                }
                if let Ok(entries) = std::fs::read_dir(&self.layout.system_root) {
                    for entry in entries.flatten() {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
                let _ = std::fs::remove_dir(&self.layout.system_root);
                let _ = std::fs::remove_file(&self.layout.system_plist);
                self.set_job(&self.layout.helper_label(), false);
                Ok(result(0, "", ""))
            }
            "/bin/bash" => {
                if fail == "package" {
                    return Ok(result(1, "", ""));
                }
                let env = env.ok_or_else(|| CoreError::new("fixture", "missing env"))?;
                let app_out = PathBuf::from(env.get("CW_APP_OUTPUT").expect("app out"));
                make_app(
                    &app_out,
                    env.get("APP_VERSION").expect("version"),
                    env.get("BUILD_NUMBER").expect("build"),
                );
                let dmg = self
                    .layout
                    .project
                    .join("monitor/dist")
                    .join(env.get("DMG_NAME").expect("dmg name"));
                std::fs::create_dir_all(dmg.parent().expect("dmg parent")).expect("dist");
                std::fs::write(&dmg, b"fixture dmg").expect("dmg");
                let mut checksum = digest(&dmg);
                if fail == "checksum" {
                    checksum = "0".repeat(64);
                }
                std::fs::write(
                    PathBuf::from(format!("{}.sha256", dmg.display())),
                    format!("{checksum}  {}\n", dmg.file_name().unwrap().to_string_lossy()),
                )
                .expect("sha");
                if fail == "reappeared" {
                    make_app(&self.layout.app, "9.9.9", "999");
                }
                Ok(result(0, "", ""))
            }
            "/usr/bin/open" => Ok(result(0, "", "")),
            _ if args.get(1).map(String::as_str) == Some("app-uninstall") => {
                if !args.iter().any(|value| value == "--apply") {
                    return Ok(result(
                        0,
                        &json!({
                            "status": "preview",
                            "action": "app-uninstall",
                            "installed": self.layout.app.display().to_string(),
                        })
                        .to_string(),
                        "",
                    ));
                }
                if fail == "uninstall" {
                    return Ok(result(
                        4,
                        &json!({"status": "error", "message": "fixture"}).to_string(),
                        "",
                    ));
                }
                let removed = self
                    .layout
                    .trash()
                    .join(format!("ClaudeWatch-removed-{}", "a".repeat(32)));
                std::fs::create_dir_all(&removed).expect("removed");
                let old = removed.join("Claude Watch Monitor.app");
                copy_dir(&self.layout.app, &old);
                std::fs::remove_dir_all(&self.layout.app).expect("remove app");
                if self.layout.agent().exists() {
                    std::fs::rename(self.layout.agent(), removed.join("io.local.claudewatch.agent.plist"))
                        .expect("move agent");
                }
                self.set_job(&self.layout.agent_label(self.uid), false);
                Ok(result(
                    0,
                    &json!({
                        "status": "ok",
                        "action": "app-uninstall",
                        "previous": old.display().to_string(),
                    })
                    .to_string(),
                    "",
                ))
            }
            _ if args.get(1).map(String::as_str) == Some("--service-preview") => {
                if fail == "gateway_unknown" { return Ok(result(78,"","unknown gateway identity")); }
                Ok(result(0,&json!({"status":"preview","action":"install","administrator_required":true,"gateway_port":1023,"previous_config":"absent"}).to_string(),""))
            }
            _ if args.get(1).map(String::as_str) == Some("app-install") => {
                let source = PathBuf::from(args.get(3).expect("source"));
                if !args.iter().any(|value| value == "--apply") {
                    return Ok(result(
                        0,
                        &json!({
                            "status": "preview",
                            "source": source.display().to_string(),
                            "installed": self.layout.app.display().to_string(),
                        })
                        .to_string(),
                        "",
                    ));
                }
                if fail == "install" {
                    return Ok(result(
                        4,
                        &json!({"status": "error", "message": "fixture"}).to_string(),
                        "",
                    ));
                }
                copy_dir(&source, &self.layout.app);
                write_plist(
                    &self.layout.agent(),
                    json!({"Label": "io.local.claudewatch.agent"}),
                );
                self.set_job(&self.layout.agent_label(self.uid), true);
                let (version, build) = self.identity(&self.layout.app);
                Ok(result(
                    0,
                    &json!({
                        "status": "ok",
                        "version": version,
                        "build": build,
                        "architecture": "arm64",
                    })
                    .to_string(),
                    "",
                ))
            }
            other => panic!("unexpected command: {other}, args: {args:?}"),
        }
    }
}

struct Harness {
    root: PathBuf,
    fake: Fake,
}

impl Harness {
    fn new() -> Self {
        let root = fixture_root();
        let fake = Fake::new(&root);
        Self { root, fake }
    }
    fn perform(&self, version: &str, build: &str, dry: bool, answer: &str) -> Result<flow::Outcome> {
        let mut confirm = |_: &str| Ok(answer.to_string());
        flow::perform(
            &self.fake.layout,
            &self.fake,
            version,
            build,
            dry,
            &mut confirm,
            self.fake.uid,
            &self.fake.cargo,
            &|_: Duration| {},
        )
    }
    fn perform_with<F>(&self, confirm: &mut F) -> Result<flow::Outcome>
    where
        F: FnMut(&str) -> Result<String>,
    {
        flow::perform(
            &self.fake.layout,
            &self.fake,
            "3.0.0",
            "314",
            false,
            confirm,
            self.fake.uid,
            &self.fake.cargo,
            &|_: Duration| {},
        )
    }
    fn assert_preserved(&self) {
        for (relative, body) in [
            ("Library/Application Support/Claude/Cookies", "keep Claude login"),
            (".claude/credentials", "keep Claude CLI"),
            ("Library/Application Support/TAG/config.yaml", "keep TAG config"),
            (".claude-switcher/data", "keep original"),
        ] {
            let path = self.fake.layout.home.join(relative);
            assert_eq!(
                std::fs::read_to_string(&path).expect(relative),
                body,
                "{relative} must be preserved"
            );
        }
        let service = self
            .fake
            .layout
            .project
            .parent()
            .expect("project parent")
            .join("Library/LaunchDaemons/local.claude-bodyguard.plist");
        assert_eq!(
            std::fs::read_to_string(service).expect("original service"),
            "keep original service"
        );
        assert_eq!(
            std::fs::read_to_string(self.fake.layout.trash().join("unrelated-user-file"))
                .expect("unrelated trash"),
            "keep trash"
        );
    }
    fn blocked<T: std::fmt::Debug>(&self, outcome: Result<T>, needle: &str) {
        let error = outcome.expect_err("flow must stop");
        assert!(
            error.message.contains(needle),
            "expected {needle:?}, got {:?}",
            error.message
        );
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn full_workflow_removes_only_watch_data_and_installs_requested_build() {
    let h = Harness::new();
    let old_artifact = h
        .fake
        .layout
        .project
        .join("monitor/build/Claude Watch Monitor build313.app");
    std::fs::create_dir_all(&old_artifact).expect("old artifact");
    std::fs::write(old_artifact.join("keep"), "previous output").expect("keep");
    h.perform("3.0.0", "314", false, "y").expect("flow");
    assert_eq!(h.fake.identity(&h.fake.layout.app), ("3.0.0".into(), "314".into()));
    assert!(!h.fake.layout.base().exists());
    assert!(!h
        .fake
        .layout
        .home
        .join("Library/Preferences/io.local.watchpanel.plist")
        .exists());
    assert!(!h.fake.layout.system_root.exists());
    let removed: Vec<_> = std::fs::read_dir(h.fake.layout.trash())
        .expect("trash")
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("ClaudeWatch-removed-")
        })
        .collect();
    assert!(removed.is_empty(), "removed directory must be deleted");
    assert_eq!(
        std::fs::read_to_string(old_artifact.join("keep")).expect("old artifact"),
        "previous output"
    );
    let packages: Vec<_> = std::fs::read_dir(h.fake.layout.project.join("monitor/dist"))
        .expect("dist")
        .flatten()
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.contains("build314") && name.ends_with(".dmg")
        })
        .collect();
    assert_eq!(packages.len(), 1, "exactly one package");
    h.assert_preserved();
}

#[test]
fn preview_and_cancel_are_read_only() {
    let h = Harness::new();
    assert_eq!(
        h.perform("3.0.0", "314", true, "y").expect("dry run"),
        flow::Outcome::DryRun,
        "a preview never reports an install"
    );
    assert_eq!(
        h.perform("3.0.0", "314", false, "取消").expect("cancel"),
        flow::Outcome::Cancelled,
        "declining the prompt is a cancel, not an install"
    );
    assert!(h.fake.layout.app.exists());
    assert!(h.fake.layout.base().exists());
    let forbidden = h.fake.calls().into_iter().any(|call| {
        call.iter().any(|value| value == "--apply")
            || matches!(call[0].as_str(), "/usr/bin/sudo" | "/bin/bash" | "/usr/bin/open")
    });
    assert!(!forbidden, "read-only paths must not mutate");
    assert_eq!(
        std::fs::read_dir(&h.fake.layout.temporary)
            .expect("temporary")
            .count(),
        0,
        "no lock file left behind"
    );
    h.assert_preserved();
}

#[test]
fn pending_transaction_blocks_before_uninstall() {
    let h = Harness::new();
    std::fs::write(
        h.fake.layout.base().join("switcher/transaction.json"),
        "{}",
    )
    .expect("transaction");
    h.blocked(h.perform("3.0.0", "314", false, "y"), "未完成");
    assert!(h.fake.layout.app.exists());
    assert!(h.fake.layout.base().exists());
    assert!(!h
        .fake
        .calls()
        .iter()
        .any(|call| call.iter().any(|value| value == "--apply")));
    h.assert_preserved();
}

#[test]
fn active_update_and_other_package_are_not_interrupted() {
    let h = Harness::new();
    let label = h.fake.layout.updater_label(h.fake.uid);
    h.fake.set_job(&label, true);
    h.blocked(h.perform("3.0.0", "314", false, "y"), "更新任务");
    h.fake.set_job(&label, false);
    *h.fake.process_output.borrow_mut() =
        format!("{} /bin/bash monitor/package-dmg.sh\n", h.fake.uid);
    h.blocked(h.perform("3.0.0", "314", false, "y"), "正在进行");
    assert!(h.fake.layout.app.exists());
    h.assert_preserved();
}

#[test]
fn symlink_and_mismatched_helper_stop_before_any_uninstall() {
    let h = Harness::new();
    let claude = h
        .fake
        .layout
        .home
        .join("Library/Application Support/Claude");
    std::fs::remove_dir_all(h.fake.layout.base()).expect("base");
    std::os::unix::fs::symlink(&claude, h.fake.layout.base()).expect("symlink");
    h.blocked(h.perform("3.0.0", "314", false, "y"), "符号链接");
    std::fs::remove_file(h.fake.layout.base()).expect("unlink");
    std::fs::create_dir_all(h.fake.layout.base().join("switcher")).expect("base");
    std::fs::write(h.fake.layout.helper(), b"different").expect("helper");
    h.blocked(h.perform("3.0.0", "314", false, "y"), "不一致");
    assert!(h.fake.layout.app.exists());
    h.assert_preserved();
}

#[test]
fn admin_failure_stops_with_watch_data_intact() {
    let h = Harness::new();
    h.fake.set_fail("admin");
    h.blocked(h.perform("3.0.0", "314", false, "y"), "数据保留");
    assert!(!h.fake.layout.app.exists());
    assert!(h.fake.layout.base().exists());
    assert!(h
        .fake
        .layout
        .home
        .join("Library/Preferences/io.local.watchpanel.plist")
        .exists());
    assert!(!h.fake.calls().iter().any(|call| call[0] == "/bin/bash"));
    h.assert_preserved();
}

#[test]
fn no_system_helper_is_supported() {
    let h = Harness::new();
    std::fs::remove_dir_all(&h.fake.layout.system_root).expect("system root");
    std::fs::remove_file(&h.fake.layout.system_plist).expect("plist");
    h.fake.set_job(&h.fake.layout.helper_label(), false);
    h.perform("3.0.0", "314", false, "y").expect("flow");
    assert_eq!(h.fake.identity(&h.fake.layout.app), ("3.0.0".into(), "314".into()));
    assert!(!h.fake.calls().iter().any(|call| call[0] == "/usr/bin/sudo"));
    h.assert_preserved();
}

#[test]
fn already_clean_system_can_build_without_repeating_uninstall() {
    let h = Harness::new();
    std::fs::remove_dir_all(&h.fake.layout.app).expect("app");
    std::fs::remove_dir_all(h.fake.layout.base()).expect("base");
    std::fs::remove_file(
        h.fake
            .layout
            .home
            .join("Library/Preferences/io.local.watchpanel.plist"),
    )
    .expect("prefs");
    std::fs::remove_file(h.fake.layout.agent()).expect("agent");
    std::fs::remove_dir_all(&h.fake.layout.system_root).expect("system root");
    std::fs::remove_file(&h.fake.layout.system_plist).expect("plist");
    h.fake.set_job(&h.fake.layout.agent_label(h.fake.uid), false);
    h.fake.set_job(&h.fake.layout.helper_label(), false);
    h.fake.prefs.set(false);
    h.perform("3.0.0", "314", false, "y").expect("flow");
    assert_eq!(h.fake.identity(&h.fake.layout.app), ("3.0.0".into(), "314".into()));
    assert!(!h
        .fake
        .calls()
        .iter()
        .any(|call| call.iter().any(|value| value == "app-uninstall")));
    h.assert_preserved();
}

#[test]
fn running_claude_and_unknown_system_files_block_before_uninstall() {
    let h = Harness::new();
    *h.fake.process_output.borrow_mut() = format!(
        "{} /Applications/Claude.app/Contents/MacOS/Claude\n",
        h.fake.uid
    );
    h.blocked(h.perform("3.0.0", "314", false, "y"), "退出 Claude");
    h.fake.process_output.borrow_mut().clear();
    std::fs::write(h.fake.layout.system_root.join("unknown"), "do not remove").expect("unknown");
    h.blocked(h.perform("3.0.0", "314", false, "y"), "未知文件");
    assert!(h.fake.layout.app.exists());
    assert!(h.fake.layout.system_root.join("unknown").exists());
    h.assert_preserved();
}

#[test]
fn uninstall_failure_does_not_clean_or_package() {
    let h = Harness::new();
    h.fake.set_fail("uninstall");
    h.blocked(h.perform("3.0.0", "314", false, "y"), "执行失败");
    assert!(h.fake.layout.app.exists());
    assert!(h.fake.layout.base().exists());
    assert!(!h
        .fake
        .calls()
        .iter()
        .any(|call| matches!(call[0].as_str(), "/usr/bin/sudo" | "/bin/bash")));
    h.assert_preserved();
}

#[test]
fn watch_process_that_does_not_exit_is_not_killed_or_cleaned() {
    let h = Harness::new();
    *h.fake.process_output.borrow_mut() = format!(
        "{} {}/runtime/watch-engine daemon\n",
        h.fake.uid,
        h.fake.layout.base().display()
    );
    h.blocked(h.perform("3.0.0", "314", false, "y"), "尚未退出");
    assert!(h.fake.layout.base().exists());
    assert!(h
        .fake
        .layout
        .home
        .join("Library/Preferences/io.local.watchpanel.plist")
        .exists());
    assert!(!h.fake.calls().iter().any(|call| call[0] == "/bin/bash"));
    assert!(!h.fake.calls().iter().any(|call| call[0].contains("kill")));
    h.assert_preserved();
}

#[test]
fn missing_build_dependency_stops_before_any_uninstall() {
    let h = Harness::new();
    std::fs::remove_file(&h.fake.cargo).expect("cargo");
    h.blocked(h.perform("3.0.0", "314", false, "y"), "Cargo");
    assert!(h.fake.layout.app.exists());
    assert!(h.fake.layout.base().exists());
    assert!(h.fake.calls().is_empty());
    h.assert_preserved();
}

#[test]
fn missing_macos_minimum_stops_before_any_uninstall() {
    let h = Harness::new();
    std::fs::remove_file(h.fake.layout.project.join("monitor/macos-minimum.txt"))
        .expect("minimum");
    h.blocked(h.perform("3.0.0", "314", false, "y"), "打包脚本");
    assert!(h.fake.layout.app.exists());
    assert!(h.fake.layout.base().exists());
    assert!(h.fake.calls().is_empty());
    h.assert_preserved();
}

#[test]
fn missing_network_backend_helper_stops_before_confirmation_or_uninstall() {
    let h = Harness::new();
    std::fs::remove_file(h.fake.layout.project.join("monitor/network-backend.sh"))
        .expect("network backend helper");
    h.blocked(h.perform_with(&mut |_| panic!("missing helper must stop before confirmation")), "打包脚本");
    assert!(h.fake.layout.app.exists());
    assert!(h.fake.layout.base().exists());
    assert!(h.fake.calls().is_empty());
    h.assert_preserved();
}

#[test]
fn missing_toolchain_stops_before_any_uninstall() {
    let h = Harness::new();
    h.fake.set_fail("toolchain");
    h.blocked(h.perform("3.0.0", "314", false, "y"), "系统工具");
    assert!(h.fake.layout.app.exists());
    assert!(h.fake.layout.base().exists());
    assert!(h.fake.calls().is_empty());
    h.assert_preserved();
}

#[test]
fn install_failure_never_opens_application_or_deletes_package() {
    let h = Harness::new();
    h.fake.set_fail("install");
    h.blocked(h.perform("3.0.0", "314", false, "y"), "执行失败");
    assert!(!h.fake.calls().iter().any(|call| call[0] == "/usr/bin/open"));
    let packages = std::fs::read_dir(h.fake.layout.project.join("monitor/dist"))
        .expect("dist")
        .flatten()
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.contains("build314") && name.ends_with(".dmg")
        })
        .count();
    assert_eq!(packages, 1);
    h.assert_preserved();
}

#[test]
fn invalid_version_is_rejected_without_calling_system_tools() {
    let h = Harness::new();
    h.blocked(h.perform("3.0.0", "314;unsafe", true, ""), "build");
    assert!(h.fake.calls().is_empty());
}

#[test]
fn build_and_checksum_failure_never_install() {
    let h = Harness::new();
    h.fake.set_fail("package");
    h.blocked(h.perform("3.0.0", "314", false, "y"), "未执行安装");
    assert!(!h
        .fake
        .calls()
        .iter()
        .any(|call| call.iter().any(|value| value == "app-install")));
    h.assert_preserved();
}

#[test]
fn checksum_mismatch_never_installs() {
    let h = Harness::new();
    h.fake.set_fail("checksum");
    h.blocked(h.perform("3.0.0", "314", false, "y"), "校验不匹配");
    assert!(!h
        .fake
        .calls()
        .iter()
        .any(|call| call.iter().any(|value| value == "app-install")));
    h.assert_preserved();
}

#[test]
fn app_created_during_build_is_not_replaced() {
    let h = Harness::new();
    h.fake.set_fail("reappeared");
    h.blocked(h.perform("3.0.0", "314", false, "y"), "发生变化");
    assert_eq!(h.fake.identity(&h.fake.layout.app), ("9.9.9".into(), "999".into()));
    assert!(!h
        .fake
        .calls()
        .iter()
        .any(|call| call.iter().any(|value| value == "app-install")));
    h.assert_preserved();
}

#[test]
fn missing_app_with_residual_data_is_cleaned_and_reinstalled() {
    // A stopped run leaves the app gone and Watch's own data behind. That is
    // the state this flow must be able to recover from, so the leftover is
    // cleaned instead of blocking the machine without an app.
    let h = Harness::new();
    std::fs::remove_dir_all(&h.fake.layout.app).expect("app");
    assert_eq!(
        h.perform("3.0.0", "314", false, "y").expect("flow"),
        flow::Outcome::Installed
    );
    assert_eq!(
        h.fake.identity(&h.fake.layout.app),
        ("3.0.0".into(), "314".into())
    );
    assert!(!h.fake.layout.base().exists());
    h.assert_preserved();
}

#[test]
fn current_state_change_after_confirmation_stops() {
    let h = Harness::new();
    let app = h.fake.layout.app.clone();
    let mut confirm = move |_: &str| {
        make_app(&app, "3.0.0", "999");
        Ok("y".to_string())
    };
    h.blocked(h.perform_with(&mut confirm), "发生变化");
    assert!(h.fake.layout.app.exists());
    assert!(h.fake.layout.base().exists());
    h.assert_preserved();
}

#[test]
fn leftovers_of_the_retired_copy_do_not_block_a_fresh_install() {
    // Repro of the reinstall that stalled after data cleanup: the bundle and
    // the data directory were already gone, but a process started from the
    // old paths was still listed. Blocking there leaves the machine without
    // an app at all, so a retired leftover must be reported, not obeyed.
    let h = Harness::new();
    std::fs::remove_dir_all(&h.fake.layout.app).expect("app removed");
    std::fs::remove_dir_all(h.fake.layout.base()).expect("data removed");
    *h.fake.process_output.borrow_mut() = format!(
        "{} {}/runtime/watch-engine daemon\n",
        h.fake.uid,
        h.fake.layout.base().display()
    );
    assert_eq!(
        h.perform("3.0.0", "314", false, "y").expect("flow must finish"),
        flow::Outcome::Installed
    );
    assert_eq!(
        h.fake.identity(&h.fake.layout.app),
        ("3.0.0".into(), "314".into())
    );
}

#[test]
fn unknown_gateway_blocks_before_confirmation_uninstall_or_package() {
    let h=Harness::new();h.fake.set_fail("gateway_unknown");
    let mut asked=false;
    let outcome=h.perform_with(&mut |_| {asked=true;Ok("y".into())});
    assert!(outcome.is_err());assert!(!asked);
    assert!(h.fake.layout.app.exists());h.assert_preserved();
    assert!(!h.fake.calls().iter().any(|c| c.iter().any(|a|a=="--apply"||a.ends_with("package-dmg.sh"))));
}

#[test]
fn reinstall_confirmation_explicitly_names_administrator_gateway_operations() {
    let h=Harness::new();let mut prompt=String::new();
    let outcome=h.perform_with(&mut |p|{prompt=p.into();Ok("n".into())}).unwrap();
    assert!(matches!(outcome,flow::Outcome::Cancelled));assert!(prompt.contains("管理员网关操作"));
    assert!(h.fake.calls().iter().any(|c| c.get(1).map(String::as_str)==Some("--service-preview")));
    assert!(h.fake.layout.app.exists());h.assert_preserved();
}
