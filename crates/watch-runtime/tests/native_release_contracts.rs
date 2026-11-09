use claude_watch_core::error::{CoreError, Result};
use claude_watch_runtime::{
    app_lifecycle::{LifecycleOs, BUNDLE_ID},
    release_native::{
        FixedCommand, FixedCommandExecutor, FixedOutput, NativeRelease, NativeReleasePaths,
    },
    update::UpdateOs,
};
use std::{collections::VecDeque, fs, path::Path, time::Duration};
use uuid::Uuid;

#[derive(Default)]
struct Fake {
    calls: Vec<FixedCommand>,
    replies: VecDeque<FixedOutput>,
}
impl FixedCommandExecutor for Fake {
    fn run(&mut self, command: FixedCommand) -> Result<FixedOutput> {
        self.calls.push(command);
        self.replies
            .pop_front()
            .ok_or_else(|| CoreError::new("fixture", "missing reply"))
    }
}
fn ok(stdout: &str) -> FixedOutput {
    FixedOutput {
        status: 0,
        stdout: stdout.into(),
        stderr: String::new(),
    }
}
fn native(replies: Vec<FixedOutput>) -> NativeRelease<Fake> {
    NativeRelease::new(
        Fake {
            calls: vec![],
            replies: replies.into(),
        },
        NativeReleasePaths {
            base: "/base".into(),
            watch: "/watch".into(),
            backend: "/backend".into(),
        },
        501,
    )
}
#[test]
fn supervised_restart_uses_shared_snapshot_verifier_for_worker_health() {
    let home = std::env::temp_dir().join(format!("cw-supervised-health-{}", Uuid::new_v4()));
    fs::create_dir(&home).unwrap();
    let paths = NativeReleasePaths::derive(&home);
    fs::create_dir_all(paths.base.join("state")).unwrap();
    let now = claude_watch_runtime::native::now();
    let stamp = "Mon Oct 26 20:45:10 2026";
    let worker = serde_json::json!({"pid":102,"parent":100,"uid":501,"executable":paths.base.join("runtime/watch-engine"),"start_seconds":1000,"start_microseconds":1,"start_stamp":stamp});
    let inventory = serde_json::json!({"schema":1,"status":"ok","uid":501,"started_at":now,"finished_at":now,"state":"ok","truncated":false,"processes":[worker.clone()],"unavailable":[],"exited":[],"requested_count":1});
    let accepted = serde_json::json!({"health":{"state":"running","pid":102,"started":stamp}});
    let fake=Fake{calls:vec![],replies:vec![ok("state = running\npid = 77\n"),ok(""),ok("gui/501/io.local.claudewatch.agent = {\nstate = running\npid = 100\nresource coalition = {\nstate = active\n}\n}\n"),ok(&inventory.to_string()),ok(&accepted.to_string())].into()};
    let mut release = NativeRelease::new(fake, paths.clone(), 501);
    fs::write(
        paths.base.join("state/heartbeat"),
        format!("77|old|{now}|ok|GUARD\n"),
    )
    .unwrap();
    release.restart_agent().unwrap();
    fs::write(
        paths.base.join("state/heartbeat"),
        format!("102|{stamp}|{now}|ok|GUARD\n"),
    )
    .unwrap();
    fs::write(
        paths.base.join("state/runtime-snapshot.json"),
        serde_json::json!({"producer":worker}).to_string(),
    )
    .unwrap();
    assert!(release.agent_healthy().unwrap());
    let last = release.executor.calls.last().unwrap();
    assert_eq!(last.program, paths.base.join("runtime/watch-engine"));
    assert_eq!(last.args, ["--home", home.to_str().unwrap(), "snapshot"]);
    fs::remove_dir_all(home).unwrap();
}
#[test]
fn architecture_and_agent_restart_are_fixed_commands() {
    let mut release = native(vec![ok("arm64\n"), ok(""), ok("")]);
    assert_eq!(release.architecture().unwrap(), "arm64");
    release.restart_agent().unwrap();
    let calls = &release.executor.calls;
    assert_eq!(calls[0].program, Path::new("/usr/bin/uname"));
    assert_eq!(
        calls[1].args,
        ["print", "gui/501/io.local.claudewatch.agent"]
    );
    assert_eq!(
        calls[2].args,
        ["kickstart", "-k", "gui/501/io.local.claudewatch.agent"]
    );
    assert!(calls.iter().all(|x| x.timeout <= Duration::from_secs(125)));
}
#[test]
fn tcc_reset_is_exact_bundle_and_standard_path_only() {
    let mut release = native(vec![
        ok(""),
        FixedOutput {
            status: 1,
            stdout: String::new(),
            stderr: String::new(),
        },
    ]);
    release
        .reset_accessibility(
            Path::new("/Applications/Claude Watch Monitor.app"),
            BUNDLE_ID,
        )
        .unwrap();
    assert_eq!(
        release.executor.calls[0].args,
        ["reset", "Accessibility", BUNDLE_ID]
    );
    assert_eq!(
        release
            .reset_accessibility(Path::new("/tmp/other.app"), BUNDLE_ID)
            .unwrap_err()
            .code,
        "invalid_app_path"
    );
}
#[test]
fn running_state_requires_exact_executable_not_substring() {
    let mut release=native(vec![ok("101 1 501 Mon Oct 26 11:20:30 2026 /Applications/Claude Watch Monitor.app/Contents/MacOS/ClaudeWatchMonitor-helper\n102 1 501 Mon Oct 26 11:20:30 2026 /Applications/Claude Watch Monitor.app/Contents/MacOS/ClaudeWatchMonitor\n")]);
    assert!(release
        .app_running(Path::new("/Applications/Claude Watch Monitor.app"))
        .unwrap());
}

#[test]
fn bootout_registration_disappearing_does_not_prove_process_exit() {
    let absent = FixedOutput {
        status: 113,
        stdout: String::new(),
        stderr: "Could not find service".into(),
    };
    // Deliberately end the fixture after proving that the old PID is still
    // alive. Returning success before the next read would be a regression.
    let mut release = native(vec![
        ok("state = running\npid = 901\n"),
        ok(""),
        absent,
        ok("901\n"),
    ]);
    assert_eq!(release.stop_agent().unwrap_err().code, "fixture");
    assert!(release
        .executor
        .calls
        .iter()
        .any(|c| c.program == Path::new("/bin/ps")));
    assert_eq!(release.executor.calls.last().unwrap().args[0], "print");
}
#[test]
fn empty_process_table_cannot_prove_agent_has_exited() {
    let absent = FixedOutput {
        status: 113,
        stdout: String::new(),
        stderr: "Could not find service".into(),
    };
    let mut release = native(vec![
        ok("state = running\npid = 901\n"),
        ok(""),
        absent,
        ok(""),
    ]);
    assert_eq!(
        release.stop_agent().unwrap_err().code,
        "agent_state_unavailable"
    );
}
#[test]
fn plist_values_use_bounded_plutil_json_with_exact_field_matching() {
    let mut release = native(vec![ok(
        r#"{"prefixCFBundleShortVersionString":"wrong","CFBundleShortVersionString":"2.5.0"}"#,
    )]);
    assert_eq!(
        release
            .installed_version(Path::new("/unused/Claude Watch Monitor.app"))
            .unwrap(),
        "2.5.0"
    );
    let call = &release.executor.calls[0];
    assert_eq!(call.program, Path::new("/usr/bin/plutil"));
    assert_eq!(call.args[..4], ["-convert", "json", "-o", "-"]);
    assert_eq!(call.timeout, Duration::from_secs(10));
}
#[test]
fn plist_json_does_not_accept_substring_keys() {
    let mut release = native(vec![ok(r#"{"prefixCFBundleShortVersionString":"wrong"}"#)]);
    assert_eq!(
        release
            .installed_version(Path::new("/unused/Claude Watch Monitor.app"))
            .unwrap_err()
            .code,
        "invalid_app_bundle"
    );
}
#[test]
fn stop_app_keeps_the_complete_executable_path_when_it_contains_spaces() {
    let target = "/Applications/Claude Watch Monitor.app/Contents/MacOS/ClaudeWatchMonitor";
    let sample=format!("101 1 501 Mon Oct 26 11:20:30 2026 {target}-helper\n102 1 501 Mon Oct 26 11:20:30 2026 {target}\n");
    let unrelated = "101 1 501 Mon Oct 26 11:20:30 2026 /usr/bin/true\n";
    let mut release = native(vec![ok(&sample), ok(&sample), ok(""), ok(unrelated)]);
    release
        .stop_app(Path::new("/Applications/Claude Watch Monitor.app"))
        .unwrap();
    assert_eq!(release.executor.calls[2].program, Path::new("/bin/kill"));
    assert_eq!(release.executor.calls[2].args, ["-TERM", "102"]);
}
#[test]
fn validate_bundle_uses_plutil_json_for_all_metadata_without_reading_plist_bytes() {
    let suffix = Uuid::new_v4();
    let app = std::env::temp_dir().join(format!("claude-watch-native-release-{suffix}.app"));
    let resources = app.join("Contents/Resources");
    fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
    fs::create_dir_all(&resources).unwrap();
    fs::write(app.join("Contents/MacOS/ClaudeWatchMonitor"), []).unwrap();
    for name in [
        "watch-engine",
        "watch-native-observer",
        "watch-process-control",
        "watch-admin.sh",
        "watch-native-collector.zsh",
    ] {
        fs::write(resources.join(name), []).unwrap();
    }
    let empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let info = r#"{"CFBundleIdentifier":"io.local.watchpanel","CFBundleExecutable":"ClaudeWatchMonitor","CFBundleShortVersionString":"2.5.0","CFBundleVersion":"250"}"#;
    let manifest=serde_json::json!({"Architecture":"arm64","ProductVersion":"2.5.0","BackendVariant":"rust-candidate","RuntimeSchema":2,
        "RuntimeHashes":{"watch-engine":empty_hash,"watch-native-observer":empty_hash,"watch-process-control":empty_hash,"watch-admin.sh":empty_hash,"watch-native-collector.zsh":empty_hash}}).to_string();
    let replies = vec![
        ok(info),
        ok(""),
        ok("arm64"),
        ok("arm64"),
        ok("arm64"),
        ok("arm64"),
        ok(&manifest),
    ];
    let mut release = native(replies);
    assert_eq!(release.validate_bundle(&app).unwrap().version, "2.5.0");
    assert_eq!(
        release
            .executor
            .calls
            .iter()
            .filter(|call| call.program == Path::new("/usr/bin/plutil"))
            .count(),
        2
    );
    assert!(release
        .executor
        .calls
        .iter()
        .filter(|call| call.program == Path::new("/usr/bin/plutil"))
        .all(|call| call.args[..4] == ["-convert", "json", "-o", "-"]));
    assert!(!resources.join("claude-watch.sh").exists());
    fs::write(resources.join("watch-engine"), b"modified").unwrap();
    let mut changed = native(vec![
        ok(info),
        ok(""),
        ok("arm64"),
        ok("arm64"),
        ok("arm64"),
        ok("arm64"),
        ok(&manifest),
    ]);
    assert_eq!(
        changed.validate_bundle(&app).unwrap_err().code,
        "release_identity_mismatch"
    );
    fs::remove_dir_all(app).unwrap();
}

#[test]
fn background_evidence_bundle_requires_all_nine_hashed_files_and_arm64_worker() {
    let app = std::env::temp_dir().join(format!("cw-evidence-release-{}.app", Uuid::new_v4()));
    let resources = app.join("Contents/Resources");
    fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
    fs::create_dir_all(&resources).unwrap();
    fs::write(app.join("Contents/MacOS/ClaudeWatchMonitor"), []).unwrap();
    let required = [
        "watch-engine",
        "watch-native-observer",
        "watch-process-control",
        "watch-admin.sh",
        "watch-native-collector.zsh",
        "watch-leak-worker",
        "netcoffee_probe.html",
        "netcoffee_probe.js",
        "netcoffee_probe.css",
    ];
    for name in required {
        fs::write(resources.join(name), []).unwrap();
    }
    let empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let hashes = required
        .into_iter()
        .map(|name| (name.to_owned(), serde_json::json!(empty_hash)))
        .collect::<serde_json::Map<_, _>>();
    let info = r#"{"CFBundleIdentifier":"io.local.watchpanel","CFBundleExecutable":"ClaudeWatchMonitor","CFBundleShortVersionString":"2.5.0","CFBundleVersion":"250"}"#;
    let manifest = serde_json::json!({
        "Architecture":"arm64", "ProductVersion":"2.5.0", "BackendVariant":"rust-candidate",
        "RuntimeSchema":2, "BackgroundEvidenceSchema":1, "RuntimeHashes":hashes,
    })
    .to_string();
    let replies = vec![
        ok(info),
        ok(""),
        ok("arm64"),
        ok("arm64"),
        ok("arm64"),
        ok("arm64"),
        ok(&manifest),
        ok("arm64"),
    ];
    let mut release = native(replies);
    assert_eq!(release.validate_bundle(&app).unwrap().version, "2.5.0");
    assert!(release.executor.calls.iter().any(|call| {
        call.program == Path::new("/usr/bin/lipo")
            && call
                .args
                .last()
                .is_some_and(|path| path.ends_with("watch-leak-worker"))
    }));

    for name in ["ipleak_probe.html", "ipleak_probe.js"] {
        fs::write(resources.join(name), []).unwrap();
    }
    let mut manifest_v2: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    manifest_v2["BackgroundEvidenceSchema"] = serde_json::json!(2);
    for name in ["ipleak_probe.html", "ipleak_probe.js"] {
        manifest_v2["RuntimeHashes"][name] = serde_json::json!(empty_hash);
    }
    let manifest_v2 = manifest_v2.to_string();
    let replies_v2 = || {
        vec![
            ok(info),
            ok(""),
            ok("arm64"),
            ok("arm64"),
            ok("arm64"),
            ok("arm64"),
            ok(&manifest_v2),
            ok("arm64"),
        ]
    };
    assert_eq!(
        native(replies_v2()).validate_bundle(&app).unwrap().version,
        "2.5.0"
    );
    fs::remove_file(resources.join("ipleak_probe.js")).unwrap();
    assert_eq!(
        native(replies_v2()).validate_bundle(&app).unwrap_err().code,
        "release_identity_mismatch"
    );

    fs::remove_file(resources.join("netcoffee_probe.js")).unwrap();
    let mut missing = native(vec![
        ok(info),
        ok(""),
        ok("arm64"),
        ok("arm64"),
        ok("arm64"),
        ok("arm64"),
        ok(&manifest),
        ok("arm64"),
    ]);
    assert_eq!(
        missing.validate_bundle(&app).unwrap_err().code,
        "release_identity_mismatch"
    );
    fs::remove_dir_all(app).unwrap();
}
#[test]
fn derived_paths_preserve_product_data_boundary() {
    let paths = NativeReleasePaths::derive(Path::new("/Users/test"));
    assert_eq!(
        paths.base,
        Path::new("/Users/test/Library/Application Support/ClaudeWatch")
    );
    assert_eq!(paths.watch, paths.base.join("switcher"));
    assert_eq!(paths.backend, paths.base.join("claude-watch.sh"));
}

#[test]
fn old_app_identity_remains_inspectable_without_old_runtime_execution() {
    let app = std::env::temp_dir().join(format!("cw-old-identity-{}.app", Uuid::new_v4()));
    fs::create_dir(&app).unwrap();
    let mut release = native(vec![ok(
        r#"{"CFBundleIdentifier":"io.local.watchpanel","CFBundleExecutable":"ClaudeWatchMonitor"}"#,
    )]);
    assert_eq!(
        release.inspect_installed(&app).unwrap().bundle_id,
        BUNDLE_ID
    );
    assert_eq!(release.executor.calls.len(), 1);
    assert_eq!(
        release.executor.calls[0].program,
        Path::new("/usr/bin/plutil")
    );
    fs::remove_dir(app).unwrap();
}

#[test]
fn reused_app_pid_is_not_signalled() {
    let target = "/Applications/Claude Watch Monitor.app/Contents/MacOS/ClaudeWatchMonitor";
    let first = format!("102 1 501 Mon Oct 26 11:20:30 2026 {target}\n");
    let reused = format!("102 1 501 Mon Oct 26 11:20:31 2026 {target}\n");
    let unrelated = "101 1 501 Mon Oct 26 11:20:30 2026 /usr/bin/true\n";
    let mut release = native(vec![ok(&first), ok(&reused), ok(unrelated)]);
    release
        .stop_app(Path::new("/Applications/Claude Watch Monitor.app"))
        .unwrap();
    assert!(release
        .executor
        .calls
        .iter()
        .all(|c| c.program != Path::new("/bin/kill")));
}

#[test]
fn seatbelt_bundle_requires_hashed_arm64_sandbox_launcher_and_gateway_broker() {
    let app = std::env::temp_dir().join(format!("cw-seatbelt-release-{}.app", Uuid::new_v4()));
    let resources = app.join("Contents/Resources");
    fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
    fs::create_dir_all(&resources).unwrap();
    fs::write(app.join("Contents/MacOS/ClaudeWatchMonitor"), []).unwrap();
    let required = [
        "watch-engine",
        "watch-native-observer",
        "watch-process-control",
        "watch-admin.sh",
        "watch-native-collector.zsh",
        "watch-sandbox-launcher",
        "watch-gateway-broker",
    ];
    for name in required {
        fs::write(resources.join(name), []).unwrap();
    }
    let empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let hashes = required
        .into_iter()
        .map(|name| (name.to_owned(), serde_json::json!(empty_hash)))
        .collect::<serde_json::Map<_, _>>();
    let info = r#"{"CFBundleIdentifier":"io.local.watchpanel","CFBundleExecutable":"ClaudeWatchMonitor","CFBundleShortVersionString":"2.5.0","CFBundleVersion":"250"}"#;
    let manifest = serde_json::json!({
        "Architecture":"arm64", "ProductVersion":"2.5.0", "BackendVariant":"rust-candidate",
        "NetworkBackend":"seatbelt", "RuntimeSchema":2, "RuntimeHashes":hashes,
    })
    .to_string();
    let replies = vec![
        ok(info),
        ok(""),
        ok("arm64"),
        ok("arm64"),
        ok("arm64"),
        ok("arm64"),
        ok(&manifest),
        ok("arm64"),
        ok("arm64"),
    ];
    let mut release = native(replies.clone());
    assert_eq!(release.validate_bundle(&app).unwrap().version, "2.5.0");
    assert!(release.executor.calls.iter().any(|call| {
        call.program == Path::new("/usr/bin/lipo")
            && call
                .args
                .last()
                .is_some_and(|path| path.ends_with("watch-sandbox-launcher"))
    }));
    assert!(release.executor.calls.iter().any(|call| {
        call.program == Path::new("/usr/bin/lipo")
            && call.args.last().is_some_and(|path| path.ends_with("watch-gateway-broker"))
    }));
    // The extra runtime hash is accepted only when the actual broker matches.
    fs::write(resources.join("watch-gateway-broker"), b"changed").unwrap();
    assert_eq!(native(replies.clone()).validate_bundle(&app).unwrap_err().code, "release_identity_mismatch");
    fs::write(resources.join("watch-gateway-broker"), []).unwrap();
    let mut wrong_arch = replies.clone();
    *wrong_arch.last_mut().unwrap() = ok("x86_64");
    assert_eq!(native(wrong_arch).validate_bundle(&app).unwrap_err().code, "release_identity_mismatch");
    let mut missing_manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    missing_manifest["RuntimeHashes"].as_object_mut().unwrap().remove("watch-gateway-broker");
    let mut missing = replies;
    missing[6] = ok(&missing_manifest.to_string());
    assert_eq!(native(missing).validate_bundle(&app).unwrap_err().code, "release_identity_mismatch");
    fs::remove_dir_all(app).unwrap();
}
