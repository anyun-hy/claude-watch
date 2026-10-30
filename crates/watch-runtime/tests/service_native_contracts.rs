use claude_watch_runtime::{
    commands::SystemRunner,
    service_native::read_job_definition,
    storage::{Paths, StateStore},
};
use std::{fs, os::unix::fs::symlink, process::Command};
#[test]
fn updater_uses_parsed_plist_and_exact_arguments() {
    let root = std::env::temp_dir().join(format!("service-native-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let store = StateStore::new(Paths::new(&root).unwrap());
    let runner = SystemRunner::development().unwrap();
    assert_eq!(
        read_job_definition(&store, "bad", &runner)
            .unwrap_err()
            .code,
        "invalid_service"
    );
    assert_eq!(
        read_job_definition(&store, "updater", &runner).unwrap()["definition_present"],
        false
    );
    let file = root.join("Library/LaunchAgents/io.local.claudewatch.update.plist");
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    let make = |extra: &str, interval: u32| {
        format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Label</key><string>io.local.claudewatch.update</string><key>ProgramArguments</key><array><string>{}</string><string>update</string><string>--auto</string><string>--apply</string>{extra}</array><key>StartInterval</key><integer>{interval}</integer><key>RunAtLoad</key><false/></dict></plist>",store.paths.watch().join("runtime/watch-engine").display())
    };
    fs::write(&file, make("", 43200)).unwrap();
    assert_eq!(
        read_job_definition(&store, "updater", &runner).unwrap()["trusted"],
        true
    );
    assert!(Command::new("/usr/bin/plutil")
        .args(["-convert", "binary1"])
        .arg(&file)
        .status()
        .unwrap()
        .success());
    assert_eq!(
        read_job_definition(&store, "updater", &runner).unwrap()["trusted"],
        true
    );
    fs::write(&file, make("<string>extra</string>", 43200)).unwrap();
    assert_eq!(
        read_job_definition(&store, "updater", &runner).unwrap()["trusted"],
        false
    );
    fs::write(&file, make("", 60)).unwrap();
    assert_eq!(
        read_job_definition(&store, "updater", &runner).unwrap()["trusted"],
        false
    );
    let decoy=format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Label</key><string>wrong</string><key>Comment</key><string>io.local.claudewatch.update {} update --auto --apply 43200</string></dict></plist>",store.paths.watch().join("runtime/watch-engine").display());
    fs::write(&file, decoy).unwrap();
    assert_eq!(
        read_job_definition(&store, "updater", &runner).unwrap()["trusted"],
        false
    );
    fs::remove_file(&file).unwrap();
    symlink(root.join("missing.plist"), &file).unwrap();
    assert!(read_job_definition(&store, "updater", &runner).is_err());
    fs::remove_dir_all(root).unwrap();
}
