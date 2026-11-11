use super::*;
use crate::managed_entry_activation::{observe_entry, EntrySource, ManagedEntryActivationManager};
use claude_watch_core::processes::Kind;

struct OwnedDescendant(ProcessKernelIdentity, PathBuf);
impl Drop for OwnedDescendant {
    fn drop(&mut self) {
        if let Some(live) = inspect_process_identity(self.0.pid).filter(|live|
            live.ppid == self.0.ppid && live.uid == self.0.uid && live.start_seconds == self.0.start_seconds
                && live.start_microseconds == self.0.start_microseconds
                && Path::new(&live.executable_path).starts_with(&self.1))
        {
            let _ = claude_watch_system::signal_bound_process(&live);
        }
    }
}

#[test]
fn v2_entry_observes_owned_live_desktop_helpers_by_instance_and_kernel_identity() {
    let fixture = Fixture::start();
    let target = LaunchTarget::ClaudeDesktop;
    let app = fixture.root.join("OwnedEntryFixture.app");
    let executable = app.join("Contents/MacOS/OwnedEntryFixture");
    let child = app.join("Contents/Frameworks/OwnedFixtureHelper");
    let replacement = app.join("Contents/Frameworks/OwnedFixtureAfterExec");
    fs::create_dir_all(executable.parent().unwrap()).unwrap();
    fs::create_dir_all(child.parent().unwrap()).unwrap();
    fs::write(app.join("Contents/Info.plist"), r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.local.watchpanel.owned-fixture</string>
<key>CFBundleExecutable</key><string>OwnedEntryFixture</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>"#).unwrap();
    fixture.compile(r#"
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 5) return 91;
  pid_t pid = fork();
  if (pid < 0) return 92;
  if (pid == 0) { execl(argv[1], argv[1], argv[2], argv[3], argv[4], (char *)0); _exit(93); }
  for (;;) pause();
}
"#, &executable);
    fixture.compile(r#"
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc == 1) { for (;;) pause(); }
  if (argc != 4) return 91;
  FILE *out = fopen(argv[1], "w");
  if (!out) return 92;
  fprintf(out, "%d\n", getpid());
  if (fclose(out) != 0) return 93;
  for (int i = 0; i < 1500; i++) {
    if (access(argv[2], F_OK) == 0) { execl(argv[3], argv[3], (char *)0); return 94; }
    usleep(10000);
  }
  return 95;
}
"#, &child);
    fixture.compile("#include <unistd.h>\nint main(void){sleep(15);}\n", &replacement);
    fixture.registry.approve_child_executable(child.to_str().unwrap(), &sha256_file_hex(&child).unwrap());
    let child_pid_file = fixture.root.join("owned-child.pid");
    let exec_trigger = fixture.root.join("exec-request");
    let main = fixture.launch(target, &executable, [&child, &child_pid_file, &exec_trigger, &replacement]
        .into_iter().map(|p| p.to_str().unwrap().into()).collect());
    let deadline = Instant::now() + Duration::from_secs(3);
    let live_child = loop {
        if let Some(live) = fs::read_to_string(&child_pid_file).ok()
            .and_then(|pid| pid.trim().parse().ok()).and_then(inspect_process_identity) { break live; }
        assert!(Instant::now() < deadline, "owned desktop helper must exec");
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(live_child.ppid, main.0.id());
    assert_eq!(Path::new(&live_child.executable_path), child);
    let descendant = OwnedDescendant(live_child, app.clone());
    let pid = descendant.0.pid;
    loop {
        fixture.registry.reconcile_process_trees(native::now());
        if fixture.registry.verified_family_tokens("claude", native::now()).iter().any(|token| token.pid == pid) { break; }
        assert!(Instant::now() < deadline, "registry must verify helper from actual inherited subtree");
        thread::sleep(Duration::from_millis(10));
    }
    let _supervisor = fixture.supervisor(&["claude"]);
    let spec = DesktopManagedEntrySpec::resolve_from_app_bundle(target, &app, "io.local.watchpanel.owned-fixture", "OwnedEntryFixture").unwrap();
    let source = EntrySource::Desktop { spec, kind: Kind::ClaudeMain };
    let manager = ManagedEntryActivationManager::new(fixture.storage.clone(), executable.clone(), fixture.helper.clone(), None);
    let status = || {
        let activity = observe_entry(&fixture.storage, target, &source, &[], native::now()).unwrap();
        manager.status(target, activity).unwrap()
    };
    let positive = status();
    assert_eq!(positive.active_managed_count, 1, "{positive:?}");
    assert!(positive.current_invocation_verified && positive.unmanaged_pids.is_empty() && positive.pending_pids.is_empty());
    // The loopback fixture does not publish a verified broker coverage scope.
    assert_eq!(positive.protected_instance_count, 0);

    let independent = Owned(Command::new(&child).spawn().unwrap());
    let unowned = status();
    assert_eq!(unowned.unmanaged_pids, vec![independent.0.id()], "{unowned:?}");
    assert_eq!(unowned.active_managed_count, 1);
    let refused = observe_entry(&fixture.storage, target, &source, &[], native::now()).unwrap();
    assert_eq!(manager.activate(target, &source, &refused).unwrap_err().code, "already_running_unmanaged");
    drop(independent);

    let state = fixture.storage.paths.watch().join("state/channel-supervision.json");
    let snapshot = fixture.storage.read_json(&state, Value::Null).unwrap();
    for (key, value) in [("producer_boot_id", json!("prior-producer")), ("executor_boot_id", json!("prior-executor")),
        ("saved_policy_version", json!({"policy_digest":"wrong","guard_policy_digest":"wrong"}))] {
        let mut stale = snapshot.clone();
        stale[key] = value;
        fixture.storage.atomic_json(&state, &stale).unwrap();
        let rejected = status();
        assert!(!rejected.current_invocation_verified && rejected.pending_pids.contains(&pid), "{key}: {rejected:?}");
    }
    let mut stale = snapshot.clone();
    let token = stale["families"]["claude"]["active_members"].as_array_mut().unwrap().iter_mut()
        .find(|token| token["pid"] == pid).unwrap();
    token["start_seconds"] = json!(descendant.0.start_seconds - 1);
    fixture.storage.atomic_json(&state, &stale).unwrap();
    let old_lifetime = status();
    assert_eq!(old_lifetime.pending_pids, vec![pid]);
    assert_eq!(old_lifetime.active_managed_count, 1);
    fixture.storage.atomic_json(&state, &snapshot).unwrap();

    fs::write(&exec_trigger, b"go").unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let execed = loop {
        if let Some(live) = inspect_process_identity(pid).filter(|p| Path::new(&p.executable_path) == replacement) { break live; }
        assert!(Instant::now() < deadline, "same-PID helper exec");
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(execed.start_seconds, descendant.0.start_seconds);
    assert_eq!(execed.start_microseconds, descendant.0.start_microseconds);
    assert_ne!(execed.audit_token, descendant.0.audit_token);
    let stale_exec = status();
    assert_eq!(stale_exec.pending_pids, vec![pid], "{stale_exec:?}");
    assert_eq!(stale_exec.protected_instance_count, 0);
    let refused = observe_entry(&fixture.storage, target, &source, &[], native::now()).unwrap();
    assert_eq!(manager.activate(target, &source, &refused).unwrap_err().code, "already_running_unmanaged");
    export("managed-entry-live-members.json", &json!({"verified":positive,"unowned":unowned,"old_lifetime":old_lifetime,"after_exec":stale_exec,
        "main_pid":main.0.id(),"helper_pid":pid,"same_pid_new_exec":true}));
}
