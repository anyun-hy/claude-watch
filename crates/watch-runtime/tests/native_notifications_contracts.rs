use claude_watch_core::error::Result;
use claude_watch_runtime::{
    events::{Alert, Mode, Notifier, Severity},
    native_notifications::{AlertDispatcher, NativeNotifier},
    release_native::{FixedCommand, FixedCommandExecutor, FixedOutput},
    storage::{Paths, StateStore},
};
use std::{
    fs,
    sync::{mpsc, Arc, Mutex},
    thread,
    time::Duration,
};

#[derive(Clone)]
struct FakeExecutor {
    commands: Arc<Mutex<Vec<FixedCommand>>>,
    started: Option<mpsc::Sender<()>>,
    gate: Option<Arc<Mutex<mpsc::Receiver<()>>>>,
}
impl FixedCommandExecutor for FakeExecutor {
    fn run(&mut self, command: FixedCommand) -> Result<FixedOutput> {
        self.commands.lock().unwrap().push(command);
        if let Some(started) = &self.started {
            let _ = started.send(());
        }
        if let Some(gate) = &self.gate {
            let _ = gate.lock().unwrap().recv();
        }
        Ok(FixedOutput {
            status: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    }
}
fn storage(name: &str) -> StateStore {
    let root = std::env::temp_dir().join(format!(
        "claude-watch-native-notify-{name}-{}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&root).unwrap();
    StateStore::new(Paths::new(&root).unwrap())
}
fn alert(title: &str, severity: Severity) -> Alert {
    Alert {
        title: title.into(),
        message: "message; $(not source)\nsecond line".into(),
        severity,
    }
}

#[test]
fn notifier_uses_the_watch_app_and_positional_data() {
    let commands = Arc::new(Mutex::new(Vec::new()));
    let notifier = NativeNotifier::new(FakeExecutor {
        commands: Arc::clone(&commands),
        started: None,
        gate: None,
    });
    notifier
        .notify(&alert("warning-title", Severity::Warning))
        .unwrap();
    let command = commands.lock().unwrap()[0].clone();
    assert_eq!(
        command.program.to_string_lossy(),
        "/Applications/Claude Watch Monitor.app/Contents/MacOS/ClaudeWatchMonitor"
    );
    assert_eq!(
        command.args,
        vec![
            "--notification-deliver",
            "warning",
            "events",
            "warning-title",
            "message; $(not source) second line",
        ]
    );
    assert!(command
        .args
        .iter()
        .all(|argument| !argument.contains(['\r', '\n'])));
    assert_eq!(command.timeout, Duration::from_secs(12));
}

#[test]
fn known_alerts_route_to_the_relevant_watch_pages() {
    let commands = Arc::new(Mutex::new(Vec::new()));
    let notifier = NativeNotifier::new(FakeExecutor {
        commands: Arc::clone(&commands),
        started: None,
        gate: None,
    });
    for (title, expected) in [
        ("Claude Watch：保护采样异常", "environment"),
        ("Claude Watch：已触发保护", "protection"),
        ("Claude Watch：敏感目录文件描述符", "events"),
    ] {
        notifier.notify(&alert(title, Severity::Warning)).unwrap();
        assert_eq!(commands.lock().unwrap().last().unwrap().args[2], expected);
    }
}

#[test]
fn a_missing_notification_permission_is_not_reported_as_success() {
    struct Denied;
    impl FixedCommandExecutor for Denied {
        fn run(&mut self, _: FixedCommand) -> Result<FixedOutput> {
            Ok(FixedOutput {
                status: 3,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }
    let error = NativeNotifier::new(Denied)
        .notify(&alert("warning", Severity::Warning))
        .unwrap_err();
    assert_eq!(error.code, "notification_not_authorized");
}

#[test]
fn critical_notification_runs_on_dispatcher_worker() {
    let commands = Arc::new(Mutex::new(Vec::new()));
    let (started_tx, started_rx) = mpsc::channel();
    let (gate_tx, gate_rx) = mpsc::channel();
    let notifier: Arc<dyn Notifier> = Arc::new(NativeNotifier::new(FakeExecutor {
        commands: Arc::clone(&commands),
        started: Some(started_tx),
        gate: Some(Arc::new(Mutex::new(gate_rx))),
    }));
    let dispatcher = AlertDispatcher::new(storage("dialog"), notifier);
    assert!(dispatcher.enqueue(alert("critical-title", Severity::Critical)));
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(commands.lock().unwrap()[0].args[1], "critical");
    gate_tx.send(()).unwrap();
}

#[test]
fn pending_duplicates_and_old_modes_are_dropped() {
    let commands = Arc::new(Mutex::new(Vec::new()));
    let (started_tx, started_rx) = mpsc::channel();
    let (gate_tx, gate_rx) = mpsc::channel();
    let notifier: Arc<dyn Notifier> = Arc::new(NativeNotifier::new(FakeExecutor {
        commands: Arc::clone(&commands),
        started: Some(started_tx),
        gate: Some(Arc::new(Mutex::new(gate_rx))),
    }));
    let dispatcher = AlertDispatcher::new(storage("mode"), notifier);
    assert!(dispatcher.enqueue(alert("active", Severity::Warning)));
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(!dispatcher.enqueue(alert("active", Severity::Warning)));
    assert!(dispatcher.enqueue(alert("queued", Severity::Warning)));
    assert!(!dispatcher.enqueue(alert("queued", Severity::Warning)));
    for index in 0..7 {
        assert!(dispatcher.enqueue(alert(&format!("queued-{index}"), Severity::Warning)));
    }
    assert!(!dispatcher.enqueue(alert("queue-overflow", Severity::Warning)));
    dispatcher.store().pause(10.0).unwrap();
    gate_tx.send(()).unwrap();
    thread::sleep(Duration::from_millis(50));
    assert_eq!(commands.lock().unwrap().len(), 1);
    assert_eq!(dispatcher.store().mode(), Mode::Paused);
}
