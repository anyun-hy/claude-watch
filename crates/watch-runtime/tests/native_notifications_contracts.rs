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
fn notifier_uses_fixed_script_and_positional_data() {
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
    assert_eq!(command.program.to_string_lossy(), "/usr/bin/osascript");
    assert_eq!(command.args[0], "-e");
    assert_eq!(
        command.args,
        vec![
            "-e",
            "on run argv",
            "-e",
            "display notification (item 2 of argv) with title (item 1 of argv)",
            "-e",
            "end run",
            "--",
            "warning-title",
            "message; $(not source) second line",
        ]
    );
    assert!(command
        .args
        .iter()
        .all(|argument| !argument.contains(['\r', '\n'])));
    assert_eq!(command.timeout, Duration::from_secs(125));
}

#[test]
fn critical_dialog_runs_on_dispatcher_worker() {
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
    assert!(commands.lock().unwrap()[0]
        .args
        .iter()
        .any(|argument| argument.contains("display dialog")));
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
