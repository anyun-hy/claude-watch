//! Bounded native macOS notification transport.
//!
//! `NativeNotifier` performs one fixed, bounded command.  `AlertDispatcher`
//! keeps automatic alerts off the daemon/guard thread and lets `EventStore`
//! remain the sole owner of cooldown and mode decisions.
#![forbid(unsafe_code)]

use crate::{
    events::{Alert, EventStore, Mode, Notifier, NotifyError, Severity},
    release_native::{FixedCommand, FixedCommandExecutor, SystemExecutor},
    storage::StateStore,
};
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const OSASCRIPT: &str = "/usr/bin/osascript";
const MAX_PENDING: usize = 8;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(125);
const NOTIFICATION_LINE: &str = "display notification (item 2 of argv) with title (item 1 of argv)";
const DIALOG_LINE: &str = "display dialog (item 2 of argv) with title (item 1 of argv) buttons {\"OK\"} default button \"OK\" with icon stop";

/// A real platform notifier.  Its AppleScript source is fixed: title and
/// message are positional argv values, never string-interpolated source.
pub struct NativeNotifier<E: FixedCommandExecutor + Send = SystemExecutor> {
    executor: Mutex<E>,
}

impl<E: FixedCommandExecutor + Send> NativeNotifier<E> {
    pub fn new(executor: E) -> Self {
        Self {
            executor: Mutex::new(executor),
        }
    }
}
impl NativeNotifier<SystemExecutor> {
    pub fn system() -> Self {
        Self::new(SystemExecutor)
    }
}
impl<E: FixedCommandExecutor + Send> Notifier for NativeNotifier<E> {
    fn notify(&self, alert: &Alert) -> std::result::Result<(), NotifyError> {
        let mut executor = self.executor.lock().map_err(|_| NotifyError {
            code: "notification_executor_poisoned".into(),
            detail: "本机通知执行器不可用".into(),
        })?;
        let output = executor
            .run(fixed_command(alert))
            .map_err(|_| NotifyError {
                code: "notification_command_failed".into(),
                detail: "本机通知命令无法执行".into(),
            })?;
        if output.status == 0 {
            Ok(())
        } else {
            Err(NotifyError {
                code: "notification_command_failed".into(),
                detail: "本机通知命令失败".into(),
            })
        }
    }
}

fn fixed_command(alert: &Alert) -> FixedCommand {
    let line = if alert.severity == Severity::Critical {
        DIALOG_LINE
    } else {
        NOTIFICATION_LINE
    };
    // `SystemExecutor` rejects line breaks in every argv element.  Keep each
    // AppleScript statement in a separate fixed `-e` argument and make alert
    // data unambiguously positional after `--`.
    let message = alert.message.replace(['\r', '\n'], " ");
    FixedCommand {
        program: PathBuf::from(OSASCRIPT),
        args: vec![
            "-e".into(),
            "on run argv".into(),
            "-e".into(),
            line.into(),
            "-e".into(),
            "end run".into(),
            "--".into(),
            alert.title.clone(),
            message,
        ],
        timeout: COMMAND_TIMEOUT,
    }
}

#[derive(Clone)]
struct PendingAlert {
    alert: Alert,
    mode: Mode,
}
struct Queue {
    pending: VecDeque<PendingAlert>,
    active_title: Option<String>,
    stopping: bool,
}
struct Shared {
    queue: Mutex<Queue>,
    ready: Condvar,
}

/// An independent bounded worker for automatic notifications.
///
/// The dispatcher stores the mode which existed at enqueue time.  A pause,
/// re-arm, or snooze transition invalidates queued work before `emit` can call
/// the notifier.  Drop does not join a dialog worker; the production command
/// itself is limited by `SystemExecutor` to at most 125 seconds.
pub struct AlertDispatcher {
    store: Arc<EventStore>,
    notifier: Arc<dyn Notifier>,
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}

impl AlertDispatcher {
    pub fn new(storage: StateStore, notifier: Arc<dyn Notifier>) -> Self {
        let store = Arc::new(EventStore::new(storage));
        Self::with_store(store, notifier)
    }
    pub fn with_store(store: Arc<EventStore>, notifier: Arc<dyn Notifier>) -> Self {
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue {
                pending: VecDeque::new(),
                active_title: None,
                stopping: false,
            }),
            ready: Condvar::new(),
        });
        let worker = thread::spawn({
            let worker_store = Arc::clone(&store);
            let worker_notifier = Arc::clone(&notifier);
            let worker_shared = Arc::clone(&shared);
            move || worker_loop(worker_store, worker_notifier, worker_shared)
        });
        Self {
            store,
            notifier,
            shared,
            worker: Some(worker),
        }
    }
    pub fn store(&self) -> Arc<EventStore> {
        Arc::clone(&self.store)
    }
    /// Returns immediately. Full queues and duplicate pending or active titles
    /// return false.
    pub fn enqueue(&self, alert: Alert) -> bool {
        let mode = self.store.mode();
        let mut queue = match self.shared.queue.lock() {
            Ok(queue) => queue,
            Err(_) => return false,
        };
        if queue.stopping
            || queue.pending.len() >= MAX_PENDING
            || queue.active_title.as_deref() == Some(alert.title.as_str())
            || queue
                .pending
                .iter()
                .any(|entry| entry.alert.title == alert.title)
        {
            return false;
        }
        queue.pending.push_back(PendingAlert { alert, mode });
        self.shared.ready.notify_one();
        true
    }
    pub fn notifier(&self) -> &Arc<dyn Notifier> {
        &self.notifier
    }
}
impl Drop for AlertDispatcher {
    fn drop(&mut self) {
        if let Ok(mut queue) = self.shared.queue.lock() {
            queue.stopping = true;
            queue.pending.clear();
            self.shared.ready.notify_all();
        }
        let _ = self.worker.take();
    }
}

fn worker_loop(store: Arc<EventStore>, notifier: Arc<dyn Notifier>, shared: Arc<Shared>) {
    loop {
        let entry = {
            let mut queue = match shared.queue.lock() {
                Ok(queue) => queue,
                Err(_) => return,
            };
            while queue.pending.is_empty() && !queue.stopping {
                queue = match shared.ready.wait(queue) {
                    Ok(queue) => queue,
                    Err(_) => return,
                };
            }
            if queue.stopping {
                return;
            }
            let entry = queue.pending.pop_front();
            if let Some(entry) = &entry {
                queue.active_title = Some(entry.alert.title.clone());
            }
            entry
        };
        let Some(entry) = entry else { continue };
        if store.mode() == entry.mode {
            let at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_secs_f64())
                .unwrap_or(0.0);
            let _ = store.emit(notifier.as_ref(), &entry.alert, at);
        }
        if let Ok(mut queue) = shared.queue.lock() {
            queue.active_title = None;
            shared.ready.notify_all();
        }
    }
}
