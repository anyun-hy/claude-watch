//! The supervisor issues process authority; this worker observes actual exits.
//! Network permits, network receipts and disk snapshots cannot authorize a signal.
use crate::{
    channel_supervisor::{ChannelSupervisor, SupervisionEvent},
    config_store::ConfigStore,
    native,
    sandbox_launch::SandboxLaunchRegistry,
    session_store::SessionStore,
    storage::StateStore,
};
use claude_watch_core::{
    channel::{
        ProcessDispositionIntent, ProcessDispositionReceipt, TargetProcessDispositionResult,
    },
    error::{CoreError, Result},
    policy::PolicyCatalog,
    session::Phase,
};
use claude_watch_system::{BoundSignalResult, ProcessKernelIdentity};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender, SyncSender},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub(crate) const INTENT_TTL: f64 = 8.0;
pub(crate) const RECEIPT_TTL: f64 = 15.0;
pub(crate) const RESULT_COMPLETION_GRACE: f64 = 2.25;
pub(crate) const MAX_TARGETS: usize = 128;
const WAIT_FOR_EXIT: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Slot {
    current: Option<ProcessDispositionIntent>,
    claimed: bool,
    cancelled: bool,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct ProcessIntentFence(Arc<Mutex<Slot>>);

impl std::fmt::Debug for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Slot")
            .field("claimed", &self.claimed)
            .finish_non_exhaustive()
    }
}

impl ProcessIntentFence {
    pub(crate) fn current(&self) -> Option<ProcessDispositionIntent> {
        let slot = self.0.lock().ok()?;
        if slot.cancelled {
            None
        } else {
            slot.current.clone()
        }
    }

    pub(crate) fn install(&self, intent: ProcessDispositionIntent) -> bool {
        let Ok(mut slot) = self.0.lock() else {
            return false;
        };
        *slot = Slot {
            current: Some(intent),
            claimed: false,
            cancelled: false,
        };
        true
    }

    pub(crate) fn cancel(&self) {
        // Cancellation fences subsequent signals. It does not rewrite the
        // result of a signal that the worker already requested.
        if let Ok(mut slot) = self.0.lock() {
            slot.cancelled = true;
        }
    }

    pub(crate) fn may_deliver_result(&self) -> bool {
        self.0.lock().is_ok_and(|slot| slot.claimed || !slot.cancelled)
    }

    fn is_current(slot: &Slot, intent: &ProcessDispositionIntent, now: f64) -> bool {
        !slot.cancelled
            && slot.current.as_ref() == Some(intent)
            && now.is_finite()
            && now >= intent.created_at
            && now < intent.valid_until
    }

    fn claim(&self, intent: &ProcessDispositionIntent, now: f64) -> bool {
        let Ok(mut slot) = self.0.lock() else {
            return false;
        };
        if slot.claimed || !Self::is_current(&slot, intent, now) {
            return false;
        }
        slot.claimed = true;
        true
    }

    pub(crate) fn is_claimed(&self, intent: &ProcessDispositionIntent) -> bool {
        self.0
            .lock()
            .is_ok_and(|slot| slot.claimed && slot.current.as_ref() == Some(intent))
    }

    fn signal(
        &self,
        job: &ProcessDispositionJob,
        target: &ProcessKernelIdentity,
        stop: &AtomicBool,
        batch_deadline: Instant,
    ) -> Option<BoundSignalResult> {
        let slot = self.0.lock().ok()?;
        if !slot.claimed
            || !Self::is_current(&slot, &job.intent, native::now())
            || Instant::now() >= batch_deadline
            || stop.load(Ordering::Acquire)
        {
            return None;
        }
        // Recheck the exact kernel identity at the signal boundary. Holding
        // this short lock orders cancellation against the actual signal.
        Some(claude_watch_system::signal_bound_process(target))
    }
}

pub(crate) struct ProcessDispositionJob {
    pub intent: ProcessDispositionIntent,
    pub fence: ProcessIntentFence,
    pub registry: Arc<SandboxLaunchRegistry>,
    pub deadline: Instant,
}

pub struct ProcessDispositionDispatcher(SyncSender<ProcessDispositionJob>);

impl ProcessDispositionDispatcher {
    pub fn start(
        storage: StateStore,
        stop: Arc<AtomicBool>,
        events: Sender<SupervisionEvent>,
    ) -> Result<(Self, JoinHandle<()>)> {
        Self::start_with(storage, stop, events, execute)
    }

    fn start_with(
        storage: StateStore,
        stop: Arc<AtomicBool>,
        events: Sender<SupervisionEvent>,
        execute_job: impl Fn(&StateStore, &ProcessDispositionJob, &AtomicBool) -> Option<ProcessDispositionReceipt>
            + Send + 'static,
    ) -> Result<(Self, JoinHandle<()>)> {
        let (tx, rx) = mpsc::sync_channel(2);
        let worker = thread::Builder::new()
            .name("channel-process-disposition".into())
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(job) => {
                            if let Some(receipt) = execute_job(&storage, &job, &stop) {
                                // Diagnostic evidence only. The supervisor never
                                // imports process authority or results from disk.
                                let path = storage
                                    .paths
                                    .watch()
                                    .join(format!("state/process-receipt-{}.json", receipt.family));
                                let _ = events.send(SupervisionEvent::ProcessReceiptArrived {
                                    receipt: receipt.clone(),
                                    received_at: native::now(),
                                });
                                if let Ok(value) = serde_json::to_value(&receipt) {
                                    let _ = storage.atomic_json(&path, &value);
                                }
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            })
            .map_err(|_| {
                CoreError::new(
                    "process_disposition_worker_failed",
                    "进程处置执行线程启动失败",
                )
            })?;
        Ok((Self(tx), worker))
    }

    pub(crate) fn submit(&self, job: ProcessDispositionJob) -> bool {
        self.0.try_send(job).is_ok()
    }
}

fn current_policy_and_session(
    storage: &StateStore,
    intent: &ProcessDispositionIntent,
    now: f64,
) -> bool {
    let Some(family) = PolicyCatalog::family(&intent.family) else {
        return false;
    };
    let Some(provider) = family.providers.first().copied() else {
        return false;
    };
    let Ok(config) = (ConfigStore {
        storage: storage.clone(),
    })
    .load() else {
        return false;
    };
    config.enabled
        && config.guard_enabled
        && config.close_action(&intent.risk_code, provider) == "force"
        && ChannelSupervisor::compute_policy_version(&config)
            .is_ok_and(|v| v == intent.policy_version)
        && SessionStore::for_family(storage.clone(), family.id)
            .load(now)
            .is_ok_and(|session| {
                session.is_some_and(|s| {
                    s.session_id == intent.session_id
                        && matches!(s.state, Phase::Active | Phase::Locked)
                })
            })
}

fn execute(
    storage: &StateStore,
    job: &ProcessDispositionJob,
    stop: &AtomicBool,
) -> Option<ProcessDispositionReceipt> {
    execute_batch(
        storage,
        job,
        stop,
        |_| {},
        |token, target, now| {
            job.registry
                .current_disposition_member(&job.intent, token, target, now)
        },
        claude_watch_system::bound_lifetime_exited,
    )
}

fn execute_batch(
    storage: &StateStore,
    job: &ProcessDispositionJob,
    stop: &AtomicBool,
    mut before_target: impl FnMut(usize),
    mut current_member: impl FnMut(
        &claude_watch_core::channel::BoundProcessToken,
        &ProcessKernelIdentity,
        f64,
    ) -> bool,
    observed_exit: impl Fn(&ProcessKernelIdentity) -> bool,
) -> Option<ProcessDispositionReceipt> {
    let intent = &job.intent;
    let family = PolicyCatalog::family(&intent.family)?;
    let session_lock = SessionStore::for_family(storage.clone(), family.id).lock_name();
    if stop.load(Ordering::Acquire)
        || Instant::now() >= job.deadline
        || !job.fence.claim(intent, native::now())
    {
        return None;
    }
    let mut results = Vec::with_capacity(intent.target_identities.len());
    let mut sent = Vec::new();
    let batch_deadline = job.deadline.min(Instant::now() + WAIT_FOR_EXIT);
    for (index, token) in intent.target_identities.iter().enumerate() {
        before_target(index);
        let mut result = TargetProcessDispositionResult {
            pid: token.pid,
            requested_action: "force_quit".into(),
            terminated: false,
            process_state: "identity_mismatch".into(),
            timestamp: native::now(),
            signal_sent_at: None,
        };
        if let (Some(audit_token), Some(executable_path)) =
            (token.audit_token, intent.target_executables.get(&token.pid))
        {
            let target = ProcessKernelIdentity {
                pid: token.pid,
                ppid: 0,
                uid: token.uid,
                start_seconds: token.start_seconds,
                start_microseconds: token.start_microseconds,
                executable_path: executable_path.clone(),
                audit_token,
            };
            if claude_watch_system::bound_lifetime_exited(&target) {
                result.process_state = "already_exited".into();
            } else if stop.load(Ordering::Acquire) || Instant::now() >= batch_deadline {
                result.process_state = "cancelled".into();
            } else if current_member(token, &target, native::now()) {
                // Serialize the last policy/session read against their writers,
                // outside the short intent fence. A busy lock fails closed.
                let current = storage.lock("operation", None).ok().and_then(|op| {
                    storage
                        .lock(&session_lock, None)
                        .ok()
                        .map(|session| (op, session))
                });
                let signal = current.and_then(|_locks| {
                    current_policy_and_session(storage, intent, native::now())
                        .then(|| job.fence.signal(job, &target, stop, batch_deadline))
                        .flatten()
                });
                result.process_state = match signal {
                    None => "cancelled",
                    Some(BoundSignalResult::AlreadyExited) => "already_exited",
                    Some(BoundSignalResult::IdentityChanged) => "identity_mismatch",
                    Some(BoundSignalResult::Failed) => "signal_failed",
                    Some(BoundSignalResult::Sent) => {
                        result.signal_sent_at = Some(native::now());
                        sent.push((results.len(), target));
                        "timeout"
                    }
                }
                .into();
            }
        }
        result.timestamp = native::now();
        results.push(result);
    }
    // One batch deadline, irrespective of the number of targets. Cancellation
    // stops future signals, but never erases outcomes for signals already sent.
    while !sent.is_empty() {
        sent.retain(|(index, target)| {
            if !observed_exit(target) {
                return true;
            }
            results[*index].terminated = true;
            results[*index].process_state = "terminated".into();
            results[*index].timestamp = native::now();
            false
        });
        if sent.is_empty() || Instant::now() >= batch_deadline {
            break;
        }
        thread::sleep(
            Duration::from_millis(10).min(batch_deadline.saturating_duration_since(Instant::now())),
        );
    }
    let observed_at = native::now();
    for (index, target) in sent {
        results[index].timestamp = observed_at;
        if !claude_watch_system::process_audit_token_matches(
            target.pid,
            target.uid,
            target.start_seconds,
            target.start_microseconds,
            &target.audit_token,
        ) {
            results[index].process_state = "exit_unconfirmed".into();
        }
    }
    let state = result_state(&results);
    Some(ProcessDispositionReceipt {
        intent_id: intent.intent_id.clone(),
        family: intent.family.clone(),
        session_id: intent.session_id.clone(),
        action: intent.action.clone(),
        process_execution_state: state.into(),
        // No exact all-live observation in a force batch means we must not
        // claim that the whole set was preserved.
        process_preserved: false,
        target_results: results,
        observed_at,
        error_code: match state {
            "failed" => Some("process_signal_failed".into()),
            "unknown" => Some("process_exit_unconfirmed".into()),
            _ => None,
        },
        authority: Some(intent.clone()),
    })
}

pub(crate) fn result_state(results: &[TargetProcessDispositionResult]) -> &'static str {
    let exited = results
        .iter()
        .filter(|r| r.terminated || r.process_state == "already_exited")
        .count();
    if exited > 0 && exited == results.len() {
        if results.iter().any(|r| r.terminated) {
            "confirmed"
        } else {
            "already_exited"
        }
    } else if exited > 0 {
        "partially_terminated"
    } else if !results.is_empty() && results.iter().all(|r| r.process_state == "cancelled") {
        "cancelled"
    } else if results.iter().any(|r| r.process_state == "signal_failed") {
        "failed"
    } else {
        "unknown"
    }
}

#[cfg(all(test, target_os = "macos"))]
#[path = "../tests/support/process_disposition_delivery.rs"]
mod delivery_contracts;

#[cfg(test)]
mod tests {
    use super::*;
    use claude_watch_core::{
        channel::{BoundProcessToken, PolicyVersion},
        config::Config,
        processes::ProcessRole,
    };
    use serde_json::json;
    use std::{
        fs,
        path::{Path, PathBuf},
        process::{Child, Command},
    };

    struct Owned(Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    struct Root(PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn identify(child: &Owned) -> ProcessKernelIdentity {
        claude_watch_system::inspect_process_identity(child.0.id())
            .expect("owned live fixture identity")
    }
    fn token(target: &ProcessKernelIdentity) -> BoundProcessToken {
        BoundProcessToken::with_system_identity(
            target.pid,
            target.uid,
            target.start_seconds,
            target.start_microseconds,
            ProcessRole::Cli,
        )
        .with_audit_token(target.audit_token)
    }

    #[test]
    fn v1_native_partial_exit_survives_current_policy_cancellation_and_replay_is_denied() {
        let root = Root(
            PathBuf::from("/private/tmp")
                .join(format!("cw-disposition-{}", uuid::Uuid::new_v4().simple())),
        );
        fs::create_dir(&root.0).unwrap();
        let storage = StateStore::new(crate::storage::Paths::new(&root.0).unwrap());
        let config_store = ConfigStore {
            storage: storage.clone(),
        };
        let mut config = Config::default_for_new_install();
        config.enabled = true;
        config.guard_enabled = true;
        config
            .policy_actions
            .insert("claude_close_ip".into(), "force".into());
        config_store.save(config.value().unwrap()).unwrap();
        let policy: PolicyVersion =
            ChannelSupervisor::compute_policy_version(&config_store.load().unwrap()).unwrap();
        let source = root.0.join("owned.c");
        let executable = root.0.join("owned");
        fs::write(
            &source,
            b"#include <unistd.h>\nint main(void){for(;;)pause();}\n",
        )
        .unwrap();
        let build = Command::new("xcrun")
            .args(["clang", "-O0", "-Werror"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
        );
        let mut first = Owned(Command::new(&executable).spawn().unwrap());
        let mut second = Owned(Command::new(&executable).spawn().unwrap());
        let first_id = identify(&first);
        let second_id = identify(&second);
        let now = native::now();
        storage.atomic_json(&storage.paths.session_for("claude"), &json!({
            "schema":1,"session_id":"owned-session","state":"locked",
            "baseline":{"ip":"1.1.1.1","country":"US","observed_at":now,"source":"fixture"},
            "reason":{"code":"egress_ip_changed","detail":"fixture","source":"fixture","observed_at":now},
            "channel_processes_v1":[token(&first_id),token(&second_id)],
        })).unwrap();
        let registry = Arc::new(SandboxLaunchRegistry::new(
            "owned-executor",
            policy.clone(),
            claude_watch_system::SandboxPeerVerifier {
                expected_uid: first_id.uid,
                expected_helper_executable: "/unused/fixture".into(),
                expected_helper_sha256: "0".repeat(64),
                expected_helper_cdhash: "0".repeat(40),
            },
            None,
        ));
        let intent = ProcessDispositionIntent {
            intent_id: "owned-intent".into(),
            family: "claude".into(),
            risk_code: "egress_ip_changed".into(),
            action: "force".into(),
            instance_id: None,
            session_id: "owned-session".into(),
            policy_version: policy,
            producer_boot_id: "owned-producer".into(),
            executor_boot_id: "owned-executor".into(),
            permit_generation: 1,
            command_seq: 1,
            target_identities: vec![token(&first_id), token(&second_id)],
            target_executables: [
                (first_id.pid, first_id.executable_path.clone()),
                (second_id.pid, second_id.executable_path.clone()),
            ]
            .into(),
            target_instances: [
                (first_id.pid, "owned-first".into()),
                (second_id.pid, "owned-second".into()),
            ]
            .into(),
            created_at: now,
            valid_until: now + INTENT_TTL,
        };
        let fence = ProcessIntentFence::default();
        assert!(fence.install(intent.clone()));
        for wrong in [
            ProcessDispositionIntent {
                command_seq: 2,
                ..intent.clone()
            },
            ProcessDispositionIntent {
                executor_boot_id: "old".into(),
                ..intent.clone()
            },
            ProcessDispositionIntent {
                session_id: "old".into(),
                ..intent.clone()
            },
        ] {
            assert!(!fence.claim(&wrong, now));
        }
        assert!(!fence.claim(&intent, intent.valid_until));
        let job = ProcessDispositionJob {
            intent,
            fence,
            registry,
            deadline: Instant::now() + Duration::from_secs(5),
        };
        let receipt = execute_batch(
            &storage,
            &job,
            &AtomicBool::new(false),
            |index| {
                if index == 1 {
                    config
                        .policy_actions
                        .insert("claude_close_ip".into(), "warn".into());
                    config_store.save(config.value().unwrap()).unwrap();
                }
            },
            |t, p, _| {
                t == &token(&first_id) && p.audit_token == first_id.audit_token
                    || t == &token(&second_id) && p.audit_token == second_id.audit_token
            },
            claude_watch_system::bound_lifetime_exited,
        )
        .unwrap();
        assert_eq!(receipt.process_execution_state, "partially_terminated");
        assert!(!receipt.process_preserved);
        assert!(receipt.target_results[0].terminated);
        assert_eq!(receipt.target_results[1].process_state, "cancelled");
        assert!(receipt.target_results[1].signal_sent_at.is_none());
        assert!(!first.0.wait().unwrap().success());
        assert!(second.0.try_wait().unwrap().is_none());
        assert_eq!(identify(&second).audit_token, second_id.audit_token);
        assert!(execute_batch(
            &storage,
            &job,
            &AtomicBool::new(false),
            |_| panic!("duplicate intent"),
            |_, _, _| false,
            claude_watch_system::bound_lifetime_exited,
        )
        .is_none());
        println!(
            "partial worker receipt: {}",
            serde_json::to_string(&receipt).unwrap()
        );
        if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                Path::new(&dir).join("process-disposition-partial.json"),
                serde_json::to_vec_pretty(&receipt).unwrap(),
            )
            .unwrap();
        }
    }
}
