//! Bounded, structured diagnostic records. Never accepts raw command lines,
//! network destinations, peer metadata, credentials or arbitrary error text.
use serde_json::json;
use std::{
    fs,
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
pub const DIRECTORY: &str = "/Library/Logs/ClaudeWatchGateway";
const LIMIT: u64 = 1024 * 1024;
const ROTATIONS: usize = 2;
const FILE: &str = "events.jsonl";

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "gateway log path is not trusted",
    )
}
fn known_file(name: &str) -> bool {
    matches!(
        name,
        "events.jsonl" | "events.jsonl.1" | "events.jsonl.2" | ".write.lock"
    )
}
fn check(path: &Path, uid: u32, directory: bool) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if m.file_type().is_symlink()
        || m.uid() != uid
        || m.mode() & 0o022 != 0
        || (directory && !m.is_dir())
        || (!directory && (!m.is_file() || m.nlink() != 1))
    {
        return Err(invalid());
    }
    #[cfg(target_os = "macos")]
    if uid == 0 {
        claude_watch_system::launchd_gateway::verify_gateway_install_path(path)?;
    }
    Ok(())
}
fn directory(path: &Path, uid: u32, create: bool) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
            let parent = path.parent().ok_or_else(invalid)?;
            check(parent, uid, true)?;
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o755).create(path)?;
        }
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    check(path, uid, true)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !entry.file_name().to_str().is_some_and(known_file) {
            return Err(invalid());
        }
        check(&entry.path(), uid, false)?;
    }
    Ok(())
}
fn emit_at(path: &Path, uid: u32, body: &[u8], limit: u64) -> io::Result<()> {
    directory(path, uid, false)?;
    if body.len() as u64 + 1 > limit {
        return Err(io::Error::other("gateway event exceeds log bound"));
    }
    let lock_path = path.join(".write.lock");
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)?;
    check(&lock_path, uid, false)?;
    // A slow/full log filesystem must not queue protection work behind another
    // writer. The stable lock inode is never rotated or removed.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "gateway logger busy",
        ));
    }
    let active = path.join(FILE);
    if let Ok(meta) = fs::symlink_metadata(&active) {
        check(&active, uid, false)?;
        if meta.len() + body.len() as u64 + 1 > limit {
            let oldest = path.join(format!("{FILE}.{ROTATIONS}"));
            if oldest.exists() {
                check(&oldest, uid, false)?;
                fs::remove_file(oldest)?;
            }
            for n in (1..ROTATIONS).rev() {
                let previous = path.join(format!("{FILE}.{n}"));
                if previous.exists() {
                    check(&previous, uid, false)?;
                    fs::rename(previous, path.join(format!("{FILE}.{}", n + 1)))?;
                }
            }
            fs::rename(&active, path.join(format!("{FILE}.1")))?;
        }
    }
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&active)?;
    check(&active, uid, false)?;
    file.write_all(body)?;
    file.write_all(b"\n")?;
    Ok(())
}
fn label(value: &str) -> &str {
    if !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
    {
        value
    } else {
        "invalid_label"
    }
}
fn transaction(value: Option<&str>) -> Option<&str> {
    value.filter(|v| v.len() == 32 && v.bytes().all(|c| c.is_ascii_hexdigit()))
}
fn binary_sha256() -> &'static Option<String> {
    static HASH: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    HASH.get_or_init(|| {
        std::env::current_exe()
            .ok()
            .and_then(|path| claude_watch_system::sha256_file_hex(&path))
    })
}
fn event(
    operation: &str,
    result: &str,
    reason: &str,
    tx: Option<&str>,
    os_error: Option<i32>,
) -> Vec<u8> {
    serde_json::to_vec(&json!({"schema":1,"ts_unix_ms":SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis(),
        "component":"watch-gateway-broker","component_version":env!("CARGO_PKG_VERSION"),"binary_sha256":binary_sha256(),"pid":std::process::id(),
        "operation":label(operation),"result":label(result),"reason":label(reason),"transaction_id":transaction(tx),"os_error":os_error})).expect("fixed event fields")
}
pub fn prepare() {
    if claude_watch_system::effective_uid() != 0 {
        return;
    }
    if directory(Path::new(DIRECTORY), 0, true).is_err() {
        eprintln!("gateway_logging_unavailable: protected log directory unavailable");
    }
}
static LOG_WARNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
fn unavailable() {
    if !LOG_WARNING.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!("gateway_logging_unavailable: structured record could not be persisted");
    }
}
#[derive(Default)]
struct LostRecords {
    queue: std::sync::atomic::AtomicU64,
    writes: std::sync::atomic::AtomicU64,
}
impl LostRecords {
    fn increment(counter: &std::sync::atomic::AtomicU64) {
        use std::sync::atomic::Ordering::Relaxed;
        let mut value = counter.load(Relaxed);
        loop {
            match counter.compare_exchange_weak(value, value.saturating_add(1), Relaxed, Relaxed) {
                Ok(_) => break,
                Err(current) => value = current,
            }
        }
    }
    fn persist(&self, write: &mut impl FnMut(Vec<u8>) -> io::Result<()>) {
        use std::sync::atomic::Ordering::Relaxed;
        let queue = self.queue.load(Relaxed);
        let writes = self.writes.load(Relaxed);
        if queue == 0 && writes == 0 {
            return;
        }
        let mut summary: serde_json::Value = serde_json::from_slice(&event(
            "logging_recovery",
            "degraded",
            "log_records_lost",
            None,
            None,
        ))
        .expect("fixed event fields");
        summary["dropped_queue_records"] = json!(queue);
        summary["failed_write_records"] = json!(writes);
        summary["counts_saturated"] = json!(queue == u64::MAX || writes == u64::MAX);
        if write(serde_json::to_vec(&summary).expect("fixed event fields")).is_ok() {
            // Only this worker subtracts. Concurrent producers can add losses,
            // which remain for the next report instead of being cleared.
            self.queue.fetch_sub(queue, Relaxed);
            self.writes.fetch_sub(writes, Relaxed);
        }
    }
}
struct AsyncLog {
    sender: std::sync::mpsc::SyncSender<Vec<u8>>,
    lost: std::sync::Arc<LostRecords>,
}
impl AsyncLog {
    fn new(mut write: impl FnMut(Vec<u8>) -> io::Result<()> + Send + 'static) -> io::Result<Self> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(64);
        let lost = std::sync::Arc::new(LostRecords::default());
        let worker_lost = lost.clone();
        std::thread::Builder::new()
            .name("gateway-event-log".into())
            .spawn(move || loop {
                match receiver.recv_timeout(std::time::Duration::from_secs(1)) {
                    Ok(body) => {
                        if write(body).is_err() {
                            LostRecords::increment(&worker_lost.writes);
                            unavailable();
                        }
                        worker_lost.persist(&mut write);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // Recovery is observable even when no further client
                        // handoff arrives after logging becomes writable.
                        worker_lost.persist(&mut write);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        worker_lost.persist(&mut write);
                        break;
                    }
                }
            })?;
        Ok(Self { sender, lost })
    }
    fn send(&self, body: Vec<u8>) -> bool {
        if self.sender.try_send(body).is_ok() {
            true
        } else {
            LostRecords::increment(&self.lost.queue);
            false
        }
    }
}
/// Only steady-state handoff events use this bounded queue. Slow storage must
/// never delay authentication, listener transfer or connection rejection.
pub fn record_async(operation: &str, result: &str, reason: &str) {
    if claude_watch_system::effective_uid() != 0 {
        return;
    }
    static LOGGER: std::sync::OnceLock<Option<AsyncLog>> = std::sync::OnceLock::new();
    let logger = LOGGER
        .get_or_init(|| AsyncLog::new(|body| emit_at(Path::new(DIRECTORY), 0, &body, LIMIT)).ok());
    if !logger
        .as_ref()
        .is_some_and(|logger| logger.send(event(operation, result, reason, None, None)))
    {
        unavailable();
    }
}

pub fn record(
    operation: &str,
    result: &str,
    reason: &str,
    tx: Option<&str>,
    os_error: Option<i32>,
) {
    if claude_watch_system::effective_uid() != 0 {
        return;
    }
    let body = event(operation, result, reason, tx, os_error);
    if emit_at(Path::new(DIRECTORY), 0, &body, LIMIT).is_err() {
        // No unbounded raw errors or supplied fields are exposed on fallback.
        unavailable();
    }
}
pub fn error_reason(error: &io::Error) -> &'static str {
    if let Some(stage) = claude_watch_system::launchd_gateway::gateway_error_stage(error) {
        return stage;
    }
    let message = error.to_string();
    if message.contains("still running") {
        "operation_busy"
    } else if message.contains("transaction") {
        "transaction_unconfirmed"
    } else if message.contains("another user") {
        "installation_scope_mismatch"
    } else if message.contains("live or unconfirmed engine") {
        "engine_still_owns_listener"
    } else if message.contains("activation failed") {
        "activation_failed"
    } else if message.contains("unknown") || message.contains("not trusted") {
        "installation_identity_untrusted"
    } else if message.contains("signature")
        || message.contains("identity")
        || message.contains("CDHash")
    {
        "component_identity_mismatch"
    } else {
        match error.kind() {
            io::ErrorKind::NotFound => "path_not_found",
            io::ErrorKind::PermissionDenied => "permission_denied",
            io::ErrorKind::TimedOut => "timed_out",
            io::ErrorKind::InvalidData => "invalid_data",
            io::ErrorKind::WouldBlock => "would_block",
            _ => "operation_failed",
        }
    }
}
pub fn operation(args: &[String]) -> Option<&'static str> {
    match args.first().map(String::as_str) {
        None => Some("broker_run"),
        Some("--service-install") => Some("service_install"),
        Some("--service-commit") => Some("service_commit"),
        Some("--service-rollback") => Some("service_rollback"),
        Some("--service-remove") => Some("service_remove"),
        _ => None,
    }
}
pub fn transaction_argument(args: &[String]) -> Option<&str> {
    args.windows(2)
        .find(|pair| pair[0] == "--transaction")
        .and_then(|pair| transaction(Some(&pair[1])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn temp() -> Temp {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "cw-broker-log-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Temp(p)
    }
    #[test]
    fn records_have_only_safe_fields_and_never_raw_arguments() {
        let body = event(
            "handoff",
            "rejected",
            "peer_identity_rejected",
            Some("Authorization: Bearer secret"),
            Some(13),
        );
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["transaction_id"], serde_json::Value::Null);
        assert!(
            value["binary_sha256"].as_str().is_some_and(
                |value| value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit())
            )
        );
        assert!(
            std::ptr::eq(binary_sha256(), binary_sha256()),
            "component identity is cached for this process"
        );
        assert!(!String::from_utf8(body).unwrap().contains("secret"));
        let bad = event(
            "https://user:secret@example.test",
            "failed",
            "Cookie: sensitive",
            None,
            None,
        );
        assert!(!String::from_utf8(bad).unwrap().contains("sensitive"));
    }
    #[test]
    fn rotation_limits_total_bytes_and_preserves_recent_complete_events() {
        let t = temp();
        let uid = claude_watch_system::effective_uid();
        let logs = t.0.join("logs");
        directory(&logs, uid, true).unwrap();
        for i in 0..20 {
            let data = serde_json::to_vec(&json!({"sequence":i,"padding":"x".repeat(40)})).unwrap();
            emit_at(&logs, uid, &data, 180).unwrap();
        }
        let mut bytes = 0;
        let mut sequences = vec![];
        for name in [FILE, "events.jsonl.1", "events.jsonl.2"] {
            let data = fs::read_to_string(logs.join(name)).unwrap();
            assert!(data.len() <= 180);
            bytes += data.len();
            for line in data.lines() {
                sequences.push(
                    serde_json::from_str::<serde_json::Value>(line).unwrap()["sequence"]
                        .as_u64()
                        .unwrap(),
                );
            }
        }
        assert!(bytes <= 540);
        assert!(sequences.contains(&19));
        assert!(!sequences.contains(&0));
    }
    #[test]
    fn unknown_files_symlinks_and_busy_writer_are_not_overwritten_or_waited_on() {
        let t = temp();
        let uid = claude_watch_system::effective_uid();
        let logs = t.0.join("logs");
        directory(&logs, uid, true).unwrap();
        fs::write(logs.join("foreign"), b"keep").unwrap();
        assert!(emit_at(&logs, uid, b"{}", 180).is_err());
        assert_eq!(fs::read(logs.join("foreign")).unwrap(), b"keep");
        fs::remove_file(logs.join("foreign")).unwrap();
        let target = t.0.join("target");
        fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, logs.join(FILE)).unwrap();
        assert!(emit_at(&logs, uid, b"{}", 180).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        fs::remove_file(logs.join(FILE)).unwrap();
        emit_at(&logs, uid, b"{}", 180).unwrap();
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(logs.join(".write.lock"))
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert_eq!(
            emit_at(&logs, uid, b"{}", 180).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn a_stalled_log_writer_cannot_block_handoff_event_submission() {
        let temp = temp();
        let uid = claude_watch_system::effective_uid();
        let logs = temp.0.join("recovered");
        directory(&logs, uid, true).unwrap();
        let written_logs = logs.clone();
        let (entered, waiting) = std::sync::mpsc::sync_channel(1);
        let (release, resume) = std::sync::mpsc::sync_channel(1);
        let (reported, report) = std::sync::mpsc::sync_channel(2);
        let mut first = true;
        let mut summary_attempts = 0;
        let logger = AsyncLog::new(move |body| {
            if first {
                first = false;
                entered.send(()).unwrap();
                resume.recv().unwrap();
                return Err(io::Error::other("fixture writer failed"));
            }
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if value["operation"] == "logging_recovery" {
                summary_attempts += 1;
                if summary_attempts == 1 {
                    return Err(io::Error::other("fixture summary write also failed"));
                }
            }
            emit_at(&written_logs, uid, &body, LIMIT)?;
            if value["operation"] == "logging_recovery" {
                reported.send(()).unwrap();
            }
            Ok(())
        })
        .unwrap();
        let body = event(
            "listener_handoff",
            "completed",
            "descriptors_transferred",
            None,
            None,
        );
        assert!(logger.send(body.clone()));
        waiting
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        for _ in 0..64 {
            assert!(logger.send(body.clone()));
        }
        let started = std::time::Instant::now();
        assert!(!logger.send(body));
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        release.send(()).unwrap();
        report
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        let values: Vec<serde_json::Value> = fs::read_to_string(logs.join(FILE))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let summary = values
            .iter()
            .find(|value| value["operation"] == "logging_recovery")
            .unwrap();
        assert_eq!(summary["dropped_queue_records"], 1);
        assert_eq!(summary["failed_write_records"], 1);
        assert_eq!(summary["counts_saturated"], false);
        assert_eq!(summary["reason"], "log_records_lost");
        drop(logger);

        // An empty queue must not strand loss evidence after storage recovers.
        let idle = temp.0.join("idle-recovery");
        directory(&idle, uid, true).unwrap();
        let written_idle = idle.clone();
        let (reported, report) = std::sync::mpsc::sync_channel(1);
        let mut failures = 2;
        let logger = AsyncLog::new(move |body| {
            if failures > 0 {
                failures -= 1;
                return Err(io::Error::other("fixture unavailable"));
            }
            emit_at(&written_idle, uid, &body, LIMIT)?;
            reported.send(()).unwrap();
            Ok(())
        })
        .unwrap();
        assert!(logger.send(event(
            "listener_handoff",
            "rejected",
            "peer_identity_rejected",
            None,
            None
        )));
        report
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        let summary: serde_json::Value =
            serde_json::from_str(fs::read_to_string(idle.join(FILE)).unwrap().trim()).unwrap();
        assert_eq!(summary["dropped_queue_records"], 0);
        assert_eq!(summary["failed_write_records"], 1);
        assert_eq!(summary["operation"], "logging_recovery");
        drop(logger);
    }
}
