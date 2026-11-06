//! Audit work runs in an owned process group: a deadline stops the actual work,
//! including its sampling helpers, rather than merely abandoning a Rust thread.
use claude_watch_core::error::{CoreError, Result};
use std::{
    io::{Read, Write},
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

static PENDING_REAP: Mutex<Vec<Child>> = Mutex::new(Vec::new());
const LIMIT: usize = 2_000_000;

fn reap_group(child: &mut Child) -> bool {
    // Only the process group created by process_group(0) below is signalled.
    claude_watch_system::terminate_owned_group(child);
    let until = Instant::now() + Duration::from_millis(500);
    while Instant::now() < until {
        if child.try_wait().ok().flatten().is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

pub fn run_json(
    command: &mut Command,
    input: &serde_json::Value,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<serde_json::Value> {
    {
        let mut pending = PENDING_REAP
            .lock()
            .map_err(|_| CoreError::new("audit_cleanup_failed", "审计回收状态不可用"))?;
        pending.retain_mut(|child| child.try_wait().ok().flatten().is_none());
        if !pending.is_empty() {
            return Err(CoreError::new(
                "audit_cleanup_pending",
                "前次审计尚未回收，未重复启动",
            ));
        }
    }
    if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
        return Err(CoreError::new("audit_cancelled", "审计已取消或超过期限"));
    }
    let bytes = serde_json::to_vec(input)
        .map_err(|_| CoreError::new("invalid_audit_request", "审计请求无法编码"))?;
    if bytes.len() > 4096 {
        return Err(CoreError::new("invalid_audit_request", "审计请求过大"));
    }
    let mut child = command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| CoreError::new("audit_worker_start_failed", "审计子进程启动失败"))?;
    let result = (|| {
        child
            .stdin
            .take()
            .ok_or_else(|| CoreError::new("audit_worker_io_failed", "审计输入不可用"))?
            .write_all(&bytes)
            .map_err(|_| CoreError::new("audit_worker_io_failed", "审计输入失败"))?;
        let mut output = child
            .stdout
            .take()
            .ok_or_else(|| CoreError::new("audit_worker_io_failed", "审计输出不可用"))?;
        claude_watch_system::set_nonblocking(&output)
            .map_err(|_| CoreError::new("audit_worker_io_failed", "审计管道无法设置期限"))?;
        let mut data = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(CoreError::new(
                    "audit_cancelled",
                    "审计超时，已终止本次采样进程组",
                ));
            }
            loop {
                match output.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        data.extend_from_slice(&buffer[..n]);
                        if data.len() > LIMIT {
                            return Err(CoreError::new(
                                "audit_output_oversize",
                                "审计结果超过上限",
                            ));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(CoreError::new("audit_worker_io_failed", "审计输出失败")),
                }
            }
            if claude_watch_system::child_has_exited(&child)
                .map_err(|_| CoreError::new("audit_worker_wait_failed", "审计进程状态不可读取"))?
            {
                // Consume the final bytes written immediately before exit.
                let _ = output.read_to_end(&mut data);
                if data.len() > LIMIT {
                    return Err(CoreError::new(
                        "audit_worker_failed",
                        "审计子进程未成功完成",
                    ));
                }
                return crate::storage::strict_json(&data);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    if !reap_group(&mut child) {
        PENDING_REAP
            .lock()
            .map_err(|_| CoreError::new("audit_cleanup_failed", "审计回收状态不可用"))?
            .push(child);
        return Err(CoreError::new(
            "audit_cleanup_pending",
            "审计进程未在回收期限内退出",
        ));
    }
    if !child.try_wait().ok().flatten().is_some_and(|s| s.success()) && result.is_ok() {
        return Err(CoreError::new(
            "audit_worker_failed",
            "审计子进程未成功完成",
        ));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_deadline_reaps_owned_work_and_next_audit_can_execute() {
        let cancel = AtomicBool::new(false);
        let started = Instant::now();
        let marker = std::env::temp_dir().join(format!("cw-late-audit-{}", uuid::Uuid::new_v4()));
        let result = run_json(
            Command::new("/bin/sh")
                .args([
                    "-c",
                    "cat >/dev/null; (sleep 0.4; echo late > \"$1\") & wait",
                    "--",
                ])
                .arg(&marker),
            &serde_json::json!({}),
            started + Duration::from_millis(100),
            &cancel,
        );
        assert_eq!(result.unwrap_err().code, "audit_cancelled");
        assert!(started.elapsed() < Duration::from_secs(2));
        let next = run_json(
            Command::new("/bin/sh").args(["-c", "cat >/dev/null; printf '{\"completed\":true}'"]),
            &serde_json::json!({}),
            Instant::now() + Duration::from_secs(2),
            &cancel,
        )
        .unwrap();
        assert_eq!(next["completed"], true);
        std::thread::sleep(Duration::from_millis(450));
        assert!(
            !marker.exists(),
            "timed-out helper must not publish a late result"
        );
    }
}
