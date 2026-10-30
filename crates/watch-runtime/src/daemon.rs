//! Single-owner daemon heartbeat and bounded round publication.
use crate::{
    monitor_snapshot,
    storage::{OperationLock, StateStore},
};
use claude_watch_core::{
    error::{CoreError, Result},
    processes::{normalized_stamp, Identity},
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const PROCESS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
pub const NETWORK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

pub struct ShutdownSignals(Vec<signal_hook::SigId>);
impl Drop for ShutdownSignals {
    fn drop(&mut self) {
        for id in self.0.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}
pub fn shutdown_signals(
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<ShutdownSignals> {
    let mut signals = ShutdownSignals(Vec::new());
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signals.0.push(
            signal_hook::flag::register(signal, stop.clone())
                .map_err(|_| CoreError::new("daemon_signal_failed", "后台停止信号无法注册"))?,
        );
    }
    Ok(signals)
}
pub struct DaemonLease {
    pub storage: StateStore,
    pub producer: Identity,
    _lock: OperationLock,
}
impl DaemonLease {
    pub fn acquire(
        storage: StateStore,
        producer: Identity,
        inventory: &BTreeMap<u32, Identity>,
    ) -> Result<Self> {
        if !producer.valid()
            || producer.uid == 0
            || !inventory
                .get(&producer.pid)
                .is_some_and(|p| p.same_process(&producer))
        {
            return Err(CoreError::new(
                "daemon_identity_invalid",
                "后台启动身份未能确认",
            ));
        }
        let lock = storage.lock("daemon", None)?;
        for (path, fields) in [
            (storage.paths.watch().join("state/heartbeat"), 5),
            (storage.paths.watch().join("state/daemon.lock/owner"), 2),
        ] {
            if let Some(bytes) = storage.read_bytes(&path, 4096)? {
                let text = std::str::from_utf8(&bytes).map_err(|_| {
                    CoreError::new("invalid_daemon_record", "旧后台身份记录格式无效")
                })?;
                let parts = text.trim().split('|').collect::<Vec<_>>();
                if parts.len() != fields {
                    return Err(CoreError::new(
                        "invalid_daemon_record",
                        "旧后台身份记录不完整",
                    ));
                }
                let pid = parts[0]
                    .parse::<u32>()
                    .map_err(|_| CoreError::new("invalid_daemon_record", "旧后台 PID 无效"))?;
                if pid != producer.pid
                    && inventory.get(&pid).is_some_and(|p| {
                        normalized_stamp(&p.start_stamp) == normalized_stamp(parts[1])
                    })
                {
                    return Err(CoreError::new(
                        "daemon_already_running",
                        "已有本工具后台运行，未启动第二套自有保镖",
                    ));
                }
            }
        }
        Ok(Self {
            storage,
            producer,
            _lock: lock,
        })
    }
    pub fn publish(&self, sample: Result<Value>, now: f64) -> Result<Value> {
        if !now.is_finite() || now <= 0.0 {
            return Err(CoreError::new("invalid_clock", "后台时钟无效"));
        }
        let snapshot = match sample {
            Ok(value) => value,
            Err(error) => {
                let mut value = monitor_snapshot::empty(&self.storage, now, &error.message);
                value["health"]["pid"] = json!(self.producer.pid);
                value["health"]["started"] = json!(self.producer.start_stamp);
                value
            }
        };
        let quality = if snapshot["health"]["state"] == "running" {
            "ok"
        } else {
            "error"
        };
        let mode = snapshot["health"]["mode"]
            .as_str()
            .filter(|v| matches!(*v, "ACTIVE" | "GUARD" | "UNKNOWN"))
            .unwrap_or("UNKNOWN");
        monitor_snapshot::publish(&self.storage, &snapshot, &self.producer)?;
        self.storage.atomic_bytes(
            &self.storage.paths.watch().join("state/heartbeat"),
            format!(
                "{}|{}|{}|{quality}|{mode}\n",
                self.producer.pid,
                self.producer.start_stamp,
                now.floor()
            )
            .as_bytes(),
            0o600,
        )?;
        Ok(snapshot)
    }
}
