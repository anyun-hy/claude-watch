//! Background WebKit refresh has an independent worker so slow external
//! diagnostics cannot pause process/session protection or heartbeat publication.
use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
    session::Desktop,
};
use claude_watch_runtime::{
    audit_store::AuditSystem,
    background_evidence::{self, EvidenceSystem, ProbeKind},
    desktop_native::NativeDesktop,
    events::{EventFields, EventStore},
    macos::Authority,
    native,
    storage::{Paths, StateStore},
};
use serde_json::Value;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

struct NativeEvidence {
    host: super::runtime::Host,
    desktop: NativeDesktop<Arc<claude_watch_runtime::commands::SystemRunner>>,
    stop: Arc<AtomicBool>,
}
fn next_interval(failures: &mut u32, incomplete: bool) -> Duration {
    if incomplete {
        *failures = failures.saturating_add(1).min(3);
        Duration::from_secs((5u64 << *failures).min(30))
    } else {
        *failures = 0;
        Duration::from_secs(5)
    }
}
impl EvidenceSystem for NativeEvidence {
    fn now(&self) -> f64 {
        native::now()
    }
    fn local(&mut self, config: &Config) -> Result<Value> {
        AuditSystem::local(&self.host, config)
    }
    fn desktop_matches(&mut self, expected: &Desktop) -> Result<bool> {
        Ok(self
            .desktop
            .desktops()?
            .iter()
            .any(|(actual, main, _)| *main && actual == expected))
    }
    fn collect(&mut self, kind: ProbeKind) -> Result<Value> {
        background_evidence::collect_native(
            &self.host.storage,
            &self.host.runner,
            &mut background_evidence::ProbeExecutor::new(self.stop.clone()),
            kind,
        )
    }
    fn cancelled(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
}
pub fn spawn(paths: Paths, stop: Arc<AtomicBool>) -> Result<thread::JoinHandle<()>> {
    let store = StateStore::new(paths.clone());
    let host = super::runtime::host(paths, Authority::ReadOnly)?;
    let desktop = NativeDesktop::new(
        host.runner.clone(),
        super::runtime::process_component()?,
        Authority::ReadOnly,
    )?;
    thread::Builder::new()
        .name("claude-background-evidence".into())
        .spawn(move || {
            let mut system = NativeEvidence {
                host,
                desktop,
                stop: stop.clone(),
            };
            let events = EventStore::new(store.clone());
            let mut last_report = String::new();
            let mut last_report_at = Instant::now();
            let mut failures = 0;
            while !stop.load(Ordering::Acquire) {
                let started = Instant::now();
                let outcome = background_evidence::refresh_active_session(&store, &mut system);
                let (status, code, count) = match &outcome {
                    Ok(v) => (
                        v["status"].as_str().unwrap_or("incomplete"),
                        None,
                        v["count"].as_u64().unwrap_or(0) as u32,
                    ),
                    Err(e) => (
                        "incomplete",
                        Some(match e.code.as_str() {
                            "evidence_worker_missing"
                            | "evidence_runtime_invalid"
                            | "evidence_context_changed"
                            | "evidence_context_unconfirmed"
                            | "evidence_session_changed"
                            | "evidence_policy_changed"
                            | "desktop_inventory_incomplete" => e.code.as_str(),
                            _ => "evidence_refresh_failed",
                        }),
                        0,
                    ),
                };
                let signature = format!("{status}:{code:?}");
                if status != "idle"
                    && (count > 0
                        || signature != last_report
                        || last_report_at.elapsed() >= Duration::from_secs(300))
                {
                    let _ = events.append(
                        "background-evidence",
                        EventFields {
                            operation: Some("session-evidence".into()),
                            status: Some(status.into()),
                            code: code.map(str::to_owned),
                            stage: outcome.as_ref().ok().and_then(|v| {
                                let probes = if status == "risk" {
                                    &v["risk_probes"]
                                } else {
                                    &v["failed_probes"]
                                };
                                let names = probes
                                    .as_array()?
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .collect::<Vec<_>>();
                                (!names.is_empty()).then(|| names.join("-"))
                            }),
                            count: Some(count),
                            elapsed_seconds: Some(started.elapsed().as_secs_f64()),
                            ..Default::default()
                        },
                        native::now(),
                    );
                    last_report_at = Instant::now();
                }
                last_report = signature;
                let interval = next_interval(&mut failures, status == "incomplete");
                while !stop.load(Ordering::Acquire) && started.elapsed() < interval {
                    thread::sleep(Duration::from_millis(100));
                }
            }
        })
        .map_err(|_| CoreError::new("evidence_worker_failed", "保护证据更新线程无法启动"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_probes_back_off_without_delaying_guard_or_renewing_evidence() {
        let mut failures = 0;
        for seconds in [10, 20, 30, 30, 30] {
            assert_eq!(
                next_interval(&mut failures, true),
                Duration::from_secs(seconds)
            );
        }
        assert_eq!(next_interval(&mut failures, false), Duration::from_secs(5));
        assert_eq!(next_interval(&mut failures, true), Duration::from_secs(10));
    }
}
