//! Bounded, read-only publication of one native observation round.
//!
//! This module deliberately owns no launchd or process-control capability.  A
//! future daemon supplies its already native-verified identity, samples using a
//! persistent [`Sampler`], and atomically publishes a presentation snapshot.
use crate::{
    commands::{ReadCommand, ReadRunner},
    monitor_snapshot,
    native::{self, Observer},
    sampler::Sampler,
    storage::{strict_json, StateStore},
};
use claude_watch_core::{
    error::{CoreError, Result},
    processes::{Identity, Target},
};
use serde_json::{json, Value};
use std::{fs, os::unix::fs::MetadataExt, time::Duration};

const AGENT_LABEL: &str = "io.local.claudewatch.agent";

fn registration_unknown() -> Value {
    json!({"installed":false,"autoStart":false,"keepAlive":false,"loadedState":"unknown","detail":"后台注册信息不可读取"})
}

/// Reads the one fixed user LaunchAgent definition and its loaded state.  This
/// is registration evidence only; it must never upgrade sampling health.
pub fn registration<R: ReadRunner>(store: &StateStore, runner: &R, uid: u32) -> Result<Value> {
    if uid == 0 {
        return Err(CoreError::new("invalid_uid", "后台读取 UID 无效"));
    }
    let plist = store
        .paths
        .home
        .join(format!("Library/LaunchAgents/{AGENT_LABEL}.plist"));
    let script = store.paths.watch().join("claude-watch.sh");
    let engine = store.paths.watch().join("runtime/watch-engine");
    let collector = store
        .paths
        .watch()
        .join("runtime")
        .join(crate::native_listener::SCRIPT);
    store.guarded(&plist)?;
    store.guarded(&script)?;
    store.guarded(&engine)?;
    store.guarded(&collector)?;
    let regular_owned = |path: &std::path::Path| match fs::symlink_metadata(path) {
        Ok(meta) => {
            meta.is_file()
                && !meta.file_type().is_symlink()
                && meta.uid() == uid
                && meta.mode() & 0o022 == 0
        }
        Err(_) => false,
    };
    if !regular_owned(&plist) {
        return Ok(
            json!({"installed":false,"autoStart":false,"keepAlive":false,"loadedState":"absent","detail":"固定 LaunchAgent 定义或监控脚本未通过核对"}),
        );
    }
    if fs::metadata(&plist)
        .map_err(|_| CoreError::new("service_read_failed", "后台定义不可读取"))?
        .len()
        > 256 * 1024
    {
        return Ok(registration_unknown());
    }
    let output = runner.run(
        ReadCommand::Plist(plist),
        &[],
        Duration::from_secs(3),
        256 * 1024,
    )?;
    let value = if output.status == 0 {
        strict_json(&output.stdout).ok()
    } else {
        None
    };
    let expected = json!([engine, "daemon", "--apply"]);
    let supervised = json!(["/bin/zsh", "-f", collector, "daemon", "--apply"]);
    let legacy = json!(["/bin/bash", script, "daemon"]);
    let trusted = value.as_ref().is_some_and(|v| {
        v["Label"] == AGENT_LABEL
            && v["Program"].is_null()
            && ((v["ProgramArguments"] == expected && regular_owned(&engine))
                || (v["ProgramArguments"] == supervised
                    && regular_owned(&engine)
                    && regular_owned(&collector))
                || (v["ProgramArguments"] == legacy && regular_owned(&script)))
    });
    let auto_start = trusted && value.as_ref().is_some_and(|v| v["RunAtLoad"] == true);
    let keep_alive = trusted && value.as_ref().is_some_and(|v| v["KeepAlive"] == true);
    let status = runner.run(
        ReadCommand::LaunchctlGuiAgent { uid },
        &[],
        Duration::from_secs(3),
        256 * 1024,
    );
    let loaded = match status {
        Ok(output) if output.status == 0 => output
            .text()
            .ok()
            .and_then(|text| {
                text.lines()
                    .filter_map(|line| line.trim().split_once(" = "))
                    .find_map(|(key, value)| (key == "state").then(|| value.trim().to_owned()))
            })
            .unwrap_or_else(|| "unknown".into()),
        Ok(_) => "not_loaded".into(),
        Err(_) => "unknown".into(),
    };
    Ok(
        json!({"installed":trusted,"autoStart":auto_start,"keepAlive":keep_alive,"loadedState":loaded,"detail":if trusted{"固定 LaunchAgent 定义已核对"}else{"固定 LaunchAgent 定义无效"}}),
    )
}

/// Reusable publisher for repeated daemon rounds.  It has only read-observer
/// commands and StateStore atomic publication; it cannot launch or stop apps.
pub struct SnapshotPublisher<R: ReadRunner> {
    store: StateStore,
    sampler: Sampler<R>,
    producer: Identity,
    last_network: Option<(std::time::Instant, Vec<Target>, Value, bool)>,
    last_network_retry: Option<std::time::Instant>,
    last_activity: Value,
    last_traffic_event: Option<std::time::Instant>,
}

/// Retry one incomplete network round early, but rate-limit repeated failures
/// to avoid turning a persistent collector problem into continuous probing.
fn network_refresh_due(
    age: Duration,
    targets_changed: bool,
    previous_complete: bool,
    last_retry_age: Option<Duration>,
) -> (bool, bool) {
    let early_retry = !targets_changed
        && !previous_complete
        && age >= crate::daemon::PROCESS_INTERVAL
        && age < crate::daemon::NETWORK_INTERVAL
        && last_retry_age.is_none_or(|age| age >= crate::daemon::NETWORK_INTERVAL);
    (
        targets_changed || age >= crate::daemon::NETWORK_INTERVAL || early_retry,
        early_retry,
    )
}

impl<R: ReadRunner> SnapshotPublisher<R> {
    pub fn new(store: StateStore, sampler: Sampler<R>, producer: Identity) -> Result<Self> {
        if !producer.valid() {
            return Err(CoreError::new(
                "invalid_snapshot_producer",
                "快照生产者身份无效",
            ));
        }
        Ok(Self {
            store,
            sampler,
            producer,
            last_network: None,
            last_network_retry: None,
            last_activity: json!({}),
            last_traffic_event: None,
        })
    }

    /// Collect and publish one internally consistent process/socket/TAG round.
    pub fn sample_once(&mut self, group: &str, pin: &str) -> Result<Value> {
        self.poll(group, pin, true)
    }
    pub fn poll(&mut self, group: &str, pin: &str, force_network: bool) -> Result<Value> {
        let current = Observer {
            runner: &self.sampler.runner,
        }
        .identities(std::slice::from_ref(&self.producer), "snapshot-publisher")?;
        if !current
            .get(&self.producer.pid)
            .is_some_and(|v| v.same_process(&self.producer))
        {
            return Err(CoreError::new(
                "snapshot_producer_changed",
                "快照生产者启动身份未通过核对",
            ));
        }
        let processes = self.sampler.processes()?;
        let (due, early_retry) =
            self.last_network
                .as_ref()
                .map_or((true, false), |(time, targets, _, complete)| {
                    network_refresh_due(
                        time.elapsed(),
                        targets != &processes.targets,
                        *complete,
                        self.last_network_retry.map(|at| at.elapsed()),
                    )
                });
        let refresh = force_network || due;
        if refresh {
            if early_retry {
                self.last_network_retry = Some(std::time::Instant::now());
            }
            let sockets = self.sampler.sockets(&processes)?;
            let tag = self.sampler.tag_report(&processes, &sockets, group, pin);
            let quality = processes.complete
                && matches!(
                    sockets.receipt["collector_state"].as_str(),
                    Some("ok" | "empty" | "no_targets")
                );
            self.last_network = Some((
                std::time::Instant::now(),
                processes.targets.clone(),
                tag,
                quality,
            ));
        }
        let (_, _, tag, network_quality) = self
            .last_network
            .as_ref()
            .ok_or_else(|| CoreError::new("network_sample_missing", "缺少本轮连接采样"))?;
        let mut quality = processes.complete && *network_quality;
        let leases = crate::lease_store::LeaseStore {
            storage: self.store.clone(),
        };
        let current = leases.load(&processes.identities, processes.uid, processes.complete)?;
        let authorization = claude_watch_core::processes::authorization(
            &processes.targets,
            &current,
            &processes.identities,
            processes.uid,
        );
        let active: Vec<u32> = authorization["active_pids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_u64().and_then(|n| u32::try_from(n).ok()))
            .collect();
        leases.save_tracked(&processes.targets, processes.complete)?;
        if refresh {
            let identities = processes
                .targets
                .iter()
                .map(|p| p.identity.clone())
                .collect::<Vec<_>>();
            let mut activity = crate::monitor_activity::collect(
                &self.sampler.runner,
                &self.store.paths.home,
                &identities,
                &active,
            );
            activity["observed_at"] = json!(native::now());
            let record_traffic = self
                .last_traffic_event
                .is_none_or(|at| at.elapsed() >= Duration::from_secs(300));
            record_activity(
                &self.store,
                &self.last_activity,
                &activity,
                native::now(),
                record_traffic,
            )?;
            if record_traffic
                && activity["bytes"]["rows"]
                    .as_array()
                    .is_some_and(|rows| !rows.is_empty())
            {
                self.last_traffic_event = Some(std::time::Instant::now());
            }
            self.last_activity = activity;
        }
        quality = quality
            && matches!(
                self.last_activity["state"].as_str(),
                Some("ok" | "no_targets")
            )
            && (processes.targets.is_empty() || self.last_activity["bytes"]["state"] != "empty");
        let registration = registration(&self.store, &self.sampler.runner, self.producer.uid)
            .unwrap_or_else(|_| registration_unknown());
        let mut snapshot = monitor_snapshot::with_registration(
            monitor_snapshot::assemble(
                &self.store,
                &processes,
                tag,
                &self.producer,
                if quality {
                    authorization["mode"].as_str().unwrap_or("GUARD")
                } else {
                    "UNKNOWN"
                },
                quality,
                native::now(),
            ),
            &registration,
        );
        snapshot["processes"] = json!(monitor_snapshot::process_rows(&processes, &active));
        snapshot["activity"] = self.last_activity.clone();
        let mut activity_reasons = std::collections::BTreeMap::<String, u32>::new();
        for value in self.last_activity["unavailable"].as_array().into_iter().flatten() {
            let key = match value.as_str() {
                Some(code @ ("identity_before_unavailable" | "identity_after_unavailable" | "identity_unverified" | "file_sample_unavailable" | "byte_sample_unavailable" | "service_sample_unavailable")) => code,
                _ => "other",
            };
            let count = activity_reasons.entry(key.to_owned()).or_default(); *count = count.saturating_add(1);
        }
        let activity_state = self.last_activity["state"].as_str().filter(|s| ["ok","partial","unavailable","no_targets"].contains(s)).unwrap_or("unknown");
        let bytes_state = self.last_activity["bytes"]["state"].as_str().filter(|s| ["ok","empty","unavailable","no_targets"].contains(s)).unwrap_or("unknown");
        let network_observation = &tag["connection_observation"];
        let diagnostics = crate::events::SamplingDiagnostics {
            process_complete: Some(processes.complete), process_reasons: processes.diagnostic_reasons.clone(), process_confirmed_exited_count: processes.confirmed_exited_count, process_sampled_at: Some(processes.observed_at),
            network_quality: Some(*network_quality), network_round_id: network_observation["round_id"].as_str().filter(|s| uuid::Uuid::parse_str(s).is_ok()).map(str::to_owned),
            network_sampled_at: network_observation["observed_at"].as_f64(), network_reused: Some(!refresh),
            activity_state: activity_state.into(), bytes_state: bytes_state.into(), activity_reasons,
            activity_sampled_at: self.last_activity["observed_at"].as_f64(), publisher_error_code: None,
        };
        if diagnostics.valid() { snapshot["samplingDiagnostics"] = serde_json::to_value(diagnostics).unwrap_or(Value::Null); }

        snapshot["health"]["alerts"] = json!(if crate::events::EventStore::new(self.store.clone())
            .notifications_enabled(native::now())
        {
            "开启"
        } else {
            "静默"
        });
        let mut raw_tag = tag.clone();
        raw_tag["producer"] = json!({"pid":self.producer.pid,"started":self.producer.start_stamp});
        self.store.atomic_json(
            &self.store.paths.watch().join("state/proxy-snapshot.json"),
            &raw_tag,
        )?;
        monitor_snapshot::publish(&self.store, &snapshot, &self.producer)?;
        Ok(snapshot)
    }

    pub fn store(&self) -> &StateStore {
        &self.store
    }
    pub fn producer(&self) -> &Identity {
        &self.producer
    }
}

fn record_activity(
    store: &StateStore,
    previous: &Value,
    current: &Value,
    now: f64,
    record_traffic: bool,
) -> Result<()> {
    use crate::events::{EventFields, EventStore};
    let log = EventStore::new(store.clone());
    for row in current["bytes"]["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|_| record_traffic)
    {
        log.append(
            "traffic-counter",
            EventFields {
                pid: row["pid"].as_u64().and_then(|v| u32::try_from(v).ok()),
                bytes_in: row["bytesIn"].as_u64(),
                bytes_out: row["bytesOut"].as_u64(),
                ..Default::default()
            },
            now,
        )?;
    }
    for (field, list, kind) in [
        ("files", "rows", "sensitive-open-descriptor"),
        ("services", "candidates", "launchd-label-candidate"),
    ] {
        let before = previous[field][list].as_array();
        for row in current[field][list].as_array().into_iter().flatten() {
            if before.is_some_and(|values| values.contains(row)) {
                continue;
            }
            let pid = row["pid"].as_u64().and_then(|v| u32::try_from(v).ok());
            if field == "files"
                && current["targets"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|v| v["pid"] == row["pid"] && v["authorized"] == true)
            {
                continue;
            }
            log.append(
                kind,
                EventFields {
                    pid,
                    count: row["fd"].as_u64().and_then(|v| u32::try_from(v).ok()),
                    code: row["category"].as_str().map(str::to_owned),
                    service_label: row["label"].as_str().map(str::to_owned),
                    ..Default::default()
                },
                now,
            )?;
        }
    }
    if previous["state"] != current["state"] {
        let unavailable = matches!(current["state"].as_str(), Some("unavailable" | "partial"));
        log.append(
            if unavailable {
                "activity-unavailable"
            } else {
                "activity-recovered"
            },
            EventFields {
                status: current["state"].as_str().map(str::to_owned),
                ..Default::default()
            },
            now,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_network_round_gets_one_bounded_early_retry() {
        let seconds = Duration::from_secs;
        assert_eq!(
            network_refresh_due(seconds(1), false, false, None),
            (false, false)
        );
        assert_eq!(
            network_refresh_due(seconds(2), false, false, None),
            (true, true)
        );
        assert_eq!(
            network_refresh_due(seconds(2), false, false, Some(seconds(2))),
            (false, false)
        );
        assert_eq!(
            network_refresh_due(seconds(10), false, false, Some(seconds(10))),
            (true, false)
        );
        assert_eq!(
            network_refresh_due(seconds(2), false, true, None),
            (false, false)
        );
        assert_eq!(
            network_refresh_due(seconds(1), true, true, None),
            (true, false)
        );
    }
    use crate::{
        commands::{ObserverAction, Output},
        monitor_snapshot::{connection_observation, read},
        storage::Paths,
    };
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicBool, Ordering},
    };

    fn identity() -> Identity {
        Identity {
            pid: 77,
            parent: 1,
            uid: 501,
            executable: "/usr/local/bin/watch-engine".into(),
            start_seconds: 1000,
            start_microseconds: 1,
            start_stamp: "stamp".into(),
        }
    }
    fn temp() -> (PathBuf, StateStore) {
        let path =
            std::env::temp_dir().join(format!("snapshot-publication-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        let store = StateStore::new(Paths::new(&path).unwrap());
        (path, store)
    }
    #[test]
    fn throttled_traffic_keeps_samples_separate_without_suppressing_activity_warnings() {
        let (path, store) = temp();
        let activity = json!({"state":"ok","bytes":{"rows":[{"pid":77,"bytesIn":4,"bytesOut":5}]},"files":{"rows":[]},"services":{"candidates":[]}});
        record_activity(&store, &activity, &activity, 10.0, true).unwrap();
        record_activity(&store, &activity, &activity, 11.0, false).unwrap();
        let mut partial = activity.clone();
        partial["state"] = json!("partial");
        record_activity(&store, &activity, &partial, 12.0, false).unwrap();
        let history = crate::events::EventStore::new(store.clone())
            .history()
            .unwrap()
            .events;
        assert_eq!(
            history
                .iter()
                .filter(|e| e.category == "traffic-counter")
                .count(),
            1
        );
        assert!(history.iter().any(|e| e.category == "activity-unavailable"));
        assert_eq!(activity["bytes"]["rows"][0]["bytesIn"], 4);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn connection_rounds_keep_zero_target_distinct_from_empty_and_recover() {
        let at = native::now();
        let base = |state: &str, targets: u64, parsed: u64, accepted: u64| json!({"round_id":"r","observed_at":at,"collector_state":state,"target_count":targets,"parsed_count":parsed,"accepted_count":accepted,"correlated_count":0,"unconfirmed_count":0,"dropped":{},"detail":""});
        assert_eq!(
            connection_observation(&base("no_targets", 0, 0, 0), at)["collectorState"],
            "no_targets"
        );
        assert_eq!(
            connection_observation(&base("empty", 0, 0, 0), at)["collectorState"],
            "unknown"
        );
        assert_eq!(
            connection_observation(&base("failed", 1, 0, 0), at)["collectorState"],
            "failed"
        );
        assert_eq!(
            connection_observation(&base("empty", 1, 0, 0), at)["collectorState"],
            "empty"
        );
        assert_eq!(
            connection_observation(&base("ok", 1, 1, 1), at)["collectorState"],
            "ok"
        );
    }

    struct Fake {
        wrong: AtomicBool,
    }
    impl ReadRunner for Fake {
        fn run(&self, command: ReadCommand, _: &[u8], _: Duration, _: usize) -> Result<Output> {
            let now = native::now();
            let id = identity();
            let value = match command {
                ReadCommand::Observer(ObserverAction::Environment) => {
                    json!({"schema":1,"status":"ok","uid":501,"started_at":now,"finished_at":now})
                }
                ReadCommand::Observer(ObserverAction::Identities) => {
                    let mut current = id.clone();
                    if self.wrong.load(Ordering::Relaxed) {
                        current.start_microseconds = 2;
                    }
                    json!({"schema":1,"status":"ok","uid":501,"started_at":now,"finished_at":now,"round_id":"snapshot-producer","identities":[{"pid":77,"state":"ok","identity":current}]})
                }
                ReadCommand::LaunchctlGuiAgent { .. } => {
                    return Ok(Output {
                        status: 0,
                        stdout: b"state = running\npid = 77\n".to_vec(),
                        stderr: vec![],
                    });
                }
                _ => return Err(CoreError::new("unexpected", "unexpected fake command")),
            };
            Ok(Output {
                status: 0,
                stdout: serde_json::to_vec(&value).unwrap(),
                stderr: vec![],
            })
        }
    }
    #[test]
    fn readback_rejects_stale_and_reused_producer_identity() {
        let (path, store) = temp();
        let id = identity();
        let fake = Fake {
            wrong: AtomicBool::new(false),
        };
        monitor_snapshot::publish(&store, &json!({"capturedAt":native::now()-31.0}), &id).unwrap();
        assert_eq!(
            read(&store, &fake).unwrap()["health"]["state"],
            "unavailable"
        );
        monitor_snapshot::publish(&store, &json!({"capturedAt":native::now()}), &id).unwrap();
        fake.wrong.store(true, Ordering::Relaxed);
        assert_eq!(
            read(&store, &fake).unwrap()["health"]["state"],
            "unavailable"
        );
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn cold_start_publishes_native_inventory_without_claiming_network_or_protection_ready() {
        let (path, store) = temp();
        let id = identity();
        let inventory = std::collections::BTreeMap::from([(id.pid, id.clone())]);
        let owner = crate::daemon::DaemonLease::acquire(store.clone(), id.clone(), &inventory).unwrap();
        let mut wrong_inventory = inventory.clone();
        wrong_inventory.get_mut(&id.pid).unwrap().start_microseconds += 1;
        assert_eq!(owner.publish_initial_inventory(&wrong_inventory, native::now()).unwrap_err().code, "daemon_identity_invalid");
        assert!(!monitor_snapshot::published_path(&store).exists());
        owner.publish_initial_inventory(&inventory, native::now()).unwrap();
        let fake = Fake { wrong: AtomicBool::new(false) };
        let snapshot = read(&store, &fake).unwrap();
        assert_eq!(snapshot["health"]["state"], "degraded");
        assert_eq!(snapshot["health"]["pid"], id.pid);
        assert_eq!(snapshot["health"]["started"], id.start_stamp);
        assert_eq!(snapshot["backendVersion"], monitor_snapshot::VERSION);
        assert_eq!(snapshot["initialObservation"]["native_inventory_count"], 1);
        assert_eq!(snapshot["initialObservation"]["application_discovery"], "pending");
        assert_eq!(snapshot["samplingDiagnostics"]["process_complete"], false);
        assert!(snapshot["samplingDiagnostics"]["network_quality"].is_null());
        assert!(snapshot["proxy"].is_null() && snapshot["processes"].as_array().unwrap().is_empty());
        assert_eq!(snapshot["grants_launch_permission"], false);
        assert!(!snapshot["channelSupervision"].is_object());
        let heartbeat = String::from_utf8(store.read_bytes(&store.paths.watch().join("state/heartbeat"), 4096).unwrap().unwrap()).unwrap();
        assert!(heartbeat.contains("|error|UNKNOWN"), "initial inventory is not a healthy network heartbeat");
        fake.wrong.store(true, Ordering::Relaxed);
        assert_eq!(read(&store, &fake).unwrap()["health"]["state"], "unavailable", "startup must use the existing producer verifier");
        fake.wrong.store(false, Ordering::Relaxed);
        let mut stale = snapshot;
        stale["capturedAt"] = json!(native::now() - 31.0);
        monitor_snapshot::publish(&store, &stale, &id).unwrap();
        assert_eq!(read(&store, &fake).unwrap()["health"]["state"], "unavailable", "startup evidence cannot remain current indefinitely");
        drop(owner);
        fs::remove_dir_all(path).unwrap();
    }
    struct PipelineFake { incomplete: AtomicBool, bundle:std::path::PathBuf }
    impl ReadRunner for PipelineFake {
        fn run(&self, command: ReadCommand, input: &[u8], timeout: Duration, limit: usize) -> Result<Output> {
            let now = native::now();
            let producer = identity();
            let mut target = identity(); target.pid = 88; target.start_stamp = "target".into(); target.executable = self.bundle.join("Contents/MacOS/PrivateMain").to_string_lossy().into_owned();
            let mut body = json!({"schema":1,"status":"ok","uid":501,"started_at":now,"finished_at":now});
            match command {
                ReadCommand::Observer(ObserverAction::Inventory) => {
                    let mut app = serde_json::to_value(&target).unwrap(); app["bundle_path"] = json!(self.bundle); app["bundle_id"] = json!("com.anthropic.claudefordesktop");
                    body["state"] = json!("ok"); body["truncated"] = json!(false); body["processes"] = json!([producer,app]); body["exited"] = json!([]);
                    let bad = self.incomplete.load(Ordering::Relaxed);
                    body["unavailable"] = if bad { json!([{"pid":90,"code":"identity_unavailable"}]) } else { json!([]) };
                    body["requested_count"] = json!(if bad {3} else {2});
                }
                ReadCommand::Observer(ObserverAction::Arguments) | ReadCommand::Observer(ObserverAction::Identities) | ReadCommand::Observer(ObserverAction::Sockets) => {
                    let request: Value = serde_json::from_slice(input).unwrap(); body["round_id"] = request["round_id"].clone();
                    let targets = request["targets"].as_array().unwrap();
                    match command {
                        ReadCommand::Observer(ObserverAction::Arguments) => body["argument_prefixes"] = json!(targets.iter().map(|p| json!({"pid":p["pid"],"state":"ok","identity":p,"arguments":["Claude"],"cwd":"/tmp","truncated":false})).collect::<Vec<_>>()),
                        ReadCommand::Observer(ObserverAction::Identities) => body["identities"] = json!(targets.iter().map(|p| json!({"pid":p["pid"],"state":"ok","identity":p})).collect::<Vec<_>>()),
                        _ => body["socket_samples"] = json!(targets.iter().map(|p| json!({"pid":p["pid"],"state":"ok","identity":p,"sockets":[],"dropped":{}})).collect::<Vec<_>>()),
                    }
                }
                ReadCommand::LsofFiles {..} => return Ok(Output {status:0,stdout:vec![],stderr:vec![]}),
                ReadCommand::NettopBytes {..} => return Ok(Output {status:0,stdout:b"name,bytes_in,bytes_out\n".to_vec(),stderr:vec![]}),
                ReadCommand::LaunchctlList => return Ok(Output {status:0,stdout:vec![],stderr:vec![]}),
                ReadCommand::Plist(path)=> {
                    assert_eq!(path,self.bundle.join("Contents/Info.plist"));
                    return crate::commands::SystemRunner::development()?.run(ReadCommand::Plist(path),input,timeout,limit);
                }
                _ => return Err(CoreError::new("fixture_unavailable", "fixture")),
            }
            Ok(Output {status:0,stdout:serde_json::to_vec(&body).unwrap(),stderr:vec![]})
        }
    }
    #[test]
    fn actual_publisher_preserves_process_activity_and_reused_network_evidence() {
        let (path, store) = temp();
        use std::os::unix::fs::PermissionsExt;
        let bundle=fs::canonicalize(&path).unwrap().join("Applications/Private Client.app");fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
        let exe=bundle.join("Contents/MacOS/PrivateMain");fs::write(&exe,b"private fixture; never executed").unwrap();fs::set_permissions(exe,fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(bundle.join("Contents/Info.plist"),r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.anthropic.claudefordesktop</string><key>CFBundleExecutable</key><string>PrivateMain</string></dict></plist>"#).unwrap();
        let runner = std::sync::Arc::new(PipelineFake { incomplete: AtomicBool::new(true),bundle });
        let mut sampler = Sampler::new(runner.clone(), store.paths.clone()); sampler.use_fixture_tag();
        let mut publisher = SnapshotPublisher::new(store.clone(), sampler, identity()).unwrap();
        let first = publisher.poll("", "", true).unwrap();
        assert_eq!(first["proxy"]["connectionObservation"]["collectorState"], "partial");
        assert_eq!(first["proxy"]["connectionObservation"]["dropped"], json!({}));
        assert_eq!(first["proxy"]["connectionObservation"]["processReasonCounts"]["identity_unavailable"], 1);
        assert_eq!(first["samplingDiagnostics"]["process_complete"], false);
        runner.incomplete.store(false, Ordering::Relaxed);
        let next = publisher.poll("", "", true).unwrap();
        assert_eq!(next["proxy"]["connectionObservation"]["collectorState"], "empty");
        assert_eq!(next["samplingDiagnostics"]["bytes_state"], "empty");
        assert_eq!(next["health"]["state"], "degraded");
        std::thread::sleep(Duration::from_millis(10));
        let cached = publisher.poll("", "", false).unwrap();
        assert_eq!(cached["samplingDiagnostics"]["network_reused"], true);
        assert_eq!(cached["samplingDiagnostics"]["network_round_id"], next["samplingDiagnostics"]["network_round_id"]);
        assert_eq!(cached["samplingDiagnostics"]["network_sampled_at"], next["samplingDiagnostics"]["network_sampled_at"]);
        assert!(cached["samplingDiagnostics"]["process_sampled_at"].as_f64().unwrap() > next["samplingDiagnostics"]["process_sampled_at"].as_f64().unwrap());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn publisher_failure_keeps_only_bounded_error_code_in_sampling_diagnostics() {
        let (path, store) = temp(); let producer = identity();
        let owner = crate::daemon::DaemonLease::acquire(store.clone(), producer.clone(), &std::collections::BTreeMap::from([(producer.pid,producer)])).unwrap();
        let snapshot = owner.publish(Err(CoreError::new("state_io_failed", "private-token 203.0.113.9")), native::now()).unwrap();
        assert_eq!(snapshot["samplingDiagnostics"]["publisher_error_code"], "state_io_failed");
        assert!(snapshot["samplingDiagnostics"]["process_complete"].is_null());
        assert!(!snapshot["samplingDiagnostics"].to_string().contains("private-token"));
        drop(owner); fs::remove_dir_all(path).unwrap();
    }

}
