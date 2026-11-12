//! Explicitly selected read-only host comparison, never an installed-service test.
use claude_watch_runtime::{commands::{ReadCommand, ReadRunner, SystemRunner}, native::Observer,
    sampler::parse_process_table};
use std::time::{Duration, Instant};

#[test]
#[ignore = "read-only macOS host timing of global versus selected-PID observation"]
fn fixed_pid_observation_avoids_global_inventory_cost() {
    let runner = SystemRunner::development().unwrap();
    let pid = std::process::id();
    let expected = runner.process_identity(pid).expect("owned test process kernel identity");
    let mut global = Vec::new();
    let mut targeted = Vec::new();
    for _ in 0..3 {
        let start = Instant::now();
        let inventory = (Observer { runner: &runner }).inventory().expect("read-only native inventory");
        assert!(inventory.processes.get(&pid).is_some_and(|row| row.identity.same_process(&expected)));
        let table = runner.run(ReadCommand::ProcessTable, &[], Duration::from_secs(3), 4 * 1024 * 1024).unwrap();
        assert_eq!(table.status, 0);
        assert!(parse_process_table(table.text().unwrap()).unwrap().contains_key(&pid));
        global.push(start.elapsed());

        let start = Instant::now();
        for _ in 0..3 { assert!(runner.process_identity(pid).is_some_and(|actual| actual.same_process(&expected))); }
        let table = runner.run(ReadCommand::ProcessTablePids { pids: vec![pid] }, &[], Duration::from_secs(1), 4096).unwrap();
        assert_eq!(table.status, 0);
        let table = parse_process_table(table.text().unwrap()).unwrap();
        assert_eq!(table.len(), 1);
        assert_eq!(table[&pid]["stamp"], expected.start_stamp);
        targeted.push(start.elapsed());
    }
    eprintln!("scope=owned-test-PID kernel identity + metadata; global_inventory_and_ps={global:?}; three_fixed_kernel_reads_and_targeted_ps={targeted:?}");
    assert!(targeted.iter().all(|elapsed| *elapsed < Duration::from_secs(1)), "fixed-PID primitive budget");
}

#[test]
#[ignore = "authorized read-only current TAG/controller and authenticated published native snapshots; no state writes"]
fn current_published_native_snapshot_and_controller_three_readonly_rounds() {
    use claude_watch_runtime::{config_store::ConfigStore, native, native_listener,
        storage::{Paths, StateStore}, vpn_observer::{HttpControllerVpnReader, VpnObserver,
            read_vpn_kernel_snapshot, resolve_vpn_controller_credentials, VPN_OBSERVATION_BUDGET}};
    use std::sync::{Arc, Mutex};

    // Read the existing configuration in place. This observer has no storage,
    // so it cannot publish samples or modify the running daemon's records.
    let home = std::env::var_os("HOME").expect("existing user home");
    let paths = Paths::new(home).unwrap();
    paths.require_owner(claude_watch_system::effective_uid()).unwrap();
    let store = StateStore::new(paths);
    let config = ConfigStore { storage: store.clone() }.load().unwrap();
    let expectation = config.vpn_expectation.expect("existing configured VPN expectation");
    assert!(expectation.configured && expectation.proxy_mode == "tag", "diagnostic requires the existing TAG expectation");
    let credentials = resolve_vpn_controller_credentials(&store, &expectation.proxy_mode).unwrap();
    let runner = SystemRunner::development().unwrap().with_listener_cache(store.clone());

    // Fail with the authenticated API's exact reason before considering any
    // standalone netstat fallback. No unverified JSON is accepted as evidence.
    let preflight_started = Instant::now();
    native_listener::read_cached(&store, &runner).unwrap_or_else(|error|
        panic!("published_native_snapshot_preflight={}", error.code));
    eprintln!("published_native_snapshot_preflight=verified elapsed_ms={:.3}", preflight_started.elapsed().as_secs_f64() * 1000.0);

    let frames = Arc::new(Mutex::new(Vec::new()));
    let observed = frames.clone();
    let reader = HttpControllerVpnReader::new_live("tag", credentials)
        .with_listener_snapshot_probe(Box::new(move |remaining| {
            let snapshot = read_vpn_kernel_snapshot(&runner, remaining)?;
            // A fallback table is deliberately not an acceptance result for
            // this hypothesis: it must carry the authenticated native frame.
            let sequence = snapshot.sequence?;
            snapshot.origin_id.as_ref()?;
            observed.lock().unwrap().push((sequence, snapshot.captured_at));
            Some(snapshot)
        }));
    let mut observer = VpnObserver::new("readonly-published-native-diagnostic", None);
    let mut verified = 0;
    for round in 0..3 {
        frames.lock().unwrap().clear();
        let now = native::now();
        let started = Instant::now();
        let result = observer.observe_from_reader(&reader, &expectation, round == 0, now).unwrap();
        let elapsed = started.elapsed();
        let observations = frames.lock().unwrap();
        let ages = observations.iter().map(|(_, captured)| (now - captured) * 1000.0).collect::<Vec<_>>();
        let same_frame = observations.len() == 2 && observations[0] == observations[1];
        let observation = result.observation;
        let remaining_ms = (observation.valid_until - native::now()) * 1000.0;
        eprintln!("readonly_round={} elapsed_ms={:.3} verdict={} source_verified={} source_error={} frames={} same_frame={} original_frame_age_ms={ages:?} evidence_remaining_ms={remaining_ms:.3}",
            round + 1, elapsed.as_secs_f64() * 1000.0, result.verdict.reason_code(), observation.source_instance.is_some(),
            observation.source_error.as_deref().unwrap_or("none"), observations.len(), same_frame);
        assert!(elapsed < VPN_OBSERVATION_BUDGET, "complete read-only round exceeded existing budget");
        if result.verdict.is_matched() && observation.consistency.is_consistent()
            && observation.source_error.is_none() && observation.source_instance.is_some() && remaining_ms > 0.0 {
            assert_eq!(observations.len(), 2);
            let oldest_frame = observations.iter().map(|(_, time)| *time).fold(f64::INFINITY, f64::min);
            assert!(observation.valid_until <= oldest_frame + 3.5, "native frame must not be renewed");
            verified += 1;
        }
        drop(observations);
        if round < 2 { std::thread::sleep(Duration::from_millis(150)); }
    }
    assert_eq!(verified, 3, "all three current rounds must retain verified fresh native evidence");
}
