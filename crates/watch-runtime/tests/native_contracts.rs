use claude_watch_core::{
    process_roots::{self, Classification, RootEvidence, TrustedCliPaths},
    processes::{Identity, Kind},
};
use claude_watch_runtime::{
    commands::{ObserverAction, Output, ReadCommand, ReadRunner, SystemRunner},
    native::{self, Observer},
    sampler::{parse_process_table, Sampler},
    storage::Paths,
};
use serde_json::{json, Value};
use std::{
    fs,
    net::{TcpListener, TcpStream},
    path::Path,
    time::Duration,
};
use uuid::Uuid;

fn identity() -> Identity {
    Identity {
        pid: 77,
        parent: 1,
        uid: 501,
        executable: "/Applications/Claude.app/Contents/MacOS/Claude".into(),
        start_seconds: 1000,
        start_microseconds: 1,
        start_stamp: "Tue Nov 14 22:12:50 2023".into(),
    }
}
fn envelope() -> Value {
    json!({"schema":1,"status":"ok","uid":501,"started_at":1001.0,"finished_at":1002.0,"round_id":"round"})
}
#[test]
fn root_classification_requires_bundle_or_real_script_entry_not_argument_substrings() {
    let home = Path::new("/fixture");
    let trusted = TrustedCliPaths::default();
    let mut p = identity();
    let classify =
        |p: &Identity, args: Option<&[String]>, bundle: Option<&str>, id: Option<&str>| {
            process_roots::classify(
                RootEvidence {
                    identity: p,
                    arguments: args,
                    bundle_path: bundle,
                    bundle_id: id,
                    cwd: Some("/fixture"),
                },
                home,
                &trusted,
                |_| None,
            )
        };
    assert_eq!(
        classify(
            &p,
            None,
            Some("/Applications/Claude.app"),
            Some("com.anthropic.claudefordesktop")
        ),
        Classification::Root(Kind::ClaudeMain)
    );
    assert_eq!(
        classify(
            &p,
            None,
            Some("/Applications/Claude.app"),
            Some("wrong.identifier")
        ),
        Classification::NotTarget
    );
    p.executable = "/usr/local/bin/node".into();
    assert_eq!(
        classify(&p, None, None, None),
        Classification::NeedArguments
    );
    for args in [
        vec![
            "node",
            "-e",
            "/tmp/node_modules/@anthropic-ai/claude-code/cli.js",
        ],
        vec![
            "node",
            "/other/script",
            "/tmp/node_modules/@anthropic-ai/claude-code/cli.js",
        ],
        vec!["node", "--eval", "anything"],
    ] {
        let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            classify(&p, Some(&args), None, None),
            Classification::NotTarget
        );
    }
    let args = vec![
        "node".into(),
        "--require".into(),
        "safe-loader".into(),
        "/tmp/node_modules/@anthropic-ai/claude-code/cli.js".into(),
    ];
    assert_eq!(
        classify(&p, Some(&args), None, None),
        Classification::Root(Kind::ClaudeCode)
    );
}
#[test]
fn native_protocol_rejects_replay_foreign_identity_duplicates_and_conflicting_rounds() {
    let p = identity();
    let mut inv = envelope();
    inv["state"] = json!("ok");
    inv["truncated"] = json!(false);
    inv["processes"] = json!([p]);
    inv["unavailable"] = json!([]);
    inv["exited"] = json!([]);
    inv["requested_count"] = json!(1);
    assert!(
        native::decode_inventory(&inv, 1000.0, 1003.0)
            .unwrap()
            .complete
    );
    let mut duplicate = inv.clone();
    duplicate["processes"] = json!([p, p]);
    assert!(native::decode_inventory(&duplicate, 1000.0, 1003.0).is_err());
    let mut foreign = inv.clone();
    foreign["processes"][0]["uid"] = json!(502);
    assert!(native::decode_inventory(&foreign, 1000.0, 1003.0).is_err());
    assert!(native::decode_inventory(&inv, 1010.0, 1011.0).is_err());
    let mut sockets = envelope();
    sockets["socket_samples"] = json!([{"pid":77,"state":"ok","identity":p,"sockets":[{"pid":77,"fd":5,"socket_state":4,"protocol":"tcp","local":["198.18.0.1",50000],"peer":["198.18.1.10",443]}],"dropped":{}}]);
    let result =
        native::decode_sockets(&sockets, std::slice::from_ref(&p), "round", 1000.0, 1003.0)
            .unwrap();
    assert!(result.complete);
    assert_eq!(result.flows.len(), 1);
    assert!(
        native::decode_sockets(&sockets, std::slice::from_ref(&p), "wrong", 1000.0, 1003.0)
            .is_err()
    );
    sockets["socket_samples"][0]["identity"]["start_microseconds"] = json!(2);
    let changed =
        native::decode_sockets(&sockets, std::slice::from_ref(&p), "round", 1000.0, 1003.0)
            .unwrap();
    assert!(!changed.complete);
    assert!(changed.flows.is_empty());
}
struct FakeRunner;
impl ReadRunner for FakeRunner {
    fn run(
        &self,
        command: ReadCommand,
        input: &[u8],
        _timeout: Duration,
        _limit: usize,
    ) -> claude_watch_core::error::Result<Output> {
        let now = native::now();
        let p = identity();
        let mut v = json!({"schema":1,"status":"ok","uid":501,"started_at":now,"finished_at":now});
        match command {
            ReadCommand::Observer(ObserverAction::Inventory) => {
                let mut record = json!(p);
                record["bundle_path"] = json!("/Applications/Claude.app");
                record["bundle_id"] = json!("com.anthropic.claudefordesktop");
                v["state"] = json!("ok");
                v["truncated"] = json!(false);
                v["processes"] = json!([record]);
                v["unavailable"] = json!([]);
                v["exited"] = json!([]);
                v["requested_count"] = json!(1);
            }
            ReadCommand::Observer(ObserverAction::Arguments) => {
                let request: Value = serde_json::from_slice(input).unwrap();
                v["round_id"] = request["round_id"].clone();
                v["argument_prefixes"] = json!([{"pid":77,"state":"ok","identity":p,"arguments":["Claude","DO_NOT_EMIT_token"],"cwd":"/fixture","truncated":false}]);
            }
            ReadCommand::Observer(ObserverAction::Sockets) => {
                let request: Value = serde_json::from_slice(input).unwrap();
                v["round_id"] = request["round_id"].clone();
                v["socket_samples"] =
                    json!([{"pid":77,"state":"ok","identity":p,"sockets":[],"dropped":{}}]);
            }
            _ => panic!("unexpected native test command"),
        }
        Ok(Output {
            status: 0,
            stdout: serde_json::to_vec(&v).unwrap(),
            stderr: Vec::new(),
        })
    }
}
#[test]
fn sampler_strips_private_argv_and_empty_socket_sample_is_not_a_network_change() {
    let home = std::env::temp_dir().join(format!("cw-native-fixture-{}", Uuid::new_v4()));
    fs::create_dir(&home).unwrap();
    let mut sampler = Sampler::new(FakeRunner, Paths::new(&home).unwrap());
    let process = sampler.processes().unwrap();
    assert!(process.complete);
    assert_eq!(process.targets.len(), 1);
    assert!(!process.public_value().to_string().contains("DO_NOT_EMIT"));
    let socket = sampler.sockets(&process).unwrap();
    assert_eq!(socket.receipt["collector_state"], "empty");
    assert_eq!(socket.receipt["target_count"], 1);
    assert!(!home.join("Library").exists());
    fs::remove_dir_all(home).unwrap();
}
#[test]
fn ps_metadata_keeps_executable_spaces_and_rejects_duplicate_pid_identity() {
    let line =
        " 77 1 501 Tue Nov 14 22:12:50 2023 /fixture/Some Application.app/Contents/MacOS/Client\n";
    let rows = parse_process_table(line).unwrap();
    assert_eq!(rows[&77]["stamp"], "Tue Nov 14 22:12:50 2023");
    assert_eq!(
        rows[&77]["executable"],
        "/fixture/Some Application.app/Contents/MacOS/Client"
    );
    assert!(parse_process_table(&format!("{line}{line}")).is_err());
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn real_native_observer_reads_only_bound_self_socket_and_rejects_reused_identity() {
    let runner = SystemRunner::development().unwrap();
    let observer = Observer { runner: &runner };
    let inv = observer.inventory().unwrap();
    let current = inv
        .processes
        .get(&std::process::id())
        .expect("test process in owned native inventory")
        .identity
        .clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect(address).unwrap();
    let (server, _) = listener.accept().unwrap();
    let result = observer
        .sockets(std::slice::from_ref(&current), "real-socket-round")
        .unwrap();
    assert!(result
        .flows
        .iter()
        .any(|f| f.pid == current.pid && f.peer.0 == "127.0.0.1" && f.peer.1 == address.port()));
    let arguments = observer
        .arguments(std::slice::from_ref(&current), "real-arguments-round")
        .unwrap();
    assert!(arguments.contains_key(&current.pid));
    let mut reused = current;
    reused.start_microseconds = (reused.start_microseconds + 1) % 1_000_000;
    let rejected = observer.sockets(&[reused], "reused-round").unwrap();
    assert!(!rejected.complete);
    assert!(rejected.flows.is_empty());
    drop((client, server));
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn own_sampling_child_has_output_and_time_limits_without_signaling_target_apps() {
    let runner = SystemRunner::development().unwrap();
    let error = runner
        .run(
            ReadCommand::Observer(ObserverAction::Inventory),
            &[],
            Duration::from_secs(8),
            64,
        )
        .err()
        .expect("native inventory exceeds tiny test limit");
    assert_eq!(error.code, "command_output_oversize");
    let error = runner
        .run(
            ReadCommand::Observer(ObserverAction::Inventory),
            &[],
            Duration::from_millis(1),
            8 * 1024 * 1024,
        )
        .err()
        .expect("native inventory cannot finish in 1ms");
    assert_eq!(error.code, "command_timeout");
    assert!(runner
        .run(
            ReadCommand::DnsA {
                host: "claude.ai;command".into(),
                port: 53
            },
            &[],
            Duration::from_secs(1),
            1024
        )
        .is_err());
}
