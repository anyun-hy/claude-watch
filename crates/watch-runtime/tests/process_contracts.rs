use claude_watch_core::processes::{self, Identity, Kind, Lease, McpSpec, Provider, Target};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::Path,
    process::{Command, Stdio},
};
fn identity(pid: u32, parent: u32) -> Identity {
    Identity {
        pid,
        parent,
        uid: 501,
        executable: format!("/mock/bin/{pid}"),
        start_seconds: 1000,
        start_microseconds: 123,
        start_stamp: "Mon Oct 19 18:25:57 2026".into(),
    }
}
fn target(identity: &Identity, kind: Kind) -> Target {
    Target {
        identity: identity.clone(),
        kind,
    }
}
fn oracle(operation: &str, cases: &[Value]) -> Vec<Value> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let mut child = Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(root.join("tools/migration_reference.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&json!({"operation":operation,"cases":cases})).unwrap())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}
#[test]
fn argument_parser_matches_python_without_executing_or_emitting_payloads() {
    let mut cases = vec![];
    for a in [
        "",
        "word",
        "''",
        "\"\"",
        "'two words'",
        "two\\ words",
        "\"a\\\"b\"",
        "\"a\\$b\"",
        "word;literal",
        "unclosed'",
        "x\\",
        "#literal",
        "word\u{000b}word",
    ] {
        for b in ["next", "'space value'", "\"x\\\\y\"", "escaped\\ value"] {
            cases.push(json!({"command":format!("node {a} {b}"),"executable":"node"}));
        }
    }
    cases.push(json!({"command":"/Applications/ChatGPT.app/Contents/MacOS/Codex (Service) --type=utility","executable":"/Applications/ChatGPT.app/Contents/MacOS/Codex (Service)"}));
    for (c, expected) in cases.iter().zip(oracle("process_tokens", &cases)) {
        assert_eq!(
            json!(processes::command_tokens(
                c["command"].as_str().unwrap(),
                c["executable"].as_str().unwrap()
            )),
            expected,
            "{c}"
        );
    }
}
#[test]
fn mcp_and_chromium_roles_match_mature_exact_entrypoint_checks() {
    let specs = vec![McpSpec {
        executable: "/tools/rea".into(),
        arguments: vec!["mcp".into()],
        name: "REA".into(),
    }];
    let mut cases = vec![];
    for tokens in [
        vec!["/tools/rea", "mcp", "--secret=DO_NOT_EMIT"],
        vec!["/usr/bin/python3", "-u", "/tools/rea", "mcp"],
        vec!["/usr/bin/node", "/tools/rea", "mcp"],
        vec!["other", "/tools/rea", "mcp"],
        vec!["node", "-e", "/tools/rea mcp"],
        vec!["python3", "-c", "/tools/rea mcp"],
        vec!["node", "/other/script", "/tools/rea", "mcp"],
        vec!["other", "--stdio"],
        vec!["Helper", "--utility-sub-type=network.mojom.NetworkService"],
        vec!["Helper", "--type=renderer"],
        vec!["Helper", "--type=gpu-process"],
    ] {
        cases.push(json!({"tokens":tokens,"executable":"/app/Helper","specs":specs}));
    }
    cases.push(json!({"tokens":["/app/chrome_crashpad_handler"],"executable":"/app/chrome_crashpad_handler","specs":specs}));
    for (c, expected) in cases.iter().zip(oracle("process_classify", &cases)) {
        let tokens: Vec<String> = serde_json::from_value(c["tokens"].clone()).unwrap();
        let actual =
            processes::classify_role(&tokens, c["executable"].as_str().unwrap(), &specs, |s| {
                Some(s.into())
            });
        assert_eq!(
            actual.map(|v| json!(v)).unwrap_or(json!({})),
            expected,
            "{c}"
        );
    }
}
#[test]
fn children_are_bound_to_start_identity_and_desktop_codex_component_is_not_independent_cli() {
    let inventory: BTreeMap<_, _> = [
        identity(10, 1),
        identity(11, 10),
        identity(12, 11),
        identity(20, 1),
        identity(21, 20),
    ]
    .into_iter()
    .map(|p| (p.pid, p))
    .collect();
    let seeds = vec![
        target(&inventory[&10], Kind::ChatgptMain),
        target(&inventory[&11], Kind::CodexCli),
        target(&inventory[&20], Kind::ClaudeMain),
    ];
    let got = processes::targets(&inventory, &seeds, &[], 501, &BTreeSet::new());
    assert_eq!(
        got.iter()
            .map(|v| (v.identity.pid, v.kind))
            .collect::<Vec<_>>(),
        vec![
            (10, Kind::ChatgptMain),
            (11, Kind::ChatgptChild),
            (12, Kind::ChatgptChild),
            (20, Kind::ClaudeMain),
            (21, Kind::ClaudeChild)
        ]
    );
    let mut moved = inventory.clone();
    moved.get_mut(&21).unwrap().parent = 1;
    let got2 = processes::targets(&moved, &seeds, &got, 501, &BTreeSet::new());
    assert!(got2.iter().any(|v| v.identity.pid == 21));
    moved.get_mut(&21).unwrap().start_microseconds += 1;
    assert!(
        !processes::targets(&moved, &seeds, &got, 501, &BTreeSet::new())
            .iter()
            .any(|v| v.identity.pid == 21)
    );
    let mut foreign = inventory.clone();
    foreign.get_mut(&20).unwrap().uid = 0;
    assert!(
        !processes::targets(&foreign, &seeds, &[], 501, &BTreeSet::new())
            .iter()
            .any(|v| v.identity.pid >= 20)
    );
    assert!(
        !processes::targets(&inventory, &seeds, &[], 501, &BTreeSet::from([10]))
            .iter()
            .any(|v| v.identity.pid == 10)
    );
}
#[test]
fn authorization_requires_matching_provider_live_root_owner_and_pid_instance() {
    let inventory: BTreeMap<_, _> = [
        identity(10, 1),
        identity(11, 10),
        identity(20, 1),
        identity(21, 20),
        identity(30, 1),
    ]
    .into_iter()
    .map(|p| (p.pid, p))
    .collect();
    let targets = vec![
        target(&inventory[&11], Kind::ClaudeChild),
        target(&inventory[&21], Kind::ChatgptChild),
    ];
    let lease = Lease {
        provider: Provider::Claude,
        root: inventory[&10].clone(),
        owner: Some(inventory[&30].clone()),
        cli: true,
    };
    let result = processes::authorization(&targets, std::slice::from_ref(&lease), &inventory, 501);
    assert_eq!(result["active_pids"], json!([11]));
    assert_eq!(result["unauthorized_pids"], json!([21]));
    for field in ["root", "owner"] {
        let mut changed = inventory.clone();
        changed
            .get_mut(&if field == "root" { 10 } else { 30 })
            .unwrap()
            .start_microseconds += 1;
        let result =
            processes::authorization(&targets, std::slice::from_ref(&lease), &changed, 501);
        assert_eq!(result["mode"], "GUARD");
    }
    let wrong = Lease {
        provider: Provider::Chatgpt,
        ..lease
    };
    assert_eq!(
        processes::authorization(&targets, &[wrong], &inventory, 501)["active_pids"],
        json!([])
    );
}
#[test]
fn role_hints_inherit_configured_tools_and_drop_reused_pids_without_returning_arguments() {
    let before: BTreeMap<_, _> = [
        Identity {
            executable: "/tools/rea".into(),
            ..identity(10, 1)
        },
        identity(11, 10),
    ]
    .into_iter()
    .map(|p| (p.pid, p))
    .collect();
    let requested = before
        .iter()
        .map(|(pid, p)| (*pid, p.start_stamp.clone()))
        .collect();
    let mut after = before.clone();
    let commands = BTreeMap::from([
        (
            10,
            vec![
                "/tools/rea".into(),
                "mcp".into(),
                "--secret=DO_NOT_EMIT".into(),
            ],
        ),
        (11, vec!["node".into(), "/child.js".into()]),
    ]);
    let specs = vec![McpSpec {
        executable: "/tools/rea".into(),
        arguments: vec!["mcp".into()],
        name: "REA".into(),
    }];
    let value = processes::role_hints(&requested, &before, &after, &commands, &specs, |s| {
        Some(s.into())
    });
    assert_eq!(value["11"]["roleEvidence"], "configured_mcp_descendant");
    let encoded = value.to_string();
    assert!(!encoded.contains("DO_NOT_EMIT"));
    assert!(!encoded.contains("/tools/rea"));
    after.get_mut(&11).unwrap().start_microseconds += 1;
    assert!(
        processes::role_hints(&requested, &before, &after, &commands, &specs, |s| Some(
            s.into()
        ))
        .get("11")
        .is_none()
    );
}
#[test]
fn interpreter_config_is_normalized_and_ambiguous_execution_flags_do_not_classify() {
    let args = vec!["-u".into(), "/tools/server.py".into(), "mcp".into()];
    let spec = McpSpec::from_config("/usr/bin/python3", &args, "Server\nName", |s| {
        Some(s.into())
    })
    .unwrap();
    assert_eq!(spec.executable, "/tools/server.py");
    assert_eq!(spec.arguments, vec!["mcp"]);
    assert_eq!(spec.name, "ServerName");
    assert!(
        McpSpec::from_config("python3", &["-c".into(), "payload".into()], "x", |s| Some(
            s.into()
        ))
        .is_none()
    );
    let tokens = vec![
        "python3".into(),
        "-u".into(),
        "/tools/server.py".into(),
        "mcp".into(),
    ];
    assert_eq!(
        processes::classify_role(&tokens, "/usr/bin/python3", &[spec], |s| Some(s.into()))
            .unwrap()
            .runtime_role,
        "mcp"
    );
}
#[test]
fn cycles_depth_bounds_and_invalid_identities_fail_closed() {
    let mut inventory: BTreeMap<_, _> = [identity(10, 11), identity(11, 10), identity(20, 1)]
        .into_iter()
        .map(|p| (p.pid, p))
        .collect();
    assert!(!processes::descendant(10, 20, &inventory));
    let mut invalid = identity(30, 1);
    invalid.start_microseconds = 1_000_000;
    assert!(!invalid.valid());
    inventory.insert(30, invalid.clone());
    assert!(processes::targets(
        &inventory,
        &[target(&invalid, Kind::ClaudeMain)],
        &[],
        501,
        &BTreeSet::new()
    )
    .is_empty());
    let mut reused = identity(10, 11);
    reused.executable = "/another/process".into();
    assert!(!inventory[&10].same_process(&reused));
}

#[test]
fn owned_cli_cleanup_never_deletes_a_replaced_foreign_record() {
    use claude_watch_core::processes::{Identity, Provider};
    use claude_watch_runtime::{
        lease_store::LeaseStore,
        storage::{Paths, StateStore},
    };
    let root = std::env::temp_dir().join(format!("cli-cleanup-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let storage = StateStore::new(Paths::new(&root).unwrap());
    let owner = Identity {
        pid: 77,
        parent: 1,
        uid: 501,
        executable: "/fixture/wrapper".into(),
        start_seconds: 100,
        start_microseconds: 7,
        start_stamp: "owner".into(),
    };
    let leases = LeaseStore {
        storage: storage.clone(),
    };
    let mut owned = leases.save_cli(Provider::Codex, &owner, 1000.).unwrap();
    let directory = storage.paths.watch().join("state/sessions");
    let path = std::fs::read_dir(&directory)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut value = storage.read_json(&path, serde_json::Value::Null).unwrap();
    value["lease"]["provider"] = serde_json::json!("claude");
    storage.atomic_json(&path, &value).unwrap();
    assert_eq!(owned.clear().unwrap_err().code, "lease_cleanup_conflict");
    assert!(path.exists());
    let mut inventory = std::collections::BTreeMap::from([(77, owner.clone())]);
    assert_eq!(leases.load(&inventory, 501, false).unwrap().len(), 1);
    inventory.get_mut(&77).unwrap().start_microseconds += 1;
    assert!(leases.load(&inventory, 501, false).unwrap().is_empty());
    assert!(path.exists());
    assert!(leases.load(&inventory, 501, true).unwrap().is_empty());
    assert!(!path.exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn data_root_owner_must_match_the_login_identity() {
    use claude_watch_runtime::storage::Paths;
    use std::os::unix::fs::MetadataExt;
    let root = std::env::temp_dir().join(format!("root-owner-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let paths = Paths::new(&root).unwrap();
    let uid = std::fs::metadata(&root).unwrap().uid();
    assert!(paths.require_owner(uid).is_ok());
    assert_eq!(
        paths.require_owner(uid.saturating_add(1)).unwrap_err().code,
        "home_owner_mismatch"
    );
    assert!(std::fs::read_dir(&root).unwrap().next().is_none());
    std::fs::remove_dir(root).unwrap();
}
