use claude_watch_runtime::{
    background_evidence::{ProbeExecutor, WORKER},
    release_native::{FixedCommand, FixedCommandExecutor},
};
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("cw-resident-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let script = r#"#!/usr/bin/python3
import json,os,sys,time
from pathlib import Path
root=Path(__file__).parent
with (root/'starts').open('a') as out: out.write(str(os.getpid())+'\n')
print(json.dumps({'schema':1,'ready':True}),flush=True)
for line in sys.stdin:
 r=json.loads(line)
 with (root/'requests').open('a') as out: out.write(r['id']+'\n')
 mode=(root/'mode').read_text() if (root/'mode').exists() else ''
 if mode=='timeout':
  print(json.dumps({'cw_trace':'phase_http','request_id':r['id'],'attached':True,'elapsed_ms':1}),file=sys.stderr,flush=True)
  time.sleep(5)
 if mode=='exit': sys.exit(3)
 if mode=='oversize':
  print('x'*1048600,flush=True);continue
 result={'kind':r['kind'],'status':'timeout' if mode=='partial' else 'complete','errors':[]}
 print(json.dumps({'schema':1,'id':'00000000-0000-0000-0000-000000000000' if mode=='stale' else r['id'],
   'kind':r['kind'],'result':result}),flush=True)
"#;
        fs::write(root.join(WORKER), script).unwrap();
        fs::set_permissions(root.join(WORKER), fs::Permissions::from_mode(0o700)).unwrap();
        Self { root }
    }
    fn command(&self, kind: &str, seconds: u64) -> FixedCommand {
        FixedCommand {
            program: self.root.join(WORKER),
            args: vec![format!("--{kind}")],
            timeout: Duration::from_secs(seconds),
        }
    }
    fn starts(&self) -> usize {
        fs::read_to_string(self.root.join("starts"))
            .unwrap()
            .lines()
            .count()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn dns_and_webrtc_reuse_one_process_with_new_request_ids() {
    let f = Fixture::new();
    let mut executor = ProbeExecutor::new(Arc::new(AtomicBool::new(false)));
    for kind in ["dns", "webrtc", "dns", "webrtc"] {
        let output = executor.run(f.command(kind, 3)).unwrap();
        let result: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(result["kind"], kind);
        assert_eq!(result["status"], "complete");
        assert!(output.stderr.is_empty());
    }
    assert_eq!(f.starts(), 1);
    let ids = fs::read_to_string(f.root.join("requests")).unwrap();
    assert_eq!(
        ids.lines().collect::<std::collections::BTreeSet<_>>().len(),
        4
    );
}

#[test]
fn incomplete_or_invalid_round_discards_process_before_next_request() {
    for mode in ["partial", "stale", "oversize", "exit", "timeout"] {
        let f = Fixture::new();
        let mut executor = ProbeExecutor::new(Arc::new(AtomicBool::new(false)));
        fs::write(f.root.join("mode"), mode).unwrap();
        let first = executor.run(f.command("dns", if mode == "timeout" { 1 } else { 3 }));
        if mode == "partial" {
            assert!(first.unwrap().stdout.contains("timeout"));
        } else {
            assert!(
                first.is_err(),
                "{mode} cannot become a successful collection"
            );
        }
        fs::remove_file(f.root.join("mode")).unwrap();
        assert!(executor
            .run(f.command("webrtc", 3))
            .unwrap()
            .stdout
            .contains("complete"));
        assert_eq!(f.starts(), 2, "{mode} must reconstruct the owned helper");
    }
}

#[test]
fn changed_runtime_manifest_restarts_the_resident_worker() {
    let f = Fixture::new();
    let mut executor = ProbeExecutor::new(Arc::new(AtomicBool::new(false)));
    executor.run(f.command("dns", 3)).unwrap();
    fs::write(f.root.join("BuildInfo.plist"), "new runtime identity").unwrap();
    executor.run(f.command("webrtc", 3)).unwrap();
    assert_eq!(f.starts(), 2);
}

#[test]
#[ignore = "requires a temporary WebKit runtime and the logged-in graphical session"]
fn real_webkit_helper_reuses_views_and_persists_only_current_receipts() {
    use claude_watch_runtime::{
        receipt_store::ReceiptStore,
        storage::{Paths, StateStore},
    };
    let runtime =
        PathBuf::from(std::env::var("CW_TEST_RESIDENT_RUNTIME").expect("temporary runtime"));
    let live = std::env::var("CW_TEST_RESIDENT_LIVE").as_deref() == Ok("1");
    let fixture = Fixture::new();
    let store = StateStore::new(Paths::new(&fixture.root).unwrap());
    let receipts = ReceiptStore {
        storage: store.clone(),
    };
    let mut executor =
        ProbeExecutor::new(Arc::new(AtomicBool::new(false))).with_diagnostics(store.clone());
    let mut previous = std::collections::BTreeMap::new();
    let local =
        serde_json::json!({"context":"fixture","context_id":"fixture","proxy":"ok","tun":"ok"});
    for kind in ["dns", "webrtc", "dns", "webrtc"] {
        let output = executor
            .run(FixedCommand {
                program: runtime.join(WORKER),
                args: vec![format!("--{kind}")],
                timeout: Duration::from_secs(if live { 80 } else { 10 }),
            })
            .unwrap();
        let result: Value = serde_json::from_str(&output.stdout).unwrap();
        assert_eq!(
            result["status"], "complete",
            "{kind}: incomplete collection"
        );
        let sampled = result["finishedAt"].as_f64().unwrap();
        if let Some(old) = previous.insert(kind, sampled) {
            assert!(sampled > old, "reuse must not reuse the old receipt time");
        }
        let receipt = if kind == "dns" {
            receipts.record_dns(&result, &local, None, sampled + 0.1)
        } else {
            receipts.record_webrtc(&result, &local, None, sampled + 0.1)
        }
        .unwrap();
        let state = receipt[if kind == "dns" { "comparison" } else { "risk" }]["state"]
            .as_str()
            .unwrap();
        assert!(
            matches!(state, "ok" | "fail"),
            "a complete receipt must be judged, never a manufactured pass"
        );
        if !live {
            assert_eq!(state, "ok");
        }
        eprintln!(
            "resident {kind}: complete, verdict={state}, observations={}",
            result["observations"].as_array().unwrap().len()
        );
    }
    drop(executor);
    let log = fs::read_to_string(store.paths.base().join("diagnostic-events.jsonl")).unwrap();
    assert_eq!(
        log.lines()
            .filter(|line| line.contains("view_reused"))
            .count(),
        2,
        "each retained WebView must be reused on its second request"
    );
}
