use claude_watch_core::processes::{targets, Identity, Kind, Target};
use std::collections::{BTreeMap, BTreeSet};

fn identity(pid: u32, parent: u32, executable: &str) -> Identity {
    Identity { pid, parent, uid: 501, executable: executable.into(),
        start_seconds: 50 + pid as u64, start_microseconds: 1, start_stamp: String::new() }
}

#[test]
fn discovered_orphan_retains_ownership_across_exec_but_not_pid_reuse() {
    let root = identity(10, 1, "/fixture/claude");
    let child = identity(20, 10, "/bin/sh");
    let ordinary = identity(30, 1, "/usr/bin/python3");
    let inventory = BTreeMap::from([(10, root.clone()), (20, child.clone()), (30, ordinary.clone())]);
    let original = targets(&inventory, &[Target { identity: root, kind: Kind::ClaudeCode }], &[], 501, &BTreeSet::new());
    assert_eq!(original.len(), 2);
    let mut execed = child.clone(); execed.parent = 1; execed.executable = "/usr/bin/python3".into();
    assert!(child.same_lifetime(&execed));
    assert!(!child.same_process(&execed), "process-control identity must remain strict");
    let next = BTreeMap::from([(20, execed.clone()), (30, ordinary)]);
    let retained = targets(&next, &[], &original, 501, &BTreeSet::new());
    assert_eq!(retained.len(), 1, "independent Python must remain outside the AI scope");
    assert_eq!(retained[0].identity, execed, "use the newly observed executable, never stale path evidence");
    assert_eq!(retained[0].kind, Kind::ClaudeChild);
    let mut reused = execed.clone(); reused.start_microseconds += 1;
    assert!(targets(&BTreeMap::from([(20, reused)]), &[], &retained, 501, &BTreeSet::new()).is_empty());
    let mut other_user = execed; other_user.uid += 1;
    assert!(targets(&BTreeMap::from([(20, other_user)]), &[], &retained, 501, &BTreeSet::new()).is_empty());
}
