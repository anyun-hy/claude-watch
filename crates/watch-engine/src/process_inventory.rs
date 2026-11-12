//! Read-only classification projection for native process control.
use claude_watch_core::{policy::PolicyCatalog, processes::{MatchReason, ProcessIdentityRef, ProcessRole}};
use claude_watch_runtime::sampler::ProcessRound;
use serde_json::{json, Value};

pub fn value(round: &ProcessRound) -> Value {
    let targets: Vec<_> = round.targets.iter().filter_map(|target| {
        // Swift's close planner expands descendants itself and protects its
        // ancestors. Lease-associated launchers/children must not become roots.
        if !matches!(target.kind.role(), ProcessRole::DesktopMain | ProcessRole::DesktopHelper | ProcessRole::Cli) {
            return None;
        }
        let evidence = round.match_evidence.get(&target.identity.pid)?;
        if !evidence.identity.same_process(&target.identity)
            || evidence.parent.is_some()
            || evidence.root.as_ref() != Some(&ProcessIdentityRef::from(&target.identity))
            || !matches!(evidence.reason, MatchReason::SupportedCliAlias | MatchReason::KnownCliLayout
                | MatchReason::VerifiedBundle | MatchReason::VerifiedBundleComponent
                | MatchReason::ScriptEntry | MatchReason::ManagedAppServer)
        {
            return None;
        }
        let family = PolicyCatalog::family_for(target.kind.provider())?;
        Some(json!({
            "identity": target.identity,
            "product": family.id,
            "desktop_main": target.kind.role() == ProcessRole::DesktopMain,
        }))
    }).collect();
    json!({
        "schema": 1, "status": "ok", "mode": "read_only",
        "grants_launch_permission": false, "grants_close_permission": false,
        "uid": round.uid, "observed_at": round.observed_at,
        "state": if round.complete && !round.match_evidence.values().any(|e| e.reason == MatchReason::InstallationPending) { "ok" } else { "partial" },
        "targets": targets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use claude_watch_core::processes::{Identity, Kind, MatchEvidence, Target};

    #[test]
    fn process_control_projection_preserves_identity_and_partial_state_without_authority() {
        let identity = Identity { pid: 71, parent: 1, uid: 501,
            executable: "/fixture/Renamed.app/Contents/MacOS/App".into(),
            start_seconds: 100, start_microseconds: 42, start_stamp: String::new() };
        let round = ProcessRound {
            id: "fixture".into(), uid: 501,
            targets: vec![
                Target { identity: identity.clone(), kind: Kind::CodexMain },
                Target { identity: Identity { pid: 72, ..identity.clone() }, kind: Kind::CodexLauncher },
                Target { identity: Identity { pid: 73, ..identity.clone() }, kind: Kind::CodexChild },
                Target { identity: Identity { pid: 74, executable: "/usr/bin/unrelated".into(), ..identity.clone() }, kind: Kind::CodexMain },
                Target { identity: Identity { pid: 75, ..identity.clone() }, kind: Kind::CodexMain },
            ],
            identities: [(identity.pid, identity.clone())].into_iter().collect(),
            roles: json!({}), match_evidence: [
                (71, MatchEvidence::direct(&identity, MatchReason::VerifiedBundle)),
                (74, MatchEvidence::direct(&Identity { pid: 74, executable: "/usr/bin/unrelated".into(), ..identity.clone() }, MatchReason::RetainedLifetime)),
                (75, MatchEvidence::direct(&Identity { pid: 75, start_seconds: 99, ..identity.clone() }, MatchReason::VerifiedBundle)),
            ].into_iter().collect(), unavailable: vec![],
            diagnostic_reasons: Default::default(), confirmed_exited_count: 0,
            complete: false, observed_at: 123.0, discovery: None, system_processes: None,
        };
        let wire = value(&round);
        assert_eq!(wire["targets"].as_array().unwrap().len(), 1);
        assert_eq!(wire["targets"][0]["identity"], json!(identity));
        assert_eq!(wire["targets"][0]["product"], "openai");
        assert_eq!(wire["targets"][0]["desktop_main"], true);
        assert_eq!(wire["state"], "partial");
        assert_eq!(wire["mode"], "read_only");
        assert_eq!(wire["grants_launch_permission"], false);
        assert_eq!(wire["grants_close_permission"], false);
    }
}
