//! Compatibility contracts for persisted desktop groups. Live membership,
//! policy and recovery are exercised through ChannelSupervisor in channel_pipeline_contracts.
use claude_watch_core::{config::Config, processes::Provider, session::{Desktop, Phase, Session}};
use claude_watch_runtime::{
    background_evidence::ProbeKind, config_store::{ConfigStore, policy_digest},
    receipt_store::ReceiptStore, session_store::{SessionStore, desktop_groups::{canonical_desktops, desktop_members, group_stamps}},
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{fs, path::PathBuf};

fn desktop(pid: u32, start: u64) -> Desktop {
    Desktop { pid, start_seconds: start, start_microseconds: 1 }
}
fn local() -> Value {
    json!({"context":"ctx","context_id":"ctx","proxy":"ok","tun":"ok",
        "guard_backend_healthy":true,"observation_unavailable":[]})
}
fn egress(now: f64, ip: &str, country: &str) -> Value {
    json!({"ip":ip,"country":country,"observed_at":now,"source":"fixture"})
}
fn audit(store: &StateStore, now: f64, openai: bool, ip: &str, country: &str) -> Value {
    let config = ConfigStore { storage: store.clone() }.load().unwrap();
    let mut value = json!({"ready":true,"observed_at":now,"expires_at":now+30.,
        "context_id":"ctx","observation_id":"fixture","context_transition":{"state":"stable"},
        "policy":policy_digest(&config.value().unwrap()).unwrap(),
        "egress_reference":{"ip":ip,"country":country,"checked_at":now,"context":"ctx","source":"fixture"}});
    if openai { value["launch_target"] = json!("codex-desktop"); value["authorization_scope"] = json!("observation"); }
    value
}
fn probe(kind: ProbeKind, now: f64, dns_country: &str) -> Value {
    let mut value = json!({"kind":kind.label(),"status":"complete","contextChanged":false,
        "startedAt":now-1.,"finishedAt":now,"errors":[],
        "observations":[{"kind":"http","address":"1.1.1.1","country":"JP"}]});
    value["observations"].as_array_mut().unwrap().push(match kind {
        ProbeKind::Dns => json!({"kind":"resolver","address":"8.8.8.8","country":dns_country}),
        ProbeKind::WebRtc => json!({"kind":"srflx","address":"1.1.1.1","country":"JP"}),
    });
    if kind == ProbeKind::Dns {
        value["externalJSON"] = json!(json!({"session":"a".repeat(40),"dns_servers":{"8.8.8.8":5},
            "http":{"address":"1.1.1.1","country":"JP"},
            "geoip":[{"ip":"8.8.8.8","country_code":dns_country}]}).to_string());
    }
    value
}
struct Fixture { root: PathBuf, store: StateStore }
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("cw-multi-main-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        store.atomic_json(&store.paths.config(), &Config { guard_enabled:true, ..Default::default() }.value().unwrap()).unwrap();
        Self { root, store }
    }
    fn seed(&self, now: f64) {
        let r = ReceiptStore { storage:self.store.clone() };
        r.record_dns(&probe(ProbeKind::Dns,now,"JP"),&local(),None,now).unwrap();
        r.record_webrtc(&probe(ProbeKind::WebRtc,now,"JP"),&local(),None,now).unwrap();
    }
    fn sessions(&self) -> SessionStore { SessionStore::for_family(self.store.clone(),"openai") }
    fn pending(&self) -> Session {
        self.seed(1000.);
        let pending = self.sessions().begin_verified(&ReceiptStore { storage:self.store.clone() },
            &audit(&self.store,1000.,true,"1.1.1.1","JP"),&egress(1000.,"1.1.1.1","JP"),1000.).unwrap();
        let mut value = self.sessions().bind_desktop(&pending.session_id,desktop(77,900),1000.).unwrap();
        // A persisted legacy group is fixture input, not a second guard loop.
        value.state = Phase::Rechecking;
        value.created_at = 1001.; value.pending_deadline = 1031.;
        value.extra.insert("desktop_group_v1".into(),json!([desktop(77,900),desktop(78,900)]));
        value.extra.insert("desktop_group_recheck_v1".into(),json!(true));
        value.extra.insert("desktop_group_continuity_v1".into(),json!(true));
        self.store.atomic_json(&self.store.paths.session_for("openai"),&json!(value)).unwrap();
        self.seed(1003.);
        value
    }
    fn bindings(&self) -> Vec<(Desktop,String)> {
        vec![(desktop(77,900),"fixture-77".into()),(desktop(78,900),"fixture-78".into())]
    }
    fn complete(&self, expected: &Session, bindings: &[(Desktop,String)], check: &Value)
        -> claude_watch_core::error::Result<Option<Session>> {
        self.sessions().complete_group_recheck(expected, bindings, check,
            &egress(1003.,"1.1.1.1","JP"),1003.,Provider::Codex)
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); } }

#[test]
fn legacy_group_completion_preserves_baseline_and_writes_all_identity_leases() {
    let f=Fixture::new(); let before=f.pending();
    let after=f.complete(&before,&f.bindings(),&audit(&f.store,1003.,true,"1.1.1.1","JP")).unwrap().unwrap();
    assert_eq!(after.state,Phase::Active); assert_eq!(after.baseline,before.baseline);
    assert_eq!(desktop_members(&after).unwrap(),vec![desktop(77,900),desktop(78,900)]);
    for pid in [77,78] { assert!(f.store.paths.watch().join(format!("state/sessions/rust-{pid}.session")).exists()); }
}

#[test]
fn completion_refuses_missing_duplicate_or_wrong_members_without_writing() {
    let f=Fixture::new(); let before=f.pending(); let check=audit(&f.store,1003.,true,"1.1.1.1","JP");
    for members in [vec![desktop(77,900)],vec![desktop(77,900),desktop(77,900)],vec![desktop(77,900),desktop(78,901)]] {
        let bindings=members.into_iter().map(|d|(d,"fixture".to_owned())).collect::<Vec<_>>();
        assert!(f.complete(&before,&bindings,&check).is_err());
        assert_eq!(f.sessions().load(1003.).unwrap(),Some(before.clone()));
        assert!(!f.store.paths.watch().join("state/sessions/rust-77.session").exists());
    }
}

#[test]
fn a_late_group_audit_cannot_replace_a_newer_session_or_mandatory_risk() {
    for replacement in [true,false] {
        let f=Fixture::new(); let before=f.pending(); let mut current=before.clone();
        if replacement { current.session_id=uuid::Uuid::new_v4().to_string(); }
        else { current.state=Phase::Locked; current.reason=Some(claude_watch_core::session::Reason::new("egress_country_cn","newer risk",1002.)); }
        f.store.atomic_json(&f.store.paths.session_for("openai"),&json!(current)).unwrap();
        assert!(f.complete(&before,&f.bindings(),&audit(&f.store,1003.,true,"1.1.1.1","JP")).unwrap().is_none());
        assert_eq!(f.sessions().load(1003.).unwrap(),Some(current));
    }
}

#[test]
fn legacy_single_desktop_recheck_cannot_drop_group_members() {
    let f=Fixture::new(); let before=f.pending();
    assert!(f.sessions().complete_recheck(&before.session_id,before.desktop.as_ref().unwrap(),"fixture",
        &audit(&f.store,1003.,true,"1.1.1.1","JP"),&egress(1003.,"1.1.1.1","JP"),1003.,Provider::Codex).unwrap().is_none());
    assert_eq!(f.sessions().load(1003.).unwrap(),Some(before));
}

#[test]
fn group_recheck_rejects_changed_context_policy_and_wrong_family_without_leases() {
    for case in ["context","policy","family"] {
        let f=Fixture::new(); let before=f.pending(); let mut check=audit(&f.store,1003.,case!="family","1.1.1.1","JP");
        if case=="context" { check["context_id"]=json!("different"); check["egress_reference"]["context"]=json!("different"); }
        if case=="policy" { check["policy"]=json!("obsolete"); }
        assert!(f.complete(&before,&f.bindings(),&check).is_err());
        assert_eq!(f.sessions().load(1003.).unwrap(),Some(before));
        assert!(!f.store.paths.watch().join("state/sessions/rust-77.session").exists());
    }
}

#[test]
fn malformed_group_is_not_silently_read_as_a_single_main() {
    let f=Fixture::new(); let mut raw=json!(f.pending());
    raw["desktop_group_v1"]=json!([desktop(77,900),desktop(77,900)]);
    f.store.atomic_json(&f.store.paths.session_for("openai"),&raw).unwrap();
    let bytes=fs::read(f.store.paths.session_for("openai")).unwrap();
    assert!(f.sessions().load(1003.).is_err());
    assert_eq!(fs::read(f.store.paths.session_for("openai")).unwrap(),bytes);
}

#[test]
fn invalid_or_duplicate_native_members_are_rejected() {
    for rows in [vec![desktop(1,900)],vec![desktop(77,0)],vec![desktop(77,900),desktop(77,901)],
        (0..33).map(|i|desktop(100+i,900)).collect()] { assert!(canonical_desktops(rows).is_err()); }
}
#[test]
fn native_group_binding_requires_the_exact_main_set_and_valid_stamps() {
    let roots=vec![desktop(77,900),desktop(78,900)];
    let mut rows=vec![(roots[0].clone(),true,"a".into()),(roots[1].clone(),true,"b".into())];
    assert!(group_stamps(&roots[..1],&rows).unwrap().is_none());
    rows.push((desktop(99,900),false,"helper".into())); assert_eq!(group_stamps(&roots,&rows).unwrap().unwrap().len(),2);
    rows[1].2="bad|stamp".into(); assert!(group_stamps(&roots,&rows).is_err());
    rows[1].2="b".into(); rows[1].1=false; assert!(group_stamps(&roots,&rows).unwrap().is_none());
}
