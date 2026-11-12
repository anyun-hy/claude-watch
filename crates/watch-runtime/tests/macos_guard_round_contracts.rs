//! Production sampler/guard paths; fixtures provide only process, OS and HTTP observations.
use claude_watch_core::{
    channel::{ChannelEnforcementCommand, ChannelPermit, ChannelPermitState, NetworkBackendKind, PolicyVersion},
    config::Config, error::{CoreError, Result}, processes::Identity,
};
use claude_watch_runtime::{
    channel_enforcer::{ChannelEnforcer, LocalTunnelEnforcer},
    commands::{ObserverAction, Output, ReadCommand, ReadRunner},
    desktop_native::{DesktopRuntime, NativeDesktop},
    macos::{Authority, Macos, Mutator}, native,
    network_client::{NetworkClient, Request, Response, Transport, TransportError},
    sampler::{ProcessRound, Sampler}, snapshot_publication::SnapshotPublisher,
    storage::{Paths, StateStore}, target_discovery::{DiscoveryHandle, DiscoveryInputs},
};
use claude_watch_system::ProcessKernelIdentity;
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}}, time::{Duration, Instant}};

const PROXY: &str = "/Applications/Surge.app/Contents/MacOS/Surge";
const TAG: &str = "/Applications/TAG.app/Contents/Resources/bin/mihomo";
fn output(text: String) -> Result<Output> { Ok(Output { status:0, stdout:text.into_bytes(), stderr:vec![] }) }
fn identity(pid: u32, uid: u32, executable: String) -> Identity {
    let seconds = 1_700_000_000;
    Identity { pid, parent:1, uid, executable, start_seconds:seconds, start_microseconds:7,
        start_stamp:claude_watch_system::process_start_stamp(seconds).unwrap() }
}
struct State {
    processes: BTreeMap<u32, Identity>, exec_generation: u32, listener: u32,
    route: &'static str, service: &'static str, route_failure: bool,
    reachable: bool, lsof_missing: bool, listener_address: &'static str, listener_port: u16, kernel_captured_at: Option<f64>,
}
struct Source {
    state: Mutex<State>, full_ps: AtomicUsize, point_ps: AtomicUsize,
    inventory: AtomicUsize, root_token_queries: AtomicUsize,
}
impl ReadRunner for Source {
    fn observed_process_identity(&self, pid: u32) -> Option<ProcessKernelIdentity> {
        let state=self.state.lock().unwrap(); let process=state.processes.get(&pid)?;
        if process.uid == 0 { self.root_token_queries.fetch_add(1,Ordering::SeqCst); return None; }
        Some(ProcessKernelIdentity { pid, ppid:process.parent, uid:process.uid, executable_path:process.executable.clone(),
            start_seconds:process.start_seconds, start_microseconds:process.start_microseconds,
            audit_token:[0,process.uid,0,0,0,pid,0,state.exec_generation] })
    }
    fn process_start_time_any_user(&self, pid: u32) -> Option<(u64,u32)> {
        self.state.lock().unwrap().processes.get(&pid).map(|p|(p.start_seconds,p.start_microseconds))
    }
    fn loopback_tcp_reachable(&self, _:u16, timeout:Duration) -> bool {
        assert!(timeout <= Duration::from_millis(500)); self.state.lock().unwrap().reachable
    }
    fn run(&self, command:ReadCommand, input:&[u8], timeout:Duration, _:usize) -> Result<Output> {
        assert!(timeout <= Duration::from_secs(8));
        let state=self.state.lock().unwrap(); let now=native::now();
        let envelope=|fields:Value| { let mut body=json!({"schema":1,"status":"ok","uid":501,"started_at":now,"finished_at":now});
            body.as_object_mut().unwrap().extend(fields.as_object().unwrap().clone()); body.to_string() };
        match command {
            ReadCommand::Observer(ObserverAction::Inventory) => {
                self.inventory.fetch_add(1,Ordering::SeqCst);
                let processes=state.processes.values().filter(|p|p.uid==501).collect::<Vec<_>>();
                output(envelope(json!({"state":"ok","truncated":false,"requested_count":processes.len(),"processes":processes,"unavailable":[],"exited":[]})))
            }
            ReadCommand::Observer(ObserverAction::Identities) => {
                let request:Value=serde_json::from_slice(input).unwrap();
                let rows=request["targets"].as_array().unwrap().iter().map(|target|
                    json!({"pid":target["pid"],"state":"ok","identity":state.processes.get(&(target["pid"].as_u64().unwrap() as u32))})).collect::<Vec<_>>();
                output(envelope(json!({"round_id":request["round_id"],"identities":rows})))
            }
            ReadCommand::Observer(ObserverAction::Environment) => output(envelope(json!({"timezone":"Asia/Tokyo","locale":"ja_JP","language":["en-US"],"ipv6":"ok",
                "network":{"service":state.service,"interface":"en0","service_id":state.service}}))),
            ReadCommand::ProcessTable | ReadCommand::ProcessTablePids { .. } => {
                let pids=if let ReadCommand::ProcessTablePids { pids }=command {
                    self.point_ps.fetch_add(1,Ordering::SeqCst); Some(pids)
                } else { self.full_ps.fetch_add(1,Ordering::SeqCst); None };
                output(state.processes.values().filter(|p|pids.as_ref().is_none_or(|pids|pids.contains(&p.pid)))
                    .map(|p|format!("{} {} {} {} {}\n",p.pid,p.parent,p.uid,p.start_stamp,p.executable)).collect())
            }
            ReadCommand::Route(_) if !state.route_failure => output(format!("interface: {}\n",state.route)),
            ReadCommand::Interfaces => output("utun4: flags=8051<UP> mtu 9000\n\tinet 198.18.0.1 netmask 0xffff0000\nen0: flags=8863<UP> mtu 1500\n\tinet 192.168.0.5 netmask 0xffffff00\n".into()),
            ReadCommand::LsofTcpListener { .. } | ReadCommand::LsofListener if state.lsof_missing => Ok(Output { status:1, stdout:vec![], stderr:vec![] }),
            ReadCommand::LsofTcpListener { port } => output(format!("p{}\nn{}:{port}\n",state.listener,state.listener_address)),
            ReadCommand::LsofListener => output(format!("p{}\nn127.0.0.1:7890\n",state.listener)),
            ReadCommand::Listeners => {
                let meta=state.kernel_captured_at.map(|at|format!("# CW_LISTENER_FRAME {}\n",json!({"captured_at":at,"origin_id":"fixture","sequence":1}))).unwrap_or_default();
                output(format!("{meta}tcp4 0 0 {}.{} *.* LISTEN mihomo:{}\n",state.listener_address.trim_matches(['[',']']),state.listener_port,state.listener))
            },
            _ => Err(CoreError::new("fixture_unavailable","unused OS observation")),
        }
    }
}
struct Http { effect:Mutex<Option<Box<dyn FnOnce()+Send>>> }
impl Transport for Http {
    fn get(&self, request:&Request) -> std::result::Result<Response,TransportError> {
        assert!(request.proxy.as_deref().is_some_and(claude_watch_core::config::valid_loopback_proxy));
        assert!(request.timeout <= Duration::from_secs(3));
        if let Some(effect)=self.effect.lock().unwrap().take() { effect(); }
        Ok(Response { status:200, headers:Default::default(), body:b"ip=1.1.1.1\nloc=JP\n".to_vec() })
    }
}
struct NoWrites;
impl Mutator for NoWrites {
    fn apply(&mut self,_:&Value)->Result<()> { panic!("read-only sampling cannot mutate") }
    fn restore(&mut self,_:&Value)->Result<bool> { panic!("read-only sampling cannot restore") }
}
struct Fixture { root:PathBuf, store:StateStore, source:Arc<Source>, http:Arc<Http> }
impl Drop for Fixture { fn drop(&mut self) { let _=fs::remove_dir_all(&self.root); } }
impl Fixture {
    fn new(root_proxy:bool,tag:bool)->Self {
        let root=std::env::temp_dir().join(format!("cw-guard-round-{}",uuid::Uuid::new_v4())); fs::create_dir(&root).unwrap();
        let store=StateStore::new(Paths::new(&root).unwrap());
        let mut config=Config::default(); config.proxy_url="http://127.0.0.1:7890".into();
        store.atomic_json(&store.paths.config(),&config.value().unwrap()).unwrap();
        store.atomic_bytes(&store.paths.watch().join("runtime/watch-process-control"),b"fixture",0o700).unwrap();
        let proxy=identity(42,if root_proxy {0}else{501},if tag {TAG}else{PROXY}.into());
        let backend=identity(77,501,store.paths.watch().join("runtime/watch-engine").to_string_lossy().into());
        Self { root,store,source:Arc::new(Source { state:Mutex::new(State { processes:[(42,proxy),(77,backend)].into(),
            exec_generation:1,listener:42,route:"utun4",service:"Wi-Fi",route_failure:false,reachable:false,lsof_missing:false,listener_address:"127.0.0.1",listener_port:7890,kernel_captured_at:None }),
            full_ps:AtomicUsize::new(0),point_ps:AtomicUsize::new(0),inventory:AtomicUsize::new(0),root_token_queries:AtomicUsize::new(0) }),
            http:Arc::new(Http { effect:Mutex::new(None) }) }
    }
    fn sampler(&self)->Sampler<Arc<Source>> {
        let mut sampler=Sampler::new(self.source.clone(),self.store.paths.clone());
        let mut inputs=DiscoveryInputs::for_home(&self.root); inputs.application_roots.clear(); inputs.prefixes.clear(); inputs.query_registry=false;
        sampler.set_discovery(DiscoveryHandle::new(inputs)); sampler
    }
    fn enforcer(&self)->LocalTunnelEnforcer {
        let enforcer=LocalTunnelEnforcer::new("guard-round-test"); let now=native::now(); enforcer.activate_interception(now).unwrap();
        let version=PolicyVersion { policy_digest:"a".repeat(64),guard_policy_digest:"b".repeat(64) };
        for family in ["claude","openai"] {
            let permit=ChannelPermit { family:family.into(),session_id:None,policy_version:version.clone(),permit_generation:1,command_seq:1,
                state:ChannelPermitState::Revoked,reason_code:"fixture_input".into(),issued_at:now,valid_until:now+30.0,
                context_id:None,baseline_ip:None,members:vec![],backend:NetworkBackendKind::Seatbelt,vpn_epoch:None,coverage_scope:None };
            enforcer.apply_command(&ChannelEnforcementCommand { family:family.into(),session_id:None,policy_version:version.clone(),permit_generation:1,command_seq:1,
                permit,allowed_processes:vec![],upstream_endpoint:claude_watch_runtime::config_store::ConfigStore { storage:self.store.clone() }.load().unwrap().proxy_url,target_executor_boot_id:None,issued_at:now },now).unwrap();
        }
        enforcer
    }
    fn sample(&self,round:&ProcessRound)->(BTreeMap<String,Value>,Value) {
        let network=NetworkClient::new(self.http.clone(),None).unwrap();
        let mut host=Macos { runner:self.source.clone(),network:network.clone(),storage:self.store.clone(),authority:Authority::ReadOnly,
            mutator:NoWrites,probes:Arc::new(||panic!("guard must not run full audit probes")) };
        let mut desktop=NativeDesktop::new(self.source.clone(),self.store.paths.watch().join("runtime/watch-process-control"),Authority::ReadOnly).unwrap();
        DesktopRuntime { desktop:&mut desktop,system:&mut host,network,storage:self.store.clone(),started:Instant::now(),cli:None }
            .sample_guard_environment(&self.enforcer(),&["claude","openai"],round)
    }
}

#[test]
fn guard_round_publisher_and_both_guard_reads_share_one_inventory_and_full_ps() {
    for tag in [false,true] {
        let fixture=Fixture::new(false,tag);
        let producer=fixture.source.state.lock().unwrap().processes[&77].clone();
        let mut publisher=SnapshotPublisher::new(fixture.store.clone(),fixture.sampler(),producer).unwrap();
        let started=Instant::now();
        for _ in 0..5 {
            publisher.poll_with_inventory("","",true,true,|round| {
                let round=round.unwrap(); let (_,local)=fixture.sample(round);
                assert_eq!(local["process_observed_at"],round.observed_at);
                assert_eq!(local["proxy"],if tag {"unknown"}else{"ok"},"{local}");
            }).unwrap();
        }
        assert_eq!(fixture.source.inventory.load(Ordering::SeqCst),5);
        assert_eq!(fixture.source.full_ps.load(Ordering::SeqCst),5);
        if tag { assert_eq!(fixture.source.point_ps.load(Ordering::SeqCst),15,"two local TAG reads plus monitor TAG read per round"); }
        assert!(started.elapsed()<Duration::from_secs(3));
        eprintln!("guard_round tag={tag}: five publisher+guard rounds {:?}, inventory=5 full_ps=5 point_ps={}",started.elapsed(),fixture.source.point_ps.load(Ordering::SeqCst));
    }
}

#[test]
fn guard_round_rejects_exec_pid_reuse_route_network_listener_and_policy_changes() {
    for change in ["exec","pid_reuse","route","network","listener","policy"] {
        let fixture=Fixture::new(false,false); let round=fixture.sampler().processes_with_system_metadata().unwrap();
        let source=fixture.source.clone(); let store=fixture.store.clone();
        *fixture.http.effect.lock().unwrap()=Some(Box::new(move|| {
            let mut state=source.state.lock().unwrap();
            match change {
                "exec"=>state.exec_generation+=1,
                "pid_reuse"=>state.processes.get_mut(&42).unwrap().start_microseconds+=1,
                "route"=>state.route="en0",
                "network"=>state.service="Ethernet",
                "listener"=>state.listener=99,
                "policy"=>{let mut config=Config::default();config.proxy_url="http://127.0.0.1:7890".into();config.require_stun=true;store.atomic_json(&store.paths.config(),&config.value().unwrap()).unwrap();},
                _=>unreachable!(),
            }
        }));
        let (egress,local)=fixture.sample(&round);
        assert_eq!(local["proxy"],"unknown","{change}: {local}");
        assert!(egress.values().all(|value|value["state"]=="unknown"),"{change}: {egress:?}");
        assert_eq!(fixture.source.full_ps.load(Ordering::SeqCst),1);
        assert_eq!(fixture.source.inventory.load(Ordering::SeqCst),1);
    }
}

#[test]
fn guard_round_root_proxy_uses_birth_and_targeted_ps_without_action_token() {
    let fixture=Fixture::new(true,false);
    let listener_at=native::now()-1.0;
    { let mut state=fixture.source.state.lock().unwrap();state.lsof_missing=true;state.kernel_captured_at=Some(listener_at); }
    let round=fixture.sampler().processes_with_system_metadata().unwrap();
    let (_,local)=fixture.sample(&round); assert_eq!(local["proxy"],"ok","{local}");
    assert_eq!(fixture.source.root_token_queries.load(Ordering::SeqCst),0);
    assert_eq!(local["environment_observed_at"],listener_at,"cached listener capture time must survive both guard reads");
    assert!(local["guard_identity_evidence"].as_array().unwrap().iter().any(|identity|identity["uid"]==0&&identity["audit_token"].is_null()));
    let source=fixture.source.clone();
    *fixture.http.effect.lock().unwrap()=Some(Box::new(move||source.state.lock().unwrap().processes.get_mut(&42).unwrap().start_microseconds+=1));
    let (_,changed)=fixture.sample(&round); assert_eq!(changed["proxy"],"unknown","{changed}");
    assert_eq!(fixture.source.full_ps.load(Ordering::SeqCst),1);
}

#[test]
fn guard_round_stale_missing_route_and_new_root_candidate_remain_unknown() {
    let fixture=Fixture::new(false,false); let round=fixture.sampler().processes_with_system_metadata().unwrap();
    let mut stale=round.clone(); stale.observed_at-=9.0;
    assert_eq!(fixture.sample(&stale).1["code"],"process_observation_stale");
    let mut missing=round.clone();missing.system_processes=None;
    assert_eq!(fixture.sample(&missing).1["code"],"process_observation_missing");
    fixture.source.state.lock().unwrap().route_failure=true;
    assert_eq!(fixture.sample(&round).1["tun"],"unknown");
    fixture.source.state.lock().unwrap().route_failure=false;
    fixture.source.state.lock().unwrap().processes.insert(99,identity(99,0,"/usr/local/bin/sing-box".into()));
    let newer=fixture.sampler().processes_with_system_metadata().unwrap();
    assert!(!claude_watch_runtime::macos::guard_round_matches(&round,&newer,&fixture.store.paths.watch().join("runtime/watch-engine")));
    assert_eq!(fixture.sample(&newer).1["proxy"],"unknown","new root candidate must retain ambiguity");
}

#[test]
fn guard_round_existing_candidates_cannot_exchange_listener_ownership_across_io() {
    for tag in [false,true] {
        let fixture=Fixture::new(false,tag);
        { let mut state=fixture.source.state.lock().unwrap();state.reachable=tag;
            state.processes.insert(43,identity(43,501,if tag {TAG}else{PROXY}.into())); }
        let round=fixture.sampler().processes_with_system_metadata().unwrap();
        let source=fixture.source.clone();
        *fixture.http.effect.lock().unwrap()=Some(Box::new(move||source.state.lock().unwrap().listener=43));
        let (_,local)=fixture.sample(&round);
        assert_eq!(local["code"],"audit_context_changed","tag={tag}: {local}");
        assert_eq!(fixture.source.full_ps.load(Ordering::SeqCst),1);
    }
}

#[test]
fn guard_round_listener_binding_accepts_explicit_default_port_and_ipv6_but_not_another_address() {
    for (endpoint,address) in [("http://127.0.0.2:80","127.0.0.2"),("http://[::1]:80","[::1]")] {
        let fixture=Fixture::new(false,false);
        let mut config=Config::default();config.proxy_url=endpoint.into();
        fixture.store.atomic_json(&fixture.store.paths.config(),&config.value().unwrap()).unwrap();
        {let mut state=fixture.source.state.lock().unwrap();state.listener_address=address;state.listener_port=80;}
        let round=fixture.sampler().processes_with_system_metadata().unwrap();
        assert_eq!(fixture.sample(&round).1["proxy"],"ok","{endpoint}");
        fixture.source.state.lock().unwrap().lsof_missing=true;
        assert_eq!(fixture.sample(&round).1["proxy"],"ok","kernel fallback for {endpoint}");
        fixture.source.state.lock().unwrap().listener_address="127.0.0.1";
        assert_eq!(fixture.sample(&round).1["proxy"],"unknown","a different loopback bind cannot confirm {endpoint}");
    }
    let fixture=Fixture::new(true,false); let round=fixture.sampler().processes_with_system_metadata().unwrap();
    {let mut state=fixture.source.state.lock().unwrap();state.lsof_missing=true;state.kernel_captured_at=Some(native::now()-4.0);}
    assert_eq!(fixture.sample(&round).1["code"],"proxy_listener_unavailable");
}
