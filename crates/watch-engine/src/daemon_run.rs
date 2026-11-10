use claude_watch_core::{
    channel::{
        BackendCoverageScope, ChannelMonitorSnapshot, NetworkBackendKind, PolicyVersion,
    },
    cli::Request,
    error::{CoreError, Result},
    policy::PolicyCatalog,
    vpn::VpnExpectation,
};
use claude_watch_runtime::{
    alert_gate::AlertGate,
    channel_enforcer::{
        register_production_enforcer, unregister_production_enforcer, ChannelEnforcer,
        LocalTunnelEnforcer,
    },
    channel_supervisor::{AsyncAuditRequest, ChannelSupervisor, SupervisionEvent},
    config_store::ConfigStore,
    controlled::{Controller, DesktopSystem},
    daemon::{DaemonLease, PROCESS_INTERVAL},
    desktop_native::{DesktopRuntime, NativeDesktop},
    events::{Alert, EventFields, EventStore, Severity},
    macos::Authority,
    native::{self, Observer},
    native_notifications::{AlertDispatcher, NativeNotifier},
    sampler::{pinned_node, Sampler},
    sandbox_launch::{
        build_helper_verifier_from_manifest, default_registration_socket_path,
        lookup_packaged_network_backend, SandboxLaunchRegistry,
    },
    snapshot_publication::SnapshotPublisher,
    storage::{Paths, StateStore},
    vpn_observer::{
        resolve_vpn_controller_credentials, HttpControllerVpnReader, VpnObserver, VpnSourceReader,
    },
};
use claude_watch_system::network_events::{NetworkEventKind, NetworkEventWatcher};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, Sender},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

pub struct ProductionChannelStack {
    stop: Arc<AtomicBool>,
    pub packaged_backend: Option<NetworkBackendKind>,
    pub backend: NetworkBackendKind,
    pub enforcer: Arc<LocalTunnelEnforcer>,
    pub sandbox_registry: Option<Arc<SandboxLaunchRegistry>>,
    pub supervisor: ChannelSupervisor,
    #[allow(dead_code)]
    pub event_tx: Sender<SupervisionEvent>,
    pub event_rx: Receiver<SupervisionEvent>,
    pub vpn_wake_handle: Option<Arc<AtomicBool>>,
    pub lease_watchdog: thread::JoinHandle<()>,
    pub async_audit_worker: thread::JoinHandle<()>,
    pub extension_watcher: Option<thread::JoinHandle<()>>,
    pub sandbox_registration_worker: Option<thread::JoinHandle<()>>,
    pub vpn_observer_worker: Option<thread::JoinHandle<()>>,
    pub last_policy_version: Option<PolicyVersion>,
    activate_local_interception: bool,
    local_proxy_worker: Option<thread::JoinHandle<()>>,
    target_refresh_worker: Option<thread::JoinHandle<()>>,
}

fn refresh_and_stage_production_targets(
    storage: &StateStore,
    resources_dir: Option<&std::path::Path>,
    registry: &SandboxLaunchRegistry,
    event_tx: &Sender<SupervisionEvent>,
) -> Result<()> {
    use claude_watch_runtime::target_discovery::DiscoveryHandle;
    let discovery = DiscoveryHandle::for_home(&storage.paths.home);
    let runner = super::runtime::runner()?;
    let snapshot = discovery.observation_snapshot(runner.as_ref(), native::now());
    stage_discovery_snapshot(storage, resources_dir, registry, event_tx, &discovery, &snapshot)
}

fn stage_discovery_snapshot(
    storage: &StateStore, resources_dir: Option<&std::path::Path>, registry: &SandboxLaunchRegistry,
    event_tx: &Sender<SupervisionEvent>, discovery: &claude_watch_runtime::target_discovery::DiscoveryHandle,
    snapshot: &claude_watch_runtime::target_discovery::DiscoverySnapshot,
) -> Result<()> {
    use claude_watch_runtime::managed_entry::stage_deliverable_entries;
    let manifest = discovery.approved_manifest(snapshot)?;
    for family in registry.replace_approved_targets_with_cli_sources(manifest.targets, manifest.children, manifest.cli_sources) {
        // Only Supervisor emits network commands. Identity loss precedes disk staging.
        let _ = event_tx.send(SupervisionEvent::ProcessInventoryUnavailable { family, observed_at: native::now() });
    }
    let entries_root = storage.paths.watch().join("entries");
    let discovered_specs = manifest.desktop_specs;
    let watch_engine_bin = resources_dir
        .map(|d| d.join("watch-engine"))
        .filter(|p| p.is_file())
        .or_else(|| std::env::current_exe().ok())
        .unwrap_or_else(|| PathBuf::from("/usr/bin/true"));
    let launcher_bin = resources_dir
        .map(|d| d.join("watch-sandbox-launcher"))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| watch_engine_bin.with_file_name("watch-sandbox-launcher"));
    let controlled_entry_macho = resources_dir
        .map(|d| d.join("ControlledEntry"))
        .filter(|p| p.is_file());
    storage.atomic_json(&storage.paths.watch().join("state/target-discovery.json"), &json!({"snapshot":snapshot,
        "selection_issues":manifest.selection_issues,"verification_pending":manifest.needs_verification_retry}))?;
    stage_deliverable_entries(
        &entries_root,
        &discovered_specs,
        &watch_engine_bin,
        &launcher_bin,
        controlled_entry_macho.as_deref(),
    )?;
    if manifest.needs_verification_retry {
        // Valid scopes and revocations above are already applied. Do not let
        // the refresh worker cache this revision as fully staged: a temporary
        // read failure can recover without any further metadata change.
        return Err(CoreError::new("target_approval_pending", "部分安装文件待重新验证，其他目标已分别更新"));
    }
    Ok(())
}

/// Shared discovery revision plus exact runtime components; no private second
/// scanner and no content hashing on an unchanged refresh round.
fn target_metadata_signature(storage: &StateStore, resources_dir: Option<&std::path::Path>) -> Vec<(PathBuf, Vec<i128>, Option<PathBuf>)> {
    use std::os::unix::fs::MetadataExt;
    let discovery=claude_watch_runtime::target_discovery::DiscoveryHandle::for_home(&storage.paths.home);
    let revision=super::runtime::runner().map(|runner|discovery.observation_snapshot(runner.as_ref(),native::now()).revision.clone()).unwrap_or_default();
    let mut out=vec![(storage.paths.watch().join("state/target-discovery-revision"),revision.bytes().map(i128::from).collect(),None)];
    if let Some(resources)=resources_dir {
        for name in ["watch-engine","watch-sandbox-launcher","ControlledEntry"] {
            let path=resources.join(name);
            let values=std::fs::metadata(&path).map(|m|vec![m.dev() as i128,m.ino() as i128,m.len() as i128,m.mtime() as i128,
                m.mtime_nsec() as i128,m.ctime() as i128,m.ctime_nsec() as i128,m.mode() as i128]).unwrap_or_else(|_|vec![-1]);
            out.push((path.clone(),values,std::fs::canonicalize(path).ok()));
        }
    }
    out
}

fn spawn_target_refresh_worker(
    storage: StateStore,
    resources_dir: Option<PathBuf>,
    registry: Arc<SandboxLaunchRegistry>,
    stop: Arc<AtomicBool>,
    event_tx: Sender<SupervisionEvent>,
) -> Result<thread::JoinHandle<()>> {
    thread::Builder::new().name("channel-target-refresh".into()).spawn(move || {
        let _discovery = claude_watch_runtime::target_discovery::DiscoveryHandle::for_home(&storage.paths.home);
        let mut previous = None;
        while !stop.load(Ordering::Acquire) {
            // Publish already-known identity/metadata loss before any slow content read.
            registry.reconcile_process_trees(native::now());
            for family in registry.take_invalidated_families() {
                let _ = event_tx.send(SupervisionEvent::ProcessInventoryUnavailable { family, observed_at: native::now() });
            }
            let current = target_metadata_signature(&storage, resources_dir.as_deref());
            if previous.as_ref() != Some(&current) {
                if refresh_and_stage_production_targets(&storage, resources_dir.as_deref(), &registry, &event_tx).is_ok() {
                    previous = Some(current);
                }
            }
            for family in registry.refresh_executable_verifications() {
                let _ = event_tx.send(SupervisionEvent::ProcessInventoryUnavailable {
                    family, observed_at: native::now(),
                });
            }
            for _ in 0..4 {
                if stop.load(Ordering::Acquire) { return; }
                thread::sleep(Duration::from_millis(250));
            }
        }
    }).map_err(|_| CoreError::new("target_refresh_worker_failed", "受控目标刷新线程启动失败"))
}

fn locate_runtime_resources_dir(storage: &StateStore) -> Option<PathBuf> {
    for candidate in [
        storage.paths.watch().join("runtime"),
        storage.paths.base().join("bin"),
    ] {
        if candidate.join("BuildInfo.plist").is_file()
            || candidate.join("components.json").is_file()
            || candidate.join("watch-sandbox-launcher").is_file()
        {
            return Some(candidate);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            if parent.join("BuildInfo.plist").is_file()
                || parent.join("components.json").is_file()
                || parent.join("watch-sandbox-launcher").is_file()
            {
                return Some(parent.to_path_buf());
            }
        }
    }
    None
}

#[cfg(test)]
mod m5_tests {
    use super::*;
    use claude_watch_core::processes::{Identity,LaunchTarget};
    use claude_watch_runtime::{commands::{ReadCommand,ReadRunner,ObserverAction,Output,SystemRunner},
        managed_entry::{prepare_desktop_managed_launch,DesktopEntryPreparation},target_discovery::*};
    use std::{fs,os::unix::fs::PermissionsExt,time::Duration};
    struct Registry(PathBuf);
    impl ApplicationRegistry for Registry {
        fn locations(&self,id:&str)->Result<claude_watch_system::application_locations::ApplicationLocations> {
            Ok(claude_watch_system::application_locations::ApplicationLocations { paths:if id==DESKTOP_IDS[0].0{vec![self.0.clone()]}else{vec![]},complete:true })
        }
    }
    struct Reader { metadata:SystemRunner, identity:Identity,bundle:PathBuf }
    impl ReadRunner for Reader {
        fn run(&self,command:ReadCommand,input:&[u8],timeout:Duration,limit:usize)->Result<Output> {
            let now=native::now();let mut value=json!({"schema":1,"status":"ok","uid":self.identity.uid,"started_at":now,"finished_at":now});
            match command {
                ReadCommand::Plist(path)=>return self.metadata.run(ReadCommand::Plist(path),input,timeout,limit),
                ReadCommand::Observer(ObserverAction::Inventory)=>{
                    let mut row=json!(self.identity);row["bundle_path"]=json!(self.bundle);row["bundle_id"]=Value::Null;
                    value["state"]=json!("ok");value["truncated"]=json!(false);value["requested_count"]=json!(1);
                    value["processes"]=json!([row]);value["unavailable"]=json!([]);value["exited"]=json!([]);
                }
                ReadCommand::Observer(ObserverAction::Arguments)=>{
                    let request:Value=serde_json::from_slice(input).unwrap();value["round_id"]=request["round_id"].clone();
                    value["argument_prefixes"]=json!([{"pid":self.identity.pid,"state":"ok","identity":self.identity,
                        "arguments":[self.identity.executable],"cwd":"/fixture","truncated":false}]);
                }
                _=>panic!("M5 staging fixture must not run AI, user shell, VPN or process control"),
            }
            Ok(Output {status:0,stdout:serde_json::to_vec(&value).unwrap(),stderr:vec![]})
        }
    }
    #[test]
    fn shared_discovery_stages_custom_claude_and_binds_the_controlled_request() {
        let root=PathBuf::from("/private/tmp").join(format!("cw-m5-stage-{}",uuid::Uuid::new_v4()));
        let home=root.join("home");fs::create_dir_all(&home).unwrap();
        let bundle=root.join("Custom & Sources/Claude 'Renamed'.app");fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
        let executable=bundle.join("Contents/MacOS/Agent & Main");fs::write(&executable,b"private native discovery fixture").unwrap();
        fs::set_permissions(&executable,fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(bundle.join("Contents/Info.plist"),r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.anthropic.claudefordesktop</string><key>CFBundleExecutable</key><string>Agent &amp; Main</string></dict></plist>"#).unwrap();
        let store=StateStore::new(Paths::new(&home).unwrap());
        let reader=Reader {metadata:SystemRunner::new(native::built_observer_path().unwrap()).unwrap(),bundle:bundle.clone(),
            identity:Identity {pid:4100,parent:1,uid:claude_watch_system::effective_uid(),executable:executable.to_string_lossy().into_owned(),
                start_seconds:100,start_microseconds:1,start_stamp:"private-stage".into()} };
        let mut inputs=DiscoveryInputs::for_home(&home);inputs.application_roots.clear();inputs.query_registry=true;
        let discovery=DiscoveryHandle::with_registry(inputs,Arc::new(Registry(bundle.clone())));
        discovery.observed_process_bundles([(bundle.clone(),None)]);
        let snapshot=discovery.refresh(&reader,native::now());
        let policy=PolicyVersion {policy_digest:"m5-policy".into(),guard_policy_digest:"m5-guard".into()};
        let registry=SandboxLaunchRegistry::new("m5-boot",policy.clone(),claude_watch_system::SandboxPeerVerifier {
            expected_uid:claude_watch_system::effective_uid(),expected_helper_executable:"/fixture/helper".into(),
            expected_helper_sha256:"fixture".into(),require_code_signature_identifier:None },None);
        let (tx,rx)=std::sync::mpsc::channel();
        stage_discovery_snapshot(&store,None,&registry,&tx,&discovery,&snapshot).unwrap();
        assert!(rx.try_recv().is_err());registry.refresh_executable_verifications();assert_eq!(registry.executable_verification_counts().1,1);
        let mut desktop=NativeDesktop::new(&reader,native::built_process_control_path().unwrap().into(),Authority::ReadOnly).unwrap();
        desktop.set_discovery(discovery.clone());desktop.select_target(LaunchTarget::ClaudeDesktop).unwrap();
        let spec=desktop.build_managed_entry_spec().unwrap();assert_eq!(spec.target_executable,executable);
        let request=match prepare_desktop_managed_launch(&spec,&[],&registry,"m5-boot",&policy,None,"127.0.0.1:1021".parse().unwrap(),vec![]).unwrap() {
            DesktopEntryPreparation::ReadyToLaunch {request}=>request,other=>panic!("unexpected preparation: {other:?}"),
        };
        assert_eq!(request.target_executable,executable.to_string_lossy());assert_eq!(request.target_fingerprint,claude_watch_system::sha256_file_hex(&executable).unwrap());
        let mut sampler=Sampler::new(&reader,store.paths.clone());sampler.set_discovery(discovery.clone());let round=sampler.processes().unwrap();
        assert_eq!(round.targets.len(),1);assert_eq!(round.targets[0].identity.executable,request.target_executable);
        assert_eq!(round.discovery.as_ref().unwrap()["revision"],snapshot.revision);
        assert_eq!(desktop.desktops().unwrap().len(),1,"actual validated path works without NSRunningApplication bundle-id presentation");
        let staged=store.paths.watch().join("entries/apps/Claude (Controlled).app");
        let info=reader.run(ReadCommand::Plist(staged.join("Contents/Info.plist")),&[],Duration::from_secs(3),128*1024).unwrap();
        let info:Value=serde_json::from_slice(&info.stdout).unwrap();
        assert_eq!(info["CWTargetBundlePath"],json!(bundle));assert_eq!(info["CWTargetExecutable"],request.target_executable);
        let script=fs::read_to_string(staged.join("Contents/MacOS/ControlledEntry")).unwrap();
        assert!(script.contains("--target-bundle") && script.contains("'\\''Renamed'\\''"));
        let parsed=claude_watch_core::cli::Request::parse(&["launch".into(),"--target".into(),"claude-desktop".into(),"--target-bundle".into(),bundle.to_string_lossy().into_owned(),"--apply".into()]).unwrap();
        assert_eq!(parsed.value("target-bundle"),bundle.to_str());
        for (target,path) in [("claude-cli",bundle.to_string_lossy().into_owned()),("claude-desktop","relative.app".into()),("claude-desktop","/tmp/control\n.app".into())] {
            assert!(claude_watch_core::cli::Request::parse(&["launch".into(),"--target".into(),target.into(),"--target-bundle".into(),path,"--apply".into()]).is_err(),"bundle binding requires a desktop target and an absolute, non-control path");
        }
        let enforcer=LocalTunnelEnforcer::new("m5-boot",None);enforcer.configure_seatbelt_backend(false,native::now()).unwrap();
        assert!(!enforcer.sandbox_ready().unwrap());assert!(registry.instances().is_empty(),"discovery/staging/preparation creates no sandbox or protected instance");
        if let Some(dir)=std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
            fs::create_dir_all(&dir).unwrap();fs::write(std::path::Path::new(&dir).join("target-discovery-staging.json"),
                serde_json::to_vec_pretty(&json!({"snapshot":snapshot.as_ref(),"entry_info":info,"request":request,"i03_ready":false})).unwrap()).unwrap();
        }
        println!("M5 production vertical: registered custom renamed Claude -> production staging and content approval -> same NativeDesktop/Sampler revision -> bound controlled request; I03 remains closed");
        fs::remove_dir_all(root).unwrap();
    }
}

fn spawn_vpn_observation_worker(
    storage: StateStore,
    packaged_backend: Option<NetworkBackendKind>,
    stop: Arc<AtomicBool>,
    event_tx: Sender<SupervisionEvent>,
    custom_reader: Option<Arc<dyn VpnSourceReader>>,
) -> Result<(thread::JoinHandle<()>, Arc<AtomicBool>)> {
    let obs_boot_id = format!(
        "vpn-obs-{}-{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    );
    let watcher = NetworkEventWatcher::default();
    let wake_handle = watcher.wake_handle();
    let handle = thread::Builder::new()
        .name("channel-vpn-observer".into())
        .spawn(move || {
            let mut observer = VpnObserver::new(obs_boot_id, Some(storage.clone()));
            let mut watcher = watcher;
            watcher.watch_file(storage.paths.config());
            watcher.watch_file(
                storage
                    .paths
                    .home
                    .join("Library/Application Support/com.tag.lab/mihomo/runtime.yaml"),
            );
            let config_store = ConfigStore {
                storage: storage.clone(),
            };
            while !stop.load(Ordering::Acquire) {
                let now = native::now();
                let resolved_cfg = config_store.resolve_runtime_config_state(packaged_backend);
                let expectation = resolved_cfg
                    .config
                    .vpn_expectation
                    .clone()
                    .unwrap_or_else(VpnExpectation::unconfigured);

                let mut invalidated_by_wake = false;
                for sys_ev in watcher.wait(Duration::from_millis(250)) {
                    match sys_ev {
                        NetworkEventKind::DarwinNotification(name) => {
                            let transition = observer.handle_invalidation_event(
                                format!("darwin_notification:{name}"),
                                &expectation,
                                now,
                            );
                            let _ = event_tx.send(SupervisionEvent::VpnObservationUpdated {
                                observation: transition.observation,
                                observed_at: now,
                            });
                            if name.contains("wake") || name.contains("sleep") {
                                invalidated_by_wake = true;
                                let _ = event_tx.send(SupervisionEvent::LeaseExpired {
                                    observed_at: now,
                                    woke_from_sleep: true,
                                });
                            }
                        }
                        NetworkEventKind::WatchedFileChanged(path) => {
                            let fname = path
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("watched_file");
                            if fname == "config.json" {
                                let latest_resolved =
                                    config_store.resolve_runtime_config_state(packaged_backend);
                                if latest_resolved.blocking_reason().is_none() {
                                    let _ = event_tx.send(SupervisionEvent::PolicyUpdated {
                                        config: latest_resolved.config,
                                        observed_at: now,
                                    });
                                }
                            } else {
                                let transition = observer.handle_invalidation_event(
                                    format!("watched_file_changed:{fname}"),
                                    &expectation,
                                    now,
                                );
                                let _ = event_tx.send(SupervisionEvent::VpnObservationUpdated {
                                    observation: transition.observation,
                                    observed_at: now,
                                });
                            }
                        }
                        NetworkEventKind::WakeSignal => {
                            invalidated_by_wake = true;
                            let transition = observer.handle_invalidation_event(
                                "system_wake",
                                &expectation,
                                now,
                            );
                            let _ = event_tx.send(SupervisionEvent::VpnObservationUpdated {
                                observation: transition.observation,
                                observed_at: now,
                            });
                            let _ = event_tx.send(SupervisionEvent::LeaseExpired {
                                observed_at: now,
                                woke_from_sleep: true,
                            });
                        }
                        NetworkEventKind::Timeout => {}
                    }
                }
                if invalidated_by_wake {
                    continue;
                }

                if let Some(ref reader) = custom_reader {
                    if let Ok(transition) =
                        observer.observe_from_reader(reader.as_ref(), &expectation, false, now)
                    {
                        let _ = event_tx.send(SupervisionEvent::VpnObservationUpdated {
                            observation: transition.observation,
                            observed_at: now,
                        });
                    }
                } else if expectation.configured {
                    match resolve_vpn_controller_credentials(&storage, &expectation.proxy_mode) {
                        Ok(creds) => {
                            let reader = HttpControllerVpnReader::new_live(
                                expectation.proxy_mode.clone(),
                                creds,
                            );
                            if let Ok(transition) =
                                observer.observe_from_reader(&reader, &expectation, false, now)
                            {
                                let _ = event_tx.send(SupervisionEvent::VpnObservationUpdated {
                                    observation: transition.observation,
                                    observed_at: now,
                                });
                            }
                        }
                        Err(err) => {
                            let transition = observer.handle_invalidation_event(
                                format!("vpn_controller_credentials_unavailable:{}", err.code),
                                &expectation,
                                now,
                            );
                            let _ = event_tx.send(SupervisionEvent::VpnObservationUpdated {
                                observation: transition.observation,
                                observed_at: now,
                            });
                        }
                    }
                } else if let Some(prev) = observer.state.current_observation() {
                    if !prev.is_fresh(now) {
                        let _ = event_tx.send(SupervisionEvent::VpnObservationUnavailable {
                            reason: "vpn_observation_stale".into(),
                            observed_at: now,
                        });
                    }
                }
            }
        })
        .map_err(|_| CoreError::new("vpn_observer_worker_failed", "VPN 状态只读观察线程启动失败"))?;
    Ok((handle, wake_handle))
}

pub fn assemble_production_channel_stack<F>(
    storage: StateStore,
    stop: Arc<AtomicBool>,
    activate_local_interception: bool,
    run_audit: F,
) -> Result<ProductionChannelStack>
where
    F: Fn(&AsyncAuditRequest) -> Result<(Value, Value, f64)> + Send + Sync + 'static,
{
    assemble_production_channel_stack_with_vpn_reader(
        storage,
        stop,
        activate_local_interception,
        None,
        run_audit,
    )
}

pub fn assemble_production_channel_stack_with_vpn_reader<F>(
    storage: StateStore,
    stop: Arc<AtomicBool>,
    activate_local_interception: bool,
    custom_vpn_reader: Option<Arc<dyn VpnSourceReader>>,
    run_audit: F,
) -> Result<ProductionChannelStack>
where
    F: Fn(&AsyncAuditRequest) -> Result<(Value, Value, f64)> + Send + Sync + 'static,
{
    let resources_dir = locate_runtime_resources_dir(&storage);
    let packaged_backend = resources_dir
        .as_deref()
        .and_then(lookup_packaged_network_backend);
    let resolved_cfg = ConfigStore {
        storage: storage.clone(),
    }
    .resolve_runtime_config_state(packaged_backend);
    let config = resolved_cfg.config.clone();
    let legacy_migration_required = resolved_cfg.legacy_migration_required;
    let package_mismatch = resolved_cfg.package_mismatch;
    let config_blocking_reason = resolved_cfg.blocking_reason();
    let backend = if legacy_migration_required || packaged_backend == Some(NetworkBackendKind::Seatbelt) {
        NetworkBackendKind::Seatbelt
    } else {
        config.effective_network_backend()
    };
    let initial_policy_version = ChannelSupervisor::compute_policy_version(&config)?;
    let boot_id = format!(
        "daemon-{}-{}",
        std::process::id(),
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let enforcer = Arc::new(LocalTunnelEnforcer::new(boot_id.clone(), Some(storage.clone())));
    enforcer.set_clock(native::now)?;
    enforcer.set_strict_peer_verification(activate_local_interception);

    let sandbox_registry: Option<Arc<SandboxLaunchRegistry>> = None;
    let sandbox_registration_worker: Option<thread::JoinHandle<()>> = None;
    let mut extension_watcher: Option<thread::JoinHandle<()>> = None;

    let now_ts = native::now();
    if let Some(ref cfg_err) = resolved_cfg.config_error {
        let _ = enforcer.record_activation_failure(&format!("config_invalid:{cfg_err}"), now_ts);
    } else if package_mismatch {
        let _ = enforcer.record_activation_failure("backend_package_config_mismatch", now_ts);
    } else if legacy_migration_required {
        let _ = enforcer.record_activation_failure("legacy_config_migration_required", now_ts);
    } else if backend.is_network_extension() && activate_local_interception {
        // Legacy NetworkExtension branch: starts local proxy listener, extension gateway,
        // and root-authored extension observation watcher.
        if let Err(e) = enforcer.start_local_proxy_listener("127.0.0.1:0", stop.clone(), now_ts) {
            let _ = enforcer.record_activation_failure(&e.code, now_ts);
        }
        enforcer.start_extension_gateway(stop.clone())?;
        let enforcer_ext = enforcer.clone();
        let stop_ext = stop.clone();
        extension_watcher = Some(
            thread::Builder::new()
                .name("channel-extension-observations".into())
                .spawn(move || {
                    let mut notification =
                        claude_watch_runtime::channel_extension::ObservationSignal::new();
                    while !stop_ext.load(Ordering::Acquire) {
                        let _ = enforcer_ext.refresh_system_extension(native::now());
                        notification.wait(Duration::from_millis(250));
                    }
                })
                .map_err(|_| {
                    CoreError::new("extension_observer_failed", "扩展回执订阅线程启动失败")
                })?,
        );
    }

    let _ = storage.atomic_json(
        &storage
            .paths
            .watch()
            .join("state/channel-protocol-coverage.json"),
        &enforcer.protocol_coverage_boundaries(),
    );
    register_production_enforcer(&storage.paths.watch(), enforcer.clone());

    let (event_tx, event_rx) = std::sync::mpsc::channel();

    // Wire receipt sink: Active and closed flows immediately emit events to supervisor
    let sink_tx = event_tx.clone();
    let _ = enforcer.set_receipt_event_sink(move |receipt| {
        let received_at = native::now();
        let _ = sink_tx.send(SupervisionEvent::EnforcementReceiptArrived {
            receipt,
            received_at,
        });
    });

    let lease_watchdog = enforcer.spawn_lease_watchdog(
        stop.clone(),
        Duration::from_millis(250),
        native::now,
        // The ordered receipt sink above already publishes these changes.
        // Re-sending this earlier snapshot here can overwrite a later relay
        // closure confirmation from the same command and generation.
        |_| {},
    )?;

    let (vpn_observer_worker, vpn_wake_handle) =
        if activate_local_interception || custom_vpn_reader.is_some() {
            let (worker, wake) = spawn_vpn_observation_worker(
                storage.clone(),
                packaged_backend,
                stop.clone(),
                event_tx.clone(),
                custom_vpn_reader,
            )?;
            (Some(worker), Some(wake))
        } else {
            (None, None)
        };

    let (audit_req_tx, async_audit_worker) =
        ChannelSupervisor::spawn_async_audit_worker(stop.clone(), event_tx.clone(), run_audit)?;

    let supervisor = ChannelSupervisor::new_with_config(
        storage,
        config,
        config_blocking_reason,
        Some(enforcer.clone()),
        Some(audit_req_tx),
    )?;

    let mut stack = ProductionChannelStack {
        stop,
        packaged_backend,
        backend,
        enforcer,
        sandbox_registry,
        supervisor,
        event_tx,
        event_rx,
        vpn_wake_handle,
        lease_watchdog,
        async_audit_worker,
        extension_watcher,
        sandbox_registration_worker,
        vpn_observer_worker,
        last_policy_version: Some(initial_policy_version),
        activate_local_interception,
        local_proxy_worker: None,
        target_refresh_worker: None,
    };
    stack.reconcile_controlled_backend(now_ts)?;
    Ok(stack)
}

impl ProductionChannelStack {
    pub fn drain_background_events(&mut self) -> Result<()> {
        while let Ok(ev) = self.event_rx.try_recv() {
            let event = match ev {
                SupervisionEvent::EnforcementReceiptArrived { receipt, .. } =>
                    SupervisionEvent::EnforcementReceiptArrived { receipt, received_at: native::now() },
                other => other,
            };
            self.supervisor.handle_event(event)?;
        }
        Ok(())
    }

    /// Initial assembly and later recovery share one registry and independent component state.
    pub fn reconcile_controlled_backend(&mut self, now: f64) -> Result<()> {
        self.reconcile_controlled_backend_with_listeners(now,
            |reg, path, stop| reg.start_registration_listener(path, stop),
            |enforcer, stop, now| enforcer.start_launchd_proxy_listener(stop, now))
    }

    fn synchronize_runtime_policy(&mut self, config: claude_watch_core::config::Config, now: f64) -> Result<()> {
        let version = ChannelSupervisor::compute_policy_version(&config)?;
        if self.supervisor.saved_policy_version() != &version {
            self.supervisor.handle_event(SupervisionEvent::PolicyUpdated { config, observed_at: now })?;
        }
        if let Some(reg) = &self.sandbox_registry { reg.update_policy_version(version.clone()); }
        self.last_policy_version = Some(version);
        Ok(())
    }

    fn reconcile_controlled_backend_with_listeners<R, P>(&mut self, now: f64, start_registration: R, start_proxy: P) -> Result<()>
    where R: FnOnce(&Arc<SandboxLaunchRegistry>, &std::path::Path, Arc<AtomicBool>) -> Result<thread::JoinHandle<()>>,
          P: FnOnce(&Arc<LocalTunnelEnforcer>, Arc<AtomicBool>, f64) -> Result<(std::net::SocketAddr, thread::JoinHandle<()>)>,
    {
        if !self.backend.is_sandbox() { return Ok(()); }
        let resolved = (ConfigStore { storage: self.supervisor.storage.clone() })
            .resolve_runtime_config_state(self.packaged_backend);
        if let Some(reason) = resolved.blocking_reason() {
            self.supervisor.set_config_blocking_reason(Some(reason), now)?;
            return Ok(());
        }
        self.synchronize_runtime_policy(resolved.config, now)?;
        self.supervisor.set_config_blocking_reason(None, now)?;
        let resources = locate_runtime_resources_dir(&self.supervisor.storage);
        if self.sandbox_registry.is_none() {
            let verifier = resources.as_deref().ok_or_else(|| CoreError::new("helper_manifest_missing", "缺少受控运行组件目录"))
                .and_then(|dir| build_helper_verifier_from_manifest(dir, &dir.join("watch-sandbox-launcher")));
            let verifier = match verifier {
                Ok(v) => v,
                Err(err) => {
                    self.enforcer.configure_seatbelt_backend(false, now)?;
                    self.enforcer.record_activation_failure(&err.code, now)?;
                    return Ok(());
                }
            };
            let reg = Arc::new(SandboxLaunchRegistry::new(self.enforcer.boot_id()?,
                self.supervisor.saved_policy_version().clone(), verifier, Some(self.supervisor.storage.clone())));
            let attribution_registry = Arc::clone(&reg);
            self.enforcer.set_accepted_connection_attributor(move |ctx| attribution_registry.attribute_accepted_connection(ctx, native::now()))?;
            // Retain this exact Arc even when only one listener starts successfully.
            self.sandbox_registry = Some(reg);
        }
        let reg = self.sandbox_registry.as_ref().unwrap().clone();
        if self.target_refresh_worker.as_ref().is_some_and(|h| h.is_finished()) {
            let _ = self.target_refresh_worker.take().unwrap().join();
        }
        if self.target_refresh_worker.is_none() {
            self.target_refresh_worker = Some(spawn_target_refresh_worker(self.supervisor.storage.clone(), resources,
                reg.clone(), self.stop.clone(), self.event_tx.clone())?);
        }
        let mut component_error = None;
        if self.activate_local_interception {
            if self.sandbox_registration_worker.as_ref().is_some_and(|h| h.is_finished()) {
                let _ = self.sandbox_registration_worker.take().unwrap().join();
            }
            if self.local_proxy_worker.as_ref().is_some_and(|h| h.is_finished()) {
                let _ = self.local_proxy_worker.take().unwrap().join();
            }
            if self.sandbox_registration_worker.is_none() {
                match start_registration(&reg, &default_registration_socket_path(&self.supervisor.storage.paths.watch()), self.stop.clone()) {
                    Ok(worker) => self.sandbox_registration_worker = Some(worker),
                    Err(err) => component_error = Some(err.code),
                }
            }
            if self.local_proxy_worker.is_none() {
                match start_proxy(&self.enforcer, self.stop.clone(), now) {
                    Ok((_, worker)) => self.local_proxy_worker = Some(worker),
                    Err(err) => component_error = Some(err.code),
                }
            }
        }
        let components_ready = self.sandbox_registration_worker.is_some() && self.local_proxy_worker.is_some();
        reg.set_gateway_endpoint_protection(self.enforcer.gateway_endpoint_protection()?);
        // The kernel attribution callback was installed on this same registry
        // above. Individual connections still require their own live evidence.
        let report = reg.identity_report(true, components_ready, true);
        self.enforcer.configure_seatbelt_backend_with_identity_gate(&report, now)?;
        if let Some(code) = component_error { self.enforcer.record_activation_failure(&code, now)?; }
        // Configuration/registration metadata is not an execution receipt or an applied policy.
        self.supervisor.storage.atomic_json(&self.supervisor.storage.paths.watch().join("state/seatbelt-runtime.json"), &json!({
            "backend": "seatbelt", "executor_boot_id": self.enforcer.boot_id()?,
            "configured_policy_version": self.supervisor.saved_policy_version(),
            "gateway_endpoint": self.enforcer.local_proxy_port().map(|p| format!("127.0.0.1:{p}")).unwrap_or_default(),
            "registration_socket": default_registration_socket_path(&self.supervisor.storage.paths.watch()),
            "components_ready": components_ready,
            "sandbox_ready": components_ready && report.can_enable_production_backend() && self.enforcer.sandbox_ready()?,
            "identity_report": report, "updated_at": now
        }))?;
        Ok(())
    }

    pub fn step_with_system<S: DesktopSystem>(
        &mut self,
        system: &mut S,
    ) -> Result<ChannelMonitorSnapshot> {
        self.drain_background_events()?;
        let now = system.now();

        if self.backend.is_network_extension() {
            self.enforcer.refresh_system_extension(now)?;
        }

        let resolved_cfg = (ConfigStore {
            storage: self.supervisor.storage.clone(),
        })
        .resolve_runtime_config_state(self.packaged_backend);
        let blocking_reason = resolved_cfg.blocking_reason();
        if blocking_reason.is_none() {
            self.synchronize_runtime_policy(resolved_cfg.config, now)?;
            self.supervisor.set_config_blocking_reason(None, now)?;
            if self.backend.is_sandbox() { self.reconcile_controlled_backend(now)?; }
        } else {
            self.supervisor.set_config_blocking_reason(blocking_reason, now)?;
        }
        let egress = system.egress();
        let local_guard = system
            .local_guard()
            .unwrap_or_else(|_| json!({"proxy": "unknown", "tun": "unknown"}));
        self.supervisor
            .handle_event(SupervisionEvent::EnvironmentUpdated {
                egress,
                local_guard,
                observed_at: system.now(),
            })?;

        for family in PolicyCatalog::families() {
            if PolicyCatalog::guard_target(family).is_none() {
                continue;
            }
            if system.set_family(family.id).is_ok() {
                let (desktops, mut processes) = match (system.desktops(), system.supervised_processes()) {
                    (Ok(desktops), Ok(processes)) => (desktops, processes),
                    _ => {
                        self.supervisor.handle_event(SupervisionEvent::ProcessInventoryUnavailable {
                            family: family.id.to_string(), observed_at: system.now(),
                        })?;
                        continue;
                    }
                };
                if let Some(ref reg) = self.sandbox_registry {
                    let verified_tokens = reg.verified_family_tokens(family.id, now);
                    let mut protected_pids: Vec<u32> =
                        verified_tokens.iter().map(|t| t.pid).collect();
                    protected_pids.sort_unstable();
                    protected_pids.dedup();
                    let mut unprotected_pids = Vec::new();
                    for tok in &processes {
                        if !protected_pids.contains(&tok.pid) {
                            unprotected_pids.push(tok.pid);
                        }
                    }
                    unprotected_pids.sort_unstable();
                    unprotected_pids.dedup();
                    // In Seatbelt mode, only verified sandboxed instances receive channel permits;
                    // discovered processes outside the sandbox registry are reported as unmanaged!
                    processes = verified_tokens;
                    let id_report = reg.identity_report(true, true, true);
                    self.supervisor.set_family_unmanaged_pids(
                        family.id,
                        unprotected_pids.clone(),
                        now,
                    );
                    self.supervisor.set_family_coverage_scope(
                        family.id,
                        Some(BackendCoverageScope {
                            backend: NetworkBackendKind::Seatbelt,
                            configured_entries: vec![family.id.to_string()],
                            protected_pids,
                            unprotected_pids,
                            uncovered_boundaries: vec![
                                "unmanaged_existing_processes".into(),
                                "direct_launch_outside_controlled_entry".into(),
                            ],
                            server_identity_verified: id_report.gateway_server_identity_verified,
                            gateway_endpoint_protection_verified: id_report.gateway_endpoint_protection_verified,
                            gateway_endpoint_protection_method: id_report.gateway_endpoint_protection_method,
                        }),
                        now,
                    );
                }
                self.supervisor
                    .handle_event(SupervisionEvent::ProcessInventoryUpdated {
                        family: family.id.to_string(),
                        desktops,
                        processes,
                        observed_at: system.now(),
                    })?;
            }
        }
        self.drain_background_events()?;
        let snapshot = self.supervisor.snapshot(system.now());

        Ok(snapshot)
    }

    pub fn wait_or_drain(&mut self, deadline: Instant, stop: &AtomicBool) {
        while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
            let wait_for = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100));
            match self.event_rx.recv_timeout(wait_for) {
                Ok(ev) => {
                    let event = match ev {
                        SupervisionEvent::EnforcementReceiptArrived { receipt, .. } =>
                            SupervisionEvent::EnforcementReceiptArrived { receipt, received_at: native::now() },
                        other => other,
                    };
                    let _ = self.supervisor.handle_event(event);
                    let _ = self.drain_background_events();
                    break;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    thread::sleep(wait_for);
                }
            }
        }
    }

    pub fn shutdown(self) {
        // The guard loop can leave on error while the daemon is still alive.
        // Signal the owned workers before joining; callers need not do it first.
        self.stop.store(true, Ordering::Release);
        let now = native::now();
        for family in PolicyCatalog::families() {
            let _ = self.enforcer.revoke_family(family.id, "daemon_shutdown", now);
        }
        unregister_production_enforcer(&self.supervisor.storage.paths.watch());
        let _ = self.lease_watchdog.join();
        let _ = self.async_audit_worker.join();
        if let Some(worker) = self.extension_watcher { let _ = worker.join(); }
        if let Some(worker) = self.sandbox_registration_worker { let _ = worker.join(); }
        if let Some(worker) = self.local_proxy_worker { let _ = worker.join(); }
        if let Some(worker) = self.target_refresh_worker { let _ = worker.join(); }
        if let Some(wake) = self.vpn_wake_handle {
            wake.store(true, Ordering::Release);
        }
        if let Some(worker) = self.vpn_observer_worker { let _ = worker.join(); }
    }
}

/// `PROCESS_INTERVAL` rounds of continuous degradation before the user is
/// interrupted (15 × 2 s ≈ 30 s).
const SUSTAINED_SAMPLING_ROUNDS: u32 = 15;
/// While an outage continues, remind at most once per half hour.
const SAMPLING_QUIET: Duration = Duration::from_secs(30 * 60);
/// Stable identity of a non-empty evidence set.
///
/// `None` means "nothing to report". Two equal signatures describe the same
/// standing fact, so the owner reports it once instead of once per sampling
/// round.
fn evidence_signature(rows: &Value) -> Option<String> {
    let rows = rows.as_array()?;
    if rows.is_empty() {
        return None;
    }
    Some(Value::Array(rows.clone()).to_string())
}

fn sleep_until(deadline: Instant, stop: &AtomicBool) {
    while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
        thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100)),
        );
    }
}

// An online baseline can take much longer than a guard heartbeat interval.
// Collect it independently so login/reboot cannot stall the guard worker.
fn spawn_baseline<F>(stop: Arc<AtomicBool>, mut collect: F) -> Result<thread::JoinHandle<()>>
where
    F: FnMut() -> Result<bool> + Send + 'static,
{
    thread::Builder::new()
        .name("claude-environment-baseline".into())
        .spawn(move || {
            for _ in 0..3 {
                if stop.load(Ordering::Acquire) || collect().is_ok() {
                    break;
                }
            }
        })
        .map_err(|_| CoreError::new("baseline_start_failed", "后台环境采样线程无法启动"))
}
// Discovery reads application metadata and may hash executable contents. It
// must never hold the process/proxy publisher or the risk loop behind its lock.
// The owner also cancels/joins on early daemon errors, not just normal shutdown.
struct DiscoveryWorker {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl DiscoveryWorker {
    fn start<R: claude_watch_runtime::commands::ReadRunner + Send + Sync + 'static>(
        discovery: claude_watch_runtime::target_discovery::DiscoveryHandle,
        runner: R,
        stop: Arc<AtomicBool>,
    ) -> Result<Self> {
        discovery.cancel_pending_when(stop.clone());
        discovery.enable_background_observation();
        let cancelled = stop.clone();
        let worker = thread::Builder::new().name("watch-installation-discovery".into()).spawn(move || {
            while !cancelled.load(Ordering::Acquire) {
                let started = Instant::now();
                discovery.refresh(&runner, native::now());
                sleep_until(started + PROCESS_INTERVAL, &cancelled);
            }
        }).map_err(|_| CoreError::new("discovery_worker_failed", "应用发现工作线程无法启动"))?;
        Ok(Self { stop, worker: Some(worker) })
    }
}
impl Drop for DiscoveryWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

pub fn run(request: &Request, paths: Paths) -> Result<Value> {
    request.require_apply()?;
    let stop = Arc::new(AtomicBool::new(false));
    let _shutdown_signals = claude_watch_runtime::daemon::shutdown_signals(stop.clone())?;
    let runner = super::runtime::runner()?;
    let inventory = Observer {
        runner: runner.as_ref(),
    }
    .inventory()?;
    let producer = inventory
        .processes
        .get(&std::process::id())
        .ok_or_else(|| CoreError::new("daemon_identity_unavailable", "后台自身身份不可读取"))?
        .identity
        .clone();
    let identities = inventory
        .processes
        .into_iter()
        .map(|(pid, p)| (pid, p.identity))
        .collect();
    let storage = StateStore::new(paths.clone());
    if stop.load(Ordering::Acquire) {
        return Ok(json!({"status":"stopped","rounds":0}));
    }
    let owner = DaemonLease::acquire(storage.clone(), producer.clone(), &identities)?;
    // Authenticate/publish the native collector relationship first. Cold
    // discovery must not hide an otherwise live, unready publisher for tens
    // of seconds. The normal snapshot reader still verifies this producer.
    runner.publish_listeners(&storage)?;
    owner.publish_initial_inventory(&identities, native::now())?;
    let sampler = Sampler::new(runner.clone(), paths.clone());
    let discovery_worker = DiscoveryWorker::start(sampler.discovery(), runner.clone(), stop.clone())?;
    let mut publisher = SnapshotPublisher::new(
        storage.clone(),
        sampler,
        producer,
    )?;
    let alerts = if request.flag("observe-only") {
        None
    } else {
        Some(Arc::new(AlertDispatcher::new(
            storage.clone(),
            Arc::new(NativeNotifier::system()),
        )))
    };
    let diagnostic_queue = super::diagnostic_queue::DiagnosticQueue::new(storage.clone());
    let events = EventStore::new(storage.clone());
    events.append(
        "daemon-start",
        EventFields {
            operation: Some("native-daemon".into()),
            pid: Some(std::process::id()),
            version: Some(claude_watch_runtime::monitor_snapshot::VERSION.into()),
            ..Default::default()
        },
        native::now(),
    )?;
    let baseline = if request.flag("observe-only") {
        None
    } else {
        let paths = paths.clone();
        let store = storage.clone();
        let mut runtime = None;
        Some(spawn_baseline(stop.clone(), move || {
            // Construct the adapter once inside this independent worker. A
            // failed observation must never terminate the guard worker.
            if runtime.is_none() {
                let host = super::runtime::host(paths.clone(), Authority::ExplicitPermit)?;
                let desktop = NativeDesktop::new(
                    host.runner.clone(),
                    super::runtime::process_component()?,
                    Authority::ExplicitPermit,
                )?;
                runtime = Some((host, desktop));
            }
            let (host, desktop) = runtime.as_mut().unwrap();
            let network = host.network.clone();
            DesktopRuntime {
                desktop,
                system: host,
                network,
                storage: store.clone(),
                started: Instant::now(),
                cli: None,
            }
            .ensure_baseline_audit()
        })?)
    };
    let guard = if request.flag("observe-only") {
        None
    } else {
        let guard_diagnostics = diagnostic_queue.clone();
        let mut host = super::runtime::host(paths.clone(), Authority::ExplicitPermit)?;
        let mut desktop = NativeDesktop::new(
            host.runner.clone(),
            super::runtime::process_component()?,
            Authority::ExplicitPermit,
        )?;
        let store = storage.clone();
        let stop = stop.clone();
        let guard_alerts = alerts.clone();
        let audit_paths = paths.clone();
        Some(
            thread::Builder::new()
                .name("claude-session-guard".into())
                .spawn(move || -> Result<()> {
                    let mut channel_stack = assemble_production_channel_stack(
                        store.clone(),
                        stop.clone(),
                        true,
                        move |req| {
                            let enforcer = claude_watch_runtime::channel_enforcer::registered_production_enforcer(&audit_paths.watch())
                                .ok_or_else(|| CoreError::new("controlled_channel_missing", "受控诊断执行器不可用，保持待验证"))?;
                            super::channel_audit::run(&audit_paths, &enforcer, req)
                        },
                    )?;
                    let controller = Controller::new(store.clone());
                    let network = host.network.clone();
                    let mut runtime = DesktopRuntime {
                        desktop: &mut desktop,
                        system: &mut host,
                        network,
                        storage: store,
                        started: Instant::now(),
                        cli: None,
                    };
                    // `guard_tick` answers `unknown` whenever the process
                    // inventory cannot be fully confirmed, which on macOS is
                    // ordinary churn: a PID disappears between `proc_listpids`
                    // and the identity sysctl, or the scan hits its deadline.
                    // Paging on the very first such round is what makes the
                    // "保护采样异常" dialog reappear after every dismissal, so
                    // it gets the same sustained-streak gate as the sampling
                    // alerts instead of firing immediately.
                    let mut guard_history = super::diagnostic_queue::GuardHistory::default();
                    let mut unknown_gate =
                        AlertGate::new(SUSTAINED_SAMPLING_ROUNDS, SAMPLING_QUIET);
                    let loop_result: Result<()> = (|| {
                        while !stop.load(Ordering::Acquire) {
                            let started = Instant::now();
                            if let Err(error) = channel_stack.step_with_system(&mut runtime) {
                                channel_stack.enforcer.record_activation_failure(&error.code, native::now())?;
                            }
                            let receipt = controller.guard_tick(&mut runtime)?;
                            guard_history.observe(&guard_diagnostics, &receipt, native::now());
                            if let Some(alerts) = &guard_alerts {
                                if matches!(
                                    receipt["action"].as_str(),
                                    Some("close-desktop" | "disconnect-channel")
                                ) {
                                    unknown_gate.observe(false);
                                    alerts.enqueue(Alert {
                                        title: "Claude Watch：已触发保护".into(),
                                        message: "检测到会话风险并已按配置处置受监督的应用。请查看具体检测结果；重新启动仍会执行完整校验。".into(),
                                        severity: Severity::Warning,
                                    });
                                } else if unknown_gate.observe(receipt["status"] == "unknown") {
                                    alerts.enqueue(Alert {
                                        title: "Claude Watch：保护采样异常".into(),
                                        message: "本轮保护证据未能完整取得，后台正在重试。详情见环境状态；这不等于已检测到网络泄漏。".into(),
                                        severity: Severity::Critical,
                                    });
                                }
                            }
                            channel_stack.wait_or_drain(started + PROCESS_INTERVAL, &stop);
                        }
                        Ok(())
                    })();
                    channel_stack.shutdown();
                    loop_result
                })
                .map_err(|_| CoreError::new("guard_start_failed", "后台保护工作线程无法启动"))?,
        )
    };
    let evidence = if request.flag("observe-only") {
        None
    } else {
        match super::evidence_run::spawn(paths, stop.clone()) {
            Ok(worker) => Some(worker),
            Err(error) => {
                stop.store(true, Ordering::Release);
                if let Some(guard) = guard {
                    let _ = guard.join();
                }
                return Err(error);
            }
        }
    };
    let mut sampling_history = super::diagnostic_queue::SamplingHistory::default();
    let mut sampling_gate = AlertGate::new(SUSTAINED_SAMPLING_ROUNDS, SAMPLING_QUIET);
    // Last reported sensitive-file evidence set.
    let mut reported_files: Option<String> = None;
    let outcome = (|| {
        let mut rounds = 0u64;
        loop {
            if stop.load(Ordering::Acquire) {
                return Ok(json!({"status":"stopped","rounds":rounds}));
            }
            if discovery_worker.worker.as_ref().is_some_and(|worker| worker.is_finished()) {
                return Err(CoreError::new(
                    "discovery_worker_failed",
                    "应用发现线程异常退出，后台停止发布正常心跳",
                ));
            }
            if evidence.as_ref().is_some_and(|worker| worker.is_finished()) {
                return Err(CoreError::new(
                    "evidence_worker_failed",
                    "保护证据线程异常退出，等待后台重新启动",
                ));
            }
            if guard.as_ref().is_some_and(|g| g.is_finished()) {
                return Err(CoreError::new(
                    "guard_worker_failed",
                    "保护循环已退出，后台停止发布正常心跳",
                ));
            }
            let started = Instant::now();
            let config = ConfigStore {
                storage: storage.clone(),
            }
            .load()?;
            runner.publish_listeners(&storage)?;
            if runner.listener_channel_finished() {
                // EOF may arrive immediately after a successful publication.
                // Publish the terminal error before exiting, never leave that
                // preceding listener sample presented as the current source.
                runner.publish_listeners(&storage)?;
                return Err(CoreError::new(
                    "native_listener_worker_failed",
                    "系统采样通道已结束；后台停止发布，等待已注册任务重新启动",
                ));
            }
            let pin = pinned_node(&storage.paths, &config.proxy_group);
            let sample = publisher.poll(&config.proxy_group, &pin, false);
            let mut log_error = diagnostic_queue.health_message();
            if let Some(count) = alerts.as_ref().map(|a| a.record_failures()).filter(|n| *n > 0) {
                let note = format!("本次后台运行的通知事件记录或冷却写入失败 {count} 次。");
                log_error = Some(log_error.map(|existing| format!("{existing}；{note}")).unwrap_or(note));
            }
            let snapshot = owner.publish_with_log_health(sample, native::now(), log_error.as_deref())?;
            sampling_history.observe(&diagnostic_queue, &snapshot, native::now());
            if let Some(alerts) = &alerts {
                // `quality` is a per-round verdict: one missing `lsof` sample
                // or an empty traffic counter flips it to "degraded" and the
                // next round usually restores it. Alerting on the first bad
                // round turned the watchdog into a recurring pop-up, because
                // the queue only suppresses an alert that is still pending or
                // on screen — dismissing one let the next round raise it
                // again. Require a sustained streak, then one reminder per
                // quiet period. The control panel keeps showing live state.
                if sampling_gate.observe(snapshot["health"]["state"] != "running") {
                    alerts.enqueue(Alert {
                        title: "Claude Watch：监控采样异常".into(),
                        message:
                            "本轮进程或连接观察未完成，采样仍会继续。请查看事件记录中的具体来源。"
                                .into(),
                        severity: Severity::Critical,
                    });
                }
                // Report each distinct sensitive-file evidence set once;
                // service-name candidates remain in the event log only.
                let files_signature = evidence_signature(&snapshot["activity"]["files"]["rows"]);
                if files_signature.is_some() && files_signature != reported_files {
                    alerts.enqueue(Alert{title:"Claude Watch：敏感目录文件描述符".into(),message:"未关联会话的进程持有敏感目录文件描述符；这不是完整的文件读取记录。详情见事件记录。".into(),severity:Severity::Warning});
                }
                reported_files = files_signature;
            }
            rounds = rounds.saturating_add(1);
            if request.flag("once") {
                return Ok(
                    json!({"status":"ok","rounds":rounds,"protection":if request.flag("observe-only"){"observation_only"}else{"enabled"},"snapshot":snapshot}),
                );
            }
            sleep_until(started + PROCESS_INTERVAL, &stop);
        }
    })();
    stop.store(true, Ordering::Release);
    let _ = events.append(
        "daemon-stop",
        EventFields {
            operation: Some("native-daemon".into()),
            status: Some(if outcome.is_err() { "error" } else { "stopped" }.into()),
            code: outcome.as_ref().err().map(|error| {
                match error.code.as_str() {
                    "native_listener_worker_failed" => "native_listener_worker_failed",
                    _ => "backend_error",
                }
                .into()
            }),
            ..Default::default()
        },
        native::now(),
    );
    let guard_result = if let Some(guard) = guard {
        match guard.join() {
            Ok(result) => result,
            Err(_) => Err(CoreError::new("guard_worker_failed", "保护循环异常退出")),
        }
    } else {
        Ok(())
    };
    // Always finish helper cancellation, even if the guard worker failed.
    if let Some(evidence) = evidence {
        let _ = evidence.join();
    }
    if let Some(baseline) = baseline {
        // A display-only HTTPS baseline has bounded requests but cannot be
        // interrupted mid-request. It must not delay launchd stop/replacement.
        if baseline.is_finished() {
            let _ = baseline.join();
        }
    }
    guard_result?;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_baseline_does_not_block_other_guard_work() {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let worker = spawn_baseline(stop, move || {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            Ok(true)
        })
        .unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let guard_work = thread::spawn(|| "guard tick");
        assert_eq!(guard_work.join().unwrap(), "guard tick");
        release_tx.send(()).unwrap();
        worker.join().unwrap();
    }

    /// No evidence means nothing to report — not an empty alert.
    #[test]
    fn an_empty_evidence_set_is_not_reported() {
        assert!(evidence_signature(&json!([])).is_none());
    }

    #[test]
    fn an_unreadable_evidence_set_is_not_reported() {
        assert!(evidence_signature(&Value::Null).is_none());
        assert!(evidence_signature(&json!({"state": "unavailable"})).is_none());
    }

    /// A standing fact must produce one alert, not one per sampling round:
    /// identical rows have to compare equal so the caller can skip repeats.
    #[test]
    fn the_same_rows_yield_the_same_signature() {
        let first = json!([{"pid": 7, "label": "com.example.helper", "ownership": "unconfirmed"}]);
        let again = json!([{"pid": 7, "label": "com.example.helper", "ownership": "unconfirmed"}]);
        assert_eq!(evidence_signature(&first), evidence_signature(&again));
    }

    /// A new process appearing is a new fact and must be reported again.
    #[test]
    fn a_changed_row_set_yields_a_new_signature() {
        let before = json!([{"pid": 7, "label": "com.example.helper", "ownership": "unconfirmed"}]);
        let after = json!([
            {"pid": 7, "label": "com.example.helper", "ownership": "unconfirmed"},
            {"pid": 9, "label": "com.example.other", "ownership": "unconfirmed"}
        ]);
        assert_ne!(evidence_signature(&before), evidence_signature(&after));
    }

    #[test]
    fn production_daemon_channel_stack_wires_enforcer_supervisor_async_audit_and_lease_watchdog() {
        use claude_watch_core::{
            channel::{BoundProcessToken, ChannelMonitorDisplayState, ChannelPermitState},
            config::Config,
            processes::{LaunchTarget, ProcessRole},
            session::{Desktop, Launcher},
        };
        use claude_watch_runtime::channel_enforcer::{registered_production_enforcer, ChannelEnforcer};

        struct DaemonFixtureSystem {
            family: &'static str,
            now: f64,
            country: &'static str,
        }
        impl DesktopSystem for DaemonFixtureSystem {
            fn launch_target(&self) -> LaunchTarget {
                if self.family == "openai" {
                    LaunchTarget::CodexDesktop
                } else {
                    LaunchTarget::ClaudeDesktop
                }
            }
            fn set_family(&mut self, family_id: &str) -> Result<()> {
                self.family = if family_id == "openai" { "openai" } else { "claude" };
                Ok(())
            }
            fn now(&self) -> f64 {
                self.now
            }
            fn monotonic(&self) -> Duration {
                Duration::from_secs(1)
            }
            fn wait(&mut self, _: Duration) {}
            fn desktops(&mut self) -> Result<Vec<(Desktop, bool, String)>> {
                if self.family == "claude" {
                    Ok(vec![(
                        Desktop {
                            pid: 4100,
                            start_seconds: 900,
                            start_microseconds: 1,
                        },
                        true,
                        "u501:900:1".into(),
                    )])
                } else {
                    Ok(vec![])
                }
            }
            fn supervised_processes(&mut self) -> Result<Vec<BoundProcessToken>> {
                // Explicit fixture identities avoid querying real host PIDs/UIDs.
                Ok(self
                    .desktops()?
                    .into_iter()
                    .map(|(desktop, main, _)| {
                        BoundProcessToken::with_system_identity(
                            desktop.pid,
                            501,
                            desktop.start_seconds,
                            desktop.start_microseconds,
                            if main {
                                ProcessRole::DesktopMain
                            } else {
                                ProcessRole::DesktopHelper
                            },
                        )
                        .with_audit_token([501, 501, 20, 501, 20, desktop.pid, 0, 9])
                    })
                    .collect())
            }
            fn desktop_alive(&mut self, _: &Desktop) -> Result<bool> {
                Ok(true)
            }
            fn desktop_tree_running(&mut self) -> Result<bool> {
                Ok(self.family == "claude")
            }
            fn launcher(&mut self) -> Result<Launcher> {
                Ok(Launcher {
                    pid: 1,
                    start: "init".into(),
                })
            }
            fn full_audit(&mut self) -> Result<Value> {
                panic!("guard loop must not call synchronous full_audit when async worker is active")
            }
            fn egress(&mut self) -> Value {
                let mut dummy_config = claude_watch_core::config::Config::default();
                dummy_config.enabled = true;
                dummy_config.guard_enabled = true;
                let policy_ver = ChannelSupervisor::compute_policy_version(&dummy_config).unwrap();
                json!({
                    "ip": if self.country == "CN" { "223.5.5.5" } else { "1.1.1.1" },
                    "country": self.country,
                    "observed_at": self.now,
                    "source": "fixture",
                    "family": "*",
                    "upstream_endpoint": "127.0.0.1:7890",
                    "policy_version": policy_ver,
                    "context_id": "ctx",
                    "via_controlled_path": true
                })
            }
            fn local_guard(&mut self) -> Result<Value> {
                Ok(json!({
                    "context": "ctx",
                    "context_id": "ctx",
                    "proxy": "ok",
                    "tun": "ok",
                    "guard_backend_healthy": true,
                    "observation_unavailable": []
                }))
            }
            fn backend_healthy(&mut self) -> Result<bool> {
                Ok(true)
            }
            fn launcher_matches(&mut self, _: &Launcher) -> Result<bool> {
                Ok(true)
            }
            fn open_desktop(&mut self) -> Result<()> {
                Ok(())
            }
            fn quit_desktop(&mut self) -> Result<()> {
                panic!("channel mode must preserve process and never call quit_desktop")
            }
            fn quit_for_confirmed_ip_risk(&mut self, _: &mut Option<u32>) -> Result<()> {
                panic!("channel mode must preserve process and never call quit_for_confirmed_ip_risk")
            }
        }

        let short_id = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let root = std::path::PathBuf::from("/tmp").join(format!("cwdm-{short_id}"));
        std::fs::create_dir_all(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        let mut cfg = Config::default();
        cfg.enabled = true;
        cfg.guard_enabled = true;
        store
            .atomic_json(&store.paths.config(), &cfg.value().unwrap())
            .unwrap();

        let now = native::now();
        let stop = Arc::new(AtomicBool::new(false));
        let (release_audit_tx, release_audit_rx) = std::sync::mpsc::channel();
        let release_audit_rx = Arc::new(std::sync::Mutex::new(release_audit_rx));
        let rx = Arc::clone(&release_audit_rx);
        let mut stack = assemble_production_channel_stack(
            store.clone(),
            stop.clone(),
            false,
            move |req| {
                rx.lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(2))
                    .map_err(|_| {
                        CoreError::new("fixture_audit_barrier_timeout", "审计测试未收到释放信号")
                    })?;
                let completed_at = native::now();
                Ok((
                    json!({
                        "ready": true,
                        "observed_at": completed_at,
                        "expires_at": completed_at + 30.0,
                        "context_id": "ctx",
                        "observation_id": "fixture",
                        "context_transition": {"state": "stable"},
                        "policy": req.policy_version.policy_digest,
                        "egress_reference": {
                            "ip": "1.1.1.1",
                            "country": "JP",
                            "checked_at": completed_at,
                            "context": "ctx",
                            "source": "fixture"
                        }
                    }),
                    json!({
                        "ip": "1.1.1.1",
                        "country": "JP",
                        "observed_at": completed_at,
                        "source": "fixture",
                        "family": "claude",
                        "upstream_endpoint": "127.0.0.1:7890",
                        "policy_version": req.policy_version,
                        "context_id": "ctx",
                        "via_controlled_path": true
                    }),
                    completed_at,
                ))
            },
        )
        .unwrap();

        // Isolated orchestration fixture: inject kernel observations separately
        // from the production authenticated observation tests.
        stack.enforcer.start_local_proxy_listener("127.0.0.1:0", stop.clone(), now).unwrap();
        // The enforcer requires both local proxy and system extension to be active.
        // Local proxy is ready, but system extension is not yet confirmed -> not ready!
        assert!(!stack.enforcer.is_ready().unwrap());
        stack.enforcer.set_system_extension_active(true, None, now).unwrap();
        assert!(stack.enforcer.is_ready().unwrap());
        assert!(registered_production_enforcer(&store.paths.watch()).is_some());

        let mut sys = DaemonFixtureSystem {
            family: "claude",
            now,
            country: "JP",
        };
        assert!(sys
            .supervised_processes()
            .unwrap()
            .iter()
            .all(|p| p.has_verified_audit_token()));
        // Step 1: Running Claude without a session schedules async audit on the worker
        sys.now = native::now();
        let snap1 = stack.step_with_system(&mut sys).unwrap();
        assert_eq!(
            snap1.families["claude"].permit_state,
            ChannelPermitState::PendingVerification
        );

        // wait_or_drain wakes for any event, including unrelated receipts.
        // Wait for the audited state, using the workers' clock and a real deadline.
        release_audit_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let snap2 = loop {
            sys.now = native::now();
            let snapshot = stack.step_with_system(&mut sys).unwrap();
            if snapshot.families["claude"].permit_state == ChannelPermitState::Permitted {
                break snapshot;
            }
            assert!(
                Instant::now() < deadline,
                "async audit did not reach Permitted: {:?}",
                snapshot.families["claude"]
            );
            stack.wait_or_drain(deadline, &stop);
        };
        assert_eq!(
            snap2.families["claude"].permit_state,
            ChannelPermitState::Permitted
        );
        assert_eq!(
            snap2.families["claude"].display_state,
            ChannelMonitorDisplayState::Forwarding
        );

        // Step 2: Trigger CN exit risk -> cuts off channel while preserving process
        sys.now = native::now();
        sys.country = "CN";
        let snap3 = stack.step_with_system(&mut sys).unwrap();
        assert_eq!(
            snap3.families["claude"].permit_state,
            ChannelPermitState::Revoked
        );
        assert_eq!(
            snap3.families["claude"].display_state,
            ChannelMonitorDisplayState::Blocked
        );
        assert!(snap3.families["claude"].process_preserved);

        stack.shutdown();
        assert!(stop.load(Ordering::Acquire));
        assert!(registered_production_enforcer(&store.paths.watch()).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn seatbelt_production_assembly_wires_registry_vpn_observer_and_enforces_i03_gate() {
        use claude_watch_core::{
            channel::{BoundProcessToken, NetworkBackendKind},
            config::Config,
            processes::{LaunchTarget, ProcessRole},
            session::{Desktop, Launcher},
            vpn::{
                ObservationConsistency, ObservedField, UpstreamProtocol, VpnEpoch, VpnExpectation,
                VpnObservation,
            },
        };

        struct SeatbeltFixtureSystem {
            family: &'static str,
            now: f64,
        }
        impl DesktopSystem for SeatbeltFixtureSystem {
            fn launch_target(&self) -> LaunchTarget {
                if self.family == "openai" {
                    LaunchTarget::CodexDesktop
                } else {
                    LaunchTarget::ClaudeDesktop
                }
            }
            fn set_family(&mut self, family_id: &str) -> Result<()> {
                self.family = if family_id == "openai" { "openai" } else { "claude" };
                Ok(())
            }
            fn now(&self) -> f64 {
                self.now
            }
            fn monotonic(&self) -> Duration {
                Duration::from_secs(1)
            }
            fn wait(&mut self, _: Duration) {}
            fn desktops(&mut self) -> Result<Vec<(Desktop, bool, String)>> {
                if self.family == "claude" {
                    Ok(vec![(
                        Desktop {
                            pid: 4100,
                            start_seconds: 900,
                            start_microseconds: 1,
                        },
                        true,
                        "u501:900:1".into(),
                    )])
                } else {
                    Ok(vec![])
                }
            }
            fn supervised_processes(&mut self) -> Result<Vec<BoundProcessToken>> {
                if self.family == "claude" {
                    Ok(vec![BoundProcessToken::with_system_identity(
                        4100,
                        501,
                        900,
                        1,
                        ProcessRole::DesktopMain,
                    )
                    .with_audit_token([501, 501, 20, 501, 20, 4100, 0, 9])])
                } else {
                    Ok(vec![])
                }
            }
            fn desktop_alive(&mut self, _: &Desktop) -> Result<bool> {
                Ok(true)
            }
            fn desktop_tree_running(&mut self) -> Result<bool> {
                Ok(self.family == "claude")
            }
            fn launcher(&mut self) -> Result<Launcher> {
                Ok(Launcher {
                    pid: 1,
                    start: "init".into(),
                })
            }
            fn full_audit(&mut self) -> Result<Value> {
                panic!("guard loop must not call synchronous full_audit")
            }
            fn egress(&mut self) -> Value {
                json!({
                    "ip": "1.1.1.1",
                    "country": "JP",
                    "observed_at": self.now,
                    "source": "fixture",
                    "family": "*",
                    "upstream_endpoint": "http://127.0.0.1:17890",
                    "context_id": "ctx",
                    "via_controlled_path": true
                })
            }
            fn local_guard(&mut self) -> Result<Value> {
                Ok(json!({
                    "context": "ctx",
                    "context_id": "ctx",
                    "proxy": "ok",
                    "tun": "disabled",
                    "guard_backend_healthy": true,
                    "observation_unavailable": []
                }))
            }
            fn backend_healthy(&mut self) -> Result<bool> {
                Ok(true)
            }
            fn launcher_matches(&mut self, _: &Launcher) -> Result<bool> {
                Ok(true)
            }
            fn open_desktop(&mut self) -> Result<()> {
                Ok(())
            }
            fn quit_desktop(&mut self) -> Result<()> {
                Ok(())
            }
            fn quit_for_confirmed_ip_risk(&mut self, _: &mut Option<u32>) -> Result<()> {
                Ok(())
            }
        }

        let short_id = &uuid::Uuid::new_v4().simple().to_string()[..8];
        let root = std::path::PathBuf::from("/tmp").join(format!("cwdsb-{short_id}"));
        std::fs::create_dir_all(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());

        // Save schema-2 seatbelt config first so `StateStore` initializes `watch/` with 0o700 permissions
        let mut cfg = Config::default_for_new_install();
        cfg.enabled = true;
        cfg.guard_enabled = true;
        cfg.proxy_mode = "tag".into();
        cfg.proxy_url = "http://127.0.0.1:17890".into();
        cfg.proxy_group = "TAG".into();
        let mut exp = VpnExpectation::unconfigured();
        exp.configured = true;
        exp.proxy_mode = "tag".into();
        exp.proxy_url = "http://127.0.0.1:17890".into();
        exp.proxy_group = "TAG".into();
        exp.running_mode = Some("rule".into());
        exp.expected_node = Some("JP-01".into());
        cfg.vpn_expectation = Some(exp);
        ConfigStore {
            storage: store.clone(),
        }
        .save(cfg.value().unwrap())
        .unwrap();

        let runtime_dir = store.paths.watch().join("runtime");
        std::fs::create_dir_all(&runtime_dir).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        // Stage a manifest-bound helper binary (`watch-sandbox-launcher`) and `components.json`
        let current_exe = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .unwrap();
        let helper_path = runtime_dir.join("watch-sandbox-launcher");
        std::fs::copy(&current_exe, &helper_path).unwrap();
        let helper_sha = claude_watch_system::sha256_file_hex(&helper_path).unwrap();
        std::fs::write(
            runtime_dir.join("components.json"),
            json!({
                "network_backend": "seatbelt",
                "hashes": {
                    "watch-sandbox-launcher": helper_sha
                }
            })
            .to_string(),
        )
        .unwrap();

        struct MockLiveVpnReader;
        impl VpnSourceReader for MockLiveVpnReader {
            fn read_observation(
                &self,
                _expectation: &VpnExpectation,
                _include_rules: bool,
                sample_seq: u64,
                epoch: VpnEpoch,
                now: f64,
            ) -> VpnObservation {
                let me = claude_watch_system::inspect_process_identity(std::process::id()).unwrap();
                VpnObservation {
                    source: "tag".into(),
                    source_instance: Some(format!(
                        "pid:{}:{}:{}",
                        me.pid, me.start_seconds, me.start_microseconds
                    )),
                    source_revision: Some("rev-prod-1".into()),
                    upstream_endpoint: Some("http://127.0.0.1:17890".into()),
                    upstream_protocol: ObservedField::Known(UpstreamProtocol::MixedHttp),
                    running_mode: ObservedField::Known("rule".into()),
                    tun_enabled: ObservedField::Known(false),
                    system_proxy_enabled: ObservedField::Unknown("system_proxy_not_sampled".into()),
                    selected_group: ObservedField::Known("TAG".into()),
                    selected_node: ObservedField::Known("JP-01".into()),
                    proxy_chain: ObservedField::Known(vec!["TAG".into(), "JP-01".into()]),
                    rules_digest: ObservedField::Unknown("controller_rules_not_sampled".into()),
                    sample_started_at: now,
                    observed_at: now,
                    valid_until: now + 5.0,
                    consistency: ObservationConsistency::RevisionVerified,
                    source_error: None,
                    sample_seq,
                    epoch,
                }
            }
        }

        let stop = Arc::new(AtomicBool::new(false));
        let mut stack = assemble_production_channel_stack_with_vpn_reader(
            store.clone(),
            stop.clone(),
            false,
            Some(Arc::new(MockLiveVpnReader)),
            |_req| Err(CoreError::new("unused", "unused")),
        )
        .expect("assemble production seatbelt stack");

        // 1. Verify Seatbelt registration service, staged deliverable entries, and VPN observer were wired in production assembly
        assert!(
            stack.sandbox_registry.is_some(),
            "Seatbelt production assembly must initialize SandboxLaunchRegistry"
        );
        assert!(
            stack.vpn_wake_handle.is_some(),
            "Seatbelt production assembly must initialize VPN observer wake handle"
        );
        let entry_deadline = Instant::now() + Duration::from_secs(3);
        while !store.paths.watch().join("entries/entries-manifest.json").is_file() {
            assert!(Instant::now() < entry_deadline, "background entry staging did not finish");
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            store.paths.watch().join("entries/bin/claude").is_file()
                && store.paths.watch().join("entries/entries-manifest.json").is_file(),
            "Production Seatbelt assembly must stage deliverable CLI shims and entries-manifest.json"
        );
        // 2. Verify I03 identity gate blocked production enablement (`sandbox_ready == false`)
        assert!(
            !stack.enforcer.sandbox_ready().unwrap(),
            "Production Seatbelt assembly must keep sandbox_ready=false while I03 is unverified"
        );
        let rt_meta = store
            .read_json(
                &store.paths.watch().join("state/seatbelt-runtime.json"),
                Value::Null,
            )
            .unwrap();
        assert_eq!(rt_meta["backend"], "seatbelt");
        assert_eq!(rt_meta["sandbox_ready"], false);
        assert_eq!(
            rt_meta["identity_report"]["blocker_code"],
            "gateway_server_identity_unverified_i03"
        );

        // 3. Verify `step_with_system` ingests VPN observations from the background worker and classifies
        //    unregistered processes as `unmanaged_member_pids` (never falsely claiming protected)
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut sys = SeatbeltFixtureSystem {
            family: "claude",
            now: native::now(),
        };
        let snap = loop {
            sys.now = native::now();
            let s = stack.step_with_system(&mut sys).unwrap();
            if s.families["claude"].vpn_epoch.is_some() {
                break s;
            }
            assert!(Instant::now() < deadline, "VPN observation worker did not deliver sample");
            stack.wait_or_drain(deadline, &stop);
        };
        assert_eq!(snap.families["claude"].backend, NetworkBackendKind::Seatbelt);
        assert!(!snap.families["claude"].sandbox_ready);
        assert!(
            snap.families["claude"]
                .unmanaged_member_pids
                .contains(&4100),
            "unregistered process must appear in unmanaged_member_pids"
        );

        stack.shutdown();
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod r1_tests {
    use super::*;
    use claude_watch_core::config::Config;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn cli_metadata_and_inventory_share_local_codex_retarget_and_removal() {
        use std::{collections::BTreeMap, os::unix::fs::symlink};
        let root = PathBuf::from("/private/tmp").join(format!("cwm-cli-meta-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
        fs::create_dir_all(root.join(".local/bin")).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        let registry = SandboxLaunchRegistry::new("metadata", PolicyVersion { policy_digest:"p".into(), guard_policy_digest:"g".into() },
            claude_watch_system::SandboxPeerVerifier { expected_uid:claude_watch_system::effective_uid(), expected_helper_executable:"/fixture/helper".into(),
                expected_helper_sha256:"fixture".into(), require_code_signature_identifier:None }, None);
        let (tx, _rx) = std::sync::mpsc::channel();
        let a = root.join("image-a"); let b = root.join("image-b");
        for (path, bytes) in [(&a, b"a"), (&b, b"b")] { fs::write(path, bytes).unwrap(); fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap(); }
        let alias = root.join(".local/bin/codex");
        let absent = target_metadata_signature(&store, None);
        symlink(&a, &alias).unwrap();
        let first = target_metadata_signature(&store, None); assert_ne!(first, absent);
        refresh_and_stage_production_targets(&store, None, &registry, &tx).unwrap(); registry.refresh_executable_verifications();
        assert_eq!(registry.executable_verification_counts().1, 1);
        fs::remove_file(&alias).unwrap(); symlink(&b, &alias).unwrap();
        assert_ne!(first, target_metadata_signature(&store, None));
        refresh_and_stage_production_targets(&store, None, &registry, &tx).unwrap(); registry.refresh_executable_verifications();
        assert_eq!(registry.executable_verification_counts().1, 1, "old canonical path must not accumulate");
        fs::remove_file(&alias).unwrap();
        refresh_and_stage_production_targets(&store, None, &registry, &tx).unwrap(); registry.refresh_executable_verifications();
        assert_eq!(registry.executable_verification_counts(), (registry.executable_verification_counts().0, 0, 0));
        assert!(registry.replace_approved_targets(BTreeMap::new(), BTreeMap::new()).is_empty());
        let broken=root.join("Applications/Unreadable.app/Contents/MacOS/Main");
        fs::create_dir_all(broken.parent().unwrap()).unwrap();fs::write(&broken,b"private native fixture").unwrap();
        fs::set_permissions(&broken,fs::Permissions::from_mode(0o111)).unwrap();
        assert!(fs::File::open(&broken).is_err());
        fs::write(broken.parent().unwrap().parent().unwrap().join("Info.plist"),
            r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.anthropic.claudefordesktop</string><key>CFBundleExecutable</key><string>Main</string></dict></plist>"#).unwrap();
        symlink(&b,&alias).unwrap();
        assert_eq!(refresh_and_stage_production_targets(&store,None,&registry,&tx).unwrap_err().code,"target_approval_pending");
        registry.refresh_executable_verifications();
        assert_eq!(registry.executable_verification_counts().1,1,"normal Codex must stage despite unreadable Claude");
        let state=store.read_json(&store.paths.watch().join("state/target-discovery.json"),Value::Null).unwrap();
        assert_eq!(state["verification_pending"],true);
        assert!(state["selection_issues"].as_array().unwrap().contains(&json!("claude-desktop:target_fingerprint_failed")));
        fs::set_permissions(&broken,fs::Permissions::from_mode(0o755)).unwrap();
        refresh_and_stage_production_targets(&store,None,&registry,&tx).unwrap();registry.refresh_executable_verifications();
        assert_eq!(registry.executable_verification_counts().1,2,"recovered image must become verifiable on retry");
        assert_eq!(store.read_json(&store.paths.watch().join("state/target-discovery.json"),Value::Null).unwrap()["verification_pending"],false);
        fs::remove_dir_all(root).unwrap();
    }

    struct Fixture { root: PathBuf, stack: Option<ProductionChannelStack>, store: StateStore }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(stack) = self.stack.take() { stack.shutdown(); }
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    fn fixture(invalid_config: bool) -> Fixture {
        let root = PathBuf::from("/tmp").join(format!("cwr1-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
        fs::create_dir_all(&root).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        ConfigStore { storage: store.clone() }.save(Config::default_for_new_install().value().unwrap()).unwrap();
        let runtime = store.paths.watch().join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let helper = runtime.join("watch-sandbox-launcher");
        fs::copy("/usr/bin/true", &helper).unwrap();
        fs::write(runtime.join("components.json"), json!({"network_backend":"seatbelt", "hashes":{
            "watch-sandbox-launcher": claude_watch_system::sha256_file_hex(&helper).unwrap()
        }}).to_string()).unwrap();
        if invalid_config { fs::write(store.paths.config(), b"{").unwrap(); }
        let stack = assemble_production_channel_stack(store.clone(), Arc::new(AtomicBool::new(false)), false,
            |_| Err(CoreError::new("unused_fixture_audit", "unused"))).unwrap();
        Fixture { root, stack: Some(stack), store }
    }

    #[test]
    fn partial_listener_failures_retry_on_the_same_registry() {
        for registration_fails_first in [true, false] {
            let mut f = fixture(false);
            let stack = f.stack.as_mut().unwrap();
            stack.activate_local_interception = true;
            let original = stack.sandbox_registry.as_ref().unwrap().clone();
            stack.reconcile_controlled_backend_with_listeners(native::now(),
                |reg, path, stop| {
                    assert!(Arc::ptr_eq(reg, &original));
                    if registration_fails_first { Err(CoreError::new("fixture_registration_failure", "injected")) }
                    else { reg.start_registration_listener(path, stop) }
                },
                |enforcer, stop, now| {
                    if !registration_fails_first { Err(CoreError::new("fixture_proxy_failure", "injected")) }
                    else { enforcer.start_local_proxy_listener("127.0.0.1:0", stop, now) }
                }).unwrap();
            assert_eq!(stack.sandbox_registration_worker.is_none(), registration_fails_first);
            assert_eq!(stack.local_proxy_worker.is_some(), registration_fails_first);
            assert!(Arc::ptr_eq(stack.sandbox_registry.as_ref().unwrap(), &original));
            // Retry the same injected component listeners. The production
            // default now requires root launchd endpoint ownership and must
            // not silently fall back to a local bind when no service exists.
            stack.reconcile_controlled_backend_with_listeners(native::now(),
                |reg, path, stop| reg.start_registration_listener(path, stop),
                |enforcer, stop, now| enforcer.start_local_proxy_listener("127.0.0.1:0", stop, now)).unwrap();
            assert!(Arc::ptr_eq(stack.sandbox_registry.as_ref().unwrap(), &original));
            assert!(stack.sandbox_registration_worker.is_some());
            assert!(stack.local_proxy_worker.is_some());
            let port = stack.enforcer.local_proxy_port().unwrap();
            stack.reconcile_controlled_backend_with_listeners(native::now(),
                |_, _, _| panic!("must not duplicate a live registration listener"),
                |_, _, _| panic!("must not duplicate a live proxy listener")).unwrap();
            assert_eq!(stack.enforcer.local_proxy_port(), Some(port));
            assert!(!stack.enforcer.sandbox_ready().unwrap(), "I03 stays closed");
        }
    }

    #[test]
    fn corrected_startup_config_updates_supervisor_before_registry_version() {
        let mut f = fixture(true);
        assert!(f.stack.as_ref().unwrap().sandbox_registry.is_none());
        let mut cfg = Config::default_for_new_install();
        cfg.proxy_url = "http://127.0.0.1:18765".into();
        cfg.enabled = true;
        // Simulate an explicit external repair; ConfigStore::save correctly refuses to
        // merge into a corrupt file, and this test must not weaken that protection.
        f.store.atomic_json(&f.store.paths.config(), &cfg.value().unwrap()).unwrap();
        let saved = ConfigStore { storage: f.store.clone() }.load().unwrap();
        let expected = ChannelSupervisor::compute_policy_version(&saved).unwrap();
        let stack = f.stack.as_mut().unwrap();
        // No VPN observer/file-change event exists in this fixture: the recovery path must apply it itself.
        stack.reconcile_controlled_backend(native::now()).unwrap();
        assert!(stack.sandbox_registry.is_some());
        assert_eq!(stack.supervisor.saved_policy_version(), &expected);
        assert_eq!(stack.last_policy_version.as_ref(), Some(&expected));
        assert_eq!(stack.supervisor.config().proxy_url, saved.proxy_url);
        assert!(stack.supervisor.config_blocking_reason().is_none());
        assert!(!stack.enforcer.sandbox_ready().unwrap());
    }

    #[test]
    fn metadata_refresh_preserves_unchanged_entries_and_observes_target_changes() {
        let f = fixture(false);
        let target = f.root.join("Applications/Claude.app/Contents/MacOS/Claude");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(f.root.join("Applications/Claude.app/Contents/Info.plist"),
            r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.anthropic.claudefordesktop</string><key>CFBundleExecutable</key><string>Claude</string></dict></plist>"#).unwrap();
        fs::write(&target, b"fixture-a").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let signature = target_metadata_signature(&f.store, Some(&f.store.paths.watch().join("runtime")));
        assert_eq!(signature, target_metadata_signature(&f.store, Some(&f.store.paths.watch().join("runtime"))));
        let entry = f.store.paths.watch().join("entries/apps/Claude (Controlled).app/Contents/Info.plist");
        let deadline = Instant::now() + Duration::from_secs(3);
        while !entry.is_file() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(20));
        }
        let modified = fs::metadata(&entry).unwrap().modified().unwrap();
        thread::sleep(Duration::from_millis(1200));
        assert_eq!(fs::metadata(&entry).unwrap().modified().unwrap(), modified,
            "unchanged metadata must not recopy/rewrite entries on every poll");
        fs::write(&target, b"fixture-b").unwrap();
        assert_ne!(signature, target_metadata_signature(&f.store, Some(&f.store.paths.watch().join("runtime"))));
        let sha = claude_watch_system::sha256_file_hex(&target).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !fs::read_to_string(&entry).unwrap().contains(&sha) {
            assert!(Instant::now() < deadline, "changed target was not refreshed");
            thread::sleep(Duration::from_millis(20));
        }
    }
}
