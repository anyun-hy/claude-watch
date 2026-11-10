use claude_watch_core::{channel::{BoundProcessToken, ChannelPermitState}, config::Config, session::Desktop,
    vpn::{ObservationConsistency, ObservedField, UpstreamProtocol, VpnEpoch, VpnExpectation, VpnObservation}};
use claude_watch_runtime::{channel_enforcer::LocalTunnelEnforcer, channel_supervisor::{ChannelSupervisor, SupervisionEvent},
    config_store::{policy_digest, ConfigStore}, receipt_store::ReceiptStore, session_store::SessionStore, storage::StateStore};
use serde_json::{json, Value};
use std::sync::Arc;
pub fn sample_vpn_observation(now: f64, change_generation: u64) -> VpnObservation {
    VpnObservation {
        source: "clash-verge".into(),
        source_instance: Some("inst-1".into()),
        source_revision: Some(format!("rev-{change_generation}")),
        upstream_endpoint: Some("http://127.0.0.1:17890".into()),
        upstream_protocol: ObservedField::Known(UpstreamProtocol::MixedHttp),
        running_mode: ObservedField::Known("rule".into()),
        tun_enabled: ObservedField::Known(false),
        system_proxy_enabled: ObservedField::Known(false),
        selected_group: ObservedField::Known("AI-Group".into()),
        selected_node: ObservedField::Known("US-West-01".into()),
        proxy_chain: ObservedField::Known(vec!["AI-Group".into(), "US-West-01".into()]),
        rules_digest: ObservedField::Unknown("controller_rules_not_sampled".into()),
        sample_started_at: now,
        observed_at: now,
        valid_until: now + 3.5,
        consistency: ObservationConsistency::RevisionVerified,
        source_error: None,
        sample_seq: change_generation,
        epoch: VpnEpoch::new("vpn-obs-boot-1", change_generation),
    }
}

fn controlled_egress(
    cfg: &Config,
    now: f64,
    ip: &str,
    country: &str,
    vpn_epoch: Option<VpnEpoch>,
) -> Value {
    let policy_ver = ChannelSupervisor::compute_policy_version(cfg).unwrap();
    let mut val = json!({
        "ip": ip,
        "country": country,
        "observed_at": now,
        "source": "fixture",
        "family": "*",
        "upstream_endpoint": cfg.proxy_url,
        "policy_version": policy_ver,
        "context_id": "ctx-vpn",
        "via_controlled_path": true
    });
    if let Some(ep) = vpn_epoch {
        val["vpn_epoch"] = json!(ep);
    }
    val
}

fn fixture_audit_val(store: &StateStore, now: f64, ip: &str, country: &str) -> Value {
    let config = (ConfigStore {
        storage: store.clone(),
    })
    .load()
    .unwrap();
    json!({
        "ready": true,
        "observed_at": now,
        "expires_at": now + 30.0,
        "context_id": "ctx-vpn",
        "observation_id": "fixture",
        "context_transition": {"state": "stable"},
        "policy": policy_digest(&config.value().unwrap()).unwrap(),
        "egress_reference": {
            "ip": ip,
            "country": country,
            "checked_at": now,
            "context": "ctx-vpn",
            "source": "fixture"
        }
    })
}

fn seed_probe_receipts(store: &StateStore, now: f64, country: &str) {
    let receipts = ReceiptStore {
        storage: store.clone(),
    };
    let local = json!({
        "context": "ctx-vpn",
        "context_id": "ctx-vpn",
        "proxy": "ok",
        "tun": "ok",
        "guard_backend_healthy": true,
        "observation_unavailable": []
    });
    for kind in [
        claude_watch_runtime::background_evidence::ProbeKind::Dns,
        claude_watch_runtime::background_evidence::ProbeKind::WebRtc,
    ] {
        let mut val = json!({
            "kind": kind.label(),
            "status": "complete",
            "contextChanged": false,
            "startedAt": now - 1.0,
            "finishedAt": now,
            "errors": [],
            "observations": [{"kind": "http", "address": "1.1.1.1", "country": country}]
        });
        val["observations"].as_array_mut().unwrap().push(match kind {
            claude_watch_runtime::background_evidence::ProbeKind::Dns => {
                json!({"kind": "resolver", "address": "8.8.8.8", "country": country})
            }
            claude_watch_runtime::background_evidence::ProbeKind::WebRtc => {
                json!({"kind": "srflx", "address": "1.1.1.1", "country": country})
            }
        });
        if kind == claude_watch_runtime::background_evidence::ProbeKind::Dns {
            val["externalJSON"] = json!(json!({
                "session": "a".repeat(40),
                "dns_servers": {"8.8.8.8": 5},
                "http": {"address": "1.1.1.1", "country": country},
                "geoip": [{"ip": "8.8.8.8", "country_code": country}]
            })
            .to_string());
            receipts.record_dns(&val, &local, None, now).unwrap();
        } else {
            receipts.record_webrtc(&val, &local, None, now).unwrap();
        }
    }
}


pub fn config(store: &StateStore, upstream: &str) -> Config {
    let mut cfg = Config::default_for_new_install();
    cfg.enabled = true; cfg.guard_enabled = true; cfg.proxy_mode = "clash-verge".into();
    cfg.proxy_url = format!("http://{upstream}"); cfg.proxy_group = "AI-Group".into();
    let mut expected = VpnExpectation::unconfigured(); expected.configured = true;
    expected.proxy_mode = cfg.proxy_mode.clone(); expected.proxy_url = cfg.proxy_url.clone(); expected.proxy_group = cfg.proxy_group.clone();
    expected.running_mode = Some("rule".into()); expected.expected_node = Some("US-West-01".into());
    expected.expected_chain = vec!["AI-Group".into(), "US-West-01".into()];
    cfg.vpn_expectation = Some(expected);
    ConfigStore { storage: store.clone() }.save(cfg.value().unwrap()).unwrap()
}
pub fn inventory(supervisor: &mut ChannelSupervisor, tokens: Vec<BoundProcessToken>, now: f64) {
    let desktops = tokens.iter().map(|t| (Desktop { pid:t.pid, start_seconds:t.start_seconds, start_microseconds:t.start_microseconds }, true, "fixture".into())).collect();
    let snapshot = supervisor.handle_event(SupervisionEvent::ProcessInventoryUpdated { family:"claude".into(), desktops, processes:tokens, observed_at:now }).unwrap();
    assert_eq!(snapshot.families["claude"].permit_state, ChannelPermitState::Permitted, "{}", snapshot.families["claude"].reason_code);
}
pub fn activate(store: &StateStore, cfg: &Config, enforcer: Arc<LocalTunnelEnforcer>, tokens: Vec<BoundProcessToken>, now: f64) -> ChannelSupervisor {
    seed_probe_receipts(store, now, "US");
    let mut supervisor = ChannelSupervisor::new(store.clone(), Some(enforcer), None).unwrap();
    let mut observation = sample_vpn_observation(now, 1); observation.upstream_endpoint = Some(cfg.proxy_url.clone());
    let egress = controlled_egress(cfg, now, "1.1.1.1", "US", Some(observation.epoch.clone()));
    let sessions = SessionStore::for_family(store.clone(), "claude");
    let pending = sessions.begin_verified(&ReceiptStore { storage:store.clone() }, &fixture_audit_val(store, now, "1.1.1.1", "US"), &egress, now).unwrap();
    for token in &tokens { sessions.bind_desktop(&pending.session_id, Desktop { pid:token.pid, start_seconds:token.start_seconds, start_microseconds:token.start_microseconds }, now).unwrap(); }
    supervisor.handle_event(SupervisionEvent::VpnObservationUpdated { observation, observed_at:now }).unwrap();
    supervisor.handle_event(SupervisionEvent::EnvironmentUpdated { egress, local_guard:json!({"proxy":"ok","tun":"disabled","context_id":"ctx-vpn"}), observed_at:now }).unwrap();
    inventory(&mut supervisor, tokens, now);
    supervisor
}
