//! Explanations for a failed guard check, never an alternative readiness gate.
//! Only fixed reason codes leave this module; raw executor/VPN errors may contain
//! paths, credentials or other data that do not belong in the first-run screen.
use crate::channel_policy_status::{producer_is_current, StatusFrame};
use claude_watch_core::channel::{NetworkBackendKind, PolicySyncState};
use serde_json::{json, Value};

pub(crate) fn read(frame: &StatusFrame<'_>, backend: bool, healthy: bool, heartbeat: &Value) -> Value {
    let installation_issue = if frame.config.effective_network_backend() == NetworkBackendKind::Seatbelt {
        let paths = [claude_watch_system::launchd_gateway::CONFIG_PATH,
            claude_watch_system::launchd_gateway::BROKER_PATH,
            "/Library/LaunchDaemons/io.local.claudewatch.gateway.plist"];
        let observations: Vec<_> = paths.iter().map(std::fs::symlink_metadata).collect();
        if observations.iter().any(|v| matches!(v, Err(e) if e.kind() == std::io::ErrorKind::NotFound)) {
            Some("gateway_not_installed")
        } else if observations.iter().any(|v| !v.as_ref().is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())) {
            Some("gateway_installation_unverified")
        } else { None }
    } else { None };
    let code = project(frame, backend, healthy, installation_issue, &frame.value["vpn_supervision"], heartbeat,
        producer_is_current(frame.value));
    report(code, frame, heartbeat)
}

fn report(code: &str, frame: &StatusFrame<'_>, heartbeat: &Value) -> Value {
    let evidence_at = match code {
        "guard_ready" | "guard_heartbeat_stale" | "guard_policy_unverified" => heartbeat["time"].clone(),
        "guard_disabled" | "gateway_not_installed" | "gateway_installation_unverified"
        | "legacy_config_migration_required" | "vpn_expectation_unconfigured" | "guard_backend_unverified" => json!(frame.now),
        _ => frame.value["captured_at"].clone(),
    };
    json!({"reason_code":code,"evidence_observed_at":evidence_at,"checked_at":frame.now})
}

fn project(frame: &StatusFrame<'_>, backend: bool, healthy: bool, installation_issue: Option<&'static str>,
    vpn: &Value, heartbeat: &Value, producer_current: bool) -> &'static str {
    let (config, now, channel) = (frame.config, frame.now, frame.value);
    if !config.enabled || !config.guard_enabled { return "guard_disabled"; }
    // A previous failure must never override an independently verified recovery.
    if healthy { return "guard_ready"; }
    if let Some(issue) = installation_issue { return issue; }
    if config.schema < 2 || config.network_backend.is_none() { return "legacy_config_migration_required"; }
    if config.vpn_expectation.as_ref().is_none_or(|v| !v.configured) { return "vpn_expectation_unconfigured"; }
    if !backend { return "guard_backend_unverified"; }
    let Some(policy) = frame.policy_wire() else { return "guard_policy_unverified"; };
    if !frame.readiness_frame_current(producer_current) {
        return "execution_evidence_stale_or_mismatched";
    }
    // A failure authenticates diagnostic details only for its own family.
    for (family, state) in frame.family_policy_states() {
        if state == PolicySyncState::ApplyFailed {
            let receipt = &channel["enforcement_receipts"][family];
            if !receipt.is_null() && receipt["vpn_epoch"] != channel["authoritative_permits"][family]["vpn_epoch"] {
                return "execution_evidence_stale_or_mismatched";
            }
            if receipt["enforcement_state"] != "failed" { return "channel_execution_failed"; }
            return match channel["enforcement_receipts"][family]["error_code"].as_str() {
                Some("gateway_endpoint_unverified_i03" | "gateway_server_identity_unverified_i03") => "gateway_identity_unverified",
                Some("active_flow_close_failed" | "flow_close_failed" | "close_timeout") => "flow_close_failed",
                _ => "channel_execution_failed",
            };
        }
    }
    if vpn["captured_at"] == channel["captured_at"] {
        if let (Some(expected), Ok(observation)) = (config.vpn_expectation.as_ref(), serde_json::from_value::<claude_watch_core::vpn::VpnObservation>(vpn["observation"].clone())) {
            let epoch_current = channel["families"].as_object().is_some_and(|families| families.iter().any(|(family, state)| {
                let permit = &channel["authoritative_permits"][family];
                state["producer_boot_id"] == channel["producer_boot_id"] && state["saved_policy_version"] == *policy
                    && permit["policy_version"] == *policy && permit["family"] == *family
                    && state["command_seq"] == permit["command_seq"] && state["permit_generation"] == permit["permit_generation"]
                    && permit["vpn_epoch"] == json!(observation.epoch) && state["vpn_epoch"] == json!(observation.epoch)
            }));
            if epoch_current {
                use claude_watch_core::vpn::VpnMatch;
                match claude_watch_core::vpn::compare_vpn(expected, &observation, now) {
                    VpnMatch::Mismatched { .. } => return "vpn_expectation_mismatched",
                    VpnMatch::Stale => return "vpn_observation_stale",
                    VpnMatch::Unknown { .. } => return "vpn_observation_unknown",
                    VpnMatch::Matched => {}
                }
            }
        }
    }
    if crate::config_store::guard_heartbeat_policy_matches(heartbeat, config) != Some(true) { return "guard_policy_unverified"; }
    if !heartbeat["time"].as_f64().is_some_and(|at| at.is_finite() && (0.0..=35.0).contains(&(now-at))) { return "guard_heartbeat_stale"; }
    "execution_not_confirmed"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel_supervisor::ChannelSupervisor;
    use claude_watch_core::config::Config;

    fn fixture() -> (Config, Value, Value) {
        let mut config = Config::default_for_new_install();
        config.enabled = true; config.guard_enabled = true;
        config.proxy_url = "http://127.0.0.1:7890".into(); config.proxy_mode = "tag".into();
        let mut expected = claude_watch_core::vpn::VpnExpectation::unconfigured();
        expected.configured = true; expected.proxy_url = config.proxy_url.clone(); expected.proxy_mode = "tag".into();
        config.vpn_expectation = Some(expected);
        let policy = ChannelSupervisor::compute_policy_version(&config).unwrap();
        let epoch = json!({"observer_boot_id":"vpn-1","change_generation":1});
        let permit = json!({"family":"claude","session_id":"s","policy_version":policy,"permit_generation":2,"command_seq":3,
            "state":"revoked","reason_code":"risk","issued_at":100.0,"valid_until":130.0,"members":[],"backend":"seatbelt","vpn_epoch":epoch});
        let receipt = json!({"family":"claude","session_id":"s","policy_version":policy,"permit_generation":2,"command_seq":3,"executor_boot_id":"executor-1",
            "permit_state":"revoked","enforcement_state":"failed","interception_active":false,"local_proxy_ready":false,"new_connections_blocked":true,
            "active_flows_closed":false,"direct_fallback_blocked":false,"active_flows_count":0,"terminated_flows_count":0,"blocked_new_connections":0,
            "observed_at":101.0,"backend":"seatbelt","sandbox_ready":false,"vpn_epoch":epoch,"error_code":"gateway_endpoint_unverified_i03"});
        let state = json!({"producer_boot_id":"producer-1","command_seq":3,"permit_generation":2,"saved_policy_version":policy,
            "policy_sync_state":"apply_failed","applied_policy_version":policy,"vpn_epoch":epoch});
        let channel = json!({"producer_boot_id":"producer-1","executor_boot_id":"executor-1","captured_at":102.0,"saved_policy_version":policy,
            "families":{"claude":state},"authoritative_permits":{"claude":permit},"enforcement_receipts":{"claude":receipt}});
        let heartbeat = json!({"time":102.0,"status":"protection_unavailable","guard_policy_v1":crate::config_store::guard_policy_digest(&config).unwrap()});
        (config, channel, heartbeat)
    }

    #[test]
    fn current_configuration_and_recovery_take_precedence_over_historical_errors() {
        let (config, channel, heartbeat) = fixture();
        let p = |c: &Config, installed, healthy| {
            project(&StatusFrame::new(&channel, c, 103.0), true, healthy, installed, &Value::Null, &heartbeat, true)
        };
        assert_eq!(p(&config,Some("gateway_not_installed"),false),"gateway_not_installed");
        assert_eq!(p(&config,None,true),"guard_ready");
        let mut old = config.clone(); old.network_backend = None; old.schema = 1;
        assert_eq!(p(&old,None,false),"legacy_config_migration_required");
        old = config.clone(); old.vpn_expectation = None;
        assert_eq!(p(&old,None,false),"vpn_expectation_unconfigured");
        old.guard_enabled = false;
        assert_eq!(p(&old,Some("gateway_not_installed"),false),"guard_disabled");
    }

    #[test]
    fn failure_reason_requires_current_authority_boot_policy_command_and_receipt() {
        let (config, channel, heartbeat) = fixture();
        let p = |v: &Value, at, live| {
            project(&StatusFrame::new(v, &config, at), true, false, None, &Value::Null, &heartbeat, live)
        };
        assert_eq!(p(&channel,103.0,true),"gateway_identity_unverified");
        assert_ne!(p(&channel,103.0,false),"gateway_identity_unverified");
        assert_ne!(p(&channel,112.0,true),"gateway_identity_unverified");
        for (path,replacement) in [
            ("/executor_boot_id",json!("old")), ("/producer_boot_id",json!("old")),
            ("/saved_policy_version/policy_digest",json!("old")),
            ("/enforcement_receipts/claude/observed_at",json!(90.0)),
            ("/enforcement_receipts/claude/executor_boot_id",json!("old")),
            ("/enforcement_receipts/claude/policy_version/policy_digest",json!("old")),
            ("/enforcement_receipts/claude/command_seq",json!(1)),
            ("/enforcement_receipts/claude/permit_generation",json!(1)),
            ("/enforcement_receipts/claude/vpn_epoch/change_generation",json!(2)),
        ] {
            let mut old = channel.clone(); *old.pointer_mut(path).unwrap() = replacement;
            assert_ne!(p(&old,103.0,true),"gateway_identity_unverified","{path}");
        }
        let mut private = channel.clone(); private["enforcement_receipts"]["claude"]["error_code"] = json!("secret:1234@proxy");
        assert_eq!(p(&private,103.0,true),"channel_execution_failed");
        assert!(!detail(p(&private,103.0,true)).contains("secret"));
        private["enforcement_receipts"] = json!({});
        assert_eq!(p(&private,103.0,true),"channel_execution_failed");
    }

    #[test]
    fn vpn_mismatch_requires_current_copublished_observation_and_epoch() {
        use claude_watch_core::vpn::{ObservedField, ObservationConsistency, UpstreamProtocol, VpnEpoch, VpnObservation};
        let (config, mut channel, heartbeat) = fixture();
        channel["enforcement_receipts"]["claude"]["enforcement_state"] = json!("blocked");
        channel["enforcement_receipts"]["claude"]["error_code"] = Value::Null;
        for key in ["interception_active","local_proxy_ready","active_flows_closed","direct_fallback_blocked","sandbox_ready"] {
            channel["enforcement_receipts"]["claude"][key] = json!(true);
        }
        channel["families"]["claude"]["policy_sync_state"] = json!("applied");
        let observation = VpnObservation { source:"tag".into(), source_instance:Some("fixture".into()),source_revision:Some("fixture".into()),
            upstream_endpoint:Some("http://127.0.0.1:7891".into()),upstream_protocol:ObservedField::Known(UpstreamProtocol::MixedHttp),
            running_mode:ObservedField::Known("rule".into()),tun_enabled:ObservedField::Known(true),system_proxy_enabled:ObservedField::Known(true),
            selected_group:ObservedField::Unknown("unused".into()),selected_node:ObservedField::Unknown("unused".into()),
            proxy_chain:ObservedField::Unknown("unused".into()),rules_digest:ObservedField::Unknown("unused".into()),
            sample_started_at:102.0,observed_at:102.0,valid_until:105.0,consistency:ObservationConsistency::RevisionVerified,
            source_error:None,sample_seq:1,epoch:VpnEpoch::new("vpn-1",1) };
        let vpn = json!({"captured_at":102.0,"observation":observation});
        let p = |v: &Value, at| {
            project(&StatusFrame::new(&channel, &config, at), true, false, None, v, &heartbeat, true)
        };
        assert_eq!(p(&vpn,103.0),"vpn_expectation_mismatched");
        assert_eq!(p(&vpn,105.0),"vpn_observation_stale");
        let mut old = vpn.clone(); old["captured_at"] = json!(101.0);
        assert_ne!(p(&old,103.0),"vpn_expectation_mismatched");
        old = vpn.clone(); old["observation"]["epoch"]["observer_boot_id"] = json!("old");
        assert_ne!(p(&old,103.0),"vpn_expectation_mismatched");
    }

    #[test]
    fn readiness_preserves_raw_failure_details_observation_times_and_late_liveness() {
        let (config, mut channel, mut heartbeat) = fixture();
        channel["enforcement_receipts"]["claude"]["observed_at"] = json!("malformed");
        channel["enforcement_receipts"]["claude"]["error_code"] = json!("active_flow_close_failed");
        heartbeat["time"] = json!(101.5);
        let frame = StatusFrame::new(&channel, &config, 103.0);
        let diagnostic = |live, healthy| {
            let code = project(&frame, true, healthy, None, &Value::Null, &heartbeat, live);
            report(code, &frame, &heartbeat)
        };
        assert_eq!(diagnostic(true, false), json!({
            "reason_code":"flow_close_failed", "evidence_observed_at":102.0, "checked_at":103.0
        }));
        assert_eq!(diagnostic(false, false), json!({
            "reason_code":"execution_evidence_stale_or_mismatched", "evidence_observed_at":102.0, "checked_at":103.0
        }));
        assert_eq!(diagnostic(false, true), json!({
            "reason_code":"guard_ready", "evidence_observed_at":101.5, "checked_at":103.0
        }));

        let mut future = channel.clone();
        future["captured_at"] = json!(103.02);
        assert_eq!(
            project(&StatusFrame::new(&future, &config, 103.0), true, false, None, &Value::Null, &heartbeat, true),
            "execution_evidence_stale_or_mismatched"
        );
    }
}

pub(crate) fn detail(code: &str) -> &'static str {
    match code {
        "guard_ready" => "保护心跳与后台身份已确认",
        "guard_disabled" => "Watch 保护设置尚未开启",
        "gateway_not_installed" => "受控网关尚未安装完整；请使用统一重装流程安装 Watch 网关后重新检查。无需付费开发者签名。",
        "gateway_installation_unverified" => "受控网关安装文件无法核验；请检查统一重装记录。",
        "legacy_config_migration_required" => "Watch 仍使用旧版保护设置；请在初始化确认页确认新版保护方式和 VPN 预期。",
        "vpn_expectation_unconfigured" => "尚未保存 Watch 的 VPN 预期；请在初始化确认页核对并保存。本工具不会修改 VPN。",
        "guard_backend_unverified" => "采集后台身份或心跳当前未确认，无法确认保护状态。",
        "gateway_identity_unverified" => "受控网关身份或监听端点尚未通过验证；当前不能确认网络保护已生效。",
        "flow_close_failed" => "网络连接尚未确认全部关闭；断流执行失败，请查看检查记录。",
        "channel_execution_failed" => "当前网络保护命令执行失败；未取得成功回执，请查看检查记录。",
        "vpn_expectation_mismatched" => "当前 VPN 状态与已保存预期不一致；恢复到预期状态后重新检查。Watch 不会修改 VPN。",
        "vpn_observation_stale" => "VPN 检测证据已过期，正在等待当前状态重新核验。",
        "vpn_observation_unknown" => "当前 VPN 状态无法完整确认，网络保护尚未就绪。",
        "guard_policy_unverified" => "保护后台尚未确认当前保存的设置，正在等待新配置的执行回执。",
        "guard_heartbeat_stale" => "保护后台运行中；最近一轮保护证据已过期，正在重新核验。",
        "execution_evidence_stale_or_mismatched" => "网络保护回执已过期或不属于当前运行实例及设置，正在等待重新核验。",
        _ => "Watch 保镖的实际执行结果尚未确认，请查看检查记录。",
    }
}
