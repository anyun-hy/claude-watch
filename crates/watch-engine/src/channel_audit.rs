use claude_watch_core::{
    error::{CoreError, Result},
    policy::PolicyCatalog,
};
use claude_watch_runtime::{
    audit_store::{AuditOptions, AuditStore, AuditSystem},
    channel_enforcer::LocalTunnelEnforcer,
    channel_supervisor::AsyncAuditRequest,
    config_store::ConfigStore,
    macos::Authority,
    native,
    region_catalog::load_system_catalog,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{
    process::Command,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

fn audit_context(audit: &Value) -> Result<&str> {
    if audit["context_changed"] == true
        || audit
            .pointer("/context_transition/state")
            .and_then(Value::as_str)
            == Some("changed")
    {
        return Err(CoreError::new(
            "audit_context_changed",
            "审计期间环境变化，保持待验证",
        ));
    }
    audit["context_id"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| CoreError::new("missing_context_id", "审计没有实际环境上下文"))
}

pub fn run(
    paths: &Paths,
    enforcer: &LocalTunnelEnforcer,
    req: &AsyncAuditRequest,
) -> Result<(Value, Value, f64)> {
    let remaining = req.requested_at + req.timeout_seconds - native::now();
    if !remaining.is_finite() || remaining <= 0.0 {
        return Err(CoreError::new("audit_cancelled", "审计已经超时"));
    }
    let deadline = Instant::now() + Duration::from_secs_f64(remaining);
    let fallback = AtomicBool::new(false);
    let cancel = req.cancellation.as_deref().unwrap_or(&fallback);
    let executable = std::env::current_exe()
        .map_err(|_| CoreError::new("audit_worker_missing", "无法定位审计运行组件"))?;
    let invoke = |kind: &str, mut input: Value| {
        input["home"] = json!(paths.home);
        input["family"] = json!(req.family);
        input["launch_target"] = json!(req.target);
        input["policy_version"] = json!(req.policy_version);
        claude_watch_runtime::audit_process::run_json(
            Command::new(&executable).args(["--channel-audit-worker", kind]),
            &input,
            deadline,
            cancel,
        )
    };
    let audit = invoke("audit", json!({}))?;
    // This context comes from this audit, never from an old session/request.
    let context = audit_context(&audit)?;
    let (mut egress, evidence) = enforcer.probe_via_controlled_diagnostic_channel(
        &req.family,
        context,
        native::now(),
        |proxy| invoke("egress", json!({"proxy":proxy,"context_id":context})),
    )?;
    egress["via_controlled_path"] = json!(true);
    egress["family"] = json!(evidence.family);
    egress["upstream_endpoint"] = json!(evidence.upstream_endpoint);
    egress["context_id"] = json!(evidence.context_id);
    egress["policy_version"] = serde_json::to_value(evidence.policy_version).unwrap();
    egress["observed_at"] = json!(evidence.observed_at);
    Ok((audit, egress, native::now()))
}

/// Private process entrypoint. No application lifecycle or installation actions.
pub fn worker(kind: &str, input: Value) -> Result<Value> {
    let home = input["home"]
        .as_str()
        .ok_or_else(|| CoreError::new("invalid_audit_request", "缺少数据目录"))?;
    let paths = Paths::new(home)?;
    let uid = claude_watch_system::effective_uid();
    if uid == 0 {
        return Err(CoreError::new(
            "root_audit_denied",
            "审计工作组件须由目标用户运行",
        ));
    }
    paths.require_owner(uid)?;
    let family = input["family"]
        .as_str()
        .and_then(PolicyCatalog::family)
        .ok_or_else(|| CoreError::new("invalid_audit_request", "审计策略家族无效"))?;
    let target = input["launch_target"].as_str().and_then(claude_watch_core::processes::LaunchTarget::parse)
        .filter(|target| PolicyCatalog::family_for(target.provider()).map(|f| f.id) == Some(family.id))
        .ok_or_else(|| CoreError::new("invalid_audit_request", "不支持的审计目标"))?;
    let mut host = super::runtime::host(paths.clone(), Authority::ExplicitPermit)?;
    let expected: claude_watch_core::channel::PolicyVersion =
        serde_json::from_value(input["policy_version"].clone())
            .map_err(|_| CoreError::new("invalid_audit_request", "缺少审计策略版本"))?;
    let config_store = ConfigStore {
        storage: host.storage.clone(),
    };
    let config = config_store.load()?;
    if claude_watch_runtime::channel_supervisor::ChannelSupervisor::compute_policy_version(&config)?
        != expected
    {
        return Err(CoreError::new(
            "audit_policy_changed",
            "审计开始前策略已经变化",
        ));
    }
    if kind == "audit" {
        let audit = AuditStore::new(StateStore::new(paths)).collect_target(
            &mut host,
            &load_system_catalog(),
            target,
            AuditOptions {
                online: true,
                persist: false,
                launch: true,
            },
        )?;
        let latest = config_store.load()?;
        if claude_watch_runtime::channel_supervisor::ChannelSupervisor::compute_policy_version(
            &latest,
        )? != expected
            || audit["policy"].as_str() != Some(expected.policy_digest.as_str())
        {
            return Err(CoreError::new(
                "audit_policy_changed",
                "审计期间策略已经变化",
            ));
        }
        return Ok(audit);
    }
    if kind != "egress" {
        return Err(CoreError::new("invalid_audit_request", "不支持的审计操作"));
    }
    let context = input["context_id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CoreError::new("missing_context_id", "缺少探针上下文"))?;
    let before = host.local_for_target(&config, target)?;
    if before["context_id"].as_str() != Some(context) {
        return Err(CoreError::new(
            "audit_context_changed",
            "探针前环境已经变化",
        ));
    }
    let proxy = input["proxy"]
        .as_str()
        .ok_or_else(|| CoreError::new("invalid_audit_request", "缺少受控出口"))?;
    let receipt = host.network.fast_egress_via(Some(proxy));
    let current = ConfigStore {
        storage: host.storage.clone(),
    }
    .load()?;
    let after = host.local_for_target(&current, target)?;
    if after["context_id"].as_str() != Some(context) || config.value()? != current.value()? {
        return Err(CoreError::new(
            "audit_context_changed",
            "探针期间环境或策略发生变化",
        ));
    }
    receipt
        .data
        .ok_or_else(|| CoreError::new("controlled_probe_failed", "受控探针没有有效出口证据"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn channel_audit_requires_the_observed_context_and_rejects_sampling_changes() {
        assert_eq!(
            audit_context(&json!({"context_id":"new-network"})).unwrap(),
            "new-network"
        );
        assert!(audit_context(&json!({"session_id":"session-only"})).is_err());
        assert!(audit_context(
            &json!({"context_id":"new","context_transition":{"state":"changed"}})
        )
        .is_err());
    }
}
