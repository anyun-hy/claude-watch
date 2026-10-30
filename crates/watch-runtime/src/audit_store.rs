//! Full audit collection and persistence orchestration.
//!
//! The native adapter owns sampling; this store owns the before/after binding
//! and the private, atomic audit history shared by launch and guard paths.
use crate::{
    config_store::{policy_digest, ConfigStore},
    receipt_store::ReceiptStore,
    storage::StateStore,
};
pub use claude_watch_core::audit::Scope as AuditScope;
use claude_watch_core::{
    audit::{self, AuditInput},
    config::Config,
    error::{CoreError, Result},
    observation,
    region::ZoneCatalog,
};
use serde_json::{json, Value};
use uuid::Uuid;

pub trait AuditSystem {
    fn now(&self) -> f64;
    fn network(&self) -> Result<Value>;
    fn local(&self, config: &Config) -> Result<Value>;
    fn local_for_target(
        &self,
        config: &Config,
        _target: claude_watch_core::processes::LaunchTarget,
    ) -> Result<Value> {
        self.local(config)
    }
    fn online(&mut self, config: &Config, local: &Value) -> Result<Value>;
    fn online_for_target(
        &mut self,
        config: &Config,
        local: &Value,
        _target: claude_watch_core::processes::LaunchTarget,
    ) -> Result<Value> {
        self.online(config, local)
    }
    /// A launch may ask the adapter to refresh a bounded DNS/WebRTC probe. A
    /// missing probe is not made safe; persisted current-context receipts decide.
    fn refresh_dns(&mut self) -> Result<Option<Value>> {
        Ok(None)
    }
    fn refresh_webrtc(&mut self) -> Result<Option<Value>> {
        Ok(None)
    }
    /// A launch re-probes UDP/STUN so the gate never trusts a cached answer.
    /// The periodic environment view does not call this and reuses the receipt
    /// for `STUN_RECEIPT_TTL` instead, which is what keeps the row stable.
    fn refresh_stun(&mut self, _context: &str) -> Result<Option<Value>> {
        Ok(None)
    }
}
pub struct AuditStore {
    pub storage: StateStore,
}
#[derive(Clone, Copy)]
pub struct AuditOptions {
    pub online: bool,
    pub persist: bool,
    pub launch: bool,
}
impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            online: true,
            persist: true,
            launch: false,
        }
    }
}
/// `status` refuses to present a stored audit whose policy digest no longer
/// matches the live configuration, and the background baseline collector must
/// make the same call before deciding to sample again. Both sides share this
/// helper so the two judgements cannot drift apart.
pub fn audit_matches_policy(stored: &Value, policy: &str) -> bool {
    stored["policy"].as_str() == Some(policy)
}
impl AuditStore {
    pub fn new(storage: StateStore) -> Self {
        Self { storage }
    }
    fn history_path(&self) -> std::path::PathBuf {
        self.storage.paths.base().join("ip-history.json")
    }
    fn audit_path(&self) -> std::path::PathBuf {
        self.storage.paths.base().join("last-audit.json")
    }
    fn detection_path(&self) -> std::path::PathBuf {
        self.storage
            .paths
            .base()
            .join("last-environment-detection.json")
    }
    pub fn collect<S: AuditSystem>(
        &self,
        system: &mut S,
        zones: &ZoneCatalog,
        launch: bool,
    ) -> Result<Value> {
        self.collect_options(
            system,
            zones,
            AuditOptions {
                online: true,
                persist: true,
                launch,
            },
        )
    }
    pub fn collect_options<S: AuditSystem>(
        &self,
        system: &mut S,
        zones: &ZoneCatalog,
        options: AuditOptions,
    ) -> Result<Value> {
        self.collect_scope(system, zones, AuditScope::Full, options)
    }
    pub fn collect_scope<S: AuditSystem>(
        &self,
        system: &mut S,
        zones: &ZoneCatalog,
        scope: AuditScope,
        options: AuditOptions,
    ) -> Result<Value> {
        self.collect_inner(
            system,
            zones,
            scope,
            claude_watch_core::processes::LaunchTarget::ClaudeDesktop,
            options,
            None,
        )
    }
    pub fn collect_target<S: AuditSystem>(
        &self,
        system: &mut S,
        zones: &ZoneCatalog,
        target: claude_watch_core::processes::LaunchTarget,
        options: AuditOptions,
    ) -> Result<Value> {
        self.collect_inner(system, zones, AuditScope::Full, target, options, None)
    }
    /// Capture supplemental evidence only for the display-only environment request.
    /// Launch and protection audits continue through the unchanged no-capture path.
    pub fn collect_environment<S: AuditSystem>(
        &self,
        system: &mut S,
        zones: &ZoneCatalog,
        target: claude_watch_core::processes::LaunchTarget,
        options: AuditOptions,
    ) -> Result<(Value, Option<crate::guard_diagnostics::GuardRound>)> {
        if options.launch {
            return Err(CoreError::new(
                "invalid_audit_scope",
                "环境展示不能授予启动许可",
            ));
        }
        let mut capture = crate::guard_diagnostics::GuardCapture::default();
        let audit = self.collect_inner(
            system,
            zones,
            AuditScope::Full,
            target,
            options,
            Some(&mut capture),
        )?;
        let round = capture
            .before
            .zip(capture.after)
            .and_then(|(before, after)| {
                let observation_id = audit["observation_id"].as_str()?.to_owned();
                let value = crate::guard_diagnostics::GuardRound {
                    observation_id,
                    before,
                    after,
                };
                value.validate().ok().map(|_| value)
            });
        Ok((audit, round))
    }
    fn collect_inner<S: AuditSystem>(
        &self,
        system: &mut S,
        zones: &ZoneCatalog,
        scope: AuditScope,
        target: claude_watch_core::processes::LaunchTarget,
        mut options: AuditOptions,
        mut guard_capture: Option<&mut crate::guard_diagnostics::GuardCapture>,
    ) -> Result<Value> {
        if !target.protected() {
            options.persist = false;
        }
        if scope != AuditScope::Full {
            if options.launch {
                return Err(CoreError::new(
                    "invalid_audit_scope",
                    "专项检测不能授予启动许可",
                ));
            }
            options.persist = false;
        }
        let config = ConfigStore {
            storage: self.storage.clone(),
        }
        .load()?;
        let policy = policy_digest(&config.value()?)?;
        let before_network = system.network()?;
        let mut before = system.local_for_target(&config, target)?;
        if let Some(capture) = guard_capture.as_deref_mut() {
            capture.before = Some(crate::guard_diagnostics::capture_phase(
                &self.storage, &config, &before, system.now(),
            ));
        }
        let transport = before["proxy"] == "ok" && before["tun"] == "ok";
        // A launch must not read a cached UDP observation: re-probe first so the
        // gate judges a fresh round.  The periodic environment view skips this
        // and reuses the receipt, which is what keeps the STUN row stable.
        if options.launch
            && scope == AuditScope::Full
            && options.online
            && config.online_enabled
            && transport
        {
            let context = before
                .get("context_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let _ = system.refresh_stun(context);
        }
        let mut online = if scope == AuditScope::Full
            && options.online
            && config.online_enabled
            && transport
        {
            system.online_for_target(&config, &before, target)?
        } else {
            json!({"query_errors":{"online": {"source":"audit","message":"联网检测未获允许或传输未确认"}}})
        };
        let receipts = ReceiptStore {
            storage: self.storage.clone(),
        };
        let dns_refresh_requested = (options.launch || scope == AuditScope::Dns)
            && options.online
            && config.online_enabled
            && transport;
        let mut dns_refresh_error = None;
        if dns_refresh_requested {
            match system.refresh_dns() {
                Ok(Some(probe)) => {
                    if let Err(error) = receipts.record_dns(&probe, &before, None, system.now()) {
                        dns_refresh_error =
                            Some(json!({"code":error.code,"message":error.message}));
                    }
                }
                Ok(None) => {}
                Err(error) if scope == AuditScope::Dns => {
                    dns_refresh_error = Some(json!({"code":error.code,"message":error.message}))
                }
                Err(error) => return Err(error),
            }
            if scope == AuditScope::Full && options.launch {
                if let Some(probe) = system.refresh_webrtc()? {
                    let _ = receipts.record_webrtc(&probe, &before, None, system.now());
                }
            }
        }
        let now = system.now();
        let after_config = ConfigStore {
            storage: self.storage.clone(),
        }
        .load()?;
        let after_network = system.network()?;
        let after = system.local_for_target(&after_config, target)?;
        if let Some(capture) = guard_capture {
            capture.after = Some(crate::guard_diagnostics::capture_phase(
                &self.storage, &after_config, &after, system.now(),
            ));
        }
        if target.cli() && before["cli_proxy"] != after["cli_proxy"] {
            before["cli_proxy"] =
                json!({"state":"unknown","detail":"预检期间CLI代理设置或入口证据发生变化，未启动"});
        }
        if !target.protected() {
            before["backend_healthy"] =
                json!(before["backend_healthy"] == true && after["backend_healthy"] == true);
            before["backend_native"] =
                json!(before["backend_native"] == true && after["backend_native"] == true);
        }
        let mut transition = observation::reconcile(&mut before, &after);
        let missing = ["service", "interface"].iter().any(|key| {
            before_network.get(*key).is_none_or(Value::is_null)
                || after_network.get(*key).is_none_or(Value::is_null)
        });
        let network_changed = ["service", "interface"].iter().any(|key| {
            before_network.get(*key).is_some_and(|v| !v.is_null())
                && after_network.get(*key).is_some_and(|v| !v.is_null())
                && before_network.get(*key) != after_network.get(*key)
        });
        // Local identity sampling can become unavailable (e.g. TAG disappears)
        // between observations.  Only a policy change or two non-null network
        // facts that disagree prove a real context change.
        if policy != policy_digest(&after_config.value()?)? || network_changed {
            transition["state"] = json!("changed");
        } else if missing && transition["state"] != "changed" {
            transition["state"] = json!("sampling_unavailable");
        }
        before["context_transition"] = transition.clone();
        before["context_changed"] = json!(transition["state"] == "changed");
        let context = before
            .get("context_id")
            .or_else(|| before.get("context"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if scope != AuditScope::Proxy {
            online["dns"] =
                receipts.dns_status(&context, options.launch, now, |v| format!("{v:.0}"));
        }
        if scope == AuditScope::Full {
            online["webrtc"] = receipts.webrtc_status(&context, now);
        }
        let history = if scope == AuditScope::Full {
            self.storage
                .read_json(&self.history_path(), json!([]))?
                .as_array()
                .cloned()
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let mut output = audit::evaluate_target(
            AuditInput {
                config: &after_config,
                local: &before,
                online: &online,
                history: &history,
                zones,
                policy: &policy,
                now,
            },
            target,
            |v| format!("{v:.0}"),
        )?;
        let id = Uuid::new_v4().to_string();
        output["context_id"] = json!(context);
        output["observation_id"] = json!(id);
        output["network_identity"] = after_network;
        output["context_transition"] = transition;
        if scope != AuditScope::Full {
            let evidence = if scope == AuditScope::Dns {
                json!({"dns":online["dns"],"dns_refresh":{"requested":dns_refresh_requested,"error":dns_refresh_error},
                    "source":"ReceiptStore；与环境页、启动校验共用DNS泄漏回执；以回执采样时间为准"})
            } else {
                json!({"source":"AuditStore.local；与环境页共用代理、TUN及规则判定", "entry":before.pointer("/tag/entry"), "controller":{"state":before.pointer("/tag/api/state"),"reason":before.pointer("/tag/api/reason")}})
            };
            return audit::project(scope, output, evidence);
        }
        // Keep the already captured inputs with the private audit receipt.  The
        // environment page is a presentation of this exact sample; it must not
        // issue a second online probe merely to fill in labels or timestamps.
        // These facts are evidence only and are never read by launch policy.
        output["display_facts"] = json!({
            "local": before,
            "online": online,
            "network": before_network,
        });
        if !options.persist {
            return Ok(output);
        }
        let _lock = self.storage.lock("observations", None)?;
        if policy
            != policy_digest(
                &ConfigStore {
                    storage: self.storage.clone(),
                }
                .load()?
                .value()?,
            )?
        {
            return Err(CoreError::new("context_changed", "采样期间策略已变化"));
        }
        let mut updated: Vec<_> = history
            .into_iter()
            .filter(|v| now - v.get("time").and_then(Value::as_f64).unwrap_or(0.0) <= 172_800.0)
            .collect();
        if let Some(ip) = output
            .pointer("/egress_reference/ip")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
        {
            updated.push(json!({"time":now,"ip":ip}));
        }
        if updated.len() > 2_048 {
            updated.drain(..updated.len() - 2_048);
        }
        if self.storage.read_json(&self.audit_path(), Value::Null)?["observed_at"]
            .as_f64()
            .is_some_and(|old| old > now)
        {
            return Err(CoreError::new(
                "superseded_audit",
                "更晚审计已保存，未用迟到结果覆盖",
            ));
        }
        self.storage
            .atomic_json(&self.history_path(), &json!(updated))?;
        self.storage.atomic_json(&self.audit_path(), &output)?;
        self.storage.atomic_json(&self.detection_path(), &output)?;
        Ok(output)
    }
}
