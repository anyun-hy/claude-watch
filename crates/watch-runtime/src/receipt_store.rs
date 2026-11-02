//! Persists receipts under the same observations lock used by the legacy backend.
//! The caller must supply a freshly sampled local context, not a saved target config.
use crate::storage::StateStore;
use claude_watch_core::{
    error::{CoreError, Result},
    receipts,
    risk::{self, SessionRiskInput},
};
use serde_json::{json, Value};

pub struct ReceiptStore {
    pub storage: StateStore,
}
impl ReceiptStore {
    pub fn record_dns(
        &self,
        probe: &Value,
        local: &Value,
        expected: Option<&str>,
        now: f64,
    ) -> Result<Value> {
        let receipt = receipts::record_dns(probe, local, expected, now)?;
        let _lock = self.storage.lock("observations", None)?;
        self.require_latest("dns-leak-receipt.json", "finished_at", &receipt)?;
        self.storage.atomic_json(
            &self.storage.paths.base().join("dns-leak-receipt.json"),
            &receipt,
        )?;
        if receipts::dns_last_valid(&receipt, receipt["context"].as_str().unwrap_or(""), now) {
            self.storage.atomic_json(
                &self.storage.paths.base().join("dns-leak-last-valid.json"),
                &receipt,
            )?;
        }
        Ok(receipt)
    }
    pub fn record_webrtc(
        &self,
        probe: &Value,
        local: &Value,
        expected: Option<&str>,
        now: f64,
    ) -> Result<Value> {
        let receipt = receipts::record_webrtc(probe, local, expected, now)?;
        let _lock = self.storage.lock("observations", None)?;
        self.require_latest("webrtc-risk-receipt.json", "sampled_at", &receipt)?;
        self.storage.atomic_json(
            &self.storage.paths.base().join("webrtc-risk-receipt.json"),
            &receipt,
        )?;
        Ok(receipt)
    }
    pub fn record_stun(&self, probe: &Value, context: &str, now: f64) -> Result<Value> {
        let receipt = receipts::record_stun(probe, context, now)?;
        let _lock = self.storage.lock("observations", None)?;
        self.require_latest("stun-receipt.json", "sampled_at", &receipt)?;
        self.storage.atomic_json(
            &self.storage.paths.base().join("stun-receipt.json"),
            &receipt,
        )?;
        Ok(receipt)
    }
    /// A fresh, context-bound observation is reused; anything else returns
    /// `None` so the caller probes again instead of presenting stale facts.
    pub fn stun_fact(&self, context: &str, now: f64) -> Option<Value> {
        let receipt = self
            .storage
            .read_json(
                &self.storage.paths.base().join("stun-receipt.json"),
                json!({}),
            )
            .ok()?;
        receipts::stun_fact(&receipt, context, now)
    }
    fn require_latest(&self, file: &str, time_key: &str, next: &Value) -> Result<()> {
        let previous = self
            .storage
            .read_json(&self.storage.paths.base().join(file), json!({}))?;
        if previous[time_key]
            .as_f64()
            .zip(next[time_key].as_f64())
            .is_some_and(|(old, new)| old > new)
        {
            return Err(CoreError::new(
                "superseded_receipt",
                "更晚的检测结果已保存，未用迟到结果覆盖",
            ));
        }
        if previous[time_key].as_f64() == next[time_key].as_f64()
            && previous.is_object()
            && previous != *next
        {
            let normalize = |value: &Value| {
                let mut value = value.clone();
                if let Some(object) = value.as_object_mut() {
                    for key in [
                        "recorded_at",
                        "observed_at",
                        "display_expires_at",
                        "launch_expires_at",
                    ] {
                        object.remove(key);
                    }
                }
                value
            };
            if normalize(&previous) != normalize(next) {
                return Err(CoreError::new(
                    "receipt_conflict",
                    "同一采样时间的回执内容冲突，未覆盖",
                ));
            }
        }
        Ok(())
    }
    pub fn dns_status(
        &self,
        context: &str,
        launch: bool,
        now: f64,
        stamp: impl Fn(f64) -> String,
    ) -> Value {
        let receipt = self
            .storage
            .read_json(
                &self.storage.paths.base().join("dns-leak-receipt.json"),
                json!({}),
            )
            .unwrap_or_else(|_| json!({}));
        let cached = self
            .storage
            .read_json(
                &self.storage.paths.base().join("dns-leak-last-valid.json"),
                json!({}),
            )
            .unwrap_or_else(|_| json!({}));
        receipts::dns_status(&receipt, &cached, context, launch, now, stamp)
    }
    pub fn webrtc_status(&self, context: &str, now: f64) -> Value {
        match self.storage.read_json(
            &self.storage.paths.base().join("webrtc-risk-receipt.json"),
            json!({}),
        ) {
            Ok(receipt) => receipts::webrtc_status(&receipt, context, now),
            Err(_) => json!({"state":"unknown","detail":"WebRTC 回执不可读取"}),
        }
    }
    /// The guard/launch path builds risk from persisted, context-bound receipts;
    /// callers cannot inject a bare `{state:"safe"}` value.
    /// Raw probe receipts used to fingerprint the exit path. Unlike the
    /// derived statuses these keep the original country and candidate lists.
    pub fn probe_receipts(&self) -> (Value, Value) {
        let dns = self
            .storage
            .read_json(
                &self.storage.paths.base().join("dns-leak-receipt.json"),
                json!({}),
            )
            .unwrap_or_else(|_| json!({}));
        let webrtc = self
            .storage
            .read_json(
                &self.storage.paths.base().join("webrtc-risk-receipt.json"),
                json!({}),
            )
            .unwrap_or_else(|_| json!({}));
        (dns, webrtc)
    }
    /// Running-session drift verdict against the baseline stored in the
    /// session extra map. Absolute probe verdicts no longer close sessions;
    /// only a change relative to the session's own baseline does.
    pub fn probe_drift_risk(&self, extra: &Value, now: f64) -> Value {
        let empty: Vec<String> = Vec::new();
        let baseline_dns = extra
            .get("baseline_dns_countries")
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| empty.clone());
        let baseline_webrtc = extra
            .get("baseline_webrtc_addresses")
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| empty.clone());
        let (dns, webrtc) = self.probe_receipts();
        claude_watch_core::risk::probe_drift(&baseline_dns, &baseline_webrtc, &dns, &webrtc, now)
    }

    pub fn session_risk(&self, context: &str, current_ip: Option<&str>, now: f64) -> Value {
        let dns = self.dns_status(context, true, now, |v| format!("{v:.0}"));
        let webrtc = self.webrtc_status(context, now);
        let names = ["last-environment-detection.json", "last-audit.json"];
        let environment: Vec<_> = names
            .iter()
            .filter_map(|name| {
                self.storage
                    .read_json(&self.storage.paths.base().join(name), json!({}))
                    .ok()
            })
            .collect();
        risk::session_risk(&SessionRiskInput {
            dns: &dns,
            webrtc: &webrtc,
            environment_receipts: &environment,
            context_id: context,
            current_ip,
            now,
        })
    }
}
