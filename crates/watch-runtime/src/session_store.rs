use crate::storage::StateStore;
use claude_watch_core::error::{CoreError, Result};
use claude_watch_core::policy::PolicyCatalog;
use claude_watch_core::processes::{LaunchTarget, Provider};
use claude_watch_core::session::{self, CheckInput, Desktop, Launcher, Outcome, Phase, Session};
use serde_json::json;
use serde_json::Value;
use uuid::Uuid;

pub struct SessionStore {
    pub storage: StateStore,
    family: &'static str,
}
impl SessionStore {
    pub fn new(storage: StateStore) -> Self {
        Self {
            storage,
            family: "claude",
        }
    }
    /// Bind the store to one policy family so its session record and lock are
    /// kept apart from the other families the guard supervises. The default
    /// `new` remains the Claude family for backward compatibility with callers
    /// that manage a single supervised service (monitor snapshots, evidence).
    pub fn for_family(storage: StateStore, family: &'static str) -> Self {
        Self { storage, family }
    }
    fn session_path(&self) -> std::path::PathBuf {
        self.storage.paths.session_for(self.family)
    }
    fn lock_name(&self) -> String {
        if self.family == "claude" {
            "session-guard".to_string()
        } else {
            format!("session-guard-{}", self.family)
        }
    }
    pub fn load(&self, now: f64) -> Result<Option<Session>> {
        let value = self
            .storage
            .read_json(&self.session_path(), Value::Null)?;
        if value.is_null() {
            return Ok(None);
        }
        let mut session: Session = serde_json::from_value(value)
            .map_err(|_| CoreError::new("invalid_session", "受控会话记录格式无效"))?;
        session.validate(now)?;
        Ok(Some(session))
    }
    fn save(&self, value: &Session) -> Result<()> {
        self.storage.atomic_json(
            &self.session_path(),
            &serde_json::to_value(value)
                .map_err(|_| CoreError::new("invalid_session", "受控会话无法序列化"))?,
        )
    }
    /// Low-level compatibility seam for in-crate transition tests. Production
    /// dispatchers must call `begin_verified`, which reconstructs risk from
    /// private receipts rather than accepting a caller-selected state.
    #[cfg(test)]
    fn begin(&self, audit: &Value, current: &Value, risk: &Value, now: f64) -> Result<Session> {
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        let value = session::begin(audit, current, risk, &Uuid::new_v4().to_string(), now)?;
        self.save(&value)?;
        Ok(value)
    }
    /// Production entry point: risk evidence is reconstructed from the private
    /// receipt store, never accepted as a caller-provided safe boolean.
    pub fn begin_verified(
        &self,
        receipts: &crate::receipt_store::ReceiptStore,
        audit: &Value,
        current: &Value,
        now: f64,
    ) -> Result<Session> {
        if audit["grants_launch_permission"] == false
            || audit
                .get("purpose")
                .and_then(Value::as_str)
                .is_some_and(|purpose| {
                    matches!(
                        purpose,
                        "environment_detection" | "launch_requirements_preview"
                    )
                })
        {
            return Err(CoreError::new(
                "display_receipt_not_authority",
                "展示结果不能授予启动许可，必须重新执行完整预检",
            ));
        }
        self.require_audit_family(audit, None)?;
        let context = audit
            .get("context_id")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| CoreError::new("egress_unconfirmed", "审计回执缺少当前网络上下文"))?;
        let current_ip = current.get("ip").and_then(Value::as_str);
        let risk = receipts.session_risk(context, current_ip, now);
        // Publish the pending session and its baseline once, under the same
        // lock. A second unlocked save could restore Pending over a concurrent
        // bind/lock/replacement made after the first save.
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        let mut session = session::begin(audit, current, &risk, &Uuid::new_v4().to_string(), now)?;
        Self::anchor_probe_baseline(&mut session, receipts, now);
        self.save(&session)?;
        Ok(session)
    }
    fn require_audit_family(&self, audit: &Value, provider: Option<Provider>) -> Result<()> {
        let mismatch = || CoreError::new("launch_target_mismatch", "启动审计、会话服务与授权范围不一致");
        // Only a genuinely absent target has the legacy Claude meaning.
        // Invalid, unknown or CLI targets cannot create a desktop session.
        let target = match audit.get("launch_target") {
            None => LaunchTarget::ClaudeDesktop,
            Some(value) => value.as_str().and_then(LaunchTarget::parse).ok_or_else(mismatch)?,
        };
        if target.cli()
            || PolicyCatalog::family_for(target.provider()).map(|f| f.id) != Some(self.family)
            || provider.is_some_and(|p| PolicyCatalog::family_for(p).map(|f| f.id) != Some(self.family))
        {
            return Err(mismatch());
        }
        Ok(())
    }
    fn anchor_probe_baseline(session: &mut Session, receipts: &crate::receipt_store::ReceiptStore, now: f64) {
        let (mut dns, mut webrtc) = receipts.probe_receipts();
        let usable = |value: &Value, context_key: &str, time_key: &str| {
            value["status"] == "complete"
                && value[context_key].as_str() == Some(session.context_id.as_str())
                && value[time_key].as_f64().is_some_and(|at| at.is_finite()
                    && (0.0..=session::RISK_EVIDENCE_TTL).contains(&(now - at)))
        };
        if !usable(&dns, "context", "finished_at") { dns = Value::Null; }
        if !usable(&webrtc, "context_id", "sampled_at") { webrtc = Value::Null; }
        let (countries, addresses) = claude_watch_core::risk::probe_fingerprint(&dns, &webrtc);
        session.extra.insert("baseline_dns_countries".into(), json!(countries));
        session.extra.insert("baseline_webrtc_addresses".into(), json!(addresses));
    }
    pub fn bind_launcher(&self, id: &str, launcher: Launcher, now: f64) -> Result<Session> {
        if launcher.pid <= 1 || launcher.start.is_empty() || launcher.start.len() > 80 {
            return Err(CoreError::new(
                "launcher_identity_unavailable",
                "启动器身份未能确认",
            ));
        }
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        let mut value = self.pending(id, now)?;
        value.launcher = Some(launcher);
        self.save(&value)?;
        Ok(value)
    }
    fn pending(&self, id: &str, now: f64) -> Result<Session> {
        self.load(now)?
            .filter(|v| v.state == Phase::Pending && v.session_id == id)
            .ok_or_else(|| CoreError::new("session_changed", "启动会话已变化，未绑定进程"))
    }
    pub fn bind_desktop(&self, id: &str, desktop: Desktop, now: f64) -> Result<Session> {
        if !desktop.valid() {
            return Err(CoreError::new(
                "desktop_identity_unavailable",
                "主进程启动身份不完整",
            ));
        }
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        let mut value = self.pending(id, now)?;
        value.state = Phase::Active;
        value.bound_at = Some(now);
        value.desktop = Some(desktop);
        self.save(&value)?;
        Ok(value)
    }
    /// A session adopted from an already-running Claude keeps its origin, so
    /// later diagnostics and the UI can tell it apart from a controlled
    /// launch without weakening any check.
    pub fn mark_adopted(&self, id: &str, now: f64) -> Result<Session> {
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        let mut value = self
            .load(now)?
            .filter(|v| v.session_id == id)
            .ok_or_else(|| CoreError::new("session_changed", "会话已变化，未写入采纳来源"))?;
        value
            .extra
            .insert("adopted_from".into(), json!("running_desktop"));
        self.save(&value)?;
        Ok(value)
    }

    /// End only the session whose exact bound process was independently
    /// confirmed gone. A stale observation must not end a replacement session.
    pub fn end_desktop(
        &self,
        id: &str,
        desktop: &Desktop,
        now: f64,
        tree_pending: bool,
    ) -> Result<bool> {
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        let Some(mut value) = self.load(now)? else {
            return Ok(false);
        };
        if value.session_id != id
            || value.desktop.as_ref() != Some(desktop)
            || !matches!(
                value.state,
                Phase::Active | Phase::Rechecking | Phase::Locked
            )
            || value
                .extra
                .get("guard_checked_at")
                .and_then(Value::as_f64)
                .is_some_and(|at| at > now)
        {
            return Ok(false);
        }
        value.state = Phase::Ended;
        value.extra.insert("ended_at".into(), json!(now));
        value
            .extra
            .insert("exit_tree_pending".into(), json!(tree_pending));
        self.save(&value)?;
        Ok(true)
    }

    pub fn clear_ended_tree(&self, id: &str, now: f64) -> Result<bool> {
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        let Some(mut value) = self.load(now)? else {
            return Ok(false);
        };
        if value.session_id != id || value.state != Phase::Ended {
            return Ok(false);
        }
        if value.extra.remove("exit_tree_pending").is_some() {
            self.save(&value)?;
        }
        Ok(true)
    }

    /// Bind the unique replacement provisionally. If the previous desktop
    /// tree was never observed empty, keep its known exit as the fast guard's
    /// baseline; otherwise a fresh sample establishes the new baseline.
    pub fn begin_recheck(&self, id: &str, desktop: Desktop, now: f64) -> Result<Option<Session>> {
        if !desktop.valid() {
            return Err(CoreError::new(
                "desktop_identity_unavailable",
                "新进程身份不完整",
            ));
        }
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        let Some(mut value) = self.load(now)? else {
            return Ok(None);
        };
        if value.session_id != id
            || value.state != Phase::Ended
            || value.desktop.as_ref() == Some(&desktop)
        {
            return Ok(None);
        }
        let keep_previous_baseline = value.extra.get("exit_tree_pending") == Some(&json!(true))
            && value.extra.get("recheck_baseline_pending") != Some(&json!(true));
        value.session_id = Uuid::new_v4().to_string();
        value.state = Phase::Rechecking;
        value.desktop = Some(desktop);
        value.created_at = now;
        value.bound_at = Some(now);
        value.pending_deadline = now + session::RISK_EVIDENCE_TTL;
        value.launcher = None;
        value.unknown_count = 0;
        value.unknown_since = None;
        value.reason = None;
        value.last_reason = None;
        value.last_check = None;
        value.last_risk_state = None;
        value.locked_at = None;
        value.extra.remove("guard_checked_at");
        value.extra.remove("ended_at");
        value.extra.remove("exit_tree_pending");
        if keep_previous_baseline {
            value.extra.remove("recheck_baseline_pending");
        } else {
            value
                .extra
                .insert("recheck_baseline_pending".into(), json!(true));
        }
        self.save(&value)?;
        Ok(Some(value))
    }

    /// Update only the provisional evidence context; this never authorizes or
    /// changes the exit baseline and cannot modify a locked/newer session.
    pub fn recheck_context(
        &self,
        id: &str,
        desktop: &Desktop,
        context: &str,
        now: f64,
    ) -> Result<bool> {
        if context.is_empty() || context.len() > 160 {
            return Err(CoreError::new(
                "evidence_context_unconfirmed",
                "新进程网络上下文无效",
            ));
        }
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        let Some(mut current) = self.load(now)? else {
            return Ok(false);
        };
        if current.session_id != id
            || current.state != Phase::Rechecking
            || current.desktop.as_ref() != Some(desktop)
        {
            return Ok(false);
        }
        if current.context_id != context {
            current.context_id = context.to_owned();
            self.save(&current)?;
        }
        Ok(true)
    }

    /// Upgrade a still-current provisional process only after the same full
    /// audit and private receipt checks used by the normal launch path.
    pub fn complete_recheck(
        &self,
        id: &str,
        desktop: &Desktop,
        stamp: &str,
        audit: &Value,
        egress: &Value,
        now: f64,
        provider: Provider,
    ) -> Result<Option<Session>> {
        // Apply the same family boundary as initial creation, before either
        // a session record or an observation lease can be changed.
        self.require_audit_family(audit, Some(provider))?;
        // Policy writes use this lock. Keep it short and outside network work;
        // the fast guard does not acquire it.
        let _operation = self.storage.lock("operation", None)?;
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        let Some(current) = self.load(now)? else {
            return Ok(None);
        };
        if current.session_id != id
            || current.state != Phase::Rechecking
            || current.desktop.as_ref() != Some(desktop)
        {
            return Ok(None);
        }
        if !current.pending_deadline.is_finite() || now > current.pending_deadline {
            return Err(CoreError::new(
                "revalidation_timeout",
                "新进程完整校验已超时",
            ));
        }
        if current.extra.get("recheck_baseline_pending") == Some(&json!(true)) {
            return Err(CoreError::new(
                "egress_unconfirmed",
                "新进程出口基准尚未确认",
            ));
        }
        let config = crate::config_store::ConfigStore {
            storage: self.storage.clone(),
        }
        .load()?;
        let policy = crate::config_store::policy_digest(&config.value()?)?;
        if !config.enabled
            || !config.guard_enabled
            || !crate::audit_store::audit_matches_policy(audit, &policy)
        {
            return Err(CoreError::new(
                "revalidation_context_changed",
                "重新校验期间保护设置已变化",
            ));
        }
        let measured = session::Egress::fresh(egress, now, session::GUARD_EGRESS_TTL)
            .ok_or_else(|| CoreError::new("egress_unconfirmed", "新进程出口未确认"))?;
        if measured.observed_at < current.created_at
            || audit["observed_at"]
                .as_f64()
                .is_none_or(|at| at < current.created_at)
            || audit["egress_reference"]["checked_at"]
                .as_f64()
                .is_none_or(|at| at < current.created_at)
        {
            return Err(CoreError::new(
                "egress_unconfirmed",
                "新进程需要本次启动之后的完整采样",
            ));
        }
        if measured.ip != current.baseline.ip {
            return Err(CoreError::new(
                "egress_changed",
                "新进程出口与原会话基准不一致",
            ));
        }
        let context = audit["context_id"].as_str().unwrap_or("");
        let receipts = crate::receipt_store::ReceiptStore { storage: self.storage.clone() };
        let risk = receipts.session_risk(context, Some(&measured.ip), now);
        if ["dns", "webrtc"].iter().any(|kind| {
            risk["sources"][*kind]["observed_at"]
                .as_f64()
                .is_none_or(|at| !at.is_finite() || at < current.created_at)
        }) {
            return Err(CoreError::new(
                "risk_evidence_unavailable",
                "新进程需要重新采集 DNS 和 WebRTC 证据",
            ));
        }
        let mut verified = session::begin(audit, egress, &risk, id, now)?;
        verified.state = Phase::Active;
        verified.desktop = Some(desktop.clone());
        verified.bound_at = Some(now);
        Self::anchor_probe_baseline(&mut verified, &receipts, now);
        let lease_path = self
            .storage
            .paths
            .watch()
            .join(format!("state/sessions/rust-{}.session", desktop.pid));
        let old_lease = self.storage.read_bytes(&lease_path, 16 * 1024)?;
        crate::controlled::Controller::new(self.storage.clone()).lease(desktop, stamp, now, provider)?;
        if let Err(error) = self.save(&verified) {
            let rollback = match old_lease {
                Some(bytes) => self.storage.atomic_bytes(&lease_path, &bytes, 0o600),
                None => {
                    self.storage.guarded(&lease_path)?;
                    std::fs::remove_file(&lease_path).map_err(|_| {
                        CoreError::new(
                            "revalidation_lease_rollback_failed",
                            "未能撤销重新校验观察记录",
                        )
                    })
                }
            };
            rollback?;
            return Err(error);
        }
        Ok(Some(verified))
    }
    /// A stale probe may never overwrite or close a newer controlled session.
    #[cfg(test)]
    fn apply_check(&self, id: Option<&str>, input: &CheckInput) -> Result<Outcome> {
        if !input.now.is_finite() || input.now <= 0.0 {
            return Err(CoreError::new("clock_unavailable", "无法核对检测时间"));
        }
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        self.apply_check_locked(id, input, false)
    }
    fn apply_check_locked(
        &self,
        id: Option<&str>,
        input: &CheckInput,
        local_unknown: bool,
    ) -> Result<Outcome> {
        let current = self.load(input.now)?;
        if current.as_ref().map(|v| v.session_id.as_str()) != id {
            return Ok(Outcome::changed(input.now));
        }
        let Some(current) = current else {
            return Ok(Outcome::missing(input.now));
        };
        if current
            .extra
            .get("guard_checked_at")
            .and_then(Value::as_f64)
            .is_some_and(|previous| input.now <= previous)
        {
            return Err(CoreError::new(
                "superseded_check",
                "更晚的会话检测已保存，未用迟到结果覆盖",
            ));
        }
        let checked = session::check(&current, input);
        let mut outcome = if local_unknown && !matches!(checked.state.as_str(), "risk" | "locked") {
            session::uncertain(
                current.clone(),
                "proxy_or_tun_unconfirmed",
                "代理或TUN连续未能确认",
                input.now,
            )
        } else {
            checked
        };
        if let Some(value) = &outcome.session {
            let mut value = value.clone();
            value
                .extra
                .insert("guard_checked_at".into(), json!(input.now));
            if value != current {
                self.save(&value)?;
            }
            outcome.session = Some(value);
        }
        Ok(outcome)
    }
    /// Production guard entry point. It binds DNS/WebRTC/environment risk to
    /// the persisted session context and current egress before transitioning.
    pub fn check_verified(
        &self,
        receipts: &crate::receipt_store::ReceiptStore,
        id: Option<&str>,
        now: f64,
        launcher_live: bool,
        identity: claude_watch_core::session::Identity,
        egress: Value,
    ) -> Result<Outcome> {
        self.check_verified_local(receipts, id, now, launcher_live, identity, egress, false)
    }
    pub fn check_verified_local(
        &self,
        receipts: &crate::receipt_store::ReceiptStore,
        id: Option<&str>,
        now: f64,
        launcher_live: bool,
        identity: claude_watch_core::session::Identity,
        egress: Value,
        local_unknown: bool,
    ) -> Result<Outcome> {
        if !now.is_finite() || now <= 0.0 {
            return Err(CoreError::new("clock_unavailable", "无法核对检测时间"));
        }
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        let current = self
            .load(now)?
            .filter(|v| Some(v.session_id.as_str()) == id);
        let immediate = current.as_ref().is_some_and(|s| {
            s.state == Phase::Locked
                || session::Egress::fresh(&egress, now, session::GUARD_EGRESS_TTL).is_some_and(
                    |e| {
                        (s.state != Phase::Rechecking || e.observed_at >= s.created_at)
                            && (e.country == "CN"
                                || (s.extra.get("recheck_baseline_pending") != Some(&json!(true))
                                    && e.ip != s.baseline.ip))
                    },
                )
        }) || identity == claude_watch_core::session::Identity::Changed;
        let risk = if immediate {
            json!({"state":"unknown"})
        } else {
            match current.as_ref() {
                // Running supervision compares probe exits against this
                // session's own baseline. The absolute probe verdict is a
                // display fact, not a close trigger.
                Some(session) => receipts.probe_drift_risk(
                    &serde_json::to_value(&session.extra).unwrap_or_else(|_| serde_json::json!({})),
                    now,
                ),
                None => json!({"state":"unknown"}),
            }
        };
        self.apply_check_locked(
            id,
            &CheckInput {
                now,
                launcher_live,
                identity,
                egress,
                risk,
            },
            local_unknown,
        )
    }
    pub fn close_if_current<T>(
        &self,
        id: Option<&str>,
        now: f64,
        closer: impl FnOnce() -> Result<T>,
    ) -> Result<Option<T>> {
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        if self.load(now)?.as_ref().map(|v| v.session_id.as_str()) != id {
            return Ok(None);
        }
        closer().map(Some)
    }
    /// A failed write must not allow a superseded probe to stop a newer observation.
    pub fn close_if_current_before<T>(
        &self,
        id: Option<&str>,
        now: f64,
        checked_at: f64,
        closer: impl FnOnce() -> Result<T>,
    ) -> Result<Option<T>> {
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        let current = self.load(now)?;
        if current.as_ref().map(|v| v.session_id.as_str()) != id
            || current.as_ref().is_some_and(|v| {
                v.extra
                    .get("guard_checked_at")
                    .and_then(Value::as_f64)
                    .is_some_and(|t| {
                        t > checked_at || (t == checked_at && v.state != Phase::Locked)
                    })
            })
        {
            return Ok(None);
        }
        closer().map(Some)
    }
    pub fn close_if_unreadable<T>(
        &self,
        now: f64,
        closer: impl FnOnce() -> Result<T>,
    ) -> Result<Option<T>> {
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        if self.load(now).is_ok() {
            return Ok(None);
        }
        closer().map(Some)
    }
    /// Resume normal supervision for a warn-tier session whose underlying
    /// condition has cleared: the latch reverts to the active phase and the
    /// stale reason is dropped. Only a still-current locked session can be
    /// resumed, and the drift baseline stays untouched.
    pub fn resume_if_current(&self, id: Option<&str>, now: f64) -> Result<bool> {
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        let Some(mut value) = self.load(now)? else {
            return Ok(false);
        };
        if value.session_id.as_str() != id.unwrap_or_default() || value.state != Phase::Locked {
            return Ok(false);
        }
        value.state = Phase::Active;
        value.reason = None;
        value.last_reason = None;
        value.locked_at = None;
        value.last_risk_state = None;
        value.unknown_count = 0;
        value.unknown_since = None;
        value.risk_evidence = json!({"state":"unknown"});
        value.extra.insert("guard_checked_at".into(), json!(now));
        self.save(&value)?;
        Ok(true)
    }
    pub fn mark_failure(
        &self,
        id: Option<&str>,
        now: f64,
        code: &str,
        detail: &str,
        confirmed: bool,
    ) -> Result<Outcome> {
        let _lock = self.storage.lock(&self.lock_name(), None)?;
        let current = self.load(now)?;
        if current.as_ref().map(|v| v.session_id.as_str()) != id {
            return Ok(Outcome::changed(now));
        }
        let Some(current) = current else {
            return Ok(Outcome::missing(now));
        };
        if current
            .extra
            .get("guard_checked_at")
            .and_then(Value::as_f64)
            .is_some_and(|t| now <= t)
        {
            return Err(CoreError::new("superseded_check", "更晚的会话检测已经保存"));
        }
        let mut outcome = if current.state == Phase::Locked {
            session::check(
                &current,
                &CheckInput {
                    now,
                    launcher_live: false,
                    identity: claude_watch_core::session::Identity::Unavailable,
                    egress: Value::Null,
                    risk: Value::Null,
                },
            )
        } else if confirmed {
            let locked = session::lock(current, code, detail, now, None, None);
            let reason = locked.reason.clone();
            Outcome {
                state: "risk".into(),
                reason,
                baseline: Some(locked.baseline.clone()),
                current: locked.last_check.clone(),
                risk_evidence: Some(locked.risk_evidence.clone()),
                session: Some(locked),
            }
        } else {
            session::uncertain(current, code, detail, now)
        };
        if let Some(session) = &mut outcome.session {
            session.extra.insert("guard_checked_at".into(), json!(now));
            self.save(session)?;
        }
        Ok(outcome)
    }
}

#[cfg(test)]
mod contract_tests;
#[cfg(test)]
mod order_tests;
