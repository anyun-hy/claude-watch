use crate::storage::StateStore;
use claude_watch_core::error::{CoreError, Result};
use claude_watch_core::session::{self, CheckInput, Desktop, Launcher, Outcome, Phase, Session};
use serde_json::json;
use serde_json::Value;
use uuid::Uuid;

pub struct SessionStore {
    pub storage: StateStore,
}
impl SessionStore {
    pub fn new(storage: StateStore) -> Self {
        Self { storage }
    }
    pub fn load(&self, now: f64) -> Result<Option<Session>> {
        let value = self
            .storage
            .read_json(&self.storage.paths.session(), Value::Null)?;
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
            &self.storage.paths.session(),
            &serde_json::to_value(value)
                .map_err(|_| CoreError::new("invalid_session", "受控会话无法序列化"))?,
        )
    }
    /// Low-level compatibility seam for in-crate transition tests. Production
    /// dispatchers must call `begin_verified`, which reconstructs risk from
    /// private receipts rather than accepting a caller-selected state.
    fn begin(&self, audit: &Value, current: &Value, risk: &Value, now: f64) -> Result<Session> {
        let _lock = self.storage.lock("session-guard", None)?;
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
        let context = audit
            .get("context_id")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| CoreError::new("egress_unconfirmed", "审计回执缺少当前网络上下文"))?;
        let current_ip = current.get("ip").and_then(Value::as_str);
        let risk = receipts.session_risk(context, current_ip, now);
        self.begin(audit, current, &risk, now)
    }
    pub fn bind_launcher(&self, id: &str, launcher: Launcher, now: f64) -> Result<Session> {
        if launcher.pid <= 1 || launcher.start.is_empty() || launcher.start.len() > 80 {
            return Err(CoreError::new(
                "launcher_identity_unavailable",
                "启动器身份未能确认",
            ));
        }
        let _lock = self.storage.lock("session-guard", None)?;
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
                "Claude 主进程启动身份不完整",
            ));
        }
        let _lock = self.storage.lock("session-guard", None)?;
        let mut value = self.pending(id, now)?;
        value.state = Phase::Active;
        value.bound_at = Some(now);
        value.desktop = Some(desktop);
        self.save(&value)?;
        Ok(value)
    }
    /// A stale probe may never overwrite or close a newer controlled session.
    #[cfg(test)]
    fn apply_check(&self, id: Option<&str>, input: &CheckInput) -> Result<Outcome> {
        if !input.now.is_finite() || input.now <= 0.0 {
            return Err(CoreError::new("clock_unavailable", "无法核对检测时间"));
        }
        let _lock = self.storage.lock("session-guard", None)?;
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
        let _lock = self.storage.lock("session-guard", None)?;
        let current = self
            .load(now)?
            .filter(|v| Some(v.session_id.as_str()) == id);
        let immediate = current.as_ref().is_some_and(|s| {
            s.state == Phase::Locked
                || session::Egress::fresh(&egress, now, session::GUARD_EGRESS_TTL)
                    .is_some_and(|e| e.country == "CN" || e.ip != s.baseline.ip)
        }) || identity == claude_watch_core::session::Identity::Changed;
        let risk = if immediate {
            json!({"state":"unknown"})
        } else {
            let context = current
                .as_ref()
                .map(|s| s.context_id.as_str())
                .unwrap_or_default();
            receipts.session_risk(context, egress.get("ip").and_then(Value::as_str), now)
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
        let _lock = self.storage.lock("session-guard", None)?;
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
        let _lock = self.storage.lock("session-guard", None)?;
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
        let _lock = self.storage.lock("session-guard", None)?;
        if self.load(now).is_ok() {
            return Ok(None);
        }
        closer().map(Some)
    }
    pub fn mark_failure(
        &self,
        id: Option<&str>,
        now: f64,
        code: &str,
        detail: &str,
        confirmed: bool,
    ) -> Result<Outcome> {
        let _lock = self.storage.lock("session-guard", None)?;
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
