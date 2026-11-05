//! Recoverable A/B Claude-profile storage.  This module deliberately has no
//! concrete process implementation: callers must inject application control.
use crate::storage::StateStore;
use claude_watch_core::{
    account::{
        evaluate_account_ownership, AccountOwnershipObservation, AccountOwnershipState,
        LegacySwitcherAnchor,
    },
    config::Config,
    error::{CoreError, Result},
};
use serde_json::{json, Value};
use sha2::Digest;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use uuid::Uuid;

mod commit_recovery;

const TRANSIENT: &[&str] = &["SingletonLock", "SingletonCookie", "SingletonSocket"];
const MANIFEST_LIMIT: usize = 2_000_000;
fn err(code: &str, message: &str) -> CoreError {
    CoreError::new(code, message)
}
fn io(_: std::io::Error) -> CoreError {
    err("account_io_failed", "账号资料文件操作失败")
}

/// Application and COW authority is injected by the eventual dispatcher.
pub trait AccountOs {
    fn claude_version(&mut self) -> Result<Option<String>>;
    fn quit_claude(&mut self) -> Result<()>;
    fn claude_running(&mut self) -> Result<bool>;
    fn launch_claude(&mut self) -> Result<()>;
    fn preflight(&mut self) -> Result<()>;
    fn clone_file(&mut self, _source: &Path, _target: &Path) -> Result<bool> {
        Ok(false)
    }
    fn checkpoint(&mut self, _stage: &str) -> Result<()> {
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountStatus {
    pub id: String,
    pub stored: bool,
    pub current: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub current: Option<String>,
    pub recovery_required: bool,
    pub accounts: Vec<AccountStatus>,
    pub legacy_conflict: Option<Value>,
}
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CopyMetrics {
    pub cloned_files: u64,
    pub copied_files: u64,
    pub strategy: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchResult {
    pub current: String,
    pub copied: Vec<CopyMetrics>,
    pub login_verified: bool,
}
impl Status {
    pub fn value(&self) -> Value {
        json!({"schema":1,"current":self.current,"recovery_required":self.recovery_required,"accounts":self.accounts.iter().map(|x|json!({"id":x.id,"stored":x.stored,"current":x.current})).collect::<Vec<_>>(),"legacy_conflict":self.legacy_conflict,"login_verified":false,"detail":"账号槽位表示本地资料目录，不证明远端账号身份或钥匙串隔离"})
    }
}
impl SwitchResult {
    pub fn value(&self) -> Value {
        json!({"status":"ok","account":self.current,"login_verified":false,"elapsed_seconds":0.0,"engine":"rust-transaction","upstream_commit":null,"source_sha256":null,"archive_method":"rust-transaction","message":"本地资料切换完成；不证明远端登录或钥匙串隔离","copies":self.copied.iter().map(|x|json!({"cloned_files":x.cloned_files,"copied_files":x.copied_files,"strategy":x.strategy})).collect::<Vec<_>>()})
    }
}

pub struct AccountStore<O> {
    pub storage: StateStore,
    pub os: O,
}
impl<O: AccountOs> AccountStore<O> {
    pub fn new(storage: StateStore, os: O) -> Self {
        Self { storage, os }
    }
    fn state_path(&self) -> PathBuf {
        self.storage.paths.base().join("accounts.json")
    }
    fn slot(&self, id: &str) -> PathBuf {
        self.storage.paths.accounts().join(id)
    }
    fn profile(&self, id: &str) -> PathBuf {
        self.slot(id).join("profile")
    }
    /// Dispatcher-facing read-only location for a stored slot; account id is validated.
    pub fn profile_path(&self, id: &str) -> Result<PathBuf> {
        Self::valid(id)?;
        Ok(self.profile(id))
    }
    fn valid(id: &str) -> Result<()> {
        if matches!(id, "A" | "B") {
            Ok(())
        } else {
            Err(err("invalid_account", "仅接受账号 A 或 B"))
        }
    }
    fn state(&self) -> Result<Option<String>> {
        let v = self
            .storage
            .read_json(&self.state_path(), json!({"schema":1,"current":null}))?;
        let c = v.get("current").and_then(Value::as_str).map(str::to_owned);
        if v["schema"] != json!(1) || c.as_deref().is_some_and(|x| !matches!(x, "A" | "B")) {
            Err(err("invalid_account_state", "账号状态损坏；需要人工核对"))
        } else {
            Ok(c)
        }
    }
    fn active_directory_ino(&self) -> Option<u64> {
        use std::os::unix::fs::MetadataExt;
        fs::symlink_metadata(self.storage.paths.active())
            .ok()
            .filter(|m| m.is_dir() && !m.file_type().is_symlink())
            .map(|m| m.ino())
    }
    fn save_state(
        &self,
        current: Option<&str>,
        token: Option<&str>,
        legacy_anchor: Option<&LegacySwitcherAnchor>,
    ) -> Result<()> {
        let prev = self
            .storage
            .read_json(&self.state_path(), json!({"schema":1,"current":null}))
            .unwrap_or_else(|_| json!({"schema":1,"current":null}));
        let prev_epoch = prev
            .get("ownership_epoch")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let prev_active_ino = prev.get("active_dir_ino").and_then(Value::as_u64);
        let mut v = json!({
            "schema": 1,
            "current": current,
            "ownership_epoch": if token.is_some() { prev_epoch + 1 } else { prev_epoch.max(1) }
        });
        if let Some(x) = token {
            v["transaction_id"] = json!(x);
            if let Some(ino) = self.active_directory_ino() {
                v["active_dir_ino"] = json!(ino);
            }
        } else if prev_active_ino.is_some() {
            if let Some(ino) = self.active_directory_ino() {
                v["active_dir_ino"] = json!(ino);
            }
        }
        if let Some(a) = legacy_anchor {
            if let Some(c) = &a.current {
                v["legacy_current_observed"] = json!(c);
            }
            if let Some(m) = a.mtime_ns {
                v["legacy_current_mtime_ns"] = json!(m);
            }
            if let Some(i) = a.ino {
                v["legacy_current_ino"] = json!(i);
            }
        }
        self.storage.atomic_json(&self.state_path(), &v)
    }
    fn legacy_switcher_dir(&self) -> PathBuf {
        self.storage.paths.home.join(".claude-switcher")
    }
    fn legacy_lock_file(&self) -> PathBuf {
        self.legacy_switcher_dir().join("cli-operation.lock")
    }
    fn legacy_current_file(&self) -> PathBuf {
        self.legacy_switcher_dir().join("current")
    }
    fn observe_legacy_switcher(&self) -> Result<(bool, Option<LegacySwitcherAnchor>)> {
        let lock_path = self.legacy_lock_file();
        let external_locked = if lock_path.exists() {
            self.storage.guarded(&lock_path)?;
            true
        } else {
            false
        };

        let current_path = self.legacy_current_file();
        if !current_path.exists() {
            return Ok((external_locked, None));
        }
        self.storage.guarded(&current_path)?;
        let meta = fs::symlink_metadata(&current_path).map_err(io)?;
        if meta.file_type().is_symlink() {
            return Err(err("symlink_rejected", "原版切换器状态文件禁止符号链接"));
        }
        use std::os::unix::fs::MetadataExt;
        let mtime_ns = ((meta.mtime() as i128) * 1_000_000_000 + (meta.mtime_nsec() as i128)) as u64;
        let ino = meta.ino();
        let content = fs::read_to_string(&current_path).map_err(io)?;
        let trimmed = content.trim().to_string();

        Ok((
            external_locked,
            Some(LegacySwitcherAnchor {
                current: if trimmed.is_empty() { None } else { Some(trimmed) },
                mtime_ns: Some(mtime_ns),
                ino: Some(ino),
            }),
        ))
    }
    fn read_recorded_ownership_anchors(&self) -> Result<(Option<LegacySwitcherAnchor>, bool)> {
        let v = self
            .storage
            .read_json(&self.state_path(), json!({"schema":1,"current":null}))?;
        let current = v
            .get("legacy_current_observed")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mtime_ns = v.get("legacy_current_mtime_ns").and_then(Value::as_u64);
        let ino = v.get("legacy_current_ino").and_then(Value::as_u64);
        let recorded_anchor = if current.is_none() && mtime_ns.is_none() && ino.is_none() {
            None
        } else {
            Some(LegacySwitcherAnchor {
                current,
                mtime_ns,
                ino,
            })
        };
        let active_mutated = match v.get("active_dir_ino").and_then(Value::as_u64) {
            Some(expected_ino) => self.active_directory_ino() != Some(expected_ino),
            None => false,
        };
        Ok((recorded_anchor, active_mutated))
    }
    fn check_external_ownership(
        &self,
        watch_current: Option<&str>,
    ) -> Result<AccountOwnershipState> {
        let (external_locked, current_anchor) = self.observe_legacy_switcher()?;
        let (recorded_anchor, active_mutated) = self.read_recorded_ownership_anchors()?;
        let obs = AccountOwnershipObservation {
            watch_current: watch_current.map(str::to_owned),
            recorded_anchor,
            current_anchor,
            external_locked,
            active_mutated,
        };
        let state = evaluate_account_ownership(&obs);
        match &state {
            AccountOwnershipState::ExternalLocked => Err(err(
                "external_switcher_locked",
                "检测到原版切换器正在执行操作，未切换账号",
            )),
            AccountOwnershipState::SplitBrainConflict { .. } => Err(err(
                "external_switcher_conflict",
                "原版切换器当前账号与 Claude Watch 不一致，为防止资料错槽覆盖已阻断切换",
            )),
            AccountOwnershipState::UntrackedActiveMutation => Err(err(
                "external_change",
                "活动资料已被外部修改，未覆盖",
            )),
            AccountOwnershipState::ExclusiveWatch
            | AccountOwnershipState::AlignedCoexistence => Ok(state),
        }
    }
    pub fn status(&self) -> Result<Status> {
        let current = self.state()?;
        let (external_locked, current_anchor) =
            self.observe_legacy_switcher().unwrap_or((false, None));
        let (recorded_anchor, active_mutated) =
            self.read_recorded_ownership_anchors().unwrap_or((None, false));
        let obs = AccountOwnershipObservation {
            watch_current: current.clone(),
            recorded_anchor,
            current_anchor,
            external_locked,
            active_mutated,
        };
        let ownership_state = evaluate_account_ownership(&obs);
        let legacy_conflict = match ownership_state {
            AccountOwnershipState::ExternalLocked => Some(json!({
                "code": "external_switcher_locked",
                "message": "检测到原版切换器正在执行操作"
            })),
            AccountOwnershipState::SplitBrainConflict { watch_current, legacy_current } => Some(json!({
                "code": "external_switcher_conflict",
                "watch_current": watch_current,
                "legacy_current": legacy_current,
                "message": "原版切换器当前账号与 Claude Watch 不一致"
            })),
            AccountOwnershipState::UntrackedActiveMutation => Some(json!({
                "code": "external_change",
                "watch_current": current,
                "message": "活动资料目录已被外部整体替换"
            })),
            _ => None,
        };
        Ok(Status {
            recovery_required: self.storage.paths.journal().exists(),
            accounts: ["A", "B"]
                .iter()
                .map(|id| AccountStatus {
                    id: (*id).into(),
                    stored: self.profile(id).is_dir(),
                    current: current.as_deref() == Some(id),
                })
                .collect(),
            current,
            legacy_conflict,
        })
    }
    pub fn import_legacy(&mut self, legacy: &Path, apply: bool) -> Result<Status> {
        self.storage.guarded(legacy)?;
        let ids: Vec<_> = ["A", "B"]
            .iter()
            .filter(|id| legacy.join("accounts").join(id).is_dir())
            .copied()
            .collect();
        if !apply {
            return Ok(Status {
                current: None,
                recovery_required: false,
                accounts: ["A", "B"]
                    .iter()
                    .map(|id| AccountStatus {
                        id: (*id).into(),
                        stored: ids.contains(id),
                        current: false,
                    })
                    .collect(),
                legacy_conflict: None,
            });
        }
        let _guard = self.storage.lock("operation", None)?;
        self.storage.initialize()?;
        if self.storage.paths.journal().exists()
            || fs::read_dir(self.storage.paths.accounts())
                .map_err(io)?
                .next()
                .is_some()
        {
            return Err(err("import_conflict", "新账号库非空或存在未完成事务"));
        }
        let cf = legacy.join("current");
        self.storage.guarded(&cf)?;
        let current = if cf.exists() {
            Some(fs::read_to_string(&cf).map_err(io)?.trim().to_owned())
        } else {
            None
        };
        if current.as_deref().is_some_and(|x| !matches!(x, "A" | "B")) {
            return Err(err("invalid_legacy_state", "旧账号状态无效"));
        }
        let mut done = vec![];
        let res = (|| {
            for id in ids {
                let slot = self.slot(id);
                fs::create_dir(&slot).map_err(io)?;
                done.push(slot.clone());
                self.copy_tree(&legacy.join("accounts").join(id), &slot.join("profile"))?;
                self.write_manifest(&slot, &tree_manifest(&slot.join("profile"))?, "legacy")?;
            }
            let (_, legacy_anchor) = self.observe_legacy_switcher().unwrap_or((false, None));
            self.save_state(current.as_deref(), None, legacy_anchor.as_ref())
        })();
        if res.is_err() {
            for p in done {
                let _ = fs::remove_dir_all(p);
            }
        }
        res?;
        self.status()
    }
    pub fn switch(
        &mut self,
        target: &str,
        config: &Config,
        acknowledge_unverified: bool,
    ) -> Result<SwitchResult> {
        Self::valid(target)?;
        let _guard = self.storage.lock("operation", None)?;
        self.storage.initialize()?;
        if self.storage.paths.journal().exists() {
            return Err(err("recovery_required", "先恢复未完成的账号切换"));
        }
        let current = self.state()?;
        self.check_external_ownership(current.as_deref())?;
        // An already selected, initialized slot is a read-only idempotent
        // request.  In particular it must not start requiring a presently
        // observable Claude version merely to report that nothing changed.
        if current.as_deref() == Some(target) {
            return Ok(SwitchResult {
                current: target.into(),
                copied: vec![],
                login_verified: false,
            });
        }
        let version = self
            .os
            .claude_version()?
            .ok_or_else(|| err("claude_missing", "未找到可确认版本的 Claude"))?;
        if !config
            .verified_claude_versions
            .iter()
            .any(|x| x == &version)
            && !acknowledge_unverified
        {
            return Err(err(
                "account_compatibility_unverified",
                "首次使用此 Claude 版本切换资料，需确认兼容性边界",
            ));
        }
        self.os.preflight()?;
        let mut copies = vec![];
        // A missing target is deliberately a fresh profile.  This is how the
        // upstream switcher enters B for the first time; it is not an error
        // after the live A directory has been safely archived.
        if self.profile(target).is_dir() {
            self.validate(target)?;
        }
        self.os.preflight()?;
        self.os.quit_claude()?;
        if self.os.claude_running()? {
            return Err(err("claude_restarted", "Claude 尚在运行，未准备资料"));
        }
        let token = Uuid::new_v4().simple().to_string();
        let work = self
            .storage
            .paths
            .accounts()
            .join(format!(".transaction-{token}"));
        fs::create_dir(&work).map_err(io)?;
        let state_existed = self.state_path().exists();
        let active_before = fingerprint_path(&self.storage.paths.active())?;
        let slot_before = current
            .as_deref()
            .map(|id| fingerprint_path(&self.slot(id)))
            .transpose()?
            .flatten();
        let mut j = json!({"schema":3,"token":token,"phase":"preparing","target":target,
            "previous":{"schema":1,"current":current},"state_existed":state_existed,"workspace":work,
            "records":{"active_before":active_before,"slot_before":slot_before,"slot":current}});
        self.storage
            .atomic_json(&self.storage.paths.journal(), &j)?;
        let res = (|| {
            self.os.checkpoint("prepared")?;
            let next = work.join("next");
            if self.profile(target).is_dir() {
                copies.push(self.copy_tree(&self.profile(target), &next)?);
            } else if current.is_none() && target == "A" && self.storage.paths.active().exists() {
                // Upstream's first-save/same-target case restores A into DATA
                // before opening Claude, while retaining a separately staged A.
                copies.push(self.copy_tree(&self.storage.paths.active(), &next)?);
            } else {
                fs::create_dir(&next).map_err(io)?;
                fs::set_permissions(&next, fs::Permissions::from_mode(0o700)).map_err(io)?;
            }
            // Copy only after the confirmed quit.  For first use this becomes
            // A's snapshot even if the requested destination is B.
            if self.storage.paths.active().exists() {
                copies
                    .push(self.copy_tree(&self.storage.paths.active(), &work.join("old-profile"))?);
            }
            j["phase"] = json!("publishing");
            self.storage
                .atomic_json(&self.storage.paths.journal(), &j)?;
            self.check_external_ownership(current.as_deref())?;
            if self.os.claude_running()?
                || fingerprint_path(&self.storage.paths.active())? != active_before
            {
                return Err(err("external_change", "提交前活动资料发生变化，未覆盖"));
            }
            if let Some(id) = current.as_deref() {
                if fingerprint_path(&self.slot(id))? != slot_before {
                    return Err(err("external_change", "提交前账号存档发生变化，未覆盖"));
                }
            }
            if self.storage.paths.active().exists() {
                fs::rename(self.storage.paths.active(), work.join("previous-active")).map_err(io)?
            }
            self.os.checkpoint("old_moved")?;
            fs::rename(&next, self.storage.paths.active()).map_err(io)?;
            self.os.checkpoint("installed")?;
            j["phase"] = json!("installed");
            self.storage
                .atomic_json(&self.storage.paths.journal(), &j)?;
            self.os.preflight()?;
            if self.os.claude_running()? {
                return Err(err("claude_restarted", "启动前 Claude 重新出现"));
            }
            j["phase"] = json!("launching");
            self.storage
                .atomic_json(&self.storage.paths.journal(), &j)?;
            self.os.launch_claude()?;
            self.os.checkpoint("launched")?;
            // Archive old DATA only after controlled launch.  The explicit
            // previous-slot directory makes this reversible after a crash.
            if work.join("old-profile").exists() {
                let archive = current.as_deref().unwrap_or("A");
                // Persist archive ownership before either directory rename so
                // recovery can restore a slot interrupted mid-replacement.
                j["records"]["archive"] = json!(archive);
                self.storage
                    .atomic_json(&self.storage.paths.journal(), &j)?;
                self.replace_slot_in_transaction(
                    archive,
                    &work.join("old-profile"),
                    &work,
                    &version,
                )?;
                j["phase"] = json!("archived");
                self.storage
                    .atomic_json(&self.storage.paths.journal(), &j)?;
                self.os.checkpoint("archived")?;
            }
            j["commit_backups_v1"] = self.commit_backup_evidence(&work)?;
            self.storage.atomic_json(&self.storage.paths.journal(), &j)?;
            self.os.checkpoint("commit_prepared")?;
            if !self.state_matches(current.as_deref(), state_existed)? {
                return Err(err("external_change", "启动期间账号标记被外部修改"));
            }
            let (_, latest_anchor) = self.observe_legacy_switcher()?;
            self.save_state(Some(target), Some(&token), latest_anchor.as_ref())?;
            self.os.checkpoint("state_saved")?;
            j["phase"] = json!("committed");
            self.storage
                .atomic_json(&self.storage.paths.journal(), &j)?;
            self.os.checkpoint("committed")?;
            fs::remove_dir_all(&work).map_err(io)?;
            fs::remove_file(self.storage.paths.journal()).map_err(io)
        })();
        if let Err(e) = res {
            if self.os.claude_running().unwrap_or(false) {
                let _ = self.os.quit_claude();
            }
            let _ = self.recover_locked();
            return Err(e);
        }
        Ok(SwitchResult {
            current: target.into(),
            copied: copies,
            login_verified: false,
        })
    }
    pub fn recover(&mut self) -> Result<()> {
        let _guard = self.storage.lock("operation", Some("account"))?;
        self.recover_locked()
    }
    fn recover_locked(&mut self) -> Result<()> {
        let p = self.storage.paths.journal();
        if !p.exists() {
            return Ok(());
        }
        if self.os.claude_running()? {
            return Err(err(
                "claude_still_running",
                "先退出 Claude，再恢复未完成事务",
            ));
        }
        let j = self.storage.read_json(&p, json!({}))?;
        let schema = j["schema"]
            .as_u64()
            .ok_or_else(|| err("invalid_journal", "恢复记录格式错误"))?;
        if !matches!(schema, 1..=3) {
            return Err(err("invalid_journal", "恢复记录版本不受支持"));
        }
        let token = j["token"]
            .as_str()
            .filter(|x| x.len() == 32 && x.bytes().all(|x| x.is_ascii_hexdigit()))
            .ok_or_else(|| err("invalid_journal", "恢复标识无效"))?;
        if schema < 3 {
            return self.recover_legacy(&j, token, &p);
        }
        // Early Rust schema-3 records predate state_existed/records.  Keep
        // their bounded, token-derived recovery path readable so an upgrade
        // does not strand an interrupted older transaction.
        if j.get("state_existed").is_none() {
            return self.recover_schema3_legacy(&j, token, &p);
        }
        let work = self
            .storage
            .paths
            .accounts()
            .join(format!(".transaction-{token}"));
        self.storage.guarded(&work)?;
        if j.get("workspace").and_then(Value::as_str) != Some(work.to_string_lossy().as_ref())
            || !matches!(
                j.get("phase").and_then(Value::as_str),
                Some(
                    "preparing"
                        | "publishing"
                        | "installed"
                        | "launching"
                        | "archived"
                        | "committed"
                )
            )
            || !matches!(j.get("target").and_then(Value::as_str), Some("A" | "B"))
        {
            return Err(err("invalid_journal", "恢复记录路径或阶段无效"));
        }
        let previous = j.pointer("/previous/current").and_then(Value::as_str);
        if previous.is_some_and(|x| !matches!(x, "A" | "B")) {
            return Err(err("invalid_journal", "恢复账号无效"));
        }
        let state_existed = j
            .get("state_existed")
            .and_then(Value::as_bool)
            .ok_or_else(|| err("invalid_journal", "恢复状态记录不完整"))?;
        if self.recover_published_marker(&j, token, &work, &p)? {
            return Ok(());
        }
        if !self.state_matches(previous, state_existed)? {
            return Err(err("recovery_conflict", "账号标记发生外部变化，未覆盖"));
        }
        let old_slot = work.join("previous-slot");
        if old_slot.exists() {
            let archive = j
                .pointer("/records/archive")
                .and_then(Value::as_str)
                .ok_or_else(|| err("invalid_journal", "恢复存档记录不完整"))?;
            Self::valid(archive)?;
            let slot = self.slot(archive);
            if slot.exists() {
                let saved = self
                    .storage
                    .paths
                    .accounts()
                    .join(format!("recovered-slot-{token}"));
                if saved.exists() {
                    return Err(err("recovery_conflict", "恢复保存目录已存在"));
                }
                fs::rename(&slot, saved).map_err(io)?;
            }
            fs::rename(old_slot, slot).map_err(io)?;
        }
        let old = work.join("previous-active");
        if old.exists() {
            if self.storage.paths.active().exists() {
                let save = self
                    .storage
                    .paths
                    .accounts()
                    .join(format!("recovered-{token}"));
                if save.exists() {
                    return Err(err("recovery_conflict", "恢复保存目录已存在"));
                }
                fs::rename(self.storage.paths.active(), save).map_err(io)?;
            }
            fs::rename(old, self.storage.paths.active()).map_err(io)?;
        }
        self.restore_state(previous, state_existed)?;
        if work.exists() {
            fs::remove_dir_all(work).map_err(io)?;
        }
        fs::remove_file(p).map_err(io)
    }
    fn state_matches(&self, current: Option<&str>, existed: bool) -> Result<bool> {
        Ok(self.state_path().exists() == existed && self.state()?.as_deref() == current)
    }
    fn restore_state(&self, current: Option<&str>, existed: bool) -> Result<()> {
        if existed {
            let (_, latest_anchor) = self.observe_legacy_switcher().unwrap_or((false, None));
            self.save_state(current, None, latest_anchor.as_ref())
        } else if self.state_path().exists() {
            fs::remove_file(self.state_path()).map_err(io)
        } else {
            Ok(())
        }
    }
    fn recover_legacy(&mut self, j: &Value, token: &str, journal: &Path) -> Result<()> {
        let parent = self
            .storage
            .paths
            .active()
            .parent()
            .ok_or_else(|| err("invalid_journal", "活动资料目录缺少父目录"))?
            .to_path_buf();
        let stage = parent.join(format!(".claude-watch-stage-{token}"));
        let old = parent.join(format!(".claude-watch-old-{token}"));
        for (key, expected) in [("stage", &stage), ("old", &old)] {
            if j.get(key).and_then(Value::as_str) != Some(expected.to_string_lossy().as_ref()) {
                return Err(err("invalid_journal", "旧恢复路径不属于此次事务"));
            }
            self.storage.guarded(expected)?;
        }
        let previous = j.pointer("/previous/current").and_then(Value::as_str);
        if previous.is_some_and(|x| !matches!(x, "A" | "B")) {
            return Err(err("invalid_journal", "恢复账号无效"));
        }
        if j.get("phase").and_then(Value::as_str) != Some("committed") && old.exists() {
            if self.storage.paths.active().exists() {
                let saved = self
                    .storage
                    .paths
                    .accounts()
                    .join(format!("recovered-{token}"));
                if saved.exists() {
                    return Err(err("recovery_conflict", "恢复保存目录已存在"));
                }
                fs::rename(self.storage.paths.active(), saved).map_err(io)?;
            }
            fs::rename(&old, self.storage.paths.active()).map_err(io)?;
            let (_, latest_anchor) = self.observe_legacy_switcher().unwrap_or((false, None));
            self.save_state(previous, None, latest_anchor.as_ref())?;
        }
        for owned in [&stage, &old] {
            if owned.exists() {
                fs::remove_dir_all(owned).map_err(io)?;
            }
        }
        fs::remove_file(journal).map_err(io)
    }
    fn recover_schema3_legacy(&mut self, j: &Value, token: &str, journal: &Path) -> Result<()> {
        let work = self
            .storage
            .paths
            .accounts()
            .join(format!(".transaction-{token}"));
        self.storage.guarded(&work)?;
        if j.get("phase").and_then(Value::as_str) == Some("committed") {
            if work.exists() {
                fs::remove_dir_all(work).map_err(io)?;
            }
            return fs::remove_file(journal).map_err(io);
        }
        let previous = j.pointer("/previous/current").and_then(Value::as_str);
        if previous.is_some_and(|x| !matches!(x, "A" | "B")) {
            return Err(err("invalid_journal", "恢复账号无效"));
        }
        let old = work.join("previous-active");
        if old.exists() {
            if self.storage.paths.active().exists() {
                let save = self
                    .storage
                    .paths
                    .accounts()
                    .join(format!("recovered-{token}"));
                if save.exists() {
                    return Err(err("recovery_conflict", "恢复保存目录已存在"));
                }
                fs::rename(self.storage.paths.active(), save).map_err(io)?;
            }
            fs::rename(old, self.storage.paths.active()).map_err(io)?;
        }
        let (_, latest_anchor) = self.observe_legacy_switcher().unwrap_or((false, None));
        self.save_state(previous, None, latest_anchor.as_ref())?;
        if work.exists() {
            fs::remove_dir_all(work).map_err(io)?;
        }
        fs::remove_file(journal).map_err(io)
    }
    fn replace_slot_in_transaction(
        &mut self,
        id: &str,
        profile: &Path,
        work: &Path,
        version: &str,
    ) -> Result<()> {
        let stage = work.join("next-slot");
        fs::create_dir(&stage).map_err(io)?;
        fs::rename(profile, stage.join("profile")).map_err(io)?;
        let m = tree_manifest(&stage.join("profile"))?;
        self.write_manifest(&stage, &m, version)?;
        let slot = self.slot(id);
        if slot.exists() {
            fs::rename(&slot, work.join("previous-slot")).map_err(io)?;
        }
        fs::rename(stage, slot).map_err(io)
    }
    fn validate(&self, id: &str) -> Result<()> {
        let v = self
            .storage
            .read_json(&self.slot(id).join("manifest.json"), json!({}))?;
        if v.get("files") != Some(&tree_manifest(&self.profile(id))?) {
            Err(err("snapshot_corrupt", "账号存档校验失败"))
        } else {
            Ok(())
        }
    }
    fn write_manifest(&self, slot: &Path, files: &Value, source: &str) -> Result<()> {
        let v = json!({"schema":1,"files":files,"source":source});
        let raw = serde_json::to_vec(&v).map_err(|_| err("invalid_state", "账号清单无法序列化"))?;
        if raw.len() + 1 > MANIFEST_LIMIT {
            return Err(err(
                "oversize_account_manifest",
                "账号文件清单过大，未替换活动资料",
            ));
        }
        self.storage.atomic_json(&slot.join("manifest.json"), &v)
    }
    fn copy_tree(&mut self, source: &Path, target: &Path) -> Result<CopyMetrics> {
        let before = tree_manifest(source)?;
        if target.exists() {
            return Err(err("copy_target_exists", "复制目标已存在"));
        }
        let mut m = CopyMetrics::default();
        copy_dir(source, target, &mut self.os, &mut m)?;
        if tree_manifest(source)? != before || tree_manifest(target)? != before {
            return Err(err(
                "copy_verification_failed",
                "复制校验失败或源数据发生变化",
            ));
        }
        m.strategy = if m.cloned_files > 0 && m.copied_files > 0 {
            "mixed"
        } else if m.cloned_files > 0 {
            "clone"
        } else {
            "copy"
        }
        .into();
        Ok(m)
    }
}
fn fingerprint_path(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let value = tree_manifest(path)?;
    let raw = serde_json::to_vec(&value).map_err(|_| err("invalid_state", "清单无法编码"))?;
    Ok(Some(hex_digest(sha2::Sha256::digest(raw).as_slice())))
}
fn tree_manifest(root: &Path) -> Result<Value> {
    let mut out = BTreeMap::new();
    walk(root, root, &mut out)?;
    serde_json::to_value(out).map_err(|_| err("invalid_state", "清单无法编码"))
}
fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Value>) -> Result<()> {
    let meta = fs::symlink_metadata(dir).map_err(io)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(err("unsafe_path", "账号数据含链接或非目录"));
    }
    let mut es = fs::read_dir(dir)
        .map_err(io)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(io)?;
    es.sort_by_key(|x| x.file_name());
    for e in es {
        let n = e.file_name();
        if TRANSIENT.contains(&n.to_string_lossy().as_ref()) {
            continue;
        }
        let p = e.path();
        let m = fs::symlink_metadata(&p).map_err(io)?;
        if m.file_type().is_symlink() {
            return Err(err(
                "unsupported_account_entry",
                "账号数据含符号链接；停止复制",
            ));
        }
        if m.is_dir() {
            walk(root, &p, out)?
        } else if m.is_file() {
            let mut f = fs::File::open(&p).map_err(io)?;
            let mut h = sha2::Sha256::new();
            let mut b = [0; 65536];
            loop {
                let n = f.read(&mut b).map_err(io)?;
                if n == 0 {
                    break;
                }
                h.update(&b[..n]);
            }
            out.insert(
                p.strip_prefix(root)
                    .map_err(|_| err("unsafe_path", "复制路径越界"))?
                    .to_string_lossy()
                    .into_owned(),
                json!({"size":m.len(),"sha256":hex_digest(h.finalize().as_slice())}),
            );
        } else {
            return Err(err(
                "unsupported_account_entry",
                "账号数据含特殊文件；停止复制",
            ));
        }
    }
    Ok(())
}
fn copy_dir<O: AccountOs>(s: &Path, t: &Path, os: &mut O, m: &mut CopyMetrics) -> Result<()> {
    let sm = fs::symlink_metadata(s).map_err(io)?;
    if sm.file_type().is_symlink() || !sm.is_dir() {
        return Err(err("unsupported_account_entry", "复制源不是普通目录"));
    }
    fs::create_dir(t).map_err(io)?;
    fs::set_permissions(t, fs::Permissions::from_mode(0o700)).map_err(io)?;
    for e in fs::read_dir(s).map_err(io)? {
        let e = e.map_err(io)?;
        let n = e.file_name();
        if TRANSIENT.contains(&n.to_string_lossy().as_ref()) {
            continue;
        }
        let a = e.path();
        let b = t.join(&n);
        let x = fs::symlink_metadata(&a).map_err(io)?;
        if x.file_type().is_symlink() {
            return Err(err(
                "unsupported_account_entry",
                "账号数据含符号链接；停止复制",
            ));
        }
        if x.is_dir() {
            copy_dir(&a, &b, os, m)?
        } else if x.is_file() {
            if os.clone_file(&a, &b)? {
                m.cloned_files += 1
            } else {
                let mut r = fs::File::open(&a).map_err(io)?;
                let mut w = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&b)
                    .map_err(io)?;
                std::io::copy(&mut r, &mut w).map_err(io)?;
                w.flush().map_err(io)?;
                m.copied_files += 1
            }
            fs::set_permissions(
                b,
                fs::Permissions::from_mode(0o600 | (x.permissions().mode() & 0o100)),
            )
            .map_err(io)?
        } else {
            return Err(err(
                "unsupported_account_entry",
                "账号数据含特殊文件；停止复制",
            ));
        }
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 15) as usize] as char);
    }
    text
}
