//! A published account marker is the transaction's commit point. The journal
//! may lag behind it; only this transaction's exact marker can roll forward.
//! No application is launched here and no active profile is rewritten.
use super::*;

fn recorded_hash(value: Option<&Value>) -> Result<Option<String>> {
    match value {
        Some(Value::Null) => Ok(None),
        Some(Value::String(hash)) if hash.len() == 64
            && hash.bytes().all(|b| b.is_ascii_hexdigit()) => Ok(Some(hash.clone())),
        _ => Err(err("invalid_journal", "提交备份指纹缺失或无效")),
    }
}

impl<O: AccountOs> AccountStore<O> {
    pub(super) fn commit_backup_evidence(&self, work: &Path) -> Result<Value> {
        let active = work.join("previous-active");
        let slot = work.join("previous-slot");
        self.storage.guarded(&active)?;
        self.storage.guarded(&slot)?;
        Ok(json!({"previous_active":fingerprint_path(&active)?,
            "previous_slot":fingerprint_path(&slot)?}))
    }

    /// Called under the operation lock after the journal path/token/shape and
    /// stopped application were checked by recover_locked. Return false only
    /// for an uncommitted transaction whose own marker has not been published.
    pub(super) fn recover_published_marker(
        &mut self, journal: &Value, token: &str, work: &Path, journal_path: &Path,
    ) -> Result<bool> {
        let state = self.storage.read_json(&self.state_path(), Value::Null)?;
        let committed = journal["phase"] == "committed";
        if state["transaction_id"].as_str() != Some(token) {
            if committed { return Err(err("recovery_conflict", "已提交账号标记发生外部变化")); }
            return Ok(false);
        }
        let state_matches_marker = |s: &Value| {
            let obj = match s.as_object() {
                Some(o) => o,
                None => return false,
            };
            if s.get("schema") != Some(&json!(1))
                || s.get("current") != journal.get("target")
                || s.get("transaction_id").and_then(Value::as_str) != Some(token)
            {
                return false;
            }
            for k in obj.keys() {
                if !matches!(
                    k.as_str(),
                    "schema"
                        | "current"
                        | "transaction_id"
                        | "ownership_epoch"
                        | "active_dir_ino"
                        | "legacy_current_observed"
                        | "legacy_current_mtime_ns"
                        | "legacy_current_ino"
                ) {
                    return false;
                }
            }
            true
        };
        if !state_matches_marker(&state) {
            return Err(err("recovery_conflict", "事务标识相同但账号标记不一致，未清理资料"));
        }
        if !committed {
            // Marker publication follows successful launch and completed
            // archival. An earlier phase cannot use a token to skip rollback.
            if !matches!(journal["phase"].as_str(), Some("launching" | "archived")) {
                return Err(err("recovery_conflict", "账号标记与未完成事务阶段不一致"));
            }
            self.storage.guarded(work)?;
            self.storage.guarded(&self.storage.paths.active())?;
            if !fs::symlink_metadata(work).map_err(io)?.is_dir()
                || !fs::symlink_metadata(self.storage.paths.active()).map_err(io)?.is_dir()
            {
                return Err(err("recovery_conflict", "提交资料目录缺失或已被替换"));
            }
            for name in ["next", "next-slot", "old-profile"] {
                let path = work.join(name);
                self.storage.guarded(&path)?;
                if path.exists() { return Err(err("recovery_conflict", "资料发布尚未完成，未清理备份")); }
            }
            let actual = self.commit_backup_evidence(work)?;
            let before = recorded_hash(journal.pointer("/records/active_before"))?;
            if recorded_hash(actual.get("previous_active"))? != before {
                return Err(err("recovery_conflict", "原活动资料备份发生变化，未清理"));
            }
            // New writers snapshot both backups before publishing the marker.
            // Legacy schema-3 journals remain recoverable using their original
            // slot fingerprint; unknown legacy backup ownership stays a conflict.
            let slot_before = if let Some(evidence) = journal.get("commit_backups_v1") {
                if evidence != &actual {
                    return Err(err("recovery_conflict", "提交备份与已记录指纹不一致"));
                }
                recorded_hash(evidence.get("previous_slot"))?
            } else if journal["phase"] == "archived" {
                recorded_hash(journal.pointer("/records/slot_before"))?
            } else { None };
            if recorded_hash(actual.get("previous_slot"))? != slot_before {
                return Err(err("recovery_conflict", "原账号存档备份发生变化，未清理"));
            }
            if journal["phase"] == "archived"
                && journal.pointer("/previous/current").and_then(Value::as_str).is_some()
                && slot_before != recorded_hash(journal.pointer("/records/slot_before"))?
            {
                return Err(err("recovery_conflict", "原账号存档与事务开始时的指纹不一致"));
            }
            if let Some(before) = before {
                let archive = journal.pointer("/records/archive").and_then(Value::as_str)
                    .ok_or_else(|| err("invalid_journal", "提交存档归属缺失"))?;
                if journal["phase"] != "archived"
                    || archive != journal.pointer("/previous/current").and_then(Value::as_str).unwrap_or("A")
                { return Err(err("recovery_conflict", "原活动资料尚未确认归档")); }
                Self::valid(archive)?;
                self.storage.guarded(&self.profile(archive))?;
                self.validate(archive)?;
                if fingerprint_path(&self.profile(archive))?.as_deref() != Some(before.as_str()) {
                    return Err(err("recovery_conflict", "存档与原活动资料不一致，保留备份"));
                }
            } else if journal["phase"] != "launching" || journal.pointer("/records/archive").is_some() {
                return Err(err("invalid_journal", "空初始资料的提交阶段不一致"));
            }
            if self.os.claude_running()? {
                return Err(err("claude_still_running", "恢复期间应用重新启动，未清理备份"));
            }
            if !state_matches_marker(&self.storage.read_json(&self.state_path(), Value::Null)?)
                || self.storage.read_json(journal_path, Value::Null)? != *journal
            { return Err(err("recovery_conflict", "恢复期间账号标记或事务记录发生变化")); }
            let mut completed = journal.clone();
            completed["phase"] = json!("committed");
            // Persist before deleting any backup. Interrupted cleanup can then
            // retry the committed path without requiring already deleted files.
            self.storage.atomic_json(journal_path, &completed)?;
            self.os.checkpoint("recovery_committed")?;
        }
        if !state_matches_marker(&self.storage.read_json(&self.state_path(), Value::Null)?) {
            return Err(err("recovery_conflict", "清理前账号标记发生外部变化"));
        }
        self.storage.guarded(work)?;
        if work.exists() { fs::remove_dir_all(work).map_err(io)?; }
        fs::remove_file(journal_path).map_err(io)?;
        Ok(true)
    }
}
