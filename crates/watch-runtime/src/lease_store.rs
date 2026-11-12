//! Process-identity leases and restart-safe observation history.
//! These records classify observations; they never authorize a desktop launch.
use crate::storage::StateStore;
use claude_watch_core::{
    error::{CoreError, Result},
    processes::{self, Identity, Kind, Lease, Provider, Target},
    session::Desktop,
};
use serde_json::json;
use std::{collections::BTreeMap, fs, path::PathBuf};

pub struct LeaseStore {
    pub storage: StateStore,
}
impl LeaseStore {
    /// The lease record names the supervised service, parsed back by the
    /// lease store's provider table.
    pub fn save_desktop(
        &self,
        desktop: &Desktop,
        stamp: &str,
        now: f64,
        provider: Provider,
    ) -> Result<()> {
        if stamp.contains(['|', '\n', '\r']) || stamp.is_empty() {
            return Err(CoreError::new(
                "desktop_identity_unavailable",
                "主进程启动时间未能确认",
            ));
        }
        let name = match provider {
            Provider::Claude => "claude",
            Provider::Codex => "codex",
            Provider::Chatgpt => "chatgpt",
            Provider::Openai => "openai",
        };
        let path = self
            .storage
            .paths
            .watch()
            .join(format!("state/sessions/rust-{}.session", desktop.pid));
        self.storage.atomic_bytes(
            &path,
            format!(
                "desktop|{name}|{}|{}|0|-|{}\n",
                desktop.pid,
                stamp,
                now.floor()
            )
            .as_bytes(),
            0o600,
        )
    }

    pub fn save_cli(&self, provider: Provider, owner: &Identity, created: f64) -> Result<CliLease> {
        let id = self.save(
            &Lease {
                provider,
                root: owner.clone(),
                owner: Some(owner.clone()),
                cli: true,
            },
            created,
        )?;
        Ok(CliLease {
            storage: self.storage.clone(),
            id,
            owner: owner.clone(),
            provider,
            active: true,
        })
    }
    fn remove_cli(&self, id: &str, owner: &Identity, provider: Provider) -> Result<()> {
        if id.len() != 32 || !id.bytes().all(|v| v.is_ascii_hexdigit()) {
            return Err(CoreError::new("invalid_lease", "观察记录编号无效"));
        }
        let _lock = self.storage.lock("leases", None)?;
        let path = self.directory().join(format!("{id}.json"));
        let Some(before) = self.storage.read_bytes(&path, 16384)? else {
            return Ok(());
        };
        let value = crate::storage::strict_json(&before)?;
        let lease: Lease = serde_json::from_value(value["lease"].clone())
            .map_err(|_| CoreError::new("invalid_lease", "观察记录损坏，未删除"))?;
        if lease.provider != provider
            || !lease.cli
            || !lease.root.same_process(owner)
            || !lease.owner.as_ref().is_some_and(|p| p.same_process(owner))
            || self.storage.read_bytes(&path, 16384)?.as_ref() != Some(&before)
        {
            return Err(CoreError::new(
                "lease_cleanup_conflict",
                "观察记录已被替换，未删除其他会话",
            ));
        }
        fs::remove_file(path)
            .map_err(|_| CoreError::new("lease_cleanup_failed", "本次观察记录无法清理"))
    }
    pub fn revoke_all(&self) -> Result<()> {
        let _lock = self.storage.lock("leases", None)?;
        let directory = self.directory();
        self.storage.guarded(&directory)?;
        let entries = match fs::read_dir(&directory) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(CoreError::new("lease_read_failed", "会话目录不可读取")),
        };
        for entry in entries {
            let path = entry
                .map_err(|_| CoreError::new("lease_read_failed", "会话记录不可读取"))?
                .path();
            if matches!(
                path.extension().and_then(|v| v.to_str()),
                Some("session" | "json")
            ) {
                self.storage.guarded(&path)?;
                if fs::symlink_metadata(&path)
                    .is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
                {
                    fs::remove_file(&path)
                        .map_err(|_| CoreError::new("lease_revoke_failed", "会话关联无法撤销"))?;
                }
            }
        }
        Ok(())
    }
    fn directory(&self) -> PathBuf {
        self.storage.paths.watch().join("state/sessions")
    }
    pub fn save(&self, lease: &Lease, created: f64) -> Result<String> {
        if !lease.root.valid()
            || !created.is_finite()
            || created < 0.0
            || (lease.cli && !lease.owner.as_ref().is_some_and(Identity::valid))
        {
            return Err(CoreError::new("invalid_lease", "会话身份无效"));
        }
        let id = uuid::Uuid::new_v4().simple().to_string();
        self.storage.atomic_json(
            &self.directory().join(format!("{id}.json")),
            &json!({"schema":1,"lease":lease,"created_at":created}),
        )?;
        Ok(id)
    }
    pub fn load(
        &self,
        inventory: &BTreeMap<u32, Identity>,
        uid: u32,
        complete: bool,
    ) -> Result<Vec<Lease>> {
        let directory = self.directory();
        self.storage.guarded(&directory)?;
        let entries = match fs::read_dir(&directory) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(_) => return Err(CoreError::new("lease_read_failed", "会话目录不可读取")),
        };
        let mut leases = Vec::new();
        for (index, entry) in entries.enumerate() {
            if index >= 4096 {
                return Err(CoreError::new("lease_limit", "会话记录超过上限"));
            }
            let path = entry
                .map_err(|_| CoreError::new("lease_read_failed", "会话目录项不可读取"))?
                .path();
            let extension = path.extension().and_then(|v| v.to_str()).unwrap_or("");
            if !matches!(extension, "json" | "session") {
                continue;
            }
            let bytes = self.storage.read_bytes(&path, 16384)?.unwrap_or_default();
            let lease = if extension == "json" {
                let value = crate::storage::strict_json(&bytes)?;
                if value["schema"] != 1 {
                    return Err(CoreError::new("invalid_lease", "会话记录版本无效"));
                }
                serde_json::from_value::<Lease>(value["lease"].clone()).ok()
            } else {
                std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(|text| legacy_lease(text, inventory, uid))
            };
            if let Some(lease) = lease.filter(|v| v.valid(inventory, uid)) {
                leases.push(lease);
            } else if complete {
                // Delete only the exact stale record read this round; preserve a
                // concurrent writer's replacement and all partially observed leases.
                if self.storage.read_bytes(&path, 16384)?.as_deref() == Some(bytes.as_slice()) {
                    fs::remove_file(&path).map_err(|_| {
                        CoreError::new("lease_cleanup_failed", "过期会话记录无法清理")
                    })?;
                }
            }
        }
        Ok(leases)
    }
    pub fn launcher_targets(leases: &[Lease]) -> Vec<Target> {
        leases
            .iter()
            .filter(|v| v.cli)
            .map(|lease| Target {
                identity: lease.root.clone(),
                kind: match lease.provider {
                    Provider::Claude => Kind::ClaudeLauncher,
                    Provider::Codex => Kind::CodexLauncher,
                    Provider::Chatgpt => Kind::ChatgptLauncher,
                    Provider::Openai => Kind::OpenaiLauncher,
                },
            })
            .collect()
    }
    pub fn tracked(&self) -> Result<Vec<Target>> {
        let value = self.storage.read_json(
            &self.storage.paths.watch().join("state/tracked-rust.json"),
            json!({"schema":1,"targets":[]}),
        )?;
        if value["schema"] != 1 {
            return Err(CoreError::new("invalid_tracked", "进程历史版本无效"));
        }
        let targets: Vec<Target> = serde_json::from_value(value["targets"].clone())
            .map_err(|_| CoreError::new("invalid_tracked", "进程历史格式无效"))?;
        if targets.len() > 65536 || targets.iter().any(|v| !v.identity.valid()) {
            return Err(CoreError::new("invalid_tracked", "进程历史身份无效"));
        }
        Ok(targets)
    }
    pub fn save_tracked(&self, targets: &[Target], complete: bool) -> Result<()> {
        if complete {
            self.storage.atomic_json(
                &self.storage.paths.watch().join("state/tracked-rust.json"),
                &json!({"schema":1,"targets":targets}),
            )?;
        }
        Ok(())
    }
}

pub struct CliLease {
    storage: StateStore,
    id: String,
    owner: Identity,
    provider: Provider,
    active: bool,
}
impl CliLease {
    pub fn clear(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        LeaseStore {
            storage: self.storage.clone(),
        }
        .remove_cli(&self.id, &self.owner, self.provider)
    }
}
impl Drop for CliLease {
    fn drop(&mut self) {
        let _ = self.clear();
    }
}
fn legacy_lease(text: &str, inventory: &BTreeMap<u32, Identity>, uid: u32) -> Option<Lease> {
    let mut fields = text.trim().split('|').collect::<Vec<_>>();
    if fields.len() == 6 {
        fields.insert(1, "claude");
    }
    if fields.len() != 7 || !matches!(fields[0], "cli" | "desktop") {
        return None;
    }
    let provider = match fields[1] {
        "claude" => Provider::Claude,
        "codex" => Provider::Codex,
        "chatgpt" => Provider::Chatgpt,
        "openai" => Provider::Openai,
        _ => return None,
    };
    let lookup = |pid: &str, stamp: &str| -> Option<Identity> {
        let current = inventory.get(&pid.parse::<u32>().ok()?)?;
        (current.uid == uid
            && processes::normalized_stamp(&current.start_stamp)
                == processes::normalized_stamp(stamp))
        .then(|| current.clone())
    };
    let root = lookup(fields[2], fields[3])?;
    let cli = fields[0] == "cli";
    let owner = if cli {
        Some(lookup(fields[4], fields[5])?)
    } else {
        None
    };
    Some(Lease {
        provider,
        root,
        owner,
        cli,
    })
}
