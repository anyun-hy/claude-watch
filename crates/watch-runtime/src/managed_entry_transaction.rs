//! Same-directory staging and compare-before/after-rename for selected entry
//! files. A displaced object is retained until every replacement commits.
use claude_watch_core::error::{CoreError, Result};
use claude_watch_system::{anchored_files::Dir, effective_uid};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, Metadata, Permissions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

const MAX_BYTES: u64 = 128 * 1024 * 1024;
const MAX_NODES: usize = 32;
const SLOT: &str = "object";

pub(crate) fn err(code: &str, detail: impl AsRef<str>) -> CoreError {
    CoreError::new(code, detail.as_ref())
}

fn io_at(path: &Path, e: io::Error) -> CoreError {
    err(
        "entry_path_unavailable",
        format!("入口路径不可安全访问：{} ({e})", path.display()),
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Stamp {
    dev: u64,
    ino: u64,
    uid: u32,
    pub(crate) mode: u32,
    directory: bool,
    digest: String,
}

fn stamp(m: &Metadata, digest: String) -> Stamp {
    Stamp {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        mode: m.mode() & 0o7777,
        directory: m.is_dir(),
        digest,
    }
}

fn same_inode(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

fn read_file(file: &mut File, before: &Metadata, limit: u64) -> io::Result<Vec<u8>> {
    if !before.is_file()
        || before.uid() != effective_uid()
        || before.nlink() != 1
        || before.len() > limit
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || after.len() != before.len()
        || !same_inode(before, &after)
        || after.mode() != before.mode()
        || after.nlink() != before.nlink()
        || after.uid() != before.uid()
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
        || after.ctime() != before.ctime()
        || after.ctime_nsec() != before.ctime_nsec()
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(bytes)
}

fn inspect(dir: &Dir, name: &str, remaining: &mut usize) -> io::Result<Option<Stamp>> {
    let mut file = match dir.read(name) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    *remaining = remaining.checked_sub(1).ok_or(io::ErrorKind::InvalidData)?;
    let meta = file.metadata()?;
    if meta.uid() != effective_uid() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let digest = if meta.is_dir() {
        let sub = dir.child(name)?;
        if !same_inode(&meta, &sub.metadata()?) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let names = sub.names(*remaining)?;
        let mut values = Vec::with_capacity(names.len());
        for child in &names {
            let value = inspect(&sub, child, remaining)?.ok_or(io::ErrorKind::NotFound)?;
            values.push((child, value));
        }
        if sub.names(MAX_NODES)? != names {
            return Err(io::ErrorKind::InvalidData.into());
        }
        crate::storage::sha256(&serde_json::to_vec(&values)?)
    } else {
        crate::storage::sha256(&read_file(&mut file, &meta, MAX_BYTES)?)
    };
    if !same_inode(&meta, &dir.read(name)?.metadata()?) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Some(stamp(&meta, digest)))
}

pub(crate) struct Leaf {
    path: PathBuf,
    parent: PathBuf,
    name: String,
    dir: Dir,
}

impl Leaf {
    pub(crate) fn open(path: &Path, create: bool) -> Result<Option<Self>> {
        let parent = path
            .parent()
            .ok_or_else(|| err("entry_invalid_path", "入口必须有绝对父目录"))?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| err("entry_invalid_path", "入口文件名无效"))?;
        let dir = match Dir::absolute(parent, create) {
            Ok(dir) => dir,
            Err(e) if !create && e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_at(parent, e)),
        };
        Ok(Some(Self {
            path: path.into(),
            parent: parent.into(),
            name: name.into(),
            dir,
        }))
    }

    pub(crate) fn read_stamp(path: &Path) -> Result<Option<Stamp>> {
        Self::open(path, false)?.map_or(Ok(None), |leaf| leaf.snapshot())
    }

    fn validate_parent(&self) -> Result<()> {
        let m = self.dir.metadata().map_err(|e| io_at(&self.parent, e))?;
        let current = Dir::absolute(&self.parent, false)
            .and_then(|d| d.metadata())
            .map_err(|e| io_at(&self.parent, e))?;
        if !same_inode(&m, &current) {
            return Err(err(
                "entry_parent_changed",
                format!("入口父目录已被替换：{}", self.parent.display()),
            ));
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<Option<Stamp>> {
        self.validate_parent()?;
        inspect(&self.dir, &self.name, &mut { MAX_NODES }).map_err(|e| io_at(&self.path, e))
    }

    pub(crate) fn read_bytes(path: &Path, limit: u64) -> Result<Option<(Vec<u8>, Stamp)>> {
        let Some(leaf) = Self::open(path, false)? else {
            return Ok(None);
        };
        let mut file = match leaf.dir.read(&leaf.name) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_at(path, e)),
        };
        let meta = file.metadata().map_err(|e| io_at(path, e))?;
        let bytes = read_file(&mut file, &meta, limit).map_err(|e| io_at(path, e))?;
        let observed = stamp(&meta, crate::storage::sha256(&bytes));
        if leaf.snapshot()?.as_ref() != Some(&observed) {
            return Err(err(
                "entry_changed",
                format!("读取入口期间文件已改变：{}", path.display()),
            ));
        }
        Ok(Some((bytes, observed)))
    }
}

pub(crate) enum Object {
    File(Vec<u8>, u32),
    Desktop { plist: Vec<u8>, executable: Vec<u8> },
}

fn write(dir: &Dir, name: &str, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut f = dir.create(name, 0o600)?;
    f.write_all(bytes)?;
    f.set_permissions(Permissions::from_mode(mode))?;
    if f.metadata()?.mode() & 0o7777 != mode {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    f.sync_all()
}

impl Object {
    fn stage(self, dir: &Dir) -> io::Result<()> {
        match self {
            Self::File(bytes, mode) => write(dir, SLOT, &bytes, mode),
            Self::Desktop { plist, executable } => {
                dir.mkdir(SLOT, 0o700)?;
                let root = dir.child(SLOT)?;
                root.mkdir("Contents", 0o700)?;
                let contents = root.child("Contents")?;
                contents.mkdir("MacOS", 0o700)?;
                write(&contents, "Info.plist", &plist, 0o644)?;
                write(
                    &contents.child("MacOS")?,
                    "ControlledEntry",
                    &executable,
                    0o755,
                )
            }
        }
    }
}

fn remove_tree(dir: &Dir, name: &str) -> io::Result<()> {
    let file = dir.read(name)?;
    let meta = file.metadata()?;
    if meta.is_dir() {
        let child = dir.child(name)?;
        if !same_inode(&meta, &child.metadata()?) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        for key in child.names(MAX_NODES)? {
            remove_tree(&child, &key)?;
        }
        dir.remove(name, true)
    } else if meta.is_file() && meta.nlink() == 1 {
        dir.remove(name, false)
    } else {
        Err(io::ErrorKind::InvalidData.into())
    }
}

pub(crate) struct Change {
    dest: Leaf,
    stage_name: String,
    stage: Dir,
    old: Option<Stamp>,
    pub(crate) new: Option<Stamp>,
    applied: bool,
    retain: bool,
}

impl Change {
    pub(crate) fn prepare(path: &Path, old: Option<Stamp>, object: Option<Object>) -> Result<Self> {
        let dest = Leaf::open(path, object.is_some())?.ok_or_else(|| {
            err(
                "entry_changed",
                format!("入口父目录已不存在：{}", path.display()),
            )
        })?;
        if dest.snapshot()? != old {
            return Err(err(
                "entry_conflict",
                format!("入口已被更改或不属于 Watch：{}", path.display()),
            ));
        }
        if old
            .as_ref()
            .is_some_and(|s| s.mode & 0o200 == 0 || s.mode & 0o7000 != 0)
        {
            return Err(err(
                "entry_read_only",
                format!("拒绝替换只读或含特殊权限的入口：{}", path.display()),
            ));
        }
        let stage_name = format!(".watch-entry-{}", uuid::Uuid::new_v4().simple());
        dest.dir
            .mkdir(&stage_name, 0o700)
            .map_err(|e| io_at(path, e))?;
        let stage = dest.dir.child(&stage_name).map_err(|e| io_at(path, e))?;
        let mut out = Self {
            dest,
            stage_name,
            stage,
            old,
            new: None,
            applied: false,
            retain: false,
        };
        if let Some(object) = object {
            if let Err(e) = object.stage(&out.stage) {
                let _ = remove_tree(&out.stage, SLOT);
                return Err(io_at(path, e));
            }
            out.new = out.staged()?;
            if out.new.is_none() {
                return Err(err("entry_stage_missing", "入口暂存对象丢失"));
            }
        }
        Ok(out)
    }

    fn staged(&self) -> Result<Option<Stamp>> {
        inspect(&self.stage, SLOT, &mut { MAX_NODES }).map_err(|e| io_at(&self.stage_path(), e))
    }
    fn stage_path(&self) -> PathBuf {
        self.dest.parent.join(&self.stage_name)
    }

    fn commit(&mut self) -> Result<()> {
        if self.dest.snapshot()? != self.old || self.staged()? != self.new {
            return Err(err(
                "entry_changed",
                format!("提交前入口内容改变：{}", self.dest.path.display()),
            ));
        }
        let res = if self.new.is_some() {
            self.stage
                .rename(SLOT, &self.dest.dir, &self.dest.name, self.old.is_some())
        } else {
            self.dest
                .dir
                .rename(&self.dest.name, &self.stage, SLOT, false)
        };
        res.map_err(|e| io_at(&self.dest.path, e))?;
        self.applied = true;
        self.check_committed()
    }

    fn check_committed(&self) -> Result<()> {
        if self.dest.snapshot()? != self.new || self.staged()? != self.old {
            return Err(err(
                "entry_changed",
                format!("提交期间入口内容改变：{}", self.dest.path.display()),
            ));
        }
        Ok(())
    }

    fn rollback(&mut self) -> Result<()> {
        if !self.applied {
            return Ok(());
        }
        // Even if the visible parent moved, restore only the objects in the
        // directory we actually touched. Do not enter its replacement.
        let current = inspect(&self.dest.dir, &self.dest.name, &mut { MAX_NODES })
            .map_err(|e| io_at(&self.dest.path, e))?;
        if current != self.new {
            return Err(err(
                "entry_rollback_conflict",
                "回滚目标已改变，保留冲突文件",
            ));
        }
        if self.old.is_some() {
            self.stage
                .rename(SLOT, &self.dest.dir, &self.dest.name, self.new.is_some())
                .map_err(|e| io_at(&self.dest.path, e))?;
        } else {
            self.dest
                .dir
                .rename(&self.dest.name, &self.stage, SLOT, false)
                .map_err(|e| io_at(&self.dest.path, e))?;
        }
        self.applied = false;
        if self.staged()? != self.new {
            return Err(err(
                "entry_rollback_conflict",
                "回滚期间入口内容改变，保留暂存文件",
            ));
        }
        Ok(())
    }

    fn cleanup(&self) -> Result<()> {
        let expected = if self.applied { &self.old } else { &self.new };
        if self.staged()?.as_ref() != expected.as_ref() {
            return Err(err("entry_cleanup_conflict", "入口暂存内容已变化，已保留"));
        }
        if expected.is_some() {
            remove_tree(&self.stage, SLOT).map_err(|e| io_at(&self.stage_path(), e))?;
        }
        let visible = self
            .dest
            .dir
            .child(&self.stage_name)
            .and_then(|d| d.metadata())
            .map_err(|e| io_at(&self.stage_path(), e))?;
        if !same_inode(
            &visible,
            &self
                .stage
                .metadata()
                .map_err(|e| io_at(&self.stage_path(), e))?,
        ) {
            return Err(err("entry_cleanup_conflict", "入口暂存目录已变化，已保留"));
        }
        self.dest
            .dir
            .remove(&self.stage_name, true)
            .map_err(|e| io_at(&self.stage_path(), e))
    }
}

impl Drop for Change {
    fn drop(&mut self) {
        if !self.retain && !self.applied {
            let _ = self.cleanup();
        }
    }
}

pub(crate) fn commit(changes: Vec<Change>) -> Result<()> {
    commit_with(changes, |_| Ok(()))
}

fn commit_with(
    mut changes: Vec<Change>,
    mut after_step: impl FnMut(usize) -> Result<()>,
) -> Result<()> {
    let result = (|| {
        for (i, change) in changes.iter_mut().enumerate() {
            change.commit()?;
            after_step(i)?;
        }
        for change in &changes {
            change.check_committed()?;
        }
        Ok::<_, CoreError>(())
    })();
    if let Err(failure) = result {
        let mut preserved = Vec::new();
        for change in changes.iter_mut().rev() {
            if change.rollback().is_err() {
                change.retain = true;
                preserved.push(change.stage_path().display().to_string());
            }
        }
        return if preserved.is_empty() {
            Err(failure)
        } else {
            Err(err(
                "entry_recovery_required",
                format!(
                    "{}；未能完整回滚，已保留暂存对象：{}",
                    failure.message,
                    preserved.join(", ")
                ),
            ))
        };
    }
    let mut preserved = Vec::new();
    for change in &mut changes {
        change.retain = true;
        if change.cleanup().is_err() {
            preserved.push(change.stage_path().display().to_string());
        }
    }
    if !preserved.is_empty() {
        return Err(err(
            "entry_committed_cleanup_pending",
            format!("入口已提交；未清理暂存对象：{}", preserved.join(", ")),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            let path = PathBuf::from("/private/tmp").join(format!(
                "watch-entry-test-{}",
                uuid::Uuid::new_v4().simple()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn v2_entry_transaction_restores_every_owned_object_after_each_failed_step() {
        for fault in 0..4 {
            let root = Root::new();
            let files: Vec<_> = ["shim", "fragment", "rc", "ledger"]
                .iter()
                .map(|p| root.0.join(p))
                .collect();
            for path in &files {
                fs::write(path, path.file_name().unwrap().as_encoded_bytes()).unwrap();
            }
            let originals: Vec<_> = files.iter().map(|p| fs::read(p).unwrap()).collect();
            let mut changes = Vec::new();
            for path in &files {
                changes.push(
                    Change::prepare(
                        path,
                        Leaf::read_stamp(path).unwrap(),
                        Some(Object::File(b"new".to_vec(), 0o600)),
                    )
                    .unwrap(),
                );
            }
            let error = commit_with(changes, |step| {
                if step == fault {
                    Err(err("fixture_commit_failure", "fixture"))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert_eq!(error.code, "fixture_commit_failure");
            assert_eq!(
                fs::read_dir(&root.0).unwrap().count(),
                files.len(),
                "no temporary objects after rollback"
            );
            for (path, original) in files.iter().zip(originals) {
                assert_eq!(fs::read(path).unwrap(), original);
            }
        }
    }
    #[test]
    fn v2_entry_transaction_refuses_parent_replacement_and_readonly_file() {
        let root = Root::new();
        let parent = root.0.join("original");
        let moved = root.0.join("moved");
        fs::create_dir(&parent).unwrap();
        let path = parent.join("entry");
        fs::write(&path, b"private original").unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o400)).unwrap();
        assert!(
            matches!(Change::prepare(&path, Leaf::read_stamp(&path).unwrap(), Some(Object::File(vec![], 0o600))),
            Err(e) if e.code == "entry_read_only")
        );
        fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        let change = Change::prepare(
            &path,
            Leaf::read_stamp(&path).unwrap(),
            Some(Object::File(b"candidate".to_vec(), 0o600)),
        )
        .unwrap();
        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::write(&path, b"separate user bytes").unwrap();
        assert_eq!(
            commit(vec![change]).unwrap_err().code,
            "entry_parent_changed"
        );
        assert_eq!(fs::read(path).unwrap(), b"separate user bytes");
        assert_eq!(fs::read(moved.join("entry")).unwrap(), b"private original");
    }
}
