//! Diagnostic source identity, never an authorization or executable integrity proof.
use serde::{Deserialize, Serialize};
use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::Path, sync::OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildIdentity {
    pub schema: u32,
    pub app_version: String,
    pub app_build: String,
    pub source_revision: Option<String>,
    pub source_dirty: Option<bool>,
    pub source_tree_digest: String,
}
impl BuildIdentity {
    pub fn valid(&self) -> bool {
        let label = |s: &str| !s.is_empty() && s.len() <= 64
            && s.bytes().all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c));
        let hex = |s: &str| s.bytes().all(|c| c.is_ascii_hexdigit());
        self.schema == 1 && label(&self.app_version) && label(&self.app_build)
            && self.source_revision.as_ref().is_none_or(|s| matches!(s.len(), 40 | 64) && hex(s))
            && self.source_tree_digest.len() == 64 && hex(&self.source_tree_digest)
    }
}

pub fn read(path: &Path) -> Option<BuildIdentity> {
    #[cfg(target_os = "macos")]
    const NOFOLLOW: i32 = 0x0100 | 0x0004; // O_NOFOLLOW | O_NONBLOCK
    #[cfg(target_os = "linux")]
    const NOFOLLOW: i32 = 0x20000 | 0x0800;
    let file = OpenOptions::new().read(true).custom_flags(NOFOLLOW).open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > 4096 { return None; }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 4096 { return None; }
    let identity: BuildIdentity = serde_json::from_slice(&bytes).ok()?;
    identity.valid().then_some(identity)
}

pub fn current() -> Option<BuildIdentity> {
    static IDENTITY: OnceLock<Option<BuildIdentity>> = OnceLock::new();
    IDENTITY.get_or_init(|| {
        let executable = std::env::current_exe().ok()?;
        read(&executable.parent()?.join("BuildIdentity.json"))
    }).clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn build_identity_rejects_unbounded_invalid_and_symlink_metadata() {
        let root = std::env::temp_dir().join(format!("cw-build-id-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("BuildIdentity.json");
        let mut value = BuildIdentity { schema: 1, app_version: "3.0.0".into(), app_build: "381".into(),
            source_revision: Some("a".repeat(40)), source_dirty: Some(true), source_tree_digest: "b".repeat(64) };
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(read(&path), Some(value.clone()));
        std::os::unix::fs::symlink(&path, root.join("link")).unwrap();
        assert!(read(&root.join("link")).is_none());
        value.app_build = "token=private".into();
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(read(&path).is_none());
        std::fs::write(&path, vec![b'x'; 4097]).unwrap();
        assert!(read(&path).is_none());
        std::fs::remove_dir_all(root).unwrap();
    }
}
