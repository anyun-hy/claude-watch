//! Content proofs are bound to an exact open file and approval revision.
//! Only the registry's bounded approved/live-image set can request work.
use sha2::{Digest, Sha256};
use std::{fs::{self, File, Metadata}, io::Read, os::unix::fs::MetadataExt, path::Path};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FileIdentity {
    dev: u64, inode: u64, size: u64, mtime: i64, mtime_nsec: i64,
    ctime: i64, ctime_nsec: i64, mode: u32,
}
impl FileIdentity {
    fn metadata(m: &Metadata) -> Option<Self> {
        (m.is_file() && m.mode() & 0o111 != 0).then_some(Self {
            dev: m.dev(), inode: m.ino(), size: m.len(), mtime: m.mtime(), mtime_nsec: m.mtime_nsec(),
            ctime: m.ctime(), ctime_nsec: m.ctime_nsec(), mode: m.mode(),
        })
    }
    pub(crate) fn read(path: &str) -> Option<Self> {
        let path = Path::new(path);
        if fs::canonicalize(path).ok()?.as_path() != path { return None; }
        Self::metadata(&fs::metadata(path).ok()?)
    }
}

/// Discovery/staging reuses the same exact-file identity and bounded streaming
/// digest as content verification. This is a fingerprint, not a permit proof.
pub(crate) fn fingerprint_file(path: &str) -> Option<(FileIdentity, String)> {
    let identity = FileIdentity::read(path)?;
    let mut file = File::open(path).ok()?;
    if FileIdentity::metadata(&file.metadata().ok()?)? != identity { return None; }
    let mut digest = Sha256::new(); let mut buffer = [0;65536];
    loop { let count=file.read(&mut buffer).ok()?; if count==0 { break; } digest.update(&buffer[..count]); }
    if FileIdentity::metadata(&file.metadata().ok()?)? != identity || FileIdentity::read(path)? != identity { return None; }
    Some((identity, digest.finalize().iter().map(|byte|format!("{byte:02x}")).collect()))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct VerificationKey {
    pub path: String,
    pub identity: FileIdentity,
    pub expected_sha: String,
    pub approval_revision: u64,
}
impl VerificationKey {
    pub(crate) fn new(path: &str, sha: &str, revision: u64) -> Option<Self> {
        Some(Self { path: path.into(), identity: FileIdentity::read(path)?, expected_sha: sha.into(), approval_revision: revision })
    }
    /// A replacement during the read, including an atomic rename, cannot commit a proof.
    pub(crate) fn verify(&self) -> Option<bool> {
        let mut file = File::open(&self.path).ok()?;
        if FileIdentity::metadata(&file.metadata().ok()?)? != self.identity { return None; }
        let mut digest = Sha256::new();
        let mut buffer = [0; 65536];
        loop {
            let count = file.read(&mut buffer).ok()?;
            if count == 0 { break; }
            digest.update(&buffer[..count]);
        }
        if FileIdentity::metadata(&file.metadata().ok()?)? != self.identity
            || FileIdentity::read(&self.path)? != self.identity { return None; }
        let sha: String = digest.finalize().iter().map(|byte| format!("{byte:02x}")).collect();
        Some(sha == self.expected_sha)
    }
}
