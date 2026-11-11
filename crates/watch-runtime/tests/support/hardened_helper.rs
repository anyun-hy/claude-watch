//! Only sign copies in a test-owned temporary directory, never a product.
#![allow(dead_code)]
use std::{fs, path::{Path, PathBuf}, process::Command};

pub fn cdhash(path: &Path) -> String {
    claude_watch_system::executable_cdhash(path).expect("fixture CDHash")
        .iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn sign(path: &Path) -> String {
    let output = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--options", "runtime,library"])
        .arg(path).output().unwrap();
    assert!(output.status.success(), "private ad-hoc signing: {}", String::from_utf8_lossy(&output.stderr));
    cdhash(path)
}

pub fn copy_signed(source: &Path, dest: &Path) -> PathBuf {
    fs::copy(source, dest).unwrap();
    sign(dest);
    dest.to_owned()
}

pub fn components(path: &Path) -> serde_json::Value {
    serde_json::json!({
        "network_backend": "seatbelt",
        "hashes": {"watch-sandbox-launcher": claude_watch_system::sha256_file_hex(path).unwrap()},
        "cdhashes": {"watch-sandbox-launcher": cdhash(path)},
    })
}

pub fn hardened_test_process(test: &str) -> bool {
    const WORKER: &str = "CW_HARDENED_PEER_TEST_WORKER";
    if std::env::var(WORKER).as_deref() == Ok(test) { return true; }
    let root = std::env::temp_dir().join(format!("cw-hardened-peer-{}-{}", std::process::id(), test));
    fs::create_dir(&root).unwrap();
    struct Root(PathBuf);
    impl Drop for Root {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }
    let root = Root(root);
    let signed = copy_signed(&std::env::current_exe().unwrap(), &root.0.join("peer"));
    let output = Command::new(signed).args(["--exact", test, "--nocapture"]).env(WORKER, test).output().unwrap();
    println!("{}", String::from_utf8_lossy(&output.stdout));
    assert!(output.status.success(), "signed fixture: {}", String::from_utf8_lossy(&output.stderr));
    false
}
