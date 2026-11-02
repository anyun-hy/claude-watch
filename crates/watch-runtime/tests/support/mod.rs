use serde_json::Value;
use std::path::PathBuf;

/// Recorded answers of the retired Python implementation.
///
/// The snapshot is keyed by the operation and a digest of the exact cases, so
/// a changed input cannot silently reuse an answer recorded for a different
/// one: it fails with a missing snapshot instead. A snapshot is a reviewed
/// baseline captured once during the migration; it is never regenerated from
/// the implementation under test, because that would only assert the code
/// agrees with itself.
pub fn oracle(operation: &str, cases: &[Value]) -> Vec<Value> {
    let path = snapshot_path(operation, cases);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing recorded snapshot {}; the cases changed, so record the expected answers deliberately",
            path.display()
        )
    });
    serde_json::from_str(&text).unwrap()
}

fn snapshot_path(operation: &str, cases: &[Value]) -> PathBuf {
    let text = serde_json::to_string(cases).unwrap();
    let mut digest: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes() {
        digest ^= byte as u64;
        digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/legacy_snapshots")
        .join(format!("{operation}-{digest:016x}.json"))
}
