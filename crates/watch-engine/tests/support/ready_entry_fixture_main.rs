// Build the same CLI main and dispatch as a fixture-only executable. Cargo
// never compiles the fixture backend into the shipped engine target.
// The regular unit-test modules are included by the source but aren't run by
// this test target's custom harness.
#![allow(dead_code, unused_imports)]

#[cfg(target_os = "macos")]
include!("../../src/main.rs");

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("ready_entry_fixture requires macOS");
}
