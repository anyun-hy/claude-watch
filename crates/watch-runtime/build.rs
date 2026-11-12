use std::{env, fs, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=../../monitor/macos-minimum.txt");
    println!("cargo:rerun-if-changed=native/Observer.swift");
    println!("cargo:rerun-if-changed=../../monitor/Sources/AIProcessControl.swift");
    println!("cargo:rerun-if-changed=../../monitor/tools/ProcessHelper.swift");
    if env::var("TARGET").as_deref() != Ok("aarch64-apple-darwin") {
        println!("cargo:rustc-env=CW_NATIVE_OBSERVER_BUILD_PATH=");
        println!("cargo:rustc-env=CW_PROCESS_CONTROL_BUILD_PATH=");
        return;
    }
    let minimum = include_str!("../../monitor/macos-minimum.txt").trim();
    assert!(
        minimum.split('.').count() == 2
            && minimum
                .split('.')
                .all(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())),
        "invalid macOS minimum version"
    );
    let swift_target = format!("arm64-apple-macosx{minimum}");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let cache = output.join("swift-modules");
    fs::create_dir_all(&cache).expect("Swift module cache");
    let executable = output.join("watch-native-observer");
    let status = Command::new("/usr/bin/xcrun")
        .args([
            "swiftc",
            "-parse-as-library",
            "-swift-version",
            "6",
            "-O",
            "-target",
            swift_target.as_str(),
            "-module-cache-path",
        ])
        .arg(&cache)
        .arg("native/Observer.swift")
        .arg("-o")
        .arg(&executable)
        .status()
        .expect("Swift compiler for macOS adapter");
    assert!(
        status.success(),
        "macOS observation adapter compilation failed"
    );
    println!(
        "cargo:rustc-env=CW_NATIVE_OBSERVER_BUILD_PATH={}",
        executable.display()
    );
    let control = output.join("watch-process-control");
    let mut compiler = Command::new("/usr/bin/xcrun");
    compiler.args([
            "swiftc",
            "-parse-as-library",
            "-swift-version",
            "6",
            "-DPROCESS_HELPER",
            "-O",
            "-target",
            swift_target.as_str(),
            "-module-cache-path",
        ])
        .arg(&cache)
        .args([
            "../../monitor/Sources/AIProcessControl.swift",
            "../../monitor/tools/ProcessHelper.swift",
        ]);
    // The development helper accepts only this Cargo build's explicitly passed
    // engine, whose live parent identity it also checks. Release has no override.
    if env::var("PROFILE").as_deref() == Ok("debug") {
        let engine = output.ancestors().nth(3).expect("Cargo profile directory")
            .join("claude-watch-engine");
        let paths = output.join("ProcessHelperDevelopment.swift");
        fs::write(&paths, format!("enum ProcessHelperDevelopment {{ static let enginePath = {:?} }}\n",
            engine.to_str().expect("UTF-8 engine path"))).expect("development helper path");
        compiler.args(["-D", "PROCESS_HELPER_DEVELOPMENT"]).arg(&paths);
    }
    let status = compiler.arg("-o")
        .arg(&control)
        .status()
        .expect("Swift process adapter compiler");
    assert!(
        status.success(),
        "macOS process-control adapter compilation failed"
    );
    println!(
        "cargo:rustc-env=CW_PROCESS_CONTROL_BUILD_PATH={}",
        control.display()
    );
}
