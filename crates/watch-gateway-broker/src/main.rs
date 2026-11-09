use claude_watch_system::launchd_gateway::{GatewayInstallConfig, INSTALL_DIR, BROKER_PATH, CONTROL_PATH, SERVICE_LABEL};
use std::{fs, io, path::Path, process::Command};

fn code_hash(path: &Path) -> io::Result<String> {
    let verify = Command::new("/usr/bin/codesign").args(["--verify", "--strict"]).arg(path).output()?;
    if !verify.status.success() { return Err(io::Error::other("component code signature is invalid")); }
    let output = Command::new("/usr/bin/codesign").args(["--display", "--verbose=4"]).arg(path).output()?;
    if !output.status.success() { return Err(io::Error::other("component code signature is unavailable")); }
    let details = String::from_utf8_lossy(&output.stderr);
    if !details.lines().any(|line| line.contains("flags=") && line.contains("runtime") && line.contains("library")) {
        return Err(io::Error::other("sign components with --options runtime,library before preparing"));
    }
    details.lines().find_map(|line| line.strip_prefix("CDHash=")).map(str::to_owned)
        .ok_or_else(|| io::Error::other("component CDHash missing"))
}

fn prepare(args: &[String]) -> io::Result<()> {
    if args.len() != 8 || args[0] != "--output" || args[2] != "--engine" || args[4] != "--uid" || args[6] != "--port" {
        return Err(io::Error::other("usage: --prepare --output <new-directory> --engine <final-signed-engine-path> --uid <user-uid> --port <gateway-port>"));
    }
    let engine = fs::canonicalize(&args[3])?;
    let broker = fs::canonicalize(std::env::current_exe()?)?;
    let config = GatewayInstallConfig {
        schema_version: 1,
        gateway_port: args[7].parse().map_err(|_| io::Error::other("invalid port"))?,
        engine_uid: args[5].parse().map_err(|_| io::Error::other("invalid UID"))?,
        engine_executable: engine.to_str().ok_or_else(|| io::Error::other("non-UTF8 engine path"))?.into(),
        engine_sha256: claude_watch_system::sha256_file_hex(&engine).ok_or_else(|| io::Error::other("engine hash unavailable"))?,
        engine_cdhash: code_hash(&engine)?,
        broker_sha256: claude_watch_system::sha256_file_hex(&broker).ok_or_else(|| io::Error::other("broker hash unavailable"))?,
        broker_cdhash: code_hash(&broker)?,
    };
    config.validate()?;
    let out = Path::new(&args[1]);
    fs::create_dir(out)?; // Never overwrite a prior reviewable installation artifact.
    fs::copy(&broker, out.join("watch-gateway-broker"))?;
    fs::write(out.join("config.json"), serde_json::to_vec_pretty(&config)?)?;
    let plist = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{SERVICE_LABEL}</string>
<key>ProgramArguments</key><array><string>{BROKER_PATH}</string></array>
<key>UserName</key><string>root</string>
<key>Sockets</key><dict>
<key>GatewayV4</key><dict><key>SockFamily</key><string>IPv4</string><key>SockType</key><string>stream</string><key>SockProtocol</key><string>TCP</string><key>SockNodeName</key><string>0.0.0.0</string><key>SockServiceName</key><integer>{0}</integer></dict>
<key>GatewayV6</key><dict><key>SockFamily</key><string>IPv6</string><key>SockType</key><string>stream</string><key>SockProtocol</key><string>TCP</string><key>SockNodeName</key><string>::</string><key>SockServiceName</key><integer>{0}</integer></dict>
<key>Control</key><dict><key>SockFamily</key><string>Unix</string><key>SockType</key><string>stream</string><key>SockPathName</key><string>{CONTROL_PATH}</string><key>SockPathMode</key><integer>438</integer></dict>
</dict></dict></plist>
"#, config.gateway_port);
    fs::write(out.join(format!("{SERVICE_LABEL}.plist")), plist)?;
    fs::write(out.join("install.sh"), include_str!("../../../monitor/GatewayBroker/install.sh"))?;
    fs::write(out.join("README.txt"), format!("Prepared only; not installed.\nBroker destination: {INSTALL_DIR}\nEngine must remain at: {}\nPort: {}\nReview config/plist/install.sh, then obtain explicit administrator installation authorization.\nChanging or re-signing the engine requires a new approved configuration.\n", config.engine_executable, config.gateway_port))?;
    println!("prepared {} (no system changes)", out.display());
    Ok(())
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = if args.first().map(String::as_str) == Some("--prepare") { prepare(&args[1..]) }
        else if args.is_empty() { claude_watch_system::launchd_gateway::run_gateway_broker() }
        else { Err(io::Error::other("unsupported broker command")) };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => { eprintln!("gateway_broker_unavailable: {error}"); std::process::ExitCode::from(78) }
    }
}
