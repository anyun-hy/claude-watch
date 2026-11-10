//! Fixed-path, administrator-authorized installation. No VPN or user process
//! is modified. The transaction survives interruption and can be rolled back.
use claude_watch_system::launchd_gateway::{
    GatewayInstallConfig, BROKER_PATH, INSTALL_DIR, SERVICE_LABEL,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const PLIST: &str = "/Library/LaunchDaemons/io.local.claudewatch.gateway.plist";
const TRANSACTION: &str = "/Library/PrivilegedHelperTools/io.local.claudewatch.gateway.transaction";
fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}

trait Host {
    fn launchctl(&mut self, args: &[&str]) -> io::Result<(i32, String)>;
    fn signature(&mut self, path: &Path) -> io::Result<String>;
}
struct Native;
impl Host for Native {
    fn launchctl(&mut self, args: &[&str]) -> io::Result<(i32, String)> {
        let out = Command::new("/bin/launchctl").args(args).output()?;
        Ok((
            out.status.code().unwrap_or(-1),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        ))
    }
    fn signature(&mut self, path: &Path) -> io::Result<String> {
        super::code_hash(path)
    }
}
#[derive(Clone)]
struct Paths {
    root: PathBuf,
    plist: PathBuf,
    transaction: PathBuf,
    owner: u32,
}
impl Paths {
    fn production() -> Self {
        Self {
            root: INSTALL_DIR.into(),
            plist: PLIST.into(),
            transaction: TRANSACTION.into(),
            owner: 0,
        }
    }
    fn broker(&self) -> PathBuf {
        self.root.join("watch-gateway-broker")
    }
    fn config(&self) -> PathBuf {
        self.root.join("config.json")
    }
    fn secure(&self, path: &Path) -> io::Result<()> {
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() || meta.uid() != self.owner || meta.mode() & 0o022 != 0 {
            return Err(invalid(
                "gateway path ownership, mode or type is not trusted",
            ));
        }
        #[cfg(target_os = "macos")]
        if self.owner == 0 {
            claude_watch_system::launchd_gateway::verify_gateway_install_path(path)?;
        }
        Ok(())
    }
    fn ensure_install_parent(&self) -> io::Result<()> {
        let parent = self.root.parent().ok_or_else(|| invalid("missing gateway parent"))?;
        if !exists(parent) {
            self.known_parent(parent)?;
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o755).create(parent)?;
        }
        self.known_parent(&self.root)
    }
    fn known_parent(&self, path: &Path) -> io::Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| invalid("missing gateway parent"))?;
        self.secure(parent)?;
        if !parent.is_dir() {
            return Err(invalid("gateway parent is not a directory"));
        }
        Ok(())
    }
}
/// The administrator child may outlive its osascript parent after a timeout.
/// Every mutating command must hold the same kernel lock; recovery refuses a
/// still-running operation instead of racing it. The fixed lock file remains.
struct ServiceLock {
    _file: fs::File,
}
fn service_lock(paths: &Paths) -> io::Result<ServiceLock> {
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
    let lock_path = PathBuf::from(format!("{}.lock", paths.root.display()));
    paths.known_parent(&lock_path)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)?;
    paths.secure(&lock_path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("gateway lock is not a regular file"));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(invalid(
            "gateway operation still running; recovery must wait for its completion",
        ));
    }
    Ok(ServiceLock { _file: file })
}
fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}
fn bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("gateway record is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("gateway record exceeds bound"));
    }
    Ok(bytes)
}
fn write(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
fn hash(path: &Path) -> io::Result<String> {
    claude_watch_system::sha256_file_hex(path).ok_or_else(|| invalid("component hash unavailable"))
}
fn config(path: &Path) -> io::Result<GatewayInstallConfig> {
    let value: GatewayInstallConfig = serde_json::from_slice(&bounded(path, 16 * 1024)?)?;
    value.validate()?;
    Ok(value)
}
fn same_config(a: &GatewayInstallConfig, b: &GatewayInstallConfig) -> bool {
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}
fn baseline(value: Option<&GatewayInstallConfig>) -> String {
    value
        .map(|value| {
            claude_watch_system::sha256_bytes_hex(
                &serde_json::to_vec(value).expect("serializable gateway config"),
            )
        })
        .unwrap_or_else(|| "absent".into())
}
fn scope(value: &GatewayInstallConfig, uid: u32, engine: &str) -> io::Result<()> {
    if value.engine_uid != uid || value.engine_executable != engine {
        return Err(invalid(
            "gateway belongs to another user or engine path; nothing changed",
        ));
    }
    Ok(())
}
fn loaded<H: Host>(host: &mut H, paths: &Paths) -> io::Result<bool> {
    let (status, text) = host.launchctl(&["print", &format!("system/{SERVICE_LABEL}")])?;
    if status == 113 {
        return Ok(false);
    }
    if status != 0 {
        return Err(invalid("cannot read gateway service state"));
    }
    // Matching files alone do not establish which definition launchd loaded.
    let program = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("program = "));
    let plist = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("path = "));
    if program != Some(BROKER_PATH) || plist != paths.plist.to_str() {
        return Err(invalid(
            "loaded gateway service identity is unknown; nothing changed",
        ));
    }
    Ok(true)
}
fn installed<H: Host>(
    paths: &Paths,
    host: &mut H,
    uid: u32,
    engine: &str,
) -> io::Result<Option<GatewayInstallConfig>> {
    let present = exists(&paths.root);
    let plist = exists(&paths.plist);
    let active = loaded(host, paths)?;
    if !present && !plist && !active {
        return Ok(None);
    }
    if !present || !plist {
        return Err(invalid(
            "incomplete or unknown gateway installation; nothing changed",
        ));
    }
    paths.secure(&paths.root)?;
    paths.secure(&paths.plist)?;
    paths.secure(&paths.config())?;
    paths.secure(&paths.broker())?;
    let value = config(&paths.config())?;
    scope(&value, uid, engine)?;
    if bounded(&paths.plist, 32 * 1024)? != super::plist(&value).as_bytes()
        || hash(&paths.broker())? != value.broker_sha256
        || host.signature(&paths.broker())? != value.broker_cdhash
    {
        return Err(invalid(
            "existing gateway identity or definition is not trusted; nothing changed",
        ));
    }
    for item in fs::read_dir(&paths.root)? {
        let item = item?;
        let name = item.file_name();
        match name.to_str() {
            Some("watch-gateway-broker" | "config.json" | "owner.json") => {
                paths.secure(&item.path())?
            }
            Some("control.sock") => {
                use std::os::unix::fs::FileTypeExt;
                let meta = fs::symlink_metadata(item.path())?;
                if !meta.file_type().is_socket() || meta.uid() != paths.owner {
                    return Err(invalid("gateway control socket identity is unknown"));
                }
            }
            _ => {
                return Err(invalid(
                    "gateway directory contains unknown entries; nothing changed",
                ))
            }
        }
    }
    Ok(Some(value))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transaction {
    schema: u32,
    id: String,
    phase: String,
    previous: Option<GatewayInstallConfig>,
    next: GatewayInstallConfig,
    was_loaded: bool,
}
fn token(value: &str) -> io::Result<()> {
    if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("invalid gateway transaction token"));
    }
    Ok(())
}
fn read_transaction(paths: &Paths, id: &str, uid: u32, engine: &str) -> io::Result<Transaction> {
    token(id)?;
    paths.secure(&paths.transaction)?;
    let manifest = paths.transaction.join("transaction.json");
    paths.secure(&manifest)?;
    let tx: Transaction = serde_json::from_slice(&bounded(&manifest, 32 * 1024)?)?;
    if tx.schema != 1 || tx.id != id || !matches!(tx.phase.as_str(), "preparing" | "replacing") {
        return Err(invalid("gateway transaction mismatch"));
    }
    tx.next.validate()?;
    scope(&tx.next, uid, engine)?;
    if let Some(old) = &tx.previous {
        old.validate()?;
        scope(old, uid, engine)?;
    }
    Ok(tx)
}
fn stop<H: Host>(paths: &Paths, host: &mut H) -> io::Result<()> {
    if paths.owner == 0 && exists(&paths.root.join("owner.json")) {
        claude_watch_system::launchd_gateway::require_gateway_owner_gone()?;
    }
    if loaded(host, paths)? {
        let (status, _) = host.launchctl(&["bootout", &format!("system/{SERVICE_LABEL}")])?;
        if status != 0 || loaded(host, paths)? {
            return Err(invalid(
                "gateway service did not stop; installation remains pending",
            ));
        }
    }
    Ok(())
}
fn start<H: Host>(paths: &Paths, host: &mut H) -> io::Result<()> {
    let (status, text) = host.launchctl(&[
        "bootstrap",
        "system",
        paths
            .plist
            .to_str()
            .ok_or_else(|| invalid("invalid plist path"))?,
    ])?;
    if status != 0 || !loaded(host, paths)? {
        return Err(invalid(&format!(
            "gateway activation failed: {}",
            text.chars().take(800).collect::<String>()
        )));
    }
    Ok(())
}
fn remove_known_files(paths: &Paths) -> io::Result<()> {
    // Directory was checked immediately before the mutation. Refuse extra
    // entries again; never recursively remove an unrecognized root directory.
    for item in fs::read_dir(&paths.root)? {
        let item = item?;
        if !matches!(
            item.file_name().to_str(),
            Some("watch-gateway-broker" | "config.json" | "owner.json" | "control.sock")
        ) {
            return Err(invalid("gateway changed during removal"));
        }
        fs::remove_file(item.path())?;
    }
    fs::remove_dir(&paths.root)?;
    fs::remove_file(&paths.plist)
}
fn copy_install(paths: &Paths, source: &Path, value: &GatewayInstallConfig) -> io::Result<()> {
    fs::create_dir(&paths.root)?;
    fs::set_permissions(&paths.root, fs::Permissions::from_mode(0o755))?;
    write(
        &paths.broker(),
        &bounded(&source.join("watch-gateway-broker"), 256 * 1024 * 1024)?,
        0o755,
    )?;
    write(&paths.config(), &serde_json::to_vec_pretty(value)?, 0o644)?;
    write(&paths.plist, super::plist(value).as_bytes(), 0o644)
}
fn rollback<H: Host>(
    paths: &Paths,
    host: &mut H,
    id: &str,
    uid: u32,
    engine: &str,
) -> io::Result<()> {
    let tx = read_transaction(paths, id, uid, engine)?;
    if tx.phase == "preparing" {
        let actual = installed(paths, host, uid, engine)?;
        if !match (&actual, &tx.previous) {
            (None, None) => true,
            (Some(a), Some(b)) => same_config(a, b),
            _ => false,
        } {
            return Err(invalid("gateway changed during transaction preparation"));
        }
        fs::remove_dir_all(&paths.transaction)?;
        return Ok(());
    }
    // An interruption can leave a partial new copy; only the files staged in
    // this transaction may be removed. Unexpected data requires manual review.
    if exists(&paths.root) {
        paths.secure(&paths.root)?;
        for item in fs::read_dir(&paths.root)? {
            let item = item?;
            if !matches!(
                item.file_name().to_str(),
                Some("watch-gateway-broker" | "config.json" | "owner.json" | "control.sock")
            ) {
                return Err(invalid("gateway rollback found unknown data"));
            }
        }
        if exists(&paths.config()) {
            paths.secure(&paths.config())?;
            let actual = config(&paths.config())?;
            if !same_config(&actual, &tx.next)
                && !tx
                    .previous
                    .as_ref()
                    .is_some_and(|old| same_config(old, &actual))
            {
                return Err(invalid("gateway configuration changed outside transaction"));
            }
        }
    }
    stop(paths, host)?;
    if exists(&paths.root) {
        for item in fs::read_dir(&paths.root)? {
            fs::remove_file(item?.path())?;
        }
        fs::remove_dir(&paths.root)?;
    }
    if exists(&paths.plist) {
        paths.secure(&paths.plist)?;
        fs::remove_file(&paths.plist)?;
    }
    if let Some(previous) = &tx.previous {
        let saved = paths.transaction.join("previous");
        paths.secure(&saved)?;
        paths.secure(&saved.join("watch-gateway-broker"))?;
        if hash(&saved.join("watch-gateway-broker"))? != previous.broker_sha256
            || host.signature(&saved.join("watch-gateway-broker"))? != previous.broker_cdhash
        {
            return Err(invalid("gateway rollback component identity mismatch"));
        }
        copy_install(paths, &saved, previous)?;
        if tx.was_loaded {
            start(paths, host)?;
        }
    }
    fs::remove_dir_all(&paths.transaction)?;
    Ok(())
}
fn install<H: Host>(paths: &Paths, host: &mut H, prepared: &Path, id: &str) -> io::Result<()> {
    token(id)?;
    paths.known_parent(&paths.root)?;
    paths.known_parent(&paths.plist)?;
    if exists(&paths.transaction) {
        return Err(invalid(
            "gateway transaction pending; explicitly recover it before another installation",
        ));
    }
    let next = config(&prepared.join("config.json"))?;
    let engine = Path::new(&next.engine_executable);
    if fs::canonicalize(engine)? != engine
        || fs::metadata(engine)?.uid() != next.engine_uid
        || !next
            .engine_executable
            .ends_with("/Library/Application Support/ClaudeWatch/runtime/watch-engine")
        || hash(engine)? != next.engine_sha256
        || host.signature(engine)? != next.engine_cdhash
    {
        return Err(invalid(
            "final runtime engine identity does not match prepared installation",
        ));
    }
    // Read the prepared payload once and verify the root-owned copy again.
    // The caller's writable preparation directory is never installed as root.
    let payload = bounded(&prepared.join("watch-gateway-broker"), 256 * 1024 * 1024)?;
    let previous = installed(paths, host, next.engine_uid, &next.engine_executable)?;
    let was_loaded = loaded(host, paths)?;
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&paths.transaction)?;
    }
    let mut tx = Transaction {
        schema: 1,
        id: id.into(),
        phase: "preparing".into(),
        previous,
        next,
        was_loaded,
    };
    // Establish a recoverable record before reading/copying either component.
    // No installed service has been touched at this point.
    if let Err(error) = write(
        &paths.transaction.join("transaction.json"),
        &serde_json::to_vec_pretty(&tx)?,
        0o600,
    ) {
        // Only the directory created by this invocation, with no root service
        // mutation, may be cleaned on this early write failure.
        let _ = fs::remove_file(paths.transaction.join("transaction.json"));
        let _ = fs::remove_dir(&paths.transaction);
        return Err(error);
    }
    let staged = paths.transaction.join("next");
    let preparation = (|| {
        fs::create_dir(&staged)?;
        write(&staged.join("watch-gateway-broker"), &payload, 0o755)?;
        if hash(&staged.join("watch-gateway-broker"))? != tx.next.broker_sha256
            || host.signature(&staged.join("watch-gateway-broker"))? != tx.next.broker_cdhash
        {
            return Err(invalid(
                "prepared broker identity changed; installation rejected",
            ));
        }
        if tx.previous.is_some() {
            let saved = paths.transaction.join("previous");
            fs::create_dir(&saved)?;
            write(
                &saved.join("watch-gateway-broker"),
                &bounded(&paths.broker(), 256 * 1024 * 1024)?,
                0o755,
            )?;
        }
        tx.phase = "replacing".into();
        let update = paths.transaction.join("transaction.next");
        write(&update, &serde_json::to_vec_pretty(&tx)?, 0o600)?;
        fs::rename(update, paths.transaction.join("transaction.json"))
    })();
    if let Err(error) = preparation {
        return match rollback(
            paths,
            host,
            id,
            tx.next.engine_uid,
            &tx.next.engine_executable,
        ) {
            Ok(()) => Err(error),
            Err(recovery) => Err(invalid(&format!(
                "{error}; gateway rollback pending: {recovery}"
            ))),
        };
    }
    let result = (|| {
        stop(paths, host)?;
        if tx.previous.is_some() {
            remove_known_files(paths)?;
        }
        copy_install(paths, &staged, &tx.next)?;
        installed(paths, host, tx.next.engine_uid, &tx.next.engine_executable)?;
        start(paths, host)
    })();
    if let Err(error) = result {
        return match rollback(
            paths,
            host,
            id,
            tx.next.engine_uid,
            &tx.next.engine_executable,
        ) {
            Ok(()) => Err(error),
            Err(recovery) => Err(invalid(&format!(
                "{error}; gateway rollback pending: {recovery}"
            ))),
        };
    }
    Ok(())
}

pub fn dispatch(args: &[String]) -> io::Result<()> {
    let command = args.first().map(String::as_str).unwrap_or("");
    let paths = Paths::production();
    let mut host = Native;
    if command == "--service-install"
        && args.len() == 5
        && args[1] == "--prepared"
        && args[3] == "--transaction"
    {
        if claude_watch_system::effective_uid() != 0 {
            return Err(invalid(
                "gateway installation requires administrator authorization",
            ));
        }
        paths.ensure_install_parent()?;
        let _lock = service_lock(&paths)?;
        install(&paths, &mut host, Path::new(&args[2]), &args[4])?;
        println!(
            "{}",
            json!({"status":"prepared","transaction":args[4],"endpoint_verified":false})
        );
        return Ok(());
    }
    if args.len() < 5 || args[1] != "--uid" || args[3] != "--engine" {
        return Err(invalid(
            "gateway service command requires --uid and --engine",
        ));
    }
    let uid = args[2]
        .parse()
        .map_err(|_| invalid("invalid gateway user"))?;
    let engine = &args[4];
    if uid == 0 || !Path::new(engine).is_absolute() {
        return Err(invalid("invalid gateway scope"));
    }
    if command == "--service-preview" && args.len() == 5 {
        if exists(&paths.transaction) {
            return Err(invalid("gateway transaction pending; use explicitly authorized --service-rollback with its transaction ID"));
        }
        let value = installed(&paths, &mut host, uid, engine)?;
        println!(
            "{}",
            json!({"status":"preview","action":if value.is_some(){"upgrade"}else{"install"},"gateway_port":value.as_ref().map(|v|v.gateway_port).unwrap_or(1023),"administrator_required":true,"endpoint_verified":false,"previous_config":baseline(value.as_ref())})
        );
        return Ok(());
    }
    if claude_watch_system::effective_uid() != 0 {
        return Err(invalid(
            "gateway management requires administrator authorization",
        ));
    }
    let _lock = service_lock(&paths)?;
    if matches!(command, "--service-rollback" | "--service-commit")
        && matches!(args.len(), 7 | 9)
        && args[5] == "--transaction"
    {
        let id = &args[6];
        token(id)?;
        if command == "--service-rollback" && !exists(&paths.transaction) {
            let current = installed(&paths, &mut host, uid, engine)?;
            if args.len() != 9
                || args[7] != "--previous-config"
                || args[8] != baseline(current.as_ref())
            {
                return Err(invalid("no matching rollback transaction and current gateway identity differs from pre-install state"));
            }
            println!(
                "{}",
                json!({"status":"ok","action":command,"transaction":id,"already_absent":true})
            );
            return Ok(());
        }
        let tx = read_transaction(&paths, id, uid, engine)?;
        if command == "--service-rollback" {
            rollback(&paths, &mut host, id, uid, engine)?;
        } else {
            let actual = installed(&paths, &mut host, uid, engine)?
                .ok_or_else(|| invalid("gateway not installed"))?;
            if !same_config(&actual, &tx.next) || !loaded(&mut host, &paths)? {
                return Err(invalid("gateway changed before transaction commit"));
            }
            fs::remove_dir_all(&paths.transaction)?;
        }
        println!(
            "{}",
            json!({"status":"ok","action":command,"transaction":id})
        );
        return Ok(());
    }
    if command == "--service-remove" && args.len() == 5 {
        if exists(&paths.transaction) {
            return Err(invalid("recover gateway transaction before removal"));
        }
        if installed(&paths, &mut host, uid, engine)?.is_some() {
            stop(&paths, &mut host)?;
            remove_known_files(&paths)?;
        }
        println!("{}", json!({"status":"ok","action":"remove"}));
        return Ok(());
    }
    Err(invalid("unsupported gateway service command"))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        active: bool,
        plist: PathBuf,
        fail_start: bool,
        calls: Vec<Vec<String>>,
        bad_signature: bool,
    }
    impl Host for Fake {
        fn launchctl(&mut self, args: &[&str]) -> io::Result<(i32, String)> {
            self.calls
                .push(args.iter().map(|s| s.to_string()).collect());
            match args[0] {
                "print" if self.active => Ok((
                    0,
                    format!("program = {BROKER_PATH}\npath = {}\n", self.plist.display()),
                )),
                "print" => Ok((113, "missing".into())),
                "bootout" => {
                    self.active = false;
                    Ok((0, String::new()))
                }
                "bootstrap" if self.fail_start => {
                    self.fail_start = false;
                    Ok((5, "fixture bind failed".into()))
                }
                "bootstrap" => {
                    self.active = true;
                    Ok((0, String::new()))
                }
                _ => panic!("unexpected system action"),
            }
        }
        fn signature(&mut self, _: &Path) -> io::Result<String> {
            Ok(if self.bad_signature {
                "b".repeat(40)
            } else {
                "a".repeat(40)
            })
        }
    }
    struct Fixture {
        dir: PathBuf,
        paths: Paths,
        host: Fake,
        prepared: PathBuf,
        value: GatewayInstallConfig,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
    fn fixture() -> Fixture {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "cw-broker-install-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            ));
        fs::create_dir(&dir).unwrap();
        let paths = Paths {
            root: dir.join("gateway"),
            plist: dir.join("gateway.plist"),
            transaction: dir.join("transaction"),
            owner: claude_watch_system::effective_uid(),
        };
        let prepared = dir.join("prepared");
        fs::create_dir(&prepared).unwrap();
        let engine = dir.join("home/Library/Application Support/ClaudeWatch/runtime/watch-engine");
        fs::create_dir_all(engine.parent().unwrap()).unwrap();
        fs::write(&engine, b"fixture engine").unwrap();
        fs::write(prepared.join("watch-gateway-broker"), b"fixture broker").unwrap();
        let value = GatewayInstallConfig {
            schema_version: 1,
            gateway_port: 1023,
            engine_uid: claude_watch_system::effective_uid(),
            engine_executable: engine.display().to_string(),
            engine_sha256: hash(&engine).unwrap(),
            engine_cdhash: "a".repeat(40),
            broker_sha256: hash(&prepared.join("watch-gateway-broker")).unwrap(),
            broker_cdhash: "a".repeat(40),
        };
        fs::write(
            prepared.join("config.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        let host = Fake {
            active: false,
            plist: paths.plist.clone(),
            fail_start: false,
            calls: vec![],
            bad_signature: false,
        };
        Fixture {
            dir,
            paths,
            host,
            prepared,
            value,
        }
    }
    const ID: &str = "01234567890123456789012345678901";
    #[test]
    fn fresh_install_is_pending_until_actual_handoff_and_can_be_revoked() {
        let mut f = fixture();
        install(&f.paths, &mut f.host, &f.prepared, ID).unwrap();
        assert!(f.host.active);
        assert!(f.paths.transaction.exists());
        assert!(installed(
            &f.paths,
            &mut f.host,
            f.value.engine_uid,
            &f.value.engine_executable
        )
        .unwrap()
        .is_some());
        rollback(
            &f.paths,
            &mut f.host,
            ID,
            f.value.engine_uid,
            &f.value.engine_executable,
        )
        .unwrap();
        assert!(!f.host.active);
        assert!(!f.paths.root.exists());
        assert!(!f.paths.plist.exists());
    }
    #[test]
    fn failed_upgrade_restores_known_previous_service_and_identity() {
        let mut f = fixture();
        copy_install(&f.paths, &f.prepared, &f.value).unwrap();
        f.host.active = true;
        let old = fs::read(f.paths.broker()).unwrap();
        fs::write(f.prepared.join("watch-gateway-broker"), b"new broker").unwrap();
        let mut next = f.value.clone();
        next.broker_sha256 = hash(&f.prepared.join("watch-gateway-broker")).unwrap();
        fs::write(
            f.prepared.join("config.json"),
            serde_json::to_vec(&next).unwrap(),
        )
        .unwrap();
        f.host.fail_start = true;
        assert!(install(&f.paths, &mut f.host, &f.prepared, ID)
            .unwrap_err()
            .to_string()
            .contains("activation failed"));
        assert!(f.host.active);
        assert_eq!(fs::read(f.paths.broker()).unwrap(), old);
        assert!(!f.paths.transaction.exists());
        assert!(same_config(&config(&f.paths.config()).unwrap(), &f.value));
    }
    #[test]
    fn unknown_root_contents_and_other_user_are_not_modified() {
        let mut f = fixture();
        copy_install(&f.paths, &f.prepared, &f.value).unwrap();
        fs::write(f.paths.root.join("foreign"), b"keep").unwrap();
        assert!(install(&f.paths, &mut f.host, &f.prepared, ID).is_err());
        assert_eq!(fs::read(f.paths.root.join("foreign")).unwrap(), b"keep");
        assert!(!f
            .host
            .calls
            .iter()
            .any(|c| c[0] == "bootout" || c[0] == "bootstrap"));
        fs::remove_file(f.paths.root.join("foreign")).unwrap();
        assert!(installed(
            &f.paths,
            &mut f.host,
            f.value.engine_uid + 1,
            &f.value.engine_executable
        )
        .is_err());
    }
    #[test]
    fn bad_prepared_payload_cleans_only_its_own_preparation_transaction() {
        let mut f = fixture();
        fs::write(f.prepared.join("watch-gateway-broker"), b"tampered").unwrap();
        assert!(install(&f.paths, &mut f.host, &f.prepared, ID).is_err());
        assert!(!f.paths.transaction.exists());
        assert!(!f.paths.root.exists());
        assert!(!f
            .host
            .calls
            .iter()
            .any(|c| c[0] == "bootout" || c[0] == "bootstrap"));
    }
    #[test]
    fn interrupted_preparation_is_recoverable_without_touching_live_service() {
        let mut f = fixture();
        copy_install(&f.paths, &f.prepared, &f.value).unwrap();
        f.host.active = true;
        fs::create_dir(&f.paths.transaction).unwrap();
        fs::set_permissions(&f.paths.transaction, fs::Permissions::from_mode(0o700)).unwrap();
        let tx = Transaction {
            schema: 1,
            id: ID.into(),
            phase: "preparing".into(),
            previous: Some(f.value.clone()),
            next: f.value.clone(),
            was_loaded: true,
        };
        write(
            &f.paths.transaction.join("transaction.json"),
            &serde_json::to_vec(&tx).unwrap(),
            0o600,
        )
        .unwrap();
        rollback(
            &f.paths,
            &mut f.host,
            ID,
            f.value.engine_uid,
            &f.value.engine_executable,
        )
        .unwrap();
        assert!(f.host.active);
        assert!(!f.paths.transaction.exists());
        assert!(!f
            .host
            .calls
            .iter()
            .any(|c| c[0] == "bootout" || c[0] == "bootstrap"));
    }
    #[test]
    fn changed_final_engine_and_unprotected_paths_are_rejected_before_root_changes() {
        let mut f = fixture();
        fs::write(&f.value.engine_executable, b"changed").unwrap();
        assert!(install(&f.paths, &mut f.host, &f.prepared, ID).is_err());
        assert!(!f.paths.transaction.exists());
        fs::set_permissions(&f.dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(install(&f.paths, &mut f.host, &f.prepared, ID).is_err());
    }
    #[test]
    fn administrator_commands_are_serialized_even_when_the_caller_disappears() {
        let f = fixture();
        let first = service_lock(&f.paths).unwrap();
        assert!(service_lock(&f.paths)
            .err()
            .unwrap()
            .to_string()
            .contains("still running"));
        drop(first);
        assert!(service_lock(&f.paths).is_ok());
    }
}
