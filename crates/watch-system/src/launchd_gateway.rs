//! System-owned socket activation boundary. A proof is constructed only after
//! kernel-authenticated IPC transfers an actual, validated listening socket.
//! No method here installs a daemon or falls back to a user-owned TCP listener.
use crate::ProcessKernelIdentity;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    os::unix::{fs::{FileTypeExt, MetadataExt, OpenOptionsExt}, net::{UnixListener, UnixStream}},
    path::{Component, Path},
    sync::Arc,
    time::Duration,
};

pub const INSTALL_DIR: &str = "/Library/PrivilegedHelperTools/io.local.claudewatch.gateway";
pub const BROKER_PATH: &str = "/Library/PrivilegedHelperTools/io.local.claudewatch.gateway/watch-gateway-broker";
pub const CONFIG_PATH: &str = "/Library/PrivilegedHelperTools/io.local.claudewatch.gateway/config.json";
pub const CONTROL_PATH: &str = "/Library/PrivilegedHelperTools/io.local.claudewatch.gateway/control.sock";
const OWNER_PATH: &str = "/Library/PrivilegedHelperTools/io.local.claudewatch.gateway/owner.json";
pub const SERVICE_LABEL: &str = "io.local.claudewatch.gateway";
const WIRE_MAGIC: &[u8; 8] = b"CWGW0001";
const MAX_CONFIG_BYTES: u64 = 16 * 1024;

fn invalid(message: &str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, message) }
fn denied(message: &str) -> io::Error { io::Error::new(io::ErrorKind::PermissionDenied, message) }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayInstallConfig {
    pub schema_version: u32,
    pub gateway_port: u16,
    pub engine_uid: u32,
    pub engine_executable: String,
    pub engine_sha256: String,
    pub engine_cdhash: String,
    pub broker_sha256: String,
    pub broker_cdhash: String,
}
impl GatewayInstallConfig {
    pub fn endpoint(&self) -> SocketAddr { SocketAddr::from((Ipv4Addr::LOCALHOST, self.gateway_port)) }
    pub fn validate(&self) -> io::Result<()> {
        let hex = |s: &str, n| s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit());
        let engine = Path::new(&self.engine_executable);
        if self.schema_version != 1 || !(1..1024).contains(&self.gateway_port) || self.engine_uid == 0
            || !engine.is_absolute() || self.engine_executable.len() > 4096
            || self.engine_executable.chars().any(char::is_control)
            || engine.components().any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
            || !hex(&self.engine_sha256, 64) || !hex(&self.broker_sha256, 64)
            || !hex(&self.engine_cdhash, 40) || !hex(&self.broker_cdhash, 40) {
            return Err(invalid("invalid protected gateway installation configuration"));
        }
        Ok(())
    }
}

/// This is intentionally neither Deserialize nor publicly constructible.
#[derive(Clone, Debug)]
pub struct GatewayEndpointProtection {
    endpoint: SocketAddr,
    broker: ProcessKernelIdentity,
    // Keep the IPv6 reservation alive even if the broker restarts. It never
    // forwards data: supported clients use the advertised IPv4 proxy endpoint.
    _ipv6_reservation: Arc<TcpListener>,
}
impl GatewayEndpointProtection {
    pub fn endpoint(&self) -> SocketAddr { self.endpoint }
    pub fn broker_identity(&self) -> &ProcessKernelIdentity { &self.broker }
}
pub struct VerifiedGatewayListener {
    listener: TcpListener,
    protection: GatewayEndpointProtection,
}
impl VerifiedGatewayListener {
    pub fn into_parts(self) -> (TcpListener, GatewayEndpointProtection) { (self.listener, self.protection) }
}

/// Reject replaceable installation paths, including ACL grants and symlink
/// ancestors. The socket itself may be writable: authentication is per peer;
/// only its protected directory controls who can replace the endpoint.
fn verify_protected_path(path: &Path, socket_leaf: bool) -> io::Result<()> {
    if !path.is_absolute() || path.components().any(|c| !matches!(c, Component::RootDir | Component::Normal(_))) {
        return Err(denied("protected path must be absolute without aliases"));
    }
    for p in path.ancestors() {
        let meta = fs::symlink_metadata(p)?;
        if meta.uid() != 0 || meta.file_type().is_symlink() || (p != path && !meta.is_dir()) {
            return Err(denied("gateway install chain is not root-owned and immutable"));
        }
        if p == path && socket_leaf {
            if !meta.file_type().is_socket() { return Err(denied("gateway control endpoint is not a socket")); }
        } else if meta.mode() & 0o022 != 0 {
            return Err(denied("gateway install chain is group/user writable"));
        }
        #[cfg(target_os = "macos")]
        platform::reject_acl(p)?;
    }
    Ok(())
}

fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    if !file.metadata()?.is_file() { return Err(invalid("expected a regular gateway record")); }
    let mut data = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_CONFIG_BYTES { return Err(invalid("gateway record too large")); }
    Ok(data)
}
pub fn load_gateway_install_config() -> io::Result<GatewayInstallConfig> {
    verify_protected_path(Path::new(CONFIG_PATH), false)?;
    verify_protected_path(Path::new(BROKER_PATH), false)?;
    let config: GatewayInstallConfig = serde_json::from_slice(&read_bounded(Path::new(CONFIG_PATH))?).map_err(|_| invalid("gateway configuration JSON invalid"))?;
    config.validate()?;
    if crate::sha256_file_hex(Path::new(BROKER_PATH)).as_deref() != Some(&config.broker_sha256) {
        return Err(denied("installed broker digest does not match protected configuration"));
    }
    Ok(config)
}

pub fn acquire_gateway_listener() -> io::Result<VerifiedGatewayListener> {
    #[cfg(not(target_os = "macos"))]
    return Err(io::Error::new(io::ErrorKind::Unsupported, "launchd gateway requires macOS"));
    #[cfg(target_os = "macos")]
    {
        let config = load_gateway_install_config()?;
        if crate::effective_uid() != config.engine_uid { return Err(denied("engine UID is not approved")); }
        verify_protected_path(Path::new(CONTROL_PATH), true)?;
        let mut stream = UnixStream::connect(CONTROL_PATH)?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        let broker = platform::verify_peer(&stream, 0, BROKER_PATH, &config.broker_sha256, &config.broker_cdhash)?;
        if broker.ppid != 1 { return Err(denied("broker is not owned by system launchd")); }
        stream.write_all(WIRE_MAGIC)?;
        let (listener, ipv6) = receive_listeners(&stream, config.gateway_port)?;
        validate_protected_listeners(&listener, &ipv6, config.gateway_port)?;
        let after = platform::verify_peer(&stream, 0, BROKER_PATH, &config.broker_sha256, &config.broker_cdhash)?;
        if after != broker { return Err(denied("broker identity changed during handoff")); }
        Ok(VerifiedGatewayListener { listener, protection: GatewayEndpointProtection { endpoint: config.endpoint(), broker, _ipv6_reservation: Arc::new(ipv6) } })
    }
}

fn int_socket_option(fd: RawFd, option: libc::c_int) -> io::Result<libc::c_int> {
    let mut value = 0;
    let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, option, (&mut value as *mut libc::c_int).cast(), &mut len) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of_val(&value) { return Err(invalid("invalid socket option length")); }
    Ok(value)
}
fn validate_listener(listener: &TcpListener, expected: SocketAddr) -> io::Result<()> {
    if !expected.ip().is_unspecified() || expected.port() == 0
        || listener.local_addr()? != expected
        || int_socket_option(listener.as_raw_fd(), libc::SO_TYPE)? != libc::SOCK_STREAM
        || !is_listening_socket(listener.as_raw_fd())?
        || int_socket_option(listener.as_raw_fd(), libc::SO_REUSEPORT)? != 0 {
        return Err(denied("gateway descriptor is not the exclusive expected TCP listener"));
    }
    Ok(())
}

fn is_listening_socket(fd: RawFd) -> io::Result<bool> {
    #[cfg(target_os = "macos")]
    {
        let (_, _, _, options) = crate::macos::own_socket_properties(fd).ok_or_else(|| denied("cannot inspect socket listener state"))?;
        Ok(options & libc::SO_ACCEPTCONN as u16 != 0)
    }
    #[cfg(not(target_os = "macos"))]
    { Ok(int_socket_option(fd, libc::SO_ACCEPTCONN)? == 1) }
}

fn validate_listeners(v4: &TcpListener, v6: &TcpListener, port: u16) -> io::Result<()> {
    validate_listener(v4, SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?;
    validate_listener(v6, SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)))?;
    let mut only: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&only) as libc::socklen_t;
    if unsafe { libc::getsockopt(v6.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, (&mut only as *mut libc::c_int).cast(), &mut length) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if only != 1 || length as usize != std::mem::size_of_val(&only) { return Err(denied("gateway IPv6 reservation is not V6ONLY")); }
    Ok(())
}

/// Reserved specific-address ports cannot be pre-bound by ordinary users on
/// supported macOS; an existing same-port wildcard prevents launchd binding.
/// After creation, the socket's root credential prevents cross-UID replacement.
/// Do not infer these properties from the receiver's UID or a JSON claim.
fn validate_protected_listeners(v4: &TcpListener, v6: &TcpListener, port: u16) -> io::Result<()> {
    if !(1..1024).contains(&port) { return Err(denied("gateway requires a reserved TCP port")); }
    validate_listeners(v4, v6, port)?;
    #[cfg(target_os = "macos")]
    for socket in [v4, v6] { verify_root_socket(socket)?; }
    #[cfg(not(target_os = "macos"))]
    return Err(denied("protected launchd listener requires macOS"));
    #[cfg(target_os = "macos")]
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_root_socket(socket: &TcpListener) -> io::Result<()> {
    let (kind, ty, protocol, _) = crate::macos::own_socket_properties(socket.as_raw_fd())
        .ok_or_else(|| denied("gateway socket properties unavailable"))?;
    if kind != 2 || ty != libc::SOCK_STREAM || protocol != libc::IPPROTO_TCP
        || socket_creator_uid(socket.as_raw_fd())? != 0
        || int_socket_option(socket.as_raw_fd(), 0x1025)? != 0 { // SO_REUSESHAREUID
        return Err(denied("gateway socket is not exclusively root-owned"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn socket_creator_uid(fd: RawFd) -> io::Result<u32> {
    // XNU sys_socket.c::soo_stat takes st_uid from so->so_cred. Unlike
    // PROC_PIDFDSOCKETINFO's zero-filled soi_stat, this describes the socket's
    // creation credential and survives SCM_RIGHTS transfer to a different UID.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 { return Err(io::Error::last_os_error()); }
    if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK { return Err(denied("gateway descriptor is not a socket")); }
    Ok(stat.st_uid)
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// cmsg storage uses usize alignment rather than a u8 Vec. All received owned
// descriptors are closed on every malformed/duplicate/truncated response.
fn send_listeners(stream: &UnixStream, listeners: &[&TcpListener]) -> io::Result<()> {
    let mut payload = *WIRE_MAGIC;
    let mut iov = libc::iovec { iov_base: payload.as_mut_ptr().cast(), iov_len: payload.len() };
    let mut control = [0usize; 8];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    if listeners.len() > 2 { return Err(invalid("too many gateway listeners")); }
    let fd_bytes = std::mem::size_of::<RawFd>() * listeners.len();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(fd_bytes as _) } as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as _) as _;
        for (i, listener) in listeners.iter().enumerate() {
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>().add(i), listener.as_raw_fd());
        }
        let sent = libc::sendmsg(stream.as_raw_fd(), &msg, 0);
        if sent < 0 { return Err(io::Error::last_os_error()); }
        if sent as usize != payload.len() { return Err(invalid("partial gateway descriptor handoff")); }
    }
    Ok(())
}

fn receive_listeners(stream: &UnixStream, port: u16) -> io::Result<(TcpListener, TcpListener)> {
    let mut payload = [0u8; 8];
    let mut iov = libc::iovec { iov_base: payload.as_mut_ptr().cast(), iov_len: payload.len() };
    let mut control = [0usize; 16];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control) as _;
    let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    if received < 0 { return Err(io::Error::last_os_error()); }
    let mut descriptors = Vec::<OwnedFd>::new();
    let mut malformed = false;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let header_len = libc::CMSG_LEN(0) as usize;
            let length = (*cmsg).cmsg_len as usize;
            if length < header_len { malformed = true; break; }
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let bytes = length - header_len;
                if bytes % std::mem::size_of::<RawFd>() != 0 { malformed = true; }
                for i in 0..bytes / std::mem::size_of::<RawFd>() {
                    let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>().add(i));
                    if fd >= 0 { descriptors.push(OwnedFd::from_raw_fd(fd)); } else { malformed = true; }
                }
            } else { malformed = true; }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    for fd in &descriptors { set_cloexec(fd.as_raw_fd())?; }
    if malformed || msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        || received as usize != payload.len() || payload != *WIRE_MAGIC || descriptors.len() != 2 {
        return Err(invalid("malformed gateway descriptor response"));
    }
    let v6 = TcpListener::from(descriptors.pop().unwrap());
    let v4 = TcpListener::from(descriptors.pop().unwrap());
    validate_listeners(&v4, &v6, port)?;
    Ok((v4, v6))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerRecord { pid: u32, uid: u32, start_seconds: u64, start_microseconds: u32, audit_token: [u32; 8] }
impl OwnerRecord {
    fn from_identity(p: &ProcessKernelIdentity) -> Self {
        Self { pid: p.pid, uid: p.uid, start_seconds: p.start_seconds, start_microseconds: p.start_microseconds, audit_token: p.audit_token }
    }
    fn matches(&self, p: &ProcessKernelIdentity) -> bool {
        self.pid == p.pid && self.uid == p.uid && self.start_seconds == p.start_seconds
            && self.start_microseconds == p.start_microseconds && self.audit_token == p.audit_token
    }
}
#[cfg(target_os = "macos")]
fn claim_owner(peer: &ProcessKernelIdentity) -> io::Result<()> {
    let path = Path::new(OWNER_PATH);
    match fs::symlink_metadata(path) {
        Ok(_) => {
            verify_protected_path(path, false)?;
            let old: OwnerRecord = serde_json::from_slice(&read_bounded(path)?).map_err(|_| invalid("invalid gateway owner record"))?;
            if !old.matches(peer) && !platform::owner_definitely_gone(&old) {
                return Err(denied("another live engine owns the gateway listener"));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // The broker is a single launchd job and processes requests serially. Its
    // root-only record survives broker restart; unknown old identities block.
    let temp = Path::new(INSTALL_DIR).join(format!("owner-{}.tmp", std::process::id()));
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&temp)?;
    let data = serde_json::to_vec(&OwnerRecord::from_identity(peer)).map_err(|_| invalid("owner serialization failed"))?;
    let result = file.write_all(&data).and_then(|_| file.sync_all()).and_then(|_| fs::rename(&temp, path));
    if result.is_err() { let _ = fs::remove_file(&temp); }
    result
}

/// Entry used only by the installed root launchd service. It does not bind TCP
/// or unlink/create a control socket; both descriptors must come from launchd.
pub fn run_gateway_broker() -> io::Result<()> {
    #[cfg(not(target_os = "macos"))]
    return Err(io::Error::new(io::ErrorKind::Unsupported, "launchd gateway requires macOS"));
    #[cfg(target_os = "macos")]
    {
        if crate::effective_uid() != 0 || unsafe { libc::getppid() } != 1 {
            return Err(denied("gateway broker requires system launchd"));
        }
        let config = load_gateway_install_config()?;
        if fs::canonicalize(std::env::current_exe()?)? != Path::new(BROKER_PATH) {
            return Err(denied("broker must run from its protected installed path"));
        }
        let listener = TcpListener::from(platform::activated_socket("GatewayV4")?);
        let ipv6 = TcpListener::from(platform::activated_socket("GatewayV6")?);
        validate_listeners(&listener, &ipv6, config.gateway_port)?;
        validate_protected_listeners(&listener, &ipv6, config.gateway_port)?;
        let control = UnixListener::from(platform::activated_socket("Control")?);
        if control.local_addr()?.as_pathname() != Some(Path::new(CONTROL_PATH))
            || !is_listening_socket(control.as_raw_fd())? {
            return Err(denied("invalid launchd control listener"));
        }
        verify_protected_path(Path::new(CONTROL_PATH), true)?;
        for connection in control.incoming() {
            let mut stream = connection?;
            let result = (|| {
                stream.set_read_timeout(Some(Duration::from_secs(3)))?;
                stream.set_write_timeout(Some(Duration::from_secs(3)))?;
                let peer = platform::verify_peer(&stream, config.engine_uid, &config.engine_executable, &config.engine_sha256, &config.engine_cdhash)?;
                let mut request = [0; 8]; stream.read_exact(&mut request)?;
                if request != *WIRE_MAGIC { return Err(invalid("unsupported gateway handoff protocol")); }
                let after = platform::verify_peer(&stream, config.engine_uid, &config.engine_executable, &config.engine_sha256, &config.engine_cdhash)?;
                if after != peer { return Err(denied("engine identity changed during handoff")); }
                claim_owner(&peer)?;
                send_listeners(&stream, &[&listener, &ipv6])
            })();
            // Never log credentials, request bytes, or raw process metadata.
            if let Err(error) = result { eprintln!("gateway_handoff_denied: {}", error.kind()); }
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use std::{ffi::{c_char, c_void, CStr, CString}, ptr};
    type Ref = *const c_void;
    unsafe extern "C" {
        fn launch_activate_socket(name: *const c_char, fds: *mut *mut libc::c_int, count: *mut usize) -> libc::c_int;
        fn proc_pidpath_audittoken(token: *mut [u32; 8], path: *mut c_void, size: u32) -> i32;
        fn csops_audittoken(pid: i32, ops: u32, useraddr: *mut c_void, size: usize, token: *mut [u32; 8]) -> i32;
        fn acl_get_file(path: *const c_char, kind: i32) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, entry_id: i32, entry: *mut *mut c_void) -> i32;
        fn acl_free(object: *mut c_void) -> i32;
    }
    #[link(name="CoreFoundation", kind="framework")]
    unsafe extern "C" {
        fn CFDataCreate(a: Ref, bytes: *const u8, len: isize) -> Ref;
        fn CFDictionaryCreate(a: Ref, keys: *const Ref, values: *const Ref, count: isize, kcb: Ref, vcb: Ref) -> Ref;
        fn CFDictionaryGetValue(dict: Ref, key: Ref) -> Ref;
        fn CFDictionaryGetCount(dict: Ref) -> isize;
        fn CFStringCreateWithCString(a: Ref, text: *const c_char, encoding: u32) -> Ref;
        fn CFRelease(value: Ref);
    }
    #[link(name="Security", kind="framework")]
    unsafe extern "C" {
        static kSecGuestAttributeAudit: Ref;
        static kSecCodeInfoEntitlementsDict: Ref;
        fn SecCodeCopyGuestWithAttributes(host: Ref, attrs: Ref, flags: u32, code: *mut Ref) -> i32;
        fn SecCodeCopyStaticCode(code: Ref, flags: u32, static_code: *mut Ref) -> i32;
        fn SecCodeCopySigningInformation(code: Ref, flags: u32, info: *mut Ref) -> i32;
        fn SecRequirementCreateWithString(text: Ref, flags: u32, requirement: *mut Ref) -> i32;
        fn SecCodeCheckValidity(code: Ref, flags: u32, requirement: Ref) -> i32;
    }
    struct Owned(Ref);
    impl Drop for Owned { fn drop(&mut self) { if !self.0.is_null() { unsafe { CFRelease(self.0) }; } } }

    pub(super) fn reject_acl(path: &Path) -> io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let cpath = CString::new(path.as_os_str().as_bytes()).map_err(|_| invalid("path NUL"))?;
        unsafe {
            let acl = acl_get_file(cpath.as_ptr(), 0x100);
            if acl.is_null() {
                let error = io::Error::last_os_error();
                // APFS can return ENOENT for an absent extended ACL on an
                // existing inode. Do not confuse that with a missing path.
                if error.raw_os_error() == Some(libc::ENOENT) && fs::symlink_metadata(path).is_ok() { return Ok(()); }
                return Err(error);
            }
            let mut entry = ptr::null_mut();
            let result = acl_get_entry(acl, 0, &mut entry);
            let error = io::Error::last_os_error();
            acl_free(acl);
            // Darwin uses 0 for a found entry and -1/EINVAL for exhausted
            // iteration; unlike Linux/POSIX 1 is not the success result.
            if result == 0 { Err(denied("ACL on protected gateway path")) }
            else if result == -1 && error.raw_os_error() == Some(libc::EINVAL) { Ok(()) }
            else { Err(io::Error::other(format!("acl_get_entry returned {result}: {error}"))) }
        }
    }
    pub(super) fn activated_socket(name: &str) -> io::Result<OwnedFd> {
        let name = CString::new(name).unwrap();
        let mut fds = ptr::null_mut(); let mut count = 0;
        let result = unsafe { launch_activate_socket(name.as_ptr(), &mut fds, &mut count) };
        if result != 0 { return Err(io::Error::from_raw_os_error(result)); }
        if fds.is_null() { return Err(invalid("launchd returned no descriptors")); }
        let mut owned = Vec::new();
        for i in 0..count { owned.push(unsafe { OwnedFd::from_raw_fd(*fds.add(i)) }); }
        unsafe { libc::free(fds.cast()); }
        if owned.len() != 1 { return Err(invalid("launchd must supply exactly one named socket")); }
        let fd = owned.pop().unwrap(); set_cloexec(fd.as_raw_fd())?; Ok(fd)
    }
    fn peer_token(stream: &UnixStream) -> io::Result<[u32; 8]> {
        let mut token = [0u32; 8]; let mut len = 32;
        if unsafe { libc::getsockopt(stream.as_raw_fd(), 0, 6, token.as_mut_ptr().cast(), &mut len) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if len != 32 || token[5] <= 1 || token[5] > i32::MAX as u32 { return Err(denied("invalid kernel peer token")); }
        Ok(token)
    }
    fn inspect_token(token: [u32; 8]) -> io::Result<ProcessKernelIdentity> {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info) as i32;
        if unsafe { libc::proc_pidinfo(token[5] as i32, libc::PROC_PIDTBSDINFO, 0, (&mut info as *mut libc::proc_bsdinfo).cast(), size) } != size {
            return Err(denied("cannot inspect kernel peer identity"));
        }
        if info.pbi_uid != token[1] { return Err(denied("peer UID changed")); }
        let mut path = [0i8; 4096]; let mut token_copy = token;
        if unsafe { proc_pidpath_audittoken(&mut token_copy, path.as_mut_ptr().cast(), path.len() as u32) } <= 0 {
            return Err(denied("peer execution identity changed"));
        }
        let executable = unsafe { CStr::from_ptr(path.as_ptr()) }.to_str().map_err(|_| denied("invalid peer path"))?;
        Ok(ProcessKernelIdentity { pid: token[5], ppid: info.pbi_ppid, uid: info.pbi_uid,
            start_seconds: info.pbi_start_tvsec, start_microseconds: info.pbi_start_tvusec as u32,
            executable_path: executable.into(), audit_token: token })
    }
    pub(super) fn verify_peer(stream: &UnixStream, uid: u32, executable: &str, sha256: &str, cdhash: &str) -> io::Result<ProcessKernelIdentity> {
        let token = peer_token(stream)?;
        if token[1] != uid { return Err(denied("unapproved gateway peer UID")); }
        let before = inspect_token(token)?;
        if before.executable_path != executable || crate::sha256_file_hex(Path::new(executable)).as_deref() != Some(sha256) {
            return Err(denied("unapproved gateway peer executable"));
        }
        verify_code(token, cdhash)?;
        if inspect_token(token)? != before || peer_token(stream)? != token { return Err(denied("gateway peer changed")); }
        Ok(before)
    }
    fn verify_code(mut token: [u32; 8], cdhash: &str) -> io::Result<()> {
        let mut flags: u32 = 0;
        // csops CS_OPS_STATUS, bound to pidversion by audit token.
        if unsafe { csops_audittoken(token[5] as i32, 0, (&mut flags as *mut u32).cast(), 4, &mut token) } != 0 {
            return Err(denied("cannot validate live gateway peer signing flags"));
        }
        let required = 0x1 | 0x2000 | 0x10000; // VALID, REQUIRE_LV, RUNTIME
        let forbidden = 0x4 | 0x10000000; // GET_TASK_ALLOW, DEBUGGED
        if flags & required != required || flags & forbidden != 0 { return Err(denied("gateway peer lacks hardened library validation")); }
        unsafe {
            let data = Owned(CFDataCreate(ptr::null(), token.as_ptr().cast(), 32));
            if data.0.is_null() { return Err(denied("audit data unavailable")); }
            let attrs = Owned(CFDictionaryCreate(ptr::null(), &kSecGuestAttributeAudit, &data.0, 1, ptr::null(), ptr::null()));
            if attrs.0.is_null() { return Err(denied("audit attributes unavailable")); }
            let mut code = ptr::null();
            if SecCodeCopyGuestWithAttributes(ptr::null(), attrs.0, 0, &mut code) != 0 || code.is_null() { return Err(denied("live code unavailable")); }
            let code = Owned(code);
            let requirement = CString::new(format!("cdhash H\"{cdhash}\"")).map_err(|_| denied("invalid CDHash"))?;
            let text = Owned(CFStringCreateWithCString(ptr::null(), requirement.as_ptr(), 0x08000100));
            let mut req = ptr::null();
            if text.0.is_null() || SecRequirementCreateWithString(text.0, 0, &mut req) != 0 { return Err(denied("CDHash requirement unavailable")); }
            let req = Owned(req);
            if SecCodeCheckValidity(code.0, 0, req.0) != 0 { return Err(denied("live gateway peer CDHash mismatch")); }
            let mut static_code = ptr::null();
            if SecCodeCopyStaticCode(code.0, 0, &mut static_code) != 0 || static_code.is_null() { return Err(denied("peer static code unavailable")); }
            let static_code = Owned(static_code);
            let mut info = ptr::null();
            if SecCodeCopySigningInformation(static_code.0, 1 << 1, &mut info) != 0 || info.is_null() { return Err(denied("peer entitlements unavailable")); }
            let info = Owned(info);
            let entitlements = CFDictionaryGetValue(info.0, kSecCodeInfoEntitlementsDict);
            // These dedicated binaries require no entitlements. Reject all
            // exceptions, including DYLD injection and library validation off.
            if !entitlements.is_null() && CFDictionaryGetCount(entitlements) != 0 { return Err(denied("gateway peer has unapproved entitlements")); }
        }
        Ok(())
    }
    pub(super) fn owner_definitely_gone(owner: &OwnerRecord) -> bool {
        if owner.pid <= 1 || owner.pid > i32::MAX as u32 { return false; }
        if unsafe { libc::kill(owner.pid as i32, 0) } != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) { return true; }
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info) as i32;
        if unsafe { libc::proc_pidinfo(owner.pid as i32, libc::PROC_PIDTBSDINFO, 0, (&mut info as *mut libc::proc_bsdinfo).cast(), size) } != size { return false; }
        info.pbi_start_tvsec != owner.start_seconds || info.pbi_start_tvusec as u32 != owner.start_microseconds
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gateway_descriptor_transfer_preserves_reservation_and_cloexec() {
        let listener = TcpListener::bind("0.0.0.0:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let ipv6 = test_ipv6_listener(addr.port());
        let (sender, receiver) = UnixStream::pair().unwrap();
        send_listeners(&sender, &[&listener, &ipv6]).unwrap();
        let (received, received_v6) = receive_listeners(&receiver, addr.port()).unwrap();
        assert!(unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC != 0);
        drop(received); drop(received_v6); // Worker loss, not launchd integration.
        assert!(TcpListener::bind(addr).is_err());
        // Same-UID local fixtures do NOT prove launchd's cross-UID exclusion.
        // macOS can permit a specific-address listener over this wildcard.
        let client = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, addr.port())).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        drop(client); drop(accepted); drop(listener);
    }
    #[test]
    fn gateway_descriptor_rejects_wrong_endpoint_and_missing_rights() {
        let listener = TcpListener::bind("0.0.0.0:0").unwrap();
        let ipv6 = test_ipv6_listener(listener.local_addr().unwrap().port());
        let (sender, receiver) = UnixStream::pair().unwrap();
        send_listeners(&sender, &[&listener, &ipv6]).unwrap();
        assert!(receive_listeners(&receiver, 1).is_err());
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        sender.write_all(WIRE_MAGIC).unwrap();
        assert!(receive_listeners(&receiver, listener.local_addr().unwrap().port()).is_err());
        let (sender, receiver) = UnixStream::pair().unwrap();
        send_listeners(&sender, &[&listener]).unwrap();
        assert!(receive_listeners(&receiver, listener.local_addr().unwrap().port()).is_err());
    }
    fn test_ipv6_listener(port: u16) -> TcpListener {
        unsafe {
            let raw_fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
            assert!(raw_fd >= 0);
            let fd = OwnedFd::from_raw_fd(raw_fd);
            let only: libc::c_int = 1;
            assert_eq!(libc::setsockopt(fd.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, (&only as *const libc::c_int).cast(), 4), 0);
            let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
            #[cfg(target_os = "macos")] { addr.sin6_len = std::mem::size_of_val(&addr) as u8; }
            addr.sin6_family = libc::AF_INET6 as _; addr.sin6_port = port.to_be();
            assert_eq!(libc::bind(fd.as_raw_fd(), (&addr as *const libc::sockaddr_in6).cast(), std::mem::size_of_val(&addr) as _), 0);
            assert_eq!(libc::listen(fd.as_raw_fd(), 16), 0);
            TcpListener::from(fd)
        }
    }
    #[test]
    fn gateway_configuration_rejects_untrusted_contract_fields() {
        let mut config = GatewayInstallConfig { schema_version: 1, gateway_port: 1021, engine_uid: 501,
            engine_executable: "/Applications/Watch.app/Contents/Resources/watch-engine".into(),
            engine_sha256: "1".repeat(64), engine_cdhash: "2".repeat(40), broker_sha256: "3".repeat(64), broker_cdhash: "4".repeat(40) };
        config.validate().unwrap();
        config.gateway_port = 18789; assert!(config.validate().is_err()); config.gateway_port = 1021;
        config.engine_uid = 0; assert!(config.validate().is_err()); config.engine_uid = 501;
        config.engine_executable = "/tmp/../engine".into(); assert!(config.validate().is_err());
        let path = std::env::temp_dir().join(format!("cw-untrusted-install-{}", std::process::id()));
        fs::write(&path, b"{}").unwrap();
        assert!(verify_protected_path(&path, false).is_err()); fs::remove_file(path).unwrap();
    }
    #[test]
    fn gateway_owner_identity_is_bound_to_birth_and_exec_token() {
        let mut identity = ProcessKernelIdentity { pid: 123, ppid: 1, uid: 501, start_seconds: 10,
            start_microseconds: 5, executable_path: "/engine".into(), audit_token: [1, 501, 1, 1, 1, 123, 1, 2] };
        let owner = OwnerRecord::from_identity(&identity);
        assert!(owner.matches(&identity));
        identity.audit_token[7] += 1; assert!(!owner.matches(&identity));
        identity.audit_token[7] -= 1; identity.start_microseconds += 1;
        assert!(!owner.matches(&identity));
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn gateway_protected_paths_distinguish_empty_and_extended_acl() {
        let path = std::env::temp_dir().join(format!("cw-gateway-acl-{}", std::process::id()));
        fs::write(&path, b"fixture").unwrap();
        platform::reject_acl(&path).expect("empty Darwin ACL accepted");
        let status = std::process::Command::new("/bin/chmod").args(["+a", "everyone allow read"]).arg(&path).status().unwrap();
        assert!(status.success());
        let rejected = platform::reject_acl(&path).is_err();
        fs::remove_file(path).unwrap();
        assert!(rejected, "extended ACL must not be accepted");
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn gateway_user_owned_socket_cannot_create_root_endpoint_proof() {
        assert_ne!(crate::effective_uid(), 0, "this negative test must run without privilege");
        let socket = TcpListener::bind("0.0.0.0:0").unwrap();
        let owner = socket_creator_uid(socket.as_raw_fd()).unwrap();
        assert_eq!(owner, crate::effective_uid(), "kernel reports original socket owner");
        assert_eq!(int_socket_option(socket.as_raw_fd(), 0x1025).unwrap(), 0, "SO_REUSESHAREUID is inspectable");
        assert!(verify_root_socket(&socket).is_err());
        let ipv6 = test_ipv6_listener(socket.local_addr().unwrap().port());
        let (sender, receiver) = UnixStream::pair().unwrap();
        send_listeners(&sender, &[&socket, &ipv6]).unwrap();
        let (v4, v6) = receive_listeners(&receiver, socket.local_addr().unwrap().port()).unwrap();
        for received in [&v4, &v6] {
            assert_eq!(socket_creator_uid(received.as_raw_fd()).unwrap(), owner);
            assert!(verify_root_socket(received).is_err(), "FD handoff cannot turn a user socket into a root socket");
        }
        let file = fs::File::open(std::env::current_exe().unwrap()).unwrap();
        assert!(socket_creator_uid(file.as_raw_fd()).is_err(), "ordinary file is not socket evidence");
    }
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires an isolated test executable ad-hoc signed with runtime,library; no installation"]
    fn gateway_signed_peer_checks_live_code_identity_and_rejects_wrong_uid_or_hash() {
        let exe = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let sha = crate::sha256_file_hex(&exe).unwrap();
        let output = std::process::Command::new("/usr/bin/codesign").args(["-d", "--verbose=4"]).arg(&exe).output().unwrap();
        assert!(output.status.success());
        let details = String::from_utf8_lossy(&output.stderr);
        let cdhash = details.lines().find_map(|line| line.strip_prefix("CDHash=")).unwrap();
        let dir = std::env::temp_dir().join(format!("cw-gateway-peer-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("peer.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let _client = UnixStream::connect(&path).unwrap();
        let (server, _) = listener.accept().unwrap();
        let uid = crate::effective_uid();
        let peer = platform::verify_peer(&server, uid, exe.to_str().unwrap(), &sha, cdhash).expect("signed kernel peer accepted");
        assert_eq!(peer.pid, std::process::id());
        assert!(platform::verify_peer(&server, 0, exe.to_str().unwrap(), &sha, cdhash).is_err());
        assert!(platform::verify_peer(&server, uid, exe.to_str().unwrap(), &sha, &"0".repeat(40)).is_err());
        assert!(platform::verify_peer(&server, uid, exe.to_str().unwrap(), &"0".repeat(64), cdhash).is_err());
        fs::remove_file(path).unwrap(); fs::remove_dir(dir).unwrap();
    }
}
