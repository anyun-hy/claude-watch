//! Narrow, safe OS boundary. Runtime policy and state machines remain unsafe-free.
pub mod network_events;
pub mod launchd_gateway;
pub mod application_locations;
pub mod anchored_files;

use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    os::unix::{io::AsRawFd, net::UnixStream},
    path::Path,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessKernelIdentity {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub start_seconds: u64,
    pub start_microseconds: u32,
    pub executable_path: String,
    pub audit_token: [u32; 8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPeerVerifier {
    pub expected_uid: u32,
    pub expected_helper_executable: String,
    pub expected_helper_sha256: String,
    pub expected_helper_cdhash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPeerIdentity {
    pub process: ProcessKernelIdentity,
    pub helper_sha256: String,
    pub helper_cdhash: String,
}
pub fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}
pub fn is_process_definitely_dead(pid: u32) -> bool {
    if pid == 0 {
        return true;
    }
    unsafe {
        if libc::kill(pid as i32, 0) == 0 {
            return false;
        }
        *libc::__error() == libc::ESRCH
    }
}
pub fn set_nonblocking(io: &impl AsRawFd) -> std::io::Result<()> {
    let fd = io.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
/// Caller must have spawned this live child with CommandExt::process_group(0).
/// Holding the unreaped child keeps its PID reserved while signalling its group.
pub fn terminate_owned_group(child: &std::process::Child) {
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
}
/// Sends SIGKILL to a verified process PID. Returns Ok(()) if the process was terminated
/// or was already dead (ESRCH).
pub fn kill_process(pid: u32) -> std::io::Result<()> {
    if pid == 0 {
        return Ok(());
    }
    unsafe {
        if libc::kill(pid as i32, libc::SIGKILL) != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            return Err(err);
        }
    }
    Ok(())
}

/// A request accepted by the kernel is not an exit receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundSignalResult { Sent, AlreadyExited, IdentityChanged, Failed }

pub fn signal_bound_process(expected: &ProcessKernelIdentity) -> BoundSignalResult {
    if expected.pid <= 1 || expected.pid > i32::MAX as u32 || expected.pid == std::process::id()
        || expected.uid != effective_uid()
    {
        return BoundSignalResult::IdentityChanged;
    }
    if bound_lifetime_exited(expected) { return BoundSignalResult::AlreadyExited; }
    let same = inspect_process_identity(expected.pid).is_some_and(|actual|
        actual.uid == expected.uid && actual.start_seconds == expected.start_seconds
        && actual.start_microseconds == expected.start_microseconds
        && actual.audit_token == expected.audit_token && actual.executable_path == expected.executable_path);
    if !same { return BoundSignalResult::IdentityChanged; }
    if unsafe { libc::kill(expected.pid as i32, libc::SIGKILL) } == 0 {
        BoundSignalResult::Sent
    } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        BoundSignalResult::AlreadyExited
    } else {
        BoundSignalResult::Failed
    }
}

/// Observe the bound lifetime without reaping someone else's child. A zombie
/// has exited even while its original parent still holds its PID.
pub fn bound_lifetime_exited(expected: &ProcessKernelIdentity) -> bool {
    if expected.pid <= 1 || expected.pid > i32::MAX as u32 { return false; }
    if is_process_definitely_dead(expected.pid) { return true; }
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info) as i32;
        if unsafe { libc::proc_pidinfo(expected.pid as i32, libc::PROC_PIDTBSDINFO, 0,
            (&mut info as *mut libc::proc_bsdinfo).cast(), size) } == size
        {
            return info.pbi_start_tvsec != expected.start_seconds
                || info.pbi_start_tvusec != u64::from(expected.start_microseconds)
                || (info.pbi_uid == expected.uid && info.pbi_status == 5 /* SZOMB */);
        }
        // libproc omits unreaped zombies on macOS. KERN_PROC_PID exposes
        // the exported extern_proc prefix even while the parent holds the PID.
        #[repr(C)]
        struct ProcPrefix {
            start: libc::timeval,
            vmspace: *mut libc::c_void,
            sigacts: *mut libc::c_void,
            flags: libc::c_int,
            status: libc::c_char,
            pid: libc::pid_t,
        }
        let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, expected.pid as i32];
        let mut bytes = [0u8; 4096];
        let mut size = bytes.len();
        if unsafe { libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, bytes.as_mut_ptr().cast(),
            &mut size, std::ptr::null_mut(), 0) } == 0 && size >= std::mem::size_of::<ProcPrefix>() {
            let info = unsafe { bytes.as_ptr().cast::<ProcPrefix>().read_unaligned() };
            if info.pid == expected.pid as i32 && info.status == 5
                && u64::try_from(info.start.tv_sec).ok() == Some(expected.start_seconds)
                && u32::try_from(info.start.tv_usec).ok() == Some(expected.start_microseconds)
            { return true; }
        }
    }
    is_process_definitely_dead(expected.pid)
}
/// Observe exit without reaping: keep the group leader's PID reserved until
/// its owned helper processes have also been signalled.
pub fn child_has_exited(child: &std::process::Child) -> std::io::Result<bool> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    #[cfg(target_os = "macos")]
    {
        Ok(info.si_pid != 0)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(unsafe { info.si_pid() } != 0)
    }
}

pub fn process_audit_token(pid: u32, uid: u32, seconds: u64, micros: u32, executable: &str) -> Option<[u32; 8]> {
    #[cfg(target_os = "macos")]
    { macos::process_token(pid, uid, seconds, micros, Some(executable)) }
    #[cfg(not(target_os = "macos"))]
    { let _ = (pid, uid, seconds, micros, executable); None }
}

/// Check liveness of an already kernel-bound member without weakening its
/// exec identity or needing a desktop window/executable path in the session.
pub fn process_audit_token_matches(pid: u32, uid: u32, seconds: u64, micros: u32, token: &[u32; 8]) -> bool {
    #[cfg(target_os = "macos")]
    { macos::process_token(pid, uid, seconds, micros, None).as_ref() == Some(token) }
    #[cfg(not(target_os = "macos"))]
    { let _ = (pid, uid, seconds, micros, token); false }
}

/// Check the kernel's per-lifetime exec flag, bound to the same audit token.
/// A child that execs the same interpreter is not a fork-only descendant.
pub fn bound_fork_only(process: &ProcessKernelIdentity) -> bool {
    #[cfg(target_os = "macos")]
    {
        if !process_audit_token_matches(process.pid, process.uid, process.start_seconds,
            process.start_microseconds, &process.audit_token) { return false; }
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info) as i32;
        (unsafe { libc::proc_pidinfo(process.pid as i32, libc::PROC_PIDTBSDINFO, 0,
            (&mut info as *mut libc::proc_bsdinfo).cast(), size) }) == size
            && info.pbi_flags & 0x4000 == 0 /* PROC_FLAG_EXEC */
            && info.pbi_uid == process.uid && info.pbi_start_tvsec == process.start_seconds
            && info.pbi_start_tvusec == u64::from(process.start_microseconds)
            && process_audit_token_matches(process.pid, process.uid, process.start_seconds,
                process.start_microseconds, &process.audit_token)
    }
    #[cfg(not(target_os = "macos"))]
    { let _ = process; false }
}

pub fn executable_cdhash(path: &Path) -> Option<[u8; 20]> {
    #[cfg(target_os = "macos")]
    { macos::static_cdhash(path) }
    #[cfg(not(target_os = "macos"))]
    { let _ = path; None }
}

pub fn bound_process_cdhash(process: &ProcessKernelIdentity) -> Option<[u8; 20]> {
    #[cfg(target_os = "macos")]
    { macos::loaded_cdhash(process) }
    #[cfg(not(target_os = "macos"))]
    { let _ = process; None }
}

/// Presentation-only lifetime correlation when an unlinked image no longer has
/// a readable path. This is not executable-file or sandbox/connection evidence.
pub fn process_lifetime_audit_digest_matches(pid: u32, uid: u32, seconds: u64, micros: u32, digest: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        if digest.len() != 64 { return false; }
        macos::process_token(pid, uid, seconds, micros, None).is_some_and(|token| {
            let bytes = token.iter().map(u32::to_string).collect::<Vec<_>>().join(":");
            sha256_bytes_hex(bytes.as_bytes()) == digest
        })
    }
    #[cfg(not(target_os = "macos"))]
    { let _ = (pid, uid, seconds, micros, digest); false }
}

pub fn inspect_process_identity(pid: u32) -> Option<ProcessKernelIdentity> {
    #[cfg(target_os = "macos")]
    {
        macos::inspect_process(pid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        None
    }
}

/// Locale-independent `ps lstart` representation of an already verified birth
/// time. Formatting does not discover processes or establish an identity.
pub fn process_start_stamp(seconds: u64) -> Option<String> {
    let seconds = libc::time_t::try_from(seconds).ok()?;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&seconds, &mut tm) }.is_null() { return None; }
    let day = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].get(usize::try_from(tm.tm_wday).ok()?)?;
    let month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].get(usize::try_from(tm.tm_mon).ok()?)?;
    Some(format!("{day} {month} {} {:02}:{:02}:{:02} {}", tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_year + 1900))
}

pub fn verify_sandbox_helper_peer(
    stream: &UnixStream,
    verifier: &SandboxPeerVerifier,
) -> Option<SandboxPeerIdentity> {
    #[cfg(target_os = "macos")]
    {
        macos::verify_sandbox_peer(stream.as_raw_fd(), verifier)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (stream, verifier);
        None
    }
}

pub const MAX_TCP_PEER_CANDIDATES: usize = 2048;
pub fn attribute_loopback_tcp_peer(
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    candidate_pids: &[u32],
) -> Option<ProcessKernelIdentity> {
    #[cfg(target_os = "macos")]
    {
        macos::attribute_tcp_socket(peer_addr, local_addr, candidate_pids)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (peer_addr, local_addr, candidate_pids);
        None
    }
}

/// Discovers the live process owning a local TCP listener on `listener_addr`
/// (`127.0.0.1:<port>` or `[::1]:<port>`), returning its verified kernel identity.
pub fn inspect_loopback_tcp_listener(listener_addr: SocketAddr) -> Option<ProcessKernelIdentity> {
    #[cfg(target_os = "macos")]
    {
        macos::inspect_tcp_listener(listener_addr)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = listener_addr;
        None
    }
}

/// Start time `(seconds, microseconds)` of a live process owned by any user,
/// read via `KERN_PROC_PID` (which macOS exposes without privileges). Used to
/// anchor the lifetime of a VPN core started by a root privileged helper, which
/// same-UID libproc/task inspection cannot read. This is a lifetime anchor
/// only, not an executable or audit-token identity.
pub fn process_start_time_any_user(pid: u32) -> Option<(u64, u32)> {
    #[cfg(target_os = "macos")]
    {
        macos::sysctl_process_start(pid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        None
    }
}

/// Lists all current user-space descendant PIDs whose parent or ancestor is in `root_pids`.
pub fn list_descendant_pids(root_pids: &[u32], expected_uid: u32) -> Vec<u32> {
    #[cfg(target_os = "macos")]
    {
        macos::list_descendants(root_pids, expected_uid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (root_pids, expected_uid);
        Vec::new()
    }
}

/// Lists all current user-space PIDs owned by `expected_uid`.
pub fn list_user_pids(expected_uid: u32) -> Vec<u32> {
    #[cfg(target_os = "macos")]
    {
        macos::list_all_user_pids(expected_uid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = expected_uid;
        Vec::new()
    }
}

/// Applies an irreversible macOS Seatbelt (`sandbox_init`) profile in the current
/// helper process immediately prior to `execvp`.
pub fn apply_macos_seatbelt_profile(profile_sbpl: &str) -> std::result::Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        macos::apply_seatbelt(profile_sbpl)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = profile_sbpl;
        Err("seatbelt_unsupported_os".into())
    }
}

pub fn sha256_file_hex(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(sha256_bytes_hex(&bytes))
}

pub fn sha256_bytes_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Posts a best-effort Darwin notification without creating a child process.
/// Success means the notification service accepted the post, not that a listener handled it.
pub fn post_darwin_notification(name: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let name = std::ffi::CString::new(name)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        // SAFETY: CString keeps the nul-terminated name alive for the synchronous call.
        let status = unsafe { notify_post(name.as_ptr()) };
        if status == 0 {
            Ok(())
        } else {
            // Darwin notification status codes are not errno values.
            Err(std::io::Error::other(format!("notify_post failed with status {status}")))
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = name;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Darwin notifications require macOS",
        ))
    }
}

// Shared Darwin notification boundary for posting and the network event watcher.
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn notify_post(name: *const std::ffi::c_char) -> u32;
    fn notify_register_file_descriptor(
        name: *const std::ffi::c_char,
        fd: *mut i32,
        flags: i32,
        token: *mut i32,
    ) -> u32;
    fn notify_cancel(token: i32) -> u32;
}

#[cfg(test)]
mod tests {
    #[test]
    fn sha256_standard_vectors() {
        for (input, expected) in [
            ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        ] {
            assert_eq!(super::sha256_bytes_hex(input.as_bytes()), expected);
        }
        assert_eq!(super::sha256_bytes_hex(&vec![b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    #[test]
    fn sha256_padding_and_block_boundaries() {
        // Fixed references for repeated ASCII 'a', independently checked with Python hashlib.
        for (length, expected) in [
            (55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"),
            (56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"),
            (63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"),
            (64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"),
            (65, "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"),
        ] {
            assert_eq!(super::sha256_bytes_hex(&vec![b'a'; length]), expected, "length={length}");
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn darwin_notification_posts_reach_the_existing_watcher() {
        use super::network_events::{NetworkEventKind, NetworkEventWatcher};
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let name = format!("io.local.claudewatch.test.native-notification.{}.{nonce}", std::process::id());
        let mut watcher = NetworkEventWatcher::new(&[&name]);
        // Darwin notifications may coalesce. Every burst must still wake the subscriber.
        for _ in 0..16 {
            for _ in 0..64 {
                super::post_darwin_notification(&name).unwrap();
            }
            assert!(watcher.wait(Duration::from_secs(1)).contains(
                &NetworkEventKind::DarwinNotification(name.clone())));
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn darwin_notification_rejects_embedded_nul() {
        let error = super::post_darwin_notification("io.local.claudewatch.test\0invalid").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn sysctl_start_time_matches_libproc_for_self() {
        let pid = std::process::id();
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info) as i32;
        assert_eq!(unsafe { libc::proc_pidinfo(pid as i32, libc::PROC_PIDTBSDINFO, 0,
            (&mut info as *mut libc::proc_bsdinfo).cast(), size) }, size);
        assert_eq!(super::macos::sysctl_process_start(pid),
            Some((info.pbi_start_tvsec, info.pbi_start_tvusec as u32)));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn process_token_is_kernel_bound_to_birth_uid_and_executable() {
        let pid = std::process::id();
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of_val(&info) as i32;
        assert_eq!(unsafe { libc::proc_pidinfo(pid as i32, libc::PROC_PIDTBSDINFO, 0,
            (&mut info as *mut libc::proc_bsdinfo).cast(), size) }, size);
        let path = std::env::current_exe().unwrap();
        let path = path.to_str().unwrap();
        let get = |uid, seconds, executable| super::process_audit_token(pid, uid,
            seconds, info.pbi_start_tvusec as u32, executable);
        let token = get(info.pbi_uid, info.pbi_start_tvsec, path).expect("actual self audit identity");
        assert_eq!(token[5], pid);
        assert_eq!(token[1], info.pbi_uid);
        assert!(super::process_audit_token_matches(pid, info.pbi_uid, info.pbi_start_tvsec, info.pbi_start_tvusec as u32, &token));
        let mut stale = token; stale[7] = stale[7].wrapping_add(1);
        assert!(!super::process_audit_token_matches(pid, info.pbi_uid, info.pbi_start_tvsec, info.pbi_start_tvusec as u32, &stale));
        assert!(get(info.pbi_uid, info.pbi_start_tvsec + 1, path).is_none());
        assert!(get(info.pbi_uid + 1, info.pbi_start_tvsec, path).is_none());
        assert!(get(info.pbi_uid, info.pbi_start_tvsec, "/not-this-executable").is_none());
    }
    #[test]
    #[cfg(target_os = "macos")]
    fn sandbox_helper_peer_and_tcp_socket_attribution_verify_live_kernel_identity() {
        let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let exe_str = exe.to_str().unwrap().to_owned();
        let sha = super::sha256_file_hex(&exe).unwrap();
        let uid = super::effective_uid();
        let pid = std::process::id();

        let (s1, s2) = std::os::unix::net::UnixStream::pair().unwrap();
        let verifier = super::SandboxPeerVerifier {
            expected_uid: uid,
            expected_helper_executable: exe_str.clone(),
            expected_helper_sha256: sha.clone(),
            expected_helper_cdhash: super::executable_cdhash(&exe).unwrap().iter()
                .map(|byte| format!("{byte:02x}")).collect(),
        };
        assert!(super::verify_sandbox_helper_peer(&s1, &verifier).is_none(),
            "the default un-hardened test process must be rejected even with matching pins");

        // Wrong sha256 or wrong executable is rejected
        let mut bad_verifier = verifier.clone();
        bad_verifier.expected_helper_sha256 = "0".repeat(64);
        assert!(super::verify_sandbox_helper_peer(&s1, &bad_verifier).is_none());
        drop(s2);

        // Live loopback TCP tuple attribution
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(local_addr).unwrap();
        let client_addr = client.local_addr().unwrap();
        let (_accepted, peer_addr) = listener.accept().unwrap();
        assert_eq!(client_addr, peer_addr);

        let attributed =
            super::attribute_loopback_tcp_peer(peer_addr, local_addr, &[pid]).expect("attributed");
        assert_eq!(attributed.pid, pid);
        assert_eq!(attributed.uid, uid);
        assert_eq!(attributed.executable_path, exe_str);

        // Non-matching candidate PID cannot claim the TCP tuple
        assert!(super::attribute_loopback_tcp_peer(peer_addr, local_addr, &[1]).is_none());
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::{
        ffi::{c_char, c_void, CString},
        ptr,
    };
    type Ref = *const c_void;
    unsafe extern "C" {
        static mach_task_self_: u32;
        fn task_name_for_pid(task: u32, pid: i32, name: *mut u32) -> i32;
        fn mach_port_deallocate(task: u32, name: u32) -> i32;
        fn proc_pidpath_audittoken(token: *mut [u32; 8], path: *mut c_void, size: u32) -> i32;
        fn sandbox_init(
            profile: *const c_char,
            flags: u64,
            errorbuf: *mut *mut c_char,
        ) -> i32;
        fn sandbox_free_error(errorbuf: *mut c_char);
        fn csops_audittoken(pid: i32, ops: u32, value: *mut c_void, size: usize, token: *mut [u32; 8]) -> i32;
    }
    pub fn apply_seatbelt(profile_sbpl: &str) -> std::result::Result<(), String> {
        let c_profile = CString::new(profile_sbpl)
            .map_err(|_| "invalid_seatbelt_profile_nul".to_string())?;
        unsafe {
            let mut err_buf: *mut c_char = ptr::null_mut();
            let rc = sandbox_init(c_profile.as_ptr(), 0, &mut err_buf);
            if rc != 0 {
                let msg = if !err_buf.is_null() {
                    let text = std::ffi::CStr::from_ptr(err_buf)
                        .to_string_lossy()
                        .into_owned();
                    sandbox_free_error(err_buf);
                    text
                } else {
                    format!("sandbox_init_rc_{rc}")
                };
                return Err(msg);
            }
        }
        Ok(())
    }
    fn raw_process_token(pid: u32) -> Option<[u32; 8]> {
        if pid <= 1 || pid > i32::MAX as u32 { return None; }
        unsafe {
            let mut task = 0;
            if task_name_for_pid(mach_task_self_, pid as i32, &mut task) != 0 { return None; }
            let mut words = [0u32; 8];
            let mut count = 8;
            let result = libc::task_info(task, 15, words.as_mut_ptr().cast(), &mut count);
            mach_port_deallocate(mach_task_self_, task);
            (result == 0 && count == 8 && words[5] == pid).then_some(words)
        }
    }
    pub fn process_token(pid: u32, uid: u32, seconds: u64, micros: u32, executable: Option<&str>) -> Option<[u32; 8]> {
        let before = raw_process_token(pid)?;
        if before[1] != uid { return None; }
        unsafe {
            let mut info: libc::proc_bsdinfo = std::mem::zeroed();
            let size = std::mem::size_of_val(&info) as i32;
            if libc::proc_pidinfo(pid as i32, libc::PROC_PIDTBSDINFO, 0, (&mut info as *mut libc::proc_bsdinfo).cast(), size) != size
                || info.pbi_uid != uid || info.pbi_start_tvsec != seconds || info.pbi_start_tvusec != micros as u64 { return None; }
            if let Some(executable) = executable {
                let mut path = [0i8; 4096];
                let mut token = before;
                if proc_pidpath_audittoken(&mut token, path.as_mut_ptr().cast(), path.len() as u32) <= 0
                    || std::ffi::CStr::from_ptr(path.as_ptr()).to_str().ok()? != executable { return None; }
            }
            if raw_process_token(pid)? != before { return None; }
        }
        Some(before)
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFRelease(value: Ref);
        fn CFURLCreateFromFileSystemRepresentation(allocator: Ref, path: *const u8, len: isize, directory: bool) -> Ref;
        fn CFDictionaryGetValue(dictionary: Ref, key: Ref) -> Ref;
        fn CFDataGetLength(data: Ref) -> isize;
        fn CFDataGetBytePtr(data: Ref) -> *const u8;
    }
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecCodeInfoUnique: Ref;
        fn SecStaticCodeCreateWithPath(path: Ref, flags: u32, code: *mut Ref) -> i32;
        fn SecCodeCopySigningInformation(code: Ref, flags: u32, info: *mut Ref) -> i32;
    }
    pub fn static_cdhash(path: &std::path::Path) -> Option<[u8; 20]> {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        unsafe {
            let url = Owned(CFURLCreateFromFileSystemRepresentation(ptr::null(), bytes.as_ptr(), bytes.len() as isize, false));
            if url.0.is_null() { return None; }
            let mut code = ptr::null();
            if SecStaticCodeCreateWithPath(url.0, 0, &mut code) != 0 || code.is_null() { return None; }
            let code = Owned(code);
            let mut info = ptr::null();
            if SecCodeCopySigningInformation(code.0, 0, &mut info) != 0 || info.is_null() { return None; }
            let info = Owned(info);
            let data = CFDictionaryGetValue(info.0, kSecCodeInfoUnique);
            if data.is_null() || CFDataGetLength(data) != 20 { return None; }
            let p = CFDataGetBytePtr(data);
            if p.is_null() { return None; }
            std::slice::from_raw_parts(p, 20).try_into().ok()
        }
    }
    pub fn loaded_cdhash(process: &super::ProcessKernelIdentity) -> Option<[u8; 20]> {
        let mut token = process.audit_token;
        if process_token(process.pid, process.uid, process.start_seconds, process.start_microseconds,
            Some(&process.executable_path))? != token { return None; }
        let mut bytes = [0u8; 20];
        // XNU CS_OPS_CDHASH reads the currently loaded code directory.
        if unsafe { csops_audittoken(process.pid as i32, 5, bytes.as_mut_ptr().cast(), bytes.len(), &mut token) } != 0
            || raw_process_token(process.pid)? != process.audit_token
        { return None; }
        Some(bytes)
    }
    struct Owned(Ref);
    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0) };
            }
        }
    }
    pub fn inspect_process(pid: u32) -> Option<super::ProcessKernelIdentity> {
        let before = raw_process_token(pid)?;
        unsafe {
            let mut info: libc::proc_bsdinfo = std::mem::zeroed();
            let size = std::mem::size_of_val(&info) as i32;
            if libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            ) != size
            {
                return None;
            }
            if info.pbi_uid == 0 || before[1] != info.pbi_uid || before[5] != pid {
                return None;
            }
            let mut path = [0i8; 4096];
            let mut token = before;
            if proc_pidpath_audittoken(&mut token, path.as_mut_ptr().cast(), path.len() as u32) <= 0
            {
                return None;
            }
            let raw_exe = std::ffi::CStr::from_ptr(path.as_ptr()).to_str().ok()?;
            let canonical_exe = std::fs::canonicalize(raw_exe)
                .ok()
                .and_then(|p| p.to_str().map(str::to_owned))
                .unwrap_or_else(|| raw_exe.to_owned());
            if raw_process_token(pid)? != before {
                return None;
            }
            Some(super::ProcessKernelIdentity {
                pid,
                ppid: info.pbi_ppid,
                uid: info.pbi_uid,
                start_seconds: info.pbi_start_tvsec,
                start_microseconds: info.pbi_start_tvusec as u32,
                executable_path: canonical_exe,
                audit_token: before,
            })
        }
    }

    pub fn verify_sandbox_peer(
        fd: i32,
        verifier: &super::SandboxPeerVerifier,
    ) -> Option<super::SandboxPeerIdentity> {
        if verifier.expected_uid == 0
            || verifier.expected_helper_executable.trim().is_empty()
            || verifier.expected_helper_sha256.len() != 64
            || verifier.expected_helper_cdhash.len() != 40
        {
            return None;
        }
        let mut token = [0u32; 8];
        let mut len = std::mem::size_of_val(&token) as libc::socklen_t;
        if unsafe { libc::getsockopt(fd, 0, 0x006, token.as_mut_ptr().cast(), &mut len) } != 0
            || len as usize != std::mem::size_of_val(&token)
        {
            return None;
        }
        let pid = token[5];
        let euid = token[1];
        if pid <= 1 || euid != verifier.expected_uid {
            return None;
        }
        let proc_id = inspect_process(pid)?;
        if proc_id.audit_token != token || proc_id.uid != verifier.expected_uid {
            return None;
        }
        let expected_canonical = std::fs::canonicalize(&verifier.expected_helper_executable)
            .ok()
            .and_then(|p| p.to_str().map(str::to_owned))
            .unwrap_or_else(|| verifier.expected_helper_executable.clone());
        if proc_id.executable_path != expected_canonical {
            return None;
        }
        let actual_sha =
            super::sha256_file_hex(std::path::Path::new(&proc_id.executable_path))?;
        if actual_sha != verifier.expected_helper_sha256 {
            return None;
        }
        super::launchd_gateway::verify_hardened_peer_code(token, &verifier.expected_helper_cdhash).ok()?;
        // Re-check process token after file read & code check so no exec/race occurred
        if raw_process_token(pid)? != token {
            return None;
        }
        Some(super::SandboxPeerIdentity {
            process: proc_id,
            helper_sha256: actual_sha,
            helper_cdhash: verifier.expected_helper_cdhash.clone(),
        })
    }

    pub fn attribute_tcp_socket(
        peer_addr: std::net::SocketAddr,
        local_addr: std::net::SocketAddr,
        candidate_pids: &[u32],
    ) -> Option<super::ProcessKernelIdentity> {
        if !peer_addr.ip().is_loopback()
            || !local_addr.ip().is_loopback()
            || peer_addr.port() == 0
            || local_addr.port() == 0
            || candidate_pids.len() > super::MAX_TCP_PEER_CANDIDATES
        {
            return None;
        }
        let mut unique_pids: Vec<u32> = candidate_pids
            .iter()
            .copied()
            .filter(|&pid| pid > 1 && pid <= i32::MAX as u32)
            .collect();
        unique_pids.sort_unstable();
        unique_pids.dedup();
        if unique_pids.is_empty() {
            return None;
        }
        let mut matched_identities = Vec::new();
        let mut remaining_fds = 32 * 1024;
        for pid in unique_pids {
            if pid_owns_tcp_tuple(pid as i32, peer_addr, local_addr, &mut remaining_fds)? {
                if let Some(identity) = inspect_process(pid) {
                    // Re-verify full 4-tuple ownership after capturing kernel audit token
                    if pid_owns_tcp_tuple(pid as i32, peer_addr, local_addr, &mut remaining_fds)? {
                        matched_identities.push(identity);
                        if matched_identities.len() > 1 { return None; }
                    }
                }
            }
        }
        if matched_identities.len() == 1 {
            matched_identities.pop()
        } else {
            None
        }
    }

    pub fn inspect_tcp_listener(
        listener_addr: std::net::SocketAddr,
    ) -> Option<super::ProcessKernelIdentity> {
        if !listener_addr.ip().is_loopback() || listener_addr.port() == 0 {
            return None;
        }
        let uid = super::effective_uid();
        let pids = list_all_user_pids(uid);
        for pid in pids {
            if pid <= 1 || pid > i32::MAX as u32 {
                continue;
            }
            if pid_owns_tcp_listener(pid as i32, listener_addr) {
                if let Some(identity) = inspect_process(pid) {
                    if pid_owns_tcp_listener(pid as i32, listener_addr) {
                        return Some(identity);
                    }
                }
            }
        }
        None
    }

    /// Start time of any live (non-zombie) process via `KERN_PROC_PID`.
    pub fn sysctl_process_start(pid: u32) -> Option<(u64, u32)> {
        if pid <= 1 || pid > i32::MAX as u32 {
            return None;
        }
        // Exported `extern_proc` prefix: `p_un.p_starttime`, two pointers,
        // `p_flag`, `p_stat`, `p_pid` (same layout as `bound_lifetime_exited`).
        #[repr(C)]
        struct ProcPrefix {
            start: libc::timeval,
            vmspace: *mut libc::c_void,
            sigacts: *mut libc::c_void,
            flags: libc::c_int,
            status: libc::c_char,
            pid: libc::pid_t,
        }
        let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid as i32];
        let mut bytes = [0u8; 4096];
        let mut size = bytes.len();
        if unsafe {
            libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, bytes.as_mut_ptr().cast(),
                &mut size, ptr::null_mut(), 0)
        } != 0
            || size < std::mem::size_of::<ProcPrefix>()
        {
            return None;
        }
        let info = unsafe { bytes.as_ptr().cast::<ProcPrefix>().read_unaligned() };
        if info.pid != pid as i32 || info.status == 5 /* SZOMB */ {
            return None;
        }
        let seconds = u64::try_from(info.start.tv_sec).ok().filter(|v| *v > 0)?;
        let micros = u32::try_from(info.start.tv_usec).ok().filter(|v| *v < 1_000_000)?;
        Some((seconds, micros))
    }

    pub fn list_descendants(root_pids: &[u32], expected_uid: u32) -> Vec<u32> {
        if root_pids.is_empty() || expected_uid == 0 {
            return Vec::new();
        }
        let all_pids = list_all_user_pids(expected_uid);
        let mut parent_map = std::collections::BTreeMap::new();
        for pid in all_pids {
            if pid <= 1 || pid > i32::MAX as u32 {
                continue;
            }
            unsafe {
                let mut info: libc::proc_bsdinfo = std::mem::zeroed();
                let size = std::mem::size_of_val(&info) as i32;
                if libc::proc_pidinfo(
                    pid as i32,
                    libc::PROC_PIDTBSDINFO,
                    0,
                    (&mut info as *mut libc::proc_bsdinfo).cast(),
                    size,
                ) == size
                    && info.pbi_uid == expected_uid
                {
                    parent_map.insert(pid, info.pbi_ppid);
                }
            }
        }
        let mut frontier: std::collections::BTreeSet<u32> =
            root_pids.iter().copied().filter(|&p| p > 1).collect();
        let mut descendants = std::collections::BTreeSet::new();
        loop {
            let mut added = false;
            for (&pid, &ppid) in &parent_map {
                if frontier.contains(&ppid) && !frontier.contains(&pid) {
                    frontier.insert(pid);
                    descendants.insert(pid);
                    added = true;
                }
            }
            if !added {
                break;
            }
        }
        descendants.into_iter().collect()
    }

    pub fn list_all_user_pids(expected_uid: u32) -> Vec<u32> {
        const PROC_ALL_PIDS: u32 = 1;
        unsafe {
            let byte_count = libc::proc_listpids(PROC_ALL_PIDS, 0, ptr::null_mut(), 0);
            if byte_count <= 0 {
                return Vec::new();
            }
            let cap = (byte_count as usize / std::mem::size_of::<i32>()).max(64) + 64;
            let mut buf = vec![0i32; cap];
            let actual = libc::proc_listpids(
                PROC_ALL_PIDS,
                0,
                buf.as_mut_ptr().cast(),
                (cap * std::mem::size_of::<i32>()) as i32,
            );
            if actual <= 0 {
                return Vec::new();
            }
            let len = actual as usize / std::mem::size_of::<i32>();
            let mut out = Vec::new();
            for &pid in buf.iter().take(len) {
                if pid <= 1 {
                    continue;
                }
                let mut info: libc::proc_bsdinfo = std::mem::zeroed();
                let size = std::mem::size_of_val(&info) as i32;
                if libc::proc_pidinfo(
                    pid,
                    libc::PROC_PIDTBSDINFO,
                    0,
                    (&mut info as *mut libc::proc_bsdinfo).cast(),
                    size,
                ) == size
                    && info.pbi_uid == expected_uid
                {
                    out.push(pid as u32);
                }
            }
            out
        }
    }

    const PROC_PIDFDSOCKETINFO: i32 = 3;
    const SOCKINFO_TCP: i32 = 2;
    const INI_IPV4: u8 = 0x1;
    const INI_IPV6: u8 = 0x2;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProcFileInfo {
        fi_openflags: u32,
        fi_status: u32,
        fi_offset: i64,
        fi_type: i32,
        fi_guardflags: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct VinfoStat {
        vst_dev: u32,
        vst_mode: u16,
        vst_nlink: u16,
        vst_ino: u64,
        vst_uid: u32,
        vst_gid: u32,
        vst_atime: i64,
        vst_atimensec: i64,
        vst_mtime: i64,
        vst_mtimensec: i64,
        vst_ctime: i64,
        vst_ctimensec: i64,
        vst_birthtime: i64,
        vst_birthtimensec: i64,
        vst_size: i64,
        vst_blocks: i64,
        vst_blksize: i32,
        vst_flags: u32,
        vst_gen: u32,
        vst_rdev: u32,
        vst_qspare: [i64; 2],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockbufInfo {
        sbi_cc: u32,
        sbi_hiwat: u32,
        sbi_mbcnt: u32,
        sbi_mbmax: u32,
        sbi_lowat: u32,
        sbi_flags: i16,
        sbi_timeo: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct InSockInfo {
        insi_fport: i32,
        insi_lport: i32,
        insi_gencnt: u64,
        insi_flags: u32,
        insi_flow: u32,
        insi_vflag: u8,
        insi_ip_ttl: u8,
        rfu_1: u32,
        insi_faddr: [u8; 16],
        insi_laddr: [u8; 16],
        insi_v4_tos: u8,
        insi_v4_pad: [u8; 3],
        insi_v6_hlim: u8,
        insi_v6_pad: [u8; 3],
        insi_v6_cksum: u32,
        insi_v6_ifindex: u16,
        insi_v6_hops: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SocketInfo {
        soi_stat: VinfoStat,
        soi_so: u64,
        soi_pcb: u64,
        soi_type: i32,
        soi_protocol: i32,
        soi_family: i32,
        soi_options: i16,
        soi_linger: i16,
        soi_state: i16,
        soi_qlen: i16,
        soi_incqlen: i16,
        soi_qlimit: i16,
        soi_timeo: i16,
        soi_error: u16,
        soi_oobmark: u32,
        soi_rcv: SockbufInfo,
        soi_snd: SockbufInfo,
        soi_kind: i32,
        rfu_1: u32,
        soi_proto_ini: InSockInfo,
        soi_proto_tail: [u8; 528 - std::mem::size_of::<InSockInfo>()],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SocketFdInfo {
        pfi: ProcFileInfo,
        psi: SocketInfo,
    }

    /// Narrow descriptor inspection for the launchd broker. The stat fields
    /// in PROC_PIDFDSOCKETINFO are not socket credentials (they can be zero).
    pub(super) fn own_socket_properties(fd: i32) -> Option<(i32, i32, i32, u16)> {
        unsafe {
            let mut info: SocketFdInfo = std::mem::zeroed();
            let size = std::mem::size_of_val(&info) as i32;
            if libc::proc_pidfdinfo(libc::getpid(), fd, PROC_PIDFDSOCKETINFO,
                (&mut info as *mut SocketFdInfo).cast(), size) != size { return None; }
            Some((info.psi.soi_kind, info.psi.soi_type, info.psi.soi_protocol,
                info.psi.soi_options as u16))
        }
    }

    fn addr_bytes_match(vflag: u8, addr_union: &[u8; 16], expected: std::net::IpAddr) -> bool {
        match expected {
            std::net::IpAddr::V4(v4) => {
                if (vflag & INI_IPV4) != 0 {
                    // `in4in6_addr`: 12 bytes of padding (`i46a_pad32[3]`) followed by 4 bytes of `in_addr`
                    &addr_union[12..16] == v4.octets().as_slice()
                } else if (vflag & INI_IPV6) != 0 {
                    // IPv4-mapped IPv6 address `::ffff:a.b.c.d`
                    addr_union[0..10].iter().all(|&b| b == 0)
                        && addr_union[10] == 0xff
                        && addr_union[11] == 0xff
                        && &addr_union[12..16] == v4.octets().as_slice()
                } else {
                    false
                }
            }
            std::net::IpAddr::V6(v6) => {
                (vflag & INI_IPV6) != 0 && addr_union == &v6.octets()
            }
        }
    }

    fn listener_addr_matches(vflag: u8, addr_union: &[u8; 16], expected: std::net::IpAddr) -> bool {
        if addr_bytes_match(vflag, addr_union, expected) {
            return true;
        }
        // Also match wildcard bind (`0.0.0.0` or `::`) when listener serves loopback
        addr_union.iter().all(|&b| b == 0)
    }

    fn pid_owns_tcp_tuple(
        pid: i32,
        expected_local: std::net::SocketAddr,
        expected_foreign: std::net::SocketAddr,
        remaining_fds: &mut usize,
    ) -> Option<bool> {
        let expected_lport_be = i32::from(expected_local.port().to_be());
        let expected_fport_be = i32::from(expected_foreign.port().to_be());
        unsafe {
            let byte_capacity = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                ptr::null_mut(),
                0,
            );
            if byte_capacity <= 0 {
                return Some(false);
            }
            let fd_size = std::mem::size_of::<libc::proc_fdinfo>() as i32;
            let count = (byte_capacity / fd_size).max(16) as usize + 16;
            // Refuse an incomplete attribution search; truncating the
            // candidates could accept a tuple with ambiguous ownership.
            if count > 8192 || count > *remaining_fds { return None; }
            *remaining_fds -= count;
            let mut fds = vec![
                libc::proc_fdinfo {
                    proc_fd: 0,
                    proc_fdtype: 0
                };
                count
            ];
            let actual_bytes = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr().cast(),
                (count * std::mem::size_of::<libc::proc_fdinfo>()) as i32,
            );
            if actual_bytes <= 0 {
                return Some(false);
            }
            let actual_len = (actual_bytes / fd_size) as usize;
            if actual_len >= count { return None; }
            let sock_info_size = std::mem::size_of::<SocketFdInfo>() as i32;
            for item in fds.iter().take(actual_len) {
                if item.proc_fdtype != libc::PROX_FDTYPE_SOCKET as u32 {
                    continue;
                }
                let mut sock_info: SocketFdInfo = std::mem::zeroed();
                let got = libc::proc_pidfdinfo(
                    pid,
                    item.proc_fd,
                    PROC_PIDFDSOCKETINFO,
                    (&mut sock_info as *mut SocketFdInfo).cast(),
                    sock_info_size,
                );
                if got != sock_info_size {
                    continue;
                }
                if sock_info.psi.soi_kind != SOCKINFO_TCP
                    || sock_info.psi.soi_type != libc::SOCK_STREAM
                    || sock_info.psi.soi_protocol != libc::IPPROTO_TCP
                {
                    continue;
                }
                let ini = sock_info.psi.soi_proto_ini;
                if ini.insi_lport == expected_lport_be
                    && ini.insi_fport == expected_fport_be
                    && addr_bytes_match(ini.insi_vflag, &ini.insi_laddr, expected_local.ip())
                    && addr_bytes_match(ini.insi_vflag, &ini.insi_faddr, expected_foreign.ip())
                {
                    return Some(true);
                }
            }
            Some(false)
        }
    }

    fn pid_owns_tcp_listener(pid: i32, expected_listener: std::net::SocketAddr) -> bool {
        let expected_lport_be = i32::from(expected_listener.port().to_be());
        unsafe {
            let byte_capacity = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                ptr::null_mut(),
                0,
            );
            if byte_capacity <= 0 {
                return false;
            }
            let fd_size = std::mem::size_of::<libc::proc_fdinfo>() as i32;
            let count = (byte_capacity / fd_size).max(16) as usize + 16;
            let mut fds = vec![
                libc::proc_fdinfo {
                    proc_fd: 0,
                    proc_fdtype: 0
                };
                count
            ];
            let actual_bytes = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr().cast(),
                (count * std::mem::size_of::<libc::proc_fdinfo>()) as i32,
            );
            if actual_bytes <= 0 {
                return false;
            }
            let actual_len = (actual_bytes / fd_size) as usize;
            let sock_info_size = std::mem::size_of::<SocketFdInfo>() as i32;
            for item in fds.iter().take(actual_len) {
                if item.proc_fdtype != libc::PROX_FDTYPE_SOCKET as u32 {
                    continue;
                }
                let mut sock_info: SocketFdInfo = std::mem::zeroed();
                let got = libc::proc_pidfdinfo(
                    pid,
                    item.proc_fd,
                    PROC_PIDFDSOCKETINFO,
                    (&mut sock_info as *mut SocketFdInfo).cast(),
                    sock_info_size,
                );
                if got != sock_info_size {
                    continue;
                }
                if sock_info.psi.soi_kind != SOCKINFO_TCP
                    || sock_info.psi.soi_type != libc::SOCK_STREAM
                    || sock_info.psi.soi_protocol != libc::IPPROTO_TCP
                {
                    continue;
                }
                let ini = sock_info.psi.soi_proto_ini;
                if ini.insi_lport == expected_lport_be
                    && ini.insi_fport == 0
                    && listener_addr_matches(
                        ini.insi_vflag,
                        &ini.insi_laddr,
                        expected_listener.ip(),
                    )
                {
                    return true;
                }
            }
            false
        }
    }
}
