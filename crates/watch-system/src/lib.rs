//! Narrow, safe OS boundary. Runtime policy and state machines remain unsafe-free.
use std::os::unix::{io::AsRawFd, net::UnixStream};
pub fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
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

/// TCP headers cannot establish the forwarding process. Only a connected Unix
/// socket's kernel audit token, validated by Security.framework, can do so.
pub fn is_authenticated_extension(stream: &UnixStream) -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::verify(stream.as_raw_fd())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = stream;
        false
    }
}

/// Never accept a team supplied by a peer or a user-writable configuration.
pub fn extension_peer_requirement(team: &str) -> Option<String> {
    (team.len() == 10 && team.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()))
        .then(|| format!("anchor apple generic and identifier \"io.local.watchpanel.network-extension\" and certificate leaf[subject.OU] = \"{team}\""))
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

/// Darwin notifications wake the consumer on execution receipts; the bounded
/// timeout also drives liveness expiry when the producer has stopped entirely.
pub struct ObservationSignal {
    fd: i32,
    token: i32,
}
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn notify_register_file_descriptor(
        name: *const std::ffi::c_char,
        fd: *mut i32,
        flags: i32,
        token: *mut i32,
    ) -> u32;
    fn notify_cancel(token: i32) -> u32;
}
impl ObservationSignal {
    pub fn new() -> Self {
        let mut value = Self { fd: -1, token: -1 };
        #[cfg(target_os = "macos")]
        unsafe {
            let status = notify_register_file_descriptor(
                c"io.local.claudewatch.extension-observation".as_ptr(),
                &mut value.fd,
                0,
                &mut value.token,
            );
            if status != 0 {
                // On failure the API may have already closed the output FD.
                // It is not ours to read/close; another thread can reuse it.
                value.fd = -1;
                value.token = -1;
            } else if libc::fcntl(value.fd, libc::F_SETFL, libc::O_NONBLOCK) < 0 {
                notify_cancel(value.token);
                value.fd = -1;
                value.token = -1;
            }
        }
        value
    }
    pub fn wait(&mut self, timeout: std::time::Duration) {
        if self.fd < 0 {
            std::thread::sleep(timeout);
            return;
        }
        let mut fd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe {
            if libc::poll(&mut fd, 1, timeout.as_millis().min(i32::MAX as u128) as i32) <= 0
                || fd.revents & libc::POLLIN == 0
            {
                return;
            }
            let mut bytes = [0u8; 256];
            while libc::read(self.fd, bytes.as_mut_ptr().cast(), bytes.len()) > 0 {}
        }
    }
}
impl Drop for ObservationSignal {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        // notify_cancel owns closing its FD. A separate close races FD reuse.
        if self.token >= 0 {
            unsafe {
                notify_cancel(self.token);
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
    fn peer_requirement_pins_the_validated_team_and_rejects_injection() {
        let requirement = super::extension_peer_requirement("ABCDE12345").unwrap();
        assert!(requirement.contains("identifier \"io.local.watchpanel.network-extension\""));
        assert!(requirement.contains("certificate leaf[subject.OU] = \"ABCDE12345\""));
        for invalid in ["", "abcde12345", "ABCDE1234\" or true", "ABCDE123456"] {
            assert!(super::extension_peer_requirement(invalid).is_none());
        }
    }
    #[test]
    fn notification_registration_and_drop_do_not_consume_unrelated_descriptors() {
        use std::io::{Read, Write};
        for _ in 0..16 {
            let mut signal = super::ObservationSignal::new();
            let (mut reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
            writer.write_all(b"unchanged").unwrap();
            signal.wait(std::time::Duration::from_millis(1));
            drop(signal);
            reader
                .set_read_timeout(Some(std::time::Duration::from_millis(100)))
                .unwrap();
            let mut bytes = [0; 9];
            reader.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"unchanged");
        }
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
        fn CFDataCreate(allocator: Ref, bytes: *const u8, length: isize) -> Ref;
        fn CFStringCreateWithCString(allocator: Ref, text: *const c_char, encoding: u32) -> Ref;
        fn CFDictionaryCreate(
            allocator: Ref,
            keys: *const Ref,
            values: *const Ref,
            count: isize,
            keys_cb: Ref,
            values_cb: Ref,
        ) -> Ref;
        fn CFRelease(value: Ref);
        fn CFDictionaryGetValue(dictionary: Ref, key: Ref) -> Ref;
        fn CFGetTypeID(value: Ref) -> usize;
        fn CFStringGetTypeID() -> usize;
        fn CFStringGetCString(value: Ref, bytes: *mut c_char, size: isize, encoding: u32) -> bool;
    }
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecGuestAttributeAudit: Ref;
        static kSecCodeInfoTeamIdentifier: Ref;
        fn SecCodeCopySelf(flags: u32, code: *mut Ref) -> i32;
        fn SecCodeCopyStaticCode(code: Ref, flags: u32, static_code: *mut Ref) -> i32;
        fn SecCodeCopySigningInformation(code: Ref, flags: u32, info: *mut Ref) -> i32;
        fn SecCodeCopyGuestWithAttributes(
            host: Ref,
            attributes: Ref,
            flags: u32,
            code: *mut Ref,
        ) -> i32;
        fn SecRequirementCreateWithString(text: Ref, flags: u32, requirement: *mut Ref) -> i32;
        fn SecCodeCheckValidity(code: Ref, flags: u32, requirement: Ref) -> i32;
    }
    struct Owned(Ref);
    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0) };
            }
        }
    }
    fn satisfies(code: Ref, text: &str) -> bool {
        let Ok(text) = CString::new(text) else { return false; };
        unsafe {
            let text = Owned(CFStringCreateWithCString(ptr::null(), text.as_ptr(), 0x08000100));
            if text.0.is_null() { return false; }
            let mut requirement = ptr::null();
            if SecRequirementCreateWithString(text.0, 0, &mut requirement) != 0 { return false; }
            let requirement = Owned(requirement);
            SecCodeCheckValidity(code, 0, requirement.0) == 0
        }
    }
    fn own_team() -> Option<String> {
        // Cache only this executable's validated signing identity, never peer data.
        static TEAM: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
        TEAM.get_or_init(|| unsafe {
            let mut code = ptr::null();
            if SecCodeCopySelf(0, &mut code) != 0 { return None; }
            let code = Owned(code);
            if !satisfies(code.0, "anchor apple generic and identifier \"io.local.watchpanel.engine\"") { return None; }
            let mut static_code = ptr::null();
            if SecCodeCopyStaticCode(code.0, 0, &mut static_code) != 0 { return None; }
            let static_code = Owned(static_code);
            let mut info = ptr::null();
            // kSecCSSigningInformation
            if SecCodeCopySigningInformation(static_code.0, 1 << 1, &mut info) != 0 { return None; }
            let info = Owned(info);
            let team = CFDictionaryGetValue(info.0, kSecCodeInfoTeamIdentifier);
            if team.is_null() || CFGetTypeID(team) != CFStringGetTypeID() { return None; }
            let mut text = [0i8; 11];
            if !CFStringGetCString(team, text.as_mut_ptr(), text.len() as isize, 0x08000100) { return None; }
            let team = std::ffi::CStr::from_ptr(text.as_ptr()).to_str().ok()?.to_owned();
            super::extension_peer_requirement(&team)?;
            Some(team)
        }).clone()
    }
    pub fn verify(fd: i32) -> bool {
        let Some(requirement) = own_team().and_then(|team| super::extension_peer_requirement(&team)) else { return false; };
        let mut token = [0u32; 8];
        let mut len = std::mem::size_of_val(&token) as libc::socklen_t;
        // LOCAL_PEERTOKEN is defined by the macOS SDK's sys/un.h. It includes
        // pidversion, avoiding the PID-reuse race of ps/lsof lookups.
        if unsafe { libc::getsockopt(fd, 0, 0x006, token.as_mut_ptr().cast(), &mut len) } != 0
            || len as usize != std::mem::size_of_val(&token)
            || token[1] != 0
            || token[5] <= 1
        {
            return false;
        }
        unsafe {
            let data = Owned(CFDataCreate(ptr::null(), token.as_ptr().cast(), 32));
            if data.0.is_null() {
                return false;
            }
            let attrs = Owned(CFDictionaryCreate(
                ptr::null(),
                &kSecGuestAttributeAudit,
                &data.0,
                1,
                ptr::null(),
                ptr::null(),
            ));
            if attrs.0.is_null() {
                return false;
            }
            let mut code = ptr::null();
            if SecCodeCopyGuestWithAttributes(ptr::null(), attrs.0, 0, &mut code) != 0 {
                return false;
            }
            let code = Owned(code);
            satisfies(code.0, &requirement)
        }
    }
}
