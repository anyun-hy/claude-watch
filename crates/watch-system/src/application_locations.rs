//! Read-only LaunchServices lookup through NSWorkspace. Never registers an app
//! or changes a default handler. Ordering is the OS's preferred-copy ordering.
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ApplicationLocations {
    pub paths: Vec<PathBuf>,
    pub complete: bool,
}

#[cfg(target_os = "macos")]
pub fn registered_applications(bundle_id: &str) -> std::io::Result<ApplicationLocations> {
    use std::{
        ffi::{c_char, c_void, CString},
        ptr,
    };
    type Ref = *const c_void;
    #[link(name = "AppKit", kind = "framework")]
    unsafe extern "C" {}
    #[link(name = "objc")]
    unsafe extern "C" {
        fn objc_getClass(name: *const c_char) -> Ref;
        fn sel_registerName(name: *const c_char) -> Ref;
        fn objc_msgSend();
        fn objc_autoreleasePoolPush() -> Ref;
        fn objc_autoreleasePoolPop(pool: Ref);
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithCString(a: Ref, s: *const c_char, encoding: u32) -> Ref;
        fn CFArrayGetCount(array: Ref) -> isize;
        fn CFArrayGetValueAtIndex(array: Ref, index: isize) -> Ref;
        fn CFURLCopyFileSystemPath(url: Ref, style: i32) -> Ref;
        fn CFStringGetCString(s: Ref, out: *mut c_char, capacity: isize, encoding: u32) -> bool;
        fn CFRelease(value: Ref);
    }
    let id = CString::new(bundle_id)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    unsafe {
        let pool = objc_autoreleasePoolPush();
        let class = objc_getClass(c"NSWorkspace".as_ptr());
        let send: unsafe extern "C" fn(Ref, Ref) -> Ref =
            std::mem::transmute(objc_msgSend as *const ());
        let send_arg: unsafe extern "C" fn(Ref, Ref, Ref) -> Ref =
            std::mem::transmute(objc_msgSend as *const ());
        let workspace = if class.is_null() {
            ptr::null()
        } else {
            send(class, sel_registerName(c"sharedWorkspace".as_ptr()))
        };
        let text = CFStringCreateWithCString(ptr::null(), id.as_ptr(), 0x08000100);
        let urls = if workspace.is_null() || text.is_null() {
            ptr::null()
        } else {
            send_arg(
                workspace,
                sel_registerName(c"URLsForApplicationsWithBundleIdentifier:".as_ptr()),
                text,
            )
        };
        let mut paths = Vec::new();
        let count = if urls.is_null() {
            0
        } else {
            CFArrayGetCount(urls)
        };
        let mut complete = count <= 512;
        for index in 0..count.min(512) {
            let path = CFURLCopyFileSystemPath(CFArrayGetValueAtIndex(urls, index), 0);
            if path.is_null() {
                complete = false;
                continue;
            }
            let mut buffer = vec![0u8; 16384];
            if CFStringGetCString(
                path,
                buffer.as_mut_ptr().cast(),
                buffer.len() as isize,
                0x08000100,
            ) {
                if let Some(end) = buffer.iter().position(|v| *v == 0) {
                    if let Ok(value) = std::str::from_utf8(&buffer[..end]) {
                        paths.push(value.into());
                    } else {
                        complete = false;
                    }
                }
            } else {
                complete = false;
            }
            CFRelease(path);
        }
        if !text.is_null() {
            CFRelease(text);
        }
        objc_autoreleasePoolPop(pool);
        if workspace.is_null() || text.is_null() {
            return Err(std::io::Error::other("application_registry_unavailable"));
        }
        Ok(ApplicationLocations { paths, complete })
    }
}

#[cfg(not(target_os = "macos"))]
pub fn registered_applications(_: &str) -> std::io::Result<ApplicationLocations> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}
