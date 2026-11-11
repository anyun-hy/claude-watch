//! Filesystem operations relative to an open directory, without following
//! links. Used by the user-selected managed entry transaction.
use std::{
    ffi::{CStr, CString},
    fs::{File, Metadata},
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path},
};

/// A private, already unlinked, read-only snapshot. The receiving interpreter
/// hashes the bytes it actually reads; it does not reopen the original name.
pub fn unlinked_read_only_bytes(bytes: &[u8]) -> io::Result<File> {
    use std::os::unix::fs::MetadataExt;
    let root = std::fs::canonicalize(std::env::temp_dir())?;
    let dir = Dir::absolute(&root, false)?;
    let mut nonce = [0u8; 16];
    unsafe {
        libc::arc4random_buf(nonce.as_mut_ptr().cast(), nonce.len());
    }
    let name = format!(".cw-script-{:032x}", u128::from_ne_bytes(nonce));
    let mut writer = dir.create(&name, 0o600)?;
    let result = (|| {
        writer.write_all(bytes)?;
        let reader = dir.read(&name)?;
        let written = writer.metadata()?;
        let readable = reader.metadata()?;
        if written.ino() != readable.ino()
            || written.dev() != readable.dev()
            || readable.nlink() != 1
            || readable.len() != bytes.len() as u64
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        dir.remove(&name, false)?;
        if reader.metadata()?.nlink() != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(reader)
    })();
    if result.is_err() {
        if dir
            .read(&name)
            .and_then(|f| f.metadata())
            .ok()
            .zip(writer.metadata().ok())
            .is_some_and(|(a, b)| a.dev() == b.dev() && a.ino() == b.ino())
        {
            let _ = dir.remove(&name, false);
        }
    }
    result
}

/// Used by the dedicated single-shot helper immediately before exec. Leave
/// the caller's stdin, stdout, stderr and registration descriptors alone.
pub fn inherit_across_exec(file: &File) -> io::Result<i32> {
    let fd = file.as_raw_fd();
    if fd <= 2 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn name(value: &str) -> io::Result<CString> {
    if value.is_empty() || value == "." || value == ".." || value.contains('/') {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    CString::new(value).map_err(|_| io::ErrorKind::InvalidInput.into())
}

#[derive(Debug)]
pub struct Dir(File);

impl Dir {
    pub fn absolute(path: &Path, create: bool) -> io::Result<Self> {
        let mut parts = path.components();
        if parts.next() != Some(Component::RootDir) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut dir = Self(unsafe { File::from_raw_fd(fd) });
        for part in parts {
            let Component::Normal(part) = part else {
                return Err(io::ErrorKind::InvalidInput.into());
            };
            let part =
                std::str::from_utf8(part.as_bytes()).map_err(|_| io::ErrorKind::InvalidInput)?;
            dir = match dir.child(part) {
                Err(e) if create && e.kind() == io::ErrorKind::NotFound => {
                    match dir.mkdir(part, 0o700) {
                        Ok(()) => {}
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(e),
                    }
                    dir.child(part)?
                }
                other => other?,
            };
        }
        Ok(dir)
    }

    fn open(&self, child: &str, flags: i32, mode: libc::mode_t) -> io::Result<File> {
        let child = name(child)?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                child.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                i32::from(mode),
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    pub fn child(&self, child: &str) -> io::Result<Self> {
        self.open(child, libc::O_RDONLY | libc::O_DIRECTORY, 0)
            .map(Self)
    }
    pub fn read(&self, child: &str) -> io::Result<File> {
        self.open(child, libc::O_RDONLY, 0)
    }
    pub fn create(&self, child: &str, mode: u16) -> io::Result<File> {
        self.open(child, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, mode)
    }
    pub fn mkdir(&self, child: &str, mode: u16) -> io::Result<()> {
        let child = name(child)?;
        let ret = unsafe { libc::mkdirat(self.0.as_raw_fd(), child.as_ptr(), mode) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    pub fn metadata(&self) -> io::Result<Metadata> {
        self.0.metadata()
    }

    /// Open a distinct file description so listing never changes the caller's
    /// directory offset. Reject non-UTF8 names instead of normalizing them.
    pub fn names(&self, limit: usize) -> io::Result<Vec<String>> {
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let raw = unsafe { libc::fdopendir(file.as_raw_fd()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let _ = file.into_raw_fd();
        struct List(*mut libc::DIR);
        impl Drop for List {
            fn drop(&mut self) {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let list = List(raw);
        let mut out = Vec::new();
        loop {
            unsafe {
                *libc::__error() = 0;
            }
            let entry = unsafe { libc::readdir(list.0) };
            if entry.is_null() {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(0) {
                    break;
                }
                return Err(e);
            }
            let value = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
                .to_str()
                .map_err(|_| io::ErrorKind::InvalidData)?;
            if value != "." && value != ".." {
                if out.len() >= limit {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                out.push(value.to_owned());
            }
        }
        out.sort();
        Ok(out)
    }

    pub fn rename(&self, from: &str, to_dir: &Self, to: &str, swap: bool) -> io::Result<()> {
        let from = name(from)?;
        let to = name(to)?;
        let ret = unsafe {
            libc::renameatx_np(
                self.0.as_raw_fd(),
                from.as_ptr(),
                to_dir.0.as_raw_fd(),
                to.as_ptr(),
                if swap {
                    libc::RENAME_SWAP
                } else {
                    libc::RENAME_EXCL
                },
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    pub fn remove(&self, child: &str, directory: bool) -> io::Result<()> {
        let child = name(child)?;
        let ret = unsafe {
            libc::unlinkat(
                self.0.as_raw_fd(),
                child.as_ptr(),
                if directory { libc::AT_REMOVEDIR } else { 0 },
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}
