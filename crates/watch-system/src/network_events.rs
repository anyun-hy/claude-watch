//! Event-driven network and local VPN configuration change notification bridge.
//!
//! Combines Darwin notifications (`com.apple.system.config.network_change` and
//! `io.local.claudewatch.vpn-observation`),watched local config file metadata
//! (`dev`, `ino`, `mtime`, `len`), and explicit test/wake triggers with safe
//! descriptor registration and drop cleanup.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkEventKind {
    DarwinNotification(String),
    WatchedFileChanged(PathBuf),
    WakeSignal,
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    exists: bool,
    dev: u64,
    ino: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    size: u64,
}

impl FileFingerprint {
    fn capture(path: &Path) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = std::fs::symlink_metadata(path) {
                return Self {
                    exists: true,
                    dev: meta.dev(),
                    ino: meta.ino(),
                    mtime_sec: meta.mtime(),
                    mtime_nsec: meta.mtime_nsec(),
                    size: meta.len(),
                };
            }
        }
        Self {
            exists: false,
            dev: 0,
            ino: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            size: 0,
        }
    }
}

struct NotifyRegistration {
    name: String,
    fd: i32,
    token: i32,
}

impl NotifyRegistration {
    fn register(name: &str) -> Option<Self> {
        #[cfg(target_os = "macos")]
        unsafe {
            let Ok(c_name) = std::ffi::CString::new(name) else {
                return None;
            };
            let mut fd = -1;
            let mut token = -1;
            let status = super::notify_register_file_descriptor(
                c_name.as_ptr(),
                &mut fd,
                0,
                &mut token,
            );
            if status != 0 || fd < 0 || token < 0 {
                return None;
            }
            if libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) < 0 {
                super::notify_cancel(token);
                return None;
            }
            Some(Self {
                name: name.to_string(),
                fd,
                token,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = name;
            None
        }
    }

    fn drain(&self) -> bool {
        if self.fd < 0 {
            return false;
        }
        let mut bytes = [0u8; 256];
        let mut read_any = false;
        unsafe {
            while libc::read(self.fd, bytes.as_mut_ptr().cast(), bytes.len()) > 0 {
                read_any = true;
            }
        }
        read_any
    }
}

impl Drop for NotifyRegistration {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if self.token >= 0 {
            unsafe {
                super::notify_cancel(self.token);
            }
            self.token = -1;
            self.fd = -1;
        }
    }
}

pub struct NetworkEventWatcher {
    registrations: Vec<NotifyRegistration>,
    watched_files: BTreeMap<PathBuf, FileFingerprint>,
    wake_flag: Arc<AtomicBool>,
    last_wall_clock: Option<std::time::SystemTime>,
    last_mono_clock: Option<std::time::Instant>,
}

impl Default for NetworkEventWatcher {
    fn default() -> Self {
        Self::new(&[
            "com.apple.system.config.network_change",
            "io.local.claudewatch.vpn-observation",
            "com.apple.powermanagement.systempowerstate",
            "io.local.claudewatch.system-wake",
        ])
    }
}

impl NetworkEventWatcher {
    pub fn new(notification_names: &[&str]) -> Self {
        let mut registrations = Vec::new();
        for name in notification_names {
            if let Some(reg) = NotifyRegistration::register(name) {
                registrations.push(reg);
            }
        }
        Self {
            registrations,
            watched_files: BTreeMap::new(),
            wake_flag: Arc::new(AtomicBool::new(false)),
            last_wall_clock: Some(std::time::SystemTime::now()),
            last_mono_clock: Some(std::time::Instant::now()),
        }
    }

    pub fn wake_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.wake_flag)
    }

    pub fn trigger_wake(&self) {
        self.wake_flag.store(true, Ordering::SeqCst);
    }

    pub fn watch_file(&mut self, path: impl Into<PathBuf>) {
        let path = path.into();
        let fp = FileFingerprint::capture(&path);
        self.watched_files.insert(path, fp);
    }

    pub fn set_watched_files<I, P>(&mut self, paths: I)
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        let mut next = BTreeMap::new();
        for raw in paths {
            let path = raw.into();
            let fp = self
                .watched_files
                .remove(&path)
                .unwrap_or_else(|| FileFingerprint::capture(&path));
            next.insert(path, fp);
        }
        self.watched_files = next;
    }

    pub fn poll_file_changes(&mut self) -> Vec<PathBuf> {
        let mut changed = Vec::new();
        for (path, previous) in &mut self.watched_files {
            let current = FileFingerprint::capture(path);
            if &current != previous {
                *previous = current;
                changed.push(path.clone());
            }
        }
        changed
    }

    pub fn wait(&mut self, timeout: Duration) -> Vec<NetworkEventKind> {
        let mut events = Vec::new();
        if self.wake_flag.swap(false, Ordering::SeqCst) {
            events.push(NetworkEventKind::WakeSignal);
        }
        for path in self.poll_file_changes() {
            events.push(NetworkEventKind::WatchedFileChanged(path));
        }

        let now_wall = std::time::SystemTime::now();
        let now_mono = std::time::Instant::now();

        // Check whether wall clock jumped forward compared to monotonic clock during
        // the interval between consecutive wait calls (e.g. system slept while thread was unblocked).
        if let (Some(prev_wall), Some(prev_mono)) = (self.last_wall_clock, self.last_mono_clock) {
            if let Ok(wall_gap) = now_wall.duration_since(prev_wall) {
                let mono_gap = now_mono.duration_since(prev_mono);
                if wall_gap > mono_gap.saturating_add(Duration::from_millis(1500)) {
                    if !events.contains(&NetworkEventKind::WakeSignal) {
                        events.push(NetworkEventKind::WakeSignal);
                    }
                }
            }
        }

        if !events.is_empty() {
            self.last_wall_clock = Some(now_wall);
            self.last_mono_clock = Some(now_mono);
            return events;
        }

        if self.registrations.is_empty() {
            std::thread::sleep(timeout.min(Duration::from_millis(250)));
        } else {
            let mut pollfds: Vec<libc::pollfd> = self
                .registrations
                .iter()
                .map(|r| libc::pollfd {
                    fd: r.fd,
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect();
            let wait_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
            let ready =
                unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, wait_ms) };
            if ready > 0 {
                for (idx, pfd) in pollfds.iter().enumerate() {
                    if pfd.revents & libc::POLLIN != 0 && self.registrations[idx].drain() {
                        let notif_name = self.registrations[idx].name.clone();
                        if notif_name.contains("power")
                            || notif_name.contains("wake")
                            || notif_name.contains("sleep")
                        {
                            events.push(NetworkEventKind::WakeSignal);
                        } else {
                            events.push(NetworkEventKind::DarwinNotification(notif_name));
                        }
                    }
                }
            }
        }

        let after_wall = std::time::SystemTime::now();
        let after_mono = std::time::Instant::now();
        self.last_wall_clock = Some(after_wall);
        self.last_mono_clock = Some(after_mono);

        if let Ok(wait_wall) = after_wall.duration_since(now_wall) {
            let wait_mono = after_mono.duration_since(now_mono);
            // If wall clock jumped forward significantly during this wait compared to
            // the requested wait window or monotonic clock, the system woke from sleep.
            if wait_wall > timeout.saturating_add(Duration::from_millis(1500))
                || wait_wall > wait_mono.saturating_add(Duration::from_millis(1500))
            {
                if !events.contains(&NetworkEventKind::WakeSignal) {
                    events.push(NetworkEventKind::WakeSignal);
                }
            }
        }

        if self.wake_flag.swap(false, Ordering::SeqCst)
            && !events.contains(&NetworkEventKind::WakeSignal)
        {
            events.push(NetworkEventKind::WakeSignal);
        }
        for path in self.poll_file_changes() {
            events.push(NetworkEventKind::WatchedFileChanged(path));
        }
        if events.is_empty() {
            events.push(NetworkEventKind::Timeout);
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watcher_detects_file_mutation_and_drops_cleanly() {
        let dir = std::env::temp_dir().join(format!(
            "cw-net-events-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("config.yaml");
        std::fs::write(&file, "mode: rule\n").unwrap();

        let mut watcher = NetworkEventWatcher::default();
        watcher.watch_file(&file);
        assert!(watcher.poll_file_changes().is_empty());

        std::fs::write(&file, "mode: direct\n").unwrap();
        let events = watcher.wait(Duration::from_millis(10));
        assert!(events
            .iter()
            .any(|e| e == &NetworkEventKind::WatchedFileChanged(file.clone())));
        drop(watcher);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

