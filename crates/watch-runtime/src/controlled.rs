//! Controlled desktop and CLI launch. The channel supervisor owns protection.
use crate::{
    receipt_store::ReceiptStore, session_store::SessionStore, storage::StateStore,
};
use claude_watch_core::{
    error::{CoreError, Result},
    processes::{Identity as ProcessIdentity, LaunchTarget, Provider, Target},
    session::{self, Desktop, Launcher},
};
use serde_json::{json, Value};
use std::time::Duration;

mod launch;

pub fn read_process_real_uid(pid: u32) -> u32 {
    #[cfg(unix)]
    {
        if pid > 1 {
            if let Ok(output) = std::process::Command::new("/usr/sbin/lsof")
                .args(["-nP", "-F", "pu", "-p", &pid.to_string()])
                .output()
            {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    for line in text.lines() {
                        if let Some(u) = line.strip_prefix('u') {
                            if let Ok(uid) = u.trim().parse::<u32>() {
                                if uid > 0 {
                                    return uid;
                                }
                            }
                        }
                    }
                }
            }
        }
        let home = std::env::var_os("HOME").unwrap_or_default();
        if let Ok(m) = std::fs::metadata(home) {
            let uid = std::os::unix::fs::MetadataExt::uid(&m);
            if uid > 0 {
                return uid;
            }
        }
    }
    1000
}

pub trait DesktopSystem {
    fn prepare_cli(&mut self) -> Result<()> {
        Err(CoreError::new(
            "cli_adapter_unavailable",
            "CLI执行适配尚不可用",
        ))
    }
    fn cli_interrupted(&self) -> Option<i32> {
        None
    }
    fn spawn_cli(&mut self, _args: &[String]) -> Result<Box<dyn CliProcess>> {
        Err(CoreError::new(
            "cli_adapter_unavailable",
            "CLI执行适配尚不可用",
        ))
    }
    fn launch_target(&self) -> LaunchTarget {
        LaunchTarget::ClaudeDesktop
    }
    /// Point the guard at one policy family before its next tick. The guard
    /// supervises every family the policy table declares, one at a time; this
    /// is how a single engine answers for each of them. Adapters that cannot
    /// change target (a fixed CLI entry) leave the default error.
    fn set_family(&mut self, _family_id: &str) -> Result<()> {
        Err(CoreError::new(
            "target_adapter_unavailable",
            "目标进程适配尚不可用",
        ))
    }
    /// Native-verified, current-user main processes for the selected target.
    fn observation_roots(&mut self) -> Result<Vec<Target>> {
        Err(CoreError::new(
            "target_adapter_unavailable",
            "目标进程适配尚不可用",
        ))
    }
    fn observation_owner(&mut self) -> Result<ProcessIdentity> {
        Err(CoreError::new(
            "target_adapter_unavailable",
            "启动器身份适配尚不可用",
        ))
    }
    fn now(&self) -> f64;
    fn monotonic(&self) -> Duration;
    fn wait(&mut self, duration: Duration);
    /// Each returned identity is native-verified as this user's Claude desktop tree.
    fn desktops(&mut self) -> Result<Vec<(Desktop, bool, String)>>;
    /// A false result requires a complete native inventory showing that this
    /// exact PID and start identity is no longer present.
    fn desktop_alive(&mut self, desktop: &Desktop) -> Result<bool>;
    /// Includes verified Claude desktop helpers, not just the main process.
    fn desktop_tree_running(&mut self) -> Result<bool>;
    fn launcher(&mut self) -> Result<Launcher>;
    fn full_audit(&mut self) -> Result<Value>;
    fn egress(&mut self) -> Value;
    fn local_guard(&mut self) -> Result<Value>;
    fn backend_healthy(&mut self) -> Result<bool>;
    fn launcher_matches(&mut self, launcher: &Launcher) -> Result<bool>;
    fn open_desktop(&mut self) -> Result<()>;
    fn quit_desktop(&mut self) -> Result<()>;
    fn channel_mode(&self) -> bool { true }
    /// Returns supervised process tokens with verified system identities (`uid > 0`,
    /// `audit_token: Some([u32; 8])`) for all desktop main, helper, and CLI processes.
    fn supervised_processes(
        &mut self,
    ) -> Result<Vec<claude_watch_core::channel::BoundProcessToken>> {
        let desktops = self.desktops().unwrap_or_default();
        let tokens = desktops
            .into_iter()
            .map(|(d, main, _)| {
                let real_uid = read_process_real_uid(d.pid);
                claude_watch_core::channel::BoundProcessToken::with_system_identity(
                    d.pid,
                    real_uid,
                    d.start_seconds,
                    d.start_microseconds,
                    if main {
                        claude_watch_core::processes::ProcessRole::DesktopMain
                    } else {
                        claude_watch_core::processes::ProcessRole::DesktopHelper
                    },
                )
            })
            .collect();
        Ok(tokens)
    }
}
pub trait CliProcess {
    fn wait(&mut self) -> Result<i32>;
}
pub struct CliOutcome {
    pub exit_code: i32,
    pub diagnostic: Option<String>,
}
pub struct Controller {
    pub storage: StateStore,
}
impl Controller {
    pub fn new(storage: StateStore) -> Self {
        Self { storage }
    }
}
