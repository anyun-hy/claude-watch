//! Controlled launch and read-only guard reporting. ChannelSupervisor owns protection.
use crate::{
    config_store::ConfigStore, receipt_store::ReceiptStore,
    storage::StateStore,
};
use claude_watch_core::{
    error::{CoreError, Result},
    processes::{Identity as ProcessIdentity, LaunchTarget, Target},
    session,
};
use serde_json::{json, Value};
use std::time::Duration;

mod launch;

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
    fn full_audit(&mut self) -> Result<Value>;
    fn egress(&mut self) -> Value;
    fn backend_healthy(&mut self) -> Result<bool>;
    fn open_desktop(&mut self) -> Result<()>;

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

    /// Project the supervisor's published frame without sampling, changing
    /// sessions, issuing permits or performing process effects.
    pub fn guard_tick<S: DesktopSystem>(&self, system: &mut S) -> Result<Value> {
        let config = match (ConfigStore { storage: self.storage.clone() }).load() {
            Ok(config) => config,
            Err(error) => return Ok(json!({"status":"unknown","action":"observe","code":error.code})),
        };
        Ok(crate::channel_policy_status::guard_summary(
            &crate::channel_policy_status::read_frame(&self.storage), &config, system.now(),
        ))
    }

    pub fn guard_tick_for_family<S: DesktopSystem>(
        &self,
        system: &mut S,
        family: &'static str,
    ) -> Result<Value> {
        if claude_watch_core::policy::PolicyCatalog::family(family).is_none() {
            return Err(CoreError::new("unknown_family", "保护服务未知"));
        }
        let summary = self.guard_tick(system)?;
        Ok(summary["families"].as_array().and_then(|rows|
            rows.iter().find(|row| row["family"] == family)).cloned().unwrap_or(summary))
    }
}
