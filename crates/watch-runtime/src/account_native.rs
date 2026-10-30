//! Owning production bridge for account switching. It builds a short-lived
//! DesktopRuntime per operation, avoiding self-referential borrows.
use crate::{
    accounts::AccountOs,
    audit_store::AuditSystem,
    commands::ReadRunner,
    controlled::Controller,
    desktop_native::{DesktopRuntime, NativeDesktop},
    network_client::{NetworkClient, Transport},
    services::ServiceSystem,
    storage::StateStore,
};
use claude_watch_core::error::{CoreError, Result};
use std::time::Instant;
pub struct AccountRuntimeHost<R: ReadRunner, T: Transport, S: AuditSystem + ServiceSystem> {
    pub storage: StateStore,
    pub controller: Controller,
    pub desktop: NativeDesktop<R>,
    pub system: S,
    pub network: NetworkClient<T>,
}
impl<R: ReadRunner, T: Transport, S: AuditSystem + ServiceSystem> AccountRuntimeHost<R, T, S> {
    fn runtime(&mut self) -> DesktopRuntime<'_, R, T, S> {
        DesktopRuntime {
            desktop: &self.desktop,
            system: &mut self.system,
            network: self.network.clone(),
            storage: self.storage.clone(),
            started: Instant::now(),
            cli: None,
        }
    }
}
impl<R: ReadRunner, T: Transport, S: AuditSystem + ServiceSystem> AccountOs
    for AccountRuntimeHost<R, T, S>
{
    fn claude_version(&mut self) -> Result<Option<String>> {
        let v = crate::native::Observer {
            runner: &self.desktop.runner,
        }
        .environment()?;
        Ok(v.pointer("/claude_app/version")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned))
    }
    fn quit_claude(&mut self) -> Result<()> {
        self.desktop.quit()
    }
    fn claude_running(&mut self) -> Result<bool> {
        Ok(!self.desktop.desktops()?.is_empty())
    }
    fn launch_claude(&mut self) -> Result<()> {
        let storage = self.storage.clone();
        let mut r = self.runtime();
        let controller = Controller::new(storage);
        controller.launch(&mut r).map(|_| ())
    }
    fn preflight(&mut self) -> Result<()> {
        let c = crate::config_store::ConfigStore {
            storage: self.storage.clone(),
        }
        .load()?;
        if !c.enabled {
            return Err(CoreError::new("disabled", "Claude Watch 已禁用"));
        }
        let mut r = self.runtime();
        use crate::controlled::DesktopSystem;
        let audit = r.full_audit()?;
        if audit["ready"] != true {
            return Err(CoreError::new(
                "preflight_not_ready",
                "当前环境未通过启动前核验",
            ));
        }
        Ok(())
    }
}
