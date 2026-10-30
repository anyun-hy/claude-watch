//! Composition of fixed system actions and scoped proxy configuration actions.
use crate::{
    macos::Mutator,
    macos_mutations::{AdminCommand, FixedMacosMutator},
    proxy_mutations::ProxyMutationAdapter,
    storage::StateStore,
};
use claude_watch_core::error::Result;
use serde_json::Value;
pub struct NativePlatformMutator {
    system: FixedMacosMutator,
    proxy: ProxyMutationAdapter,
}
impl NativePlatformMutator {
    pub fn new(storage: StateStore) -> Result<Self> {
        Ok(Self {
            system: FixedMacosMutator::native(storage.paths.home.clone(), storage.paths.watch())?,
            proxy: ProxyMutationAdapter::native(storage),
        })
    }
    pub fn administrative(&mut self, command: AdminCommand) -> Result<()> {
        self.system.administrative(command)
    }
}
impl Mutator for NativePlatformMutator {
    fn apply(&mut self, action: &Value) -> Result<()> {
        if matches!(
            action["id"].as_str(),
            Some("start_proxy" | "reload_proxy" | "enable_tun" | "rules")
        ) {
            self.proxy.apply(action)
        } else {
            self.system.apply(action)
        }
    }
    fn restore(&mut self, action: &Value) -> Result<bool> {
        if matches!(
            action["id"].as_str(),
            Some("start_proxy" | "reload_proxy" | "enable_tun" | "rules")
        ) {
            self.proxy.restore(action)
        } else {
            self.system.restore(action)
        }
    }
}
