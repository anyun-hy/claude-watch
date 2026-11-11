//! Composition of fixed system actions and scoped proxy configuration actions.
use crate::{
    macos::Mutator,
    macos_mutations::{AdminCommand, FixedMacosMutator},
    storage::StateStore,
};
use claude_watch_core::error::{CoreError, Result};
use serde_json::Value;

pub struct NativePlatformMutator {
    system: FixedMacosMutator,
}

impl NativePlatformMutator {
    pub fn new(storage: StateStore) -> Result<Self> {
        Ok(Self {
            system: FixedMacosMutator::native(storage.paths.home.clone(), storage.paths.watch())?,
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
            return Err(CoreError::new(
                "vpn_managed_externally",
                "VPN 与代理配置由外部客户端管理，Watch 仅执行只读观测与通道断流",
            ));
        }
        self.system.apply(action)
    }
    fn restore(&mut self, action: &Value) -> Result<bool> {
        if matches!(
            action["id"].as_str(),
            Some("start_proxy" | "reload_proxy" | "enable_tun" | "rules")
        ) {
            return Err(CoreError::new(
                "vpn_managed_externally",
                "VPN 与代理配置由外部客户端管理，Watch 仅执行只读观测与通道断流",
            ));
        }
        self.system.restore(action)
    }
}
