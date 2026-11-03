//! User-run full reset, native package and install flow.
//!
//! This is the native replacement for the retired `reinstall_clean.py`: one
//! state machine that uninstall the installed app through its own lifecycle
//! entry, removes only Watch-owned data, packages a fresh build with the
//! project's shell pipeline, verifies it, and installs it. Every step refuses
//! to continue when the machine is not in the state the previous step
//! promised, because the destructive steps cannot be undone.

pub mod flow;
pub mod layout;
pub mod plist;
pub mod runner;

pub use flow::{app_identity, perform, LayoutPlan, Outcome};
pub use layout::Layout;
pub use runner::{Output, RunMode, Runner, SystemRunner};

use claude_watch_core::error::CoreError;

/// One blocking condition: the flow stops and nothing further is executed.
pub fn blocked(message: impl Into<String>) -> CoreError {
    CoreError::new("reinstall_blocked", &message.into())
}
