//! Online probe adapters shared by macOS fact collection.
//!
//! This module intentionally owns no UDP protocol logic.  `stun_probe` is the
//! native RFC 5389 implementation and remains the single authority for server
//! selection, retries, deadline handling, and strict all-server completion.
#![forbid(unsafe_code)]

use crate::stun_probe::{self, Endpoint, ProbeReceipt, Requester};
use serde_json::Value;
use std::{sync::Arc, time::Duration};

pub trait OnlineProbes: Send + Sync {
    fn stun(&self) -> Value;
}
pub struct NativeProbes;
impl OnlineProbes for NativeProbes {
    fn stun(&self) -> Value {
        default_stun_value()
    }
}
impl<F: Fn() -> Value + Send + Sync> OnlineProbes for F {
    fn stun(&self) -> Value {
        self()
    }
}

/// Preserve the existing STUN receipt schema while making it directly usable
/// as the `online["stun"]` fact consumed by `claude-watch-core`.
pub fn stun_value(receipt: ProbeReceipt) -> Value {
    // Every field in `ProbeReceipt` is serializable data; failure would be a
    // programming error, not a network observation outcome.
    serde_json::to_value(receipt).expect("STUN receipt must serialize")
}

/// Collect a bounded native UDP/STUN receipt using an injected requester.
///
/// Kept public for loopback/fake contract tests. Production callers should use
/// `default_stun_value`, which retains the established four-server policy.
pub fn collect_stun_value(
    servers: &[Endpoint],
    requester: Arc<dyn Requester>,
    budget: Duration,
) -> Value {
    stun_value(stun_probe::probe(servers, requester, budget))
}

/// The production STUN fact for a single online collection round.
pub fn default_stun_value() -> Value {
    stun_value(stun_probe::probe_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use claude_watch_core::{
        audit::{self, AuditInput},
        config::Config,
        error::Result,
        region::ZoneCatalog,
    };
    use serde_json::json;
    use std::time::Instant;

    struct FakeRequester;
    impl Requester for FakeRequester {
        fn request(
            &self,
            _: &Endpoint,
            _: Instant,
        ) -> std::result::Result<String, stun_probe::ProbeError> {
            Ok("8.8.8.8".into())
        }
    }

    #[test]
    fn native_receipt_is_consumed_by_the_core_stun_gate() -> Result<()> {
        let servers = (0..4)
            .map(|port| Endpoint {
                host: format!("loopback-fixture-{port}"),
                port: 3478 + port,
            })
            .collect::<Vec<_>>();
        let stun = collect_stun_value(&servers, Arc::new(FakeRequester), Duration::from_secs(1));
        assert_eq!(stun["complete"], true, "all fake STUN servers passed");
        assert_eq!(stun["observations"].as_array().map(Vec::len), Some(4));

        let config = Config::default();
        let zones: ZoneCatalog = serde_json::from_value(json!({"US":["America/Los_Angeles"]}))
            .expect("fixed zone fixture is valid");
        let online = json!({
            "trace":{"ip":"8.8.8.8","loc":"US"},
            "geo":{"ip":"8.8.8.8","country":"US","timezone":"America/Los_Angeles"},
            "stun":stun,
        });
        let audit = audit::evaluate(
            AuditInput {
                config: &config,
                local: &json!({}),
                online: &online,
                history: &[],
                zones: &zones,
                policy: "test",
                now: 1.0,
            },
            |_| "test".into(),
        )?;
        let row = audit["rows"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["id"] == "stun"))
            .expect("core audit includes STUN row");
        assert_eq!(row["state"], "ok");
        assert_eq!(row["stun_probe"], online["stun"]);
        Ok(())
    }
}
