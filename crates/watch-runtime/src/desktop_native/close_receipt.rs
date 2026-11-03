//! Close completion is a helper contract, not an inference from desktop absence.
//! All functions in this module are side-effect free except the injected reader.
use claude_watch_core::error::{CoreError, Result};
use serde_json::Value;

#[derive(Debug)]
struct CloseReceipt {
    remaining: u32,
    unconfirmed: u32,
    forced: u32,
    ok: bool,
    code: String,
}
fn invalid() -> CoreError {
    CoreError::new("invalid_close_receipt", "退出回执缺失、版本不符或计数无效，未确认全部退出")
}
impl CloseReceipt {
    fn decode(bytes: &[u8], product: &str, allow_force: bool) -> Result<Self> {
        let value = crate::storage::strict_json(bytes).map_err(|_| invalid())?;
        if value["schema"].as_u64() != Some(1)
            || !matches!(product, "claude" | "openai")
            || value["product"].as_str() != Some(product)
        {
            return Err(invalid());
        }
        let count = |key: &str| -> Result<u32> {
            value.get(key).and_then(Value::as_u64)
                .filter(|n| *n <= 65_536)
                .map(|n| n as u32).ok_or_else(invalid)
        };
        let planned = count("planned")?;
        if count("requested")? + count("skipped")? + count("failed")? != planned {
            return Err(invalid());
        }
        let forced = count("force_requested")?;
        let force_total = forced + count("force_skipped")? + count("force_failed")?;
        if (!allow_force && force_total != 0)
            || (force_total != 0 && force_total != planned)
        {
            return Err(invalid());
        }
        let remaining = count("remaining")?;
        let unconfirmed = count("identity_unconfirmed")?;
        let ok = match value["status"].as_str() {
            Some("ok") => true,
            Some("error") => false,
            _ => return Err(invalid()),
        };
        let code = value["code"].as_str().ok_or_else(invalid)?.to_owned();
        if ok && (remaining != 0 || unconfirmed != 0 || !code.is_empty()) {
            return Err(invalid());
        }
        if !ok && !matches!(code.as_str(), "target_still_running" | "process_identity_unavailable") {
            return Err(invalid());
        }
        Ok(Self { remaining, unconfirmed, forced, ok, code })
    }
    fn confirm(&self) -> Result<()> {
        if self.unconfirmed > 0 || self.code == "process_identity_unavailable" {
            return Err(CoreError::new("process_identity_unavailable", "部分原计划进程身份无法复核，未确认退出"));
        }
        if !self.ok || self.remaining != 0 {
            return Err(CoreError::new("target_still_running", "受监督应用、CLI或原计划子进程尚未完全退出"));
        }
        Ok(())
    }
}

/// A failed helper call, a malformed receipt or residual CLI cannot be made
/// successful by a subsequent scan that happens to find no desktop bundle.
pub(super) fn finish(
    request: Result<Vec<u8>>,
    product: &str,
    allow_force: bool,
    forced: &mut Option<u32>,
    desktop_running: impl FnOnce() -> Result<bool>,
) -> Result<()> {
    *forced = None;
    let report = CloseReceipt::decode(&request?, product, allow_force)?;
    if allow_force { *forced = Some(report.forced); }
    report.confirm()?;
    if desktop_running()? {
        return Err(CoreError::new("target_still_running", "退出复核期间又发现受监督应用，未确认全部退出"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn receipt() -> Value {
        json!({"schema":1,"product":"openai","status":"ok","code":"",
            "planned":2,"requested":2,"skipped":0,"failed":0,"remaining":0,
            "identity_unconfirmed":0,"force_requested":0,"force_skipped":0,"force_failed":0})
    }
    fn bytes(v: Value) -> Vec<u8> { serde_json::to_vec(&v).unwrap() }
    #[test]
    fn normal_close_needs_a_valid_full_scope_receipt_and_an_empty_desktop_scan() {
        let mut forced = Some(99);
        finish(Ok(bytes(receipt())), "openai", false, &mut forced, || Ok(false)).unwrap();
        assert_eq!(forced, None);
    }
    #[test]
    fn remaining_cli_or_orphan_is_not_hidden_by_absent_desktop() {
        let mut value = receipt();
        value["status"] = json!("error"); value["code"] = json!("target_still_running");
        value["remaining"] = json!(1);
        let error = finish(Ok(bytes(value)), "openai", false, &mut None,
            || panic!("residual helper evidence must be checked before any narrower scan")).unwrap_err();
        assert_eq!(error.code, "target_still_running");
    }
    #[test]
    fn unavailable_identity_is_not_a_confirmed_exit() {
        let mut value = receipt();
        value["status"] = json!("error"); value["code"] = json!("process_identity_unavailable");
        value["identity_unconfirmed"] = json!(1);
        assert_eq!(finish(Ok(bytes(value)), "openai", false, &mut None, || Ok(false))
            .unwrap_err().code, "process_identity_unavailable");
    }
    #[test]
    fn helper_timeout_cannot_turn_into_success() {
        let error = CoreError::new("desktop_operation_timeout", "fixture");
        assert_eq!(finish(Err(error), "openai", true, &mut None,
            || panic!("no fallback success after helper failure")).unwrap_err().code, "desktop_operation_timeout");
    }
    #[test]
    fn missing_legacy_and_wrong_family_receipts_are_rejected() {
        for value in [json!({"status":"ok"}), json!(null), {
            let mut v = receipt(); v["product"] = json!("claude"); v
        }] {
            assert_eq!(finish(Ok(bytes(value)), "openai", false, &mut None, || Ok(false))
                .unwrap_err().code, "invalid_close_receipt");
        }
    }
    #[test]
    fn invalid_counts_and_contradictory_success_fail_closed() {
        for (key, value) in [("remaining", json!(1)), ("identity_unconfirmed", json!(true)),
            ("planned", json!(-1)), ("requested", json!(1.5)), ("failed", json!(65_537))] {
            let mut v = receipt(); v[key] = value;
            assert_eq!(finish(Ok(bytes(v)), "openai", false, &mut None, || Ok(false))
                .unwrap_err().code, "invalid_close_receipt");
        }
    }
    #[test]
    fn a_force_report_is_retained_even_when_a_process_remains() {
        let mut value = receipt();
        value["force_requested"] = json!(1); value["force_skipped"] = json!(1);
        value["status"] = json!("error"); value["code"] = json!("target_still_running");
        value["remaining"] = json!(1);
        let mut forced = None;
        assert_eq!(finish(Ok(bytes(value)), "openai", true, &mut forced, || Ok(false))
            .unwrap_err().code, "target_still_running");
        assert_eq!(forced, Some(1));
    }
    #[test]
    fn normal_close_does_not_accept_force_accounting() {
        let mut value = receipt(); value["force_requested"] = json!(2);
        assert_eq!(finish(Ok(bytes(value)), "openai", false, &mut None, || Ok(false))
            .unwrap_err().code, "invalid_close_receipt");
    }
    #[test]
    fn restarted_desktop_and_failed_independent_reader_prevent_success() {
        assert_eq!(finish(Ok(bytes(receipt())), "openai", false, &mut None, || Ok(true))
            .unwrap_err().code, "target_still_running");
        assert_eq!(finish(Ok(bytes(receipt())), "openai", false, &mut None,
            || Err(CoreError::new("desktop_inventory_incomplete", "fixture")))
            .unwrap_err().code, "desktop_inventory_incomplete");
    }
}
