//! Installation verification by the final, signed runtime engine. Acquiring
//! these handles verifies the installed broker and both protected listeners;
//! this short-lived command never accepts or forwards application traffic.
use claude_watch_core::error::{CoreError, Result};
use claude_watch_system::launchd_gateway::{acquire_gateway_listener_for_install, VerifiedGatewayListener};
use serde_json::{json, Value};

pub fn run(arguments: &[String]) -> Result<Value> {
    check(arguments, acquire_gateway_listener_for_install)
}

fn check(
    arguments: &[String],
    acquire: impl FnOnce() -> std::io::Result<VerifiedGatewayListener>,
) -> Result<Value> {
    if arguments != ["gateway-endpoint-check"] {
        return Err(CoreError::new(
            "invalid_arguments",
            "网关端点核验不接受额外参数",
        ));
    }
    let verified = acquire().map_err(|error| {
        CoreError::new(
            "gateway_endpoint_unverified_i03",
            &format!("系统托管网关端点核验失败：{error}"),
        )
    })?;
    let (_listener, protection) = verified.into_parts();
    // VerifiedGatewayListener can only be constructed after kernel-authenticated
    // handoff, root ownership, signature, socket options and IPv4/IPv6 checks.
    // A present config or an ordinary connect() is not an installation receipt.
    Ok(json!({
        "status": "ok",
        "gateway_endpoint": protection.endpoint().to_string(),
        "ipv4_verified": true,
        "ipv6_verified": true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unexpected_arguments_never_request_protected_handles() {
        for arguments in [
            vec!["gateway-endpoint-check".into(), "--apply".into()],
            vec!["gateway-endpoint-check".into(), "--home".into(), "/tmp/other".into()],
            Vec::new(),
        ] {
            let error = check(&arguments, || panic!("invalid input must not acquire handles"))
                .unwrap_err();
            assert_eq!(error.code, "invalid_arguments");
        }
    }

    #[test]
    fn failed_handoff_keeps_the_real_error_instead_of_install_success() {
        let error = check(&["gateway-endpoint-check".into()], || {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "engine identity does not match approved executable",
            ))
        })
        .unwrap_err();
        assert_eq!(error.code, "gateway_endpoint_unverified_i03");
        assert!(error.message.contains("engine identity does not match approved executable"));
    }
}
