//! GUI-compatible, fixed-endpoint Net.Coffee receipt dispatch.
use claude_watch_core::{
    cli::Request,
    error::{CoreError, Result},
};
use claude_watch_runtime::{
    network_client::{NetworkClient, Receipt, UreqTransport, DEFAULT_PROXY},
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

static HAR_TEMPORARY_ID: AtomicU64 = AtomicU64::new(0);

fn utc_timestamp(value: f64) -> String {
    let seconds = if value.is_finite() && value >= 0.0 {
        value.floor() as i64
    } else {
        0
    };
    let days = seconds.div_euclid(86_400);
    let within_day = seconds.rem_euclid(86_400);
    // Civil date from Unix-day count, adapted from the public-domain
    // Gregorian conversion by Howard Hinnant.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let day_of_year = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = month_index + if month_index < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        within_day / 3_600,
        (within_day % 3_600) / 60,
        within_day % 60
    )
}

fn har_value(receipt: &Receipt) -> Value {
    let raw_bytes = receipt.raw.len();
    json!({"log":{"version":"1.2","creator":{"name":"Claude Watch HTTP receipt exporter","version":"1"},"entries":[{
        "startedDateTime":utc_timestamp(receipt.queried_at),
        "time":((receipt.finished_at-receipt.queried_at).max(0.0))*1000.0,
        "request":{"method":"GET","url":receipt.source_url,"httpVersion":"HTTP/1.1","headers":[],"queryString":[],"cookies":[],"headersSize":-1,"bodySize":0},
        "response":{"status":receipt.http_status.unwrap_or(0),"statusText":"","httpVersion":"HTTP/1.1","headers":[],"cookies":[],"content":{"size":raw_bytes,"mimeType":if receipt.kind=="trace"{"text/plain"}else{"application/json"},"text":receipt.raw},"redirectURL":"","headersSize":-1,"bodySize":raw_bytes},
        "cache":{},"timings":{"send":0,"wait":((receipt.finished_at-receipt.queried_at).max(0.0))*1000.0,"receive":0},
        "_provenance":"Claude Watch own HTTP client response; not a packet/browser capture"
    }]}})
}

fn export_har(path: &str, receipt: &Receipt) -> Result<()> {
    let requested = Path::new(path);
    if requested.as_os_str().is_empty()
        || requested
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(CoreError::new("export_failed", "HAR 导出路径无效"));
    }
    let output = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| CoreError::new("export_failed", "导出目录不可读取"))?
            .join(requested)
    };
    let parent = output
        .parent()
        .filter(|parent| parent.is_dir())
        .ok_or_else(|| CoreError::new("export_failed", "HAR 导出目录不可用"))?;
    for ancestor in output.ancestors() {
        if fs::symlink_metadata(ancestor).is_ok_and(|meta| meta.file_type().is_symlink()) {
            return Err(CoreError::new(
                "unsafe_export_path",
                "拒绝通过符号链接导出 HAR",
            ));
        }
    }
    if fs::symlink_metadata(&output).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(CoreError::new("unsafe_export_path", "拒绝覆盖符号链接 HAR"));
    }
    let encoded = serde_json::to_vec(&har_value(receipt))
        .map_err(|_| CoreError::new("export_failed", "HAR 无法编码"))?;
    if encoded.len() > 1_048_576 {
        return Err(CoreError::new("export_failed", "HAR 导出超过资源上限"));
    }
    let temporary = parent.join(format!(
        ".coffee-har-{}-{}",
        std::process::id(),
        HAR_TEMPORARY_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| CoreError::new("export_failed", "HAR 临时文件不可写"))?;
        file.write_all(&encoded)
            .and_then(|_| file.sync_all())
            .map_err(|_| CoreError::new("export_failed", "HAR 写入未完成"))?;
        if fs::symlink_metadata(parent).is_ok_and(|meta| meta.file_type().is_symlink()) {
            return Err(CoreError::new("unsafe_export_path", "HAR 导出目录已变更"));
        }
        fs::rename(&temporary, &output)
            .map_err(|_| CoreError::new("export_failed", "HAR 导出未完成"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Dispatches the exact Net.Coffee operations previously exposed by
/// `netcoffee_client.py`. Metadata calls retain the runtime's shared durable
/// cache and cooling receipts; trace and DNS are intentionally uncached.
pub fn dispatch(request: &Request, paths: Paths) -> Result<Option<Value>> {
    if request.command != "coffee" {
        return Ok(None);
    }
    let kind = request
        .action
        .as_deref()
        .ok_or_else(|| CoreError::new("invalid_arguments", "缺少 Net.Coffee 查询类型"))?;
    let query = request.target.as_deref().unwrap_or("");
    if kind == "trace" && !query.is_empty() {
        return Err(CoreError::new("invalid_arguments", "trace 不接受查询参数"));
    }
    if kind != "trace" && query.is_empty() {
        return Err(CoreError::new("invalid_arguments", "查询参数不能为空"));
    }
    let network = NetworkClient::new(Arc::new(UreqTransport), Some(DEFAULT_PROXY.into()))
        .map_err(|error| CoreError::new(&error.code, &error.detail))?
        .with_state_store(StateStore::new(paths));
    let receipt = match kind {
        "lookup" | "geoip" | "risk" => network.metadata(kind, query),
        "dns" => network.netcoffee_dns(query),
        "trace" => network.trace("https://1.1.1.1/cdn-cgi/trace"),
        _ => {
            return Err(CoreError::new(
                "invalid_arguments",
                "不支持的 Net.Coffee 查询类型",
            ))
        }
    };
    if let Some(path) = request.value("record-har") {
        export_har(path, &receipt)?;
    }
    Ok(Some(receipt.display_value()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::{BTreeMap, BTreeSet, HashMap},
        fs,
    };

    fn request(kind: &str, query: &str) -> Request {
        Request {
            command: "coffee".into(),
            action: Some(kind.into()),
            target: Some(query.into()),
            flags: BTreeSet::new(),
            values: BTreeMap::new(),
            receipt_id: None,
            child_args: Vec::new(),
        }
    }
    fn paths() -> (Paths, std::path::PathBuf) {
        let home = std::env::temp_dir().join(format!("cw-coffee-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        (Paths::new(&home).unwrap(), home)
    }
    fn receipt() -> Receipt {
        Receipt {
            kind: "lookup".into(),
            query: "1.1.1.1".into(),
            source_url: "https://ip.net.coffee/api/ip/lookup/1.1.1.1".into(),
            queried_at: 1_700_000_000.0,
            finished_at: 1_700_000_000.25,
            status: "complete".into(),
            http_status: Some(200),
            raw: r#"{"ip":"1.1.1.1"}"#.into(),
            data: Some(json!({"ip":"1.1.1.1"})),
            error: None,
            context_id: None,
            measurement_at: None,
            response_headers: HashMap::new(),
            transport: "fixture".into(),
            cache_state: "miss".into(),
            cache_age: None,
            retry_after: None,
            last_good: None,
        }
    }

    #[test]
    fn invalid_metadata_argument_returns_a_receipt_without_network() {
        let (paths, home) = paths();
        let value = dispatch(&request("lookup", "127.0.0.1"), paths)
            .unwrap()
            .unwrap();
        assert_eq!(value["kind"], "lookup");
        assert_eq!(value["query"], "127.0.0.1");
        assert_eq!(value["status"], "error");
        assert_eq!(value["sourceURL"], "");
        assert_eq!(value["cache_state"], "miss");
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn invalid_dns_token_returns_a_receipt_without_network() {
        let (paths, home) = paths();
        let value = dispatch(&request("dns", "../etc"), paths).unwrap().unwrap();
        assert_eq!(value["kind"], "dns");
        assert_eq!(value["status"], "error");
        assert_eq!(value["sourceURL"], "");
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn invalid_kind_is_rejected_before_transport() {
        let (paths, home) = paths();
        let error = dispatch(&request("portscan", "1.1.1.1"), paths).unwrap_err();
        assert_eq!(error.code, "invalid_arguments");
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn har_export_reuses_receipt_and_omits_sensitive_headers() {
        let directory = std::path::PathBuf::from("/private/tmp")
            .join(format!("cw-coffee-har-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let output = directory.join("receipt.har");
        export_har(output.to_str().unwrap(), &receipt()).unwrap();
        let value: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
        let entry = &value["log"]["entries"][0];
        assert_eq!(
            entry["request"]["url"],
            "https://ip.net.coffee/api/ip/lookup/1.1.1.1"
        );
        assert_eq!(entry["response"]["content"]["text"], r#"{"ip":"1.1.1.1"}"#);
        assert_eq!(entry["request"]["headers"], json!([]));
        assert_eq!(entry["response"]["cookies"], json!([]));
        assert_eq!(
            entry["_provenance"],
            "Claude Watch own HTTP client response; not a packet/browser capture"
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn har_export_rejects_a_symlink_destination_without_writing() {
        let directory = std::path::PathBuf::from("/private/tmp")
            .join(format!("cw-coffee-har-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let target = directory.join("target.har");
        let link = directory.join("receipt.har");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = export_har(link.to_str().unwrap(), &receipt()).unwrap_err();
        assert_eq!(error.code, "unsafe_export_path");
        assert!(!target.exists());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn record_har_parser_value_exports_the_same_invalid_receipt_without_network() {
        let (paths, home) = paths();
        let directory = std::path::PathBuf::from("/private/tmp")
            .join(format!("cw-coffee-har-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let output = directory.join("invalid.har");
        let request = Request::parse(&[
            "coffee".into(),
            "lookup".into(),
            "127.0.0.1".into(),
            "--record-har".into(),
            output.to_string_lossy().into_owned(),
        ])
        .unwrap();
        let value = dispatch(&request, paths).unwrap().unwrap();
        let har: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(har["log"]["entries"][0]["response"]["status"], 0);
        let _ = fs::remove_dir_all(home);
        let _ = fs::remove_dir_all(directory);
    }
}
