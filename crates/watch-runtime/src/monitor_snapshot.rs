//! Shared monitor presentation. A cache becomes current only after its producer is verified.
use crate::{
    commands::{ReadCommand, ReadRunner},
    events::{Event, EventStore},
    native::{self, Observer},
    sampler::ProcessRound,
    storage::{sha256, strict_json, StateStore},
};
use claude_watch_core::{
    error::{CoreError, Result},
    processes::Identity,
    tag_flow,
};
use serde_json::{json, Value};
use serde::Deserialize;
use std::time::Duration;

pub const VERSION: &str = "3.0.0";
pub const MONITORED: [&str; 3] = ["claude", "codex", "chatgpt"];
pub fn endpoint(value: &Value) -> String {
    let Some(row) = value.as_array().filter(|v| v.len() == 2) else {
        return "未确认".into();
    };
    let Some(ip) = row[0].as_str() else {
        return "未确认".into();
    };
    let Some(port) = row[1].as_u64().filter(|v| *v > 0 && *v < 65536) else {
        return "未确认".into();
    };
    if ip.parse::<std::net::IpAddr>().is_err() {
        return "未确认".into();
    }
    format!(
        "{}:{port}",
        if ip.contains(':') {
            format!("[{ip}]")
        } else {
            ip.into()
        }
    )
}
fn count(v: &Value, key: &str) -> Option<u64> {
    v[key].as_u64()
}
pub fn connection_observation(raw: &Value, observed: f64) -> Value {
    let bad = |detail: &str| json!({"schema":1,"roundID":"","observedAt":0,"collectorState":"unknown","targetCount":0,"parsedCount":0,"acceptedCount":0,"correlatedCount":0,"unconfirmedCount":0,"dropped":{},"detail":detail,"uiFilteredCount":0,"uiDropped":{}});
    let Some(round) = raw["round_id"]
        .as_str()
        .filter(|s| !s.trim().is_empty() && s.len() <= 128)
    else {
        return bad("连接采样回执缺失或无效");
    };
    let Some(time) = raw["observed_at"]
        .as_f64()
        .filter(|v| v.is_finite() && *v > 0.0 && (*v - observed).abs() <= 5.0)
    else {
        return bad("连接采样与代理回合不一致");
    };
    let Some(state) = raw["collector_state"]
        .as_str()
        .filter(|s| ["ok", "empty", "partial", "failed", "no_targets", "unknown"].contains(s))
    else {
        return bad("连接采样状态无效");
    };
    let Some((targets, parsed, accepted, correlated, unknown)) = count(raw, "target_count")
        .zip(count(raw, "parsed_count"))
        .zip(count(raw, "accepted_count"))
        .zip(count(raw, "correlated_count"))
        .zip(count(raw, "unconfirmed_count"))
        .map(|((((a, b), c), d), e)| (a, b, c, d, e))
    else {
        return bad("连接采样计数无效");
    };
    let exited = match raw.get("confirmed_exited_count") {
        None => 0,
        Some(value) => match value.as_u64() {
            Some(value) if value <= targets => value,
            _ => return bad("已退出目标计数无效"),
        },
    };
    if (targets > 0 && exited == targets && (parsed > 0 || accepted > 0))
        || accepted > parsed
        || correlated.saturating_add(unknown) > accepted
        || (targets == 0 && parsed + accepted + correlated + unknown > 0)
        || (state == "no_targets" && targets != 0)
        || (state == "empty" && (targets == 0 || parsed != 0 || accepted != 0))
        || (state == "ok" && accepted == 0)
    {
        return bad("连接采样计数关系无效");
    }
    let Some(dropped) = raw["dropped"].as_object().filter(|m| {
        m.iter()
            .all(|(k, v)| !k.is_empty() && k.len() <= 80 && v.as_u64().is_some())
    }) else {
        return bad("连接丢弃计数无效");
    };
    let process_exited = match raw.get("process_confirmed_exited_count") { None => 0, Some(value) => match value.as_u64() { Some(n) if n <= u32::MAX as u64 => n, _ => return bad("进程退出计数无效") } };
    let process_reasons = match raw.get("process_reason_counts") {
        None => json!({}),
        Some(value) => {
            let Some(map) = value.as_object() else { return bad("进程采样原因无效") };
            if map.iter().any(|(k,v)| !["inventory_partial","inventory_truncated","inventory_count_mismatch","identity_unavailable","inventory_deadline","bundle_identity_unavailable","root_arguments_unavailable","other"].contains(&k.as_str()) || v.as_u64().is_none_or(|n| n > u32::MAX as u64)) { return bad("进程采样原因无效"); }
            value.clone()
        }
    };
    let state = if ["ok", "empty", "no_targets"].contains(&state)
        && dropped.values().any(|v| v.as_u64().is_some_and(|n| n > 0))
    {
        "partial"
    } else {
        state
    };
    json!({"schema":1,"roundID":round,"observedAt":time,"collectorState":state,"targetCount":targets,"parsedCount":parsed,"acceptedCount":accepted,"correlatedCount":correlated,"unconfirmedCount":unknown,
        "confirmedExitedCount":exited,"processConfirmedExitedCount":process_exited,"processReasonCounts":process_reasons,"dropped":dropped,"detail":raw["detail"].as_str().unwrap_or(""),"uiFilteredCount":0,"uiDropped":{}})
}
pub fn proxy(raw: &Value) -> Option<Value> {
    if raw["schema"] != 1 || !raw["entry"].is_object() || !raw["api"].is_object() {
        return None;
    }
    let observed = raw["observed_epoch"].as_f64().filter(|v| v.is_finite())?;
    let entry = &raw["entry"];
    let api = &raw["api"];
    let owner = entry["owners"]
        .as_array()
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or(json!({}));
    let mut flows = Vec::new();
    for flow in raw["flows"].as_array().into_iter().flatten() {
        let Some(pid) = flow["pid"].as_u64() else {
            continue;
        };
        let local = endpoint(&flow["local"]);
        let peer = endpoint(&flow["peer"]);
        let protocol = flow["protocol"].as_str().unwrap_or("").to_ascii_uppercase();
        let id = serde_json::to_vec(&json!([
            pid,
            protocol,
            local,
            peer,
            flow["connection_id"].as_str().unwrap_or("")
        ]))
        .ok()?;
        let destination = tag_flow::destination_evidence(
            &json!({"destinationIP":flow["destination_ip"],"destinationPort":flow["destination_port"],"destinationGeoIP":flow["destination_country"]}),
        );
        let chains: Vec<_> = flow["chains"]
            .as_array()
            .into_iter()
            .flatten()
            .rev()
            .filter_map(Value::as_str)
            .collect();
        flows.push(json!({"id":format!("{pid}|{}",&sha256(&id)[..20]),"pid":pid,"host":flow["host"].as_str().filter(|v|!v.is_empty()).unwrap_or(&peer),"peer":peer,"local":local,"protocol":protocol,
            "path":flow["path"].as_str().unwrap_or(""),"interface":flow["interface"].as_str().unwrap_or(""),"destinationIP":destination[0],"destinationPort":destination[1],"destinationIPState":destination[2],"destinationCountry":destination[3],
            "association":flow["association"].as_str().unwrap_or("unconfirmed"),"policy":flow["policy"].as_str().unwrap_or("unconfirmed"),"reason":flow["reason"].as_str().unwrap_or(""),"chains":chains}));
    }
    Some(
        json!({"backendVersion":raw.get("monitor_version").unwrap_or(&json!(VERSION)),"monitoredApps":raw.get("monitored_apps").unwrap_or(&json!(MONITORED)),"observedAt":observed,
        "entryState":entry["state"].as_str().unwrap_or("unconfirmed"),"entryReason":entry["reason"].as_str().unwrap_or(""),"entrySource":entry["source"].as_str().unwrap_or(""),"endpoint":entry["endpoint"].as_str().unwrap_or("http://127.0.0.1:7890"),
        "listenerPID":owner["pid"],"listenerPath":owner["executable"].as_str().unwrap_or(""),"listenerStarted":if entry["state"]=="verified"{owner.get("stamp").cloned().unwrap_or(Value::Null)}else{Value::Null},
        "apiState":api["state"].as_str().unwrap_or("unavailable"),"apiReason":api["reason"].as_str().unwrap_or(""),"mode":api["mode"].as_str().unwrap_or(""),"coversProxy":api["covers_7890"]==true,
        "expectedGroup":raw["expected_group"].as_str().unwrap_or(""),"expectedNode":raw["expected_node"].as_str().unwrap_or(""),"selectedNode":api["selected_node"].as_str().unwrap_or(""),"globalNode":api["global_node"].as_str().unwrap_or(""),
        "pinned":raw["pinned"]==true,"selectionChanged":raw["selection_changed"]==true,"flows":flows,"connectionObservation":connection_observation(&raw["connection_observation"],observed)}),
    )
}
pub fn process_rows(round: &ProcessRound, active: &[u32]) -> Vec<Value> {
    round.targets.iter().map(|p|{
    let kind=serde_json::to_value(p.kind).unwrap_or(json!("unknown"));let mut row=json!({"id":format!("{}|{}",p.identity.pid,p.identity.start_stamp),"pid":p.identity.pid,"started":p.identity.start_stamp,"kind":kind,"authorized":active.contains(&p.identity.pid)});
    if let Some(role)=round.roles.get(p.identity.pid.to_string()){if role["started"]==p.identity.start_stamp{for key in ["runtimeRole","serviceName","roleEvidence"]{row[key]=role[key].clone();}}}row
}).collect()
}
fn guard_phase_summary(name: &str, phase: &crate::guard_diagnostics::GuardPhase) -> String {
    let decision = match phase.decision.as_str() {
        "ok" => "已确认",
        "disabled" => "未启用",
        "unknown" => "未确认",
        _ => "不可用",
    };
    let backend = match phase.backend_reason.as_str() {
        "confirmed" => "后台身份已确认",
        "sample_not_ok" => "后台采样未正常",
        "heartbeat_unreadable" => "后台心跳不可读",
        "heartbeat_encoding" => "后台心跳编码无效",
        "heartbeat_stale" => "后台心跳过期或时间异常",
        "process_sample_failed" => "进程采样失败",
        "pid_invalid" | "pid_unconfirmed" | "uid_invalid" | "identity_mismatch"
        | "job_unconfirmed" => "后台身份或任务未确认",
        "time_invalid" => "后台心跳时间无效",
        "legacy_backend" => "旧版后台",
        _ => "后台原因未取得",
    };
    let heartbeat = match phase.guard_heartbeat_status.as_str() {
        "ok" => "正常",
        "degraded" => "降级",
        "unknown" => "未知",
        "disabled" => "停用",
        "missing" => "缺失",
        "unreadable" => "不可读",
        _ => "无效",
    };
    let age = |value: Option<f64>| match value {
        Some(n) if n < 0.0 => format!("未来 {:.1} 秒", -n),
        Some(n) => format!("{n:.1} 秒前"),
        None => "未知".into(),
    };
    let guard_age = age(phase.guard_heartbeat_age_seconds);
    let backend_age = age(phase.backend_heartbeat_age_seconds);
    let policy = match phase.policy_matches {
        Some(true) => "一致",
        Some(false) => "不一致",
        None => "未知",
    };
    let enabled = if phase.enabled && phase.guard_enabled {
        "启用"
    } else {
        "未启用"
    };
    let backend_status = match phase.backend_heartbeat_status.as_str() {
        "ok" => "正常",
        "error" => "错误",
        "missing" => "缺失",
        "unreadable" => "不可读",
        _ => "无效",
    };
    let code = phase
        .guard_heartbeat_code
        .as_deref()
        .map(|value| format!("（{value}）"))
        .unwrap_or_default();
    format!("{name}判定：{decision}（{backend}）；判定后附读：后台心跳 {backend_status} / {backend_age}，保护心跳 {heartbeat}{code} / {guard_age}，策略 {policy}，保护 {enabled}")
}
fn guard_decision_label(phase: &crate::guard_diagnostics::GuardPhase) -> &'static str {
    match phase.decision.as_str() {
        "ok" => "已确认",
        "disabled" => "未启用",
        "unknown" => "未确认",
        _ => "不可用",
    }
}
fn present_event(e: Event) -> Value {
    let (title, mut severity, category) = match e.category.as_str() {
        "traffic-counter" => ("流量采样", "info", "network"),
        "sensitive-open-descriptor" => ("敏感目录文件描述符", "warning", "process"),
        "unauthorized-process" => ("发现未关联会话的进程", "warning", "process"),
        "launchd-label-candidate" => ("后台任务名称候选", "notice", "service"),
        "activity-unavailable" => ("活动采样未完成", "warning", "service"),
        "activity-recovered" => ("活动采样恢复", "info", "service"),
        "daemon-start" => ("监控服务已启动", "info", "service"),
        "daemon-stop" => ("监控服务已停止", "info", "service"),
        "controlled-launch" => ("受控启动", "info", "process"),
        "controlled-exit" => ("CLI已退出", "info", "process"),
        "alert-dispatched" => ("通知请求已提交系统", "notice", "service"),
        "alert-failed" => ("系统提醒发送失败", "warning", "service"),
        "dns-diagnostic" => ("DNS 检测", "info", "network"),
        "webrtc-diagnostic" => ("WebRTC 检测", "info", "network"),
        "guard-diagnostic" => ("保护后台心跳检查", "info", "service"),
        "guard-decision" => ("会话保护判定", "info", "service"),
        "guard-stop" => ("会话保护退出", "info", "service"),
        "receipt-diagnostic" => ("检测回执提交", "info", "network"),
        "sampling-state" => ("采样状态变化", "info", "network"),
        "background-evidence" => ("后台保护证据更新", "info", "service"),
        _ => ("监控记录", "info", "service"),
    };
    let fields = &e.fields;
    if e.category == "guard-decision" && matches!(fields.status.as_deref(), Some("risk" | "locked")) { severity = "warning"; }
    if e.category == "receipt-diagnostic" && fields.status.as_deref() == Some("rejected") { severity = "warning"; }
    if e.category == "background-evidence" && fields.status.as_deref() == Some("risk") {
        severity = "error";
    }
    if matches!(e.category.as_str(), "dns-diagnostic" | "webrtc-diagnostic") {
        severity = match fields.status.as_deref() {
            Some("difference" | "incomplete") => "warning",
            _ => "info",
        };
    } else if e.category == "controlled-exit" && fields.code.as_deref().is_some_and(|s| s != "0") {
        severity = "warning";
    } else if e.category == "daemon-stop" && fields.status.as_deref() == Some("error") {
        severity = "error";
    } else if e.category == "guard-diagnostic" && fields.status.as_deref() == Some("disabled") {
        severity = "warning";
    }
    if matches!(fields.status.as_deref(), Some("error" | "failed" | "fail")) {
        severity = "error";
    } else if severity == "info"
        && matches!(
            fields.status.as_deref(),
            Some("timeout" | "partial" | "incomplete" | "blocked" | "unknown" | "degraded")
        )
    {
        severity = "warning";
    }
    let mut summary = Vec::new();
    let mut explanation = None;
    if title == "监控记录" {
        summary.push(format!("事件：{}", e.category));
    }
    if let Some(round) = &fields.guard_diagnostics {
        summary.push(format!(
            "检测前：{} · 检测后：{}",
            guard_decision_label(&round.before),
            guard_decision_label(&round.after)
        ));
        let elapsed = round.after.sampled_at - round.before.sampled_at;
        if elapsed >= 0.0 {
            summary.push(format!("两次附读间隔 {elapsed:.1} 秒"));
        } else {
            summary.push("两次附读时间倒退".into());
        }
        explanation = Some(format!(
            "{}\n{}\n心跳状态与年龄是各次判定后的附加读取，不代表判定瞬间。",
            guard_phase_summary("检测前", &round.before),
            guard_phase_summary("检测后", &round.after)
        ));
    }
    if let Some(source) = fields
        .action
        .as_deref()
        .filter(|_| e.category != "guard-diagnostic")
    {
        if matches!(e.category.as_str(), "dns-diagnostic" | "webrtc-diagnostic") {
            let source = match source {
                "netcoffee" => "Net.Coffee",
                "ipleak" => "IPLeak.net",
                "local" => "本机 WebRTC",
                other => other,
            };
            summary.push(format!("来源：{source}"));
        } else {
            let label = match (e.category.as_str(), source) {
                ("guard-stop", "request_post_action") => "退出请求（事后记录）",
                ("guard-stop", "retry_post_action") => "重试退出（事后记录）",
                ("guard-stop", "result_post_action") => "退出结果（事后记录）",
                ("guard-decision", "post_action") => "保护判定（事后记录）",
                ("sampling-state", "transition") => "状态变化",
                ("sampling-state", "summary") => "稳定期摘要",
                _ => source,
            };
            summary.push(format!("操作：{label}"));
        }
    }
    if let Some(status) = fields.status.as_deref() {
        let status = match status {
            "matched" => "本轮结果一致",
            "difference" => "本轮发现差异",
            "incomplete" => "本轮未完成",
            "ok" => "完成",
            "exited" => "已退出",
            "error" => "异常",
            "stopped" => "已停止",
            "unknown" => "未确认",
            "disabled" => "未启用",
            "partial" => "部分完成",
            "sent" => "已发送",
            "accepted" if e.category == "receipt-diagnostic" => "回执已保存（不代表检测通过）",
            "rejected" if e.category == "receipt-diagnostic" => "回执未接受",
            "confirmed" => "已确认退出",
            "risk" => "已确认风险",
            "locked" => "会话已锁定",
            "running" => "运行中",
            "degraded" => "采样异常",
            "empty" => "完整空样本",
            "no_targets" => "无目标",
            "failed" if e.category == "guard-stop" => "退出失败",
            "failed" => "失败",
            other => other,
        };
        summary.push(format!("结果：{status}"));
    }
    if let Some(stage) = fields.stage.as_deref() {
        let stage = match stage {
            "dns" => "DNS 查询",
            "dns_images" => "DNS 权威查询轮次",
            "dns_records" => "DNS 记录读取",
            "http" => "HTTP 参考",
            "geoip" => "地址归属",
            "ice" => "ICE 采集",
            "collector" => "采集组件",
            other => other,
        };
        summary.push(format!("阶段：{stage}"));
    }
    if let Some(code) = fields
        .code
        .as_deref()
        .filter(|s| !matches!(*s, "matched" | "difference" | "none"))
    {
        let reason = match code {
            "timeout" => Some("超时"),
            "context_changed" => Some("网络上下文变化"),
            "component_missing" => Some("检测组件缺失"),
            "invalid_result" => Some("检测结果无效"),
            "page_failed" => Some("检测页面失败"),
            "script_failed" => Some("检测脚本失败"),
            "network_error" => Some("网络请求失败"),
            "incomplete" => Some("结果不完整"),
            "native_listener_worker_failed" => Some("系统监听通道中断"),
            "backend_error" => Some("后台执行异常"),
            "claude_still_running" | "target_still_running" => Some("退出后进程仍在运行"),
            "permission_denied" => Some("退出权限未确认"),
            "component_unavailable" => Some("退出组件不可用"),
            "identity_unconfirmed" => Some("进程身份未确认"),
            "force_requested" => Some("已向身份核验通过的进程发送强制退出请求"),
            "force_report_unavailable" => Some("进程已退出，强制步骤记录不可确认"),
            _ => None,
        };
        if let Some(reason) = reason {
            summary.push(format!("原因：{reason}（{code}）"));
        } else if e.category == "controlled-exit" {
            summary.push(format!("退出码：{code}"));
        } else if e.category == "sensitive-open-descriptor" {
            summary.push(format!("类型：{code}"));
        } else {
            summary.push(format!("代码：{code}"));
        }
    }
    if let Some(previous) = &fields.previous_state {
        let label = match previous.as_str() { "ok" => "正常", "partial" => "部分完成", "running" => "运行中", "degraded" => "采样异常", "unknown" => "未确认", "safe" => "安全", "risk" => "风险", "locked" => "锁定", "empty" => "完整空样本", "no_targets" => "无目标", "failed" => "失败", "idle" => "待命", "disabled" => "未启用", "missing" => "无会话", "pending" => "建立中", _ => "其他" };
        summary.push(format!("先前状态：{label}"));
    }
    if let Some(counts) = &fields.process_reason_counts {
        for (reason, count) in counts { if *count > 0 {
            let label = match reason.as_str() { "identity_unavailable" => "进程身份不可读", "inventory_deadline" => "进程枚举超时", "inventory_truncated" => "进程列表截断", "inventory_count_mismatch" => "进程数量不一致", "inventory_partial" => "进程枚举不完整", "bundle_identity_unavailable" => "应用身份不可读", "root_arguments_unavailable" => "入口参数不可读", _ => "其他进程原因" };
            summary.push(format!("{label}：{count}"));
        }}
    }
    if let Some(diag) = &fields.sampling_diagnostics {
        summary.push(format!("进程采样：{}，网络采样：{}{}，活动：{}，字节：{}", match diag.process_complete {Some(true)=>"完整",Some(false)=>"不完整",None=>"未知"}, match diag.network_quality {Some(true)=>"完整",Some(false)=>"不完整",None=>"未知"}, match diag.network_reused {Some(true)=>"（复用）",Some(false)=>"（新采样）",None=>""}, diag.activity_state, diag.bytes_state));
        if diag.process_confirmed_exited_count > 0 { summary.push(format!("进程枚举确认退出：{}", diag.process_confirmed_exited_count)); }
        if let Some(code) = &diag.publisher_error_code { summary.push(format!("快照采样错误：{code}")); }
        for (reason,count) in &diag.activity_reasons { if *count > 0 { summary.push(format!("活动采样 {reason}：{count}")); } }
    }
    if let Some(count) = fields.confirmed_exited_count { summary.push(format!("确认退出目标：{count}")); }
    if let Some(counts) = &fields.reason_counts {
        for (reason, count) in counts {
            let label = match reason.as_str() {
                "process_exited" => "进程退出", "identity_changed" => "身份变化", "identity_unavailable" => "进程身份不可读", "missing_target_sample" => "目标缺样", "fd_inventory_unavailable" => "描述符不可读", "socket_deadline" => "采样超时", "socket_info_unavailable" => "套接字不可读", "fd_closed_during_sample" => "采样时句柄关闭", "fd_list_truncated" => "描述符列表截断", "foreign_socket_pid" => "套接字身份不符", "socket_sample_partial" => "采样不完整", _ => "其他原因",
            };
            if *count > 0 { summary.push(format!("{label}：{count}")); }
        }
    }
    if e.category == "guard-decision" {
        for (name, sample) in [("出口采样", fields.egress_sampled_at), ("DNS采样", fields.dns_sampled_at), ("WebRTC采样", fields.webrtc_sampled_at)] {
            summary.push(sample.map(|v| format!("{name}：本事件前 {:.1} 秒", (e.time - v).max(0.0))).unwrap_or_else(|| format!("{name}：未提供")));
        }
    }
    if let Some(pid) = fields.pid {
        summary.push(format!("PID {pid}"));
    }
    if let Some(count) = fields.count {
        if e.category == "guard-stop" {
            summary.push(format!("强制退出请求 {count} 项"));
        } else {
            summary.push(format!("数量 {count}"));
        }
    }
    if let Some(bytes) = fields.bytes_in {
        summary.push(format!("接收 {bytes} B"));
    }
    if let Some(bytes) = fields.bytes_out {
        summary.push(format!("发送 {bytes} B"));
    }
    if let Some(seconds) = fields.elapsed_seconds {
        summary.push(format!("{} {:.1} 秒", if e.category == "sampling-state" && fields.action.as_deref() == Some("summary") { "汇总区间" } else if e.category == "sampling-state" { "先前状态持续" } else { "耗时" }, seconds));
    }
    if let Some(version) = &fields.version {
        summary.push(format!("后台版本 {version}"));
    }
    if let Some(label) = &fields.service_label {
        summary.push(format!("后台任务：{label}"));
    }
    if let Some(operation) = &fields.operation {
        if !matches!(
            e.category.as_str(),
            "dns-diagnostic" | "webrtc-diagnostic" | "guard-diagnostic"
        ) {
            let label = match operation.as_str() { "health" => "总采样", "connection" => "连接采样", "guard_stop" => "保护退出通知", "guard_sampling" => "保护采样通知", "monitor_sampling" => "监控采样通知", "sensitive_file" => "敏感文件通知", _ => operation };
            summary.push(format!("来源：{label}"));
        }
    }
    let raw = serde_json::to_string(fields).unwrap_or_default();
    let detail = if summary.is_empty() {
        "没有更多摘要，可展开原始记录。".to_string()
    } else {
        summary.join(" · ")
    };
    let id = if e.id.is_empty() {
        format!("{}|{}|{}", e.time, e.category, sha256(raw.as_bytes()))
    } else {
        e.id
    };
    json!({"id":id,"timestamp":format!("{:.0}",e.time),"epoch":e.time,"severity":severity,"category":category,"title":title,"detail":detail,"rawDetail":raw,"explanation":explanation})
}
pub fn events(store: &StateStore) -> Result<Vec<Value>> {
    Ok(EventStore::new(store.clone())
        .recent_non_traffic(100)?
        .into_iter()
        .rev()
        .map(present_event)
        .collect())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventHistoryQuery {
    pub filter: String,
    pub query: String,
    pub offset: usize,
}
/// Filter the entire retained history before applying the fixed page size.
pub fn event_history(store: &StateStore, query: &EventHistoryQuery) -> Result<Value> {
    if !matches!(
        query.filter.as_str(),
        "key" | "all" | "attention" | "network" | "process" | "sample"
    ) || query.query.len() > 512
    {
        return Err(CoreError::new("invalid_event_query", "事件筛选条件无效"));
    }
    let history = EventStore::new(store.clone()).history()?;
    let term = query.query.trim().to_lowercase();
    let mut page = Vec::new();
    let mut total = 0usize;
    for e in history.events {
        let sample = matches!(e.category.as_str(), "traffic-counter" | "sampling-state");
        let value = present_event(e);
        let severity = value["severity"].as_str().unwrap_or("");
        let category = value["category"].as_str().unwrap_or("");
        let selected = match query.filter.as_str() {
            "key" => !sample,
            "all" => true,
            "attention" => matches!(severity, "notice" | "warning" | "error"),
            "network" => category == "network" && !sample,
            "process" => category == "process",
            "sample" => sample,
            _ => false,
        };
        let contains = term.is_empty()
            || ["title", "detail", "rawDetail", "explanation", "timestamp"]
                .iter()
                .any(|key| {
                    value[*key]
                        .as_str()
                        .is_some_and(|s| s.to_lowercase().contains(&term))
                });
        if selected && contains {
            if total >= query.offset && page.len() < 100 {
                page.push(value);
            }
            total += 1;
        }
    }
    let next = query.offset.saturating_add(page.len());
    Ok(
        json!({"status":"ok","events":page,"total":total,"nextOffset":next,"hasMore":next < total,"invalidRecords":history.invalid_records}),
    )
}
pub fn assemble(
    store: &StateStore,
    round: &ProcessRound,
    tag: &Value,
    producer: &Identity,
    mode: &str,
    quality: bool,
    at: f64,
) -> Value {
    let agent = store
        .paths
        .home
        .join("Library/LaunchAgents/io.local.claudewatch.agent.plist");
    let installed = store.paths.watch().join("runtime/watch-engine").is_file() && agent.is_file();
    let (events, event_error) = match events(store) { Ok(events) => (events, None), Err(_) => (Vec::new(), Some("事件日志不可读取")) };
    let channel_supervision = store
        .read_json(
            &store.paths.watch().join("state/channel-supervision.json"),
            Value::Null,
        )
        .unwrap_or(Value::Null);
    let channel_events = store
        .read_json(
            &store.paths.watch().join("state/channel-events.json"),
            json!([]),
        )
        .unwrap_or_else(|_| json!([]));
    json!({"capturedAt":at,"health":{"state":if quality{"running"}else{"degraded"},"mode":mode,"pid":producer.pid,"heartbeatAge":0.0,"started":producer.start_stamp,"detail":if quality{"后台进程存活，采样心跳正常"}else{"部分监控采样需要检查"},"alerts":"开启"},
        "installed":installed,"autoStart":false,"keepAlive":false,"hasBaseline":has_session_reference(store,at),"stderrBytes":0,
        "processes":process_rows(round,&[]),"events":events,"eventError":event_error,"proxy":proxy(tag),"proxyError":Value::Null,"channelSupervision":channel_supervision,"channelEvents":channel_events,"backendVersion":VERSION,"monitoredApps":MONITORED,"logPath":store.paths.base().join("events.jsonl")})
}
/// Applies independently verified LaunchAgent registration facts without changing
/// the legacy monitor snapshot shape or its sampling-health interpretation.
pub fn with_registration(mut snapshot: Value, registration: &Value) -> Value {
    for key in ["installed", "autoStart", "keepAlive"] {
        snapshot[key] = json!(registration[key] == true);
    }
    snapshot
}
pub fn empty(store: &StateStore, at: f64, detail: &str) -> Value {
    let (events, event_error) = match events(store) { Ok(events) => (events, None), Err(_) => (Vec::new(), Some("事件日志不可读取")) };
    json!({"capturedAt":at,"health":{"state":"unavailable","mode":"UNKNOWN","pid":Value::Null,"heartbeatAge":Value::Null,"started":"","detail":detail,"alerts":"未知"},
    "installed":store.paths.watch().join("runtime/watch-engine").is_file(),"autoStart":false,"keepAlive":false,"hasBaseline":has_session_reference(store,at),"stderrBytes":0,"processes":[],"events":events,"eventError":event_error,"proxy":Value::Null,"proxyError":detail,"backendVersion":Value::Null,"monitoredApps":[],"logPath":store.paths.base().join("events.jsonl")})
}
fn has_session_reference(store: &StateStore, at: f64) -> bool {
    crate::session_store::SessionStore::new(store.clone())
        .load(at)
        .ok()
        .flatten()
        .is_some()
}
pub fn published_path(store: &StateStore) -> std::path::PathBuf {
    store.paths.watch().join("state/runtime-snapshot.json")
}
pub fn publish(store: &StateStore, snapshot: &Value, producer: &Identity) -> Result<()> {
    store.atomic_json(
        &published_path(store),
        &json!({"schema":1,"producer":producer,"snapshot":snapshot}),
    )
}
pub fn read<R: ReadRunner>(store: &StateStore, runner: &R) -> Result<Value> {
    let at = native::now();
    let Some(bytes) = store.read_bytes(&published_path(store), 8 * 1024 * 1024)? else {
        return Ok(empty(store, at, "后台尚未提供Rust采样快照"));
    };
    let raw = strict_json(&bytes)?;
    let snapshot = &raw["snapshot"];
    let producer: Identity = serde_json::from_value(raw["producer"].clone())
        .map_err(|_| CoreError::new("invalid_snapshot_producer", "快照生产者身份无效"))?;
    if raw["schema"] != 1
        || !producer.valid()
        || !snapshot["capturedAt"]
            .as_f64()
            .is_some_and(|v| v.is_finite() && (0.0..=30.0).contains(&(at - v)))
    {
        return Ok(empty(store, at, "后台快照已过期或字段无效"));
    }
    let env = Observer { runner }.environment()?;
    if env["uid"] != producer.uid {
        return Ok(empty(store, at, "后台快照不属于当前用户"));
    }
    let job = runner.run(
        ReadCommand::LaunchctlGuiAgent { uid: producer.uid },
        &[],
        Duration::from_secs(3),
        256 * 1024,
    )?;
    let direct_job = job.status == 0
        && crate::commands::loaded_agent_identity(job.text()?) == Some(("running", producer.pid));
    if !direct_job && !crate::native_listener::registered_worker(store, runner, producer.pid) {
        return Ok(empty(store, at, "后台任务与快照生产者不一致"));
    }
    let current =
        Observer { runner }.identities(std::slice::from_ref(&producer), "snapshot-producer")?;
    if !current
        .get(&producer.pid)
        .is_some_and(|p| p.same_process(&producer))
    {
        return Ok(empty(store, at, "后台进程启动身份未通过核对"));
    }
    let mut result = snapshot.clone();
    let age = at - snapshot["capturedAt"].as_f64().unwrap();
    result["health"]["heartbeatAge"] = json!(age);
    Ok(result)
}
