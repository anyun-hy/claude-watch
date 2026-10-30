//! Managed routing coverage and preservation of unrelated user rules.
//! Conservative, ownership-marked routing rules.  This module never talks to a
//! controller and never decrypts TAG configuration; callers supply snapshots.
use claude_watch_core::{
    error::{CoreError, Result},
    tag_config::RULE_DOMAINS,
};
use serde_json::{json, Value};

pub const BEGIN: &str = "# >>> ClaudeWatch pinned rules >>>";
pub const END: &str = "# <<< ClaudeWatch pinned rules <<<";
pub const LEGACY_BEGIN: &str = "# >>> claude-switcher pinned rules >>>";
pub const LEGACY_END: &str = "# <<< claude-switcher pinned rules <<<";

fn invalid(code: &str, message: &str) -> CoreError {
    CoreError::new(code, message)
}
fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}
fn valid_group(group: &str) -> bool {
    !group.is_empty()
        && group.chars().count() <= 256
        && !group.chars().any(|c| matches!(c, '\r' | '\n' | '\0'))
}

/// Removes exactly one block owned by ClaudeWatch.  Damaged or duplicated
/// markers are rejected so an edit can never consume user rules by accident.
pub fn remove_block(text: &str) -> Result<String> {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let starts: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| (l.trim() == BEGIN || l.trim() == LEGACY_BEGIN).then_some(i))
        .collect();
    let ends: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| (l.trim() == END || l.trim() == LEGACY_END).then_some(i))
        .collect();
    if starts.is_empty() && ends.is_empty() {
        return Ok(text.into());
    }
    if starts.len() != 1 || ends.len() != 1 || starts[0] >= ends[0] {
        return Err(invalid(
            "ambiguous_rules",
            "规则标记不完整或重复；未修改配置",
        ));
    }
    Ok(lines[..starts[0]]
        .iter()
        .chain(lines[ends[0] + 1..].iter())
        .copied()
        .collect())
}

/// Renders only the managed prepend-rules block and preserves every unrelated
/// line, including a user's TAG or Clash rules.
pub fn render_rules(text: &str, group: &str, remove: bool) -> Result<String> {
    if !valid_group(group) {
        return Err(invalid("invalid_group", "请选择有效的代理组"));
    }
    let clean = remove_block(text)?;
    if remove {
        return Ok(clean);
    }
    let mut lines: Vec<String> = clean.split_inclusive('\n').map(str::to_owned).collect();
    if !clean.is_empty() && !clean.ends_with('\n') {
        if let Some(last) = lines.last_mut() {
            last.push('\n');
        }
    }
    let headers: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| {
            l.strip_prefix("prepend-rules")
                .filter(|x| x.trim_start().starts_with(':'))
                .map(|_| i)
        })
        .collect();
    if headers.len() > 1 {
        return Err(invalid("ambiguous_rules", "存在重复 prepend-rules 键"));
    }
    let position = if let Some(i) = headers.first().copied() {
        let value = lines[i].split_once(':').map(|x| x.1.trim()).unwrap_or("");
        if !value.is_empty() && !value.starts_with('#') && !matches!(value, "[]" | "null" | "~") {
            return Err(invalid(
                "unsupported_yaml",
                "现有规则使用复杂行内格式，请手动调整；原配置未改",
            ));
        }
        if !value.is_empty() {
            lines[i] = "prepend-rules:\n".into();
        }
        i + 1
    } else {
        lines.push("prepend-rules:\n".into());
        lines.len()
    };
    let mut block = format!("  {BEGIN}\n");
    for domain in RULE_DOMAINS {
        block.push_str(&format!(
            "  - {}\n",
            serde_json::to_string(&format!("DOMAIN-SUFFIX,{domain},{group}")).unwrap()
        ));
    }
    block.push_str(&format!("  {END}\n"));
    lines.insert(position, block);
    Ok(lines.concat())
}

fn parse_rule(raw: &str) -> Option<(String, String, String)> {
    let raw = raw.trim().trim_matches('"').trim_matches('\'');
    let mut p = raw.split(',').map(str::trim);
    let kind = p.next()?.to_ascii_uppercase();
    let subject = p
        .next()?
        .trim_start_matches(['+', '.'])
        .to_ascii_lowercase();
    let policy = p.next()?.to_string();
    Some((kind, subject, policy))
}
fn policy(domain: &str, entries: &[String]) -> (Option<String>, String) {
    for raw in entries {
        if let Some((kind, subject, target)) = parse_rule(raw) {
            if kind == "DOMAIN-SUFFIX"
                && (domain == subject || domain.ends_with(&format!(".{subject}")))
            {
                return (Some(target), "suffix".into());
            }
            if kind == "DOMAIN" && domain == subject {
                return (Some(target), "exact".into());
            }
            if matches!(
                kind.as_str(),
                "GEOSITE"
                    | "RULE-SET"
                    | "DOMAIN-KEYWORD"
                    | "DST-PORT"
                    | "IP-CIDR"
                    | "IP-CIDR6"
                    | "GEOIP"
                    | "SRC-IP-CIDR"
                    | "SRC-PORT"
                    | "NETWORK"
                    | "IN-TYPE"
                    | "PROCESS-NAME"
            ) {
                return (None, kind);
            }
        }
    }
    (None, "missing".into())
}
fn bypass(v: &str) -> bool {
    matches!(v, "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS")
}

/// Inspects a redacted active rules snapshot.  `entries` must come from the
/// already authenticated runtime adapter; this function performs no I/O.
/// `direct_targets` names proxies or selector groups whose current selection
/// is a bypass (DIRECT/REJECT); a rule pointing at one of them matches
/// nothing, so it counts as bypass, never as coverage.
pub fn inspect_rules(
    mode: &str,
    entries: &[String],
    runtime_mode: Option<&str>,
    direct_targets: &[String],
) -> Value {
    let mut covered = Vec::new();
    let mut missing = Vec::new();
    let mut bypasses = Vec::new();
    let mut uncertain = serde_json::Map::new();
    let mut policies = serde_json::Map::new();
    // A global-mode short-circuit must not masquerade as per-domain evidence:
    // the rule table never matches in that mode, so the honest wording names the
    // mode instead of claiming coverage the snapshot never demonstrated.
    let global_short = mode == "tag" && runtime_mode == Some("global");
    if global_short {
        covered = RULE_DOMAINS.iter().map(|x| x.to_string()).collect();
    } else {
        for domain in RULE_DOMAINS {
            let (target, reason) = policy(domain, entries);
            match target {
                Some(t) if bypass(&t) || direct_targets.iter().any(|x| x == &t) => {
                    bypasses.push(domain.to_string())
                }
                Some(t) => {
                    covered.push(domain.to_string());
                    policies.insert(domain.into(), Value::String(t));
                }
                None if reason != "missing" => {
                    uncertain.insert(domain.into(), Value::String(reason));
                }
                None => missing.push(domain.to_string()),
            };
        }
    }
    let count = covered.len();
    let state = if !bypasses.is_empty() {
        "fail"
    } else if !missing.is_empty() {
        "missing"
    } else if !uncertain.is_empty() {
        "unknown"
    } else {
        "ok"
    };
    let detail = if global_short {
        "全局模式：全部流量走单一节点，规则表不参与匹配".to_string()
    } else if !bypasses.is_empty() {
        format!(
            "{} 个域名的规则指向直连或拒绝：{}",
            bypasses.len(),
            bypasses.join("、")
        )
    } else {
        format!("{count}/13 已覆盖")
    };
    json!({"state":state,"saved_domains":RULE_DOMAINS,"covered_domains":covered,"missing_domains":missing,"bypass_domains":bypasses,"policy_by_domain":policies,"uncertain_domains":uncertain,"actual_mode":runtime_mode.unwrap_or(""),"source":"runtime snapshot","detail":detail})
}

/// TAG active controller rules take precedence over its readable runtime copy.
/// A global mode is acceptable only with a known non-bypass global node.
pub fn inspect_tag_rules(controller: Option<&[String]>, runtime: &[String], api: &Value) -> Value {
    let active = controller.unwrap_or(runtime);
    let mode = text(api, "mode");
    // Selector groups currently parked on a bypass target make every rule that
    // points at them ineffective; the API snapshot already resolved the chains.
    let direct_targets: Vec<String> = api["direct_groups"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let mut out = inspect_rules("tag", active, Some(mode), &direct_targets);
    out["controller_rule_state"] = json!(if controller.is_some() {
        "available"
    } else {
        "unavailable"
    });
    out["runtime_domains"] = json!(runtime);
    // Rules the user switched off exist in the table but match nothing; naming
    // them keeps the gap between "written" and "effective" visible.  Under a
    // global mode the rule table never matches anyway, so the note is noise.
    if mode != "global" {
        if let Some(disabled) = api.pointer("/rules/disabled_domains").and_then(Value::as_array) {
            let names: Vec<&str> = disabled.iter().filter_map(Value::as_str).collect();
            if !names.is_empty() {
                out["disabled_domains"] = json!(names);
                let detail = text(&out, "detail");
                out["detail"] = json!(format!(
                    "{detail}；其中 {} 的规则已被禁用",
                    names.join("、")
                ));
            }
        }
    }
    if mode == "global" {
        let node = text(api, "global_node");
        if node.is_empty() || matches!(node, "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS") {
            out["state"] = json!("fail");
            out["detail"] = json!("全局节点未确认或为旁路策略");
        }
    }
    out
}
