"""Rule inspection and conservative edits of our own Clash Verge block.

TAG keeps its user-facing configuration encrypted, but exposes the loaded
Mihomo configuration as a local runtime file.  Reading that file is useful for
comparison only: this module never writes TAG files, selects a node, or reloads
the proxy.
"""
import json
import re

from .common import DOMAINS, SwitcherError, reject_symlink

BEGIN = "# >>> ClaudeWatch pinned rules >>>"
END = "# <<< ClaudeWatch pinned rules <<<"
LEGACY_BEGIN = "# >>> claude-switcher pinned rules >>>"
LEGACY_END = "# <<< claude-switcher pinned rules <<<"
TAG_RUNTIME = "Library/Application Support/com.tag.lab/mihomo/runtime.yaml"
_MAX_RULE_CONFIG = 2_000_000
_BYPASS = frozenset(("DIRECT", "REJECT", "REJECT-DROP", "PASS"))
_BROAD_RULES = frozenset(("GEOSITE", "RULE-SET", "DOMAIN-KEYWORD", "DST-PORT", "IP-CIDR",
                          "IP-CIDR6", "GEOIP", "SRC-IP-CIDR", "SRC-PORT", "NETWORK",
                          "IN-TYPE", "PROCESS-NAME"))


def merge_path(paths):
    return paths.home / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/profiles/Merge.yaml"


def discover_groups(paths):
    path = paths.home / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml"
    reject_symlink(path, paths.home)
    if not path.is_file() or path.stat().st_size > 8_000_000: return []
    groups, name, inside = [], "", False
    for line in path.read_text().splitlines():
        if line.startswith("proxy-groups:"): inside = True; continue
        if inside and line and not line[0].isspace(): inside = False
        if not inside: continue
        match = re.match(r"\s*-\s*name:\s*(.+?)\s*$", line)
        if match:
            name = match[1]
            if name.startswith('"'):
                try: name = json.loads(name)
                except ValueError: name = ""
            elif name.startswith("'") and name.endswith("'"):
                name = name[1:-1].replace("''", "'")
        if re.match(r"\s*type:\s*select\s*(?:#.*)?$", line) and name:
            if len(name) <= 256 and "\n" not in name: groups.append(name)
    return list(dict.fromkeys(groups))


def remove_block(text, begin=BEGIN, end=END):
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.strip() == begin]
    stops = [i for i, line in enumerate(lines) if line.strip() == end]
    if not starts and not stops: return text
    if len(starts) != 1 or len(stops) != 1 or starts[0] >= stops[0]:
        raise SwitcherError("ambiguous_rules", "规则标记不完整或重复；未修改配置")
    return "".join(lines[:starts[0]] + lines[stops[0] + 1:])


def render_rules(text, group, *, remove=False):
    if not group or len(group) > 256 or any(c in group for c in "\r\n\x00"):
        raise SwitcherError("invalid_group", "请选择有效的代理组")
    text = remove_block(text)
    if remove: return text
    lines = text.splitlines(keepends=True)
    headers = [i for i, line in enumerate(lines) if re.match(r"^prepend-rules\s*:", line)]
    if len(headers) > 1:
        raise SwitcherError("ambiguous_rules", "存在重复 prepend-rules 键")
    if headers:
        index = headers[0]
        value = lines[index].split(":", 1)[1].strip()
        if value and not value.startswith("#"):
            if value not in ("[]", "null", "~"):
                raise SwitcherError("unsupported_yaml", "现有规则使用复杂行内格式，请手动调整；原配置未改")
            lines[index] = "prepend-rules:\n"
        position = index + 1
    else:
        if lines and not lines[-1].endswith("\n"): lines[-1] += "\n"
        lines.append("prepend-rules:\n")
        position = len(lines)
    block = "  " + BEGIN + "\n"
    block += "".join("  - " + json.dumps("DOMAIN-SUFFIX," + d + "," + group, ensure_ascii=False) + "\n" for d in DOMAINS)
    block += "  " + END + "\n"
    lines.insert(position, block)
    return "".join(lines)


def _routing_result(state, detail, *, source, actual_mode="", configured=(), covered=(),
                    missing=(), bypass=(), policies=None, unsupported=(), runtime=(), controller=(),
                    controller_state="unavailable", controller_reason="", uncertain=None,
                    controller_total=None, controller_published=None, mode_consistency="未确认"):
    """Return a stable, display-ready comparison without exposing credentials."""
    def ordered(values):
        present = set(values)
        return [domain for domain in DOMAINS if domain in present] + sorted(present - set(DOMAINS))
    return {
        "state": state, "detail": detail, "source": source,
        "actual_mode": actual_mode, "saved_domains": list(DOMAINS),
        "configured_domains": ordered(configured), "covered_domains": ordered(covered),
        "missing_domains": ordered(missing), "bypass_domains": ordered(bypass),
        "policy_by_domain": dict(sorted((policies or {}).items())),
        "unsupported_entries": list(unsupported),
        # TAG's durable UI configuration is encrypted.  ``runtime`` is the
        # readable loaded configuration; ``controller`` is the currently
        # active rule table when its loopback API supplies one.
        "tag_saved_container": "encrypted_unreadable",
        "runtime_domains": ordered(runtime), "controller_domains": ordered(controller),
        "controller_rule_state": controller_state, "controller_rule_reason": controller_reason,
        "controller_rule_total": controller_total, "controller_rule_published": controller_published,
        "mode_consistency": mode_consistency,
        "uncertain_domains": dict(sorted((uncertain or {}).items())),
    }


def tag_runtime_path(paths):
    return paths.home / TAG_RUNTIME


def _read_tag_runtime(paths):
    path = tag_runtime_path(paths)
    reject_symlink(path, paths.home)
    try:
        if not path.is_file():
            return None, "TAG 运行配置不存在"
        if path.stat().st_size > _MAX_RULE_CONFIG:
            return None, "TAG 运行配置过大，未读取"
        return path.read_text(encoding="utf-8"), ""
    except (OSError, UnicodeError):
        return None, "TAG 运行配置无法读取"


def _strip_comment(value):
    # Mihomo rule records are plain comma-separated scalars.  Preserve a # in a
    # quoted value, although quoted rules are not needed for the comparison.
    quote = ""
    for index, char in enumerate(value):
        if char in "\"'":
            quote = "" if quote == char else (char if not quote else quote)
        elif char == "#" and not quote and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
    return value.rstrip()


def _yaml_scalar(value):
    value = _strip_comment(value.strip())
    if value.startswith('"'):
        try:
            return json.loads(value)
        except ValueError:
            return ""
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("''", "'")
    return value


def _parse_rule_line(value):
    value = _yaml_scalar(value)
    fields = [item.strip() for item in value.split(",")]
    if not fields or not fields[0]:
        return None, "无法解析的规则条目"
    kind = fields[0].upper()
    if kind == "MATCH":
        if len(fields) >= 2 and fields[1]:
            return (kind, "", fields[1]), ""
        return None, "无法解析的规则条目"
    if kind in _BROAD_RULES:
        if len(fields) >= 3:
            return (kind, fields[1], fields[2]), ""
        return None, "无法解析的规则条目"
    if len(fields) < 3:
        return None, "无法解析的规则条目"
    subject, policy = fields[1].lower(), fields[2]
    if kind in ("DOMAIN", "DOMAIN-SUFFIX"):
        return (kind, subject.lstrip("+."), policy), ""
    return None, ""


def _tag_runtime_rules(text):
    """Read only top-level mode and literal rules from a Mihomo YAML file.

    A full YAML loader would also deserialize proxy passwords and provider
    credentials.  The small parser deliberately ignores everything except the
    top-level ``mode`` scalar and literal entries under ``rules``.
    """
    mode, rules, unsupported, in_rules = "", [], [], False
    for raw in text.splitlines():
        if raw and not raw[0].isspace():
            key, colon, value = raw.partition(":")
            if key == "mode" and colon:
                mode = _yaml_scalar(value).lower()
            in_rules = key == "rules" and bool(colon)
            continue
        if not in_rules:
            continue
        match = re.match(r"^\s*-\s*(.+?)\s*$", raw)
        if not match:
            continue
        parsed, unsupported_kind = _parse_rule_line(match.group(1))
        if parsed:
            rules.append(parsed)
        elif unsupported_kind:
            # These can affect a domain but cannot establish its per-domain
            # destination from text alone.
            unsupported.append(unsupported_kind)
    return mode, rules, list(dict.fromkeys(unsupported))


def _policy_for(domain, rules):
    """Apply only rule semantics that can prove coverage for one domain.

    ``DOMAIN`` handles just the root host, while ``DOMAIN-SUFFIX`` covers the
    whole family.  A preceding rule-set, keyword or port rule could win before a
    later suffix entry, so it yields an explicit uncertainty instead of a false
    13/13 result.  ``MATCH`` identifies the fallback policy but does not prove
    that its selector chain reaches a non-bypass node.
    """
    domain = domain.lower()
    for kind, subject, policy in rules:
        if kind == "DOMAIN-SUFFIX" and (domain == subject or domain.endswith("." + subject)):
            return policy, "suffix"
        if kind == "DOMAIN" and domain == subject:
            return policy, "exact"
        if kind == "MATCH":
            return policy, "match"
        if kind in _BROAD_RULES:
            return None, kind
    return None, "missing"


def _controller_rules(tag):
    """Accept the bounded, redacted `/rules` snapshot published by the backend.

    The backend owns loopback authentication and returns literal rule strings
    only.  This parser does no network I/O and treats an unavailable snapshot as
    an explicit limitation rather than a missing rule.
    """
    raw = tag.get("rules", {}) if isinstance(tag, dict) else {}
    if not isinstance(raw, dict):
        return [], [], "unavailable", "TAG 控制接口未提供规则表"
    state, reason = raw.get("state", "unavailable"), raw.get("reason", "")
    entries = raw.get("entries", raw.get("rules", []))
    if state != "available":
        return [], [], state, reason or "TAG 控制接口规则表未确认"
    if not isinstance(entries, list) or len(entries) > 20_000:
        return [], [], "invalid", "TAG 控制接口规则表格式无效"
    rules, unsupported = [], []
    for value in entries:
        if not isinstance(value, str) or len(value) > 2_048:
            continue
        parsed, unsupported_kind = _parse_rule_line(value)
        if parsed:
            rules.append(parsed)
        elif unsupported_kind:
            unsupported.append(unsupported_kind)
    return rules, list(dict.fromkeys(unsupported)), state, reason


def _inspect_tag_rules(paths, tag):
    raw_controller = tag.get("rules", {}) if isinstance(tag, dict) else {}
    raw_total = raw_controller.get("total") if isinstance(raw_controller, dict) else None
    controller_total = raw_total if type(raw_total) is int and 0 <= raw_total <= 20_000 else None
    raw_entries = raw_controller.get("entries") if isinstance(raw_controller, dict) else None
    controller_published = len(raw_entries) if isinstance(raw_entries, list) and len(raw_entries) <= 20_000 else None
    def finish(*args, **kwargs):
        if api.get("state") == "available" and runtime_mode in ("rule", "global", "direct"):
            consistency = "一致" if api.get("mode") == runtime_mode else "不一致"
        elif runtime_mode in ("rule", "global", "direct"):
            consistency = "控制接口未确认"
        else:
            consistency = "运行配置未声明"
        kwargs.update(controller_total=controller_total, controller_published=controller_published,
                      mode_consistency=consistency)
        return _routing_result(*args, **kwargs)
    text, issue = _read_tag_runtime(paths)
    if text is None:
        return _routing_result("unknown", issue, source="TAG 运行配置",
                               controller_total=controller_total, controller_published=controller_published)
    runtime_mode, runtime_rules, unsupported = _tag_runtime_rules(text)
    controller_rules, controller_unsupported, controller_state, controller_reason = _controller_rules(tag)
    unsupported = list(dict.fromkeys(unsupported + controller_unsupported))
    api = tag.get("api", {}) if isinstance(tag, dict) else {}
    if not isinstance(api, dict):
        api = {}
    actual_mode = api.get("mode") if api.get("state") == "available" else ""
    if actual_mode not in ("rule", "global", "direct"):
        actual_mode = runtime_mode if runtime_mode in ("rule", "global", "direct") else ""
    # `/rules` is the active source whenever available.  The runtime file is a
    # comparison source; it can be stale after TAG reloads its configuration.
    effective_rules = controller_rules if controller_state == "available" else runtime_rules
    decisions = {domain: _policy_for(domain, effective_rules) for domain in DOMAINS}
    policies = {domain: policy for domain, (policy, _) in decisions.items() if policy}
    runtime_domains = [domain for domain in DOMAINS if _policy_for(domain, runtime_rules)[0]]
    controller_domains = [domain for domain in DOMAINS if _policy_for(domain, controller_rules)[0]]
    configured = [domain for domain, (policy, _) in decisions.items() if policy]
    bypass = [domain for domain, (policy, _) in decisions.items() if policy and policy.upper() in _BYPASS]
    proxied = [domain for domain, (policy, basis) in decisions.items()
               if policy and policy.upper() not in _BYPASS and basis == "suffix"]
    uncertain = {domain: basis for domain, (_, basis) in decisions.items()
                 if basis not in ("suffix", "missing")}
    source = "TAG 控制接口 + 已加载 runtime.yaml" if api.get("state") == "available" else "TAG 已加载 runtime.yaml（控制接口未确认）"

    if actual_mode == "global":
        # In global mode only the GLOBAL selector proves the final route.  The
        # ordinary selected group can remain healthy while GLOBAL itself is
        # DIRECT, so it must never be used as a fallback here.
        node = api.get("global_node")
        if api.get("state") == "available" and node and str(node).upper() not in _BYPASS:
            return finish("ok", "TAG 当前为全局模式；13 项域名随全局节点转发，无需逐域名置顶规则",
                                   source=source, actual_mode=actual_mode, configured=configured,
                                   covered=DOMAINS, bypass=bypass, policies=policies,
                                   unsupported=unsupported, runtime=runtime_domains,
                                   controller=controller_domains, controller_state=controller_state,
                                   controller_reason=controller_reason, uncertain=uncertain)
        return finish("unknown", "保存配置为全局模式，但未能从 TAG 控制接口确认有效的全局代理节点",
                               source=source, actual_mode=actual_mode, configured=configured,
                               bypass=bypass, policies=policies,
                               unsupported=unsupported, runtime=runtime_domains,
                               controller=controller_domains, controller_state=controller_state,
                               controller_reason=controller_reason, uncertain=uncertain)
    if actual_mode == "direct":
        return finish("fail", "TAG 当前为直连模式；13 项域名不会按代理规则转发",
                               source=source, actual_mode=actual_mode, configured=configured,
                               bypass=DOMAINS, policies=policies, unsupported=unsupported,
                               runtime=runtime_domains, controller=controller_domains,
                               controller_state=controller_state, controller_reason=controller_reason,
                               uncertain=uncertain)
    if actual_mode != "rule":
        return finish("unknown", "未能确认 TAG 当前规则模式", source=source,
                               configured=configured, bypass=bypass, policies=policies,
                               unsupported=unsupported, runtime=runtime_domains,
                               controller=controller_domains, controller_state=controller_state,
                               controller_reason=controller_reason, uncertain=uncertain)
    if bypass:
        return finish("fail", "TAG 规则中发现直连或拒绝项：" + "、".join(bypass),
                               source=source, actual_mode=actual_mode, configured=configured,
                               covered=proxied, missing=[d for d in DOMAINS if d not in configured],
                               bypass=bypass, policies=policies, unsupported=unsupported,
                               runtime=runtime_domains, controller=controller_domains,
                               controller_state=controller_state, controller_reason=controller_reason,
                               uncertain=uncertain)
    missing = [domain for domain in DOMAINS if domain not in proxied]
    if missing:
        return finish("unknown", "未找到 " + str(len(missing)) + " 项域名的可解析 TAG 规则；未据此认定直连",
                               source=source, actual_mode=actual_mode, configured=configured,
                               covered=proxied, missing=missing, policies=policies,
                               unsupported=unsupported, runtime=runtime_domains,
                               controller=controller_domains, controller_state=controller_state,
                               controller_reason=controller_reason, uncertain=uncertain)
    return finish("ok", "TAG 已加载 13 项域名的显式代理规则", source=source,
                           actual_mode=actual_mode, configured=configured, covered=proxied,
                           policies=policies, unsupported=unsupported, runtime=runtime_domains,
                           controller=controller_domains, controller_state=controller_state,
                           controller_reason=controller_reason, uncertain=uncertain)


def inspect_rules(paths, config, mode, tag=None):
    if mode == "tag":
        return _inspect_tag_rules(paths, tag or {})
    if mode != "clash-verge":
        return _routing_result("unknown", "此客户端暂无可读取的规则来源；Fake-IP 解析不能证明规则覆盖",
                               source="客户端未提供可验证规则")
    path = merge_path(paths)
    reject_symlink(path, paths.home)
    try: text = path.read_text()
    except FileNotFoundError:
        return _routing_result("fail", "缺少 Clash Verge 合并规则", source="Clash Verge Merge.yaml")
    group = config["proxy_group"]
    if not group: return _routing_result("unknown", "未选择代理组", source="Clash Verge Merge.yaml")
    required = ["DOMAIN-SUFFIX," + d + "," + group for d in DOMAINS]
    verified = (BEGIN in text or LEGACY_BEGIN in text) and all(x in text for x in required)
    return _routing_result("ok" if verified else "fail",
                           "13 项规则文本已核对；需重载客户端后结合实际连接验证" if verified else "规则缺失或代理组不匹配",
                           source="Clash Verge Merge.yaml", configured=DOMAINS if verified else (),
                           covered=DOMAINS if verified else (), missing=() if verified else DOMAINS)


def format_detail(result):
    """Render routing evidence for a hover sheet without inventing an action.

    The input is the structured result from :func:`inspect_rules`; malformed
    values are ignored so a controller response cannot inject UI text.
    """
    if not isinstance(result, dict):
        return "规则检测结果不可读取"
    def domains(key):
        value = result.get(key)
        return "、".join(item for item in value if isinstance(item, str) and item in DOMAINS) if isinstance(value, list) else ""
    lines = [str(result.get("detail") or "规则检测未完成")]
    mode = result.get("actual_mode")
    if isinstance(mode, str) and mode:
        lines.append("当前模式：" + mode + "；运行配置与控制接口：" + str(result.get("mode_consistency") or "未确认"))
    total, published = result.get("controller_rule_total"), result.get("controller_rule_published")
    if type(total) is int:
        lines.append("控制器规则：" + str(total) + " 项；已发布比较证据：" + (str(published) if type(published) is int else "未确认") + " 项")
    lines.append("保存清单：Claude Watch/原版相同的 13 项域名；TAG 持久配置为加密容器，不能逐条比较")
    runtime, controller = domains("runtime_domains"), domains("controller_domains")
    if mode == "global":
        lines.append("全局模式不使用逐域名规则表分流；切换为规则模式后需重新核对规则优先级。")
    elif runtime or controller:
        lines.append("运行配置命中：" + (runtime or "无") + "；控制器规则表命中：" + (controller or "无"))
    for key, title in (("covered_domains", "已覆盖"), ("missing_domains", "未能证明覆盖"),
                       ("bypass_domains", "直连或拒绝")):
        value = domains(key)
        if value:
            lines.append(title + "：" + value)
    uncertain = result.get("uncertain_domains")
    if mode != "global" and isinstance(uncertain, dict):
        items = [domain + "（前置 " + reason + "）" for domain, reason in uncertain.items()
                 if domain in DOMAINS and isinstance(reason, str) and len(reason) <= 64]
        if items:
            lines.append("优先级无法证明：" + "、".join(items))
    return "\n".join(lines)
