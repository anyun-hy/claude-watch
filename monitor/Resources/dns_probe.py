#!/usr/bin/env python3
"""Collect bounded, read-only DNS-path observations for the monitor UI.

This program deliberately records observations only.  The Swift client owns any
policy decision about those observations.
"""
import hashlib
import ipaddress
import json
import re
import signal
import subprocess
import sys
import time


SCOPE = "dig/resolv.conf DNS 路径；HTTP 经 7890 参考"
MAX_JSON_BYTES = 64 * 1024
TOTAL_BUDGET_SECONDS = 25.0
DNS_COMMAND = ["/usr/bin/dig", "+time=3", "+tries=1", "+short", "whoami.ds.akahelp.net", "TXT"]
HTTP_COMMAND = [
    "/usr/bin/curl", "-q", "-fsS", "--proto", "=https", "--proxy", "http://127.0.0.1:7890",
    "--noproxy", "", "--connect-timeout", "3", "--max-time", "6", "--max-filesize", "32768",
    "https://www.cloudflare.com/cdn-cgi/trace",
]
CONTEXT_COMMANDS = [
    ("dns", ["/usr/sbin/scutil", "--dns"]),
    ("proxy", ["/usr/sbin/scutil", "--proxy"]),
    ("route4", ["/sbin/route", "-n", "get", "-inet", "default"]),
    ("route6", ["/usr/sbin/netstat", "-rn", "-f", "inet6"]),
]
GEOIP_URL_PREFIX = "https://ip.net.coffee/api/geoip/"
ACTIVE_CHILD = None


def public_address(value):
    """Return a canonical globally routable address, otherwise None."""
    if not isinstance(value, str) or "%" in value:
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except (AttributeError, ValueError):
        return None
    # Normalize v4-mapped v6 so the Swift consumer compares one representation.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    # Do not rely on is_global alone: its classification of multicast addresses
    # differs between Python releases.  Keep the benchmark range explicit too.
    if (address in ipaddress.ip_network("198.18.0.0/15") or address.is_multicast
            or address.is_reserved or address.is_loopback or address.is_link_local
            or address.is_unspecified or address.is_private or not address.is_global):
        return None
    return str(address)


def error(stage, code, message):
    return {"stage": stage, "code": code, "message": message}


def terminate_active_child():
    """Terminate only the child created for this invocation, if it still runs."""
    global ACTIVE_CHILD
    child = ACTIVE_CHILD
    ACTIVE_CHILD = None
    if child is None:
        return
    try:
        if child.poll() is None:
            child.terminate()
        try:
            child.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            # This is still only the one child object this collector created.
            child.kill()
            child.communicate(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        pass


def cancellation_handler(signum, _frame):
    terminate_active_child()
    raise SystemExit(128 + signum)


def bounded_run(command, deadline, normal_timeout, stage):
    """Run one command without inheriting stderr text or environment into JSON."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None, "budget_timeout"
    global ACTIVE_CHILD
    child = None
    try:
        child = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        ACTIVE_CHILD = child
        stdout, _ = child.communicate(timeout=min(normal_timeout, max(0.1, remaining)))
    except subprocess.TimeoutExpired:
        terminate_active_child()
        return None, "timeout"
    except OSError:
        return None, "exec_error"
    finally:
        if ACTIVE_CHILD is child:
            ACTIVE_CHILD = None
    if child.returncode != 0:
        return None, "command_error"
    stdout = stdout or ""
    if len(stdout.encode("utf-8", "replace")) > 32768:
        return None, "output_limit"
    return stdout, None


def stable_inet6_defaults(output):
    """Keep only stable default-route columns; an absent v6 default is valid."""
    columns = None
    defaults = []
    for raw in output.splitlines():
        fields = raw.split()
        lowered = [field.lower() for field in fields]
        if "destination" in lowered and "gateway" in lowered:
            columns = {name: index for index, name in enumerate(lowered)}
            continue
        if not fields or fields[0] != "default":
            continue
        if columns is not None:
            keep = [
                fields[columns[name]] for name in ("destination", "gateway", "netif")
                if name in columns and columns[name] < len(fields)
            ]
        else:
            keep = fields[:2]
        if keep:
            defaults.append(" ".join(keep))
    if columns is None:
        return None
    return "\n".join(sorted(set(defaults))) if defaults else "absent"


def context_snapshot(deadline, errors):
    """Hash readable network context, retaining no configuration content."""
    parts = []
    complete = True
    for name, command in CONTEXT_COMMANDS:
        output, problem = bounded_run(command, deadline, 1.5, "context")
        if problem or not output or not output.strip():
            complete = False
            errors.append(error("context", "context_unknown", "网络上下文无法完整读取"))
        else:
            if name == "route6":
                output = stable_inet6_defaults(output)
                if output is None:
                    complete = False
                    errors.append(error("context", "context_unknown", "网络上下文无法完整读取"))
                    continue
            parts.append(name + "\0" + output)
    if not complete:
        return None
    return hashlib.sha256("\0".join(parts).encode("utf-8", "replace")).hexdigest()


def parse_dns_ns(output, errors):
    observations = []
    saw_ns = False
    for line in output.splitlines():
        fields = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', line)
        if len(fields) < 2 or fields[0].strip().lower() != "ns":
            continue
        saw_ns = True
        address = public_address(fields[1])
        if address is None:
            errors.append(error("dns", "invalid_ns", "DNS 返回了非公网或无效的 NS 地址"))
            continue
        observations.append({"address": address, "kind": "resolver", "source": "akamai-whoami-ns", "family": ipaddress.ip_address(address).version})
    if not saw_ns:
        errors.append(error("dns", "no_ns", "DNS 返回中没有 NS 递归出口"))
    # A resolver can repeat its answer; keeping one canonical observation avoids
    # making output size depend on a malformed long answer.
    unique = {item["address"]: item for item in observations}
    return [unique[address] for address in sorted(unique, key=lambda item: (ipaddress.ip_address(item).version, item))]


def parse_http_ip(output, errors):
    # The trace response carries the egress country for free (`loc=`); dropping
    # it forced every downstream geography verdict into "incomplete" even when
    # both addresses were observed.  Only a well-formed short code is kept —
    # anything else stays absent so the verdict still fails closed.
    country = None
    for line in output.splitlines():
        if not line.startswith("loc="):
            continue
        code = line.partition("=")[2].strip()
        if code and len(code) <= 8 and code.isalnum() and code.isascii():
            country = code
            break
    for line in output.splitlines():
        if not line.startswith("ip="):
            continue
        address = public_address(line.partition("=")[2])
        if address is not None:
            row = {"address": address, "kind": "http", "source": "cloudflare-trace-via-7890", "family": ipaddress.ip_address(address).version}
            if country:
                row["country"] = country
            return row
        errors.append(error("http", "invalid_ip", "HTTP 参考返回了非公网或无效 IP"))
        return None
    errors.append(error("http", "no_ip", "HTTP 参考未返回 IP"))
    return None


def geoip_command(address):
    return [
        "/usr/bin/curl", "-q", "-fsS", "--proto", "=https", "--proxy", "http://127.0.0.1:7890",
        "--noproxy", "", "--connect-timeout", "3", "--max-time", "5", "--max-filesize", "32768",
        GEOIP_URL_PREFIX + address,
    ]


def geoip_country(address, deadline):
    """Attribution for one observed resolver address, through the same proxy as
    the HTTP reference.  Enrichment only: any failure returns None and is never
    recorded as an error, so a broken side channel cannot downgrade a complete
    round — it only leaves the verdict failing closed on missing attribution."""
    if not isinstance(address, str) or public_address(address) != address:
        return None
    output, problem = bounded_run(geoip_command(address), deadline, 5.0, "geoip")
    if problem:
        return None
    try:
        data = json.loads(output)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    # `/api/geoip/` reports the full country name in `country` and the ISO
    # code in `country_code`, so the code wins; a name-shaped value must
    # never be read as a country code.
    for key in ("country_code", "countryCode", "country"):
        value = data.get(key)
        if isinstance(value, str):
            code = value.strip().upper()
            if len(code) == 2 and code.isascii() and code.isalpha():
                return code
    return None


def collect():
    started = time.time()
    deadline = time.monotonic() + TOTAL_BUDGET_SECONDS
    observations, errors = [], []
    before = context_snapshot(deadline, errors)

    dns_output, dns_problem = bounded_run(DNS_COMMAND, deadline, 4.0, "dns")
    dns_ok = False
    dns_timed_out = dns_problem in {"timeout", "budget_timeout"}
    if dns_problem:
        code = "timeout" if dns_timed_out else ("output_limit" if dns_problem == "output_limit" else ("unavailable" if dns_problem == "exec_error" else "query_failed"))
        errors.append(error("dns", code, "DNS 查询未完成"))
    else:
        resolvers = parse_dns_ns(dns_output, errors)
        observations.extend(resolvers)
        dns_ok = bool(resolvers)

    http_output, http_problem = bounded_run(HTTP_COMMAND, deadline, 7.0, "http")
    if http_problem:
        code = "timeout" if http_problem in {"timeout", "budget_timeout"} else ("output_limit" if http_problem == "output_limit" else ("unavailable" if http_problem == "exec_error" else "request_failed"))
        errors.append(error("http", code, "HTTP 7890 参考未完成"))
    else:
        http = parse_http_ip(http_output, errors)
        if http is not None:
            observations.append(http)

    after = context_snapshot(deadline, errors)
    # Resolver attribution is enrichment, not evidence: a failed lookup stays
    # out of `errors` so it cannot downgrade a complete round; it only leaves
    # the verdict failing closed on missing attribution.
    if time.monotonic() < deadline - 3.0:
        for row in observations:
            if row.get("kind") != "resolver":
                continue
            country = geoip_country(row.get("address"), deadline)
            if country:
                row["country"] = country
    context_known = before is not None and after is not None
    context_changed = context_known and before != after

    dns_error = any(item["stage"] == "dns" for item in errors)
    http_error = any(item["stage"] == "http" for item in errors)
    context_error = any(item["stage"] == "context" for item in errors)
    if dns_timed_out:
        status = "timeout"
    elif dns_error and not dns_ok:
        status = "error"
    elif dns_error or http_error or context_error or context_changed:
        status = "partial"
    else:
        status = "complete"

    result = {
        "kind": "dns", "status": status, "startedAt": started, "finishedAt": time.time(), "scope": SCOPE,
        "observations": observations, "errors": errors, "contextChanged": context_changed,
        "details": ["DNS 使用 Akamai whoami TXT；HTTP 参考经本机 7890 访问 Cloudflare。", "dig 走 resolv.conf DNS 路径，可能不同于浏览器的 DoH 或分域解析。"],
    }
    # The inputs are bounded, but keep the wire contract bounded even if future
    # parsers add fields.  This fallback preserves valid JSON and signals loss.
    encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_JSON_BYTES:
        result["observations"] = result["observations"][:128]
        result["errors"] = result["errors"][:128]
        result["details"] = ["结果已截断；仅保留部分观测。"]
        result["status"] = "partial"
    return result


def main():
    signal.signal(signal.SIGTERM, cancellation_handler)
    signal.signal(signal.SIGINT, cancellation_handler)
    print(json.dumps(collect(), ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
