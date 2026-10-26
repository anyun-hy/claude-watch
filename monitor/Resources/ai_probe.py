#!/usr/bin/env python3
"""Bounded, read-only Claude/GPT connectivity observations via local proxy."""
import argparse
import ipaddress
import json
import signal
import subprocess
import time


PROXY = "http://127.0.0.1:7890"
REQUEST_TIMEOUT_SECONDS = 6.0
TOTAL_BUDGET_SECONDS = 30.0
MAX_RESPONSE_BYTES = 32768
MAX_GEO_TEXT_BYTES = 256
STATUS_MARKER = "__AI_PROBE_HTTP_STATUS__:"
REFERENCE_URL = "https://1.1.1.1/cdn-cgi/trace"
SERVICE_ENDPOINTS = {
    "claude": [
        ("https://claude.ai/cdn-cgi/trace", True),
        ("https://www.anthropic.com/cdn-cgi/trace", False),
    ],
    "gpt": [
        ("https://chatgpt.com/cdn-cgi/trace", True),
        ("https://api.openai.com/v1/models", False),
    ],
}
ACTIVE_CHILD = None


def public_address(value):
    """Return a canonical globally-routable address, otherwise None."""
    if not isinstance(value, str) or "%" in value:
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if (address.is_private or address.is_loopback or address.is_link_local
            or address.is_multicast or address.is_reserved or address.is_unspecified
            or address in ipaddress.ip_network("198.18.0.0/15") or not address.is_global):
        return None
    return str(address)


def issue(stage, code, message):
    return {"stage": stage, "code": code, "message": message}


def geo_text(value):
    """Keep only bounded string metadata from an untrusted Geo response."""
    if not isinstance(value, str):
        return ""
    return value[:MAX_GEO_TEXT_BYTES]


def terminate_active_child():
    """Clean up only this collector's current child process."""
    global ACTIVE_CHILD
    child, ACTIVE_CHILD = ACTIVE_CHILD, None
    if child is None:
        return
    try:
        if child.poll() is None:
            child.terminate()
        try:
            child.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        pass


def cancellation_handler(signum, _frame):
    terminate_active_child()
    raise SystemExit(128 + signum)


def curl_command(url):
    # Never follow redirects or relax TLS, and never permit curl's direct bypass.
    return [
        "/usr/bin/curl", "-q", "--proto", "=https", "--proxy", PROXY,
        "--noproxy", "", "--connect-timeout", str(REQUEST_TIMEOUT_SECONDS),
        "--max-time", str(REQUEST_TIMEOUT_SECONDS), "--max-filesize", str(MAX_RESPONSE_BYTES),
        "-sS", "-w", "\n" + STATUS_MARKER + "%{http_code}", url,
    ]


def bounded_run(command, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None, None, "budget_timeout"
    global ACTIVE_CHILD
    child = None
    try:
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 text=True, encoding="utf-8", errors="replace")
        ACTIVE_CHILD = child
        output, _ = child.communicate(timeout=min(REQUEST_TIMEOUT_SECONDS, max(0.1, remaining)))
    except subprocess.TimeoutExpired:
        terminate_active_child()
        return None, None, "timeout"
    except OSError:
        return None, None, "exec_error"
    finally:
        if ACTIVE_CHILD is child:
            ACTIVE_CHILD = None
    output = output or ""
    # curl --max-filesize limits the body.  Leave room for our small status trailer.
    if len(output.encode("utf-8", "replace")) > MAX_RESPONSE_BYTES + 128:
        return None, None, "output_limit"
    # curl reports a timeout as 28 and TLS/proxy failures as other nonzero
    # statuses, even when its write-out trailer says HTTP 000.
    if child.returncode == 28:
        return None, None, "timeout"
    if child.returncode != 0:
        return None, None, "request_failed"
    marker_at = output.rfind(STATUS_MARKER)
    if marker_at < 0:
        return None, None, "no_http_status"
    status_text = output[marker_at + len(STATUS_MARKER):].strip()
    try:
        http_status = int(status_text)
    except ValueError:
        return None, None, "invalid_http_status"
    if not 100 <= http_status <= 599:
        return None, None, "invalid_http_status"
    return output[:marker_at], http_status, None


def trace_ip(body):
    for line in body.splitlines():
        if line.startswith("ip="):
            return public_address(line.partition("=")[2])
    return None


def endpoint_message(http_status, problem):
    if problem == "timeout" or problem == "budget_timeout":
        return "请求超时"
    if problem:
        return "请求未完成"
    if http_status == 401:
        return "服务已响应；该端点需要认证"
    if http_status == 403:
        return "服务已响应；访问被拒绝"
    if http_status == 429:
        return "服务已响应；请求受限"
    if http_status is not None and http_status >= 500:
        return "服务已响应；服务端异常"
    return "服务已响应"


def observe_endpoint(url, deadline, errors):
    begun = time.monotonic()
    body, http_status, problem = bounded_run(curl_command(url), deadline)
    elapsed = round((time.monotonic() - begun) * 1000, 3)
    if problem:
        code = "timeout" if problem in {"timeout", "budget_timeout"} else problem
        errors.append(issue("endpoint", code, url + " 请求未完成"))
        return {"url": url, "status": "timeout" if code == "timeout" else "error",
                "httpStatus": http_status, "elapsedMs": elapsed, "message": endpoint_message(http_status, problem)}, None
    endpoint = {"url": url, "status": "responded", "httpStatus": http_status,
                "elapsedMs": elapsed, "message": endpoint_message(http_status, None)}
    if http_status != 401 and not 200 <= http_status < 300:
        errors.append(issue("endpoint", "http_status", url + " 返回 HTTP " + str(http_status)))
    return endpoint, body


def geo_lookup(address, deadline, errors):
    url = "https://ipinfo.io/" + address + "/json"
    endpoint, body = observe_endpoint(url, deadline, errors)
    if endpoint["status"] != "responded" or not (200 <= endpoint["httpStatus"] < 300):
        errors.append(issue("geo", "lookup_failed", "出口 IP 地理信息查询未完成"))
        return {}
    try:
        payload = json.loads(body)
    except (TypeError, ValueError):
        errors.append(issue("geo", "invalid_json", "出口 IP 地理信息格式无效"))
        return {}
    country = payload.get("country") if isinstance(payload, dict) else None
    if (not isinstance(payload, dict) or "error" in payload or payload.get("ip") != address
            or not isinstance(country, str) or len(country) != 2
            or not country.isascii() or not country.isalpha()):
        errors.append(issue("geo", "identity_mismatch", "地理信息未验证为当前出口 IP"))
        return {}
    return {"countryCode": country.upper(), "country": geo_text(payload.get("country_name")) or country.upper(),
            "region": geo_text(payload.get("region")), "city": geo_text(payload.get("city")),
            "organization": geo_text(payload.get("org")), "ipTimezone": geo_text(payload.get("timezone"))}


def collect(service):
    started = time.time()
    deadline = time.monotonic() + TOTAL_BUDGET_SECONDS
    errors, details, endpoints = [], [], []
    exit_ip = None
    for url, is_primary_trace in SERVICE_ENDPOINTS[service]:
        endpoint, body = observe_endpoint(url, deadline, errors)
        endpoints.append(endpoint)
        if is_primary_trace:
            if endpoint["status"] == "responded" and 200 <= endpoint["httpStatus"] < 300:
                exit_ip = trace_ip(body)
                if exit_ip is None:
                    errors.append(issue("exit", "invalid_exit_ip", "主服务 trace 未返回有效公网出口 IP"))
            else:
                details.append("主服务 trace 未成功，未使用其他端点替代 AI 出口。")

    reference, reference_body = observe_endpoint(REFERENCE_URL, deadline, errors)
    reference_ip = None
    if reference["status"] == "responded" and 200 <= reference["httpStatus"] < 300:
        reference_ip = trace_ip(reference_body)
        if reference_ip is None:
            errors.append(issue("reference", "invalid_reference_ip", "HTTP 参考未返回有效公网 IP"))
    else:
        errors.append(issue("reference", "unavailable", "HTTP 参考未完成"))

    geo = geo_lookup(exit_ip, deadline, errors) if exit_ip else {}
    all_network = endpoints + [reference]
    if all(item["status"] == "timeout" for item in all_network):
        status = "timeout"
    elif errors or not exit_ip:
        status = "partial"
    else:
        status = "complete"
    result = {"service": service, "status": status, "startedAt": started, "finishedAt": time.time(),
              "exitIP": exit_ip or "", "referenceIP": reference_ip or "",
              "exitSource": SERVICE_ENDPOINTS[service][0][0] if exit_ip else "",
              "countryCode": "", "country": "", "region": "", "city": "",
              "organization": "", "ipTimezone": "", "endpoints": endpoints,
              "errors": errors, "details": details + ["所有请求经本机 7890 HTTPS 代理；未跟随重定向或回退直连。"]}
    result.update(geo)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", required=True, choices=sorted(SERVICE_ENDPOINTS))
    args = parser.parse_args(argv)
    signal.signal(signal.SIGTERM, cancellation_handler)
    signal.signal(signal.SIGINT, cancellation_handler)
    print(json.dumps(collect(args.service), ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
