"""Read-only transport checks, independent of account state and launch policy."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import math
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit

TARGETS = (("anthropic_api", "https://api.anthropic.com/v1/models"),
           ("claude_web", "https://claude.ai/"))
MAX_CONFIG = 64 * 1024


class DiagnosticParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes rejected values, which can contain credentials.
        raise ValueError("invalid arguments")


def config_value(raw):
    if len(raw) > MAX_CONFIG:
        raise ValueError("oversize config")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("invalid config")
    return value.get("proxy_url")


def select_proxy(args, environ, input_stream):
    if args.proxy is not None:
        value, source = args.proxy, "argument"
    elif args.config is not None:
        with Path(args.config).open("rb") as stream:
            value, source = config_value(stream.read(MAX_CONFIG + 1)), "config"
    elif args.stdin_config:
        value, source = config_value(input_stream.read(MAX_CONFIG + 1)), "stdin"
    else:
        value = environ.get("CLAUDE_WATCH_PROXY_URL", environ.get("CLAUDE_SWITCHER_PROXY_URL"))
        source = "environment"
    if not isinstance(value, str) or not value.strip() or len(value) > 16384:
        raise ValueError("proxy required")
    value = value.strip()
    value.encode("utf-8")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("invalid proxy")
    parsed = urlsplit(value)
    if (parsed.scheme not in ("http", "https", "socks5", "socks5h")
            or not parsed.hostname or parsed.port is None or not 0 < parsed.port < 65536
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("invalid proxy")
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname.lower() == "localhost"
    return value, {"scheme": parsed.scheme, "port": parsed.port,
                   "host_scope": "loopback" if loopback else "remote",
                   "authentication_configured": parsed.username is not None, "source": source}


def probe(name, url, proxy, environ, runner):
    # Fixed destinations, no redirect following, no inherited credentials/proxies.
    # The proxy (including any credentials) enters curl through stdin, not argv.
    escaped = proxy.replace("\\", "\\\\").replace('"', '\\"')
    args = ["/usr/bin/curl", "--disable", "--config", "-", "--silent", "--show-error",
            "--output", os.devnull, "--proto", "=https", "--noproxy", "",
            "--connect-timeout", "6", "--max-time", "12", "--write-out",
            "%{http_code}\t%{http_connect}\t%{ssl_verify_result}\t%{time_appconnect}\t%{time_total}", url]
    keep = {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE",
            "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE"}
    env = {k: v for k, v in environ.items() if k in keep}
    result = {"name": name, "url": url, "transport_reached": False, "access": "unknown"}
    try:
        process = runner(args, input='proxy = "' + escaped + '"\n', env=env,
                         capture_output=True, text=True, timeout=15)
        if len(process.stdout) > 4096:
            raise ValueError("oversize metrics")
        fields = process.stdout.strip().split()
        if len(fields) != 5:
            raise ValueError("invalid metrics")
        status, connect, verify = map(int, fields[:3])
        tls, elapsed = map(float, fields[3:])
        if (not 0 <= status <= 599 or not 0 <= connect <= 599 or verify < 0
                or not math.isfinite(tls) or not math.isfinite(elapsed) or tls < 0 or elapsed < 0):
            raise ValueError("invalid metrics")
        reached = process.returncode == 0 and 100 <= status <= 599 and verify == 0 and tls > 0
        access = ("unauthenticated" if status == 401 else "access_restricted" if status in (403, 407)
                  else "server_error" if status >= 500 else "http_response")
        result.update(curl_exit=process.returncode, http_status=status, proxy_connect_status=connect,
                      tls_verified=reached, elapsed_seconds=elapsed, transport_reached=reached,
                      access=access if reached else "unknown")
    except subprocess.TimeoutExpired:
        result["error"] = "probe_timeout"
    except OSError:
        result["error"] = "curl_unavailable"
    except (ValueError, TypeError):
        result["error"] = "invalid_probe_output"
    return result


def diagnose(argv, *, environ=None, input_stream=None, runner=None):
    parser = DiagnosticParser(description=__doc__, allow_abbrev=False)
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument("--proxy", help="explicit HTTP/HTTPS/SOCKS5/SOCKS5H proxy URL with a port")
    choice.add_argument("--config", help="private JSON file containing proxy_url")
    choice.add_argument("--stdin-config", action="store_true", help="read private JSON from stdin")
    environ = os.environ if environ is None else environ
    input_stream = sys.stdin if input_stream is None else input_stream
    runner = subprocess.run if runner is None else runner
    report = {"schema_version": 1, "mode": "proxy_diagnostics", "scope": "unauthenticated_transport_only",
              "account_status": "not_evaluated", "leak_protection": "not_evaluated",
              "launch_allowed": None, "application_started": False, "system_modified": False,
              "checks": []}
    try:
        args = parser.parse_args(argv)
        proxy, public = select_proxy(args, environ, input_stream)
    except (OSError, ValueError, TypeError, UnicodeError):
        report.update(status="error", state="configuration_error", error="invalid_or_missing_proxy",
                      message="请明确提供带端口的 HTTP/HTTPS/SOCKS5/SOCKS5H 代理；认证信息可通过私有 JSON 或标准输入提供。")
        return report, 2
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(probe, name, url, proxy, environ, runner) for name, url in TARGETS]
        checks = [future.result() for future in futures]
    reached = all(check["transport_reached"] for check in checks)
    report.update(status="ok" if reached else "partial", proxy=public, checks=checks,
                  state="transport_reached" if reached else "transport_failed",
                  message="两个目标均收到 TLS 验证后的 HTTP 响应；认证与访问限制见逐项结果。" if reached
                  else "部分传输未完成；失败或未知项没有被视为通过。")
    return report, 0 if reached else 1


def main(argv=None):
    report, code = diagnose(sys.argv[1:] if argv is None else argv)
    print(json.dumps(report, ensure_ascii=False))
    return code
