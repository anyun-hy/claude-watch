#!/usr/bin/env python3
"""Proxy-only DNS and GeoIP reference lookup for supported AI service hosts.

This is reference data, not traffic evidence.  It intentionally has no disk
cache: the GUI owns cache duration and request coalescing.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
import time
from typing import Any, Optional


CURL = "/usr/bin/curl"
PROXY = "http://127.0.0.1:7890"
DNS_URL = "https://cloudflare-dns.com/dns-query"
GEO_URL = "https://ipinfo.io/{}/json"
MAX_RESPONSE_BYTES = 65_536
CONNECT_TIMEOUT_SECONDS = 3
TOTAL_TIMEOUT_SECONDS = 8
REFERENCE_TTL_SECONDS = 600
FAILURE_TTL_SECONDS = 300
ALLOWED_ROOTS = (
    "chatgpt.com",
    "openai.com",
    "oaiusercontent.com",
    "claude.ai",
    "anthropic.com",
)
FAKE_BENCHMARK_NET = ipaddress.ip_network("198.18.0.0/15")


def empty_result(host: str, now: int, message: str) -> dict[str, Any]:
    return {
        "host": host,
        "basis": "dns_reference",
        "address": "",
        "addresses": [],
        "countryCode": "",
        "country": "",
        "region": "",
        "city": "",
        "status": "unavailable",
        "message": message,
        "queriedAt": now,
        "expiresAt": now + FAILURE_TTL_SECONDS,
        "dnsSource": "Cloudflare DoH",
        "geoSource": "IPinfo",
    }


def normalize_host(value: str) -> Optional[str]:
    """Return a permitted DNS hostname, allowing only a numeric :port suffix."""
    candidate = value.strip().lower()
    if not candidate or any(token in candidate for token in ("://", "/", "@", "?", "#", "[", "]")):
        return None
    if candidate.endswith("."):
        candidate = candidate[:-1]
    if ":" in candidate:
        host, separator, port = candidate.rpartition(":")
        if not separator or not host or not port.isdecimal() or not 1 <= int(port) <= 65535:
            return None
        candidate = host
    if candidate.endswith("."):
        candidate = candidate[:-1]
    if not candidate or len(candidate) > 253 or candidate.endswith("."):
        return None
    try:
        ipaddress.ip_address(candidate)
        return None
    except ValueError:
        pass
    labels = candidate.split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        return None
    if not any(candidate == root or candidate.endswith("." + root) for root in ALLOWED_ROOTS):
        return None
    return candidate


def is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        address.is_global
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
        and not address.is_link_local
        and not address.is_loopback
        and address not in FAKE_BENCHMARK_NET
    )


def curl_json(url: str, headers: Optional[list[str]] = None) -> Optional[dict[str, Any]]:
    command = [
        CURL, "-q", "--fail", "--silent", "--show-error",
        "--proto", "=https", "--proxy", PROXY, "--noproxy", "",
        "--connect-timeout", str(CONNECT_TIMEOUT_SECONDS),
        "--max-time", str(TOTAL_TIMEOUT_SECONDS),
        "--max-filesize", str(MAX_RESPONSE_BYTES),
    ]
    for header in headers or []:
        command.extend(["--header", header])
    command.append(url)
    try:
        completed = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=False, timeout=TOTAL_TIMEOUT_SECONDS + 2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 or len(completed.stdout) > MAX_RESPONSE_BYTES:
        return None
    try:
        parsed = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def resolve_dns(host: str) -> list[str]:
    for record_type, dns_type in (("A", 1), ("AAAA", 28)):
        payload = curl_json(
            DNS_URL + "?name=" + host + "&type=" + record_type,
            headers=["Accept: application/dns-json"],
        )
        if payload is None or ("Status" in payload and payload["Status"] != 0):
            continue
        answers = payload.get("Answer")
        if not isinstance(answers, list):
            continue
        addresses: list[str] = []
        for answer in answers:
            if not isinstance(answer, dict) or answer.get("type") != dns_type:
                continue
            data = answer.get("data")
            if isinstance(data, str) and is_public_ip(data):
                addresses.append(data)
        if addresses:
            return sorted(set(addresses))
    return []


def lookup_geo(address: str) -> Optional[dict[str, str]]:
    payload = curl_json(GEO_URL.format(address))
    country = payload.get("country") if isinstance(payload, dict) else None
    if (
        payload is None
        or "error" in payload
        or payload.get("ip") != address
        or not isinstance(country, str)
        or re.fullmatch(r"[A-Za-z]{2}", country) is None
    ):
        return None
    return {
        "countryCode": country.upper(),
        "country": "",
        "region": payload.get("region") if isinstance(payload.get("region"), str) else "",
        "city": payload.get("city") if isinstance(payload.get("city"), str) else "",
    }


def query(host_input: str, supplied_ip: Optional[str] = None, now: Optional[int] = None) -> dict[str, Any]:
    queried_at = int(time.time() if now is None else now)
    host = normalize_host(host_input)
    if host is None:
        return empty_result("", queried_at, "仅支持指定 AI 服务的域名或子域名。")

    if supplied_ip is not None:
        address = supplied_ip.strip()
        if not is_public_ip(address):
            return empty_result(host, queried_at, "目标 IP 不是可查询的公网地址。")
        addresses = [address]
        basis = "observed_ip"
        dns_source = ""
    else:
        addresses = resolve_dns(host)
        if not addresses:
            return empty_result(host, queried_at, "DNS 参考查询未返回可用公网地址。")
        address = addresses[0]
        basis = "dns_reference"
        dns_source = "Cloudflare DoH"

    geo = lookup_geo(address)
    result = {
        "host": host,
        "basis": basis,
        "address": address,
        "addresses": addresses,
        "countryCode": "",
        "country": "",
        "region": "",
        "city": "",
        "status": "ready" if basis == "dns_reference" else "unavailable",
        "message": "IP 归属参考查询未完成。",
        "queriedAt": queried_at,
        "expiresAt": queried_at + REFERENCE_TTL_SECONDS,
        "dnsSource": dns_source,
        "geoSource": "IPinfo",
    }
    if geo is not None:
        result.update(geo)
        result["status"] = "ready"
        result["message"] = "DNS 解析与 IP 归属仅作参考，非这条连接的实测目标 IP。" if basis == "dns_reference" else "基于已观测目标 IP 的归属参考。"
    elif basis == "observed_ip":
        result["expiresAt"] = queried_at + FAILURE_TTL_SECONDS
    return result


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--ip")
    args = parser.parse_args(argv)
    print(json.dumps(query(args.host, args.ip), ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
