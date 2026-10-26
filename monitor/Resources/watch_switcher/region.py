"""One measured-egress reference for region, date conventions and timezone."""
from __future__ import annotations

from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .common import LOCALES


@lru_cache(maxsize=1)
def country_timezones():
    result = {}
    for filename in ("/usr/share/zoneinfo/zone.tab", "/usr/share/zoneinfo/zone1970.tab",
                     "/var/db/timezone/zoneinfo/zone.tab"):
        try: lines = Path(filename).read_text().splitlines()
        except OSError: continue
        for line in lines:
            if not line or line.startswith("#"): continue
            fields = line.split("\t")
            if len(fields) < 3: continue
            for country in fields[0].split(","):
                result.setdefault(country, set()).add(fields[2])
    return result


def reference(trace, geo):
    """Missing/inconsistent evidence stays missing; no country or NY fallback."""
    if not isinstance(trace, dict) or not isinstance(geo, dict): return {}
    try:
        address = ip_address(trace.get("ip"))
        country = geo.get("country")
        if (not address.is_global or str(address) != geo.get("ip") or
                not isinstance(country, str) or not re.fullmatch(r"[A-Z]{2}", country) or
                trace.get("loc") != country): return {}
    except (ValueError, TypeError): return {}
    timezone = geo.get("timezone")
    valid_timezone = None
    timezone_source = ""
    if isinstance(timezone, str) and re.fullmatch(r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)+", timezone):
        try:
            ZoneInfo(timezone)
            if timezone in country_timezones().get(country, set()):
                valid_timezone = timezone
                timezone_source = str(geo.get("timezone_source") or "Net.Coffee / IPinfo timezone")[:160]
        except (ValueError, ZoneInfoNotFoundError): pass
    if valid_timezone is None and not timezone:
        candidates = country_timezones().get(country, set())
        if len(candidates) == 1:
            valid_timezone = next(iter(candidates))
            timezone_source = "出口国家唯一 IANA 时区"
    return dict(ip=str(address), country=country, timezone=valid_timezone,
                locale=LOCALES.get(country), timezone_source=timezone_source or "出口时区未确认",
                locale_source="出口国家对应的地区格式；界面语言独立")


def date_check(local, expected_locale):
    """Compare actual Foundation date styles with the same SDK's fixed locale."""
    observed = local.get("date_format", {})
    if not isinstance(observed, dict) or observed.get("state") != "available" or not expected_locale:
        return "unknown"
    references = observed.get("reference_patterns")
    actual = observed.get("patterns")
    expected = references.get(expected_locale) if isinstance(references, dict) else None
    if not isinstance(actual, dict) or not isinstance(expected, dict): return "unknown"
    styles = ("short", "medium", "long")
    if any(not isinstance(values.get(style), str) or not values[style] for values in (actual, expected) for style in styles):
        return "unknown"
    if observed.get("configured_locale") != local.get("locale"): return "unknown"
    return "ok" if all(actual[style] == expected[style] for style in styles) else "fail"


def locale_check(local, expected_locale):
    if not expected_locale or not local.get("locale"): return "unknown"
    if local["locale"] != expected_locale: return "fail"
    return date_check(local, expected_locale)


def date_summary(local):
    data = local.get("date_format", {})
    sample = data.get("short_sample") if isinstance(data, dict) else None
    if not isinstance(sample, str): sample = None
    return str(local.get("locale") or "未知") + (" · 示例 " + sample if sample else " · 日期格式未确认")


def expected_date_summary(local, expected_locale):
    data = local.get("date_format", {})
    samples = data.get("reference_samples") if isinstance(data, dict) else None
    sample = samples.get(expected_locale) if isinstance(samples, dict) else None
    if not isinstance(sample, str): sample = None
    return (expected_locale or "出口地区格式未确认") + (" · 示例 " + sample if sample else "")
