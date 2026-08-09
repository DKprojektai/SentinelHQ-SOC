"""GeoIP lookup via ip-api.com (free, no key, 45 req/min)."""

import time
import logging
import ipaddress
import requests

log = logging.getLogger(__name__)

_cache: dict = {}
CACHE_TTL = 86400  # 24h — IPs don't move often


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified)
    except ValueError:
        return False


def lookup(ip: str) -> dict:
    """
    Returns dict: {country_code, country, asn, isp, city}
    Returns {} for private IPs or on error.
    """
    if not ip or not _is_public(ip):
        return {}

    now = time.time()
    if ip in _cache and _cache[ip]["expires"] > now:
        return _cache[ip]["data"]

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,city,isp,org,as"},
            timeout=3,
        )
        d = r.json()
        if d.get("status") != "success":
            return {}

        result = {
            "country_code": d.get("countryCode", ""),
            "country":      d.get("country", ""),
            "asn":          d.get("as", "") or d.get("org", ""),
            "isp":          d.get("isp", ""),
            "city":         d.get("city", ""),
        }
        _cache[ip] = {"data": result, "expires": now + CACHE_TTL}
        return result

    except Exception as e:
        log.debug("GeoIP lookup failed for %s: %s", ip, e)
        return {}
