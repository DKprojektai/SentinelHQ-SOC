"""AlienVault OTX IP lookup for collector enrichment (cached)."""

import os
import time
import logging
import ipaddress
import requests

log = logging.getLogger(__name__)

OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
OTX_BASE    = "https://otx.alienvault.com/api/v1"

# Minimum OTX pulse count to flag an IP as malicious. Many legit IPs appear in
# 1 pulse (CDN edges, scanners, debug pulses) → require >=2 to reduce FP noise.
MIN_MALICIOUS_PULSES = int(os.environ.get("OTX_MALICIOUS_MIN_PULSES", 2))

_cache: dict = {}
CACHE_TTL = 3600  # 1h


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified)
    except ValueError:
        return False


def lookup(ip: str) -> dict:
    """
    Returns {pulse_count, is_malicious}.
    Returns {pulse_count:0, is_malicious:False} on error or private IP.
    """
    empty = {"pulse_count": 0, "is_malicious": False}

    if not OTX_API_KEY or not ip or not _is_public(ip):
        return empty

    now = time.time()
    if ip in _cache and _cache[ip]["expires"] > now:
        return _cache[ip]["data"]

    try:
        r = requests.get(
            f"{OTX_BASE}/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=4,
        )
        r.raise_for_status()
        d = r.json()
        pulse_count = d.get("pulse_info", {}).get("count", 0)
        result = {
            "pulse_count":  pulse_count,
            "is_malicious": pulse_count >= MIN_MALICIOUS_PULSES,
        }
        _cache[ip] = {"data": result, "expires": now + CACHE_TTL}
        return result

    except Exception as e:
        log.debug("OTX lookup failed for %s: %s", ip, e)
        _cache[ip] = {"data": empty, "expires": now + 300}  # cache failure 5min
        return empty
