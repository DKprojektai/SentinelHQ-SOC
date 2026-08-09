"""AlienVault OTX threat intelligence lookup with in-memory cache."""

import os
import time
import logging
import requests

log = logging.getLogger(__name__)

OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
OTX_BASE    = "https://otx.alienvault.com/api/v1"

# cache: ip -> {data, expires}
_cache: dict = {}
CACHE_TTL = 3600  # 1 hour


def _is_private(ip: str) -> bool:
    """Skip OTX lookup for private/loopback IPs."""
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


def lookup_ip(ip: str) -> dict:
    """
    Fetch OTX reputation for an IP.
    Returns dict with keys: ip, pulse_count, reputation, threat_types,
    malware_families, country, asn, is_malicious, error (if any).
    """
    if not OTX_API_KEY:
        return {"ip": ip, "error": "OTX_API_KEY not configured"}

    if _is_private(ip):
        return {"ip": ip, "private": True, "pulse_count": 0, "is_malicious": False}

    now = time.time()
    if ip in _cache and _cache[ip]["expires"] > now:
        return _cache[ip]["data"]

    try:
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        r = requests.get(
            f"{OTX_BASE}/indicators/IPv4/{ip}/general",
            headers=headers,
            timeout=8
        )
        r.raise_for_status()
        d = r.json()

        pulse_count  = d.get("pulse_info", {}).get("count", 0)
        reputation   = d.get("reputation", 0)
        country      = d.get("country_name", "") or d.get("country_code", "")
        asn          = d.get("asn", "")

        # Collect threat types and malware families from pulses
        pulses       = d.get("pulse_info", {}).get("pulses", [])[:10]
        threat_types = list({t for p in pulses for t in (p.get("tags") or [])})[:8]
        malware_fams = list({m.get("display_name", "") for p in pulses
                             for m in (p.get("malware_families") or [])
                             if m.get("display_name")})[:6]

        result = {
            "ip":             ip,
            "pulse_count":    pulse_count,
            "reputation":     reputation,
            "country":        country,
            "asn":            asn,
            "threat_types":   threat_types,
            "malware_families": malware_fams,
            "is_malicious":   pulse_count > 0,
            "otx_url":        f"https://otx.alienvault.com/indicator/ip/{ip}",
        }

        _cache[ip] = {"data": result, "expires": now + CACHE_TTL}
        return result

    except requests.HTTPError as e:
        log.warning("OTX lookup HTTP error for %s: %s", ip, e)
        return {"ip": ip, "error": f"HTTP {e.response.status_code}"}
    except Exception as e:
        log.warning("OTX lookup failed for %s: %s", ip, e)
        return {"ip": ip, "error": str(e)}
