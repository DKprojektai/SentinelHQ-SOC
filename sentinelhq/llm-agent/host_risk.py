"""
SentinelHQ — Host Risk (crown-jewel fusion)
Pulls per-host exposure straight from Wazuh: critical/high CVE counts (indexer
wazuh-states-vulnerabilities) + externally-exposed risky listening ports
(syscollector). Used by the correlator to add live context to an incident popup
and modestly bump severity when an alert lands on an already-exposed host.

Cached in-memory (TTL) so clustered notifications don't hammer the API/indexer.
Fully defensive: any failure → empty risk, never breaks the correlation cycle.
"""

import os
import time
import logging

import requests
try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

log = logging.getLogger("host_risk")

WAZUH_API_URL   = os.environ.get("WAZUH_API_URL", "")
WAZUH_API_USER  = os.environ.get("WAZUH_API_USER", "")
WAZUH_API_PASS  = os.environ.get("WAZUH_API_PASS", "")
OPENSEARCH_URL  = os.environ.get("OPENSEARCH_URL", "")
OPENSEARCH_USER = os.environ.get("OPENSEARCH_USER", "admin")
OPENSEARCH_PASS = os.environ.get("OPENSEARCH_PASS", "")
_VERIFY_SSL     = os.environ.get("WAZUH_VERIFY_SSL", "false").lower() == "true"

HOST_RISK_ENABLED = os.environ.get("HOST_RISK_ENABLED", "true").lower() == "true"
_TTL              = int(os.environ.get("HOST_RISK_TTL", 1800))   # 30 min

RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 135: "RPC", 137: "NetBIOS", 139: "NetBIOS",
    445: "SMB", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "Postgres", 5900: "VNC", 5985: "WinRM", 5986: "WinRM", 6379: "Redis",
    7070: "AnyDesk", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}
_LOCALHOST_IPS = {"127.0.0.1", "::1", ""}

_cache = {}   # agent_id -> (ts, risk dict)
_token = {"val": None, "ts": 0}


def _empty():
    return {"crit": 0, "high": 0, "exposed_risky": [], "available": False}


def _api_token():
    if _token["val"] and (time.time() - _token["ts"]) < 600:
        return _token["val"]
    try:
        r = requests.get(f"{WAZUH_API_URL}/security/user/authenticate",
                         auth=(WAZUH_API_USER, WAZUH_API_PASS),
                         verify=_VERIFY_SSL, timeout=15)
        r.raise_for_status()
        _token["val"] = r.json()["data"]["token"]
        _token["ts"] = time.time()
        return _token["val"]
    except Exception as e:
        log.warning("host_risk API auth failed: %s", e)
        return None


def _cve_counts(agent_id):
    if not (OPENSEARCH_URL and OPENSEARCH_PASS):
        return 0, 0
    try:
        body = {"size": 0,
                "query": {"term": {"agent.id": agent_id}},
                "aggs": {"sev": {"terms": {"field": "vulnerability.severity",
                                           "size": 10}}}}
        r = requests.post(
            f"{OPENSEARCH_URL}/wazuh-states-vulnerabilities*/_search",
            auth=(OPENSEARCH_USER, OPENSEARCH_PASS), verify=_VERIFY_SSL,
            timeout=15, json=body, headers={"Content-Type": "application/json"})
        sev = {b["key"].lower(): b["doc_count"]
               for b in r.json().get("aggregations", {}).get("sev", {}).get("buckets", [])}
        return sev.get("critical", 0), sev.get("high", 0)
    except Exception as e:
        log.warning("host_risk CVE query failed for %s: %s", agent_id, e)
        return 0, 0


def _risky_ports(agent_id, token):
    if not token:
        return []
    try:
        r = requests.get(f"{WAZUH_API_URL}/syscollector/{agent_id}/ports",
                         headers={"Authorization": f"Bearer {token}"},
                         verify=_VERIFY_SSL, timeout=15,
                         params={"limit": 500, "q": "state=listening",
                                 "select": "local.port,local.ip,protocol"})
        seen = set()
        for it in r.json().get("data", {}).get("affected_items", []):
            ip = (it.get("local", {}).get("ip") or "").strip()
            port = it.get("local", {}).get("port")
            if ip in _LOCALHOST_IPS or port not in RISKY_PORTS:
                continue
            seen.add(RISKY_PORTS[port])
        return sorted(seen)
    except Exception as e:
        log.warning("host_risk ports query failed for %s: %s", agent_id, e)
        return []


def get_host_risk(agent_id: str, agent_name: str = "") -> dict:
    """Return {crit, high, exposed_risky:[labels], available}. Cached per agent."""
    if not HOST_RISK_ENABLED or not agent_id or agent_id == "000":
        return _empty()
    now = time.time()
    hit = _cache.get(agent_id)
    if hit and (now - hit[0]) < _TTL:
        return hit[1]
    crit, high = _cve_counts(agent_id)
    risky = _risky_ports(agent_id, _api_token())
    risk = {"crit": crit, "high": high, "exposed_risky": risky,
            "available": True}
    _cache[agent_id] = (now, risk)
    return risk


def is_exposed(risk: dict) -> bool:
    """High-exposure host: has critical CVEs OR risky externally-listening ports."""
    return bool(risk.get("crit", 0) > 0 or risk.get("exposed_risky"))


def severity_boost(risk: dict) -> int:
    """+1 if host is exposed, +2 if critical CVEs AND a risky port (worst case)."""
    if not risk.get("available"):
        return 0
    crit = risk.get("crit", 0)
    has_port = bool(risk.get("exposed_risky"))
    if crit > 0 and has_port:
        return 2
    if crit > 0 or has_port:
        return 1
    return 0


def context_line(risk: dict, en: bool) -> str:
    """One-line host-exposure context for the incident popup ('' if none)."""
    if not risk.get("available") or not is_exposed(risk):
        return ""
    parts = []
    crit, high = risk.get("crit", 0), risk.get("high", 0)
    if crit or high:
        parts.append((f"{crit} critical / {high} high CVEs" if en
                      else f"{crit} kritiniai / {high} aukšti CVE"))
    if risk.get("exposed_risky"):
        ports = ", ".join(risk["exposed_risky"][:6])
        parts.append((f"exposed: {ports}" if en else f"atviri: {ports}"))
    if not parts:
        return ""
    label = "Host exposure" if en else "Hosto rizika"
    return f"⚠️ {label}: " + " | ".join(parts)

