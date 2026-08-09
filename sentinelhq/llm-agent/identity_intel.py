"""
SentinelHQ — Identity Intelligence
Behavioral logon analytics on agent-collected Windows Security events already in
the DB (no new agent):
  • EID 4624 — logon success
  • EID 4672 — special privileges assigned (admin logon)

(Brute-force 4625→4624 is already handled by chain_detector.win_brute_force —
not duplicated here.)

Emits signals in correlator's shape {type, desc, severity, alert_id} — flows
through the existing correlation → cooldown → LLM → Telegram pipeline — and
records each finding in the user_anomalies table.

Detections (mapped to response_playbooks, DB/UI-controlled):
  1. IDENTITY_OFFHOURS_LOGON — logon during off-hours window (UI-configurable)
  2. IDENTITY_NEW_HOST_LOGON — user logs into a host never used before (lateral)
  3. IDENTITY_PRIV_ANOMALY   — user gets admin privileges, not privileged before
"""

import os
import re
import logging
from collections import defaultdict
from datetime import timedelta

try:
    import zoneinfo
except Exception:
    zoneinfo = None

log = logging.getLogger("identity_intel")

NI_RECENT_MIN   = int(os.environ.get("ID_RECENT_MIN", 15))    # "recent" logon window
NI_BASELINE_DAYS= int(os.environ.get("ID_BASELINE_DAYS", 30)) # novelty baseline
NI_MAX_PER_TYPE = int(os.environ.get("ID_MAX_PER_TYPE", 5))
_TZ_NAME        = os.environ.get("TZ", "Europe/Vilnius")

# Logon full_log carries the account in the "Process:" field, e.g.
#   "Rule: Windows Workstation Logon Success | Process: Karolis"
_USER_RE = re.compile(r"Process:\s*([^\|]+)", re.IGNORECASE)

# Windows virtual / service pseudo-accounts that get "special privileges" every
# session — pure noise, never real identities. DWM-N (Desktop Window Manager) and
# UMFD-N (User-Mode Font Driver Host) are per-session; the rest are constants.
_IGNORE_USERS = {
    "system", "-", "anonymous logon", "local service", "network service",
    "dwm", "umfd", "iusr", "defaultaccount", "wdagutilityaccount",
}
_IGNORE_RE = re.compile(r"^(dwm|umfd)-\d+$", re.IGNORECASE)  # DWM-1, UMFD-2, ...
# Extra accounts to ignore via env (comma-separated), case-insensitive.
_IGNORE_USERS |= {u.strip().lower() for u in
                  os.environ.get("ID_IGNORE_USERS", "").split(",") if u.strip()}


def _user(full_log: str) -> str:
    m = _USER_RE.search(full_log or "")
    if not m:
        return ""
    u = m.group(1).strip().strip("\\").strip()
    if not u or u.endswith("$"):                 # machine accounts (HOST$)
        return ""
    lu = u.lower()
    if lu in _IGNORE_USERS or _IGNORE_RE.match(lu):
        return ""
    return u


def _local_tz():
    if zoneinfo:
        try:
            return zoneinfo.ZoneInfo(_TZ_NAME)
        except Exception:
            pass
    from datetime import timezone
    return timezone(timedelta(hours=2))


def _is_offhours(dt_utc, start, end, weekend) -> bool:
    """dt_utc: tz-aware UTC datetime. start/end: local hours. weekend: bool."""
    loc = dt_utc.astimezone(_local_tz())
    if weekend and loc.weekday() >= 5:        # Sat/Sun
        return True
    h = loc.hour
    if start == end:
        return False
    if start < end:                            # e.g. 9..17 daytime window
        return start <= h < end
    return h >= start or h < end               # overnight window e.g. 20..7


def _record_anomaly(cur, username, agent_id, atype, confidence, details):
    try:
        cur.execute("""
            INSERT INTO user_anomalies(username, agent_id, anomaly_type, confidence, details)
            VALUES (%s, %s, %s, %s, %s::jsonb)
        """, (username, agent_id, atype, confidence,
              __import__("json").dumps(details)))
    except Exception as e:
        log.debug("user_anomalies insert failed: %s", e)


# ── Detections ──────────────────────────────────────────────────────────────────

def _detect_offhours(cur, agent_id, en, ttype, sev, cfg):
    start, end, weekend = cfg["start"], cfg["end"], cfg["weekend"]
    cur.execute("""
        SELECT id, full_log, COALESCE(alert_ts, collected_at) AS ts
        FROM alerts
        WHERE agent_id=%s AND event_id=4624
          AND collected_at >= now() - make_interval(mins => %s)
        ORDER BY id DESC LIMIT 500
    """, (agent_id, NI_RECENT_MIN))
    sigs, seen = [], set()
    for r in cur.fetchall():
        u = _user(r["full_log"])
        if not u or u in seen:
            continue
        if not _is_offhours(r["ts"], start, end, weekend):
            continue
        seen.add(u)
        loc = r["ts"].astimezone(_local_tz())
        when = loc.strftime("%a %H:%M")
        desc = (f"Off-hours logon: {u} at {when}"
                if en else f"Loginas ne darbo metu: {u} ({when})")
        _record_anomaly(cur, u, agent_id, ttype, 70,
                        {"when": loc.isoformat(), "window": f"{start}-{end}", "weekend": weekend})
        sigs.append({"type": ttype, "desc": desc, "severity": sev, "alert_id": r["id"]})
        if len(sigs) >= NI_MAX_PER_TYPE:
            break
    return sigs


def _detect_new_host(cur, agent_id, en, ttype, sev, cfg):
    cur.execute("""
        SELECT id, full_log, collected_at
        FROM alerts
        WHERE agent_id=%s AND event_id=4624
          AND collected_at >= now() - make_interval(days => %s)
        ORDER BY id DESC LIMIT 20000
    """, (agent_id, NI_BASELINE_DAYS))
    rows = cur.fetchall()
    recent, historic, recent_id = set(), set(), {}
    if rows:
        newest = rows[0]["collected_at"]
        for r in rows:
            u = _user(r["full_log"])
            if not u:
                continue
            age_min = (newest - r["collected_at"]).total_seconds() / 60.0
            if age_min <= NI_RECENT_MIN:
                recent.add(u); recent_id.setdefault(u, r["id"])
            else:
                historic.add(u)
    sigs = []
    for u in recent - historic:
        desc = (f"First-ever logon by {u} on this host — possible lateral movement"
                if en else f"{u} pirmą kartą jungiasi prie šio hosto — galimas šoninis judėjimas")
        _record_anomaly(cur, u, agent_id, ttype, 65, {"baseline_days": NI_BASELINE_DAYS})
        sigs.append({"type": ttype, "desc": desc, "severity": sev, "alert_id": recent_id[u]})
        if len(sigs) >= NI_MAX_PER_TYPE:
            break
    return sigs


def _detect_priv_anomaly(cur, agent_id, en, ttype, sev, cfg):
    cur.execute("""
        SELECT id, full_log, collected_at
        FROM alerts
        WHERE agent_id=%s AND event_id=4672
          AND collected_at >= now() - make_interval(days => %s)
        ORDER BY id DESC LIMIT 20000
    """, (agent_id, NI_BASELINE_DAYS))
    rows = cur.fetchall()
    recent, historic, recent_id = set(), set(), {}
    if rows:
        newest = rows[0]["collected_at"]
        for r in rows:
            u = _user(r["full_log"])
            if not u:
                continue
            age_min = (newest - r["collected_at"]).total_seconds() / 60.0
            if age_min <= NI_RECENT_MIN:
                recent.add(u); recent_id.setdefault(u, r["id"])
            else:
                historic.add(u)
    sigs = []
    for u in recent - historic:
        desc = (f"New privileged account: {u} assigned admin rights (not seen before)"
                if en else f"Naujas privilegijuotas vartotojas: {u} gavo admin teises (nematytas anksčiau)")
        _record_anomaly(cur, u, agent_id, ttype, 75, {"baseline_days": NI_BASELINE_DAYS})
        sigs.append({"type": ttype, "desc": desc, "severity": sev, "alert_id": recent_id[u]})
        if len(sigs) >= NI_MAX_PER_TYPE:
            break
    return sigs


_DETECTORS = (
    ("IDENTITY_OFFHOURS_LOGON", _detect_offhours),
    ("IDENTITY_NEW_HOST_LOGON", _detect_new_host),
    ("IDENTITY_PRIV_ANOMALY",   _detect_priv_anomaly),
)

ID_TRIGGER_TYPES = frozenset(t for t, _ in _DETECTORS)


def detect(conn, agent_id, agent_name="", lang="lt", playbooks=None, offhours=None) -> list:
    """Run identity detections for one agent. Playbook-driven (enabled/severity/
    cooldown from DB). offhours = {start, end, weekend} from llm_config.
    """
    en = (lang == "en")
    playbooks = playbooks or {}
    cfg = offhours or {"start": 20, "end": 7, "weekend": True}
    out = []
    for ttype, fn in _DETECTORS:
        pb = playbooks.get(ttype)
        if not pb or not pb.get("enabled", True):
            continue
        sev = int(pb.get("min_severity") or 9)
        cd  = pb.get("cooldown_minutes")
        try:
            with conn.cursor() as cur:
                sigs = fn(cur, agent_id, en, ttype, sev, cfg)
            for s in sigs:
                if cd is not None:
                    s["cooldown"] = cd
            out.extend(sigs)
        except Exception as e:
            log.warning("identity_intel %s failed for %s: %s", ttype, agent_id, e)
    if out:
        log.info("identity_intel %s: %s", agent_name or agent_id, [s["type"] for s in out])
    return out
