"""
SentinelHQ — Network Intelligence
Mines agent-collected Sysmon network telemetry already in the DB:
  • EID 3  — Network connection (destinationIp/Port, sourceIp, process)
  • EID 22 — DNS Request (queryName)

Emits signals in the same shape as correlator.check_absolute_signals:
    {"type": str, "desc": str (localized), "severity": int, "alert_id": int}
so they flow through the existing correlation → cooldown → LLM → Telegram
pipeline (incl. /muted). No mirror/SPAN, no new agent — pure analytics.

Detections (mapped to response_playbooks trigger_type — all DB/UI-controlled:
enabled, min_severity, cooldown_minutes, notify_telegram, auto_isolate):
  1. OTX_BAD_DESTINATION — connection/DNS to OTX-flagged indicator
  2. NETWORK_C2_BEACON   — periodic, low-jitter connections (C2 pattern)
  3. DNS_EXFIL           — long/high-entropy queries or many subdomains/parent
  4. RARE_DESTINATION    — external dst first seen for this agent
  5. NETWORK_PORT_SCAN   — one process → many distinct dst ports fast

Nothing about WHICH detections run / how loud they are is hardcoded: a detection
is skipped entirely if its playbook row is missing or disabled; severity and
cooldown come from the playbook row. Only the detection *math* thresholds
(jitter, port count, entropy…) are env-tunable constants below.
"""

import os
import re
import math
import logging
import ipaddress
import statistics
from collections import defaultdict

log = logging.getLogger("network_intel")

# ── Tunable thresholds (env-overridable) ────────────────────────────────────────
NI_LOOKBACK_HOURS   = int(os.environ.get("NI_LOOKBACK_HOURS", 24))    # beaconing window
NI_DNS_HOURS        = int(os.environ.get("NI_DNS_HOURS", 6))
NI_OTX_MIN_PULSES   = int(os.environ.get("NI_OTX_MIN_PULSES", 2))
NI_BEACON_MIN_CONN  = int(os.environ.get("NI_BEACON_MIN_CONN", 8))
NI_BEACON_MAX_CV    = float(os.environ.get("NI_BEACON_MAX_CV", 0.20)) # interval coeff. of variation
NI_DNS_MAX_LEN      = int(os.environ.get("NI_DNS_MAX_LEN", 50))       # query length
NI_DNS_MIN_ENTROPY  = float(os.environ.get("NI_DNS_MIN_ENTROPY", 3.5))
NI_DNS_SUBDOM_MAX   = int(os.environ.get("NI_DNS_SUBDOM_MAX", 30))    # unique subdomains/parent
NI_SCAN_PORTS       = int(os.environ.get("NI_SCAN_PORTS", 15))        # distinct dst ports
NI_SCAN_WINDOW_MIN  = int(os.environ.get("NI_SCAN_WINDOW_MIN", 10))
NI_MAX_PER_TYPE     = int(os.environ.get("NI_MAX_PER_TYPE", 3))       # cap signals/type/cycle

_QNAME_RE = re.compile(r"queryName:\s*([^\s|]+)", re.IGNORECASE)
_DPORT_RE = re.compile(r"destinationPort:\s*(\d+)", re.IGNORECASE)


def _is_external(ip: str) -> bool:
    """True if ip is a routable public address (not private/loopback/link-local)."""
    try:
        o = ipaddress.ip_address(ip)
        return not (o.is_private or o.is_loopback or o.is_link_local
                    or o.is_multicast or o.is_reserved or o.is_unspecified)
    except Exception:
        return False


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _parent_domain(qname: str) -> str:
    parts = (qname or "").strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else qname


def _subdomain(qname: str) -> str:
    parts = (qname or "").strip(".").split(".")
    return ".".join(parts[:-2]) if len(parts) > 2 else ""


def _qname(full_log: str) -> str:
    m = _QNAME_RE.search(full_log or "")
    return m.group(1).rstrip(".").lower() if m else ""


def _dport(full_log: str):
    m = _DPORT_RE.search(full_log or "")
    return int(m.group(1)) if m else None


# ── Individual detections ───────────────────────────────────────────────────────

def _detect_otx(cur, agent_id, en, ttype, sev):
    sigs = []
    cur.execute("""
        SELECT id, event_id, dst_ip, src_proc_name, otx_pulses, full_log
        FROM alerts
        WHERE agent_id=%s AND event_id IN (3, 22)
          AND collected_at >= now() - interval '6 hours'
          AND (otx_malicious = true OR otx_pulses >= %s)
        ORDER BY otx_pulses DESC NULLS LAST, id DESC
        LIMIT 50
    """, (agent_id, NI_OTX_MIN_PULSES))
    seen = set()
    for r in cur.fetchall():
        ind = r["dst_ip"] or _qname(r["full_log"]) or "?"
        if ind in seen:
            continue
        seen.add(ind)
        proc = r["src_proc_name"] or "?"
        pulses = r["otx_pulses"] or 0
        desc = (f"Connection to OTX-flagged {ind} (pulses {pulses}) by {proc}"
                if en else
                f"Ryšys su OTX pažymėtu {ind} (pulsai {pulses}), procesas {proc}")
        sigs.append({"type": ttype, "desc": desc,
                     "severity": sev, "alert_id": r["id"]})
        if len(sigs) >= NI_MAX_PER_TYPE:
            break
    return sigs


def _detect_beaconing(cur, agent_id, en, ttype, sev):
    sigs = []
    cur.execute("""
        SELECT src_proc_name, dst_ip,
               array_agg(extract(epoch FROM collected_at) ORDER BY collected_at) AS ts,
               (array_agg(id ORDER BY id DESC))[1] AS last_id,
               count(*) AS n
        FROM alerts
        WHERE agent_id=%s AND event_id=3 AND dst_ip IS NOT NULL
          AND collected_at >= now() - make_interval(hours => %s)
        GROUP BY src_proc_name, dst_ip
        HAVING count(*) >= %s
    """, (agent_id, NI_LOOKBACK_HOURS, NI_BEACON_MIN_CONN))
    cands = []
    for r in cur.fetchall():
        if not _is_external(r["dst_ip"]):
            continue
        ts = sorted(float(x) for x in r["ts"])
        intervals = [b - a for a, b in zip(ts, ts[1:]) if (b - a) > 0]
        if len(intervals) < NI_BEACON_MIN_CONN - 1:
            continue
        mean = statistics.fmean(intervals)
        if mean <= 0:
            continue
        cv = (statistics.pstdev(intervals) / mean) if mean else 1.0
        if cv <= NI_BEACON_MAX_CV:
            cands.append((cv, mean, r))
    cands.sort(key=lambda x: x[0])  # most regular first
    for cv, mean, r in cands[:NI_MAX_PER_TYPE]:
        proc = r["src_proc_name"] or "?"
        period = f"{mean/60:.1f} min" if mean >= 60 else f"{mean:.0f} s"
        desc = (f"Beaconing: {proc} → {r['dst_ip']} every ~{period} "
                f"({r['n']}× , jitter {cv:.0%}) — possible C2"
                if en else
                f"Beaconing: {proc} → {r['dst_ip']} kas ~{period} "
                f"({r['n']}× , jitter {cv:.0%}) — galimas C2")
        sigs.append({"type": ttype, "desc": desc,
                     "severity": sev, "alert_id": r["last_id"]})
    return sigs


def _detect_dns_tunneling(cur, agent_id, en, ttype, sev):
    sigs = []
    cur.execute("""
        SELECT id, src_proc_name, full_log
        FROM alerts
        WHERE agent_id=%s AND event_id=22
          AND collected_at >= now() - make_interval(hours => %s)
        ORDER BY id DESC LIMIT 5000
    """, (agent_id, NI_DNS_HOURS))
    # per (proc, parent): unique subdomains, worst query
    agg = defaultdict(lambda: {"subs": set(), "worst": None, "worst_e": 0.0,
                               "last_id": None, "proc": "?"})
    for r in cur.fetchall():
        q = _qname(r["full_log"])
        if not q or "." not in q:
            continue
        parent = _parent_domain(q)
        sub = _subdomain(q)
        key = (r["src_proc_name"] or "?", parent)
        a = agg[key]
        a["proc"] = r["src_proc_name"] or "?"
        a["last_id"] = a["last_id"] or r["id"]
        if sub:
            a["subs"].add(sub)
        e = _entropy(sub or q)
        if (len(q) > a.get("worst_len", 0)) or e > a["worst_e"]:
            a["worst"] = q
            a["worst_e"] = e
            a["worst_len"] = len(q)
    scored = []
    for (proc, parent), a in agg.items():
        n_subs = len(a["subs"])
        long_hi = a["worst"] and len(a["worst"]) > NI_DNS_MAX_LEN and a["worst_e"] >= NI_DNS_MIN_ENTROPY
        if n_subs >= NI_DNS_SUBDOM_MAX or long_hi:
            scored.append((n_subs, parent, a))
    scored.sort(key=lambda x: -x[0])
    for n_subs, parent, a in scored[:NI_MAX_PER_TYPE]:
        desc = (f"Possible DNS tunneling on {parent}: {n_subs} unique subdomains "
                f"by {a['proc']} (e.g. {(a['worst'] or '')[:40]})"
                if en else
                f"Galimas DNS tuneliavimas per {parent}: {n_subs} unikalūs subdomenai, "
                f"procesas {a['proc']} (pvz. {(a['worst'] or '')[:40]})")
        sigs.append({"type": ttype, "desc": desc,
                     "severity": sev, "alert_id": a["last_id"]})
    return sigs


def _detect_rare_destination(cur, agent_id, en, ttype, sev):
    sigs = []
    cur.execute("""
        SELECT DISTINCT ON (dst_ip) dst_ip, src_proc_name, geo_country, id
        FROM alerts
        WHERE agent_id=%s AND event_id=3 AND dst_ip IS NOT NULL
          AND collected_at >= now() - interval '2 hours'
        ORDER BY dst_ip, id DESC
    """, (agent_id,))
    cands = [r for r in cur.fetchall() if _is_external(r["dst_ip"])]
    for r in cands:
        cur.execute("""
            SELECT 1 FROM alerts
            WHERE agent_id=%s AND dst_ip=%s
              AND collected_at <  now() - interval '2 hours'
              AND collected_at >= now() - interval '30 days'
            LIMIT 1
        """, (agent_id, r["dst_ip"]))
        if cur.fetchone():
            continue  # seen before → not rare
        proc = r["src_proc_name"] or "?"
        geo = (r["geo_country"] or "").strip()
        geo_s = f" [{geo}]" if geo else ""
        desc = (f"First-seen external destination {r['dst_ip']}{geo_s} by {proc}"
                if en else
                f"Pirmą kartą matomas išorinis adresas {r['dst_ip']}{geo_s}, procesas {proc}")
        sigs.append({"type": ttype, "desc": desc,
                     "severity": sev, "alert_id": r["id"]})
        if len(sigs) >= NI_MAX_PER_TYPE:
            break
    return sigs


def _detect_port_scan(cur, agent_id, en, ttype, sev):
    sigs = []
    cur.execute("""
        SELECT id, src_proc_name, dst_ip, full_log
        FROM alerts
        WHERE agent_id=%s AND event_id=3
          AND collected_at >= now() - make_interval(mins => %s)
        ORDER BY id DESC LIMIT 5000
    """, (agent_id, NI_SCAN_WINDOW_MIN))
    agg = defaultdict(lambda: {"ports": set(), "dsts": set(), "last_id": None})
    for r in cur.fetchall():
        port = _dport(r["full_log"])
        if port is None:
            continue
        key = r["src_proc_name"] or "?"
        a = agg[key]
        a["ports"].add(port)
        if r["dst_ip"]:
            a["dsts"].add(r["dst_ip"])
        a["last_id"] = a["last_id"] or r["id"]
    scored = sorted(((len(a["ports"]), proc, a) for proc, a in agg.items()),
                    key=lambda x: -x[0])
    for nports, proc, a in scored[:NI_MAX_PER_TYPE]:
        if nports < NI_SCAN_PORTS:
            break
        desc = (f"Port scan: {proc} hit {nports} distinct ports across "
                f"{len(a['dsts'])} host(s) in {NI_SCAN_WINDOW_MIN} min"
                if en else
                f"Portų skenavimas: {proc} kreipėsi į {nports} skirtingų portų "
                f"{len(a['dsts'])} host(uose) per {NI_SCAN_WINDOW_MIN} min")
        sigs.append({"type": ttype, "desc": desc,
                     "severity": sev, "alert_id": a["last_id"]})
    return sigs


# ── Public entry ────────────────────────────────────────────────────────────────

# Detector → response_playbooks.trigger_type. Behaviour (on/off, severity,
# cooldown) lives in the DB row — NOT here.
_DETECTORS = (
    ("OTX_BAD_DESTINATION", _detect_otx),
    ("NETWORK_C2_BEACON",   _detect_beaconing),
    ("DNS_EXFIL",           _detect_dns_tunneling),
    ("RARE_DESTINATION",    _detect_rare_destination),
    ("NETWORK_PORT_SCAN",   _detect_port_scan),
)

# trigger_types this module owns (for the correlator popup header)
NET_TRIGGER_TYPES = frozenset(t for t, _ in _DETECTORS)


def detect(conn, agent_id: str, agent_name: str = "", lang: str = "lt",
           playbooks: dict = None) -> list:
    """Run network-intel detections for one agent. Returns signal list.

    Each detection is driven by its response_playbooks row (passed in `playbooks`):
      • skipped if the row is missing or enabled=false   → UI on/off switch
      • signal severity  = row.min_severity              → UI-tunable
      • signal cooldown  = row.cooldown_minutes          → UI-tunable
    Fully defensive: any single detection failing must not break the cycle.
    """
    en = (lang == "en")
    playbooks = playbooks or {}
    out = []
    for ttype, fn in _DETECTORS:
        pb = playbooks.get(ttype)
        if not pb or not pb.get("enabled", True):
            continue  # DB controls whether this detection runs at all
        sev = int(pb.get("min_severity") or 10)
        cd  = pb.get("cooldown_minutes")
        try:
            with conn.cursor() as cur:
                sigs = fn(cur, agent_id, en, ttype, sev)
            for s in sigs:
                if cd is not None:
                    s["cooldown"] = cd
            out.extend(sigs)
        except Exception as e:
            log.warning("network_intel %s failed for %s: %s", ttype, agent_id, e)
    if out:
        log.info("network_intel %s: %s", agent_name or agent_id,
                 [s["type"] for s in out])
    return out
