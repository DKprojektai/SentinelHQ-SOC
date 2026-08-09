"""
SentinelHQ — LLM Agent
Per-alert analysis for rule_level >= 9 with adaptive suppression learning.
Correlation-level LLM analysis is handled by correlator.py.
"""

import os
import json
import time
import logging
import requests
from datetime import datetime, timezone, timedelta
from typing import Optional

import schedule

from db import get_db
from prompts import get_stage1_prompt, get_stage2_prompt, _get_lang
import llm_client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [llm-agent] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_SECONDS", 30))

# Max alerts sent to LLM per poll cycle (cost control)
LLM_BATCH_PER_CYCLE = int(os.environ.get("LLM_BATCH_PER_CYCLE", 5))

# After this many LLM false_positive verdicts for (agent, rule) → stop sending to LLM
LLM_FP_SUPPRESS_THRESHOLD = int(os.environ.get("LLM_FP_SUPPRESS_THRESHOLD", 3))

# Min rule_level to trigger real LLM analysis
LLM_MIN_LEVEL = 9


def fetch_raw_log(wazuh_id: str) -> str:
    """Fetch full log from OpenSearch by wazuh_id using _search."""
    import urllib3
    urllib3.disable_warnings()
    url  = os.environ.get("OPENSEARCH_URL", "https://wazuh.indexer:9200")
    user = os.environ.get("OPENSEARCH_USER", "admin")
    pwd  = os.environ.get("OPENSEARCH_PASS", "SecretPassword")
    try:
        r = requests.post(
            f"{url}/wazuh-alerts-*/_search",
            auth=(user, pwd), verify=False, timeout=10,
            json={"query": {"ids": {"values": [wazuh_id]}}, "size": 1}
        )
        if r.ok:
            hits = r.json().get("hits", {}).get("hits", [])
            if hits:
                src = hits[0].get("_source", {})
                msg = src.get("message") or ""
                if not msg:
                    evd = src.get("data", {}).get("win", {}).get("eventdata", {})
                    parts = []
                    for k in ["image","parentImage","commandLine","targetObject","queryName"]:
                        if evd.get(k): parts.append(f"{k}: {evd[k]}")
                    msg = " | ".join(parts)
                msg = msg.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
                return msg[:500]
    except Exception as e:
        log.debug("fetch_raw_log error: %s", e)
    return ""

VALID_VERDICTS = {"true_positive", "false_positive", "uncertain"}

def normalize_verdict(v: str) -> str:
    v = (v or "").lower().strip()
    if v in VALID_VERDICTS:
        return v
    if v in ("true", "tp", "positive"):
        return "true_positive"
    if v in ("false", "fp", "noise", "suppress"):
        return "false_positive"
    return "uncertain"


def parse_verdict(text: str) -> dict:
    text = text.strip()
    try:
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()
        return json.loads(text)
    except Exception:
        lower = text.lower()
        if "true_positive" in lower or "tikras" in lower:
            verdict = "true_positive"
        elif "false_positive" in lower or "triukšmas" in lower:
            verdict = "false_positive"
        else:
            verdict = "uncertain"
        return {"verdict": verdict, "confidence": 50, "reasoning": text[:300], "action": "review"}


def get_agent_memory(conn, agent_id: str) -> str:
    with conn.cursor() as cur:
        cur.execute("""
            SELECT summary, event_type, recorded_at FROM agent_memory
            WHERE agent_id=%s AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY recorded_at DESC LIMIT 10
        """, (agent_id,))
        rows = cur.fetchall()
    if not rows:
        return "No past events." if _get_lang() == "en" else "Nėra praeities įvykių."
    return "\n".join(
        f"[{r['recorded_at'].strftime('%Y-%m-%d %H:%M') if r['recorded_at'] else '?'}] "
        f"{r['event_type']}: {r['summary']}"
        for r in rows
    )


def save_memory(conn, agent_id: str, agent_name: str, event_type: str, summary: str):
    expires = datetime.now(timezone.utc) + timedelta(days=30)
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO agent_memory(agent_id, agent_name, event_type, summary, expires_at)
            VALUES(%s,%s,%s,%s,%s)
        """, (agent_id, agent_name, event_type, summary, expires))


def get_config(conn) -> Optional[dict]:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM llm_config WHERE id=1")
        return cur.fetchone()


# ── Content quality pre-filter ───────────────────────────────────────────────

# PowerShell/cmd keywords that indicate ACTUAL commands worth analyzing.
# If none of these appear in cmd_line or full_log, the alert is content-free.
_MEANINGFUL_PS_KW = [
    "-enc", "-encodedcommand", "-command", "-exec", "-nop", "-noni",
    "iex", "invoke-expression", "invoke-webrequest", "downloadstring",
    "downloadfile", "bypass", "hidden", "windowstyle", "webclient",
    "net.webclient", "start-process", "invoke-mimikatz", "credential",
    "sekurlsa", "lsass", "dump", "registry", "schtask", "scheduled",
    "http://", "https://", ":\\users\\", ":\\temp\\", ":\\appdata\\",
    "\\programdata\\", "base64", "frombase64", "compress", "decompress",
    "new-object", "add-type", "reflective", "shellcode", "meterpreter",
]

def _has_no_forensic_value(alert: dict) -> bool:
    """Return True when the alert carries no actionable forensic data.

    Typical pattern: powershell.exe spawned powershell.exe with no arguments.
    Sending such alerts to the LLM wastes tokens and produces meaningless verdicts.

    The adaptive FP suppressor (llm_alert_suppressions) handles rule+agent combos
    that are repeatedly FP — this filter catches the structural content problem:
    the *data itself* has zero investigative value regardless of rule or agent.
    """
    cmd = (alert.get("cmd_line")   or "").strip()
    log = (alert.get("full_log")   or "").strip()
    img = (alert.get("image_path") or "").strip()

    # 1. Absolutely empty — nothing to analyze
    if not cmd and not log:
        return True

    # 2. Command line is just the executable itself with no arguments
    #    e.g. cmd_line = "powershell.exe"  or  "C:\...\powershell.exe"
    if cmd and img:
        img_name = img.rsplit("\\", 1)[-1].lower().strip('"')
        cmd_first_token = cmd.strip('"').strip("'").split()[0].rsplit("\\", 1)[-1].lower()
        if cmd_first_token == img_name:
            # e.g. powershell.exe launched "powershell.exe" — no arguments
            remaining = cmd.strip('"').strip("'")[len(cmd.strip('"').strip("'").split()[0]):].strip()
            if not remaining:
                return True

    # 3. No meaningful PS/shell keywords in either cmd or log — content-free
    combined = (cmd + " " + log).lower()
    if not any(kw in combined for kw in _MEANINGFUL_PS_KW):
        # Only skip if the text is also short (not a long structured log)
        if len(combined) < 200:
            return True

    return False


# ── LLM Suppression Learning ─────────────────────────────────────────────────

def _is_llm_suppressed(conn, agent_id: str, rule_id: str, image_path: str = "") -> bool:
    """Return True if this agent+rule+image combo was repeatedly marked FP."""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT fp_count FROM llm_alert_suppressions
                WHERE agent_id=%s AND rule_id=%s AND image_path=%s
            """, (agent_id, str(rule_id), image_path or ""))
            row = cur.fetchone()
        return bool(row and row["fp_count"] >= LLM_FP_SUPPRESS_THRESHOLD)
    except Exception as e:
        log.debug("_is_llm_suppressed error: %s", e)
        return False


def _record_llm_fp(conn, agent_id: str, rule_id: str, image_path: str = ""):
    """Increment FP counter for this agent+rule+image. After threshold → LLM skipped."""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO llm_alert_suppressions(agent_id, rule_id, image_path, fp_count, last_fp_at, updated_at)
                VALUES (%s, %s, %s, 1, NOW(), NOW())
                ON CONFLICT (agent_id, rule_id, image_path) DO UPDATE SET
                    fp_count   = llm_alert_suppressions.fp_count + 1,
                    last_fp_at = NOW(),
                    updated_at = NOW()
            """, (agent_id, str(rule_id), image_path or ""))
        log.info("LLM FP recorded agent=%s rule=%s image=%s", agent_id, rule_id, image_path)
    except Exception as e:
        log.error("_record_llm_fp error: %s", e)


def _reset_llm_suppression(conn, agent_id: str, rule_id: str, image_path: str = ""):
    """When LLM confirms true_positive, reset the FP counter — rule is real after all."""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE llm_alert_suppressions
                SET fp_count = GREATEST(0, fp_count - 1), updated_at = NOW()
                WHERE agent_id=%s AND rule_id=%s AND image_path=%s
            """, (agent_id, str(rule_id), image_path or ""))
    except Exception as e:
        log.debug("_reset_llm_suppression error: %s", e)


# ── Telegram (per-alert) ──────────────────────────────────────────────────────

def _send_alert_telegram(conn, alert: dict, v2: dict, analysis_id: int,
                          auto_isolated: bool = False):
    """Send Telegram notification for a LLM-confirmed true_positive alert.
    Deduplicates: same rule_id+agent_id not sent within 60 minutes."""
    DEDUP_MINUTES = 60
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id   = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not bot_token or not chat_id:
        return

    agent_id = alert.get("agent_id", "")
    rule_id  = str(alert.get("rule_id", ""))

    # Dedup check
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT COUNT(*) AS cnt FROM telegram_messages tm
                JOIN alerts a ON a.id = tm.alert_id
                WHERE a.rule_id  = %s
                  AND a.agent_id = %s
                  AND tm.sent_at >= NOW() - (%s * INTERVAL '1 minute')
                  AND tm.status  = 'sent'
            """, (rule_id, agent_id, DEDUP_MINUTES))
            if cur.fetchone()["cnt"] > 0:
                log.info("DEDUP: alert rule %s agent %s already notified — skip", rule_id, agent_id)
                return
    except Exception as e:
        log.warning("Dedup check error: %s", e)

    # NOTE: do NOT send to Telegram directly here. The bot (telegram-bot/
    # send_pending_alerts) is the SINGLE Telegram gateway and renders the
    # detailed alert message (process tree, parent, cmd, VirusTotal link).
    # We only QUEUE the alert here. Sending here too caused DUPLICATE messages
    # (user received both "CONFIRMED INCIDENT" + "SentinelHQ Alert").
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO telegram_messages(alert_id, analysis_id, chat_id, status)
                VALUES(%s,%s,%s,'sent')
            """, (alert["id"], analysis_id, chat_id))
        log.info("Queued alert for Telegram: alert=%d rule=%s agent=%s",
                 alert["id"], rule_id, agent_id)
    except Exception as e:
        log.warning("Queue alert error alert=%d: %s", alert["id"], e)


# ── Core analysis ─────────────────────────────────────────────────────────────

def analyze_alert(conn, alert: dict, config: dict):
    """Full 2-stage LLM analysis for a single alert.
    Returns final verdict dict or None on error."""
    model  = llm_client.LLM_MODEL
    memory = get_agent_memory(conn, alert["agent_id"])

    full_log = alert.get('full_log') or fetch_raw_log(alert.get('wazuh_id',''))

    # ── Threat intel context (geo + OTX) ─────────────────────────────────────
    _intel_ip = alert.get("dst_ip") or alert.get("src_ip") or ""
    threat_ctx = ""
    if alert.get("otx_malicious"):
        pulses = alert.get("otx_pulses") or 0
        _ip_lbl = f" ({_intel_ip})" if _intel_ip else ""
        threat_ctx = f"⚠️ THREAT INTEL: IP{_ip_lbl} has {pulses} OTX pulse(s) — KNOWN MALICIOUS.\n"
    if alert.get("geo_country") or alert.get("geo_asn"):
        geo_parts = []
        if alert.get("geo_country"): geo_parts.append(f"Country: {alert['geo_country']}")
        if alert.get("geo_asn"):     geo_parts.append(f"ASN: {alert['geo_asn']}")
        threat_ctx += f"GeoIP ({_intel_ip or alert.get('dst_proc_name','')}): {', '.join(geo_parts)}\n"

    # ── Stage 1: quick filter ─────────────────────────────────────────────────
    user_s1 = (
        f"Rule ID: {alert['rule_id']}\n"
        f"Rule level: {alert['rule_level']}\n"
        f"Rule description: {alert['rule_desc']}\n"
        f"Agent: {alert['agent_name']} ({alert.get('agent_ip','')})\n"
        f"Location: {alert['location']}\n"
        f"{threat_ctx}"
        f"Log: {full_log[:300]}\n"
        f"Agent history: {memory[:500]}"
    )
    try:
        text_s1, tokens_s1 = llm_client.call(get_stage1_prompt(), user_s1,
                                               model=model, max_tokens=300)
        v1 = parse_verdict(text_s1)
    except Exception as e:
        log.error("Stage 1 error alert %s: %s", alert["id"], e)
        return None

    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO llm_analyses
            (alert_id, model, verdict, confidence, reasoning,
             recommended_action, stage, tokens_used)
            VALUES(%s,%s,%s,%s,%s,%s,1,%s) RETURNING id
        """, (
            alert["id"], model,
            normalize_verdict(v1.get("verdict")), v1.get("confidence", 50),
            v1.get("reasoning", ""), v1.get("action", "review"), tokens_s1,
        ))
        analysis_id = cur.fetchone()["id"]

    log.info("Alert %d Lv%s | S1: %s (%d%%)",
             alert["id"], alert.get("rule_level","?"),
             v1.get("verdict"), v1.get("confidence", 0))

    # Confident FP at stage 1 → record, learn, no stage 2
    if normalize_verdict(v1.get("verdict")) == "false_positive" and v1.get("confidence", 0) >= 80:
        _record_llm_fp(conn, alert["agent_id"], str(alert["rule_id"]), alert.get("image_path") or "")
        save_memory(conn, alert["agent_id"], alert["agent_name"],
                    "false_positive",
                    f"Rule {alert['rule_id']}: {alert['rule_desc'][:60]}")
        return {"verdict": "false_positive"}

    # ── Stage 2: deep analysis ────────────────────────────────────────────────
    user_s2 = (
        f"Rule ID: {alert['rule_id']}\n"
        f"Rule level: {alert['rule_level']}\n"
        f"Rule description: {alert['rule_desc']}\n"
        f"Agent: {alert['agent_name']} (IP: {alert.get('agent_ip','')})\n"
        f"Location: {alert['location']}\n"
        f"{threat_ctx}"
        f"Full log: {full_log[:800] or '(nėra)'}\n"
        f"Image path: {alert.get('image_path','')}\n"
        f"Command line: {alert.get('cmd_line','')}\n"
        f"Process user: {alert.get('proc_user','')}\n"
        f"MITRE: {alert.get('mitre_id','')} / {alert.get('mitre_tactic','')}\n"
        f"Agent history:\n{memory}\n\n"
        f"Stage 1: {v1.get('verdict')} ({v1.get('confidence')}%) — {v1.get('reasoning','')}"
    )
    try:
        text_s2, tokens_s2 = llm_client.call(get_stage2_prompt(), user_s2,
                                               model=model, max_tokens=800)
        v2 = parse_verdict(text_s2)
    except Exception as e:
        log.error("Stage 2 error alert %s: %s", alert["id"], e)
        return None

    final_verdict = normalize_verdict(v2.get("verdict"))

    with conn.cursor() as cur:
        cur.execute("""
            UPDATE llm_analyses
            SET verdict=%s, confidence=%s, reasoning=%s,
                recommended_action=%s, suggested_xml=%s,
                stage=2, tokens_used=tokens_used+%s
            WHERE id=%s
        """, (
            final_verdict, v2.get("confidence", 50),
            v2.get("reasoning", ""), v2.get("action", "review"),
            v2.get("suppress_xml"), tokens_s2, analysis_id,
        ))

    log.info("Alert %d Lv%s | S2: %s (%d%%)",
             alert["id"], alert.get("rule_level","?"),
             final_verdict, v2.get("confidence", 0))

    save_memory(conn, alert["agent_id"], alert["agent_name"],
                final_verdict,
                f"Rule {alert['rule_id']} lvl{alert['rule_level']}: "
                f"{(v2.get('reasoning') or '')[:100]}")

    # ── Learning: update suppression counters ─────────────────────────────────
    _img = alert.get("image_path") or ""
    if final_verdict == "false_positive":
        _record_llm_fp(conn, alert["agent_id"], str(alert["rule_id"]), _img)
    elif final_verdict == "true_positive":
        # Confirmed real — slightly reduce FP counter (don't suppress too aggressively)
        _reset_llm_suppression(conn, alert["agent_id"], str(alert["rule_id"]), _img)

    # ── Actions for confirmed true_positive ───────────────────────────────────
    if final_verdict == "true_positive":
        action       = v2.get("action", "review")
        auto_isolated = False

        # Izoliacija vykdoma TIK per correlator.py (pagal playbook auto_isolate nustatymą).
        # agent.py niekada neizoliuoja pats — tik rekomenduoja Telegram pranešime.

        # Send Telegram notification
        _send_alert_telegram(conn, alert, v2, analysis_id, auto_isolated=auto_isolated)

    return {"verdict": final_verdict, "action": v2.get("action")}


# ── Poll loop ─────────────────────────────────────────────────────────────────

def poll():
    with get_db() as conn:
        config = get_config(conn)
        if not config or not config["enabled"]:
            return
        if config["vacation_mode"] and config["vacation_until"]:
            if datetime.now(timezone.utc) < config["vacation_until"]:
                return

        # Fetch all alerts that have no llm_analyses entry yet.
        # Normal window keeps recent noise from piling up, but CRITICAL alerts
        # (Lv>=12) must NOT be silently dropped if the LLM agent was down >window
        # — they stay eligible for a much longer backlog window so downtime does
        # not become a missed-incident gap.
        backlog_h  = int(os.environ.get("LLM_BACKLOG_HOURS", 4))
        critical_h = int(os.environ.get("LLM_CRITICAL_BACKLOG_HOURS", 48))
        with conn.cursor() as cur:
            cur.execute("""
                SELECT a.* FROM alerts a
                LEFT JOIN llm_analyses la ON la.alert_id = a.id
                WHERE la.id IS NULL
                  AND a.rule_level >= %s
                  AND (
                        a.collected_at >= NOW() - (%s * INTERVAL '1 hour')
                     OR (a.rule_level >= 12 AND a.collected_at >= NOW() - (%s * INTERVAL '1 hour'))
                  )
                ORDER BY a.rule_level DESC, a.collected_at ASC
                LIMIT %s
            """, (config["min_level"], backlog_h, critical_h, config["batch_size"]))
            alerts = cur.fetchall()

        if not alerts:
            return

        llm_budget = LLM_BATCH_PER_CYCLE  # max real LLM calls per cycle

        for alert in alerts:
            try:
                level = alert["rule_level"] or 0

                # ── Real LLM path: Lv9+ ──────────────────────────────────────
                if level >= LLM_MIN_LEVEL and llm_budget > 0:
                    agent_id = alert["agent_id"]
                    rule_id  = str(alert["rule_id"] or "")

                    # ── Content quality gate (before any LLM call) ────────────
                    # If the alert has no forensic data (empty cmd, process=parent,
                    # no meaningful keywords) → instant FP. No tokens spent.
                    # Also feeds the adaptive suppressor so repeated empty alerts
                    # from the same rule+agent accumulate FP count and get skipped
                    # even faster next time.
                    if _has_no_forensic_value(alert):
                        _insert_rule_based(conn, alert["id"], level,
                                           verdict="false_positive", confidence=85,
                                           reason="Content-free alert: no forensic data to analyze")
                        _record_llm_fp(conn, agent_id, rule_id, alert.get("image_path") or "")
                        log.debug("Content-free skip: alert=%d rule=%s agent=%s",
                                  alert["id"], rule_id, alert.get("agent_name","?"))
                        continue

                    # ── Adaptive LLM suppression ──────────────────────────────
                    suppressed = _is_llm_suppressed(conn, agent_id, rule_id, alert.get("image_path") or "")
                    if suppressed:
                        # LLM has repeatedly rejected this combo — treat as FP
                        _insert_rule_based(conn, alert["id"], level,
                                           verdict="false_positive", confidence=80,
                                           reason="LLM suppressed (repeated FP)")
                        log.debug("LLM suppressed: rule=%s agent=%s (fp_count>=%d)",
                                  rule_id, agent_id, LLM_FP_SUPPRESS_THRESHOLD)
                        continue

                    log.info("LLM analyze: alert=%d Lv%d rule=%s agent=%s",
                             alert["id"], level, rule_id, alert.get("agent_name","?"))
                    try:
                        analyze_alert(conn, alert, config)
                        llm_budget -= 1
                    except Exception as e:
                        log.error("analyze_alert error alert=%d: %s", alert["id"], e)
                        # Fallback to rule-based so we don't retry endlessly
                        _insert_rule_based(conn, alert["id"], level)

                # ── Rule-based path: <Lv9 or budget exhausted ────────────────
                else:
                    _insert_rule_based(conn, alert["id"], level)

            except Exception as e:
                log.debug("poll loop error alert=%s: %s", alert.get("id"), e)


def _insert_rule_based(conn, alert_id: int, level: int,
                        verdict: str = None, confidence: int = None,
                        reason: str = None):
    """Insert a rule-based (non-LLM) analysis entry."""
    _lang = _get_lang()
    if verdict is None:
        if level >= 12:
            verdict    = "true_positive"
            confidence = 90
            reason     = (f"Lv{level} — automatiškai true_positive"
                          if _lang == "lt" else f"Lv{level} — automatically true_positive")
        elif level >= 9:
            verdict    = "uncertain"
            confidence = 60
            reason     = (f"Lv{level} — reikia koreliacijos konteksto"
                          if _lang == "lt" else f"Lv{level} — needs correlation context")
        else:
            verdict    = "false_positive"
            confidence = 85
            reason     = (f"Lv{level} — žemas lygis, tikriausiai triukšmas"
                          if _lang == "lt" else f"Lv{level} — low level, likely noise")

    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO llm_analyses
                (alert_id, model, verdict, confidence, reasoning,
                 recommended_action, stage, tokens_used)
                VALUES(%s,'rule-based',%s,%s,%s,'review',0,0)
            """, (alert_id, verdict, confidence, reason))
    except Exception as e:
        log.debug("_insert_rule_based error %s: %s", alert_id, e)


def run_correlator():
    try:
        from correlator import correlate
        correlate()
    except Exception as e:
        log.error("Correlator error: %s", e)


if __name__ == "__main__":
    log.info("SentinelHQ LLM Agent starting")
    log.info("API: %s | Model: %s | Poll: %ds | LLM min level: %d | FP suppress after: %d",
             llm_client.LLM_API_URL, llm_client.LLM_MODEL, POLL_INTERVAL,
             LLM_MIN_LEVEL, LLM_FP_SUPPRESS_THRESHOLD)

    time.sleep(10)
    poll()

    # Bootstrap: learn from 7-day history first
    try:
        from correlator import bootstrap_learning
        bootstrap_learning()
    except Exception as e:
        log.error("Bootstrap klaida: %s", e)

    run_correlator()

    schedule.every(POLL_INTERVAL).seconds.do(poll)
    schedule.every(int(os.environ.get("CORRELATE_INTERVAL_SECONDS", 30))).seconds.do(run_correlator)

    while True:
        schedule.run_pending()
        time.sleep(5)
