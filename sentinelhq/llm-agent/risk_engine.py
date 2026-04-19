"""
SentinelHQ — Risk Engine
Hibridinis sprendimų modelis: taisyklės + AI

Principas:
  confidence > 80 → veiksmas be AI
  confidence 40-80 → AI patikrina
  confidence < 40 → stebėti

Vartotojo profilis mokomas iš Windows Event 4624/4625 logų.
"""

import logging
import os
from datetime import datetime, timezone

from prompts import _get_lang

log = logging.getLogger(__name__)

# Confidence slenkščiai
CONF_AUTO_ACT  = 80   # Veikia be AI
CONF_ASK_AI    = 40   # Klausia AI
# < 40 — tik stebėti

# Bootstrap: kiek loginų reikia kol agentas "išmokęs"
BOOTSTRAP_MIN_LOGONS = 20   # bent 20 loginų iš agento prieš auto_act

# Laiko anomalijos
NIGHT_HOURS    = set(range(0, 6))    # 00:00-05:59
WEEKEND_DAYS   = {5, 6}             # Šeštadienis, sekmadienis


# ── Vartotojo profilio mokymasis ─────────────────────────────────────────────

def learn_logon(conn, username: str, agent_id: str, agent_name: str,
                ip: str, logon_time: datetime, is_admin: bool = False,
                is_service: bool = False):
    """
    Mokosi iš sėkmingo prisijungimo (Event 4624).
    Atnaujina vartotojo profilį: tipinės valandos, dienos, IP.
    """
    if not username or username.lower() in {"", "-", "anonymous logon",
                                             "local service", "network service",
                                             "system", "dwm-1", "dwm-2"}:
        return

    hour = logon_time.hour
    day  = logon_time.weekday()  # 0=Pirm, 6=Sekm

    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO user_profiles
                    (username, agent_id, agent_name, typical_hours, typical_days,
                     typical_ips, logon_count, last_logon_ip, last_logon_time,
                     is_admin, is_service, updated_at)
                VALUES (%s, %s, %s, ARRAY[%s], ARRAY[%s], ARRAY[%s], 1,
                        %s, %s, %s, %s, NOW())
                ON CONFLICT (username, agent_id) DO UPDATE SET
                    typical_hours   = (
                        SELECT ARRAY(SELECT DISTINCT unnest(
                            user_profiles.typical_hours || ARRAY[%s]
                        ) ORDER BY 1)
                    ),
                    typical_days    = (
                        SELECT ARRAY(SELECT DISTINCT unnest(
                            user_profiles.typical_days || ARRAY[%s]
                        ) ORDER BY 1)
                    ),
                    typical_ips     = (
                        SELECT ARRAY(SELECT DISTINCT unnest(
                            user_profiles.typical_ips || ARRAY[%s]
                        ) LIMIT 20)
                    ),
                    logon_count     = user_profiles.logon_count + 1,
                    last_logon_ip   = %s,
                    last_logon_time = %s,
                    is_admin        = %s OR user_profiles.is_admin,
                    updated_at      = NOW()
            """, (
                username, agent_id, agent_name, hour, day, ip,
                ip, logon_time, is_admin, is_service,
                # ON CONFLICT update params
                hour, day, ip, ip, logon_time, is_admin,
            ))
        conn.commit()
    except Exception as e:
        log.debug("learn_logon error: %s", e)
        try:
            conn.rollback()
        except Exception:
            pass


def is_agent_bootstrapped(conn, agent_id: str) -> bool:
    """
    Tikrina ar agentas turi pakankamai loginų duomenų sprendimams.
    Grąžina False jei sistema dar mokosi.
    """
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT COALESCE(SUM(logon_count), 0) AS total
                FROM user_profiles WHERE agent_id = %s
            """, (agent_id,))
            row = cur.fetchone()
            total = row["total"] if row else 0
            return int(total) >= BOOTSTRAP_MIN_LOGONS
    except Exception:
        return False


def get_user_profile(conn, username: str, agent_id: str) -> dict | None:
    """Gauna vartotojo profilį iš DB."""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM user_profiles
                WHERE username=%s AND agent_id=%s
            """, (username, agent_id))
            row = cur.fetchone()
            return dict(row) if row else None
    except Exception:
        return None


# ── Confidence skaičiavimas ──────────────────────────────────────────────────

def calc_confidence(signal_type: str, severity: int, context: dict,
                    profile: dict | None, conn=None, agent_id: str = None) -> dict:
    """
    Skaičiuoja confidence score (0-100) pagal signalą ir kontekstą.

    context turi:
      username    — prisijungęs vartotojas
      src_ip      — šaltinio IP
      logon_time  — prisijungimo laikas (datetime)
      agent_name  — agento vardas

    Grąžina:
      confidence  — 0-100
      reasons     — kodėl toks score
      action      — "auto_act" | "ask_ai" | "monitor"
    """
    reasons = []
    base = min(severity * 6, 60)  # Max 60 iš severity
    _lang = _get_lang()

    now         = context.get("logon_time") or datetime.now(timezone.utc)
    hour        = now.hour
    day         = now.weekday()
    src_ip      = context.get("src_ip", "")
    username    = context.get("username", "")

    # ── Laiko anomalijos ─────────────────────────────────────────────────────
    if hour in NIGHT_HOURS:
        base = min(base * 1.5, 95)
        reasons.append(f"Night time ({hour:02d}:xx)" if _lang == "en" else f"Naktinis laikas ({hour:02d}:xx)")

    if day in WEEKEND_DAYS:
        base = min(base * 1.3, 95)
        reasons.append("Weekend" if _lang == "en" else "Savaitgalis")

    # ── Tarpagentinė koreliacija ─────────────────────────────────────────────
    if conn and src_ip:
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(DISTINCT agent_id) as cnt
                    FROM alerts
                    WHERE agent_ip != %s
                      AND full_log LIKE %s
                      AND collected_at >= NOW() - INTERVAL '60 minutes'
                """, (src_ip, f"%{src_ip}%"))
                row = cur.fetchone()
                attacked_agents = row["cnt"] if row else 0
            if attacked_agents > 1:
                base = min(base * 2.0, 95)
                reasons.append(
                    f"Coordinated attack — {attacked_agents} agents from {src_ip}" if _lang == "en"
                    else f"Koordinuota ataka — {attacked_agents} agentai iš {src_ip}"
                )
        except Exception:
            pass

    # ── Vartotojo profilio anomalijos ────────────────────────────────────────
    if profile:
        typical_hours = profile.get("typical_hours") or []
        typical_days  = profile.get("typical_days") or []
        typical_ips   = profile.get("typical_ips") or []
        logon_count   = profile.get("logon_count", 0)
        _days_en = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun']
        _days_lt = ['Pr','An','Tr','Kt','Pn','Št','Sk']

        if logon_count >= 10:  # Pakankamai duomenų
            if hour not in typical_hours:
                base = min(base * 2.0, 95)
                reasons.append(
                    f"Unusual time — {username} typically doesn't log in at {hour:02d}h" if _lang == "en"
                    else f"Neįprastas laikas — {username} paprastai nesilogina {hour:02d}h"
                )

            if day not in typical_days:
                base = min(base * 1.3, 95)
                _day_name = _days_en[day] if _lang == "en" else _days_lt[day]
                reasons.append(
                    f"Unusual day — {username} typically doesn't log in on {_day_name}" if _lang == "en"
                    else f"Neįprasta diena — {username} paprastai nesilogina {_day_name}"
                )

            if src_ip and typical_ips and src_ip not in typical_ips:
                base = min(base * 1.5, 95)
                reasons.append(
                    f"New IP {src_ip} — {username} usually connects from {', '.join(typical_ips[:2])}" if _lang == "en"
                    else f"Naujas IP {src_ip} — {username} paprastai jungiasi iš {', '.join(typical_ips[:2])}"
                )

        if profile.get("is_admin"):
            base = min(base * 1.2, 95)
            reasons.append(
                f"{username} has admin privileges" if _lang == "en"
                else f"{username} turi admin teises"
            )

        # Mažiname jei normalus elgesys
        if (hour in typical_hours and day in typical_days and
                src_ip in typical_ips and logon_count >= 10):
            base = max(base * 0.4, 5)
            reasons.append("Normal behavior based on profile" if _lang == "en" else "Normalus elgesys pagal profilį")
    else:
        # Nėra profilio — naujas vartotojas
        if username:
            base = min(base * 1.2, 95)
            reasons.append(
                f"Unknown user {username} — no profile" if _lang == "en"
                else f"Nežinomas vartotojas {username} — profilio nėra"
            )

    confidence = round(min(base, 100))

    if confidence >= CONF_AUTO_ACT:
        action = "auto_act"
    elif confidence >= CONF_ASK_AI:
        action = "ask_ai"
    else:
        action = "monitor"

    return {
        "confidence": confidence,
        "reasons":    reasons,
        "action":     action,
    }


# ── Pagrindinė funkcija koreliatoriui ────────────────────────────────────────

def evaluate_threat(conn, agent_id: str, agent_name: str,
                    signal_type: str, severity: int,
                    username: str = "", src_ip: str = "",
                    logon_time: datetime = None) -> dict:
    """
    Pagrindinis įėjimo taškas iš correlator.py.
    Grąžina: confidence, action, reasons, profile
    """
    logon_time = logon_time or datetime.now(timezone.utc)

    # Normalizuojame username: "DOMAIN\user" arba "MACHINE\user" → "user"
    # proc_user iš Sysmon ateina su mašinos prefiksu, bet profilis saugomas be jo
    _raw_username = username
    if username and "\\" in username:
        username = username.split("\\")[-1]
    elif username and "/" in username:
        username = username.split("/")[-1]

    profile = get_user_profile(conn, username, agent_id) if username else None
    # Jei su normalizuotu nerado — bandome su originaliu
    if profile is None and _raw_username != username:
        profile = get_user_profile(conn, _raw_username, agent_id)

    context = {
        "username":   username,
        "src_ip":     src_ip,
        "logon_time": logon_time,
        "agent_name": agent_name,
    }

    result = calc_confidence(
        signal_type, severity, context, profile,
        conn=conn, agent_id=agent_id
    )
    result["profile"] = profile

    # Bootstrap apsauga: jei sistema dar mokosi — nesileisti į auto_act
    bootstrapped = is_agent_bootstrapped(conn, agent_id)
    result["bootstrapped"] = bootstrapped
    if not bootstrapped and result["action"] == "auto_act":
        result["action"] = "ask_ai"
        result["reasons"].append(
            f"Bootstrap fazė — dar mokomasi (reikia {BOOTSTRAP_MIN_LOGONS}+ loginų)"
        )

    log.info(
        "RiskEngine | agent=%s signal=%s user=%s ip=%s conf=%d action=%s bootstrap=%s",
        agent_name, signal_type, username or "?", src_ip or "?",
        result["confidence"], result["action"], bootstrapped
    )

    return result


# ── Vartotojo profilio mokymasis iš alertų ──────────────────────────────────

# SQL-based agregacija: iš JSON full_log ištraukiame laukus tiesiai DB lygyje.
# Tai ~100x greičiau nei Python ciklas dideliems duomenų kiekiams.
_LEARN_SQL = """
WITH parsed AS (
    SELECT
        agent_id,
        agent_name,
        LOWER(
            COALESCE(
                full_log::json->'win'->'eventdata'->>'targetUserName',
                full_log::json->'win'->'eventdata'->>'subjectUserName',
                ''
            )
        ) AS username,
        COALESCE(
            full_log::json->'win'->'eventdata'->>'ipAddress',
            full_log::json->'win'->'eventdata'->>'workstationName',
            agent_ip,
            ''
        ) AS src_ip,
        EXTRACT(HOUR FROM COALESCE(alert_ts, collected_at)) AS hour,
        EXTRACT(DOW  FROM COALESCE(alert_ts, collected_at)) AS dow,
        COALESCE(alert_ts, collected_at) AS logon_ts,
        (full_log ILIKE '%%administrators%%'
         OR full_log ILIKE '%%domain admins%%'
         OR full_log ILIKE '%%enterprise admins%%') AS is_admin
    FROM alerts
    WHERE agent_id = %s
      AND rule_id = ANY(%s)
      AND collected_at >= %s
      AND full_log IS NOT NULL
      AND full_log != ''
),
filtered AS (
    SELECT *
    FROM parsed
    WHERE username NOT IN (
        '', '-', 'anonymous logon', 'local service', 'network service',
        'system', 'dwm-1', 'dwm-2', 'umfd-0', 'umfd-1'
    )
)
INSERT INTO user_profiles
    (username, agent_id, agent_name, typical_hours, typical_days,
     typical_ips, logon_count, last_logon_ip, last_logon_time,
     is_admin, is_service, updated_at)
SELECT
    username,
    agent_id,
    MAX(agent_name),
    ARRAY(SELECT DISTINCT unnest(array_agg(hour::int))),
    ARRAY(SELECT DISTINCT unnest(array_agg(dow::int))),
    ARRAY(SELECT DISTINCT unnest(array_agg(src_ip)) LIMIT 20),
    COUNT(*),
    (array_agg(src_ip  ORDER BY logon_ts DESC))[1],
    MAX(logon_ts),
    BOOL_OR(is_admin),
    FALSE,
    NOW()
FROM filtered
GROUP BY username, agent_id
ON CONFLICT (username, agent_id) DO UPDATE SET
    typical_hours   = (
        SELECT ARRAY(SELECT DISTINCT unnest(
            user_profiles.typical_hours || EXCLUDED.typical_hours
        ) ORDER BY 1)
    ),
    typical_days    = (
        SELECT ARRAY(SELECT DISTINCT unnest(
            user_profiles.typical_days || EXCLUDED.typical_days
        ) ORDER BY 1)
    ),
    typical_ips     = (
        SELECT ARRAY(SELECT DISTINCT unnest(
            user_profiles.typical_ips || EXCLUDED.typical_ips
        ) LIMIT 20)
    ),
    logon_count     = user_profiles.logon_count + EXCLUDED.logon_count,
    last_logon_ip   = EXCLUDED.last_logon_ip,
    last_logon_time = GREATEST(user_profiles.last_logon_time, EXCLUDED.last_logon_time),
    is_admin        = user_profiles.is_admin OR EXCLUDED.is_admin,
    updated_at      = NOW()
"""

_LOGON_RULES = ['60103', '60106', '60109', '92652', '92657']


def learn_from_alerts(conn, agent_id: str, agent_name: str, alerts: list):
    """
    Mokosi iš alertų sąrašo — kviečiamas kas ciklą su naujais alertais.
    Naudojamas inkrementiniam mokymui (nauji loginai per paskutinę valandą).
    """
    if not alerts:
        return
    # Imame tik naujausią alert timestamp kaip ribą
    since = min(
        (a.get("collected_at") or a.get("alert_ts") for a in alerts),
        default=None
    )
    if since is None:
        return
    if hasattr(since, 'isoformat'):
        since_dt = since
    else:
        try:
            since_dt = datetime.fromisoformat(str(since).replace("Z", "+00:00"))
        except Exception:
            return

    _learn_sql_batch(conn, agent_id, agent_name, since_dt)


def _learn_sql_batch(conn, agent_id: str, agent_name: str, since):
    """Vykdo SQL agregaciją tiesiai DB — greitai veikia net su tūkstančiais eilučių."""
    try:
        with conn.cursor() as cur:
            cur.execute(_LEARN_SQL, (agent_id, _LOGON_RULES, since))
        conn.commit()
        log.debug("learn_sql_batch: agent=%s since=%s", agent_name, since)
    except Exception as e:
        log.warning("learn_sql_batch error agent=%s: %s", agent_name, e)
        try:
            conn.rollback()
        except Exception:
            pass


def bootstrap_from_db(conn, agent_id: str, agent_name: str, days: int = 7) -> int:
    """
    Greitas bootstrap iš DB istorijos — vienas SQL per visą laikotarpį.
    Grąžina kiek vartotojų profilių sukurta/atnaujinta.
    """
    since = datetime.now(timezone.utc) - __import__('datetime').timedelta(days=days)
    try:
        with conn.cursor() as cur:
            cur.execute(_LEARN_SQL, (agent_id, _LOGON_RULES, since))
            count = cur.rowcount
        conn.commit()
        return max(count, 0)
    except Exception as e:
        log.warning("bootstrap_from_db error agent=%s: %s", agent_name, e)
        try:
            conn.rollback()
        except Exception:
            pass
        return 0
