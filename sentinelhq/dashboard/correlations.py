"""
SentinelHQ — Correlations Blueprint
"""

import json
import logging
from functools import wraps

log = logging.getLogger(__name__)
from flask import Blueprint, jsonify, request, session
from db import get_db

correlations_bp = Blueprint("correlations", __name__)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


@correlations_bp.route("/api/correlations")
@login_required
def api_correlations():
    status = request.args.get("status", "open")
    allowed = ["open", "investigating", "resolved", "false_positive", "all"]
    if status not in allowed:
        status = "open"
    # all = no filter

    with get_db() as conn:
        with conn.cursor() as cur:
            if status == "all":
                cur.execute("""
                    SELECT * FROM correlations
                    ORDER BY detected_at DESC LIMIT 100
                """)
            else:
                cur.execute("""
                    SELECT * FROM correlations
                    WHERE status=%s
                    ORDER BY detected_at DESC LIMIT 100
                """, (status,))
            rows = cur.fetchall()

    return jsonify({"items": [dict(r) for r in rows]})


@correlations_bp.route("/api/correlations/<int:cid>/status", methods=["POST"])
@login_required
def api_correlation_status(cid):
    body   = request.get_json() or {}
    status = body.get("status", "")
    allowed = ["open", "investigating", "resolved", "false_positive"]
    if status not in allowed:
        return jsonify({"error": "invalid status"}), 400

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE correlations SET status=%s,
                resolved_at=CASE WHEN %s IN ('resolved','false_positive') THEN NOW() ELSE NULL END
                WHERE id=%s
            """, (status, status, cid))
            cur.execute("""
                INSERT INTO audit_log(actor, action, target_type, target_id)
                VALUES(%s, %s, 'correlation', %s)
            """, (session.get("username"), f"corr_{status}", str(cid)))

        # ── False positive feedback loop ────────────────────────────────────
        # Kai pažymima false_positive — išmokstame: sumažiname tų rule_id
        # taškų koeficientą šiam agentui, kad ateityje score augtu lėčiau.
        if status == "false_positive":
            try:
                with conn.cursor() as cur:
                    # Gauname agent_id ir alert_ids iš šios koreliacijos
                    cur.execute(
                        "SELECT agent_id, alert_ids FROM correlations WHERE id=%s", (cid,)
                    )
                    corr = cur.fetchone()

                if corr and corr["alert_ids"]:
                    agent_id  = corr["agent_id"]
                    alert_ids = corr["alert_ids"]

                    # Randame unikalius rule_id iš tų alertų (tik Lv7+ — jie turi įtakos)
                    with conn.cursor() as cur:
                        cur.execute("""
                            SELECT DISTINCT rule_id FROM alerts
                            WHERE id = ANY(%s) AND rule_level >= 7
                        """, (alert_ids,))
                        rules = [r["rule_id"] for r in cur.fetchall()]

                    # Upsert į risk_suppressions:
                    # Kiekvienas false_positive pažymėjimas mažina multiplier × 0.5
                    # (0→1.0→0.5→0.25→0.1 minimum)
                    with conn.cursor() as cur:
                        for rule_id in rules:
                            cur.execute("""
                                INSERT INTO risk_suppressions
                                    (agent_id, rule_id, multiplier, fp_count, reason, updated_at)
                                VALUES (%s, %s, 0.5, 1, %s, NOW())
                                ON CONFLICT (agent_id, rule_id) DO UPDATE SET
                                    multiplier = GREATEST(0.1,
                                        risk_suppressions.multiplier * 0.5),
                                    fp_count   = risk_suppressions.fp_count + 1,
                                    reason     = EXCLUDED.reason,
                                    updated_at = NOW()
                            """, (agent_id, rule_id,
                                  f"false_positive pažymėta vartotojo {session.get('username','')}"))

                    log.info("FP feedback: agent=%s rules=%s multiplieriai sumažinti",
                             agent_id, rules)

                    # FP → score_ema koregavimas žemyn:
                    # Sistema "supranta" kad šio agento normalus lygis yra mažesnis
                    # nei paskutinė koreliacija parodė. EMA × 0.7 = greitas koregavimas.
                    with conn.cursor() as cur:
                        cur.execute("""
                            UPDATE agent_baseline
                            SET score_ema = GREATEST(0, score_ema * 0.7),
                                updated_at = NOW()
                            WHERE agent_id = %s
                        """, (agent_id,))
                    log.info("FP feedback: agent=%s score_ema sumažinta ×0.7", agent_id)

                    # Signal cooldown 7 dienoms pagal trigger_type
                    with conn.cursor() as cur:
                        cur.execute("SELECT trigger_type FROM correlations WHERE id=%s", (cid,))
                        crow = cur.fetchone()
                    if crow and crow["trigger_type"]:
                        with conn.cursor() as cur:
                            cur.execute("""
                                INSERT INTO signal_cooldowns(agent_id, signal_type, last_fired)
                                VALUES (%s, %s, NOW() + INTERVAL '7 days')
                                ON CONFLICT (agent_id, signal_type) DO UPDATE
                                  SET last_fired = NOW() + INTERVAL '7 days'
                            """, (agent_id, crow["trigger_type"].upper()))
            except Exception as e:
                log.error("FP feedback error: %s", e)

    return jsonify({"ok": True})


@correlations_bp.route("/api/correlations/<int:cid>/detail")
@login_required
def api_correlation_detail(cid):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM correlations WHERE id=%s", (cid,))
            corr = cur.fetchone()
            if not corr:
                return jsonify({"error": "not found"}), 404
            alert_ids = corr["alert_ids"] or []
            alerts = []
            if alert_ids:
                # Noisy rule IDs that should not clutter correlation view
                EXCLUDE_RULES = {"61643", "510", "900070"}
                MAX_PER_RULE  = 20
                cur.execute("""
                    SELECT a.id, a.wazuh_id, a.rule_id, a.rule_level, a.rule_desc,
                           a.agent_id, a.agent_name, a.src_proc_name, a.dst_proc_name,
                           a.alert_ts, a.full_log, a.mitre_id, a.event_id, a.location,
                           a.image_path, a.parent_image_path, a.proc_sha256, a.cmd_line,
                           a.proc_user, a.mitre_tactic,
                           -- parent SHA256: look for another alert where this alert's
                           -- parent_image_path matches another alert's image_path
                           (SELECT p.proc_sha256
                            FROM alerts p
                            WHERE p.agent_id = a.agent_id
                              AND p.image_path IS NOT NULL
                              AND a.parent_image_path IS NOT NULL
                              AND lower(p.image_path) = lower(a.parent_image_path)
                              AND p.proc_sha256 IS NOT NULL
                              AND p.alert_ts BETWEEN a.alert_ts - INTERVAL '30 minutes'
                                                 AND a.alert_ts + INTERVAL '5 minutes'
                            ORDER BY p.alert_ts DESC
                            LIMIT 1
                           ) AS parent_sha256
                    FROM alerts a
                    WHERE a.id = ANY(%s)
                    ORDER BY a.rule_level DESC, a.alert_ts ASC
                """, (alert_ids,))
                rows = cur.fetchall()
                rule_counts: dict = {}
                for r in rows:
                    rid = str(r["rule_id"] or "")
                    if rid in EXCLUDE_RULES:
                        continue
                    if rule_counts.get(rid, 0) >= MAX_PER_RULE:
                        continue
                    rule_counts[rid] = rule_counts.get(rid, 0) + 1
                    alerts.append(dict(r))
                # Sort final list by alert_ts for display
                alerts.sort(key=lambda x: x["alert_ts"] or "")
    return jsonify({"correlation": dict(corr), "alerts": alerts})
