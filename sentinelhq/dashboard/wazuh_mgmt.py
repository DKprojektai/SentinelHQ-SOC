"""
SentinelHQ — Wazuh Management Blueprint
Approve → push to Wazuh, Reboot Manager + DB cleanup.
"""

import json
from functools import wraps
from flask import Blueprint, jsonify, request, session
from db import get_db
import wazuh_api

wazuh_mgmt_bp = Blueprint("wazuh_mgmt", __name__)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


@wazuh_mgmt_bp.route("/api/wazuh/pending-reboot")
@login_required
def api_wazuh_pending_reboot():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT COUNT(*) AS c FROM suppression_rules
                WHERE status='deployed'
            """)
            count = cur.fetchone()["c"]
    return jsonify({"pending": count})


@wazuh_mgmt_bp.route("/api/wazuh/reboot", methods=["POST"])
@login_required
def api_wazuh_reboot():
    ok, msg = wazuh_api.restart_manager()
    if not ok:
        return jsonify({"ok": False, "message": msg}), 500

    with get_db() as conn:
        with conn.cursor() as cur:
            # Delete suppressed alerts
            cur.execute("""
                DELETE FROM alerts
                WHERE fingerprint IN (
                    SELECT fingerprint FROM suppression_rules
                    WHERE status='deployed'
                )
            """)
            deleted = cur.rowcount
            # Mark as active — no longer waiting for reboot
            cur.execute("""
                UPDATE suppression_rules SET status='active'
                WHERE status='deployed'
            """)
            cur.execute("""
                INSERT INTO audit_log(actor, action, target_type, target_id, details)
                VALUES(%s, 'wazuh_reboot', 'system', 'manager',
                       %s::jsonb)
            """, (session.get("username"),
                  json.dumps({"deleted_alerts": deleted, "message": msg})))

    return jsonify({"ok": True, "message": msg, "deleted_alerts": deleted})


@wazuh_mgmt_bp.route("/api/wazuh/ping")
@login_required
def api_wazuh_ping():
    ok, msg = wazuh_api.ping()
    return jsonify({"ok": ok, "message": msg})
