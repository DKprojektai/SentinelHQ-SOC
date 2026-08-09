"""
Wazuh Noise Reducer - Dashboard
Flask web app with simple session-based login.
"""

import os
import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, jsonify, request, Response, session, redirect, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "changeme-in-production")

DB_PATH          = os.environ.get("DB_PATH", "/data/alerts.db")
DASHBOARD_USER   = os.environ.get("DASHBOARD_USER", "admin")
DASHBOARD_PASS   = os.environ.get("DASHBOARD_PASS", "changeme")
RULES_EXPORT_DIR = Path("/rules_export")
RULES_EXPORT_DIR.mkdir(exist_ok=True)


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


# ── Auth ──────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


@app.route("/login", methods=["GET"])
def login_page():
    error = request.args.get("error")
    return render_template("login.html", error=error)


@app.route("/login", methods=["POST"])
def login_post():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username == DASHBOARD_USER and password == DASHBOARD_PASS:
        session["logged_in"] = True
        session["username"]  = username
        return redirect(url_for("index"))
    return redirect(url_for("login_page", error="1"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ── Pages ─────────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    return render_template("index.html", username=session.get("username"))


# ── API: Stats ────────────────────────────────────────────────────────────────

@app.route("/api/stats")
@login_required
def api_stats():
    with get_db() as conn:
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        total_cands  = conn.execute("SELECT COUNT(*) FROM noise_candidates").fetchone()[0]
        pending      = conn.execute("SELECT COUNT(*) FROM noise_candidates WHERE status='pending'").fetchone()[0]
        approved     = conn.execute("SELECT COUNT(*) FROM noise_candidates WHERE status='approved'").fetchone()[0]
        dismissed    = conn.execute("SELECT COUNT(*) FROM noise_candidates WHERE status='dismissed'").fetchone()[0]
        rules_ready  = conn.execute("SELECT COUNT(*) FROM suppression_rules WHERE status='ready'").fetchone()[0]
        alerts_24h   = conn.execute("SELECT COUNT(*) FROM alerts WHERE collected_at >= datetime('now','-24 hours')").fetchone()[0]
        top_rules    = conn.execute("""
            SELECT rule_id, rule_desc, COUNT(*) as cnt
            FROM alerts WHERE collected_at >= datetime('now','-72 hours')
            GROUP BY rule_id ORDER BY cnt DESC LIMIT 5
        """).fetchall()
    return jsonify({
        "total_alerts": total_alerts, "alerts_24h": alerts_24h,
        "total_candidates": total_cands,
        "pending": pending, "approved": approved, "dismissed": dismissed,
        "rules_ready": rules_ready,
        "top_rules": [dict(r) for r in top_rules],
    })


# ── API: Candidates ───────────────────────────────────────────────────────────

@app.route("/api/candidates")
@login_required
def api_candidates():
    status    = request.args.get("status", "pending")
    min_score = int(request.args.get("min_score", 0))
    limit     = int(request.args.get("limit", 100))
    offset    = int(request.args.get("offset", 0))
    with get_db() as conn:
        rows = conn.execute("""
            SELECT * FROM noise_candidates
            WHERE status=? AND noise_score>=?
            ORDER BY noise_score DESC, occurrence_count DESC
            LIMIT ? OFFSET ?
        """, (status, min_score, limit, offset)).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) FROM noise_candidates WHERE status=? AND noise_score>=?",
            (status, min_score)
        ).fetchone()[0]
    return jsonify({"total": total, "items": [dict(r) for r in rows]})


@app.route("/api/candidates/<fingerprint>")
@login_required
def api_candidate_detail(fingerprint):
    with get_db() as conn:
        c = conn.execute(
            "SELECT * FROM noise_candidates WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
        if not c:
            return jsonify({"error": "not found"}), 404
        samples = conn.execute("""
            SELECT collected_at, agent_name, full_log, alert_ts
            FROM alerts WHERE fingerprint=?
            ORDER BY collected_at DESC LIMIT 10
        """, (fingerprint,)).fetchall()
        rule = conn.execute(
            "SELECT * FROM suppression_rules WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
    return jsonify({
        "candidate": dict(c),
        "samples":   [dict(s) for s in samples],
        "rule":      dict(rule) if rule else None,
    })


@app.route("/api/candidates/<fingerprint>/review", methods=["POST"])
@login_required
def api_review(fingerprint):
    body   = request.get_json() or {}
    action = body.get("action")
    notes  = body.get("notes", "")
    if action not in ("approve", "dismiss"):
        return jsonify({"error": "action must be approve or dismiss"}), 400
    status = "approved" if action == "approve" else "dismissed"
    now    = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute("""
            UPDATE noise_candidates
            SET status=?, reviewed_at=?, notes=?, updated_at=?
            WHERE fingerprint=?
        """, (status, now, notes, now, fingerprint))
        if action == "approve":
            conn.execute("""
                UPDATE suppression_rules SET status='ready', approved_at=?
                WHERE fingerprint=?
            """, (now, fingerprint))
    return jsonify({"ok": True, "status": status})


# ── API: Rules ────────────────────────────────────────────────────────────────

@app.route("/api/rules")
@login_required
def api_rules():
    status = request.args.get("status", "ready")
    with get_db() as conn:
        rows = conn.execute("""
            SELECT * FROM suppression_rules WHERE status=?
            ORDER BY noise_score DESC
        """, (status,)).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


@app.route("/api/rules/export")
@login_required
def api_rules_export():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT * FROM suppression_rules WHERE status='ready'
            ORDER BY wazuh_rule_id ASC
        """).fetchall()
    if not rows:
        return jsonify({"error": "No ready rules to export"}), 404
    lines = [
        '<!-- Wazuh Noise Reducer - Auto-generated suppression rules -->',
        '<!-- Rule ID range: 122000-122999                           -->',
        '<!-- Review before deploying to local_rules.xml             -->',
        '<group name="noise_suppression,">',
        '',
    ]
    for r in rows:
        lines.append(r["wazuh_xml"])
        lines.append('')
    lines.append('</group>')
    xml_content = "\n".join(lines)
    ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"noise_suppression_{ts}.xml"
    (RULES_EXPORT_DIR / filename).write_text(xml_content, encoding="utf-8")
    return Response(
        xml_content,
        mimetype="application/xml",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/api/rules/<int:rule_id>/xml")
@login_required
def api_rule_xml(rule_id):
    with get_db() as conn:
        r = conn.execute(
            "SELECT wazuh_xml FROM suppression_rules WHERE id=?", (rule_id,)
        ).fetchone()
    if not r:
        return jsonify({"error": "not found"}), 404
    return Response(r["wazuh_xml"], mimetype="text/plain")


# ── API: Timeline ─────────────────────────────────────────────────────────────

@app.route("/api/timeline")
@login_required
def api_timeline():
    fp    = request.args.get("fingerprint")
    hours = int(request.args.get("hours", 72))
    query = """
        SELECT strftime('%Y-%m-%dT%H:00:00', collected_at) as hour,
               COUNT(*) as cnt
        FROM alerts
        WHERE collected_at >= datetime('now', ? || ' hours')
    """
    params = [f"-{hours}"]
    if fp:
        query += " AND fingerprint=?"
        params.append(fp)
    query += " GROUP BY hour ORDER BY hour"
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
