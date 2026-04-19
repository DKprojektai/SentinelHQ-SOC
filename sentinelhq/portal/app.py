"""
SentinelHQ — Client Portal
Read-only portal for clients with TOTP MFA.
"""

import os
import io
import base64
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from functools import wraps

import pyotp
import qrcode
from flask import (Flask, render_template, jsonify, request,
                   Response, session, redirect, url_for, send_file, send_from_directory)

from db import get_db
from brute_force import is_blocked, record_attempt, is_account_locked, record_http_error

def get_lang() -> str:
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT value FROM collector_state WHERE key='bot_lang'")
                row = cur.fetchone()
                return row["value"] if row and row["value"] in ("lt", "en") else "lt"
    except Exception:
        return "lt"

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "changeme")
ORG_NAME    = os.environ.get("ORG_NAME", "My Organization")
REPORTS_DIR = Path("/reports")


@app.route("/favicon.ico")
@app.route("/favicon.svg")
def favicon():
    return send_from_directory(
        os.path.join(os.path.dirname(__file__), "static"),
        "favicon.svg", mimetype="image/svg+xml"
    )


def hash_pass(p: str) -> str:
    return hashlib.sha256(p.encode()).hexdigest()


def _get_request_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

@app.before_request
def block_scanners():
    ip = _get_request_ip()
    try:
        if is_blocked(ip):
            return "Forbidden", 403
    except Exception:
        pass

@app.after_request
def set_security_headers(response):
    public_url = os.environ.get("PORTAL_URL", "")   # https://soc-portal.dkprojektai.eu
    https      = public_url.startswith("https://")
    response.headers["X-Content-Type-Options"]            = "nosniff"
    response.headers["X-Frame-Options"]                   = "DENY"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Referrer-Policy"]                   = "strict-origin-when-cross-origin"
    response.headers["Cross-Origin-Opener-Policy"]        = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"]      = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"]      = "require-corp"
    response.headers["Permissions-Policy"]                = "geolocation=(), microphone=(), camera=()"
    if https:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    csp_extra = f" {public_url}" if public_url else ""
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'{csp_extra}; "
        f"script-src 'self'{csp_extra} 'unsafe-inline'; "
        f"style-src 'self'{csp_extra} 'unsafe-inline'; "
        f"img-src 'self'{csp_extra} data:; "
        f"connect-src 'self'{csp_extra}; "
        "frame-ancestors 'none';"
    )
    return response

@app.after_request
def track_http_errors(response):
    if 400 <= response.status_code < 500 and response.status_code != 401:
        ip = _get_request_ip()
        try:
            record_http_error(ip, request.path, response.status_code, "portal")
        except Exception:
            pass
    return response


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("portal_mfa_setup"):
            return redirect(url_for("portal_setup_mfa"))
        if not session.get("portal_logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("portal_login"))
        return f(*args, **kwargs)
    return decorated


# ── Auth ──────────────────────────────────────────────────────────────────────

def _get_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()


@app.route("/login", methods=["GET"])
def portal_login():
    return render_template("login.html", org=ORG_NAME, lang=get_lang(), error=request.args.get("error"))


@app.route("/login", methods=["POST"])
def portal_login_post():
    ip       = _get_ip()
    email    = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if is_blocked(ip):
        return render_template("login.html", org=ORG_NAME, lang=get_lang(), error="blocked")

    if is_account_locked(email):
        return render_template("login.html", org=ORG_NAME, lang=get_lang(), error="account_locked")

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM portal_users
                WHERE email=%s AND password_hash=%s AND is_active=true
            """, (email, hash_pass(password)))
            user = cur.fetchone()

    if not user:
        record_attempt(ip, email, False, "portal")
        return redirect(url_for("portal_login", error="1"))

    record_attempt(ip, email, True, "portal")

    session["portal_user_id"]    = user["id"]
    session["portal_email"]      = email
    session["portal_prev_login"]    = user["last_login"].isoformat() if user["last_login"] else None
    session["portal_prev_login_ip"] = user.get("last_login_ip")

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE portal_users SET last_login=NOW(), last_login_ip=%s WHERE id=%s",
                        (ip, user["id"]))

    if user["mfa_enabled"] and user["totp_secret"]:
        session["portal_needs_mfa"] = True
        return redirect(url_for("portal_mfa"))

    # MFA not set up yet — must set up before entering portal
    if not user["totp_secret"]:
        session["portal_logged_in"] = False
        session["portal_mfa_setup"] = True
        return redirect(url_for("portal_setup_mfa"))

    session["portal_logged_in"] = True
    return redirect(url_for("portal_index"))


@app.route("/mfa", methods=["GET"])
def portal_mfa():
    if not session.get("portal_user_id"):
        return redirect(url_for("portal_login"))
    return render_template("mfa.html", org=ORG_NAME, lang=get_lang(), error=request.args.get("error"))


@app.route("/mfa", methods=["POST"])
def portal_mfa_post():
    ip    = _get_ip()
    code  = request.form.get("code", "").strip()
    email = session.get("portal_email", "")

    if is_blocked(ip):
        return render_template("mfa.html", org=ORG_NAME, lang=get_lang(), error="blocked")

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT totp_secret FROM portal_users WHERE id=%s",
                        (session.get("portal_user_id"),))
            row = cur.fetchone()

    if not row:
        return redirect(url_for("portal_login"))

    totp = pyotp.TOTP(row["totp_secret"])
    if totp.verify(code, valid_window=1):
        record_attempt(ip, email, True, "portal_mfa")
        session.pop("portal_needs_mfa", None)
        session["portal_logged_in"] = True
        return redirect(url_for("portal_index"))

    record_attempt(ip, email, False, "portal_mfa")
    return redirect(url_for("portal_mfa", error="1"))


@app.route("/logout")
def portal_logout():
    session.clear()
    return redirect(url_for("portal_login"))


# ── Pages ─────────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def portal_index():
    return render_template("index.html", org=ORG_NAME, lang=get_lang(),
                           email=session.get("portal_email"),
                           prev_login=session.get("portal_prev_login"),
                           prev_login_ip=session.get("portal_prev_login_ip"))


# ── API ───────────────────────────────────────────────────────────────────────

@app.route("/api/summary")
@login_required
def api_summary():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT COUNT(*) AS total,
                       COUNT(*) FILTER (WHERE rule_level >= 12) AS critical,
                       COUNT(*) FILTER (WHERE rule_level >= 10) AS high
                FROM alerts WHERE collected_at >= NOW()-INTERVAL '30 days'
            """)
            stats = dict(cur.fetchone())

            cur.execute("""
                SELECT score, trend FROM health_scores
                ORDER BY calculated_at DESC LIMIT 1
            """)
            health = cur.fetchone()

            cur.execute("""
                SELECT COUNT(*) AS c FROM suppression_rules WHERE status IN ('ready','deployed')
            """)
            rules = cur.fetchone()["c"]

            cur.execute("""
                SELECT COUNT(*) AS c FROM correlations
                WHERE status='resolved' AND detected_at >= NOW()-INTERVAL '30 days'
            """)
            resolved = cur.fetchone()["c"]

    return jsonify({
        "stats":         stats,
        "health_score":  health["score"] if health else None,
        "health_trend":  health["trend"] if health else None,
        "rules_active":  rules,
        "incidents_resolved": resolved,
        "period":        "30 dienų",
    })


@app.route("/api/health/history")
@login_required
def api_health_history():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT score, trend, calculated_at
                FROM health_scores ORDER BY calculated_at DESC LIMIT 168
            """)
            rows = cur.fetchall()
    return jsonify([{
        "score": r["score"],
        "trend": r["trend"],
        "at":    r["calculated_at"].isoformat()
    } for r in rows])


@app.route("/api/reports")
@login_required
def api_reports():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, generated_at, period_start, period_end,
                       report_type, llm_summary, pdf_path
                FROM reports ORDER BY generated_at DESC LIMIT 12
            """)
            rows = cur.fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


@app.route("/api/reports/<int:rid>/pdf")
@login_required
def api_report_pdf(rid):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pdf_path FROM reports WHERE id=%s", (rid,))
            row = cur.fetchone()
    if not row or not row["pdf_path"]:
        return jsonify({"error": "not found"}), 404
    path = Path(row["pdf_path"])
    if not path.exists():
        return jsonify({"error": "file missing"}), 404
    return send_file(path, mimetype="application/pdf",
                     as_attachment=True, download_name=path.name)


@app.route("/api/recommendations")
@login_required
def api_recommendations():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT title, description, priority, status, due_date, created_at
                FROM recommendations WHERE status != 'done'
                ORDER BY CASE priority
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3 ELSE 4 END, created_at DESC
            """)
            rows = cur.fetchall()
    return jsonify({"items": [dict(r) for r in rows]})



# ── MFA Setup ─────────────────────────────────────────────────────────────────

@app.route("/setup-mfa", methods=["GET"])
def portal_setup_mfa():
    if not session.get("portal_logged_in") and not session.get("portal_mfa_setup"):
        return redirect(url_for("portal_login"))

    import pyotp, qrcode, io, base64
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT totp_secret, mfa_enabled FROM portal_users WHERE id=%s",
                        (session.get("portal_user_id"),))
            user = cur.fetchone()

    if not user:
        return redirect(url_for("portal_logout"))

    secret = user["totp_secret"] or pyotp.random_base32()

    if not user["totp_secret"]:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE portal_users SET totp_secret=%s WHERE id=%s",
                            (secret, session.get("portal_user_id")))

    totp = pyotp.TOTP(secret)
    uri  = totp.provisioning_uri(session.get("portal_email", "user"),
                                  issuer_name=f"SentinelHQ - {ORG_NAME}")
    qr  = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render_template("setup_mfa.html", org=ORG_NAME, lang=get_lang(),
                           secret=secret, qr_b64=qr_b64,
                           enabled=bool(user["mfa_enabled"]))


@app.route("/setup-mfa", methods=["POST"])
def portal_setup_mfa_post():
    if not session.get("portal_logged_in") and not session.get("portal_mfa_setup"):
        return redirect(url_for("portal_login"))

    import pyotp
    code = request.form.get("code", "").strip()

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT totp_secret FROM portal_users WHERE id=%s",
                        (session.get("portal_user_id"),))
            row = cur.fetchone()

    if not row:
        return redirect(url_for("portal_login"))

    totp = pyotp.TOTP(row["totp_secret"])
    if totp.verify(code, valid_window=1):
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE portal_users SET mfa_enabled=true WHERE id=%s",
                            (session.get("portal_user_id"),))
        session["portal_logged_in"] = True
        session.pop("portal_mfa_setup", None)
        return redirect(url_for("portal_index"))

    return redirect(url_for("portal_setup_mfa") + "?error=1")
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)


