"""
SentinelHQ — Admin Dashboard
Auth, MFA, and UI only. All API endpoints in separate Blueprint files.
"""

import os
import io
import base64
import hashlib
import secrets
import requests
from datetime import datetime, timezone, timedelta
from functools import wraps

import pyotp
import qrcode
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response, stream_with_context, send_from_directory

from db import get_db
from brute_force import is_blocked, record_attempt, unblock_ip, get_blocked_list, is_account_locked, unlock_account, get_locked_accounts, record_http_error

ORG_NAME = os.environ.get("ORG_NAME", "My Organization")


def hash_pass(p: str) -> str:
    return hashlib.sha256(p.encode()).hexdigest()


def safe_int(val, default=0, min_val=None, max_val=None) -> int:
    try:
        result = int(str(val).strip())
    except (ValueError, TypeError):
        result = default
    if min_val is not None: result = max(result, min_val)
    if max_val is not None: result = min(result, max_val)
    return result


def safe_str(val, max_len=64) -> str:
    if val is None: return ""
    return str(val).strip()[:max_len]


def safe_fingerprint(val) -> str:
    import re
    if not val: return ""
    val = str(val).strip()
    if not re.match(r'^[0-9a-f]{16}$', val): return ""
    return val


def safe_status(val, allowed) -> str:
    val = str(val).strip() if val else ""
    return val if val in allowed else allowed[0]


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "changeme")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True

# Serialize datetime objects to ISO 8601 strings in JSON responses
from flask.json.provider import DefaultJSONProvider
from datetime import date
class _ISOProvider(DefaultJSONProvider):
    def default(self, o):
        if hasattr(o, "isoformat"):
            return o.isoformat()
        return super().default(o)
app.json_provider_class = _ISOProvider
app.json = _ISOProvider(app)

# ── Register Blueprints ────────────────────────────────────────────────────────
from portal_users  import portal_users_bp;  app.register_blueprint(portal_users_bp)
from ipinfo        import ipinfo_bp;        app.register_blueprint(ipinfo_bp)
from wazuh_mgmt    import wazuh_mgmt_bp;    app.register_blueprint(wazuh_mgmt_bp)
from correlations  import correlations_bp;  app.register_blueprint(correlations_bp)
from isolation     import isolation_bp;      app.register_blueprint(isolation_bp)
from api_routes    import api_bp;           app.register_blueprint(api_bp)
import wazuh_api


@app.route("/favicon.ico")
@app.route("/favicon.svg")
def favicon():
    return send_from_directory(
        os.path.join(os.path.dirname(__file__), "static"),
        "favicon.svg", mimetype="image/svg+xml"
    )


# ── Scanner detection (4xx → ban) ────────────────────────────────────────────

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
    public_url = os.environ.get("DASHBOARD_URL", "")   # https://soc.dkprojektai.eu
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
            record_http_error(ip, request.path, response.status_code, "admin")
        except Exception:
            pass
    return response


# ── Auth decorators ───────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("needs_mfa_setup"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "mfa_setup_required"}), 403
            return redirect(url_for("setup_mfa_page"))
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


def mfa_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("needs_mfa"):
            return redirect(url_for("mfa_page"))
        return f(*args, **kwargs)
    return decorated


def ensure_admin(conn):
    username = os.environ.get("DASHBOARD_USER", "admin")
    password = os.environ.get("DASHBOARD_PASS", "changeme")
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM admin_users WHERE username=%s", (username,))
        if not cur.fetchone():
            cur.execute("""
                INSERT INTO admin_users(username, password_hash)
                VALUES(%s,%s) ON CONFLICT DO NOTHING
            """, (username, hash_pass(password)))


# ── Auth routes ───────────────────────────────────────────────────────────────

def _get_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()


@app.route("/login", methods=["GET"])
def login_page():
    if session.get("logged_in"):
        return redirect(url_for("index"))
    return render_template("login.html", org=ORG_NAME,
                           error=request.args.get("error"))


@app.route("/login", methods=["POST"])
def login_post():
    ip       = _get_ip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if is_blocked(ip):
        return render_template("login.html", org=ORG_NAME, error="blocked")

    if is_account_locked(username):
        return render_template("login.html", org=ORG_NAME, error="account_locked")

    with get_db() as conn:
        ensure_admin(conn)
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM admin_users
                WHERE username=%s AND password_hash=%s
            """, (username, hash_pass(password)))
            user = cur.fetchone()

    if not user:
        record_attempt(ip, username, False, "admin")
        return redirect(url_for("login_page", error="1"))

    record_attempt(ip, username, True, "admin")
    session["user_id"]   = user["id"]
    session["username"]  = username
    session["prev_login"]    = user["last_login"].isoformat() if user["last_login"] else None
    session["prev_login_ip"] = user.get("last_login_ip")

    lang = request.form.get("lang", "en")
    if lang not in ("lt", "en"):
        lang = "en"

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE admin_users SET last_login=NOW(), last_login_ip=%s WHERE id=%s",
                        (ip, user["id"]))
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO collector_state(key, value) VALUES('bot_lang', %s)
                ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value
            """, (lang,))

    if user["mfa_enabled"] and user["totp_secret"]:
        session["needs_mfa"] = True
        return redirect(url_for("mfa_page"))

    if not user["mfa_enabled"] or not user["totp_secret"]:
        session["needs_mfa_setup"] = True
        return redirect(url_for("setup_mfa_page"))

    session["logged_in"] = True
    return redirect(url_for("index"))


@app.route("/mfa", methods=["GET"])
def mfa_page():
    if not session.get("user_id"):
        return redirect(url_for("login_page"))
    return render_template("mfa.html", org=ORG_NAME,
                           error=request.args.get("error"))


@app.route("/mfa", methods=["POST"])
def mfa_post():
    ip    = _get_ip()
    code  = request.form.get("code", "").strip()
    uname = session.get("username", "")

    if is_blocked(ip):
        return render_template("mfa.html", org=ORG_NAME, error="blocked")

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT totp_secret FROM admin_users WHERE id=%s",
                        (session.get("user_id"),))
            row = cur.fetchone()
    if not row:
        return redirect(url_for("login_page"))
    totp = pyotp.TOTP(row["totp_secret"])
    if totp.verify(code, valid_window=1):
        record_attempt(ip, uname, True, "admin_mfa")
        session.pop("needs_mfa", None)
        session["logged_in"] = True
        return redirect(url_for("index"))
    record_attempt(ip, uname, False, "admin_mfa")
    return redirect(url_for("mfa_page", error="1"))


@app.route("/setup-mfa", methods=["GET"])
def setup_mfa_page():
    if not session.get("user_id"):
        return redirect(url_for("login_page"))
    with get_db() as conn:
        ensure_admin(conn)
        with conn.cursor() as cur:
            cur.execute("SELECT totp_secret, mfa_enabled FROM admin_users WHERE id=%s",
                        (session.get("user_id"),))
            user = cur.fetchone()
    if not user:
        return redirect(url_for("logout"))
    secret  = user["totp_secret"] or pyotp.random_base32()
    enabled = bool(user["mfa_enabled"])
    totp    = pyotp.TOTP(secret)
    uri     = totp.provisioning_uri(session.get("username", "admin"),
                                    issuer_name="SentinelHQ")
    qr  = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    if not user["totp_secret"]:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE admin_users SET totp_secret=%s WHERE id=%s",
                            (secret, session.get("user_id")))
    return render_template("setup_mfa.html", org=ORG_NAME,
                           secret=secret, qr_b64=qr_b64, enabled=enabled,
                           forced=session.get("needs_mfa_setup", False))


@app.route("/setup-mfa", methods=["POST"])
def setup_mfa_post():
    if not session.get("user_id"):
        return redirect(url_for("login_page"))
    code = request.form.get("code", "").strip()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT totp_secret FROM admin_users WHERE id=%s",
                        (session.get("user_id"),))
            row = cur.fetchone()
    if not row:
        return redirect(url_for("login_page"))
    totp = pyotp.TOTP(row["totp_secret"])
    if totp.verify(code, valid_window=1):
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE admin_users SET mfa_enabled=true WHERE id=%s",
                            (session.get("user_id"),))
        session.pop("needs_mfa_setup", None)
        session["logged_in"] = True
        return redirect(url_for("index"))
    return redirect(url_for("setup_mfa_page", error="1"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/")
@login_required
def index():
    manager_ip = os.environ.get("MANAGER_PUBLIC_IP", "192.168.1.177")
    wazuh_dashboard_url = os.environ.get("WAZUH_DASHBOARD_URL", f"https://{manager_ip}")
    prev_login = prev_login_ip = None
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT last_login, last_login_ip FROM admin_users WHERE id=%s",
                        (session.get("user_id"),))
            row = cur.fetchone()
    if row:
        prev_login    = session.get("prev_login")
        prev_login_ip = session.get("prev_login_ip")
    return render_template("index.html", org=ORG_NAME,
                           username=session.get("username"),
                           prev_login=prev_login,
                           prev_login_ip=prev_login_ip,
                           manager_ip=manager_ip,
                           wazuh_dashboard_url=wazuh_dashboard_url)


VELO_STATIC = {
    "velociraptor_client.msi":    "/velociraptor/clients/windows/velociraptor_client_repacked.msi",
    "velociraptor_client_linux":  "/velociraptor/clients/linux/velociraptor_client_repacked",
    "velociraptor_client_mac":    "/velociraptor/clients/mac/velociraptor_client",
}

# suffix -> pattern to match in uploaded filenames
VELO_DYNAMIC = {
    "velociraptor_linux_amd64.deb": ".deb",
    "velociraptor_linux_x86_64.rpm": ".rpm",
}

@app.route("/api/blocked-ips")
@login_required
def api_blocked_ips():
    rows = get_blocked_list()
    for r in rows:
        for k in ("blocked_at", "blocked_until", "unblocked_at"):
            if r.get(k):
                r[k] = r[k].isoformat()
    return jsonify(rows)


@app.route("/api/unblock-ip", methods=["POST"])
@login_required
def api_unblock_ip():
    ip    = request.json.get("ip", "").strip()
    actor = session.get("username", "admin")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    ok = unblock_ip(ip, actor)
    return jsonify({"ok": ok})


# ── Admin users ───────────────────────────────────────────────────────────────

@app.route("/api/admin-users")
@login_required
def api_admin_users_list():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, username, mfa_enabled, last_login, created_at
                FROM admin_users ORDER BY created_at
            """)
            rows = cur.fetchall()
    current = session.get("user_id")
    items = []
    for r in rows:
        d = dict(r)
        d["is_current"] = (d["id"] == current)
        for k in ("last_login", "created_at"):
            if d.get(k): d[k] = d[k].isoformat()
        items.append(d)
    return jsonify({"items": items})


@app.route("/api/admin-users", methods=["POST"])
@login_required
def api_admin_users_create():
    data     = request.json or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or len(password) < 8:
        return jsonify({"error": "Vartotojo vardas ir slaptažodis (min 8) privalomi"}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute("""
                    INSERT INTO admin_users(username, password_hash)
                    VALUES(%s,%s)
                """, (username, hash_pass(password)))
            except Exception:
                return jsonify({"error": "Vartotojas jau egzistuoja"}), 409
    return jsonify({"ok": True})


@app.route("/api/admin-users/<int:uid>", methods=["PATCH"])
@login_required
def api_admin_users_update(uid):
    data     = request.json or {}
    password = data.get("password") or ""
    with get_db() as conn:
        with conn.cursor() as cur:
            if password:
                if len(password) < 8:
                    return jsonify({"error": "Slaptažodis per trumpas (min 8)"}), 400
                cur.execute("UPDATE admin_users SET password_hash=%s WHERE id=%s",
                            (hash_pass(password), uid))
            cur.execute("SELECT id FROM admin_users WHERE id=%s", (uid,))
            if not cur.fetchone():
                return jsonify({"error": "Nerastas"}), 404
    return jsonify({"ok": True})


@app.route("/api/admin-users/<int:uid>", methods=["DELETE"])
@login_required
def api_admin_users_delete(uid):
    if uid == session.get("user_id"):
        return jsonify({"error": "Negalima ištrinti savo paskyros"}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM admin_users WHERE id=%s", (uid,))
            if cur.rowcount == 0:
                return jsonify({"error": "Nerastas"}), 404
    return jsonify({"ok": True})


@app.route("/api/admin-users/<int:uid>/reset-mfa", methods=["POST"])
@login_required
def api_admin_users_reset_mfa(uid):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE admin_users SET mfa_enabled=false, totp_secret=NULL WHERE id=%s", (uid,))
    return jsonify({"ok": True})


@app.route("/api/locked-accounts", methods=["GET"])
@login_required
def api_locked_accounts():
    from portal_users import get_locked_portal_accounts
    rows = get_locked_accounts() + get_locked_portal_accounts()
    for r in rows:
        if r.get("locked_at"):
            r["locked_at"] = r["locked_at"].isoformat()
    return jsonify(rows)


@app.route("/api/locked-accounts/unlock", methods=["POST"])
@login_required
def api_unlock_account():
    data     = request.get_json() or {}
    username = data.get("username", "").strip()
    service  = data.get("service", "admin")
    if not username:
        return jsonify({"error": "username required"}), 400
    actor = f"dashboard:{session.get('username','?')}"
    if service == "portal":
        from portal_users import unlock_portal_account
        ok = unlock_portal_account(username, actor)
    else:
        ok = unlock_account(username, actor)
    return jsonify({"ok": ok})


def _velo_stub():
    import sys; sys.path.insert(0, '/app')
    import pyvelociraptor
    from pyvelociraptor import api_pb2, api_pb2_grpc
    import grpc
    api_config = os.environ.get("VELOCIRAPTOR_API_CONFIG", "/app/sentinelhq_api.yaml")
    config = pyvelociraptor.LoadConfigFile(api_config)
    creds = grpc.ssl_channel_credentials(
        root_certificates=config['ca_certificate'].encode(),
        private_key=config['client_private_key'].encode(),
        certificate_chain=config['client_cert'].encode(),
    )
    channel = grpc.secure_channel(config['api_connection_string'], creds,
                                  options=[('grpc.ssl_target_name_override', 'VelociraptorServer')])
    from pyvelociraptor import api_pb2_grpc
    return api_pb2_grpc.APIStub(channel)

def _vql(stub, q):
    import json as _j
    from pyvelociraptor import api_pb2
    rows = []
    for resp in stub.Query(api_pb2.VQLCollectorArgs(max_wait=30, Query=[api_pb2.VQLRequest(VQL=q)])):
        if resp.Response:
            rows.extend(_j.loads(resp.Response))
    return rows

def _find_latest_package(stub, suffix):
    """Find the file path from the most recent Server.Utils.CreateLinuxPackages flow."""
    rows = _vql(stub,
        "SELECT session_id, create_time FROM flows(client_id='server') "
        "WHERE request =~ 'CreateLinuxPackages' "
        "ORDER BY create_time DESC LIMIT 1"
    )
    if not rows:
        return None
    session_id = rows[0]['session_id']
    base = f"/velociraptor/clients/server/collections/{session_id}/uploads/auto"
    files = _vql(stub, f"SELECT FullPath FROM glob(globs='{base}/*')")
    for f in files:
        if f.get('FullPath', '').endswith(suffix):
            return f['FullPath']
    return None

@app.route("/api/set-lang", methods=["POST"])
@login_required
def api_set_lang():
    lang = (request.get_json() or {}).get("lang", "lt")
    if lang not in ("lt", "en"):
        return jsonify({"error": "invalid lang"}), 400
    session["lang"] = lang
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO collector_state(key, value) VALUES('bot_lang', %s)
                ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value
            """, (lang,))
    return jsonify({"ok": True, "lang": lang})

@app.route("/downloads/<filename>")
def download_velo(filename):
    try:
        stub = _velo_stub()

        if filename in VELO_STATIC:
            velo_path = VELO_STATIC[filename]
        elif filename in VELO_DYNAMIC:
            velo_path = _find_latest_package(stub, VELO_DYNAMIC[filename])
            if not velo_path:
                return "Package not found - run Server.Utils.CreateLinuxPackages first", 404
        else:
            return "Not found", 404

        chunk = 1024 * 1024  # 1MB

        def generate():
            off = 0
            import base64 as _b64
            while True:
                rs = _vql(stub,
                    f"SELECT base64encode(string=read_file(filename='{velo_path}', offset={off}, length={chunk})) AS d FROM scope()"
                )
                if not rs or not rs[0].get('d'):
                    break
                data = _b64.b64decode(rs[0]['d'])
                if not data:
                    break
                yield data
                off += len(data)
                if len(data) < chunk:
                    break

        mime = "application/octet-stream"
        return Response(stream_with_context(generate()), mimetype=mime,
                        headers={"Content-Disposition": f"attachment; filename={filename}"})
    except Exception as e:
        return str(e), 500


# ── LLM Patarėjas API ─────────────────────────────────────────────────────────

@app.route("/api/llm-advisor", methods=["POST"])
@login_required
def api_llm_advisor():
    """Chat with LLM about Wazuh data."""
    data     = request.get_json(force=True) or {}
    question = (data.get("question") or "").strip()
    history  = data.get("history") or []
    lang     = data.get("lang") or session.get("lang", "lt")
    if not question:
        return jsonify({"error": "empty question"}), 400
    try:
        import sys, os as _os
        _tg = _os.path.join(_os.path.dirname(__file__), "ai")
        if _tg not in sys.path:
            sys.path.insert(0, _tg)
        import ask_engine
        with get_db() as conn:
            answer, new_history = ask_engine.run_agent_loop(
                question, conn, lang, history=history[-10:])
        return jsonify({"answer": answer, "history": new_history[-10:]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── LLM Forenzikai API ────────────────────────────────────────────────────────

def _forensics_agent_status(lang: str, question: str = "") -> dict:
    """Check Wazuh agents + Velociraptor online status, return as redirect_hint message.
    Filters based on question context:
    - specific hostname/IP → show only that agent
    - 'prisijungę/online/active' → show only online agents
    - otherwise → show all
    """
    import sys, os as _os, re as _re
    _tg = _os.path.join(_os.path.dirname(__file__), "ai")
    if _tg not in sys.path:
        sys.path.insert(0, _tg)
    import ask_engine, velo_engine

    # Detect filter mode from question
    q = question.lower()
    only_online = bool(_re.search(
        r'(prisijung|online|aktyvūs|aktyvus|gyvi|gyvas|active|connected)', q))
    # OS filter
    os_filter = None
    if _re.search(r'\b(linux|kali|ubuntu|debian|centos|rhel)\b', q):
        os_filter = "linux"
    elif _re.search(r'\b(windows|win)\b', q):
        os_filter = "windows"
    # Specific host/IP filter
    specific = None
    _hp = _re.search(r'\b([A-Z]{2,}-[A-Z0-9]{4,}|\d{1,3}(?:\.\d{1,3}){3})\b', question, _re.I)
    if _hp:
        specific = _hp.group(1).upper()

    # 1. Get agents from Wazuh
    wazuh_agents = []
    try:
        data = ask_engine._wazuh_get("/agents", {"limit": 50, "select": "id,name,ip,status,os.platform"})
        wazuh_agents = [a for a in (data or {}).get("affected_items", []) if a.get("id") != "000"]
    except Exception:
        pass

    # 2. Velociraptor stub
    stub = None
    try:
        stub = velo_engine._get_stub()
    except Exception:
        pass

    # Build agent rows with velo status
    rows = []
    for a in wazuh_agents:
        name   = a.get("name", "?")
        ip     = a.get("ip", "?")
        status = a.get("status", "?")
        os_p   = (a.get("os") or {}).get("platform", "?")
        wazuh_online = (status == "active")
        wazuh_icon   = "🟢" if wazuh_online else "🔴"

        velo_online = False
        velo_icon   = "⚪"
        if stub:
            try:
                cid, _ = velo_engine.resolve_client(stub, name)
                if cid:
                    velo_online = velo_engine.is_client_online(stub, cid)
                    velo_icon   = "🟢" if velo_online else "🔴"
            except Exception:
                pass

        rows.append({"name": name, "ip": ip, "os": os_p,
                     "wazuh_icon": wazuh_icon, "velo_icon": velo_icon,
                     "wazuh_online": wazuh_online, "velo_online": velo_online})

    # Apply filters
    if os_filter:
        rows = [r for r in rows if r["os"].lower() == os_filter or
                (os_filter == "linux" and r["os"].lower() not in ("windows",))]
        # More precise: keep only matching OS platform
        rows = [r for r in rows if os_filter in r["os"].lower() or
                (os_filter == "linux" and r["os"].lower() not in ("windows", "windows server"))]
    if specific:
        rows = [r for r in rows if specific in r["name"].upper() or specific == r["ip"]]
        if not rows:
            msg = (f"Agent '{specific}' not found." if lang == "en"
                   else f"Agentas '{specific}' nerastas.")
            return {"redirect_hint": msg, "artifacts": []}
    if only_online:
        rows = [r for r in rows if r["wazuh_online"] or r["velo_online"]]

    # Build message
    lines = []
    os_label = f" ({os_filter.capitalize()})" if os_filter else ""
    if specific:
        title = f"**Agent {specific}:**" if lang == "en" else f"**Agentas {specific}:**"
    elif only_online:
        title = f"**Online agents{os_label}:**" if lang == "en" else f"**Prisijungę agentai{os_label}:**"
    else:
        title = f"**All agents{os_label} (Wazuh + Velociraptor):**" if lang == "en" else f"**Visi agentai{os_label} (Wazuh + Velociraptor):**"
    lines.append(title + "\n")

    if not rows:
        lines.append("— " + ("None found." if lang == "en" else "Nerasta."))
    else:
        for r in rows:
            lines.append(f"* **{r['name']}** ({r['ip']}) — Wazuh:{r['wazuh_icon']} Velo:{r['velo_icon']} OS:{r['os']}")


    return {"redirect_hint": "\n".join(lines), "artifacts": []}


@app.route("/api/llm-forensics/search", methods=["POST"])
@login_required
def api_llm_forensics_search():
    """Find relevant Velociraptor artifacts for a question."""
    data     = request.get_json(force=True) or {}
    question = (data.get("question") or "").strip()
    history  = data.get("history") or []
    lang     = data.get("lang") or session.get("lang", "lt")
    if not question:
        return jsonify({"error": "empty question"}), 400
    try:
        import sys, os as _os, re as _re
        _tg = _os.path.join(_os.path.dirname(__file__), "ai")
        if _tg not in sys.path:
            sys.path.insert(0, _tg)
        import velo_engine

        # Detect "list agents / what agents" type questions — check Wazuh + Velo status
        _agent_q = _re.compile(
            r'(kokie|kurie|koki|list|show|what|which|available|prieinam|aktyvūs|gyvi|online)'
            r'.{0,20}agent', _re.I)
        if _agent_q.search(question) or _re.search(r'agent.{0,20}(prieinam|online|gyvi|aktyvūs|veikia)', question, _re.I):
            return jsonify(_forensics_agent_status(lang, question))

        # Detect questions that belong to LLM Advisor, not Velociraptor
        _non_velo = _re.compile(
            r'\b(whois|ip\s+check|kas\s+(yra|tai)\s+ip|patikrink\s+(ip|abu\s+ip)|'
            r'reputaci|virustotal|abuseipdb|geoloc|country|šalis)\b', _re.I)
        if _non_velo.search(question):
            redirect_msg = ("This question is better suited for the LLM Advisor (Wazuh data). "
                            "Try asking there instead."
                            if lang == "en" else
                            "Šis klausimas geriau tinka LLM Patarėjui (Wazuh duomenys). "
                            "Pabandyk ten.")
            return jsonify({"redirect_hint": redirect_msg, "artifacts": []})

        # Use pre-supplied agent_id/hostname (from agent bar) or search in question/history
        client_id = data.get("agent_id") or None
        hostname  = data.get("hostname") or None

        if not client_id:
            _pat = _re.compile(r'\b([A-Z]{2,}-[A-Z0-9]{4,}|\d{1,3}(?:\.\d{1,3}){3})\b')
            for src in [question] + [m.get("content","") for m in reversed(history)
                                      if isinstance(m.get("content"), str)]:
                m2 = _pat.search(src)
                if m2:
                    hostname = m2.group(1)
                    break
            if hostname:
                try:
                    stub = velo_engine._get_stub()
                    client_id, _ = velo_engine.resolve_client(stub, hostname)
                except Exception:
                    pass

        # Check agent is online BEFORE showing artifacts (same as Telegram)
        if client_id:
            try:
                stub2 = velo_engine._get_stub()
                if not velo_engine.is_client_online(stub2, client_id):
                    msg = (f"Agent '{hostname or client_id}' is offline in Velociraptor. Cannot collect artifacts."
                           if lang == "en" else
                           f"Agentas '{hostname or client_id}' yra išjungtas Velociraptor. Negalima rinkti duomenų.")
                    return jsonify({"error": msg}), 503
            except Exception:
                pass

        artifacts = velo_engine.find_relevant_artifacts(question, lang, client_id)
        if not artifacts:
            hint = ("I couldn't find relevant Velociraptor artifacts for this question. "
                    "For forensic collection, ask something like: 'what processes are running on WIN-PC' or 'show browser history'."
                    if lang == "en" else
                    "Nerandu tinkamų Velociraptor artifacts šiam klausimui. "
                    "Forenzikai tinka klausimai kaip: 'kokie procesai veikia WIN-PC' arba 'parodyk naršymo istoriją'.")
            return jsonify({"redirect_hint": hint, "artifacts": []})
        return jsonify({"artifacts": artifacts, "client_id": client_id, "hostname": hostname})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/llm-forensics/collect", methods=["POST"])
@login_required
def api_llm_forensics_collect():
    """Collect selected artifacts and analyse with LLM."""
    data      = request.get_json(force=True) or {}
    question  = (data.get("question") or "").strip()
    artifacts = data.get("artifacts") or []
    history   = data.get("history") or []
    lang      = data.get("lang") or session.get("lang", "lt")
    if not question or not artifacts:
        return jsonify({"error": "missing question or artifacts"}), 400
    try:
        import sys, os as _os, re as _re
        _tg = _os.path.join(_os.path.dirname(__file__), "ai")
        if _tg not in sys.path:
            sys.path.insert(0, _tg)
        import velo_engine

        # Use pre-supplied agent_id/hostname (from agent bar) or search in question/history
        client_id = data.get("agent_id") or None
        hostname  = data.get("hostname") or None

        if not client_id:
            _pat = _re.compile(r'\b([A-Z]{2,}-[A-Z0-9]{4,}|\d{1,3}(?:\.\d{1,3}){3})\b')
            for src in [question] + [m.get("content","") for m in reversed(history)
                                      if isinstance(m.get("content"), str)]:
                m2 = _pat.search(src)
                if m2:
                    hostname = m2.group(1)
                    break
            if not hostname:
                return jsonify({"error": "Agent hostname not found in question or history"}), 400

        stub = velo_engine._get_stub()
        if client_id:
            # Resolve name from known client_id
            try:
                _, client_name = velo_engine.resolve_client(stub, hostname or client_id)
            except Exception:
                client_name = hostname or client_id
        else:
            client_id, client_name = velo_engine.resolve_client(stub, hostname)
        if not client_id:
            return jsonify({"error": f"Agent '{hostname}' not found in Velociraptor"}), 404

        if not velo_engine.is_client_online(stub, client_id):
            msg = (f"Agent '{client_name}' is offline in Velociraptor. Cannot collect artifacts."
                   if lang == "en" else
                   f"Agentas '{client_name}' yra išjungtas Velociraptor. Negalima rinkti duomenų.")
            return jsonify({"error": msg}), 503

        answer, new_history = velo_engine.run_selected_artifacts(
            question, client_id, client_name, artifacts, lang, history[-10:])
        return jsonify({"answer": answer, "history": new_history[-10:]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
