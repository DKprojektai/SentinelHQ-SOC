"""
SentinelHQ — IP Info Blueprint
Proxy to ipinfo.io to avoid CORS issues.
"""

import requests as req
from flask import Blueprint, jsonify, request, session
from functools import wraps

ipinfo_bp = Blueprint("ipinfo", __name__)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


@ipinfo_bp.route("/api/ipinfo")
@login_required
def api_ipinfo():
    ip = request.args.get("ip", "").strip()
    # Basic IP validation
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return jsonify({"error": "invalid ip"}), 400
    try:
        r = req.get(f"https://ipinfo.io/{ip}/json",
                    timeout=5, headers={"Accept": "application/json"})
        d = r.json()
        return jsonify({
            "hostname": d.get("hostname"),
            "org":      d.get("org"),
            "country":  d.get("country"),
            "city":     d.get("city"),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
