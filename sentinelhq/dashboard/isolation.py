"""
SentinelHQ — Host Isolation via Velociraptor built-in artifacts.
Windows : Windows.Remediation.Quarantine
Linux   : Linux.Remediation.Quarantine.IPTables
macOS   : Linux.Remediation.Quarantine.IPTables (via bash)
"""

import json
import logging
import os
from functools import wraps

from flask import Blueprint, jsonify, request, session
from db import get_db
import wazuh_api

isolation_bp = Blueprint("isolation", __name__)
log = logging.getLogger(__name__)

VELOCIRAPTOR_API_CONFIG  = os.environ.get("VELOCIRAPTOR_API_CONFIG", "/app/sentinelhq_api.yaml")
VELOCIRAPTOR_URL         = os.environ.get("VELOCIRAPTOR_URL", "")   # https://192.168.1.177:8000
INTERNAL_API_TOKEN       = os.environ.get("INTERNAL_API_TOKEN", "")


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        # Allow internal service calls with token
        if INTERNAL_API_TOKEN and request.headers.get("X-Internal-Token") == INTERNAL_API_TOKEN:
            return f(*args, **kwargs)
        if not session.get("logged_in"):
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# ── Velociraptor gRPC ─────────────────────────────────────────────────────────

def _get_stub():
    try:
        import pyvelociraptor
        from pyvelociraptor import api_pb2_grpc
        import grpc

        config = pyvelociraptor.LoadConfigFile(VELOCIRAPTOR_API_CONFIG)
        if isinstance(config, dict):
            ca, key, cert = config["ca_certificate"], config["client_private_key"], config["client_cert"]
            url = config.get("api_connection_string", "")
        else:
            ca, key, cert = config.ca_certificate, config.client_private_key, config.client_cert
            url = getattr(config, "api_connection_string", "")

        creds = grpc.ssl_channel_credentials(
            root_certificates=ca.encode(),
            private_key=key.encode(),
            certificate_chain=cert.encode(),
        )
        channel = grpc.secure_channel(url, creds,
            options=[("grpc.ssl_target_name_override", "VelociraptorServer")])
        return api_pb2_grpc.APIStub(channel)
    except Exception as e:
        log.error("Velociraptor connect error: %s", e)
        return None


def _vql(stub, query: str, env: dict | None = None) -> list:
    try:
        from pyvelociraptor import api_pb2
        e = [api_pb2.VQLEnv(key=k, value=str(v)) for k, v in (env or {}).items()]
        req = api_pb2.VQLCollectorArgs(
            max_wait=30,
            Query=[api_pb2.VQLRequest(VQL=query)],
            env=e,
        )
        rows = []
        for resp in stub.Query(req):
            if resp.Response:
                rows.extend(json.loads(resp.Response))
        return rows
    except Exception as e:
        log.error("VQL error [%s]: %s", query[:60], e)
        return []


# ── Client lookup ─────────────────────────────────────────────────────────────

def _find_client(stub, hostname: str) -> tuple[str | None, str | None]:
    """Find client_id + os_type by hostname (case-insensitive)."""
    rows = _vql(stub, f"SELECT client_id, os_info FROM clients(search='host:{hostname}')")
    if not rows:
        # Fallback: list all and match
        rows = _vql(stub, "SELECT client_id, os_info FROM clients()")
        hn_lower = hostname.lower()
        rows = [r for r in rows if (r.get("os_info") or {}).get("hostname", "").lower() == hn_lower]

    if not rows:
        log.warning("Velociraptor: client '%s' not found", hostname)
        return None, None

    row    = rows[0]
    system = (row.get("os_info") or {}).get("system", "").lower()
    os_type = "windows" if "windows" in system else ("darwin" if "darwin" in system else "linux")
    return row["client_id"], os_type


def _collect(stub, hostname: str, artifact: str, params: dict) -> tuple[bool, str]:
    """
    Run collect_client for the given hostname + artifact.
    Uses clients(search='host:...') — same as GUI Quarantine button.
    """
    if params:
        params_str = ", ".join(f"{k}='{v}'" for k, v in params.items() if v)
        vql = (
            f"SELECT collect_client(client_id=client_id, "
            f"artifacts='{artifact}', "
            f"spec=dict(`{artifact}`=dict({params_str}))) AS result "
            f"FROM clients(search='host:{hostname}') LIMIT 1"
        )
    else:
        vql = (
            f"SELECT collect_client(client_id=client_id, "
            f"artifacts='{artifact}') AS result "
            f"FROM clients(search='host:{hostname}') LIMIT 1"
        )

    log.info("VQL: %s", vql)
    rows = _vql(stub, vql)
    if not rows:
        return False, "Klientas nerastas arba neatsakė"

    result = rows[0].get("result") or {}
    flow_id = result.get("flow_id", "?")
    return True, f"flow {flow_id}"


# ── Real isolation status from Velociraptor ───────────────────────────────────

def get_real_isolation_status() -> dict[str, bool]:
    """
    Returns {client_id: True/False} isolation status from Velociraptor.
    Checks Windows.Remediation.Quarantine / Linux quarantine artifacts last run result.
    Falls back to empty dict if Velociraptor unreachable.
    """
    stub = _get_stub()
    if not stub:
        return {}
    try:
        # Check all clients - query last quarantine artifact result
        rows = _vql(stub, """
            SELECT client_id, os_info,
                   last_label
            FROM clients()
        """)
        result = {}
        for r in rows:
            cid = r.get("client_id", "")
            if not cid:
                continue
            # Check if quarantine label is set
            labels = _vql(stub, f"SELECT labels FROM clients(search='id:{cid}') LIMIT 1")
            if labels:
                lbl = labels[0].get("labels") or []
                result[cid] = "quarantine" in [l.lower() for l in lbl]
        return result
    except Exception as e:
        log.warning("get_real_isolation_status error: %s", e)
        return {}


# ── Public API ────────────────────────────────────────────────────────────────

def _set_label(stub, client_id: str, label: str, remove: bool = False) -> None:
    """Adds or removes a Velociraptor client label."""
    try:
        op = "remove" if remove else "set"
        _vql(stub, f"SELECT label(client_id='{client_id}', labels='{label}', op='{op}') FROM scope()")
        log.info("Label '%s' %s for client %s", label, op, client_id)
    except Exception as e:
        log.warning("Label %s error client=%s: %s", op, client_id, e)


def isolate_host(agent_id: str, agent_name: str, hostname: str = None) -> tuple[bool, str]:
    stub = _get_stub()
    if not stub:
        return False, "Nepavyko prisijungti prie Velociraptor"

    search = hostname or agent_name
    client_id, os_type = _find_client(stub, search)
    if not os_type:
        return False, f"Velociraptor klientas '{search}' nerastas"

    artifact = "Windows.Remediation.Quarantine" if os_type == "windows" else "Linux.Remediation.Quarantine.IPTables"
    params = {"VelociraptorURL": VELOCIRAPTOR_URL} if VELOCIRAPTOR_URL and os_type == "windows" else {}
    ok, msg = _collect(stub, search, artifact, params)

    if ok and client_id:
        _set_label(stub, client_id, "quarantine", remove=False)

    log.info("[ISOLATE] agent=%s os=%s ok=%s msg=%s", agent_id, os_type, ok, msg)
    return (True, f"Hostas {agent_name} izoliuotas ({os_type})") if ok else (False, msg)


def unisolate_host(agent_id: str, agent_name: str, hostname: str = None) -> tuple[bool, str]:
    stub = _get_stub()
    if not stub:
        return False, "Nepavyko prisijungti prie Velociraptor"

    search = hostname or agent_name
    client_id, os_type = _find_client(stub, search)
    if not os_type:
        return False, f"Velociraptor klientas '{search}' nerastas"

    artifact = "Windows.Remediation.Quarantine" if os_type == "windows" else "Linux.Remediation.Quarantine.IPTables"
    ok, msg = _collect(stub, search, artifact, {"RemovePolicy": "True"})

    if ok and client_id:
        _set_label(stub, client_id, "quarantine", remove=True)

    log.info("[UNISOLATE] agent=%s os=%s ok=%s msg=%s", agent_id, os_type, ok, msg)
    return (True, f"Hostas {agent_name} atblokuotas ({os_type})") if ok else (False, msg)


# ── Flask routes ──────────────────────────────────────────────────────────────

@isolation_bp.route("/api/isolate/<agent_id>", methods=["POST"])
@login_required
def api_isolate(agent_id):
    import threading
    body       = request.get_json() or {}
    agent_name = body.get("agent_name", agent_id)
    hostname   = body.get("hostname", agent_name)
    reason     = body.get("reason", "Manual isolation")
    corr_id    = body.get("correlation_id")
    actor      = session.get("username", "system")

    def _do_isolate():
        ok, msg = isolate_host(agent_id, agent_name, hostname)
        log.info("[ISOLATE-BG] agent=%s ok=%s msg=%s", agent_id, ok, msg)
        if not ok:
            # Nerašome 'isolate' į DB jei Velociraptor nepavyko
            log.warning("[ISOLATE-BG] FAILED — DB nebus atnaujinta: %s", msg)
            return
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO audit_log(actor, action, target_type, target_id, details)
                    VALUES(%s, 'isolate', 'agent', %s, %s::jsonb)
                """, (
                    actor, agent_id,
                    json.dumps({"ok": ok, "msg": msg, "reason": reason,
                                "hostname": hostname, "correlation_id": corr_id}),
                ))
                if corr_id:
                    cur.execute("""
                        UPDATE correlations SET status='investigating',
                        summary = summary || ' [IZOLIUOTA]'
                        WHERE id=%s
                    """, (corr_id,))

    threading.Thread(target=_do_isolate, daemon=True).start()
    return jsonify({"ok": True, "message": f"Izoliacija paleista foniniame režime: {agent_name}"})


@isolation_bp.route("/api/unisolate/<agent_id>", methods=["POST"])
@login_required
def api_unisolate(agent_id):
    body       = request.get_json() or {}
    agent_name = body.get("agent_name", agent_id)
    hostname   = body.get("hostname", agent_name)
    reason     = body.get("reason", "Manual unisolation")

    ok, msg = unisolate_host(agent_id, agent_name, hostname)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_log(actor, action, target_type, target_id, details)
                VALUES(%s, 'unisolate', 'agent', %s, %s::jsonb)
            """, (
                session.get("username", "system"),
                agent_id,
                json.dumps({"ok": ok, "msg": msg, "reason": reason, "hostname": hostname}),
            ))

    return jsonify({"ok": ok, "message": msg})


@isolation_bp.route("/api/agents")
@login_required
def api_agents():
    agents = wazuh_api.get_agents()

    # Real isolation status from Velociraptor (by hostname match)
    stub = _get_stub()
    velo_clients = {}
    if stub:
        try:
            rows = _vql(stub, "SELECT client_id, os_info, labels FROM clients()")
            for r in rows:
                hn = (r.get("os_info") or {}).get("hostname", "").lower()
                lbls = r.get("labels") or []
                is_isolated = "quarantine" in [l.lower() for l in lbls]
                if hn:
                    velo_clients[hn] = is_isolated
        except Exception as e:
            log.warning("Velociraptor status check error: %s", e)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT ON (target_id)
                    target_id AS agent_id, action, happened_at, actor
                FROM audit_log
                WHERE action IN ('isolate', 'unisolate')
                ORDER BY target_id, happened_at DESC
            """)
            iso_map = {r["agent_id"]: dict(r) for r in cur.fetchall()}

    # Build sync list before opening a new connection
    from datetime import datetime, timezone, timedelta
    sync_actions = []
    SYNC_GRACE = timedelta(minutes=2)  # don't sync if last action was recent
    now_utc = datetime.now(timezone.utc)

    for ag in agents:
        ag_id = ag.get("id", "")
        ag_name = ag.get("name", "").lower()

        if ag_name in velo_clients:
            real_isolated = velo_clients[ag_name]
            ag["isolated"] = real_isolated

            iso = iso_map.get(ag_id)
            db_isolated = bool(iso and iso["action"] == "isolate")
            if real_isolated != db_isolated:
                # Skip sync if last action was very recent (race condition guard)
                last_at = iso.get("happened_at") if iso else None
                if last_at and (now_utc - last_at) < SYNC_GRACE:
                    log.debug("Isolation sync skipped (grace): agent=%s last=%s", ag_id, last_at)
                else:
                    action = "isolate" if real_isolated else "unisolate"
                    sync_actions.append((action, ag_id))
                    log.info("Isolation sync: agent=%s db=%s velo=%s -> %s", ag_id, db_isolated, real_isolated, action)
        else:
            iso = iso_map.get(ag_id)
            ag["isolated"] = bool(iso and iso["action"] == "isolate")

        iso = iso_map.get(ag_id)
        ag["isolation_actor"] = iso["actor"] if iso else None
        ag["isolation_at"]    = iso["happened_at"].isoformat() if iso and iso.get("happened_at") else None

    if sync_actions:
        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    for action, ag_id in sync_actions:
                        cur.execute("""
                            INSERT INTO audit_log (action, target_type, target_id, actor, details)
                            VALUES (%s, 'agent', %s, 'velociraptor_sync', '{}')
                        """, (action, ag_id))
        except Exception as e:
            log.warning("Isolation sync DB error: %s", e)

    return jsonify({"agents": agents})


@isolation_bp.route("/api/isolation/status")
@login_required
def api_isolation_status():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT ON (target_id)
                    target_id AS agent_id, action, actor, happened_at, details
                FROM audit_log
                WHERE action IN ('isolate', 'unisolate')
                ORDER BY target_id, happened_at DESC
            """)
            rows = cur.fetchall()

    isolated = [dict(r) for r in rows if r["action"] == "isolate"]
    return jsonify({"isolated_agents": isolated})
