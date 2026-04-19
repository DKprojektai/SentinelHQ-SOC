"""
SentinelHQ — Velociraptor /velo engine
LLM-driven forensic artifact collection via Velociraptor gRPC API.

Flow:
  1. User asks a question
  2. LLM searches for relevant artifacts
  3. Bot shows list → user picks
  4. Bot collects artifact(s), waits for results
  5. LLM analyses and answers
"""

import json
import logging
import os
import re
import time
from typing import Any

import llm_client as _llmc

log = logging.getLogger(__name__)

VELOCIRAPTOR_API_CONFIG = os.environ.get("VELOCIRAPTOR_API_CONFIG", "/app/sentinelhq_api.yaml")
VELOCIRAPTOR_URL        = os.environ.get("VELOCIRAPTOR_URL", "192.168.1.177:8001")

WAZUH_URL  = os.environ.get("WAZUH_API_URL",  "https://wazuh.manager:55000")
WAZUH_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_PASS = os.environ.get("WAZUH_API_PASS", "")


# ── gRPC helpers ──────────────────────────────────────────────────────────────

def _get_stub():
    """Return a Velociraptor gRPC APIStub or raise."""
    import pyvelociraptor
    from pyvelociraptor import api_pb2_grpc
    import grpc

    config  = pyvelociraptor.LoadConfigFile(VELOCIRAPTOR_API_CONFIG)
    if isinstance(config, dict):
        ca   = config["ca_certificate"]
        key  = config["client_private_key"]
        cert = config["client_cert"]
        url  = config.get("api_connection_string", VELOCIRAPTOR_URL)
    else:
        ca   = config.ca_certificate
        key  = config.client_private_key
        cert = config.client_cert
        url  = getattr(config, "api_connection_string", VELOCIRAPTOR_URL)

    creds = grpc.ssl_channel_credentials(
        root_certificates=ca.encode(),
        private_key=key.encode(),
        certificate_chain=cert.encode(),
    )
    channel = grpc.secure_channel(url, creds,
        options=[("grpc.ssl_target_name_override", "VelociraptorServer")])
    return api_pb2_grpc.APIStub(channel)


def _vql(stub, query: str, env: dict | None = None, max_wait: int = 60) -> list[dict]:
    """Execute a VQL query and return list of row dicts."""
    from pyvelociraptor import api_pb2
    kwargs: dict = {
        "max_wait": max_wait,
        "Query": [api_pb2.VQLRequest(VQL=query)],
    }
    # env field name differs across pyvelociraptor versions
    if env:
        try:
            e = [api_pb2.VQLEnv(key=k, value=str(v)) for k, v in env.items()]
            kwargs["env"] = e
        except Exception:
            pass  # skip env if not supported
    req = api_pb2.VQLCollectorArgs(**kwargs)
    rows = []
    try:
        for resp in stub.Query(req):
            if resp.Response:
                rows.extend(json.loads(resp.Response))
    except Exception as exc:
        log.error("VQL error [%s]: %s", query[:80], exc)
    return rows


# ── Client resolution ─────────────────────────────────────────────────────────

def _ip_to_hostname_via_wazuh(ip: str) -> str | None:
    """
    Resolve an IP address to a hostname by querying the Wazuh API.
    Velociraptor shows internal Docker IPs, so real agent IPs must come from Wazuh.
    """
    try:
        import requests as _req, urllib3 as _u3
        _u3.disable_warnings(_u3.exceptions.InsecureRequestWarning)
        r = _req.post(f"{WAZUH_URL}/security/user/authenticate",
                      auth=(WAZUH_USER, WAZUH_PASS), verify=False, timeout=8)
        r.raise_for_status()
        token = r.json()["data"]["token"]
        r2 = _req.get(f"{WAZUH_URL}/agents",
                      headers={"Authorization": f"Bearer {token}"},
                      params={"ip": ip, "select": "name,ip", "limit": 5},
                      verify=False, timeout=8)
        if r2.ok:
            items = r2.json().get("data", {}).get("affected_items", [])
            if items:
                return items[0].get("name")
    except Exception as e:
        log.debug("_ip_to_hostname_via_wazuh error: %s", e)
    return None


def resolve_client(stub, hostname: str) -> tuple[str | None, str | None]:
    """
    Resolve hostname/IP to (client_id, display_name).
    If an IP is given, first resolves to hostname via Wazuh (Velociraptor
    shows internal Docker IPs which don't match real agent IPs).
    """
    import re as _re
    # If looks like an IP — resolve to hostname via Wazuh first
    if _re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', hostname):
        resolved = _ip_to_hostname_via_wazuh(hostname)
        if resolved:
            log.info("resolve_client: IP %s → hostname %s (via Wazuh)", hostname, resolved)
            hostname = resolved
        else:
            log.warning("resolve_client: could not resolve IP %s via Wazuh", hostname)

    rows = _vql(stub, f"SELECT client_id, os_info FROM clients(search='host:{hostname}')")
    if not rows:
        all_c = _vql(stub, "SELECT client_id, os_info FROM clients()")
        hn_l  = hostname.lower()
        rows  = [r for r in all_c
                 if (r.get("os_info") or {}).get("hostname", "").lower() == hn_l
                 or (r.get("os_info") or {}).get("fqdn", "").lower().startswith(hn_l)]
    if not rows:
        return None, None
    row  = rows[0]
    name = (row.get("os_info") or {}).get("hostname") or row["client_id"]
    return row["client_id"], name


def is_client_online(stub, client_id: str, max_age_sec: int = 300) -> bool:
    """
    Returns True if the client was seen within the last max_age_sec seconds.
    Velociraptor last_seen_at is in microseconds.
    """
    try:
        rows = _vql(stub, "SELECT client_id, last_seen_at FROM clients()")
        for r in rows:
            if r.get("client_id") == client_id:
                last = r.get("last_seen_at") or 0
                # last_seen_at is in microseconds
                age = time.time() - (last / 1_000_000)
                return age < max_age_sec
    except Exception as e:
        log.warning("is_client_online error: %s", e)
    return False


def list_clients(stub) -> list[dict]:
    """Return all online clients: [{client_id, hostname, os, last_seen}]"""
    rows = _vql(stub, """
        SELECT client_id,
               os_info.hostname AS hostname,
               os_info.system   AS os,
               last_seen_at
        FROM clients()
        ORDER BY last_seen_at DESC
    """)
    return rows


# ── Artifact search ───────────────────────────────────────────────────────────

def search_artifacts(stub, keyword: str, limit: int = 10) -> list[dict]:
    """
    Search artifact definitions by keyword in name or description.
    Returns [{name, description}]
    """
    kw = keyword.replace("'", "").replace('"', "")
    rows = _vql(stub, f"""
        SELECT name, description
        FROM artifact_definitions()
        WHERE name =~ '{kw}' OR description =~ '{kw}'
        ORDER BY name
        LIMIT {limit}
    """)
    return [{"name": r.get("name", ""), "description": r.get("description", "")} for r in rows]


# ── Artifact collection ───────────────────────────────────────────────────────

def collect_artifact(stub, client_id: str, artifact_name: str,
                     params: dict | None = None,
                     timeout: int = 90) -> tuple[bool, list[dict], str]:
    """
    Collect an artifact from a client. Waits for completion.
    Returns (success, rows, error_msg).
    """
    # Build collect_client VQL
    if params:
        env_pairs = ", ".join(f"{k}='{v}'" for k, v in params.items())
        collect_vql = f"""
            SELECT collect_client(
                client_id='{client_id}',
                artifacts=['{artifact_name}'],
                env=dict({env_pairs})
            ) FROM scope()
        """
    else:
        collect_vql = f"""
            SELECT collect_client(
                client_id='{client_id}',
                artifacts=['{artifact_name}']
            ) FROM scope()
        """

    rows = _vql(stub, collect_vql)
    if not rows:
        return False, [], "Velociraptor: no response to collect_client"

    # The response key is the full VQL expression — find flow_id anywhere in row
    row     = rows[0]
    flow_id = None
    for v in row.values():
        if isinstance(v, dict):
            flow_id = v.get("flow_id") or v.get("FlowId")
            if flow_id:
                break
    if not flow_id:
        return False, [], f"No flow_id returned: {row}"

    log.info("Collecting %s on %s → flow %s", artifact_name, client_id, flow_id)

    # Poll for completion
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(2)
        status_rows = _vql(stub, f"""
            SELECT state, total_collected_rows, total_expected_rows
            FROM flows(client_id='{client_id}', flow_id='{flow_id}')
        """)
        if not status_rows:
            continue
        state = status_rows[0].get("state", "")
        log.debug("Flow %s state: %s", flow_id, state)
        if state in ("FINISHED", "ERROR", "CANCELLED"):
            break
    else:
        return False, [], f"Timeout waiting for flow {flow_id}"

    if state == "ERROR":
        return False, [], f"Flow {flow_id} failed"

    # Fetch results
    result_rows = _vql(stub, f"""
        SELECT *
        FROM source(client_id='{client_id}',
                    flow_id='{flow_id}',
                    artifact='{artifact_name}')
        LIMIT 200
    """)

    return True, result_rows, ""


def run_vql_on_client(stub, client_id: str, vql_query: str,
                      timeout: int = 60) -> tuple[bool, list[dict], str]:
    """
    Run a raw VQL query on a specific client via schedserver.
    Falls back to server-side execution for non-client queries.
    """
    # Wrap in client scheduling
    collect_vql = f"""
        SELECT collect_client(
            client_id='{client_id}',
            artifacts=['Generic.Client.VQL'],
            env=dict(VQL='{vql_query.replace(chr(39), chr(34))}')
        ) FROM scope()
    """
    rows = _vql(stub, collect_vql)
    if not rows:
        return False, [], "No response"
    flow_id = (rows[0].get("collect_client") or {}).get("flow_id")
    if not flow_id:
        return False, [], "No flow_id"

    deadline = time.time() + timeout
    state = ""
    while time.time() < deadline:
        time.sleep(2)
        sr = _vql(stub, f"SELECT state FROM flows(client_id='{client_id}', flow_id='{flow_id}')")
        if sr:
            state = sr[0].get("state", "")
            if state in ("FINISHED", "ERROR", "CANCELLED"):
                break

    if state != "FINISHED":
        return False, [], f"Flow {flow_id} ended with state: {state}"

    result_rows = _vql(stub, f"""
        SELECT * FROM source(client_id='{client_id}', flow_id='{flow_id}',
                             artifact='Generic.Client.VQL')
        LIMIT 200
    """)
    return True, result_rows, ""


# ── LLM-driven artifact selection ────────────────────────────────────────────

_SUGGEST_SYS = (
    "You are a Velociraptor forensic expert. "
    "Given a user question (possibly in Lithuanian), suggest the most relevant "
    "Velociraptor artifact names to answer it. "
    "Return ONLY a JSON array of exact artifact names (up to 5). "
    "Use your full knowledge of Velociraptor artifact names. "
    "Examples: "
    "browser history/naršyklė → [\"Windows.Applications.Chrome.History\","
    "\"Windows.Applications.Firefox.History\",\"Windows.Applications.Edge.History\"], "
    "users/vartotojai → [\"Windows.Sys.Users\",\"Windows.Sys.LoggedInUsers\"], "
    "processes/procesai → [\"Windows.System.Pslist\",\"Windows.Events.TrackProcesses\"], "
    "DNS cache → [\"Windows.System.DNSCache\"], "
    "network connections/tinklo ryšiai → [\"Windows.Network.NetstatEnriched\",\"Windows.Network.Netstat\"], "
    "scheduled tasks/suplanuotos užduotys → [\"Windows.System.TaskScheduler\"], "
    "services/paslaugos → [\"Windows.System.Services\"], "
    "persistence/išlikimas → [\"Windows.Sys.Autoruns\",\"Windows.Persistence.PermanentWMIEvents\"], "
    "prefetch/paleidimų istorija → [\"Windows.Forensics.Prefetch\"], "
    "registry/registras → [\"Windows.Registry.Get\"], "
    "event logs/įvykiai → [\"Windows.EventLogs.EvtxHunter\"], "
    "files/failai → [\"Windows.Search.FileFinder\"], "
    "Linux users → [\"Linux.Sys.Users\",\"Linux.Sys.LoggedInUsers\"]. "
    "No explanation, no markdown — ONLY the JSON array of artifact names."
)


def _get_client_os(stub, client_id: str) -> str:
    """Return 'windows', 'linux', 'darwin', or '' for the given client."""
    rows = _vql(stub, "SELECT client_id, os_info FROM clients()")
    for r in rows:
        if r.get("client_id") == client_id:
            return ((r.get("os_info") or {}).get("system") or "").lower()
    return ""


def _validate_artifacts(stub, names: list[str]) -> list[dict]:
    """Check which artifact names actually exist in this Velociraptor instance."""
    if not names:
        return []
    # Build regex: match any of the names exactly
    import re as _re
    valid = []
    for name in names:
        safe = _re.escape(name)
        rows = _vql(stub, f"SELECT name, description FROM artifact_definitions() "
                          f"WHERE name =~ '^{safe}$' LIMIT 1")
        if rows:
            valid.append({"name": rows[0]["name"],
                          "description": rows[0].get("description", "")})
        else:
            log.debug("Artifact not found in this instance: %s", name)
    return valid


_KW_EXTRACT_SYS = (
    "Extract 1-3 short English keywords suitable for searching Velociraptor artifact names/descriptions. "
    "Return ONLY a JSON array of lowercase strings, nothing else. "
    "Examples: 'kokie procesai veikia?' → [\"process\"] ; "
    "'show browser history' → [\"browser\"] ; "
    "'tinklo ryšiai' → [\"network\"] ; "
    "'scheduled tasks' → [\"scheduled\"] ; "
    "'naršyklės istorija' → [\"browser\"] ; "
    "'kas prisijungė' → [\"logon\"] ; "
    "'registry persistence' → [\"registry\", \"persistence\"] ; "
    "'dns cache' → [\"dns\"]"
)


def find_relevant_artifacts(question: str, lang: str = "lt",
                             client_id: str | None = None) -> list[dict]:
    """
    1. LLM extracts 1-3 English keywords from question (any language → EN keywords)
    2. Direct Velociraptor regex search with those keywords (same engine as Velo UI)
    """
    import re as _re
    try:
        stub = _get_stub()

        # Determine OS for filtering
        os_str = ""
        if client_id:
            os_str = _get_client_os(stub, client_id)
        os_prefix = ""
        if "windows" in os_str:   os_prefix = "Windows"
        elif "linux" in os_str:   os_prefix = "Linux"
        elif "darwin" in os_str:  os_prefix = "Darwin"

        # ── Step 1: LLM extracts English keywords ────────────────────────────
        keywords: list[str] = []
        try:
            text, _ = _llmc.call(_KW_EXTRACT_SYS, question, max_tokens=60)
            m = _re.search(r'\[.*?\]', text.strip(), _re.DOTALL)
            if m:
                keywords = json.loads(m.group())
                keywords = [str(k).strip().lower() for k in keywords if k]
        except Exception as e:
            log.warning("Keyword extraction failed: %s", e)

        # Fallback: raw English words from question
        if not keywords:
            keywords = [w.lower() for w in _re.findall(r'[A-Za-z]{4,}', question)
                        if w.lower() not in ("what", "show", "list", "give", "find",
                                              "that", "this", "with", "from", "have",
                                              "does", "which", "about")][:3]

        log.info("Artifact search keywords for '%s': %s", question[:50], keywords)

        # ── Step 2: Direct Velociraptor regex search ─────────────────────────
        seen: dict[str, str] = {}
        for kw in dict.fromkeys(keywords):
            safe = kw.replace("'", "").replace('"', "")
            rows = _vql(stub, f"""
                SELECT name, description
                FROM artifact_definitions()
                WHERE name =~ '{safe}' OR description =~ '{safe}'
                ORDER BY name
                LIMIT 50
            """)
            for r in rows:
                name = r.get("name", "")
                if os_prefix and not (name.startswith(os_prefix) or name.startswith("Generic")):
                    continue
                seen[name] = r.get("description", "")

        log.info("Velo search → %d artifacts (os_filter=%s)", len(seen), os_prefix or "none")

        if seen:
            return [{"name": n, "description": d} for n, d in seen.items()]

        # ── Last resort: no OS filter ─────────────────────────────────────────
        for kw in dict.fromkeys(keywords):
            safe = kw.replace("'", "").replace('"', "")
            rows = _vql(stub, f"""
                SELECT name, description FROM artifact_definitions()
                WHERE name =~ '{safe}' OR description =~ '{safe}'
                ORDER BY name LIMIT 30
            """)
            for r in rows:
                seen[r.get("name", "")] = r.get("description", "")
        return [{"name": n, "description": d} for n, d in seen.items()]

    except Exception as e:
        log.error("find_relevant_artifacts error: %s", e)
        return []


# ── Main: run selected artifacts and analyse ──────────────────────────────────

def run_selected_artifacts(question: str, client_id: str, client_name: str,
                            artifact_names: list[str],
                            lang: str = "lt",
                            history: list[dict] | None = None) -> tuple[str, list[dict]]:
    """
    Collect selected artifacts and let LLM analyse results.
    Returns (answer, updated_history).
    """
    try:
        stub    = _get_stub()

        # Check agent is online before collecting
        if not is_client_online(stub, client_id):
            msg = (f"Agent '{client_name}' is offline or unreachable in Velociraptor."
                   if lang == "en" else
                   f"Agentas '{client_name}' yra išjungtas arba nepasiekiamas Velociraptor.")
            return msg, list(history or [])

        context = []

        for artifact in artifact_names:
            log.info("Collecting %s on %s (%s)", artifact, client_name, client_id)
            ok, rows, err = collect_artifact(stub, client_id, artifact)
            if not ok:
                context.append(f"[{artifact}] Klaida: {err}")
                continue
            if not rows:
                context.append(f"[{artifact}] Rezultatų nerasta.")
                continue
            # Format rows
            lines = [f"[{artifact}] ({len(rows)} eilučių):"]
            for r in rows[:50]:  # limit to 50 rows per artifact
                lines.append("  " + " | ".join(f"{k}={v}" for k, v in r.items()
                                                 if v not in (None, "", [], {}))[:200])
            context.append("\n".join(lines))

        ctx_text = "\n\n".join(context)
        if len(ctx_text) > 8000:
            ctx_text = ctx_text[:8000] + "\n...(sutrumpinta)"

        # LLM analysis
        _lvl = ("Wazuh levels: 0-3 info, 4-6 low, 7-9 medium, 10-11 high, 12-15 critical."
                if lang == "en" else
                "Wazuh lygiai: 0-3 info, 4-6 žemas, 7-9 vid., 10-11 aukštas, 12-15 kritinis.")
        _lim = "Answer under 3000 chars." if lang == "en" else "Atsakyk ne daugiau 3000 simbolių."

        if lang == "en":
            sys_p = (
                f"You are a forensic analyst. Analyse the Velociraptor artifact data below "
                f"and answer the user's question. {_lvl} {_lim} "
                "Be concise. Highlight suspicious findings."
            )
        else:
            sys_p = (
                f"Tu esi forensikos analitikas. Išanalizuok žemiau pateiktus Velociraptor "
                f"artifact duomenis ir atsakyk į klausimą. {_lvl} {_lim} "
                "Būk glaustas. Išryšlink įtartinus radinius."
            )

        _q_label   = "Question" if lang == "en" else "Klausimas"
        _d_label   = "Data"     if lang == "en" else "Duomenys"
        _lang_hint = " [RESPOND IN ENGLISH ONLY]" if lang == "en" else " [ATSAKYK TIK LIETUVIŠKAI]"
        user_msg = f"{_q_label}: {question}{_lang_hint}\n\n{_d_label}:\n{ctx_text}"
        messages = list(history or []) + [{"role": "user", "content": user_msg}]
        answer, _ = _llmc.call_multi(sys_p, messages, max_tokens=1200)

        new_history = messages + [{"role": "assistant", "content": answer}]
        return answer, new_history[-10:]

    except Exception as e:
        log.error("run_selected_artifacts error: %s", e)
        err_msg = (f"Error: {e}" if lang == "en" else f"Klaida: {e}")
        return err_msg, list(history or [])
