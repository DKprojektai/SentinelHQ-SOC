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
from datetime import datetime, timezone, timedelta
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


def is_client_online(stub, client_id: str) -> bool:
    """
    Check if client is reachable RIGHT NOW by running a trivial VQL query on it.
    Returns True if the agent responds within timeout.
    """
    try:
        ok, rows, err = collect_artifact(stub, client_id, "Generic.Client.Info",
                                         timeout=30)
        log.info("is_client_online %s → ok=%s err=%s", client_id, ok, err)
        return ok
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


# ── Date range helpers ───────────────────────────────────────────────────────

def _detect_date_after(question: str) -> str | None:
    """Extract DateAfter (ISO 8601) from natural language time expressions."""
    q = question.lower()
    now = datetime.now(timezone.utc)

    # Specific phrases → fixed offsets
    _map = [
        (["paskutinį mėnesį", "last month", "per mėnesį", "per pastarąjį mėnesį"], 30 * 24),
        (["paskutines 2 savaites", "last 2 weeks"], 14 * 24),
        (["paskutinę savaitę", "last week", "per savaitę", "per 7 dien"], 7 * 24),
        (["šiandien", "today", "per dieną", "per 24", "last 24h", "last day"], 24),
        (["paskutines 2 valandas", "last 2 hours"], 2),
        (["paskutinę valandą", "last hour", "per valandą"], 1),
    ]
    for phrases, hours in _map:
        if any(p in q for p in phrases):
            return (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Pattern: last N weeks
    m_w = re.search(r'(\d+)\s*(?:sav\b|savait|week)', q)
    if m_w:
        return (now - timedelta(weeks=int(m_w.group(1)))).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Pattern: last N days / N dienų
    m_d = re.search(r'(\d+)\s*(?:dien|day)', q)
    if m_d:
        return (now - timedelta(days=int(m_d.group(1)))).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Pattern: last N hours / N valandų
    m_h = re.search(r'(\d+)\s*(?:val\b|valand|hour|h\b)', q)
    if m_h:
        return (now - timedelta(hours=int(m_h.group(1)))).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Pattern: last N minutes / N minučių
    m_m = re.search(r'(\d+)\s*(?:min\b|minut)', q)
    if m_m:
        return (now - timedelta(minutes=int(m_m.group(1)))).strftime("%Y-%m-%dT%H:%M:%SZ")

    return None


def _get_artifact_param_names(stub, artifact_name: str) -> set:
    """Return set of parameter names defined for given artifact."""
    try:
        rows = _vql(stub, f"SELECT parameters FROM artifact_definitions() WHERE name = '{artifact_name}'")
        if rows and rows[0].get("parameters"):
            params = rows[0]["parameters"]
            if isinstance(params, list):
                return {p.get("name", "") for p in params if p.get("name")}
    except Exception:
        pass
    return set()


# Parameter names that bound the collection to a time window (Velociraptor varies)
_TIME_PARAMS = ("DateAfter", "StartDate", "StartTime", "dateAfter", "after",
                "TimeAfter", "FromDate")


def _get_artifact_params(stub, artifact_name: str) -> list[dict]:
    """Return artifact parameter definitions [{name, default, type}, ...]."""
    try:
        rows = _vql(stub, f"SELECT parameters FROM artifact_definitions() WHERE name = '{artifact_name}'")
        if rows and isinstance(rows[0].get("parameters"), list):
            return rows[0]["parameters"]
    except Exception:
        pass
    return []


def _llm_choose_params(stub, question: str, artifact_names: list[str],
                       lang: str = "lt") -> dict:
    """Artifact parameters are not only time (globs, paths, yara, hashing, limits…).
    Ask the LLM ONCE to pick OPTIMAL parameter values per artifact for the question
    while LIMITING scope (no whole-disk scans), unless the user asked for broad scope.
    Returns {artifact: {param: value}}. Unknown/empty params are dropped."""
    import json as _json, re as _re2
    catalog: dict = {}
    for art in artifact_names:
        ps = _get_artifact_params(stub, art)
        if ps:
            catalog[art] = ps
    if not catalog:
        return {}
    lines = []
    for art, ps in catalog.items():
        lines.append(f"## {art}")
        for p in ps[:15]:
            d = (p.get("description") or "")[:80]
            lines.append(f"- {p.get('name')} (type={p.get('type') or '?'}, "
                         f"default={str(p.get('default'))[:40]!r}) {d}")
    listing = "\n".join(lines)
    sys = ("You configure Velociraptor artifact collection. For the user's question, choose "
           "OPTIMAL parameter values per artifact that ANSWER the question while LIMITING scope "
           "(narrow globs/paths, sensible time windows; NEVER scan the whole disk). "
           "Only include parameters you intentionally set; omit the rest to keep defaults. "
           "If the user explicitly asked for broad or specific scope, honor it. "
           'Return ONLY JSON: {"<artifact>": {"<param>": "<value>"}}. No prose.')
    user = f"Question: {question}\n\nArtifacts and parameters:\n{listing}"
    try:
        text, _ = _llmc.call(sys, user, max_tokens=400, temperature=0)
        data = _json.loads(_re2.search(r'\{.*\}', text, _re2.DOTALL).group())
    except Exception as e:
        log.warning("LLM param selection failed: %s — using artifact defaults", e)
        return {}
    out: dict = {}
    if isinstance(data, dict):
        for art, vals in data.items():
            if art in catalog and isinstance(vals, dict):
                names = {p.get("name") for p in catalog[art]}
                clean = {k: v for k, v in vals.items() if k in names and v not in (None, "", [])}
                if clean:
                    out[art] = clean
    log.info("LLM chose params for %d/%d artifacts", len(out), len(catalog))
    return out


def _artifact_time_bound(stub, artifact_name: str, question_date: str | None,
                         default_iso: str) -> tuple[dict | None, str]:
    """Decide the time window for an artifact, preferring (1) the user's question,
    (2) the artifact's OWN default for its time param, (3) a safety default.
    Returns (env_params_or_None, human_note)."""
    params = _get_artifact_params(stub, artifact_name)
    tparam = next((p for p in params if p.get("name") in _TIME_PARAMS), None)
    if not tparam:
        return None, "no time param — bounded by flow timeout + max_rows"
    name = tparam["name"]
    if question_date:
        return {name: question_date}, f"{name}={question_date} (from your question)"
    art_default = tparam.get("default")
    if art_default:
        # Artifact already bounds itself — let Velociraptor use its default
        return None, f"{name} default '{art_default}' (artifact's own limit)"
    # No user value, no artifact default → impose safety window
    return {name: default_iso}, f"{name}={default_iso} (safety default, 30d)"


# ── Artifact collection ───────────────────────────────────────────────────────

# Known timestamp fields per artifact — used for ORDER BY in retrieval VQL
_ARTIFACT_TS_FIELD: dict[str, str] = {
    "Windows.Applications.Chrome.History": "visit_time",
    "Windows.Applications.Edge.History":   "visit_time",
    "Windows.Applications.Firefox.History": "visit_time",
    "Windows.Applications.Chrome.Downloads": "start_time",
    "Windows.Applications.Edge.Downloads":  "start_time",
}

def collect_artifact(stub, client_id: str, artifact_name: str,
                     params: dict | None = None,
                     timeout: int = 90,
                     row_limit: int = 200,
                     cpu_limit: int = 80,
                     max_rows: int = 50000) -> tuple[bool, list[dict], str]:
    """
    Collect an artifact from a client. Waits for completion.
    Returns (success, rows, error_msg).

    Server-side safety limits sent to collect_client so a single collection can
    NEVER scan the whole machine indefinitely:
      timeout   — endpoint cancels the flow after this many seconds
      cpu_limit — caps endpoint CPU (%), so the machine stays responsive
      max_rows  — hard ceiling on rows the flow collects
    """
    # Server-side guards applied to every collection
    _guards = f"timeout={int(timeout)}, cpu_limit={int(cpu_limit)}, max_rows={int(max_rows)}"
    # Build collect_client VQL
    if params:
        env_pairs = ", ".join(f"{k}='{v}'" for k, v in params.items())
        collect_vql = f"""
            SELECT collect_client(
                client_id='{client_id}',
                artifacts=['{artifact_name}'],
                env=dict({env_pairs}),
                {_guards}
            ) FROM scope()
        """
    else:
        collect_vql = f"""
            SELECT collect_client(
                client_id='{client_id}',
                artifacts=['{artifact_name}'],
                {_guards}
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

    # Detect timestamp field for ORDER BY (newest-first retrieval)
    # Priority: known mapping → auto-detect from sample row → no ordering
    ts_field = _ARTIFACT_TS_FIELD.get(artifact_name)
    if not ts_field:
        # Fetch 1 sample row to detect timestamp field
        _sample = _vql(stub, f"""
            SELECT * FROM source(client_id='{client_id}',
                                 flow_id='{flow_id}',
                                 artifact='{artifact_name}')
            LIMIT 1
        """)
        if _sample:
            # First: try known high-priority names
            _TS_PRIORITY = ("EventTime", "Timestamp", "Time", "timestamp", "date",
                            "CreatedTime", "WriteTime", "LastWriteTime", "_ts",
                            "visited", "last_visit_time", "LastVisitTime", "visit_time",
                            "VisitTime", "AccessTime", "access_time", "mtime",
                            "CreateTime", "StartTime", "ModTime", "BTime", "CTime",
                            "MTime", "ATime")
            ts_field = next((f for f in _TS_PRIORITY if f in _sample[0]), None)
            # Fallback: any field whose name contains "time" or "date"
            if not ts_field:
                ts_field = next(
                    (f for f in _sample[0].keys()
                     if any(x in f.lower() for x in ("time", "_ts", "date"))
                     and isinstance(_sample[0][f], str) and "T" in str(_sample[0][f])),
                    None
                )
            if ts_field:
                # Cache for future calls
                _ARTIFACT_TS_FIELD[artifact_name] = ts_field
                log.info("Auto-detected ts_field='%s' for %s", ts_field, artifact_name)

    if ts_field:
        result_rows = _vql(stub, f"""
            SELECT *
            FROM source(client_id='{client_id}',
                        flow_id='{flow_id}',
                        artifact='{artifact_name}')
            ORDER BY {ts_field} DESC
            LIMIT {row_limit}
        """)
    else:
        result_rows = _vql(stub, f"""
            SELECT *
            FROM source(client_id='{client_id}',
                        flow_id='{flow_id}',
                        artifact='{artifact_name}')
            LIMIT {row_limit}
        """)

    # Results are now in result_rows and kept in SentinelHQ's session for follow-ups
    # (we never re-read the flow by id). Delete the server-side flow so the
    # Velociraptor datastore doesn't grow with every /velo query. Done via the
    # Server.Utils.DeleteFlow server artifact (fire-and-forget; best-effort).
    try:
        _vql(stub, f"""
            SELECT collect_client(
                client_id='server',
                artifacts=['Server.Utils.DeleteFlow'],
                env=dict(ClientId='{client_id}', FlowId='{flow_id}', ReallyDoIt='Y')
            ) FROM scope()
        """)
        log.info("Requested delete of flow %s on %s after retrieval", flow_id, client_id)
    except Exception as e:
        log.warning("flow delete failed for %s: %s", flow_id, e)

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
    "Extract 1-4 short English keywords for searching Velociraptor artifact names/descriptions. "
    "Use CANONICAL Windows/forensic terms, not literal user words: e.g. 'logon' (NOT 'login'), "
    "'authentication', 'account', 'eventlog', 'security'. Add close synonyms that improve recall. "
    "Return ONLY a JSON array of lowercase strings, nothing else. "
    "Examples: 'kokie procesai veikia?' → [\"process\"] ; "
    "'show browser history' → [\"browser\"] ; "
    "'tinklo ryšiai' → [\"network\"] ; "
    "'scheduled tasks' → [\"scheduled\"] ; "
    "'naršyklės istorija' → [\"browser\"] ; "
    "'guest login' → [\"logon\", \"authentication\"] ; "
    "'kas prisijungė' → [\"logon\", \"authentication\"] ; "
    "'kokie vartotojai' → [\"users\", \"account\"] ; "
    "'registry persistence' → [\"registry\", \"persistence\"] ; "
    "'dns cache' → [\"dns\"]"
)


def _llm_rank_artifacts(question: str, candidates: list[dict], lang: str = "lt",
                        top_k: int = 6) -> list[dict]:
    """Many keyword matches (often 50+) are too many to show. Take ALL candidates
    and ask the LLM to pick the few MOST relevant to the question. Falls back to
    the first top_k (keyword-score order) on any error."""
    if len(candidates) <= top_k:
        return candidates
    import json as _json, re as _re2
    pool = candidates[:60]  # cap prompt size
    listing = "\n".join(f"{i+1}. {c['name']} — {(c.get('description') or '')[:140]}"
                        for i, c in enumerate(pool))
    sys = ("You are a DFIR analyst selecting Velociraptor artifacts for a forensic "
           f"question. From the numbered list choose the {top_k} MOST relevant. "
           "Reply ONLY with a JSON array of the chosen 1-based numbers, best first. No prose.")
    user = f"Question: {question}\n\nArtifacts:\n{listing}"
    try:
        text, _ = _llmc.call(sys, user, max_tokens=80, temperature=0)
        arr = _json.loads(_re2.search(r'\[.*?\]', text, _re2.DOTALL).group())
        seen: set = set()
        out: list[dict] = []
        for n in arr:
            if isinstance(n, int) and 1 <= n <= len(pool):
                c = pool[n - 1]
                if c["name"] not in seen:
                    seen.add(c["name"])
                    out.append(c)
        if out:
            # Top up to top_k from score order if the LLM picked too few — avoids
            # showing just 1 artifact when several are reasonably relevant.
            if len(out) < top_k:
                _have = {c["name"] for c in out}
                for c in pool:
                    if c["name"] not in _have:
                        out.append(c)
                        if len(out) >= top_k:
                            break
            log.info("LLM ranked artifacts: %d candidates → %d shown", len(candidates), len(out))
            return out[:top_k]
    except Exception as e:
        log.warning("Artifact ranking failed: %s — falling back to top %d by score", e, top_k)
    return candidates[:top_k]


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
            text, _ = _llmc.call(_KW_EXTRACT_SYS, question, max_tokens=60, temperature=0)
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

        # ── Step 2: Direct Velociraptor regex search — score by keyword hits ────
        # Each artifact gets +1 per keyword that matches its name/description.
        # Multi-keyword query → full-match artifacts (score==n_kw) shown first.
        scored: dict[str, dict] = {}  # name → {description, score}
        unique_kws = list(dict.fromkeys(keywords))
        for kw in unique_kws:
            safe = kw.replace("'", "").replace('"', "")
            rows = _vql(stub, f"""
                SELECT name, description
                FROM artifact_definitions()
                WHERE name =~ '(?i){safe}' OR description =~ '(?i){safe}'
                ORDER BY name
                LIMIT 200
            """)
            for r in rows:
                name = r.get("name", "")
                if os_prefix and not (name.startswith(os_prefix) or name.startswith("Generic")):
                    continue
                if name not in scored:
                    scored[name] = {"description": r.get("description", ""), "score": 0}
                scored[name]["score"] += 1

        log.info("Velo search → %d artifacts (os_filter=%s, kws=%s)",
                 len(scored), os_prefix or "none", unique_kws)

        if scored:
            n_kw = len(unique_kws)
            # Full matches first, then partial, sorted alphabetically within each tier
            full    = sorted([(n, v) for n, v in scored.items() if v["score"] == n_kw],
                             key=lambda x: x[0])
            partial = sorted([(n, v) for n, v in scored.items() if v["score"] < n_kw],
                             key=lambda x: x[0])
            # If multi-keyword and full matches exist — return only full matches
            # Full (all-keyword) matches first, then partial — but DON'T drop partial
            # matches: requiring every keyword to match collapses the pool to ~1.
            # Hand the rich pool (best-scored first) to the LLM ranker to choose.
            result = full + partial
            _cands = [{"name": n, "description": v["description"]} for n, v in result]
            return _llm_rank_artifacts(question, _cands, lang)

        # ── Last resort: no OS filter ─────────────────────────────────────────
        seen: dict[str, str] = {}
        for kw in unique_kws:
            safe = kw.replace("'", "").replace('"', "")
            rows = _vql(stub, f"""
                SELECT name, description FROM artifact_definitions()
                WHERE name =~ '(?i){safe}' OR description =~ '(?i){safe}'
                ORDER BY name LIMIT 100
            """)
            for r in rows:
                seen[r.get("name", "")] = r.get("description", "")
        _cands = [{"name": n, "description": d} for n, d in seen.items()]
        return _llm_rank_artifacts(question, _cands, lang)

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
    Returns (answer, updated_history, all_rows) where all_rows = {artifact: {"rows": [...], "ts_key": str|None}}.
    """
    try:
        stub    = _get_stub()

        # Check agent is online before collecting
        if not is_client_online(stub, client_id):
            # Find last_seen for better diagnostics
            last_seen_str = ""
            try:
                rows = _vql(stub, "SELECT client_id, last_seen_at FROM clients()")
                for r in rows:
                    if r.get("client_id") == client_id:
                        last = r.get("last_seen_at") or 0
                        age_min = int((time.time() - last / 1_000_000) / 60)
                        last_seen_str = f" (last seen {age_min} min ago)" if lang == "en" else f" (paskutinį kartą matytas prieš {age_min} min)"
                        break
            except Exception:
                pass
            msg = (f"⚠️ Agent '{client_name}' is offline in Velociraptor. Cannot collect artifacts.{last_seen_str}"
                   if lang == "en" else
                   f"⚠️ Agentas '{client_name}' yra išjungtas Velociraptor. Negalima rinkti artefaktų.{last_seen_str}")
            return msg, list(history or []), {}

        context = []
        all_rows: dict = {}  # artifact -> {"rows": list, "ts_key": str|None}
        date_after = _detect_date_after(question)
        if date_after:
            log.info("Detected DateAfter from question: %s", date_after)
        # Safety window used only when neither the question nor the artifact's own
        # default bounds the time range — prevents "collect the whole machine's life".
        _default_iso = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        applied_filters: dict = {}   # artifact -> human-readable applied params
        art_bounded: dict = {}       # artifact -> bool (a time param was applied)
        # LLM picks OPTIMAL parameters (globs/paths/time/hashing/…) per artifact for
        # this question, scoped to avoid whole-machine scans. User-specified scope wins.
        chosen_params = _llm_choose_params(stub, question, artifact_names, lang)

        def _collect_one(artifact):
            # Time safety net first, then LLM-chosen params override/extend it.
            tparams, _ = _artifact_time_bound(stub, artifact, date_after, _default_iso)
            params = dict(tparams or {})
            params.update(chosen_params.get(artifact) or {})
            params = params or None
            art_bounded[artifact] = bool(params and any(k in _TIME_PARAMS for k in params))
            applied_filters[artifact] = (
                ", ".join(f"{k}={v}" for k, v in params.items()) if params
                else "defaults (bounded by flow timeout + max_rows)"
            )
            _row_limit = 5000 if (date_after or params) else 200
            try:
                return (artifact,) + collect_artifact(stub, client_id, artifact,
                                                       params=params, row_limit=_row_limit)
            except Exception as e:
                return artifact, False, [], str(e)

        # Collect all selected artifacts in PARALLEL. Sequential collection of ~6
        # live artifacts took minutes and tripped the UI reverse-proxy timeout
        # (HTTP 504 → HTML page → "Unexpected token '<'"). Threads cut wall time to
        # roughly the slowest single artifact.
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(4, max(1, len(artifact_names)))) as _ex:
            _collected = list(_ex.map(_collect_one, artifact_names))

        for artifact, ok, rows, err in _collected:
            log.info("Collected %s on %s (%s): ok=%s rows=%d",
                     artifact, client_name, client_id, ok, len(rows or []))
            if not ok:
                context.append(f"[{artifact}] Klaida: {err}")
                continue
            if not rows:
                context.append(f"[{artifact}] Rezultatų nerasta.")
                continue
            # Sort rows by timestamp field (newest first)
            # Priority: use known artifact-specific ts field first, then generic fallback
            _TS_FIELDS = ("EventTime", "Timestamp", "Time", "timestamp", "date",
                          "CreatedTime", "WriteTime", "LastWriteTime", "_ts",
                          "visit_time", "VisitTime", "visited",
                          "last_visit_time", "LastVisitTime",
                          "AccessTime", "access_time", "mtime")
            _known_ts = _ARTIFACT_TS_FIELD.get(artifact)
            if _known_ts and rows and _known_ts in rows[0]:
                _ts_key = _known_ts
            else:
                _ts_key = next((f for f in _TS_FIELDS if f in (rows[0] if rows else {})), None)
            log.info("Artifact %s: %d rows, ts_key=%s, first_row_keys=%s",
                     artifact, len(rows), _ts_key, list(rows[0].keys()) if rows else [])
            if rows and _ts_key:
                log.info("Artifact %s: first row ts value=%r", artifact, rows[0].get(_ts_key))
            if _ts_key:
                try:
                    sample = rows[0].get(_ts_key)
                    # Numeric timestamps (Chrome FILETIME, epoch) — sort as numbers
                    if isinstance(sample, (int, float)):
                        rows = sorted(rows, key=lambda r: r.get(_ts_key) or 0, reverse=True)
                    else:
                        rows = sorted(rows, key=lambda r: str(r.get(_ts_key) or ""), reverse=True)
                except Exception:
                    pass

            # Post-filter by date when the artifact had no server-side time param
            if date_after and not art_bounded.get(artifact):
                from datetime import datetime as _dt
                try:
                    cutoff = _dt.fromisoformat(date_after.replace("Z", "+00:00"))
                    def _row_ts(r):
                        v = r.get(_ts_key) if _ts_key else None
                        if v is None:
                            return None
                        if isinstance(v, (int, float)):
                            # Chrome FILETIME: microseconds since 1601-01-01
                            if v > 1e15:
                                from datetime import timedelta as _td
                                return _dt(1601, 1, 1, tzinfo=timezone.utc) + _td(microseconds=v)
                            # Unix epoch seconds
                            return _dt.fromtimestamp(v, tz=timezone.utc)
                        try:
                            return _dt.fromisoformat(str(v).replace("Z", "+00:00"))
                        except Exception:
                            return None
                    filtered = [r for r in rows if (_row_ts(r) is not None and _row_ts(r) >= cutoff)]
                    log.info("Post-filtered %s: %d/%d rows after %s", artifact, len(filtered), len(rows), date_after)
                    if filtered:
                        rows = filtered
                except Exception as fe:
                    log.warning("Post-filter error for %s: %s", artifact, fe)

            # Store full (post-filtered) rows for direct listing on follow-up
            all_rows[artifact] = {"rows": rows, "ts_key": _ts_key}

            # Format rows — when date filter active, sample evenly across the period
            # so LLM sees data spread over full time range, not just the newest 50
            total_rows = len(rows)
            max_display = 80
            if total_rows <= max_display:
                display_rows = rows
            elif date_after:
                # Evenly spaced sample: newest 20 + middle sample + oldest 20
                step = max(1, (total_rows - 40) // (max_display - 40))
                middle = rows[20: total_rows - 20: step][: max_display - 40]
                display_rows = rows[:20] + middle + rows[total_rows - 20:]
            else:
                display_rows = rows[:max_display]

            ts_label = ""
            if total_rows > 0 and _ts_key:
                first_ts = rows[-1].get(_ts_key, "?")   # oldest (list sorted DESC)
                last_ts  = rows[0].get(_ts_key, "?")    # newest
                ts_label = f" | {first_ts} → {last_ts}"
            lines = [f"[{artifact}] ({total_rows} eilučių{ts_label}, rodoma {len(display_rows)}):"]
            for r in display_rows:
                lines.append("  " + " | ".join(f"{k}={v}" for k, v in r.items()
                                                 if v not in (None, "", [], {}))[:200])
            context.append("\n".join(lines))

        ctx_text = "\n\n".join(context)
        if len(ctx_text) > 12000:
            ctx_text = ctx_text[:12000] + "\n...(sutrumpinta)"

        # LLM analysis
        _lvl = ("Wazuh levels: 0-3 info, 4-6 low, 7-9 medium, 10-11 high, 12-15 critical."
                if lang == "en" else
                "Wazuh lygiai: 0-3 info, 4-6 žemas, 7-9 vid., 10-11 aukštas, 12-15 kritinis.")
        _lim = "Answer under 3000 chars." if lang == "en" else "Atsakyk ne daugiau 3000 simbolių."
        _time_hint = (
            "Time units (LT/EN): min/minutė=minute, val/valanda=hour, "
            "dien/diena=day, sav/savaitė=week, mėn/mėnuo=month. "
            "E.g. '24 val'=24h, '30 min'=30min, '7 dien'=7 days."
        )

        if lang == "en":
            sys_p = (
                f"You are a forensic analyst. Analyse the Velociraptor artifact data below "
                f"and answer the user's question. {_lvl} {_time_hint} {_lim} "
                "Be concise. Highlight suspicious findings. "
                "At the very end add a short line 'ℹ️ Scope:' summarising the time "
                "filter / collection limit applied per artifact (given in the data)."
            )
        else:
            sys_p = (
                f"Tu esi forensikos analitikas. Išanalizuok žemiau pateiktus Velociraptor "
                f"artifact duomenis ir atsakyk į klausimą. {_lvl} {_time_hint} {_lim} "
                "Būk glaustas. Išryšlink įtartinus radinius. "
                "Pačioje pabaigoje pridėk trumpą eilutę 'ℹ️ Apimtis:' su pritaikytu laiko "
                "filtru / rinkimo apribojimu kiekvienam artefaktui (nurodyta duomenyse)."
            )

        _q_label   = "Question" if lang == "en" else "Klausimas"
        _d_label   = "Data"     if lang == "en" else "Duomenys"
        _lang_hint = " [RESPOND IN ENGLISH ONLY]" if lang == "en" else " [ATSAKYK TIK LIETUVIŠKAI]"

        # If time filter was applied — tell LLM explicitly so it doesn't re-interpret time units
        _filter_hint = ""
        if date_after:
            _filter_hint = (
                f"\n[Time filter applied: data contains only entries after {date_after}]"
                if lang == "en" else
                f"\n[Laiko filtras pritaikytas: duomenyse tik įrašai po {date_after}]"
            )

        # Per-artifact collection scope/limit — surfaced so the LLM can tell the user
        _limits_block = ""
        if applied_filters:
            _hdr = ("Collection scope applied per artifact"
                    if lang == "en" else "Pritaikytas rinkimo apribojimas pagal artefaktą")
            _limits_block = (f"\n[{_hdr}:\n"
                             + "\n".join(f"- {a}: {n}" for a, n in applied_filters.items())
                             + f"\n(server guards: flow timeout 90s, cpu_limit 80%, max_rows 50000)]")

        user_msg = f"{_q_label}: {question}{_lang_hint}{_filter_hint}{_limits_block}\n\n{_d_label}:\n{ctx_text}"
        messages = list(history or []) + [{"role": "user", "content": user_msg}]
        answer, _ = _llmc.call_multi(sys_p, messages, max_tokens=1200)

        new_history = messages + [{"role": "assistant", "content": answer}]
        return answer, new_history[-10:], all_rows

    except Exception as e:
        log.error("run_selected_artifacts error: %s", e)
        err_msg = (f"Error: {e}" if lang == "en" else f"Klaida: {e}")
        return err_msg, list(history or []), {}


def _format_raw_rows_compact(raw_rows: dict) -> str:
    """Format all collected rows compactly for LLM follow-up context.
    Each row: ts | primary_field (url/path/name) — max ~120 chars.
    Keeps full dataset visible to LLM without hitting context limits.
    """
    # Fields tried in order to pick the most informative non-ts value
    _URL_FIELDS  = ("url", "URL", "Url")
    _NAME_FIELDS = ("name", "Name", "Path", "path", "FullPath", "CommandLine",
                    "ProcessName", "Image", "TargetFilename", "FileName")
    parts: list[str] = []
    for art, art_data in raw_rows.items():
        art_rows = art_data.get("rows", [])
        ts_k     = art_data.get("ts_key")
        parts.append(f"\n[{art}] {len(art_rows)} rows:")
        for r in art_rows:
            seg: list[str] = []
            # Timestamp — trimmed to seconds
            if ts_k and ts_k in r:
                seg.append(str(r[ts_k])[:25])
            # Primary value: prefer URL, then name/path, then first non-ts field
            pval = None
            for f in _URL_FIELDS + _NAME_FIELDS:
                if r.get(f):
                    pval = str(r[f])
                    break
            if pval is None:
                pval = next((f"{k}={v}" for k, v in r.items()
                             if k != ts_k and v not in (None, "", [], {})), "")
            seg.append(pval[:100])
            parts.append(" | ".join(seg))
    return "\n".join(parts)


def run_followup(question: str, history: list[dict], lang: str = "lt",
                 raw_rows: dict | None = None) -> tuple[str, list[dict]]:
    """Answer a follow-up question using collected artifact data.
    raw_rows: full dataset from run_selected_artifacts — always included in context
    so LLM can answer any question (list, filter, count, aggregate) against full data.
    """
    _time_hint = (
        "Time units (LT/EN): min/minutė=minute, val/valanda=hour, "
        "dien/diena=day, sav/savaitė=week, mėn/mėnuo=month. "
        "E.g. '24 val'=24h, '30 min'=30min, '7 dien'=7 days."
    )
    _lim = "Answer under 4000 chars." if lang == "en" else "Atsakyk ne daugiau 4000 simbolių."
    if lang == "en":
        sys_p = (
            f"You are a forensic analyst. Full artifact dataset is provided below with "
            f"the question. Answer using the data — list, filter, count or aggregate as "
            f"requested. Never say you cannot access data. {_time_hint} {_lim} "
            "[RESPOND IN ENGLISH ONLY]"
        )
    else:
        sys_p = (
            f"Tu esi forenzikos analitikas. Pilnas artefaktų duomenų rinkinys pateiktas "
            f"žemiau kartu su klausimu. Atsakyk naudodamas duomenis — sąrašuok, filtruok, "
            f"skaičiuok ar agreguok pagal prašymą. Niekada nesakyk kad negali pasiekti duomenų. "
            f"{_time_hint} {_lim} [ATSAKYK TIK LIETUVIŠKAI]"
        )

    # Build user message: question + full compact dataset
    _data_ctx = ""
    if raw_rows:
        _compact = _format_raw_rows_compact(raw_rows)
        _label = "Full dataset" if lang == "en" else "Pilnas duomenų rinkinys"
        _data_ctx = f"\n\n{_label}:{_compact}"

    user_content = question + _data_ctx
    messages = list(history or []) + [{"role": "user", "content": user_content}]
    try:
        answer, _ = _llmc.call_multi(sys_p, messages, max_tokens=2000)
    except Exception as e:
        log.error("run_followup error: %s", e)
        answer = f"Error: {e}" if lang == "en" else f"Klaida: {e}"
    # Store only question (without full data) in history to avoid bloat
    history_user = {"role": "user", "content": question}
    new_history = list(history or []) + [history_user, {"role": "assistant", "content": answer}]
    return answer, new_history[-10:]
