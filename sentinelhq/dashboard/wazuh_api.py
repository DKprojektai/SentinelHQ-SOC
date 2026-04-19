"""
SentinelHQ — Wazuh API Helper
Handles authentication, rule file management, and manager restart.
"""

import os
import re
import logging
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)

WAZUH_URL   = os.environ.get("WAZUH_API_URL",  "https://wazuh.manager:55000")
WAZUH_USER  = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_PASS  = os.environ.get("WAZUH_API_PASS", "")
VERIFY_SSL  = os.environ.get("WAZUH_VERIFY_SSL", "false").lower() == "true"
RULES_FILE  = "sentinelhq_rules.xml"
GROUP_NAME  = "sentinelhq_noise"


def get_token() -> str:
    r = requests.post(
        f"{WAZUH_URL}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=VERIFY_SSL, timeout=10
    )
    r.raise_for_status()
    return r.json()["data"]["token"]


def get_headers() -> dict:
    return {"Authorization": f"Bearer {get_token()}"}


def get_rules_xml() -> str:
    """Get current sentinelhq_rules.xml content from Wazuh."""
    try:
        r = requests.get(
            f"{WAZUH_URL}/rules/files/{RULES_FILE}",
            headers=get_headers(),
            params={"raw": "true"},
            verify=VERIFY_SSL, timeout=10
        )
        if r.ok and "<group" in r.text:
            return r.text
    except Exception as e:
        log.debug("get_rules_xml error: %s", e)
    return f'<group name="{GROUP_NAME},">\n</group>\n'


def sanitize_rule_xml(rule_xml: str) -> str:
    """Fix XML issues that cause Wazuh to reject/delete rules."""

    # For registry targetObject — keep only first 4 key levels
    def fix_registry(m):
        val = m.group(1)
        parts = re.split(r'\\\\', val)
        if len(parts) > 4:
            val = '\\\\'.join(parts[:4])
        return f'<field name="win.eventdata.targetObject">{val}</field>'

    rule_xml = re.sub(
        r'<field name="win\.eventdata\.targetObject">(.*?)</field>',
        fix_registry,
        rule_xml,
        flags=re.DOTALL
    )

    return rule_xml


def is_alive() -> bool:
    """Check if Wazuh Manager API is reachable and responsive."""
    try:
        r = requests.post(
            f"{WAZUH_URL}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASS),
            verify=VERIFY_SSL, timeout=5
        )
        return r.status_code == 200
    except Exception:
        return False


def put_rules_xml(xml_content: str) -> tuple[bool, str]:
    """Upload sentinelhq_rules.xml to Wazuh."""
    if not is_alive():
        return False, "Wazuh Manager nepasiekiamas — palauk kol pasileis ir bandyk vėl"
    try:
        r = requests.put(
            f"{WAZUH_URL}/rules/files/{RULES_FILE}",
            headers={**get_headers(), "Content-Type": "application/octet-stream"},
            params={"overwrite": "true"},
            data=xml_content.encode("utf-8"),
            verify=VERIFY_SSL, timeout=15
        )
        if r.ok:
            data = r.json().get("data", {})
            if data.get("total_failed_items", 0) > 0:
                err = data["failed_items"][0]["error"]["message"]
                log.error("Wazuh rejected rule: %s", err)
                return False, err
            return True, "OK"
        log.error("put_rules_xml HTTP %s: %s", r.status_code, r.text[:200])
        return False, r.text[:100]
    except Exception as e:
        log.error("put_rules_xml error: %s", e)
        return False, str(e)


def add_rule(rule_xml: str) -> tuple[bool, str]:
    """Add a single rule to sentinelhq_rules.xml."""
    try:
        rule_xml = sanitize_rule_xml(rule_xml)
        current  = get_rules_xml()

        rule_id_match = re.search(r'<rule id="(\d+)"', rule_xml)
        if rule_id_match:
            rule_id = rule_id_match.group(1)
            if f'rule id="{rule_id}"' in current:
                log.info("Rule %s already in Wazuh", rule_id)
                return True, f"Rule {rule_id} already exists"

        new_content = current.replace(
            "</group>",
            f"\n{rule_xml.strip()}\n\n</group>"
        )

        ok, msg = put_rules_xml(new_content)
        if ok:
            log.info("Rule added: %s", rule_id_match.group(1) if rule_id_match else "?")
        return ok, msg

    except Exception as e:
        log.error("add_rule error: %s", e)
        return False, str(e)


def remove_rule(rule_id: int) -> tuple[bool, str]:
    """Remove a rule by ID from sentinelhq_rules.xml."""
    try:
        current = get_rules_xml()
        new_content = re.sub(
            r'<!--[^\n]*-->\n<rule id="' + str(rule_id) + r'".*?</rule>\n?',
            "", current, flags=re.DOTALL
        )
        return put_rules_xml(new_content)
    except Exception as e:
        log.error("remove_rule error: %s", e)
        return False, str(e)


def restart_manager() -> tuple[bool, str]:
    """Restart Wazuh manager."""
    try:
        r = requests.put(
            f"{WAZUH_URL}/manager/restart",
            headers=get_headers(),
            verify=VERIFY_SSL, timeout=15
        )
        if r.ok:
            return True, "Wazuh manager restartuojamas..."
        return False, r.text[:200]
    except Exception as e:
        return False, str(e)


def ping() -> tuple[bool, str]:
    """Check if Wazuh API is reachable."""
    try:
        get_token()
        return True, f"OK ({WAZUH_URL})"
    except Exception as e:
        return False, str(e)


def get_alert(alert_id: str) -> tuple[bool, dict]:
    """Fetch single alert from Wazuh indexer by document ID using _search."""
    import urllib3
    urllib3.disable_warnings()

    os_url  = os.environ.get("OPENSEARCH_URL", "https://wazuh.indexer:9200").rstrip("/")
    os_user = os.environ.get("OPENSEARCH_USER", "admin")
    os_pass = os.environ.get("OPENSEARCH_PASS", "SecretPassword")

    try:
        r = requests.post(
            f"{os_url}/wazuh-alerts-*/_search",
            auth=(os_user, os_pass),
            verify=False, timeout=10,
            json={"query": {"ids": {"values": [alert_id]}}, "size": 1}
        )
        if r.ok:
            hits = r.json().get("hits", {}).get("hits", [])
            if hits:
                return True, hits[0].get("_source", {})
        return False, {}
    except Exception as e:
        log.debug("get_alert error: %s", e)
        return False, {}



def get_agents() -> list:
    """Fetch all agents from Wazuh API."""
    try:
        r = requests.get(
            f"{WAZUH_URL}/agents",
            headers=get_headers(),
            params={"limit": 500, "select": "id,name,ip,os.name,os.platform,os.arch,status,lastKeepAlive,version"},
            verify=VERIFY_SSL, timeout=10
        )
        if r.ok:
            return r.json().get("data", {}).get("affected_items", [])
    except Exception as e:
        log.error("get_agents error: %s", e)
    return []


def get_next_free_rule_id(db_conn) -> int:
    """
    Get next free rule ID.
    Only IDs in Wazuh or deployed/active DB rules are considered used.
    Draft rules do NOT reserve IDs.
    """
    import re as _re

    rule_id_max   = int(os.environ.get("RULE_ID_MAX",   122999))
    rule_id_start = int(os.environ.get("RULE_ID_START", 122000))

    # Get IDs actually in Wazuh XML
    used = set()
    try:
        xml = get_rules_xml()
        for m in _re.finditer(r'<rule id="(\d+)"', xml):
            used.add(int(m.group(1)))
    except Exception:
        pass

    # Add ALL existing rule IDs from DB (any status) to avoid collisions
    with db_conn.cursor() as cur:
        cur.execute("""
            SELECT wazuh_rule_id FROM suppression_rules
            WHERE wazuh_rule_id IS NOT NULL
        """)
        for row in cur.fetchall():
            if row["wazuh_rule_id"]:
                used.add(row["wazuh_rule_id"])

    # Find first free ID
    for candidate in range(rule_id_start, rule_id_max + 1):
        if candidate not in used:
            return candidate

    raise RuntimeError(f"Rule ID range exhausted")
