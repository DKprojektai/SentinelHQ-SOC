"""
SentinelHQ — Analyzer utilities for dashboard on-demand use.
Shared logic: rule ID generation, XML building.
"""

import os
import re
import sys

# Add analyzer path for imports
_analyzer_path = "/app/../analyzer" if os.path.exists("/app") else \
                 os.path.join(os.path.dirname(__file__), "../analyzer")

RULE_ID_START = int(os.environ.get("RULE_ID_START", 122000))
RULE_ID_MAX   = int(os.environ.get("RULE_ID_MAX",   122999))


def next_rule_id_db(conn) -> int:
    """Get next available Wazuh rule ID from counter, skipping used IDs."""
    with conn.cursor() as cur:
        while True:
            cur.execute("SELECT next FROM rule_id_counter WHERE id=1 FOR UPDATE")
            current = cur.fetchone()["next"]
            if current > RULE_ID_MAX:
                raise RuntimeError(f"Rule ID range exhausted ({RULE_ID_START}-{RULE_ID_MAX})")
            cur.execute("UPDATE rule_id_counter SET next=%s WHERE id=1", (current + 1,))
            cur.execute("SELECT id FROM suppression_rules WHERE wazuh_rule_id=%s", (current,))
            if not cur.fetchone():
                return current


def build_suppress_xml_db(wazuh_rule_id: int, c: dict) -> str:
    """Build Wazuh suppress rule XML from candidate dict."""
    rule_id    = c.get("rule_id", "")
    agent_name = c.get("agent_name", "")
    src        = c.get("src_proc_name") or ""
    dst        = c.get("dst_proc_name") or ""
    rule_desc  = c.get("rule_desc", "")
    event_id   = c.get("event_id")
    mitre_id   = c.get("mitre_id", "")
    noise_score = c.get("noise_score", 0)
    fingerprint = c.get("fingerprint", "")

    def esc_re(s):
        return re.sub(r'([.+*?^${}()|[\]\\])', r'\\\1', s) if s else s

    def esc_xml(s):
        return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    lines = [
        f'<!-- sentinelhq | score={noise_score} | original_rule={rule_id} | event={event_id} | agent={agent_name} -->',
        f'<rule id="{wazuh_rule_id}" level="0">',
        f'  <if_sid>{rule_id}</if_sid>',
        f'  <hostname>{esc_xml(agent_name)}</hostname>',
    ]

    if event_id in (1,):  # ProcessCreate
        if src: lines.append(f'  <field name="win.eventdata.parentImage">{esc_xml(esc_re(src))}</field>')
        if dst: lines.append(f'  <field name="win.eventdata.image">{esc_xml(esc_re(dst))}</field>')
    elif event_id == 3:  # Network
        if src: lines.append(f'  <field name="win.eventdata.image">{esc_xml(esc_re(src))}</field>')
        if dst:
            # IP adresas → destinationIp, hostname → destinationHostname
            import re as _re
            ip_field = "destinationIp" if _re.match(r'^\d+\.\d+\.\d+\.\d+$', dst) else "destinationHostname"
            lines.append(f'  <field name="win.eventdata.{ip_field}">{esc_xml(esc_re(dst))}</field>')
    elif event_id == 10:  # ProcessAccess
        if src: lines.append(f'  <field name="win.eventdata.sourceImage">{esc_xml(esc_re(src))}</field>')
        if dst: lines.append(f'  <field name="win.eventdata.targetImage">{esc_xml(esc_re(dst))}</field>')
    elif event_id in (12, 13, 14):  # Registry
        if src: lines.append(f'  <field name="win.eventdata.image">{esc_xml(esc_re(src))}</field>')
        if dst:
            parts = re.split(r'\\\\', dst)
            short = '\\\\'.join(parts[:4]) if len(parts) > 4 else dst
            lines.append(f'  <field name="win.eventdata.targetObject">{esc_xml(short)}</field>')
    elif event_id == 22:  # DNS
        if src: lines.append(f'  <field name="win.eventdata.image">{esc_xml(esc_re(src))}</field>')
        if dst: lines.append(f'  <field name="win.eventdata.queryName">{esc_xml(esc_re(dst))}</field>')
    else:
        if src: lines.append(f'  <field name="win.eventdata.image">{esc_xml(esc_re(src))}</field>')

    short_desc = esc_xml(rule_desc[:100]) if rule_desc else f"SUPPRESSED: rule {rule_id}"
    lines.append(f'  <description>SUPPRESSED (noise): {short_desc} | src:{src} | dst:{dst}</description>')
    lines.append(f'  <options>no_log</options>')
    lines.append(f'</rule>')

    return "\n".join(lines)
