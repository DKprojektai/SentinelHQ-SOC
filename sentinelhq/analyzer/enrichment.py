"""
SentinelHQ — Alert Enrichment
Extracts 4 key fields from Wazuh alerts for fingerprinting and XML generation.
"""

import hashlib
import re


def proc_name(path: str) -> str:
    """Extract just filename from process path. code.exe not C:\\Users\\..."""
    if not path:
        return ""
    # Handle both / and \ separators
    name = re.split(r'[/\\]', path.replace("\\\\", "\\"))[-1]
    return name.lower().strip()


def extract_enrichment(src: dict) -> dict:
    """
    Extract 4 enrichment fields from raw alert source.
    Returns: event_id, src_proc_name, dst_proc_name, mitre_id
    """
    data      = src.get("data", {})
    win       = data.get("win", {})
    eventdata = win.get("eventdata", {})
    system    = win.get("system", {})
    rule      = src.get("rule", {})
    mitre     = rule.get("mitre", {})

    # MITRE ID (e.g. "T1055" or "T1055|T1204")
    mitre_ids = mitre.get("id", [])
    mitre_id  = "|".join(mitre_ids) if mitre_ids else None

    # Sysmon event ID
    try:
        event_id = int(system.get("eventID") or 0)
    except (ValueError, TypeError):
        event_id = 0

    src_proc_name = None
    dst_proc_name = None

    if eventdata:
        if event_id == 1:
            # Process Create — who created what
            src_proc_name = proc_name(eventdata.get("parentImage", ""))
            dst_proc_name = proc_name(eventdata.get("image", ""))

        elif event_id == 3:
            # Network Connection — who connects where
            src_proc_name = proc_name(eventdata.get("image", ""))
            dst_proc_name = (
                eventdata.get("destinationHostname") or
                eventdata.get("destinationIp") or ""
            )[:200]

        elif event_id in (7, 11, 23):
            # Image Load / File Create / File Delete
            src_proc_name = proc_name(eventdata.get("image", ""))
            dst_proc_name = proc_name(
                eventdata.get("imageLoaded") or
                eventdata.get("targetFilename") or ""
            )

        elif event_id == 10:
            # Process Access — who accesses whom
            src_proc_name = proc_name(eventdata.get("sourceImage", ""))
            dst_proc_name = proc_name(eventdata.get("targetImage", ""))

        elif event_id in (12, 13, 14):
            # Registry events — strip SID/GUID to get stable key prefix
            import re as _re
            src_proc_name = proc_name(eventdata.get("image", ""))
            target = eventdata.get("targetObject") or ""
            # Strip SID (S-1-5-21-...) and everything after
            target = _re.split(r"S-1-[0-9-]+", target)[0]
            target = target.strip("/")
            # Strip GUID ({xxxxxxxx-...}) and everything after
            target = _re.split(r"[{][0-9a-fA-F]{8}-[0-9a-fA-F-]+[}]", target)[0]
            target = target.strip("/")
            dst_proc_name = target[:200] if target else None

        elif event_id == 22:
            # DNS Query — who queries what domain
            src_proc_name = proc_name(eventdata.get("image", ""))
            dst_proc_name = (eventdata.get("queryName") or "")[:200]

        else:
            # Fallback
            src_proc_name = proc_name(
                eventdata.get("sourceImage") or
                eventdata.get("image") or ""
            )
            dst_proc_name = proc_name(
                eventdata.get("targetImage") or
                eventdata.get("targetFilename") or
                eventdata.get("queryName") or ""
            )
    else:
        # Non-Windows alert
        src_proc_name = (
            data.get("srcip") or
            data.get("program_name") or
            data.get("srcuser") or ""
        )[:100]

    return {
        "event_id":      event_id or None,
        "src_proc_name": src_proc_name[:100] if src_proc_name else None,
        "dst_proc_name": dst_proc_name[:200] if dst_proc_name else None,
        "mitre_id":      mitre_id,
    }


def make_fingerprint(rule_id: str, agent_id: str,
                     src_proc_name: str, dst_proc_name: str) -> str:
    """
    Fingerprint = rule_id + agent_id + src_proc + dst_proc
    Same process pair on same agent = same fingerprint.
    """
    raw = f"{rule_id}|{agent_id}|{src_proc_name or ''}|{dst_proc_name or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def build_suppress_xml(wazuh_rule_id: int, c: dict) -> str:
    """
    Build precise Wazuh suppress XML based on event_id and proc names.
    """
    event_id      = c.get("event_id") or 0
    src_proc_name = c.get("src_proc_name") or ""
    dst_proc_name = c.get("dst_proc_name") or ""
    rule_id       = c["rule_id"]
    score         = c.get("noise_score", 0)
    desc          = (c.get("rule_desc") or "")[:80]

    def esc(s: str) -> str:
        """Escape regex special chars for Wazuh field matching."""
        return re.sub(r'([.+*?^${}()|[\]\\])', r'\\\1', s)

    agent_name = (c.get("agent_name") or "").strip()

    lines = [
        f'<!-- sentinelhq | score={score} | original_rule={rule_id} | event={event_id} | agent={agent_name} -->',
        f'<rule id="{wazuh_rule_id}" level="0">',
        f'  <if_sid>{rule_id}</if_sid>',
    ]

    # Always scope to specific agent — prevents suppressing other agents
    if agent_name:
        lines.append(f'  <hostname>{agent_name}</hostname>')

    if event_id == 1 and dst_proc_name:
        # Process Create — match by created process name
        lines.append(f'  <field name="win.eventdata.image">{esc(dst_proc_name)}</field>')
        if src_proc_name:
            lines.append(f'  <field name="win.eventdata.parentImage">{esc(src_proc_name)}</field>')

    elif event_id == 3 and dst_proc_name:
        # Network Connection — match by process + destination
        if src_proc_name:
            lines.append(f'  <field name="win.eventdata.image">{esc(src_proc_name)}</field>')
        lines.append(f'  <field name="win.eventdata.destinationHostname">{esc(dst_proc_name)}</field>')

    elif event_id == 10 and src_proc_name:
        # Process Access — match by source + target
        lines.append(f'  <field name="win.eventdata.sourceImage">{esc(src_proc_name)}</field>')
        if dst_proc_name:
            lines.append(f'  <field name="win.eventdata.targetImage">{esc(dst_proc_name)}</field>')

    elif event_id == 22 and dst_proc_name:
        # DNS Query — match by process + domain
        if src_proc_name:
            lines.append(f'  <field name="win.eventdata.image">{esc(src_proc_name)}</field>')
        lines.append(f'  <field name="win.eventdata.queryName">{esc(dst_proc_name)}</field>')

    elif event_id in (12, 13, 14) and dst_proc_name:
        # Registry — match by process + key
        if src_proc_name:
            lines.append(f'  <field name="win.eventdata.image">{esc(src_proc_name)}</field>')
        lines.append(f'  <field name="win.eventdata.targetObject">{esc(dst_proc_name)}</field>')

    elif event_id in (7, 11, 23) and src_proc_name:
        lines.append(f'  <field name="win.eventdata.image">{esc(src_proc_name)}</field>')
        if dst_proc_name:
            lines.append(f'  <field name="win.eventdata.imageLoaded">{esc(dst_proc_name)}</field>')

    else:
        # Fallback — generic match
        if src_proc_name:
            lines.append(f'  <match>{src_proc_name}</match>')

    # Build description
    parts = [desc]
    if src_proc_name:
        parts.append(f"src:{src_proc_name}")
    if dst_proc_name:
        parts.append(f"dst:{dst_proc_name}")
    full_desc = " | ".join(parts)[:120]

    lines += [
        f'  <description>SUPPRESSED (noise): {full_desc}</description>',
        f'  <options>no_log</options>',
        f'</rule>',
    ]
    return "\n".join(lines)
