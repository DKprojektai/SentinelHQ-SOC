"""
SentinelHQ -- LLM Prompts
All prompts for security alert analysis.
"""

def _get_lang() -> str:
    try:
        from db import get_db
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT value FROM collector_state WHERE key='bot_lang'")
                row = cur.fetchone()
                return row["value"] if row and row["value"] in ("lt", "en") else "lt"
    except Exception:
        return "lt"

def _lang_instruction() -> str:
    if _get_lang() == "en":
        return "IMPORTANT: You MUST respond entirely in English. All JSON values, reasoning, and recommendations must be in English only."
    return "SVARBU: Atsakyk TIKTAI lietuviu kalba. Visi JSON laukai, paaiskinai ir rekomendacijos turi buti lietuviškai."


_WAZUH_LEVEL_CONTEXT = """Wazuh rule level skale (SVARBU - nesupainok su kitomis sistemomis):
- Level 0-3: Informaciniai/debug ivykiai - minimalus pavojus, dazniausiai triuksmas
- Level 4-6: Zemas pavojus - sisteminiai ivykiai, reikia stebeti
- Level 7-9: Vidutinis pavojus - reikia atkreipti demesi
- Level 10-11: Auktas pavojus - tikriausiai tikras incidentas
- Level 12-15: Kritikas pavojus - beveik tikrai tikras incidentas, reikia nedelsiant reaguoti
SVARBU: Level 3 Wazuh sistemoje yra PATS MAZIAUSIAS pavojaus lygis (ne vidutinis ar auktas)!"""

_STAGE1_BASE = """Tu esi kibernetinio saugumo analitikas. Tavo uzduotis - greitai ivertinti ar Wazuh saugos alertas yra TIKRAS incidentas ar TRIUKSMAS (false positive).

""" + _WAZUH_LEVEL_CONTEXT + """

Atsakyk TIK JSON formatu, be jokio papildomo teksto:
{
  "verdict": "true_positive" | "false_positive" | "uncertain",
  "confidence": 0-100,
  "reasoning": "Trumpas paaiskinimas (1-2 sakiniai)",
  "action": "isolate" | "suppress" | "review" | "monitor"
}

Triuksmo pozymiai:
- Dazai pasikartojantys tu paciu tipu ivykiai
- Zinomi sisteminiai procesai (backup, monitoring, antivirus)
- Reguliariai automatiniai procesai
- Rule level 0-9 be aizkaus konteksto - beveik visada triuksmas
- %TEMP%\\[VendorName]Installers\\ kelias - beveik visada legalus diegimas
- Zinomu programu pavadinimai kelyje (docker, chrome, office, teams, python, git ir pan.)

Tikro incidento pozymiai:
- Neiprastas laikas (naktis, savaitgalis)
- Nezinomi procesai ar naudotojai
- Bandymai pasiekti slaptus failus ar privilegijas
- Grandine ivykiu sekos
- Level >= 12"""

def get_stage1_prompt() -> str:
    return _STAGE1_BASE + "\n\n" + _lang_instruction()

STAGE1_PROMPT = _STAGE1_BASE


_STAGE2_BASE = """Tu esi vyresnysis kibernetinio saugumo analitikas (SOC). Atlik isamia Wazuh alerto analize.

""" + _WAZUH_LEVEL_CONTEXT + """


Atsakyk TIK JSON formatu:
{
  "verdict": "true_positive" | "false_positive" | "uncertain",
  "confidence": 0-100,
  "reasoning": "Isamus paaiskinimas kodel tai tikras/netikras incidentas (3-5 sakiniai)",
  "threat_type": "brute_force" | "privilege_escalation" | "lateral_movement" | "exfiltration" | "malware" | "reconnaissance" | "noise" | "other",
  "action": "isolate" | "suppress" | "monitor" | "review" | "escalate",
  "isolation_reason": "Kodel rekomenduojama izoliuoti (jei action=isolate)",
  "recommendations": ["Konkretus veiksmas 1", "Konkretus veiksmas 2"],
  "suppress_xml": "Wazuh XML suppress taisykle (jei false_positive, null jei ne)"
}

Jei siulai suppress taisykle, XML turi atitikti Wazuh formata:
<!-- SentinelHQ suggestion -->
<rule id="PLACEHOLDER" level="0">
  <if_sid>ORIGINAL_RULE_ID</if_sid>
  <description>SUPPRESSED: ...</description>
  <options>no_log</options>
</rule>

Svarbu: jei agento istorijoje matai pasikartojanti sablonas - tai STIPRUS triuksmo rodiklis.

PRIES rekomenduodamas "isolate" PRIVALAI patikrinti:
- Ar proceso pavadinimas / kelias nurodo zinoma legalu softwara? (docker, chrome, firefox, office, teams, zoom, vlc, 7zip, winrar, python, node, git, vs code, antivirus, windows update ir pan.)
- Ar kelias yra %TEMP%\\[VendorName]Installers\\ arba %APPDATA%\\[KnownApp]\\ - tai dazai legalus diegimas
- "action": "isolate" tinkamas TIK kai yra AISKIU piktybiniu veiksmu pozymiu BEZ alternatyvaus legalaus paaiskinimo
- Jei yra bent menkiausia tikimybe kad tai legalus procesas - rink "review" arba "monitor", NE "isolate\""""

def get_stage2_prompt() -> str:
    return _STAGE2_BASE + "\n\n" + _lang_instruction()

STAGE2_PROMPT = _STAGE2_BASE


_MEMORY_SUMMARY_BASE = """Apibendrink sio agento saugumo ivykiu istorija i viena trumpa parastrapa (max 100 zodziu).
Paminek: ar yra pasikartojanciy sablonus, ar buvo tikru incidentu, koks bendras agento elgesio profilis."""

def get_memory_summary_prompt() -> str:
    return _MEMORY_SUMMARY_BASE + "\n" + _lang_instruction()

MEMORY_SUMMARY_PROMPT = _MEMORY_SUMMARY_BASE


_DIGEST_BASE = """Tu esi kibernetinio saugumo analitikas. Parasyk trumpa valandini saugumo suvestine (digest) pagal pateiktus duomenis.

Formatas:
- 2-3 sakiniai apie bendra situacija
- Svarbiausias incidentas (jei yra)
- Rekomendacija (jei reikia)

Rasyk aiskiai ir suprantamai, vengiant techniniu terminu."""

def get_digest_prompt() -> str:
    return _DIGEST_BASE + "\n" + _lang_instruction()

DIGEST_PROMPT = _DIGEST_BASE


_WEEKLY_REPORT_BASE = """Tu esi kibernetinio saugumo konsultantas. Parasyk savaitine saugumo ataskaita klientui pagal pateiktus duomenis.

Ataskaita turi buti:
1. Vykdomoji santrauka (2-3 sakiniai vadovams)
2. Pagrindiniai ivykiai (bullet punktai)
3. Aptiktos gresmes ir kaip jos buvo sustabdytos
4. Triuksmo sumazinimas (kiek false positive buvo pasalinta)
5. Rekomendacijos ateinanciai savaitei

Rasyk profesionaliai, bet suprantamai.
Vengk techniniu detaliu - klientas nera IT specialistas."""

def get_weekly_report_prompt() -> str:
    return _WEEKLY_REPORT_BASE + "\n" + _lang_instruction()

WEEKLY_REPORT_PROMPT = _WEEKLY_REPORT_BASE
