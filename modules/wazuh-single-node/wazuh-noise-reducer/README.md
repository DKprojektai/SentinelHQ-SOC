# Wazuh Noise Reducer

Automatinis Wazuh false positive / triukšmo identifikavimo ir slopinimo įrankis.

## Kaip veikia

```
Wazuh API → [Collector] → SQLite → [Analyzer] → [Dashboard] → Wazuh XML
```

1. **Collector** kas 2 min. traukia alertus iš Wazuh REST API
2. **Analyzer** kas 10 min. analizuoja fingerprint grupes pagal:
   - Dažnį (alerts/valandą vs slenkstis)
   - Pasikartojimą (ta pati kombinacija rule+agent+location)
   - Pasiskirstymą agentams (tas pats rule_id daug agentų)
   - Lygio baudą (high severity = mažiau tikėtinas triukšmas)
3. **Dashboard** rodo kandidatus, leidžia approve/dismiss
4. **Export** generuoja `local_rules.xml` tiesiai į Wazuh formatą

## Greitas startas

```bash
# 1. Klonuok arba nukopijuok projektą
cp .env.example .env

# 2. Pakeisk kredencialus .env faile
nano .env

# 3. Paleisk
docker compose up -d

# 4. Atidaryk naršyklėje
open http://localhost:8080
```

## .env konfigūracija

| Kintamasis | Numatyta | Aprašymas |
|---|---|---|
| `WAZUH_API_URL` | — | Wazuh manager URL su portu (55000) |
| `WAZUH_USER` | wazuh | API vartotojas |
| `WAZUH_PASS` | — | API slaptažodis |
| `WAZUH_VERIFY_SSL` | false | SSL sertifikato tikrinimas |
| `COLLECT_INTERVAL_SECONDS` | 120 | Alertų traukimo intervalas |
| `NOISE_THRESHOLD_HOURLY` | 20 | alerts/h slenkstis triukšmui |
| `NOISE_WINDOW_HOURS` | 72 | Analizės lango ilgis valandomis |
| `MIN_OCCURRENCES` | 10 | Min. kartų, kad taptų kandidatu |
| `DASHBOARD_PORT` | 8080 | Dashboard prievadas |

## Noise scoring algoritmas

```
score = frequency_score (0-40)
      + repetition_score (0-30)
      + spread_score     (0-15)
      - level_penalty    (0-40 jei level >= 7)

score >= 60 → noise kandidatas
score >= 75 → didelė tikimybė triukšmas
```

## Wazuh XML diegimas

1. Atsisiųsk iš Export → Download local_rules.xml
2. Merge į `/var/ossec/etc/rules/local_rules.xml`
3. Patikrink: `ossec-logtest`
4. Paleisk iš naujo: `systemctl restart wazuh-manager`

## Konteinerių sveikatos tikrinimas

```bash
docker compose logs -f collector
docker compose logs -f analyzer
docker compose logs -f dashboard
```

## Duomenų vieta

- SQLite DB: Docker volume `wnr-data` → `/data/alerts.db`
- Eksportuoti XML failai: `./rules_export/` kataloge

## Reset

```bash
docker compose down -v   # ištrina visus duomenis
docker compose up -d
```
