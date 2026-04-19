# SentinelHQ — Diegimo instrukcija

> **Iki pilnai veikiančio AI-powered SOC jus skiria 15 minučių.**
> Versija: 1.1 | Kalba: Lietuvių

---

## Turinys

1. [Sistemos apžvalga](#1-sistemos-apžvalga)
2. [Reikalavimai](#2-reikalavimai)
3. [1 žingsnis — Wazuh diegimas](#3-1-žingsnis--wazuh-diegimas)
4. [2 žingsnis — Velociraptor diegimas](#4-2-žingsnis--velociraptor-diegimas)
5. [3 žingsnis — SentinelHQ diegimas](#5-3-žingsnis--sentinelhq-diegimas)
6. [4 žingsnis — Wazuh Active Response konfigūracija](#6-4-žingsnis--wazuh-active-response-konfigūracija)
7. [5 žingsnis — Telegram botas](#7-5-žingsnis--telegram-botas)
8. [6 žingsnis — LLM konfigūracija](#8-6-žingsnis--llm-konfigūracija)
9. [7 žingsnis — Agentų prijungimas](#9-7-žingsnis--agentų-prijungimas)
10. [Patikrinimas](#10-patikrinimas)
11. [Problemų sprendimas](#11-problemų-sprendimas)

---

## 1. Sistemos apžvalga

**SentinelHQ** — AI-powered SOC platforma, jungianti Wazuh SIEM, Velociraptor DFIR ir AI analizę į vieną valdymo centrą, valdoma tiesiog iš Telegram.

Įdiegę turėsite:
- **Realaus laiko AI analizę** kiekvienam saugumo alertui — tikra grėsmė ar triukšmas, nusprendžiama per sekundes
- **Telegram komandų centras** — izoliuokite kompiuterius, klauskite klausimų, tirkite incidentus iš telefono
- **`/ask` AI analitikas** — klauskite bet ko apie bet kurią mašiną natūralia kalba, gaukite atsakymus akimirksniu
- **Automatinis triukšmo nutildymas** — AI sugeneruotos Wazuh taisyklės, kurios nutildys klaidingus signalus visam laikui
- **Savaitinės PDF ataskaitos** — automatiškai siunčiamos jūsų klientams kiekvieną pirmadienį

Jokio debesies. Jokių prenumeratų. Veikia jūsų pačių serveryje.

```
OpenSearch (Wazuh Indexer)
         ↓
   [shq-collector]   — traukia alertus kas 10 sek
         ↓
    [PostgreSQL]
         ↓
   [shq-analyzer]    — noise scoring, suppress taisyklės
         ↓
    [shq-llm]        — AI dviejų etapų analizė + koreliacijos
         ↓
  ┌─────────────────────────┐
  │ [shq-dashboard] :8082   │  ← Admin UI + MFA
  │ [shq-portal]    :8083   │  ← Klientų portalas + MFA
  │ [shq-telegram]          │  ← Interaktyvus Telegram botas
  │ [shq-reporter]          │  ← PDF ataskaitos
  └─────────────────────────┘
```

### Komponentai

| Komponentas | Image / Versija | Paskirtis |
|---|---|---|
| **Wazuh Manager** | `wazuh/wazuh-manager:4.14.4` | SIEM — saugumo įvykių rinkimas |
| **Wazuh Indexer** | `wazuh/wazuh-indexer:4.14.4` | OpenSearch duomenų saugojimas |
| **Wazuh Dashboard** | `wazuh/wazuh-dashboard:4.14.4` | Wazuh UI |
| **Velociraptor** | `wlambert/velociraptor` (0.75.6) | DFIR — izoliacija, forensics |
| **shq-collector** | sentinelhq-collector | Alertai iš OpenSearch → PostgreSQL |
| **shq-analyzer** | sentinelhq-analyzer | Triukšmo aptikimas, suppress taisyklės |
| **shq-llm** | sentinelhq-llm-agent | AI analizė + atakų grandinės |
| **shq-telegram** | sentinelhq-telegram-bot | Interaktyvus botas su eskalavimo logika |
| **shq-dashboard** | sentinelhq-dashboard | Admin sąsaja su TOTP MFA |
| **shq-portal** | sentinelhq-portal | Klientų read-only portalas |
| **shq-reporter** | sentinelhq-reporter | Savaitinės PDF ataskaitos |

---

## 2. Reikalavimai

### Serverio reikalavimai

| Parametras | Minimalus | Rekomenduojamas |
|---|---|---|
| **CPU** | 4 branduoliai | 8 branduolių |
| **RAM** | 16 GB | 32 GB |
| **Diskas** | 100 GB SSD | 500 GB SSD |
| **OS** | Windows 10/11 arba Ubuntu 22.04 | Windows 11 / Ubuntu 22.04 |

### Programinė įranga

- **Docker Desktop** ≥ 4.x (Windows) arba **Docker Engine** ≥ 24.0 (Linux)
- **Docker Compose** ≥ 2.20 (įeina į Docker Desktop)
- **Git**
- Atviri prievadai: `1514`, `1515`, `55000`, `8000`, `8082`, `8083`, `8889`, `9200`

### Paskyros / API raktai

- [OpenRouter](https://openrouter.ai) arba kitas OpenAI-suderinamai LLM tiekėjas (API raktas)
- Telegram Bot Token (iš [@BotFather](https://t.me/botfather))
- Telegram Chat ID

---

## 3. 1 žingsnis — Wazuh diegimas

Wazuh diegiamas kaip Docker Compose `single-node` konfigūracija.

### 3.1 Parsisiųsti Wazuh Docker

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.4
cd wazuh-docker/single-node
```

### 3.2 Sugeneruoti sertifikatus

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

### 3.3 Paleisti

```bash
docker compose up -d
```

> ⏳ Pirmas paleidimas trunka ~3–5 minutes.

### 3.4 Patikrinimas

```bash
docker compose ps
# Turi rodyti: wazuh.manager, wazuh.indexer, wazuh.dashboard — visi "healthy"
```

- Wazuh Dashboard: `https://SERVERIO_IP` (prievadas 5601 arba 443)
- Numatytieji kredencialai: `admin` / `SecretPassword`

### 3.5 Slaptažodžių keitimas

Wazuh Dashboard → ☰ → Security → Internal users → Pakeisti `admin` ir `wazuh-wui` slaptažodžius.

### 3.6 Wazuh API patikrinimas

```bash
curl -k -u "wazuh-wui:JUSU_SLAPTAZODIS" \
  https://localhost:55000/security/user/authenticate
# Turi grąžinti JWT token
```

### 3.7 Suppress taisyklių failo sukūrimas

SentinelHQ rašo suppress taisykles į atskirą failą. Sukurti **vieną kartą**:

```bash
docker exec -it single-node-wazuh.manager-1 bash

cat > /var/ossec/etc/rules/sentinelhq_rules.xml << 'EOF'
<group name="sentinelhq_noise,">
</group>
EOF

exit
```

### 3.8 Sysmon konfigūracija (Windows agentams, rekomenduojama)

```powershell
# Windows PowerShell (kaip Administratorius)
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive Sysmon.zip
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmon.xml"
.\Sysmon\Sysmon64.exe -accepteula -i sysmon.xml
```

---

## 4. 2 žingsnis — Velociraptor diegimas

Velociraptor diegiamas kaip atskiras Docker konteineris naudojant `wlambert/velociraptor` image.

### 4.1 Klonuoti velociraptor-docker repozitoriją

```bash
# Rekomenduojama diegti šalia Wazuh katalogo
cd wazuh-docker/single-node
git clone https://github.com/weslambert/velociraptor-docker
cd velociraptor-docker
```

### 4.2 Konfigūruoti .env

```bash
cp .env.example .env  # arba sukurti naują
nano .env
```

```env
VELOX_USER=admin
VELOX_PASSWORD=stiprus-slaptazodis
VELOX_ROLE=administrator
VELOX_SERVER_URL=https://SERVERIO_IP:8000/
VELOX_FRONTEND_HOSTNAME=VelociraptorServer
```

### 4.3 Paleisti

```bash
docker compose up -d
```

Velociraptor GUI: `https://SERVERIO_IP:8889`

### 4.4 Sukurti API konfigūraciją SentinelHQ

```bash
# Prisijungti prie Velociraptor konteinerio
docker exec -it velociraptor bash

# Sukurti API vartotoją (jei dar nėra)
./velociraptor --config /velociraptor/server.config.yaml \
  user add sentinelhq --role administrator

# Eksportuoti API konfigūraciją
./velociraptor --config /velociraptor/server.config.yaml \
  config api_client --name sentinelhq \
  --output /velociraptor/sentinelhq_api.yaml

exit
```

### 4.5 Nukopijuoti API konfigūraciją į SentinelHQ

```bash
cp wazuh-docker/single-node/velociraptor-docker/velociraptor/sentinelhq_api.yaml \
   sentinelhq/sentinelhq_api.yaml
```

---

## 5. 3 žingsnis — SentinelHQ diegimas

### 5.1 Parsisiųsti

```bash
git clone https://github.com/DKprojektai/SentinelHQ-SOC.git sentinelhq
cd sentinelhq
```

### 5.2 Konfigūruoti .env

```bash
cp .env.example .env
nano .env
```

Būtini pakeitimai:

```env
# Organizacija
ORG_NAME=Jusu Imone
MANAGER_PUBLIC_IP=192.168.1.100      # ← Jusu serverio IP

# Wazuh
WAZUH_API_URL=https://wazuh.manager:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASS=jusu-wazuh-slaptazodis
WAZUH_NETWORK=single-node_default    # Wazuh Docker tinklo pavadinimas

# OpenSearch / Wazuh Indexer
OPENSEARCH_URL=https://wazuh.indexer:9200
OPENSEARCH_PASS=jusu-opensearch-slaptazodis

# Dashboard
DASHBOARD_USER=admin
DASHBOARD_PASS=stiprus-slaptazodis
SECRET_KEY=  # python3 -c "import secrets; print(secrets.token_hex(32))"

# LLM
LLM_API_URL=https://openrouter.ai/api/v1
LLM_API_KEY=sk-or-...
LLM_MODEL=google/gemini-2.5-flash

# Telegram
TELEGRAM_BOT_TOKEN=1234567890:AAB...
TELEGRAM_CHAT_ID=123456789

# DB
DB_PASS=stiprus-db-slaptazodis

# Velociraptor
VELOCIRAPTOR_URL=https://192.168.1.100:8000
```

> **Pastaba:** `WAZUH_NETWORK=single-node_default` — tai Wazuh Docker Compose sukurtas tinklas. Patikrinti: `docker network ls | grep single-node`

### 5.3 Patikrinti Wazuh tinklo pavadinimą

```bash
docker network ls
# Rasti tinklą su "single-node" pavadinimu, pvz: single-node_default
```

Jei pavadinimas kitoks — atitinkamai pakeisti `.env`.

### 5.4 Paleisti SentinelHQ

```bash
docker compose up -d --build
docker compose logs -f
```

> ⏳ Pirmas build'as trunka ~5–10 minučių.

### 5.5 Patikrinti servisus

```bash
docker compose ps
```

Visi konteineriai turi būti `running`:

| Konteineris | Statusas |
|---|---|
| shq-postgres | running (healthy) |
| shq-collector | running |
| shq-analyzer | running |
| shq-llm | running |
| shq-telegram | running |
| shq-dashboard | running |
| shq-portal | running |
| shq-reporter | running |

---

## 6. 4 žingsnis — Wazuh Active Response konfigūracija

SentinelHQ naudoja Wazuh Active Response agentų izolacijai tinkle. Konfigūruoti **vieną kartą**.

```bash
# Iš SentinelHQ katalogo
docker exec single-node-wazuh.manager-1 sh -c \
  "cat >> /var/ossec/etc/ossec.conf" < wazuh-config/sentinelhq_active_response.conf

# Patikrinti
docker exec single-node-wazuh.manager-1 \
  grep -q sentinelhq-isolation /var/ossec/etc/ossec.conf && echo "OK"

# Paleisti Wazuh iš naujo
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

---

## 7. 5 žingsnis — Telegram botas

### 7.1 Sukurti botą

1. Rašyti [@BotFather](https://t.me/botfather) Telegram
2. `/newbot` → įvesti pavadinimą → gauti **Bot Token**

### 7.2 Gauti Chat ID

1. Siųsti bet kokią žinutę botui
2. Atidaryti: `https://api.telegram.org/botTOKEN/getUpdates`
3. Rasti `"chat":{"id": NUMERIS}` — tai yra **Chat ID**

### 7.3 Patikrinimas

```bash
docker logs shq-telegram --tail=20
# Turi rodyti: "Bot started" arba "Polling..."
```

---

## 8. 6 žingsnis — LLM konfigūracija

### 8.1 OpenRouter (rekomenduojama)

```env
LLM_API_URL=https://openrouter.ai/api/v1
LLM_API_KEY=sk-or-v1-...
LLM_MODEL=google/gemini-2.5-flash
```

**Rekomenduojami modeliai:**

| Modelis | Kaina | Kokybė |
|---|---|---|
| `google/gemini-2.5-flash` | ~$0.001/1k | ⭐⭐⭐⭐⭐ |
| `google/gemini-2.5-flash` | ~$0.0005/1k | ⭐⭐⭐⭐ |
| `anthropic/claude-3-haiku` | ~$0.001/1k | ⭐⭐⭐⭐ |

### 8.2 Lokalus LLM (nemokamas)

**LM Studio:**
```env
LLM_API_URL=http://host.docker.internal:1234/v1
LLM_API_KEY=lm-studio
LLM_MODEL=llama-3.2-3b-instruct
```

**Ollama:**
```env
LLM_API_URL=http://host.docker.internal:11434/v1
LLM_API_KEY=ollama
LLM_MODEL=llama3.2
```

### 8.3 LLM agento aktyvavimas

Dashboard → 🤖 LLM Agentas → Toggle įjungti

> ⚠️ Rekomenduojama aktyvuoti po 3–7 dienų, kai suppress taisyklės sukurtos ir triukšmas sumažėja.

---

## 9. 7 žingsnis — Agentų prijungimas

### 9.1 Windows agentas (Wazuh)

Dashboard → 🖥️ Agentai → ➕ Prijungti agentą → Windows

Nukopijuoti ir paleisti sugeneruotą PowerShell skriptą **kaip Administratorius**.

### 9.2 Linux agentas

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
  https://packages.wazuh.com/4.x/apt/ stable main" | \
  tee /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER='SERVERIO_IP' apt-get install wazuh-agent
systemctl enable wazuh-agent && systemctl start wazuh-agent
```

### 9.3 Velociraptor klientas

Velociraptor klientų dvejetainiai failai automatiškai sukuriami konteinerio viduje ir pasiekiami per:

```
https://SERVERIO_IP:8889
```

Dashboard → 🖥️ Agentai → ➕ Prijungti agentą → Velociraptor → Windows

---

## 10. Patikrinimas

✅ `docker compose ps` — visi konteineriai `running`
✅ Dashboard: `http://SERVERIO_IP:8082`
✅ Portalas: `http://SERVERIO_IP:8083`
✅ Po ~30 sekundžių alertai pasirodo Apžvalgoje
✅ Telegram gauna pranešimus apie Lv9+ alertus

### Log'ų tikrinimas

```bash
docker compose logs -f shq-collector
docker compose logs -f shq-analyzer
docker compose logs -f shq-llm
docker compose logs -f shq-telegram
```

---

## 11. Problemų sprendimas

### ❌ Collector negauna alertų

```bash
docker logs shq-collector --tail=30
```

Patikrinti:
- `OPENSEARCH_PASS` teisingas
- `WAZUH_NETWORK` — tikslus Docker tinklo pavadinimas (`docker network ls`)
- Wazuh konteineriai veikia: `docker ps | grep wazuh`

### ❌ Wazuh API nepasiekiamas

```bash
curl -k -u "wazuh-wui:SLAPTAZODIS" \
  https://localhost:55000/security/user/authenticate
```

Jei `500` — patikrinti `WAZUH_API_PASS` `.env` faile.

### ❌ LLM neanalizuoja

```bash
docker logs shq-llm --tail=30
```

Patikrinti:
- `LLM_API_KEY` teisingas (Ping mygtukas Dashboard → LLM Agentas)
- LLM Agentas įjungtas Dashboard
- Alertų lygis ≥ 9

### ❌ Telegram neveikia

```bash
docker logs shq-telegram --tail=30
```

Patikrinti `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, siųsti `/start` botui.

### ❌ Suppress taisyklės neveikia

```bash
docker exec single-node-wazuh.manager-1 \
  ls /var/ossec/etc/rules/sentinelhq_rules.xml
```

Jei nėra — sukurti pagal 3.7 žingsnį.

### ❌ Izoliacija neveikia

Patikrinti:
- `sentinelhq_api.yaml` egzistuoja SentinelHQ kataloge
- Active Response konfigūruotas (6 žingsnis)
- Velociraptor veikia: `docker ps | grep velociraptor`
- `VELOCIRAPTOR_URL` teisingas (prievadas `8000`)

---

## Priedas — .env šablonas

```env
ORG_NAME=Jusu Imone
MANAGER_PUBLIC_IP=192.168.1.100

DB_NAME=sentinelhq
DB_USER=shq
DB_PASS=PAKEISTI

OPENSEARCH_URL=https://wazuh.indexer:9200
OPENSEARCH_USER=admin
OPENSEARCH_PASS=PAKEISTI
OPENSEARCH_INDEX=wazuh-alerts-*
WAZUH_VERIFY_SSL=false

WAZUH_API_URL=https://wazuh.manager:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASS=PAKEISTI
WAZUH_NETWORK=single-node_default

COLLECT_INTERVAL_SECONDS=10

ANALYZE_INTERVAL_SECONDS=600
NOISE_THRESHOLD_HOURLY=20
NOISE_WINDOW_HOURS=72
MIN_OCCURRENCES=10
RULE_ID_START=122000
RULE_ID_MAX=122999

LLM_API_URL=https://openrouter.ai/api/v1
LLM_API_KEY=PAKEISTI
LLM_MODEL=google/gemini-2.5-flash
LLM_POLL_INTERVAL=30

TELEGRAM_BOT_TOKEN=PAKEISTI
TELEGRAM_CHAT_ID=PAKEISTI

DASHBOARD_PORT=8082
DASHBOARD_USER=admin
DASHBOARD_PASS=PAKEISTI
SECRET_KEY=SUGENERUOTI

PORTAL_PORT=8083

VELOCIRAPTOR_URL=https://192.168.1.100:8000

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=jusu@email.com
SMTP_PASS=jusu-app-slaptazodis
REPORT_EMAIL_TO=klientas@imone.com
REPORT_DAY=monday
REPORT_HOUR=8

CORRELATE_INTERVAL=120
CORRELATE_WINDOW=10

TZ=Europe/Vilnius
```

---

*SentinelHQ — Kibernetinio saugumo stebėjimo platforma*
