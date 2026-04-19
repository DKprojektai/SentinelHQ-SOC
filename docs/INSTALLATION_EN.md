# SentinelHQ — Installation Guide

> **You're 15 minutes away from a fully operational AI-powered SOC.**
> Version: 1.1 | Language: English

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Requirements](#2-requirements)
3. [Step 1 — Wazuh Installation](#3-step-1--wazuh-installation)
4. [Step 2 — Velociraptor Installation](#4-step-2--velociraptor-installation)
5. [Step 3 — SentinelHQ Installation](#5-step-3--sentinelhq-installation)
6. [Step 4 — Wazuh Active Response Configuration](#6-step-4--wazuh-active-response-configuration)
7. [Step 5 — Telegram Bot](#7-step-5--telegram-bot)
8. [Step 6 — LLM Configuration](#8-step-6--llm-configuration)
9. [Step 7 — Connecting Agents](#9-step-7--connecting-agents)
10. [Verification](#10-verification)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. System Overview

**SentinelHQ** is an AI-powered SOC platform that unifies Wazuh SIEM, Velociraptor DFIR, and AI analysis into a single management center — operated entirely from Telegram.

Once installed, you'll have:
- **Real-time AI analysis** of every security alert — true threat or noise, decided in seconds
- **Telegram command center** — isolate machines, ask questions, investigate incidents from your phone
- **`/ask` AI analyst** — ask anything about any machine in natural language, get instant answers
- **Automatic noise suppression** — AI-generated Wazuh rules that silence false positives forever
- **Weekly PDF reports** — sent automatically to your clients every Monday

No cloud required. No subscriptions. Runs on your own server.

```
OpenSearch (Wazuh Indexer)
         ↓
   [shq-collector]   — pulls alerts every 10 sec
         ↓
    [PostgreSQL]
         ↓
   [shq-analyzer]    — noise scoring, suppress rules
         ↓
    [shq-llm]        — two-stage AI analysis + correlations
         ↓
  ┌─────────────────────────┐
  │ [shq-dashboard] :8082   │  ← Admin UI + MFA
  │ [shq-portal]    :8083   │  ← Client portal + MFA
  │ [shq-telegram]          │  ← Interactive Telegram bot
  │ [shq-reporter]          │  ← PDF reports
  └─────────────────────────┘
```

### Components

| Component | Image / Version | Purpose |
|---|---|---|
| **Wazuh Manager** | `wazuh/wazuh-manager:4.14.4` | SIEM — security event collection |
| **Wazuh Indexer** | `wazuh/wazuh-indexer:4.14.4` | OpenSearch data storage |
| **Wazuh Dashboard** | `wazuh/wazuh-dashboard:4.14.4` | Wazuh UI |
| **Velociraptor** | `wlambert/velociraptor` (0.75.6) | DFIR — isolation, forensics |
| **shq-collector** | sentinelhq-collector | Alerts from OpenSearch → PostgreSQL |
| **shq-analyzer** | sentinelhq-analyzer | Noise detection, suppress rules |
| **shq-llm** | sentinelhq-llm-agent | AI analysis + attack chain detection |
| **shq-telegram** | sentinelhq-telegram-bot | Interactive bot with escalation logic |
| **shq-dashboard** | sentinelhq-dashboard | Admin UI with TOTP MFA |
| **shq-portal** | sentinelhq-portal | Client read-only portal |
| **shq-reporter** | sentinelhq-reporter | Weekly PDF reports |

---

## 2. Requirements

### Server Requirements

| Parameter | Minimum | Recommended |
|---|---|---|
| **CPU** | 4 cores | 8 cores |
| **RAM** | 16 GB | 32 GB |
| **Disk** | 100 GB SSD | 500 GB SSD |
| **OS** | Windows 10/11 or Ubuntu 22.04 | Windows 11 / Ubuntu 22.04 |

### Software

- **Docker Desktop** ≥ 4.x (Windows) or **Docker Engine** ≥ 24.0 (Linux)
- **Docker Compose** ≥ 2.20 (included in Docker Desktop)
- **Git**
- Open ports: `1514`, `1515`, `55000`, `8000`, `8082`, `8083`, `8889`, `9200`

### Accounts / API Keys

- [OpenRouter](https://openrouter.ai) or other OpenAI-compatible LLM provider (API key)
- Telegram Bot Token (from [@BotFather](https://t.me/botfather))
- Telegram Chat ID

---

## 3. Step 1 — Wazuh Installation

Wazuh is deployed as a Docker Compose `single-node` setup.

### 3.1 Clone Wazuh Docker

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.4
cd wazuh-docker/single-node
```

### 3.2 Generate Certificates

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

### 3.3 Start

```bash
docker compose up -d
```

> ⏳ First startup takes ~3–5 minutes.

### 3.4 Verify

```bash
docker compose ps
# Should show: wazuh.manager, wazuh.indexer, wazuh.dashboard — all "healthy"
```

- Wazuh Dashboard: `https://SERVER_IP` (port 5601 or 443)
- Default credentials: `admin` / `SecretPassword`

### 3.5 Change Passwords

Wazuh Dashboard → ☰ → Security → Internal users → Change `admin` and `wazuh-wui` passwords.

### 3.6 Verify Wazuh API

```bash
curl -k -u "wazuh-wui:YOUR_PASSWORD" \
  https://localhost:55000/security/user/authenticate
# Should return a JWT token
```

### 3.7 Create Suppress Rules File

SentinelHQ writes suppress rules to a dedicated file. Create it **once**:

```bash
docker exec -it single-node-wazuh.manager-1 bash

cat > /var/ossec/etc/rules/sentinelhq_rules.xml << 'EOF'
<group name="sentinelhq_noise,">
</group>
EOF

exit
```

### 3.8 Sysmon Configuration (recommended for Windows agents)

```powershell
# Windows PowerShell (as Administrator)
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive Sysmon.zip
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmon.xml"
.\Sysmon\Sysmon64.exe -accepteula -i sysmon.xml
```

---

## 4. Step 2 — Velociraptor Installation

Velociraptor is deployed as a separate Docker container using the `wlambert/velociraptor` image.

### 4.1 Clone velociraptor-docker

```bash
# Recommended: install alongside the Wazuh directory
cd wazuh-docker/single-node
git clone https://github.com/weslambert/velociraptor-docker
cd velociraptor-docker
```

### 4.2 Configure .env

```bash
nano .env
```

```env
VELOX_USER=admin
VELOX_PASSWORD=strong-password
VELOX_ROLE=administrator
VELOX_SERVER_URL=https://SERVER_IP:8000/
VELOX_FRONTEND_HOSTNAME=VelociraptorServer
```

### 4.3 Start

```bash
docker compose up -d
```

Velociraptor GUI: `https://SERVER_IP:8889`

### 4.4 Create API Config for SentinelHQ

```bash
# Connect to Velociraptor container
docker exec -it velociraptor bash

# Create API user (if not exists)
./velociraptor --config /velociraptor/server.config.yaml \
  user add sentinelhq --role administrator

# Export API config
./velociraptor --config /velociraptor/server.config.yaml \
  config api_client --name sentinelhq \
  --output /velociraptor/sentinelhq_api.yaml

exit
```

### 4.5 Copy API Config to SentinelHQ

```bash
cp wazuh-docker/single-node/velociraptor-docker/velociraptor/sentinelhq_api.yaml \
   sentinelhq/sentinelhq_api.yaml
```

---

## 5. Step 3 — SentinelHQ Installation

### 5.1 Clone

```bash
git clone https://github.com/DKprojektai/SentinelHQ-SOC.git sentinelhq
cd sentinelhq
```

### 5.2 Configure .env

```bash
cp .env.example .env
nano .env
```

Required changes:

```env
# Organization
ORG_NAME=Your Company Name
MANAGER_PUBLIC_IP=192.168.1.100      # ← Your server IP

# Wazuh
WAZUH_API_URL=https://wazuh.manager:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASS=your-wazuh-password
WAZUH_NETWORK=single-node_default    # Wazuh Docker network name

# OpenSearch / Wazuh Indexer
OPENSEARCH_URL=https://wazuh.indexer:9200
OPENSEARCH_PASS=your-opensearch-password

# Dashboard
DASHBOARD_USER=admin
DASHBOARD_PASS=strong-password
SECRET_KEY=  # generate: python3 -c "import secrets; print(secrets.token_hex(32))"

# LLM
LLM_API_URL=https://openrouter.ai/api/v1
LLM_API_KEY=sk-or-...
LLM_MODEL=google/gemini-2.5-flash

# Telegram
TELEGRAM_BOT_TOKEN=1234567890:AAB...
TELEGRAM_CHAT_ID=123456789

# DB
DB_PASS=strong-db-password

# Velociraptor
VELOCIRAPTOR_URL=https://192.168.1.100:8000
```

> **Note:** `WAZUH_NETWORK=single-node_default` is the Docker network created by Wazuh Compose. Verify with: `docker network ls | grep single-node`

### 5.3 Verify Wazuh Network Name

```bash
docker network ls
# Find the network containing "single-node", e.g.: single-node_default
```

If the name differs, update `.env` accordingly.

### 5.4 Start SentinelHQ

```bash
docker compose up -d --build
docker compose logs -f
```

> ⏳ First build takes ~5–10 minutes.

### 5.5 Verify Services

```bash
docker compose ps
```

All containers should be `running`:

| Container | Status |
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

## 6. Step 4 — Wazuh Active Response Configuration

SentinelHQ uses Wazuh Active Response for agent network isolation. Configure **once**.

```bash
# From the SentinelHQ directory
docker exec single-node-wazuh.manager-1 sh -c \
  "cat >> /var/ossec/etc/ossec.conf" < wazuh-config/sentinelhq_active_response.conf

# Verify
docker exec single-node-wazuh.manager-1 \
  grep -q sentinelhq-isolation /var/ossec/etc/ossec.conf && echo "OK"

# Restart Wazuh
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

---

## 7. Step 5 — Telegram Bot

### 7.1 Create Bot

1. Message [@BotFather](https://t.me/botfather) on Telegram
2. `/newbot` → enter a name → receive **Bot Token**

### 7.2 Get Chat ID

1. Send any message to your bot
2. Open: `https://api.telegram.org/botTOKEN/getUpdates`
3. Find `"chat":{"id": NUMBER}` — this is your **Chat ID**

### 7.3 Verify

```bash
docker logs shq-telegram --tail=20
# Should show: "Bot started" or "Polling..."
```

---

## 8. Step 6 — LLM Configuration

### 8.1 OpenRouter (recommended)

```env
LLM_API_URL=https://openrouter.ai/api/v1
LLM_API_KEY=sk-or-v1-...
LLM_MODEL=google/gemini-2.5-flash
```

**Recommended models (cost/quality ratio):**

| Model | Cost | Quality |
|---|---|---|
| `google/gemini-2.5-flash` | ~$0.001/1k | ⭐⭐⭐⭐⭐ |
| `google/gemini-2.5-flash` | ~$0.0005/1k | ⭐⭐⭐⭐ |
| `anthropic/claude-3-haiku` | ~$0.001/1k | ⭐⭐⭐⭐ |

### 8.2 Local LLM (free)

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

### 8.3 Enable LLM Agent

Dashboard → 🤖 LLM Agent → Toggle on

> ⚠️ Recommended to enable after 3–7 days, once suppress rules are created and noise is reduced.

---

## 9. Step 7 — Connecting Agents

### 9.1 Windows Agent (Wazuh)

Dashboard → 🖥️ Agents → ➕ Add Agent → Windows

Copy and run the generated PowerShell script **as Administrator**.

### 9.2 Linux Agent

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
  https://packages.wazuh.com/4.x/apt/ stable main" | \
  tee /etc/apt/sources.list.d/wazuh.list
apt-get update
WAZUH_MANAGER='SERVER_IP' apt-get install wazuh-agent
systemctl enable wazuh-agent && systemctl start wazuh-agent
```

### 9.3 Velociraptor Client

Velociraptor client binaries are automatically built and available at:

```
https://SERVER_IP:8889
```

Dashboard → 🖥️ Agents → ➕ Add Agent → Velociraptor → Windows

---

## 10. Verification

✅ `docker compose ps` — all containers `running`
✅ Dashboard: `http://SERVER_IP:8082`
✅ Portal: `http://SERVER_IP:8083`
✅ Alerts appear in Overview within ~30 seconds
✅ Telegram receives notifications for Lv9+ alerts

### Checking Logs

```bash
docker compose logs -f shq-collector
docker compose logs -f shq-analyzer
docker compose logs -f shq-llm
docker compose logs -f shq-telegram
```

---

## 11. Troubleshooting

### ❌ Collector not receiving alerts

```bash
docker logs shq-collector --tail=30
```

Check:
- `OPENSEARCH_PASS` is correct
- `WAZUH_NETWORK` matches the actual Docker network name (`docker network ls`)
- Wazuh containers are running: `docker ps | grep wazuh`

### ❌ Wazuh API unreachable

```bash
curl -k -u "wazuh-wui:PASSWORD" \
  https://localhost:55000/security/user/authenticate
```

If `500` — verify `WAZUH_API_PASS` in `.env`.

### ❌ LLM not analyzing

```bash
docker logs shq-llm --tail=30
```

Check:
- `LLM_API_KEY` is correct (use Ping button in Dashboard → LLM Agent)
- LLM Agent is enabled in Dashboard
- Alert level ≥ 9

### ❌ Telegram not working

```bash
docker logs shq-telegram --tail=30
```

Check `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, and send `/start` to the bot.

### ❌ Suppress rules not working

```bash
docker exec single-node-wazuh.manager-1 \
  ls /var/ossec/etc/rules/sentinelhq_rules.xml
```

If missing — create it following step 3.7.

### ❌ Isolation not working

Check:
- `sentinelhq_api.yaml` exists in the SentinelHQ directory
- Active Response is configured (Step 4)
- Velociraptor is running: `docker ps | grep velociraptor`
- `VELOCIRAPTOR_URL` uses port `8000`

---

## Appendix — .env Template

```env
ORG_NAME=Your Company Name
MANAGER_PUBLIC_IP=192.168.1.100

DB_NAME=sentinelhq
DB_USER=shq
DB_PASS=CHANGE_ME

OPENSEARCH_URL=https://wazuh.indexer:9200
OPENSEARCH_USER=admin
OPENSEARCH_PASS=CHANGE_ME
OPENSEARCH_INDEX=wazuh-alerts-*
WAZUH_VERIFY_SSL=false

WAZUH_API_URL=https://wazuh.manager:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASS=CHANGE_ME
WAZUH_NETWORK=single-node_default

COLLECT_INTERVAL_SECONDS=10

ANALYZE_INTERVAL_SECONDS=600
NOISE_THRESHOLD_HOURLY=20
NOISE_WINDOW_HOURS=72
MIN_OCCURRENCES=10
RULE_ID_START=122000
RULE_ID_MAX=122999

LLM_API_URL=https://openrouter.ai/api/v1
LLM_API_KEY=CHANGE_ME
LLM_MODEL=google/gemini-2.5-flash
LLM_POLL_INTERVAL=30

TELEGRAM_BOT_TOKEN=CHANGE_ME
TELEGRAM_CHAT_ID=CHANGE_ME

DASHBOARD_PORT=8082
DASHBOARD_USER=admin
DASHBOARD_PASS=CHANGE_ME
SECRET_KEY=GENERATE_ME

PORTAL_PORT=8083

VELOCIRAPTOR_URL=https://192.168.1.100:8000

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@email.com
SMTP_PASS=your-app-password
REPORT_EMAIL_TO=client@company.com
REPORT_DAY=monday
REPORT_HOUR=8

CORRELATE_INTERVAL=120
CORRELATE_WINDOW=10

TZ=Europe/Vilnius
```

---

*SentinelHQ — Cybersecurity Monitoring Platform*
