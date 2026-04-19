# SentinelHQ — AI SOC in Your Pocket

> **Your entire Security Operations Center. In Telegram. Powered by AI.**

While your competitors are hiring SOC analysts at €4,000/month each — you get the same coverage for a fraction of the cost, managed from your phone, 24/7.

- [Lietuviškai](README_LT.md)

---

## The Problem Every Security Team Knows

You deployed Wazuh. Now you get **500–2,000 security alerts every day.**

Most of them are noise. But which ones? Finding that one real threat hidden in thousands of false alarms takes hours — hours you don't have. Meanwhile, if you miss it, the consequences can be devastating.

Traditional SOC solutions cost **€10,000–50,000/month** and require a dedicated team. That's simply not realistic for most organizations.

**There had to be a better way.**

---

## SentinelHQ: One Person. Full Coverage. Phone in Hand.

SentinelHQ is an AI-powered SOC platform that connects directly to your Wazuh SIEM and turns the overwhelming flood of alerts into **clear, actionable intelligence** — delivered straight to Telegram.

**No extra screens. No extra staff. No alert fatigue.**

```
Wazuh detects 1,847 events today
         ↓
AI filters: 1,801 noise → suppressed automatically
         ↓
46 real alerts → analyzed by AI
         ↓
3 true positives → sent to your Telegram with full context
         ↓
You tap 🔒 Isolate. Threat contained. Done.
```

---

## What Makes It Different

### 🤖 AI That Actually Works
Every alert is analyzed by a large language model — not just rule-matching. The AI understands context: *why* this alert matters, *what* the attacker is trying to do, and *what* you should do about it. Verdict in seconds: **True Positive / False Positive / Uncertain**.

### 📱 Your SOC Lives in Telegram
No VPN. No dashboard. No laptop required. Real-time alerts arrive with full context, AI verdict, and action buttons. Tap to isolate a machine, suppress noise, or request a deeper explanation — all from your phone.

### 🔍 Ask Anything. Get Answers Instantly.
The `/ask` command turns natural language into security intelligence:

```
/ask what happened on WIN-23JJCFPQEPF in the last 12 hours?
→ AI queries 20+ data sources and gives you a full incident summary

/ask #4821 is this alert a real threat?
→ AI analyzes the specific incident with full context

/ask what software was installed on WIN-23JJCFPQEPF today?
→ Checks Wazuh syscollector and gives you the exact list

/ask what ports are open on WIN-23JJCFPQEPF?
→ Pulls live data from Wazuh API and answers immediately
```

No digging. No pivot tables. No waiting. **Just ask.**

### 🔗 Attack Chain Detection
SentinelHQ doesn't just alert on individual events — it connects the dots. Brute force → successful login → lateral movement → credential dump? That's one correlated incident, not 50 separate alerts. You see the full attack story.

### ⚡ One-Tap Response
When a threat is confirmed:
- **Isolate** the machine from the network instantly — via Velociraptor, without touching a keyboard
- **Block** the attacker's IP automatically — Wazuh Active Response kicks in
- **Suppress** recurring false positives forever — AI-generated Wazuh rules, one approval click

### 📊 Client Reports on Autopilot
Every Monday morning, your clients automatically receive a professional PDF security report — no manual work required. They see what was monitored, what was detected, and what was done. You look like a pro.

---

## What You Get

| | Community | Pro |
|---|---|---|
| **Wazuh agents monitored** | 3 | Unlimited |
| **Client portal accounts** | 1 | Unlimited |
| **AI alert analysis** | ✅ | ✅ |
| **Attack chain correlation** | ✅ | ✅ |
| **Telegram bot + /ask** | ✅ | ✅ |
| **Automatic noise suppression** | ✅ | ✅ |
| **One-tap machine isolation** | ✅ | ✅ |
| **Weekly PDF reports** | ✅ | ✅ |
| **Client portal** | ✅ | ✅ |
| **Priority support** | — | ✅ |

**Pro license:** Contact us → [GitHub Issues](../../issues)

---

## Screenshots

### Telegram — True Positive Alert
![True Positive](screenshots/True%20Positive.png)

### Telegram — False Positive Alert
![False Positive](screenshots/False%20Positive.png)

### Telegram — Correlation (Attack Chain)
![Correlation](screenshots/Correlation.png)

### Telegram — Hourly Digest
![Hourly Digest](screenshots/Hourly%20digest.png)

---

### Admin — Login & MFA
![Login](screenshots/ADMIN_login.png)
![MFA](screenshots/ADMIN_MFA.png)

### Admin — Alert Overview
![Overview](screenshots/ADMIN_overview.png)

### Admin — Correlations
![Correlations](screenshots/ADMIN_corelations.png)

### Admin — LLM Analyses
![LLM Analyses](screenshots/ADMIN_llm_analyses.png)

### Admin — LLM Agent
![LLM Agent](screenshots/ADMIN_llm_agent.png)

### Admin — Noise Scoring
![Noise](screenshots/ADMIN_noise.png)

### Admin — Agents
![Agents](screenshots/ADMIN_agents.png)

### Admin — Blocked IPs
![Blocked IPs](screenshots/ADMIN_blocked_ip.png)

### Admin — Playbooks
![Playbooks](screenshots/ADMIN_playbooks.png)

### Admin — Client Access
![Client Access](screenshots/ADMIN_client_access.png)

### Admin — Administrators
![Administrators](screenshots/ADMIN_administrators.png)

### Admin — Add Wazuh / Velociraptor
![Add Wazuh Velociraptor](screenshots/ADMIN_add_wazuh_velocirapto.png)

### Client Portal
![Client Login](screenshots/CLIENT_login.png)
![Client Portal](screenshots/CLIENT_portal.png)

---

## Up and Running in 15 Minutes

No Kubernetes. No cloud dependencies. No consultants needed.

SentinelHQ runs entirely on **your own infrastructure** — one server, Docker, done.

### Windows
```powershell
git clone https://github.com/DKprojektai/SentinelHQ-SOC.git
cd SentinelHQ-SOC
.\setup.ps1
```

### Linux / Mac
```bash
git clone https://github.com/DKprojektai/SentinelHQ-SOC.git
cd SentinelHQ-SOC
bash setup.sh
```

The setup wizard asks a few questions and handles everything automatically — Wazuh, Velociraptor, database, Telegram bot, AI integration. **~15 minutes from zero to fully operational SOC.**

---

## After Installation

| Service | URL |
|---|---|
| **Dashboard** (admin) | `http://SERVER_IP:8082` |
| **Portal** (clients) | `http://SERVER_IP:8083` |
| **Velociraptor** | `https://SERVER_IP:8889` |
| **Wazuh Dashboard** | `https://SERVER_IP:5601` |

---

## Maintenance Scripts

```powershell
.\backup.ps1          # Backup everything
.\update.ps1          # Update to latest version
```

```bash
bash backup.sh
bash update.sh
```

---

## Tech Stack

Built on proven open-source foundations — no vendor lock-in:

- **[Wazuh 4.14.4](https://wazuh.com)** — industry-standard SIEM
- **[Velociraptor](https://docs.velociraptor.app)** — enterprise DFIR platform
- **Any OpenAI-compatible LLM** — OpenRouter, LM Studio, Ollama, Azure OpenAI
- **PostgreSQL** — reliable, battle-tested storage
- **Docker Compose** — simple, portable deployment

---

## License

MIT — free to use, modify, and distribute.
Pro features require a valid license.

---

*Stop drowning in alerts. Start responding to threats.*
**SentinelHQ — AI SOC in Your Pocket.**
