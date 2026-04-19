# SentinelHQ — User Guide

> **"AI SOC in your pocket"** — AI-powered security monitoring with a Telegram-first interface.
> **Version:** 1.1 | **Language:** English

---

**Welcome to SentinelHQ.** You now have a security analyst that never sleeps, never misses an alert, and fits in your pocket. This guide shows you how to get the most out of it — but honestly, most of it is intuitive enough that you'll figure it out as you go.

The one thing worth reading carefully: **[Section 11 — Telegram](#11-telegram--ai-soc-in-your-pocket)**. That's where the real power is.

---

## Table of Contents

1. [Login](#1-login)
2. [Overview Dashboard](#2-overview-dashboard)
3. [LLM Analyses](#3-llm-analyses)
4. [Noise Candidates](#4-noise-candidates)
5. [Rules](#5-rules)
6. [Correlations](#6-correlations)
7. [Agents](#7-agents)
8. [Blocked IPs](#8-blocked-ips)
9. [Playbooks](#9-playbooks)
10. [LLM Agent Configuration](#10-llm-agent-configuration)
11. [Telegram — AI SOC in Your Pocket](#11-telegram--ai-soc-in-your-pocket)
12. [Reports](#12-reports)
13. [Client Access](#13-client-access)

---

## 1. Login

Open in your browser: `http://SERVER_IP:8082`

Enter the administrator username and password (configured in `.env`: `DASHBOARD_USER` / `DASHBOARD_PASS`).

### MFA (Two-Factor Authentication)

Recommended: **MFA Setup** (bottom of left menu).

1. Download Google Authenticator or Authy
2. Scan the QR code
3. Confirm with the 6-digit code

---

## 2. Overview Dashboard

The main screen shows the overall system health at a glance.

### Stat Cards (top)

| Card | Meaning |
|---|---|
| **Alerts (24h)** | Number of Wazuh alerts in the last 24 hours |
| **True Positive** | AI-confirmed real incidents |
| **False Positive** | AI-rejected false signals |
| **Agents** | Connected and active agents |

### Top 10 Rules

Shows the most frequently triggered Wazuh rules. Useful for identifying noise sources.

### Recent Alerts

Latest Lv9+ alerts with LLM verdicts.

---

## 3. LLM Analyses

**Menu:** 🧠 LLM Analyses

Shows all AI-performed security alert analyses.

### Filters

- **Verdict** — filter by `true_positive`, `false_positive`, `uncertain`
- **Real LLM only** — show only AI-analyzed (not rule-based)
- **Agent** — search by machine name
- **Rule ID** — search by Wazuh rule number
- **Description** — search by event description

### Verdict Meanings

| Verdict | Meaning | Action |
|---|---|---|
| 🔴 `true_positive` | Real incident | Respond immediately |
| 🟡 `false_positive` | Noise / false alarm | Consider suppress rule |
| 🟣 `uncertain` | AI uncertain | Investigate manually |

### Details (click a row)

A side panel opens with:
- Full AI explanation (why it decided this)
- Threat type (brute_force, malware, recon...)
- Recommendations
- Process information (path, SHA256, command line)
- Suppress XML rule (if false_positive)

---

## 4. Noise Candidates

**Menu:** 📋 Candidates

The system automatically detects repeating events and suggests suppressing them.

### How It Works

Every 10 minutes the `shq-analyzer` service:
1. Analyzes the last 72 hours
2. Finds repeating patterns (>20/h)
3. Generates a Wazuh suppress XML rule
4. Adds it to the candidates list

### Score Meaning

| Score | Meaning |
|---|---|
| 20–39 | Moderate noise |
| 40–59 | High noise |
| 60+ | Very high noise — suppression recommended |

### Actions

**✓ Approve:**
- Checks that Wazuh Manager is reachable before making any changes
- XML rule is written to Wazuh
- Wazuh Manager restarts automatically
- Future matching events will no longer be logged

**✗ Dismiss:**
- Candidate is removed from the list
- Wazuh is unchanged
- Events continue to be logged

### Notes Field

Before approving, you can add a note explaining why you chose to suppress this event.

### ⚠️ Important

Before approving, make sure Wazuh Manager is active. The "🔄 Restart Wazuh Manager" button shows the count of pending rules — if Wazuh is currently restarting, wait for it to finish.

---

## 5. Rules

**Menu:** 📜 Rules

Shows all approved suppress rules.

### Statuses

| Status | Meaning |
|---|---|
| `ready` | Prepared but not yet uploaded to Wazuh |
| `deployed` | Actively running in Wazuh |

### XML Export

The **Export XML** button downloads the full `sentinelhq_rules.xml` file, which can be manually uploaded to Wazuh if needed.

---

## 6. Correlations

**Menu:** 🔗 Correlations

Correlations are detected attack chains. The system automatically groups related events into a single incident.

### Attack Types

| Type | Description |
|---|---|
| `WIN_BRUTE_SUCCESS` | Brute-force attack + successful login |
| `WIN_BRUTE_ATTEMPT` | Many failed login attempts |
| `OFFICE_SHELL` | Office document spawned a shell |
| `LINUX_PRIVESC` | Linux privilege escalation |
| `LATERAL_MOVEMENT` | Movement across the network |
| `RECON` | System reconnaissance |

### Statuses

| Status | Action |
|---|---|
| **Open** | New, not yet reviewed |
| **Investigating** | Currently being investigated |
| **Resolved** | Incident resolved |
| **False Positive** | Incorrect detection |

### Details (click a row)

- Full event chain with timestamps
- Each event with process, user, IP
- AI explanation
- Actions: Investigate / Resolve / False Positive

---

## 7. Agents

**Menu:** 🖥️ Agents

Shows all connected Wazuh agents.

### Statuses

| Status | Meaning |
|---|---|
| 🟢 **active** | Agent is active and sending data |
| 🟡 **disconnected** | Agent disconnected (machine off?) |

### Isolation

**🔒 Isolate** — isolates the machine from the network via Velociraptor:
- Machine loses internet / network access
- Forensic investigation can be performed safely
- Notification sent to Telegram

**🔓 Unisolate** — restores network access.

### Adding an Agent

➕ **Add Agent** → select OS → copy and run the generated script.

---

## 8. Blocked IPs

**Menu:** 🚫 Blocked IPs

Shows all IP addresses automatically blocked due to brute-force attacks.

### How Auto-Blocking Works

When Wazuh detects a brute-force attack (many failed logins), SentinelHQ automatically blocks the attacker's IP via Wazuh Active Response.

### Unblocking

Click the **🔓** button — the IP is removed from the block list.

---

## 9. Playbooks

**Menu:** 📋 Playbooks

Playbooks are automated response rules that define what the system does when it detects a specific threat.

### Configurable Parameters

| Parameter | Meaning |
|---|---|
| **Enabled** | Whether this playbook is active |
| **Auto-Isolate** | Automatically isolate the machine |
| **Telegram** | Send notification to Telegram |
| **Min Severity** | Minimum threat level to trigger |
| **Cooldown (min)** | Minutes between repeated triggers |

### Editing

Click **Edit** → adjust parameters → **Save**.

---

## 10. LLM Agent Configuration

**Menu:** 🤖 LLM Agent

Controls the AI analysis module.

### Enable / Disable

The toggle button turns LLM analysis on or off. When disabled, alerts are still recorded but not analyzed by AI.

### Configuration

| Parameter | Recommended Value |
|---|---|
| **Min. level** | 9 (analyze only important alerts) |
| **Batch size** | 5 (alerts per cycle) |
| **Auto-isolate (level ≥)** | 12 (for critical threats) |
| **Escalation time** | 30 min |

### Vacation Mode 🏖

When you're away — enable vacation mode (`/vacation` in Telegram or via Dashboard). The system continues monitoring but sends notifications less aggressively (for 7 days).

### Readiness Indicators

- **Alerts DB** — total alerts collected
- **True Positives** — AI-confirmed real incidents
- **False Positives** — AI-rejected false alerts
- **Real LLM** — how many times AI was actually called
- **Suppressed rules** — rules no longer sent to AI (cost savings)

### Ping

The **✓ Ping** button checks if the LLM API is reachable.

---

## 11. Telegram — AI SOC in Your Pocket

SentinelHQ is designed to be used primarily from Telegram. You receive real-time alerts with AI verdicts and can investigate, isolate, and ask questions — all without opening a browser.

### Alert Message Format

Every alert sent to Telegram includes an incident ID (`#4821`) which you can use with the `/ask` command:

```
🔴 SentinelHQ Alert #4821
──────────────────
📋 Rule: 92200 — Suspicious PowerShell execution
🔥 Level: 12
🖥 Agent: WIN-23JJCFPQEPF (192.168.1.50)
🎯 MITRE: T1059 — Execution
⚙️ Process: C:\Windows\System32\powershell.exe
💻 Cmd: powershell -enc JABjAG0AZA...
👤 User: CORP\john.doe
──────────────────
🤖 LLM: TRUE_POSITIVE (92%)
Encoded PowerShell command — possible credential theft.
⏰ 2026-04-15 22:04

[🔒 Isolate]  [❌ Noise]
[💬 More info]  [👁 Monitor]
```

### Commands

| Command | Action |
|---|---|
| `/status` | System health — LLM status, health score, alerts (24h), open correlations |
| `/ask <question>` | AI analyst — ask anything about any machine |
| `/isolate` | Machine list with isolation controls — search by hostname or IP |
| `/digest` | Request hourly alert summary on demand |
| `/vacation` | Toggle vacation mode on/off (pauses LLM for 7 days) |
| `/blocked` | List of blocked IPs with unblock buttons |
| `/help` | Help text |

### /ask — Your AI Security Analyst

The `/ask` command is the most powerful feature of SentinelHQ. Ask any question in natural language — the system automatically selects the right data sources and gives you a thorough answer.

**The engine uses 20+ data sources:**
- Security alerts and incident history from the database
- MITRE ATT&CK tactics and techniques detected
- Correlated multi-step attack chains
- OS version, kernel, hostname
- Hardware (CPU, RAM)
- Installed software with installation dates
- Windows hotfixes and patches
- Running processes (pid, user, command)
- System services and their state
- Open and listening network ports
- Local user accounts and groups
- Browser extensions (Chrome, Firefox, etc.)
- Network interfaces and IP addresses
- File integrity monitoring — recently changed files
- Login activity and failed authentication events

**Question examples:**

```
/ask what users are on WIN-23JJCFPQEPF?
/ask what software was installed on WIN-23JJCFPQEPF in last 2 days?
/ask what ports are open on WIN-23JJCFPQEPF?
/ask are there any suspicious processes on WIN-23JJCFPQEPF?
/ask what services are stopped on WIN-23JJCFPQEPF?
/ask what browser extensions are installed on WIN-23JJCFPQEPF?
/ask what happened on the network in the last 24 hours?
/ask what MITRE tactics were detected this week?
/ask what were the most critical incidents in the last 12 hours?
```

**Time ranges:**
```
last 12 hours / last 2 days / last week
```

**Asking about a specific incident by ID:**

Every alert message shows `#ID`. Use it with `/ask` to get details, context, and recommendations:

```
/ask #4821 what is this incident?
/ask #4821 how should I respond?
/ask #4821 is this a real threat or false positive?
/ask explain incident #4821 in detail
```

### Interactive Buttons (on alert messages)

| Button | Action |
|---|---|
| 🔒 **Isolate** | Wazuh Active Response — isolates the agent from the network |
| ❌ **Noise** | Override → false positive, creates a suppress rule |
| ✅ **Add suppress** | Confirms the LLM-suggested suppress rule |
| ❌ **Not noise** | Override → true positive |
| 💬 **More info** | Request additional LLM explanation |
| 👁 **Monitor** | Mark as being monitored, no isolation |

### Escalation Logic

```
0 min  → Telegram notification sent
15 min → Repeat (if no response)
30 min → Auto-isolate (if level ≥ auto_isolate_level)
```

### Notification Settings

Configure which notification types to receive in **Dashboard → LLM Agent → Telegram Notifications**:

| Setting | Description |
|---|---|
| Alerts | Real-time AI-analyzed security alerts |
| Correlations | Multi-step attack chain notifications |
| Digests | Hourly summary |

---

## 12. Reports

### Hourly Digest

Automatically sent to Telegram on the configured interval — a summary of alerts, verdicts, and system status.

Can be requested manually: `/digest`

### Weekly Report

Automatically sent every **Monday at 08:00** (configurable via `REPORT_DAY` and `REPORT_HOUR` in `.env`):
- PDF format
- Sent via email and Telegram

---

## 13. Client Access

**Menu:** 👥 Client Access

Clients can view their own security report portal at a separate URL: `http://SERVER_IP:8083`

### Creating a User

1. Dashboard → 👥 Client Access → **+ New User**
2. Enter email and password
3. The client gains access to the portal

### What Clients See

- Weekly security reports (PDF)
- General statistics
- Summary of active incidents

---

## Best Practices

### The 5-Minute Morning Check

With SentinelHQ, your daily security review takes 5 minutes — not hours:

1. ☀️ Open **Telegram** — any unhandled alerts from overnight? (They escalate automatically, so you won't miss critical ones)
2. 📋 Check **Correlations** — any new attack chains? These are the ones that matter most
3. 🔍 Skim **LLM Analyses** — any `true_positive` verdicts that need follow-up?
4. 💬 Ask the AI anything unusual: `/ask what happened on the network last night?`

### Weekly (10 minutes)

1. 📊 **Noise Candidates** — approve score ≥ 60 to progressively silence your false positives
2. 🖥️ **Agents** — any machines disconnected that shouldn't be?
3. 📧 Client report is already sent automatically — nothing to do here

### Incident Response Workflow

```
1. Receive Telegram alert 🔴 with incident #ID
2. Ask the AI: /ask #ID what is this and how should I respond?
3. If confirmed dangerous → tap 🔒 Isolate directly in Telegram
4. Investigate further: /ask what processes were running on AGENT?
5. Check for related activity: /ask what happened on AGENT in last 24h?
6. Open Dashboard → LLM Analyses for full details
7. Mark incident as "Resolved"
```

---

---

*Stop drowning in alerts. Start responding to threats.*
**SentinelHQ — AI SOC in Your Pocket.**
