# SentinelHQ — AI SOC kišenėje

> **Visas jūsų Saugumo Operacijų Centras. Telegram žinutėje. Su AI pagalba.**

Kol konkurentai samdo SOC analitikus po 4 000 €/mėn. kiekvieną — jūs gausite tą patį aprėptį už dalelę kainos, valdydami iš telefono, 24/7.

→ [English](README.md)

---

## Problema, kurią pažįsta kiekviena saugumo komanda

Įdiegėte Wazuh. Dabar gausite **500–2 000 saugumo įspėjimų per dieną.**

Dauguma — triukšmas. Bet kurie tikri? Surasti vieną realią grėsmę tūkstančiuose klaidingų signalų užima valandas — valandas, kurių neturite. Ir jei praleistumėte — pasekmės gali būti katastrofiškos.

Tradiciniai SOC sprendimai kainuoja **10 000–50 000 €/mėn.** ir reikalauja atskiros komandos. Dauguma organizacijų to tiesiog negali sau leisti.

**Turėjo būti geresnis kelias.**

---

## SentinelHQ: Vienas žmogus. Pilna apsauga. Telefonas rankoje.

SentinelHQ yra AI-powered SOC platforma, kuri tiesiogiai jungiasi prie jūsų Wazuh SIEM ir paverčia milžinišką alertų srautą į **aiškią, veiksmingą informaciją** — tiesiai į Telegram.

**Jokie papildomi ekranai. Jokios papildomos darbo jėgos. Jokio alertų nuovargio.**

```
Wazuh šiandien aptinka 1 847 įvykius
         ↓
AI filtruoja: 1 801 triukšmas → automatiškai nutildomas
         ↓
46 realūs alertai → analizuojami AI
         ↓
3 tikri incidentai → siunčiami į Telegram su pilnu kontekstu
         ↓
Paspaudžiate 🔒 Izoliuoti. Grėsmė sustabdyta. Viskas.
```

---

## Kuo tai skiriasi

### 🤖 AI, kuris tikrai veikia
Kiekvienas alertas analizuojamas dideliu kalbų modeliu — ne tik taisyklių sutapimu. AI supranta kontekstą: *kodėl* šis alertas svarbus, *ką* užpuolikas bando padaryti ir *ką* turėtumėte daryti. Verdiktas per sekundes: **Tikras incidentas / Klaidingas signalas / Neaišku**.

### 📱 Jūsų SOC gyvena Telegram
Jokio VPN. Jokio dashboard. Jokio nešiojamojo kompiuterio. Realaus laiko alertai ateina su pilnu kontekstu, AI verdiktu ir veiksmų mygtukais. Palieskite, kad izoliuotumėte kompiuterį, nutildytumėte triukšmą ar paprašytumėte gilesnio paaiškinimo — visa tai iš telefono.

### 🔍 Klauskite bet ko. Gaukite atsakymus akimirksniu.
`/ask` komanda paverčia natūralią kalbą saugumo žvalgyba:

```
/ask kas vyko ant WIN-23JJCFPQEPF per paskutines 12 valandų?
→ AI parenka 20+ duomenų šaltinių ir pateikia pilną incidento suvestinę

/ask #4821 ar šis alertas tikra grėsmė?
→ AI analizuoja konkretų incidentą su pilnu kontekstu

/ask kas buvo įdiegta ant WIN-23JJCFPQEPF šiandien?
→ Patikrina Wazuh syscollector ir pateikia tikslų sąrašą

/ask kokie portai atidaryti ant WIN-23JJCFPQEPF?
→ Ima realius duomenis iš Wazuh API ir atsako iš karto
```

Jokie kastuvavimai. Jokie suvestiniai. Jokie laukimai. **Tiesiog paklauskite.**

### 🔗 Atakų grandinių aptikimas
SentinelHQ ne tik perspėja apie atskirus įvykius — jis sujungia taškus. Brute force → sėkmingas prisijungimas → šoninė judėjimas → credential dump? Tai vienas koreliuotas incidentas, o ne 50 atskirų alertų. Matote pilną atakos istoriją.

### ⚡ Reagavimas vienu prisilietimu
Kai grėsmė patvirtinta:
- **Izoliuokite** kompiuterį nuo tinklo akimirksniu — per Velociraptor, neliesdami klaviatūros
- **Blokuokite** užpuoliko IP automatiškai — Wazuh Active Response įsijungia savaime
- **Nutildykite** pasikartojančius klaidingus signalus visam laikui — AI sugeneruotos Wazuh taisyklės, vienas patvirtinimo paspaudimas

### 📊 Klientų ataskaitos autopilotu
Kiekvieną pirmadienio rytą jūsų klientai automatiškai gauna profesionalią PDF saugumo ataskaitą — jokio rankinio darbo nereikia. Jie mato, kas buvo stebima, kas aptikta ir kas atlikta. Jūs atrodote profesionaliai.

---

## Ką gausite

| | Community | Pro |
|---|---|---|
| **Stebimi Wazuh agentai** | 3 | Neribota |
| **Klientų portalo paskyros** | 1 | Neribota |
| **AI alertų analizė** | ✅ | ✅ |
| **Atakų grandinių koreliacija** | ✅ | ✅ |
| **Telegram botas + /ask** | ✅ | ✅ |
| **Automatinis triukšmo nutildymas** | ✅ | ✅ |
| **Vieno prisilietimo izoliacija** | ✅ | ✅ |
| **Savaitinės PDF ataskaitos** | ✅ | ✅ |
| **Klientų portalas** | ✅ | ✅ |
| **Prioritetinis palaikymas** | — | ✅ |

**Pro licencija:** Susisiekite → [GitHub Issues](../../issues)

---

## Screenshots

### Telegram — True Positive įspėjimas
![True Positive](screenshots/True%20Positive.png)

### Telegram — False Positive įspėjimas
![False Positive](screenshots/False%20Positive.png)

### Telegram — Koreliacija (atakos grandinė)
![Correlation](screenshots/Correlation.png)

### Telegram — Valandinė suvestinė
![Hourly Digest](screenshots/Hourly%20digest.png)

---

### Admin — Prisijungimas ir MFA
![Login](screenshots/ADMIN_login.png)
![MFA](screenshots/ADMIN_MFA.png)

### Admin — Alertų apžvalga
![Overview](screenshots/ADMIN_overview.png)

### Admin — Koreliacijos
![Correlations](screenshots/ADMIN_corelations.png)

### Admin — LLM Analizės
![LLM Analyses](screenshots/ADMIN_llm_analyses.png)

### Admin — LLM Agentas
![LLM Agent](screenshots/ADMIN_llm_agent.png)

### Admin — Triukšmo scoring
![Noise](screenshots/ADMIN_noise.png)

### Admin — Agentai
![Agents](screenshots/ADMIN_agents.png)

### Admin — Blokuoti IP
![Blocked IPs](screenshots/ADMIN_blocked_ip.png)

### Admin — Playbooks
![Playbooks](screenshots/ADMIN_playbooks.png)

### Admin — Klientų prieiga
![Client Access](screenshots/ADMIN_client_access.png)

### Admin — Administratoriai
![Administrators](screenshots/ADMIN_administrators.png)

### Admin — Pridėti Wazuh / Velociraptor
![Add Wazuh Velociraptor](screenshots/ADMIN_add_wazuh_velocirapto.png)

### Klientų portalas
![Client Login](screenshots/CLIENT_login.png)
![Client Portal](screenshots/CLIENT_portal.png)

---

## Paruošta veikti per 15 minučių

Jokio Kubernetes. Jokių debesų priklausomybių. Jokių konsultantų.

SentinelHQ veikia visiškai **jūsų infrastruktūroje** — vienas serveris, Docker, atlikta.

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

Setup wizard užduos kelis klausimus ir viską suinstaliuos automatiškai — Wazuh, Velociraptor, duomenų bazę, Telegram botą, AI integraciją. **~15 minučių nuo nulio iki pilnai veikiančio SOC.**

---

## Po diegimo

| Servisas | URL |
|---|---|
| **Dashboard** (admin) | `http://SERVERIO_IP:8082` |
| **Portalas** (klientai) | `http://SERVERIO_IP:8083` |
| **Velociraptor** | `https://SERVERIO_IP:8889` |
| **Wazuh Dashboard** | `https://SERVERIO_IP:5601` |

---

## Priežiūros skriptai

```powershell
.\backup.ps1          # Sukurti backup
.\update.ps1          # Atnaujinti į naujausią versiją
```

```bash
bash backup.sh
bash update.sh
```

---

## Technologijų stack'as

Sukurta ant patikrintų atviro kodo pamatų — jokio tiekėjo priklausomybės:

- **[Wazuh 4.14.4](https://wazuh.com)** — pramonės standartas SIEM
- **[Velociraptor](https://docs.velociraptor.app)** — enterprise DFIR platforma
- **Bet koks OpenAI-compatible LLM** — OpenRouter, LM Studio, Ollama, Azure OpenAI
- **PostgreSQL** — patikima, patikrinta duomenų bazė
- **Docker Compose** — paprastas, pernešamas diegimas

---

## Licencija

MIT — laisvas naudojimas, keitimas, platinimas.
Pro funkcijos reikalauja galiojančios licencijos.

---

*Liaukitės skanduoti alertuose. Pradėkite reaguoti į grėsmes.*
**SentinelHQ — AI SOC kišenėje.**
