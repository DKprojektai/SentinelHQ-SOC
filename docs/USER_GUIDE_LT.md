# SentinelHQ — Naudojimo instrukcija

> **"AI SOC kišenėje"** — AI-powered saugumo stebėjimas su Telegram valdymu.
> **Versija:** 1.2 | **Kalba:** Lietuvių

---

**Sveiki atvykę į SentinelHQ.** Dabar turite saugumo analitikus, kuris niekada nemiega, niekada nepraleidžia alertų ir telpa kišenėje. Šis vadovas parodo kaip išnaudoti visas galimybes — bet dauguma funkcijų tokios intuityvios, kad atrasite jas patys.

Vienas dalykas, kurį verta perskaityti atidžiai: **[11 skyrius — Telegram](#11-telegram--ai-soc-kišenėje)**. Ten slypi tikroji galia.

---

## Turinys

1. [Prisijungimas](#1-prisijungimas)
2. [Apžvalga (Dashboard)](#2-apžvalga)
3. [LLM Analizės](#3-llm-analizės)
4. [Triukšmo kandidatai](#4-triukšmo-kandidatai)
5. [Taisyklės](#5-taisyklės)
6. [Koreliacijos](#6-koreliacijos)
7. [Agentai](#7-agentai)
8. [Blokuoti IP](#8-blokuoti-ip)
9. [Playbooks](#9-playbooks)
10. [LLM Agentas (konfigūracija)](#10-llm-agentas)
11. [Telegram — AI SOC kišenėje](#11-telegram--ai-soc-kišenėje)
12. [Ataskaitų siuntimas](#12-ataskaitų-siuntimas)
13. [Klientų prieiga](#13-klientų-prieiga)

---

## 1. Prisijungimas

Naršyklėje atidaryti: `http://SERVERIO_IP:8082`

Įvesti administratoriaus vartotojo vardą ir slaptažodį (nurodyta `.env` faile: `DASHBOARD_USER` / `DASHBOARD_PASS`).

### MFA (dviejų faktorių autentifikacija)

Rekomenduojama įjungti: **MFA Setup** (kairiniame meniu apačioje).

1. Parsisiųsti Google Authenticator arba Authy
2. Nuskaityti QR kodą
3. Patvirtinti 6 skaitmenų kodu

---

## 2. Apžvalga

Pagrindinis ekranas rodo bendrą sistemos būklę.

### Statistikos kortelės (viršuje)

| Kortelė | Reikšmė |
|---|---|
| **Alertai (24h)** | Wazuh alertų kiekis per pastarą parą |
| **True Positive** | AI patvirtintų realių incidentų skaičius |
| **False Positive** | AI atmestų netikrų signalų skaičius |
| **Agentai** | Prijungtų ir aktyvių agentų skaičius |

### Viršutinės 10 taisyklių

Rodo dažniausiai suveikiančias Wazuh taisykles. Naudinga identifikuoti triukšmo šaltinius.

### Svarbūs alertai

Paskutiniai Lv9+ alertai su LLM verdiktu.

---

## 3. LLM Analizės

**Meniu:** 🧠 LLM Analizės

Čia rodomos visos AI atliekamos saugumo alertų analizės.

### Filtrai

- **Verdiktas** — filtruoti pagal `true_positive`, `false_positive`, `uncertain`
- **Tik realios LLM** — rodyti tik AI analizuotus (ne rule-based)
- **Agentas** — ieškoti pagal kompiuterio pavadinimą
- **Rule ID** — ieškoti pagal Wazuh taisyklės numerį
- **Aprašymas** — ieškoti pagal įvykio aprašymą

### Verdiktų reikšmės

| Verdiktas | Reikšmė | Veiksmas |
|---|---|---|
| 🔴 `true_positive` | Realus incidentas | Reaguoti nedelsiant |
| 🟡 `false_positive` | Triukšmas / klaidingas signalas | Svarstyti suppress taisyklę |
| 🟣 `uncertain` | AI neaiškus | Patikrinti rankiniu būdu |

### Detalės (paspaudus eilutę)

Atsidaro šoninis langas su:
- Pilnas AI paaiškinimas (kodėl taip nusprendė)
- Grėsmės tipas (brute_force, malware, recon...)
- Rekomendacijos
- Proceso informacija (kelias, SHA256, komandų eilutė)
- Suppress XML taisyklė (jei false_positive)

### 🌍 Geo / OTX stulpelis

Kandidatų lentelėje rodomas tinklo IP žvalgybos stulpelis:
- **🚨 + šalis** (raudona) — IP žinomas kaip kenkėjiškas (OTX); spausti → OTX detalės
- **šalis + ASN** (pilka) — GeoIP vieta (pvz. `RU AS12345`)
- **—** — nėra public IP duomenų

---

## 4. Triukšmo kandidatai

**Meniu:** 📋 Kandidatai

Sistema automatiškai aptinka pasikartojančius įvykius ir siūlo juos slopinti.

### Kaip veikia

Kas 10 minučių `shq-analyzer` servisas:
1. Analizuoja paskutines 72 valandas
2. Suranda pasikartojančius šablonus (>20/h)
3. Generuoja Wazuh suppress XML taisyklę
4. Įtraukia į kandidatų sąrašą

### Score reikšmė

| Score | Reiškia |
|---|---|
| 20–39 | Vidutinis triukšmas |
| 40–59 | Didelis triukšmas |
| 60+ | Labai didelis triukšmas — rekomenduojama slopinti |

### Veiksmai

**✓ Patvirtinti:**
- Tikrinama ar Wazuh Manager pasiekiamas
- XML taisyklė įrašoma į Wazuh
- Wazuh Manager automatiškai restartuojamas
- Tolesni tokie įvykiai nebus registruojami

**✗ Atmesti:**
- Kandidatas pašalinamas iš sąrašo
- Wazuh nekeičiamas
- Įvykiai toliau registruojami

### Pastabos laukas

Prieš tvirtinant galima įrašyti pastabą — kodėl nusprendėte slopinti šį įvykį.

### ⚠️ Svarbu

Prieš tvirtindami įsitikinkite, kad Wazuh Manager yra aktyvus. Mygtukas „🔄 Paleisti Wazuh iš naujo" rodo laukiančių taisyklių skaičių — jei restartuojasi, palaukite.

---

## 5. Taisyklės

**Meniu:** 📜 Taisyklės

Rodo visas patvirtintas suppress taisykles.

### Statusai

| Statusas | Reikšmė |
|---|---|
| `ready` | Paruošta, bet dar neįkelta į Wazuh |
| `deployed` | Aktyviai veikia Wazuh |

### XML eksportas

Mygtukas **Eksportuoti XML** — parsisiunčia pilną `sentinelhq_rules.xml` failą, kurį galima rankiniu būdu įkelti į Wazuh.

---

## 6. Koreliacijos

**Meniu:** 🔗 Koreliacijos

Koreliacijos — tai aptiktos atakų grandinės. Sistema automatiškai grupuoja susijusius įvykius į vieną incidentą.

### Atakų tipai

| Tipas | Aprašymas |
|---|---|
| `WIN_BRUTE_SUCCESS` | Brute-force ataka + sėkmingas prisijungimas |
| `WIN_BRUTE_ATTEMPT` | Daug nesėkmingų prisijungimų |
| `OFFICE_SHELL` | Office dokumentas paleido shellą |
| `LINUX_PRIVESC` | Linux privilegijų eskalavimas |
| `LATERAL_MOVEMENT` | Judėjimas per tinklą |
| `RECON` | Žvalgyba sistemoje |

### Statusai

| Statusas | Veiksmas |
|---|---|
| **Atviros** | Naujos, dar neperžiūrėtos |
| **Tiriamos** | Šiuo metu tiriamos |
| **Išspręstos** | Incidentas išspręstas |
| **False Positive** | Klaidingas aptikimas |

### Detalės (paspaudus eilutę)

- Pilna įvykių grandinė su laiko žymomis
- Kiekvienas įvykis su procesu, vartotoju, IP
- **Geo/OTX juosta** — jei grandinėje yra public IP: 🚨 OTX malicious / 🌍 šalis+ASN
- Timeline eilutėse: 🚨OTX / ⚠️Np pulses + 🌍 vėliavėlė prie atitinkamo įvykio
- AI paaiškinimas
- Veiksmai: Tirti / Išspręsti / False Positive

> **Greitis:** koreliacijos tikrinamos kas 15 sek (anksčiau 120 sek). 187 attack patterns + UEBA aptinka atakų grandines beveik realiu laiku.

### Telegram veiksmai prie chain alerto

Kai gauni „🔴 CHAIN DETECTED" Telegram žinutę, yra trys mygtukai:

| Mygtukas | Ką daro |
|---|---|
| 🔍 **Tirti** | Atidaro tyrimo režimą (be slopinimo) |
| ✅ **Išspręsta** (Resolved) | Uždaro **TIK šitą** incidentą. **Neslopina** — tas pats chain tipas vėl alertins kitą kartą |
| 🚫 **False positive** | **Visam laikui užtildo** šitą chain tipą **šitam agentui** — daugiau nebematysi (kol atblokuosi per `/muted`) |

> ⚠️ **Svarbu:** jei nori kad pasikartojantis chain'as DINGTŲ — spausk **False positive**, NE „Išspręsta". „Išspręsta" tik uždaro vieną instance.

### Užtildytų chain'ų valdymas — `/muted`

Komanda **`/muted`** atidaro mygtukų meniu (jokio rašymo):

1. **Agentų sąrašas** — pasirink agentą (skliausteliuose kiek chain'ų užtildyta)
2. **Signalų sąrašas** — to agento užtildyti chain'ai. Kiekvienam: `🔓 atblokuoti` ir `ℹ️ info`
3. **ℹ️** — parodo **techninę** grandinės informaciją (kad nuspręstum ar atblokuoti, NEišeinant į Wazuh):
   - **🔎 Aptikimo taisyklės** — Wazuh rule ID + lygis + aprašymas
   - **🎯 MITRE ATT&CK** — technikos ID + taktika (pvz. T1543.003 — Persistence)
   - **⚙️ Kas suveikė (3 paskutinės)** — serviso/proceso pavadinimas + pilnas kelias (`imagePath`) išskleidžiamame bloke (paspaudus). Čia matosi ar tai legalu (pvz. `C:\Program Files\...`) ar įtartina (`%TEMP%\...`)
   - **📊 Aktyvumas** — kiek kartų suveikė, pirma/paskutinė data, verdiktų pasiskirstymas
   Ten pat yra 🔓 Atblokuoti.
4. Spausk **🔓 signalą** — iškart atblokuoja (sąrašas atsinaujina)
5. **⬅️ Atgal** — grįžta į agentų sąrašą

```
/muted
🔇 Užtildyti chain'ai — pasirink agentą:
[ DESKTOP-VFADT1S  (1) ]

→ paspaudus agentą:
🔇 DESKTOP-VFADT1S — spausk signalą atblokuoti:
[ 🔓 WIN_SERVICE_INSTALL ] [ ℹ️ ]
[ ⬅️ Atgal ]

→ paspaudus ℹ️ (techninė info, kad nuspręstum):
ℹ️ DESKTOP-VFADT1S — WIN_SERVICE_INSTALL
🔇 Užtildyta: 2026-06-04 14:19 (visam laikui)

🔎 Aptikimo taisyklės:
• 61138 (lvl 5) — New Windows Service Created

🎯 MITRE ATT&CK:
• T1543.003 — Persistence

⚙️ Kas suveikė (3 paskutinės):
• Google Updater Internal Service
  ▸ kelias: C:\Program Files (x86)\Google\...\updater.exe   ← išskleidžiama
    paleidimas: auto start | user mode service

📊 Aktyvumas:
Suveikė: 14× | pirma: 2026-04-11 | paskutinė: 2026-06-04
Verdiktai: false_positive 7, resolved 7
[ 🔓 Atblokuoti ]
[ ⬅️ Atgal ]

→ paspaudus 🔓 — iškart atblokuota, sąrašas atsinaujina
```

> 💡 **Kaip nuspręsti:** žiūrėk `kelias` (imagePath). `C:\Program Files\...` + žinomas tiekėjas = legalu → atblokuok drąsiai. `%TEMP%\`, atsitiktinis pavadinimas = palik užtildytą, tirk.

> Galima ir tiesiogiai komanda: `/unmute <agentas> <signalas>`

> 🔒 **Saugumo pastaba:** „False positive" slopina ir TIKRĄ kenksmingą įvykį tam agentui+tipui. Naudok tik kai tikrai esi tikras kad tai triukšmas. Bet kada gali atblokuoti per `/muted` (arba `/unmute`).

---

## 7. Agentai

**Meniu:** 🖥️ Agentai

Rodo visus prijungtus Wazuh agentus.

### Statusai

| Statusas | Reikšmė |
|---|---|
| 🟢 **active** | Agentas aktyvus ir siunčia duomenis |
| 🟡 **disconnected** | Agentas atjungtas (išjungtas kompiuteris?) |

### Izoliacija

**🔒 Izoliuoti** — izoliuoja kompiuterį nuo tinklo per Velociraptor:
- Kompiuteris nebegali jungtis prie interneto / tinklo
- Galima atlikti forensics tyrimą
- Pranešimas siunčiamas į Telegram

**🔓 Panaikinti izoliciją** — grąžina tinklo prieigą.

### Agento pridėjimas

➕ **Prijungti agentą** → pasirinkti OS tipą → nukopijuoti ir paleisti sugeneruotą skriptą.

---

## 7b. LLM Forensics (Dashboard)

Dashboard turi atskirą **LLM Forensics** skydelį giliai galinio taško analizei per Velociraptor — tas pats variklis kaip `/velo` Telegram, bet naršyklės sąsajoje.

### Kaip naudoti

1. **Pasirinkti agentą** — spausk bet kurį agentą Agentų sąraše; Forensics skydelio viršuje esanti agento juosta rodo pasirinktą mašiną
2. **Užduoti klausimą** — įvesti forensics klausimą natūralia kalba
3. **Peržiūrėti siūlomus artefaktus** — sistema ieško Velociraptor artefaktų bibliotekoje ir rodo tinkančius kolektorius; pagal nutylėjimą niekas nepažymėta
4. **Išskleisti artefaktų aprašymus** — spausti ▼ norint pamatyti pilną aprašymą prieš renkantis
5. **Pasirinkti artefaktus** — pažymėti norimus paleisti
6. **Rinkti ir analizuoti** — sistema paleidžia pasirinktus artefaktus ant gyvo galinio taško ir atsako į klausimą su rezultatais

### Agento kontekstas

Agento juosta Forensics skydelio viršuje rodo, kuri mašina šiuo metu taikoma. Ji išsaugoma tarp papildomų klausimų — nereikia kiekvieną kartą iš naujo pasirinkti agento.

---

## 8. Blokuoti IP

**Meniu:** 🚫 Blokuoti IP

Rodo visus IP adresus, kurie buvo automatiškai užblokuoti dėl brute-force atakų.

### Kaip veikia automatinis blokavimas

Kai Wazuh aptinka brute-force ataką (daug nesėkmingų prisijungimų) — SentinelHQ automatiškai blokuoja užpuoliko IP per Wazuh Active Response.

### Atblokavimas

Paspaudus **🔓** mygtuką — IP pašalinamas iš blokavimo sąrašo.

---

## 9. Playbooks

**Meniu:** 📋 Scenarijai

Playbooks — tai automatinio reagavimo taisyklės. Apibrėžia ką sistema daro kai aptinka tam tikrą grėsmę. **215 playbookų**, įskaitant naujausias AI-eros grėsmes (ClickFix, MCP serveris, Ollama RCE, ML pickle RCE, SharePoint ToolShell CVE-2025-53770, infostealer cookie theft, Telegram C2, AI-polimorfinis loader ir kt.).

### Konfigūruojami parametrai

| Parametras | Reikšmė |
|---|---|
| **Įjungta** | Ar šis playbook aktyvus |
| **Auto-izoliuoti** | Ar automatiškai izoliuoti kompiuterį |
| **Telegram** | Ar siųsti pranešimą į Telegram |
| **Min Severity** | Minimalus grėsmės lygis suveikimui |
| **Cooldown (min)** | Minutės tarp pakartotinių suveikimų |

### 💡 Popup (užvedus pelę)

Užvedus pelę ant playbook aprašymo — iššoka langas su:
- **MITRE** technika (pvz. T1204.004)
- **Aprašas** (LT arba EN pagal pasirinktą kalbą)
- **Indikatoriai** (procesai/komandos dėl kurių suveikia)

### Redagavimas

Paspaudus **Redaguoti** → galima keisti parametrus → **Išsaugoti**.

---

## 10. LLM Agentas

**Meniu:** 🤖 LLM Agentas

Valdomas AI analizės modulis.

### Įjungimas / išjungimas

Toggle mygtukas įjungia/išjungia LLM analizę. Kai išjungtas — alertai registruojami, bet AI jų neanalizuoja.

### Konfigūracija

| Parametras | Rekomenduojama reikšmė |
|---|---|
| **Min. lygis** | 9 (analizuoti tik svarbius) |
| **Batch dydis** | 5 (alertų kiekis per ciklą) |
| **Auto-izoliacija (lygis ≥)** | 12 (labai rimtiems) |
| **Eskalacijos laikas** | 30 min |

### Atostogų režimas 🏖

Kai esate atostogose — įjunkite atostogų režimą (`/vacation` Telegram arba Dashboard). Sistema toliau stebi, bet mažiau agresyviai siunčia pranešimus (7 dienoms).

### Pasiruošimo rodikliai

- **Alertai DB** — kiek iš viso alertų sukaupti
- **True Positives** — kiek AI patvirtino kaip realius
- **False Positives** — kiek AI atmetė
- **Realios LLM** — kiek kartų tikrai buvo kviečiamas AI
- **Slopinamos taisyklės** — kiek taisyklių nebesiunčiama į AI (taupoma kaina)

### Ping

Mygtukas **✓ Ping** — patikrina ar LLM API pasiekiamas.

---

## 11. Telegram — AI SOC kišenėje

SentinelHQ sukurta valdyti pirmiausia iš Telegram. Gauni realaus laiko alertus su AI verdiktu ir gali tirti, izoliuoti bei klausinėti — viską be naršyklės.

### Alert pranešimo formatas

Kiekvienas alertas turi incidento ID (`#4821`) — naudojamas su `/ask` komanda:

```
🔴 SentinelHQ Alert #4821
──────────────────
📋 Rule: 92200 — Suspicious PowerShell execution
🔥 Level: 12
🖥 Agent: WIN-23JJCFPQEPF (192.168.1.50)
🚨 OTX: KNOWN MALICIOUS (42 pulses)
🌍 GeoIP [185.220.101.5]: RU — AS12345
🎯 MITRE: T1059 — Execution
⚙️ Process: C:\Windows\System32\powershell.exe
💻 Cmd: powershell -enc JABjAG0AZA...
👤 User: CORP\jonas.jonaitis
──────────────────
🤖 LLM: TRUE_POSITIVE (92%)
Koduota PowerShell komanda — galimas credential theft bandymas.
⏰ 2026-04-15 22:04

[🔒 Izoliuoti]  [❌ Triukšmas]
[💬 Daugiau info]  [👁 Stebėti]
[💬 Ask AI]
```

> **🌍 Geo/OTX:** jei alerte yra public IP (tinklo ryšys, brute-force šaltinis) — žinutė rodo OTX threat intel ir GeoIP vietą. Tas pats koreliacijų ir eskalavimo žinutėse.

### Komandos

| Komanda | Veiksmas |
|---|---|
| `/status` | Sistemos būklė — LLM statusas, health score, alertai (24h), atvirós koreliacijos |
| `/ask <klausimas>` | AI analitikas — klausk bet ko apie bet kurią mašiną (Wazuh duomenys) |
| `/velo <klausimas>` | LLM Forensics — gili galinio taško analizė per Velociraptor artefaktus |
| `/isolate` | Mašinų sąrašas su izoliavimo valdymu — paieška pagal hostname/IP |
| `/digest` | Rankinis valandinės suvestinės siuntimas |
| `/vacation` | Atostogų režimas on/off (stabdo LLM 7 dienoms) |
| `/blocked` | Blokuotų IP sąrašas su atblokavimo mygtukais |
| `/muted` | Užtildyti chain'ai (False positive) — mygtukais: agentas → signalas → 🔓/ℹ️ |
| `/help` | Pagalbos tekstas |

### /velo — Gili forensics per Velociraptor

`/velo` komanda vykdo **gyvus artefaktų rinkimus** tiesiogiai galuose per Velociraptor — tai daug giliau nei Wazuh syscollector duomenys.

**Kaip veikia:**
1. Nurodyk hostname: `/velo DESKTOP-B94MS7J kokie procesai veikia?`
2. Sistema ieško Velociraptor artefaktų bibliotekoje tinkamų kolektorių
3. Matai atitinkančių artefaktų sąrašą — pasirink kuriuos paleisti
4. Artefaktai vykdomi ant gyvo galinio taško — rezultatai analizuojami AI

**Agento kontekstas išsaugomas** — kai pirmą kartą nurodysi hostname, visi tolesni `/velo` klausimai toje pačioje sesijoje automatiškai nukreipiami į tą pačią mašiną:
```
/velo DESKTOP-B94MS7J kokie procesai veikia?
→ Suranda ir prisimena agentą. Rodo tinkančius artefaktus.

/velo ar yra suplanuotų užduočių?
→ Vis dar naudoja DESKTOP-B94MS7J (nereikia kartoti)
```

**Veikia ir su Wazuh+Velociraptor agentais, ir su tik Velociraptor agentais.** Jei `/ask kokie agentai` rodo mašiną su žyme `[Velo]`, ji yra tik Velociraptor sistemoje — naudok `/velo`.

**Pavyzdžiai:**
```
/velo HOSTNAME kokie procesai veikia?
/velo HOSTNAME parodyk suplanuotas užduotis
/velo HOSTNAME kokie tinklo ryšiai aktyvūs?
/velo HOSTNAME patikrink persistencijos mechanizmus
/velo HOSTNAME sąrašas neseniai pakeistų failų
```

---

### 🔭 Sistemos sveikatos pranešimai (automatiniai)

SentinelHQ turi **sveikatos sargą (watchdog)**, kuris kas kelias minutes (`HEALTH_CHECK_MINUTES`, numatyta 3) **pats pabeldžia** į kiekvieną svarbų komponentą ir tikrina ar jis atsiliepia. Jokių laiko ribų — tylus periodas niekada nelaikomas gedimu. Pranešimas siunčiamas **tik kai būsena pasikeičia** (gyvas→miręs arba miręs→atsistatė).

**Tikrinami 6 komponentai:**

| Komponentas | Ką reiškia gedimas |
|---|---|
| **PostgreSQL** | Duomenų bazė — sustoja VISKAS |
| **Wazuh Manager API** | Izoliacija ir taisyklių valdymas per API nustoja |
| **Wazuh Indexer** | Alertų rinkimas STOJA (collector traukia iš čia) |
| **Velociraptor** | Forenzika ir izoliacija neveiks |
| **LLM API** | AI verdiktai ir koreliacijų analizė pristabdyti (alertai vis tiek renkami) |
| **OTX** | Nekritinis — IP reputacijos turtinimas praleidžiamas |

**Pavyzdys — gedimo pranešimas:**
```
🔴 SYSTEM ALERT
──────────────
❌ Wazuh Indexer nepasiekiamas
cluster=red
🛠 Ką daryti: Alertų rinkimas STOJA (collector traukia iš čia).
Dažna priežastis: pilnas diskas arba per mažas heap. Tikrink
indexer konteinerį; cluster gali būti 'red'.
⏰ 2026-05-31 11:50
```

**Pavyzdys — atsistatymo pranešimas:**
```
✅ RECOVERED
──────────────
Wazuh Indexer atsistatė (2026-05-31 11:50 → now)
⏰ 2026-05-31 12:05
```

Kiekvienas gedimo pranešimas turi eilutę **🛠 Ką daryti** su poveikiu ir pirmu veiksmu — kad žinotum reaguoti net be gilaus sistemos pažinimo.

> **Vidiniai servisai** (collector, analyzer, llm-agent) atskirai laiku netikrinami — Docker juos automatiškai perkrauna nukritus, o jų realūs gedimai matosi per kurį nors iš 6 komponentų aukščiau (pvz. Indexer ar LLM).

---

### 🧭 Kaip teisingai klausti (`/ask` ir `/velo`)

Bendros taisyklės abiem komandoms — kad sistema atpažintų mašiną:

| Įvestis | Reikšmė |
|---------|---------|
| `/ask kali kokie procesai` | **Pirmas žodis = mašina** (hostname/IP). Likę — klausimas. |
| `/ask #685574 kas įvyko` | **`#` = incidentas** (alerto/koreliacijos ID). |
| `kokie vartotojai` (be komandos) | **Tęsia tą pačią mašiną** — nereikia kartoti vardo. |
| Kita mašina | Vėl rašyk su `/ask` arba `/velo` ir nauju pirmu žodžiu. |
| `/ask kurioje mašinoje yra vartotojas jdoe` | **Bendras klausimas** (per visas mašinas) — pirmas žodis ne mašina. |

**Pavyzdys (sesija):**
```
/ask kali kokie procesai veikia?      → atsako apie kali, įsimena kali
kokie vartotojai prisijungę?          → vis dar apie kali (be komandos)
/ask WIN-23JJCFPQEPF suplanuotos užduotys?  → perjungia į kitą mašiną
```

`/velo` veikia taip pat: `/velo kali kokie procesai` arba `/velo #685574 ...`.

> **Pastaba:** `/ask` naudoja Wazuh duomenis; `/velo` — gyvą Velociraptor rinkimą. Mašina turi būti žinoma (Wazuh agentas arba Velociraptor klientas).

---

### /ask — AI saugumo analitikas kišenėje

`/ask` yra galingiausia SentinelHQ funkcija. Klausk bet kokio klausimo natūralia kalba — sistema automatiškai parenka tinkamus duomenų šaltinius ir pateikia išsamų atsakymą.

**Pastaba:** `/ask` naudoja Wazuh duomenis ir veikia su Wazuh agentais. Mašinoms, kurios yra tik Velociraptor sistemoje (žymimos `[Velo]` agentų sąraše), naudok `/velo`.

**Naudoja 20+ duomenų šaltinių:**
- Saugumo alertai ir incidentų istorija iš DB
- MITRE ATT&CK taktikos ir technikos
- Koreliuoti daugiažingsniiai incidentai
- OS versija, kernel, hostname
- Hardware (CPU, RAM)
- Įdiegta programinė įranga su diegimo datomis
- Windows hotfixes ir pataisymai
- Veikiantys procesai (pid, vartotojas, komanda)
- Servisai ir jų būsena
- Atviri ir klausantys portai
- Lokalūs vartotojai ir grupės
- Naršyklių plėtiniai (Chrome, Firefox ir kt.)
- Tinklo sąsajos ir IP adresai
- Failų vientisumas — paskutiniai pakeitimai
- Prisijungimų aktyvumas ir nesėkmingi bandymai

**Klausimų pavyzdžiai:**

```
/ask kokie vartotojai yra ant WIN-23JJCFPQEPF?
/ask kas buvo įdiegta per paskutines 2 dienas ant WIN-23JJCFPQEPF?
/ask kokie portai atidaryti ant WIN-23JJCFPQEPF?
/ask ar yra įtartinų procesų ant WIN-23JJCFPQEPF?
/ask kokie servisai sustabdyti ant WIN-23JJCFPQEPF?
/ask kas vyko tinkle per paskutines 24h?
/ask kokie MITRE atakų vektoriai aptikti šią savaitę?
/ask kokie buvo patys rimčiausi incidentai per pastarąsias 12 valandų?
/ask kokie agentai prijungti?             (rodo Wazuh ir Velociraptor-only agentus)
/ask patikrink IP 185.220.101.5           (IP reputacija + geolokacija + grėsmių žvalgyba)
```

**Laiko nurodymas:**
```
per paskutines 12 valandų / per 2 dienas / šią savaitę
last 12 hours / last 2 days / last week
```

**Klausinėjimas apie konkretų incidentą pagal ID:**

Kiekviename alert pranešime matosi `#ID`. Naudok jį su `/ask`:

```
/ask #4821 kas tai per incidentas?
/ask #4821 kaip reaguoti?
/ask #4821 ar tai tikra grėsmė ar false positive?
/ask paaiškink incidentą #4821 detaliai
```

### Interaktyvūs mygtukai (prie alertų)

| Mygtukas | Veiksmas |
|---|---|
| 🔒 **Izoliuoti** | Wazuh Active Response — izoliuoja agentą nuo tinklo |
| ❌ **Triukšmas** | Override → false positive, sukuria suppress taisyklę |
| ✅ **Pridėti suppress** | Patvirtina LLM siūlomą suppress taisyklę |
| ❌ **Ne, tai tikras** | Override → true positive |
| 💬 **Daugiau info** | LLM papildomas paaiškinimas |
| 👁 **Stebėti** | Pažymi kaip stebimą, neizoliuoja |
| 💬 **Ask AI** | **Techninė** alerto analizė — pilna komanda, parent grandinė, hashes, MITRE sub-technika, mechanizmas (pažengusiems; ne bendros rekomendacijos) |

### Eskalavimo logika

```
0 min  → Telegram žinutė apie incidentą
15 min → Pakartojimas (jei nereaguota)
30 min → Automatinė izoliacija (jei lygis ≥ auto_isolate_level)
```

### Telegram pranešimų nustatymai

Dashboard → LLM Agentas → **Telegram pranešimai**:

| Nustatymas | Aprašymas |
|---|---|
| Alertai | Realiu laiku siunčiami AI-analizuoti alertai |
| Koreliacijos | Daugiažingsniiai incidentai |
| Digests | Valandinė suvestinė |

---

## 12. Ataskaitų siuntimas

### Valandinė suvestinė (Digest)

Automatiškai siunčiama į Telegram pagal nustatytą intervalą — alertų, verdiktų ir sistemos būklės santrauka.

Galima gauti rankiniu būdu: `/digest`

### Savaitinė ataskaita

Automatiškai siunčiama kiekvieną **pirmadienį 8:00** (konfigūruojama `REPORT_DAY` ir `REPORT_HOUR` `.env`):
- PDF failas
- Siunčiama el. paštu ir Telegram

**PDF sekcijos:**
- **KPI** — patvirtinti incidentai, izoliacijos, stebimi kompiuteriai, MTTD, SLA, triukšmo %
- **Alertų statistika** + **Incidentų būsena**
- **Kompiuterių apžvalga** — alertai/aukšti/patvirtinti per mašiną (visas parkas)
- **Reikšmingiausi incidentai** — dedubliuota pagal mašiną+tipą
- **Reagavimo santrauka** — izoliacijos, atblokavimai, suppress taisyklės (skaičiai)
- **Saugumo būklė (gyvi Wazuh duomenys):**
  - **Turto aprėptis** — agentai active/disconnected/viso + offline sąrašas
  - **Pažeidžiamumai (CVE)** — Critical/High/Medium/Low + daugiausia CVE turintys kompiuteriai
  - **Konfigūracijos saugumas (CIS)** — CIS hardening balas per mašiną (10 prasčiausių; su offline žyma + skenavimo data)
  - **Atviri rizikingi portai** — eksponuoti į tinklą (SMB, RDP, DB ir kt.): `portas/proto (procesas)` (10 rizikingiausių mašinų)
- **Santrauka** — AI naratyvas verslo kalba

> Saugumo būklės duomenys traukiami tiesiai iš Wazuh API + indexer. Jei Wazuh nepasiekiamas — šios sekcijos praleidžiamos, ataskaita vis tiek sugeneruojama.

---

## 13. Klientų prieiga

**Meniu:** 👥 Klientų prieiga

Klientai gali matyti savo saugumo ataskaitų portalą per atskirą URL: `http://SERVERIO_IP:8083`

### Vartotojo kūrimas

1. Dashboard → 👥 Klientų prieiga → **+ Naujas vartotojas**
2. Įvesti el. paštą ir slaptažodį
3. Klientas gauna prieigą prie portalo

### Kas matoma portale

- Savaitinės saugumo ataskaitos (PDF)
- Bendroji statistika
- Aktyvių incidentų santrauka

---

## Geriausia praktika

### Kasdienė rutina

1. ☀️ Ryte — peržiūrėti **Apžvalgą** (ar nebuvo incidentų naktį?)
2. 🔍 Patikrinti **LLM Analizes** — ar yra `true_positive` verdiktų?
3. 📋 Peržiūrėti **Koreliacijas** — ar nėra naujų atakų grandinių?
4. 🤖 Patikrinti **Telegram** — ar negauta neatsakytų pranešimų?

### Savaitinė rutina

1. 📊 Peržiūrėti **Triukšmo kandidatus** — patvirtinti score ≥ 60
2. 📜 Patikrinti **Taisykles** — ar visos `deployed`?
3. 🖥️ Patikrinti **Agentus** — ar nėra atjungtų?
4. 📧 Ataskaita automatiškai siunčiama klientui pirmadienį

### Incidento valdymo eiga

```
1. Gautas Telegram pranešimas 🔴 su incidento #ID
2. Klausk AI: /ask #ID kas tai ir kaip reaguoti?
3. Jei patvirtinta grėsmė → spausk 🔒 Izoliuoti tiesiai Telegram
4. Tirk toliau: /ask kokie procesai veikė ant AGENTO?
5. Tikrink susijusią veiklą: /ask kas vyko ant AGENTO per 24h?
6. Atidaryti Dashboard → LLM Analizės pilnoms detalėms
7. Incidentą pažymėti kaip "Išspręsta"
```

---

*SentinelHQ — Kibernetinio saugumo stebėjimo platforma*
