# SentinelHQ — Naudojimo instrukcija

> **"AI SOC kišenėje"** — AI-powered saugumo stebėjimas su Telegram valdymu.
> **Versija:** 1.1 | **Kalba:** Lietuvių

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
- AI paaiškinimas
- Veiksmai: Tirti / Išspręsti / False Positive

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

Playbooks — tai automatinio reagavimo taisyklės. Apibrėžia ką sistema daro kai aptinka tam tikrą grėsmę.

### Konfigūruojami parametrai

| Parametras | Reikšmė |
|---|---|
| **Įjungta** | Ar šis playbook aktyvus |
| **Auto-izoliuoti** | Ar automatiškai izoliuoti kompiuterį |
| **Telegram** | Ar siųsti pranešimą į Telegram |
| **Min Severity** | Minimalus grėsmės lygis suveikimui |
| **Cooldown (min)** | Minutės tarp pakartotinių suveikimų |

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
```

### Komandos

| Komanda | Veiksmas |
|---|---|
| `/status` | Sistemos būklė — LLM statusas, health score, alertai (24h), atvirós koreliacijos |
| `/ask <klausimas>` | AI analitikas — klausk bet ko apie bet kurią mašiną |
| `/isolate` | Mašinų sąrašas su izoliavimo valdymu — paieška pagal hostname/IP |
| `/digest` | Rankinis valandinės suvestinės siuntimas |
| `/vacation` | Atostogų režimas on/off (stabdo LLM 7 dienoms) |
| `/blocked` | Blokuotų IP sąrašas su atblokavimo mygtukais |
| `/help` | Pagalbos tekstas |

### /ask — AI saugumo analitikas kišenėje

`/ask` yra galingiausia SentinelHQ funkcija. Klausk bet kokio klausimo natūralia kalba — sistema automatiškai parenka tinkamus duomenų šaltinius ir pateikia išsamų atsakymą.

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
