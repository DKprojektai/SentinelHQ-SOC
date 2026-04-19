-- SentinelHQ PostgreSQL Schema — full, clean, all columns included

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ── Alerts ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id            BIGSERIAL PRIMARY KEY,
    wazuh_id      TEXT UNIQUE,
    fingerprint   TEXT NOT NULL,
    collected_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    alert_ts      TIMESTAMPTZ,
    rule_id       TEXT,
    rule_level    SMALLINT,
    rule_desc     TEXT,
    agent_id      TEXT,
    agent_name    TEXT,
    agent_ip      TEXT,
    location      TEXT,
    full_log      TEXT,
    event_id      INTEGER,
    src_proc_name TEXT,
    dst_proc_name TEXT,
    mitre_id      TEXT,
    mitre_tactic  TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint  ON alerts(fingerprint);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id      ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_agent_id     ON alerts(agent_id);
CREATE INDEX IF NOT EXISTS idx_alerts_collected_at ON alerts(collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_level   ON alerts(rule_level);
CREATE INDEX IF NOT EXISTS idx_alerts_src_proc     ON alerts(src_proc_name);
CREATE INDEX IF NOT EXISTS idx_alerts_dst_proc     ON alerts(dst_proc_name);
CREATE INDEX IF NOT EXISTS idx_alerts_event_id     ON alerts(event_id);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS cmd_line          TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS image_path        TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS parent_image_path TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS proc_user         TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS proc_sha256       TEXT;

-- ── Collector state ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS collector_state (
    key   TEXT PRIMARY KEY,
    value TEXT
);
INSERT INTO collector_state(key, value) VALUES('tg_offset', '0') ON CONFLICT DO NOTHING;

-- ── Noise candidates ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS noise_candidates (
    id               BIGSERIAL PRIMARY KEY,
    fingerprint      TEXT UNIQUE NOT NULL,
    rule_id          TEXT,
    rule_desc        TEXT,
    agent_id         TEXT,
    agent_name       TEXT,
    location         TEXT,
    occurrence_count INTEGER DEFAULT 0,
    hourly_rate      NUMERIC(10,2),
    noise_score      SMALLINT DEFAULT 0,
    first_seen       TIMESTAMPTZ,
    last_seen        TIMESTAMPTZ,
    status           TEXT DEFAULT 'pending' CHECK (status IN ('pending','approved','dismissed')),
    reviewed_at      TIMESTAMPTZ,
    reviewed_by      TEXT,
    notes            TEXT,
    updated_at       TIMESTAMPTZ DEFAULT NOW(),
    event_id         INTEGER,
    src_proc_name    TEXT,
    dst_proc_name    TEXT,
    mitre_id         TEXT
);
CREATE INDEX IF NOT EXISTS idx_nc_status ON noise_candidates(status);
CREATE INDEX IF NOT EXISTS idx_nc_score  ON noise_candidates(noise_score DESC);

-- ── Suppression rules ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS suppression_rules (
    id            BIGSERIAL PRIMARY KEY,
    wazuh_rule_id INTEGER UNIQUE,
    fingerprint   TEXT UNIQUE,
    rule_id       TEXT,
    agent_name    TEXT,
    location      TEXT,
    rule_desc     TEXT,
    noise_score   SMALLINT,
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    approved_at   TIMESTAMPTZ,
    status        TEXT DEFAULT 'draft' CHECK (status IN ('draft','ready','deployed','active')),
    wazuh_xml     TEXT
);

CREATE INDEX IF NOT EXISTS idx_supp_status     ON suppression_rules(status);
CREATE INDEX IF NOT EXISTS idx_supp_created    ON suppression_rules(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_supp_rule_id    ON suppression_rules(rule_id);
CREATE INDEX IF NOT EXISTS idx_supp_agent      ON suppression_rules(agent_name);
CREATE INDEX IF NOT EXISTS idx_alerts_agent_collected ON alerts(agent_name, collected_at DESC);

-- ── Rule ID counter ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rule_id_counter (
    id   INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    next INTEGER NOT NULL DEFAULT 122000
);
INSERT INTO rule_id_counter(id, next) VALUES(1, 122000) ON CONFLICT DO NOTHING;

-- ── LLM analyses ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS llm_analyses (
    id                 BIGSERIAL PRIMARY KEY,
    alert_id           BIGINT REFERENCES alerts(id) ON DELETE CASCADE,
    analyzed_at        TIMESTAMPTZ DEFAULT NOW(),
    model              TEXT,
    verdict            TEXT CHECK (verdict IN ('true_positive','false_positive','uncertain')),
    confidence         SMALLINT CHECK (confidence BETWEEN 0 AND 100),
    reasoning          TEXT,
    recommended_action TEXT,
    suggested_xml      TEXT,
    stage              SMALLINT DEFAULT 1,
    tokens_used        INTEGER,
    cost_usd           NUMERIC(10,6),
    overridden_by      TEXT,
    overridden_at      TIMESTAMPTZ,
    override_reason    TEXT
);
CREATE INDEX IF NOT EXISTS idx_llm_alert_id  ON llm_analyses(alert_id);
CREATE INDEX IF NOT EXISTS idx_llm_verdict   ON llm_analyses(verdict);
CREATE INDEX IF NOT EXISTS idx_llm_analyzed  ON llm_analyses(analyzed_at DESC);

-- ── Agent memory ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_memory (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    agent_name  TEXT,
    event_type  TEXT,
    summary     TEXT,
    recorded_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_memory_agent ON agent_memory(agent_id, recorded_at DESC);

-- ── Telegram messages ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS telegram_messages (
    id                 BIGSERIAL PRIMARY KEY,
    alert_id           BIGINT REFERENCES alerts(id) ON DELETE SET NULL,
    analysis_id        BIGINT REFERENCES llm_analyses(id) ON DELETE SET NULL,
    chat_id            TEXT NOT NULL,
    message_id         INTEGER,
    sent_at            TIMESTAMPTZ DEFAULT NOW(),
    status             TEXT DEFAULT 'sent' CHECK (status IN ('sent','acknowledged','escalated','auto_resolved')),
    action_taken       TEXT,
    action_at          TIMESTAMPTZ,
    action_by          TEXT,
    escalation_level   SMALLINT DEFAULT 0,
    next_escalation_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_tg_status     ON telegram_messages(status);
CREATE INDEX IF NOT EXISTS idx_tg_escalation ON telegram_messages(next_escalation_at)
    WHERE status = 'sent';

-- ── Correlations ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS correlations (
    id           BIGSERIAL PRIMARY KEY,
    agent_id     TEXT,
    agent_name   TEXT,
    detected_at  TIMESTAMPTZ DEFAULT NOW(),
    pattern_type TEXT,
    severity     SMALLINT,
    summary      TEXT,
    alert_ids    BIGINT[],
    status       TEXT DEFAULT 'open' CHECK (status IN ('open','investigating','resolved','false_positive')),
    resolved_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_corr_agent    ON correlations(agent_id);
CREATE INDEX IF NOT EXISTS idx_corr_status   ON correlations(status);
CREATE INDEX IF NOT EXISTS idx_corr_detected ON correlations(detected_at DESC);

-- ── Health scores ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS health_scores (
    id            BIGSERIAL PRIMARY KEY,
    calculated_at TIMESTAMPTZ DEFAULT NOW(),
    score         SMALLINT CHECK (score BETWEEN 0 AND 100),
    trend         TEXT CHECK (trend IN ('improving','stable','degrading')),
    details       JSONB
);
CREATE INDEX IF NOT EXISTS idx_health_calc ON health_scores(calculated_at DESC);

-- ── Recommendations ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS recommendations (
    id           BIGSERIAL PRIMARY KEY,
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    due_date     DATE,
    title        TEXT NOT NULL,
    description  TEXT,
    priority     TEXT CHECK (priority IN ('low','medium','high','critical')),
    status       TEXT DEFAULT 'open' CHECK (status IN ('open','in_progress','done','overdue')),
    completed_at TIMESTAMPTZ,
    source       TEXT
);
CREATE INDEX IF NOT EXISTS idx_rec_status ON recommendations(status);

-- ── Reports ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reports (
    id           BIGSERIAL PRIMARY KEY,
    generated_at TIMESTAMPTZ DEFAULT NOW(),
    period_start TIMESTAMPTZ,
    period_end   TIMESTAMPTZ,
    report_type  TEXT CHECK (report_type IN ('weekly','monthly','incident')),
    llm_summary  TEXT,
    pdf_path     TEXT,
    html_content TEXT,
    sent_via     TEXT[],
    sent_at      TIMESTAMPTZ
);

-- ── Admin users ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS admin_users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    totp_secret   TEXT,
    mfa_enabled   BOOLEAN DEFAULT FALSE,
    last_login    TIMESTAMPTZ,
    last_login_ip VARCHAR(64),
    prev_login_ip VARCHAR(64),
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ── Portal users ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS portal_users (
    id            BIGSERIAL PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    totp_secret   TEXT,
    mfa_enabled   BOOLEAN DEFAULT FALSE,
    portal_token  TEXT UNIQUE DEFAULT uuid_generate_v4()::TEXT,
    last_login    TIMESTAMPTZ,
    last_login_ip VARCHAR(64),
    prev_login_ip VARCHAR(64),
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    is_active     BOOLEAN DEFAULT TRUE
);

-- ── LLM config ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS llm_config (
    id                      INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled                 BOOLEAN DEFAULT FALSE,
    enabled_at              TIMESTAMPTZ,
    enabled_by              TEXT,
    model                   TEXT DEFAULT 'google/gemini-2.5-flash-lite',
    min_level               SMALLINT DEFAULT 7,
    batch_size              SMALLINT DEFAULT 10,
    vacation_mode           BOOLEAN DEFAULT FALSE,
    vacation_until          TIMESTAMPTZ,
    auto_isolate_level      SMALLINT DEFAULT 12,
    escalation_minutes      SMALLINT DEFAULT 15,
    digest_interval_minutes SMALLINT DEFAULT 60,
    tg_alerts_enabled       BOOLEAN DEFAULT TRUE,
    tg_correlations_enabled BOOLEAN DEFAULT TRUE,
    tg_digest_enabled       BOOLEAN DEFAULT TRUE
);
INSERT INTO llm_config(id) VALUES(1) ON CONFLICT DO NOTHING;

-- ── Audit log ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    happened_at TIMESTAMPTZ DEFAULT NOW(),
    actor       TEXT,
    action      TEXT NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    details     JSONB
);
CREATE INDEX IF NOT EXISTS idx_audit_happened ON audit_log(happened_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor    ON audit_log(actor);

CREATE TABLE IF NOT EXISTS login_attempts (
    id           SERIAL PRIMARY KEY,
    ip           VARCHAR(64)  NOT NULL,
    email        VARCHAR(255),
    success      BOOLEAN      NOT NULL DEFAULT false,
    source       VARCHAR(20)  NOT NULL DEFAULT 'portal',
    attempted_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip, attempted_at DESC);

CREATE TABLE IF NOT EXISTS blocked_ips (
    ip           VARCHAR(64)  NOT NULL,
    source       VARCHAR(20)  NOT NULL DEFAULT 'portal',
    blocked_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    blocked_until TIMESTAMPTZ NOT NULL,
    reason       VARCHAR(255),
    unblocked_at  TIMESTAMPTZ,
    unblocked_by  VARCHAR(100),
    PRIMARY KEY (ip, source)
);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_until ON blocked_ips(blocked_until);

-- ── Agent process graph ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_graph (
    agent_id    TEXT NOT NULL,
    parent_proc TEXT NOT NULL DEFAULT '',
    child_proc  TEXT NOT NULL DEFAULT '',
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    seen_count  INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (agent_id, parent_proc, child_proc)
);

-- ── Agent behavioral baseline ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_baseline (
    agent_id      TEXT PRIMARY KEY,
    agent_name    TEXT,
    known_tactics TEXT[] DEFAULT '{}',
    known_rules   TEXT[] DEFAULT '{}',
    baseline_since TIMESTAMPTZ DEFAULT NOW(),
    updated_at    TIMESTAMPTZ DEFAULT NOW(),
    days_observed INTEGER DEFAULT 0,
    is_trusted    BOOLEAN DEFAULT FALSE
);

ALTER TABLE correlations ADD COLUMN IF NOT EXISTS updated_at     TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE correlations ADD COLUMN IF NOT EXISTS trigger_type   TEXT DEFAULT 'score';

-- ── LLM per-alert suppression learning ───────────────────────────────────────
-- Tracks how many times LLM said false_positive for (agent, rule).
-- After fp_count >= 3 the system stops sending that rule+agent to LLM.
CREATE TABLE IF NOT EXISTS llm_alert_suppressions (
    agent_id    TEXT    NOT NULL,
    rule_id     TEXT    NOT NULL,
    fp_count    INTEGER NOT NULL DEFAULT 1,
    last_fp_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (agent_id, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_llm_sup_agent ON llm_alert_suppressions(agent_id);

ALTER TABLE agent_baseline
    ADD COLUMN IF NOT EXISTS score_ema     FLOAT   DEFAULT 0,
    ADD COLUMN IF NOT EXISTS score_samples INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS score_peak    FLOAT   DEFAULT 0;

-- ── Response Playbooks ────────────────────────────────────────────────────────
-- Kiekvienas įrašas susietas su vienu chain/signal/pattern tipu.
-- auto_isolate  = automatiškai izoliuoti agentą kai aptikta
-- notify_telegram = siųsti Telegram pranešimą
-- min_severity  = minimali severity (1-15) auto-izoliacijos suaktyvimui
-- cooldown_minutes = kiek minučių nebekartoti pranešimo
CREATE TABLE IF NOT EXISTS response_playbooks (
    id               BIGSERIAL PRIMARY KEY,
    trigger_type     TEXT NOT NULL UNIQUE,   -- chain/signal/pattern tipas
    description      TEXT,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    auto_isolate     BOOLEAN NOT NULL DEFAULT FALSE,
    notify_telegram  BOOLEAN NOT NULL DEFAULT TRUE,
    min_severity     SMALLINT NOT NULL DEFAULT 10,
    cooldown_minutes INTEGER  NOT NULL DEFAULT 30,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_by       TEXT DEFAULT 'system'
);
CREATE INDEX IF NOT EXISTS idx_playbooks_trigger ON response_playbooks(trigger_type);
CREATE INDEX IF NOT EXISTS idx_playbooks_enabled  ON response_playbooks(enabled);

-- ── Default playbook įrašai ───────────────────────────────────────────────────
-- Grupės pagal auto_isolate politiką:
--   KRITINIAI  (score 90-95): auto_isolate=TRUE,  min_severity=11
--   AUKŠTI     (score 70-89): auto_isolate=TRUE,  min_severity=12
--   VIDUTINIAI (score 50-69): auto_isolate=FALSE, min_severity=13 (tik pranešimas)
--   ŽEMI       (score <50):   auto_isolate=FALSE, tik Telegram

INSERT INTO response_playbooks (trigger_type, description, auto_isolate, notify_telegram, min_severity, cooldown_minutes) VALUES

-- ── KRITINIAI — automatinė izoliacija nuo severity 11 ─────────────────────
('RANSOMWARE_ENCRYPTION',  'Aktyvus failų šifravimas — nedelsiamas atsakas',              TRUE,  TRUE, 11, 0),
('WIPER_INDICATORS',       'Duomenų naikinimas — nedelsiamas atsakas',                     TRUE,  TRUE, 11, 0),
('FIRMWARE_PERSIST',       'UEFI/Firmware rootkit — kritinis kompromisas',                 TRUE,  TRUE, 11, 0),
('SKELETON_KEY',           'Skeleton Key — DC kompromisas',                                TRUE,  TRUE, 11, 0),
('ZEROLOGON',              'Zerologon CVE-2020-1472 — DC perėmimas',                       TRUE,  TRUE, 11, 0),
('ICS_PROTOCOL_ABUSE',     'ICS/SCADA protokolų manipuliacija — fizinis pavojus',          TRUE,  TRUE, 11, 0),
('RANSOMWARE_PRELUDE',     'Ransomware preliudija (VSS+BCDedit) — izoliuoti prieš šifr.', TRUE,  TRUE, 11, 5),
('DCSYNC',                 'DCSync — domeno kredencialų ištraukimas',                      TRUE,  TRUE, 11, 10),
('DCSHADOW',               'DCShadow — klaidingų replikacijų injekcija',                   TRUE,  TRUE, 11, 10),
('NTDS_EXTRACTION',        'NTDS.dit ištraukimas — visi domeno kredencialai',              TRUE,  TRUE, 11, 10),
('DISK_ENCRYPTION_PREP',   'MBR/disko šifravimo paruošimas',                               TRUE,  TRUE, 11, 0),
('LOG4SHELL',              'Log4Shell RCE exploit',                                         TRUE,  TRUE, 11, 15),
('MOVEIT_EXPLOIT',         'MOVEit Transfer exploitation',                                  TRUE,  TRUE, 11, 15),
('CONFLUENCE_EXPLOIT',     'Confluence RCE exploitation',                                   TRUE,  TRUE, 11, 15),
('EXCHANGE_ABUSE',         'Exchange ProxyLogon/ProxyShell exploit',                        TRUE,  TRUE, 11, 15),

-- ── AUKŠTI — automatinė izoliacija nuo severity 12 ───────────────────────
('CREDENTIAL_DUMP',        'LSASS/SAM/NTDS kredencialų ištraukimas',                       TRUE,  TRUE, 12, 15),
('LSASS_COMSVCS',          'LSASS dump per comsvcs.dll',                                   TRUE,  TRUE, 12, 15),
('LSASS_PPL_BYPASS',       'LSASS PPL apsaugos aplenkimas',                                TRUE,  TRUE, 12, 15),
('GOLDEN_SILVER_TICKET',   'Kerberos bilietų klastojimas',                                 TRUE,  TRUE, 12, 15),
('DIAMOND_TICKET',         'Diamond ticket Kerberos',                                       TRUE,  TRUE, 12, 15),
('PASS_THE_HASH',          'Pass-the-Hash autentifikacija',                                 TRUE,  TRUE, 12, 20),
('PASS_THE_TICKET',        'Pass-the-Ticket Kerberos',                                     TRUE,  TRUE, 12, 20),
('PASS_CERTIFICATE',       'Pass-the-Certificate PKINIT',                                   TRUE,  TRUE, 12, 20),
('SAM_HIVE_DUMP',          'SAM/SYSTEM registry dump',                                     TRUE,  TRUE, 12, 15),
('WIN_LSASS_DUMP',         'Sysmon LSASS process access',                                  TRUE,  TRUE, 12, 15),
('C2_FRAMEWORK',           'Žinomas C2 framework aptiktas',                                TRUE,  TRUE, 12, 20),
('COBALT_STRIKE_INDICATORS','Cobalt Strike indikatoriai',                                  TRUE,  TRUE, 12, 20),
('KERNEL_CALLBACK_REMOVAL','Kernel callback šalinimas — EDR neutralizacija',               TRUE,  TRUE, 12, 15),
('BRING_YOUR_OWN_DRIVER',  'BYOVD kernel exploit',                                         TRUE,  TRUE, 12, 15),
('ESXI_ATTACK',            'VMware ESXi taikymas',                                          TRUE,  TRUE, 12, 15),
('SERVICE_BULK_STOP',      'Masinis paslaugų stabdymas',                                   TRUE,  TRUE, 12, 10),
('AV_KILL',                'AV/EDR procesų stabdymas',                                     TRUE,  TRUE, 12, 10),
('SAFE_MODE_EVASION',      'Saugaus režimo įjungimas ransomware tikslais',                 TRUE,  TRUE, 12, 10),
('WIN_UNSIGNED_DRIVER',    'Nepasirašyta tvarkyklė įkelta',                                TRUE,  TRUE, 12, 20),
('DOCKER_SOCKET_ABUSE',    'Docker socket privilege escalation',                            TRUE,  TRUE, 12, 15),
('K8S_ABUSE',              'Kubernetes RBAC/pod abuse',                                     TRUE,  TRUE, 12, 15),
('CITRIX_EXPLOIT',         'Citrix/NetScaler CVE exploitation',                             TRUE,  TRUE, 12, 15),
('FORTINET_EXPLOIT',       'FortiGate/FortiOS CVE exploitation',                            TRUE,  TRUE, 12, 15),
('ANYCONNECT_EXPLOIT',     'Cisco ASA/AnyConnect exploitation',                             TRUE,  TRUE, 12, 15),
('PASSKEY_BYPASS',         'Passkey/FIDO2 aplenkimas',                                     TRUE,  TRUE, 12, 20),
('BITM_ATTACK',            'Browser-in-the-Middle sesijos perėmimas',                      TRUE,  TRUE, 12, 20),
('ENTRA_ID_ABUSE',         'Entra ID PRT vagystė',                                         TRUE,  TRUE, 12, 20),
('LINUX_ROOTKIT',          'Linux kernel rootkit įkėlimas',                                TRUE,  TRUE, 12, 15),
('LINUX_EBPF_ABUSE',       'eBPF rootkit/stealthinis monitoringas',                        TRUE,  TRUE, 12, 15),
('LINUX_SSH_BRUTE_SUCCESS','SSH brute force sėkmingas prisijungimas',                      TRUE,  TRUE, 12, 20),
('WIN_BRUTE_SUCCESS',      'Windows brute force sėkmingas prisijungimas',                  TRUE,  TRUE, 12, 20),
('TPM_SNIFF',              'TPM magistralės klausymas BitLocker raktams',                  TRUE,  TRUE, 12, 30),

-- ── VIDUTINIAI — tik pranešimas, auto_isolate=FALSE ───────────────────────
('LATERAL_MOVEMENT',       'Šoninis judėjimas tinkle',                                     FALSE, TRUE, 10, 30),
('WINRM_LATERAL',          'WinRM lateral movement',                                        FALSE, TRUE, 10, 30),
('DCOM_LATERAL',           'DCOM lateral movement',                                         FALSE, TRUE, 10, 30),
('RDP_ABUSE',              'Neįprastas RDP naudojimas',                                    FALSE, TRUE, 10, 30),
('KERBEROASTING',          'Kerberoasting SPN harvesting',                                  FALSE, TRUE, 10, 30),
('AS_REP_ROASTING',        'AS-REP Roasting',                                               FALSE, TRUE, 10, 30),
('OVERPASS_THE_HASH',      'Overpass-the-Hash TGT',                                        FALSE, TRUE, 10, 30),
('KERBEROS_DELEGATION',    'Kerberos delegation abuse',                                     FALSE, TRUE, 10, 30),
('ADCS_ABUSE',             'ADCS sertifikatų piktnaudžiavimas',                            FALSE, TRUE, 10, 30),
('SHADOW_CREDENTIALS',     'Shadow Credentials msDS-KeyCredentialLink',                    FALSE, TRUE, 10, 30),
('NTLM_COERCION',          'NTLM coercion/relay',                                           FALSE, TRUE, 10, 30),
('DPAPI_ABUSE',            'DPAPI slaptų duomenų ištraukimas',                             FALSE, TRUE, 10, 30),
('LAPS_ABUSE',             'LAPS slaptažodžių skaitymas',                                  FALSE, TRUE, 10, 30),
('TOKEN_MANIPULATION',     'Token impersonation/theft',                                     FALSE, TRUE, 10, 30),
('PRIVESC_TOOLS',          'Privilege escalation tools',                                    FALSE, TRUE, 10, 30),
('WIN_ADMIN_GROUP_ADD',    'Vartotojas pridėtas į administratorius',                       FALSE, TRUE, 10, 30),
('WIN_USER_CREATED',       'Nauja vartotojo paskyra sukurta',                              FALSE, TRUE,  9, 30),
('USER_ACCOUNT_MANIP',     'Vartotojų paskyrų manipuliacija',                              FALSE, TRUE,  9, 30),
('GPO_ABUSE',              'GPO manipuliacija',                                             FALSE, TRUE, 10, 30),
('WSUS_ATTACK',            'WSUS ataka',                                                    FALSE, TRUE, 10, 30),
('PRINT_NIGHTMARE',        'PrintNightmare exploit',                                        FALSE, TRUE, 10, 30),
('AMSI_BYPASS',            'AMSI/ETW bypass',                                               FALSE, TRUE, 10, 30),
('REFLECTIVE_LOAD',        'Reflektyvus DLL/assembly load',                                FALSE, TRUE, 10, 30),
('ETW_PATCH',              'ETW/NT API patching',                                           FALSE, TRUE, 10, 30),
('PPID_SPOOF',             'Parent PID spoofing',                                           FALSE, TRUE,  9, 30),
('PROCESS_INJECTION',      'Process injection/hollowing',                                   FALSE, TRUE, 10, 30),
('PHANTOM_DLL_HOLLOW',     'Phantom DLL hollowing',                                        FALSE, TRUE, 10, 30),
('MEMORY_ONLY_STAGE',      'Fileless memory-only execution',                               FALSE, TRUE, 10, 30),
('DEFENSE_EVASION',        'Gynybos vengimas',                                              FALSE, TRUE,  9, 30),
('LOG_CLEARING',           'Įvykių žurnalų valymas',                                       FALSE, TRUE,  9, 30),
('WINDOWS_DEFENDER_EXCL',  'Windows Defender exclusion pridėjimas',                        FALSE, TRUE,  9, 30),
('ACCESSIBILITY_BACKDOOR', 'Sticky Keys/Utilman backdoor',                                 FALSE, TRUE, 10, 30),
('WMI_PERSISTENCE',        'WMI event subscription persistence',                           FALSE, TRUE,  9, 30),
('REGISTRY_DEEP_PERSISTENCE','Gilusis registro persistence',                               FALSE, TRUE,  9, 30),
('LSA_PROVIDER_PERSIST',   'LSA security package persistence',                             FALSE, TRUE, 10, 30),
('BITS_ABUSE',             'BITS persistence/download',                                    FALSE, TRUE,  8, 30),
('COM_HIJACK',             'COM object hijacking',                                          FALSE, TRUE,  8, 30),
('OFFICE_ADDIN_PERSIST',   'Office add-in persistence',                                    FALSE, TRUE,  8, 30),
('ACTIVE_SETUP_PERSIST',   'Active Setup persistence',                                     FALSE, TRUE,  8, 30),
('PERSISTENCE_SETUP',      'Bendrasis persistence',                                         FALSE, TRUE,  8, 30),
('STARTUP_PERSISTENCE',    'Startup katalogo persistence',                                FALSE, TRUE,  8, 30),
('LINUX_SSH_ABUSE',        'Linux SSH raktų vagystė/tuneliavimas',                         FALSE, TRUE,  8, 30),
('NETSH_HELPER_DLL',       'Netsh helper DLL persistence',                                 FALSE, TRUE,  8, 30),
('SCREENSAVER_PERSIST',    'Ekrano saugiklio persistence',                                 FALSE, TRUE,  6, 60),
('VDSO_INJECTION',         'Linux vDSO/vsyscall injekcija',                               FALSE, TRUE, 10, 30),
('AI_TOOL_ABUSE',          'AI įrankių piktnaudžiavimas',                                 FALSE, TRUE,  7, 60),
('LINUX_WEBSHELL',         'Linux web shell aptiktas',                                     FALSE, TRUE, 10, 20),
('LINUX_PRIVESC',          'Linux privilege escalation',                                   FALSE, TRUE,  9, 30),
('LOLBIN_EXEC',            'LOLBin download+execute',                                       FALSE, TRUE,  9, 30),
('LIVING_OFF_THE_LAND_PS', 'PowerShell LOLBin chain',                                      FALSE, TRUE,  9, 30),
('APPLOCKER_BYPASS',       'AppLocker bypass',                                              FALSE, TRUE,  8, 30),
('DLL_SIDELOAD',           'DLL sideloading',                                               FALSE, TRUE,  8, 30),
('MASQUERADE_PROC',        'Proceso vardo maskavimas',                                     FALSE, TRUE,  9, 30),
('OBFUSCATION_INDICATORS', 'Kodo obfuskacija',                                             FALSE, TRUE,  8, 30),
('DATA_EXFIL',             'Duomenų išfiltravimas',                                         FALSE, TRUE, 10, 30),
('DNS_EXFIL',              'DNS tuneliavimas',                                              FALSE, TRUE,  9, 30),
('TUNNELING',              'Tinklo tuneliavimas',                                           FALSE, TRUE,  9, 30),
('TOR_I2P_USAGE',          'Tor/I2P naudojimas',                                            FALSE, TRUE,  8, 30),
('ICMP_COVERT',            'ICMP covert channel',                                           FALSE, TRUE,  8, 30),
('PROXY_MULTIHOP',         'Multi-hop proxy grandinė',                                     FALSE, TRUE,  8, 30),
('PORT_FORWARD',           'Port forwarding',                                               FALSE, TRUE,  7, 30),
('NETWORK_C2_BEACON',      'C2 beacon aptiktas',                                           FALSE, TRUE, 10, 20),
('NETWORK_PORT_SCAN',      'Port scan aptiktas',                                            FALSE, TRUE,  7, 60),
('LLMNR_POISONING',        'LLMNR/NBT-NS apnuodijimas',                                   FALSE, TRUE,  8, 30),
('AD_RECON',               'Active Directory žvalgyba',                                     FALSE, TRUE,  8, 30),
('CLOUD_RECON',            'Cloud infrastruktūros žvalgyba',                               FALSE, TRUE,  8, 30),
('RECON_CHAIN',            'Žvalgybos komandų grandinė',                                   FALSE, TRUE,  7, 60),
('LINUX_RECON',            'Linux sistemos žvalgyba',                                       FALSE, TRUE,  7, 60),
('LINUX_PERSISTENCE',      'Linux persistence',                                             FALSE, TRUE,  8, 30),
('LINUX_CRED_DUMP',        'Linux kredencialų ištraukimas',                                FALSE, TRUE,  9, 30),
('LINUX_LD_PRELOAD',       'LD_PRELOAD injekcija',                                         FALSE, TRUE,  9, 30),
('LINUX_CAPABILITY_ABUSE', 'Linux capabilities abuse',                                     FALSE, TRUE,  9, 30),
('LINUX_PROC_INJECTION',   'Linux ptrace/proc injekcija',                                  FALSE, TRUE,  9, 30),
('LINUX_MEMFD_EXEC',       'Linux fileless ataka',                                          FALSE, TRUE, 10, 30),
('LINUX_SSH_BRUTE',        'SSH brute force bandymas',                                     FALSE, TRUE,  7, 60),
('CRON_DOWNLOAD_EXEC',     'Cron download+exec',                                            FALSE, TRUE,  9, 30),
('WIN_RECON_CHAIN',        'Windows žvalgybos grandinė',                                   FALSE, TRUE,  7, 60),
('WIN_CREDENTIAL_TOOL',    'Kredencialų įrankis aptiktas',                                 FALSE, TRUE, 10, 20),
('WIN_LATERAL_MOVEMENT',   'Windows lateral movement',                                     FALSE, TRUE, 10, 20),
('WIN_MACRO_SHELL',        'Office macro→shell',                                            FALSE, TRUE, 10, 20),
('WIN_SCHEDULED_TASK',     'Scheduled task sukurta',                                       FALSE, TRUE,  8, 30),
('WIN_SERVICE_INSTALL',    'Windows service įdiegta',                                      FALSE, TRUE,  8, 30),
('WIN_TIMESTOMPING',       'File timestomping',                                             FALSE, TRUE,  8, 30),
('WIN_BRUTE_ATTEMPT',      'Windows brute force bandymas',                                 FALSE, TRUE,  6, 60),
('VULNERABILITY_CRITICAL', 'Critical CVE pažeidžiamumas',                                  FALSE, TRUE,  8, 120),
('OFFICE_MACRO_CHAIN',     'Office macro vykdymo grandinė',                                FALSE, TRUE,  9, 30),
('ISO_LNK_EXEC',           'ISO/LNK failo vykdymas',                                       FALSE, TRUE,  8, 30),
('HTML_SMUGGLING',         'HTML smuggling',                                                FALSE, TRUE,  8, 30),
('CHM_SCRIPTLET',          'CHM/Scriptlet vykdymas',                                       FALSE, TRUE,  8, 30),
('CREDENTIAL_FILE_ACCESS', 'Credential failų prieiga',                                     FALSE, TRUE,  8, 30),
('BROWSER_CRED_THEFT',     'Naršyklių kredencialai',                                       FALSE, TRUE,  9, 30),
('KEYLOGGING',             'Klaviatūros sekimas',                                           FALSE, TRUE,  9, 30),
('NETWORK_SNIFF',          'Tinklo srauto klausymas',                                      FALSE, TRUE,  7, 60),
('SCREEN_CAPTURE',         'Ekrano/klaviatūros rinkimas',                                  FALSE, TRUE,  7, 60),
('EMAIL_COLLECTION',       'El. pašto duomenų rinkimas',                                   FALSE, TRUE,  8, 30),
('SHARE_ENUM_COLLECTION',  'Tinklo diskų išvardijimas',                                    FALSE, TRUE,  6, 60),
('RMM_ABUSE',              'RMM įrankio piktnaudžiavimas',                                 FALSE, TRUE,  8, 30),
('SUPPLY_CHAIN_INDICATORS','Tiekimo grandinės ataka',                                       FALSE, TRUE,  9, 30),
('CONTAINER_ESCAPE',       'Konteinerio izoliacija pažeista',                              FALSE, TRUE, 10, 30),
('MFA_BYPASS',             'MFA aplenkimas',                                                FALSE, TRUE, 10, 30),
('MFA_FATIGUE_ADVANCED',   'MFA fatigue ataka',                                            FALSE, TRUE,  9, 30),
('WINDOWS_HELLO_BYPASS',   'Windows Hello bypass',                                          FALSE, TRUE, 10, 30),
('OAUTH_ABUSE',            'OAuth piktnaudžiavimas',                                        FALSE, TRUE,  9, 30),
('O365_TOKEN_THEFT',       'O365 token vagystė',                                            FALSE, TRUE, 10, 30),
('AZURE_ABUSE',            'Azure AD piktnaudžiavimas',                                    FALSE, TRUE, 10, 30),
('AWS_ABUSE',              'AWS IAM piktnaudžiavimas',                                     FALSE, TRUE, 10, 30),
('IMDS_ABUSE',             'Cloud IMDS metadata abuse',                                    FALSE, TRUE,  9, 30),
('SaaS_LATERAL',           'SaaS lateral movement',                                         FALSE, TRUE,  9, 30),
('AZURE_ARC_ABUSE',        'Azure Arc agent abuse',                                         FALSE, TRUE, 10, 30),
('POWER_PLATFORM_ABUSE',   'Power Platform/Automate abuse',                                FALSE, TRUE,  8, 30),
('MICROSOFT_TEAMS_PHISH',  'Teams phishing',                                                FALSE, TRUE,  8, 30),
('NHI_CREDENTIAL_ABUSE',   'Non-Human Identity abuse',                                     FALSE, TRUE,  9, 30),
('SLOPSQUATTING',          'AI paketo pavadinimų apgaulė',                                 FALSE, TRUE,  8, 30),
('AI_AGENT_COMPROMISE',    'AI agento kompromitavimas',                                    FALSE, TRUE,  9, 30),
('PROMPT_INJECTION_RCE',   'Prompt injection→RCE',                                         FALSE, TRUE,  9, 30),
('DEEPFAKE_VISHING',       'Deepfake vishing/BEC',                                         FALSE, TRUE,  7, 60),
('QUISHING',               'QR phishing',                                                   FALSE, TRUE,  6, 60),
('RUST_GO_MALWARE',        'Rust/Go malware loader',                                        FALSE, TRUE,  8, 30),
('GITHUB_ACTIONS_ABUSE',   'CI/CD pipeline abuse',                                          FALSE, TRUE,  8, 30),
('ICS_OT_RECON',           'ICS/SCADA žvalgyba',                                           FALSE, TRUE,  8, 30),
('CRYPTOMINING',           'Kriptovaliutų kasimas',                                         FALSE, TRUE,  7, 60),
('WIFI_ATTACK',            'Wi-Fi ataka',                                                   FALSE, TRUE,  7, 60),
('SCATTERED_SPIDER_TTP',   'Scattered Spider TTP',                                          FALSE, TRUE, 10, 30),
('VOLT_TYPHOON_TTP',       'Volt Typhoon TTP',                                              FALSE, TRUE, 10, 30),
('BLACKCAT_ALPHV_TTP',     'BlackCat/ALPHV TTP',                                           FALSE, TRUE, 11, 10),
('LAZARUS_TTP',            'Lazarus Group TTP',                                             FALSE, TRUE, 10, 30),
('HNDL_COLLECTION',        'Harvest Now Decrypt Later',                                    FALSE, TRUE,  7, 60),
('LIVING_OFF_TRUSTED_SITES','LOTS C2 per patikimas svetaines',                             FALSE, TRUE,  8, 30),
('SEO_POISONING_EXEC',     'SEO poisoning vykdymo grandinė',                               FALSE, TRUE,  7, 30),
('PASSWORD_POLICY_ENUM',   'Slaptažodžių politikos žvalgyba',                              FALSE, TRUE,  5, 60),
('SECURITY_TOOL_ENUM',     'AV/EDR įrankių išvardijimas',                                  FALSE, TRUE,  5, 60),
('VM_SANDBOX_DETECT',      'VM/sandbox aplinkos aptikimas',                                FALSE, TRUE,  5, 60),
('INTERNAL_SPEARPHISH',    'Vidinis spearphishing',                                         FALSE, TRUE,  8, 30),
('NTFS_ADS',               'NTFS Alternate Data Streams',                                   FALSE, TRUE,  7, 60),
('TIMESTOMPING',           'Failo laiko keitimas',                                          FALSE, TRUE,  6, 60)

ON CONFLICT (trigger_type) DO NOTHING;
