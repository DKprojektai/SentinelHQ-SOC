# ============================================================
#  SentinelHQ - Setup Wizard (Windows)
#  Reikalavimai: Docker Desktop, Git
#  Paleidimas: .\setup.ps1
# ============================================================

#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path

# ── SSL bypass (self-signed certs, PS 5.1 compatible) ────────
Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class SHQSsl {
    public static void TrustAll() {
        ServicePointManager.ServerCertificateValidationCallback =
            new RemoteCertificateValidationCallback((s,c,ch,e) => true);
        ServicePointManager.SecurityProtocol =
            SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
    }
}
"@ -ErrorAction SilentlyContinue
[SHQSsl]::TrustAll()

# ── i18n ─────────────────────────────────────────────────────
$T = @{}  # Vertimu zodynas - uzpildomas po kalbos pasirinkimo

function Set-Language {
    param([string]$lang)
    $script:LANG = $lang
    if ($lang -eq "en") {
        $script:T = @{
            title          = "SOC platform: Wazuh + Velociraptor + AI"
            step_prereq    = "Checking prerequisites"
            step_wazuh     = "Wazuh configuration"
            step_velo      = "Velociraptor configuration"
            step_shq       = "SentinelHQ configuration"
            step_llm       = "LLM configuration (optional)"
            step_telegram  = "Telegram configuration (optional)"
            step_extras    = "Additional components"
            step_confirm   = "Configuration summary"
            wazuh_opts     = @("Install new - Single Node (recommended)", "Install new - Multi Node", "Use existing Wazuh")
            velo_opts      = @("Install new (automatic)", "Use existing Velociraptor")
            llm_opts       = @("OpenRouter (recommended, paid)", "Local - LM Studio", "Local - Ollama", "Other (OpenAI-compatible)")
            docker_ok      = "Docker Desktop is running"
            docker_fail    = "Docker Desktop is not running. Start it and try again."
            git_ok         = "Git found"
            git_warn       = "Git not found - some modules may not download"
            wazuh_ip       = "Wazuh server IP"
            wazuh_api_user = "Wazuh API user"
            wazuh_api_pass = "Wazuh API password"
            wazuh_os_pass  = "OpenSearch/Indexer password"
            wazuh_local    = "Is Wazuh running on this same Docker host?"
            wazuh_network  = "Wazuh Docker network name"
            velo_url       = "Velociraptor URL"
            velo_api_cfg   = "Path to sentinelhq_api.yaml"
            velo_user      = "Velociraptor admin user"
            file_not_found = "File not found"
            org_name       = "Organization name"
            server_ip      = "Server IP address"
            dash_user      = "Dashboard admin user"
            llm_url_prompt = "LLM API URL"
            llm_key_prompt = "LLM API key (Enter = skip if local)"
            llm_model      = "LLM model"
            tg_prompt      = "Configure Telegram notifications?"
            tg_token       = "Bot Token"
            tg_chat_id     = "Chat ID"
            tg_info1       = "Get Bot Token from @BotFather on Telegram"
            tg_info2       = "Chat ID: send /start to bot - https://api.telegram.org/botTOKEN/getUpdates"
            tg_later       = "Telegram can be configured later via .env file"
            llm_later      = "LLM can be configured later: Dashboard -> LLM Agent"
            install_rules  = "Install socfortress Wazuh-Rules (extra detection rules)?"
            install_sysmon = "Install Sysmon configuration for Windows agents?"
            confirm_start  = "Start installation?"
            cancelled      = "Cancelled."
            installing     = "Installing..."
            done_title     = "INSTALLATION COMPLETE!"
            dash_url       = "Dashboard (admin)"
            portal_url     = "Portal (clients)"
            velo_url_lbl   = "Velociraptor GUI"
            wazuh_url      = "Wazuh Dashboard"
            login_user     = "User"
            login_pass     = "Password"
            save_warn      = "IMPORTANT: Save your passwords!"
            saved_at       = "Saved at: sentinelhq\.env"
            other_scripts  = "Other scripts"
            backup_script  = "create backup"
            update_script  = "update SentinelHQ"
            llm_warn       = "LLM not configured - Dashboard -> LLM Agent -> enter API key"
            tg_warn        = "Telegram not configured - edit sentinelhq\.env"
            auto_pass      = "passwords generated automatically"
            auto_velo_pass = "Velociraptor password generated"
            auto_shq_pass  = "SentinelHQ passwords generated"
            llm_config_q   = "Configure LLM?"
            summary_wazuh  = "Wazuh"
            summary_velo   = "Velociraptor"
            summary_ip     = "Server IP"
            summary_org    = "Organization"
            summary_llm    = "LLM"
            summary_tg     = "Telegram"
            summary_rules  = "Wazuh-Rules"
            summary_sysmon = "Sysmon"
            not_configured = "not configured"
            configured     = "configured"
            err_prefix     = "ERROR"
            help_wazuh     = @(
                "URL format: https://HOST:55000",
                "Default API user: wazuh-wui",
                "API password: check Wazuh .env file -> API_PASSWORD value",
                "Verify Wazuh containers are running: docker ps"
            )
            help_velo      = @(
                "URL format: https://HOST:8000",
                "Default Velociraptor GUI/API port: 8000",
                "Verify Velociraptor is running: docker ps"
            )
            help_api_yaml  = @(
                "The file must exist on THIS machine, not on the Velociraptor server",
                "See instructions above: generate -> copy via scp/WinSCP -> enter local path",
                "Example path: C:\Users\YourName\Downloads\sentinelhq_api.yaml"
            )
            help_llm       = @(
                "OpenRouter: get API key from openrouter.ai/keys",
                "URL must be: https://openrouter.ai/api/v1",
                "Local LM Studio: verify it is running and listening on port 1234",
                "Local Ollama: verify it is running and listening on port 11434"
            )
            help_tg        = @(
                "Get Bot Token from @BotFather on Telegram -> send /newbot",
                "Token format: 1234567890:AAABBBCCC...",
                "Make sure you copied the FULL token including the number prefix"
            )
        }
    } else {
        $script:T = @{
            title          = "SOC platforma: Wazuh + Velociraptor + AI"
            step_prereq    = "Tikrinamos prielaidos"
            step_wazuh     = "Wazuh konfigūracija"
            step_velo      = "Velociraptor konfigūracija"
            step_shq       = "SentinelHQ konfigūracija"
            step_llm       = "LLM konfigūracija (neprivaloma)"
            step_telegram  = "Telegram konfigūracija (neprivaloma)"
            step_extras    = "Papildomi komponentai"
            step_confirm   = "Konfigūracijos apžvalga"
            wazuh_opts     = @("Diegti nauja - Single Node (rekomenduojama)", "Diegti nauja - Multi Node", "Naudoti esama Wazuh")
            velo_opts      = @("Diegti naują (automatiškai)", "Naudoti esamą Velociraptor")
            llm_opts       = @("OpenRouter (rekomenduojama, mokamas)", "Lokalus - LM Studio", "Lokalus - Ollama", "Kitas (OpenAI-compatible)")
            docker_ok      = "Docker Desktop veikia"
            docker_fail    = "Docker Desktop neveikia. Paleisk ir bandyk iš naujo."
            git_ok         = "Git rastas"
            git_warn       = "Git nerastas - kai kurie moduliai gali neatsisiusti"
            wazuh_ip       = "Wazuh serverio IP"
            wazuh_api_user = "Wazuh API vartotojas"
            wazuh_api_pass = "Wazuh API slaptažodis"
            wazuh_os_pass  = "OpenSearch/Indexer slaptažodis"
            wazuh_local    = "Ar Wazuh veikia siame paciame Docker host'e?"
            wazuh_network  = "Wazuh Docker tinklo pavadinimas"
            velo_url       = "Velociraptor URL"
            velo_api_cfg   = "Kelias iki sentinelhq_api.yaml"
            velo_user      = "Velociraptor admin vartotojas"
            file_not_found = "Failas nerastas"
            org_name       = "Organizacijos pavadinimas"
            server_ip      = "Serverio IP adresas"
            dash_user      = "Dashboard admin vartotojas"
            llm_url_prompt = "LLM API URL"
            llm_key_prompt = "LLM API raktas (Enter = praleisti jei lokalus)"
            llm_model      = "LLM modelis"
            tg_prompt      = "Konfigūruoti Telegram notifikacijas?"
            tg_token       = "Bot Token"
            tg_chat_id     = "Chat ID"
            tg_info1       = "Bot Token gauti iš @BotFather Telegram"
            tg_info2       = "Chat ID: siusti /start botui - https://api.telegram.org/botTOKEN/getUpdates"
            tg_later       = "Telegram galima konfigūruoti vėliau per .env failą"
            llm_later      = "LLM galima konfigūruoti veliau Dashboard -> LLM Agentas"
            install_rules  = "Diegti socfortress Wazuh-Rules (papildomos aptikimo taisyklės)?"
            install_sysmon = "Diegti Sysmon konfigūraciją Windows agentams?"
            confirm_start  = "Pradėti diegimą?"
            cancelled      = "Atšaukta."
            installing     = "Diegiama..."
            done_title     = "DIEGIMAS BAIGTAS!"
            dash_url       = "Dashboard (admin)"
            portal_url     = "Portalas (klientai)"
            velo_url_lbl   = "Velociraptor GUI"
            wazuh_url      = "Wazuh Dashboard"
            login_user     = "Vartotojas"
            login_pass     = "Slaptažodis"
            save_warn      = "SVARBU: Išsaugokite slaptažodžius!"
            saved_at       = "Jie saugomi: sentinelhq\.env"
            other_scripts  = "Kiti skriptai"
            backup_script  = "sukurti backup"
            update_script  = "atnaujinti SentinelHQ"
            llm_warn       = "LLM nesukonf. - Dashboard -> LLM Agentas -> iveskite API rakta"
            tg_warn        = "Telegram nesukonf. - redaguokite sentinelhq\.env"
            auto_pass      = "slaptažodžiai sugeneruoti automatiškai"
            auto_velo_pass = "Velociraptor slaptažodis sugeneruotas"
            auto_shq_pass  = "SentinelHQ slaptažodžiai sugeneruoti"
            llm_config_q   = "Konfigūruoti LLM?"
            summary_wazuh  = "Wazuh"
            summary_velo   = "Velociraptor"
            summary_ip     = "Serverio IP"
            summary_org    = "Organizacija"
            summary_llm    = "LLM"
            summary_tg     = "Telegram"
            summary_rules  = "Wazuh-Rules"
            summary_sysmon = "Sysmon"
            not_configured = "nekonfigūruota"
            configured     = "sukonfigūruota"
            err_prefix     = "KLAIDA"
            help_wazuh     = @(
                "URL formatas: https://HOST:55000",
                "Numatytasis API vartotojas: wazuh-wui",
                "Slaptazodis: tikrinkite Wazuh .env faila -> API_PASSWORD reiksme",
                "Patikrinkite ar Wazuh konteineriai veikia: docker ps"
            )
            help_velo      = @(
                "URL formatas: https://HOST:8000",
                "Numatytasis Velociraptor GUI/API prievadas: 8000",
                "Patikrinkite ar Velociraptor veikia: docker ps"
            )
            help_api_yaml  = @(
                "Failas turi buti SIA masina, ne Velociraptor serveryje",
                "Ziurekite instrukcijas: generuoti -> kopijuoti (scp/WinSCP) -> ivesti lokalu kelia",
                "Pavyzdys: C:\Users\VardasPavarde\Downloads\sentinelhq_api.yaml"
            )
            help_llm       = @(
                "OpenRouter: API raktas is openrouter.ai/keys",
                "URL turi buti: https://openrouter.ai/api/v1",
                "Lokalus LM Studio: patikrinkite ar veikia ir klauso 1234 prievada",
                "Lokalus Ollama: patikrinkite ar veikia ir klauso 11434 prievada"
            )
            help_tg        = @(
                "Bot Token is @BotFather Telegram -> siusti /newbot",
                "Tokeno formatas: 1234567890:AAABBBCCC...",
                "Isitikinkite, kad nukopijuotas VISAS tokenas su skaiciaus prefiksu"
            )
        }
    }
}

# ── Spalvos / UI ─────────────────────────────────────────────
function Write-Header {
    Clear-Host
    Write-Host @"

  +----------------------------------------------------------+
  |                                                          |
  |          SentinelHQ  -  Setup Wizard                     |
  |          $($T.title)
  |                                                          |
  +----------------------------------------------------------+

"@ -ForegroundColor Magenta
}

function Write-Step  { param($n,$t) Write-Host "`n  [$n] $t" -ForegroundColor Cyan }
function Write-OK    { param($m) Write-Host "      OK  $m" -ForegroundColor Green }
function Write-Warn  { param($m) Write-Host "      !!  $m" -ForegroundColor Yellow }
function Write-Fail  { param($m) Write-Host "`n  $($T.err_prefix): $m`n" -ForegroundColor Red; exit 1 }
function Write-Info  { param($m) Write-Host "      ->  $m" -ForegroundColor Gray }

function Write-HelpBox {
    param([string[]]$Lines)
    Write-Host ""
    Write-Host "      [?] Help:" -ForegroundColor DarkCyan
    foreach ($line in $Lines) {
        Write-Host "          $line" -ForegroundColor Cyan
    }
    Write-Host ""
}

function Ask {
    param([string]$Prompt, [string]$Default = "", [switch]$Secret)
    $display = if ($Default) { "$Prompt [$Default]: " } else { "${Prompt}: " }
    Write-Host "      $display" -NoNewline -ForegroundColor White
    if ($Secret) {
        $s = Read-Host -AsSecureString
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))
    }
    $ans = Read-Host
    if ($ans -eq "" -and $Default -ne "") { return $Default }
    return $ans
}

function AskYN {
    param([string]$Prompt, [string]$Default = "Y")
    $opts = if ($Default -eq "Y") { "Y/n" } else { "y/N" }
    Write-Host "      $Prompt ($opts): " -NoNewline -ForegroundColor White
    $ans = Read-Host
    if ($ans -eq "") { return ($Default -eq "Y") }
    return ($ans -match '^[Yy]')
}

function AskChoice {
    param([string]$Prompt, [string[]]$Options, [int]$Default = 1)
    Write-Host "`n      $Prompt" -ForegroundColor White
    for ($i = 0; $i -lt $Options.Length; $i++) {
        Write-Host "        ($($i+1)) $($Options[$i])" -ForegroundColor Gray
    }
    Write-Host "      Choice [$Default]: " -NoNewline -ForegroundColor White
    $ans = Read-Host
    if ($ans -eq "") { return $Default }
    $n = [int]$ans
    if ($n -lt 1 -or $n -gt $Options.Length) { return $Default }
    return $n
}

function New-Password {
    param([int]$Length = 24)
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$"
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] $Length
    $rng.GetBytes($bytes)
    return -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

function New-HexString { param([int]$Bytes = 32)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $b = New-Object byte[] $Bytes; $rng.GetBytes($b)
    return [BitConverter]::ToString($b) -replace '-',''
}

function Get-LocalIP {
    try {
        $ip = (Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.InterfaceAlias -notmatch 'Loopback|vEthernet' -and
                           $_.IPAddress -notmatch '^169\.' } |
            Sort-Object PrefixLength | Select-Object -First 1).IPAddress
        return $ip
    } catch { return "127.0.0.1" }
}

function Wait-Healthy {
    # $ProbePort > 0: for images WITHOUT a Docker HEALTHCHECK (e.g. Wazuh 4.14),
    # fall back to "running + a successful TCP connect on the published port".
    # Otherwise .State.Health never becomes "healthy" and we always time out.
    # $ExecCmd: in-container readiness check (port-independent — for multi-node where
    # ports aren't published to host). Priority: ExecCmd > ProbePort > running.
    param([string]$Container, [int]$TimeoutSec = 180, [int]$ProbePort = 0, [string]$ExecCmd = "")
    Write-Info "Waiting for $Container to be ready..."
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $hasHealth = docker inspect --format='{{if .State.Health}}yes{{else}}no{{end}}' $Container 2>$null
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        $state = docker inspect --format='{{.State.Status}}' $Container 2>$null
        if ($state -eq "exited") { Write-Warn "$Container stopped!"; return $false }
        if ($hasHealth -eq "yes") {
            $status = docker inspect --format='{{.State.Health.Status}}' $Container 2>$null
            if ($status -eq "healthy") { Write-OK "$Container healthy"; return $true }
        } elseif ($state -eq "running") {
            if ($ExecCmd -ne "") {
                docker exec $Container sh -c $ExecCmd *> $null
                if ($LASTEXITCODE -eq 0) { Write-OK "$Container ready"; return $true }
            } elseif ($ProbePort -gt 0) {
                $ok = $false
                try {
                    $tc  = New-Object Net.Sockets.TcpClient
                    $iar = $tc.BeginConnect("127.0.0.1", $ProbePort, $null, $null)
                    if ($iar.AsyncWaitHandle.WaitOne(3000)) { $tc.EndConnect($iar); $ok = $tc.Connected }
                    $tc.Close()
                } catch { $ok = $false }
                if ($ok) { Write-OK "$Container ready (port $ProbePort)"; return $true }
            } else {
                Write-OK "$Container running"; return $true
            }
        }
        Write-Host "." -NoNewline
        Start-Sleep 5
    }
    Write-Warn "$Container timeout"
    return $false
}

function Wait-Up {
    param([string]$Container, [int]$TimeoutSec = 60)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        $state = docker inspect --format='{{.State.Status}}' $Container 2>$null
        if ($state -eq "running") { return $true }
        Start-Sleep 3
    }
    return $false
}

function Set-IndexerPassword {
    # Set OpenSearch 'admin' to the unique WazuhOsPass. filebeat (manager+worker) and
    # the manager keystore already use the same value via INDEXER_PASSWORD env; the
    # dashboard service uses 'kibanaserver', not 'admin'. 'admin' is reserved -> needs
    # securityadmin. internal_users.yml is a bind-mounted single file (host edits change
    # the inode; container sees stale) -> docker cp to a non-mounted path and feed that
    # to securityadmin, targeting the node hostname (-h), not 127.0.0.1. Best-effort.
    param([string]$Idx, [string]$NodeHost, [string]$Mgr, [string]$WazuhDir)
    $iu = Join-Path $WazuhDir "config\wazuh_indexer\internal_users.yml"
    if (-not (Test-Path $iu)) { Write-Warn "internal_users.yml not found - Wazuh admin keeps default"; return }
    Write-Info "Setting Wazuh indexer admin password..."
    $hashOut = docker exec $Idx bash -c "OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p '$($cfg.WazuhOsPass)'" 2>$null
    $hash = ($hashOut | Where-Object { $_ -match '^\$2' } | Select-Object -Last 1)
    if (-not $hash) { Write-Warn "hash generation failed - Wazuh admin keeps default"; return }
    $lines = Get-Content $iu; $a = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^admin:') { $a = $true; continue }
        if ($a -and $lines[$i] -match '^\s*hash:') { $lines[$i] = ('  hash: "{0}"' -f $hash); $a = $false }
    }
    [IO.File]::WriteAllLines($iu, $lines, (New-Object Text.UTF8Encoding $false))
    docker cp $iu "$Idx`:/tmp/iu.yml" 2>$null | Out-Null
    $applied = $false
    for ($n = 0; $n -lt 6; $n++) {
        docker exec $Idx bash -c "export JAVA_HOME=/usr/share/wazuh-indexer/jdk; /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f /tmp/iu.yml -t internalusers -icl -nhnv -cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem -cert /usr/share/wazuh-indexer/config/certs/admin.pem -key /usr/share/wazuh-indexer/config/certs/admin-key.pem -h $NodeHost" *> $null
        if ($LASTEXITCODE -eq 0) { $applied = $true; break }
        Start-Sleep 10
    }
    if ($applied) {
        docker exec $Mgr filebeat setup --index-management *> $null
        Write-OK "Wazuh indexer admin password set + filebeat template loaded"
    } else {
        Write-Warn "securityadmin apply failed - Wazuh admin may keep default (check manually)"
    }
}

function Set-IsmRetention {
    # Create an ISM policy that DELETES wazuh-alerts-*/wazuh-archives-* indices older
    # than $Days (default 90). Without it the indexer keeps every daily alert index
    # forever (23GB+ observed) -> disk fills. ism_template auto-applies to FUTURE
    # indices; we also attach to any that already exist. In-container curl against
    # localhost:9200 works for both single (9200 published) and multi (9200 internal).
    # JSON bodies are written to files + docker cp'd (PS 5.1 mangles embedded quotes
    # in native args). admin pw = WazuhOsPass if securityadmin succeeded else the
    # default SecretPassword -> try both. Best-effort + non-fatal.
    param([string]$Idx, [int]$Days = 90)
    if (-not (Test-ContainerPresent $Idx)) { Write-Warn "indexer '$Idx' not present - skipping ISM retention"; return }
    Write-Info "Configuring indexer log retention (ISM ${Days}d)..."
    $policy = '{"policy":{"description":"Delete wazuh-alerts/archives indices after ' + $Days + ' days","default_state":"hot","states":[{"name":"hot","actions":[],"transitions":[{"state_name":"delete","conditions":{"min_index_age":"' + $Days + 'd"}}]},{"name":"delete","actions":[{"delete":{}}],"transitions":[]}],"ism_template":[{"index_patterns":["wazuh-alerts-*","wazuh-archives-*"],"priority":100}]}}'
    $polFile = Join-Path $env:TEMP "ism_policy.json"
    $addFile = Join-Path $env:TEMP "ism_add.json"
    $enc = New-Object Text.UTF8Encoding $false
    [IO.File]::WriteAllText($polFile, $policy, $enc)
    [IO.File]::WriteAllText($addFile, '{"policy_id":"wazuh-alerts-retention"}', $enc)
    docker cp $polFile "$Idx`:/tmp/ism_policy.json" 2>$null | Out-Null
    docker cp $addFile "$Idx`:/tmp/ism_add.json" 2>$null | Out-Null
    $applied = $false
    foreach ($pw in @($cfg.WazuhOsPass, "SecretPassword")) {
        $resp = docker exec $Idx curl -sk -u "admin:$pw" -XPUT "https://localhost:9200/_plugins/_ism/policies/wazuh-alerts-retention" -H "Content-Type: application/json" -d "@/tmp/ism_policy.json" 2>$null
        if ($resp -match '"_id"|version_conflict|already exists|resource_already_exists') {
            $applied = $true
            docker exec $Idx curl -sk -u "admin:$pw" -XPOST "https://localhost:9200/_plugins/_ism/add/wazuh-alerts-*,wazuh-archives-*" -H "Content-Type: application/json" -d "@/tmp/ism_add.json" *> $null
            break
        }
    }
    Remove-Item $polFile, $addFile -ErrorAction SilentlyContinue
    if ($applied) { Write-OK "Indexer retention set: wazuh-alerts-*/archives deleted after ${Days}d" }
    else { Write-Warn "ISM retention not applied - set it manually (Dashboard > Index Management)" }
}

function Set-DashboardApiPassword {
    # Wazuh dashboard's wazuh.yml ships the DEFAULT manager-API password and is NOT
    # refreshed from env -> the Wazuh app 401s ("No API available"). Set it to
    # WazuhApiPass. wazuh.yml is a bind-mounted single file -> edit in place via
    # 'cat >' (sed -i rename fails). Best-effort + non-fatal.
    # The dashboard creates wazuh.yml LATE (after setup ends) and it's owned by the
    # wazuh-dashboard user. Don't block the installer: write a helper .ps1 and launch
    # it DETACHED — it waits in the background for wazuh.yml, rewrites the password
    # (as -u root; 'cat >' since the bind-mounted file can't be sed -i renamed) and
    # restarts the dashboard.
    param([string]$Dash, [string]$ApiPass)
    $wy = "/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
    $helper = Join-Path $ROOT ".set_wazuh_dashboard_pw.ps1"
    $body = @"
for (`$i=0; `$i -lt 120; `$i++) {
    docker exec -u root $Dash test -f $wy 2>`$null
    if (`$LASTEXITCODE -eq 0) {
        docker exec -u root $Dash bash -c "sed 's|password: .*|password: \`"$ApiPass\`"|' $wy > /tmp/wy && cat /tmp/wy > $wy && rm -f /tmp/wy" 2>`$null
        docker restart $Dash 2>`$null
        break
    }
    Start-Sleep 10
}
"@
    Set-Content -Path $helper -Value $body -Encoding utf8
    Start-Process powershell -ArgumentList "-NoProfile","-WindowStyle","Hidden","-File",$helper -WindowStyle Hidden
    Write-OK "Wazuh dashboard API password will be applied automatically once the dashboard finishes starting"
}

# ── Config objektas ───────────────────────────────────────────
$cfg = @{}

# ── Kalbos pasirinkimas ───────────────────────────────────────
Clear-Host
Write-Host @"

  +--------------------------------------+
  |     SentinelHQ - Setup Wizard        |
  +--------------------------------------+
  |  Select language / Pasirinkite kalba |
  |                                      |
  |    (1) English  [default]            |
  |    (2) Lietuviskai                   |
  +--------------------------------------+

"@ -ForegroundColor Magenta
Write-Host "  Choice / Pasirinkimas [1]: " -NoNewline -ForegroundColor White
$langInput = Read-Host
$selectedLang = if ($langInput -eq "2") { "lt" } else { "en" }
Set-Language $selectedLang

# ============================================================
Write-Header

# ── Žingsnis 0: Prielaidos ────────────────────────────────────
Write-Step "0/7" $T.step_prereq

# Docker
try { docker info 2>$null | Out-Null; Write-OK $T.docker_ok }
catch { Write-Fail $T.docker_fail }

# Git
try { git --version 2>$null | Out-Null; Write-OK $T.git_ok }
catch { Write-Warn $T.git_warn }

# ============================================================
# ── Žingsnis 1: WAZUH ─────────────────────────────────────────
Write-Step "1/7" $T.step_wazuh

$wazuhChoice = AskChoice "Wazuh:" $T.wazuh_opts

$cfg.WazuhMode = @("single","multi","existing")[$wazuhChoice - 1]

if ($cfg.WazuhMode -eq "existing") {
    $wazuhOk = $false
    do {
        $cfg.WazuhIP       = Ask $T.wazuh_ip
        $cfg.WazuhApiUser  = Ask $T.wazuh_api_user "wazuh-wui"
        $cfg.WazuhApiPass  = Ask $T.wazuh_api_pass -Secret
        $cfg.WazuhOsPass   = Ask $T.wazuh_os_pass -Secret
        $cfg.WazuhApiUrl   = "https://$($cfg.WazuhIP):55000"
        $cfg.OpenSearchUrl = "https://$($cfg.WazuhIP):9200"

        # Test Wazuh API connectivity
        Write-Host "      -> Testing Wazuh API..." -ForegroundColor Gray -NoNewline
        try {
            $pair = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($cfg.WazuhApiUser):$($cfg.WazuhApiPass)"))
            $resp = Invoke-WebRequest -Uri "$($cfg.WazuhApiUrl)/security/user/authenticate" `
                -Method POST -Headers @{Authorization="Basic $pair"} `
                -TimeoutSec 8 -ErrorAction Stop
            Write-Host " OK" -ForegroundColor Green
            $wazuhOk = $true
        } catch {
            # PS 5.1 throws exception on non-2xx - check if we got an HTTP response
            $statusCode = 0
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            } elseif ($_.Exception.InnerException -and $_.Exception.InnerException.Response) {
                $statusCode = [int]$_.Exception.InnerException.Response.StatusCode
            }
            if ($statusCode -eq 200) {
                Write-Host " OK" -ForegroundColor Green
                $wazuhOk = $true
            } elseif ($statusCode -gt 0) {
                Write-Host " HTTP $statusCode" -ForegroundColor Red
                Write-Warn "Wazuh API reachable but returned HTTP $statusCode. Check credentials."
                Write-HelpBox $T.help_wazuh
            } else {
                Write-Host " FAILED" -ForegroundColor Red
                Write-Warn "Cannot reach Wazuh API at $($cfg.WazuhApiUrl)."
                Write-Warn "Error: $($_.Exception.Message)"
                Write-HelpBox $T.help_wazuh
            }
        }
    } while (-not $wazuhOk)

    # Same Docker host question
    $cfg.WazuhSameHost = AskYN $T.wazuh_local "N"
    if ($cfg.WazuhSameHost) {
        $cfg.WazuhNetwork = Ask $T.wazuh_network "single-node_default"
    } else {
        $cfg.WazuhNetwork = ""
    }
} else {
    # Passwords auto-generated. Wazuh API rejects "insecure" passwords (Error 5007):
    # needs upper+lower+digit+special; New-Password is [A-Za-z0-9_-] and may omit a
    # special, so append a guaranteed-complexity suffix ('.' is safe everywhere).
    $cfg.WazuhApiPass  = (New-Password 16) + "aA1."
    $cfg.WazuhOsPass   = New-Password 20
    $cfg.WazuhApiUser  = "wazuh-wui"
    # Service hostnames differ: single (wazuh.manager/wazuh.indexer) vs
    # multi (wazuh.master + wazuh1.indexer cluster).
    if ($cfg.WazuhMode -eq "multi") {
        $cfg.WazuhApiUrl   = "https://wazuh.master:55000"
        $cfg.OpenSearchUrl = "https://wazuh1.indexer:9200"
    } else {
        $cfg.WazuhApiUrl   = "https://wazuh.manager:55000"
        $cfg.OpenSearchUrl = "https://wazuh.indexer:9200"
    }
    $cfg.WazuhNetwork  = if ($cfg.WazuhMode -eq "single") { "single-node_default" } else { "multi-node_default" }
    Write-OK $T.auto_pass
}

# ── Žingsnis 2: VELOCIRAPTOR ──────────────────────────────────
Write-Step "2/7" $T.step_velo

$veloChoice = AskChoice "Velociraptor:" $T.velo_opts

$cfg.VeloMode = @("new","existing")[$veloChoice - 1]

if ($cfg.VeloMode -eq "existing") {
    $veloOk = $false
    do {
        $cfg.VeloUrl = Ask $T.velo_url "https://192.168.1.100:8000"

        # Test Velociraptor URL connectivity (use curl.exe to avoid .NET TLS issues)
        Write-Host "      -> Testing Velociraptor..." -ForegroundColor Gray -NoNewline
        $curlExe = "$env:SystemRoot\System32\curl.exe"
        if (Test-Path $curlExe) {
            $httpCode = & $curlExe -sk -o NUL -w "%{http_code}" --connect-timeout 8 $cfg.VeloUrl 2>$null
            if ($httpCode -ne "000") {
                Write-Host " OK (HTTP $httpCode)" -ForegroundColor Green
                $veloOk = $true
            } else {
                Write-Host " FAILED" -ForegroundColor Red
                Write-Warn "Cannot reach Velociraptor at $($cfg.VeloUrl). Check IP/port and try again."
                Write-HelpBox $T.help_velo
            }
        } else {
            # Fallback: TCP port check
            try {
                $uri = [Uri]$cfg.VeloUrl
                $tcp = New-Object System.Net.Sockets.TcpClient
                $tcp.Connect($uri.Host, $uri.Port)
                $tcp.Close()
                Write-Host " OK (port open)" -ForegroundColor Green
                $veloOk = $true
            } catch {
                Write-Host " FAILED" -ForegroundColor Red
                Write-Warn "Cannot reach Velociraptor at $($cfg.VeloUrl). Check IP/port and try again."
                Write-HelpBox $T.help_velo
            }
        }
    } while (-not $veloOk)

    # sentinelhq_api.yaml - explain and loop until valid
    Write-Host ""
    Write-Host "  sentinelhq_api.yaml - Velociraptor API credentials file." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  STEP 1 - Generate on your Velociraptor server:" -ForegroundColor White
    Write-Host "    Docker:     docker exec velociraptor bash -c `"/velociraptor/velociraptor --config /velociraptor/server.config.yaml config api_client --name sentinelhq --role administrator /velociraptor/sentinelhq_api.yaml`"" -ForegroundColor Yellow
    Write-Host "                docker cp velociraptor:/velociraptor/sentinelhq_api.yaml ." -ForegroundColor Yellow
    Write-Host "    Standalone: velociraptor --config /etc/velociraptor/server.config.yaml config api_client --name sentinelhq --role administrator ~/sentinelhq_api.yaml" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  STEP 2 - Copy to THIS machine:" -ForegroundColor White
    Write-Host "    scp user@$($cfg.VeloUrl -replace 'https?://([^:/]+).*','$1'):/path/to/sentinelhq_api.yaml C:\sentinelhq_api.yaml" -ForegroundColor Yellow
    Write-Host "    (or use WinSCP / FileZilla to download it)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  STEP 3 - Enter the LOCAL path on THIS machine:" -ForegroundColor White
    Write-Host "    Example: C:\Users\$env:USERNAME\Downloads\sentinelhq_api.yaml" -ForegroundColor Gray
    Write-Host ""

    do {
        $cfg.VeloApiConfig = Ask $T.velo_api_cfg
        if ([string]::IsNullOrWhiteSpace($cfg.VeloApiConfig)) {
            Write-Warn "Path cannot be empty."
            Write-HelpBox $T.help_api_yaml
        } elseif (-not (Test-Path $cfg.VeloApiConfig)) {
            Write-Warn "$($T.file_not_found): $($cfg.VeloApiConfig) - enter the path on THIS machine"
            Write-HelpBox $T.help_api_yaml
            $cfg.VeloApiConfig = ""
        }
    } while ([string]::IsNullOrWhiteSpace($cfg.VeloApiConfig))
    Write-OK "sentinelhq_api.yaml found"
} else {
    $cfg.VeloUser = Ask $T.velo_user "admin"
    $cfg.VeloPass = New-Password 16
    Write-OK $T.auto_velo_pass
}

# ── Žingsnis 3: SENTINELHQ ────────────────────────────────────
Write-Step "3/7" $T.step_shq

$cfg.OrgName     = Ask $T.org_name "My Organization"
$detectedIP      = Get-LocalIP
$cfg.ServerIP    = Ask $T.server_ip $detectedIP
$cfg.DbPass      = New-Password 24
$cfg.SecretKey   = New-HexString 32
$cfg.InternalToken = New-HexString 32
$cfg.DashUser    = Ask $T.dash_user "admin"
$cfg.DashPass    = New-Password 16

Write-OK $T.auto_shq_pass

# ── Žingsnis 4: LLM (neprivaloma) ────────────────────────────
Write-Step "4/7" $T.step_llm
Write-Info "Supported: OpenRouter, LM Studio, Ollama or any OpenAI-compatible API"

$useLLM = AskYN $T.llm_config_q
if ($useLLM) {
    $llmChoice = AskChoice "LLM:" $T.llm_opts
    switch ($llmChoice) {
        1 { $cfg.LlmUrl = "https://openrouter.ai/api/v1"; $cfg.LlmModel = "google/gemini-2.5-flash" }
        2 { $cfg.LlmUrl = "http://host.docker.internal:1234/v1"; $cfg.LlmModel = "llama-3.2-3b-instruct" }
        3 { $cfg.LlmUrl = "http://host.docker.internal:11434/v1"; $cfg.LlmModel = "llama3.2" }
        4 { $cfg.LlmUrl = Ask $T.llm_url_prompt }
    }

    $llmValidated = $false
    do {
        $cfg.LlmKey   = Ask $T.llm_key_prompt ""
        $_llmDefault = if ($cfg.LlmModel) { $cfg.LlmModel } else { "google/gemini-2.5-flash" }
        $cfg.LlmModel = Ask $T.llm_model $_llmDefault

        Write-Host "      -> Testing LLM API..." -ForegroundColor Gray -NoNewline
        try {
            $llmHeaders = @{}
            if (-not [string]::IsNullOrWhiteSpace($cfg.LlmKey)) {
                $llmHeaders["Authorization"] = "Bearer $($cfg.LlmKey)"
            }
            $resp = Invoke-WebRequest -Uri "$($cfg.LlmUrl)/models" -Headers $llmHeaders `
                -TimeoutSec 10 -ErrorAction Stop
            Write-Host " OK" -ForegroundColor Green
            $llmValidated = $true
        } catch [System.Net.WebException] {
            if ($_.Exception.Response) {
                $code = [int]$_.Exception.Response.StatusCode
                if ($code -eq 401 -or $code -eq 403) {
                    Write-Host " UNAUTHORIZED (HTTP $code)" -ForegroundColor Red
                    Write-Warn "Invalid API key. Try again."
                    Write-HelpBox $T.help_llm
                } else {
                    # Any other HTTP response means server is reachable
                    Write-Host " OK (HTTP $code)" -ForegroundColor Green
                    $llmValidated = $true
                }
            } else {
                Write-Host " FAILED" -ForegroundColor Red
                Write-Warn "Cannot reach LLM at $($cfg.LlmUrl). Check URL/key and try again."
                Write-HelpBox $T.help_llm
            }
        } catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Warn "LLM API error: $($_.Exception.Message). Try again."
            Write-HelpBox $T.help_llm
        }
    } while (-not $llmValidated)
} else {
    $cfg.LlmUrl = "https://openrouter.ai/api/v1"
    $cfg.LlmKey = "UNCONFIGURED"
    $cfg.LlmModel = "google/gemini-2.5-flash"
    Write-Info $T.llm_later
}

# ── Žingsnis 5: TELEGRAM (neprivaloma) ───────────────────────
Write-Step "5/7" $T.step_telegram

$useTelegram = AskYN $T.tg_prompt
if ($useTelegram) {
    $tgOk = $false
    do {
        Write-Info $T.tg_info1
        $cfg.TgToken = Ask $T.tg_token

        Write-Host "      -> Testing Telegram bot token..." -ForegroundColor Gray -NoNewline
        try {
            $resp = Invoke-WebRequest -Uri "https://api.telegram.org/bot$($cfg.TgToken)/getMe" `
                -TimeoutSec 8 -ErrorAction Stop
            $botData = $resp.Content | ConvertFrom-Json
            if ($botData.ok) {
                Write-Host " OK (@$($botData.result.username))" -ForegroundColor Green
                $tgOk = $true
            } else {
                Write-Host " FAILED" -ForegroundColor Red
                Write-Warn "Invalid bot token. Get it from @BotFather and try again."
                Write-HelpBox $T.help_tg
            }
        } catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Warn "Cannot validate Telegram token: $($_.Exception.Message). Try again."
            Write-HelpBox $T.help_tg
        }
    } while (-not $tgOk)

    Write-Info $T.tg_info2
    $cfg.TgChatId = Ask $T.tg_chat_id
} else {
    $cfg.TgToken  = "UNCONFIGURED"
    $cfg.TgChatId = "UNCONFIGURED"
    Write-Info $T.tg_later
}

# ── Žingsnis 6: PAPILDOMI KOMPONENTAI ────────────────────────
Write-Step "6/7" $T.step_extras

$cfg.InstallWazuhRules = AskYN $T.install_rules "Y"
$cfg.InstallSysmon     = AskYN $T.install_sysmon "Y"

# ── Žingsnis 7: PATVIRTINIMAS ─────────────────────────────────
Write-Step "7/7" $T.step_confirm

Write-Host @"

  +---------------------------------------------+
  | $($T.summary_wazuh):        $($cfg.WazuhMode)
  | $($T.summary_velo): $($cfg.VeloMode)
  | $($T.summary_ip):  $($cfg.ServerIP)
  | $($T.summary_org): $($cfg.OrgName)
  | $($T.summary_llm):          $(if ($useLLM) { $cfg.LlmModel } else { $T.not_configured })
  | $($T.summary_tg):     $(if ($useTelegram) { $T.configured } else { $T.not_configured })
  | $($T.summary_rules):  $($cfg.InstallWazuhRules)
  | $($T.summary_sysmon):       $($cfg.InstallSysmon)
  +---------------------------------------------+

"@ -ForegroundColor Gray

$proceed = AskYN $T.confirm_start
if (-not $proceed) { Write-Host "`n  $($T.cancelled)`n"; exit 0 }

# ============================================================
#  DIEGIMAS
# ============================================================

Write-Host "`n  $($T.installing)`n" -ForegroundColor Cyan

# Container names depend on Wazuh mode. NOTE multi-node service is `wazuh1.indexer`
# (cluster wazuh1/2/3.indexer), NOT `wazuh.indexer`.
$wazuhManagerContainer = if ($cfg.WazuhMode -eq "multi") { "multi-node-wazuh.master-1" } else { "single-node-wazuh.manager-1" }
$wazuhIndexerContainer  = if ($cfg.WazuhMode -eq "multi") { "multi-node-wazuh1.indexer-1" } else { "single-node-wazuh.indexer-1" }
$wazuhIndexerHostname   = if ($cfg.WazuhMode -eq "multi") { "wazuh1.indexer" } else { "wazuh.indexer" }
$wazuhDashboardContainer = if ($cfg.WazuhMode -eq "multi") { "multi-node-wazuh.dashboard-1" } else { "single-node-wazuh.dashboard-1" }

# True only when a LOCAL manager container with that name exists. For WazuhMode=existing
# (remote / unknown name) the docker-exec steps below are skipped.
function Test-ContainerPresent { param([string]$Name) ((docker ps --format '{{.Names}}' 2>$null) -contains $Name) }
# Manager readiness command — works for single AND multi (port-independent).
$mgrReadyCmd = '/var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-analysisd is running"'

# ── A. WAZUH ──────────────────────────────────────────────────
if ($cfg.WazuhMode -ne "existing") {
    Write-Host "`n  [A] $($T.summary_wazuh)..." -ForegroundColor Cyan

    $wazuhDir = Join-Path $ROOT "modules\wazuh-$($cfg.WazuhMode)-node"

    if (-not (Test-Path (Join-Path $wazuhDir "docker-compose.yml"))) {
        Write-Info "Downloading Wazuh files..."
        $branch = if ($cfg.WazuhMode -eq "single") { "v4.14.7" } else { "v4.14.7" }
        $folder = if ($cfg.WazuhMode -eq "single") { "single-node" } else { "multi-node" }
        git clone --depth 1 -b $branch https://github.com/wazuh/wazuh-docker.git "$ROOT\_wazuh_tmp" 2>$null
        Copy-Item "$ROOT\_wazuh_tmp\$folder\*" $wazuhDir -Recurse -Force
        Remove-Item "$ROOT\_wazuh_tmp" -Recurse -Force
        Write-OK "Wazuh files downloaded"
    }

    # multi-node publishes the dashboard on host 443 (443:5601); single uses 5601.
    # Normalize multi to 5601 so the access URL is consistent across modes.
    if ($cfg.WazuhMode -eq "multi") {
        $composePath = Join-Path $wazuhDir "docker-compose.yml"
        (Get-Content $composePath -Raw) -replace '-\s*443:5601', '- 5601:5601' | Set-Content $composePath -Encoding utf8
    }

    # Certificates
    Write-Info "Generating SSL certificates..."
    # Pin compose project name: the module dir is wazuh-<mode>-node so the default
    # project would be "wazuh-single-node", but container names + WazuhNetwork below
    # assume "<mode>-node" (single-node). Pin -p to keep them consistent.
    $wazuhProject = "$($cfg.WazuhMode)-node"
    Push-Location $wazuhDir
    docker compose -p $wazuhProject -f generate-indexer-certs.yml run --rm generator 2>$null
    Write-OK "Certificates generated"

    # .env Wazuh
    @"
INDEXER_USERNAME=admin
INDEXER_PASSWORD=$($cfg.WazuhOsPass)
API_USERNAME=$($cfg.WazuhApiUser)
API_PASSWORD=$($cfg.WazuhApiPass)
"@ | Out-File ".env" -Encoding utf8

    # Start Wazuh
    Write-Info "Starting Wazuh (this may take 3-5 min)..."
    docker compose -p $wazuhProject up -d 2>$null
    Pop-Location

    # Wazuh 4.14 images have NO healthcheck. single-node publishes 9200; multi-node
    # does NOT (ports internal behind nginx) -> wait running only for multi indexer.
    # Manager uses an in-container wazuh-control check (port-independent, both modes).
    if ($cfg.WazuhMode -eq "multi") {
        Wait-Healthy $wazuhIndexerContainer 420 0 | Out-Null
    } else {
        Wait-Healthy $wazuhIndexerContainer 420 9200 | Out-Null
    }
    Wait-Healthy $wazuhManagerContainer 420 0 $mgrReadyCmd | Out-Null
    Write-OK "Wazuh started"

    # Set the unique indexer admin password (filebeat/keystore already use it via env)
    Set-IndexerPassword -Idx $wazuhIndexerContainer -NodeHost $wazuhIndexerHostname -Mgr $wazuhManagerContainer -WazuhDir $wazuhDir

    # Cap indexer disk growth: auto-delete alert indices older than 90 days (ISM).
    # (Manager .gz log pruning is handled by the wazuh.logcleaner compose sidecar.)
    Set-IsmRetention -Idx $wazuhIndexerContainer -Days 90

    $cfg.WazuhNetwork = "$($cfg.WazuhMode)-node_default"
}

# Create suppress rules file (skip if no local manager container — existing/remote Wazuh)
if (Test-ContainerPresent $wazuhManagerContainer) {
    Write-Info "Creating sentinelhq_rules.xml..."
    # Must be VALID: an empty <group></group> makes wazuh-analysisd fail (CRITICAL 1220)
    # and the manager won't start. Ship a level-0 no-op anchor rule.
    $xmlContent = @'
<group name="sentinelhq_noise,">
  <rule id="100099" level="0">
    <if_sid>1</if_sid>
    <description>SentinelHQ noise-suppression anchor (no-op)</description>
  </rule>
</group>
'@
    docker exec $wazuhManagerContainer bash -c "echo '$xmlContent' > /var/ossec/etc/rules/sentinelhq_rules.xml" 2>$null
    Write-OK "sentinelhq_rules.xml created"
} else {
    Write-Warn "Local Wazuh manager '$wazuhManagerContainer' not found - skipping sentinelhq_rules.xml (add it on your Wazuh manager manually)"
}

# ── B. WAZUH RULES (socfortress) ─────────────────────────────
if ($cfg.InstallWazuhRules -and -not (Test-ContainerPresent $wazuhManagerContainer)) {
    Write-Warn "Local Wazuh manager '$wazuhManagerContainer' not found - skipping socfortress rules (install on your Wazuh manager manually)"
} elseif ($cfg.InstallWazuhRules) {
    Write-Host "`n  [B] Wazuh-Rules (socfortress) install..." -ForegroundColor Cyan
    # socfortress ships DECODERS + RULES + CDB lists mixed. Dumping every *.xml into
    # rules/ puts decoder files there, so rules referencing them (maltrail -> CEF
    # decoder) fail with CRITICAL (1220) and analysisd refuses to start. Classify by
    # content (decoders -> decoders/, rules -> rules/), then VALIDATE; roll back if
    # analysisd won't come back. Best-effort: never fail the whole install.
    try {
        $rulesDir = Join-Path $ROOT "modules\wazuh-rules"
        if (-not (Test-Path (Join-Path $rulesDir ".git"))) {
            git clone --depth 1 https://github.com/socfortress/Wazuh-Rules.git $rulesDir 2>$null
        }
        # Snapshot current-good rules + decoders for rollback
        docker exec $wazuhManagerContainer bash -c 'rm -rf /var/ossec/etc/rules.bak /var/ossec/etc/decoders.bak; cp -a /var/ossec/etc/rules /var/ossec/etc/rules.bak; cp -a /var/ossec/etc/decoders /var/ossec/etc/decoders.bak' 2>$null
        # Classify each xml: decoder vs rule, copy to the correct dir
        Get-ChildItem $rulesDir -Filter "*.xml" -Recurse | ForEach-Object {
            $head = Get-Content $_.FullName -TotalCount 50 -ErrorAction SilentlyContinue
            if ($head -match '<decoder') {
                docker cp $_.FullName "${wazuhManagerContainer}:/var/ossec/etc/decoders/$($_.Name)" 2>$null
            } elseif ($head -match '<group|<rule') {
                docker cp $_.FullName "${wazuhManagerContainer}:/var/ossec/etc/rules/$($_.Name)" 2>$null
            }
        }
        # Validate: restart and confirm analysisd is actually running
        docker exec $wazuhManagerContainer /var/ossec/bin/wazuh-control restart 2>$null | Out-Null
        Start-Sleep 3
        $anal = docker exec $wazuhManagerContainer /var/ossec/bin/wazuh-control status 2>$null
        if ($anal -match 'wazuh-analysisd is running') {
            docker exec $wazuhManagerContainer bash -c 'rm -rf /var/ossec/etc/rules.bak /var/ossec/etc/decoders.bak' 2>$null
            Write-OK "Wazuh-Rules installed (socfortress)"
        } else {
            Write-Warn "socfortress rules broke analysisd config -> rolling back (core detection unaffected)"
            docker exec $wazuhManagerContainer bash -c 'rm -rf /var/ossec/etc/rules /var/ossec/etc/decoders; mv /var/ossec/etc/rules.bak /var/ossec/etc/rules; mv /var/ossec/etc/decoders.bak /var/ossec/etc/decoders' 2>$null
            docker exec $wazuhManagerContainer /var/ossec/bin/wazuh-control restart 2>$null | Out-Null
        }
    } catch {
        Write-Warn "Wazuh-Rules install failed: $_"
    }
}

# ── C. VELOCIRAPTOR ───────────────────────────────────────────
if ($cfg.VeloMode -eq "new") {
    Write-Host "`n  [C] Velociraptor install..." -ForegroundColor Cyan

    $veloDir = Join-Path $ROOT "modules\velociraptor"

    if (-not (Test-Path (Join-Path $veloDir "docker-compose.yaml"))) {
        Write-Info "Downloading Velociraptor files..."
        git clone --depth 1 https://github.com/weslambert/velociraptor-docker.git $veloDir 2>$null
        Write-OK "Velociraptor files downloaded"
    }

    # .env Velociraptor
    @"
VELOX_USER=$($cfg.VeloUser)
VELOX_PASSWORD=$($cfg.VeloPass)
VELOX_ROLE=administrator
VELOX_SERVER_URL=https://$($cfg.ServerIP):8000/
VELOX_FRONTEND_HOSTNAME=VelociraptorServer
"@ | Out-File (Join-Path $veloDir ".env") -Encoding utf8

    Push-Location $veloDir
    docker compose up -d --build 2>$null
    Pop-Location
    Wait-Up "velociraptor" 60 | Out-Null
    Start-Sleep 10

    # Generate API config
    Write-Info "Generating Velociraptor API config..."
    # `config api_client` output path is POSITIONAL, not --output (this velociraptor
    # build: "error: unknown long flag '--output'").
    docker exec velociraptor bash -c "/velociraptor/velociraptor --config /velociraptor/server.config.yaml config api_client --name sentinelhq --role administrator /velociraptor/sentinelhq_api.yaml" 2>$null
    $apiCfg = Join-Path $ROOT "config\sentinelhq_api.yaml"
    docker cp "velociraptor:/velociraptor/sentinelhq_api.yaml" $apiCfg 2>$null
    # api_connection_string defaults to frontend hostname "VelociraptorServer" which
    # SentinelHQ containers can't resolve; point it at the host IP (velo publishes 8001).
    if (Test-Path $apiCfg) {
        (Get-Content $apiCfg) -replace 'api_connection_string:.*', ('api_connection_string: "{0}:8001"' -f $cfg.ServerIP) |
            Set-Content $apiCfg -Encoding ascii
    }
    Write-OK "API config generated"

    $cfg.VeloUrl       = "https://$($cfg.ServerIP):8000"
    $cfg.VeloApiConfig = "/app/sentinelhq_api.yaml"
} else {
    # Use existing - copy API config
    Copy-Item $cfg.VeloApiConfig (Join-Path $ROOT "config\sentinelhq_api.yaml") -Force
}

# ── D. ACTIVE RESPONSE ────────────────────────────────────────
Write-Host "`n  [D] Wazuh Active Response..." -ForegroundColor Cyan
if (-not (Test-ContainerPresent $wazuhManagerContainer)) {
    Write-Warn "Local Wazuh manager '$wazuhManagerContainer' not found - skipping Active Response (append wazuh-config\sentinelhq_active_response.conf to ossec.conf on your Wazuh manager manually)"
} else {
    try {
        $arConf = Get-Content (Join-Path $ROOT "sentinelhq\wazuh-config\sentinelhq_active_response.conf") -Raw
        docker exec $wazuhManagerContainer bash -c "cat >> /var/ossec/etc/ossec.conf << 'AREOF'`n$arConf`nAREOF" 2>$null
        Write-OK "Active Response configured"
    } catch {
        Write-Warn "Active Response config failed - configure manually"
    }
}

# ── E. SENTINELHQ .env ────────────────────────────────────────
Write-Host "`n  [E] SentinelHQ configuration..." -ForegroundColor Cyan


$envContent = @"
# Auto-generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')

ORG_NAME=$($cfg.OrgName)
MANAGER_PUBLIC_IP=$($cfg.ServerIP)

DB_NAME=sentinelhq
DB_USER=shq
DB_PASS=$($cfg.DbPass)

OPENSEARCH_URL=$($cfg.OpenSearchUrl)
OPENSEARCH_USER=admin
OPENSEARCH_PASS=$($cfg.WazuhOsPass)
OPENSEARCH_INDEX=wazuh-alerts-*
WAZUH_VERIFY_SSL=false

WAZUH_API_URL=$($cfg.WazuhApiUrl)
WAZUH_API_USER=$($cfg.WazuhApiUser)
WAZUH_API_PASS=$($cfg.WazuhApiPass)
WAZUH_NETWORK=$($cfg.WazuhNetwork)

COLLECT_INTERVAL_SECONDS=30

ANALYZE_INTERVAL_SECONDS=600
NOISE_THRESHOLD_HOURLY=20
NOISE_WINDOW_HOURS=72
MIN_OCCURRENCES=10
RULE_ID_START=122000
RULE_ID_MAX=122999

LLM_API_URL=$($cfg.LlmUrl)
LLM_API_KEY=$($cfg.LlmKey)
LLM_MODEL=$($cfg.LlmModel)
LLM_POLL_INTERVAL=30

TELEGRAM_BOT_TOKEN=$($cfg.TgToken)
TELEGRAM_CHAT_ID=$($cfg.TgChatId)

DASHBOARD_PORT=8082
DASHBOARD_USER=$($cfg.DashUser)
DASHBOARD_PASS=$($cfg.DashPass)
SECRET_KEY=$($cfg.SecretKey)

PORTAL_PORT=8083

VELOCIRAPTOR_URL=$($cfg.VeloUrl)
VELOCIRAPTOR_API_CONFIG=$($cfg.VeloApiConfig)

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
REPORT_EMAIL_TO=
REPORT_DAY=monday
REPORT_HOUR=8

CORRELATE_INTERVAL=120
CORRELATE_WINDOW=10

INTERNAL_API_TOKEN=$($cfg.InternalToken)

TZ=Europe/Vilnius
"@

$envContent | Out-File (Join-Path $ROOT "sentinelhq\.env") -Encoding utf8

# Velociraptor API config -> sentinelhq/
Copy-Item (Join-Path $ROOT "config\sentinelhq_api.yaml") (Join-Path $ROOT "sentinelhq\sentinelhq_api.yaml") -Force -ErrorAction SilentlyContinue
Write-OK ".env created"

# ── Generate docker-compose.override.yml for wazuh-net ───────
$overridePath = Join-Path $ROOT "sentinelhq\docker-compose.override.yml"
if ($cfg.WazuhMode -eq "existing" -and -not $cfg.WazuhSameHost) {
    @"
# Auto-generated by setup - Wazuh is on a remote server
networks:
  wazuh-net:
    driver: bridge
    name: shq-wazuh-isolated
"@ | Out-File $overridePath -Encoding utf8
    Write-Info "wazuh-net: isolated bridge (Wazuh is remote)"
} else {
    $wazuhNetName = if ($cfg.WazuhNetwork) { $cfg.WazuhNetwork } else { "single-node_default" }
    @"
# Auto-generated by setup - Wazuh is on the same Docker host
networks:
  wazuh-net:
    external: true
    name: $wazuhNetName
"@ | Out-File $overridePath -Encoding utf8
    Write-Info "wazuh-net: external '$wazuhNetName'"
}

# ── F. START SENTINELHQ ───────────────────────────────────────
Write-Host "`n  [F] Starting SentinelHQ..." -ForegroundColor Cyan

Push-Location (Join-Path $ROOT "sentinelhq")
docker compose up -d --build 2>&1 | Where-Object { $_ -match "error|warning" } | ForEach-Object { Write-Info $_ }
Pop-Location

@("shq-postgres","shq-dashboard","shq-collector") | ForEach-Object {
    Wait-Healthy $_ 120 | Out-Null
}
Write-OK "SentinelHQ started"

# Point the Wazuh dashboard's wazuh.yml at the real API password (skip existing/remote)
if (($cfg.WazuhMode -ne "existing") -and (Test-ContainerPresent $wazuhDashboardContainer)) {
    Set-DashboardApiPassword -Dash $wazuhDashboardContainer -ApiPass $cfg.WazuhApiPass
}

# ── G. SYSMON CONFIG ──────────────────────────────────────────
if ($cfg.InstallSysmon) {
    $sysmonXml = Join-Path $ROOT "modules\sysmon\sysmonconfig.xml"
    if (-not (Test-Path $sysmonXml)) {
        Write-Info "Downloading Sysmon config..."
        try {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
                -OutFile $sysmonXml -TimeoutSec 15
        } catch { Write-Warn "Sysmon config download failed" }
    }
    Write-OK "Sysmon config ready: $sysmonXml"
    Write-Info "Deploy on Windows agents: Sysmon64.exe -accepteula -i sysmonconfig.xml"
}

# ── RESULT ────────────────────────────────────────────────────
Write-Host @"

  +--------------------------------------------------------------+
  |  $($T.done_title)
  +--------------------------------------------------------------+
  |                                                              |
  |  $($T.dash_url):   http://$($cfg.ServerIP):8082
  |  $($T.portal_url): http://$($cfg.ServerIP):8083
  |  $($T.velo_url_lbl):    https://$($cfg.ServerIP):8889
  |  $($T.wazuh_url):     https://$($cfg.ServerIP):5601
  |                                                              |
  |  Dashboard:                                                  |
  |    $($T.login_user): $($cfg.DashUser)
  |    $($T.login_pass): $($cfg.DashPass)
  |                                                              |
  |  Velociraptor:                                               |
  |    $($T.login_user): $(if ($cfg.VeloUser) { $cfg.VeloUser } else { 'admin' })
  |    $($T.login_pass): $(if ($cfg.VeloPass) { $cfg.VeloPass } else { '(existing)' })
  |                                                              |
  |  Wazuh Dashboard:                                            |
  |    $($T.login_user): admin
  |    $($T.login_pass): $($cfg.WazuhOsPass)
  |                                                              |
  |  $($T.save_warn)
  |  $($T.saved_at)
  |                                                              |
"@ -ForegroundColor Green

if (-not $useLLM) {
    Write-Host "  !!  $($T.llm_warn)" -ForegroundColor Yellow
}
if (-not $useTelegram) {
    Write-Host "  !!  $($T.tg_warn)" -ForegroundColor Yellow
}

Write-Host @"
  |                                                              |
  |  $($T.other_scripts):                                        |
  |    .\backup.ps1    - $($T.backup_script)
  |    .\update.ps1    - $($T.update_script)
  +--------------------------------------------------------------+

"@ -ForegroundColor Green
