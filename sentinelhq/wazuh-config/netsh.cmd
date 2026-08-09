@echo off
:: SentinelHQ — Windows Host Isolation via Windows Firewall
::
:: Palaikoma:
::   - Keli Wazuh manageriai (cluster) — taisyklė kiekvienam
::   - Hostname adresai — resolveinti į IP PRIEŠ izoliuojant
::   - DNS taisyklė tik jei DNS_SERVER nurodytas sentinelhq.conf
::   - Velociraptor forensics kanalas
::   - Lokalizacija-nepriklausoma politika per PowerShell

setlocal EnableDelayedExpansion

set ACTION=%~1
set RULE_NAME=SentinelHQ-ISOLATION
set "AGENT_DIR=%PROGRAMFILES(X86)%\ossec-agent"
set "OSSEC_CONF=%AGENT_DIR%\ossec.conf"
set "SENTINELHQ_CONF=%AGENT_DIR%\shared\sentinelhq.conf"
set "POLICY_BACKUP=%AGENT_DIR%\shared\sentinelhq_fw_policy.json"
set "LOG_FILE=%AGENT_DIR%\logs\active-responses.log"

:: ── 1. Visi managerių adresai iš ossec.conf (cluster palaikymas) ─────────────
set "MGR_COUNT=0"
for /f "tokens=2 delims=<>" %%i in (
    'findstr /i "<address>" "%OSSEC_CONF%" ^| findstr /v "<!--"'
) do (
    set /a MGR_COUNT+=1
    set "MGR_!MGR_COUNT!=%%i"
)

if %MGR_COUNT%==0 (
    echo %DATE% %TIME% ERROR: no manager addresses found in ossec.conf >> "%LOG_FILE%"
    goto END
)

:: ── 2. Resolve visi hostname'ai į IP PRIEŠ izoliuojant ──────────────────────
:: Po izoliacijos DNS gali būti nepasiekiamas — resolve darome dabar
for /l %%n in (1,1,%MGR_COUNT%) do (
    set "ADDR=!MGR_%%n!"
    echo !ADDR! | findstr /r "^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$" >nul 2>&1
    if errorlevel 1 (
        :: Tai hostname — resolveinti per ping
        set "RESOLVED="
        for /f "tokens=2 delims=[]" %%j in (
            'ping -n 1 -4 -w 1000 "!ADDR!" 2^>nul ^| findstr /i "Pinging"'
        ) do (
            if not defined RESOLVED set "RESOLVED=%%j"
        )
        if defined RESOLVED (
            echo %DATE% %TIME% Resolved !ADDR! ^-> !RESOLVED! >> "%LOG_FILE%"
            set "MGR_%%n=!RESOLVED!"
        ) else (
            echo %DATE% %TIME% WARN: Could not resolve !ADDR! -- skipping this manager >> "%LOG_FILE%"
            set "MGR_%%n="
        )
    )
)

:: ── 3. Velociraptor ir DNS iš sentinelhq.conf ────────────────────────────────
set "VELOCIRAPTOR_PORT="
set "DNS_SERVER="
if exist "%SENTINELHQ_CONF%" (
    for /f "tokens=1,2 delims==" %%a in (
        'findstr /v "^#" "%SENTINELHQ_CONF%"'
    ) do (
        if /i "%%a"=="VELOCIRAPTOR_PORT" if not defined VELOCIRAPTOR_PORT set "VELOCIRAPTOR_PORT=%%b"
        if /i "%%a"=="DNS_SERVER"        if not defined DNS_SERVER        set "DNS_SERVER=%%b"
    )
)

:: ── 4. Veiksmo nustatymas (Wazuh 4.2+ siunčia JSON per stdin) ────────────────
if /i "%ACTION%"=="add"    goto ISOLATE
if /i "%ACTION%"=="delete" goto UNISOLATE

for /f "delims=" %%i in (
    'powershell -NoProfile -ExecutionPolicy Bypass -Command "$j=([Console]::In.ReadToEnd()|ConvertFrom-Json); $j.command"'
) do set "ACTION=%%i"

if /i "%ACTION%"=="add"    goto ISOLATE
if /i "%ACTION%"=="delete" goto UNISOLATE
goto END

:: ════════════════════════════════════════════════════════════════════════════
:ISOLATE
echo %DATE% %TIME% ISOLATING managers=%MGR_COUNT% velociraptor_port=%VELOCIRAPTOR_PORT% dns=%DNS_SERVER% >> "%LOG_FILE%"

:: Išsaugome politiką į JSON (PowerShell — lokalizacija-nepriklausoma)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Get-NetFirewallProfile | Select-Object Name,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json | Set-Content -Encoding UTF8 -Path '%POLICY_BACKUP%'"

:: Keičiame politiką — blokuoti viską pagal nutylėjimą
:: Allow taisyklės viršija numatytąją politiką (ne explicit Block taisykles)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Block"

:: ── Loopback ─────────────────────────────────────────────────────────────────
netsh advfirewall firewall add rule name="%RULE_NAME%-LOOP-IN"  protocol=any dir=in  action=allow remoteip=127.0.0.1
netsh advfirewall firewall add rule name="%RULE_NAME%-LOOP-OUT" protocol=any dir=out action=allow remoteip=127.0.0.1

:: ── Wazuh manageriai — taisyklė kiekvienam (cluster) ────────────────────────
for /l %%n in (1,1,%MGR_COUNT%) do (
    if defined MGR_%%n (
        echo %DATE% %TIME% Allow manager %%n: !MGR_%%n! >> "%LOG_FILE%"
        netsh advfirewall firewall add rule name="%RULE_NAME%-WAZUH-OUT-%%n" protocol=TCP dir=out action=allow remoteip=!MGR_%%n! remoteport=1514
        netsh advfirewall firewall add rule name="%RULE_NAME%-WAZUH-IN-%%n"  protocol=TCP dir=in  action=allow remoteip=!MGR_%%n! remoteport=1514
    )
)

:: ── Velociraptor (tik jei sukonfigūruotas) ───────────────────────────────────
if defined VELOCIRAPTOR_PORT (
    :: Velociraptor serveris — tas pats kaip pirmasis manager
    if defined MGR_1 (
        netsh advfirewall firewall add rule name="%RULE_NAME%-VELOCI-OUT" protocol=TCP dir=out action=allow remoteip=!MGR_1! remoteport=%VELOCIRAPTOR_PORT%
        netsh advfirewall firewall add rule name="%RULE_NAME%-VELOCI-IN"  protocol=TCP dir=in  action=allow remoteip=!MGR_1! remoteport=%VELOCIRAPTOR_PORT%
    )
)

:: ── DNS (tik jei DNS_SERVER nurodytas sentinelhq.conf) ───────────────────────
:: Visi hostname'ai jau resolveinti prieš izoliuojant — DNS paprastai nebūtinas
if defined DNS_SERVER (
    netsh advfirewall firewall add rule name="%RULE_NAME%-DNS-OUT" protocol=UDP dir=out action=allow remoteip=%DNS_SERVER% remoteport=53
)

echo %DATE% %TIME% ISOLATED OK >> "%LOG_FILE%"
goto END

:: ════════════════════════════════════════════════════════════════════════════
:UNISOLATE
echo %DATE% %TIME% UNISOLATING >> "%LOG_FILE%"

:: Pašaliname loopback taisykles
netsh advfirewall firewall delete rule name="%RULE_NAME%-LOOP-IN"  >nul 2>&1
netsh advfirewall firewall delete rule name="%RULE_NAME%-LOOP-OUT" >nul 2>&1

:: Pašaliname managerių taisykles (bandome iki 10 — cluster dažniausiai ≤ 3)
for /l %%n in (1,1,10) do (
    netsh advfirewall firewall delete rule name="%RULE_NAME%-WAZUH-OUT-%%n" >nul 2>&1
    netsh advfirewall firewall delete rule name="%RULE_NAME%-WAZUH-IN-%%n"  >nul 2>&1
)

:: Pašaliname Velociraptor ir DNS taisykles
netsh advfirewall firewall delete rule name="%RULE_NAME%-VELOCI-OUT" >nul 2>&1
netsh advfirewall firewall delete rule name="%RULE_NAME%-VELOCI-IN"  >nul 2>&1
netsh advfirewall firewall delete rule name="%RULE_NAME%-DNS-OUT"    >nul 2>&1

:: Grąžiname originalią politiką iš JSON backup
if exist "%POLICY_BACKUP%" (
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "$profiles = @(Get-Content -Encoding UTF8 -Path '%POLICY_BACKUP%' | ConvertFrom-Json);" ^
        "foreach ($p in $profiles) {" ^
        "    Set-NetFirewallProfile -Name $p.Name" ^
        "        -DefaultInboundAction $p.DefaultInboundAction" ^
        "        -DefaultOutboundAction $p.DefaultOutboundAction" ^
        "}" ^
        "Remove-Item -Path '%POLICY_BACKUP%' -Force"
) else (
    echo %DATE% %TIME% WARN: policy backup not found, restoring Windows default >> "%LOG_FILE%"
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow"
)

echo %DATE% %TIME% UNISOLATED OK >> "%LOG_FILE%"
goto END

:END
endlocal
