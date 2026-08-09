# ============================================================
#  SentinelHQ - Update (Windows)
#  Usage: .\update.ps1 [-SkipBackup]
# ============================================================

param([switch]$SkipBackup)

$ROOT    = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvFile = Join-Path $ROOT "sentinelhq\.env"

function Write-Step { param($m) Write-Host "`n  >>> $m" -ForegroundColor Cyan }
function Write-OK   { param($m) Write-Host "      OK  $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "      !!  $m" -ForegroundColor Yellow }
function Write-Fail { param($m) Write-Host "`n  ERROR: $m`n" -ForegroundColor Red; exit 1 }

Write-Host "`n  SentinelHQ - Update`n" -ForegroundColor Magenta

# Current version
$curVer = Get-Content (Join-Path $ROOT "VERSION") -ErrorAction SilentlyContinue
Write-Host "  Current version: $curVer" -ForegroundColor Gray

# 1. Backup before update
if (-not $SkipBackup) {
    Write-Step "1/4 Creating backup..."
    & (Join-Path $ROOT "backup.ps1")
    Write-OK "Backup created"
} else {
    Write-Warn "Backup skipped (-SkipBackup)"
}

# 2. Git pull
Write-Step "2/4 Downloading new version..."
try {
    Push-Location $ROOT
    git fetch origin 2>$null
    $localRev  = git rev-parse HEAD 2>$null
    $remoteRev = git rev-parse origin/main 2>$null

    if ($localRev -eq $remoteRev) {
        Write-OK "Already up to date ($curVer)"
        Pop-Location
        exit 0
    }

    git pull origin main 2>$null
    Pop-Location
} catch {
    Pop-Location
    Write-Fail "git pull failed: $_"
}

$newVer = Get-Content (Join-Path $ROOT "VERSION") -ErrorAction SilentlyContinue
Write-OK "Version: $curVer -> $newVer"

# 3. Build and restart
Write-Step "3/4 Rebuilding SentinelHQ..."
try {
    Push-Location (Join-Path $ROOT "sentinelhq")
    docker compose pull 2>$null
    docker compose build --no-cache 2>&1 | Where-Object { $_ -match "error" } | ForEach-Object { Write-Warn $_ }
    docker compose up -d 2>$null
    Pop-Location
    Write-OK "Services started"
} catch {
    Pop-Location
    Write-Fail "Update failed: $_ - restore from backup"
}

# 4. Verify
Write-Step "4/4 Verifying..."
Start-Sleep 10
@("shq-postgres","shq-dashboard","shq-collector","shq-llm") | ForEach-Object {
    $s = docker inspect --format='{{.State.Status}}' $_ 2>$null
    if ($s -eq "running") { Write-OK "$_ running" }
    else { Write-Warn "$_ - $s" }
}

Write-Host "`n  Update complete: $newVer`n" -ForegroundColor Green
