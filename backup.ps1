# ============================================================
#  SentinelHQ - Backup (Windows)
#  Usage: .\backup.ps1 [KeepDays]
#  Automatic: Task Scheduler nightly
# ============================================================

param([int]$KeepDays = 7)

$ROOT    = Split-Path -Parent $MyInvocation.MyCommand.Path
$TS      = Get-Date -Format "yyyyMMdd_HHmmss"
$BackDir = Join-Path $ROOT "backups\$TS"

function Write-OK   { param($m) Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "  [!!] $m" -ForegroundColor Yellow }
function Write-Fail { param($m) Write-Host "  [XX] $m" -ForegroundColor Red; exit 1 }

Write-Host "`n  SentinelHQ Backup - $TS`n" -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path $BackDir | Out-Null

# 1. PostgreSQL dump
Write-Host "  PostgreSQL dump..." -NoNewline
try {
    $sql = docker exec shq-postgres pg_dumpall -U shq 2>$null
    $sql | Out-File "$BackDir\postgres.sql" -Encoding utf8
    Compress-Archive -Path "$BackDir\postgres.sql" -DestinationPath "$BackDir\postgres.sql.gz" -Force
    Remove-Item "$BackDir\postgres.sql"
    Write-OK "postgres.sql.gz"
} catch {
    Write-Warn "PostgreSQL dump failed: $_"
}

# 2. .env
$envFile = Join-Path $ROOT "sentinelhq\.env"
if (Test-Path $envFile) {
    Copy-Item $envFile "$BackDir\.env"
    Write-OK ".env"
}

# 3. sentinelhq_api.yaml
$apiYaml = Join-Path $ROOT "sentinelhq\sentinelhq_api.yaml"
if (Test-Path $apiYaml) {
    Copy-Item $apiYaml "$BackDir\sentinelhq_api.yaml"
    Write-OK "sentinelhq_api.yaml"
}

# 4. Reports
$repDir = Join-Path $ROOT "sentinelhq\reports"
if (Test-Path $repDir) {
    $repCount = (Get-ChildItem $repDir -File).Count
    if ($repCount -gt 0) {
        Compress-Archive -Path "$repDir\*" -DestinationPath "$BackDir\reports.zip" -Force
        Write-OK "reports.zip ($repCount files)"
    }
}

# 5. Old backup cleanup
$cutoff = (Get-Date).AddDays(-$KeepDays)
Get-ChildItem (Join-Path $ROOT "backups") -Directory |
    Where-Object { $_.CreationTime -lt $cutoff } |
    ForEach-Object {
        Remove-Item $_.FullName -Recurse -Force
        Write-Warn "Deleted old backup: $($_.Name)"
    }

Write-OK "Backup complete: backups\$TS\"
Write-Host ""
