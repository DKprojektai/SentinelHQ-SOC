#!/usr/bin/env bash
# ============================================================
#  SentinelHQ - Backup (Linux/Mac)
#  Usage: bash backup.sh [keep_days]
#  Automatic: cron 0 2 * * * /path/to/backup.sh
# ============================================================

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS=$(date '+%Y%m%d_%H%M%S')
KEEP_DAYS="${1:-7}"
BACK_DIR="$ROOT/backups/$TS"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}[OK]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!!]${NC} $1"; }

echo -e "\n  ${CYAN}SentinelHQ Backup - $TS${NC}\n"
mkdir -p "$BACK_DIR"

# 1. PostgreSQL dump
echo -n "  PostgreSQL dump..."
if docker exec shq-postgres pg_dumpall -U shq 2>/dev/null | gzip > "$BACK_DIR/postgres.sql.gz"; then
    ok "postgres.sql.gz"
else
    warn "PostgreSQL dump failed"
fi

# 2. .env
[ -f "$ROOT/sentinelhq/.env" ] && cp "$ROOT/sentinelhq/.env" "$BACK_DIR/.env" && ok ".env"

# 3. sentinelhq_api.yaml
[ -f "$ROOT/sentinelhq/sentinelhq_api.yaml" ] && \
    cp "$ROOT/sentinelhq/sentinelhq_api.yaml" "$BACK_DIR/sentinelhq_api.yaml" && ok "sentinelhq_api.yaml"

# 4. Reports
REP_DIR="$ROOT/sentinelhq/reports"
if [ -d "$REP_DIR" ] && [ "$(ls -A "$REP_DIR" 2>/dev/null)" ]; then
    tar -czf "$BACK_DIR/reports.tar.gz" -C "$REP_DIR" . && ok "reports.tar.gz"
fi

# 5. Old backup cleanup
find "$ROOT/backups" -maxdepth 1 -mindepth 1 -type d -mtime "+$KEEP_DAYS" | while read -r d; do
    rm -rf "$d"
    warn "Deleted old backup: $(basename "$d")"
done

ok "Backup complete: backups/$TS/"
echo
