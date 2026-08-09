#!/usr/bin/env bash
# ============================================================
#  SentinelHQ - Update (Linux/Mac)
#  Usage: bash update.sh [--skip-backup]
# ============================================================

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKIP_BACKUP="${1:-}"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; PURPLE='\033[0;35m'; NC='\033[0m'
step() { echo -e "\n  ${CYAN}>>> $1${NC}"; }
ok()   { echo -e "      ${GREEN}OK${NC}  $1"; }
warn() { echo -e "      ${YELLOW}!!${NC}  $1"; }
fail() { echo -e "\n  ${YELLOW}ERROR:${NC} $1\n"; exit 1; }

echo -e "\n  ${PURPLE}SentinelHQ - Update${NC}\n"
CUR_VER=$(cat "$ROOT/VERSION" 2>/dev/null || echo "unknown")
echo -e "  Current version: $CUR_VER"

# 1. Backup
if [ "$SKIP_BACKUP" != "--skip-backup" ]; then
    step "1/4 Creating backup..."
    bash "$ROOT/backup.sh"
    ok "Backup created"
else
    warn "Backup skipped"
fi

# 2. Git pull
step "2/4 Downloading new version..."
cd "$ROOT"
git fetch origin 2>/dev/null
LOCAL=$(git rev-parse HEAD 2>/dev/null)
REMOTE=$(git rev-parse origin/main 2>/dev/null)

if [ "$LOCAL" = "$REMOTE" ]; then
    ok "Already up to date ($CUR_VER)"
    exit 0
fi

git pull origin main
NEW_VER=$(cat "$ROOT/VERSION" 2>/dev/null || echo "unknown")
ok "Version: $CUR_VER -> $NEW_VER"

# 3. Build
step "3/4 Rebuilding SentinelHQ..."
(cd "$ROOT/sentinelhq" && docker compose build --no-cache && docker compose up -d)
ok "Services started"

# 4. Verify
step "4/4 Verifying..."
sleep 10
for c in shq-postgres shq-dashboard shq-collector shq-llm; do
    state=$(docker inspect --format='{{.State.Status}}' "$c" 2>/dev/null || echo "not found")
    [ "$state" = "running" ] && ok "$c running" || warn "$c - $state"
done

echo -e "\n  ${GREEN}Update complete: $NEW_VER${NC}\n"
