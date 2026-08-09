#!/usr/bin/env bash
# ============================================================
#  SentinelHQ - Setup Wizard (Linux / Mac)
#  Requirements: Docker, Docker Compose, Git
#  Usage: bash setup.sh
# ============================================================

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Colors / UI ───────────────────────────────────────────────
CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; PURPLE='\033[0;35m'; GRAY='\033[0;37m'; NC='\033[0m'; BOLD='\033[1m'

# ── i18n ─────────────────────────────────────────────────────
set_language() {
    LANG_CODE="$1"
    if [ "$LANG_CODE" = "lt" ]; then
        T_TITLE="SOC platforma: Wazuh + Velociraptor + AI"
        T_STEP_PREREQ="Tikrinamos prielaidos"
        T_STEP_WAZUH="Wazuh konfigūracija"
        T_STEP_VELO="Velociraptor konfigūracija"
        T_STEP_SHQ="SentinelHQ konfigūracija"
        T_STEP_LLM="LLM konfigūracija (neprivaloma)"
        T_STEP_TELEGRAM="Telegram konfigūracija (neprivaloma)"
        T_STEP_EXTRAS="Papildomi komponentai"
        T_STEP_CONFIRM="Konfigūracijos apžvalga"
        T_DOCKER_OK="Docker veikia"
        T_DOCKER_FAIL="Docker neveikia. Paleisk ir bandyk iš naujo."
        T_COMPOSE_OK="Docker Compose rastas"
        T_COMPOSE_FAIL="Docker Compose nerastas"
        T_GIT_OK="Git rastas"
        T_GIT_WARN="Git nerastas"
        T_WAZUH_OPT1="Diegti nauja - Single Node (rekomenduojama)"
        T_WAZUH_OPT2="Diegti nauja - Multi Node"
        T_WAZUH_OPT3="Naudoti esamą Wazuh"
        T_VELO_OPT1="Diegti naują (automatiškai)"
        T_VELO_OPT2="Naudoti esamą Velociraptor"
        T_LLM_OPT1="OpenRouter (rekomenduojama, mokamas)"
        T_LLM_OPT2="Lokalus - LM Studio"
        T_LLM_OPT3="Lokalus - Ollama"
        T_LLM_OPT4="Kitas (OpenAI-compatible)"
        T_WAZUH_IP="Wazuh serverio IP"
        T_WAZUH_API_USER="Wazuh API vartotojas"
        T_WAZUH_API_PASS="Wazuh API slaptažodis"
        T_WAZUH_OS_PASS="OpenSearch/Indexer slaptažodis"
        T_WAZUH_LOCAL="Ar Wazuh veikia siame paciame Docker host'e?"
        T_WAZUH_NETWORK="Wazuh Docker tinklo pavadinimas"
        T_VELO_URL="Velociraptor URL"
        T_VELO_API_CFG="Kelias iki sentinelhq_api.yaml"
        T_VELO_USER="Velociraptor admin vartotojas"
        T_FILE_NOT_FOUND="Failas nerastas"
        T_ORG_NAME="Organizacijos pavadinimas"
        T_SERVER_IP="Serverio IP adresas"
        T_DASH_USER="Dashboard admin vartotojas"
        T_AUTO_WAZUH_PASS="Wazuh slaptažodžiai sugeneruoti automatiškai"
        T_AUTO_VELO_PASS="Velociraptor slaptažodis sugeneruotas"
        T_AUTO_SHQ_PASS="SentinelHQ slaptažodžiai sugeneruoti"
        T_LLM_CHOICE="LLM tiekėjas:"
        T_LLM_CONFIG_Q="Konfigūruoti LLM?"
        T_LLM_URL="LLM API URL"
        T_LLM_KEY="LLM API raktas (Enter = praleisti jei lokalus)"
        T_LLM_MODEL="LLM modelis"
        T_LLM_LATER="LLM galima konfigūruoti veliau Dashboard -> LLM Agentas"
        T_TG_Q="Konfigūruoti Telegram notifikacijas?"
        T_TG_TOKEN="Bot Token"
        T_TG_CHAT_ID="Chat ID"
        T_TG_INFO1="Bot Token gauti iš @BotFather Telegram"
        T_TG_INFO2="Chat ID: siusti /start botui - https://api.telegram.org/botTOKEN/getUpdates"
        T_TG_LATER="Telegram galima konfigūruoti vėliau per .env failą"
        T_INSTALL_RULES="Diegti socfortress Wazuh-Rules (papildomos aptikimo taisyklės)?"
        T_INSTALL_SYSMON="Diegti Sysmon konfigūraciją Windows agentams?"
        T_CONFIRM_START="Pradėti diegimą?"
        T_CANCELLED="Atšaukta."
        T_INSTALLING="Diegiama..."
        T_SUMMARY_WAZUH="Wazuh"
        T_SUMMARY_VELO="Velociraptor"
        T_SUMMARY_IP="Serverio IP"
        T_SUMMARY_ORG="Organizacija"
        T_SUMMARY_LLM="LLM"
        T_SUMMARY_TG="Telegram"
        T_SUMMARY_RULES="Wazuh-Rules"
        T_SUMMARY_SYSMON="Sysmon"
        T_NOT_CONFIGURED="nekonfigūruota"
        T_CONFIGURED="sukonfigūruota"
        T_DONE_TITLE="DIEGIMAS BAIGTAS!"
        T_DASH_URL="Dashboard (admin)"
        T_PORTAL_URL="Portalas (klientai)"
        T_VELO_URL_LBL="Velociraptor GUI"
        T_WAZUH_URL="Wazuh Dashboard"
        T_LOGIN_USER="Vartotojas"
        T_LOGIN_PASS="Slaptažodis"
        T_SAVE_WARN="SVARBU: Išsaugokite slaptažodžius!"
        T_SAVED_AT="Jie saugomi: sentinelhq/.env"
        T_OTHER_SCRIPTS="Kiti skriptai"
        T_BACKUP_SCRIPT="sukurti backup"
        T_UPDATE_SCRIPT="atnaujinti SentinelHQ"
        T_LLM_WARN="LLM nesukonf. - Dashboard -> LLM Agentas -> iveskite API rakta"
        T_TG_WARN="Telegram nesukonf. - redaguokite sentinelhq/.env"
        T_CHOICE="Pasirinkimas"
        T_ERR="KLAIDA"
        T_HELP_WAZUH_1="URL formatas: https://HOST:55000"
        T_HELP_WAZUH_2="Numatytasis API vartotojas: wazuh-wui"
        T_HELP_WAZUH_3="Slaptazodis: tikrinkite Wazuh .env faila -> API_PASSWORD reiksme"
        T_HELP_WAZUH_4="Patikrinkite ar Wazuh konteineriai veikia: docker ps"
        T_HELP_VELO_1="URL formatas: https://HOST:8000"
        T_HELP_VELO_2="Numatytasis Velociraptor GUI/API prievadas: 8000"
        T_HELP_VELO_3="Patikrinkite ar Velociraptor veikia: docker ps"
        T_HELP_APIYAML_1="Failas turi buti SIA masina, ne Velociraptor serveryje"
        T_HELP_APIYAML_2="Ziurekite instrukcijas: generuoti -> kopijuoti (scp) -> ivesti lokalu kelia"
        T_HELP_APIYAML_3="Pavyzdys: /home/$(whoami)/sentinelhq_api.yaml"
        T_HELP_LLM_1="OpenRouter: API raktas is openrouter.ai/keys"
        T_HELP_LLM_2="URL turi buti: https://openrouter.ai/api/v1"
        T_HELP_LLM_3="Lokalus LM Studio: patikrinkite ar veikia ir klauso 1234 prievada"
        T_HELP_LLM_4="Lokalus Ollama: patikrinkite ar veikia ir klauso 11434 prievada"
        T_HELP_TG_1="Bot Token is @BotFather Telegram -> siusti /newbot"
        T_HELP_TG_2="Tokeno formatas: 1234567890:AAABBBCCC..."
        T_HELP_TG_3="Isitikinkite, kad nukopijuotas VISAS tokenas su skaiciaus prefiksu"
    else
        T_TITLE="SOC platform: Wazuh + Velociraptor + AI"
        T_STEP_PREREQ="Checking prerequisites"
        T_STEP_WAZUH="Wazuh configuration"
        T_STEP_VELO="Velociraptor configuration"
        T_STEP_SHQ="SentinelHQ configuration"
        T_STEP_LLM="LLM configuration (optional)"
        T_STEP_TELEGRAM="Telegram configuration (optional)"
        T_STEP_EXTRAS="Additional components"
        T_STEP_CONFIRM="Configuration summary"
        T_DOCKER_OK="Docker is running"
        T_DOCKER_FAIL="Docker is not running. Start it and try again."
        T_COMPOSE_OK="Docker Compose found"
        T_COMPOSE_FAIL="Docker Compose not found"
        T_GIT_OK="Git found"
        T_GIT_WARN="Git not found"
        T_WAZUH_OPT1="Install new - Single Node (recommended)"
        T_WAZUH_OPT2="Install new - Multi Node"
        T_WAZUH_OPT3="Use existing Wazuh"
        T_VELO_OPT1="Install new (automatic)"
        T_VELO_OPT2="Use existing Velociraptor"
        T_LLM_OPT1="OpenRouter (recommended, paid)"
        T_LLM_OPT2="Local - LM Studio"
        T_LLM_OPT3="Local - Ollama"
        T_LLM_OPT4="Other (OpenAI-compatible)"
        T_WAZUH_IP="Wazuh server IP"
        T_WAZUH_API_USER="Wazuh API user"
        T_WAZUH_API_PASS="Wazuh API password"
        T_WAZUH_OS_PASS="OpenSearch/Indexer password"
        T_WAZUH_LOCAL="Is Wazuh running on this same Docker host?"
        T_WAZUH_NETWORK="Wazuh Docker network name"
        T_VELO_URL="Velociraptor URL"
        T_VELO_API_CFG="Path to sentinelhq_api.yaml"
        T_VELO_USER="Velociraptor admin user"
        T_FILE_NOT_FOUND="File not found"
        T_ORG_NAME="Organization name"
        T_SERVER_IP="Server IP address"
        T_DASH_USER="Dashboard admin user"
        T_AUTO_WAZUH_PASS="Wazuh passwords generated automatically"
        T_AUTO_VELO_PASS="Velociraptor password generated"
        T_AUTO_SHQ_PASS="SentinelHQ passwords generated"
        T_LLM_CHOICE="LLM provider:"
        T_LLM_CONFIG_Q="Configure LLM?"
        T_LLM_URL="LLM API URL"
        T_LLM_KEY="LLM API key (Enter = skip if local)"
        T_LLM_MODEL="LLM model"
        T_LLM_LATER="LLM can be configured later: Dashboard -> LLM Agent"
        T_TG_Q="Configure Telegram notifications?"
        T_TG_TOKEN="Bot Token"
        T_TG_CHAT_ID="Chat ID"
        T_TG_INFO1="Get Bot Token from @BotFather on Telegram"
        T_TG_INFO2="Chat ID: send /start to bot - https://api.telegram.org/botTOKEN/getUpdates"
        T_TG_LATER="Telegram can be configured later via .env file"
        T_INSTALL_RULES="Install socfortress Wazuh-Rules (extra detection rules)?"
        T_INSTALL_SYSMON="Install Sysmon configuration for Windows agents?"
        T_CONFIRM_START="Start installation?"
        T_CANCELLED="Cancelled."
        T_INSTALLING="Installing..."
        T_SUMMARY_WAZUH="Wazuh"
        T_SUMMARY_VELO="Velociraptor"
        T_SUMMARY_IP="Server IP"
        T_SUMMARY_ORG="Organization"
        T_SUMMARY_LLM="LLM"
        T_SUMMARY_TG="Telegram"
        T_SUMMARY_RULES="Wazuh-Rules"
        T_SUMMARY_SYSMON="Sysmon"
        T_NOT_CONFIGURED="not configured"
        T_CONFIGURED="configured"
        T_DONE_TITLE="INSTALLATION COMPLETE!"
        T_DASH_URL="Dashboard (admin)"
        T_PORTAL_URL="Portal (clients)"
        T_VELO_URL_LBL="Velociraptor GUI"
        T_WAZUH_URL="Wazuh Dashboard"
        T_LOGIN_USER="User"
        T_LOGIN_PASS="Password"
        T_SAVE_WARN="IMPORTANT: Save your passwords!"
        T_SAVED_AT="Saved at: sentinelhq/.env"
        T_OTHER_SCRIPTS="Other scripts"
        T_BACKUP_SCRIPT="create backup"
        T_UPDATE_SCRIPT="update SentinelHQ"
        T_LLM_WARN="LLM not configured - Dashboard -> LLM Agent -> enter API key"
        T_TG_WARN="Telegram not configured - edit sentinelhq/.env"
        T_CHOICE="Choice"
        T_ERR="ERROR"
        T_HELP_WAZUH_1="URL format: https://HOST:55000"
        T_HELP_WAZUH_2="Default API user: wazuh-wui"
        T_HELP_WAZUH_3="API password: check Wazuh .env file -> API_PASSWORD value"
        T_HELP_WAZUH_4="Verify Wazuh containers are running: docker ps"
        T_HELP_VELO_1="URL format: https://HOST:8000"
        T_HELP_VELO_2="Default Velociraptor GUI/API port: 8000"
        T_HELP_VELO_3="Verify Velociraptor is running: docker ps"
        T_HELP_APIYAML_1="The file must exist on THIS machine, not on the Velociraptor server"
        T_HELP_APIYAML_2="See instructions above: generate -> copy via scp -> enter local path"
        T_HELP_APIYAML_3="Example: /home/$(whoami)/sentinelhq_api.yaml"
        T_HELP_LLM_1="OpenRouter: get API key from openrouter.ai/keys"
        T_HELP_LLM_2="URL must be: https://openrouter.ai/api/v1"
        T_HELP_LLM_3="Local LM Studio: verify it is running and listening on port 1234"
        T_HELP_LLM_4="Local Ollama: verify it is running and listening on port 11434"
        T_HELP_TG_1="Get Bot Token from @BotFather on Telegram -> send /newbot"
        T_HELP_TG_2="Token format: 1234567890:AAABBBCCC..."
        T_HELP_TG_3="Make sure you copied the FULL token including the number prefix"
    fi
}

header() {
    clear
    echo -e "${PURPLE}${BOLD}
  +----------------------------------------------------------+
  |                                                          |
  |          SentinelHQ  -  Setup Wizard                     |
  |          ${T_TITLE}
  |                                                          |
  +----------------------------------------------------------+
${NC}"
}

step()   { echo -e "\n  ${CYAN}[$1] $2${NC}"; }
ok()     { echo -e "      ${GREEN}OK${NC}  $1"; }
warn()   { echo -e "      ${YELLOW}!!${NC}  $1"; }
info()   { echo -e "      ${GRAY}->  $1${NC}"; }
fail()   { echo -e "\n  ${RED}${T_ERR}: $1${NC}\n"; exit 1; }

help_box() {
    echo ""
    echo -e "      ${CYAN}[?] Help:${NC}"
    while [ $# -gt 0 ]; do
        echo -e "          ${CYAN}$1${NC}"
        shift
    done
    echo ""
}

# NOTE: these helpers return their value on STDOUT (captured via $(...)), so all
# PROMPT text must go to STDERR (>&2) — otherwise it is swallowed into the
# variable and the user sees no prompt/menu.
ask() {
    local prompt="$1"; local default="${2:-}"
    if [ -n "$default" ]; then
        echo -ne "      ${BOLD}$prompt [$default]:${NC} " >&2
    else
        echo -ne "      ${BOLD}$prompt:${NC} " >&2
    fi
    read -r ans
    if [ -z "$ans" ] && [ -n "$default" ]; then echo "$default"; else echo "$ans"; fi
}

ask_secret() {
    local prompt="$1"
    echo -ne "      ${BOLD}$prompt:${NC} " >&2
    read -rs ans; echo >&2
    echo "$ans"
}

ask_yn() {
    local prompt="$1"; local default="${2:-Y}"
    local opts; [ "$default" = "Y" ] && opts="Y/n" || opts="y/N"
    echo -ne "      ${BOLD}$prompt ($opts):${NC} " >&2
    read -r ans
    [ -z "$ans" ] && ans="$default"
    [[ "$ans" =~ ^[Yy] ]]
}

ask_choice() {
    local prompt="$1"; shift; local opts=("$@")
    echo -e "\n      ${BOLD}$prompt${NC}" >&2
    local i=1
    for o in "${opts[@]}"; do echo -e "        ${GRAY}($i) $o${NC}" >&2; ((i++)); done
    echo -ne "      ${T_CHOICE} [1]: " >&2
    read -r ans
    [ -z "$ans" ] && ans=1
    echo "$ans"
}

gen_pass() {
    local len="${1:-24}"
    # Charset is restricted to URL/.env/shell-SAFE chars: [A-Za-z0-9_-] (URL
    # "unreserved"). Symbols like % @ # $ : / break the libpq DATABASE_URL
    # (postgresql://user:PASS@host/db) — e.g. '%' triggers psycopg2
    # "invalid dsn: invalid percent-encoded token" — and '$' is expanded by
    # docker-compose .env interpolation. 24 chars of [A-Za-z0-9_-] is ample entropy.
    # `tr </dev/urandom | head -c` makes head close the pipe → tr gets SIGPIPE
    # (exit 141). Under `set -euo pipefail` that aborts the whole script. The
    # trailing `|| true` swallows the SIGPIPE status; head still yields $len chars.
    LC_ALL=C tr -dc 'A-Za-z0-9_-' < /dev/urandom 2>/dev/null | head -c "$len" || true
}

gen_hex() {
    local bytes="${1:-32}"
    # openssl is the primary path; the /dev/urandom fallback has SIGPIPE-prone
    # pipes, so guard it with `|| true` to never abort under `set -euo pipefail`.
    openssl rand -hex "$bytes" 2>/dev/null || \
        { head -c "$bytes" /dev/urandom 2>/dev/null | xxd -p | tr -d '\n' || true; }
}

get_local_ip() {
    ip route get 1 2>/dev/null | awk '{print $7; exit}' || \
    hostname -I 2>/dev/null | awk '{print $1}' || \
    echo "127.0.0.1"
}

wait_healthy() {
    # $1=container  $2=timeout(s)  $3=HTTPS port on host (0/empty=skip)  $4=in-container readiness cmd
    # Wazuh 4.14 images define NO Docker HEALTHCHECK, so .State.Health is absent
    # (docker inspect errors "map has no entry for key Health"). Detect that and fall
    # back, in priority order: (a) $4 in-container exec check (port-independent — works
    # for multi-node where ports aren't published to host); (b) $3 host HTTPS port probe
    # (any HTTP response incl 401 = listening); (c) just "running". Only health-aware
    # images use the .State.Health path.
    local container="$1"; local timeout="${2:-180}"; local probe_port="${3:-}"; local exec_cmd="${4:-}"
    info "Waiting for $container to be ready..."
    local elapsed=0
    local has_health
    has_health=$(docker inspect --format='{{if .State.Health}}yes{{else}}no{{end}}' "$container" 2>/dev/null || echo "no")
    while [ $elapsed -lt $timeout ]; do
        local state; state=$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null || echo "unknown")
        [ "$state" = "exited" ] && { warn "$container stopped!"; return 1; }
        if [ "$has_health" = "yes" ]; then
            local status; status=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "unknown")
            [ "$status" = "healthy" ] && { ok "$container healthy"; return 0; }
        elif [ "$state" = "running" ]; then
            if [ -n "$exec_cmd" ]; then
                if docker exec "$container" sh -c "$exec_cmd" >/dev/null 2>&1; then
                    ok "$container ready"; return 0
                fi
            elif [ -n "$probe_port" ] && [ "$probe_port" != "0" ]; then
                local code; code=$(curl -sk -o /dev/null -w '%{http_code}' --connect-timeout 5 "https://localhost:${probe_port}" 2>/dev/null || echo "000")
                [ "$code" != "000" ] && { ok "$container ready (port ${probe_port}: HTTP ${code})"; return 0; }
            else
                ok "$container running"; return 0
            fi
        fi
        echo -n "."
        sleep 5; elapsed=$((elapsed+5))
    done
    echo; warn "$container timeout"; return 1
}

wait_up() {
    local container="$1"; local timeout="${2:-60}"
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        local state; state=$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null || echo "unknown")
        [ "$state" = "running" ] && return 0
        sleep 3; elapsed=$((elapsed+3))
    done
    return 1
}

set_indexer_password() {
    # Set the OpenSearch 'admin' password to the unique generated WAZUH_OS_PASS.
    # filebeat (manager+worker) and the manager keystore already pick up the same
    # value via the INDEXER_PASSWORD env (cont-init regenerates filebeat.yml from it
    # each start); the dashboard service uses 'kibanaserver', not 'admin', so it is
    # unaffected. 'admin' is a reserved user -> must be changed with securityadmin.
    # IMPORTANT lessons baked in:
    #   * internal_users.yml is a bind-mounted SINGLE FILE: editing it on the host via
    #     mv/sed changes the inode and the container keeps seeing the OLD content, so
    #     we 'docker cp' the edited file to a NON-mounted path and feed THAT to
    #     securityadmin.
    #   * securityadmin must target the node hostname (-h $WAZUH_INDEXER_HOSTNAME),
    #     NOT 127.0.0.1 (the indexer binds the hostname; loopback fails to connect).
    # Best-effort + NON-FATAL.
    local idx="$WAZUH_INDEXER_CONTAINER" host="$WAZUH_INDEXER_HOSTNAME"
    local iu="$WAZUH_DIR/config/wazuh_indexer/internal_users.yml"
    [ -f "$iu" ] || { warn "internal_users.yml not found — Wazuh admin keeps default password"; return 0; }
    info "Setting Wazuh indexer admin password..."
    local hash=""
    hash=$(docker exec "$idx" bash -c "OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p '$WAZUH_OS_PASS'" 2>/dev/null | grep '^\$2' | tail -n1) || true
    [ -n "$hash" ] || { warn "hash generation failed — Wazuh admin keeps default password"; return 0; }
    awk -v h="$hash" '/^admin:/{a=1} a&&/^[[:space:]]*hash:/{sub(/hash:.*/,"hash: \"" h "\"");a=0} {print}' "$iu" > "$iu.tmp" && mv "$iu.tmp" "$iu" || { rm -f "$iu.tmp"; warn "could not edit internal_users.yml"; return 0; }
    docker cp "$iu" "$idx:/tmp/iu.yml" >/dev/null 2>&1
    local applied=false n=0
    while [ $n -lt 6 ]; do
        if docker exec "$idx" bash -c "export JAVA_HOME=/usr/share/wazuh-indexer/jdk; /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f /tmp/iu.yml -t internalusers -icl -nhnv -cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem -cert /usr/share/wazuh-indexer/config/certs/admin.pem -key /usr/share/wazuh-indexer/config/certs/admin-key.pem -h $host" >/dev/null 2>&1; then
            applied=true; break
        fi
        n=$((n+1)); sleep 10
    done
    if [ "$applied" = true ]; then
        # filebeat already uses WAZUH_OS_PASS (INDEXER_PASSWORD env) -> load template now
        docker exec "$WAZUH_MANAGER_CONTAINER" filebeat setup --index-management >/dev/null 2>&1 || true
        ok "Wazuh indexer admin password set + filebeat template loaded"
    else
        warn "securityadmin apply failed — Wazuh admin may keep default password (check manually)"
    fi
}

configure_ism_retention() {
    # Create an ISM policy that DELETES wazuh-alerts-*/wazuh-archives-* indices
    # older than ISM_RETENTION_DAYS (default 90). Without it the indexer keeps
    # every daily alert index forever (23GB+ observed) -> disk fills. The policy's
    # ism_template auto-applies to FUTURE indices; we also attach it to any that
    # already exist. Runs in-container against localhost:9200 so it works for both
    # single (9200 published) and multi (9200 internal). Best-effort + NON-FATAL.
    # admin password is WAZUH_OS_PASS if securityadmin succeeded, else the default
    # SecretPassword -> try both.
    local idx="$WAZUH_INDEXER_CONTAINER"
    local days="${ISM_RETENTION_DAYS:-90}"
    docker ps --format '{{.Names}}' | grep -qx "$idx" || { warn "indexer '$idx' not present — skipping ISM retention"; return 0; }
    info "Configuring indexer log retention (ISM ${days}d)..."
    local policy
    policy=$(cat <<JSON
{"policy":{"description":"Delete wazuh-alerts/archives indices after ${days} days","default_state":"hot","states":[{"name":"hot","actions":[],"transitions":[{"state_name":"delete","conditions":{"min_index_age":"${days}d"}}]},{"name":"delete","actions":[{"delete":{}}],"transitions":[]}],"ism_template":[{"index_patterns":["wazuh-alerts-*","wazuh-archives-*"],"priority":100}]}}
JSON
)
    local pw applied=false resp
    for pw in "$WAZUH_OS_PASS" "SecretPassword"; do
        resp=$(docker exec "$idx" curl -sk -u "admin:$pw" -XPUT \
            "https://localhost:9200/_plugins/_ism/policies/wazuh-alerts-retention" \
            -H 'Content-Type: application/json' -d "$policy" 2>/dev/null)
        if echo "$resp" | grep -qE '"_id"|version_conflict|already exists|resource_already_exists'; then
            applied=true
            # attach to any pre-existing indices (idempotent; none on a fresh install)
            docker exec "$idx" curl -sk -u "admin:$pw" -XPOST \
                "https://localhost:9200/_plugins/_ism/add/wazuh-alerts-*,wazuh-archives-*" \
                -H 'Content-Type: application/json' \
                -d '{"policy_id":"wazuh-alerts-retention"}' >/dev/null 2>&1 || true
            break
        fi
    done
    if [ "$applied" = true ]; then
        ok "Indexer retention set: wazuh-alerts-*/archives deleted after ${days}d"
    else
        warn "ISM retention not applied — set it manually (Dashboard > Index Management)"
    fi
}

set_dashboard_api_password() {
    # The Wazuh DASHBOARD stores the manager-API connection in wazuh.yml with the
    # DEFAULT password (MyS3cr37P450r.*-) and does NOT refresh it from env, so the
    # Wazuh app 401s against the API ("No API available"). Set it to WAZUH_API_PASS.
    # wazuh.yml is a bind-mounted single file -> edit in place via 'cat >' (sed -i's
    # rename fails: "Device or resource busy"). Best-effort + NON-FATAL.
    # The OpenSearch Dashboards process creates wazuh.yml LATE (well after setup ends)
    # and the file is owned by the wazuh-dashboard user. Rather than block the
    # installer, drop a tiny helper that runs DETACHED: it waits (in the background)
    # for wazuh.yml to appear, then rewrites the password (as -u root; sed -i rename
    # fails on the bind-mounted file -> use 'cat >') and restarts the dashboard.
    local d="$WAZUH_DASHBOARD_CONTAINER"
    local helper="$ROOT/.set_wazuh_dashboard_pw.sh"
    cat > "$helper" <<EOF
#!/bin/bash
# Auto-generated by setup. Sets the Wazuh dashboard's API password once it is ready.
wy=/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
for i in \$(seq 1 120); do
  if docker exec -u root $d test -f "\$wy" 2>/dev/null; then
    docker exec -u root $d bash -c "sed 's|password: .*|password: \"$WAZUH_API_PASS\"|' \$wy > /tmp/wy && cat /tmp/wy > \$wy && rm -f /tmp/wy"
    docker restart $d
    exit 0
  fi
  sleep 10
done
EOF
    chmod +x "$helper"
    nohup "$helper" >/dev/null 2>&1 &
    ok "Wazuh dashboard API password will be applied automatically once the dashboard finishes starting"
}

# ============================================================
#  LANGUAGE SELECTION
# ============================================================
clear
echo -e "${PURPLE}${BOLD}
  +--------------------------------------+
  |     SentinelHQ - Setup Wizard        |
  +--------------------------------------+
  |  Select language / Pasirinkite kalba |
  |                                      |
  |    (1) English  [default]            |
  |    (2) Lietuviskai                   |
  +--------------------------------------+
${NC}"
echo -ne "  Choice / Pasirinkimas [1]: "
read -r lang_input
[ "$lang_input" = "2" ] && set_language "lt" || set_language "en"

# ============================================================
header

# ── Step 0: Prerequisites ─────────────────────────────────────
step "0/7" "$T_STEP_PREREQ"

docker info >/dev/null 2>&1 || fail "$T_DOCKER_FAIL"
ok "$T_DOCKER_OK"

docker compose version >/dev/null 2>&1 || \
    docker-compose version >/dev/null 2>&1 || \
    fail "$T_COMPOSE_FAIL"
ok "$T_COMPOSE_OK"

git --version >/dev/null 2>&1 && ok "$T_GIT_OK" || warn "$T_GIT_WARN"

# ── Step 1: WAZUH ─────────────────────────────────────────────
step "1/7" "$T_STEP_WAZUH"

WAZUH_CHOICE=$(ask_choice "Wazuh:" "$T_WAZUH_OPT1" "$T_WAZUH_OPT2" "$T_WAZUH_OPT3")

WAZUH_MODE="single"
case $WAZUH_CHOICE in
    2) WAZUH_MODE="multi" ;;
    3) WAZUH_MODE="existing" ;;
esac

if [ "$WAZUH_MODE" = "existing" ]; then
    WAZUH_OK=false
    while [ "$WAZUH_OK" = false ]; do

        WAZUH_IP=$(ask "$T_WAZUH_IP")
        WAZUH_API_USER=$(ask "$T_WAZUH_API_USER" "wazuh-wui")
        WAZUH_API_PASS=$(ask_secret "$T_WAZUH_API_PASS")
        WAZUH_OS_PASS=$(ask_secret "$T_WAZUH_OS_PASS")
        WAZUH_API_URL="https://${WAZUH_IP}:55000"
        OPENSEARCH_URL="https://${WAZUH_IP}:9200"

        echo -ne "      ${GRAY}-> Testing Wazuh API...${NC} "
        HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
            -X POST -u "${WAZUH_API_USER}:${WAZUH_API_PASS}" \
            --connect-timeout 8 \
            "${WAZUH_API_URL}/security/user/authenticate" 2>/dev/null || echo "000")
        if [ "$HTTP_CODE" = "200" ]; then
            echo -e "${GREEN}OK${NC}"
            WAZUH_OK=true
        else
            echo -e "${RED}FAILED (HTTP ${HTTP_CODE})${NC}"
            warn "Cannot reach Wazuh API at ${WAZUH_API_URL}. Check IP and credentials and try again."
            help_box "$T_HELP_WAZUH_1" "$T_HELP_WAZUH_2" "$T_HELP_WAZUH_3" "$T_HELP_WAZUH_4"
        fi
    done
else
    # Wazuh API rejects "insecure" passwords (Error 5007): requires upper+lower+digit
    # +special. gen_pass charset is [A-Za-z0-9_-] (URL/.env-safe) and may omit a
    # special by chance, so append a guaranteed-complexity suffix ('.' is URL/.env/
    # Wazuh-safe). Without this the manager crash-loops configuring the API user.
    WAZUH_API_PASS="$(gen_pass 16)aA1."
    WAZUH_OS_PASS=$(gen_pass 20)
    WAZUH_API_USER="wazuh-wui"
    # Service hostnames differ between single (wazuh.manager/wazuh.indexer) and
    # multi (wazuh.master + wazuh1.indexer cluster). SentinelHQ resolves these on
    # the shared wazuh-net, so the .env URLs must match the chosen mode.
    if [ "$WAZUH_MODE" = "multi" ]; then
        WAZUH_API_URL="https://wazuh.master:55000"
        OPENSEARCH_URL="https://wazuh1.indexer:9200"
    else
        WAZUH_API_URL="https://wazuh.manager:55000"
        OPENSEARCH_URL="https://wazuh.indexer:9200"
    fi
    WAZUH_NETWORK="${WAZUH_MODE}-node_default"
    ok "$T_AUTO_WAZUH_PASS"
fi

# ── Step 2: VELOCIRAPTOR ──────────────────────────────────────
step "2/7" "$T_STEP_VELO"

VELO_CHOICE=$(ask_choice "Velociraptor:" "$T_VELO_OPT1" "$T_VELO_OPT2")

VELO_MODE="new"
[ "$VELO_CHOICE" = "2" ] && VELO_MODE="existing"

if [ "$VELO_MODE" = "existing" ]; then
    VELO_OK=false
    while [ "$VELO_OK" = false ]; do
        VELO_URL=$(ask "$T_VELO_URL" "https://192.168.1.100:8000")

        echo -ne "      ${GRAY}-> Testing Velociraptor...${NC} "
        HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
            --connect-timeout 8 "${VELO_URL}" 2>/dev/null || echo "000")
        if [ "$HTTP_CODE" != "000" ]; then
            echo -e "${GREEN}OK (HTTP ${HTTP_CODE})${NC}"
            VELO_OK=true
        else
            echo -e "${RED}FAILED${NC}"
            warn "Cannot reach Velociraptor at ${VELO_URL}. Check IP/port and try again."
            help_box "$T_HELP_VELO_1" "$T_HELP_VELO_2" "$T_HELP_VELO_3"
        fi
    done

    # Same Docker host?
    WAZUH_SAME_HOST=false
    if ask_yn "$T_WAZUH_LOCAL" "N"; then
        WAZUH_SAME_HOST=true
        WAZUH_NETWORK=$(ask "$T_WAZUH_NETWORK" "single-node_default")
    else
        WAZUH_SAME_HOST=false
        WAZUH_NETWORK=""
    fi

    # sentinelhq_api.yaml - explain and loop until valid
    VELO_HOST=$(echo "$VELO_URL" | sed 's|https\?://||' | cut -d: -f1)
    echo ""
    echo -e "  ${CYAN}sentinelhq_api.yaml - Velociraptor API credentials file.${NC}"
    echo ""
    echo -e "  ${BOLD}STEP 1 - Generate on your Velociraptor server:${NC}"
    echo -e "    ${YELLOW}Docker:     docker exec velociraptor bash -c \"/velociraptor/velociraptor --config /velociraptor/server.config.yaml config api_client --name sentinelhq --role administrator /velociraptor/sentinelhq_api.yaml\"${NC}"
    echo -e "    ${YELLOW}            docker cp velociraptor:/velociraptor/sentinelhq_api.yaml .${NC}"
    echo -e "    ${YELLOW}Standalone: velociraptor --config /etc/velociraptor/server.config.yaml config api_client --name sentinelhq --role administrator ~/sentinelhq_api.yaml${NC}"
    echo ""
    echo -e "  ${BOLD}STEP 2 - Copy to THIS machine:${NC}"
    echo -e "    ${YELLOW}scp user@${VELO_HOST}:/path/to/sentinelhq_api.yaml ~/sentinelhq_api.yaml${NC}"
    echo ""
    echo -e "  ${BOLD}STEP 3 - Enter the LOCAL path on THIS machine:${NC}"
    echo -e "    ${GRAY}Example: /home/$(whoami)/sentinelhq_api.yaml${NC}"
    echo ""

    while true; do
        VELO_API_CONFIG=$(ask "$T_VELO_API_CFG")
        if [ -z "$VELO_API_CONFIG" ]; then
            warn "Path cannot be empty."
            help_box "$T_HELP_APIYAML_1" "$T_HELP_APIYAML_2" "$T_HELP_APIYAML_3"
        elif [ ! -f "$VELO_API_CONFIG" ]; then
            warn "$T_FILE_NOT_FOUND: $VELO_API_CONFIG - enter the path on THIS machine"
            help_box "$T_HELP_APIYAML_1" "$T_HELP_APIYAML_2" "$T_HELP_APIYAML_3"
        else
            ok "sentinelhq_api.yaml found"
            break
        fi
    done
else
    VELO_USER=$(ask "$T_VELO_USER" "admin")
    VELO_PASS=$(gen_pass 16)
    ok "$T_AUTO_VELO_PASS"
fi

# ── Step 3: SENTINELHQ ────────────────────────────────────────
step "3/7" "$T_STEP_SHQ"

ORG_NAME=$(ask "$T_ORG_NAME" "My Organization")
DETECTED_IP=$(get_local_ip)
SERVER_IP=$(ask "$T_SERVER_IP" "$DETECTED_IP")
DB_PASS=$(gen_pass 24)
SECRET_KEY=$(gen_hex 32)
INTERNAL_TOKEN=$(gen_hex 32)
DASH_USER=$(ask "$T_DASH_USER" "admin")
DASH_PASS=$(gen_pass 16)

ok "$T_AUTO_SHQ_PASS"

# ── Step 4: LLM ───────────────────────────────────────────────
step "4/7" "$T_STEP_LLM"

USE_LLM=false
LLM_URL="https://openrouter.ai/api/v1"
LLM_KEY="UNCONFIGURED"
LLM_MODEL="google/gemini-2.5-flash"

if ask_yn "$T_LLM_CONFIG_Q"; then
    USE_LLM=true
    LLM_CHOICE=$(ask_choice "$T_LLM_CHOICE" "$T_LLM_OPT1" "$T_LLM_OPT2" "$T_LLM_OPT3" "$T_LLM_OPT4")
    case $LLM_CHOICE in
        1) LLM_URL="https://openrouter.ai/api/v1"; LLM_MODEL="google/gemini-2.5-flash" ;;
        2) LLM_URL="http://host.docker.internal:1234/v1"; LLM_MODEL="llama-3.2-3b-instruct" ;;
        3) LLM_URL="http://host.docker.internal:11434/v1"; LLM_MODEL="llama3.2" ;;
        4) LLM_URL=$(ask "$T_LLM_URL") ;;
    esac

    LLM_VALIDATED=false
    while [ "$LLM_VALIDATED" = false ]; do
        LLM_KEY=$(ask "$T_LLM_KEY" "")
        LLM_MODEL=$(ask "$T_LLM_MODEL" "$LLM_MODEL")

        echo -ne "      ${GRAY}-> Testing LLM API...${NC} "
        if [ -n "$LLM_KEY" ]; then
            HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
                -H "Authorization: Bearer ${LLM_KEY}" \
                --connect-timeout 10 "${LLM_URL}/models" 2>/dev/null || echo "000")
        else
            HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
                --connect-timeout 10 "${LLM_URL}/models" 2>/dev/null || echo "000")
        fi
        if [ "$HTTP_CODE" = "000" ]; then
            echo -e "${RED}FAILED${NC}"
            warn "Cannot reach LLM at ${LLM_URL}. Check URL/key and try again."
            help_box "$T_HELP_LLM_1" "$T_HELP_LLM_2" "$T_HELP_LLM_3" "$T_HELP_LLM_4"
        elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
            echo -e "${RED}UNAUTHORIZED (HTTP ${HTTP_CODE})${NC}"
            warn "Invalid API key. Try again."
            help_box "$T_HELP_LLM_1" "$T_HELP_LLM_2" "$T_HELP_LLM_3" "$T_HELP_LLM_4"
        else
            echo -e "${GREEN}OK (HTTP ${HTTP_CODE})${NC}"
            LLM_VALIDATED=true
        fi
    done
else
    info "$T_LLM_LATER"
fi

# ── Step 5: TELEGRAM ─────────────────────────────────────────
step "5/7" "$T_STEP_TELEGRAM"

TG_TOKEN="UNCONFIGURED"
TG_CHAT_ID="UNCONFIGURED"

if ask_yn "$T_TG_Q"; then
    TG_OK=false
    while [ "$TG_OK" = false ]; do
        info "$T_TG_INFO1"
        TG_TOKEN=$(ask "$T_TG_TOKEN")

        echo -ne "      ${GRAY}-> Testing Telegram bot token...${NC} "
        TG_RESP=$(curl -s --connect-timeout 8 \
            "https://api.telegram.org/bot${TG_TOKEN}/getMe" 2>/dev/null || echo "{}")
        TG_OK_FIELD=$(echo "$TG_RESP" | grep -o '"ok":true' || echo "")
        TG_USERNAME=$(echo "$TG_RESP" | grep -o '"username":"[^"]*"' | cut -d'"' -f4 || echo "")
        if [ -n "$TG_OK_FIELD" ]; then
            echo -e "${GREEN}OK (@${TG_USERNAME})${NC}"
            TG_OK=true
        else
            echo -e "${RED}FAILED${NC}"
            warn "Invalid bot token. Get it from @BotFather and try again."
            help_box "$T_HELP_TG_1" "$T_HELP_TG_2" "$T_HELP_TG_3"
        fi
    done

    info "$T_TG_INFO2"
    TG_CHAT_ID=$(ask "$T_TG_CHAT_ID")
else
    info "$T_TG_LATER"
fi

# ── Step 6: EXTRAS ────────────────────────────────────────────
step "6/7" "$T_STEP_EXTRAS"

INSTALL_WAZUH_RULES=false; INSTALL_SYSMON=false
ask_yn "$T_INSTALL_RULES" "Y" && INSTALL_WAZUH_RULES=true || true
ask_yn "$T_INSTALL_SYSMON" "Y" && INSTALL_SYSMON=true || true

# ── Step 7: CONFIRM ───────────────────────────────────────────
step "7/7" "$T_STEP_CONFIRM"
echo -e "
  ${GRAY}+---------------------------------------------+
  | ${T_SUMMARY_WAZUH}:        $WAZUH_MODE
  | ${T_SUMMARY_VELO}: $VELO_MODE
  | ${T_SUMMARY_IP}:  $SERVER_IP
  | ${T_SUMMARY_ORG}: $ORG_NAME
  | ${T_SUMMARY_LLM}:          $([ "$USE_LLM" = true ] && echo "$LLM_MODEL" || echo "$T_NOT_CONFIGURED")
  | ${T_SUMMARY_TG}:     $([ "$TG_TOKEN" != "UNCONFIGURED" ] && echo "$T_CONFIGURED" || echo "$T_NOT_CONFIGURED")
  | ${T_SUMMARY_RULES}:  $INSTALL_WAZUH_RULES
  | ${T_SUMMARY_SYSMON}:       $INSTALL_SYSMON
  +---------------------------------------------+${NC}
"

ask_yn "$T_CONFIRM_START" || { echo -e "\n  $T_CANCELLED\n"; exit 0; }

# ============================================================
#  INSTALLATION
# ============================================================
echo -e "\n  ${CYAN}${T_INSTALLING}${NC}\n"

# Container names depend on Wazuh mode. NOTE multi-node service is `wazuh1.indexer`
# (cluster of wazuh1/2/3.indexer), NOT `wazuh.indexer`.
if [ "$WAZUH_MODE" = "multi" ]; then
    WAZUH_MANAGER_CONTAINER="multi-node-wazuh.master-1"
    WAZUH_INDEXER_CONTAINER="multi-node-wazuh1.indexer-1"
    WAZUH_INDEXER_HOSTNAME="wazuh1.indexer"
    WAZUH_DASHBOARD_CONTAINER="multi-node-wazuh.dashboard-1"
else
    WAZUH_MANAGER_CONTAINER="single-node-wazuh.manager-1"
    WAZUH_INDEXER_CONTAINER="single-node-wazuh.indexer-1"
    WAZUH_INDEXER_HOSTNAME="wazuh.indexer"
    WAZUH_DASHBOARD_CONTAINER="single-node-wazuh.dashboard-1"
fi

# True only when a LOCAL manager container with that name actually exists. For
# WAZUH_MODE=existing (remote / unknown name) the docker-exec steps below are skipped.
manager_present() { docker ps --format '{{.Names}}' | grep -qx "$WAZUH_MANAGER_CONTAINER"; }
# Manager readiness: works for single AND multi (port-independent; multi doesn't
# publish 55000/9200 to the host).
MGR_READY_CMD='/var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-analysisd is running"'

# ── A. WAZUH ──────────────────────────────────────────────────
if [ "$WAZUH_MODE" != "existing" ]; then
    echo -e "\n  ${CYAN}[A] Wazuh...${NC}"
    WAZUH_DIR="$ROOT/modules/wazuh-${WAZUH_MODE}-node"

    if [ ! -f "$WAZUH_DIR/docker-compose.yml" ]; then
        info "Downloading Wazuh files..."
        git clone --depth 1 -b v4.14.7 https://github.com/wazuh/wazuh-docker.git "$ROOT/_wazuh_tmp"
        cp -r "$ROOT/_wazuh_tmp/${WAZUH_MODE}-node/." "$WAZUH_DIR/"
        rm -rf "$ROOT/_wazuh_tmp"
        ok "Wazuh files downloaded"
    fi

    # multi-node publishes the dashboard on host 443 (443:5601); single uses 5601.
    # Normalize multi to 5601 so the access URL is consistent across modes.
    if [ "$WAZUH_MODE" = "multi" ]; then
        sed -i 's/- *443:5601/- 5601:5601/' "$WAZUH_DIR/docker-compose.yml"
    fi

    info "Generating SSL certificates..."
    (cd "$WAZUH_DIR" && docker compose -p "${WAZUH_MODE}-node" -f generate-indexer-certs.yml run --rm generator)
    ok "Certificates generated"

    cat > "$WAZUH_DIR/.env" << EOF
INDEXER_USERNAME=admin
INDEXER_PASSWORD=${WAZUH_OS_PASS}
API_USERNAME=${WAZUH_API_USER}
API_PASSWORD=${WAZUH_API_PASS}
EOF

    info "Starting Wazuh (this may take 3-5 min)..."
    (cd "$WAZUH_DIR" && docker compose -p "${WAZUH_MODE}-node" up -d)

    # Indexer must come up first (manager healthcheck depends on it). On a fresh
    # low-RAM VM full init can exceed 4 min, so allow 420s and never abort the
    # whole install on a slow-but-running container (set -euo pipefail would kill
    # it otherwise) — later steps + a final 'docker ps' check still apply.
    # single-node publishes 9200; multi-node does NOT (ports internal behind nginx),
    # so for multi we only wait for running state (port 0).
    if [ "$WAZUH_MODE" = "multi" ]; then
        wait_healthy "$WAZUH_INDEXER_CONTAINER" 420 0 || warn "$WAZUH_INDEXER_CONTAINER not ready yet — continuing (check 'docker ps')"
    else
        wait_healthy "$WAZUH_INDEXER_CONTAINER" 420 9200 || warn "$WAZUH_INDEXER_CONTAINER not ready yet — continuing (check 'docker ps')"
    fi
    # Manager: in-container wazuh-control check (port-independent, both modes).
    wait_healthy "$WAZUH_MANAGER_CONTAINER" 420 0 "$MGR_READY_CMD" || warn "$WAZUH_MANAGER_CONTAINER not ready yet — continuing (check 'docker ps')"
    ok "Wazuh started"

    # Set the unique indexer admin password (filebeat/keystore already use it via env)
    set_indexer_password || true

    # Cap indexer disk growth: auto-delete alert indices older than 90 days (ISM).
    # (Manager .gz log pruning is handled by the wazuh.logcleaner compose sidecar.)
    configure_ism_retention || true

    WAZUH_NETWORK="${WAZUH_MODE}-node_default"
fi

# Create suppress rules file (skip if no local manager container — e.g. existing/remote Wazuh)
if manager_present; then
    info "Creating sentinelhq_rules.xml..."
    # Must be a VALID rules file: an empty <group></group> makes wazuh-analysisd fail
    # ("Group without any rule" -> CRITICAL 1220) and the manager won't start. Ship a
    # level-0 no-op anchor rule; the analyzer appends real suppression rules later.
    docker exec "$WAZUH_MANAGER_CONTAINER" bash -c 'cat > /var/ossec/etc/rules/sentinelhq_rules.xml << "XML"
<group name="sentinelhq_noise,">
  <rule id="100099" level="0">
    <if_sid>1</if_sid>
    <description>SentinelHQ noise-suppression anchor (no-op)</description>
  </rule>
</group>
XML'
    ok "sentinelhq_rules.xml created"
else
    warn "Local Wazuh manager '$WAZUH_MANAGER_CONTAINER' not found — skipping sentinelhq_rules.xml (add it on your Wazuh manager manually)"
fi

# ── B. WAZUH RULES ───────────────────────────────────────────
# socfortress/Wazuh-Rules ships DECODERS, RULES and CDB lists mixed in one repo.
# The naive "copy every *.xml into etc/rules/" dumps decoder files into rules/,
# so rules that reference those decoders (e.g. maltrail -> CEF decoder) fail with
# CRITICAL (1220) and analysisd refuses to start. These rules are also inter-
# dependent (missing SIDs/CDB lists), so a partial install can still break config.
# Strategy: classify by content (decoders -> decoders/, rules -> rules/), snapshot
# first, then VALIDATE; if analysisd won't come back, ROLL BACK and continue.
# Whole block is best-effort (never aborts the install under set -euo pipefail).
if [ "$INSTALL_WAZUH_RULES" = true ] && ! manager_present; then
    warn "Local Wazuh manager '$WAZUH_MANAGER_CONTAINER' not found — skipping socfortress rules (install on your Wazuh manager manually)"
elif [ "$INSTALL_WAZUH_RULES" = true ]; then
    echo -e "\n  ${CYAN}[B] Wazuh-Rules (socfortress)...${NC}"
    (
        set +e
        RULES_DIR="$ROOT/modules/wazuh-rules"
        [ -d "$RULES_DIR/.git" ] || git clone --depth 1 https://github.com/socfortress/Wazuh-Rules.git "$RULES_DIR"

        # Snapshot current-good rules + decoders for rollback
        docker exec "$WAZUH_MANAGER_CONTAINER" bash -c \
            'rm -rf /var/ossec/etc/rules.bak /var/ossec/etc/decoders.bak; cp -a /var/ossec/etc/rules /var/ossec/etc/rules.bak; cp -a /var/ossec/etc/decoders /var/ossec/etc/decoders.bak'

        # Classify each xml: decoder vs rule, copy to the correct dir
        while IFS= read -r f; do
            if grep -ql "<decoder" "$f"; then
                docker cp "$f" "$WAZUH_MANAGER_CONTAINER:/var/ossec/etc/decoders/" >/dev/null 2>&1
            elif grep -qlE "<group|<rule" "$f"; then
                docker cp "$f" "$WAZUH_MANAGER_CONTAINER:/var/ossec/etc/rules/" >/dev/null 2>&1
            fi
        done < <(find "$RULES_DIR" -name "*.xml")

        # Validate: restart and confirm analysisd is actually running
        docker exec "$WAZUH_MANAGER_CONTAINER" /var/ossec/bin/wazuh-control restart >/dev/null 2>&1
        sleep 3
        if docker exec "$WAZUH_MANAGER_CONTAINER" /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q 'wazuh-analysisd is running'; then
            docker exec "$WAZUH_MANAGER_CONTAINER" bash -c \
                'rm -rf /var/ossec/etc/rules.bak /var/ossec/etc/decoders.bak'
            ok "Wazuh-Rules installed (socfortress)"
        else
            warn "socfortress rules broke analysisd config -> rolling back (core detection unaffected)"
            docker exec "$WAZUH_MANAGER_CONTAINER" bash -c \
                'rm -rf /var/ossec/etc/rules /var/ossec/etc/decoders; mv /var/ossec/etc/rules.bak /var/ossec/etc/rules; mv /var/ossec/etc/decoders.bak /var/ossec/etc/decoders'
            docker exec "$WAZUH_MANAGER_CONTAINER" /var/ossec/bin/wazuh-control restart >/dev/null 2>&1
        fi
    ) || warn "[B] Wazuh-Rules step encountered an error — continuing (core detection unaffected)"
fi

# ── C. VELOCIRAPTOR ───────────────────────────────────────────
if [ "$VELO_MODE" = "new" ]; then
    echo -e "\n  ${CYAN}[C] Velociraptor...${NC}"
    VELO_DIR="$ROOT/modules/velociraptor"

    if [ ! -f "$VELO_DIR/docker-compose.yaml" ]; then
        info "Downloading Velociraptor files..."
        git clone --depth 1 https://github.com/weslambert/velociraptor-docker.git "$VELO_DIR"
        ok "Velociraptor files downloaded"
    fi

    cat > "$VELO_DIR/.env" << EOF
VELOX_USER=${VELO_USER}
VELOX_PASSWORD=${VELO_PASS}
VELOX_ROLE=administrator
VELOX_SERVER_URL=https://${SERVER_IP}:8000/
VELOX_FRONTEND_HOSTNAME=VelociraptorServer
EOF

    # entrypoint-patched.sh is bind-mounted as the container entrypoint
    # (docker-compose.yaml). Git committed on Windows loses the +x bit (mode
    # 100644), so on a Linux clone the OCI runtime fails with
    # 'exec: "/velociraptor/entrypoint-patched.sh": permission denied'.
    # Restore the executable bit cross-platform before starting.
    chmod +x "$VELO_DIR/entrypoint-patched.sh" "$VELO_DIR/entrypoint" 2>/dev/null || true

    (cd "$VELO_DIR" && docker compose up -d --build)
    wait_up "velociraptor" 60
    sleep 10

    info "Generating Velociraptor API config..."
    # NOTE: `config api_client` takes the output path as a POSITIONAL arg, not a
    # --output flag (this velociraptor build: "error: unknown long flag '--output'").
    docker exec velociraptor bash -c \
        "/velociraptor/velociraptor --config /velociraptor/server.config.yaml config api_client --name sentinelhq --role administrator /velociraptor/sentinelhq_api.yaml"
    mkdir -p "$ROOT/config"
    docker cp "velociraptor:/velociraptor/sentinelhq_api.yaml" "$ROOT/config/sentinelhq_api.yaml"
    # The generated api_connection_string uses the frontend hostname
    # "VelociraptorServer", which SentinelHQ containers can't resolve
    # (dial tcp: lookup VelociraptorServer ... server misbehaving). Point it at the
    # host IP — velo publishes 8001, reachable from the SentinelHQ network.
    sed -i "s|api_connection_string:.*|api_connection_string: \"${SERVER_IP}:8001\"|" "$ROOT/config/sentinelhq_api.yaml"
    ok "API config generated"

    VELO_URL="https://${SERVER_IP}:8000"
    VELO_API_CONFIG="/app/sentinelhq_api.yaml"
else
    # Use existing - copy API config
    mkdir -p "$ROOT/config"
    cp "$VELO_API_CONFIG" "$ROOT/config/sentinelhq_api.yaml"
fi

# ── D. ACTIVE RESPONSE ────────────────────────────────────────
echo -e "\n  ${CYAN}[D] Wazuh Active Response...${NC}"
AR_CONF="$ROOT/sentinelhq/wazuh-config/sentinelhq_active_response.conf"
if ! manager_present; then
    warn "Local Wazuh manager '$WAZUH_MANAGER_CONTAINER' not found — skipping Active Response (append $AR_CONF to ossec.conf on your Wazuh manager manually)"
elif [ -f "$AR_CONF" ]; then
    docker exec "$WAZUH_MANAGER_CONTAINER" bash -c "cat >> /var/ossec/etc/ossec.conf" < "$AR_CONF"
    ok "Active Response configured"
else
    warn "Active Response config file not found - configure manually"
fi

# ── E. SENTINELHQ .env ────────────────────────────────────────
echo -e "\n  ${CYAN}[E] SentinelHQ configuration...${NC}"

mkdir -p "$ROOT/config"
cat > "$ROOT/sentinelhq/.env" << EOF
# Auto-generated: $(date '+%Y-%m-%d %H:%M')

ORG_NAME=${ORG_NAME}
MANAGER_PUBLIC_IP=${SERVER_IP}

DB_NAME=sentinelhq
DB_USER=shq
DB_PASS=${DB_PASS}

OPENSEARCH_URL=${OPENSEARCH_URL}
OPENSEARCH_USER=admin
OPENSEARCH_PASS=${WAZUH_OS_PASS}
OPENSEARCH_INDEX=wazuh-alerts-*
WAZUH_VERIFY_SSL=false

WAZUH_API_URL=${WAZUH_API_URL}
WAZUH_API_USER=${WAZUH_API_USER}
WAZUH_API_PASS=${WAZUH_API_PASS}
WAZUH_NETWORK=${WAZUH_NETWORK}

COLLECT_INTERVAL_SECONDS=30

ANALYZE_INTERVAL_SECONDS=600
NOISE_THRESHOLD_HOURLY=20
NOISE_WINDOW_HOURS=72
MIN_OCCURRENCES=10
RULE_ID_START=122000
RULE_ID_MAX=122999

LLM_API_URL=${LLM_URL}
LLM_API_KEY=${LLM_KEY}
LLM_MODEL=${LLM_MODEL}
LLM_POLL_INTERVAL=30

TELEGRAM_BOT_TOKEN=${TG_TOKEN}
TELEGRAM_CHAT_ID=${TG_CHAT_ID}

DASHBOARD_PORT=8082
DASHBOARD_USER=${DASH_USER}
DASHBOARD_PASS=${DASH_PASS}
SECRET_KEY=${SECRET_KEY}

PORTAL_PORT=8083

VELOCIRAPTOR_URL=${VELO_URL}
VELOCIRAPTOR_API_CONFIG=${VELO_API_CONFIG}

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
REPORT_EMAIL_TO=
REPORT_DAY=monday
REPORT_HOUR=8

CORRELATE_INTERVAL=120
CORRELATE_WINDOW=10

INTERNAL_API_TOKEN=${INTERNAL_TOKEN}

TZ=Europe/Vilnius
EOF

[ -f "$ROOT/config/sentinelhq_api.yaml" ] && \
    cp "$ROOT/config/sentinelhq_api.yaml" "$ROOT/sentinelhq/sentinelhq_api.yaml"
ok ".env created"

# ── Generate docker-compose.override.yml for wazuh-net ───────
OVERRIDE_PATH="$ROOT/sentinelhq/docker-compose.override.yml"
if [ "$WAZUH_MODE" = "existing" ] && [ "$WAZUH_SAME_HOST" = false ]; then
    cat > "$OVERRIDE_PATH" << 'EOF'
# Auto-generated by setup - Wazuh is on a remote server
networks:
  wazuh-net:
    driver: bridge
    name: shq-wazuh-isolated
EOF
    info "wazuh-net: isolated bridge (Wazuh is remote)"
else
    WAZUH_NET_NAME="${WAZUH_NETWORK:-single-node_default}"
    cat > "$OVERRIDE_PATH" << EOF
# Auto-generated by setup - Wazuh is on the same Docker host
networks:
  wazuh-net:
    external: true
    name: ${WAZUH_NET_NAME}
EOF
    info "wazuh-net: external '${WAZUH_NET_NAME}'"
fi

# ── F. START SENTINELHQ ───────────────────────────────────────
echo -e "\n  ${CYAN}[F] Starting SentinelHQ...${NC}"
(cd "$ROOT/sentinelhq" && docker compose up -d --build)

wait_healthy "shq-postgres" 120
wait_healthy "shq-dashboard" 120
ok "SentinelHQ started"

# Point the Wazuh dashboard's wazuh.yml at the real API password (done late so the
# dashboard has had time to create wazuh.yml). Skip for existing/remote Wazuh.
if [ "$WAZUH_MODE" != "existing" ] && manager_present; then
    set_dashboard_api_password || true
fi

# ── G. SYSMON ─────────────────────────────────────────────────
if [ "$INSTALL_SYSMON" = true ]; then
    SYSMON_XML="$ROOT/modules/sysmon/sysmonconfig.xml"
    if [ ! -f "$SYSMON_XML" ]; then
        info "Downloading Sysmon config..."
        curl -fsSL "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" \
            -o "$SYSMON_XML" 2>/dev/null && ok "Sysmon config downloaded" || warn "Sysmon config download failed"
    fi
    ok "Sysmon config ready: $SYSMON_XML"
    info "Deploy on Windows agents: Sysmon64.exe -accepteula -i sysmonconfig.xml"
fi

# ── RESULT ────────────────────────────────────────────────────
echo -e "${GREEN}${BOLD}
  +--------------------------------------------------------------+
  |  ${T_DONE_TITLE}
  +--------------------------------------------------------------+
  |                                                              |
  |  ${T_DASH_URL}:   http://${SERVER_IP}:8082
  |  ${T_PORTAL_URL}: http://${SERVER_IP}:8083
  |  ${T_VELO_URL_LBL}:    https://${SERVER_IP}:8889
  |  ${T_WAZUH_URL}:     https://${SERVER_IP}:5601
  |                                                              |
  |  Dashboard:                                                  |
  |    ${T_LOGIN_USER}: ${DASH_USER}
  |    ${T_LOGIN_PASS}: ${DASH_PASS}
  |                                                              |
  |  Velociraptor:                                               |
  |    ${T_LOGIN_USER}: ${VELO_USER:-admin}
  |    ${T_LOGIN_PASS}: ${VELO_PASS:-(existing)}
  |                                                              |
  |  Wazuh Dashboard:                                            |
  |    ${T_LOGIN_USER}: admin
  |    ${T_LOGIN_PASS}: ${WAZUH_OS_PASS}
  |                                                              |
  |  ${T_SAVE_WARN}
  |  ${T_SAVED_AT}
  +--------------------------------------------------------------+
${NC}"

[ "$TG_TOKEN" = "UNCONFIGURED" ] && \
    echo -e "  ${YELLOW}!!  ${T_TG_WARN}${NC}"
[ "$LLM_KEY" = "UNCONFIGURED" ] && \
    echo -e "  ${YELLOW}!!  ${T_LLM_WARN}${NC}"

echo -e "
  ${T_OTHER_SCRIPTS}:
    bash backup.sh  - ${T_BACKUP_SCRIPT}
    bash update.sh  - ${T_UPDATE_SCRIPT}
"
