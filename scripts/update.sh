#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# Enterprise NGFW v2.0 - System Updater (Thin CLI Wrapper)
# ═══════════════════════════════════════════════════════════════════
#
# This script is a lightweight wrapper around the built-in OTA Update API.
# The real update logic is in:  api/rest/endpoints/update_routes.py
# Usage:
#   ./update.sh [--branch main] [--check-only] [--api-url http://localhost:8000]
#
# For automated / scriptless updates — the preferred method is via the API:
#   1. Check for updates:  GET  /api/v1/system/update/check
#   2. Apply update:       POST /api/v1/system/update/apply
#   3. View logs:          GET  /api/v1/system/update/history
# ═══════════════════════════════════════════════════════════════════

set -e

# ── Defaults ────────────────────────────────────────────────────────
BRANCH="main"
CHECK_ONLY=false
API_URL="${NGFW_API_URL:-http://localhost:8000}"
INSTALL_DIR="${NGFW_HOME:-/opt/enterprise_ngfw}"
SERVICE_NAME="ngfw"
VENV_DIR="$INSTALL_DIR/venv"

# ── Colors ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; }

# ── Args ─────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --branch)    BRANCH="$2"; shift 2 ;;
        --check-only) CHECK_ONLY=true; shift ;;
        --api-url)   API_URL="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo -e "${CYAN}${BOLD}🔄 Enterprise NGFW — System Updater${NC}"
echo ""

# ── Try API-based update first (preferred) ────────────────────────────────────
if command -v curl &>/dev/null; then
    log_info "Checking update via API: $API_URL"

    # Login to get a token (reads env vars for credentials)
    NGFW_ADMIN_USER="${NGFW_ADMIN_USER:-admin}"
    NGFW_ADMIN_PASS="${NGFW_ADMIN_PASS:-admin123}"

    TOKEN=$(curl -s -X POST "$API_URL/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$NGFW_ADMIN_USER\",\"password\":\"$NGFW_ADMIN_PASS\"}" \
        | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('access_token',''))" 2>/dev/null)

    if [ -z "$TOKEN" ]; then
        log_warning "Could not obtain API token. Falling back to direct git mode."
    else
        # -- Check for updates
        CHECK_RESULT=$(curl -s -H "Authorization: Bearer $TOKEN" "$API_URL/api/v1/system/update/check")
        echo "$CHECK_RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f\"  Current commit : {d.get('current',{}).get('commit','?')[:12]}\")
print(f\"  Commits behind : {d.get('commits_behind', '?')}\")
print(f\"  Update available: {d.get('update_available', False)}\")
" 2>/dev/null || echo "  (status query failed)"

        if [ "$CHECK_ONLY" = true ]; then
            log_info "Check-only mode. Exiting."
            exit 0
        fi

        # -- Apply update
        log_info "Applying update from branch '$BRANCH' via API..."
        curl -s -X POST "$API_URL/api/v1/system/update/apply" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "{\"branch\":\"$BRANCH\",\"run_migrations\":true,\"restart_service\":true}" \
            | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('message','Done'))"

        log_success "Update initiated. The service will restart momentarily."
        echo -e "  Check logs: ${YELLOW}GET $API_URL/api/v1/system/update/history${NC}"
        exit 0
    fi
fi

# ── Fallback: Direct git-based update (no running API) ────────────────────────
log_warning "Running in fallback direct mode (API not reachable)."

[ "$EUID" -ne 0 ] && { log_error "Fallback mode requires root (sudo)."; exit 1; }

if [ ! -d "$INSTALL_DIR/.git" ]; then
    log_error "Not a git repository: $INSTALL_DIR"
    exit 1
fi

log_info "Stopping $SERVICE_NAME..."
systemctl is-active --quiet "$SERVICE_NAME" && systemctl stop "$SERVICE_NAME" || true

log_info "Pulling from git (branch: $BRANCH)..."
git -C "$INSTALL_DIR" reset --hard HEAD
git -C "$INSTALL_DIR" checkout "$BRANCH"
git -C "$INSTALL_DIR" pull
log_success "Code updated"

if [ -d "$VENV_DIR" ]; then
    log_info "Updating Python dependencies..."
    for req in requirements.txt requirements/base.txt requirements/production.txt; do
        if [ -f "$INSTALL_DIR/$req" ]; then
            "$VENV_DIR/bin/pip" install -q -r "$INSTALL_DIR/$req"
            log_success "Dependencies updated from $req"
            break
        fi
    done
fi

if [ -f "$INSTALL_DIR/alembic.ini" ]; then
    log_info "Running database migrations..."
    "$VENV_DIR/bin/alembic" -c "$INSTALL_DIR/alembic.ini" upgrade head || log_warning "Alembic error (manual check may be needed)"
fi

log_info "Starting $SERVICE_NAME..."
systemctl daemon-reload
systemctl start "$SERVICE_NAME"

sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    log_success "Service restarted successfully."
else
    log_error "Service failed. Check: journalctl -u $SERVICE_NAME -f"
    exit 1
fi

echo ""
log_success "Update complete!"
