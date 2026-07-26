#!/usr/bin/env bash
#
# End-to-end test suite for simply_firewall.
#
# Builds the project, boots a fresh instance against a throwaway SQLite database, captures the
# auto-generated bootstrap master key, and drives the whole HTTP API with curl + jq: RBAC across a
# multi-key permission matrix, IP add/list/filter/update/delete across multiple groups, key
# lifecycle (create/update/rotate), bound-IP CIDR enforcement, audit log generation, and the two
# group-identification bug fixes (duplicate-name 409, flexible group_id).
#
# Usage: ./scripts/test_e2e.sh
# Requires: curl, jq. Needs port 3000 free (the app's listen address is not configurable).
# Exit code: 0 if every check passed, 1 otherwise.

set -uo pipefail
# Not using `set -e`: assertions on purpose expect non-2xx responses (401/403/404/409), so a
# non-zero curl/jq exit inside a check must not abort the whole run.

# ── Configuration ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BASE_URL="${BASE_URL:-http://localhost:3000}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/simply_firewall_e2e.XXXXXX")"
DB_PATH="$WORK_DIR/e2e.db"
SERVER_LOG="$WORK_DIR/server.log"
RESP_BODY_FILE="$WORK_DIR/resp_body"
SERVER_PID=""

PASS_COUNT=0
FAIL_COUNT=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Helpers ──────────────────────────────────────────────────────────────────
#
# Every diagnostic/progress function below writes to STDERR, never STDOUT. This is deliberate,
# not cosmetic: helper functions like `create_scoped_key` (further down) need to hand a real
# value back to the caller via `$(...)`  command substitution, and command substitution captures
# *only* stdout. If timestamps/status lines/PASS-FAIL output went to stdout too, they'd be mixed
# into the captured "return value" and silently corrupt it (an early version of this script had
# exactly that bug). Keeping stdout pristine for real data and routing everything else to stderr
# is the standard, robust fix — and since a terminal shows both streams interleaved anyway, a
# normal run of this script looks identical either way.

ts() { date +"%H:%M:%S.%3N"; }

log() { echo -e "$(ts) ${CYAN}[INFO]${RESET} $*" >&2; }
warn() { echo -e "$(ts) ${YELLOW}[WARN]${RESET} $*" >&2; }
err() { echo -e "$(ts) ${RED}[ERROR]${RESET} $*" >&2; }

log_section() {
    echo "" >&2
    echo -e "$(ts) ${BOLD}${MAGENTA}=== $* ===${RESET}" >&2
}

status_color() {
    case "$1" in
        2??) echo -n "$GREEN" ;;
        401|403|404|409|422) echo -n "$YELLOW" ;;
        4??) echo -n "$YELLOW" ;;
        5??) echo -n "$RED" ;;
        *) echo -n "$RESET" ;;
    esac
}

# Performs an HTTP request and leaves the outcome in $RESP_STATUS / $RESP_BODY.
# Usage: api_call METHOD PATH [API_KEY] [JSON_BODY] [X_FORWARDED_FOR]
api_call() {
    local method="$1" path="$2" api_key="${3:-}" data="${4:-}" xff="${5:-}"
    local args=(-s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method")
    [ -n "$api_key" ] && args+=(-H "X-API-Key: $api_key")
    [ -n "$xff" ] && args+=(-H "X-Forwarded-For: $xff")
    if [ -n "$data" ]; then
        args+=(-H "Content-Type: application/json" -d "$data")
    fi
    RESP_STATUS=$(curl "${args[@]}" "$BASE_URL$path")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    local color; color=$(status_color "$RESP_STATUS")
    printf "%s ${color}[%s]${RESET} %-6s %s\n" "$(ts)" "$RESP_STATUS" "$method" "$path" >&2
}

# Usage: check EXPECTED_STATUS "description"
check() {
    local expected="$1" description="$2"
    if [ "$RESP_STATUS" == "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description (expected $expected, got $RESP_STATUS)" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected $expected, got $RESP_STATUS)" >&2
        echo -e "$(ts)          body: $RESP_BODY" >&2
    fi
}

# Usage: check_jq '.some.jq.filter' "expected value" "description"
check_jq() {
    local filter="$1" expected="$2" description="$3"
    local actual
    actual=$(echo "$RESP_BODY" | jq -r "$filter" 2>/dev/null)
    if [ "$actual" == "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description (got '$actual')" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected '$expected', got '$actual')" >&2
        echo -e "$(ts)          body: $RESP_BODY" >&2
    fi
}

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        log "Stopping server (pid $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

# ── Preflight ────────────────────────────────────────────────────────────────

log_section "Preflight"

for bin in curl jq cargo; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        err "$bin is required but not found on PATH"
        exit 1
    fi
    log "Found $bin: $(command -v "$bin")"
done

if command -v fuser >/dev/null 2>&1 && fuser 3000/tcp >/dev/null 2>&1; then
    err "Port 3000 is already in use (the app's listen address is not configurable)."
    err "Stop whatever is bound to it and re-run this script."
    exit 1
fi

# ── Build & start ────────────────────────────────────────────────────────────

log_section "Build"
log "Running cargo build in $PROJECT_ROOT ..."
if ! (cd "$PROJECT_ROOT" && cargo build --quiet 2>"$WORK_DIR/build.log"); then
    err "Build failed:"
    cat "$WORK_DIR/build.log"
    exit 1
fi
log "Build succeeded."

log_section "Boot"
log "Starting server against a fresh database at $DB_PATH"
DATABASE_URL="sqlite://$DB_PATH?mode=rwc" RUST_LOG=info \
    "$PROJECT_ROOT/target/debug/simply_firewall" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

log "Waiting for the server to become ready (pid $SERVER_PID)..."
READY=0
for _ in $(seq 1 60); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        err "Server process exited during startup. Log:"
        cat "$SERVER_LOG"
        exit 1
    fi
    if curl -sf "$BASE_URL/" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.5
done
if [ "$READY" -ne 1 ]; then
    err "Server did not become ready in time. Log:"
    cat "$SERVER_LOG"
    exit 1
fi
log "Server is up."

MASTER_KEY=$(grep -oE '(Key:    )[a-f0-9]{64}' "$SERVER_LOG" | awk '{print $2}' | head -1)
if [ -z "$MASTER_KEY" ]; then
    err "Could not extract the bootstrap master key from the server log:"
    cat "$SERVER_LOG"
    exit 1
fi
log "Captured master key (prefix: ${MASTER_KEY:0:8}...)"

# ── 1. Basic auth ────────────────────────────────────────────────────────────

log_section "1. Basic Authentication"

api_call GET "/api/auth/me"
check "401" "no X-API-Key header is rejected"

api_call GET "/api/auth/me" "not-a-real-key"
check "401" "an invalid key is rejected"

api_call GET "/api/auth/me" "$MASTER_KEY"
check "200" "the master key authenticates"
check_jq ".is_master" "true" "master key reports is_master=true"

# ── 2. Multi-key permission matrix ──────────────────────────────────────────

log_section "2. Multi-Key Permission Matrix (Group A)"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"Group-A"}'
check "200" "Group A is created"
GROUP_A_ID=$(echo "$RESP_BODY" | jq -r '.id')
log "Group A id: $GROUP_A_ID"

# Creates a key and leaves its plaintext/id in $CREATED_KEY / $CREATED_ID. Deliberately does NOT
# run in a subshell (no `$(...)`/`<(...)` around the whole function) — those globals need to
# propagate back to the calling scope, which a subshell would prevent.
create_scoped_key() {
    local name="$1"
    api_call POST "/api/keys" "$MASTER_KEY" "{\"name\":\"$name\",\"bound_ips\":\"0.0.0.0/0\"}"
    check "200" "create scoped key '$name'"
    CREATED_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
    CREATED_ID=$(echo "$RESP_BODY" | jq -r '.id')
}

log "Creating Read-Only Key..."
create_scoped_key "Read-Only Key"
READONLY_KEY="$CREATED_KEY"; READONLY_ID="$CREATED_ID"

log "Creating Write-Only Key..."
create_scoped_key "Write-Only Key"
WRITEONLY_KEY="$CREATED_KEY"; WRITEONLY_ID="$CREATED_ID"

log "Creating No-Access Key..."
create_scoped_key "No-Access Key"
NOACCESS_KEY="$CREATED_KEY"; NOACCESS_ID="$CREATED_ID"

# Read-Only: can_read only.
api_call POST "/api/keys/$READONLY_ID/groups" "$MASTER_KEY" \
    "{\"group_id\":\"$GROUP_A_ID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "grant Read-Only Key read-only rights on Group A (by group_id)"

# Write-Only: can_read + can_write (can_write requires can_read, per AGENT.MD least-privilege).
api_call POST "/api/keys/$WRITEONLY_ID/groups" "$MASTER_KEY" \
    "{\"group_id\":\"$GROUP_A_ID\",\"can_read\":true,\"can_write\":true,\"can_delete\":false}"
check "200" "grant Write-Only Key read+write rights on Group A"

# No-Access Key: no grant at all — left as-is.

log "Seeding Group A with an address as master..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.50","group_name":"Group-A","cause":"seed"}'
check "200" "master seeds an address into Group A"

log "-- Read-Only Key --"
api_call GET "/api/ips?group_id=$GROUP_A_ID" "$READONLY_KEY"
check "200" "Read-Only Key can list Group A"
api_call POST "/api/ban" "$READONLY_KEY" '{"target_address":"198.51.100.51","group_name":"Group-A"}'
check "403" "Read-Only Key cannot write to Group A"

log "-- Write-Only Key --"
api_call GET "/api/ips?group_id=$GROUP_A_ID" "$WRITEONLY_KEY"
check "200" "Write-Only Key can list Group A"
api_call POST "/api/ban" "$WRITEONLY_KEY" '{"target_address":"198.51.100.52","group_name":"Group-A"}'
check "200" "Write-Only Key can write to Group A"
api_call DELETE "/api/ips?target_address=198.51.100.52&group_name=Group-A" "$WRITEONLY_KEY"
check "403" "Write-Only Key cannot delete from Group A (no can_delete)"

log "-- No-Access Key --"
api_call GET "/api/ips?group_id=$GROUP_A_ID" "$NOACCESS_KEY"
check "200" "No-Access Key's list call still succeeds..."
check_jq "length" "0" "...but returns zero rows (RBAC-filtered, not a 403)"
api_call POST "/api/ban" "$NOACCESS_KEY" '{"target_address":"198.51.100.53","group_name":"Group-A"}'
check "403" "No-Access Key cannot write to Group A"

# ── 3. IP management across multiple groups ─────────────────────────────────

log_section "3. IP Add / List / Filter / Update / Delete Across Groups"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"Group-B"}'
check "200" "Group B is created"

api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.10","group_name":"Group-B","cause":"initial-cause"}'
check "200" "add an address to Group B"

# A group's type (banlist/whitelist) is fixed at creation and doesn't change per-membership, so
# the whitelist example needs its OWN group rather than reusing Group B — /white auto-creates it
# as type=whitelist since it doesn't exist yet.
api_call POST "/api/white" "$MASTER_KEY" '{"target_address":"203.0.113.11","group_name":"Group-C"}'
check "200" "whitelist an address into a fresh whitelist group (Group C)"

api_call GET "/api/ips?groups=Group-A,Group-B,Group-C" "$MASTER_KEY"
check "200" "list across multiple groups at once"
check_jq "length" "4" "sees all 4 addresses across Group A + Group B + Group C"

api_call GET "/api/ips?ip=203.0.113.10" "$MASTER_KEY"
check "200" "filter by IP substring"
check_jq "length" "1" "IP substring filter narrows to exactly one record"

api_call GET "/api/ips?status=white" "$MASTER_KEY"
check "200" "filter by status=white"
check_jq ".[0].target_address" "203.0.113.11" "status filter finds the whitelisted address"

log "Updating (re-registering) 203.0.113.10 with a new cause..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.10","group_name":"Group-B","cause":"updated-cause"}'
check "200" "re-registering an existing address updates it rather than failing"
api_call GET "/api/ips?ip=203.0.113.10" "$MASTER_KEY"
check_jq ".[0].cause" "updated-cause" "the cause was actually updated"
check_jq "length" "1" "still exactly one row — no duplicate created"

log "Deleting 203.0.113.10 from Group B..."
api_call DELETE "/api/ips?target_address=203.0.113.10&group_name=Group-B" "$MASTER_KEY"
check "204" "delete succeeds"
api_call GET "/api/ips?ip=203.0.113.10" "$MASTER_KEY"
check_jq "length" "0" "the deleted address is gone"

# ── 4. Key lifecycle: update + rotate ───────────────────────────────────────

log_section "4. Key Lifecycle (Update + Rotate)"

api_call PUT "/api/keys/$READONLY_ID" "$MASTER_KEY" '{"name":"Read-Only Key (renamed)","can_manage_webhooks":true}'
check "200" "PUT updates the key"
check_jq ".name" "Read-Only Key (renamed)" "the name was actually updated"
check_jq ".can_manage_webhooks" "true" "the new scope was actually granted"

api_call GET "/api/webhooks" "$READONLY_KEY"
check "200" "the updated scope takes effect immediately, with the same secret"

log "Rotating the Read-Only Key's secret..."
api_call POST "/api/keys/$READONLY_ID/rotate" "$MASTER_KEY"
check "200" "rotate succeeds"
NEW_READONLY_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')

api_call GET "/api/auth/me" "$READONLY_KEY"
check "401" "the OLD secret is rejected immediately after rotation"

api_call GET "/api/auth/me" "$NEW_READONLY_KEY"
check "200" "the NEW secret works"
READONLY_KEY="$NEW_READONLY_KEY"

# ── 5. Bound IP (CIDR) restrictions ─────────────────────────────────────────

log_section "5. Bound IP / CIDR Restrictions"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"CIDR-Restricted Key","bound_ips":"203.0.113.0/24"}'
check "200" "create a key bound to 203.0.113.0/24"
RESTRICTED_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')

api_call GET "/api/auth/me" "$RESTRICTED_KEY" "" "203.0.113.99"
check "200" "an X-Forwarded-For address inside the bound CIDR is allowed"

api_call GET "/api/auth/me" "$RESTRICTED_KEY" "" "8.8.8.8"
check "403" "an X-Forwarded-For address outside the bound CIDR is rejected"

api_call GET "/api/auth/me" "$RESTRICTED_KEY" "" "8.8.8.8, 203.0.113.42"
check "200" "only the rightmost (trusted-proxy) hop of X-Forwarded-For is honored"

# ── 6. Audit log generation ──────────────────────────────────────────────────

log_section "6. Audit Log Generation"

api_call GET "/api/audit-logs" "$READONLY_KEY"
check "403" "a non-master key cannot read audit logs"

api_call GET "/api/audit-logs?action=IP_ADD&limit=50" "$MASTER_KEY"
check "200" "master can read audit logs"
IP_ADD_COUNT=$(echo "$RESP_BODY" | jq 'length')
if [ "${IP_ADD_COUNT:-0}" -ge 1 ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} at least one IP_ADD audit entry exists (found $IP_ADD_COUNT)" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} expected at least one IP_ADD audit entry, found $IP_ADD_COUNT" >&2
fi

api_call GET "/api/audit-logs?action=KEY_ROTATE" "$MASTER_KEY"
check_jq "length" "1" "exactly one KEY_ROTATE audit entry exists (from step 4)"

# ── 7. Regression checks: duplicate group name, flexible group_id ──────────

log_section "7. Regression: Duplicate Group Name & Flexible group_id"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"Group-A"}'
check "409" "creating a group with a name that already exists returns 409, not 500"

api_call POST "/api/keys/$NOACCESS_ID/groups" "$MASTER_KEY" \
    "{\"group_id\":\"Group-B\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "a literal NAME in the group_id field is accepted (no 422)"

api_call POST "/api/keys/$NOACCESS_ID/groups" "$MASTER_KEY" \
    "{\"group_id\":\"$GROUP_A_ID\",\"can_read\":false,\"can_write\":true,\"can_delete\":false}"
check "400" "can_write without can_read is rejected (least-privilege rule)"

# ── Summary ──────────────────────────────────────────────────────────────────

log_section "Summary"
echo -e "$(ts) ${GREEN}Passed: $PASS_COUNT${RESET}   ${RED}Failed: $FAIL_COUNT${RESET}" >&2

if [ "$FAIL_COUNT" -gt 0 ]; then
    err "E2E suite FAILED ($FAIL_COUNT failing check(s))."
    exit 1
fi

log "E2E suite PASSED — all $PASS_COUNT checks succeeded."
exit 0
