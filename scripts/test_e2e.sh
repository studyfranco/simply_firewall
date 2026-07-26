#!/usr/bin/env bash
#
# End-to-end test suite for simply_firewall.
#
# Builds the project, boots a fresh instance against a throwaway SQLite database with a
# deterministic bootstrap master key (via INITIAL_MASTER_KEY — no log-scraping), and drives the
# whole HTTP API with curl + jq: RBAC across a multi-key permission matrix, IP add/list/filter/
# update/delete across multiple groups (including banlist/whitelist overlap, and deletion via
# both query-string params and a JSON body), key lifecycle (create/update/rotate/delete), bound-IP
# CIDR enforcement, audit log generation + pagination, webhook lifecycle (create/list/delete, with
# the mandatory `name` field), and the group-identification bug fixes (duplicate-name 409,
# flexible group_id/group_name). Every request is logged with a timestamp, method, full URL,
# color-coded status, and jq-formatted body.
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
# 127.0.0.1 rather than "localhost": avoids any IPv6 (::1) resolution first-try delay against a
# server that only ever binds the IPv4 wildcard address.
BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
# Deterministic bootstrap secret: passed to the server as INITIAL_MASTER_KEY so this script never
# needs to scrape the master key back out of the (buffered, redirected) server log.
MASTER_KEY="e2e_master_secret_key_for_testing_123456789"
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
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Helpers ──────────────────────────────────────────────────────────────────
#
# Every diagnostic/progress function below writes to STDERR, never STDOUT. This is deliberate,
# not cosmetic: helper functions like `create_scoped_key` (further down) need to hand a real
# value back to the caller via plain global variables, and several `check_jq` calls parse
# `$RESP_BODY` via `$(...)` command substitution elsewhere in the script. Command/process
# substitution captures *only* stdout, so if timestamps/status lines/PASS-FAIL/response-body
# output went to stdout too, they'd contaminate any captured value (an early version of this
# script had exactly that bug, traced to a `mapfile < <(...)` capturing a helper function's log
# lines instead of its actual return value). Keeping stdout pristine and routing everything else
# to stderr is the robust fix — a terminal shows both streams interleaved anyway, so a normal run
# of this script looks identical either way.

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

# Pretty-prints $RESP_BODY (JSON via jq when possible, indented under the request line above).
print_response_body() {
    if [ -z "$RESP_BODY" ]; then
        echo -e "$(ts)          ${DIM}(empty body)${RESET}" >&2
        return
    fi
    local formatted
    if formatted=$(echo "$RESP_BODY" | jq . 2>/dev/null); then
        while IFS= read -r line; do
            echo -e "$(ts)          ${DIM}${line}${RESET}" >&2
        done <<< "$formatted"
    else
        echo -e "$(ts)          ${DIM}${RESP_BODY}${RESET}" >&2
    fi
}

# Performs an HTTP request and leaves the outcome in $RESP_STATUS / $RESP_BODY. Every call prints
# a timestamped, colored "[STATUS] METHOD /path" line followed by the jq-formatted response body.
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
    printf "%s ${color}[%s]${RESET} %-6s %s\n" "$(ts)" "$RESP_STATUS" "$method" "$BASE_URL$path" >&2
    print_response_body
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
    fi
}

# Usage: check_true "jq boolean expression producing true/false" "description"
check_true() {
    local expr="$1" description="$2"
    local actual
    actual=$(echo "$RESP_BODY" | jq -e "$expr" 2>/dev/null)
    if [ "$actual" == "true" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (jq expr '$expr' was not true)" >&2
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
    cat "$WORK_DIR/build.log" >&2
    exit 1
fi
log "Build succeeded."

log_section "Boot"
log "Starting server against a fresh database at $DB_PATH"
log "Using INITIAL_MASTER_KEY for deterministic bootstrap (no log-scraping needed)"
DATABASE_URL="sqlite://$DB_PATH?mode=rwc" RUST_LOG=info INITIAL_MASTER_KEY="$MASTER_KEY" \
    "$PROJECT_ROOT/target/debug/simply_firewall" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

log "Waiting for the server to become ready (pid $SERVER_PID)..."
READY=0
for _ in $(seq 1 60); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        err "Server process exited during startup. Log:"
        cat "$SERVER_LOG" >&2
        exit 1
    fi
    # Readiness is decided purely by whether the HTTP listener answers on a real API route —
    # never by log content, which may be buffered and lag behind the process actually being
    # ready to serve. `/api/groups` sits behind auth middleware, so an unauthenticated probe
    # never returns a plain connection failure once the server is up; any of 200/401/404 proves
    # the listener is live and axum is routing requests (curl's own exit code, not `-f`, is what
    # actually distinguishes "no HTTP response yet" from "got a response").
    STATUS_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/groups" 2>/dev/null)
    case "$STATUS_CODE" in
        200|401|404)
            READY=1
            break
            ;;
    esac
    sleep 0.5
done
if [ "$READY" -ne 1 ]; then
    err "Server did not become ready in time. Log:"
    cat "$SERVER_LOG" >&2
    exit 1
fi
log "Server is up."

api_call GET "/api/auth/me" "$MASTER_KEY"
check "200" "the deterministic INITIAL_MASTER_KEY authenticates"
check_jq ".is_master" "true" "it reports is_master=true"

# ── 1. Basic auth ────────────────────────────────────────────────────────────

log_section "1. Basic Authentication"

api_call GET "/api/auth/me"
check "401" "no X-API-Key header is rejected"

api_call GET "/api/auth/me" "not-a-real-key"
check "401" "an invalid key is rejected"

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

log "Deleting 203.0.113.10 from Group B via query-string parameters..."
api_call DELETE "/api/ips?target_address=203.0.113.10&group_name=Group-B" "$MASTER_KEY"
check "204" "delete via query string succeeds"
api_call GET "/api/ips?ip=203.0.113.10" "$MASTER_KEY"
check_jq "length" "0" "the query-string-deleted address is gone"

log "Adding 203.0.113.20 to Group B, then deleting it via a JSON request body instead..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.20","group_name":"Group-B","cause":"json-body-delete-test"}'
check "200" "add 203.0.113.20 to Group B for the JSON-body delete test"
api_call DELETE "/api/ips" "$MASTER_KEY" '{"target_address":"203.0.113.20","group_name":"Group-B"}'
check "204" "delete via JSON body (no query string at all) succeeds"
api_call GET "/api/ips?ip=203.0.113.20" "$MASTER_KEY"
check_jq "length" "0" "the JSON-body-deleted address is gone"

# ── 4. Multi-group overlap / conflict detection ─────────────────────────────

log_section "4. Multi-Group Overlap (Banlist + Whitelist) Conflict Detection"

log "Adding the SAME address to both a banlist group and a whitelist group..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"192.0.2.200","group_name":"Group-B","cause":"flagged as hostile"}'
check "200" "address added to banlist Group B"
api_call POST "/api/white" "$MASTER_KEY" '{"target_address":"192.0.2.200","group_name":"Group-C","cause":"also a trusted partner"}'
check "200" "the SAME address added to whitelist Group C"

api_call GET "/api/ips?ip=192.0.2.200" "$MASTER_KEY"
check "200" "list the overlapping address"
check_jq "length" "2" "GET /api/ips exposes BOTH memberships (one row per group), not a single merged/deduped row"
check_true '[.[].group_type] | sort == ["banlist","whitelist"]' "the two rows carry the two different group_types the UI conflict indicator diffs on"
check_true '[.[].target_address] | unique == ["192.0.2.200"]' "both rows are unambiguously the same address"

# ── 5. Key lifecycle: update + rotate ───────────────────────────────────────

log_section "5. Key Lifecycle (Update + Rotate)"

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

# ── 6. Bound IP (CIDR) restrictions ─────────────────────────────────────────

log_section "6. Bound IP / CIDR Restrictions"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"CIDR-Restricted Key","bound_ips":"203.0.113.0/24"}'
check "200" "create a key bound to 203.0.113.0/24"
RESTRICTED_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')

api_call GET "/api/auth/me" "$RESTRICTED_KEY" "" "203.0.113.99"
check "200" "an X-Forwarded-For address inside the bound CIDR is allowed"

api_call GET "/api/auth/me" "$RESTRICTED_KEY" "" "8.8.8.8"
check "403" "an X-Forwarded-For address outside the bound CIDR is rejected"

api_call GET "/api/auth/me" "$RESTRICTED_KEY" "" "8.8.8.8, 203.0.113.42"
check "200" "only the rightmost (trusted-proxy) hop of X-Forwarded-For is honored"

log "Dedicated strict scenario: bound_ips=127.0.0.1/32, request claims to be from 203.0.113.50..."
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Loopback-Only Key","bound_ips":"127.0.0.1/32"}'
check "200" "create a key bound to 127.0.0.1/32"
LOOPBACK_ONLY_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')

api_call GET "/api/auth/me" "$LOOPBACK_ONLY_KEY" "" "203.0.113.50"
check "403" "an out-of-CIDR X-Forwarded-For is strictly rejected"
check_jq ".error" "Client IP not allowed" "the error message is exactly 'Client IP not allowed'"

# ── 7. Audit log generation & pagination ────────────────────────────────────

log_section "7. Audit Log Generation & Pagination"

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
check_jq "length" "1" "exactly one KEY_ROTATE audit entry exists (from step 5)"

log "Generating a deterministic run of mutating actions for pagination testing..."
for i in 1 2 3 4 5 6; do
    api_call POST "/api/groups" "$MASTER_KEY" "{\"name\":\"pagination-group-$i\"}"
    check "200" "create pagination-group-$i (audit entry #$i)"
done

api_call GET "/api/audit-logs?action=GROUP_CREATE&limit=3&offset=0" "$MASTER_KEY"
check "200" "page 1 of GROUP_CREATE audit logs (limit=3, offset=0)"
check_jq "length" "3" "page 1 has exactly 3 entries"
PAGE1_IDS=$(echo "$RESP_BODY" | jq -c '[.[].id]')

api_call GET "/api/audit-logs?action=GROUP_CREATE&limit=3&offset=3" "$MASTER_KEY"
check "200" "page 2 of GROUP_CREATE audit logs (limit=3, offset=3)"
check_jq "length" "3" "page 2 has exactly 3 entries"
PAGE2_IDS=$(echo "$RESP_BODY" | jq -c '[.[].id]')

if [ "$PAGE1_IDS" != "$PAGE2_IDS" ]; then
    OVERLAP=$(jq -n --argjson a "$PAGE1_IDS" --argjson b "$PAGE2_IDS" '[$a[] | select(. as $x | $b | index($x))] | length')
    if [ "$OVERLAP" == "0" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} page 1 and page 2 contain disjoint entries (no overlap)" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} page 1 and page 2 overlap by $OVERLAP entr(ies)" >&2
    fi
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} page 1 and page 2 are identical — offset is not advancing the window" >&2
fi

# ── 8. Group identification & least-privilege regressions ──────────────────

log_section "8. Regression: Duplicate Group Name, Flexible group_id, and group_name"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"Group-A"}'
check "409" "creating a group with a name that already exists returns 409, not 500"

api_call POST "/api/keys/$NOACCESS_ID/groups" "$MASTER_KEY" \
    "{\"group_id\":\"Group-B\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "a literal NAME in the group_id field is accepted (no 422)"

api_call POST "/api/keys/$NOACCESS_ID/groups" "$MASTER_KEY" \
    "{\"group_id\":\"$GROUP_A_ID\",\"can_read\":false,\"can_write\":true,\"can_delete\":false}"
check "400" "can_write without can_read is rejected (least-privilege rule)"

log "Assigning rights via a literal group_name ('fail2ban_nginx') alongside a UUID-based grant..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.77","group_name":"fail2ban_nginx","cause":"nginx probing"}'
check "200" "seed the fail2ban_nginx group into existence"
api_call GET "/api/groups" "$MASTER_KEY"
check "200" "list groups to find fail2ban_nginx's id"
FAIL2BAN_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.[] | select(.name=="fail2ban_nginx") | .id')
log "fail2ban_nginx group id: $FAIL2BAN_GROUP_ID"

api_call POST "/api/keys/$NOACCESS_ID/permissions" "$MASTER_KEY" \
    '{"group_name":"fail2ban_nginx","can_read":true,"can_write":true,"can_delete":false}'
check "200" "grant rights via the literal group_name field"

create_scoped_key "fail2ban_nginx UUID-grant key"
FAIL2BAN_UUID_KEY_ID="$CREATED_ID"
api_call POST "/api/keys/$FAIL2BAN_UUID_KEY_ID/permissions" "$MASTER_KEY" \
    "{\"group_id\":\"$FAIL2BAN_GROUP_ID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "grant rights on the SAME group via its UUID, seamlessly alongside the group_name grant"

api_call GET "/api/ips?group_name=fail2ban_nginx" "$NOACCESS_KEY"
check "200" "the group_name-granted key can read fail2ban_nginx"
check_jq "length" "1" "and sees the seeded address"

# ── 9. Webhook lifecycle ─────────────────────────────────────────────────────

log_section "9. Webhook Lifecycle (Create / List / Delete)"

log "Omitting the mandatory 'name' field reproduces the originally-reported 422 bug..."
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"target_url\":\"https://webhook.site/e2e-missing-name\",\"secret_token\":\"whsec_e2e\",\"payload_template\":\"{}\",\"group_id\":\"$GROUP_A_ID\"}"
check "422" "creating a webhook without 'name' is rejected with 422 (missing required field)"

log "Creating a webhook with the correct payload shape (name/target_url/secret_token/payload_template/group_id)..."
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"slack_alert\",\"target_url\":\"https://webhook.site/e2e-test-endpoint\",\"secret_token\":\"whsec_e2e_test_secret\",\"payload_template\":\"{\\\"ip\\\":\\\"{{target_address}}\\\"}\",\"group_id\":\"$GROUP_A_ID\"}"
check "200" "create the webhook"
WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')
log "Webhook id: $WEBHOOK_ID"

api_call GET "/api/webhooks" "$MASTER_KEY"
check "200" "list webhooks"
check_true "any(.[]; .id == \"$WEBHOOK_ID\" and .name == \"slack_alert\")" "the created webhook appears in the list with the right name"
check_true 'all(.[]; has("secret_token") | not)' "no listed webhook ever exposes its secret_token"

api_call DELETE "/api/webhooks/$WEBHOOK_ID" "$MASTER_KEY"
check "204" "delete the webhook"

api_call GET "/api/webhooks" "$MASTER_KEY"
check_true "all(.[]; .id != \"$WEBHOOK_ID\")" "the deleted webhook no longer appears in the list"

api_call DELETE "/api/webhooks/$WEBHOOK_ID" "$MASTER_KEY"
check "404" "deleting an already-deleted webhook returns 404, not another 204"

# ── 10. Key deletion ─────────────────────────────────────────────────────────

log_section "10. Key Deletion"

log "Creating a disposable key to delete..."
create_scoped_key "Disposable Key"
DISPOSABLE_KEY="$CREATED_KEY"; DISPOSABLE_ID="$CREATED_ID"

api_call GET "/api/auth/me" "$DISPOSABLE_KEY"
check "200" "the disposable key authenticates before deletion"

api_call DELETE "/api/keys/$WRITEONLY_ID" "$NOACCESS_KEY"
check "403" "a key without can_manage_keys cannot delete other keys"

api_call DELETE "/api/keys/$DISPOSABLE_ID" "$MASTER_KEY"
check "204" "master deletes the disposable key"

api_call GET "/api/auth/me" "$DISPOSABLE_KEY"
check "401" "the deleted key's secret is rejected immediately after deletion"

api_call DELETE "/api/keys/$DISPOSABLE_ID" "$MASTER_KEY"
check "404" "deleting an already-deleted key returns 404, not another 204"

# ── Summary ──────────────────────────────────────────────────────────────────

log_section "Summary"
echo -e "$(ts) ${GREEN}Passed: $PASS_COUNT${RESET}   ${RED}Failed: $FAIL_COUNT${RESET}" >&2

if [ "$FAIL_COUNT" -gt 0 ]; then
    err "E2E suite FAILED ($FAIL_COUNT failing check(s))."
    exit 1
fi

log "E2E suite PASSED — all $PASS_COUNT checks succeeded."
exit 0
