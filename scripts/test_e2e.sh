#!/usr/bin/env bash
#
# End-to-end test suite for simply_ip_vault.
#
# Builds the project, boots a fresh instance against a throwaway SQLite database with a
# deterministic bootstrap master key (via INITIAL_MASTER_KEY — no log-scraping), and drives the
# whole HTTP API with curl + jq: RBAC across a multi-key permission matrix, IP add/list/filter/
# update/delete across multiple groups (including banlist/whitelist overlap, and deletion via
# both query-string params and a JSON body), key lifecycle (create/update/rotate/delete), bound-IP
# CIDR enforcement, audit log generation + pagination + enrichment (client IP, API key name/
# prefix), webhook lifecycle (create/list/delete, with the mandatory `name` field) and per-webhook
# event filtering (events=IP_ADD/IP_UPDATE/IP_DELETE), RBAC-before-group-type-validation precedence
# and strict banlist/whitelist type enforcement on /api/ban and /api/white, auto-granted creator
# permissions on both explicit (POST /api/groups) and implicit (ban/white auto-create) group
# creation, explicit group_type selection on group creation (with a lenient default-to-banlist
# fallback for an omitted/invalid value), IP/CIDR canonicalization (a bare address and its /32 or
# /128 form are the same stored record, while genuine subnets keep their notation), latest-
# activity-first ordering on GET /api/ips, a lightweight format=iplist/mode=iplist response mode,
# human-readable target-key names in audit log details (instead of a bare UUID), and the
# group-identification bug fixes (duplicate-name 409, flexible group_id/group_name). Every request
# is logged with a timestamp, method, full URL, color-coded status, and jq-formatted body.
#
# Usage: ./scripts/test_e2e.sh
# Requires: curl, jq. Needs port 3000 free (the app's listen address is not configurable).
# Optional: python3 (only for live webhook-delivery verification in §13; that one section degrades
# to a skip + warning without it, everything else is unaffected).
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
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/simply_ip_vault_e2e.XXXXXX")"
DB_PATH="$WORK_DIR/e2e.db"
SERVER_LOG="$WORK_DIR/server.log"
RESP_BODY_FILE="$WORK_DIR/resp_body"
SERVER_PID=""
# Local loopback listener used only by the webhook event-filtering section to observe whether a
# dispatch actually happened; started lazily there, but declared here so `cleanup()` can always
# safely check it even if the script exits before that section runs.
RECEIVER_PORT="${RECEIVER_PORT:-18763}"
RECEIVER_LOG="$WORK_DIR/receiver_hits.log"
RECEIVER_PID=""

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
    if [ -n "$RECEIVER_PID" ] && kill -0 "$RECEIVER_PID" 2>/dev/null; then
        log "Stopping local webhook receiver (pid $RECEIVER_PID)..."
        kill "$RECEIVER_PID" 2>/dev/null || true
        wait "$RECEIVER_PID" 2>/dev/null || true
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

# python3 is a *soft* dependency: only the live webhook-delivery verification (§13) needs a local
# HTTP listener to observe whether a dispatch actually happened. Its absence — or the receiver
# port being busy — degrades that one section to a warning + skip rather than failing the suite,
# since every other check (including the events-field API contract itself) needs only curl/jq.
if command -v python3 >/dev/null 2>&1; then
    log "Found python3: $(command -v python3) (used for live webhook-delivery verification)"
else
    warn "python3 not found — live webhook-delivery verification (§13) will be skipped."
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
# ALLOW_PRIVATE_WEBHOOKS=true: §13 targets a webhook at a loopback receiver to observe deliveries,
# which SSRF protection would otherwise block by default. Every other webhook test in this script
# targets a real public host, so this doesn't loosen anything they depend on.
DATABASE_URL="sqlite://$DB_PATH?mode=rwc" RUST_LOG=info INITIAL_MASTER_KEY="$MASTER_KEY" \
    ALLOW_PRIVATE_WEBHOOKS=true \
    "$PROJECT_ROOT/target/debug/simply_ip_vault" >"$SERVER_LOG" 2>&1 &
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

# ── 11. Invalid input validation ────────────────────────────────────────────

log_section "11. Invalid Input Validation"

api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"999.999.999.999","group_name":"Group-A","cause":"malformed"}'
check "400" "banning a malformed address (999.999.999.999) is rejected with 400 Bad Request"

# ── 12. Group deletion cascade ───────────────────────────────────────────────

log_section "12. Group Deletion Cascade"

log "Creating a temporary group, then attaching an IP record and a key permission to it..."
api_call POST "/api/groups" "$MASTER_KEY" '{"name":"cascade-test-group"}'
check "200" "create the temporary cascade-test-group"
CASCADE_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.90","group_name":"cascade-test-group","cause":"cascade delete test"}'
check "200" "add an IP record into the temporary group"

create_scoped_key "Cascade Test Key"
CASCADE_KEY_ID="$CREATED_ID"
api_call POST "/api/keys/$CASCADE_KEY_ID/groups" "$MASTER_KEY" \
    "{\"group_id\":\"$CASCADE_GROUP_ID\",\"can_read\":true,\"can_write\":true,\"can_delete\":false}"
check "200" "grant a key permission on the temporary group"

log "Deleting the group while it still owns an IP record and a key permission..."
api_call DELETE "/api/groups/$CASCADE_GROUP_ID" "$MASTER_KEY"
check "204" "the group with attached records/permissions is removed cleanly, with no FK error"

api_call GET "/api/groups" "$MASTER_KEY"
check_true "all(.[]; .id != \"$CASCADE_GROUP_ID\")" "the deleted group no longer appears in the group list"

api_call GET "/api/ips?ip=198.51.100.90" "$MASTER_KEY"
check_jq "length" "0" "its IP record's membership was cascade-deleted along with the group"

api_call POST "/api/keys/$CASCADE_KEY_ID/groups" "$MASTER_KEY" \
    "{\"group_id\":\"$CASCADE_GROUP_ID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "404" "re-granting a permission against the now-deleted group id fails (group no longer resolvable)"

# ── 13. Webhook event filtering ─────────────────────────────────────────────

log_section "13. Webhook Event Filtering"

api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"bad-events-hook\",\"target_url\":\"https://webhook.site/e2e-bad-events\",\"secret_token\":\"x\",\"payload_template\":\"{}\",\"group_id\":\"$GROUP_A_ID\",\"events\":\"NOT_A_REAL_EVENT\"}"
check "400" "creating a webhook with an unrecognized events entry is rejected with 400"

WEBHOOK_RECEIVER_AVAILABLE=0
if command -v python3 >/dev/null 2>&1; then
    if command -v fuser >/dev/null 2>&1 && fuser "$RECEIVER_PORT/tcp" >/dev/null 2>&1; then
        warn "Port $RECEIVER_PORT is already in use; skipping live webhook-delivery verification."
    else
        cat > "$WORK_DIR/receiver.py" <<'PYEOF'
import http.server
import sys

port = int(sys.argv[1])
log_path = sys.argv[2]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)
        with open(log_path, 'a') as f:
            f.write('hit\n')
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass

http.server.HTTPServer(('127.0.0.1', port), Handler).serve_forever()
PYEOF
        : > "$RECEIVER_LOG"
        python3 "$WORK_DIR/receiver.py" "$RECEIVER_PORT" "$RECEIVER_LOG" &
        RECEIVER_PID=$!
        sleep 0.3
        if kill -0 "$RECEIVER_PID" 2>/dev/null; then
            WEBHOOK_RECEIVER_AVAILABLE=1
            log "Local webhook receiver listening on 127.0.0.1:$RECEIVER_PORT (pid $RECEIVER_PID)"
        else
            warn "Local webhook receiver failed to start; skipping live webhook-delivery verification."
        fi
    fi
else
    warn "python3 not found; skipping live webhook-delivery verification."
fi

count_receiver_hits() {
    wc -l < "$RECEIVER_LOG" 2>/dev/null | tr -d ' '
}

if [ "$WEBHOOK_RECEIVER_AVAILABLE" -eq 1 ]; then
    api_call POST "/api/groups" "$MASTER_KEY" '{"name":"event-filter-group"}'
    check "200" "create a dedicated group for event-filtering tests"
    EVENT_FILTER_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"add-only-hook\",\"target_url\":\"http://127.0.0.1:$RECEIVER_PORT/hook\",\"secret_token\":\"x\",\"payload_template\":\"{}\",\"group_id\":\"$EVENT_FILTER_GROUP_ID\",\"events\":\"IP_ADD\"}"
    check "200" "create a webhook restricted to events=IP_ADD"
    EVENT_FILTER_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call GET "/api/webhooks" "$MASTER_KEY"
    check_true "any(.[]; .id == \"$EVENT_FILTER_WEBHOOK_ID\" and .events == \"IP_ADD\")" "the events field round-trips and is visible when listing webhooks"

    log "Banning a brand-new address (IP_ADD) — the events:\"IP_ADD\" webhook should fire..."
    api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"192.0.2.250","group_name":"event-filter-group","cause":"event filter test"}'
    check "200" "add the address (IP_ADD)"

    HITS=0
    for _ in $(seq 1 20); do
        HITS=$(count_receiver_hits)
        [ "${HITS:-0}" -ge 1 ] && break
        sleep 0.2
    done
    if [ "${HITS:-0}" == "1" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} IP_ADD was delivered to the events:\"IP_ADD\" webhook (1 hit)" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} expected exactly 1 delivery after IP_ADD, got ${HITS:-0}" >&2
    fi

    log "Re-registering the same address (IP_UPDATE) — must NOT fire (not subscribed)..."
    api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"192.0.2.250","group_name":"event-filter-group","cause":"updated"}'
    check "200" "re-register the address (IP_UPDATE)"
    sleep 1
    HITS=$(count_receiver_hits)
    if [ "${HITS:-0}" == "1" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} IP_UPDATE was correctly skipped (still 1 hit)" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} expected delivery count to stay at 1 after IP_UPDATE, got ${HITS:-0}" >&2
    fi

    log "Deleting the address (IP_DELETE) — must also NOT fire..."
    api_call DELETE "/api/ips?target_address=192.0.2.250&group_name=event-filter-group" "$MASTER_KEY"
    check "204" "delete the address (IP_DELETE)"
    sleep 1
    HITS=$(count_receiver_hits)
    if [ "${HITS:-0}" == "1" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} IP_DELETE was correctly skipped (still 1 hit)" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} expected delivery count to stay at 1 after IP_DELETE, got ${HITS:-0}" >&2
    fi
else
    warn "Live webhook-delivery verification skipped (see above); the events-field API contract check above still ran."
fi

# ── 14. Audit log enrichment (client IP, API key name/prefix) ──────────────

log_section "14. Audit Log Enrichment (Client IP, API Key Name/Prefix)"

api_call GET "/api/audit-logs?action=GROUP_CREATE&limit=1" "$MASTER_KEY"
check "200" "fetch the most recent GROUP_CREATE audit entry to inspect enrichment fields"
check_jq ".[0].client_ip" "127.0.0.1" "the audit entry's client_ip is populated with the real caller address"
check_jq ".[0].api_key_name" "System Master" "the audit entry's api_key_name is denormalized from the acting key"
check_true '(.[0].api_key_prefix | length) == 8' "the audit entry's api_key_prefix is present and 8 characters"

# ── 15. RBAC precedence & strict group-type validation ──────────────────────

log_section "15. RBAC Precedence & Strict Group Type Validation"

log "Master creates a whitelist group and a banlist group for the type-validation scenarios..."
api_call POST "/api/white" "$MASTER_KEY" '{"target_address":"203.0.113.60","group_name":"rbac-precedence-whitelist","cause":"seed"}'
check "200" "seed the whitelist group"
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.61","group_name":"rbac-precedence-banlist","cause":"seed"}'
check "200" "seed the banlist group"

log "A key with NO permission mapping on the whitelist group attempts to ban into it..."
api_call POST "/api/ban" "$NOACCESS_KEY" '{"target_address":"198.51.100.30","group_name":"rbac-precedence-whitelist"}'
check "403" "no-access key gets 403 (RBAC), not 400 (type mismatch) — permission is checked first"
check_true '.error | contains("Permission denied")' "the 403 body is a genuine permission-denied error, not a type-validation one"

log "Granting a dedicated key full read+write on both groups..."
create_scoped_key "Type Validation Key"
TYPE_CHECK_KEY="$CREATED_KEY"; TYPE_CHECK_ID="$CREATED_ID"
api_call POST "/api/keys/$TYPE_CHECK_ID/groups" "$MASTER_KEY" \
    '{"group_name":"rbac-precedence-whitelist","can_read":true,"can_write":true,"can_delete":false}'
check "200" "grant the type-validation key rights on the whitelist group"
api_call POST "/api/keys/$TYPE_CHECK_ID/groups" "$MASTER_KEY" \
    '{"group_name":"rbac-precedence-banlist","can_read":true,"can_write":true,"can_delete":false}'
check "200" "grant the type-validation key rights on the banlist group"

log "Now authorized: banning into the whitelist group is rejected with the exact 400 message..."
api_call POST "/api/ban" "$TYPE_CHECK_KEY" '{"target_address":"198.51.100.31","group_name":"rbac-precedence-whitelist"}'
check "400" "banning into a whitelist group is rejected with 400, not 200 or 403"
check_jq ".error" "Cannot ban IP into group 'rbac-precedence-whitelist': group type is 'whitelist'. Use /api/white or target a banlist group." \
    "the error message exactly matches the spec"

log "Whitelisting into the banlist group is rejected with the exact reverse 400 message..."
api_call POST "/api/white" "$TYPE_CHECK_KEY" '{"target_address":"198.51.100.32","group_name":"rbac-precedence-banlist"}'
check "400" "whitelisting into a banlist group is rejected with 400, not 200 or 403"
check_jq ".error" "Cannot whitelist IP into group 'rbac-precedence-banlist': group type is 'banlist'. Use /api/ban or target a whitelist group." \
    "the error message exactly matches the reverse spec"

# ── 16. Auto-grant full permissions on group creation ───────────────────────

log_section "16. Auto-Grant Full Permissions on Group Creation"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Group Creator Key","bound_ips":"0.0.0.0/0","can_create_groups":true}'
check "200" "create a key with can_create_groups=true"
GROUP_CREATOR_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')

log "Explicit creation via POST /api/groups..."
api_call POST "/api/groups" "$GROUP_CREATOR_KEY" '{"name":"explicit-creator-group"}'
check "200" "the can_create_groups key creates a new group via POST /api/groups"
EXPLICIT_CREATOR_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call GET "/api/auth/me" "$GROUP_CREATOR_KEY"
check "200" "fetch the creator key's own profile to inspect its granted permissions"
check_true "[.group_permissions[] | select(.group_id == \"$EXPLICIT_CREATOR_GROUP_ID\")] | length == 1" \
    "the creator has exactly one permission record on the group it just created"
check_true "[.group_permissions[] | select(.group_id == \"$EXPLICIT_CREATOR_GROUP_ID\")][0] | .can_read and .can_write and .can_delete" \
    "that permission record grants full can_read/can_write/can_delete"

log "Implicit creation via POST /api/ban (auto-create-on-first-use)..."
api_call POST "/api/ban" "$GROUP_CREATOR_KEY" '{"target_address":"198.51.100.240","group_name":"implicit-creator-group","cause":"testing implicit auto-grant"}'
check "200" "the can_create_groups key implicitly creates a new group via POST /api/ban"

api_call GET "/api/groups" "$MASTER_KEY"
IMPLICIT_CREATOR_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.[] | select(.name=="implicit-creator-group") | .id')

api_call GET "/api/auth/me" "$GROUP_CREATOR_KEY"
check "200" "fetch the creator key's profile again after implicit group creation"
check_true "[.group_permissions[] | select(.group_id == \"$IMPLICIT_CREATOR_GROUP_ID\")][0] | .can_read and .can_write and .can_delete" \
    "the implicitly-created group also grants full can_read/can_write/can_delete"

# ── 17. Group type creation & display ───────────────────────────────────────

log_section "17. Group Type Creation & Display"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"explicit-whitelist-group","group_type":"whitelist"}'
check "200" "create a group with an explicit group_type=whitelist"
check_jq ".group_type" "whitelist" "the response reports group_type=whitelist"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"explicit-banlist-group","group_type":"banlist"}'
check "200" "create a group with an explicit group_type=banlist"
check_jq ".group_type" "banlist" "the response reports group_type=banlist"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"default-type-group"}'
check "200" "create a group omitting group_type entirely"
check_jq ".group_type" "banlist" "an omitted group_type defaults to banlist"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"invalid-type-group","group_type":"not-a-real-type"}'
check "200" "an invalid group_type value is NOT rejected with 400..."
check_jq ".group_type" "banlist" "...it silently falls back to the banlist default instead"

api_call GET "/api/groups" "$MASTER_KEY"
check "200" "list groups to confirm the whitelist group's type persisted"
check_true '[.[] | select(.name=="explicit-whitelist-group")][0].group_type == "whitelist"' \
    "GET /api/groups shows the persisted whitelist type, not just the create response"

# ── 18. IP address canonicalization (/32, /128 stripping) ───────────────────

log_section "18. IP Address Canonicalization"

log "Banning the same address once as '/32' and once bare must produce exactly ONE record..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"188.190.74.128/32","group_name":"canon-e2e-group","cause":"first as /32"}'
check "200" "ban the /32 form"
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"188.190.74.128","group_name":"canon-e2e-group","cause":"second as bare"}'
check "200" "ban the bare form of the SAME address"

api_call GET "/api/ips?groups=canon-e2e-group" "$MASTER_KEY"
check "200" "list the canonicalization test group"
check_jq "length" "1" "the /32 and bare forms collapsed into exactly one stored record"
check_jq ".[0].target_address" "188.190.74.128" "stored in canonical (bare) form, not '.../32'"
check_jq ".[0].cause" "second as bare" "the second call updated the same row (proving it was a re-registration, not a duplicate insert)"

log "Deleting via the /32 form must remove a record that is actually stored bare..."
api_call DELETE "/api/ips?target_address=188.190.74.128/32&group_name=canon-e2e-group" "$MASTER_KEY"
check "204" "delete succeeds even though the stored value has no '/32' suffix"
api_call GET "/api/ips?groups=canon-e2e-group" "$MASTER_KEY"
check_jq "length" "0" "the record is actually gone"

log "A genuine subnet (not a single-host CIDR) must keep its CIDR notation unchanged..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.0/24","group_name":"canon-e2e-group","cause":"real subnet"}'
check "200" "ban a /24 subnet"
api_call GET "/api/ips?groups=canon-e2e-group" "$MASTER_KEY"
check_jq ".[0].target_address" "203.0.113.0/24" "a /24 is stored with its CIDR notation intact, not stripped like /32"

# ── 19. Latest-activity-first ordering & lightweight iplist format ──────────

log_section "19. Latest-Activity-First Ordering & Lightweight iplist Format"

log "Banning 3 addresses in sequence — GET /api/ips must return them most-recent-first..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.201","group_name":"ordering-e2e-group"}'
check "200" "ban address 1"
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.202","group_name":"ordering-e2e-group"}'
check "200" "ban address 2"
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.203","group_name":"ordering-e2e-group"}'
check "200" "ban address 3"

api_call GET "/api/ips?groups=ordering-e2e-group" "$MASTER_KEY"
check "200" "list the ordering test group"
check_jq ".[0].target_address" "198.51.100.203" "the most recently created record sorts first"
check_jq ".[2].target_address" "198.51.100.201" "the oldest record sorts last"

log "Re-banning the oldest address must move it back to the front..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.201","group_name":"ordering-e2e-group","cause":"renewed"}'
check "200" "re-ban address 1"
api_call GET "/api/ips?groups=ordering-e2e-group" "$MASTER_KEY"
check_jq ".[0].target_address" "198.51.100.201" "the re-registered record jumps back to the front"

log "GET /api/ips?format=iplist returns a lightweight, deduplicated address list..."
api_call GET "/api/ips?groups=ordering-e2e-group&format=iplist" "$MASTER_KEY"
check "200" "iplist format request succeeds"
check_true '(.ip_list | type) == "array"' "the response has an ip_list array"
check_jq "(.ip_list | length)" "3" "all 3 addresses are present"
check_true '.ip_list | contains(["198.51.100.201","198.51.100.202","198.51.100.203"])' "the exact addresses are present"

log "mode=iplist is accepted as a synonym for format=iplist..."
api_call GET "/api/ips?groups=ordering-e2e-group&mode=iplist" "$MASTER_KEY"
check "200" "mode=iplist request succeeds"
check_jq "(.ip_list | length)" "3" "same result via the mode= synonym"

# ── 20. Readable audit log details (human-readable key names) ──────────────

log_section "20. Readable Audit Log Details"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"readable_logs_key","bound_ips":"0.0.0.0/0"}'
check "200" "create a dedicated key to exercise KEY_ROTATE/KEY_PERM_UPDATE/KEY_DELETE logging"
READABLE_LOGS_KEY_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/keys/$READABLE_LOGS_KEY_ID/rotate" "$MASTER_KEY"
check "200" "rotate its secret"
api_call GET "/api/audit-logs?action=KEY_ROTATE&limit=1" "$MASTER_KEY"
check "200" "fetch the most recent KEY_ROTATE entry"
check_true '(.[0].details | contains("readable_logs_key")) and (.[0].details | contains("Rotated secret for key"))' \
    "the details string names the key by name, not just its raw UUID"

api_call POST "/api/keys/$READABLE_LOGS_KEY_ID/groups" "$MASTER_KEY" \
    '{"group_name":"readable-logs-group","can_read":true,"can_write":false,"can_delete":false}'
check "200" "grant it a group permission"
api_call GET "/api/audit-logs?action=KEY_PERM_UPDATE&limit=1" "$MASTER_KEY"
check "200" "fetch the most recent KEY_PERM_UPDATE entry"
check_jq ".[0].details" "Updated permissions for key 'readable_logs_key' (${READABLE_LOGS_KEY_ID:0:8}...)" \
    "the details string exactly matches the spec's example format"

api_call DELETE "/api/keys/$READABLE_LOGS_KEY_ID" "$MASTER_KEY"
check "204" "delete the key"
api_call GET "/api/audit-logs?action=KEY_DELETE&limit=1" "$MASTER_KEY"
check "200" "fetch the most recent KEY_DELETE entry"
check_true '.[0].details | contains("readable_logs_key")' "the delete log also names the key by name, even though it no longer exists"

# ── Summary ──────────────────────────────────────────────────────────────────

log_section "Summary"
echo -e "$(ts) ${GREEN}Passed: $PASS_COUNT${RESET}   ${RED}Failed: $FAIL_COUNT${RESET}" >&2

if [ "$FAIL_COUNT" -gt 0 ]; then
    err "E2E suite FAILED ($FAIL_COUNT failing check(s))."
    exit 1
fi

log "E2E suite PASSED — all $PASS_COUNT checks succeeded."
exit 0
