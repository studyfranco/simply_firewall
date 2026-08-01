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
# Its HMAC counterpart, passed as INITIAL_MASTER_SIGNING_SECRET for the same reason: every request
# must now carry an X-Signature-256, so the script needs the bootstrap key's signing secret up front.
MASTER_SIGNING_SECRET="e2e_master_signing_secret_for_testing_987654321"

# Maps a plaintext API key -> its HMAC signing secret, so api_call() can sign on behalf of whichever
# key a check happens to use without every call site having to pass a second credential.
# register_key_secret() populates it as keys are minted during the run.
declare -A SIGNING_SECRETS=()
SIGNING_SECRETS["$MASTER_KEY"]="$MASTER_SIGNING_SECRET"
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

# Computes the hex HMAC-SHA256 the server expects in X-Signature-256, over the CANONICAL_V1 string
# METHOD\nPATH\nTIMESTAMP\nRAW_BODY (the four fields joined by single LFs, no trailing newline).
#
# The query string is stripped from PATH before signing, matching the server's
# `crypto::verify_signature` — it signs the URL path only, so that reverse proxies are free to
# rewrite query parameters without invalidating otherwise-valid requests.
#
# `printf` with an explicit `%s\n%s\n%s\n%s` format (rather than `echo`, or interpolating "\n" into
# a single string) is what makes the delimiters real newlines and keeps the message byte-exact:
# no trailing newline, and no mangling of JSON bodies containing backslashes or leading dashes.
# Usage: hmac_sign SECRET METHOD PATH TIMESTAMP BODY
hmac_sign() {
    local secret="$1" method="$2" path="$3" timestamp="$4" body="${5:-}"
    local path_only="${path%%\?*}"
    printf '%s\n%s\n%s\n%s' "$method" "$path_only" "$timestamp" "$body" \
        | openssl dgst -sha256 -hmac "$secret" \
        | sed 's/^.*= //'
}

# Records the signing secret for a freshly minted key so subsequent api_call invocations using that
# key can sign with it. Call immediately after any response carrying .plaintext_key/.signing_secret.
# Usage: register_key_secret PLAINTEXT_KEY SIGNING_SECRET
register_key_secret() {
    local key="$1" secret="$2"
    if [ -z "$key" ] || [ "$key" == "null" ] || [ -z "$secret" ] || [ "$secret" == "null" ]; then
        err "register_key_secret called with an empty key/secret — the API response was malformed"
        return 1
    fi
    SIGNING_SECRETS["$key"]="$secret"
}

# Performs an HTTP request and leaves the outcome in $RESP_STATUS / $RESP_BODY. Every call prints
# a timestamped, colored "[STATUS] METHOD /path" line followed by the jq-formatted response body.
# Usage: api_call METHOD PATH [API_KEY] [JSON_BODY] [X_FORWARDED_FOR]
api_call() {
    local method="$1" path="$2" api_key="${3:-}" data="${4:-}" xff="${5:-}"
    local args=(-s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method")

    # Anti-replay timestamp: always sent, even for the deliberately-unauthenticated checks, so those
    # still fail on the credential under test rather than on a missing X-Timestamp.
    local timestamp; timestamp=$(date -u +%s)
    args+=(-H "X-Timestamp: $timestamp")

    if [ -n "$api_key" ]; then
        args+=(-H "X-API-Key: $api_key")
        # An unknown key (the "invalid key is rejected" checks) has no registered secret; sign with a
        # placeholder so the request is still well-formed and gets rejected at key lookup, which is
        # the failure those checks are actually asserting.
        local secret="${SIGNING_SECRETS[$api_key]:-unregistered-key-has-no-signing-secret}"
        args+=(-H "X-Signature-256: $(hmac_sign "$secret" "$method" "$path" "$timestamp" "$data")")
    fi

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

for bin in curl jq cargo openssl; do
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
log "Using INITIAL_MASTER_KEY + INITIAL_MASTER_SIGNING_SECRET for deterministic bootstrap (no log-scraping needed)"
# ALLOW_PRIVATE_WEBHOOKS=true: §13 targets a webhook at a loopback receiver to observe deliveries,
# which SSRF protection would otherwise block by default. Every other webhook test in this script
# targets a real public host, so this doesn't loosen anything they depend on.
# VAULT_ENCRYPTION_KEY is set so the run exercises the AES-GCM-256 seal/open path for signing
# secrets end to end, rather than the plaintext development fallback.
# TRUSTED_PROXIES=localhost: curl connects over loopback, so declaring it a trusted proxy is what
# lets the CIDR checks below use X-Forwarded-For to stand in for a client address — exactly as a
# real reverse proxy would. Spelled as a *hostname* rather than 127.0.0.1 on purpose: that exercises
# the dynamic DNS resolution path (the Docker/Traefik case) end to end against a real resolver,
# rather than only the literal-CIDR path the unit tests cover. It resolves to 127.0.0.1 and
# deliberately NOT to 127.0.0.2, which §6b connects from to exercise the untrusted-peer path.
DATABASE_URL="sqlite://$DB_PATH?mode=rwc" RUST_LOG=info INITIAL_MASTER_KEY="$MASTER_KEY" \
    INITIAL_MASTER_SIGNING_SECRET="$MASTER_SIGNING_SECRET" \
    VAULT_ENCRYPTION_KEY="e2e-vault-encryption-passphrase" \
    ALLOW_PRIVATE_WEBHOOKS=true \
    TRUSTED_PROXIES="localhost" \
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

# ── 1b. HMAC signing & anti-replay guard ────────────────────────────────────
#
# These checks bypass api_call() and drive curl directly: they need to send deliberately malformed
# or omitted auth headers, which api_call() exists precisely to get right.

log_section "1b. HMAC Signing & Anti-Replay Guard"

# Usage: raw_call METHOD PATH [curl args...] — same $RESP_STATUS/$RESP_BODY contract as api_call.
raw_call() {
    local method="$1" path="$2"; shift 2
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method" "$@" "$BASE_URL$path")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    local color; color=$(status_color "$RESP_STATUS")
    printf "%s ${color}[%s]${RESET} %-6s %s\n" "$(ts)" "$RESP_STATUS" "$method" "$BASE_URL$path" >&2
    print_response_body
}

NOW_TS=$(date -u +%s)
VALID_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "GET" "/api/auth/me" "$NOW_TS" "")

# Control: the three headers together authenticate.
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: $VALID_SIG"
check "200" "X-API-Key + X-Timestamp + X-Signature-256 authenticates"

# Each header is individually mandatory.
raw_call GET "/api/auth/me" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: $VALID_SIG"
check "401" "missing X-API-Key is rejected"

raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Signature-256: $VALID_SIG"
check "401" "missing X-Timestamp is rejected"

# This is exactly the pre-HMAC request shape — it must no longer be sufficient.
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $NOW_TS"
check "401" "missing X-Signature-256 is rejected (a bare API key no longer authenticates)"

raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: not-a-number" -H "X-Signature-256: $VALID_SIG"
check "401" "a malformed X-Timestamp is rejected"

raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: deadbeef"
check "401" "a wrong signature is rejected"

# Anti-replay window: +/-300s, symmetric. Each of these carries a *correct* signature for the
# timestamp it sends, so only the freshness check can reject it.
#
# The two directions need different margins, because elapsed wall-clock time moves them oppositely:
# a stale timestamp only gets staler while the script runs, so 301 can never drift back inside the
# window. A *future* timestamp decays toward it — at NOW+301, one second of elapsed time between
# capturing NOW_TS and the server reading its own clock leaves a skew of 300, which is inside the
# window and legitimately returns 200. Hence a fresh capture immediately before the call plus a
# margin comfortably clear of the boundary.
#
# The exact ±300/±301 edge is pinned deterministically in
# `tests/security_tests.rs::attack_timestamp_forgery_outside_the_window_is_rejected_both_directions`,
# where the request is handled in-process microseconds after the timestamp is chosen. E2E asserts
# the behaviour, not the boundary.
STALE_TS=$((NOW_TS - 301))
STALE_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "GET" "/api/auth/me" "$STALE_TS" "")
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $STALE_TS" -H "X-Signature-256: $STALE_SIG"
check "401" "a 301s-stale timestamp is rejected as a replay"

FUTURE_TS=$(( $(date -u +%s) + 360 ))
FUTURE_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "GET" "/api/auth/me" "$FUTURE_TS" "")
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $FUTURE_TS" -H "X-Signature-256: $FUTURE_SIG"
check "401" "a future-dated timestamp beyond the window is rejected"

EDGE_TS=$((NOW_TS - 290))
EDGE_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "GET" "/api/auth/me" "$EDGE_TS" "")
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $EDGE_TS" -H "X-Signature-256: $EDGE_SIG"
check "200" "a 290s-old timestamp is still inside the 300s window"

# The signature binds the body: replaying an authentic signature over different content fails.
BIND_BODY='{"target_address":"198.51.100.77","group_name":"Group-Sig","cause":"signed"}'
BIND_TS=$(date -u +%s)
BIND_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "POST" "/api/ban" "$BIND_TS" "$BIND_BODY")
raw_call POST "/api/ban" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $BIND_TS" \
    -H "X-Signature-256: $BIND_SIG" -H "Content-Type: application/json" -d "$BIND_BODY"
check "200" "a correctly signed body is accepted"

raw_call POST "/api/ban" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $BIND_TS" \
    -H "X-Signature-256: $BIND_SIG" -H "Content-Type: application/json" \
    -d '{"target_address":"9.9.9.9","group_name":"Group-Sig","cause":"tampered"}'
check "401" "the same signature over a tampered body is rejected"

# ...and the path: a /api/ban signature cannot be replayed onto /api/white.
raw_call POST "/api/white" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $BIND_TS" \
    -H "X-Signature-256: $BIND_SIG" -H "Content-Type: application/json" -d "$BIND_BODY"
check "401" "a /api/ban signature replayed onto /api/white is rejected"

# ── CANONICAL_V1 adversarial probes ─────────────────────────────────────────
# Each of these carries an otherwise *perfect* request — correct key, correct signature over the
# exact bytes sent — and changes one thing. A 200 here means the corresponding control is not
# actually being enforced. Mirrors tests/security_tests.rs at the HTTP boundary.

# X-Timestamp must be mandatory, not merely validated when present. If a missing header skipped the
# freshness check, every captured signature would stay replayable forever, since the signature
# itself encodes no notion of time.
STRIP_TS=$(date -u +%s)
STRIP_BODY='{"target_address":"198.51.100.91","group_name":"Group-Sig","cause":"no-timestamp"}'
STRIP_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "POST" "/api/ban" "$STRIP_TS" "$STRIP_BODY")
raw_call POST "/api/ban" -H "X-API-Key: $MASTER_KEY" \
    -H "X-Signature-256: $STRIP_SIG" -H "Content-Type: application/json" -d "$STRIP_BODY"
check "401" "CANONICAL_V1: omitting X-Timestamp on an otherwise valid signed request is rejected"

# The same, on a GET with no body, so the rejection cannot be attributed to body handling.
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Signature-256: $VALID_SIG"
check "401" "CANONICAL_V1: omitting X-Timestamp on a signed GET is rejected"

# An empty X-Timestamp must not be treated as absent-and-therefore-skipped, nor parsed as 0.
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp;" -H "X-Signature-256: $VALID_SIG"
check "401" "CANONICAL_V1: an empty X-Timestamp is rejected"

# Signature forgery: flip only the final hex digit, keeping 64 valid hex characters so the request
# reaches the constant-time MAC comparison instead of failing early in hex decoding.
FORGED_SIG="${VALID_SIG%?}"
case "${VALID_SIG: -1}" in
    0) FORGED_SIG="${FORGED_SIG}1" ;;
    *) FORGED_SIG="${FORGED_SIG}0" ;;
esac
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: $FORGED_SIG"
check "401" "a signature differing only in its last character is rejected"

# ...and the first character, so no position of the digest goes uncompared.
FIRST_FLIPPED="0${VALID_SIG:1}"
[ "${VALID_SIG:0:1}" == "0" ] && FIRST_FLIPPED="1${VALID_SIG:1}"
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: $FIRST_FLIPPED"
check "401" "a signature differing only in its first character is rejected"

# A truncated signature sharing a valid prefix must not pass a length-agnostic comparison.
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: ${VALID_SIG:0:32}"
check "401" "a truncated signature with a valid prefix is rejected"

raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: ${VALID_SIG}00"
check "401" "an over-long signature with a valid prefix is rejected"

# The signing secret must never come back from a read endpoint.
api_call GET "/api/keys" "$MASTER_KEY"
check "200" "list keys"
if echo "$RESP_BODY" | grep -q "signing_secret"; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} GET /api/keys must not expose signing_secret" >&2
else
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} GET /api/keys does not expose signing_secret" >&2
fi

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
    CREATED_SIGNING_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
    register_key_secret "$CREATED_KEY" "$CREATED_SIGNING_SECRET"
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
register_key_secret "$NEW_READONLY_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

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
register_key_secret "$RESTRICTED_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

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
register_key_secret "$LOOPBACK_ONLY_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

api_call GET "/api/auth/me" "$LOOPBACK_ONLY_KEY" "" "203.0.113.50"
check "403" "an out-of-CIDR X-Forwarded-For is strictly rejected"
check_jq ".error" "Client IP not allowed" "the error message is exactly 'Client IP not allowed'"

# ── 6b. X-Forwarded-For spoofing from an UNTRUSTED peer ─────────────────────
#
# Everything above connects from 127.0.0.1, which this run declares a trusted proxy, so the header
# is honoured. The attack is the opposite case: a client that is NOT a configured proxy must not be
# able to satisfy bound_ips by writing an allowed address into a header it controls.
#
# 127.0.0.2 is a loopback address that is NOT in TRUSTED_PROXIES, so binding curl's source address
# to it reproduces an untrusted peer without needing a second machine. Guarded, because
# `--interface` against a 127/8 alias is Linux-specific.

log_section "6b. X-Forwarded-For Spoofing From an Untrusted Peer"

# Signs and sends a request from an explicit source address. Mirrors api_call's signing, but adds
# --interface so the server sees a different TCP peer.
call_from_interface() {
    local iface="$1" method="$2" path="$3" api_key="$4" xff="$5"
    local timestamp; timestamp=$(date -u +%s)
    local secret="${SIGNING_SECRETS[$api_key]:-unregistered-key-has-no-signing-secret}"
    local args=(-s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method" --interface "$iface")
    args+=(-H "X-API-Key: $api_key" -H "X-Timestamp: $timestamp")
    args+=(-H "X-Signature-256: $(hmac_sign "$secret" "$method" "$path" "$timestamp" "")")
    [ -n "$xff" ] && args+=(-H "X-Forwarded-For: $xff")
    RESP_STATUS=$(curl "${args[@]}" "$BASE_URL$path")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    local color; color=$(status_color "$RESP_STATUS")
    printf "%s ${color}[%s]${RESET} %-6s %s (from %s)\n" "$(ts)" "$RESP_STATUS" "$method" "$BASE_URL$path" "$iface" >&2
    print_response_body
}

if curl -s -o /dev/null --interface 127.0.0.2 --max-time 5 "$BASE_URL/api/auth/me" 2>/dev/null; then
    api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Spoof-Target Key","bound_ips":"203.0.113.0/24"}'
    check "200" "create a key bound to 203.0.113.0/24 for the spoofing test"
    SPOOF_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
    register_key_secret "$SPOOF_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

    # The attack: an untrusted peer claiming an address inside the bound CIDR.
    call_from_interface "127.0.0.2" GET "/api/auth/me" "$SPOOF_KEY" "203.0.113.99"
    check "403" "a spoofed X-Forwarded-For from an untrusted peer does NOT satisfy bound_ips"
    check_jq ".error" "Client IP not allowed" "the spoofing rejection is the CIDR check, not an auth error"

    # Impersonating the trusted proxy inside the header must not bootstrap trust either.
    call_from_interface "127.0.0.2" GET "/api/auth/me" "$SPOOF_KEY" "127.0.0.1, 203.0.113.99"
    check "403" "naming the trusted proxy inside X-Forwarded-For does not bootstrap trust"

    # TRUSTED_PROXIES is spelled as the hostname "localhost" for this run, so the control below
    # passing proves the dynamic DNS resolution path works against a real resolver — the same
    # mechanism a Docker/Traefik deployment relies on to keep trusting a container whose IP moves.

    # Control: the identical header from the trusted peer (127.0.0.1) IS honoured, proving the
    # difference is the peer address and not something incidental about the request.
    api_call GET "/api/auth/me" "$SPOOF_KEY" "" "203.0.113.99"
    check "200" "the same X-Forwarded-For from the trusted proxy IS honored"

    # A master key with bound_ips is subject to them like any other key — no exemption.
    api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Bound Master Key","is_master":true,"bound_ips":"203.0.113.0/24"}'
    check "200" "create a master key bound to 203.0.113.0/24"
    BOUND_MASTER_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
    register_key_secret "$BOUND_MASTER_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

    api_call GET "/api/auth/me" "$BOUND_MASTER_KEY" "" "203.0.113.99"
    check "200" "a bound master key works from inside its CIDR"

    api_call GET "/api/auth/me" "$BOUND_MASTER_KEY" "" "8.8.8.8"
    check "403" "a bound MASTER key is rejected outside its CIDR (no master exemption)"
else
    warn "curl --interface 127.0.0.2 unavailable — skipping untrusted-peer spoofing checks."
fi

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
import json
import sys

port = int(sys.argv[1])
log_path = sys.argv[2]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', 'replace')
        # One JSON object per line: still exactly one line per delivery (so the existing
        # `wc -l` hit-counting checks are unaffected), but now carrying everything the
        # auth-mode checks need to verify each of the four dispatch shapes.
        with open(log_path, 'a') as f:
            f.write(json.dumps({
                'path': self.path,
                'signature': self.headers.get('X-Signature-256'),
                'timestamp': self.headers.get('X-Timestamp'),
                'api_key': self.headers.get('X-API-Key'),
                'body': body,
            }) + '\n')
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
register_key_secret "$GROUP_CREATOR_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

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

# ── 21. API key signing-secret rotation ─────────────────────────────────────

log_section "21. Signing Secret Rotation (POST /api/keys/{id}/rotate-secret)"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"rotate_secret_key","bound_ips":"0.0.0.0/0","can_create_groups":true}'
check "200" "create a key to rotate the secret of"
ROTATE_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
ROTATE_KEY_ID=$(echo "$RESP_BODY" | jq -r '.id')
ROTATE_OLD_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
register_key_secret "$ROTATE_KEY" "$ROTATE_OLD_SECRET"

api_call GET "/api/auth/me" "$ROTATE_KEY"
check "200" "the key authenticates with its original signing secret"

api_call POST "/api/keys/$ROTATE_KEY_ID/rotate-secret" "$MASTER_KEY"
check "200" "rotate the signing secret"
check_true '.id != null' "the response carries the key id"
check_true '.name == "rotate_secret_key"' "the key name is preserved"
check_true '.signing_secret != null and (.signing_secret | length) > 0' "a new signing secret is returned"
check_true '.plaintext_key == null' "rotate-secret does NOT reissue the API key"
ROTATE_NEW_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')

if [ "$ROTATE_NEW_SECRET" != "$ROTATE_OLD_SECRET" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the new signing secret differs from the old one" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} rotate-secret returned the same signing secret" >&2
fi

# The old secret is dead: sign with it explicitly (the same API key, the previous secret).
NOW_TS=$(date -u +%s)
OLD_SIG=$(hmac_sign "$ROTATE_OLD_SECRET" "GET" "/api/auth/me" "$NOW_TS" "")
raw_call GET "/api/auth/me" -H "X-API-Key: $ROTATE_KEY" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: $OLD_SIG"
check "401" "the OLD signing secret no longer authenticates"

# The same, unchanged API key works with the new secret.
register_key_secret "$ROTATE_KEY" "$ROTATE_NEW_SECRET"
api_call GET "/api/auth/me" "$ROTATE_KEY"
check "200" "the SAME API key authenticates with the new signing secret"
check_true ".id == \"$ROTATE_KEY_ID\"" "identity is unchanged after rotation"
check_true '.can_create_groups == true' "global scopes survive rotation"

api_call GET "/api/audit-logs?action=KEY_SECRET_ROTATE&limit=1" "$MASTER_KEY"
check "200" "fetch the KEY_SECRET_ROTATE audit entry"
check_true '.[0].details | contains("rotate_secret_key")' "the audit entry names the rotated key"

api_call POST "/api/keys/00000000-0000-0000-0000-000000000000/rotate-secret" "$MASTER_KEY"
check "404" "rotating an unknown key id is a 404"

api_call POST "/api/keys/$ROTATE_KEY_ID/rotate-secret" "$NOACCESS_KEY"
check "403" "a key without can_manage_keys cannot rotate secrets"

api_call DELETE "/api/keys/$ROTATE_KEY_ID" "$MASTER_KEY"
check "204" "clean up the rotation test key"

# ── 22. Webhook auth modes ──────────────────────────────────────────────────

log_section "22. Webhook Auth Modes (CANONICAL_V1 / BODY_ONLY / API_KEY_ONLY / NONE)"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"SigMode-Group"}'
check "200" "create a group for auth-mode webhooks"
SIGMODE_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

# Validation happens at the API boundary rather than silently downgrading.
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"bad-mode\",\"target_url\":\"https://example.com/h\",\"secret_token\":\"s\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"CANONICAL_V2\"}"
check "400" "an unknown auth_mode is rejected"

# Per-mode preconditions: a signing mode with no key signs with the empty secret (forgeable), and
# API_KEY_ONLY with no key sends no credential at all (silently equivalent to NONE).
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"no-secret\",\"target_url\":\"https://example.com/h\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\"}"
check "400" "a signing auth_mode without a secret_token is rejected"

# The explicitly-blank variant, which is what an untouched HTML form field actually posts — it must
# not slip past a check that only looks for an absent field.
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"empty-secret\",\"target_url\":\"https://example.com/h\",\"secret_token\":\"\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\"}"
check "400" "CANONICAL_V1 with an empty secret_token is rejected"

# Case-insensitive mode parsing must not become a route around the precondition.
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"lowercase-mode\",\"target_url\":\"https://example.com/h\",\"secret_token\":\"\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"canonical_v1\"}"
check "400" "a lowercase canonical_v1 with an empty secret_token is rejected"

# ...nor may the deprecated alias reach a different validation path.
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"alias-mode\",\"target_url\":\"https://example.com/h\",\"secret_token\":\"\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"signature_mode\":\"CANONICAL_V1\"}"
check "400" "the deprecated signature_mode alias enforces the same secret precondition"

api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"no-key\",\"target_url\":\"https://example.com/h\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"API_KEY_ONLY\"}"
check "400" "API_KEY_ONLY without an api_key is rejected"

api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"bodyless-template\",\"target_url\":\"https://example.com/h\",\"secret_token\":\"s\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\",\"hmac_template\":\"{method}\\\\n{path}\\\\n{timestamp}\"}"
check "400" "an hmac_template that omits {body} is rejected"

api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"default-mode\",\"target_url\":\"https://example.com/h\",\"secret_token\":\"s\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\"}"
check "200" "omitting auth_mode is accepted"
check_true '.auth_mode == "CANONICAL_V1"' "an omitted auth_mode defaults to CANONICAL_V1"
DEFAULT_MODE_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

# The previous field name still selects a mode, so existing callers keep working.
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"alias-mode\",\"target_url\":\"https://example.com/h\",\"secret_token\":\"s\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"signature_mode\":\"BODY_ONLY\"}"
check "200" "the deprecated signature_mode alias is still accepted"
check_true '.auth_mode == "BODY_ONLY"' "the alias selects the same mode under the new name"
ALIAS_MODE_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call GET "/api/webhooks" "$MASTER_KEY"
check "200" "list webhooks"
check_true "[.[] | select(.id == \"$DEFAULT_MODE_WEBHOOK_ID\")] | length == 1" "the webhook appears in the listing"
check_true "[.[] | select(.id == \"$DEFAULT_MODE_WEBHOOK_ID\") | .auth_mode == \"CANONICAL_V1\"] | all" "the listing exposes auth_mode"
check_true "[.[] | select(.id == \"$DEFAULT_MODE_WEBHOOK_ID\") | .hmac_template == \"{method}\\\\n{path}\\\\n{timestamp}\\\\n{body}\"] | all" "the listing resolves hmac_template to the effective default"
check_true "[.[] | select(.id == \"$DEFAULT_MODE_WEBHOOK_ID\") | .has_api_key == false] | all" "the listing reports api_key presence, not its value"
check_true 'all(.[]; has("api_key") | not)' "no listed webhook ever exposes its api_key"

api_call DELETE "/api/webhooks/$ALIAS_MODE_WEBHOOK_ID" "$MASTER_KEY"
check "204" "delete the alias-mode webhook"

api_call DELETE "/api/webhooks/$DEFAULT_MODE_WEBHOOK_ID" "$MASTER_KEY"
check "204" "delete the default-mode webhook"

# Live CANONICAL_V1 dispatch verification needs the local receiver from §13.
if [ "${WEBHOOK_RECEIVER_AVAILABLE:-0}" -eq 1 ]; then
    CANON_SECRET="canonical-e2e-secret"
    : > "$RECEIVER_LOG"

    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"canonical-hook\",\"target_url\":\"http://127.0.0.1:$RECEIVER_PORT/canon\",\"secret_token\":\"$CANON_SECRET\",\"payload_template\":\"{\\\"ip\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\",\"events\":\"IP_ADD\"}"
    check "200" "create a CANONICAL_V1 webhook"
    check_true '.auth_mode == "CANONICAL_V1"' "creation echoes CANONICAL_V1"
    CANON_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/ban" "$MASTER_KEY" "{\"target_address\":\"198.51.100.222\",\"group_name\":\"SigMode-Group\",\"cause\":\"canonical dispatch\"}"
    check "200" "ban an address to trigger the canonical dispatch"

    # Dispatch is asynchronous; poll for the delivery line.
    for _ in $(seq 1 40); do
        [ -s "$RECEIVER_LOG" ] && break
        sleep 0.25
    done

    if [ -s "$RECEIVER_LOG" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the CANONICAL_V1 webhook was delivered" >&2

        HIT=$(head -n 1 "$RECEIVER_LOG")
        HOOK_SIG=$(echo "$HIT" | jq -r '.signature // empty')
        HOOK_TS=$(echo "$HIT" | jq -r '.timestamp // empty')
        HOOK_BODY=$(echo "$HIT" | jq -r '.body // empty')
        HOOK_PATH=$(echo "$HIT" | jq -r '.path // empty')
        log "Captured dispatch: path=$HOOK_PATH ts=$HOOK_TS sig=${HOOK_SIG:0:16}..."

        if [ -n "$HOOK_TS" ]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the dispatch carries an X-Timestamp header" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} CANONICAL_V1 dispatch is missing X-Timestamp" >&2
        fi

        # Recompute the signature exactly as the server should have: POST\npath\nts\nbody.
        EXPECTED_SIG=$(hmac_sign "$CANON_SECRET" "POST" "$HOOK_PATH" "$HOOK_TS" "$HOOK_BODY")
        if [ -n "$HOOK_SIG" ] && [ "$HOOK_SIG" == "$EXPECTED_SIG" ]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} X-Signature-256 matches HMAC(POST\\npath\\ntimestamp\\nbody)" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} canonical signature mismatch (got '$HOOK_SIG', expected '$EXPECTED_SIG')" >&2
        fi

        # Bare hex, unlike BODY_ONLY's `sha256=` prefix — identical to what the API itself emits.
        case "$HOOK_SIG" in
            sha256=*)
                FAIL_COUNT=$((FAIL_COUNT + 1))
                echo -e "$(ts)   ${RED}✗ FAIL${RESET} CANONICAL_V1 signature should be bare hex, not sha256=-prefixed" >&2
                ;;
            *)
                PASS_COUNT=$((PASS_COUNT + 1))
                echo -e "$(ts)   ${GREEN}✓ PASS${RESET} CANONICAL_V1 sends a bare hex signature" >&2
                ;;
        esac
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} CANONICAL_V1 webhook was never delivered" >&2
    fi

    api_call DELETE "/api/webhooks/$CANON_WEBHOOK_ID" "$MASTER_KEY"
    check "204" "delete the canonical webhook"

    # And the legacy mode, through the same receiver, must still be `sha256=`-prefixed with no
    # timestamp — the regression guard for third-party consumers.
    : > "$RECEIVER_LOG"
    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"legacy-hook\",\"target_url\":\"http://127.0.0.1:$RECEIVER_PORT/legacy\",\"secret_token\":\"$CANON_SECRET\",\"payload_template\":\"{\\\"ip\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"BODY_ONLY\",\"events\":\"IP_ADD\"}"
    check "200" "create a BODY_ONLY webhook on the same receiver"
    LEGACY_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/ban" "$MASTER_KEY" "{\"target_address\":\"198.51.100.223\",\"group_name\":\"SigMode-Group\"}"
    check "200" "ban an address to trigger the legacy dispatch"

    for _ in $(seq 1 40); do
        [ -s "$RECEIVER_LOG" ] && break
        sleep 0.25
    done

    if [ -s "$RECEIVER_LOG" ]; then
        HIT=$(head -n 1 "$RECEIVER_LOG")
        LEGACY_SIG=$(echo "$HIT" | jq -r '.signature // empty')
        LEGACY_TS=$(echo "$HIT" | jq -r '.timestamp // empty')
        LEGACY_BODY=$(echo "$HIT" | jq -r '.body // empty')
        LEGACY_EXPECTED="sha256=$(printf '%s' "$LEGACY_BODY" | openssl dgst -sha256 -hmac "$CANON_SECRET" | sed 's/^.*= //')"

        if [ -z "$LEGACY_TS" ]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} BODY_ONLY sends no X-Timestamp header" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} BODY_ONLY unexpectedly sent X-Timestamp: $LEGACY_TS" >&2
        fi

        if [ "$LEGACY_SIG" == "$LEGACY_EXPECTED" ]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} BODY_ONLY signature is sha256=HMAC(body) — unchanged legacy format" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} BODY_ONLY signature mismatch (got '$LEGACY_SIG', expected '$LEGACY_EXPECTED')" >&2
        fi
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} BODY_ONLY webhook was never delivered" >&2
    fi

    api_call DELETE "/api/webhooks/$LEGACY_WEBHOOK_ID" "$MASTER_KEY"
    check "204" "delete the legacy webhook"
else
    warn "Local webhook receiver unavailable — skipping live CANONICAL_V1/BODY_ONLY dispatch verification."
fi

# ── 23. Dynamic HMAC templates & key-based dispatch ─────────────────────────

log_section "23. Dynamic HMAC Templates, API_KEY_ONLY and NONE Dispatch"

if [ "${WEBHOOK_RECEIVER_AVAILABLE:-0}" -eq 1 ]; then
    TEMPLATE_SECRET="template-e2e-secret"
    DOWNSTREAM_KEY="downstream-e2e-key"
    # The simply_hook_executor shape: the vault POSTs to whatever URL the proxy exposes, while the
    # receiver behind it signs over the path IT sees. Hardcoding that path in the template is the
    # whole mechanism — no extra column, no proxy-awareness in the dispatcher.
    EXECUTOR_PATH="/api/hooks/42/execute"
    ESCAPED_TEMPLATE="{method}\\\\n$EXECUTOR_PATH\\\\n{timestamp}\\\\n{body}"
    : > "$RECEIVER_LOG"

    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"executor-hook\",\"target_url\":\"http://127.0.0.1:$RECEIVER_PORT/proxied/path\",\"secret_token\":\"$TEMPLATE_SECRET\",\"payload_template\":\"{\\\"ip\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\",\"api_key\":\"$DOWNSTREAM_KEY\",\"hmac_template\":\"$ESCAPED_TEMPLATE\",\"events\":\"IP_ADD\"}"
    check "200" "create a CANONICAL_V1 webhook with a hardcoded-path hmac_template"
    TEMPLATE_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/ban" "$MASTER_KEY" "{\"target_address\":\"198.51.100.224\",\"group_name\":\"SigMode-Group\",\"cause\":\"templated dispatch\"}"
    check "200" "ban an address to trigger the templated dispatch"

    for _ in $(seq 1 40); do
        [ -s "$RECEIVER_LOG" ] && break
        sleep 0.25
    done

    if [ -s "$RECEIVER_LOG" ]; then
        HIT=$(head -n 1 "$RECEIVER_LOG")
        T_SIG=$(echo "$HIT" | jq -r '.signature // empty')
        T_TS=$(echo "$HIT" | jq -r '.timestamp // empty')
        T_BODY=$(echo "$HIT" | jq -r '.body // empty')
        T_PATH=$(echo "$HIT" | jq -r '.path // empty')
        T_KEY=$(echo "$HIT" | jq -r '.api_key // empty')

        if [ "$T_PATH" == "/proxied/path" ]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the request is still sent to target_url's path" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} expected delivery to /proxied/path, got '$T_PATH'" >&2
        fi

        if [ "$T_KEY" == "$DOWNSTREAM_KEY" ]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} CANONICAL_V1 sends the configured api_key as X-API-Key" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} expected X-API-Key '$DOWNSTREAM_KEY', got '$T_KEY'" >&2
        fi

        # Signed over the template's hardcoded path...
        TEMPLATE_EXPECTED=$(hmac_sign "$TEMPLATE_SECRET" "POST" "$EXECUTOR_PATH" "$T_TS" "$T_BODY")
        if [ -n "$T_SIG" ] && [ "$T_SIG" == "$TEMPLATE_EXPECTED" ]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the signature covers the template's hardcoded path, not target_url's" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} templated signature mismatch (got '$T_SIG', expected '$TEMPLATE_EXPECTED')" >&2
        fi

        # ...and NOT over the URL-derived one, or the check above would pass for the wrong reason.
        URL_DERIVED=$(hmac_sign "$TEMPLATE_SECRET" "POST" "/proxied/path" "$T_TS" "$T_BODY")
        if [ "$T_SIG" != "$URL_DERIVED" ]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the URL-derived path does not produce a matching signature" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} the template's path did not override the URL-derived one" >&2
        fi
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} the templated webhook was never delivered" >&2
    fi

    api_call DELETE "/api/webhooks/$TEMPLATE_WEBHOOK_ID" "$MASTER_KEY"
    check "204" "delete the templated webhook"

    # The two unsigned modes, back to back through the same receiver.
    for MODE_SPEC in "API_KEY_ONLY:198.51.100.225:$DOWNSTREAM_KEY" "NONE:198.51.100.226:"; do
        MODE="${MODE_SPEC%%:*}"
        REST="${MODE_SPEC#*:}"
        MODE_ADDR="${REST%%:*}"
        EXPECT_KEY="${REST#*:}"
        : > "$RECEIVER_LOG"

        api_call POST "/api/webhooks" "$MASTER_KEY" \
            "{\"name\":\"${MODE}-hook\",\"target_url\":\"http://127.0.0.1:$RECEIVER_PORT/unsigned\",\"payload_template\":\"{\\\"ip\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"$MODE\",\"api_key\":\"$DOWNSTREAM_KEY\",\"events\":\"IP_ADD\"}"
        check "200" "create a $MODE webhook (no secret_token required)"
        UNSIGNED_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

        api_call POST "/api/ban" "$MASTER_KEY" "{\"target_address\":\"$MODE_ADDR\",\"group_name\":\"SigMode-Group\"}"
        check "200" "ban an address to trigger the $MODE dispatch"

        for _ in $(seq 1 40); do
            [ -s "$RECEIVER_LOG" ] && break
            sleep 0.25
        done

        if [ -s "$RECEIVER_LOG" ]; then
            HIT=$(head -n 1 "$RECEIVER_LOG")
            U_SIG=$(echo "$HIT" | jq -r '.signature // empty')
            U_TS=$(echo "$HIT" | jq -r '.timestamp // empty')
            U_KEY=$(echo "$HIT" | jq -r '.api_key // empty')
            U_BODY=$(echo "$HIT" | jq -r '.body // empty')

            if [ -z "$U_SIG" ] && [ -z "$U_TS" ]; then
                PASS_COUNT=$((PASS_COUNT + 1))
                echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $MODE sends neither X-Signature-256 nor X-Timestamp" >&2
            else
                FAIL_COUNT=$((FAIL_COUNT + 1))
                echo -e "$(ts)   ${RED}✗ FAIL${RESET} $MODE unexpectedly sent sig='$U_SIG' ts='$U_TS'" >&2
            fi

            if [ "$U_KEY" == "$EXPECT_KEY" ]; then
                PASS_COUNT=$((PASS_COUNT + 1))
                echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $MODE X-API-Key header is as expected ('$EXPECT_KEY')" >&2
            else
                FAIL_COUNT=$((FAIL_COUNT + 1))
                echo -e "$(ts)   ${RED}✗ FAIL${RESET} $MODE expected X-API-Key '$EXPECT_KEY', got '$U_KEY'" >&2
            fi

            case "$U_BODY" in
                *"$MODE_ADDR"*)
                    PASS_COUNT=$((PASS_COUNT + 1))
                    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $MODE still delivers the templated payload" >&2
                    ;;
                *)
                    FAIL_COUNT=$((FAIL_COUNT + 1))
                    echo -e "$(ts)   ${RED}✗ FAIL${RESET} $MODE payload did not contain $MODE_ADDR (got '$U_BODY')" >&2
                    ;;
            esac
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} the $MODE webhook was never delivered" >&2
        fi

        api_call DELETE "/api/webhooks/$UNSIGNED_WEBHOOK_ID" "$MASTER_KEY"
        check "204" "delete the $MODE webhook"
    done
else
    warn "Local webhook receiver unavailable — skipping live template/API_KEY_ONLY/NONE dispatch verification."
fi

# ── Summary ──────────────────────────────────────────────────────────────────

log_section "24. IP Soft Delete, Restore, Hard Delete & 92-Day Purge"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"softdelete-group"}'
check "200" "create a group for the soft-delete checks"
SOFTDEL_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

# A delegated key with full group rights but no master status — the one whose deletes must be soft.
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Soft Deleter"}'
check "200" "create a non-master deleter key"
SOFTDEL_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
SOFTDEL_KEY_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$SOFTDEL_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

api_call POST "/api/keys/$SOFTDEL_KEY_ID/permissions" "$MASTER_KEY" \
    "{\"group_id\":\"$SOFTDEL_GROUP_ID\",\"can_read\":true,\"can_write\":true,\"can_delete\":true}"
check "200" "grant the deleter full rights on the group"

api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.201","group_name":"softdelete-group","cause":"soft delete test"}'
check "200" "ban an address to soft-delete"

api_call GET "/api/ips?groups=softdelete-group" "$MASTER_KEY"
check "200" "list the group before deletion"
SOFTDEL_RECORD_ID=$(echo "$RESP_BODY" | jq -r '.[] | select(.target_address == "198.51.100.201") | .id')
log "Soft-delete target record id: $SOFTDEL_RECORD_ID"

# A non-master delete must be soft: hidden from reads, row retained.
api_call DELETE "/api/ips/$SOFTDEL_RECORD_ID" "$SOFTDEL_KEY"
check "200" "a non-master DELETE /api/ips/{id} succeeds"
check_true '.deleted == "soft"' "a non-master delete is soft, not permanent"

api_call GET "/api/ips?groups=softdelete-group" "$SOFTDEL_KEY"
check "200" "the deleter lists the group after deleting"
check_true '[.[] | select(.target_address == "198.51.100.201")] | length == 0' \
    "the soft-deleted record is hidden from the non-master listing"

api_call GET "/api/ips?groups=softdelete-group&format=iplist" "$SOFTDEL_KEY"
check "200" "the iplist export also runs after deletion"
check_true '[.ip_list[] | select(. == "198.51.100.201")] | length == 0' \
    "the soft-deleted record is excluded from the iplist export too"

# A non-master cannot escalate to a permanent delete.
api_call DELETE "/api/ips/$SOFTDEL_RECORD_ID?hard=true" "$SOFTDEL_KEY"
check "403" "a non-master cannot hard-delete a record"

# The master trash view sees it, with its attribution.
api_call GET "/api/ips?include_deleted=true&groups=softdelete-group" "$MASTER_KEY"
check "200" "master lists the trash with include_deleted=true"
check_true '[.[] | select(.target_address == "198.51.100.201" and .is_deleted == true)] | length == 1' \
    "the master trash view exposes the soft-deleted record"
check_true "[.[] | select(.target_address == \"198.51.100.201\") | .deleted_by == \"$SOFTDEL_KEY_ID\"] | all" \
    "deleted_by attributes the key that issued the delete"

# The master's DEFAULT listing still hides it — the trash is opt-in, not a master-only default view.
api_call GET "/api/ips?groups=softdelete-group" "$MASTER_KEY"
check "200" "master lists the group without include_deleted"
check_true '[.[] | select(.target_address == "198.51.100.201")] | length == 0' \
    "the trash stays hidden unless include_deleted is explicitly requested"

# Restore.
api_call POST "/api/ips/$SOFTDEL_RECORD_ID/restore" "$SOFTDEL_KEY"
check "403" "a non-master cannot restore a deleted record"

api_call POST "/api/ips/$SOFTDEL_RECORD_ID/restore" "$MASTER_KEY"
check "200" "master restores the soft-deleted record"
check_true '.restored == true' "the restore is reported"

api_call GET "/api/ips?groups=softdelete-group" "$SOFTDEL_KEY"
check "200" "list the group after restoration"
check_true '[.[] | select(.target_address == "198.51.100.201")] | length == 1' \
    "the restored record is visible again"

api_call POST "/api/ips/$SOFTDEL_RECORD_ID/restore" "$MASTER_KEY"
check "400" "restoring an already-live record is rejected"

# Re-banning a soft-deleted address must resurrect it rather than collide with the unique index.
api_call DELETE "/api/ips/$SOFTDEL_RECORD_ID" "$SOFTDEL_KEY"
check "200" "soft-delete the record again"
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.201","group_name":"softdelete-group","cause":"seen again"}'
check "200" "re-banning a soft-deleted address succeeds instead of colliding"
api_call GET "/api/ips?groups=softdelete-group" "$MASTER_KEY"
check_true '[.[] | select(.target_address == "198.51.100.201")] | length == 1' \
    "re-registration resurrected the record"

# Purge: master-only, and the window cannot be set to a destructive zero.
api_call POST "/api/system/purge-ips" "$SOFTDEL_KEY"
check "403" "a non-master cannot purge deleted records"

api_call POST "/api/system/purge-ips" "$MASTER_KEY" '{"older_than_days":0}'
check "400" "older_than_days=0 is rejected rather than treated as 'purge everything'"

api_call POST "/api/system/purge-ips" "$MASTER_KEY" '{"older_than_days":-5}'
check "400" "a negative older_than_days is rejected"

api_call POST "/api/system/purge-ips" "$MASTER_KEY"
check "200" "master runs the purge with the default window"
check_true '.retention_days == 92' "the default retention window is 92 days"
check_true '.purged == 0' "nothing is purged: the only deleted record is far younger than 92 days"

api_call GET "/api/ips?groups=softdelete-group" "$MASTER_KEY"
check_true '[.[] | select(.target_address == "198.51.100.201")] | length == 1' \
    "the live record survived the purge"

# Master hard delete really drops the row.
api_call DELETE "/api/ips/$SOFTDEL_RECORD_ID?hard=true" "$MASTER_KEY"
check "200" "master hard-deletes the record"
check_true '.deleted == "permanent"' "the hard delete is reported as permanent"

api_call GET "/api/ips?include_deleted=true&groups=softdelete-group" "$MASTER_KEY"
check_true '[.[] | select(.target_address == "198.51.100.201")] | length == 0' \
    "a hard-deleted record is gone even from the trash view"

# ── SQLite concurrency pragmas ──────────────────────────────────────────────
# Asserted from the startup log rather than by querying, because the pragma is applied once at
# connection setup and this is the only place its actual effect is reported.

log_section "24b. SQLite WAL Mode & Busy Timeout"

if grep -q "journal_mode=WAL enabled" "$SERVER_LOG"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} SQLite journal_mode=WAL is enabled at startup" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} SQLite WAL mode was not reported at startup" >&2
fi

if grep -q "busy_timeout set to 5000ms" "$SERVER_LOG"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} SQLite busy_timeout is set to 5000ms" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} SQLite busy_timeout was not reported at startup" >&2
fi

# WAL leaves a -wal sidecar next to the database file while connections are open.
if [ -f "$DB_PATH-wal" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the WAL sidecar file exists alongside the database" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} no -wal sidecar found at $DB_PATH-wal" >&2
fi

# The retention worker must have started with the 92-day window.
if grep -q "IP retention worker started" "$SERVER_LOG"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the IP retention worker started" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} the IP retention worker did not start" >&2
fi

log_section "25. RBAC Privilege Escalation & Webhook Hijacking"

# A delegated key manager: full can_manage_keys, but NOT master. Everything below asks whether that
# scope can be turned into master authority.
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Delegated Key Manager","can_manage_keys":true,"can_manage_webhooks":true}'
check "200" "create a non-master key manager"
MANAGER_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
MANAGER_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$MANAGER_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

# A master key for it to attack.
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Escalation Victim","is_master":true}'
check "200" "create a master key to serve as the escalation target"
VICTIM_ID=$(echo "$RESP_BODY" | jq -r '.id')

# 1. Minting a master key would return its plaintext in this very response.
api_call POST "/api/keys" "$MANAGER_KEY" '{"name":"Self-Promoted Master","is_master":true}'
check "403" "a non-master cannot mint a master key"

# 2. Rotating a master key hands back a working master credential outright.
api_call POST "/api/keys/$VICTIM_ID/rotate" "$MANAGER_KEY"
check "403" "a non-master cannot rotate a master key"

api_call POST "/api/keys/$VICTIM_ID/rotate-secret" "$MANAGER_KEY"
check "403" "a non-master cannot rotate a master key's signing secret"

# 3. Relocating a master key's network binding to the attacker's own range.
api_call PUT "/api/keys/$VICTIM_ID" "$MANAGER_KEY" '{"bound_ips":"203.0.113.0/24"}'
check "403" "a non-master cannot rewrite a master key's bound_ips"

# 4. Removing the master keys that would contain the incident.
api_call DELETE "/api/keys/$VICTIM_ID" "$MANAGER_KEY"
check "403" "a non-master cannot delete a master key"

# 5. Widening its own scopes through the generic update endpoint.
api_call PUT "/api/keys/$MANAGER_ID" "$MANAGER_KEY" '{"can_create_groups":true}'
check "403" "a key cannot grant itself additional scopes"

# The master-only scopes cannot be handed to ANY key by a non-master, not just to itself: each is a
# path back to master authority (co-administrators, or groups whose creator is auto-granted access).
api_call POST "/api/keys" "$MANAGER_KEY" '{"name":"Escalated Manager","can_manage_keys":true}'
check "403" "a non-master cannot grant can_manage_keys"

api_call POST "/api/keys" "$MANAGER_KEY" '{"name":"Escalated Groups","can_create_groups":true}'
check "403" "a non-master cannot grant can_create_groups"

# Controls: the delegated scope still works against non-master targets, so the guards are scoped to
# master escalation rather than having disabled key administration.
api_call POST "/api/keys" "$MANAGER_KEY" '{"name":"Ordinary Delegated Key"}'
check "200" "a non-master can still create ordinary keys"
ORDINARY_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/keys/$ORDINARY_ID/rotate" "$MANAGER_KEY"
check "200" "a non-master can still rotate a non-master key"

api_call DELETE "/api/keys/$ORDINARY_ID" "$MANAGER_KEY"
check "204" "a non-master can still delete a non-master key"

# Webhook hijacking: repointing a webhook must invalidate the secret it signs with, since
# secret_token is write-only and the attacker's route to it is to redirect a signed dispatch to a
# server they control.
api_call POST "/api/groups" "$MASTER_KEY" '{"name":"hijack-group"}'
check "200" "create a group for the webhook hijacking checks"
HIJACK_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"hijack-target\",\"target_url\":\"https://legitimate.example.com/hook\",\"secret_token\":\"original-e2e-secret\",\"payload_template\":\"{}\",\"group_id\":\"$HIJACK_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\"}"
check "200" "create a webhook to attempt to hijack"
HIJACK_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

# An unrelated edit must not churn the secret.
api_call PUT "/api/webhooks/$HIJACK_HOOK_ID" "$MASTER_KEY" '{"name":"hijack-target-renamed"}'
check "200" "renaming a webhook succeeds"
check_true '.secret_rotated == false' "a rename does not rotate the secret"

# Re-submitting the identical URL is not a repoint, so an idempotent save must not rotate either.
api_call PUT "/api/webhooks/$HIJACK_HOOK_ID" "$MASTER_KEY" '{"target_url":"https://legitimate.example.com/hook"}'
check "200" "re-submitting the same target_url succeeds"
check_true '.secret_rotated == false' "re-submitting the same URL is not a repoint"

# The attack: repoint at an attacker-controlled server.
api_call PUT "/api/webhooks/$HIJACK_HOOK_ID" "$MASTER_KEY" '{"target_url":"https://attacker.example.net/collect"}'
check "200" "repointing a webhook succeeds"
check_true '.secret_rotated == true' "repointing a webhook FORCES its secret_token to rotate"
check_true '.secret_token != null and (.secret_token | length) == 64' "the replacement secret is returned once, full width"
if echo "$RESP_BODY" | grep -q "original-e2e-secret"; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} the pre-rotation secret leaked in the update response" >&2
else
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the pre-rotation secret never appears in the response" >&2
fi

# Rewriting the template decides which bytes the signature covers, so it rotates too.
api_call PUT "/api/webhooks/$HIJACK_HOOK_ID" "$MASTER_KEY" '{"hmac_template":"{method}\\n{path}\\n{timestamp}\\n{body}\\nx"}'
check "200" "rewriting hmac_template succeeds"
check_true '.secret_rotated == true' "rewriting hmac_template also forces rotation"

# A template that never covers the body is refused on update as it is on create.
api_call PUT "/api/webhooks/$HIJACK_HOOK_ID" "$MASTER_KEY" '{"hmac_template":"{method}\\n{path}\\n{timestamp}"}'
check "400" "an hmac_template omitting {body} is rejected on update"

# A caller supplying its own replacement gets no generated value echoed back.
api_call PUT "/api/webhooks/$HIJACK_HOOK_ID" "$MASTER_KEY" '{"target_url":"https://elsewhere.example.com/h","secret_token":"caller-chosen-secret"}'
check "200" "repointing with a caller-supplied secret succeeds"
check_true '.secret_rotated == true' "a caller-supplied secret still counts as a rotation"
check_true '.secret_token == null' "a caller-supplied secret is not echoed back"

# No read endpoint ever discloses either secret.
api_call GET "/api/webhooks" "$MASTER_KEY"
check "200" "list webhooks after the rotations"
if echo "$RESP_BODY" | grep -qE "original-e2e-secret|caller-chosen-secret"; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} GET /api/webhooks leaked a secret_token" >&2
else
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} no secret_token is exposed by the webhook listing" >&2
fi

# A webhook that carries an api_key is *privileged*: its dispatches authenticate as a real caller on
# the receiving system (instance chaining), and that credential belongs to the remote system so
# rotation cannot invalidate it. Repointing one is therefore master-only.
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"privileged-hook\",\"target_url\":\"https://legitimate.example.com/hook\",\"secret_token\":\"s\",\"api_key\":\"downstream-credential\",\"payload_template\":\"{}\",\"group_id\":\"$HIJACK_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\"}"
check "200" "create a privileged webhook that carries an api_key"
PRIV_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Webhook Manager","can_manage_webhooks":true}'
check "200" "create a non-master webhook manager"
WHM_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
WHM_KEY_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$WHM_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

api_call POST "/api/keys/$WHM_KEY_ID/permissions" "$MASTER_KEY" \
    "{\"group_id\":\"$HIJACK_GROUP_ID\",\"can_read\":true,\"can_write\":true,\"can_delete\":true}"
check "200" "grant the webhook manager access to the hijack group"

api_call PUT "/api/webhooks/$PRIV_HOOK_ID" "$WHM_KEY" '{"target_url":"https://attacker.example.net/collect"}'
check "403" "a non-master cannot repoint a privileged (api_key-bearing) webhook"

api_call PUT "/api/webhooks/$PRIV_HOOK_ID" "$WHM_KEY" '{"hmac_template":"{method}\\n{path}\\n{timestamp}\\n{body}\\nx"}'
check "403" "a non-master cannot rewrite a privileged webhook's hmac_template"

# Non-critical fields stay editable by the delegated manager.
api_call PUT "/api/webhooks/$PRIV_HOOK_ID" "$WHM_KEY" '{"name":"privileged-hook-renamed"}'
check "200" "a non-master can still rename a privileged webhook"

# ...and a master may repoint it, which still forces the secret to rotate.
api_call PUT "/api/webhooks/$PRIV_HOOK_ID" "$MASTER_KEY" '{"target_url":"https://elsewhere.example.com/h"}'
check "200" "a master can repoint a privileged webhook"
check_true '.secret_rotated == true' "repointing a privileged webhook still rotates its secret"

api_call DELETE "/api/webhooks/$PRIV_HOOK_ID" "$MASTER_KEY"
check "204" "delete the privileged webhook"

api_call DELETE "/api/webhooks/$HIJACK_HOOK_ID" "$MASTER_KEY"
check "204" "delete the hijack-target webhook"

log_section "Summary"
echo -e "$(ts) ${GREEN}Passed: $PASS_COUNT${RESET}   ${RED}Failed: $FAIL_COUNT${RESET}" >&2

if [ "$FAIL_COUNT" -gt 0 ]; then
    err "E2E suite FAILED ($FAIL_COUNT failing check(s))."
    exit 1
fi

log "E2E suite PASSED — all $PASS_COUNT checks succeeded."
exit 0
