# AGENT NOTES

> This file is the living worklog for the `simply_ip_vault` (formerly `simply_firewall`)
> implementation & audit sweep.
> The version of this file found at the start of this session claimed the project was "fully
> up-to-date and completed... Ready to hand over to the user." A fresh line-by-line audit against
> `AGENT.MD` and `SCHEMA.MD` showed that claim was **not accurate** — the project did not even
> compile at the start of this session (see Finding 0 below), and several real gaps existed. This
> file replaces the previous notes with an honest, current record of what was found and fixed.

## 2026-07-26 — Audit Plan (written before any fix was applied)

### Confirmed via direct code inspection

0. **The crate did not compile.** `Cargo.toml` had been bumped to `rand = "0.10"` (uncommitted
   local diff) but `src/api.rs` still called `rand::rng().random()` using the old rand 0.9 API
   surface — rand 0.10 moved `.random()` onto a new `RngExt` trait. `cargo check` failed with
   `E0599`. This is the most important finding: nothing else in the codebase could be trusted
   until this was fixed.
1. `src/lib_tmp.rs` was dead code — not referenced by any `mod` declaration anywhere (verified via
   grep across `*.rs`, `*.toml`, `Dockerfile`, `*.yml`). It also targeted a stale schema
   (`can_view_ips`, `can_add_ips`, singular `group_id` on `api_key`) that predates the current M:N
   RBAC model. Safe to delete outright.
2. `src/middleware.rs` did not normalize IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) before
   checking them against `bound_ips` CIDRs, and did not consult `X-Real-IP` as AGENT.MD §1
   requires (only `X-Forwarded-For` was read, falling straight back to `ConnectInfo`).
3. `bootstrap_master_key` (`src/main.rs`) treated "any key exists" as "a master key exists" — if
   all master keys were ever deleted while sub-keys remained, no new master key would be
   generated and admins could be locked out. AGENT.MD §7 explicitly requires checking for the
   absence of a **master** key.
4. Non-test `.unwrap()`/`.expect()` calls found (violates AGENT.MD's zero-panic mandate):
   - `src/webhooks.rs` `.expect("Failed to build reqwest client")`
   - `src/api.rs` `.unwrap()` on a group lookup inside the `list_ips` HTTP handler
   - `src/main.rs` `shutdown_signal()` used `.expect()` twice for signal registration
5. `GET /api/v1/ips` did not support the `since=<timestamp>` parameter mandated by AGENT.MD §3,
   and applied `max_age` filtering *after* `LIMIT`/`OFFSET` at the application level instead of in
   the query — this could silently truncate a page (fewer results than `limit` even though more
   rows existed).
6. The dashboard's filter bar (`ip`, `group_name`, `cause`, `status` query params — see
   `static/app.js`'s `loadIps()`) sent filters the backend's `QueryFilters` struct didn't declare,
   so Axum's `Query` extractor silently dropped them. The IP/group/cause/status filters in the UI
   had never actually filtered anything server-side.
7. `list_api_keys` (`GET /api/v1/keys`) serialized the raw `api_key::Model`, which includes
   `key_hash` (the SHA-256 hash of the live secret key) — leaking hash material to the
   frontend/network unnecessarily. Not an immediately practical break (the underlying key is a
   256-bit random value, so the hash isn't brute-forceable), but a real "don't expose internal
   secrets over the API" violation worth fixing on a security audit.
8. `IpRecordResponse` didn't expose the associated group's `group_type`, so the frontend had no
   data at all to implement the banlist/whitelist conflict badge requested for this task.
9. `SCHEMA.MD`'s `ip_records` table was missing two columns that exist in the real
   entity/migration: `is_locked` and `updated_at`.
10. AGENT.MD's mandatory test coverage list requires webhook HMAC-signature-delivery tests and
    multi-group + temporal (`max_age`/`since`) query tests. Neither existed in
    `tests/rbac_integration_tests.rs`.
11. `#![allow(missing_docs)]` blanketed `src/entities/mod.rs` and `src/migration/mod.rs`, and
    there was not a single `///` doc comment anywhere under either tree.
12. `.badge-group` was used in `app.js` (group-name pill) but never defined in `style.css` —
    rendered with no background/border, just inherited text styling.
13. The IP table's "status" column always rendered the literal text "Active" regardless of
    ban/whitelist state (colored only by whether a `cause` was present) — the `.badge-ban`/
    `.badge-white` CSS classes existed in `style.css` but were never referenced by `app.js`.

### Already done correctly (verified, not re-done)

- `Cargo.toml`: `edition = "2024"` already set.
- Audit logging was already wired for all six mandated actions (`IP_ADD`, `IP_DELETE`,
  `KEY_CREATE`, `KEY_DELETE`, `GROUP_CREATE`, `WEBHOOK_CREATE`) plus extra coverage
  (`GROUP_DELETE`, `WEBHOOK_DELETE`, `KEY_PERM_UPDATE`).
- Webhook HMAC `X-Signature-256` signing and SSRF protection (private/loopback/link-local
  rejection unless `ALLOW_PRIVATE_WEBHOOKS=true`) were both already implemented in
  `src/webhooks.rs`.
- M:N RBAC (`ApiKeyGroupPermission`), auto-provisioning of permissions on group creation, and
  least-privilege checks were implemented and covered by existing tests.
- SeaORM's `DeriveEntityModel`-generated types (`Entity`, `Column`, `PrimaryKey`, `ActiveModel`)
  turned out **not** to trigger `missing_docs` at all — the blanket allows were only masking the
  genuinely undocumented `Model`/`Relation` items, confirmed empirically (see Fix #6 below).

---

## Fixes Applied

### 1. `Cargo.toml`
No changes needed beyond what was already present (`edition = "2024"`, `rand = "0.10"`
uncommitted diff kept as-is) — see Finding 0 for why that version bump alone wasn't sufficient.

### 2. Deleted `src/lib_tmp.rs`
Confirmed unreferenced anywhere, deleted outright.

### 3. `src/middleware.rs`
- Added `normalize_ip()`: converts IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`, via
  `Ipv6Addr::to_ipv4_mapped()`) to plain IPv4 before the CIDR containment check, so a client
  behind a dual-stack proxy no longer gets a false `403 Forbidden` against an IPv4 `bound_ips`
  entry.
- Added `X-Real-IP` as a fallback source (after `X-Forwarded-For`, before `ConnectInfo`), matching
  AGENT.MD §1's "Resilient IP Extraction" directive literally.

### 4. `src/main.rs`
- `bootstrap_master_key` now filters specifically on `api_key::Column::IsMaster.eq(true)` instead
  of "any key exists", per AGENT.MD §7.
- `shutdown_signal()` no longer uses `.expect()`. If Ctrl+C or SIGTERM registration itself fails,
  that branch is left pending forever (instead of firing immediately) so a broken signal handler
  can't be misread as "shutdown requested now".

### 5. `src/webhooks.rs`
- `Client::builder()...build()` no longer `.expect()`s; on failure it logs an error and the worker
  simply doesn't start (the HTTP server still runs).
- Removed a stale/contradictory comment ("Safe: ... is infallible") sitting above code that
  already treats the same call as fallible via `match`.
- Collapsed a nested `if let` into a single let-chain (clippy `collapsible_if`).

### 6. `src/entities/*.rs`, `src/entities/mod.rs`, `src/entities/prelude.rs`, `src/migration/mod.rs`
Removed both blanket `#![allow(missing_docs)]` attributes and added real `///` doc comments to
every `Model` struct/field and `Relation` enum/variant, sourced from `SCHEMA.MD`'s field
descriptions. Verified empirically with `cargo check` that SeaORM's macro-generated `Entity`/
`Column`/`PrimaryKey`/`ActiveModel` items do **not** trigger `missing_docs` — the allow was only
ever needed because the hand-written `Model`/`Relation` items were undocumented, not because of
anything macro-generated. Result: zero `missing_docs` warnings with no allow-suppression at all.

### 7. `src/api.rs`
- Fixed the rand 0.10 break: `use rand::Rng` → `use rand::RngExt` (see Finding 0).
- `list_ips`:
  - Removed the `.unwrap()` on the per-row group lookup; a membership row whose group vanished
    (shouldn't happen given `ON DELETE CASCADE`, but shouldn't panic either) is now skipped via
    `let-else` instead of panicking the request.
  - Added `since` (Unix timestamp) support alongside `max_age`, per AGENT.MD §3.
  - Moved `max_age`/`since` temporal filtering into the SQL query (`ip_record::Column::LastSeenAt
    .gte(threshold)`) instead of filtering an already-paginated page in memory — fixes silent
    under-fetching where a page could return fewer than `limit` rows despite more matching data
    existing.
  - Added `group_name` (singular), `ip` (substring), `cause` (substring), and `status`
    (`ban`/`banlist` or `white`/`whitelist`) filters so the query params the dashboard has always
    sent (`static/app.js`'s `loadIps()`) actually do something server-side.
  - Added `group_type` to `IpRecordResponse` so the frontend can tell whether a given row came
    from a banlist or whitelist group — required for the conflict-highlighting feature.
- `list_api_keys` / new `ApiKeySummary` DTO: no longer serializes `api_key::Model` directly (which
  leaked `key_hash`). Returns `id`, `name`, `prefix`, `bound_ips`, the four global scopes,
  `created_at`, and a `group_permissions: Vec<MePermission>` (per-group read/write/delete, reusing
  the same shape `GET /auth/me` already returns) so the admin UI can show what a key can actually
  do.

### 8. `SCHEMA.MD` / `AGENT.MD`
- `SCHEMA.MD`: added the previously-undocumented `is_locked` and `updated_at` columns to the
  `ip_records` table, and marked `target_address` as `Unique` (matches the actual entity/migration
  and the "re-registering updates `last_seen_at`" upsert behavior). Broadened the `audit_logs.action`
  description to acknowledge the extra action types actually in use (`GROUP_DELETE`,
  `WEBHOOK_DELETE`, `KEY_PERM_UPDATE`).
- `AGENT.MD`: documented the newly-implemented `since`, `ip`, `cause`, `status`, and singular
  `group_name` query parameters for `GET /api/v1/ips`, and the per-row `group_type` field.

### 9. Frontend (`static/`)
- **`style.css`**:
  - `.filters` is now a `display: flex; flex-wrap: wrap; gap: 0.5rem;` container (was
    `flex-shrink: 0` with 100%-width children, which forced them to stack to full intrinsic width
    and overflow the panel to the right); `.list-header` also wraps now.
  - Added a `max-width: 640px` media-query rule making filter inputs full-width/stacked on small
    screens.
  - Added `.badge-group` (previously used in markup but never styled), `.badge-conflict` (uses the
    existing-but-previously-unused `--warning` color token), `.scope-badges`, `.badge-scope`, and
    `.badge-scope-master`.
- **`static/index.html`**: added a `Global Permissions / Scopes` column to the API Keys table
  (Administration tab); updated the empty-state `colspan` from 3 to 4 to match.
- **`static/app.js`**:
  - `renderIpTable()` now renders a real ban/whitelist status badge from `ip.group_type` (previously
    always displayed the literal text "Active"), and calls a new `findConflictingAddresses()` helper
    that groups the currently-loaded rows by `target_address` and flags any address that appears
    with both `banlist` and `whitelist` group types — those rows get a `⚠ Conflict` warning badge.
    (This is computed over the currently loaded/paginated `this.state.ips`, the same scope the
    filter bar itself operates over; there is no new backend aggregate endpoint, matching the "in
    the Vanilla JS dashboard" framing of the task.)
  - `renderKeysTable()` / new `renderKeyScopes()` render pills for the four global scopes (Master,
    Manage Keys, Manage Webhooks, Create Groups) plus one pill per group permission
    (`groupName: RWD`-style rights string), reading the `group_permissions` array now returned by
    the corrected `GET /api/v1/keys`.

### 10. Tests (`tests/rbac_integration_tests.rs`)
- Added `test_multi_group_and_temporal_filtering`: creates a fresh record via the real `/api/ban`
  endpoint and a 2-hour-stale record inserted directly, then asserts `groups=`, `max_age=`, and
  `since=` all correctly include the fresh record and exclude the stale one.
- Added `test_webhook_hmac_signature_and_delivery`: spins up a real mock HTTP endpoint (a second,
  tiny axum server on an OS-assigned loopback port), registers a webhook pointing at it (with
  `ALLOW_PRIVATE_WEBHOOKS=true` for the duration of the test, since the mock is on loopback), fires
  a real `/api/ban`, and asserts the delivered body and `X-Signature-256` header match an
  independently-computed HMAC-SHA256 over the actual delivered payload.
- Fixed 6 pre-existing `clippy` warnings surfaced along the way in this same file
  (`assert_eq!(x, true/false)` → `assert!`/`assert!(!...)`, one needless `&format!(...)` borrow).

---

## Final Verification

### `cargo check --all-targets`
```
Checking simply_firewall v0.1.0 (...)
Finished `dev` profile [unoptimized + debuginfo] target(s) in 17.94s
```
Zero warnings.

### `cargo test --all-targets`
```
running 6 tests
test test_auth_and_cidr_rejection ... ok
test test_auto_provisioning_on_group_creation ... ok
test test_explicit_key_group_manipulation ... ok
test test_tenant_isolation_mn_rbac ... ok
test test_multi_group_and_temporal_filtering ... ok
test test_webhook_hmac_signature_and_delivery ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### `cargo clippy --all-targets --all-features -- -D warnings`
```
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.14s
```
Zero warnings, including with warnings promoted to errors.

### `grep -rn -E "\.unwrap\(\)|\.expect\(" src/`
No matches. Zero panics possible from `src/` (non-test) code paths.

### Manual / runtime verification
Started the real server (`cargo run`, scratch SQLite DB) and drove it end-to-end with `curl`:
- Boot log showed migrations applying and a bootstrap master key being printed once.
- `GET /api/auth/me` returned the expected RBAC payload.
- `POST /api/ban` + `POST /api/white` for the **same address** into a banlist group and a
  whitelist group, then `GET /api/ips`, confirmed each row now carries the correct `group_type`
  and that a single address can legitimately appear as both — exactly the data shape the new
  conflict-badge logic in `app.js` consumes.
- `POST /api/keys` to create a scoped sub-key, then `GET /api/keys`, confirmed the response no
  longer contains `key_hash` and does contain `group_permissions`.
- Fetched `/app.js`, `/style.css`, `/index.html` from the running server directly and confirmed
  they contain the new functions/classes/column (rules out any stale-file surprise).

**Browser/screenshot verification was attempted but not achievable in this environment**: headless
Chromium (`/usr/bin/chromium`) crashes with `SIGTRAP` in this sandbox on essentially every
invocation shape tried (`--headless=new`, legacy `--headless` with `--remote-debugging-port`,
`--screenshot`, `--dump-dom` with `--virtual-time-budget`), including a plain `--dump-dom
about:blank` that succeeded exactly once and then reliably crashed on every subsequent retry with
identical flags — and `~/.config/chromium/Crash Reports` predates this session, indicating the
browser has never run reliably in this container. `dangerouslyDisableSandbox` on the launching
Bash command did not change the outcome, which points at a kernel/container-level restriction
rather than anything fixable from here. No Node/npm/Playwright/Selenium/pip were available either
(no package manager could reach a working state — `python3` has no `pip`/`ensurepip` module), so
no other browser-automation path existed. As a substitute, the exact JS logic added
(`findConflictingAddresses`, `renderKeyScopes`) was hand-traced against the real, curl-captured
API response shapes above and confirmed to produce the intended output (only the shared `5.5.5.5`
address's two rows get flagged; the master key renders 4 scope badges, the scoped sub-key renders
1 scope badge + 1 group-permission badge). This is a real gap relative to "use the feature in a
browser" — flagging it rather than claiming a visual check that didn't happen.

---

## Production Readiness Summary

- **Compiles cleanly, zero warnings**: `cargo check`/`cargo build` clean; the crate did not
  compile at session start (rand 0.10 API break) — that is now fixed.
- **Tests**: 6/6 integration tests pass, including two new ones closing previously-unmet mandatory
  coverage requirements (webhook HMAC delivery, multi-group + temporal filtering).
- **Lints**: `cargo clippy --all-targets --all-features -- -D warnings` is clean.
- **Panics**: zero `.unwrap()`/`.expect()` in `src/` (non-test) code, verified by grep.
- **Docs**: `#![warn(missing_docs)]` remains enforced in `lib.rs`; every public module, struct,
  enum, field, and handler across `src/` has a real `///`/`//!` doc comment (no blanket
  suppressions left anywhere).
- **Security**: IPv4-mapped-IPv6 CIDR bypass fixed, master-key-lockout bootstrap bug fixed,
  `key_hash` no longer leaves the server over the API, webhook HMAC signing + SSRF protection
  confirmed working end-to-end against a real mock endpoint in a test.
- **Known, accepted scope limits** (not bugs, documented choices made during this sweep):
  - `ip_records.is_locked` has no API path to set it to `true` — it's a data-layer safeguard with
    no corresponding "lock this record" endpoint. Nothing in AGENT.MD asks for one; flagged in
    case a future task wants it.
  - `SCHEMA.MD`'s "SeaORM Enums & Custom Types" section describes a `GroupType` enum, but
    `ip_group.group_type` is a plain validated `String` ("banlist"/"whitelist") throughout the
    codebase, not a `DeriveActiveEnum`. Every write path already only ever writes one of the two
    valid values, so there's no live bug — this is a type-safety nice-to-have, not a correctness
    issue, and was left as-is rather than risking a wide, mechanical refactor across
    entities/migration/API/frontend serialization for a cosmetic gain.
  - The Vanilla-JS conflict badge is computed over the currently loaded/paginated rows in the
    dashboard, not a global server-side aggregate — matches the "in the Vanilla JS dashboard"
    framing of the task; a global-across-all-pages version would need a new backend endpoint,
    which wasn't requested.
  - Full pixel/visual browser verification of the UI could not be performed — see the Manual
    Verification section above for exactly what was and wasn't checked, and why.

Everything explicitly listed in `<known_gaps_to_fix>` and `<tasks>` has been addressed, plus the
critical rand-0.10 compile break and several additional correctness/security findings surfaced by
the full-codebase audit (listed above). The project is in a materially better, honestly-verified
state than the pre-session notes claimed.

---

## 2026-07-26 (session 2) — Live exploratory testing: "test the app and find the errors"

Static analysis (`cargo check`/`test`/`clippy`) had already been clean, but static analysis can't
catch every runtime defect — SeaORM's `on_conflict` behavior in particular is a well-known footgun
that no lint catches. This session actually ran the compiled server against a scratch SQLite DB
and drove it with real HTTP requests (auth, IPv4/IPv6/CIDR ban+whitelist validation boundaries,
every new query filter, RBAC permission boundaries, cascade deletes, webhook SSRF blocking and
delivery, malformed input, and a simulated "all master keys deleted" disaster-recovery scenario)
to find defects that only show up when the code actually runs. Full request/response transcript
lives in `/tmp/.../scratchpad/testrun/` (probe script + server logs) for this session; not
committed, as it's throwaway test tooling, not project source.

### Bug found: re-banning/re-whitelisting an IP already in the target group returned `500`

**This is the most severe defect found across both sessions.** `handle_ip_upsert` in `src/api.rs`
inserts the `ip_record_group_memberships` row with:
```rust
ip_record_group_membership::Entity::insert(mem)
    .on_conflict(OnConflict::columns([...]).do_nothing().to_owned())
    .exec(&state.db)   // <-- bug: must be exec_without_returning
    .await?;
```
When the membership already exists (i.e. re-banning/re-whitelisting an address into a group it's
*already* in — the single most common real-world firewall operation, e.g. fail2ban repeatedly
reporting the same offender to the same jail), SQLite's `ON CONFLICT ... DO NOTHING` correctly
performs zero inserts. But SeaORM's `Insert::exec()` tries to read back the inserted row's data via
`RETURNING` to build its `InsertResult`, and when nothing was inserted it raises
`DbErr::RecordNotInserted` ("None of the records are inserted") instead of treating the no-op as
success. That `DbErr` propagates through `AppError::DbError` straight to a `500 Internal Server
Error`, directly violating AGENT.MD §3's explicit mandate: *"Re-registering an existing IP updates
`last_seen_at` rather than failing."* Confirmed via live `curl` reproduction and the exact SQL/error
trace in the debug log (`rows_affected=0 rows_returned=0` → `ERROR ... None of the records are
inserted`). **Fix:** changed `.exec(&state.db)` to `.exec_without_returning(&state.db)` for this
specific insert (`src/api.rs`) — that variant returns rows-affected instead of requiring a returned
row, so a conflict-caused no-op is correctly treated as success. Verified live (re-ban now returns
`200`) and locked in with a new regression test, `test_reban_into_same_group_does_not_500`.
Cross-checked the *other* `on_conflict` usage in the file (`update_key_group_permissions`, which
uses `.update_columns(...)` instead of `.do_nothing()`) — that one always has a row to return
either way, so `.exec()` there is correct as-is; confirmed live by granting permissions on the same
(key, group) pair twice and checking the second grant's values actually stuck.

### Gap found: `POST /api/webhooks` accepted a malformed `target_url` with no feedback

Creating a webhook with `target_url: "not a url"` (or any non-http(s) scheme) returned `200` and
stored it; the only place the URL is ever validated was `is_url_safe()` at *dispatch* time, which
would just log a `WARN` and silently drop every delivery attempt forever — the caller who
misconfigured it would never find out except by noticing events never arrive. **Fix:** `create_webhook`
now parses `target_url` with `reqwest::Url::parse` and rejects (400) anything that doesn't parse or
isn't `http`/`https`, before it's ever stored. Added `test_create_webhook_rejects_invalid_url`.

### Verified correct (no changes needed), via live testing

- IPv4-mapped IPv6 normalization: a key bound to `203.0.113.5/32` was correctly let through with
  `X-Forwarded-For: ::ffff:203.0.113.5` and correctly rejected for a mismatched address; `X-Real-IP`
  fallback also confirmed.
- Ban validation boundaries: loopback/private/link-local IPv4 and IPv6 (including unique-local
  `fc00::/7`) all correctly rejected with `400`; the same addresses are correctly *allowed* via
  `/white`.
- `since`/`max_age`/`status`/`cause`/`ip`/`group_name` filters all behave correctly for realistic
  inputs. (An initial test using an absurd 13-digit `since` value — ~317,000 years out — got a
  `400`; that's `chrono`'s date range being correctly rejected, not a bug, and was a test-authoring
  mistake, not an app defect.)
- RBAC boundaries: a key with no grant on an existing group gets `403`; granting `can_read` only
  still blocks write/delete with `403`; a non-admin key can't delete API keys; master can't delete
  itself.
- Cascade deletes: deleting a group correctly cascades its memberships (`ip_records` rows survive,
  memberships in that group vanish) and a key whose *only* grant was on the deleted group correctly
  loses access.
- `GET /api/keys` never contains `key_hash`, confirmed live across multiple keys.
- Webhook SSRF protection: a webhook pointed at `127.0.0.1` was accepted at creation time (correct —
  validation is a dispatch-time concern per AGENT.MD) but the actual dispatch was blocked and logged
  (`WARN ... Webhook blocked by SSRF protection`), and the local listener never received the request.
- Master-key-lockout fix (from session 1): directly deleted every `is_master=1` row from a live DB
  (leaving 4 ordinary sub-keys) and restarted the real binary — it correctly detected the absence of
  a master key and bootstrapped a fresh one, while leaving the sub-keys untouched.
- Audit log: inspected the raw SQLite table after a long mixed session (bans, deletes, key/group/
  webhook CRUD, permission grants) — every mutating action produced the expected row.
- Malformed/incomplete JSON bodies: syntax errors → `400`, missing required fields → `422`. This is
  Axum's own default `JsonRejection` behavior (`JsonSyntaxError` vs `JsonDataError`), not an app bug
  — confirmed both cases behave differently as designed, so nothing to fix.

### Final verification (session 2)

- `cargo check --all-targets`: clean.
- `cargo test --all-targets`: **8/8 pass** (6 from session 1 + 2 new regression tests this session:
  `test_reban_into_same_group_does_not_500`, `test_create_webhook_rejects_invalid_url`).
- `cargo clippy --all-targets --all-features -- -D warnings`: clean.
- `grep -rn -E "\.unwrap\(\)|\.expect\(" src/`: no matches.
- All live-server manual findings above re-verified against the rebuilt binary after the fixes.

### Updated production-readiness note

The rand-0.10 fix and full audit from session 1 were necessary but not sufficient — they made the
code *compile and pass static analysis*, but the re-ban 500 could only be found by actually running
the server and exercising its most basic, most common operation twice in a row. Static checks
(`check`/`test`/`clippy`) passing is not the same as the app working; this session's fixes close
that gap for the specific paths exercised above. Recommend that any future change touching
`on_conflict(...)` double-check whether `.do_nothing()` is used and, if so, use
`exec_without_returning` — this is a recurring SeaORM pitfall, not a one-off typo.

---

## 2026-07-26 (session 3) — README, doc-path fix, expanded RBAC/key-lifecycle tests, commit

### Found: working tree was already committed (and pushed) under a WIP message

At the start of this session `git status`/`git diff` were both empty — `git log` showed a new top
commit, `c4c0bd6 "Try to debug"`, containing the entirety of sessions 1 and 2's changes (confirmed
via `git show --stat`, which matches the file list from both prior worklog entries). `git branch -vv`
showed `master` exactly matching `origin/master` — **that commit is already pushed**. This turn's
task asked for "a clean, structured commit" with a specific message; since the existing commit is
already on the shared remote, amending/rewriting it would require a force-push, which is out of
scope for a task that didn't ask for one. Instead, this session's new work (below) is committed
fresh on top, using the requested message/title for that new commit — see the end of this entry.

### Found & fixed: `AGENT.MD` documented `/api/v1/*`, but the router mounts at `/api`

This session's task (and `AGENT.MD` itself, in half a dozen places) referred to the API living
under `/api/v1/*`. The actual router (`src/lib.rs`) does `.nest("/api", api_routes)` — there has
never been a `/v1` segment. Also found in the same block: the `AGENT.MD` "Add multiples IP" `curl`
example posted to `/api/v1/ips`, which isn't a route at all (no handler is registered for `POST
/ips`; adding an IP is `POST /ban` or `POST /white`). Given:
- three independent sources (`AGENT.MD`, this task's own text, and the original curl examples)
  all assumed `/api/v1`, but
- actually adding a real `/v1` prefix would be an invasive, wide-reaching change (touching the
  router, `static/app.js`'s `apiBase`, and every path string across the whole test suite) that
  wasn't asked for and risks regressions right before a "final sanity check",

the fix applied was to correct the **documentation** to match the actual, tested, working paths
(`/api/...`), and fix the broken example to use `POST /api/ban` instead of a non-existent `POST
/api/ips`. Flagging here explicitly in case the intent really was to add versioning to the live
API — that's a bigger, separate decision this session did not make unilaterally.

### `README.md`

Was previously just a two-line stub (title + tagline, no setup/usage/API docs at all). Rewritten
to cover: prerequisites, `cargo run`, exactly what happens on first boot (migrations, the
master-key bootstrap banner and that it's a one-time, unrecoverable reveal — including that
deleting all master keys causes a fresh one to be generated on next boot, matching the fix from
session 1), the environment variable table (`DATABASE_URL`, `BOOTSTRAP_SUBNET`,
`ALLOW_PRIVATE_WEBHOOKS`, `RUST_LOG` — cross-checked against actual `std::env::var(...)` call sites
in `src/main.rs`/`src/webhooks.rs`, not assumed), Docker usage, a full route table with the real
`/api` paths and `GET /api/ips` query parameters, worked `curl` examples, and a development section
(`cargo check --all-targets`, `cargo test`, `cargo clippy`).

### `tests/rbac_integration_tests.rs` — three new tests (API key lifecycle & RBAC)

Added a small `insert_key(...)` test helper (name + all four boolean flags → `(Uuid, plaintext)`)
to cut down on the boilerplate the existing tests all repeated by hand, and three new
`#[tokio::test]`s:

- **`test_key_creation_lifecycle`**: a master key creates a new key via `POST /api/keys` with
  `bound_ips` and specific global flags (`can_manage_keys`, `can_manage_webhooks`); asserts the
  create response *and* the row actually persisted in the DB match what was requested (not just an
  echo of the input), and that a non-privileged key gets `403` attempting the same call.
- **`test_group_permission_assignment_boundaries`**: `Key_B` with zero global rights is granted
  `can_read=true, can_write=false` on `Group_X` via `POST /api/keys/{id}/groups`; asserts it can
  read (`200`, correct data) but not write (`403`); the grant is then upgraded to `can_write=true`
  and the same write that was just forbidden now succeeds (`200`) — proves permission changes take
  effect immediately, no caching.
- **`test_key_deletion_revokes_access_and_cascades_permissions`**: after confirming `Key_B` works,
  master deletes it via `DELETE /api/keys/{id}`; asserts every subsequent request using that key's
  header gets `401` immediately (not just that it's absent from `GET /api/keys`), and queries
  `api_key_group_permissions` directly to confirm the `ON DELETE CASCADE` FK left zero orphaned
  rows for the deleted key.

Needed to add `ColumnTrait`/`QueryFilter` to the file's `sea_orm` import (the two new DB assertions
needed `.filter(...)`, which the file hadn't required before).

### Final verification (session 3)

- `cargo check --tests`: clean.
- `cargo test --all-targets`: **11/11 pass** (8 carried over from sessions 1–2 + 3 new this
  session).
- `cargo clippy --all-targets --all-features -- -D warnings`: clean.
- `grep -rn -E "\.unwrap\(\)|\.expect\(" src/`: no matches.

### Git

Reviewed `git status`/`git diff` for this session's changes (`AGENT.MD`, `README.md`,
`AGENT_NOTES.MD`, `tests/rbac_integration_tests.rs`) before staging — nothing unexpected, no
secrets, no unrelated files. Committed with:

```
feat: upgrade to Rust 2024, fix SeaORM re-ban conflict bug, harden webhooks and improve UI
```

as the title (as requested), with a body listing this commit's actual contents (README, doc-path
fix, new tests) plus a note that it builds on the already-pushed `c4c0bd6` for the bulk of the
Rust-2024/bug-fix/UI work the title refers to — kept the title the user asked for while keeping the
body honest about which changes are actually in this diff. Not pushed — no push was requested.

---

## 2026-07-26 (session 4) — Concurrency tests uncover two more real races; module cleanup verified

### Tasks 1 & 2 (rand fix, dead code) — already satisfied, re-verified

`use rand::RngExt;` / `rand::rng().random()` in `src/api.rs` and the `Cargo.toml` `rand = "0.10"`
bump were both already done (session 1). Re-ran a full repo file listing plus a check that every
file under `static/` is actually referenced from `index.html` — no dead files, no orphans,
`src/lib_tmp.rs` (deleted session 1) has not reappeared. `cargo check --all-targets` is clean.

### Task 3 — four new tests added, two of them found real, previously-unknown production bugs

Added to `tests/rbac_integration_tests.rs`:

- `test_concurrent_burst_ban_requests` — 10 concurrent `tokio::spawn` tasks POST the same
  address+group. **This test failed on first run: 9 of 10 requests got `500`, not `200`.**
- `test_reverse_proxy_xff_extracts_rightmost_trusted_hop` — asserts a key bound to the *rightmost*
  `X-Forwarded-For` hop is let through, and a key bound to the *leftmost* (client-forgeable) claim
  in the same header is rejected. Passed immediately — this is exactly what session 1's middleware
  fix already implements (`.split(',').next_back()`), just not previously exercised by an explicit
  security-focused test.
- `test_cidr_and_ipv6_boundary_validation` — `256.0.0.1/32`, `10.0.0.1/35`, and free-form garbage
  all correctly `400`; `2001:db8::/32` correctly parses and is accepted. Passed immediately;
  verified by hand-checking the IPv6 private/link-local bitmask logic in `handle_ip_upsert` against
  `2001:db8::`'s first segment (`0x2001`) before trusting the assertion.
- `test_webhook_dispatch_does_not_block_api_response` — registers a webhook pointing at a mock
  endpoint that sleeps 3 seconds before responding, then asserts `POST /api/ban` still returns
  `200` in under 50ms. Passed immediately: `handle_ip_upsert` only ever does
  `state.webhook_tx.send(event).await` (a bounded mpsc channel, capacity 100, never full in this
  test) — the slow HTTP dispatch happens later, in the separate `run_webhook_worker` task.

Needed a `static ENV_MUTATION_LOCK: LazyLock<tokio::sync::Mutex<()>>` shared between this new test
and the existing `test_webhook_hmac_signature_and_delivery` (session 2): both mutate the
process-wide `ALLOW_PRIVATE_WEBHOOKS` env var, which is `unsafe` in this Rust version specifically
because concurrent `set_var`/`var` calls from different threads race — and libtest runs different
`#[tokio::test]`s on different threads by default. Both tests now hold this lock for the full
duration they depend on that env var, so they can never interleave.

Before writing the concurrency test, checked whether SeaORM's SQLite driver would even make "10
truly concurrent connections to `sqlite::memory:`" mean anything sane: by default, sqlx pools up to
10 connections, and *without* `cache=shared` in the DSN, each connection to `:memory:` is a fully
separate, isolated database. Checked the vendored source
(`sea-orm-2.0.0/src/driver/sqlx_sqlite.rs:91-92`) and confirmed SeaORM's SQLite driver
unconditionally forces `max_connections(1)` whenever the caller hasn't set one explicitly — so
`Database::connect("sqlite::memory:")` (used by every test's `setup_test_db()`) was already safe
for this without any changes.

### Bug #1 (found by `test_concurrent_burst_ban_requests`): `ip_groups.name` auto-creation race

`handle_ip_upsert` and `update_key_group_permissions` both do `find group by name` → if `None`,
`insert` a new group. Two concurrent requests for a group name neither has seen yet both take the
`insert` branch; `ip_groups.name` is unique, so the loser gets a raw `UNIQUE constraint failed`
`DbErr` → `500`. Fixed by adding `get_or_create_group(db, name, default_type)` (new helper in
`src/api.rs`'s Helpers section): the insert uses `.on_conflict(OnConflict::column(Name)
.do_nothing()).exec_without_returning(...)`, then always re-reads the row by name afterwards —
whichever request's insert actually won, everyone converges on the same canonical row instead of
erroring. Replaced both call sites. Also made the *auto-provisioned permission grant* insert in
`handle_ip_upsert`'s new-group branch conflict-safe the same way (`on_conflict(...).do_nothing()
.exec_without_returning(...)` on the `(api_key_id, group_id)` pair) — a burst of new-group-creating
requests from the *same* non-master key would otherwise hit that unique index next, even after the
group-name race was fixed.

### Bug #2 (the actual reason the test still failed after fixing bug #1): `ip_records.target_address` upsert race

This is the more important one — it's the core "re-register an IP" path AGENT.MD explicitly
mandates must not fail. Same shape of bug as #1, in `handle_ip_upsert`'s record resolution: `find
by target_address` → if `None`, `insert`. Confirmed via `RUST_LOG=error` with a temporary
`tracing_subscriber` init in the test (removed afterward) that the real error was `UNIQUE
constraint failed: ip_records.target_address` on 9 of 10 concurrent inserts — session 2's
`exec_without_returning` fix only covered the *membership* insert, not this one, and the existing
sequential regression test (`test_reban_into_same_group_does_not_500`) couldn't catch it because
awaiting each ban one at a time means the second one always finds the first one's already-committed
row.

This one *can't* use the same `on_conflict().do_nothing()` trick directly, because the update path
has real conditional business logic a blind "insert-or-overwrite" would lose: preserve the existing
`cause` when the caller doesn't supply one, and refuse to touch a record with `is_locked = true`.
Instead, wrapped the existing find-or-insert logic in a `loop`, and on the insert attempt, used
SeaORM 2.0's built-in, portable `DbErr::sql_err() -> Option<SqlErr>` classifier (documented in
`sea-orm-2.0.0/src/error.rs` as the correct cross-backend way to detect this, rather than matching
SQLite's numeric error codes directly, which would violate AGENT.MD's SQL-agnosticism constraint)
to detect specifically `SqlErr::UniqueConstraintViolation` and retry — at that point the concurrent
winner's row is guaranteed already committed (SQLite here is pooled to exactly one connection, so
there's no interleaving left to race against), so the retry's `find` succeeds and takes the normal
update branch, `is_locked` check and conditional `cause` preservation fully intact. At most one
retry is ever possible.

Diagnosis process, for the record: the client-facing error is intentionally generic ("Internal
database error"), so getting the real DB error required temporarily adding
`tracing_subscriber::fmt().with_test_writer().try_init()` plus `eprintln!`-ing each task's real
status/body inside the test itself, running with `RUST_LOG=error --nocapture`, then removing all of
that instrumentation once the actual `DbErr` message was captured. The final committed test has
none of that — it's a plain, clean assertion.

Re-ran the concurrency test 5 times in isolation and the full suite 3 times after both fixes — 100%
stable, no flakes.

### Final verification (session 4)

- `cargo check --all-targets`: clean.
- `cargo test --all-targets`: **15/15 pass** (11 carried over from sessions 1–3 + 4 new this
  session), stable across repeated runs.
- `cargo clippy --all-targets --all-features -- -D warnings`: clean.
- `grep -rn -E "\.unwrap\(\)|\.expect\(" src/`: no matches.
- Full repo file sweep: no dead/orphaned files; every `static/` asset is referenced from
  `index.html`.

### Updated production-readiness note

Three sessions in, the pattern holding true is: **every previously-undiscovered bug in this
codebase has been a SeaORM `on_conflict`/upsert pitfall, and every one of them was found by
actually exercising a code path, not by reading the code or by static analysis.** Session 2 found
one such bug (membership insert) via manual sequential `curl` testing. This session's *purpose-built
concurrency test* found two more in the same family, including one that a sequential test
structurally cannot detect. If more concurrent/multi-writer paths are added later (or reviewed),
the standing recommendation from session 2 still applies and now has two additional data points:
any `find-then-insert` or `on_conflict(...)` in this codebase needs to be checked against genuine
concurrent execution, not just sequential re-invocation — a bug can be (and twice was) invisible to
a test that awaits each request one at a time.

---

## 2026-07-26 (session 5) — Unified group identification, key lifecycle, audit log UI

Driven by live cURL/UI review findings: `DELETE /api/ips` rejected JSON bodies, group permission
mapping only accepted `group_name`, audit logs had no UI or endpoint at all, and the dashboard had
no way to edit a key, rotate its secret, or revoke a single group permission.

### New module/route structure (`src/api.rs`, `src/lib.rs`)

- `resolve_group_ref(db, group_id, group_name)` — shared resolver requiring exactly one of the
  two; `group_id` never auto-creates (an ID isn't something a client can legitimately invent), only
  `group_name` can. Used by `handle_ip_upsert` (`/ban`, `/white`) and
  `update_key_group_permissions`.
- `resolve_group_by_identifier(db, &str)` — resolves a single path segment that may be a UUID or a
  literal name; tries UUID first, falls back to name. Used by the new revoke route, where REST path
  conventions only allow one placeholder.
- `BanWhitePayload`, `GroupPermInput`: `group_name: String` → `group_id: Option<Uuid>` +
  `group_name: Option<String>`. Purely additive — every existing test/call site that only ever sent
  `group_name` keeps working unchanged (confirmed: all pre-existing tests still pass with zero
  modification to their payloads).
- `QueryFilters` (`GET /api/ips`): added `group_id: Option<Uuid>`, OR'd together with the existing
  name-based `groups`/`group_name` matches.
- `DeleteIpQuery`: every field became `Option<...>`; `delete_ip` now takes `Query<DeleteIpQuery>`
  *and* raw `axum::body::Bytes`, parses the body as the same shape if non-empty, and merges
  (query wins on overlap) before validating that a `target_address` and exactly one group
  identifier were supplied from *either* source.
- `PUT /api/keys/{id}` (`update_api_key`) — updates `name`/`bound_ips`/global scope flags only;
  deliberately excludes `is_master` (promotion/demotion isn't exposed through a generic update).
- `POST /api/keys/{id}/rotate` (`rotate_api_key`) — new `key_hash`/`prefix`, returns the plaintext
  once. The old hash is overwritten, not retained, so the old secret is invalid the instant the
  response is sent.
- `DELETE /api/keys/{id}/permissions/{group_identifier}` (`revoke_key_group_permission`) — new.
- `POST /api/keys/{id}/permissions` — added as an alias for the existing
  `update_key_group_permissions` handler. The task text referred to the assignment endpoint as
  living at `/permissions`, but it has always been `/keys/{id}/groups`; renaming outright would
  break every existing caller (frontend + all prior tests), so `/groups` keeps working and
  `/permissions` was added alongside it, giving the new `DELETE .../permissions/{id}` route a
  natural, matching collection to sit under.
- `GET /api/audit-logs` (`list_audit_logs`) — master-only (not just `can_manage_keys` or similar:
  audit entries span every key/group in the system, so anything less than master would be an RBAC
  leak), supports `action`/`limit`/`offset`.
- `build_api_key_summary()` — extracted from `list_api_keys` so `update_api_key` returns the exact
  same shape.

### Security finding along the way: `GET /api/webhooks` leaked `secret_token`

Same shape of bug as the `api_keys.key_hash` leak fixed in an earlier session, found while touching
this exact code for the audit-log work: `list_webhooks` serialized the raw `webhook_config::Model`,
which includes `secret_token` in plaintext. Unlike `key_hash` (a hash of a 256-bit *generated*
value, so a leak isn't practically exploitable), `secret_token` is the actual, caller-chosen HMAC
signing secret — leaking it lets any reader with `can_manage_webhooks` forge valid
`X-Signature-256` signatures for that webhook. Fixed with a new `WebhookSummary` DTO (mirrors
`ApiKeySummary`'s pattern) that omits it; `list_webhooks` now maps through it. Verified live: created
a webhook with a real secret, confirmed `GET /webhooks` response has no `secret_token` key at all.

### Also found and fixed: broken rustdoc intra-link (latent since session 1)

`cargo check`/`cargo clippy` don't run rustdoc's link checker, so this had never surfaced:
`src/entities/ip_record.rs`'s module doc linked
`` [`ip_record_group_membership`](super::ip_record_group_membership) ``, which `cargo doc` reports
as unresolvable. Fixed by switching to an unambiguous `crate::entities::ip_record_group_membership`
path. Worth normalizing: `cargo doc --no-deps` isn't in this project's usual validation loop
(`check`/`test`/`clippy`) and should probably be added, since it caught something the other three
didn't.

### Frontend (`static/`)

- **Dynamic group dropdown**: `#manage-rights-group` changed from a free-text input to a `<select>`
  populated by a new `updateGroupSelector()`, called after every `loadGroups()`. Closes a real
  papercut, not just a nicety — a typo in the old text field would silently auto-create a brand-new
  group (if the caller had `can_create_groups`) instead of erroring, and the mistake wouldn't be
  obvious until someone asked "why doesn't my key have access?".
- **Audit Logs tab**: new nav button + panel, hidden entirely for non-master keys in
  `enforceRBACUI()` (matches the backend's master-only restriction — no point showing a tab that
  will just 403). Own pagination state (`auditPagination`), loaded as part of `loadInitialData()`
  when the profile is master.
- **Edit Key modal** (`openEditKeyModal`/`closeEditKeyModal`/`submitEditKey`): plain-CSS overlay
  (`.modal-overlay`/`.modal-card`, same fixed-overlay pattern as the existing login screen, just
  layered above it at a higher `z-index`), pre-filled from `this.state.apiKeys`, `PUT`s on submit.
- **Regenerate Secret** (`regenerateKeySecret`): confirms, calls the rotate endpoint, shows the new
  plaintext in a small reused reveal modal (`#secret-reveal-modal`) rather than inline in the table
  row (there's no good inline spot once the row already has three action buttons).
- **Group permission revoke**: each group badge in `renderKeyScopes()` now embeds a small `×`
  button (`.badge-revoke`) calling `revokeGroupPermission(keyId, groupId)` — passes the group's
  UUID rather than its name specifically to avoid breaking the inline `onclick` attribute if a group
  name ever contains a quote character.
- Verified structurally: every `getElementById(...)` string in the new/changed `app.js` code has a
  matching `id="..."` in `index.html` (scripted diff of both ID sets — zero mismatches).

### Tests added (`tests/rbac_integration_tests.rs`)

- `test_delete_ip_accepts_query_or_json_body`
- `test_group_identification_by_id_and_name_are_interchangeable` (also covers both-supplied and
  neither-supplied validation, and that an unknown `group_id` 404s instead of auto-creating)
- `test_key_rotation_invalidates_old_secret`
- `test_update_api_key_changes_take_effect_immediately`
- `test_revoke_group_permission_by_name_and_by_id`
- `test_audit_log_query_returns_entries_after_mutations`

One self-inflicted test bug caught before finalizing: `test_update_api_key_changes_take_effect_immediately`
originally set the target key's `bound_ips` to `192.0.2.0/24` as part of the update payload, which
doesn't cover the test harness's simulated client address (`127.0.0.1`) — the *next* request
correctly got `403` from the CIDR check, not from the scope check the test meant to exercise.
Fixed by using `0.0.0.0/0` instead, which still proves the field persists (asserted against the
response) without accidentally locking the test out of its own key.

### Live manual verification

Hit a real environment snag worth recording: the first server start for manual testing bound
successfully enough to print the bootstrap banner and generate a master key in its own fresh
database, but then failed with `Error: Os { code: 98, kind: AddrInUse, ... }` on the actual
`TcpListener::bind` — a *different*, already-running `simply_firewall` process from earlier in this
session had never been stopped and was still holding port 3000. `ps aux`/`fuser` briefly showed a
PID that appeared to belong to the new (crashed) process, which was really just PID-reuse
coincidence pointing at the old one. Lesson applied: after seeing `AddrInUse` (or any unexplained
auth mismatch against a freshly-generated key), check `fuser 3000/tcp` / confirm the log has no
bind error *before* trusting `ps aux` — don't assume the most recently launched process is the one
actually serving. Once the stale process was force-killed and a genuinely fresh one started (log
verified clean, no `AddrInUse`), every new endpoint was exercised directly and matched the
automated tests: `group_id`/`group_name` interchangeable on `/ban`, `DELETE /ips` via query string
and via JSON body, `PUT`/`rotate`/permission-grant/permission-revoke on a real sub-key, master-only
`/audit-logs` showing the real action history in order, and `GET /webhooks` confirmed to omit
`secret_token` after creating one with a real secret.

### Final verification (session 5)

- `cargo check --all-targets`: clean.
- `cargo test --all-targets`: **21/21 pass** (15 carried over from sessions 1–4 + 6 new this
  session).
- `cargo clippy --all-targets --all-features -- -D warnings`: clean.
- `cargo doc --no-deps`: clean (after the intra-link fix above).
- `grep -rn -E "\.unwrap\(\)|\.expect\(" src/`: no matches.
- Live server: every new/changed endpoint exercised manually via `curl` against a real (non-test)
  SQLite database, see above.

### Production readiness note

All five `<task>` items are done: unified group identification, flexible `DELETE /api/ips`, key
rotation, key update, and permission revocation are implemented, routed, tested, and manually
verified; the audit log endpoint and its UI panel exist and are master-gated; the dashboard gained
an edit-key modal, a regenerate-secret flow, a dynamic group dropdown, and per-badge permission
revocation. Two items beyond the literal ask were fixed because they were directly adjacent to the
work and represent real, live security/documentation gaps: the `secret_token` leak on
`GET /webhooks`, and the broken rustdoc link. Neither required expanding scope beyond files already
being edited for the requested work.

---

## 2026-07-26 (session 6) — Two live-cURL bug fixes, a real E2E shell suite, and a scripting lesson

### Bug fix #1: `POST /api/groups` 500'd on a duplicate name

`create_ip_group` did a bare `ip_group::Entity::insert(...).exec(...).await?` with no conflict
handling — a second request for a name that already exists hit `ip_groups.name`'s unique
constraint and propagated a raw `DbErr` straight to a `500`. This is the exact same *shape* of bug
fixed for the auto-create-on-write paths in an earlier session (`get_or_create_group`'s
`on_conflict().do_nothing()`), but this is a genuinely different code path — the *explicit*
"create a group" endpoint — which was deliberately left alone at the time on the theory that an
explicit create hitting a genuine duplicate is a more defensible edge case than a fail2ban-style
implicit-create race. Live testing showed that reasoning doesn't hold up: it's still just a
500 for an entirely predictable, common mistake (calling create twice, or two admins racing to set
up the same group name). Fixed by adding `AppError::Conflict(String)` (`409`) to `src/error.rs` and
catching `SqlErr::UniqueConstraintViolation` specifically around the insert (same
`DbErr::sql_err()` classifier used for the `ip_records` upsert race in an earlier session), rather
than silently falling back to "return the existing group" — an explicit create endpoint getting a
clean `409` on a genuine name collision is the more correct REST semantic, and it still tells the
caller unambiguously what happened.

### Bug fix #2: `POST /api/keys/{id}/groups` 422'd when `group_id` held a name

`GroupPermInput.group_id` was `Option<Uuid>` — strict typing that Axum/serde reject at
deserialization time, before the handler ever runs, if the JSON value isn't UUID-shaped. A client
passing a group's name into `group_id` (an easy mistake once `group_id`/`group_name` are supposed
to be interchangeable, which was the whole point of introducing `group_id` in the first place)
got a `422` with no chance for the server's own resolution logic to help. Fixed by changing
`group_id`'s type to `Option<String>` and adding `resolve_group_ref_flexible()`, which reuses the
existing `resolve_group_by_identifier()` helper (built for the `DELETE .../permissions/{id}` route
in an earlier session) to try UUID-parse-then-name-lookup on whatever string is in `group_id`.
`group_id` still never auto-creates (whether it looks like a UUID or a name) — only the dedicated
`group_name` field can do that — so the existing "an identifier is a 404, a name is create-or-use"
distinction from the previous session is preserved, just extended to tolerate either shape in the
`group_id` slot specifically.

### Adjacent finding fixed while in this code: least-privilege was documented but not enforced

AGENT.MD states "`can_write` or `can_delete` require `can_read` to be true" as a Core Architectural
Rule. Grepping `update_key_group_permissions` for any check of this turned up nothing — a client
could set `can_write: true, can_read: false` and it would be persisted as-is. Added a validation
check (before group resolution, so it fails fast) returning `400` when `can_write || can_delete`
is set without `can_read`. Locked in with `test_group_permission_write_or_delete_requires_read`.

### `tests/rbac_integration_tests.rs`: 3 new tests, all passing alongside the 21 carried over

- `test_create_duplicate_group_returns_conflict_not_500`
- `test_group_permission_assignment_accepts_uuid_or_name_in_group_id_field` (also exercises the
  new `/permissions` alias route from an earlier session)
- `test_group_permission_write_or_delete_requires_read`

No existing test needed changes — `GroupPermInput.group_id` going from `Uuid` to `String` is
wire-compatible (a UUID serializes identically either way), confirmed by all pre-existing tests
passing unmodified.

### `scripts/test_e2e.sh`: a real, repeatable, self-contained E2E suite

Builds the project, boots a fresh instance against a throwaway `mktemp -d` SQLite database,
scrapes the one-time bootstrap master key out of the server's own log, drives the full HTTP API
with `curl`+`jq`, tears the server down and cleans up on exit (`trap cleanup EXIT INT TERM`) no
matter how the script ends. Covers, in order: basic auth (missing/invalid/valid key); a 4-key
permission matrix on a shared "Group A" (Master / Read-Only / Write-Only / No-Access — "Write-Only"
means *read+write, no delete*, not literally write-without-read, since that would itself violate
the least-privilege rule just added); add/list/filter(by IP substring, group, status)/update
(re-registration)/delete of IPs spanning three groups (a banlist, a second banlist, and a
whitelist); key update + secret rotation with old-secret invalidation; bound-IP CIDR enforcement
via `X-Forwarded-For` (including the rightmost-hop-is-trusted case); master-only audit log access
and content; and both bugs fixed above, live over HTTP. Every status code is timestamped
(`HH:MM:SS.mmm`) and color-coded (2xx green, 401/403/404/409/422 yellow, 5xx red); every ID/key
used is captured from real API responses via `jq`, never hardcoded.

**A real bash bug found and fixed while writing it, worth recording because it's a recurring trap,
not a one-off typo:** the first version used
`mapfile -t _RO < <(create_scoped_key "Read-Only Key")` to capture a helper function's "return
values" (a created key's plaintext + id) via command substitution. Every one of that function's
*diagnostic* prints (`log`, the `api_call` status line, the `check` PASS/FAIL line) also went to
stdout — and process substitution captures a command's entire stdout, so `mapfile` scooped up the
diagnostic lines right along with the two real values, leaving `_RO[0]`/`_RO[1]` full of garbage
instead of the key/id. That cascaded into the vast majority of the script's first-run failures
(23 of them) — every subsequent call using the corrupted `$READONLY_ID` etc. hit a malformed URL
and got a `400` from Axum's own path-parameter parsing, which looked at first glance like a wall of
unrelated backend bugs. It wasn't: it was one bash mistake with a very wide blast radius. Fixed by
(a) routing every diagnostic helper (`log`/`warn`/`err`/`log_section`/the status line in
`api_call`/the PASS-FAIL lines in `check`/`check_jq`) to stderr unconditionally, so stdout is
*never* anything but an intentional return value, and (b) rewriting `create_scoped_key` to set
plain global variables (`$CREATED_KEY`/`$CREATED_ID`) instead of relying on stdout capture through
a subshell at all — simpler, and sidesteps subshells silently losing `PASS_COUNT`/`FAIL_COUNT`
increments too (process substitution runs in a subshell; variables it sets don't propagate back).
Separately (a genuine test-design bug, not a bash mechanics one): the first version banned one
address into "Group B" then tried to `/white` a second address into the *same* group name,
expecting per-address ban/whitelist semantics — but group type is fixed at creation and doesn't
vary per membership, so the second address silently landed in a banlist group and the
`status=white` filter correctly found nothing. Fixed by giving the whitelist example its own group.

Re-ran the fixed script twice back-to-back: **51/51 checks pass both times**, clean shutdown, port
3000 free afterward.

### Final verification (session 6)

- `cargo check --all-targets`: clean.
- `cargo test --all-targets`: **24/24 pass** (21 carried over from sessions 1–5 + 3 new this
  session).
- `cargo clippy --all-targets --all-features -- -D warnings`: clean.
- `cargo doc --no-deps`: clean.
- `grep -rn -E "\.unwrap\(\)|\.expect\(" src/`: no matches.
- `scripts/test_e2e.sh`: **51/51 checks pass**, twice in a row, against a real running instance.

### Environment note carried forward

Before running anything that binds port 3000 (including this new script), `fuser 3000/tcp` first —
this session, like session 5, found a stale `simply_firewall` process still holding the port from
earlier manual testing before either the script or a fresh manual run could bind it. The E2E
script itself now checks for this up front and exits with a clear message instead of limping along
against a leftover instance the way manual testing did in session 5.

---

## 2026-07-26 (session 7) — Deterministic bootstrap, verbose E2E logging, 4 more test scenarios

Root cause of the reported "I/O buffering timeout": `scripts/test_e2e.sh` extracted the bootstrap
master key by `grep`-ing the server's redirected log file (`grep -oE '(Key:    )[a-f0-9]{64}'
"$SERVER_LOG"`). `tracing-subscriber`'s fmt writer doesn't flush after every event the way a
line-buffered TTY would, so a reader polling that log file immediately after the readiness `curl`
succeeds can race a banner that's already been *printed* by the process but not yet flushed to the
actual file on disk. The fix in this session removes the race at its source rather than papering
over it with a longer timeout.

### `src/main.rs`: `INITIAL_MASTER_KEY` + explicit flush

`bootstrap_master_key` now checks `INITIAL_MASTER_KEY` before falling back to
`api::generate_random_key()`. Deliberately scoped as a test/CI-only affordance, not a documented
deployment option: it logs a `tracing::warn!` every time it's used, precisely so a fixed,
attacker-guessable secret can't end up in a real deployment without someone noticing it in the
logs. Also added the explicit `std::io::stdout().flush()` / `std::io::stderr().flush()` the task
specified, right after the bootstrap banner — belt-and-suspenders alongside the `INITIAL_MASTER_KEY`
fix, since some other future reader of this log might still want to tail it for the banner. Smoke
tested directly (not just through the E2E script): started the real binary with
`INITIAL_MASTER_KEY=e2e_master_secret_key_for_testing_123456789`, confirmed the warning appears,
confirmed `GET /api/auth/me` authenticates with that exact literal string, confirmed
`is_master: true`.

### `scripts/test_e2e.sh`: rebuilt around the deterministic key, verbose per-call logging, port default

- Removed the log-grep entirely. The script now sets `INITIAL_MASTER_KEY` when launching the
  server and uses that same literal value directly — zero dependency on log content or timing for
  the single piece of state the whole rest of the script depends on.
  - `BASE_URL` default changed from `http://localhost:3000` to `http://127.0.0.1:3000` (avoids an
    IPv6 `::1`-first resolution attempt against a server that only binds the IPv4 wildcard
    address) — readiness polling already used `curl`, not log content; it just needed the more
    precise host literal the task specified.
- `api_call` now prints the jq-pretty-printed response body (dimmed, indented under the status
  line) after **every** call, not just on failures — moved this out of `check`/`check_jq`'s
  failure branches (which were the only places a body used to get printed) since printing it
  unconditionally in one place made the redundant per-assertion copy pointless. Falls back to
  printing the raw body verbatim if it isn't valid JSON (e.g. a `204 No Content` body), and prints
  `(empty body)` for a genuinely empty one.
- Found and fixed one remaining call that bypassed the `api_call` wrapper (a raw `curl` to resolve
  `fail2ban_nginx`'s group id) while auditing the script for "format every single HTTP call" —
  routed it through `api_call` like everything else so it gets the same timestamp/status/body
  treatment.
- Added `check_true` (wraps `jq -e`) for boolean-expression assertions, used by the new conflict-
  detection section to check `[.[].group_type] | sort == ["banlist","whitelist"]` in one line
  instead of several separate scalar `check_jq` calls.
- Added new sections: **§4 Multi-Group Overlap / Conflict Detection** (same address into a
  banlist and a whitelist group, asserts `GET /api/ips` returns 2 rows with the two different
  `group_type`s), a dedicated **bound-IP strict-rejection** case inside §6 (`bound_ips=127.0.0.1/32`
  key, `X-Forwarded-For: 203.0.113.50`, asserts exactly `403` + `"error": "Client IP not allowed"`),
  **§7 audit log pagination** (6 `GROUP_CREATE` actions, `limit=3&offset=0` vs `limit=3&offset=3`,
  asserts each page has exactly 3 entries and the two pages don't overlap), and a
  **group_name-vs-group_id interop** case in §8 using a realistic `fail2ban_nginx` group name
  granted to one key while a second key gets the same group by UUID.
- Two full runs back-to-back: **78/78 checks pass both times**, clean shutdown, port 3000 free
  after each.

### `tests/rbac_integration_tests.rs`: 4 new tests (28 total, all passing)

- `test_multi_group_overlap_exposes_both_memberships_for_conflict_detection` — same address into
  a banlist and a whitelist group; asserts `GET /api/ips` returns exactly 2 rows (not deduplicated
  into 1), with `group_type`s `["banlist","whitelist"]` after sorting.
- `test_group_permission_assignment_via_group_name_alongside_uuid` — a realistic
  `fail2ban_nginx`-named group, one key granted access via `group_name`, a second key granted
  access to the *same* group via its UUID; asserts both keys can read it and both grants resolved
  to the identical `group_id`.
- `test_audit_log_pagination` — 6 `GROUP_CREATE` actions, asserts `limit=3&offset=0` and
  `limit=3&offset=3` each return exactly 3 entries whose ID sets are disjoint and whose union is
  all 6 (via `HashSet::is_disjoint`/`union`, not just eyeballing individual entries).
- `test_bound_ip_strictly_rejects_out_of_cidr_forwarded_address` — the exact scenario named in the
  task (`bound_ips=127.0.0.1/32`, `X-Forwarded-For: 203.0.113.50`), asserting the precise error
  body (`{"error": "Client IP not allowed"}`), plus a sanity check that the same key from
  `127.0.0.1` itself is let through.

No existing test needed modification.

### Final verification (session 7)

- `cargo check --all-targets`: clean.
- `cargo test --all-targets`: **28/28 pass** (24 carried over from sessions 1–6 + 4 new this
  session).
- `cargo clippy --all-targets --all-features -- -D warnings`: clean.
- `cargo doc --no-deps`: clean.
- `grep -rn -E "\.unwrap\(\)|\.expect\(" src/`: no matches.
- `scripts/test_e2e.sh`: **78/78 checks pass**, twice in a row, against a real running instance
  with verbose per-call JSON logging throughout.

---

## 2026-07-26 (session 8) — Readiness polling on a real route, webhook payload fix, full-URL logging

Two issues were reported from live shell testing of the session-7 script: (1) `test_e2e.sh` timed
out during server boot when cargo's output was redirected, and (2) `POST /api/webhooks` returned
422 (`missing field 'name'`). Investigated both against the actual current source before touching
anything, since the task's own suggested webhook payload (`url`/`secret`/`events`) turned out not
to match the real `CreateWebhookPayload` struct (`name`/`target_url`/`secret_token`/
`payload_template`/`group_id`) — copying it verbatim would have just traded one 422 for another.

### Root causes

- **Boot timeout**: `src/main.rs` already had both `INITIAL_MASTER_KEY` and explicit
  `stdout()`/`stderr()` `.flush()` from session 7 — confirmed by direct read, no code change
  needed there. The actual remaining bug was in the script's *readiness poll*, not the server: it
  still probed `curl -s -f "$BASE_URL/"` (the static-file root, served by `ServeDir`), and `-f`
  makes curl treat any non-2xx as a hard failure. If `static/` has no `index.html` (or the timing
  window catches the listener before `ServeDir` is fully wired), that probe can fail indefinitely
  even though the API itself is completely up and answering — a false "not ready" that only a real
  API route would avoid.
- **Webhook 422**: not actually a broken payload to fix — `test_e2e.sh` had **no webhook test at
  all** before this session. The 422 in the bug report is exactly what you get from Axum's `Json`
  extractor when a `#[derive(Deserialize)]` struct has a non-`Option` field that's missing from the
  body; `CreateWebhookPayload::name` is `String`, not `Option<String>`, so any caller omitting it
  gets that exact error. Confirmed the real field names by reading `src/api.rs:1292-1309` directly
  rather than trusting the task's example.

### `scripts/test_e2e.sh` changes

- **Readiness polling** (Boot section): replaced the `curl -f "$BASE_URL/"` check with
  `STATUS_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/groups")`, looping until it's
  `200`, `401`, or `404`. `/api/groups` sits behind `auth_middleware`, so an unauthenticated probe
  reliably gets a real HTTP response (401, in practice) the instant the listener can route
  requests — no dependency on `static/`'s contents or on log content/timing either way.
- **Full URL in every log line**: `api_call`'s status-line `printf` used to show bare `%-6s %s`
  (method + path only); changed the second `%s` from `"$path"` to `"$BASE_URL$path"` so every
  logged request line is copy-pasteable as a real URL.
- **JSON-body IP deletion**, added right after the existing query-string deletion case in §3: adds
  `203.0.113.20` to Group B, then deletes it with `DELETE /api/ips` sending
  `{"target_address":"...","group_name":"..."}` as the request body instead of query parameters,
  and confirms it's gone. The query-string variant already existed; this was the untested half of
  "accepts query or JSON body" (the behavior itself was already covered by
  `test_delete_ip_accepts_query_or_json_body` in the Rust suite — the shell script just hadn't
  exercised that path).
- **New §9 Webhook Lifecycle**: first asserts the *actual* bug report reproduces (`POST
  /api/webhooks` without `name` → `422`), then creates one with the correct shape (`name`,
  `target_url`, `secret_token`, `payload_template`, `group_id: $GROUP_A_ID`), lists it back and
  checks both that it round-trips correctly (`any(.[]; .id == ... and .name == "slack_alert")`) and
  that `secret_token` never appears in any listed webhook (`all(.[]; has("secret_token") | not)` —
  exercising the `WebhookSummary` leak guard from session 5 end-to-end over real HTTP, not just in
  the Rust unit test), deletes it (`204`), confirms it's gone, and confirms deleting it again is
  `404` rather than a second `204`.
- **New §10 Key Deletion**: creates a disposable key, confirms a key without `can_manage_keys`
  gets `403` trying to delete another key, has master delete the disposable key (`204`), confirms
  the deleted key's secret is rejected (`401`) on the very next request, and confirms deleting the
  same id again is `404`.
- Updated the file's header comment to list the newly-covered scenarios (JSON-body IP deletion,
  key deletion, webhook lifecycle) and the full-URL/timestamp/color/jq-body logging contract.

No changes were needed to `src/main.rs`, `src/api.rs`, or `tests/rbac_integration_tests.rs` this
session — the Rust-side behavior (webhook creation validation, key deletion cascade, flexible IP
deletion) was already correct and already covered by existing integration tests; the gap was
entirely in the shell E2E script's coverage and its readiness-probe target.

### Final verification (session 8)

- `cargo check --all-targets`: clean.
- `cargo test --all-targets`: **28/28 pass**, unchanged from session 7 (no Rust source touched).
- `cargo clippy --all-targets -- -D warnings`: clean.
- `scripts/test_e2e.sh`: **95/95 checks pass**, twice in a row (78 carried over from session 7 + 17
  new: 1 JSON-body-delete sequence + 8 webhook-lifecycle checks + 8 key-deletion checks), exit code
  `0` both times, port 3000 confirmed free after each run.

---

## 2026-07-26 (session 9) — Dedicated Webhooks tab, UI polish, 2 more edge-case E2E tests

Scope this session: frontend-only navigation restructuring (`static/`) plus two more E2E edge
cases (invalid IP validation, group-deletion cascade). No backend logic changes were required for
either — both behaviors already existed and just needed test coverage.

### `static/index.html` + `static/app.js`: 3 tabs → 4 tabs

Split the old 3-tab layout (Firewall Rules / Administration / Audit Logs) into 4, per the task's
explicit naming: **IPs & Groups**, **API Keys & Permissions**, **Webhooks**, **Audit Logs**. The
old "Administration" tab had crammed three unrelated sections (API Keys, IP Groups, Webhook
Configs) into one shared panel; this session gives each its own top-level tab, moving IP Groups
alongside IP records (both are "the firewall's data model", unlike Keys/Webhooks which are
"who's allowed to touch it").

- `data-tab`/`id="tab-*"` pairs: kept `firewall` (relabeled "IPs & Groups" — the internal id
  didn't need to match the new display text) and `audit` unchanged; added `keys` and `webhooks` as
  new top-level tabs. The existing generic tab-click handler (`document.getElementById(\`tab-${trg.dataset.tab}\`)`)
  needed zero changes — it was already fully data-driven.
- `enforceRBACUI()`: previously toggled `display` on 3 sections nested inside one shared `adminTab`
  button; rewritten to show/hide the `keys-tab-btn` and `webhooks-tab-btn` buttons independently
  (`is_master || can_manage_keys` and `is_master || can_manage_webhooks` respectively — unchanged
  logic, just re-targeted at two buttons instead of one). The IP Groups card's visibility rule was
  left exactly as before (visible whenever `is_master || can_manage_keys || can_manage_webhooks`)
  to avoid a behavior change beyond what was asked.
- **Found and fixed a pre-existing markup bug** while relocating the Webhook Configs section: the
  `webhook-url` field's `<div class="form-group">` was never closed, so `webhook-name`,
  `webhook-secret`, `webhook-group-id`, `webhook-headers`, and `webhook-template` were all nested
  *inside* the URL field's div instead of being siblings. Browsers silently tolerate this (no
  visible symptom), but it was still wrong markup; fixed while the section was already being
  touched.
- **Webhook "Target Group" upgraded from a raw text input to a `<select>`**: it previously asked
  the operator to hand-type a group UUID with a placeholder of `"UUID"` — a copy-paste-or-guess
  field with no validation until submit. Added `updateWebhookGroupSelector()` (mirrors the
  existing `updateGroupSelector()` pattern used by "Manage Group Rights"), populated with
  `<option value="${g.id}">${g.name}</option>` since `CreateWebhookPayload.group_id` is a strict
  `Uuid` with no name-or-id flexible resolution (unlike the permission-assignment endpoints) — the
  dropdown shows names but still submits a real UUID underneath.
  - This introduced a real dependency that didn't exist before: populating that dropdown needs
    `this.state.groups` loaded, but `loadInitialData()` previously only called `loadGroups()` under
    `is_master || can_manage_keys` — a key with `can_manage_webhooks` alone (a legitimate,
    intentional RBAC combination per `AGENT.MD`) would reach the Webhooks tab but find the group
    dropdown permanently empty. Fixed by broadening that condition to
    `is_master || can_manage_keys || can_manage_webhooks`; confirmed `GET /api/groups` itself has
    no scope requirement beyond authentication, so this doesn't over-fetch anything a
    webhooks-only key wasn't already allowed to see.
- Custom Headers field changed from a single-line `<input>` to a 2-row `<textarea>`, matching the
  task's framing of this as "a dedicated page for webhook configuration, custom headers, and
  payload templates" — cosmetic only, `document.getElementById('webhook-headers').value` reads
  identically off either element so no JS logic changed.
- `static/style.css`: **no changes needed.** The existing utility classes (`.admin-grid` as a
  single-column card wrapper, `.tab-nav`'s already-responsive flex row with mobile
  `overflow-x: auto`, `.select-field`, `.input-field` applying uniformly to both `<input>` and
  `<textarea>`) already fully supported the new 4-tab structure. Forcing a CSS edit just to touch
  the file would have been unjustified churn.

### UI verification: static analysis, not a live browser

Attempted to launch a real headless browser to click through the new tabs and screenshot them
(the established pattern from an earlier session's UI check). Headless Chromium crashes
immediately in this container on startup (`Trace/breakpoint trap`, exit 133) regardless of
`--no-sandbox`, `--disable-dev-shm-usage`, `--single-process`, or disabling the Bash tool's own
sandbox — `crashpad`'s own diagnostics point to `pread64: Input/output error` against
`/proc/*/mem`, indicating the restriction is enforced by the container runtime itself, below
anything a Chromium flag or this tool's sandbox setting can reach. `chromedriver` (also present)
hits the identical crash when it launches Chromium under the hood. No project skill for driving
this app's UI existed to fall back to.

Rather than claim a visual verification that didn't happen, substituted a static structural check
(`html.parser`-based, in `scripts/` scratch space, not committed) that: parses `index.html` for
unclosed/mismatched tags (would have caught the `webhook-url` div bug above on its own), checks
every element `id` is unique, cross-references all 70 `getElementById()` calls in `app.js` against
real ids in `index.html`, and confirms the 4 `data-tab` values and 4 `id="tab-*"` panels are an
exact bijection. All checks passed. This is weaker evidence than an actual rendered screenshot and
is disclosed as such — if real browser rendering is ever needed again, this container needs
investigation outside Claude Code's own sandboxing (or testing from a different environment).

### `scripts/test_e2e.sh`: 2 new edge-case sections (11, 12)

- **§11 Invalid Input Validation**: `POST /api/ban` with `target_address: "999.999.999.999"`
  asserts `400`. Traced the path first rather than assuming: `handle_ip_upsert` calls
  `payload.target_address.parse::<IpNetwork>()`, which rejects the malformed address, mapping to
  `AppError::InvalidInput` → `StatusCode::BAD_REQUEST` in `src/error.rs`. No backend change needed.
- **§12 Group Deletion Cascade**: creates `cascade-test-group`, adds an IP record and a key
  permission to it, deletes the group, and asserts: the `DELETE` itself is `204` (not an FK-
  violation error), the group is gone from `GET /api/groups`, the IP record's row disappears from
  `GET /api/ips` (not just becomes group-less — see below), and re-granting a permission against
  the now-dead UUID returns `404`.
  - Verified this would actually pass *before* running it, since AGENT.MD documents `(CASCADE)` FKs
    but doesn't guarantee SQLite enforces them: `grep`ped the whole repo for `foreign_keys`/`PRAGMA`
    and found it's never explicitly set anywhere. Checked `sqlx-sqlite`'s own source
    (`~/.cargo/registry/.../sqlx-sqlite-0.9.0/src/options/mod.rs:187`) and confirmed
    `SqliteConnectOptions` defaults `PRAGMA foreign_keys` to `ON` per-connection — unlike raw
    SQLite's own C-library default (off) — so the declarative `ON DELETE CASCADE` in the
    migrations is genuinely enforced, not just documentation. No latent orphan-row bug found.
  - Also confirmed why the *IP record itself* disappears from `GET /api/ips?ip=...` rather than
    surviving with no group: `list_ips` is rooted at
    `ip_record_group_membership::Entity::find().find_also_related(ip_record::Entity)` — a query
    that starts from the membership join table, not `ip_records` directly. Cascading away the
    group's only membership row for that address removes it from every possible `GET /api/ips`
    result, since there's no membership row left to join through.
- Both new sections use the same `api_call`/`check`/`check_jq`/`check_true` helpers as every other
  section — no new script infrastructure needed.

No changes were needed to `src/main.rs`, `src/api.rs`, `src/error.rs`, `src/migration/`, or
`tests/rbac_integration_tests.rs` this session — every behavior exercised by the two new E2E
sections was already correctly implemented; the gap was purely in test coverage.

### Final verification (session 9)

- `cargo check --all-targets`: clean.
- `cargo test --all-targets`: **28/28 pass**, unchanged (no Rust source touched this session).
- `cargo clippy --all-targets -- -D warnings`: clean.
- `scripts/test_e2e.sh`: **104/104 checks pass**, twice in a row (95 carried over from session 8 +
  9 new: 1 invalid-input check + 8 group-deletion-cascade checks), exit code `0` both times, port
  3000 confirmed free after each run.
- `static/`: HTML tag balance, duplicate-id, and `getElementById`/tab-wiring cross-checks all
  clean (see "UI verification" above for why this substitutes for a live screenshot here).

---

## 2026-07-26 (session 10) — Webhook event filtering, searchable group combobox, enriched audit logs, IP conflict view

Four features this session: (1) per-webhook event filtering, (2) a reusable searchable-dropdown
component replacing three group `<select>`s, (3) audit log enrichment with client IP and acting
key name/prefix, (4) a "Conflicted IPs Only" quick filter. Backend first (validated with
`cargo check`/`test`/`clippy` before touching the frontend), then frontend, then E2E tests.

### Schema (`src/migration/m20230101_000001_initial_schema.rs`)

Edited the single existing migration in place rather than adding a new one — confirmed this is
the established convention for this project (the file already carries the M:N RBAC junction table
added in an earlier session's "update schema migrations" commit; there's no second migration file
anywhere, and no production deployment yet whose existing data would need an incremental path).
Added `webhook_configs.events` (nullable string) and `audit_logs.{api_key_name,api_key_prefix,
client_ip}` (all nullable strings). Mirrored into `src/entities/webhook_config.rs` and
`src/entities/audit_log.rs`.

### Webhook event filtering (`src/api.rs`, `src/webhooks.rs`, `src/state.rs`)

- `WebhookEvent.event_type` (previously `"ban"`/`"white"`/`"delete"`, used only for a tracing log
  field) renamed to `action`, now carrying `"IP_ADD"`/`"IP_UPDATE"`/`"IP_DELETE"` — the same
  vocabulary `audit_log.action` already used. This removed a genuinely redundant field rather than
  adding a second one alongside it: `is_whitelist` already separately captured ban-vs-whitelist,
  so `event_type`'s old ban/white/delete distinction was never adding information beyond what
  `is_whitelist` + the new `action` together now express more clearly.
- **Found and fixed a real accuracy bug while wiring this up**: `handle_ip_upsert` unconditionally
  logged `"IP_ADD"` to the audit trail even when the address already existed and was merely being
  re-registered (cause/`last_seen_at` refresh) — there was no `IP_UPDATE` concept anywhere. Fixed
  by keying add-vs-update off whether the (address, group) *membership* row was newly inserted
  (via the existing `ON CONFLICT DO NOTHING` membership insert's returned row count), not whether
  the underlying `ip_records` row was new. This distinction matters: an address already banned in
  Group A that now *also* gets added to Group B is an `IP_ADD` from Group B's (and Group B's
  webhooks') perspective even though the `ip_records` row itself already existed — only
  re-registering into a group it's *already* a member of is a true `IP_UPDATE`.
- `run_webhook_worker`: for each candidate webhook config, if `events` is `Some`, skip dispatch
  unless the incoming event's `action` is in that comma-separated list. `None` (the default when
  the field is omitted) means all events, matching the pre-existing behavior exactly.
- `CreateWebhookPayload.events: Option<String>` validates each comma-separated token is one of
  `IP_ADD`/`IP_UPDATE`/`IP_DELETE` at creation time (400 on anything else) rather than silently
  accepting a typo that would make the webhook never fire for anything. `WebhookSummary` now
  includes `events` so the UI can display/edit it.
- New Rust integration test `test_webhook_event_filtering_skips_non_matching_actions`: a webhook
  scoped to `events: "IP_ADD"` against a real in-process mock HTTP server (same pattern as the
  existing `test_webhook_hmac_signature_and_delivery`) — asserts it fires exactly once for a new
  address, then stays at exactly one hit through both a re-registration (`IP_UPDATE`) and a
  deletion (`IP_DELETE`) of that same address.

### Audit log enrichment (`src/middleware.rs`, `src/api.rs`)

- Added `middleware::ClientIp(pub std::net::IpAddr)`, a dedicated newtype extension (not a bare
  `Extension<IpAddr>`, to avoid ever silently colliding with some unrelated future `IpAddr`
  extension) inserted into request extensions by `auth_middleware` right alongside the existing
  `key_record` — it already computes this exact resolved address for CIDR-bound-key checking, so
  this just exposes it downstream instead of discarding it.
- `create_audit_log`'s signature changed from `api_key_id: Option<Uuid>` to
  `key: Option<&api_key::Model>` plus a new `client_ip: Option<std::net::IpAddr>` — deriving
  `api_key_id`/`api_key_name`/`api_key_prefix` from the one model reference instead of asking
  every call site to spell out three separate fields that must always come from the same key
  anyway. All 12 call sites updated (every mutating handler now also takes
  `Extension(client_ip): Extension<ClientIp>`): `handle_ip_upsert` (ban/white), `delete_ip`,
  `create_api_key`, `delete_api_key`, `update_api_key`, `rotate_api_key`,
  `update_key_group_permissions`, `revoke_key_group_permission`, `create_ip_group`,
  `delete_ip_group`, `create_webhook`, `delete_webhook`.
- `api_key_name`/`api_key_prefix` are denormalized (copied at write time), not live-joined: the
  `audit_logs.api_key_id` FK is `ON DELETE SET NULL` (per `SCHEMA.MD`), so a live join would go
  blank the moment the acting key is deleted, defeating the point of an audit trail surviving the
  thing it's auditing. `client_ip` is stored as a plain string (`IpAddr::to_string()`).
- `list_audit_logs` needed no response-shape changes — it already serializes the raw
  `audit_log::Model` directly (unlike webhooks, which need a `WebhookSummary` DTO to strip
  `secret_token`), so the three new columns just appear once added to the entity.

### Frontend: reusable searchable group combobox (`static/app.js`, `static/index.html`, `static/style.css`)

- New `SearchableSelect` class: a text input plus a live-filtered `<div>` dropdown, click-to-select,
  Enter-selects-first-match, Escape/click-outside closes. Two modes selected by whether its
  `searchId`/`valueId` point at the same element: **free-text** (IP Group filter — the input's own
  text still IS the substring filter sent to `GET /api/ips?group_name=...`, unchanged from before;
  the dropdown is purely a suggestion convenience) or **strict-select** (Webhook Target Group,
  Manage Group Rights' Group field — a separate hidden input only changes value when an option is
  actually clicked, and typing without picking a fresh option clears it so a stale prior selection
  can never be silently resubmitted next to now-mismatched displayed text).
- Deliberately kept the pre-existing hidden-value element **ids** (`webhook-group-id`,
  `manage-rights-group`) unchanged when converting them from `<select>` to `<input type="hidden">`
  — `createWebhook()`/`manageKeyRights()` still read `.value` off the same id, so neither needed
  any change beyond a small explicit "did the user actually pick something" guard (a `<select
  required>` blocks submission natively; a hidden input's `required` attribute is not enforced by
  HTML constraint validation at all, so this check is now load-bearing, not just redundant).
- `loadGroups()`'s gate in `loadInitialData()` was removed entirely (previously
  `is_master || can_manage_keys || can_manage_webhooks`): `GET /api/groups` is safe for any
  authenticated key — the backend already narrows results to what that key can read — and the
  group-filter combobox's suggestions need it for every user, not just admins. The two admin-only
  consumers of the same data (groups table, key-rights/webhook selectors) stay correctly hidden by
  their own tab/section visibility regardless.
- `static/style.css`: new `.combobox`/`.combobox-menu`/`.combobox-option`/`.combobox-empty` rules
  and a `.btn-toggle.active` state (reused for the conflict-filter button below).

### Frontend: webhook event checkboxes, conflict-only filter, audit log columns

- Webhook form gained three checkboxes (IP Added/Updated/Deleted, default all checked). All three
  checked is sent as `events: null` (the backend's own "no filter" default) rather than a
  redundant explicit three-item list; unchecking all three is blocked client-side with a toast
  (a webhook subscribed to nothing would just silently never fire — better to say so up front).
- "⚠️ Conflicted IPs Only" toggle button in the IP filters bar: purely a client-side re-filter of
  the already-loaded `this.state.ips` through the existing `findConflictingAddresses()` helper
  (added in an earlier session for the conflict *badge*) — inherits that helper's same
  current-page-only scope, not a new limitation.
- Audit Logs table gained **API Key** and **Client IP** columns (placed right after Timestamp,
  before Action — "who, from where, did what" reads more naturally than appending them at the
  end); a key-less system action renders as "System" rather than a blank cell.

### UI verification

Same constraint as session 9: headless Chromium still cannot start in this container (confirmed
this limitation is environmental, not something that changed). Used the same static-analysis
substitute — `html.parser`-based tag balance/duplicate-id check plus a full `getElementById`/
`data-tab` cross-reference between `app.js` and `index.html` — extended this session to also grep-
verify the three `.combobox`/`.combobox-menu` pairs `SearchableSelect` depends on via
`querySelector` (not caught by the `getElementById`-only cross-check). All clean.

### `scripts/test_e2e.sh`: 2 new sections (13, 14)

- **§13 Webhook Event Filtering**: first confirms an unrecognized `events` token is rejected with
  `400` (pure API-contract check, no new infrastructure). Then, if `python3` is available and its
  receiver port is free, starts a tiny stdlib-only local HTTP listener (written via heredoc into
  the work dir) and drives a *real* delivery-vs-skip verification against an `events: "IP_ADD"`
  webhook: bans a new address (expects exactly 1 hit), re-registers it (expects the count to stay
  at 1), deletes it (expects it to stay at 1 again). `python3` is a soft dependency — its absence,
  or the receiver port being busy, degrades this specific section to a warning + skip rather than
  failing the whole suite; every other check in the script only ever needed curl/jq. Required
  adding `ALLOW_PRIVATE_WEBHOOKS=true` to the server's boot env so a loopback webhook target isn't
  blocked by SSRF protection (every *other* webhook test in the script already targets a real
  public host, so this doesn't loosen anything they depend on).
- **§14 Audit Log Enrichment**: fetches the most recent `GROUP_CREATE` entry and asserts
  `client_ip == "127.0.0.1"` (curl always connects over IPv4 loopback here — `BASE_URL` is
  `127.0.0.1`, not `localhost`, precisely to keep this deterministic), `api_key_name == "System
  Master"`, and `api_key_prefix` is present and exactly 8 characters.

No changes were needed to `tests/rbac_integration_tests.rs`'s existing tests, `src/error.rs`, or
`src/middleware.rs` beyond the `ClientIp` addition described above.

### Final verification (session 10)

- `cargo check --all-targets`: clean.
- `cargo test --all-targets`: **29/29 pass** (28 carried over + 1 new:
  `test_webhook_event_filtering_skips_non_matching_actions`).
- `cargo clippy --all-targets -- -D warnings`: clean.
- `scripts/test_e2e.sh`: **118/118 checks pass**, twice in a row (104 carried over from session 9
  + 14 new: 1 invalid-events-value check + 8 live-delivery-filtering checks + 1 events-round-trip
  check + 4 audit-log-enrichment checks), exit code `0` both times, both port 3000 and the webhook
  receiver's port 18763 confirmed free after each run.
- `static/`: HTML tag balance, duplicate-id, `getElementById`, `data-tab`, and combobox-class
  cross-checks all clean.

---

## 2026-07-26 (session 11) — RBAC-before-type-validation, auto-grant verification, toast bug fixes

Three of this session's four tasks turned out to be "verify/close a gap," not "build from
scratch" — worth stating plainly since it changes what actually got touched:

1. **Task 1 (RBAC precedence)**: the RBAC permission check in `handle_ip_upsert` already ran
   before anything else — but there was no group-*type* validation anywhere to have an ordering
   problem with. `/api/ban` on an existing whitelist group (or `/api/white` on a banlist group)
   silently succeeded with no check at all. So this wasn't a reordering fix; it was adding a
   missing feature, in the position the task specified.
2. **Task 2 (auto-grant on group creation)**: already fully implemented on both paths —
   `create_ip_group` (explicit `POST /api/groups`) and `handle_ip_upsert`'s auto-create branch
   (implicit, via `/api/ban`/`/api/white` on a not-yet-existing `group_name`) both already insert a
   full `can_read`/`can_write`/`can_delete = true` permission row for non-master creators. No code
   changes needed — this session added the missing explicit-path test and an E2E section proving
   it, since only the implicit path had prior coverage.
3. **Task 3 (toast UI)**: the toast component already existed in skeleton form and was completely
   non-functional — see below. This was a real bug fix, not new construction.

### Task 1: `src/api.rs` — strict group-type validation, correctly ordered

Added directly after the existing RBAC permission-check block inside `handle_ip_upsert`'s
"existing group" branch (not before it, and not as a replacement for it):

```rust
if is_whitelist && g.group_type == "banlist" {
    return Err(AppError::InvalidInput(format!(
        "Cannot whitelist IP into group '{resolved_group_name}': group type is 'banlist'. Use /api/ban or target a whitelist group."
    )));
}
if !is_whitelist && g.group_type == "whitelist" {
    return Err(AppError::InvalidInput(format!(
        "Cannot ban IP into group '{resolved_group_name}': group type is 'whitelist'. Use /api/white or target a banlist group."
    )));
}
```

Runs unconditionally (even for `is_master`, which bypasses the permission check above it but not
this one — banning into a whitelist group is a mistake regardless of who's doing it) but only
after the permission check has already had a chance to return 403 first — a caller with zero
access to a group must never learn its type via a 400 instead of the 403 they should actually get.
The auto-create branch (`else if let Some(group_name) = ...`) needed no change: a newly-created
group is always created with `default_type` matching the endpoint being called, so no mismatch is
ever possible there by construction. Confirmed via a full `cargo test` run *before* adding any new
tests that no existing test relied on the old (missing) validation — 29/29 unchanged.

### Task 3: `static/app.js`, `static/style.css` — two real bugs, not a from-scratch build

- **Toasts were completely invisible.** `.toast`'s base CSS starts at
  `opacity: 0; transform: translateX(120%)` (off-screen, awaiting a `.visible` class to transition
  in) — but `showToast()` never added that class. Every toast existed in the DOM for its full
  3.3-second lifetime at zero opacity, then got silently removed. Every one of the ~15 call sites
  across the app had been firing into the void since whenever this was written. Fixed by adding
  `.visible` via `requestAnimationFrame` (deferring one frame so the hidden initial state actually
  paints before the class change, letting the CSS transition animate instead of the two states
  collapsing into one browser-coalesced update) and symmetrically removing it before deletion,
  replacing a dead inline `toast.style.opacity = '0'` that duplicated — and fought — the CSS
  class-based approach without resetting `transform`.
- **`apiFetch` treated `403` the same as `401`**: both triggered `handleAuthFailure()` (clearing
  the stored key and forcing the user back to the login screen) and both got overwritten with a
  generic `"Authentication failed"` message, discarding whatever the server actually said. This
  directly defeated task 3's own requirement ("403 permission denied... display... the exact
  server error message") for every single 403 in the app, including all the new ones this
  session's task 1 introduces: a user hitting the new "Cannot ban IP into group... group type
  is..." 400 would see it fine, but a *401-coded* permission-denied response would never surface
  and would spuriously log them out. `401` (key itself is invalid) and `403` (key is valid but
  lacks permission for this one action) are different failure modes — logging out on `403` is
  wrong regardless of this session's other changes. Fixed by making only `401` trigger
  `handleAuthFailure()`; `403` now falls through to the same generic `!res.ok` handling as every
  other 4xx, which already correctly extracts and displays `errData.error`.
- **Five genuinely-successful actions were shown as plain/neutral toasts, not green ones**:
  `showToast(message)` calls with no explicit type default to `'info'`, and five call sites
  ("Logged out successfully", "Key deleted", "Group created", "Webhook configured", "Webhook
  configuration deleted") were missing the `'success'` argument entirely. Fixed all five —
  directly required by "on success, display a subtle green success toast."
- Gave `.toast-success`/`.toast-error` a tinted background (reusing the same `rgba(...)` tokens
  already used by the separate `.message.success`/`.message.error` component) on top of the
  existing colored left-border, since a 4px accent bar alone reads as fairly subtle for an error
  state the task explicitly wants in "amber/red."

### Tests

- `tests/rbac_integration_tests.rs`, 3 new: `test_explicit_group_creation_grants_full_permissions_to_creator`
  (closes the explicit-path coverage gap noted above), `test_rbac_denial_precedes_group_type_validation`
  (a key with *no* permission mapping on an existing whitelist group gets `403` attempting
  `/api/ban`, asserting the body contains `"Permission denied"` — proving the 403 path, not a
  generic error), `test_group_type_mismatch_rejected_with_exact_message_for_authorized_key` (a key
  *with* full read+write on both a whitelist and a banlist group still gets exactly the specified
  `400` message in both directions — proving type validation actually fires once RBAC clears).
- `scripts/test_e2e.sh`, 2 new sections: **§15 RBAC Precedence & Strict Group Type Validation**
  (no-access key → 403 on a whitelist group; then an authorized dedicated key → 400 with the exact
  message in both ban→whitelist and white→banlist directions) and **§16 Auto-Grant Full Permissions
  on Group Creation** (a fresh `can_create_groups=true` key creates one group explicitly via
  `POST /api/groups` and a second implicitly via `POST /api/ban`, then `GET /api/auth/me` confirms
  full `can_read`/`can_write`/`can_delete` on both — covering the symmetry the Rust tests split
  across two separate tests in a single end-to-end pass).

No changes were needed to `src/error.rs`, `src/middleware.rs`, `src/migration/`, or any entity —
this session was scoped entirely to `src/api.rs`'s ban/white handler and the frontend toast path.

### Final verification (session 11)

- `cargo check --all-targets`: clean.
- `cargo test --all-targets`: **32/32 pass** (29 carried over + 3 new).
- `cargo clippy --all-targets -- -D warnings`: clean.
- `scripts/test_e2e.sh`: **137/137 checks pass**, twice in a row (118 carried over from session 10
  + 19 new: 4 RBAC-precedence/type-validation checks + 2 seed checks + 2 grant checks + 2 exact-
  message checks in §15, plus 1 key-creation + 2 explicit-creation + 2 implicit-creation checks in
  §16 — 9 + 7, rounding out via the intermediate seed/grant/fetch checks each section also runs),
  exit code `0` both times, both port 3000 and the webhook receiver's port 18763 confirmed free
  after each run.
- `static/`: HTML tag balance, duplicate-id, `getElementById`, `data-tab`, and combobox-class
  cross-checks all clean (no HTML changed this session; re-run to confirm the JS changes didn't
  introduce any new unresolved references).

---

## 2026-07-26 (session 12) — group_type on creation, JSON.parse crash fix, IP canonicalization

Three independent fixes this session, one of which (`apiFetch`'s crash) traced back to a real,
previously-undiscovered backend inconsistency rather than being purely a frontend bug.

### Task 2: `apiFetch` crashed on any 200-with-empty-body response, not just 204

Root cause: `update_key_group_permissions` and `handle_ip_upsert` both return a bare
`Ok(axum::http::StatusCode::OK)` — 200 with **no body at all** — while the old `apiFetch` only
special-cased genuine `204`s (`if (res.status === 204) return null;`) before unconditionally
calling `await res.json()`. Any successful call to `POST /api/keys/:id/groups` (i.e. every
"Assign Group Rights" submission) or `/api/ban`/`/api/white` (every ban/whitelist submission) hit
`res.json()` against zero bytes and threw `SyntaxError: Unexpected end of JSON input` — this was
likely happening on some of the most common actions in the app, not an edge case.

Rewrote the body-handling in `static/app.js`'s `apiFetch` to read the body as text once, then
`JSON.parse` only when non-empty (falling back to `{}` for a genuinely empty body), with the
`JSON.parse` itself wrapped in a `try`/`catch` that falls back to the raw text — this also
subsumed the old error-path's separate `content-type`-sniffing branch (`isJson ? await res.json()
: await res.text()`), which had the identical crash risk on a JSON-content-typed-but-empty error
body. Confirmed no call site anywhere in `app.js` checks the return value against `=== null`
before making this change (`grep`ped for it), so collapsing "204" and "200 empty body" into the
same `{}` return value is behavior-neutral for every existing caller.

### Task 1: `group_type` on `POST /api/groups`

`CreateIpGroupPayload` gained `pub group_type: Option<String>`; `create_ip_group` now does
`match payload.group_type.as_deref() { Some("whitelist") => "whitelist", _ => "banlist" }` —
deliberately never rejects the request over this field, matching the task's explicit
"defaulting to banlist if omitted **or invalid**" (a typo'd `group_type` silently becomes
banlist rather than a 400, which is arguably debatable but is exactly what was specified). The
create response now also echoes back `group_type` so the frontend doesn't need a full reload to
know what it just created.

`static/index.html`: added `<select id="group-type-select">` (Banlist selected by default,
Whitelist as the other option) next to the group-name input, and a `Type` column to the groups
table. `static/app.js`: `createGroup()` reads the select and includes `group_type` in the POST
body; `renderGroupsTable()` renders it as a badge, reusing the *existing* `.badge-ban`/
`.badge-white` classes (already used by the IP-records status column) rather than inventing
parallel new ones — same red/green semantics the task asked for, already in the stylesheet.

### Task 3: IP/CIDR canonicalization

Added `pub fn normalize_ip_or_cidr(input: &str) -> String` in `src/api.rs`, using the crate
already in `Cargo.toml` (`ipnetwork`, not the `ipnet` the task's example mentioned — functionally
equivalent, and introducing a second network-address crate for one function would've been pure
duplication). Infallible by design: unparseable input passes through unchanged, since two of its
three call sites need that fallback to keep working as a substring/best-effort match rather than
becoming a new validation gate:

```rust
pub fn normalize_ip_or_cidr(input: &str) -> String {
    match input.parse::<IpNetwork>() {
        Ok(net) => {
            let is_single_host = (net.is_ipv4() && net.prefix() == 32) || (net.is_ipv6() && net.prefix() == 128);
            if is_single_host { net.ip().to_string() } else { net.to_string() }
        }
        Err(_) => input.to_owned(),
    }
}
```

Verified `ipnetwork::IpNetwork::ip()` returns the address exactly as parsed, not masked to the
network base (checked the crate source directly rather than assuming) — this is what makes a
non-aligned host-within-a-subnet like `188.190.74.130/24` round-trip unchanged instead of
silently becoming `188.190.74.0/24`, which the task's "subnets retain their CIDR notation"
requirement depends on.

Applied at all three places that actually needed it:
- `handle_ip_upsert` (`/api/ban`, `/api/white`): computed once as `normalized_address` right
  after the existing parse/validation, then used for the DB lookup, the stored `target_address`,
  the audit log, and the webhook event — replacing every prior use of the raw
  `payload.target_address`.
- `delete_ip`: normalized immediately after extracting `target_address` from the merged query/body
  params (shadowed in place), before the exact-match DB lookup — a record banned as `"X/32"` is
  now deletable by a caller passing plain `"X"`, and vice versa.
- `list_ips`'s `ip=` substring filter: best-effort only — normalizes the filter value if it
  happens to parse as a full address/CIDR, otherwise passes a genuine partial fragment (e.g.
  `"74.128"`) through unchanged, since that's a substring `.contains()` match, not an exact
  lookup, and over-normalizing would break legitimate partial searches.

No change was needed anywhere `WebhookEvent.address`/audit `target_address` read from an
already-fetched `ip_record` row (e.g. `delete_ip`'s webhook event uses `record.target_address`) —
those are already correct by construction once writes are canonicalized, since whatever's actually
stored in the DB is definitionally already in canonical form.

### Tests

- `tests/rbac_integration_tests.rs`, 2 new (Rust-side scope was explicitly canonicalization only
  per the task; group_type creation coverage was explicitly scoped to the E2E script instead —
  followed that split rather than second-guessing it):
  `test_normalize_ip_or_cidr_strips_single_host_prefixes_only` (direct calls into
  `simply_firewall::api::normalize_ip_or_cidr`, matching the established pattern already used for
  `generate_random_key`/`hash_key` — a table of `/32`, `/128`, bare, real-subnet, non-aligned-host,
  and unparseable-input cases) and `test_ban_deduplicates_slash_32_and_bare_ip_representations`
  (end-to-end: ban `/32` then bare → exactly one record in canonical form; delete via `/32` a
  record that's actually stored bare, and vice versa).
- `scripts/test_e2e.sh`, 2 new sections: **§17 Group Type Creation & Display** (explicit
  whitelist, explicit banlist, omitted → banlist default, invalid value → banlist default
  rather than 400, and confirms the type persists through `GET /api/groups` not just the create
  response) and **§18 IP Address Canonicalization** (the same dedup/cross-representation-delete
  scenario as the Rust test, driven over real HTTP via curl, plus a negative case proving a `/24`
  subnet's notation survives unstripped).

No changes were needed to `src/error.rs`, `src/middleware.rs`, `src/state.rs`,
`src/migration/`, or any entity this session.

### Final verification (session 12)

- `cargo check --all-targets`: clean.
- `cargo test --all-targets`: **34/34 pass** (32 carried over + 2 new).
- `cargo clippy --all-targets -- -D warnings`: clean.
- `scripts/test_e2e.sh`: **157/157 checks pass**, twice in a row (137 carried over from session 11
  + 20 new: 5 group-type-creation checks + 2 group-type-persistence checks in §17, plus 4
  dedup/canonical-form checks + 2 cross-representation-delete checks + 2 subnet-preservation
  checks in §18, plus the intermediate seed/list checks each section also runs), exit code `0`
  both times, both port 3000 and the webhook receiver's port 18763 confirmed free after each run.
- `static/`: HTML tag balance, duplicate-id, `getElementById`, `data-tab`, and combobox-class
  cross-checks all clean.

---

## 2026-07-27 (session 13) — Client caching/prefetch, explicit search, dedicated Groups tab, iplist endpoint, readable audit logs

Seven task areas this session; two turned out to already be satisfied by prior sessions' work
(checkbox theming, `.table-container` responsive wrapping) and needed verification rather than
new code — noted below rather than making unnecessary changes.

### Backend (`src/api.rs`)

- **`GET /api/ips` ordering**: added `.order_by_desc(ip_record::Column::UpdatedAt)` to the query
  builder before `.limit()/.offset()`. `GET /api/audit-logs` already had `.order_by_desc(Timestamp)`
  from an earlier session — verified, not re-added. Confirmed via a full `cargo test` run *before*
  adding new tests that no existing test relied on the previous unspecified order — 34/34 unchanged.
- **`format=iplist` / `mode=iplist`**: both accepted as synonyms (`QueryFilters` gained `format`
  and `mode: Option<String>`). Branches *before* the per-row `ip_group` lookup, skipping it
  entirely for this path — not needed for a flat address list — and returns
  `{"ip_list": [...]}`, sorted and de-duplicated (an address matched via two different group
  memberships in the same query would otherwise appear twice). Hit an `impl IntoResponse` type
  inference snag: with two different concrete response types now returned from the same handler
  (`Json<Vec<IpRecordResponse>>` vs `Json<serde_json::Value>`), the opaque return type no longer
  resolved to a single concrete type; fixed by calling `.into_response()` at every return site
  (including the pre-existing early-return for an empty `accessible_groups` list) so all paths
  agree on `axum::response::Response`.
- **Readable audit log `details`**: added `fn format_key_reference(name: &str, id: Uuid) -> String`
  (`"'name' (xxxxxxxx...)"`) and applied it at all 5 call sites that previously logged a bare
  `id.to_string()` as `details` — `KEY_DELETE`, `KEY_UPDATE`, `KEY_ROTATE`, `KEY_PERM_UPDATE`,
  `KEY_PERM_REVOKE`. Two of the five (`delete_api_key`, `revoke_key_group_permission`) previously
  never fetched the target key at all; added a `find_by_id` lookup in each — for `delete_api_key`
  specifically, this has to happen *before* the delete, since the row (and its name) is gone
  afterward. `update_api_key` uses the *post*-update name (if the call itself renamed the key, the
  log should say what it's called now, not what it used to be called) — the other four use the
  name as it already was, since none of them can change it.

### Frontend (`static/app.js`, `static/index.html`, `static/style.css`)

- **`PagedCache` class**: fetches 100 items per server request, paginates 15 at a time locally —
  most "Next"/"Prev" clicks are now a pure in-memory slice, zero network round-trip. Prefetches the
  next 100-item chunk in the background the moment the user's local page index hits
  `totalLocalPages - 2` (exactly "second-to-last page of the currently cached dataset," re-derived
  dynamically off the live item count on every page change, so it correctly re-fires after each
  new chunk arrives rather than only once). One shared class backs both `this.ipCache` and
  `this.auditCache` rather than duplicating the same fetch/cache/paginate logic twice.
  - Bonus, low-risk side effect: the conflict-detection scan (`findConflictingAddresses`) now
    scans the whole cached 100-item chunk instead of just the visible 15-row page, so a
    banlist/whitelist conflict split across two local pages is far less likely to be missed.
- **Root cause of the "infinite table append" bug**: every `render*Table()` already used
  `tbody.innerHTML = ...` (a full replace) — there was no literal DOM-append bug. The actual bug
  was `loadIps()`'s old pagination: `this.state.ips = [...this.state.ips, ...data]` on every
  "Next" click, then rendering that *entire* ever-growing accumulated array each time — clicking
  Next repeatedly did produce a monotonically longer rendered table, just via data accumulation
  feeding a full re-render, not via literal `appendChild`. `PagedCache.currentPageItems` always
  renders a fixed-size slice, which eliminates this by construction. Also found and fixed a real,
  separate accessibility bug in the same tab-switching code this touches:
  `classList.add('active', 'aria-selected')` was adding a CSS class literally *named*
  `aria-selected` (which does nothing — no such selector exists) instead of updating the actual
  `aria-selected` *attribute* via `setAttribute`, so screen readers never saw which tab was
  actually selected after the first switch. Fixed alongside the tab-click handler rewrite this
  session already needed for the new Groups tab.
- **Explicit search (no auto-search-on-keystroke)**: removed the debounced `input`-event listeners
  on `ip-filter`/`group-filter`/`cause-filter` entirely (and the now-fully-unused `debounce()`
  utility with them). Added a 🔍 `ip-search-btn` plus `keydown`→Enter handlers on each text filter;
  `status-filter`'s own `change` event is unaffected (a dropdown has no "keystrokes" to suppress).
  The group-filter combobox's `SearchableSelect` already had its own Enter handler (selects the
  highlighted suggestion); wired its `onSelect` callback to fire the search directly, and made the
  new field-level Enter handler only fire when the combobox menu is *closed*, so picking a
  suggestion via Enter doesn't double-fire the search once through selection and again through the
  raw keydown.
- **Dedicated IP Groups tab**: split out of the "IPs & Groups" tab (renamed to "IP Records") into
  its own `data-tab="groups"` / `#tab-groups`, gated by the same `groups-tab-btn` visibility rule
  the shared section used before (`is_master || can_manage_keys || can_manage_webhooks`).
- **Verified, not changed** (task described as needed; already true from earlier sessions):
  *Checkbox theming* — all 13 checkboxes in `index.html` already use the dark-themed
  `.checkbox-container`/`.checkmark` component (grepped for every `type="checkbox"` to confirm no
  raw unstyled ones exist). *Responsive tables* — every table was already wrapped in
  `.table-container { overflow-x: auto }`. Did add one small, genuine improvement here:
  `.data-table { min-width: 640px }`, so a wide table (the 7-column Audit Logs) scrolls cleanly
  instead of the browser silently squeezing every column illegibly thin first.
- **Action button consistency**: `renderKeysTable()` already wrapped its (3) action buttons in
  `<div class="flex gap-2">`; the single-button cases (`renderIpTable`, `renderGroupsTable`,
  `renderWebhooksTable`) didn't. Wrapped all three the same way for one consistent DOM shape
  across every table's Actions column, even though a single button doesn't strictly need the
  wrapper.

### Tests

- `tests/rbac_integration_tests.rs`, 2 new (Rust-side scope was explicitly iplist-format +
  DESC-ordering per the task list; per-task-6 audit-log-readability coverage went into the E2E
  script instead, matching how the task itself only listed those two for backend tests):
  `test_list_ips_iplist_format_returns_deduplicated_address_list` (same address banned into two
  groups appears exactly once; asserts the response is *only* `{"ip_list": [...]}`, nothing else
  leaks in; checks both the `format=` and `mode=` query keys) and
  `test_list_ips_orders_by_updated_at_descending` (three addresses banned in sequence come back
  newest-first; re-registering the oldest jumps it back to the front).
- `scripts/test_e2e.sh`, 2 new sections: **§19 Latest-Activity-First Ordering & Lightweight iplist
  Format** (same ordering/re-registration proof as the Rust test, driven over real HTTP, plus both
  `format=iplist` and `mode=iplist`) and **§20 Readable Audit Log Details** (rotates a key's
  secret, grants it a permission, then deletes it — asserts each of the three resulting audit
  entries' `details` names the key by name, and that the `KEY_PERM_UPDATE` message exactly matches
  the task's own example format character-for-character).

No changes were needed to `src/error.rs`, `src/middleware.rs`, `src/state.rs`, `src/webhooks.rs`,
`src/migration/`, or any entity this session.

### Final verification (session 13)

- `cargo check --all-targets`: clean.
- `cargo test --all-targets`: **36/36 pass** (34 carried over + 2 new).
- `cargo clippy --all-targets -- -D warnings`: clean.
- `scripts/test_e2e.sh`: **181/181 checks pass**, twice in a row (157 carried over from session 12
  + 24 new: 3 sequential-ban + 2 ordering + 1 re-registration + 5 iplist-format checks in §19,
  plus 1 key-creation + 2 rotate + 2 grant + 2 delete checks in §20, plus the intermediate
  fetch/list checks each section also runs), exit code `0` both times, both port 3000 and the
  webhook receiver's port 18763 confirmed free after each run.
- `static/`: HTML tag balance, duplicate-id, `getElementById`, `data-tab` (now 5 tabs: audit,
  firewall, groups, keys, webhooks), and combobox-class cross-checks all clean.
- Headless Chromium remains unable to launch in this container (unchanged from prior sessions);
  the frontend rewrite this session — including the new `PagedCache` pagination/prefetch logic —
  was verified via the static structural checks above plus careful manual trace-through of every
  state transition, not a live rendered screenshot. Flagging this explicitly again since this was
  the largest pure-frontend logic change of any session so far.

## 2026-07-27 (session 14) — Custom dark confirmation modal, row checkboxes, batch delete

Frontend-only task, purely `static/index.html` + `static/app.js` + `static/style.css`: replace
every native `window.confirm()` with a themed modal, add row-selection checkboxes + "Delete
Selected" batch actions to the IP/Groups/Keys tables, and give bare (unwrapped) checkboxes a dark
custom style to match the app. `test_simply_firewall.sh` does not exist anywhere in the repo
(confirmed via `find`), so the "do not modify" instruction had nothing to protect — noted and
respected regardless. No Rust files touched.

### Custom confirmation modal (task 1)

- `grep` confirmed exactly 6 `confirm()` call sites and **zero** `alert()` usages in `app.js`
  before this session — `alert()` needed no cleanup.
- New `#confirm-modal` in `index.html`, reusing the *existing* `.modal-overlay` / `.modal-card
  card` pattern already established by `#edit-key-modal` / `#secret-reveal-modal`, rather than
  inventing a parallel `.modal-backdrop` class as the task's own example naming suggested — the
  task said "e.g." for a reason, and duplicating a component the app already has would be pure
  churn. New `.modal-actions` CSS class (`display: flex; justify-content: space-between`) gives
  Cancel (left) / Confirm (right) the "aligned on the left/right" layout the task asked for,
  distinct from the existing `.form-actions` (which keeps buttons adjacent, used by the other
  modals — left untouched).
- `showConfirmModal({ title, message, confirmText, cancelText, danger })` (new method on
  `FirewallClient`) shows the modal, populates it, and returns a `Promise<boolean>`. Resolves
  `true` on Confirm-click or Enter, `false` on Cancel-click, Escape, or a backdrop click. Every
  call attaches its own listeners and tears them down via `removeEventListener` on resolve, so
  back-to-back calls (e.g. a normal delete right after a batch delete) never leak or stack
  duplicate handlers on the shared `#confirm-modal` element.
- All 6 call sites converted to `const ok = await this.showConfirmModal({...}); if (!ok) return;`
  — `deleteIp`, `deleteKey`, `regenerateKeySecret`, `revokeGroupPermission`, `deleteGroup`,
  `deleteWebhook`. Each message was upgraded from the original generic confirm() text to name the
  specific record where the data was already in hand (e.g. `deleteKey`/`deleteGroup`/
  `deleteWebhook` now look up the target's name from `this.state.*` and interpolate it into the
  message) — the modal has room for it where a native `confirm()` didn't invite it.

### Row checkboxes & batch delete (task 2)

- Checkbox column added to the IP table, Groups table, and Keys table only — exactly the three
  the task named. The Webhooks table and Audit Logs table were deliberately left unchanged.
- Selection state: `this.state.selectedIpIds` / `selectedGroupIds` / `selectedKeyIds`, each a
  `Set` of the row's own **real id** (`IpRecordResponse.id`, `group.id`, `key.id`) — not a
  synthesized composite key. IP records are logically identified by (address, group) but an
  IPv6 address like `2001:db8::1` already contains the substring `::`, so any delimiter-joined
  composite key risks corrupting on split; using the record's own UUID and looking the full row
  back up from `this.ipCache.items` by id at delete time sidesteps that entirely.
- New `wireRowSelection({ tbodySelector, selectAllId, deleteBtnId, deleteBtnLabel, selectedSet,
  onDeleteSelected })` helper, called at the end of every `render{Ip,Keys,Groups}Table()` (both
  the empty-state branch and the populated branch, so the button/select-all always reflect
  what's actually on screen). It syncs `.row-select` checkboxes ↔ the Set, drives the header
  `select-all` checkbox's `checked`/`indeterminate` state, and updates the "Delete Selected"
  button's `disabled` state + `(N)` count label. Row checkboxes get a fresh `addEventListener`
  every render (safe — the whole `tbody` is replaced via `innerHTML =`, so old elements are
  discarded, not reused); the `select-all` checkbox and delete button live in static markup
  *outside* the tbody and persist across renders, so their handlers are (re)assigned via
  `.onchange` / `.onclick` property assignment instead of `addEventListener`, which would
  otherwise stack a new duplicate listener on every single re-render.
- Locked IP rows (`ip.is_locked`) get no checkbox at all (same rule the per-row Delete button
  already followed) — nothing to select where the single-item action was already disabled.
- Selection persists across `PagedCache` page flips within the same loaded chunk (ids matching
  the same rows naturally stay checked) but is explicitly `.clear()`-ed at the top of
  `loadIps()`/`loadKeys()`/`loadGroups()` — i.e. on every *fresh* reload/search, since ids from a
  discarded dataset are meaningless once the new one lands.
- Three new batch methods (`batchDeleteIps`, `batchDeleteKeys`, `batchDeleteGroups`): show the
  confirm modal once for the whole batch (not once per item), then loop the *existing* single-item
  DELETE endpoints via `Promise.allSettled` (no new backend endpoint — the task's file list never
  mentioned `src/api.rs`, and a partial-failure-tolerant client-side loop covers it, e.g. a master
  key that happens to include itself in a batch key-delete still gets the existing backend
  self-delete guard's rejection surfaced as "N of M deleted" rather than aborting the whole batch).
  Toast reports full success or a partial-failure count; the table is reloaded afterward either
  way, which also naturally clears the (now-stale) selection.

### Universal checkbox theming (task 3)

- New `input[type="checkbox"] { appearance: none; ... }` block in `style.css`, styled with the
  existing `--bg-input`/`--border`/`--accent` tokens plus a `::after` pseudo-element checkmark —
  works on bare checkboxes that aren't wrapped in a `<label>`, which the new row-select/select-all
  checkboxes are (they sit alone in a `<td>`/`<th>`, unlike every pre-existing checkbox in the
  app). Also styles `:indeterminate` (a dash, for the select-all header checkbox when some but not
  all visible rows are checked) and `:focus-visible`.
- Deliberately did **not** touch or replace the pre-existing `.checkbox-container` / `.checkmark`
  system (the label+span wrapper used by all 13 prior checkboxes — permission grids, webhook
  event toggles, edit-key-modal). `.checkbox-container input` has higher CSS specificity (one
  class + one element vs. the new rule's one attribute selector) and already fully hides the
  native input via `opacity: 0; width: 0; height: 0`, so it keeps winning there unchanged; the new
  universal rule only actually applies where nothing more specific claims the element — exactly
  the new bare table checkboxes. Confirmed by reasoning through CSS specificity rather than a live
  render (headless Chromium still unavailable in this container).

### Tests

No Rust files changed this session — `cargo check`/`test`/`clippy` were run per the task's
explicit instruction and confirmed unchanged/clean rather than skipped. `scripts/test_e2e.sh`
required no new sections (nothing in this task is observable over the HTTP API — it's pure DOM
markup/JS), so it was run twice purely as a regression check.

### Final verification (session 14)

- `cargo check --all-targets`: clean.
- `cargo test --all-targets`: **36/36 pass** (unchanged from session 13 — no Rust files touched).
- `cargo clippy --all-targets -- -D warnings`: clean.
- `scripts/test_e2e.sh`: **181/181 checks pass**, twice in a row (unchanged count — confirms zero
  regression from the frontend-only changes).
- `static/index.html`: zero duplicate `id` attributes, `<div>`/`<table>`/`<thead>`/`<tbody>` tags
  balanced (76/76, 5/5, 5/5, 5/5).
- `static/app.js`: brace/paren/bracket counts balanced (352/352, 812/812, 19/19); `grep` confirms
  zero remaining `confirm(`/`alert(` calls outside of the `showConfirmModal` doc comment itself.
- No `node`/`deno`/other JS engine is available in this container to run a real syntax check
  (`node --check`), so every edited function was additionally read back in full and traced by
  hand for balanced braces/parens and correct control flow. Headless Chromium remains unable to
  launch here (unchanged from every prior session) — verified via the static checks above plus
  manual trace-through, not a live rendered screenshot.

## 2026-07-27 (session 15) — IP Records layout breakpoint & batch-delete button contrast

Small, targeted CSS-mostly fix for two visual issues on the "IP Records" tab found after session
14's batch-delete work landed: the two-column grid stayed side-by-side too long as the viewport
narrowed, and the new "Delete Selected" buttons were nearly unreadable. `static/app.js` needed no
changes — both fixes are pure CSS/markup, and the button's disabled/enabled toggling logic added
in session 14 (`wireRowSelection`) already drives the native `:disabled` state the new CSS keys
off of. `test_simply_firewall.sh` still doesn't exist in the repo; left untouched regardless.

### Layout responsiveness (task 1)

- `.grid-layout`'s existing stack breakpoint (`static/style.css`) moved from `max-width: 900px` to
  `max-width: 1100px`, per the task's explicit ask. At the old 900px threshold, the fixed 380px
  "Manage Access" column left as little as ~500–630px for the "Recent IP Records" side (filters,
  badges, and the 7-column table with its `min-width: 640px`) before stacking — genuinely tight.
  Moving the trigger to 1100px stacks the two panels a full viewport-width earlier, well before
  that squeeze. Added `.grid-layout > * { width: 100%; }` alongside it so the stacked
  "Manage Access" and "Recent IP Records" panels each take the full row width rather than
  retaining any intrinsic/content-based sizing once they're no longer sharing a grid track.
- `.table-container` already had `overflow-x: auto` (so a table wider than its column scrolls
  cleanly instead of squeezing) — added the missing explicit `max-width: 100%` alongside the
  existing `width: 100%` so it can never be forced wider than its parent card regardless of the
  table's own `min-width: 640px`.
- `.filters` (the IP/group/cause text filters + status dropdown + search/conflict buttons above
  the IP table) already had `flex-wrap: wrap` and `gap: 0.5rem` (8px) from an earlier session —
  confirmed still correct and left as-is; the actual crush was the outer grid column staying at
  a fixed 380px split too long, not the filter bar itself.

### Batch-delete button contrast (task 2)

- The three "Delete Selected" buttons (`#delete-selected-ips` / `-groups` / `-keys`, added in
  session 14) used `.btn-danger-outline`: transparent background + `var(--danger)` (#e74c3c) text.
  On the dark card/table backdrop that's already low-contrast, and the generic `.btn:disabled`
  rule's `opacity: 0.4` washed the already-dim red text out further for the common case (0 items
  selected) — exactly the "completely unreadable" bug reported.
  `.btn-danger-outline` had no other callers anywhere in the app (`grep` confirmed), so it was
  replaced outright with a new `.btn-batch-delete` class (renamed since "outline" no longer
  described it) rather than kept alongside a second, redundant style:
  - Enabled: solid `#dc2626` background, white text, `font-weight: 600`, no border,
    `padding: 6px 14px`, `border-radius: 6px`, `box-shadow: 0 2px 4px rgba(0,0,0,0.2)` — exactly
    the palette specified.
  - Hover: `#b91c1c`.
  - Disabled: explicit `opacity: 1` (to cancel out `.btn:disabled`'s `opacity: 0.4`, which would
    otherwise wash out these specific muted colors into something dimmer than intended — the two
    rules have equal CSS specificity, so without the explicit override the generic one still wins
    on `opacity` since `.btn-batch-delete:disabled` doesn't otherwise touch that property),
    `#2a2f3d` background, `#6b7280` text, `cursor: not-allowed`.
  - `static/index.html`'s 3 button elements updated from `class="btn btn-sm btn-danger-outline"`
    to `class="btn btn-batch-delete"` (the new class defines its own padding/font-size directly
    rather than relying on `.btn-sm`, since the task specified an exact `padding: 6px 14px`).

### Tests

No Rust files changed. `cargo check`/`test`/`clippy` run per the task's explicit instruction and
confirmed unchanged/clean. No new `scripts/test_e2e.sh` sections — nothing in this fix is
observable over the HTTP API — run twice purely as a regression check. One stale
`target/debug/simply_firewall` process from an earlier interrupted run was found still bound to
port 3000 before the first run this session; killed before proceeding (confirmed via `ss -ltnp`
it was the app binary, not an unrelated process).

### Final verification (session 15)

- `cargo check --all-targets`: clean.
- `cargo test --all-targets`: **36/36 pass** (unchanged — no Rust files touched).
- `cargo clippy --all-targets -- -D warnings`: clean.
- `scripts/test_e2e.sh`: **181/181 checks pass**, twice in a row (unchanged count — confirms zero
  regression from the CSS/markup-only changes).
- `static/index.html`: zero duplicate `id` attributes, `<div>` tags balanced (76/76), exactly 3
  `btn-batch-delete` usages (the 3 batch-delete buttons, and only those).
- `static/style.css`: brace count balanced (174/174).
- Headless Chromium remains unable to launch in this container; verified via the static checks
  above plus manual reasoning through the CSS cascade/specificity (particularly the
  `:disabled`-opacity interaction) rather than a live rendered screenshot at each breakpoint.

## 2026-07-29 (session 16) — Project rename: simply_firewall → simply_ip_vault

Repo-wide rename of the crate/package/binary and all first-party branding from `simply_firewall`
to `simply_ip_vault`, per the new "centralized IP address vault & management service" framing.
Mechanical in nature but touched 15 files — `AGENT.MD`, `Cargo.toml`, `Dockerfile`,
`docker-compose.yml`, `README.md`, `SCHEMA.MD`, `scripts/test_e2e.sh`, `src/lib.rs`,
`src/main.rs`, `src/migration/mod.rs`, `static/app.js`, `static/index.html`, `static/style.css`,
`tests/rbac_integration_tests.rs`, plus this file.

### What changed

- **`Cargo.toml`**: `name = "simply_firewall"` → `"simply_ip_vault"`. No `[[bin]]` target exists,
  so the produced binary is renamed automatically along with the package (confirmed via
  `cargo check`: `target/debug/simply_ip_vault` now builds; the old `target/debug/simply_firewall`
  is just an orphaned stale artifact left in the gitignored `target/` dir, harmless). `Cargo.lock`
  is itself gitignored/untracked in this repo (`git check-ignore` confirmed) so it's never part of
  a commit, but it picked up the new package name automatically on the next `cargo check` (likely
  rust-analyzer's background check reacting to the `Cargo.toml` edit) — verified, not manually
  touched.
- **`src/`**: `lib.rs`'s crate doc comment, `main.rs`'s `use simply_firewall::{...}` import, the
  hardcoded default `DATABASE_URL` fallback (`sqlite://firewall.db` → `sqlite://simply_ip_vault.db`
  — the task's own example assumed the old default was named `simply_firewall.db`, but it was
  actually just `firewall.db`; renamed to the new project name regardless, matching the task's
  intent), the startup log banner (`"Simply Firewall API listening on {}"` →
  `"Simply IP Vault API listening on {}"`), and `migration/mod.rs`'s two doc comments.
- **`tests/rbac_integration_tests.rs`**: 67 occurrences of the `simply_firewall::` crate path
  prefix, mechanically replaced with `simply_ip_vault::` via a single `replace_all` edit (every
  occurrence is an identical literal substring, so no per-call-site review was needed — verified
  count matches exactly before/after and `cargo test` confirms all 36 tests still compile and pass
  unchanged).
- **`static/`**: `<title>`, meta description, and both `<h1>` branding occurrences in
  `index.html`; the `style.css` and `app.js` header comments; and — a functional change, not just
  branding — the `localStorage` key `app.js` uses to persist the logged-in API key,
  `simply_firewall_key` → `simply_ip_vault_key` (all 3 call sites: `getItem`/`removeItem`/
  `setItem`, kept consistent via `replace_all`). No dual-read backward-compat fallback for the old
  key name was added — `AGENT.MD` has no such requirement for client-side storage (only the task's
  own conditional env-var clause mentioned backward compat, and that clause turned out to be
  inapplicable — see below), and this is pre-production tooling with no real deployed users to
  preserve sessions for; anyone with an existing `simply_firewall_key` entry just needs to log in
  again once, which is a one-time, low-cost effect of the rename.
- **`Dockerfile`** / **`docker-compose.yml`**: binary path, `CMD`, default `DATABASE_URL` DB
  filename, Compose service name (`simply-firewall` → `simply-ip-vault`) and `container_name`.
- **`scripts/test_e2e.sh`**: header comment, the `mktemp` work-dir prefix
  (`simply_firewall_e2e.XXXXXX` → `simply_ip_vault_e2e.XXXXXX`), and the built-binary path the
  script execs (`target/debug/simply_firewall` → `target/debug/simply_ip_vault`) — this last one
  is load-bearing, not cosmetic: without it the script would `cargo build` a binary that no longer
  exists under the old path and fail at the "Boot" stage.
- **`README.md`, `AGENT.MD`, `SCHEMA.MD`**: title headings and every literal `simply_firewall`
  identifier/code-span reference, including the `RUST_LOG` example value
  (`simply_firewall=debug` → `simply_ip_vault=debug`) and the `DATABASE_URL` default shown in the
  config table. Left untouched: generic prose that merely uses the English word "firewall" as a
  concept rather than the project's identifier (e.g. AGENT.MD's "central Firewall and ACL
  management API", README's "Simply efficient. A homelab firewall." tagline) — the task asked for
  an identifier rename, not a rewrite of the product's conceptual description, and those phrases
  contain no literal `simply_firewall` string to begin with.
- **`AGENT_NOTES.MD`**: only the file's living intro line (now "the `simply_ip_vault` (formerly
  `simply_firewall`)..."). Deliberately did **not** rewrite the 7 other occurrences that live
  inside already-dated, historical session entries (e.g. session 5's "Checking simply_firewall
  v0.1.0" cargo output, mentions of a stale `simply_firewall` process holding a port, past
  sessions' confirmations that `test_simply_firewall.sh` didn't exist at the time) — those are
  accurate historical record of what was literally true *at the time each entry was written*,
  analogous to not rewriting old git commit messages after a rename. Rewriting them would misrepresent
  what those past sessions actually observed.

### Not applicable

- Task 2 asked to "align default environment variables if applicable (e.g. `SIMPLY_IP_VAULT_LOG`,
  `SIMPLY_IP_VAULT_PORT`, etc.)". Checked every `std::env::var(...)` call site in `src/`
  (`DATABASE_URL`, `RUST_LOG`, `INITIAL_MASTER_KEY`, `BOOTSTRAP_SUBNET`,
  `ALLOW_PRIVATE_WEBHOOKS`) — none was ever prefixed with `SIMPLY_FIREWALL_` in the first place, so
  there was nothing to rename here, and the listen port isn't configurable via env var at all (it's
  hardcoded to `0.0.0.0:3000`, per `AGENT.MD` — unchanged, out of scope for a rename). No new env
  vars were invented to satisfy the task's own example names, since doing so would be unrequested
  scope creep beyond "if applicable."
- `test_simply_ip_vault.sh` (task 5 asks to run it): confirmed via `find` that neither this file
  nor its pre-rename equivalent `test_simply_firewall.sh` exists anywhere in the repo — consistent
  with every prior session's identical finding for the old name. Nothing was created to satisfy
  this, since task 3's explicit file list only calls for updating `scripts/test_e2e.sh`, not
  authoring a new/duplicate test script.
- The stray root-level `firewall.db` local SQLite file (gitignored, untracked, pre-existing dev
  artifact) was left alone — renaming or deleting a local file outside the explicit task list and
  outside version control isn't something this rename asked for.

### Final verification (session 16)

- `cargo check --all-targets`: clean, package reported as `simply_ip_vault v0.1.0`.
- `cargo test --all-targets`: **36/36 pass** (unchanged test count — purely a rename, no behavior
  changed), binary/doctest sections now report under `simply_ip_vault` instead of `simply_firewall`.
- `cargo clippy --all-targets -- -D warnings`: clean.
- `scripts/test_e2e.sh`: **181/181 checks pass**, twice in a row, confirming the renamed binary
  path/work-dir prefix didn't break the build-and-boot sequence and there's zero behavioral
  regression from the rename.
- Repo-wide `grep -rniI "simply_firewall|simply-firewall|SIMPLY_FIREWALL"` (excluding `target/` and
  `.git/`) confirmed zero remaining matches anywhere except the intentionally-preserved
  `AGENT_NOTES.MD` historical entries described above.

---

## 2026-07-29 (session 17) — Post-rename health check & full E2E verification

Verification-only session. No source, test, script, or config file was modified — every check
passed on the first run, so there was nothing to fix, and per the "no breaking changes" directive
nothing was touched speculatively.

### Results

| Check | Command | Result |
| --- | --- | --- |
| Compilation | `cargo check --all-targets` | ✅ clean, 0 warnings |
| Static analysis | `cargo clippy --all-targets -- -D warnings` | ✅ clean, 0 warnings |
| Rust test suite | `cargo test --all-targets` | ✅ **36/36 passed**, 0 failed, 0 ignored (1.27s) |
| End-to-end suite | `./scripts/test_e2e.sh` | ✅ **181/181 checks passed**, 0 failed |

Test-count breakdown for `cargo test`: `src/lib.rs` unittests 0, `src/main.rs` unittests 0, and
`tests/rbac_integration_tests.rs` 36 — i.e. the entire Rust suite lives in the integration test
binary, matching session 16's count exactly (the rename was behaviour-neutral, as claimed).

The E2E script builds the binary itself (`cargo build --quiet`), boots
`target/debug/simply_ip_vault` with a deterministic `INITIAL_MASTER_KEY`, spins up a local Python
webhook receiver, and drives the live HTTP API — so it doubles as the "build and run the server
binary" verification, exercising the real boot path (migrations, master-key bootstrap, static file
serving, webhook dispatch) rather than the in-memory test harness.

### Root-level verification script: still does not exist

Task 2 asked to run a root-level verification script *if present*. Confirmed via
`find . -name "*.sh" -not -path "./target/*" -not -path "./.git/*"` that `scripts/test_e2e.sh` is
the **only** shell script in the repository — there is no root-level `test_simply_ip_vault.sh`,
`verify.sh`, or equivalent, and no non-`.sh` executable at the root either. This matches the
identical finding recorded in sessions 5–16 (for both the old and new project names). Nothing was
authored to fill the gap: inventing a second entry-point script that duplicates
`scripts/test_e2e.sh` was not asked for and would create a maintenance fork of the E2E suite.

### Artifact cleanup

No cleanup action was necessary — the suites leave nothing behind by design, verified after the run:

- `scripts/test_e2e.sh` allocates its SQLite DB, server log, and webhook receiver log inside a
  `mktemp -d "${TMPDIR:-/tmp}/simply_ip_vault_e2e.XXXXXX"` work dir removed by an
  `EXIT INT TERM` trap. Post-run `ls -d /tmp/simply_ip_vault_e2e.*` → none remaining.
- Integration tests use `sqlite::memory:` per `AGENT.MD`, so they never touch the filesystem.
- `find` for `*.db` / `*.db-journal` / `*.sqlite*` outside `target/` → zero matches. Note the stray
  root-level `firewall.db` mentioned in session 16 is no longer present; it was a gitignored local
  dev artifact, not something this session created or removed.
- `git status --porcelain` → empty. The working tree is byte-identical to commit `71767a4`.
- No orphaned server or webhook-receiver processes left listening on ports 3000 / the receiver port.

---

## 2026-07-30 (session 18) — HMAC-SHA256 request authentication, anti-replay, encryption at rest, UI fixes

Replaced bearer-style `X-API-Key` authentication with an HMAC-SHA256 signature scheme plus a
±300-second anti-replay window, added per-key signing secrets encrypted at rest with AES-GCM-256,
and fixed three UI issues. **This is a breaking API change**: possession of an API key alone no
longer authenticates anything.

### Results

| Check | Result |
| --- | --- |
| `cargo check --all-targets` | ✅ clean |
| `cargo clippy --all-targets -- -D warnings` | ✅ clean |
| `cargo test --all-targets` | ✅ **48/48** (4 new `crypto` unit tests + 44 integration, up from 36) |
| `./scripts/test_e2e.sh` | ✅ **195/195** (up from 181; +14 new HMAC/anti-replay checks) |

### The signing scheme

Canonical signed string is `METHOD + PATH + TIMESTAMP + RAW_BODY`, concatenated with **no**
separator, hex HMAC-SHA256, keyed by the key's `signing_secret`.

Two decisions inside that deserve recording:

- **`PATH` excludes the query string.** Reverse proxies routinely reorder, re-encode or append query
  parameters; signing them would silently break valid requests behind ordinary infrastructure. The
  security cost is bounded because every mutating field on `/api/*` travels in the (signed) body —
  query parameters are read-only filters. Documented explicitly in `AGENT.MD` rather than left
  implicit, since it is the one place the scheme is deliberately weaker than "sign everything".
- **`PATH` is the *original* request path.** This cost an hour of debugging: the auth middleware is
  layered *inside* `.nest("/api", ...)`, and Axum's nesting rewrites `req.uri()` to the path relative
  to the mount point — the middleware saw `/ips` while every client signs `/api/ips`, so all 36
  integration tests failed with `401`. Fixed by reading `axum::extract::OriginalUri` from the request
  extensions, with `req.uri()` only as a fallback for the (currently impossible) un-nested case.
  Worth remembering for any future middleware that hashes or logs the request path.

### Ordering: authenticate, then authorize

The middleware now runs: timestamp validation (no I/O) → key lookup → **signature verification** →
CIDR binding check. The CIDR check deliberately moved *after* signature verification, which is a
behaviour change from the previous ordering. Rationale: with the old order, a caller who merely
guessed a valid `X-API-Key` could distinguish `403` ("that key exists but isn't bound to your
network") from `401`, learning something about a key it cannot actually use. All CIDR tests still
pass unchanged because the test helper signs every request that carries a key.

Timestamp validation runs first purely as a cheap gate: it needs no database round-trip, so an
unauthenticated flood of stale requests never costs a query.

### `signing_secret`: why it is encrypted rather than hashed

`key_hash` is a one-way hash, but a signing secret must be recoverable *verbatim* to verify an HMAC,
so hashing is not an option. Hence AES-GCM-256 (`src/crypto.rs`) when `VAULT_ENCRYPTION_KEY` is set,
raw storage otherwise. Specifics:

- The env var is **SHA-256'd** to derive the 32-byte key, so operators can supply a passphrase of any
  length instead of hitting a "must be exactly 64 hex chars" footgun. Deterministic, so the same
  passphrase always opens the same database.
- Sealed values are tagged `aesgcm256:<hex nonce><hex ciphertext‖tag>`. Detection keys off **the
  prefix, not off whether the env var is currently set** — that makes enabling encryption on an
  existing database non-destructive (old raw rows keep working), and makes a *removed* key surface as
  a loud error instead of silently handing ciphertext to the HMAC and producing a baffling `401`.
- Fresh random 12-byte nonce per value (GCM loses all confidentiality on nonce reuse). A unit test
  asserts the same plaintext seals to two different ciphertexts, and that flipping one ciphertext
  byte is caught by the auth tag.
- `Model::signing_secret` carries `#[serde(skip_serializing)]` as a standing guard: `api_key::Model`
  derives `Serialize` and rides in request extensions, so the annotation prevents a future endpoint
  from leaking the secret by serializing a whole model. An integration test asserts neither
  `GET /api/auth/me` nor `GET /api/keys` mentions it, and the E2E suite greps the key listing too.

Rotation replaces **both** credentials. Leaving the old signing secret in place would defeat the
purpose of rotating after a compromise, and it doubles as the upgrade path for pre-existing keys.

### Migration strategy for existing databases

Added as a separate additive migration (`m20260729_000002_add_api_key_signing_secret`) rather than by
editing the initial schema — that migration has already run on existing databases and would never
re-run. The column is **nullable**, so the `ALTER TABLE` cannot fail on a populated table.

Existing keys therefore carry `NULL` and **cannot authenticate**; they fail closed with a `401`
naming the fix (`POST /api/keys/{id}/rotate`). Back-filling random secrets in the migration was
considered and rejected: a secret generated inside a migration can never be shown to its owner, so it
would be unusable anyway — silently converting "must rotate" into "permanently broken".

The new migration re-declares the `ApiKeys` iden locally instead of importing it from the initial
schema module. Making that module `pub` would have exported a dozen undocumented public enums and
tripped the crate's `#![warn(missing_docs)]`.

### Test-suite convention (the reason the diff is ~105 lines wide but shallow)

Every `/api/*` request in `tests/` now needs a timestamp and a signature. Rather than thread a second
credential through ~105 call sites by hand, keys seeded directly into the database use a deterministic
signing secret derived from their plaintext key (`test_signing_secret`), so the `signed()` helper
recovers it from the request's own `X-API-Key` header. The 105 sites were converted mechanically
(`inject_connect_info(B).body(X).unwrap()` → `signed(inject_connect_info(B), X)`) by a script, and
the compiler plus the full suite verified the result — no call site needed individual review.

Keys minted through `POST /api/keys` or `/rotate` get a server-generated random secret and use
`signed_with(...)` explicitly. Those tests now also hold `ENV_MUTATION_LOCK`, even though they set no
env var themselves: whether their key's secret is sealed is decided by `VAULT_ENCRYPTION_KEY` *at
creation time*, so a concurrent encryption test clearing it in between would leave them unable to
decrypt their own secret. That was a latent flake, not an observed one — caught by reasoning about
the shared global rather than by a failure.

8 new integration tests and a new E2E section (§1b) cover the auth surface directly: each of the
three headers individually mandatory (including the exact pre-HMAC "key + timestamp" shape), the
replay window enforced symmetrically using *correctly signed* stale/future timestamps (so the
rejection provably comes from the freshness check and not the HMAC), and signature binding to method,
path and body (an authentic `/api/ban` signature replayed onto `/api/white`, or over a tampered body,
must fail). The E2E suite now boots the server **with** `VAULT_ENCRYPTION_KEY` set, so the whole run
exercises the seal/open path rather than the plaintext fallback.

`scripts/test_e2e.sh` signs via `openssl dgst -sha256 -hmac` (now a hard preflight dependency) and
keeps a `key -> secret` map so all ~180 pre-existing call sites were left untouched.

### Frontend

`app.js`'s fetch wrapper signs every call with the Web Crypto API. The secret is imported as its raw
**UTF-8 bytes**, not hex-decoded — the server keys its HMAC with `secret.as_bytes()`, i.e. the ASCII
bytes of the hex string, so decoding to 32 bytes would silently fail every check. The imported
`CryptoKey` is memoized and invalidated through `setCredentials()`, which writes/clears both
localStorage entries together so the key and secret can never drift out of sync.

Two consequences worth flagging:

- **`crypto.subtle` requires a secure context.** Served over plain HTTP to a LAN address, the
  dashboard cannot sign anything. The wrapper detects this and reports it explicitly instead of
  failing with an opaque `401`, and both `AGENT.MD` and `README.md` now say to deploy behind TLS.
  This is a genuine new deployment constraint on the UI, not a code defect.
- Rotating the key you are logged in with now invalidates your own session. Handled explicitly:
  the new credentials are shown in the reveal modal (z-index 20000, layered above the login screen at
  10000, so they stay readable) and the session logs out deliberately rather than appearing to fail
  at random.

### UI fixes

- **Modal actions**: `justify-content: space-between` → `flex-end`, so Cancel sits immediately left of
  Confirm as a right-aligned pair instead of being pushed to the opposite edge of the card. Cancel got
  a dedicated `.btn-cancel` bluish-slate theme (`#1e293b` / `#60a5fa`, hover `#2563eb`) rather than the
  generic dark grey `.btn-secondary`.
- **Batch delete visibility**: hidden outright (`display: none`) at 0 selections instead of merely
  disabled. Toggled at the single existing choke point (`wireRowSelection`'s `updateControls`), on both
  the button and its `.batch-actions` wrapper so the row reclaims its vertical space. The containers
  are also `hidden` in the initial markup, so there is no flash of a dead button before first render.
- **API Keys tab spacing**: new `.batch-actions-keys` adds `margin-top: 1.5rem` plus a hairline rule,
  separating "Delete Selected" from the "Create API Key" form (and the key-reveal box between them)
  that it was previously flush against.

### Known limitation introduced (not fixed — needs a decision)

**Chaining `simply_ip_vault` instances via webhooks is now broken.** `AGENT.MD` §4 advertises setting
`X-API-Key` in a webhook's `headers_json` to forward events to another instance. An outbound dispatch
signs *the payload alone* with the webhook's `secret_token` and sends no `X-Timestamp`; a receiving
instance now demands a timestamp plus a signature over `METHOD + PATH + TIMESTAMP + RAW_BODY` keyed by
the *receiving key's* `signing_secret` — different message, different key — so the dispatch gets `401`.

Not fixed here because a correct fix changes webhook semantics (the dispatcher would need to emit
vault-style auth headers derived from the target key's signing secret, which would break generic
third-party consumers of the existing payload signature) and that is a design decision outside this
task's scope. Documented inline in `AGENT.MD` §4 so it cannot be rediscovered by surprise. Webhooks to
ordinary third-party endpoints are entirely unaffected.

### Also updated

`README.md`: the env-var table gained `VAULT_ENCRYPTION_KEY`, the API reference documents the
three-header scheme, the bootstrap banner sample was refreshed (it now prints the signing secret, and
the box is drawn against a computed width — the old hardcoded one never actually aligned around a
64-char key), and every `curl` example was rewritten around a copy-pasteable `call()` signing helper,
since a bare `curl -H "X-API-Key: ..."` no longer works at all.

---

## 2026-07-30 (session 19) — CANONICAL_V1 signing, webhook signature modes, signing-secret rotation, SPA crypto fallback

Harmonized the inbound auth engine and the outbound webhook dispatcher onto one canonical signature
format, added a per-webhook signature mode, a narrow signing-secret rotation endpoint, and a pure-JS
HMAC fallback so the dashboard works over plain HTTP.

### Results

| Check | Result |
| --- | --- |
| `cargo check --all-targets` | ✅ clean |
| `cargo clippy --all-targets -- -D warnings` | ✅ clean |
| `cargo test --all-targets` | ✅ **56/56** (6 crypto unit + 50 integration, up from 48) |
| `./scripts/test_e2e.sh` | ✅ **233/233** (up from 195; +38 new checks) |

### The inbound signature format changed — a second breaking change

The task brief specifies CANONICAL_V1 as `METHOD\nPATH\nTIMESTAMP\nRAW_BODY` "for incoming API
requests **AND** outgoing Webhook dispatches". Session 18 had shipped the inbound format as plain
concatenation with **no** separator, so honouring "harmonize" meant changing the inbound format too,
not just adding the webhook one. Every signer moved in lockstep: `crypto::canonical_v1_payload`,
the test helper, `scripts/test_e2e.sh`'s `hmac_sign`, `app.js`, and the `curl` helpers in `AGENT.MD`
and `README.md`. Clients written against session 18's format break; that is inherent to the request.

The delimiter is a genuine improvement, not just a compatibility choice, and there is now a test
pinning it (`delimiter_removes_field_boundary_ambiguity`): under plain concatenation
`("POST", "/api/ban")` and `("POS", "T/api/ban")` hash identically, so a signature over one is a
valid signature over the other. `\n` cannot occur in an HTTP method or a URL path, so the encoding
becomes unambiguous. The empty-body case keeps its trailing delimiter, so "no body" stays
distinguishable from a body that begins where the timestamp ended.

### Webhook signature modes

`webhook_configs.signature_mode`, `TEXT NOT NULL DEFAULT 'BODY_ONLY'` via an additive migration, so
applying it changes nothing about how existing webhooks are delivered.

- `BODY_ONLY` (default, unchanged): HMAC over the body alone, `X-Signature-256: sha256=<hex>`.
- `CANONICAL_V1`: HMAC over `POST\n<path>\n<timestamp>\n<body>` where `<path>` comes from
  `target_url`, sent as **bare hex** alongside an `X-Timestamp` header.

Bare hex vs the `sha256=` prefix was a deliberate split: `CANONICAL_V1` output must be byte-identical
to what the inbound middleware produces, since the entire point is that a dispatch can authenticate
as a normal API request. `BODY_ONLY` keeps its prefix because GitHub-style third-party receivers
expect exactly that, and a silent change there would break real integrations. (The middleware accepts
either form, so this is about matching each *receiver's* expectations, not about our own parsing.)

Modelled as a real `SignatureMode` enum rather than stringly-typed comparisons, so a future third mode
is a compiler-enforced exhaustive match. Two deliberate asymmetries in how invalid values are treated:

- **At the API boundary** an unrecognized `signature_mode` is a `400`, never a silent downgrade. A
  caller who believes they enabled canonical signing would otherwise deploy a receiver that rejects
  every dispatch, with nothing in the response to point at.
- **When read from the database** an unrecognized value falls back to `BODY_ONLY` with a warning. One
  hand-edited or downgraded row must not take the whole webhook worker down.

### This fixes the chaining limitation flagged in session 18

Session 18 recorded that instance chaining had been broken by HMAC auth, and left it as a decision to
be made. `CANONICAL_V1` is that decision, implemented without disturbing generic receivers: point a
webhook at another instance's `/api/ban`, set `secret_token` to the *receiving* key's signing secret,
put that key in `headers_json` as `X-API-Key`, and the dispatch arrives as an ordinary signed,
timestamped API request that passes the receiver's own anti-replay check. `AGENT.MD` §4's warning has
been replaced with the working recipe.

### `POST /api/keys/{id}/rotate-secret`

Deliberately a *separate* endpoint from the existing `/rotate` rather than a flag on it, because the
two have very different blast radii. `/rotate` reissues the API key itself, forcing every client to be
reconfigured with a new identity. `/rotate-secret` re-keys only the HMAC while id, name, `key_hash`,
`bound_ips`, global scopes and every `api_key_group_permissions` row stay exactly as they were — the
right tool for routine hygiene, and the recovery path for a `NULL` `signing_secret` left by session
18's migration. A test asserts the response carries no `plaintext_key`, so the two can never quietly
converge.

The UI handles self-rotation differently from `/rotate` for the same reason: rotating your own key via
`/rotate` logs you out (the API key changed), whereas `/rotate-secret` re-signs the live session in
place with the new secret, since the key you authenticate with is still valid.

### Pure-JS HMAC fallback

`crypto.subtle` exists only in a secure context, so session 18's dashboard could not authenticate at
all when served over plain HTTP to a LAN address — which is the normal way a homelab tool is reached.
`app.js` now carries a dependency-free SHA-256 + HMAC implementation and picks Web Crypto whenever it
is available, falling back automatically otherwise.

**Verification without a JS runtime.** No `node`/`deno`/`qjs` is installed on this machine, so the
implementation could not be executed. Instead it was transliterated 1:1 into Python and checked
against `hashlib`/`hmac` across every SHA-256 input length from 0–199 plus the block-boundary cases
(439/440/447/448/449/511/512/513/1000) and 56 HMAC key×message length combinations including keys
shorter than, equal to, and longer than the 64-byte block — all matching. That validates the constants
and the algorithm; JS-specific correctness was covered separately by a structural scanner (bracket
balance, string/template/comment termination) and by cross-checking all 87 literal
`getElementById` targets against `index.html`. Worth redoing properly if a JS runtime ever lands here.

Two JS-specific details that are easy to get wrong and are commented in place: the 64-bit length field
is built with `Math.floor(bitLen / 2**32)` rather than a shift (JS bitwise ops truncate to 32 bits),
and intermediate sums are reduced with `>>> 0`, which is correct even when an operand is a negative
int32 because ToUint32 adds 2^32.

The fallback is **not** constant-time. That is an accepted, documented trade-off rather than an
oversight: it only ever runs on a plain-HTTP connection where the request and all its headers are
already fully visible on the wire, so a browser-side timing side-channel is not the weak link. Web
Crypto still wins wherever it exists, and TLS remains the recommendation.

### Tests

6 new integration tests and 38 new E2E checks. The E2E mock receiver was upgraded from writing a bare
`hit\n` per delivery to one JSON object per line carrying path/headers/body — still exactly one line
per hit, so §13's existing `wc -l` counting is unaffected, but now enough to verify a dispatch.

Both signature modes are verified **live** against that receiver, not just at the API contract level:
a `CANONICAL_V1` dispatch is captured and its signature recomputed from the observed path, timestamp
and body, and a `BODY_ONLY` dispatch through the same receiver is asserted to still be
`sha256=`-prefixed with no `X-Timestamp` — the regression guard for third-party consumers. The
integration test additionally round-trips the captured bytes back through `crypto::verify_signature`,
i.e. literally the function the inbound middleware calls, closing the loop on the interoperability
claim.

`test_rotate_secret_swaps_only_the_signing_secret` asserts the *negative* space explicitly — name,
scopes, and the per-group grant all survive — because "rotation didn't disturb anything else" is the
whole contract of that endpoint and would otherwise be untested.

---

## 2026-07-30 (session 20) — Webhook auth modes, dynamic HMAC templates, proxy-aware SPA signing

### Scope

Four dispatch auth modes replacing the two signature modes from session 19, a user-editable HMAC
template so a webhook can be made to match any receiver's canonicalization, and the SPA change that
lets the dashboard work behind a path-rewriting reverse proxy. Inbound API authentication is
untouched — it remains strictly CANONICAL_V1 with no per-key configurability, deliberately, since a
configurable *verifier* is an attack surface in a way a configurable *signer* is not.

### `signature_mode` → `auth_mode`: replaced, not added beside

`signature_mode` could only ever answer "how do I sign?". Real receivers also want "authenticate with
a key and no signature" and "send nothing"; expressing those with a second column would have created
two fields that can contradict each other. `auth_mode` is a strict superset — its `BODY_ONLY` and
`CANONICAL_V1` mean exactly what the old values meant — so the migration replaces the column.

The migration is add → backfill → drop rather than a rename, for one specific reason: the new default
is `CANONICAL_V1` and no portable `ALTER TABLE` can change an existing column's default. **The
backfill is the load-bearing part.** Without it the new default would rewrite every existing
`BODY_ONLY` webhook to canonical signing, and their receivers would reject the very next event. A test
(`test_auth_mode_migration_preserves_existing_rows_and_reverses_cleanly`) seeds a row, runs `down`,
then `up` again, and asserts the row keeps `BODY_ONLY` — i.e. that the backfill, not the default, is
what decided its value.

`POST /api/webhooks` still accepts `signature_mode` as a deprecated alias, so callers written against
session 19 keep working. Only `auth_mode` is emitted on the way out.

**This is a behaviour change worth flagging:** a webhook created with *no* mode specified now gets
`CANONICAL_V1` where it previously got `BODY_ONLY`. That is what the brief specified. Existing rows
are unaffected (see the backfill above); only newly created webhooks that omit the field are.

### Single-pass template resolution

`resolve_hmac_template` expands escapes (`\n`, `\r`, `\t`, `\\`) and placeholders (`{method}`,
`{path}`, `{timestamp}`, `{body}`) in **one left-to-right scan**. This is a security property, not a
performance one, and the obvious "simpler" implementations are both broken:

- *unescape, then `.replace()`* — a body containing the characters `{path}` gets the target path
  substituted into it, after the body was already placed in the signed string.
- *`.replace()`, then unescape* — a body containing `\n` gains real newlines, letting it forge field
  boundaries in the canonical string.

Neither is hypothetical: the payload template interpolates `$cause`, which is attacker-influenced text
from an IP record. `substituted_values_are_never_rescanned` pins this down. The escape layer exists at
all because the template is edited in a single-line HTML input, where a real newline cannot be typed.

The "hardcoded path overrides `{path}`" behaviour the brief asked for needs no code — a template that
never mentions `{path}` simply never substitutes it. That is why it is a documented property rather
than a feature: there is nothing there to break.

### Validation at configuration time, not dispatch time

Three preconditions are `400`s on `POST /api/webhooks` rather than warnings in the worker:

1. A signing mode with an empty `secret_token` — an HMAC keyed with the empty secret is forgeable by
   anyone while still *looking* authenticated, which is strictly worse than sending nothing.
2. `API_KEY_ONLY` with no `api_key` — silently identical to `NONE`.
3. An `hmac_template` without `{body}` — signs a constant, replayable across every payload.

A webhook is configured once and dispatches forever in the background; a mistake caught at dispatch
time surfaces only as a log line the operator is not watching.

`AuthMode::from_stored` still falls back to `BODY_ONLY` — deliberately **not** the new column default,
and never `NONE`. An unreadable mode must resolve to *more* authentication, not less.

### Two base paths in the SPA

`this.apiBase` split into `requestBase` (where to send) and `signingBase` (what to sign), because
behind a prefix-stripping proxy they are genuinely different strings and no single value is correct
for both. `requestBase` is derived from the page's own directory, so a `/vault/` mount needs no
configuration to reach the API; `signingBase` is the login screen's **API Base Path Override**,
because what the vault process sees after rewriting is unknowable from the browser. Served at `/`,
`deriveRequestBase()` yields `/api` — byte-identical to the old hardcoded value, so direct
deployments are unchanged.

The failure mode when these are conflated is total and silent-looking: every request 401s, including
the first, with nothing in the response to suggest the path is the problem. Hence the explicit
callout in `AGENT.MD` §5 and `README.md`.

### UI

Auth Mode dropdown plus conditionally-shown API Key and HMAC Signature Template fields.
`syncWebhookAuthFields()` keeps `required` in step with visibility — a hidden `required` input makes
the browser refuse to submit while reporting the error on an element nobody can see, which reads as a
dead button. Hidden fields are also omitted from the request body, so a value typed under one mode and
then hidden cannot be persisted invisibly.

`NONE` is badged in the danger colour and `API_KEY_ONLY` in the warning colour. Both are legitimate
choices, but an unauthenticated dispatch should never look ordinary in a list of otherwise-signed
ones.

### Tests

| Suite | Before | After |
| :--- | :--- | :--- |
| `cargo test` | 56 | 67 (13 unit + 54 integration) |
| `scripts/test_e2e.sh` | 233 | 261 |

The 7 new unit tests live in `webhooks.rs` next to the resolver; the 4 new integration tests cover the
migration round-trip, the per-mode preconditions, a custom template with a hardcoded path, and the two
unsigned modes.

Every live dispatch assertion is made **negatively as well as positively**: the custom-template test
checks that the template's path validates *and* that the `target_url`-derived path does not, because
the positive check alone passes for the wrong reason if the override silently didn't happen. The
`API_KEY_ONLY`/`NONE` tests assert the *absence* of `X-Signature-256` and `X-Timestamp`, not merely
that delivery occurred.

The E2E mock receiver now also records `X-API-Key`. New §23 exercises the executor-shaped case end to
end: post to `/proxied/path`, sign `/api/hooks/42/execute`, verify both.

## 2026-07-30 (session 21) — Adversarial security review: SSRF bypasses fixed, regression suite added

### Scope

An attack-oriented review of `crypto.rs` and `webhooks.rs` — timing attacks, SSRF, template
injection — followed by a dedicated regression suite (`tests/security_tests.rs`) that replays each
attack and asserts it fails. No functional behaviour changed except the SSRF fixes below.

### Timing attacks — no finding

`crypto::verify_signature` is the only place a signature is compared, and it uses
`Mac::verify_slice`, which is constant-time. Grepping the whole of `src/` for `==`, `!=`, `.eq(` and
`.contains(` against any signature/HMAC-derived value returns nothing. There is no second comparison
path to miss: the webhook dispatcher only ever *produces* signatures, never verifies them.

Worth stating explicitly because it is easy to reintroduce: `verify_slice` takes the **expected tag
bytes**, so the `hex::decode` of the caller's input happens first and a non-hex signature is rejected
before the MAC is consulted. That early return is not a timing leak — it reveals only the encoding of
the input the caller already knows, not any part of the true digest.

### Template injection — no finding

`resolve_hmac_template`'s single-pass design (session 20) holds up under the specific attack it was
built for. The reasoning, restated as the property the tests now pin:

Substituted values are appended to `out` and `rest` advances *past* the placeholder, so no byte of a
substituted value is ever re-examined by the loop. `out` is never read back. Therefore for any body
`B`, the resolved string under the default template is exactly `POST\n<path>\n<ts>\n` ++ `B` — `B`
contributes no bytes to the first three fields regardless of its content. A receiver that splits into
**exactly four** fields (`splitn(4, '\n')`) recovers the true method, path and timestamp for every
`B`. The injected `\n` and `{path}` land wholly inside field four.

The one caveat, which is a *receiver-side* contract rather than a defect here: a receiver that splits
unbounded (`split('\n')`) and then indexes, or that validates a field count, will misparse a body
containing newlines. That is why the four-field split is the documented contract.

### SSRF — two real bypasses found and fixed, one documented as future work

The existing `is_url_safe` check was sound in intent but had gaps that fully defeated it:

**1. Redirects were followed without re-screening (fixed).** `Client::builder()` never set a redirect
policy, so `reqwest`'s default of following up to 10 hops applied. `is_url_safe` screens only the
*configured* `target_url`. A webhook pointed at an attacker-controlled public host that answers
`302 Location: http://169.254.169.254/latest/meta-data/` would therefore have the SSRF filter pass on
the public host and then follow the redirect to the metadata service — delivering the signed payload
and `X-API-Key` there. This is the whole control bypassed with a single response header. Now
`.redirect(Policy::none())`; a 3xx from a receiver surfaces as a failed delivery instead of being
followed silently.

**2. IPv4-mapped IPv6 was not normalized (fixed).** `Ipv6Addr::is_loopback()` is `false` for
`::ffff:127.0.0.1`, and the v4 rules were never applied to the mapped form, so
`http://[::ffff:127.0.0.1]/` walked straight through. `middleware.rs` already normalized inbound
addresses this way (`normalize_ip`) — the two directions were inconsistent, which is what made this
easy to miss. The blocklist is now a pure function, `is_blocked_address(IpAddr)`, that unwraps mapped
addresses first, and is unit-tested against address literals with no DNS involved.

Also tightened while in there: only the *first* resolved address was checked, so a hostname with two
A records (one public, one `127.0.0.1`) could pass the gate on one record while the HTTP client
independently picked the other — now every resolved address is screened and an empty resolution fails
closed. Added the ranges the original check missed: 100.64.0.0/10 (CGNAT, common for internal service
meshes), 0.0.0.0/8, 192.0.0.0/24, 198.18.0.0/15, broadcast and documentation ranges. Non-http(s)
schemes are now rejected in `is_url_safe` rather than left to the HTTP client.

**3. DNS rebinding remains open — deliberate, needs a connector (NOT fixed).** This is still a
check-then-connect design: `is_url_safe` resolves the host, and `reqwest` resolves it again
independently when it connects. A DNS server answering differently between those two lookups (short
TTL, round-robin) defeats the check no matter how good the blocklist is. Closing it properly means
resolving **once** and pinning the resulting socket address for the connection — i.e. a custom
`reqwest` connector, or `resolve()` on the client builder with a per-request override. That is a
larger change than this session's scope and is left as explicit future work.

Until then the mitigations are: `ALLOW_PRIVATE_WEBHOOKS` defaults to `false`, redirects are refused,
and webhook creation requires `can_manage_webhooks` — so the attacker must already be a privileged
operator. **This is a real residual risk, not a theoretical one**, and should be the next thing done
to `webhooks.rs`.

### `tests/security_tests.rs`

A separate binary from `rbac_integration_tests.rs`, with its own duplicated fixture setup. The
duplication is intentional: a refactor of the functional harness must not be able to silently weaken
the security assertions. Every test is named for the attack it replays, so a failure reads as "this
vulnerability is open" rather than "a test broke".

Two patterns worth keeping when extending it:

- **Every attack probe carries an otherwise-valid request.** The timestamp tests send a
  *cryptographically correct* signature over the stale timestamp, so only the freshness check can
  reject them — a test that sent a bad signature would pass even with the anti-replay check deleted.
  Each attack block also asserts a positive control first, so a broken fixture returning a blanket
  401 fails loudly instead of passing everything.
- **The signature forgery test keeps the mutated signature valid hex.** Mangling it into non-hex
  would have it thrown out by `hex::decode` before `verify_slice` is ever reached, and the test would
  pass without exercising the constant-time comparison at all. `flip_last_hex_digit` swaps `0`↔`1` for
  exactly this reason. The suite also covers truncated and over-long signatures sharing a valid
  prefix, which is what a length-agnostic or prefix-only comparison would accept.

The injection test drives the *real* attacker path rather than calling the resolver directly:
`cause` → `POST /api/ban` body → `$cause` substitution → dispatched payload → `{body}` field of the
signed string. It asserts the injection reached the payload verbatim (otherwise the test proves
nothing), that the signature covers the true path and timestamp, and — negatively — that the injected
`POST /api/fake @123456` does *not* verify against the delivered signature.

### Tests

| Suite | Before | After |
| :--- | :--- | :--- |
| `cargo test` | 67 | 77 (15 unit + 54 RBAC + 8 security) |
| `scripts/test_e2e.sh` | 261 | 271 |

The 2 new unit tests are the SSRF blocklist and URL screening in `webhooks.rs`. The 10 new E2E checks
cover omitting `X-Timestamp` in `CANONICAL_V1` mode (on both a signed POST-with-body and a signed
GET, so the rejection cannot be attributed to body handling), an empty `X-Timestamp`, first/last
character signature flips, truncated and over-long signatures, and the empty/lowercase/aliased
`secret_token` preconditions on webhook creation.

### Observation not acted on

`secret_token` is checked with `.is_empty()` while `api_key` is `.trim()`-ed first, so a
whitespace-only `secret_token` is accepted for `CANONICAL_V1`. It is a weak operator-chosen secret
rather than an attacker-reachable flaw — and trimming would silently change the signing key of any
existing webhook whose secret legitimately has surrounding whitespace. Left as-is; noted so the
inconsistency is a decision rather than an oversight.

## 2026-08-01 (session 22) — XFF spoofing, RBAC master escalation, permission self-granting

### Scope

Audit prompted by findings in the sister project `simply_hook_executor`, on the theory that both
share flawed boilerplate. They do. Six distinct escalation paths were live, four of them reachable by
any holder of a *delegated* scope — i.e. exactly the keys an operator hands out believing they are
limited.

### 1. `X-Forwarded-For` was trusted unconditionally

The middleware took the rightmost `X-Forwarded-For` entry (falling back to `X-Real-IP`) from **any**
peer. Both are ordinary request headers. `bound_ips` was therefore not a network restriction at all:
any client, anywhere, could satisfy an arbitrary CIDR by writing an allowed address into a header.
The prior test `test_reverse_proxy_xff_extracts_rightmost_trusted_hop` did not catch this because it
only proved that the *leftmost* (client-supplied) entry is ignored — with no trusted-proxy concept,
the rightmost entry is equally client-supplied when there is no proxy in front.

New `src/config.rs` holds `TRUSTED_PROXIES` (comma-separated IPs or CIDRs; a bare address is promoted
to a single-host network) and the resolution logic. `resolve_client_ip(peer, headers, trusted)` is a
**pure function** — no environment, no state — which is why it carries 11 unit tests covering cases
that would be awkward through the HTTP stack.

The algorithm: if the TCP peer is not itself inside `TRUSTED_PROXIES`, the headers are not read at
all. If it is, `X-Forwarded-For` is walked **right to left, skipping entries that are themselves
trusted proxies**, and the first remaining address is the client. Rightmost-first is what makes a
client-supplied prefix unforgeable (each proxy appends the address it actually saw). Skipping trusted
entries is what makes a *chain* work: with `client → P1 → P2 → us` the header reads `client, P1` and
the naive rightmost entry is `P1`, a proxy rather than the client.

**Breaking change, and the reason it is the right one:** `TRUSTED_PROXIES` unset means trust nothing,
so a proxied deployment that does not set it will reject every CIDR-bound key with `403`. That is the
safe direction to fail — the alternative is honouring a header the client writes — but it is a
silent, confusing failure if undocumented, so `main.rs` now warns loudly at startup in both
directions (set and unset).

The list lives in `AppState` rather than being re-read per request. It is an authorization input, and
a value that can change under a running process is one that cannot be reasoned about. It also lets
one test process exercise both the trusted and untrusted paths, which a process-wide env var cannot.
That cost 57 mechanical `AppState { .. }` → `AppState::new(..)` edits; `with_trusted_proxies` is the
test-only escape hatch.

### 2. Master keys were exempt from their own `bound_ips`

`if !is_allowed && !key_record.is_master` — the single most powerful credential in the system was the
only one whose network restriction was decorative. Worse than not offering the field: it silently
ignored a restriction an operator had explicitly configured. Removed. An *empty* `bound_ips` still
means unrestricted; that is how a key opts out, and it is unchanged.

### 3. `can_manage_keys` was transitively equal to `is_master`

Four separate paths, all reachable by a non-master key manager:

- `POST /keys` accepted `is_master: true` and returned the new key's plaintext in the same response —
  a **one-request** escalation from a delegated scope to full control.
- `POST /keys/{id}/rotate` against a master key returned a working master API key *and* signing
  secret. Complete, immediate takeover.
- `POST /keys/{id}/rotate-secret` — the same takeover, narrower blast radius.
- `PUT /keys/{id}` could rewrite a master key's `bound_ips` (relocating it to the attacker's network);
  `DELETE /keys/{id}` could remove the master keys that would otherwise contain the incident.

`guard_master_target` now gates every operation whose target is another key. `403` not `404`: the
caller legitimately holds `can_manage_keys` and can already see the key in `GET /api/keys`, so hiding
its existence buys nothing and makes a legitimate operator's failure inscrutable.

Separately, `PUT /keys/{id}` let a key **widen its own** global scopes. Narrowing is still allowed —
dropping a scope you hold is not an escalation — but widening now requires a second party.

### 4. Group permissions could be self-granted

`POST /keys/{id}/permissions` checked only `can_manage_keys`, so a caller could target its own id and
grant itself read/write/delete on any group in the system. Two rules now:

- **Self-granting is refused outright** for non-masters, rather than merely bounded by the rule
  below. The two are not equivalent: the "cannot grant beyond your own" check compares against the
  grants held *at this instant*, so a caller allowed to target itself could ratchet — grant itself
  `can_read` on a group it can already read, then use that row as the basis for widening. Requiring a
  second party for every self-affecting change removes the ratchet entirely.
- **Cannot grant what you do not hold**, per verb. Holding `can_read` on a group does not confer the
  right to grant `can_write` on it. Without this the accomplice pattern (grant a second key you
  control, then use it) walks straight around the self-grant rule.

The group auto-create path needs no special case: it grants the creator full permissions first, so
the subsequent lookup legitimately permits the delegation.

### 5. Webhook CRUD ignored per-group RBAC entirely

Not in the brief, found while auditing it. A webhook is a standing export of everything that happens
in its group, to a URL the creator chooses — so `can_manage_webhooks` alone let a key scoped to one
group subscribe to **every** group's events and stream them to a server it controls. `list_webhooks`
also returned every row regardless of group, leaking other tenants' target URLs and headers. Create,
list, update and delete are now all scoped to groups the caller can read (master bypasses). Delete and
update answer `404` rather than `403` for an invisible webhook, matching what the caller's own
listing shows.

### 6. `PUT /api/webhooks/{id}` — the endpoint the brief assumed existed

Task 4 asked to secure editing a webhook's `target_url`/`hmac_template`. **No update endpoint
existed** — routes were create, list, delete only — so there was nothing to patch. Rather than leave
the task unimplemented, the endpoint was added *with the mandated protection built in*, which also
removes the delete-and-recreate dance that was previously the only way to edit a webhook.

**Repointing rotates the secret.** If `target_url` or `hmac_template` changes, `secret_token` is
replaced — with the caller's value if supplied, otherwise generated and returned exactly once.

The attack this closes is indirect, which is what makes it easy to miss. `secret_token` is write-only
(no endpoint returns it, pinned by `attack_webhook_secret_is_not_recoverable_from_read_endpoints`), so
an editor cannot read it. Instead they point the webhook at a server they control and *wait*: the next
dispatch arrives at their endpoint carrying a valid `X-Signature-256` over a payload they influenced
via `$cause` — a working forgery oracle for the receiver's shared secret. Rotating on repoint means a
secret is only ever usable against the destination it was configured for.

`hmac_template` is treated identically because it decides *which bytes* the signature covers: a caller
who can rewrite it can make the existing secret vouch for content it never saw.

Comparison is against the **effective** current values, so re-submitting a field unchanged is not a
repoint. A dashboard that PUTs every field on every save must not churn the secret on each click.
Rotation is also skipped for `API_KEY_ONLY`/`NONE`, which have no secret worth protecting — minting
one there would produce a value that is never used and cannot be verified against anything.

### Tests

| Suite | Before | After |
| :--- | :--- | :--- |
| `cargo test` | 77 | 97 (26 unit + 54 RBAC + 17 security) |
| `scripts/test_e2e.sh` | 271 | 309 |

Three existing tests (`test_auth_and_cidr_rejection`,
`test_reverse_proxy_xff_extracts_rightmost_trusted_hop`,
`test_bound_ip_strictly_rejects_out_of_cidr_forwarded_address`) asserted the old always-trust-XFF
behaviour and now build state through a `proxied_state()` helper that trusts `127.0.0.1`. Their
original intent — that the *leftmost* hop is never honoured, and that out-of-CIDR is rejected — is
preserved exactly; what changed is that they now say *why* the header is believed.

**The E2E spoofing check is the one worth keeping.** `curl --interface 127.0.0.2` gives a real
untrusted TCP peer over loopback without a second machine (127/8 is entirely loopback on Linux), and
the run sets `TRUSTED_PROXIES=127.0.0.1` — deliberately not `.2`. So the same request, with the same
header, is honoured from `127.0.0.1` and ignored from `127.0.0.2`, which isolates the peer address as
the only variable. Guarded with a capability probe and a skip, since `--interface` against a 127/8
alias is Linux-specific.

Every escalation test carries a **positive control against a non-master target** — a guard that
returned 403 unconditionally would pass the attack assertions while having broken key administration
outright, and only the control catches that.

## 2026-08-01 (session 23) — Dynamic proxy resolution, IP soft delete + 92-day purge, SQLite WAL

### Scope

Completes the security parity pass against `simply_hook_executor` (now vendored at
`example/simply_hook_executor/` and audited directly) and adds the operational features the vault
was missing: recoverable IP deletion, container-friendly proxy trust, and SQLite concurrency
settings. Sessions 21–22 did the bulk of the security work; this session extends it rather than
repeating it.

### 1. `TRUSTED_PROXIES` now accepts hostnames, resolved at request time

The reference implementation parses `TRUSTED_PROXIES` as IPs and CIDRs only. That is fine for a
static deployment and useless in Docker or Kubernetes, where the proxy's address is assigned by the
orchestrator and changes on every recreate while its *name* is stable. Pinning a CIDR wide enough to
cover the whole bridge network re-opens the bypass for every container on it.

`ProxyMatcher` is now either a `Network` or a `Hostname`. Resolution happens in
`TrustedProxies::contains`, which is `async`, with a 30-second cache keyed on the name. The TTL is a
deliberate compromise: a recreated container is over-trusted at its *old* address for up to 30s and
under-trusted at its new one for the same window. Both windows are small; making the cache longer
trades safety for fewer lookups, and making it shorter puts a DNS round-trip on the request path.

**Divergence from the reference, kept on purpose:** the reference takes the rightmost
`X-Forwarded-For` entry unconditionally. This implementation walks the chain right-to-left *skipping
entries that are themselves trusted proxies*. In the single-proxy case the two are identical; with
chained proxies (`client → P1 → P2 → us`) the reference resolves to `P1` — a proxy — while this
resolves to `client`. The *validation* rule the task asked to match is identical: the peer, and only
the peer, decides whether a forwarding header is evidence.

The chain walk deliberately consults only *literal* networks (`is_literal_network`), never hostnames.
It runs per header entry, and firing a DNS lookup for each would put resolution latency on the
request path for no security gain — the decision that matters was already made by `contains`. The
consequence is narrow and conservative: a chained hop identified only by hostname is treated as a
client rather than skipped, resolving to that hop instead of the one behind it. It never trusts an
address further left than it should.

Parsing changed shape as a result. Anything that is not an address or CIDR but *could* be a DNS name
now becomes a hostname matcher, so a typo is no longer dropped at parse time — it becomes a name that
never resolves, which fails in the same safe direction. Only shapes that cannot be a hostname are
rejected outright, and `is_plausible_hostname` specifically rejects anything containing `/` so a
near-miss CIDR like `10.0.0.0/99` surfaces as a configuration error instead of silently becoming a
nonsense hostname.

### 2. RBAC: three scopes are now master-only to grant

Session 22 blocked minting `is_master`. This extends it to `can_manage_keys` and `can_create_groups`
on both the create and update paths, because each is a *path back to* master authority rather than a
leaf capability: the first mints co-administrators, the second mints groups whose creator is
auto-granted full read/write/delete (`AGENT.MD` §2), which is the one way to obtain group access
without a master signing off.

`can_manage_webhooks` is deliberately **not** on the list — it confers no authority over keys or
groups and is bounded by the caller's own group access, so a delegated key manager can still hand it
out. Without that exception the delegated role would have nothing left to delegate.

`guard_scope_elevation` compares against the target's *current* values, so re-submitting a scope a
key already holds is a no-op rather than a rejection. That matters for an idempotent `PUT` from a
dashboard that posts every field on every save.

### 3. Webhook repointing: privileged webhooks are master-only

Session 22 forced `secret_token` rotation on any `target_url`/`hmac_template` change. That is
sufficient when the only credential is the vault's own secret. It is *not* sufficient for a webhook
carrying an `api_key`: that credential belongs to the receiving system (instance chaining,
`AGENT.MD` §4), so rotating our secret does not invalidate it, and repointing aims a working remote
credential at a destination of the editor's choosing.

So for webhooks with a non-empty `api_key`, changing `target_url` or `hmac_template` now requires
master. Everything else about them — name, payload template, event filter, enabled/disabled — stays
editable by any `can_manage_webhooks` holder, and non-privileged webhooks are unaffected. Forced
rotation still applies on top, for both.

### 4. IP records: soft delete, master trash, 92-day purge

Migration `m20260801_000005` adds `is_deleted` / `deleted_at` / `deleted_by`, both flags indexed.
`deleted_by` is `TEXT` holding the acting key's UUID rather than a foreign key — a FK would either
block deleting that key later or null the attribution out via `ON DELETE SET NULL`, and the point of
an attribution field is that it survives the actor.

New `DELETE /api/ips/{id}` is **record-level** and distinct from the existing `DELETE /api/ips`
(query/body), which removes a membership in one group and leaves the record alone. Both still exist;
`AGENT.MD` §3 mandates the latter's flexible query/body contract.

A non-master can only ever soft-delete. The reasoning: `can_delete` on a group is a routine,
widely-handed-out scope, and the blast radius of it being misused — or of the key being stolen —
should be a recoverable mistake rather than permanent data loss. Making destruction master-only costs
a legitimate operator one extra step and costs an attacker the ability to cover their tracks.

Three details that are easy to get wrong and are pinned by tests:

- **The purge matches on `is_deleted = true` AND `deleted_at < threshold`, not the timestamp alone.**
  A restored record keeps no `deleted_at` (restore clears all three columns), but a hand-edited row
  or a future code path could leave one set — and filtering on the timestamp alone would then destroy
  live data. `purge_removes_only_records_past_the_92_day_retention_window` seeds exactly that row.
- **Re-registering a soft-deleted address resurrects it.** `target_address` is unique, so without
  this a delete would permanently deny that address until a master emptied the trash — a delete
  would function as a denial of service on the address.
- **A repeated soft delete does not move `deleted_at`.** Otherwise a caller could keep a record out
  of the purge indefinitely by re-deleting it.

`POST /api/system/purge-ips` rejects `older_than_days: 0` rather than treating it as "purge
everything": the difference between "empty the trash" and "empty the trash older than zero days" is
one character, and the destructive reading should never be what a typo selects. (`IP_RETENTION_DAYS=0`
in the *environment* does mean "disable purging", which is the opposite default and safe.)

### 5. SQLite WAL mode and busy timeout

`state::apply_sqlite_pragmas` sets `journal_mode=WAL` and `busy_timeout=5000`, guarded on
`get_database_backend() == Sqlite` rather than on the URL string. Called *before* migrations, so the
migration writes benefit too.

This is the one deliberate exception to the SQL-agnostic rule in `AGENT.MD`: `PRAGMA` is a syntax
error on PostgreSQL and MySQL. It configures the *engine*, not a query, and every other backend skips
it entirely. The applied `journal_mode` is read back and logged rather than assumed — it legitimately
comes back as `memory` for `sqlite::memory:` (which is what the whole test suite uses), and an
operator debugging lock contention needs to know which mode is actually in force.

### Tests

| Suite | Before | After |
| :--- | :--- | :--- |
| `cargo test` | 97 | 110 (31 unit + 54 RBAC + 25 security) |
| `scripts/test_e2e.sh` | 309 | 360 |

`clippy --all-targets -- -D warnings` is clean.

**The E2E run now sets `TRUSTED_PROXIES="localhost"` rather than `127.0.0.1`** — spelled as a
hostname on purpose, so the whole suite's proxy-dependent checks exercise the dynamic DNS path
against a real resolver end to end, not just the literal-CIDR path the unit tests cover. It still
resolves to `127.0.0.1` and still deliberately excludes `127.0.0.2`, which §6b connects from via
`curl --interface` to prove the untrusted-peer rejection.

**One pre-existing E2E flake fixed, not papered over.** `a 301s-future timestamp is rejected` captured
`NOW_TS` once near the top of the script and asserted `NOW_TS + 301` was rejected. Elapsed wall-clock
time moves a *future* timestamp toward the window (at one second elapsed the skew is 300, which is
legitimately inside it), so the check only passed when the request landed in the same second the
timestamp was captured. It now captures fresh immediately before the call and uses a margin clear of
the boundary. The stale direction keeps `301` unchanged — a stale timestamp only gets staler, so it
can never drift back inside. The exact ±300/±301 edge stays pinned deterministically in
`tests/security_tests.rs`, where the request is handled in-process microseconds after the timestamp
is chosen; E2E asserts the behaviour, not the boundary.

Two other existing tests needed updating, both because they encoded assumptions this session
invalidated rather than because they broke:

- `attack_non_master_cannot_mint_a_master_key`'s control granted `can_create_groups`, which is now
  master-only; it uses `can_manage_webhooks` instead and gained explicit coverage of the two newly
  restricted scopes.
- `test_auth_mode_migration_preserves_existing_rows_and_reverses_cleanly` called
  `Migrator::down(Some(1))`, which unwinds from the *newest* migration — so adding the soft-delete
  migration silently retargeted it. It now derives the step count by locating the auth-mode migration
  in the registry by name, so future migrations cannot turn it into a test of something else.
