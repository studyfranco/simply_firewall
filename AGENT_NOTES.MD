# AGENT NOTES

> This file is the living worklog for the `simply_firewall` implementation & audit sweep.
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
