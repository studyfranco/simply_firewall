# Comparative Security Audit — `simply_ip_vault` ↔ `simply_hook_executor`

**Date:** 2026-08-02
**Mode:** Strictly read-only. No source file in `src/` or `./example` was modified; no commit was created. This report supersedes the 2026-08-01 edition (committed as `ca6ecf4`), which predates both projects' convergence passes.

---

## 0. Reference freshness

### 0.1 Reference commit

**`./example` is not a git checkout, so no commit hash exists to record.**

| Probe | Result |
| :--- | :--- |
| `git -C example/simply_hook_executor rev-parse --show-toplevel` | `/home/fallrik/.../simply_ip_vault` — resolves to the **parent** repo, not a nested one |
| `.git` directory inside `example/simply_hook_executor/` | absent |
| `.gitmodules` | absent — not a submodule |
| `git ls-files example` | 0 files — untracked |
| `.gitignore` | line 9: `example/*` — deliberately excluded |

`./example` is an untracked, ignored working copy of the sibling project. The closest available markers are file timestamps and the reference's own notes:

| Marker | Value |
| :--- | :--- |
| Newest source file (`src/db.rs`, `src/crypto.rs`) | 2026-08-02 00:18 |
| Newest file of any kind (`AGENT_NOTES.MD`) | 2026-08-02 00:26 |
| Directory mtimes (`src/`, `tests/`, `scripts/`) | 2026-08-02 12:01 — the tree was re-copied today |
| Reference's own `AGENT_NOTES.MD` section markers | `## 2026-08-01 — Convergence pass (shared arbitrated architecture)`, `## Convergence Parity Check` |
| This repository's HEAD | `f544ff406202e7969afcff80f8659b4b095c7fa5` — 2026-08-02 11:47:36 +0200 |

### 0.2 Freshness verdict

> ### ⚠ Reference freshness: UNVERIFIED — findings below may reflect an outdated `simply_ip_vault`
>
> There is no commit, tag, or version marker in `./example` to compare against its upstream, so its currency cannot be established by any means available inside this repository. Its file content predates this repository's HEAD by roughly 11½ hours.

Two observations temper that flag, and both are worth stating because they change how much weight the findings carry:

- **The reference has demonstrably been refreshed since the previous cross-audit.** It now contains a dedicated `src/replay.rs` (227 lines) that did not exist when this repository's convergence pass was written, and its `AGENT_NOTES.MD` carries a completed *Convergence Parity Check*. The prior report's premise — that `./example` had gone stale — **no longer holds**. The reference has done its half of the arbitrated convergence.
- **The directory mtimes (12:01 today) postdate this repository's HEAD (11:47 today)**, consistent with the tree having been re-copied after the convergence commit landed. That is suggestive, not probative — mtimes are not provenance.

### 0.3 Correction: the two projects are transposed in the audit brief

The brief describes `simply_ip_vault` as living in `./example` and `simply_hook_executor` as the current repository. **This is inverted**, and it was inverted in the two preceding briefs as well.

| Location | `[package] name` | Distinguishing modules |
| :--- | :--- | :--- |
| Repository root (`.`) | `simply_ip_vault` | `src/webhooks.rs`, `api::handle_ban`, `ip_record` entity |
| `./example/simply_hook_executor/` | `simply_hook_executor` | `src/executor.rs`, `src/replay.rs`, `hook` entity |

The mandated column headers are therefore preserved in **position** but corrected in **label**, so that no cell in this report is attributed to the wrong codebase. The left project column is always the reference in `./example`; the right project column is always the current repository.

---

## 1. Proxy & IP middleware

Files: `src/config.rs`, `src/middleware.rs` on both sides.

| Aspect | `simply_hook_executor` (./example) | `simply_ip_vault` (this repo) | Assessment |
| :--- | :--- | :--- | :--- |
| `TRUSTED_PROXIES` entry kinds | `parse_trusted_proxies` → `ProxySpec::Network` \| `ProxySpec::Hostname`; bare address widened to `/32`/`/128`; malformed entry dropped with a warning | `parse_trusted_proxies` → `ProxyMatcher`, same two variants, same widening, same drop-with-warning | **Equivalent.** Both fail in the safe direction — a dropped entry is a proxy that is *not* trusted. |
| Hostname → address resolution | `resolve_hostname` via `tokio::net::lookup_host((host, 0u16))`, each address through `normalize_ip` | `resolve_hostname`, same call, same normalization | **Equivalent.** |
| Positive cache TTL | `TRUSTED_PROXY_DNS_TTL = 30s` | `POSITIVE_TTL = 30s` | **Equivalent.** Bounds how long a re-assigned container address stays trusted. |
| Negative cache TTL | `TRUSTED_PROXY_DNS_NEGATIVE_TTL = 5s` | `NEGATIVE_TTL = 5s` | **Equivalent.** Both bound DNS traffic to one query per name per window, closing the "request rate becomes query rate" amplification path. |
| Per-name vs. whole-set expiry | `HostnameEntry` per name in `ResolvedProxies.hosts`; `is_fresh` selects positive/negative TTL by the `resolved` flag | `HostnameState` per name in `ResolutionCache.hosts`; identical `is_fresh` | **Equivalent.** One failing name cannot drag healthy names into re-resolution on either side. |
| Thundering-herd guard | `resolved()` re-checks `all_fresh` under the write lock before calling `refresh_stale` | `resolved()` takes the write lock and calls `refresh_locked`, which re-checks per-name freshness inside its loop | **Equivalent outcome**, different placement. Both collapse a burst arriving on an expired entry into a single lookup. |
| Merged-snapshot rebuild | Rebuilt only `if changed` — i.e. only when a lookup actually ran | Rebuilt unconditionally at the end of every `refresh_locked` | **Reference marginally stronger.** The vault allocates a fresh `Vec` + `Arc` under the write lock even when no name was re-queried. Performance only; no trust decision changes. |
| Empty answer vs. lookup error | Distinguished: `Ok(addrs)` yielding zero addresses logs its own warning and returns `resolved = false` | Collapsed: `resolved = !addresses.is_empty()` | **Reference marginally stronger.** Same trust outcome; the vault cannot distinguish NXDOMAIN from "resolved to nothing" in its logs. Diagnosability only. |
| Boot-time priming | `prime_trusted_proxies` in `main.rs`, detached `tokio::spawn`, calls `prime()` with `force = true` | `TrustedProxies::prime_with_grace()`, detached `tokio::spawn`; `prime()` clears `cache.hosts` then refreshes | **Equivalent.** Both force a real lookup rather than reusing an answer a concurrent request just cached. |
| Boot grace period | `TRUSTED_PROXY_BOOT_GRACE = 60s`, one loud re-check, never aborts startup | `BOOT_GRACE_PERIOD = 60s`, one loud re-check, never aborts startup | **Equivalent.** Both explicitly reject crash-looping: an unresolvable entry is fail-closed for that entry alone, service-wide availability is preserved. |
| XFF trust precondition | `resolve_client_ip` returns `peer` verbatim unless `is_trusted(peer, trusted)` | Identical | **Equivalent.** This is the load-bearing control on both sides. |
| XFF chain walk | `.split(',')` → `filter_map(parse)` → `map(normalize_ip)` → `.rev().find(\|ip\| !is_trusted(*ip, trusted))` | Identical construction | **Equivalent.** Right-to-left, skipping exactly the trusted hops, stopping at the first untrusted one. |
| Chain exhausted / unparseable | Falls through to `X-Real-IP`, then to `peer` — never to an unvalidated claim | Identical | **Equivalent.** |
| Hostname-shape validation | `is_hostname_like`: rejects `/`, `:`, non-alphanumeric edges, all-digits-and-dots, length > 253 | `is_plausible_hostname`: same predicate set | **Equivalent.** Both refuse `999.1.1.1` and `10.0.0.0/8x` as names rather than turning a botched CIDR into a lookup that silently never matches. |
| `bound_ips` vs. master keys | `is_allowed = networks.is_empty() \|\| networks.iter().any(...)`; comment records that `is_master` once bypassed this and no longer does | Identical expression, identical recorded rationale | **Equivalent.** On both sides a populated `bound_ips` binds every key including master; empty is the only opt-out. |
| `bound_ips` check position | After authentication — the `// ── Authorization ──` block, `middleware.rs:334` | After authentication *and* replay checking — `middleware.rs:254` | **Equivalent.** Both close the 401-vs-403 network-binding oracle. |
| Dual-stack normalization | `normalize_ip` applied to the peer, every XFF hop, `X-Real-IP`, and resolved hostname addresses | Identical coverage | **Equivalent.** |

**Prose.** This category is fully converged; the only two rows scored as differences are an allocation and a log message, neither of which changes a trust decision. Both services independently arrived at the same non-obvious structural choice — flattening the whole trusted set into one `Arc<Vec<IpNetwork>>` snapshot *before* walking the chain — and that choice is what makes a hostname-identified intermediate hop skippable. A per-entry `is_literal_network`-style test returns false for every hostname matcher and would silently report the inner proxy as the client in exactly the containerized topology that hostname support exists to serve.

---

## 2. RBAC & privilege-escalation guards

Files: `src/api.rs` on both sides.

| Aspect | `simply_hook_executor` (./example) | `simply_ip_vault` (this repo) | Assessment |
| :--- | :--- | :--- | :--- |
| Scopes master-only to grant | `require_master_to_grant_scopes` (`api.rs:343`): `is_master`, `can_manage_keys`, `can_manage_hooks` | `MASTER_ONLY_SCOPES` (`api.rs:183`): `is_master`, `can_manage_keys`, `can_create_groups`; `can_manage_webhooks` deliberately delegable | **Domain-appropriate, not a discrepancy.** Each side gates the scopes that are a *path back to* master authority in its own model. The vault documents why `can_manage_webhooks` is excluded: it confers nothing over keys or groups and is bounded by the caller's own group access. |
| Idempotent re-submission of a held scope | Blocked — any `Some(true)` from a non-master is refused regardless of the target's current value | Allowed — `guard_scope_elevation` compares `requested` against the target's `held` array and refuses only `Some(true) && !current` | **Equivalent security; vault more ergonomic.** Re-asserting a scope the target already holds grants nothing. The reference's form is simpler to audit; the vault's supports a dashboard that PUTs every field. |
| Revoking a scope | Explicitly permitted to any key manager — "removing authority is not an escalation" | Same rule, same stated rationale | **Equivalent.** |
| `is_master` in the update payload | `UpdateApiKeyPayload` carries no `is_master` field; promotion via `PUT` is impossible | `UpdateApiKeyPayload` carries no `is_master` field; same | **Equivalent.** Both remove the escalation path at the type level rather than guarding it at runtime. |
| Non-master acting on a master *target* | `require_master_to_administer(key, target, action)` — `if !target.is_master \|\| key.is_master { Ok }` | `guard_master_target(caller, target)` — `if target.is_master && !caller.is_master { Forbidden }` | **Equivalent** — contrapositive forms of the same predicate. |
| Coverage of the master-target guard | 3 sites: `update_api_key` (2006), `delete_api_key` (2079), `rotate_api_key` (2129) | 4 sites: `delete_api_key` (1578), `update_api_key` (1621), `rotate_api_key` (1714), `rotate_signing_secret` (1771) | **Equivalent — full parity.** The vault's fourth site is its extra `POST /keys/{id}/rotate-secret` endpoint, which the reference does not have. Every path that returns credential material is covered on both sides. |
| Self-granting of M:N permissions | `if !key.is_master && id == key.id` → `403` in `update_key_hook_permissions` (2204) | `if id == key.id && !key.is_master` → `403` in `update_key_group_permissions` (1828), with an explicit anti-ratchet rationale | **Equivalent.** Both require a second party for every self-affecting grant. |
| M:N permissions on a master target | `if target_key.is_master` → `InvalidInput` (2195) | `if target_key.is_master` → `InvalidInput` (1815) | **Equivalent**, including the error class. |
| Delegating access beyond your own | `require_manage(db, key, hook.id)` — boolean, you must manage the hook — plus `require_master_for_privileged_hook` for `run_as_user` hooks | `guard_delegated_group_grant` — **per verb**: `can_read`/`can_write`/`can_delete` each checked independently against the caller's own permission row | **Vault stronger in granularity.** The vault refuses a `can_read`-only holder granting `can_write`. In the reference's two-verb model the equivalent grant is lateral rather than escalating, so the practical gap is small — but the vault's shape survives adding a third verb and the reference's does not. |
| Elevated-resource carve-out | `require_master_for_privileged_hook` — distributing rights over a `run_as_user` hook stays master-only even for a legitimate manager | No counterpart; the vault has no privilege-carrying resource analogous to `run_as_user` | **Reference-only surface, correctly handled.** Nothing to unify. |
| Auto-created resource ownership | n/a — no auto-create path | Group auto-create grants the creator full read/write/delete first, so `guard_delegated_group_grant` finds a legitimate row without a special case | **Vault-only surface, correctly handled.** |
| Base scope gate on key-admin routes | `!key.is_master && !key.can_manage_keys` → `403` on create/list/update/delete/rotate/permissions | Identical predicate on the same six route families | **Equivalent.** |
| Self-deletion | `if id == key.id` → "Cannot delete yourself" (2073) | `if id == key.id` → "Cannot delete yourself" (1572) | **Equivalent.** |
| Audit-log visibility | Master-only (2353) | Master-only — "Only master keys can view audit logs" (2597) | **Equivalent.** |

**Prose.** Both codebases converged on the same three-layer model: a base scope gate, a guard on the *target* key's privilege, and a guard on what the caller may *hand out*. Both document the same historical bug that motivated the middle layer — rotation returns plaintext credential material, so an unguarded `POST /keys/{id}/rotate` against a master key is a one-request takeover that also locks out the legitimate holder. The one structural difference, granularity of the delegation guard, follows from the permission models differing (three verbs versus two) rather than from either side having overlooked something.

---

## 3. Cryptography, HMAC & authentication posture

Files: `src/crypto.rs`, `src/middleware.rs`, plus `src/replay.rs` (reference) / `src/state.rs` (vault).

| Aspect | `simply_hook_executor` (./example) | `simply_ip_vault` (this repo) | Assessment |
| :--- | :--- | :--- | :--- |
| **Authentication posture** | Per-key configurable: `HmacMode::CanonicalV1` \| `HmacMode::BodyOnly`; signature optional by default; `REQUIRE_SIGNED_REQUESTS` promotes it to mandatory; `X-Hub-Signature-256` honoured for `BodyOnly` keys only | Mandatory full-URI HMAC + timestamp + anti-replay on **every** key. No per-key mode, no environment switch, no opt-out route | **Intentional asymmetry — do not unify.** |
| `X-Hub-Signature-256` acceptance | Accepted, and only in `BodyOnly` mode, so a `CanonicalV1` key cannot be downgraded by sending the other header name | Not accepted at all | **Intentional asymmetry — do not unify.** Follows directly from the posture row; the mode guard on the header name is the correct containment. |
| At-rest AEAD | XChaCha20-Poly1305, 192-bit random nonce per operation | XChaCha20-Poly1305, 192-bit random nonce per operation | **Equivalent.** Both avoid the AES-GCM 96-bit birthday bound with no counter state to persist. |
| Legacy ciphertext path | None — the daemon never shipped an AES-GCM format | `LEGACY_GCM_PREFIX = "aesgcm256:"`, **open-only**; `aes-gcm` retained as a read-only dependency; nothing in the crate writes it | **Not a weakness.** A migration obligation the reference does not carry. The path decrypts only, and the legacy key is derived as `SHA-256(raw hex env text)` — matching what wrote those rows. Worth deleting once no `aesgcm256:` rows remain. |
| Cipher instantiation | Once in `main`, into `Arc<SecretCipher>`; `AppState::new` takes it as an explicit parameter so no caller can default into plaintext | Once via `SecretCipher::from_env()`, into `Arc<SecretCipher>` in `AppState` | **Equivalent.** Never rebuilt per request on either side. |
| Fail-closed on a malformed key | `from_env` → `from_hex_key` → `CryptoError::InvalidKey`, propagated from `main` with `?`; empty/whitespace is "unset" (the documented plaintext fallback), anything else aborts | Identical semantics, identical env-var pair (`SIGNING_SECRET_KEY` / `VAULT_ENCRYPTION_KEY`, primary wins), identical empty-is-unset rule | **Equivalent.** Neither degrades to plaintext for an operator who set the variable. |
| Position of the fail-closed check in startup | Cipher built *after* DB connect, pragmas, and migrations | Cipher built *before* DB connect | **Vault marginally stronger** — a mistyped key aborts before any database work is done. Cosmetic. |
| Canonical signed string | `signature_base` → `METHOD\nPATH_AND_QUERY\nTIMESTAMP\nRAW_BODY`, LF-joined, no trailing newline | `canonical_v1_payload` → `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`, byte-identical construction | **Equivalent.** Both delimit to defeat component-boundary shifting (`POST`+`/api/x` vs. `POS`+`T/api/x`). |
| Signed target scope | `path_and_query()`, read through `OriginalUri` so `Router::nest("/api", ..)` prefix stripping does not break signatures | `signed_target()` → `path_and_query()` through `OriginalUri`, same rationale | **Equivalent.** Both cover the query string, closing the rewrite-a-captured-request hole (`?older_than_days=`, `?hard=true`, `?include_deleted=true`). |
| Body-only / unsigned keys | `BodyOnly` signs the raw body alone and carries no timestamp; unsigned permitted unless `REQUIRE_SIGNED_REQUESTS` | Neither exists | **Intentional asymmetry — do not unify.** |
| Constant-time signature comparison | `Mac::verify_slice` in `verify_signature`; chain documented as `verify_slice → CtOutput::eq → subtle::ConstantTimeEq::ct_eq` | `Mac::verify_slice` in `crypto::verify_signature`; same chain, same recorded prohibition on "simplifying" to `==` | **Equivalent.** Grep confirms no `==`/memcmp comparison against a secret, signature, digest, or MAC anywhere in either `src/`. |
| Hex decoding before comparison | `hex::decode` on the header value, then `verify_slice` on the bytes — wrong-length tags rejected inside `verify_slice` | `hex::decode` on the header value, then `verify_slice` on the bytes | **Equivalent.** Both reject non-hex and wrong-width tags before any comparison occurs. |
| Key lookup by `key_hash` | `Sha256(presented_key)` → `.filter(Column::KeyHash.eq(hash))` — an indexed DB lookup on a digest | Identical | **Equivalent, and correctly *not* constant-time.** This is a lookup keyed on a hash digest, not a comparison against a secret: the digest is derived from caller-supplied input and the query returns a row or nothing. No timing obligation applies, and neither side mistakenly applies one. |
| Verification return shape | `verify_signature` returns `Result<Vec<u8>>` — the verified digest, handed straight to the replay guard | `verify_signature` returns `bool`; the middleware separately re-derives a replay token from the header text | **Reference stronger.** Returning the decoded digest keys the guard on canonical bytes *by construction* rather than by remembering to normalize the header a second time. |
| Replay-guard key material | `SignatureId { key_id: Uuid, digest: Vec<u8> }` — raw bytes, so `sha256=AB…` and `sha256=ab…` cannot become two entries | `format!("{key_id}:{signature}")`, where `signature` is the header `.trim()`ed, `sha256=`-stripped, and `.to_ascii_lowercase()`d | **Equivalent in effect.** The vault's normalization is complete only because `hex::decode` inside `verify_signature` has already rejected non-canonical hex before the token is built — the property holds, but at a distance rather than by construction. |
| Anti-replay: window | Symmetric ±`signature_max_age_seconds`, checked before the HMAC | Symmetric ±`MAX_TIMESTAMP_SKEW_SECS` (300), checked before the DB lookup | **Equivalent.** Both refuse forward-dated requests, which would otherwise stay replayable for the length of the skew. |
| Anti-replay: window configurability | `SIGNATURE_MAX_AGE_SECONDS`, `.max(1)` at parse and clamped again to `[1, 3600]` in `ReplayGuard::new` | Hard-coded `const MAX_TIMESTAMP_SKEW_SECS: i64 = 300` | **Reference marginally stronger.** The vault's constant cannot be misconfigured at all, which is defensible for a locked-down service; the reference is tunable *and* a typo cannot disable the guard. |
| Anti-replay: single-use tracking | `ReplayGuard::check_and_record(key_id, digest)`, `CanonicalV1` keys only | `ReplayGuard::observe(key_id, token, timestamp)`, every key | Both track `(key, signature)` pairs rather than merely bounding the window. The reference's `BodyOnly` exclusion is part of the **intentional asymmetry** — that mode carries no timestamp, so there is no window to be single-use within, and third-party senders redeliver on purpose. |
| Ordering relative to HMAC | Recorded strictly **after** `verify_signature` succeeds | Recorded strictly **after** `crypto::verify_signature` returns `true` | **Equivalent.** Both document the same two reasons: unauthenticated map-filling, and burning a signature a legitimate client is about to send. |
| Lock poisoning | Fails **closed** — `check_and_record` returns `false`, the request is rejected | Fails **closed** — `observe` returns `false`, the request is rejected | **Equivalent.** |
| Replay-guard expiry clock | Monotonic `std::time::Instant`; each entry stores `now + window` | Wall-clock `chrono::Utc::now().timestamp()`; `retain` on `(now - ts).abs() <= 300` | **Reference stronger.** A backward NTP step on the vault evicts still-in-window entries early — and `.abs()` makes a forward step do the same — re-opening replay for signatures the freshness check may still accept. `Instant` is immune to clock adjustment. |
| Replay-guard pruning cost | Amortized: `prune_if_due` sweeps at most once per `window / 4` | `seen.retain(...)` over the **entire map on every `observe()` call**, inside the global `std::sync::Mutex` | **Reference stronger.** The vault pays O(n) per authenticated request inside the lock every request must take — a throughput cliff that worsens precisely as traffic rises. |
| Replay-guard capacity behaviour | `MAX_TRACKED_SIGNATURES = 250_000`; on overflow, prune expired entries, then **keep enforcing** and log a warning | `MAX_TRACKED_SIGNATURES = 100_000`; on overflow, `seen.clear()` — self-documented as *"Replay protection is degraded for the current window"* | **Reference materially stronger.** The vault's `clear()` makes every previously-accepted signature replayable at once, and because the map is process-global the flush is triggered by *any* key and affects *every* key. |
| Timestamp check placement | After the key lookup, inside the signature branch; the error reports `off by {skew}s` | Before the key lookup; the error names the window but discloses no measured offset | **Vault marginally stronger on two axes.** An unauthenticated caller costs the vault no DB query and learns no clock offset. The reference's disclosure is post-bearer-auth, so its exposure is small. |
| Plaintext storage mode | Supported with a loud startup warning; values hex-encoded so the secret is not a `grep`-able substring of a dump | Supported with a loud startup warning; same hex encoding | **Equivalent.** |
| Secret redaction in `Debug` | `SecretCipher::Sealed(<redacted>)` | `SecretCipher` `Debug` impl redacts key material | **Equivalent.** |

**Prose.** Everything outside the three posture-derived rows has converged, with one exception that is genuinely one-sided: the reference's dedicated `src/replay.rs` is a better implementation of the anti-replay guard than the vault's in-line `ReplayGuard` in `src/state.rs`, on three independent counts — clock source, pruning cost, and overflow behaviour. The overflow difference is the one that matters. Both maps are reachable only by a caller holding a valid signing secret, so neither is an unauthenticated attack surface; but the vault's response to pressure is to *drop the security property*, while the reference's is to keep enforcing and complain. Because the map is shared across all keys, one misbehaving or compromised client can flush the vault's guard for every other client.

---

## 4. Database configuration & edge cases

Files: `src/main.rs`, `src/lib.rs`, `src/retention.rs`, plus `src/db.rs` (reference) / `src/state.rs` (vault).

| Aspect | `simply_hook_executor` (./example) | `simply_ip_vault` (this repo) | Assessment |
| :--- | :--- | :--- | :--- |
| Pragma module location | Dedicated `src/db.rs` | `state::apply_sqlite_pragmas` | **Equivalent.** Organizational only. |
| `journal_mode=WAL` | Issued, and the result **read back** and compared (`eq_ignore_ascii_case("wal")`) rather than inferred from a clean return | Issued, result read back and compared identically | **Equivalent.** Both know SQLite silently declines the switch for in-memory and read-only databases rather than erroring. |
| `busy_timeout` | `5_000` ms via `execute_raw`; failure warned and swallowed | `5000` ms via `execute_raw`; failure warned and swallowed | **Equivalent**, including the documented note that `journal_mode` is persistent (database file header) while `busy_timeout` is per-connection, with SQLx supplying the pool-wide default. |
| Non-fatality | `apply_sqlite_pragmas` returns `Result<(), DbErr>` — every internal failure is swallowed, but `main` still wraps the call in `if let Err(e)` | `apply_sqlite_pragmas` returns `()`; `main` calls it with no `?` | **Vault marginally stronger.** Non-fatality is guaranteed by the signature and cannot be undone by a future caller adding `?`. The reference relies on the caller remembering. |
| Backend guard | `if db.get_database_backend() != DatabaseBackend::Sqlite { return }` — keyed on backend, not URL text | Identical | **Equivalent.** Keeps the SQL-agnostic rule intact once PostgreSQL is in play; there is no URL parsing to get wrong. |
| Pragma test coverage | Three tests: a **file-backed** database asserting WAL actually engages *and* survives reconnection; an in-memory database asserting tolerance and continued usability; a backend-scoping test | One test (`sqlite_pragma_failures_never_stop_the_service`): in-memory tolerance and idempotent re-application | **Reference stronger.** The vault never verifies anywhere that WAL genuinely engages on a file-backed database, nor that it persists — so a regression that silently stopped applying WAL would pass the vault's suite unchanged. |
| Retention window default | `DEFAULT_DELETED_HOOK_RETENTION_DAYS = 92` | `DEFAULT_RETENTION_DAYS = 92` | **Equivalent.** |
| Retention window override | `DELETED_HOOK_RETENTION_DAYS` via `parse_or_warn`, then `.max(0)` | `IP_RETENTION_DAYS` via `retention_days_from_env`, warn-and-fall-back on a malformed value | **Equivalent.** Both treat a non-positive value as "keep forever", and neither lets a typo destroy history. |
| Soft-delete purge predicate | `IsDeleted.eq(true)` ∧ `DeletedAt.is_not_null()` ∧ `DeletedAt.lt(threshold)` | `IsDeleted.eq(true)` ∧ `DeletedAt.is_not_null()` ∧ `DeletedAt.lt(threshold)` | **Equivalent.** Both carry the redundant `is_not_null` guard, so a row with an inconsistent flag pair is never purged. |
| Retention worker shutdown | Own `mpsc` channel; `main` drops the sender and awaits the handle | Own `mpsc` channel; `main` drops the sender and awaits the handle | **Equivalent.** Neither cuts a sweep off mid-delete on SIGTERM. |
| Separation of retention windows | `log_retention_days` and `deleted_hook_retention_days` governed independently, with a documented rationale | Single `IP_RETENTION_DAYS` — the vault has one soft-deleted entity | **Equivalent for the surface each has.** |
| `DefaultBodyLimit` | `MAX_REQUEST_BODY_BYTES = 3 * 1024 * 1024`, one router-wide layer applied **outside** both `nest()` calls | `MAX_REQUEST_BODY_BYTES = 3 * 1024 * 1024`, one router-wide layer applied **outside** the `nest()` | **Equivalent.** Both cover the static fallback too, so the limit cannot be sidestepped by aiming at a route that never reaches the auth middleware. |
| Per-route body-limit override | None | None | **Equivalent.** Both state explicitly that an exception would reintroduce the differential the constant exists to remove. |
| Signature-buffering constant | `const MAX_SIGNED_BODY_BYTES: usize = crate::MAX_REQUEST_BODY_BYTES;` | `const MAX_SIGNED_BODY_BYTES: usize = crate::MAX_REQUEST_BODY_BYTES;` | **Equivalent — byte-identical derivation.** No band of sizes exists that one layer accepts and the other refuses. |
| Bind-address resolution | `resolve_bind_addr` / `parse_bind_addr` — `BIND_HOST` over `HOST`, `PORT`, literal IPs only, lenient fallback, port `0` passed through | Identical pair, identical precedence and fallback rules | **Equivalent.** Both log from `listener.local_addr()` rather than the requested address, so `PORT=0` is reported truthfully. |
| DNS-failure handling at boot | Covered in §1 — negative caching plus a 60s delayed re-check, never an abort | Covered in §1 — identical | **Equivalent.** |

**Prose.** The only scored gap here is test coverage rather than behaviour: the two pragma implementations are functionally the same, but only the reference proves that WAL actually engages on a real file and survives reconnection. That matters more than it appears, because the entire vault suite runs on `sqlite::memory:`, where WAL legitimately cannot engage — so the vault's single test would still pass if the pragma stopped being issued altogether.

---

## 5. Executive summary

Across four categories this audit compared **73 aspect rows**: 17 on proxy and IP middleware, 14 on RBAC and privilege escalation, 26 on cryptography, HMAC and authentication posture, and 16 on database configuration and edge cases. Of these, **66 are equivalent or differ only cosmetically**, **3 are intentional asymmetries** — the per-key versus mandatory authentication posture, the `X-Hub-Signature-256` acceptance path, and the `BodyOnly` exclusion from replay tracking, all three of which follow from `simply_hook_executor`'s need to interoperate with third-party senders and none of which should be unified — and **4 are genuine discrepancies**, all of them on the `simply_ip_vault` side and concentrated in two places. Three concern the anti-replay guard: on capacity overflow the vault calls `seen.clear()` and self-documents the result as degraded replay protection, whereas the reference prunes, keeps enforcing, and warns — and because the map is process-global, one client's burst flushes the guard for every key; the vault expires entries against the wall clock rather than a monotonic `Instant`, so an NTP step evicts still-valid entries early; and it runs an O(n) `retain` over the whole map inside the global mutex on every authenticated request instead of amortizing the sweep. The fourth is test coverage: the vault never verifies that `journal_mode=WAL` actually engages on a file-backed database, only that failing to apply it is non-fatal. A follow-up convergence pass is warranted for the replay guard specifically — the reference's dedicated `src/replay.rs` is the better design on all three counts, and porting it wholesale (keyed on the raw digest returned by `verify_signature`, expiring on `Instant`, pruning on an interval, and refusing to flush under pressure) would close every one of them; the WAL test is worth adding in the same pass. No discrepancy was found on the reference side, and no exploitable unauthenticated path was found on either. **All findings are subject to the freshness flag in §0: `./example` carries no commit marker, so its currency relative to its own upstream cannot be verified from within this repository.**
