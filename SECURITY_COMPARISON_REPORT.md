# Comparative Security Audit — `simply_ip_vault` ↔ `simply_hook_executor`

**Date:** 2026-08-02 · **Mode:** strictly read-only — no source file in `src/` or `./example` was
modified, and no commit was created. **Scope:** closing pass on the audit committed as `f6239ee`,
re-verifying its contested findings against current source rather than against commit messages.

---

## 0. Reference freshness

### 0.1 The reference is not a git checkout — and `rev-parse` lies about it

`git -C ./example rev-parse HEAD` **returns a hash, and that hash is a trap.** It answers
`5f7b5b1de4511eff4babdd367b8d5def5384a678`, which is *this* repository's HEAD. `./example` holds no
`.git`, so git walks up to the enclosing repository and reports its commit. Recording that number
would attribute a provenance the reference does not have.

| Probe | Result | Meaning |
| :--- | :--- | :--- |
| `example/simply_hook_executor/.git` | absent | not an independent checkout |
| `.gitmodules` | does not exist | not a submodule |
| `git ls-files example \| wc -l` | `0` | untracked by this repo |
| `.gitignore` line 9 | `example/*` | deliberately excluded |

**No commit hash can be pinned.** Freshness is corroborated by mtime and by content instead.

### 0.2 Corroboration — the reference is CURRENT

| Artifact | Timestamp |
| :--- | :--- |
| `example/.../src/api.rs`, `src/middleware.rs` | 2026-08-02 17:13 |
| `example/.../src/lib.rs`, `src/main.rs` | 2026-08-02 17:31 |
| `example/.../Cargo.toml` | 2026-08-02 17:32 |
| `example/.../src/config.rs` | 2026-08-02 17:33 |
| `example/.../AGENT_NOTES.MD` | 2026-08-02 17:35 |
| `example/.../src/` (directory) | 2026-08-02 18:46 |
| this repo — `ee84e72` (ReplayGuard rewrite) | 2026-08-02 17:21 |
| this repo — `40cb4f4` (legacy-crypto purge) | 2026-08-02 17:38 |
| this repo — `5f7b5b1` (HEAD) | 2026-08-02 21:28 |

The reference's newest content postdates `ee84e72` and falls within five minutes of `40cb4f4`.
Content corroborates the timestamps independently, which matters more than the mtimes themselves:
the reference's `AGENT_NOTES.MD` documents *its own* dead-code sweep (177 tests, 632/632 e2e), its
`src/replay.rs` exists as a standalone module, and its `SecretCipher::open` is already fail-closed.
All three are post-audit states that could not have been present in a stale copy.

> **✅ Reference freshness: CURRENT** — corroborated by mtime and content, not pinned to a hash.
> This supersedes the previous audit's `⚠ UNVERIFIED` flag, which was correct when written.
>
> HEAD has since moved to `5f7b5b1`, which touches `static/app.js` only (+1/−2) and changes nothing
> in scope.

### 0.3 Project-direction correction

The brief states that `simply_ip_vault` "is in `./example`" and that `simply_hook_executor` is the
current repository. **This is inverted**, per the package manifests:

| Path | `Cargo.toml` `name` |
| :--- | :--- |
| `.` (this repository) | `simply_ip_vault` |
| `./example/simply_hook_executor/` | `simply_hook_executor` |

The mandated column *positions* are preserved so the table shape matches the brief; the *labels* are
corrected so each cell describes the codebase it actually came from.

---

## 1. Proxy & IP middleware

| Aspect | `simply_ip_vault` — **this repo** (brief's col. 1) | `simply_hook_executor` — **`./example`** (brief's col. 2) | Assessment |
| :--- | :--- | :--- | :--- |
| `resolve_client_ip` body | `config.rs:563` | `config.rs:416` | **Equivalent** — textually identical, line for line |
| Trust gate | `if !is_trusted(peer, trusted) { return peer }` before any header read | identical | **Equivalent** — the load-bearing check; headers unreachable for an untrusted peer |
| XFF chain walk | `.rev().find(\|ip\| !is_trusted(*ip, trusted))` | identical | **Equivalent** — right-to-left, skipping trusted hops |
| All-trusted chain | falls through; never invents a client | identical | **Equivalent** |
| `X-Real-IP` | honoured only from a trusted peer, only when XFF yielded nothing | identical | **Equivalent** |
| IPv4-mapped normalization | `normalize_ip` on the peer and every hop | identical | **Equivalent** |
| Positive DNS TTL | `POSITIVE_TTL = 30s` (`config.rs:97`) | `TRUSTED_PROXY_DNS_TTL = 30s` (`config.rs:23`) | **Equivalent** — names differ, values match |
| Negative DNS TTL | `NEGATIVE_TTL = 5s` (`config.rs:108`) | `TRUSTED_PROXY_DNS_NEGATIVE_TTL = 5s` (`config.rs:38`) | **Equivalent** |
| Boot grace period | `BOOT_GRACE_PERIOD = 60s`, private | `TRUSTED_PROXY_BOOT_GRACE = 60s`, `pub` | **Equivalent** behaviour; visibility differs only |
| Negative-caching granularity | per-hostname (`HostnameState`) | per-hostname (`HostnameEntry`) | **Equivalent** — one bad name never drags healthy ones onto the short window |
| Concurrent-resolution collapse | re-check under the write lock in `resolved()` | equivalent double-check | **Equivalent** — bounds DNS amplification across simultaneous requests |
| `resolve_hostname` return shape | `Vec<IpNetwork>`; caller derives `resolved = !addresses.is_empty()` (`config.rs:468`) | `(Vec<IpNetwork>, bool)` | **Equivalent — previously misreported.** The peer returns `false` in *exactly* the empty cases, so the bool is `!networks.is_empty()` by construction. See §5.1 |
| DNS-failure direction | empty ⇒ untrusted; never widens trust | identical | **Equivalent** — fails safe on both sides |
| Malformed `TRUSTED_PROXIES` entry | dropped with a warning; startup continues | identical | **Equivalent** |
| `bound_ips` on master keys | enforced, no `is_master` bypass (`middleware.rs:274`) | enforced, no bypass (`middleware.rs:439`) | **Equivalent** — both fixed the decorative-restriction bug |
| `bound_ips` check position | after HMAC verification (`middleware.rs:257`) | after HMAC verification (`middleware.rs:421`) | **Equivalent** — closes the 403-vs-401 topology oracle |
| Malformed CIDR in DB | `AppError::Internal` (500); never fail-open | identical | **Equivalent** |
| Positive-TTL **expiry** test | **absent** — no test drives a positive entry to expiry | `a_successful_resolution_is_re_queried_once_its_positive_ttl_expires` | **`simply_hook_executor` stronger** — see §5.2 |

Both sides expose a test-only TTL builder, but only the peer's suite exercises the positive window's
*expiry*. All three of our TTL tests pass a 30-second positive TTL, which cannot lapse inside a test.

---

## 2. RBAC & privilege-escalation guards

| Aspect | `simply_ip_vault` — **this repo** | `simply_hook_executor` — **`./example`** | Assessment |
| :--- | :--- | :--- | :--- |
| **Contested finding #1** — cross-tenant revocation | `revoke_key_group_permission` (`api.rs:1944`) resolves the caller's own grant via `caller_group_permission`, then applies `guard_delegated_group_grant(.., "revoke", ..)` against the *existing* grant's verbs | n/a — finding was against this repo | **CLOSED** — verified in source |
| **Contested finding #2** — any-verb-grants-any-verb | n/a — finding was against the peer | `guard_delegated_hook_grant` (`api.rs:461`) tests `can_execute` and `can_manage` **independently** via `wanted && !holds` | **CLOSED** — verified in source |
| Revocation authority scope | caller must hold each verb being removed | caller needs only `can_manage` on the hook (`require_manage`) | **`simply_ip_vault` stronger** — see §5.3 |
| Ordering of `404` vs `403` on revoke | `NotFound` returned before the authority guard (`api.rs:1980` → `:1985`) | `delete_many` first; `404` derived from `rows_affected == 0` | **`simply_ip_vault` stronger** — peer's order is safe today but structurally fragile |
| Self-revocation of own grants | blocked for non-master (`api.rs:1958`) | not blocked | **Equivalent in risk** — dropping your own access is de-escalation |
| Self-**granting** of own permissions | blocked for non-master | blocked for non-master (`api.rs:2272`) | **Equivalent** |
| Master-target guard | `guard_master_target` (`api.rs:225`) | `require_master_to_administer` (`api.rs:379`) | **Equivalent** — same predicate; peer additionally names the action |
| — applied on `update` | ✅ (`api.rs:1630`) | ✅ (`api.rs:2077`) | **Equivalent** |
| — applied on `delete` | ✅ (`api.rs:1587`) | ✅ (`api.rs:2150`) | **Equivalent** |
| — applied on `rotate` | ✅ (`api.rs:1723`) | ✅ (`api.rs:2200`) | **Equivalent** — rotation returns the new plaintext secret, so this is the critical one |
| Self-deletion | blocked | blocked | **Equivalent** |
| `is_master` promotion via update | payload carries no `is_master` field | payload carries no `is_master` field | **Equivalent** — promotion unreachable by construction |
| Master-only scope grants on create | `MASTER_ONLY_SCOPES` zip-check (`api.rs:208`) | `require_master_to_grant_scopes` (`api.rs:343`) | **Equivalent** — `can_manage_keys` is no longer transitively `is_master` |
| Permission rows on a master target | refused as `InvalidInput` (`api.rs:1824`) | refused as `InvalidInput` (`api.rs:2266`) | **Equivalent** |
| Entry gate on permission handlers | `!is_master && !can_manage_keys` ⇒ 403 | identical | **Equivalent** |
| Audit logging of grant/revoke | `KEY_PERM_REVOKE` with actor, IP, target | identical vocabulary | **Equivalent** |

---

## 3. Cryptography, HMAC, authentication posture & replay protection

| Aspect | `simply_ip_vault` — **this repo** | `simply_hook_executor` — **`./example`** | Assessment |
| :--- | :--- | :--- | :--- |
| **Authentication posture** | mandatory full-URI HMAC + anti-replay on **every** key; no per-key mode, no opt-out, no alternate signature header | per-key `HmacMode` (`CanonicalV1` / `BodyOnly`), `X-Hub-Signature-256` accepted in `BodyOnly` only, `BodyOnly` excluded from replay tracking, `REQUIRE_SIGNED_REQUESTS` promotes signing to mandatory | **Intentional asymmetry — do not unify** |
| MAC comparison | `Mac::verify_slice` (`crypto.rs:165`) — the only comparison in the crate | `Mac::verify_slice` (`middleware.rs:195`) — the only one | **Equivalent** — constant-time via `CtOutput::eq` → `subtle::ct_eq` |
| Non-constant-time comparison of secret material | none — no `==` against any secret, signature, digest or MAC | none | **Equivalent** |
| `key_hash` lookup | indexed DB lookup keyed on a SHA-256 digest | identical | **Equivalent** — *not* a secret comparison; timing reveals only index behaviour |
| Canonical string | `METHOD\nTARGET\nTIMESTAMP\nBODY`, LF-joined | identical (`signature_base`) | **Equivalent** |
| Target component | `path_and_query()`, never `path()` (`middleware.rs:96`) | `path_and_query()`, never `path()` (`middleware.rs:362`) | **Equivalent** — query string covered on both |
| `OriginalUri` under `nest()` | used, with a `parts.uri` fallback | used, with a `parts.uri` fallback | **Equivalent** — without it every signature would mismatch |
| Signature header parsing | `sha256=` prefix **optional**; bare hex accepted (`crypto.rs:156`) | `sha256=` prefix **required** (`middleware.rs:182`) | **`simply_hook_executor` stronger** — see §5.4 |
| Digest returned from verification | `Option<Vec<u8>>` — raw decoded bytes | `Result<Vec<u8>, AppError>` — raw decoded bytes | **Equivalent** — both normalize hex spelling by construction |
| `open()` accepted formats | exactly `v1.plain.` and `v1.xchacha20poly1305.` (`crypto.rs:346`) | exactly `v1.plain.` and `v1.xchacha20poly1305.` (`crypto.rs:141`) | **Equivalent** — closed set matching what `seal()` emits |
| Unrecognized prefix | `MalformedCiphertext` — **fail-closed** | `MalformedCiphertext` — **fail-closed** | **Equivalent** — neither returns an unprefixed value verbatim |
| Legacy ciphertext format | none — `aesgcm256:` purged in `40cb4f4`, `aes-gcm` crate removed | none | **Equivalent** — neither carries a legacy format the other has dropped |
| Sealed row with no key configured | `DecryptionFailed`, never silent passthrough | `DecryptionFailed` | **Equivalent** |
| AEAD | XChaCha20-Poly1305, fresh 24-byte random nonce per seal | identical | **Equivalent** — 192-bit nonce, no counter state to persist |
| Malformed encryption key at startup | hard error; never degrades to plaintext | hard error | **Equivalent** |
| Decryption failure at request time | `500`, logged loudly — not `401` | `500`, logged loudly | **Equivalent** — an operator emergency must not read as a client error |
| Replay clock source | `tokio::time::Instant` (monotonic) | `std::time::Instant` (monotonic) | **Equivalent** — both immune to NTP steps; ours is additionally pausable for deterministic tests |
| Replay key | `SignatureId { key_id, digest: Vec<u8> }`, raw bytes | identical | **Equivalent** — cross-key collision and hex re-spelling both impossible |
| Behaviour at capacity | sweep + warn, **never** `clear()`; map may grow | sweep + warn, **never** `clear()` | **Equivalent** — the `seen.clear()` defect is closed on both sides |
| Capacity-sweep backoff | `CAPACITY_BACKOFF_DIVISOR = 16` — at most one sweep per window/16 while saturated | none — sweeps on **every request** while saturated (`replay.rs:143`) | **`simply_ip_vault` stronger** — see §5.5 |
| Routine sweep strategy | interval, `PRUNE_INTERVAL_DIVISOR = 4` | interval, `PRUNE_INTERVAL_DIVISOR = 4` | **Equivalent** — amortized, not per-request `O(n)` |
| Tracked-signature ceiling | `100_000` | `250_000` | **Equivalent** — both are runaway-client alarms, not attack controls |
| Poisoned-lock behaviour | fails **closed** (rejects the request) | fails **closed** | **Equivalent** |
| Window clamp | `clamp(1, 3600)` | `clamp(1, 3600)` | **Equivalent** — a config typo cannot disable the guard |
| Record-after-verify ordering | recorded only after `verify_slice` passes | identical | **Equivalent** — avoids the DoS-against-the-client inversion |
| `X-Timestamp` vs. API-key DB lookup | validated **before** the lookup (`middleware.rs:155`) | validated **before** the lookup (`middleware.rs:281`) | **Equivalent** — an unauthenticated caller cannot buy a query with a stale timestamp |
| Authoritative window re-check | single unconditional check | `prevalidate_timestamp_header` is the fast path; authoritative check repeated in the `CanonicalV1` branch | **Equivalent** — the peer's duplication is required by its per-key posture |
| Skew symmetry | `.abs()` — future-dated rejected too | `.abs()` | **Equivalent** |
| Encryption-key env var | primary `VAULT_ENCRYPTION_KEY`, alias `SIGNING_SECRET_KEY` | primary `SIGNING_SECRET_KEY`, alias `VAULT_ENCRYPTION_KEY` | **Equivalent** — deliberate mirror; each service seals its own database |
| `ReplayGuard::tracked()` | `#[cfg(test)]` — compiled out of release builds | `pub` | **`simply_ip_vault` marginally tighter** — no security impact |
| `ReplayGuard::new()` | private; `Default` is the only production path | `pub` — takes the configurable window from `RuntimeConfig` | **Equivalent** — follows from the posture asymmetry |
| Signature-buffer cap | `MAX_SIGNED_BODY_BYTES = crate::MAX_REQUEST_BODY_BYTES` | identical derivation | **Equivalent** — no parser-differential band |

---

## 4. Database configuration & edge cases

| Aspect | `simply_ip_vault` — **this repo** | `simply_hook_executor` — **`./example`** | Assessment |
| :--- | :--- | :--- | :--- |
| `journal_mode=WAL` issued | `state::apply_sqlite_pragmas` (`state.rs:58`) | `db::apply_sqlite_pragmas` (`db.rs:49`) | **Equivalent** — different module, same logic |
| Failure handling | **non-fatal**; returns `()`, so no error channel exists | **non-fatal**; returns `Result`, swallowed by `if let Err` at `main.rs:239` | **Equivalent** — ours makes it unpropagatable by construction; peer's is explicit at the call site |
| Mode read-back | reads `journal_mode` from the response row | reads `journal_mode` from the response row | **Equivalent** — SQLite declines silently, so a clean return proves nothing |
| `busy_timeout` | `5000` ms | `5000` ms | **Equivalent** |
| Backend guard | skips unless `DatabaseBackend::Sqlite` | identical | **Equivalent** — the one documented exception to the SQL-agnostic rule |
| Applied before migrations | yes | yes | **Equivalent** — migration is the long write that would otherwise hit `SQLITE_BUSY` |
| **File-backed WAL test** | `wal_engages_on_a_file_backed_database_and_survives_reconnection` (`tests/security_tests.rs:2591`) | `wal_and_busy_timeout_are_applied_to_a_file_backed_database` (`src/db.rs:106`) | **Equivalent** — both now test a real file, not only `sqlite::memory:` |
| — asserts `journal_mode == wal` | ✅ | ✅ | **Equivalent** |
| — asserts `busy_timeout == 5000` | ✅ | ✅ | **Equivalent** |
| — asserts survival across reconnection | ✅ fresh pool, no re-apply | ✅ fresh connection | **Equivalent** — proves the setting lives in the file header |
| — runs migrations under WAL | ✅ | ✗ | **`simply_ip_vault` marginally stronger** — proves usability, not just reporting |
| — temp-directory cleanup | `tempfile::tempdir()` — RAII, survives a panic | `std::env::temp_dir()` + manual `remove_dir_all` | **`simply_ip_vault` stronger** — peer leaks a directory on test panic (hygiene, not security) |
| In-memory graceful-decline test | `sqlite_pragma_failures_never_stop_the_service` — also serves a signed request afterwards | `a_database_that_cannot_use_wal_still_starts_and_works` | **Equivalent** — ours additionally proves the app still serves |
| DNS failure ⇒ negative cache | 5s, per hostname | 5s, per hostname | **Equivalent** |
| Boot-time delayed abort | `prime()` + 60s grace on a detached task | `prime_trusted_proxies` + 60s grace | **Equivalent** — a slow-starting proxy is not fatal |
| `DefaultBodyLimit` | `3 * 1024 * 1024`, one router-wide layer set exactly once | `3 * 1024 * 1024`, set once | **Equivalent** |
| Signature buffer derives from it | `= crate::MAX_REQUEST_BODY_BYTES` | `= crate::MAX_REQUEST_BODY_BYTES` | **Equivalent** — not an independently chosen number |

---

## 5. Notes a table cell cannot hold

### 5.1 The previous audit's `resolve_hostname` divergence is retired as cosmetic

It was recorded as an open divergence on diagnosability grounds. Reading both implementations side
by side retires that claim: the peer returns `true` only when `!networks.is_empty()`, and `false` in
both empty cases — the lookup error *and* the zero-address success. Ours computes
`resolved = !addresses.is_empty()` at the call site. The tuple therefore carries **no information
the scalar does not**, both feed the same positive/negative TTL split, and cache behaviour is
identical. Nothing to port; the item should be struck from the divergence register rather than
carried forward.

### 5.2 The one new finding, and it is on our side

Our TTL suite tests that a *negative* entry expires, and that a *positive* entry stays fresh
alongside a failing one — but never that a positive entry **lapses**. That is the security-relevant
direction: `POSITIVE_TTL` is the window during which a recreated container keeps its old address
trusted, an address the orchestrator may already have reassigned. A positive entry that never
expired would be a standing trust grant to whoever inherited that address, clearable only by a
restart — and every current test would still pass. `with_ttls` already accepts a positive duration,
so the test is writable without touching production code. The peer added exactly this test
(`a_successful_resolution_is_re_queried_once_its_positive_ttl_expires`) in its most recent sweep,
and mutation-checked it.

### 5.3 Revocation authority: a defensible difference, not a defect

Ours requires the caller to hold each verb it removes; the peer requires only `can_manage` on the
hook. Under the peer's rule, a caller holding `can_manage` but not `can_execute` can destroy an
`can_execute` grant it could not have created. That is an asymmetry, but not an escalation — the
peer's own rationale (`api.rs:450`, `api.rs:2373`) argues that removing authority should never
require a master, and it is coherent. Recorded as a difference in strictness; neither side is wrong.

### 5.4 Bare-hex signatures

Ours accepts `sha256=<hex>` *or* a bare `<hex>`; the peer requires the prefix. Not exploitable — the
HMAC must still verify and `hex::decode` still rejects non-canonical spellings — but it is a laxer
parse than the documented wire format, and laxity in a signature parser is worth removing on
principle rather than after a reason appears.

### 5.5 The capacity-sweep backoff is still worth porting back

The peer's `prune_if_due` returns early only when `now < *next_prune && !over_capacity`. Once the map
is saturated with entries that are all still live, `over_capacity` stays true, every request takes
the sweep branch, and the full `retain` runs per request inside the global lock — freeing nothing and
reinstating precisely the `O(n)`-per-request scan the module exists to remove. Ours bounds this to
one sweep per window/16. The peer's higher ceiling (250k vs. 100k) makes the saturated state rarer
but more expensive when reached. This was flagged in the previous audit and has not been picked up;
it remains the clearest single improvement either codebase could take from the other.

Both implementations also acquire the `seen` lock once per request purely to read `len()` for the
capacity test. Hoisting that behind the schedule check would remove a lock acquisition from every
authenticated request on both sides.

---

## 6. Executive summary

**Eighty-three aspects were compared across four categories** — 18 proxy/IP, 16 RBAC, 32
crypto/HMAC/replay, and 17 database/edge-case rows. **Seventy-four are equivalent**, one is the
permanent intentional asymmetry (mandatory full-HMAC on `simply_ip_vault` versus per-key `HmacMode`
on `simply_hook_executor` — recorded, not scored, and now subsuming the `X-Hub-Signature-256`
acceptance path and the `BodyOnly` replay exclusion that the previous audit listed as separate
asymmetries), and **eight are genuine differences in strictness — six favouring `simply_ip_vault`,
two favouring `simply_hook_executor`. None is exploitable.** Both contested RBAC findings are
**CLOSED**, verified by reading current source rather than trusting either side's commit message:
`simply_ip_vault`'s `revoke_key_group_permission` now resolves the caller's own grant and re-uses the
same per-verb delegation predicate as granting, with the `404` deliberately ordered ahead of the
authority check so a nonexistent grant cannot become a `403` that confirms a group's existence to
someone with no access to it; and `simply_hook_executor`'s `guard_delegated_hook_grant` now tests
`can_execute` and `can_manage` independently, so holding one confers no right to grant the other.
Every other patch the previous round claimed also holds up: the `seen.clear()` flush is gone from
both replay guards, both expire entries against a monotonic clock, both `open()` implementations
accept only the closed two-format set that `seal()` can produce — with no legacy prefix on either
side and no fail-open passthrough — both validate `X-Timestamp` before the API-key lookup, both check
`bound_ips` only after the HMAC has verified, and both now exercise WAL against a real file-backed
database rather than only `sqlite::memory:`. Two items are worth acting on. The **new** one is a
test-coverage gap on *our* side: nothing drives a positive DNS entry to expiry, so a `POSITIVE_TTL`
that never lapsed — a standing trust grant to whoever inherits a recycled container address — would
pass the suite unnoticed. The **carried-over** one is the peer's missing capacity-sweep backoff,
which reinstates an `O(n)` scan per request while the replay map is saturated. Separately, the
previous audit's `resolve_hostname` divergence is **retired as cosmetic**: the peer's `(Vec, bool)`
return is `true` in exactly the non-empty cases, making it identical to the `!addresses.is_empty()`
our caller already derives. Reference freshness is **CURRENT**, corroborated by mtime and by content
rather than pinned to a hash, because `./example` is an untracked, ignored directory with no `.git`
of its own — and `git -C ./example rev-parse HEAD` silently reports the *parent* repository's commit,
a result to distrust rather than record.
