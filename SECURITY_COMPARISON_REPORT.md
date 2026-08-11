# Comparative Security Audit — `simply_ip_vault` ↔ `simply_hook_executor`

**Date:** 2026-08-11 · **Mode:** strictly read-only. No file under `src/`, `tests/`, `scripts/` or
`migration/` was modified in either project; `git status --porcelain src/ tests/` is empty.

**Scope.** The **current project** — this repository, at HEAD `6f1c4c7` — against its **peer**, read
exclusively from `example/simply_hook_executor`, pulled to its current head before analysis (Task 0).
No source outside these two trees was consulted.

**Replaces the 2026-08-10 edition of this file.** Its findings are re-verified below rather than
restated; that edition remains retrievable at `git show f252387:SECURITY_COMPARISON_REPORT.md`.

Every claim was checked against source or by execution. Prior reports and commit messages were treated
as leads only.

---

## 0. Reference state

| Probe | Result |
| :--- | :--- |
| `git pull` in `example/simply_hook_executor` | **Already up to date** at `4865a82` |
| Peer working tree | clean — 0 modified files |
| Peer remote | `https://oshino.tomidejetsu.ovh/fallrik/simply_hook_executor.git` |
| Peer head commit | `refactor: enforce 64-hex master key, adopt ConflictWithDetails, unify guard prefixes and harden readiness probe` |
| `RBAC_MODEL.md` byte-identity | **identical**, `md5 cb0b76abd6c00f28af9bee951f804f7b` |

The peer's head commit addresses, by name, every open item the previous edition raised. Each is
verified in §1 and §3 against source rather than taken on the commit message.

---

## 1. Resolution of the one open finding

The 2026-08-10 edition closed 7 of 7 historical findings and left exactly **one** open item, against
the peer. It is now closed.

| Finding | Against | Then | Now | Evidence |
| :--- | :--- | :--- | :--- | :--- |
| `INITIAL_MASTER_KEY` accepted any non-empty string, with a startup warning as its only objection | peer | ❌ Open | ✅ **RESOLVED** | `src/config.rs:720` `INITIAL_MASTER_KEY_HEX_LEN = 64`; `:782` `validate_initial_master_key`; `:798` rejects on `is_ascii_hexdigit` |

Both projects now hold the credential that administers every other credential to the same standard:

| Property | Current project | Peer |
| :--- | :--- | :--- |
| Required form | exactly 64 ASCII hex characters | exactly 64 ASCII hex characters |
| Constant | `MASTER_KEY_HEX_LEN` | `INITIAL_MASTER_KEY_HEX_LEN` |
| Validator | `config::validate_initial_master_key` | `config::validate_initial_master_key` |
| On malformed input | aborts startup | aborts startup |
| Error names the remedy | ✅ | ✅ — and reports the **offending character position** |

The peer's implementation is marginally the better of the two: it names which character failed, where
this project reports only that non-hex characters are present.

---

## 2. Historical findings — all still closed

Re-verified against current source rather than carried forward on the previous report's word.

| # | Finding (2026-08-07) | Against | Status | Evidence |
| ---: | :--- | :--- | :--- | :--- |
| D1 | §5 uniqueness bypassable — the marker was application-written and could simply be omitted | current | ✅ Closed | `GENERATED ALWAYS AS` present in both migration trees; the `s5_` suite replays the original raw-SQL attack and it is refused |
| D2 | R2 conjunction missing — a Daughter key could rewrite `script_path` | peer | ✅ Closed | `can_manage_keys` appears 17× in `api/guards.rs`; the conjunction is enforced |
| D3 | Dormant `api_keys.owner_key_id` — written and inventoried, read by no guard | peer | ✅ Closed | Column dropped; absent from `entities/api_key.rs` |
| D4 | `is_master` retained on payload types; no `deny_unknown_fields` | current | ✅ Closed | 0 payload occurrences either side; 5 and 7 `deny_unknown_fields` sites |
| S1 | `can_create_webhooks` names a column that exists nowhere | spec | ✅ Closed | Terminology table names the real columns |
| S2 | `can_create_executor` names a column that exists nowhere | spec | ✅ Closed | as above |
| S3 | Table implies one creation right where this project has two | spec | ✅ Closed | as above |

**8 of 8 findings ever raised are closed**, and `RBAC_MODEL.md` remains byte-identical after the
coordinated edit that closed S1–S3 — the harder half of that fix, since it could not be made on one
side alone.

---

## 3. Security parity

| Control | Current project | Peer | Parity |
| :--- | :--- | :--- | :--- |
| §5 uniqueness — engine-generated marker under a unique index | ✅ | ✅ | ✅ |
| §5 identity — boot-time pin (`MasterPin`) | ✅ | ✅ | ✅ |
| Demotion at one choke point (`MasterPin::authenticate`) | ✅ | ✅ | ✅ |
| Test-only pin (`MasterPin::pinned_to`) | ✅ | ✅ | ✅ |
| R2 conjunction — global `can_manage_keys` **and** per-resource `can_manage` | ✅ | ✅ | ✅ |
| Master immutable (rotate / delete), caller-independent | ✅ | ✅ | ✅ |
| Master held to `bound_ips` — no exemption | ✅ | ✅ | ✅ |
| Anti-replay guard, monotonic expiry | ✅ | ✅ | ✅ |
| Trusted-proxy boundary; forwarding headers ignored unless the peer is trusted | ✅ | ✅ | ✅ |
| At-rest AEAD — XChaCha20-Poly1305, 192-bit nonce | ✅ | ✅ | ✅ |
| Encryption key strictly 64 hex, fatal | ✅ | ✅ | ✅ |
| **Bootstrap master key strictly 64 hex, fatal** | ✅ | ✅ **(new)** | ✅ |
| Constant-time signature comparison | ✅ | ✅ | ✅ |
| `sha256=` prefix mandatory — no bare-hex fallback | ✅ | ✅ | ✅ |
| SQLite `foreign_keys=ON` at connect time | ✅ | ✅ | ✅ |
| Raw-SQL / DML ban in `src/`, enforced at `cargo test` | ✅ `tests/source_hygiene.rs` | ✅ `tests/source_hygiene.rs` | ✅ |
| Audit attribution `NOT NULL` (`api_key_name`, `api_key_prefix`, `client_ip`) | ✅ | ✅ | ✅ |
| Audit FK `ON DELETE SET NULL` — a deleted key cannot erase its own trail | ✅ | ✅ | ✅ |
| Unauthenticated surface — `/health`, `/ready`, `/healthz`, `/readyz` only | ✅ | ✅ | ✅ |
| Probes disclose no build version | ✅ | ✅ | ✅ |
| Readiness proves DB **and** Master pin, via a typed query | ✅ | ✅ **(converged)** | ✅ |
| Inbound HMAC posture | unconditional, every key | per-key configurable | ⚖️ **Intentional** |

**21 of 22 controls identical.** The exception is the authentication posture, permanent and recorded:
the peer speaks to third-party senders that cannot all sign; this project is the internal half of the
pair and has no interoperability argument for a weaker default.

### Two divergences the previous edition recorded, now converged

| Item | 2026-08-10 | Now |
| :--- | :--- | :--- |
| Readiness query | peer used a literal `SELECT 1`, allowlisted in its own hygiene test | peer moved to **SeaORM's typed builder**; the allowlist entry is gone. `api/health.rs:69` records the reason |
| Readiness scope | peer checked the database only | peer now also asserts `master_pin.get()` — `api/health.rs:116` |

Both moved toward this project's stricter position, and neither move was requested by the previous
report — the peer's own audit reached the same conclusion independently.

---

## 4. Payload and input strictness

| Control | Current project | Peer | Parity |
| :--- | :--- | :--- | :--- |
| `deny_unknown_fields` on both key payload types | ✅ | ✅ | ✅ |
| Total sites in `src/api/` | 5 | 7 | Equivalent — tracks endpoint count |
| `is_master` on any **payload** type | ❌ 0 | ❌ 0 | ✅ |
| `is_master` on **response** DTOs | ✅ full view only | ✅ | ✅ read-only projection |
| Strict JSON extractor | `StrictJson` | `StrictJson` | ✅ |
| Optional-body extractor | `OptionalStrictJson` | `OptionalStrictJson` | ✅ |
| Oversized body preserves `413` rather than flattening to `400` | ✅ `AppError::BodyRejected` | ✅ same variant | ✅ |
| Body limit applied pre-auth | ✅ 3 MiB, one constant shared with the HMAC buffer | ✅ | ✅ |

The §5 control lives in the **type** on both sides: the request is refused by serde before any handler
runs, which is what the specification requires — *"removing the field from the payload type is
required; rejecting it at the handler is not sufficient, since a later handler can reintroduce the
path."*

---

## 5. Verification discipline

Parity in controls matters less than parity in the mechanisms that keep controls honest. Both projects
carry the same set.

| Mechanism | Current project | Peer |
| :--- | :--- | :--- |
| `RBAC_MODEL.md` byte-identity gate | ✅ | ✅ |
| Compliance suite, one test per rule | 25 tests, 12 prefixes | 24 tests, 12 prefixes |
| Adversarial tests bypassing the application layer | 5 | 5 |
| Raw-SQL / DML ban at `cargo test` | ✅ | ✅ |
| Convergence script | ✅ | ✅ |
| e2e suite | ✅ | ✅ |

The adversarial requirement is the direct institutional response to D1, where cooperative tests
certified a bypassable constraint. Both projects enforce it through an automated gate and differ only
in how a test is *marked*: this project uses a doc-comment token `ADVERSARIAL(§N)`, the peer makes the
function name `<rule>_adversarial_…` load-bearing. Equivalent rigour, divergent convention — recorded
so no future audit re-raises it as a gap.

---

## 6. Gate status

| Gate | Current project |
| :--- | :--- |
| `cargo test` | **260 passed**, 0 failed |
| `./scripts/verify_convergence.sh` | **exit 0** — 62 matching, 0 divergences, 0 unexplained |
| `git diff RBAC_MODEL.md` | empty |
| `git status --porcelain src/ tests/` | empty — read-only compliance |

---

## 7. Executive verdict

**Every security finding ever raised against either project is closed — 8 of 8.** The last open item,
the peer's unvalidated `INITIAL_MASTER_KEY`, was closed in `4865a82`. There is no outstanding security
work in the ecosystem.

**Security parity is 21 of 22 controls.** The exception is the authentication posture — a deliberate,
documented, permanent asymmetry, not a gap.

The most informative development is not any single fix but the *direction* of the last two. On the
readiness probe the peer independently abandoned a literal `SELECT 1` for a typed query and added the
Master-pin assertion, adopting this project's stricter position without being asked. On the master key
its implementation went slightly further, naming the offending character. Convergence is no longer one
service copying the other after an audit; both are arriving at the same answers, and occasionally
overshooting each other.

**Maturity.** The controls themselves have been stable for several sessions. What distinguishes these
codebases now is that each carries the machinery to detect its own regressions: a byte-identity check
on the shared specification, one compliance test per rule with an enforced adversarial subset, a
raw-SQL ban that runs on every `cargo test`, and a convergence gate. D1 remains the reference failure —
a rule documented as enforced, covered by passing tests, and bypassable in fact. Every mechanism above
exists so that the next D1 fails loudly instead of passing quietly.

**Verdict: converged, and production-ready on both sides.** No finding in this audit blocks deployment
of either service, and none is carried forward.
