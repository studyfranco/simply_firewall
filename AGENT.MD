# Simply Firewall - AI Agent Context & Directives

Hello AI Agent! You are assisting with the development of `simply_firewall`. Read and strictly adhere to these guidelines before inspecting or writing any code.

---

## 📄 Document & Context Hierarchy

To keep this context clean and modular, responsibilities are split across three files:
1. **`AGENT.MD`** *(This file)*: Core architectural rules, security constraints, documentation standards, and testing directives.
2. **`SCHEMA.MD`**: Official Database Schema, SeaORM Entity relations, M:N RBAC definitions, and Enum specifications.
3. **`AGENT_NOTES.MD`**: Agent worklog. You MUST update this file with architectural decisions, progress notes, or pending tasks after completing significant modifications.

---

## 🎯 Project Overview

`simply_firewall` is an enterprise-grade, central Firewall and ACL management API written in Rust. It acts as the single source of truth for IP banning/whitelisting and dispatches signed, templated webhook events to downstream systems or other `simply_firewall` instances. It features an integrated Vanilla JS dashboard governed by a granular multi-tenant Role-Based Access Control (RBAC) system.

---

## 🛠️ Tech Stack & Constraints

- **Backend:** Rust + Axum (0.8+) + Tokio (1.x).
- **ORM (SQL-Agnostic):** SeaORM (2.0+). Defaults to **SQLite** for zero-config local development/testing, but MUST remain strictly **SQL-agnostic** (PostgreSQL-ready). **Never write vendor-specific raw SQL queries.**
- **Frontend:** STRICTLY Vanilla JS, HTML5, and CSS3. **NO external dependencies** (No React, Vue, Tailwind, Bootstrap, CDN links, or Axios). Native `fetch()` only.
- **Quality & Safety:**
  - Zero compiler warnings, zero `clippy` warnings.
  - **Zero `.unwrap()` or `.expect()`** in production or HTTP handlers. Use structured `AppError` and Axum's `IntoResponse`.
  - **Mandatory `rustdoc`**: All public modules, structs, enums, functions, and Axum handlers MUST be documented using `///` (or `//!` for crates/modules). Enforce `#![warn(missing_docs)]` in `lib.rs`.

---

## 🏛️ Core Architectural Rules

### 1. Security & Network (Zero-Trust)

- **Middleware Protection:** All `/api/*` routes pass through custom authentication middleware (`src/middleware.rs`).
- **Authentication:** Verified via `X-API-Key` header.
- **CIDR Restriction:** API Keys are bound to CIDR network ranges (`bound_ips`, supporting comma-separated IPv4/IPv6 ranges like `127.0.0.1/32, 10.0.0.0/8, ::/0`). Middleware MUST validate the client's IP against these bounds.
- **Resilient IP Extraction:** Do NOT use external IP extraction crates. Extract the rightmost IP from `X-Forwarded-For` or `X-Real-IP`, falling back safely to `axum::extract::ConnectInfo`.

### 2. Granular Multi-Tenant RBAC (M:N)

- **Global Rights:** An `ApiKey` can be `is_master` (bypasses all checks) or hold global booleans (`can_manage_keys`, `can_manage_webhooks`, `can_create_groups`).
- **Group Rights:** Managed via junction table `ApiKeyGroupPermission` linking keys to `IpGroup` with explicit flags (`can_read`, `can_write`, `can_delete`).
- **Least Privilege:** `can_write` or `can_delete` require `can_read` to be true.
- **Auto-Provisioning:** When an API Key creates a new `IpGroup`, the backend MUST automatically generate full read/write/delete permissions for that key on the new group.

### 3. IP Management & Query Filtering

- **IPv4 & IPv6 CIDRs:** Full support for single IPs and subnet ranges (e.g., `/24`, `/64`).
- **Rerecord Tracking:** Store `created_at` and `last_seen_at`. Re-registering an existing IP updates `last_seen_at` rather than failing.
- **Multi-Group Membership:** An IP can belong to multiple `IpGroup`s simultaneously.
- **Group Tagging:** A group can be tag as whitelist or banlist. By default it is a banlist.
- **Flexible Fetching (`GET /api/ips`):**
  - Parameter `groups=fail2ban,sshd` (or singular `group_name=fail2ban`): Filters IPs belonging to specified groups. If omitted, returns all IPs accessible to the API Key.
  - Parameter `max_age=3600` or `since=<unix_timestamp>`: Temporal filtering based on `last_seen_at`, applied at the query level (before pagination). (No automatic TTL deletion worker exists; filtering is strictly query-driven).
  - Parameter `ip=<substring>`: Filters by a substring of `target_address`.
  - Parameter `cause=<substring>`: Filters by a substring of `cause`.
  - Parameter `status=ban|white`: Filters to only the group type (`banlist`/`whitelist`) matching the associated IP group.
  - Each result row includes the associated `group_type`, so a single address in both a `banlist` and a `whitelist` group is distinguishable per-row (used by the dashboard's conflict-highlighting badge).

### 4. Advanced & Secure Webhooks

- **Group Scoping:** Webhooks are bound to specific `IpGroup`s. Actions on IPs in those groups dispatch asynchronous HTTP POST requests via Tokio tasks.
- **Templating & Headers:** Custom JSON payload templates (e.g., `{"ip": "$target_address", "group": "$group_name"}`) and custom HTTP headers (e.g., `X-API-Key` for chaining `simply_firewall` instances).
- **HMAC Signatures:** All webhook dispatches MUST include a signature header: `X-Signature-256: sha256=<hex_hmac>` calculated using the webhook's secret token.
- **SSRF Prevention:** Validate target URLs. Reject private/loopback IP ranges (RFC 1918, RFC 4193, loopback) unless `ALLOW_PRIVATE_WEBHOOKS=true` is set in environment.

### 5. Frontend Integration & Dynamic UI

- The UI is a Single Page Application (SPA). Authentication state is held in `localStorage`.
- Single Page Application served from `static/`.
- Authenticates via `X-API-Key` stored in `localStorage`.
- **Dynamic Permission Rendering:** On startup, `app.js` calls `GET /api/auth/me`. The UI dynamically renders/hides tabs and controls (e.g., Webhooks, Key Management) based solely on the returned permissions based on the RBAC payload received from `GET /api/auth/me`.
- The JS implements a global fetch wrapper that automatically injects the `X-API-Key` header and intercepts `401/403` responses to clear the token and return to the login screen.

### 6. Audit Logging

- Every write/delete operation generates an `AuditLog` entry storing `api_key_id`, `action`, `target_ip`, affected groups, and timestamp.

### 7. Database Bootstrapping

- Database connections use `ConnectOptions` with SQLx logging set to `DEBUG` to prevent console spam.
- Migrations run automatically on startup.
- **Master Key Auto-Gen:** If `api_keys` contains no master keys at boot, generate a default Master Key and output it once clearly to `stdout`.

---

## 🧪 Testing & Validation Standards

- **Integration Tests:** Located in `tests/`. Use SQLite in-memory (`sqlite::memory:`) for test isolation.
- **Coverage Mandatory Requirements:**
  1. **Positive RBAC:** Authorized keys successfully read/write allowed groups.
  2. **Negative RBAC:** Unauthorized attempts MUST return HTTP `403 Forbidden`.
  3. **Webhook Signatures:** Mock HTTP endpoints (e.g., via Tokio task) verifying payload delivery and HMAC `X-Signature-256` validity.
  4. **Multi-Group & Temporal Querying:** Validate `GET /api/ips` with group filters and `max_age`/`since` constraints.

Compilation via `cargo build` or `cargo check` is recommended to validate syntax. Integration tests reside in `tests/` using SQLite in-memory (`sqlite::memory:`).
To test endpoints manually during development, use `curl`:

- **Auth check:**
  `curl -H "X-API-Key: <KEY>" http://localhost:3000/api/auth/me`
- **Ban an IP (adds it to a banlist group):**
  `curl -X POST -H "X-API-Key: <KEY>" -H "Content-Type: application/json" -d '{"target_address": "192.168.1.100/32", "group_name": "fail2ban", "cause": "SSH brute force"}' http://localhost:3000/api/ban`
- **List IPs (Filtered by groups):**
  `curl -H "X-API-Key: <KEY>" "http://localhost:3000/api/ips?groups=fail2ban,sshd&limit=10"`
- **Delete IP:**
  `curl -X DELETE -H "X-API-Key: <KEY>" "http://localhost:3000/api/ips?target_address=192.168.1.100/32&group_name=fail2ban"`

### 1. Mandatory Test Matrix per Endpoint
For every route registered under `/api`, tests MUST assert three distinct outcomes:
  1. **Positive Assertion (200/201 OK):** Valid payload with sufficient permissions returns expected JSON structure and persists changes in DB.
  2. **Authentication Check (401 Unauthorized):** Missing, invalid, or revoked `X-API-Key` header immediately rejects the request.
  3. **Authorization Boundary (403 Forbidden):** Valid API key lacking explicit scope or group permission is denied access.
  4. **Validation Check (400 Bad Request):** Malformed CIDR blocks, bad URLs, or invalid JSON payloads are rejected before processing.

### 2. Required Endpoint Test Coverage

  - **Authentication Profile (`GET /api/auth/me`):**
    - Verify returned global scopes and group permissions match the database state.
  - **IP Records (`POST /api/ban`, `POST /api/white`, `GET /api/ips`, `DELETE /api/ips`):**
    - Verify IP insertion and `last_seen_at` updates on duplicate records.
    - Test filtering via `?groups=g1,g2` and temporal filtering via `?max_age=3600`.
    - Assert non-authorized keys cannot write to groups where `can_write = false`.
  - **API Keys Management (`GET /api/keys`, `POST /api/keys`, `DELETE /api/keys/{id}`, `POST /api/keys/{id}/permissions`):**
    - Test master-only access for key generation and revocation.
    - Verify cascading deletion cleans `api_key_group_permissions` without orphan records.
  - **Group Management (`GET /api/groups`, `POST /api/groups`, `DELETE /api/groups/{id}`):**
    - Test auto-provisioning of permissions when a key creates a new group.
  - **Webhooks (`GET /api/webhooks`, `POST /api/webhooks`, `DELETE /api/webhooks/{id}`):**
    - Verify URL validation (HTTP/HTTPS required, private IPs blocked).
    - Test HMAC SHA-256 signature header (`X-Signature-256`) generation.
  - **Audit Trail (`GET /api/audit-logs`):**
    - Verify mutating actions write audit entries and read access is restricted to `is_master` keys.

### 3. API Contract Flexibility & Lifecycle Validation
  - **Query & Group Identification:**
    Endpoints manipulating group permissions (`/api/keys/{id}/permissions`) or records (`/api/ips`, `/api/ban`, `/api/white`) MUST accept both `group_id` (UUID) and `group_name` (string) seamlessly.
  - **Flexible Body / Query Deserialization (`DELETE /api/ips`):**
    `DELETE /api/ips` MUST accept parameters both via URL Query strings (`?target_address=...&group_name=...`) and via JSON request body (`{"target_address": "...", "group_name": "..."}`).
  - **Key Rotation & Editing:**
    `POST /api/keys/{id}/rotate` MUST generate a new secret while keeping key ID/name intact and invalidating the old secret. `PUT /api/keys/{id}` MUST allow updating key name, bound IPs, and global scopes.
  - **Revoking Group Permissions:**
    `DELETE /api/keys/{id}/permissions/{group_identifier}` MUST remove specific group permission mappings from a key.
  - **Audit Log Interface & Endpoint:**
    All mutating actions MUST write audit logs, accessible via `GET /api/audit-logs` for Master keys and rendered in a dedicated UI panel.

*End of directives. Write safe, panic-free (`no .unwrap()`), and elegant Rust code.*