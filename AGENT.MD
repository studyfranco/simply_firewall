# Simply Firewall - AI Agent Context & Directives

Hello AI Agent! If you are reading this, you are assisting with the development of the `simply_firewall` repository. Please read and strictly adhere to the architectural guidelines below before modifying any code.

## 🎯 Project Overview

`simply_firewall` is a lightweight, centralized Firewall and ACL management API written in Rust. It serves as a single source of truth for IP banning/whitelisting and dispatches webhook events when rules change. It includes a multi-tenant, Role-Based Access Control (RBAC) web dashboard built without modern frontend frameworks.

## 🛠️ Tech Stack & Constraints

- **Backend:** Rust + Axum + Tokio.
- **ORM (SQL-Agnostic):** SeaORM. While the project defaults to **SQLite** for zero-configuration local development and testing, the architecture relies on SeaORM to remain strictly **SQL-agnostic** (PostgreSQL or MySQL ready). Do not write SQLite-specific raw queries.
- **Frontend:** STRICTLY Vanilla JS, HTML5, and standard CSS. **Absolutely NO external dependencies** (No React, Vue, Tailwind, Bootstrap, CDN links, or Axios). Native `fetch()` only.

## 🏛️ Core Architectural Rules

### 1. Security & Authentication (Zero-Trust)

- Every route under `/api/*` is protected by a custom middleware (`src/middleware.rs`).
- Authentication requires an `X-API-Key` header.
- **CIDR Validation:** Keys are bound to specific network ranges (`bound_ips`, supporting multiple comma-separated CIDRs like `127.0.0.1/32, ::/0`).
- **Resilient IP Extraction:** We DO NOT use external crates like `axum-client-ip`. The middleware safely extracts the rightmost IP from `X-Forwarded-For` and falls back to `axum::extract::ConnectInfo` for direct TCP access.
- **State Injection:** The authenticated `api_key::Model` is injected into the request state by the middleware (`req.extensions_mut().insert(...)`) for downstream handlers to use.

### 2. RBAC & Tenant Isolation

- Keys have granular boolean permissions (`can_view_ips`, `can_add_ips`, `is_master`, etc.).
- **Scoping (Multi-Tenant):** If a key has a `group_id` assigned (and `is_master == false`), it is strictly isolated to that tenant. The backend MUST enforce this at the database level: silently forcing the `group_id` on INSERTs, and filtering by `group_id` on SELECT/DELETEs.

### 3. Database Handling & First Boot

- Database connections use `ConnectOptions` with SQLx logging set to `DEBUG` to prevent console spam.
- Migrations are run automatically on application startup.
- **Master Key Auto-Gen:** If the `api_keys` table is empty on startup, the application auto-generates a default Master Key and logs it to the console.
- **Key Recovery:** If the developer loses the Master Key in a local/test environment, the standard procedure is to delete the `.sqlite` file and restart the application to generate a new database and key.

### 4. Immutable Logic & UX

- **Locked IPs:** `IpRecord` has an `is_locked` boolean. If true, the API MUST reject modifications or deletions (HTTP 403).
- **Group Names over UUIDs:** The frontend interacts with `group_name` strings, not UUIDs. The backend dynamically resolves or creates the `IpGroup` on the fly during POST operations.

### 5. Frontend Paradigm

- The UI is a Single Page Application (SPA).
- Authentication state is held in `localStorage`.
- The JS implements a global fetch wrapper that automatically injects the `X-API-Key` header and intercepts `401/403` responses to instantly clear the token and log the user out.
- The UI dynamically hides/shows elements based on the RBAC payload received from `GET /api/auth/me`.

### 6. Testing (cURL + cargo)

Compilation via cargo build or cargo check is allowed and recommended to validate syntax.
To test endpoints manually, developers use `curl`. Examples:

- **Auth check:** `curl -H "X-API-Key: <KEY>" http://localhost:3000/api/auth/me`
- **List IPs:** `curl -H "X-API-Key: <KEY>" "http://localhost:3000/api/ips?limit=10&offset=0"`
- **Ban IP:** `curl -X POST -H "X-API-Key: <KEY>" -H "Content-Type: application/json" -d '{"target_address": "192.168.1.100/32", "group_name": "Test Group"}' http://localhost:3000/api/ban`

*End of directives. Write safe, panic-free (`no .unwrap()`), and elegant Rust code.*
