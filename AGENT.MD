# Simply Firewall - AI Agent Context & Directives

Hello AI Agent! If you are reading this, you are assisting with the development of the `simply_firewall` repository. Please read and strictly adhere to the architectural guidelines below before modifying any code.

## 🎯 Project Overview

`simply_firewall` is a lightweight, centralized Firewall and ACL management API written in Rust. It serves as a single source of truth for IP banning/whitelisting and dispatches webhook events when rules change. It includes a multi-tenant, Role-Based Access Control (RBAC) web dashboard built without modern frontend frameworks.

## 🛠️ Tech Stack & Constraints

- **Backend Framework:** Rust + Axum.
- **Async Runtime:** Tokio.
- **ORM & Database:** SeaORM using SQLite by default. It use other database if needed.
- **Frontend:** STRICTLY Vanilla JS, HTML5, and standard CSS. **Absolutely NO external dependencies** (No React, Vue, Tailwind, Bootstrap, CDN links, or Axios). Native `fetch()` only.

## 🏛️ Core Architectural Rules

### 1. Security & Authentication (Zero-Trust)

- Every route under `/api/*` is protected by a custom middleware (`src/middleware.rs`).
- Authentication requires an `X-API-Key` header.
- **CIDR Validation:** The API key is bound to a specific network range (`bound_ips`). The middleware validates the client's IP against these CIDRs.
- **Resilient IP Extraction:** We DO NOT use external crates like `axum-client-ip`. The middleware uses custom logic to read the rightmost IP from `X-Forwarded-For` (for Traefik/Prod), and safely falls back to `axum::extract::ConnectInfo` for direct TCP testing.

### 2. RBAC & Tenant Isolation

- Keys are categorized by permissions (e.g., `can_view_ips`, `can_add_ips`, `is_master`).
- **Scoping:** If a key has a `group_id` assigned (and is not master), it is isolated to that specific tenant. The backend must enforce this at the database query level (forcing the `group_id` on INSERT, and filtering by `group_id` on SELECT/DELETE).
- The authenticated `api_key::Model` is injected into the request state by the middleware for downstream handlers to use.

### 3. Immutable Logic

- **Locked IPs:** `IpRecord` has an `is_locked` boolean. If true, the API MUST reject modifications or deletions (HTTP 403).
- **Group Names over UUIDs:** The frontend interacts with `group_name` strings, not UUIDs. The backend dynamically resolves or creates the `IpGroup` on the fly during POST operations, and JOINs the group name during GET operations.

### 4. Database Handling

- Database connections use `ConnectOptions` with SQLx logging set to `DEBUG` to prevent console spam.
- Migrations are run automatically on application startup.
- If the `api_keys` table is empty on startup, the application auto-generates a Master Key and logs it to the console.

### 5. Frontend Paradigm

- The UI is a Single Page Application (SPA).
- Authentication state is held in `localStorage`.
- The JS implements a global fetch wrapper that injects the `X-API-Key` header and intercepts `401/403` responses to instantly log the user out.
- The UI dynamically hides/shows elements based on the payload received from `GET /api/auth/me`.

*End of directives. Write safe, panic-free (`no .unwrap()`), and elegant Rust code.*
