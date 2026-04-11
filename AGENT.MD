# Simply Firewall - AI Agent Context & Directives

Hello AI Agent! If you are reading this, you are assisting with the development of the `simply_firewall` repository. Please read and strictly adhere to the architectural guidelines below before modifying any code.

## 🎯 Project Overview

`simply_firewall` is an "Enterprise Grade", centralized Firewall and ACL management API written in Rust. It serves as a single source of truth for IP banning/whitelisting and dispatches templated webhook events when rules change. It includes a multi-tenant, advanced Role-Based Access Control (RBAC) web dashboard built without modern frontend frameworks.

## 🛠️ Tech Stack & Constraints

- **Backend:** Rust + Axum + Tokio.
- **ORM (SQL-Agnostic):** SeaORM. Defaults to **SQLite** for zero-configuration testing, but the architecture MUST remain strictly **SQL-agnostic** (PostgreSQL or MySQL ready). Do not write SQLite-specific raw queries.
- **Frontend:** STRICTLY Vanilla JS, HTML5, and standard CSS. **Absolutely NO external dependencies** (No React, Vue, Tailwind, Bootstrap, CDN links, or Axios). Native `fetch()` only.
- **Quality:** Code must compile cleanly and pass `cargo clippy` without warnings. No `.unwrap()` or `.expect()` in HTTP handlers.

## 🏛️ Core Architectural Rules

### 1. Security & Network (Zero-Trust)

- Every route under `/api/*` is protected by a custom middleware (`src/middleware.rs`).
- Authentication requires an `X-API-Key` header.
- **CIDR Validation:** Keys are bound to specific network ranges (`bound_ips`, supporting multiple comma-separated CIDRs like `127.0.0.1/32, ::/0`). The middleware MUST validate the client's IP against these ranges.
- **Resilient IP Extraction:** We DO NOT use external crates like `axum-client-ip`. The middleware safely extracts the rightmost IP from `X-Forwarded-For` and falls back to `axum::extract::ConnectInfo` for direct TCP access.

### 2. Granular RBAC & Tenant Isolation (Many-to-Many)

- **Global vs Scoped:** An `ApiKey` can be `is_master` (bypasses all rules) or have global boolean rights (`can_manage_keys`, `can_manage_webhooks`, `can_create_groups`).
- **M:N IP Permissions:** IP management rights are managed via a Many-to-Many junction table (`ApiKeyGroupPermission`) linking the API Key to an `IpGroup` with specific booleans (`can_read`, `can_write`, `can_delete`).
- **Rule of Least Privilege:** `can_write` and `can_delete` inherently require `can_read` to be true.
- **Auto-Provisioning:** If an API key creates a new group, the backend MUST automatically grant that key read/write/delete permissions for this new group.

### 3. Advanced Webhooks

- Webhooks trigger on specific actions (e.g., `ban`, `white`, `delete`).
- They support **Payload Templating** to inject variables dynamically (e.g., `{"address": "$ip", "reason": "$cause"}`).
- They support custom authentication headers (e.g., injecting `X-API-Key: <secret>`) to chain instances together.

### 4. Database Handling & First Boot

- Database connections use `ConnectOptions` with SQLx logging set to `DEBUG` to prevent console spam.
- Migrations are run automatically on application startup.
- **Master Key Auto-Gen:** If the `api_keys` table is empty on startup (e.g., newly generated DB), the application auto-generates a default Master Key and logs it to the console. This is crucial for initial setup and testing.
- **Key Recovery:** If the developer loses the Master Key in a local/test environment, the standard procedure is to delete the `.sqlite` file and restart the application to generate a new database and a new master key.

### 5. Frontend Paradigm

- The UI is a Single Page Application (SPA). Authentication state is held in `localStorage`.
- The JS implements a global fetch wrapper that automatically injects the `X-API-Key` header and intercepts `401/403` responses to instantly clear the token and log the user out.
- The UI dynamically hides/shows elements (including Webhook and API Key management menus) based on the RBAC payload received from `GET /api/auth/me`.

### 6. Testing (cURL + cargo)

Compilation via `cargo build` or `cargo check` is allowed and recommended to validate syntax.
To test endpoints manually, developers use `curl`. Examples:

- **Auth check:** `curl -H "X-API-Key: <KEY>" http://localhost:3000/api/auth/me`
- **List IPs:** `curl -H "X-API-Key: <KEY>" "http://localhost:3000/api/ips?limit=10&offset=0"`
- **Ban IP:** `curl -X POST -H "X-API-Key: <KEY>" -H "Content-Type: application/json" -d '{"target_address": "192.168.1.100/32", "group_name": "Test Group", "cause": "Malicious activity"}' http://localhost:3000/api/ban`
*End of directives. Write safe, panic-free (`no .unwrap()`), and elegant Rust code.*
