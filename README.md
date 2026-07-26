# simply_firewall

Simply efficient. A homelab firewall.

`simply_firewall` is a small, self-hosted API and dashboard for centrally managing IP ban/whitelist
rules across your infrastructure. It's the single source of truth for "is this address allowed?",
and can notify other systems (or other `simply_firewall` instances) of changes via signed,
templated webhooks.

- **Backend:** Rust, Axum, SeaORM (SQLite by default, zero config).
- **Frontend:** a single-page dashboard in `static/` — vanilla HTML/CSS/JS, no build step, no
  external dependencies.
- **Access control:** every API key can be a full master key, or scoped with fine-grained
  per-group read/write/delete rights plus a handful of global privileges (manage keys, manage
  webhooks, create groups).

## Features

- Ban or whitelist single IPs or CIDR ranges (IPv4 and IPv6), organized into named groups.
- Re-registering an address just refreshes its `last_seen_at` — safe to call repeatedly (e.g. from
  fail2ban) without creating duplicates or erroring.
- An address can belong to multiple groups at once, including simultaneously to a `banlist` and a
  `whitelist` group; the dashboard flags that as a conflict.
- Query IPs by group, address/cause substring, ban-vs-whitelist status, or recency (`max_age`/
  `since`).
- Multi-tenant RBAC: API keys can be scoped to exactly the groups (and read/write/delete rights)
  they need.
- Webhooks: HMAC-SHA256-signed (`X-Signature-256`), templated JSON payloads, custom headers, with
  SSRF protection against private/loopback targets by default.
- Every mutating action is recorded in an audit log.

## Getting Started

### Prerequisites

- A recent stable Rust toolchain (edition 2024).
- No database server to install — SQLite is used out of the box.

### Run it

```bash
cargo run
```

On first boot, `simply_firewall`:

1. Connects to the database (creating the SQLite file if needed) and runs all pending migrations
   automatically.
2. Checks whether any API key with master rights exists. If not — which is always true on a brand
   new database, and also true again if every master key is ever deleted later — it generates one
   and prints it **once**, to stdout, in a boxed banner:

   ```
   ╔══════════════════════════════════════════════════════════════╗
   ║  BOOTSTRAP: Master API Key Generated                       ║
   ║  Key:    <64 hex characters>                                ║
   ║  Bound:  0.0.0.0/0                                             ║
   ║  ⚠ This key will NOT be shown again. Store it securely!    ║
   ╚══════════════════════════════════════════════════════════════╝
   ```

   Copy that key immediately — only its SHA-256 hash is stored, so it cannot be recovered later.
   If you lose every master key, just delete the corresponding rows from `api_keys` (or the whole
   database, for a fresh start) and restart; a new one will be generated the same way.
3. Starts listening on `0.0.0.0:3000` and serves the dashboard from `static/` at `/`.

Open `http://localhost:3000` and paste the key into the login screen, or drive the API directly
with `curl` (see below).

### Configuration

All configuration is via environment variables (a `.env` file in the working directory is loaded
automatically if present):

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `DATABASE_URL` | `sqlite://firewall.db?mode=rwc` | SeaORM connection string. |
| `BOOTSTRAP_SUBNET` | `0.0.0.0/0` | `bound_ips` assigned to the auto-generated master key. |
| `ALLOW_PRIVATE_WEBHOOKS` | `false` | Set to `true` to allow webhook targets on private/loopback/link-local addresses (useful for local testing; leave `false` in production to keep SSRF protection active). |
| `RUST_LOG` | `info` | Standard `tracing-subscriber` env filter, e.g. `debug`, `simply_firewall=debug`. |

The listen address is currently fixed at `0.0.0.0:3000`.

### Docker

A `Dockerfile` and `docker-compose.yml` are included:

```bash
docker compose up --build
```

This persists the database under `./data` and exposes port `3000`.

## API Reference

Every route below is nested under `/api` and requires an `X-API-Key` header; missing or invalid
keys get `401`, and keys whose `bound_ips` CIDRs don't cover the caller's (proxy-aware) source
address get `403`. Master keys bypass all group/CIDR checks.

| Method | Path | Purpose |
| :--- | :--- | :--- |
| `GET` | `/api/auth/me` | Identity + effective RBAC permissions for the calling key. |
| `POST` | `/api/ban` | Add/refresh an address in a `banlist` group. |
| `POST` | `/api/white` | Add/refresh an address in a `whitelist` group. |
| `GET` | `/api/ips` | List IP records (see filters below). |
| `DELETE` | `/api/ips` | Remove an address from a group. |
| `POST` / `GET` | `/api/keys` | Create / list API keys (requires `is_master` or `can_manage_keys`). |
| `DELETE` | `/api/keys/{id}` | Delete an API key. |
| `POST` | `/api/keys/{id}/groups` | Grant/update a key's read/write/delete rights on a group. |
| `POST` / `GET` | `/api/groups` | Create / list IP groups. |
| `DELETE` | `/api/groups/{id}` | Delete a group (cascades its memberships and permissions). |
| `POST` / `GET` | `/api/webhooks` | Create / list webhook configs. |
| `DELETE` | `/api/webhooks/{id}` | Delete a webhook config. |

`GET /api/ips` query parameters: `groups=fail2ban,sshd` (or singular `group_name=`), `ip=<substring>`,
`cause=<substring>`, `status=ban|white`, `max_age=<seconds>`, `since=<unix timestamp>`, `limit`,
`offset`. All filters combine with AND semantics and are always narrowed by the caller's own group
permissions first.

### Examples

```bash
# Who am I / what can I do?
curl -H "X-API-Key: <KEY>" http://localhost:3000/api/auth/me

# Ban an address into the "fail2ban" group
curl -X POST -H "X-API-Key: <KEY>" -H "Content-Type: application/json" \
  -d '{"target_address": "192.168.1.100", "group_name": "fail2ban", "cause": "SSH brute force"}' \
  http://localhost:3000/api/ban

# Whitelist a CIDR range
curl -X POST -H "X-API-Key: <KEY>" -H "Content-Type: application/json" \
  -d '{"target_address": "10.0.0.0/24", "group_name": "vpn"}' \
  http://localhost:3000/api/white

# List recently-seen banned IPs in specific groups
curl -H "X-API-Key: <KEY>" "http://localhost:3000/api/ips?groups=fail2ban,sshd&status=ban&max_age=3600"

# Remove an address from a group
curl -X DELETE -H "X-API-Key: <KEY>" \
  "http://localhost:3000/api/ips?target_address=192.168.1.100&group_name=fail2ban"

# Create a scoped API key
curl -X POST -H "X-API-Key: <MASTER_KEY>" -H "Content-Type: application/json" \
  -d '{"name": "ci-bot", "bound_ips": "10.0.0.0/8", "can_create_groups": true}' \
  http://localhost:3000/api/keys
```

## Development

```bash
cargo check --all-targets            # compile everything, including tests
cargo test                           # integration tests, run against sqlite::memory:
cargo clippy --all-targets -- -D warnings
```

Integration tests live in `tests/` and spin up a fresh in-memory SQLite database per test — no
external services required.

See `AGENT.MD` for the full architectural/security ruleset this project is built and audited
against, `SCHEMA.MD` for the database schema, and `AGENT_NOTES.MD` for the running audit worklog.

## License

GPLv3 — see [LICENSE](LICENSE).
