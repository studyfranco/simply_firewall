# simply_ip_vault

Simply efficient. A homelab firewall.

`simply_ip_vault` is a small, self-hosted API and dashboard for centrally managing IP ban/whitelist
rules across your infrastructure. It's the single source of truth for "is this address allowed?",
and can notify other systems (or other `simply_ip_vault` instances) of changes via signed,
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

On first boot, `simply_ip_vault`:

1. Connects to the database (creating the SQLite file if needed) and runs all pending migrations
   automatically.
2. Checks whether any API key with master rights exists. If not — which is always true on a brand
   new database, and also true again if every master key is ever deleted later — it generates one
   and prints it **once**, to stdout, in a boxed banner:

   ```
   ╔══════════════════════════════════════════════════════════════════════════════════╗
   ║ BOOTSTRAP: Master API Key Generated                                              ║
   ╠══════════════════════════════════════════════════════════════════════════════════╣
   ║ X-API-Key      : <64 hex characters>                                             ║
   ║ Signing secret : <64 hex characters>                                             ║
   ║ Bound IPs      : 0.0.0.0/0                                                       ║
   ║                                                                                  ║
   ║ Both values are needed to sign requests (X-Timestamp + X-Signature-256).         ║
   ║ They will NOT be shown again — store them securely!                              ║
   ╚══════════════════════════════════════════════════════════════════════════════════╝
   ```

   Copy **both** values immediately. Only the key's SHA-256 hash is stored, and the signing secret
   is stored encrypted (or, without `VAULT_ENCRYPTION_KEY`, raw) but never echoed back — neither can
   be recovered from the API afterwards. If you lose every master credential, delete the
   corresponding rows from `api_keys` (or the whole database, for a fresh start) and restart; a new
   pair will be generated the same way.
3. Starts listening on `0.0.0.0:3000` and serves the dashboard from `static/` at `/`.

Open `http://localhost:3000` and paste **both** the key and the signing secret into the login
screen, or drive the API directly with `curl` (see below).

> **Note:** the dashboard signs requests with the Web Crypto API, which browsers only expose in a
> secure context. `http://localhost` works; serving the UI over plain HTTP to a LAN address does
> not — put it behind TLS.

### Configuration

All configuration is via environment variables (a `.env` file in the working directory is loaded
automatically if present):

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `DATABASE_URL` | `sqlite://simply_ip_vault.db?mode=rwc` | SeaORM connection string. |
| `BOOTSTRAP_SUBNET` | `0.0.0.0/0` | `bound_ips` assigned to the auto-generated master key. |
| `ALLOW_PRIVATE_WEBHOOKS` | `false` | Set to `true` to allow webhook targets on private/loopback/link-local addresses (useful for local testing; leave `false` in production to keep SSRF protection active). |
| `VAULT_ENCRYPTION_KEY` | *(unset)* | Passphrase (any length) used to encrypt each API key's HMAC `signing_secret` at rest with AES-GCM-256. **Unset means signing secrets are stored in plaintext** — the zero-config development default, warned about at startup. Set it for any real deployment, and keep it: losing it makes every existing key unauthenticatable (they must then be rotated). |
| `RUST_LOG` | `info` | Standard `tracing-subscriber` env filter, e.g. `debug`, `simply_ip_vault=debug`. |

The listen address is currently fixed at `0.0.0.0:3000`.

### Docker

A `Dockerfile` and `docker-compose.yml` are included:

```bash
docker compose up --build
```

This persists the database under `./data` and exposes port `3000`.

## API Reference

Every route below is nested under `/api` and requires **three** headers — an API key alone is not
enough:

| Header | Value |
| :--- | :--- |
| `X-API-Key` | The plaintext key. Identifies which key record to look up. |
| `X-Timestamp` | Current UTC Unix time in seconds. Rejected if more than **300s** from the server's clock, in either direction (anti-replay). |
| `X-Signature-256` | Hex HMAC-SHA256 of `METHOD + PATH + TIMESTAMP + RAW_BODY` (concatenated, no separator), keyed with the key's **signing secret**. `PATH` excludes the query string. |

The signing secret is issued alongside the key by `POST /api/keys` and `POST /api/keys/{id}/rotate`
and is shown **once** — it is never returned by any read endpoint. See the `call()` helper under
[Examples](#examples) for a copy-pasteable signing implementation.

Missing/invalid credentials or a stale timestamp get `401`; keys whose `bound_ips` CIDRs don't cover
the caller's (proxy-aware) source address get `403`. Master keys bypass all group/CIDR checks.

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

Requests must be signed, so these examples go through a small helper. Drop it into your shell
(requires `openssl`):

```bash
KEY="<PLAINTEXT_API_KEY>"
SECRET="<SIGNING_SECRET>"     # shown once, when the key is created or rotated

# call METHOD PATH [JSON_BODY]
call() {
  local method="$1" path="$2" body="${3:-}"
  local ts; ts=$(date -u +%s)
  # The query string is stripped before signing, but still sent.
  local sig; sig=$(printf '%s' "${method}${path%%\?*}${ts}${body}" \
                   | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.*= //')
  curl -sS -X "$method" \
    -H "X-API-Key: $KEY" -H "X-Timestamp: $ts" -H "X-Signature-256: $sig" \
    ${body:+-H "Content-Type: application/json" -d "$body"} \
    "http://localhost:3000$path"
}
```

```bash
# Who am I / what can I do?
call GET /api/auth/me

# Ban an address into the "fail2ban" group
call POST /api/ban \
  '{"target_address": "192.168.1.100", "group_name": "fail2ban", "cause": "SSH brute force"}'

# Whitelist a CIDR range
call POST /api/white '{"target_address": "10.0.0.0/24", "group_name": "vpn"}'

# List recently-seen banned IPs in specific groups
call GET "/api/ips?groups=fail2ban,sshd&status=ban&max_age=3600"

# Remove an address from a group
call DELETE "/api/ips?target_address=192.168.1.100&group_name=fail2ban"

# Create a scoped API key (returns both plaintext_key and signing_secret — copy both)
call POST /api/keys '{"name": "ci-bot", "bound_ips": "10.0.0.0/8", "can_create_groups": true}'
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
