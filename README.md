# Reflag 🚩

A secure, self-hosted feature flag and remote configuration service with full [OpenFeature](https://openfeature.dev/) specification support.

## Features

- **Full OpenFeature Spec**: Boolean, string, number, and object flag types with targeting rules, percentage rollouts, and default rules
- **Secrets Management**: Encrypted configuration secrets (API tokens, passwords) with AES-256-GCM encryption at rest
- **Secret Feature Flags**: Flags whose variation values reference stored secrets (`{"$secret": "KEY"}`), resolved to decrypted values at evaluation time — use targeting rules to serve different secrets per user/environment
- **Dual Authentication**: OIDC (admin UI) + API keys (programmatic SDK access)
- **Environments**: Per-environment flag overrides (production, staging, etc.)
- **Segments**: Reusable targeting segments for audience management
- **Audit Logging**: Every change is tracked with actor, action, and timestamp
- **Security Hardened**: Rate limiting, CSP headers, CSRF protection, secure API key hashing (SHA-256)
- **Single Binary**: Go backend with embedded React frontend — no runtime dependencies
- **Pure-Go SQLite**: No CGO, cross-compiles trivially

## Tech Stack

- **Backend**: Go 1.22+, `net/http` ServeMux, `modernc.org/sqlite` (pure-Go SQLite)
- **Frontend**: React 19, Vite 6, TanStack Query, Tailwind CSS v4, shadcn/ui-style components
- **Auth**: OIDC (admin UI via JWT), API keys (programmatic, SHA-256 hashed)
- **Database**: SQLite with WAL mode

## Quick Start

### Docker

```bash
docker compose up -d
```

The server starts on `http://localhost:8080`.

### Local Development

**Backend:**
```bash
go run .
```

**Frontend (hot reload):**
```bash
cd web && npm install && npm run dev
```

The Vite dev server proxies API calls to `:8080`.

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Server port |
| `DB_PATH` | `reflag.db` | SQLite database path |
| `JWT_SECRET` | dev-only | Secret for JWT signing (min 32 chars in production) |
| `OIDC_ISSUER` | (none) | OIDC provider issuer URL |
| `OIDC_CLIENT_ID` | (none) | OIDC client ID |
| `OIDC_CLIENT_SECRET` | (none) | OIDC client secret |
| `OIDC_REDIRECT_URL` | (none) | OIDC redirect URL |
| `SECRETS_KEY` | (derived from JWT_SECRET) | Encryption key for secrets at rest (min 32 chars) |
| `APP_ENV` | (none) | Set to `production` for prod mode |

## API

### Evaluate a Flag (OpenFeature-compatible)

```bash
# Using API key
curl -X POST http://localhost:8080/api/v1/flags/evaluate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: rfk_..." \
  -d '{
    "flagKey": "my-feature",
    "environment": "production",
    "context": {
      "targetingKey": "user-123",
      "attributes": { "email": "user@example.com" }
    }
  }'
```

Response:
```json
{
  "value": true,
  "variant": "True",
  "reason": "TARGETING_MATCH"
}
```

### Admin API

All admin endpoints require a JWT (from OIDC login):

- `GET/POST /api/flags` — List/create flags
- `GET/PUT/DELETE /api/flags/{id}` — Get/update/delete flag
- `GET/POST /api/environments` — List/create environments
- `DELETE /api/environments/{id}` — Delete environment
- `GET/POST /api/segments` — List/create segments
- `DELETE /api/segments/{id}` — Delete segment
- `GET/POST /api/api-keys` — List/create API keys
- `DELETE /api/api-keys/{id}` — Revoke API key
- `GET/POST /api/secrets` — List/create secrets
- `GET/PUT/DELETE /api/secrets/{id}` — Get/update/delete secret
- `GET /api/audit` — View audit log

### Resolve a Secret (API key only)

```bash
curl -X POST http://localhost:8080/api/v1/secrets/DATABASE_URL/resolve \
  -H "X-API-Key: rfk_..."
```

Response:
```json
{
  "key": "DATABASE_URL",
  "value": "postgres://user:***@host:5432/db"
}
```

### Evaluate a Secret Feature Flag

Secret feature flags use `{"$secret": "KEY"}` as variation values. At evaluation time,
the system resolves the secret reference to its decrypted value.

```bash
curl -X POST http://localhost:8080/api/v1/flags/evaluate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: rfk_..." \
  -d '{
    "flagKey": "payment-key",
    "environment": "production",
    "context": {
      "targetingKey": "user-123",
      "attributes": { "email": "dev@internal.com" }
    }
  }'
```

Response (internal user gets the production Stripe key):
```json
{
  "value": "sk_live_...",
  "variant": "Production Key",
  "reason": "TARGETING_MATCH"
}
```

Non-internal users get the default variation (e.g., a test key):
```json
{
  "value": "sk_test_...",
  "variant": "Test Key",
  "reason": "DEFAULT"
}
```

If the referenced secret doesn't exist, evaluation returns an error:
```json
{
  "value": null,
  "reason": "ERROR",
  "errorCode": "SECRET_NOT_FOUND",
  "errorMessage": "secret \"MISSING\" not found"
}
```

## OpenFeature Evaluation Reasons

The evaluation endpoint returns standard OpenFeature reason codes:

| Reason | Description |
|---|---|
| `TARGETING_MATCH` | A targeting rule matched |
| `SPLIT` | Percentage rollout bucketing applied |
| `DEFAULT` | Default rule applied |
| `DISABLED` | Flag is disabled |
| `ERROR` | Evaluation error (e.g., flag not found) |

## Targeting Rule Operators

| Operator | Aliases | Description |
|---|---|---|
| `eq` | `EQUALS` | Equals |
| `neq` | `NOT_EQUALS` | Not equals |
| `in` | `IN` | Value is in list |
| `not_in` | `NOT_IN` | Value is not in list |
| `starts_with` | `STARTS_WITH` | String starts with |
| `ends_with` | `ENDS_WITH` | String ends with |
| `contains` | `CONTAINS` | String contains |
| `gt` | `GREATER_THAN` | Greater than |
| `gte` | `GREATER_THAN_OR_EQUAL` | Greater than or equal |
| `lt` | `LESS_THAN` | Less than |
| `lte` | `LESS_THAN_OR_EQUAL` | Less than or equal |
| `true` | `TRUE` | Boolean true |
| `false` | `FALSE` | Boolean false |
| `empty` | `EMPTY` | Empty string |
| `not_empty` | `NOT_EMPTY` | Non-empty string |

## Security

- **API Keys**: Generated with `crypto/rand`, stored as SHA-256 hashes, never logged in plaintext
- **Secrets**: Encrypted at rest with AES-256-GCM (random nonce per secret), decrypted only on read
- **JWT**: HS256 signed, 24-hour expiry, validated on every admin request
- **Rate Limiting**: 100 requests/minute per IP (configurable)
- **Security Headers**: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- **CSRF Protection**: Origin validation for state-changing requests
- **SQL Injection**: All queries use parameterized statements
- **Input Validation**: All API inputs validated before processing
- **Audit Trail**: Every mutation is logged with actor identity

## License

MIT
