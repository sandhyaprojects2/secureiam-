# SecureIAM

[![Tests](https://github.com/sandhyaprojects2/secureiam-/actions/workflows/test.yml/badge.svg)](https://github.com/sandhyaprojects2/secureiam-/actions/workflows/test.yml)

A backend Identity and Access Management service — authentication, RBAC
authorization, multi-tenancy, refresh-token security, and audit logging —
built with FastAPI and PostgreSQL.

---

## Highlights

- Refresh-token rotation with **reuse detection**: replaying an
  already-rotated-away token revokes its entire token family, not just
  the one token presented.
- **Concurrency-safe rotation** — an atomic conditional `UPDATE` closes a
  real lost-update race where two simultaneous refresh requests for the
  same token could both succeed.
- Deny-by-default, permission-based RBAC with organization-scoped
  (multi-tenant) role assignments alongside global ones.
- Enumeration-resistant authentication: indistinguishable responses
  across distinct failure causes, both for login and refresh.
- Append-only audit log for every auth outcome and privileged mutation,
  queryable through a permission-gated API.
- 394 tests (159 unit, 235 integration), including concurrency and
  security-behavior tests; CI runs the full suite on every push.

---

## Architecture

```
Client
  │
  ▼
FastAPI routers            /v1/auth  /v1/authorize  /v1/organizations  /v1/audit-logs
  │
  ▼
Service layer               AuthService · AuthorizationService
                             OrganizationService · AuditLogService
  │
  ▼
Repository layer             one repository per table, persistence only
  │
  ▼
PostgreSQL
```

The API layer handles HTTP only; services hold business rules and have
no SQL/FastAPI dependency; repositories only read and write the
database. Full diagram, data model, and request flows:
[`docs/architecture-overview.md`](docs/architecture-overview.md).

---

## Authentication Flow

```
Register     Client → API → hash password (Argon2id) → persist user

Login        Credentials → verify password → issue access token (JWT)
                                             + refresh token (opaque)

Refresh      Refresh token → hash → look up → validate → rotate
                            → new access + refresh token pair

Reuse        Replay of an already-rotated-away refresh token
detection      → token family revoked, security event recorded
               → caller still receives the same generic rejection
```

---

## Authorization Model

```
User → Role (global or organization-scoped) → Permission (resource, action)
```

`AuthorizationService.authorize(user, resource, action)` resolves a
user's permission set for the requested scope and checks membership in
it — no cached result, so revoking a role or removing a permission takes
effect on the next check. Authorization is permission-based; role names
carry no special meaning to the check itself, so changing what a role
can do is a data change, never a code change.

---

## Security Engineering Highlights

**Opaque, hashed-at-rest refresh tokens.** A refresh token is a 64-byte
random value, looked up by SHA-256 hash. Only the hash is stored; the raw
value exists once, in the response at issuance.

**Rotation.** Every refresh revokes the presented token and issues a new
one, linked via a `replaced_by` chain.

**Reuse detection.** A token revoked *by rotation* (it has a
`replaced_by` successor) being presented again means it was already
exchanged — a signal of possible interception. This walks the chain to
the family's current active token and revokes it too, fail-closed, even
at the cost of logging out a legitimate concurrent session. Uses the
existing `replaced_by` column; no schema change.

**Concurrency-safe rotation.** The earlier implementation revoked a
token with an unconditional write — two concurrent refresh calls for the
same token could both read "not yet revoked" and both succeed. Fixed
with an atomic conditional update:
```sql
UPDATE refresh_tokens SET revoked_at = now()
WHERE id = :id AND revoked_at IS NULL
```
Only one caller's update can affect the row; the losing request sees
`rowcount = 0` and cannot complete the rotation.

**Enumeration prevention.** Unknown-email and wrong-password return the
same login response; unknown, expired, revoked, and reused refresh
tokens return the same rejection. The audit log — never returned to the
client — records the actual reason.

**Audit logging.** Every auth outcome and privileged RBAC/organization
change is an append-only row, queryable by actor, organization, and
action through a permission-gated endpoint.

---

## Testing

**394 tests, all passing** (159 unit, 235 integration):

- **Unit** — service-layer logic against mocked repositories, no database
- **Integration** — real PostgreSQL: repository behavior, full API flows
  via `httpx.AsyncClient`, a fresh-database migration check
- **Concurrency** — a real-concurrency test (`asyncio.gather`, two
  simultaneous refresh requests) and a sequential test proving the same
  rotation guarantee with no timing dependency
- **Security behavior** — reuse detection and family revocation,
  enumeration-response equivalence, audit-event correctness per code path

```bash
python -m pytest tests/unit -v      # no database required
python -m pytest -v                 # full suite, requires the test database
```

CI runs the full suite on every push —
[`.github/workflows/test.yml`](.github/workflows/test.yml).

---

## Tech Stack

| Category | Technology |
|---|---|
| API framework | FastAPI |
| Language | Python 3.12 |
| Database | PostgreSQL |
| ORM / DB driver | SQLAlchemy (async) + asyncpg |
| Migrations | Alembic |
| Password hashing | Argon2id (`argon2-cffi`) |
| Access tokens | JWT (`PyJWT`) |
| Config validation | Pydantic / `pydantic-settings` |
| Testing | Pytest + `pytest-asyncio`, `httpx` |
| Containerization | Docker + Docker Compose |
| CI | GitHub Actions |

---

## Project Structure

```text
app/
├── core/           security primitives, config, time — depends on nothing above it
├── domain/
│   ├── models/      SQLAlchemy ORM models (one file per table)
│   ├── schemas/      service-layer return types (not HTTP models)
│   └── services/     business logic — AuthService, AuthorizationService,
│                      OrganizationService, AuditLogService
├── repositories/     one repository per table — persistence only
├── api/v1/           FastAPI routers + HTTP-facing request/response schemas
└── db/               session/engine setup, Alembic migrations

tests/
├── unit/             mocked-repository tests, zero database
└── integration/      real Postgres + real HTTP tests

docs/                 architecture, security rationale, and a
                       per-phase design record for every decision
```

---

## Running Locally

**Prerequisites:** Docker and Docker Compose.

```bash
# 1. Clone
git clone https://github.com/sandhyaprojects2/secureiam-.git secureiam
cd secureiam

# 2. Configure environment
cp .env.example .env
python3 -c "import secrets; print(secrets.token_hex(32))"   # put the output in JWT_SECRET_KEY

# 3. Start Postgres + the API
docker compose up

# 4. Run migrations (first run only)
docker compose exec api python -m alembic upgrade head

# 5. Verify
curl http://localhost:8000/health          # {"status": "ok"}
```

Interactive API docs: `http://localhost:8000/docs`.

**Run the tests** (requires the isolated test database):
```bash
docker compose -f docker-compose.test.yml up -d
TEST_DATABASE_URL=postgresql+asyncpg://secureiam_test:secureiam_test@localhost:5433/secureiam_test \
  python -m pytest -v
```

Tear down and remove all local database state: `docker compose down -v`.

---

## Example API Flow

```
POST /v1/auth/register
POST /v1/auth/login                 → access token + refresh token A
POST /v1/auth/refresh (token A)     → refresh token B, token A revoked
POST /v1/auth/refresh (token A)     → 401 — reuse: token B revoked too
POST /v1/auth/refresh (token B)     → 401 — whole family now dead
GET  /v1/audit-logs?action=refresh_token.family_revoked   (as Admin)
                                     → the incident, recorded and queryable
```

---

## Engineering Decisions

- [`docs/architecture-overview.md`](docs/architecture-overview.md) —
  architecture, data model, request flows
- [`docs/security-review.md`](docs/security-review.md) — authentication
  and refresh-token security rationale
- [`docs/phases/phase-5.md`](docs/phases/phase-5.md) — the concurrency
  race, why an atomic conditional update was chosen over
  `SELECT ... FOR UPDATE`, and the token-family-revocation algorithm
- [`docs/phases/`](docs/phases/) — a design record per phase (RBAC,
  multi-tenancy, audit logging)
- [`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md) — current status
  and what's genuinely undefined vs. implemented

---

## Current Limitations

- No access-token revocation/blacklisting — a leaked access token is
  valid until its 15-minute expiry. The JWT `jti` claim is reserved for
  this but no mechanism consumes it yet.
- No rate limiting or lockout on login/refresh attempts.

See [`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md) for the full
accounting.

---

## Project Status

Complete through Phase 5 (authentication → RBAC → multi-tenancy → audit
logging → refresh-token reuse detection and concurrency-safe rotation).
394/394 tests passing, CI green, tagged `phase-5-complete`. No
implementation work is in progress. Full phase history:
[`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md).
