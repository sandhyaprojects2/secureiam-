# SecureIAM

[![Tests](https://github.com/sandhyaprojects2/secureiam-/actions/workflows/test.yml/badge.svg)](https://github.com/sandhyaprojects2/secureiam-/actions/workflows/test.yml)

A backend Identity and Access Management (IAM) platform implementing
authentication, RBAC authorization, multi-tenancy, refresh-token security
(rotation, reuse detection, concurrency-safe writes), and security audit
logging — the kind of centralized identity service other applications
delegate "who is this" and "can they do this" to, conceptually similar in
role to Okta, Auth0, or AWS IAM.

---

## Why I Built This

Most auth demos stop at "login returns a JWT." The interesting, and
harder, engineering problems in identity systems live one level deeper:

- A refresh token that's stolen and replayed should be *detected*, not
  just rejected — and detecting it should revoke the entire compromised
  session chain, not only the one token presented.
- Rotating a refresh token is a write against shared state — under real
  concurrent load, two simultaneous requests for the same token can race,
  and an unguarded rotation can let both win.
- An authorization engine has to stay correct the instant a role is
  revoked, not "eventually" — which rules out caching the answer.
- None of the above is worth anything if it isn't provable: an admin
  needs a queryable record of what actually happened, and the test suite
  needs to prove security properties deterministically, not just "usually
  pass."

SecureIAM exists to build and prove out those specific properties, layer
by layer, with the reasoning behind each decision written down as it was
made — not reconstructed afterward.

---

## Key Features

**Authentication**
- Argon2id password hashing
- JWT access tokens (HS256, short-lived, issuer-validated)
- Opaque, SHA-256-hashed-at-rest refresh tokens
- Refresh-token rotation on every use
- Refresh-token reuse detection with token-family revocation
- Concurrency-safe rotation (atomic conditional database update)

**Authorization**
- Role-based access control (RBAC): roles, permissions, role-permission
  grants, user-role assignments
- Deny-by-default, permission-based (never role-name-based) authorization
  engine
- Multi-tenancy: organization-scoped roles and role assignments alongside
  global ones

**Security Engineering**
- Enumeration-resistant authentication responses (identical errors across
  distinguishable failure causes)
- Append-only, internal-only audit log of every authentication outcome
  and privileged mutation, queryable via a permission-gated API
- Fail-fast configuration (the app refuses to boot with missing required
  secrets)

**Engineering**
- FastAPI + async SQLAlchemy/PostgreSQL + Alembic migrations
- Strict layered architecture (API → Service → Repository → Database),
  enforced by tests, not just described
- 394 automated tests (unit + real-Postgres integration), CI-enforced on
  every push

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

Each layer answers exactly one kind of question: the API layer handles
HTTP only; services hold business rules and contain zero SQL/FastAPI
(enforced for `AuthService` by a test that inspects its actual imports);
repositories answer "what does the database say," never "should this be
allowed." A dependency-free Core layer (password hashing, JWT, config)
sits underneath all of it.

Full diagram, data model, and request-flow walkthroughs:
[`docs/architecture-overview.md`](docs/architecture-overview.md).

---

## Authentication Flow

```
Register     Client → API → hash password (Argon2id) → persist user

Login        Credentials → verify password → issue access token (JWT)
                                             + refresh token (opaque)

Refresh      Refresh token → hash → look up → validate → rotate
                            → new access + refresh token pair
                            (atomic conditional UPDATE guards the rotation)

Reuse        Replay of an already-rotated-away refresh token
detection      → detected as reuse (not an ordinary invalid token)
               → entire token family revoked
               → security event recorded
               → caller still receives the same generic rejection
```

The reuse-detection path is the project's strongest security property —
see [Security Engineering Highlights](#security-engineering-highlights)
below.

---

## Authorization Model

```
User → Role (global or organization-scoped) → Permission (resource, action)
```

`AuthorizationService.authorize(user, resource, action)` resolves a
user's full permission set for the requested scope and checks membership
in it — deny-by-default, with no cached result: revoking a role or
removing a permission takes effect on the very next check, not after some
TTL expires. Authorization decisions are never made by comparing a role's
*name* (e.g. `"Admin"`); granting a new role Admin-equivalent access is a
data change (attach the right permissions to it), never a code change —
enforced by a test that inspects the method's actual source.

---

## Security Engineering Highlights

**Refresh tokens are opaque, not JWTs, and hashed at rest.** A refresh
token is a 64-byte cryptographically random value — there's no benefit to
making it self-describing, since the server always looks it up by hash.
Only the SHA-256 hash is stored; the raw value exists only once, at
issuance, in the response to the client.

**Rotation, not indefinite reuse.** Every successful refresh revokes the
presented token and issues a new one, linked via a `replaced_by` chain —
so a leaked refresh token has a limited window of usefulness even if
never explicitly revoked.

**Reuse detection via the `replaced_by` chain.** Presenting a token that
was already revoked *by rotation* (it has a `replaced_by` successor) is
structurally different from presenting one revoked by logout (no
successor) — the first is evidence of a possible stolen-token replay, the
second is just an ordinary already-logged-out token. Only the former
walks the chain forward to the family's current active token and revokes
it too, fail-closed, even at the cost of collaterally logging out a
legitimate concurrent session. This required no schema migration — the
`replaced_by` column existed since the very first authentication
migration specifically so this logic could be added later.

**Concurrency-safe rotation.** The previous implementation revoked a
token via a plain, unconditional database write — under real concurrent
load, two simultaneous requests for the same token could both read
"not yet revoked" and both succeed, producing two valid child tokens from
one parent. This is fixed with an atomic conditional update:
```sql
UPDATE refresh_tokens SET revoked_at = now()
WHERE id = :id AND revoked_at IS NULL
```
Postgres resolves the race at the row level — at most one concurrent
caller's update can ever affect the row — turning "usually only one
request succeeds" into "provably, deterministically, exactly one does."

**Enumeration prevention.** Unknown-email and wrong-password produce the
identical login response; unknown, expired, revoked, and reused refresh
tokens all produce the identical refresh rejection. The *internal* audit
log is deliberately more permissive — it's never returned in a response,
so it can record the real reason (`wrong_password` vs. `unknown_email`)
for investigation without weakening what the public API ever reveals.

**Audit logging as a first-class, queryable surface**, not just log
lines: every authentication outcome and privileged RBAC/organization
mutation is a structured, append-only database row, filterable by actor,
organization, and action through a permission-gated API — including
`refresh_token.reuse_detected` and `refresh_token.family_revoked`, so a
stolen-token incident is not just handled, it's forensically visible.

---

## Testing

**394 automated tests, all passing** (159 unit, 235 integration; verified
directly against this repository, not carried over from a stale README):

- **Unit tests** — service-layer business logic against
  `unittest.mock.AsyncMock` repositories, zero database
- **Integration tests** — real PostgreSQL throughout: repository behavior
  (constraints, cascades, transactions), full API flows via
  `httpx.AsyncClient`, a fresh-database migration check, dependency
  wiring
- **Concurrency tests** — a real-concurrency proof (`asyncio.gather`,
  two simultaneous refresh requests) *and* a fully deterministic,
  non-timing-dependent proof of the same guarantee at the repository
  layer
- **Security-behavior tests** — reuse detection and token-family
  revocation, enumeration-prevention response equivalence, audit-event
  correctness for every success and failure path

```bash
python -m pytest tests/unit -v      # no database required
python -m pytest -v                 # full suite, requires the test database
```

CI runs the full suite on every push and pull request —
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

docs/
├── architecture-overview.md   current, whole-system architecture reference
├── architecture.md            original Phase 1 layering rationale
├── security-review.md         authentication/refresh-token security decisions
├── phase-2-readiness.md       what Phase 2 inherited from Phase 1
├── PROJECT_STATUS.md          living source of truth: phases, roadmap, status
└── phases/                    one detailed design record per phase
```

---

## Running Locally

**Prerequisites:** Docker and Docker Compose (Python 3.12+ only needed if
running outside Docker).

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

**Interactive API docs:** `http://localhost:8000/docs` (Swagger UI).

**Run the tests** (requires the isolated test database):
```bash
docker compose -f docker-compose.test.yml up -d
TEST_DATABASE_URL=postgresql+asyncpg://secureiam_test:secureiam_test@localhost:5433/secureiam_test \
  python -m pytest -v
```

Tear down and remove all local database state: `docker compose down -v`.

---

## Example API Flow

A concrete way to see the security properties above in action:

```
POST /v1/auth/register              → account created
POST /v1/auth/login                 → access token + refresh token A
POST /v1/auth/refresh (token A)     → refresh token B; token A now revoked
POST /v1/auth/refresh (token A)     → 401 — replaying a rotated-away token
                                         is reuse: token B is revoked too,
                                         and a security event is recorded
POST /v1/auth/refresh (token B)     → 401 — the whole family is now dead,
                                         confirming the fail-closed response
GET  /v1/audit-logs?action=refresh_token.family_revoked   (as Admin)
                                     → the incident, recorded and queryable
```

---

## Engineering Decisions

Deeper design reasoning, one document per phase:

- [`docs/architecture-overview.md`](docs/architecture-overview.md) —
  whole-system architecture, data model, request flows
- [`docs/security-review.md`](docs/security-review.md) — authentication
  and refresh-token security rationale
- [`docs/phases/phase-5.md`](docs/phases/phase-5.md) — reuse detection
  and concurrency-safe rotation: the race condition, why an atomic
  conditional update was chosen over `SELECT ... FOR UPDATE`, and the
  token-family-revocation algorithm
- [`docs/phases/`](docs/phases/) — the full phase-by-phase design record
  (RBAC, multi-tenancy, audit logging)
- [`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md) — current status,
  completed phases, and what remains genuinely undefined (not invented)

---

## Project Status

**Core implementation complete through Phase 5.** All automated tests
passing (394/394), CI green on the current commit, repository tagged
`phase-5-complete`. No implementation work is currently in progress.

| Phase | Scope |
|---|---|
| 1 | Authentication — registration, login, JWT, refresh-token rotation |
| 2 | RBAC — roles, permissions, authorization engine and API |
| 3 | Multi-tenancy — organizations, organization-scoped roles |
| 4 | Audit logging — append-only event log and query API |
| 5 | Refresh-token reuse detection and concurrency-safe rotation |

The only further work named anywhere in this project's own documentation
is access-token blacklisting/rate-limiting (the JWT `jti` claim is
reserved for it but no mechanism exists yet) — see
[`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md) for the exact,
non-speculative accounting of what's implemented, what's genuinely open,
and what isn't defined yet.
