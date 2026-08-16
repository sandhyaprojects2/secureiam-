# SecureIAM — Phase 1 Architecture

> This document is Phase 1's original architecture writeup, preserved as
> written. For a current, whole-system view covering RBAC, multi-tenancy,
> audit logging, and refresh-token security added in later phases, see
> [`docs/architecture-overview.md`](architecture-overview.md). The
> layering principle described below (API → Service → Repository →
> Database) is unchanged and still applies to every subsystem added
> since.

This document explains how Phase 1's authentication system is layered, and
— more importantly — *why* each layer exists and what it's forbidden from
doing. The boundaries below were enforced throughout implementation, not
just described after the fact; several are backed directly by tests (see
each section).

---

## Dependency Flow

```
HTTP Request
     │
     ▼
┌─────────────────────┐
│   API Layer          │  app/api/v1/auth.py, app/api/v1/schemas/
│   (routes, Pydantic   │
│    request/response) │
└─────────┬────────────┘
          │  calls
          ▼
┌─────────────────────┐
│  Service Layer        │  app/domain/services/auth_service.py
│  (AuthService)         │  app/domain/exceptions.py
└─────────┬────────────┘
          │  calls
          ▼
┌─────────────────────┐
│  Repository Layer     │  app/repositories/
│  (UserRepository,      │
│   RefreshTokenRepository)
└─────────┬────────────┘
          │  queries
          ▼
┌─────────────────────┐
│  Database Layer        │  app/domain/models/, app/db/migrations/
│  (SQLAlchemy models,    │
│   Alembic migrations)  │
└─────────┬────────────┘
          │
          ▼
     PostgreSQL

(app/core/ -- security primitives, config, time -- is used across every
 layer above, but depends on nothing above it.)
```

---

## Layer Responsibilities

### API Layer
**Location:** `app/api/v1/auth.py`, `app/api/v1/schemas/auth.py`,
`app/core/dependencies.py`

**Responsible for:**
- Receiving HTTP requests and validating their shape (via Pydantic request
  schemas — `EmailStr` format checking, `password` minimum length, etc.)
- Constructing `AuthService` via dependency injection (`get_auth_service`)
- Translating exactly four domain exceptions into HTTP status codes and
  response bodies
- Returning HTTP-facing response schemas

**Explicitly not responsible for:** password hashing, token generation,
database queries, or any authentication/business decision. A route body is
never more than: validate → call service → catch known exceptions → return
schema.

**Enforcement:** this is the *only* layer (along with `get_current_user` in
`core/dependencies.py`) where `HTTPException` is permitted to exist at all.

---

### Service Layer
**Location:** `app/domain/services/auth_service.py`,
`app/domain/exceptions.py`, `app/domain/schemas/auth.py`

**Responsible for:**
- All authentication workflows: register, login, refresh, logout
- Every business rule: what counts as a duplicate email, what makes
  credentials invalid, when a refresh token is acceptable, how rotation
  works
- Translating repository-level exceptions (`DuplicateEmailError`) into
  domain-level exceptions (`EmailAlreadyExistsError`)

**Explicitly not responsible for:** SQL, SQLAlchemy model queries, database
session management, HTTP status codes, or FastAPI of any kind.

**Enforcement:** verified both by code review and by an `ast`-based test
(`test_auth_service_module_has_no_forbidden_imports`) that inspects actual
import statements and used names in the module — not just a string search
— to confirm zero coupling to `sqlalchemy`, `fastapi`, or `HTTPException`.
Every unit test for this layer uses `unittest.mock.AsyncMock` repositories;
none touch a database.

---

### Repository Layer
**Location:** `app/repositories/user_repository.py`,
`app/repositories/refresh_token_repository.py`,
`app/repositories/exceptions.py`

**Responsible for:**
- Executing database queries and persistence operations
- Translating database-level failures (a `UNIQUE` constraint violation)
  into repository-level exceptions (`DuplicateEmailError`)
- Nothing else — a repository answers "what does the database say," never
  "what should happen as a result"

**Explicitly not responsible for:** deciding whether a returned row is
still valid (e.g. `RefreshTokenRepository.get_by_hash()` returns whatever
row matches, without checking expiry or revocation — that evaluation
belongs to `AuthService`), password/token generation, or any workflow logic.

**Enforcement:** every repository test in
`tests/integration/test_repositories.py` runs against real Postgres — no
mocked SQLAlchemy — specifically to prove actual constraint/cascade
behavior, not just that the Python code calls the right methods.

---

### Core Layer
**Location:** `app/core/security.py`, `app/core/config.py`,
`app/core/time.py`

**Responsible for:**
- Security primitives: password hashing/verification, JWT issuance/
  validation, refresh token generation/hashing
- Configuration: a single typed, validated `Settings` object — the only
  place environment variables are read anywhere in the codebase
- Infrastructure utilities: `utc_now()`, used everywhere a timestamp is
  generated or compared, preventing naive/aware datetime bugs

**Design principle:** every function here is pure (no I/O beyond reading
already-loaded settings) and independently testable. `AuthService` depends
on this layer, not the other way around — `core/security.py` has zero
awareness that a service layer or API layer exists.

---

### Database Layer
**Location:** `app/domain/models/user.py`,
`app/domain/models/refresh_token.py`, `app/db/session.py`,
`app/db/migrations/`

**Responsible for:** persistence only — table definitions, constraints,
indexes, and the versioned migration history that produces them. Server-side
defaults (`gen_random_uuid()`, `now()`) are used wherever correctness should
hold even for a row inserted outside the ORM.

---

## Why This Layering, Concretely

The clearest evidence the boundaries are real, not aspirational: `AuthService`
was fully unit-tested (21 tests) with zero database and zero HTTP framework
in the loop, using nothing but `unittest.mock.AsyncMock` standing in for
both repositories. If the service layer had a hidden dependency on
SQLAlchemy or FastAPI, those tests simply couldn't exist in their current
form — they'd need a real database or a running app, which they don't.
