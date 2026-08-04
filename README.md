# SecureIAM

A production-inspired Identity and Access Management (IAM) platform, built
as a portfolio project demonstrating backend engineering, security
fundamentals, and system design — the kind of centralized identity layer
other applications (like the demo app in later phases) delegate
authentication and authorization decisions to, conceptually similar to
Okta, Auth0, or Microsoft Entra ID.

**Status: Phase 1 (Authentication) complete.** Phase 2 (RBAC +
Authorization) has not yet begun.

---

## Project Overview

SecureIAM is not "an app with a login page" — it's infrastructure that
answers two questions on behalf of client applications:

1. **"Who is this?"** — Authentication (Phase 1, complete)
2. **"Can they do this?"** — Authorization (Phase 2, not yet started)

Phase 1 implements the first question end-to-end: registration, login,
JWT access tokens, rotating refresh tokens, and logout — all built with
clean architecture (API → Service → Repository → Database), framework-
independent business logic, and a security posture documented in
[`docs/security-review.md`](docs/security-review.md).

---

## Architecture

```
Client
  │
  ▼
FastAPI (app/api/v1/auth.py)       — HTTP, request validation, exception translation
  │
  ▼
AuthService (app/domain/services)  — authentication workflows, business rules
  │
  ▼
Repositories (app/repositories)    — database access only
  │
  ▼
PostgreSQL
```

Full layer-by-layer responsibilities, with the reasoning behind each
boundary, are documented in [`docs/architecture.md`](docs/architecture.md).

---

## Local Development

### Prerequisites
- Docker and Docker Compose
- (Optional, for running outside Docker) Python 3.12+

### Steps

1. **Clone the repository**
   ```bash
   git clone <repo-url>
   cd secureiam
   ```

2. **Create your environment file**
   ```bash
   cp .env.example .env
   ```
   Then generate a real JWT secret and put it in `.env`:
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```

3. **Start the stack**
   ```bash
   docker compose up
   ```
   This starts PostgreSQL and the FastAPI app. The API waits for Postgres'
   healthcheck to pass before starting.

4. **Run database migrations** (first time, or after a schema change)
   ```bash
   docker compose exec api python -m alembic upgrade head
   ```
   The migration creates the `pgcrypto` extension itself — no manual
   database setup step is required beyond `docker compose up`.

5. **Verify it's running**
   ```bash
   curl http://localhost:8000/health
   # {"status": "ok"}
   ```

To tear down and remove all local database state:
```bash
docker compose down -v
```

---

## Authentication API

All endpoints are under `/v1/auth`. Interactive API docs are available at
`http://localhost:8000/docs` once the app is running.

### `POST /v1/auth/register`
```json
{ "email": "user@company.com", "password": "correct-horse-battery-staple" }
```
→ `201` with `{ "id", "email", "created_at" }`, or `409` if the email is
already registered.

### `POST /v1/auth/login`
```json
{ "email": "user@company.com", "password": "correct-horse-battery-staple" }
```
→ `200` with `{ "access_token", "refresh_token", "token_type", "expires_in" }`,
`401` for invalid credentials (unknown email and wrong password return the
identical response, by design), or `403` if the account is deactivated.

### `POST /v1/auth/refresh`
```json
{ "refresh_token": "<opaque refresh token>" }
```
→ `200` with a **new** access/refresh token pair (the old refresh token is
revoked as part of rotation), or `401` if the token is invalid, expired,
revoked, or unknown.

### `POST /v1/auth/logout`
```json
{ "refresh_token": "<opaque refresh token>" }
```
→ `204` always — logout is idempotent and never reveals whether the token
existed.

---

## Testing

```bash
# Unit tests only (no database required)
python -m pytest tests/unit -v

# Full suite (requires a running test database)
python -m pytest -v
```

The test suite (102 tests as of Phase 1 completion) spans:
- **Unit tests** — password hashing, JWT issuance/validation, `AuthService`
  business logic (all with mocked repositories, zero database)
- **Integration tests** — real PostgreSQL throughout: repository behavior
  (constraints, cascades), full API flows via `httpx.AsyncClient`, a fresh-
  database migration check, dependency wiring, and refresh-rotation edge
  cases including a concurrency sanity check

CI runs the full suite automatically on every push and pull request — see
[`.github/workflows/test.yml`](.github/workflows/test.yml).

---

## Security Decisions

Full detail and rationale in [`docs/security-review.md`](docs/security-review.md).
In summary:

- **Argon2id** for password hashing (slow, memory-hard — appropriate for
  low-entropy human secrets)
- **Opaque refresh tokens, hashed with SHA-256** (fast hash appropriate for
  a high-entropy random value — Argon2 here would only add latency with no
  security benefit)
- **JWT access tokens (HS256, 15-minute TTL)** with issuer validation and
  required-claim enforcement
- **Refresh token rotation** on every use, with the schema already in place
  for Phase 7's reuse-detection logic
- **Enumeration prevention**: unknown-email and wrong-password produce an
  identical login response; unknown/expired/revoked refresh tokens produce
  an identical refresh response
- **Fail-fast configuration**: the app refuses to start if required
  environment variables are missing

Known limitations and what Phase 2/7 will address are documented in
[`docs/phase-2-readiness.md`](docs/phase-2-readiness.md).

---

## Project Documentation

- [`docs/architecture.md`](docs/architecture.md) — layer responsibilities and boundaries
- [`docs/security-review.md`](docs/security-review.md) — security decisions and rationale
- [`docs/phase-2-readiness.md`](docs/phase-2-readiness.md) — what Phase 2 inherits, and known limitations
