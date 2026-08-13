# Phase 1 — Authentication

**Tag:** `phase-1-complete` → `0566370`
**Commits:** `3c91504` … `0566370` (10 commits)

## What This Phase Accomplished

Phase 1 answers a single question: **who is this?** It delivers a complete,
production-shaped authentication system — registration, login, JWT access
tokens, rotating refresh tokens, and logout — built on a strict layered
architecture (API → Service → Repository → Database, with a dependency-free
Core layer underneath).

## Why It Was Needed

Every later phase depends on being able to identify a caller. Phase 2's RBAC
system in particular needs a resolved, authenticated `User` before it can ask
"what can they do" — Phase 1 exists to make that resolution trustworthy: no
plaintext password storage, no forgeable tokens, no way to distinguish a
wrong password from a nonexistent account.

## Files / Features Introduced

- **Project skeleton** (`3c91504`): FastAPI app, Docker/Compose (dev +
  isolated test db), pinned `requirements.txt`, `/health` endpoint.
- **Core infrastructure** (`6c11919`): `app/core/config.py` (typed,
  fail-fast `Settings` via pydantic-settings — the only place environment
  variables are read), `app/core/time.py` (`utc_now()`), `app/db/session.py`
  (async engine/session factory, `get_db()`).
- **Security primitives** (`8d13196`): `app/core/security.py` — Argon2id
  password hashing, HS256 JWT issuance/validation with a fixed claim set
  (`sub`, `type`, `iat`, `exp`, `jti`, `iss`), opaque refresh tokens
  (`secrets.token_urlsafe(64)`) hashed with SHA-256 for storage.
- **Database models & migrations** (`cd4e977`): `app/domain/models/user.py`,
  `app/domain/models/refresh_token.py` (self-referential `replaced_by` FK
  forming the rotation chain), Alembic wired for async SQLAlchemy.
- **Repository layer** (`cf39b23`): `UserRepository`, `RefreshTokenRepository`
  — persistence only, translating DB constraint violations
  (`DuplicateEmailError`) without deciding what they mean.
- **Service layer** (`bf538ac`): `AuthService` (register/login/refresh/logout)
  and `app/domain/exceptions.py` — zero SQLAlchemy, zero FastAPI, verified by
  an `ast`-based hygiene test.
- **API layer** (`a720380`): `app/api/v1/auth.py`, HTTP-facing request/response
  schemas, `app/core/dependencies.py` (`get_auth_service`, `get_current_user`).
- **Hardening & docs** (`0566370`): `docs/architecture.md`,
  `docs/security-review.md`, `docs/phase-2-readiness.md`, CI workflow, plus
  edge-case tests (multi-step rotation chains, fresh-database migration
  verification, dependency wiring).

## Tests Added

102 tests by the end of the phase, spanning:
- Unit: config/time (7), security primitives (17), `AuthService` (21) —
  entirely mock-based, no database.
- Integration: repositories (15), database models (5), API endpoints (16),
  `get_current_user` (7), refresh edge cases, fresh-database migration,
  dependency wiring, app startup/wiring.

## Important Architectural / Security Decisions

- **Enumeration prevention by construction, not convention.** Login's
  "unknown email" and "wrong password" raise the identical
  `InvalidCredentialsError` with the identical message; refresh's "unknown",
  "expired", "revoked", and "inactive owner" all raise the identical
  `InvalidRefreshTokenError`. Every one of these equivalences has a direct
  test asserting the messages are byte-for-byte identical, not just that
  both raise *some* exception.
- **Layer boundaries are enforced by tests, not just described.** The
  service layer's independence from SQLAlchemy/FastAPI is checked via `ast`
  inspection of actual imports and used names — not a substring search that
  a docstring could accidentally satisfy.
- **`get_current_user` deliberately does not check `is_active`.** It answers
  "who is this," not "should this request be allowed" — that distinction is
  explicitly deferred to Phase 2's authorization layer.
- **Known, documented limitations carried forward** (see
  `docs/security-review.md` and `docs/phase-2-readiness.md`): `InactiveUserError`
  has a narrower enumeration leak than the other exceptions; refresh rotation
  has no row-level locking; `get_current_user` doesn't re-verify account
  status. None were blockers — each was scoped and flagged for a later phase.

## What This Phase Enables for Phase 2

- A working `get_current_user` dependency that resolves a Bearer token to a
  real `User`, ready to sit behind any future protected route with no changes.
- A JWT claim set already sufficient for authorization checks keyed on the
  `sub` claim's user id — no new claims (`org_id`, `roles`, etc.) required.
- A proven layering pattern (repository → service, with translated
  exceptions at each boundary) that Phase 2's `RoleRepository` /
  `PermissionRepository` / `AuthorizationService` extend rather than
  reinvent.
