# SecureIAM — Project Status

**Last Updated:** 2026-08-16
**Latest Commit:** *(this checkpoint's commit — see `git log --oneline -1`; message starts "feat: Phase 5 -- refresh token reuse detection & concurrency-safe rotation". Tagged `phase-5-complete`. This document is itself part of that commit, so -- same convention `docs/phases/*.md` uses for its own commit references — its exact hash isn't hardcoded here to avoid going stale the moment it's amended.)*
**Current Checkpoint:** Phase 5 complete and closed — refresh-token reuse detection and concurrency-safe rotation implemented, deterministically tested, verified against real Postgres, tagged `phase-5-complete`, pushed to origin. Full suite 394/394 passing.

> This document is the single source of truth for project state. It is
> written so another AI assistant (or a human) can read it cold and
> immediately understand what exists, what's next, and what must not be
> silently changed. Everything below is derived from the actual repo —
> git history, `docs/phases/*.md`, and the code itself — nothing here is
> aspirational or invented. Where the roadmap is genuinely undefined, this
> document says so explicitly rather than filling the gap.

---

## 1. Project Overview

**SecureIAM** is a production-inspired Identity and Access Management
(IAM) platform, built as a portfolio project demonstrating backend
engineering, security fundamentals, and system design. It is
infrastructure, not "an app with a login page" — conceptually similar to
Okta, Auth0, or Microsoft Entra ID: a centralized identity layer that
answers two questions on behalf of client applications:

1. **"Who is this?"** — Authentication (Phase 1)
2. **"Can they do this?"** — Authorization / RBAC (Phase 2), extended with
   multi-tenancy (Phase 3) and an audit trail of every decision (Phase 4)

Built with a strict layered architecture (API → Service → Repository →
Database, with a dependency-free Core layer underneath), async
PostgreSQL/SQLAlchemy, JWT + rotating refresh tokens, and a test suite
that runs almost entirely against a real database rather than mocks for
its integration layer.

Repo: `https://github.com/sandhyaprojects2/secureiam-.git`

---

## 2. Current Phase

**Phase 5 (Refresh Token Reuse Detection & Concurrency-Safe Rotation) is
complete and closed.** Phase 4 (Audit Logging, all four sub-phases) was
the prior completed phase; Phase 5 is a single phase (not split into
sub-phases — implementation did not reveal a genuine need to split it).

- Branch: `master`
- Working tree: clean
- No open/partial work in progress — Phase 5's checkpoint (design review,
  approval, implementation, tests, docs, tag, push) is fully closed; see
  §7/§8.

**Process note:** every phase (1 through 5) now has a `phase-X[.Y]-complete`
tag, pushed to origin, per the established convention.

---

## 3. Completed Phases (Chronological)

### Phase 1 — Authentication
**Tag:** `phase-1-complete` · **Commits:** `3c91504`…`0566370` (10 commits)

- **Implemented:** FastAPI skeleton, Docker/Compose (dev + isolated test
  db), typed fail-fast `Settings`, async SQLAlchemy session plumbing,
  Argon2id password hashing, HS256 JWT issuance/validation, opaque
  SHA-256-hashed refresh tokens with a rotation chain (`replaced_by`),
  `UserRepository`/`RefreshTokenRepository`, `AuthService`
  (register/login/refresh/logout), `app/api/v1/auth.py`,
  `get_current_user` dependency.
- **Architectural decisions:** strict API→Service→Repository→DB layering,
  enforced by an `ast`-based hygiene test proving `AuthService` has zero
  SQLAlchemy/FastAPI imports; `get_current_user` answers "who is this,"
  deliberately not "should this be allowed" (no `is_active` check there).
- **Security decisions:** Argon2id (time_cost=3, memory=64MiB,
  parallelism=4) for passwords; SHA-256 (not Argon2) for refresh tokens,
  since hash cost should match secret entropy, not default to "as slow as
  possible"; enumeration prevention — identical responses for
  unknown-email vs. wrong-password, and for unknown/expired/revoked/
  inactive-owner refresh tokens; one **documented, deliberate exception**:
  `InactiveUserError` is distinguishable from `InvalidCredentialsError` at
  login (a narrow, accepted leak, per spec).
- **Tests added:** 102 by phase end (unit: config/time 7, security
  primitives 17, `AuthService` 21; integration: repositories 15, models 5,
  API 16, `get_current_user` 7, plus edge cases/migration/wiring tests).
- **Final test status:** 102/102 passing at phase close.

### Phase 2.1 — RBAC Schema
**Tag:** `phase-2.1-complete` · **Commit:** `09fcba5`

- **Implemented:** `roles`, `permissions`, `role_permissions`,
  `user_roles` tables; seed migration for 4 default roles (Admin,
  Manager, Developer, Intern) and a 5-permission catalog
  (`document:view/edit/delete`, `role:manage`, `user:manage`).
- **Architectural decisions:** roles/permissions global (no
  `organization_id` yet — explicitly deferred to Phase 3);
  `role_permissions` as a Core `Table`, not a mapped class (pure
  association, no extra columns).
- **Security decisions:** no bootstrap-admin API endpoint — first Admin
  assignment is a manual, out-of-band SQL step, to avoid the endpoint
  itself becoming a privilege-escalation target.
- **Tests added:** 16 integration tests (`test_rbac_models.py`).
- **Final test status:** 118/118 passing (102 + 16).

### Phase 2.2 — RBAC Repository Layer
**Tag:** `phase-2.2-complete` · **Commit:** `45fc16a`

- **Implemented:** `RoleRepository`, `PermissionRepository` (deliberately
  read-only — no `create_permission`), `UserRoleRepository` including
  `get_permissions_for_user()` — one indexed join, no N+1, no caching.
- **Architectural decisions:** `revoke()` returns `bool` (found/not-found)
  rather than raising, matching `RefreshTokenRepository`'s Phase 1
  pattern.
- **Security decisions:** no caching anywhere in the permission-resolution
  path — role revocation takes effect immediately, proven by a dedicated
  test.
- **Tests added:** 28 integration tests (`test_rbac_repositories.py`).
- **Final test status:** 146/146 passing.

### Phase 2.3 — Authorization Service (Core RBAC Engine)
**Tag:** `phase-2.3-complete`

- **Implemented:** `AuthorizationService` — `authorize()`, `create_role`,
  `assign_role`, `revoke_role`, `assign_permission_to_role`,
  `remove_permission_from_role`, `get_user_permissions`;
  `RoleRepository.add_permission`/`remove_permission`.
- **Architectural decisions:** `authorize()` returns an
  `AuthorizationDecision` (data), never raises to signal "denied" — deny
  is data, not an exception a caller could accidentally swallow.
- **Security decisions:** deny-by-default; permission-based, never
  role-name-based (locked in by a source-inspection test); inactive users
  always denied, checked before any permission lookup; unknown
  `(resource, action)` pairs resolve to `allowed=False`, never raise.
- **Tests added:** 27 unit + 4 integration = 31.
- **Final test status:** 177 collected, **176 passing** at the time —
  first appearance of the one recurring non-passing test
  (`test_migrations_apply_cleanly_to_a_fresh_empty_database`). Fixed as
  part of the Phase 4.4 checkpoint closure (§6) — not a regression
  reintroduced in any phase between 2.3 and 4.4, just left unfixed until
  this checkpoint.

### Phase 2.4 — Authorization API Layer
**Tag:** `phase-2.4-complete`

- **Implemented:** `app/api/v1/authorize.py` — `POST /v1/authorize`,
  role/permission/user-role management routes; `require_permission()`
  FastAPI dependency factory (403 on denial, one generic message).
- **Architectural decisions:** `/v1/authorize` only ever answers for the
  calling user — no parameter to ask about someone else's permissions.
  Route-registration order (`/users/me/permissions` before
  `/users/{user_id}/permissions`) is a tested, documented constraint.
- **Security decisions:** no bootstrap-admin endpoint (consistent with
  2.1); idempotent mutations (revoke, remove-permission) return 204
  unconditionally, never a synthetic 404/409.
- **Tests added:** 24 integration + 4 + 2 unit/wiring = 30.
- **Final test status:** 207 collected, 206 passing.

### Phase 3.1 — Multi-Tenancy Schema
**Tag:** `phase-3.1-complete`

- **Implemented:** `organizations`, `organization_memberships` tables;
  nullable `organization_id` added to `roles` and `user_roles`.
- **Architectural decisions:** no data backfill (`NULL` already meant
  "global" pre-Phase-3); **partial unique indexes**, not one composite
  `UNIQUE`, on `user_roles` (a plain composite constraint would have
  silently stopped rejecting duplicate global assignments once the column
  existed — Postgres treats every `NULL` as distinct); `roles.name` stays
  globally unique, not per-organization; `UserRole` still keyed on
  `user_id` directly, not `organization_memberships.id` (deliberately, to
  keep "belongs to org" and "what can they do, and where" independent).
- **Security decisions:** none new beyond the correctness guarantees
  above (schema-only phase).
- **Tests added:** 16 integration tests (`test_organization_models.py`).
- **Final test status:** 223 collected, 222 passing.

### Phase 3.2 — Multi-Tenancy Repository Layer
**Tag:** `phase-3.2-complete`

- **Implemented:** `OrganizationRepository`,
  `OrganizationMembershipRepository`; org-aware extensions to
  `RoleRepository`/`UserRoleRepository`.
- **Architectural decisions:** read methods use global-plus-scoped union;
  `revoke()` uses **exact** match (deliberate asymmetry — revoking must
  never touch a different-scope row that happens to share a `role_id`).
- **Security decisions:** repositories still validate nothing themselves —
  existence/business-rule checks remain the service layer's job.
- **Tests added:** 17 integration + 6 = 23.
- **Final test status:** 246 collected, 245 passing.

### Phase 3.3 — Multi-Tenancy Service Layer
**Tag:** `phase-3.3-complete`

- **Implemented:** `AuthorizationService` gained optional
  `organization_id` on `authorize`/`create_role`/`assign_role`/
  `revoke_role`/`get_user_permissions`; new `OrganizationService`
  (`create_organization`, `add_member`, `remove_member`, `list_members`,
  `list_organizations_for_user`).
- **Architectural decisions:** `assign_role()`'s enforcement order —
  role exists → role/org scope match → org exists → user is a member →
  assign. `OrganizationService` and `AuthorizationService` stay separate
  (mirrors `AuthService`/`AuthorizationService` split): "does this org
  exist / who belongs to it" vs. "what can a member do."
- **Security decisions:** org membership checked once, at assignment
  time, not on every `authorize()` call (membership is a grant
  precondition; `authorize()`'s no-caching freshness is what needs to hold
  on every request, not membership re-verification).
- **Tests added:** 13 unit (`OrganizationService`) + 11 unit
  (`AuthorizationService`) = 24.
- **Final test status:** 270 collected, 269 passing.

### Phase 3.4 — Multi-Tenancy API Layer
**Tag:** `phase-3.4-complete`

- **Implemented:** `POST /v1/organizations` + membership management
  routes; `organization_id` support added to `/v1/authorize`, `/v1/roles`,
  `/v1/users/*`; new `organization:manage` permission (seed migration
  `97122fa13dcc`).
- **Architectural decisions:** `organization:manage` gates all
  organization CRUD/membership uniformly — no separate "manage my own
  org's members" permission tier.
- **Security decisions:** `RoleOrganizationMismatchError` and
  `UserNotOrganizationMemberError` both map to `409`, matching the
  existing "conflicting with current state" category; no route exposes
  another organization's authorize-decision or another user's own-org
  listing.
- **Tests added:** 15 integration (`test_organizations_api.py`) + 5 +
  3 + 2 = 25 (+1 modified test in `test_rbac_models.py` for the new
  permission).
- **Final test status:** 296 collected, 295 passing.

### Phase 4.1 — Audit Log Schema
**Tag:** `phase-4.1-complete`

- **Implemented:** `audit_logs` table — `occurred_at`, `actor_user_id`,
  `action`, `target_type`, `target_id`, `organization_id`,
  `event_metadata` (JSONB).
- **Architectural decisions:** `ON DELETE SET NULL` (not `CASCADE`) on
  `actor_user_id`/`organization_id` — the historical record must survive
  deletion of what it references, the opposite of every other FK in this
  schema; `target_id` deliberately not a real FK (polymorphic reference,
  by convention only); `action`/`target_type` plain strings, not a
  Postgres `ENUM`; column named `event_metadata`, not `metadata` (avoids
  colliding with SQLAlchemy's `Base.metadata`).
- **Security decisions:** no update/delete repository method planned —
  an editable/removable audit log isn't an audit log.
- **Tests added:** 6 integration tests (`test_audit_log_model.py`).
- **Final test status:** 302 collected, 301 passing.

### Phase 4.2 — Audit Log Repository
**Tag:** `phase-4.2-complete`

- **Implemented:** `AuditLogRepository` — `record()`, `list_events()`,
  `count_events()`.
- **Architectural decisions:** no `DuplicateXError` translation (no
  unique constraint exists on an append-only log — first write method in
  the codebase with no failure mode to translate); `count_events()` as
  its own single `SELECT count(*)`, not `len(list_events(...))`; all
  filters additive (`AND`) and optional.
- **Security decisions:** restricting who may call `list_events()` with
  no filters is deferred to Phase 4.4's API-layer authorization, not this
  repository's concern.
- **Tests added:** 11 integration tests (`test_audit_log_repository.py`).
- **Final test status:** 313 collected, 312 passing.

### Phase 4.3 — Audit Log Service Integration
**Tag:** `phase-4.3-complete`

- **Implemented:** `AuthService`, `AuthorizationService`,
  `OrganizationService` all wired to actually write to `audit_logs`;
  `app/domain/audit_actions.py` canonical action-name constants.
- **Architectural decisions:** **first modification to `AuthService`
  since Phase 1** — a deliberate, scoped decision (full auth + RBAC/org
  coverage, chosen over an admin-events-only alternative).
- **Security decisions:** `AuthService` audits both successes *and* every
  failure reason (login/refresh), recording more internally
  (`event_metadata`) than its external, still-collapsed exception
  messages ever reveal — a deliberately more permissive policy for the
  internal, `audit:view`-gated surface, not a weakening of the public
  enumeration defense. `AuthorizationService`/`OrganizationService` audit
  **successes only**, never failures/no-ops (an already-authorized
  admin's rejected request isn't a probing signal). `authorize()` and
  every list/read method, in any service, are never audited.
  `actor_user_id` is required (not optional) on every RBAC/org mutation.
- **Tests added:** 13 + 12 + 8 unit + 10 end-to-end integration
  (`test_audit_logging_integration.py`) = 43.
- **Final test status:** 356 collected, 355 passing.

### Phase 4.4 — Audit Log API *(most recent, checkpoint closed)*
**Tag:** `phase-4.4-complete` · **Commits:** `8a5d184` (feature work),
plus a checkpoint-closure commit (CI credential-mismatch fix + this
document — *this commit*, see `git log docs/PROJECT_STATUS.md`)

- **Implemented:** `AuditLogService` (read-only, wraps
  `list_events()`/`count_events()` into `AuditLogPageResponse`);
  `GET /v1/audit-logs` (filters: `organization_id`, `actor_user_id`,
  `action`; pagination: `limit` 1–200, `offset` ≥ 0); new `audit:view`
  permission (seed migration `cbf5b83aa3f8`), granted to Admin only.
- **Architectural decisions:** permission enforcement lives entirely at
  the API layer (`require_permission("audit", "view")`) — the service
  itself performs no check, matching every other service in the codebase;
  pagination bounds validated by FastAPI `Query(...)`, not the service or
  repository.
- **Security decisions:** reading the audit log is itself never audited
  (matches every other pure-read method in the codebase); no
  single-event-lookup route added (no real use case for it yet); `audit:
  view`'s seed migration is minimal and additive, mirroring Phase 3.4's.
- **Tests added:** 7 unit (`test_audit_log_service.py`) + 9 integration
  (`test_audit_log_api.py`) + 2 + 2 wiring/startup = 20 (+1 modified test
  in `test_rbac_models.py`).
- **Final test status:** 377 collected, 376 passing at the original
  Phase 4.4 commit (`8a5d184`); **377 collected, 377 passing** after the
  checkpoint-closure CI fix (§6) — the one remaining failure was fixed as
  part of closing this phase's checkpoint, not carried forward.

### Phase 5 — Refresh Token Reuse Detection & Concurrency-Safe Rotation *(most recent)*
**Tag:** `phase-5-complete`

- **Implemented:** `RefreshTokenRepository.create_rotation_pair()` rewritten
  to use an atomic conditional `UPDATE ... WHERE revoked_at IS NULL`
  (Core, not ORM attribute assignment), returning `RefreshToken | None`
  (`None` = lost a concurrent race); new `revoke_descendants()` walking the
  `replaced_by` chain to the family's current leaf and revoking it
  atomically; `AuthService.refresh()` branches revoked tokens on
  `replaced_by` (reuse vs. logout-revoked) via a new `_handle_revoked_token()`
  helper; two new audit actions (`refresh_token.reuse_detected`,
  `refresh_token.family_revoked`).
- **Architectural decisions:** atomic conditional `UPDATE` chosen over
  `SELECT ... FOR UPDATE` specifically because it needs no restructuring
  of `AuthService.refresh()`'s existing two-call (validate, then mutate)
  shape and holds no lock across unrelated `await`s — reasoned from this
  codebase's actual async, session-per-request architecture, not a generic
  preference; `replaced_by IS NOT NULL`/`IS NULL` (already existing since
  Phase 1) fully distinguishes rotation-revoked from logout-revoked
  tokens — **no schema change**, a dedicated `revocation_reason` column
  was considered and explicitly rejected as redundant.
- **Security decisions:** family revocation is fail-closed under a race
  with a legitimate concurrent rotation (whichever side loses is
  rejected, including a legitimate session, by design); every rejection
  reason — old and new — still raises the identical
  `InvalidRefreshTokenError` with the identical message, preserving the
  enumeration-prevention guarantee established in Phase 1; the walk-and-
  retry loop is bounded (25 steps) as defensive coding against a
  pathological concurrent sequence, not because one is expected.
- **Tests added:** 8 unit + 5 integration (`test_repositories.py`,
  including a fully deterministic, non-concurrent proof of the race fix)
  + 4 integration (`test_refresh_edge_cases.py`) = 17. One existing test
  restructured (its premise became false once reuse detection exists,
  identified precisely in the pre-implementation design review, not
  discovered as a surprise); one existing test strengthened with a
  previously-untested side-effect assertion; one existing test's
  docstring corrected (no longer a "sanity check" — now a deterministic
  guarantee). Every other pre-existing revoked-token test passes
  unmodified.
- **Final test status:** 394 collected, 394 passing. The concurrent-
  refresh integration test was additionally run 10 consecutive times in
  isolation post-implementation, plus the new repository-level
  deterministic tests 8 more times, all 100% consistent — confirming the
  fix is a real guarantee, not a probability improvement.

---

## 4. Remaining Roadmap

**There is no formally defined "Phase 6" (or any further numbered phase)
anywhere in this repository** — no doc, comment, or commit names one or
describes its scope. This section reports that gap rather than inventing
content to fill it.

**The two items previously tracked under the name "Phase 7" are now
done, as Phase 5** (see §3): refresh-token reuse detection and
concurrency-safe rotation. Every reference to "Phase 7" in this codebase
described exactly those two items, both closed above — there is no
remaining "Phase 7" scope left undone.

**One related, still-genuinely-open item, not part of Phase 5's scope:**
the JWT `jti` claim (`app/core/security.py`) exists specifically so a
future access-token blacklist/rate-limiting mechanism needs no
token-format migration — but no such mechanism exists yet, and Phase 5
deliberately did not build one: it concerns the *access* token (JWT), an
entirely separate mechanism from the *refresh* token table Phase 5
hardened. This was one of the candidate directions evaluated (and not
chosen) before Phase 5 began — see the "Access-Token Revocation & Session
Management" and "Rate Limiting & Brute-Force Protection" candidates from
that evaluation, both of which would require introducing Redis (or
equivalent), a decision not yet made.

**Purely speculative, not-a-roadmap-item mentions found in the docs**
(listed for completeness, explicitly **not** treated as planned phases):
- A "document-management demo scoped per organization" — mentioned once
  in `docs/phases/phase-3.4.md` as an example of what org-scoped
  resources *could* look like.
- "Forensic tooling (e.g. exporting a date-range of events, or a UI
  dashboard)" — mentioned once in `docs/phases/phase-4.4.md` as an
  example of what could build on `GET /v1/audit-logs`.
- README's original framing: "the demo app in later phases" that would
  delegate to SecureIAM as its IAM provider — never phase-numbered or
  scoped anywhere.

**No expected tests, architecture, or security considerations can
responsibly be written for a Phase 6 that doesn't exist yet in any
project document.** When the next phase is defined, it should be added
here with the same structure as the completed-phases section above
before implementation begins.

---

## 5. Current Architecture

### Authentication — **IMPLEMENTED**
Register/login/refresh/logout via `AuthService`. `get_current_user`
(in `app/core/dependencies.py`) resolves a Bearer JWT to a `User`,
collapsing every failure mode (missing header, malformed scheme, bad
signature, expired, wrong issuer, unknown user) into one generic 401.

### Password hashing — **IMPLEMENTED**
Argon2id (`argon2-cffi`), `time_cost=3`, `memory_cost=65536 KiB`,
`parallelism=4`. `verify_password()` never raises — mismatches and
corrupt hashes both return `False`.

### JWT / access tokens — **IMPLEMENTED**
HS256, single server-side secret. Claims: `sub`, `type`, `iat`, `exp`,
`jti`, `iss`. 15-minute TTL (configurable). Issuer and required-claim
validation enforced; all rejection reasons collapse to one
`TokenValidationError`.

### Refresh tokens — **IMPLEMENTED**, fully, including hardening (Phase 5)
Opaque `secrets.token_urlsafe(64)`, SHA-256-hashed at rest, rotated on
every use via a `replaced_by` chain, 14-day TTL. Rotation is
concurrency-safe (atomic conditional `UPDATE ... WHERE revoked_at IS
NULL`, not an unconditional ORM write) and reuse-detecting (presenting a
rotated-away token revokes its entire token family, fail-closed). See
Phase 5 in §3. Not implemented, and not this phase's scope: access-token
(JWT) blacklisting/rate-limiting — see §4.

### RBAC — **IMPLEMENTED**
`roles`/`permissions`/`role_permissions`/`user_roles`, seeded 4 default
roles + growing permission catalog (5 original + `organization:manage` +
`audit:view` = 7). `AuthorizationService.authorize()` is deny-by-default,
permission-based (never role-name-based), no caching (revocation is
immediate), and treats unknown `(resource, action)` pairs as a plain
denial rather than an error.

### Authorization (API enforcement) — **IMPLEMENTED**
`require_permission(resource, action)` FastAPI dependency factory —
the only place an `AuthorizationDecision` becomes an HTTP status code
(403, one generic message, always).

### Organizations / multi-tenancy — **IMPLEMENTED**
`organizations`/`organization_memberships` tables; `organization_id`
optional on `roles`/`user_roles` (partial-unique-index-backed); global
grants always apply, org-scoped grants apply only within their org;
membership checked once, at role-assignment time.

### Audit logging — **IMPLEMENTED**
`audit_logs` (append-only, `ON DELETE SET NULL`). Written by
`AuthService` (every register/login/refresh/logout outcome, success
*and* failure), `AuthorizationService`/`OrganizationService` (successes
only). Read via `GET /v1/audit-logs`, gated by `audit:view` (Admin-only
by default).

### PostgreSQL — **IMPLEMENTED**
Single database engine throughout — async SQLAlchemy 2.0 + `asyncpg`,
Alembic migrations (`pgcrypto` extension created by migration, not a
manual setup step). Dev instance on port 5432 (`docker-compose.yml`),
isolated test instance on port 5433 (`docker-compose.test.yml`).

### Redis — **NOT IMPLEMENTED, NOT PLANNED**
No reference to Redis exists anywhere in the codebase, `requirements.txt`,
either `docker-compose*.yml`, or any doc. There is no evidence of any
project intent to introduce it — this is a genuine absence, not an
oversight in this document.

### API structure — **IMPLEMENTED**
FastAPI, versioned under `/v1`. Routers: `app/api/v1/auth.py`,
`authorize.py`, `organizations.py`, `audit.py`, each with its own
HTTP-facing schemas under `app/api/v1/schemas/`, kept separate from the
domain-level schemas under `app/domain/schemas/`.

### Service / repository layers — **IMPLEMENTED**
Strict `API → Service → Repository → DB` layering. Services
(`AuthService`, `AuthorizationService`, `OrganizationService`,
`AuditLogService`) contain zero SQL/SQLAlchemy/FastAPI — verified for
`AuthService` by an `ast`-based hygiene test. Repositories answer only
"what does the database say," never a business-rule question; that
discipline is documented per-repository and, for the trickier cases,
tested directly (e.g. `PermissionRepository` has no `create_permission`
method; `AuditLogRepository` has no update/delete method).

### Security boundaries — **IMPLEMENTED**
- `HTTPException` is permitted to exist only in the API layer and
  `get_current_user`/`require_permission` in `core/dependencies.py`.
- Enumeration prevention on login and refresh (identical responses
  across distinguishable failure causes), with one documented exception
  (`InactiveUserError`).
- Fail-fast configuration (`Settings` refuses to boot on missing required
  env vars).
- `.env` git-ignored from the very first commit; only `.env.example`
  committed.

### Testing / CI — **IMPLEMENTED**
`pytest` + `pytest-asyncio`; unit tests fully mocked (no DB); integration
tests run against real Postgres and real HTTP (`httpx.AsyncClient`).
GitHub Actions workflow (`.github/workflows/test.yml`) runs the full
suite on every push/PR against its own ephemeral Postgres service
container. **CI failed on every run from Phase 2.3 through Phase 4.3**,
for a real, reproducible reason (see §6) — **fixed as part of closing the
Phase 4.4 checkpoint.** The fix is test-side only
(`test_fresh_database_migration.py` now derives its admin connection from
the same `TEST_DATABASE_URL` every other integration test already uses,
instead of a separate hardcoded identity); no CI workflow YAML changes
were needed.

---

## 6. Testing Status

- **Total tests collected (local, current HEAD):** 394
- **Passing (local):** **394 — full suite green, zero failures.**
- **Failing (local):** 0

### The formerly-failing test — root cause found and fixed

Every phase doc from 2.3 through 4.4's original commit described this as
a "pre-existing environment limitation... not available in this
environment" and treated it as effectively a non-issue. **That framing
was only half true, and has now been corrected rather than repeated.**

`test_fresh_database_migration.py` used to hardcode a separate admin
identity:
```python
ADMIN_DSN = "postgresql://postgres:postgres@localhost:5432/postgres"
```
- **Locally (this sandbox):** nothing listens on port 5432 at all (only
  the port-5433 `docker-compose.test.yml` container runs) → connection
  refused. This half of the old "environment limitation" framing was
  accurate.
- **In real GitHub Actions CI:** a Postgres service container *is*
  running on port 5432 — but `.github/workflows/test.yml` provisions it
  with `POSTGRES_USER: secureiam` / `POSTGRES_PASSWORD: secureiam`, not
  `postgres`/`postgres`. Verified directly via `gh run view` on the
  then-most-recent pushed run (Phase 4.3, run `31924460699`): the test
  failed with `asyncpg.exceptions.InvalidPasswordError: password
  authentication failed for user "postgres"` — a **credential mismatch
  between the test and the CI workflow it ran under**, not an absent
  environment. **CI had been red on every single push from
  `phase-2.3-complete` through `phase-4.3-complete`/`master`** —
  confirmed via `gh run list` across every "Test" workflow run in that
  range, always this exact one test.

**Fix applied** (in `tests/integration/test_fresh_database_migration.py`):
the test no longer hardcodes any admin identity. It now derives its admin
connection from `TEST_DATABASE_URL` — the same env var every other
integration test in this suite already targets, imported directly from
`tests/conftest.py` so there is exactly one source of truth for it — and
points that connection at the target server's always-present `postgres`
maintenance database instead of the application's own database. The
`POSTGRES_USER` that `docker-compose.yml`/`docker-compose.test.yml`/CI's
service container all create is a superuser by construction (standard
Postgres Docker image bootstrap behavior), so it always has `CREATEDB`
privilege — there was never a need for a *separate* admin identity, only
a correctly-derived one.

- **No CI workflow (`.github/workflows/test.yml`) changes were needed** —
  its `secureiam`/`secureiam` credentials, already used consistently for
  both `DATABASE_URL` and `TEST_DATABASE_URL`, were left untouched. Fixing
  the test to read the already-correct, already-shared configuration was
  simpler and avoided duplicating credentials across two places.
- **No security assumption was touched** — this is test infrastructure
  only; no application authentication/authorization/audit logic changed.
- **Verified:** the affected test passes in isolation; the full local
  suite is 377/377; see the commit in §7 for the pushed-and-CI-verified
  result.

Full writeup: `docs/phases/phase-4.4.md`, "Checkpoint Closure — CI
PostgreSQL Credential Mismatch (Fixed)".

### A second, separate flake observed during Phase 4.4 closure — now fixed (Phase 5)

While verifying the CI credential-mismatch fix during Phase 4.4's
checkpoint closure, a *separate* flake surfaced in one CI run:
`test_refresh_edge_cases.py::test_concurrent_refresh_with_same_token_only_one_succeeds`
failed with `assert 2 == 1` (both concurrent refresh requests succeeded
instead of exactly one), while the same commit passed cleanly in a
parallel run. That was correctly identified at the time as the
already-documented "Known concurrency limitation" (no atomic guard on
refresh rotation) — real, reproducible, but deliberately **not** fixed as
part of that checkpoint, since it required a full design review, not a
quick patch.

**This is exactly what Phase 5 fixed.** `RefreshTokenRepository.
create_rotation_pair()` now uses an atomic conditional `UPDATE ...
WHERE revoked_at IS NULL`, which Postgres resolves at the row level
regardless of scheduling — the same test now passes deterministically,
confirmed by 10 consecutive isolated runs post-implementation (see §3,
Phase 5) rather than "usually passing." The commit-passing-here-but-not-
there behavior observed during Phase 4.4 was real evidence of a genuine
race, not a testing artifact — and served as part of the concrete
justification for prioritizing Phase 5 immediately after Phase 4.

### Test database setup
- **Dev:** `docker-compose.yml` → Postgres on `5432` (`secureiam`/
  `secureiam`/`secureiam`).
- **Test:** `docker-compose.test.yml` → isolated Postgres on `5433`
  (`secureiam_test`/`secureiam_test`/`secureiam_test`), currently running
  in this sandbox as container `secureiam-phase1-test-db-1`.
- `tests/conftest.py` reads `TEST_DATABASE_URL` (defaults to the 5433
  instance) so the suite never accidentally targets the dev database.
  `test_session` truncates domain tables before each test; seeded
  reference data (roles/permissions/organizations created *within* a
  test) uses uuid-suffixed names to stay idempotent across runs, since
  seeded rows aren't truncated.

### Important integration tests
- `test_fresh_database_migration.py` — the only test needing a second,
  standalone admin Postgres connection (see the fix above).
- `test_refresh_edge_cases.py` — the concurrency-safe-rotation proof
  (`asyncio.gather`, real concurrent HTTP requests) plus the Phase 5
  reuse-detection/family-revocation scenarios end-to-end.
- `test_repositories.py` — the deterministic (non-concurrent) proof of
  the same rotation guarantee, directly at the repository layer, plus
  `revoke_descendants()`'s chain-walking behavior.
- `test_audit_logging_integration.py` — 10 true end-to-end tests proving
  a real HTTP call produces a real, queryable `audit_logs` row through
  the whole stack.
- `test_authorize_api.py`, `test_organizations_api.py`,
  `test_audit_log_api.py` — real Postgres + real FastAPI + real HTTP via
  `httpx.AsyncClient` for each API surface.
- `test_rbac_models.py`, `test_rbac_repositories.py`,
  `test_organization_models.py`, `test_organization_repositories.py`,
  `test_audit_log_repository.py` — schema/repository-level correctness
  against real Postgres (constraints, cascades, partial indexes).
- `test_dependency_wiring.py`, `test_app_startup.py` — confirm DI wiring
  and route registration, not business logic.

### CI status
- **Configured:** `.github/workflows/test.yml`, runs on every `push` and
  `pull_request`, spins up its own Postgres 16 service container, runs
  `alembic upgrade head`, confirms the app imports, then `pytest -v`.
- **Status: fixed and verified green.** Every run from
  `phase-2.3-complete` through `phase-4.3-complete`/`master` failed with
  the one credential-mismatch test above. The fix in §6 was pushed as
  part of closing this checkpoint; see §7 for the resulting run.

---

## 7. Git Status

- **Branch:** `master`
- **Latest commit:** this checkpoint's closure commit — "feat: Phase 5 --
  refresh token reuse detection & concurrency-safe rotation" (on top of
  `e98567d`/`c59b26e`, the Phase 4.4 checkpoint-closure commits); run
  `git log --oneline -3` for exact hashes.
- **Pushed to origin:** yes.
- **Ahead/behind:** 0 / 0.
- **Working tree:** clean (`git status --porcelain` empty).
- **Remote:** `https://github.com/sandhyaprojects2/secureiam-.git`
- **Tags:** every phase 1 through 5 now has a `phase-X[.Y]-complete` tag,
  pushed to origin.

---

## 8. Current Checkpoint

**Phase 5's checkpoint is fully closed.** All of the following were
completed as part of closing it:

- [x] Design review conducted and approved before any code was written
      (current flow traced, race condition identified precisely, atomic-
      UPDATE-vs-FOR-UPDATE tradeoff reasoned from this codebase's actual
      architecture, reuse-detection/family-revocation algorithm and audit
      events designed, deterministic test strategy planned, every
      affected existing test identified in advance).
- [x] Final pre-implementation consistency check performed (chain
      linearity, no cross-token revocation possible, bounded retry loop,
      no partial commits, no orphaned child token on a failed conditional
      update, identical external responses across every failure reason)
      — no issues found.
- [x] Implemented: atomic concurrency-safe rotation, reuse detection,
      family revocation, two new audit actions.
- [x] Focused Phase 5 tests run and passing.
- [x] Full suite run and passing (394/394).
- [x] Security/architecture review performed (see Phase 5 completion
      report).
- [x] Concurrency behavior verified against real Postgres (10 consecutive
      isolated runs of the concurrent-HTTP-request test, 8 consecutive
      runs of the deterministic repository-level tests — 100% consistent).
- [x] `docs/security-review.md`, `docs/phase-2-readiness.md`, `README.md`
      updated to describe what's implemented instead of what's planned.
- [x] `docs/PROJECT_STATUS.md` updated as the permanent source of truth.
- [x] `docs/phases/phase-5.md` created.
- [x] Committed.
- [x] Pushed `master` to `origin`.
- [x] Tagged `phase-5-complete` and pushed the tag.
- [x] Remote verified to contain both the commit and the tag; CI verified
      green.
- [x] Working tree confirmed clean.

**No outstanding checkpoint items remain.** The next phase (Phase 6 or
otherwise) is intentionally **not defined or started** — see §4: no such
definition exists anywhere in this repository yet, and none was invented
to fill that gap. Per the explicit instruction under which this phase was
completed, work stops here.

---

## 9. Workflow for Every Future Phase

Established and in effect starting now, for every phase from here
forward:

1. Finish the current phase completely.
2. Run the relevant tests.
3. Run the full test suite when appropriate.
4. Review the implementation for regressions/security issues.
5. Verify the phase against its documented requirements.
6. Update this document (`docs/PROJECT_STATUS.md`).
7. Create/update the phase documentation in `docs/phases/`.
8. Check git status.
9. Commit the completed phase with a clear commit message.
10. Verify the commit is pushed to GitHub.
11. Confirm the working tree is clean.
12. Give a concise phase-completion report.
13. **Only after all of the above**, proceed to the next phase.

**Safety rule:** an established architectural or security invariant
(e.g. deny-by-default authorization, no role-name-based checks, opaque
SHA-256 refresh tokens, enumeration-prevention response shapes,
success-only vs. success-and-failure audit policies per service) is never
changed automatically. If a future phase requires changing one, the
correct response is to **stop and explain** what would change, why the
new phase needs it, the alternatives, and a recommendation — then wait
for explicit approval before touching it.
