# Phase 2.3 — Authorization Service (Core RBAC Engine)

**Tag:** `phase-2.3-complete`
**Commit:** *(this phase's commit — see `git log docs/phases/phase-2.3.md`)*

## What This Phase Accomplished

Phase 2.3 adds `AuthorizationService`: the component that finally answers
the question Phase 1 deferred and Phase 2.1/2.2 built the schema and
repositories for — **can this user do this?** It also adds the last piece
of repository surface RBAC needs (`RoleRepository.add_permission` /
`remove_permission`) and the domain-level exceptions and schemas that go
with it. This phase is service-layer only — no new API routes; a future
`POST /v1/authorize` (flagged as buildable-without-changes back in
`docs/phase-2-readiness.md`) can sit on top of this unchanged.

## Why It Was Needed

Every prior RBAC phase was building toward this: Phase 2.1 gave the data a
home, Phase 2.2 gave it an efficient, immediately-consistent read path
(`UserRoleRepository.get_permissions_for_user`). Neither phase made a single
authorization *decision* — that logic didn't exist anywhere in the codebase
until this phase. Without it, having roles and permissions in the database
was inert data with no consumer.

## Files Created

- **`app/domain/services/authorization_service.py`** — `AuthorizationService`,
  constructor-injected with `user_repository`, `role_repository`,
  `permission_repository`, `user_role_repository` (same DI shape as
  `AuthService`). Provides:
  - `authorize(user_id, resource, action)` — the core deny-by-default check.
  - `create_role(name, description=None)`
  - `assign_role(user_id, role_id)`
  - `revoke_role(user_id, role_id)`
  - `assign_permission_to_role(role_id, permission_id)`
  - `remove_permission_from_role(role_id, permission_id)`
  - `get_user_permissions(user_id)`

  Like `AuthService`, this module contains no SQL, no SQLAlchemy queries, no
  session management, and no FastAPI/`HTTPException` — it's fully testable
  with mocked repositories.

- **`app/domain/schemas/authorization.py`** — `AuthorizationDecision`
  (`allowed`, `resource`, `action` — deliberately *no* `reason` field, for
  the same anti-enumeration logic behind `InvalidCredentialsError`),
  `RoleResponse`, `PermissionResponse`. Same rationale as
  `app/domain/schemas/auth.py`: return types for the service layer, not HTTP
  models.

- **`tests/unit/test_authorization_service.py`** — 27 unit tests against
  mocked repositories (`unittest.mock.AsyncMock`), zero database.

- **`docs/phases/phase-2.3.md`** — this document.

## Files Modified

- **`app/domain/exceptions.py`** — added `RoleNotFoundError`,
  `PermissionNotFoundError`, `RoleNameAlreadyExistsError`,
  `RoleAlreadyAssignedError`, `PermissionAlreadyAssignedError`. Notably
  *absent*: any `PermissionDeniedError`-style exception —
  `authorize()` never raises to signal "not allowed," it returns an
  `AuthorizationDecision`. That's a deliberate control-flow choice: deny is
  data, not an exception a caller could accidentally catch-and-ignore.

- **`app/repositories/role_repository.py`** — added `add_permission(role_id,
  permission_id)` and `remove_permission(role_id, permission_id)`, following
  the exact shape of the phase's existing methods: `add_permission` raises
  `DuplicateRolePermissionError` on the composite-PK conflict (mirroring
  `create_role`'s `IntegrityError` handling); `remove_permission` returns
  `bool` rather than raising on "not attached" (mirroring
  `UserRoleRepository.revoke`).

- **`app/repositories/exceptions.py`** — added `DuplicateRolePermissionError`.

- **`tests/integration/test_rbac_repositories.py`** — added 4 tests for the
  two new `RoleRepository` methods, against real Postgres.

## Tests Added

- **27 unit tests** for `AuthorizationService` (mocked repositories):
  module hygiene (1 — asserts the literal source of `authorize()` never
  contains a seeded role name, locking in "permission-based, not
  role-name-based"), `authorize()` (8 — allow, deny-by-default, no-roles,
  inactive user, inactive-user-skips-permission-lookup, unknown user,
  unrecognized resource/action pair handled without raising, immediate
  reflection of a permission change across two calls), `create_role` (3),
  `assign_role` (3), `revoke_role` (2), `assign_permission_to_role` (4),
  `remove_permission_from_role` (3), `get_user_permissions` (3, including an
  immediate-revocation-reflection test).
- **4 integration tests** for `RoleRepository.add_permission` /
  `remove_permission` against real Postgres: attach succeeds and is visible
  in `role_permissions`, duplicate attach raises
  `DuplicateRolePermissionError`, detach succeeds and removes the row,
  detaching a never-attached permission returns `False`.

Full suite after this phase: **177 tests collected, 176 passing** (146 from
Phase 1/2.1/2.2 + 27 new unit + 4 new integration = 177). The one
non-passing test, `test_fresh_database_migration.py::
test_migrations_apply_cleanly_to_a_fresh_empty_database`, is a **pre-existing
environment limitation, not a Phase 2.3 regression** — it requires a second,
standalone Postgres admin instance on port 5432 (to `CREATE DATABASE`
against), which isn't running in this local environment (only the
port-5433 test-db container from `docker-compose.test.yml` is available).
It failed identically before any Phase 2.3 code was written; the baseline
was independently confirmed as 145/146 passing prior to this phase.

## Important Architectural / Security Decisions

- **Deny by default.** `authorize()` starts from `allowed=False` and only
  flips to `True` if a matching `(resource, action)` pair is found in the
  user's resolved permission set. There is no implicit-allow branch.
- **Permission-based, never role-name-based.** `authorize()` never compares
  a role's *name* to a string (`if role.name == "Admin"`) — it only checks
  the resolved permission set. `test_authorize_never_compares_against_a_
  hardcoded_role_name` inspects the actual source of the method (via
  `inspect.getsource`) to lock this in structurally, not just by review.
  This means granting a new role Admin-equivalent access is a data change
  (attach permissions to it), never a code change to `authorize()`.
- **Inactive users are always denied**, checked *before* any permission
  lookup — mirrors `AuthService.login()`'s `InactiveUserError` check, and
  is asserted directly (`test_authorize_inactive_user_never_queries_
  permissions`) so the short-circuit can't silently regress into an
  unnecessary query.
- **No caching, anywhere in this service.** `authorize()` and
  `get_user_permissions()` both call `UserRoleRepository.get_permissions_
  for_user()` fresh on every invocation, inheriting Phase 2.2's
  no-caching guarantee. This is what makes role revocation and permission
  removal take effect immediately — proven with mock-based tests that
  change the repository's return value between two calls to the same
  service method and assert the second call reflects the change.
- **Unknown permissions never raise.** Asking `authorize()` about a
  `(resource, action)` pair that doesn't exist in the permission catalog at
  all is handled identically to asking about one that exists but isn't
  granted — both simply resolve to `allowed=False`. This keeps the hot
  authorization path exception-free and matches the "properly handle
  unknown permissions" requirement directly.
- **Role/permission *management* exceptions are unambiguous, unlike
  authentication's.** `RoleNotFoundError`, `PermissionNotFoundError`, etc.
  are each their own distinct exception type — there's no enumeration
  concern here, since role/permission ids are internal, admin-supplied
  identifiers, not user-facing secrets like an email address.
- **Existence is validated before mutation, not inferred from the
  failure mode.** `assign_permission_to_role` checks both the role and the
  permission exist *before* calling `RoleRepository.add_permission` — this
  is what lets that repository method safely assume any `IntegrityError` it
  catches is the duplicate-assignment case, not a foreign-key violation
  against a nonexistent role or permission.

## What This Phase Enables

`AuthorizationService` is now a complete, self-contained authorization
engine, ready to sit behind a future `POST /v1/authorize` route or any
protected endpoint via `Depends(get_current_user)` plus a service call —
with zero changes required to `AuthService`, the RBAC repositories, or the
schema, exactly as `docs/phase-2-readiness.md` anticipated for the
authentication side back in Phase 1. Later phases (multi-tenancy/Phase 3,
audit logging/Phase 4, an actual `/authorize` HTTP surface) can build on
this without touching its internals.
