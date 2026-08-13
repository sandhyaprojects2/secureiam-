# Phase 2.4 — Authorization API Layer

**Tag:** `phase-2.4-complete`
**Commit:** *(this phase's commit — see `git log docs/phases/phase-2.4.md`)*

## What This Phase Accomplished

Phase 2.4 exposes `AuthorizationService` (Phase 2.3) over HTTP: a
`POST /v1/authorize` endpoint for permission checks, plus role and
role/permission/user-role management routes, all protected by a new
`require_permission()` FastAPI dependency. This is exactly the surface
`docs/phase-2-readiness.md` predicted back in Phase 1 — `app/api/v1/
authorize.py`, `POST /v1/authorize` — and it required zero changes to
`AuthService`, the RBAC repositories, `AuthorizationService` itself, or the
JWT claim structure.

## Why It Was Needed

Phase 2.3 made `AuthorizationService` a complete, tested engine, but
nothing in the running application could call it — there was no way for an
HTTP client to ask "can I do this" or for an admin to actually create a
role or grant a permission outside a Python shell. Phase 2.4 is the last
piece needed to make RBAC usable end-to-end through the real API, the same
way Phase 1's API layer made `AuthService` usable.

## Files Created

- **`app/api/v1/authorize.py`** — thin routes only, following the exact
  contract of `app/api/v1/auth.py`: validate request → call
  `AuthorizationService` → translate exactly five domain exceptions
  (`RoleNotFoundError`, `PermissionNotFoundError`, `RoleNameAlreadyExistsError`,
  `RoleAlreadyAssignedError`, `PermissionAlreadyAssignedError`) into HTTP
  responses.
  - `POST /v1/authorize` — checks the *caller's own* permissions only (no
    `user_id` parameter; asking about someone else's permissions would
    itself be an authorization question this endpoint has no way to gate).
  - `POST /v1/roles` (requires `role:manage`) → 201, or 409 on duplicate name.
  - `POST /v1/roles/{role_id}/permissions` (requires `role:manage`) → 204,
    or 404 (unknown role/permission) / 409 (already assigned).
  - `DELETE /v1/roles/{role_id}/permissions/{permission_id}` (requires
    `role:manage`) → 204 always, except 404 for an unknown role — removing
    an unattached permission is a no-op, not an error.
  - `GET /v1/users/me/permissions` (requires only authentication) — a
    user's own permission listing is not a privileged operation.
  - `POST /v1/users/{user_id}/roles` (requires `user:manage`) → 204, or 404
    / 409.
  - `DELETE /v1/users/{user_id}/roles/{role_id}` (requires `user:manage`)
    → 204 always (idempotent, same shape as `AuthService.logout()`).
  - `GET /v1/users/{user_id}/permissions` (requires `user:manage`).

- **`app/api/v1/schemas/authorization.py`** — HTTP-facing request/response
  types, deliberately kept separate from `app.domain.schemas.authorization`
  (same rationale as `app/api/v1/schemas/auth.py` vs.
  `app/domain/schemas/auth.py`).

- **`tests/integration/test_authorize_api.py`** — 24 tests against real
  Postgres, real FastAPI, real HTTP calls (`httpx.AsyncClient`),
  `AuthorizationService` not mocked.

- **`docs/phases/phase-2.4.md`** — this document.

## Files Modified

- **`app/core/dependencies.py`** — added `get_authorization_service()`
  (same DI shape as `get_auth_service()`) and `require_permission(resource,
  action)`, a dependency *factory* that wraps `get_current_user` with an
  `AuthorizationService.authorize()` call, raising a single generic 403
  for every denial reason (inactive user, no matching role, permission
  exists but isn't granted) — mirroring how `get_current_user` already
  collapses every authentication failure into one generic 401. This is the
  only place an `AuthorizationDecision` is translated into an HTTP status
  code.
- **`app/main.py`** — registered the new router; bumped the app version and
  description to reflect Phase 2's RBAC surface now being live.
- **`tests/unit/test_app_startup.py`** — added route-wiring assertions for
  the new endpoints, including a dedicated test locking in the
  `/users/me/permissions`-before-`/users/{user_id}/permissions`
  registration-order requirement (see below).
- **`tests/integration/test_dependency_wiring.py`** — added the equivalent
  wiring checks for `get_authorization_service()`.

## Tests Added

- **24 integration tests** (`test_authorize_api.py`): `/v1/authorize`
  (allow, deny-by-default, unrecognized permission handled without
  erroring, requires authentication), role creation (success, missing
  `role:manage` → 403, duplicate name → 409), role-permission assignment
  and removal (success, unknown role/permission → 404, duplicate → 409,
  removing an unattached permission is idempotent 204), self-service
  permission listing, user-role assignment and revocation (success, missing
  `user:manage` → 403, unknown role → 404, duplicate → 409, revocation is
  idempotent and immediately reflected in a subsequent permission check),
  and admin-only user-permission listing.
- **4 unit tests** added to `test_app_startup.py` for route registration,
  HTTP methods, and configured status codes on the new routes.
- **2 unit tests** added to `test_dependency_wiring.py` for
  `get_authorization_service()`.

Full suite after this phase: **207 tests collected, 206 passing**
(177 from Phase 1–2.3 + 24 new integration + 4 + 2 new unit = 207). The same
pre-existing environment-only failure from Phase 2.3
(`test_fresh_database_migration.py`, requiring a second Postgres instance
on port 5432 not available locally) is the only non-passing test, unchanged
by this phase.

## Important Architectural / Security Decisions

- **No bootstrap-admin endpoint exists, and none was added.** Every test
  that needs an admin-privileged caller assigns the seeded "Admin" role
  directly via `UserRoleRepository`, bypassing the API entirely — mirroring
  the Phase 2.1 seed migration's documented decision that the first Admin
  assignment is a manual, out-of-band step. Phase 2.4 does not introduce a
  way to self-escalate to Admin through the API, on purpose.
- **`require_permission()` denies with one generic message, always.**
  Exactly like `get_current_user`'s single generic 401, a 403 from
  `require_permission()` never distinguishes "you're inactive" from "you
  have no roles" from "your role doesn't grant this" — it only ever
  inspects the boolean `AuthorizationDecision.allowed`.
- **`POST /v1/authorize` only ever answers for the caller.** There is no
  parameter to ask about another user's permissions — that operation isn't
  offered at all, rather than gated by yet another permission check, since
  it isn't needed by anything else in this phase and each additional
  capability is its own attack surface.
- **Route registration order is a documented, tested constraint.**
  `/users/me/permissions` must be registered before the parameterized
  `/users/{user_id}/permissions`, since Starlette matches path patterns in
  registration order, not by specificity — a `uuid.UUID`-typed path
  parameter doesn't prevent the parameterized route from being *tried*
  first if it's registered first, it just makes that attempt fail with 422
  instead of reaching the intended `/me` route. This is called out in the
  module docstring and locked in by
  `test_users_me_permissions_is_registered_before_the_parameterized_route`.
- **Idempotent mutations return 204 unconditionally, never a synthetic
  404/409 for "already in the requested end state."** Revoking a role a
  user doesn't have, or removing a permission a role never had, succeeds
  silently — consistent with `AuthService.logout()`'s established pattern
  from Phase 1 and `AuthorizationService.revoke_role()`'s/`remove_
  permission_from_role()`'s own contracts from Phase 2.3.

## What This Phase Enables

RBAC is now fully wired end-to-end: schema (2.1) → repositories (2.2) →
service (2.3) → API (2.4). Every protected route in a future phase can gate
itself with a single line —
`Depends(require_permission("<resource>", "<action>"))` — with no further
plumbing required. Multi-tenancy (Phase 3) and audit logging (Phase 4) can
build on this surface without modifying it.
