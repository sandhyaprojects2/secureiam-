# Phase 3.4 — Multi-Tenancy API Layer

**Tag:** `phase-3.4-complete`
**Commit:** *(this phase's commit — see `git log docs/phases/phase-3.4.md`)*

## What This Phase Accomplished

Phase 3.4 exposes Phase 3.3's `OrganizationService` over HTTP
(`POST /v1/organizations` and membership management), and adds
`organization_id` support to the existing `/v1/authorize`, `/v1/roles`, and
`/v1/users/*` endpoints from Phase 2.4. This completes Phase 3 end-to-end:
schema (3.1) → repositories (3.2) → service (3.3) → API (3.4), the same
four-layer shape Phase 2 used for RBAC.

## Why It Was Needed

Phase 3.3 made the service layer organization-aware, but nothing in the
running application could create an organization, add a member to one, or
ask for an org-scoped authorization decision over HTTP. This phase is the
last piece needed to make multi-tenancy usable end-to-end through the real
API.

## Files Created

- `app/api/v1/organizations.py` — `POST /v1/organizations` (requires
  `organization:manage`) → 201, or 409 on duplicate name;
  `POST /v1/organizations/{organization_id}/members` (requires
  `organization:manage`) → 204, or 404 (unknown user/organization) / 409
  (already a member); `DELETE .../members/{user_id}` (requires
  `organization:manage`) → 204 always (idempotent);
  `GET .../members` (requires `organization:manage`) → member list, or 404
  for an unknown organization; `GET /v1/users/me/organizations` (requires
  only authentication) — self-service, not a privileged operation.
- `app/api/v1/schemas/organization.py` — HTTP-facing request/response
  types, kept separate from `app.domain.schemas.organization`.
- `app/db/migrations/versions/97122fa13dcc_seed_organization_manage_permission.py`
  — seeds one new permission, `organization:manage`, granted to the
  existing seeded Admin role. This is exactly the extensibility case the
  original Phase 2.1 seed migration's docstring anticipated: "new
  resource:action pairs can be added later as plain data, with no schema
  change and no code change to `AuthorizationService`'s evaluation logic."
- `tests/integration/test_organizations_api.py` — 15 tests against real
  Postgres, real FastAPI, real HTTP calls.
- `docs/phases/phase-3.4.md` — this document.

## Files Modified

- `app/api/v1/authorize.py` — `POST /v1/authorize` and `POST /v1/roles`
  gained optional `organization_id` in their request bodies;
  `POST /v1/users/{user_id}/roles` gained the same, now translating three
  new domain exceptions (`OrganizationNotFoundError` → 404,
  `RoleOrganizationMismatchError` → 409, `UserNotOrganizationMemberError` →
  409); `DELETE /v1/users/{user_id}/roles/{role_id}`,
  `GET /v1/users/me/permissions`, and `GET /v1/users/{user_id}/permissions`
  all gained `organization_id` as an optional query parameter.
- `app/api/v1/schemas/authorization.py` — `AuthorizeRequest`,
  `CreateRoleRequest`, and `AssignRoleRequest` gained optional
  `organization_id`; `AuthorizeResponse` and `RoleResponse` echo it back.
- `app/core/dependencies.py` — added `get_organization_service()`, same DI
  shape as `get_auth_service()`/`get_authorization_service()`.
- `app/main.py` — registered the new router; bumped version to `0.3.0` and
  description to mention Phase 3.
- `tests/integration/test_authorize_api.py` — +5 tests for
  organization-scoped assignment, authorization, and revocation.
- `tests/integration/test_rbac_models.py` — the Admin
  all-permissions test now includes `organization:manage`; added a
  dedicated test confirming that permission is granted to Admin only.
- `tests/integration/test_fresh_database_migration.py` — permission/mapping
  counts updated from 5/12 to 6/13 to reflect the new seed migration.
- `tests/unit/test_app_startup.py` — +3 tests for the new routes' wiring
  and status codes.
- `tests/integration/test_dependency_wiring.py` — +2 tests for
  `get_organization_service()`.

## Tests Added

- **15 tests** in `test_organizations_api.py`: organization creation
  (requires permission, success, duplicate name), member management
  (add success, unknown organization/user, duplicate; remove success and
  idempotent no-op; list success, unknown organization, requires
  permission), and self-service organization listing (populated, empty,
  requires authentication).
- **5 tests** added to `test_authorize_api.py`: assigning an org-scoped
  role to a non-member is rejected (409); assigning it to a member
  succeeds and is visible only under that organization's context, not
  without one; assigning under an unknown organization is a 404;
  `/v1/authorize` with an `organization_id` correctly includes org-scoped
  grants that are invisible without one; revoking an org-scoped assignment
  removes only that assignment.
- **2 tests** modified + **1 test** added in `test_rbac_models.py` for the
  new seeded permission's exact grant shape.
- **3 tests** added to `test_app_startup.py`, **2 tests** added to
  `test_dependency_wiring.py` for route/DI wiring.

Full suite after this phase: **296 tests collected, 295 passing** (270
from Phase 1–3.3 + 26 new). The one non-passing test is the same
pre-existing environment limitation carried since Phase 2.3, unchanged by
this phase — its updated assertions (6 permissions, 13 mappings on a fresh
install) were independently verified against a throwaway database created
on the available test-db instance, then dropped, the same way Phase 3.1
verified its own fresh-install assertions.

## Important Architectural / Security Decisions

- **`organization:manage` gates organization CRUD and membership
  management uniformly — there is no separate, lesser "can view my own
  organization's members" permission.** Only a platform-level Admin (or
  anyone else explicitly granted `organization:manage`) can list an
  organization's members, add one, or remove one. A future phase could
  introduce a narrower "manage members of organizations I already belong
  to" permission if that's needed; this phase deliberately keeps the
  simpler, single-permission shape rather than inventing per-organization
  admin roles nobody has asked for yet.
- **`RoleOrganizationMismatchError` and `UserNotOrganizationMemberError`
  both map to `409 Conflict`, not `400`/`422`/`403`.** Both represent the
  request conflicting with the current state of a named resource (this
  role's fixed scope; this user's actual membership), which is the same
  category `RoleAlreadyAssignedError` and the other existing `409`s in
  this codebase already represent — kept consistent rather than
  introducing a new status-code convention for two exceptions that are
  conceptually the same shape as ones already mapped.
- **No route lets a caller ask about another organization's `authorize()`
  decision or another user's `/v1/users/me/organizations`.** Exactly the
  same reasoning as Phase 2.4's `/v1/authorize` design: each additional
  capability is its own attack surface, and nothing in this phase needs
  either.
- **The new seed migration is deliberately minimal and additive** — one
  permission, one role mapping, nothing else touched. Two pre-existing
  Phase 2 tests that asserted an *exact* permission set for Admin needed
  updating as a direct, expected consequence (not a regression): they were
  the only two tests in the whole suite written as strict equality against
  a "final" catalog rather than a subset check, and both are now the
  authoritative source of truth for what "all of Admin's permissions"
  currently means.

## What This Phase Enables

Multi-tenancy is now fully wired end-to-end: schema (3.1) → repositories
(3.2) → service (3.3) → API (3.4), the same shape Phase 2 completed for
RBAC itself. Every organization-scoped capability introduced across
Phase 3 is reachable over real HTTP, with the same deny-by-default,
no-caching, and idempotent-mutation guarantees Phase 2's RBAC engine
established. A future phase needing organization-scoped resources (e.g. a
document-management demo scoped per organization) can build directly on
this without further changes to the authorization surface.
