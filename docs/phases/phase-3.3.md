# Phase 3.3 — Multi-Tenancy Service Layer

**Tag:** `phase-3.3-complete`
**Commit:** *(this phase's commit — see `git log docs/phases/phase-3.3.md`)*

## What This Phase Accomplished

Phase 3.3 makes `AuthorizationService` organization-aware
(`authorize()`, `create_role()`, `assign_role()`, `revoke_role()`,
`get_user_permissions()` all gained an optional `organization_id`), and
introduces a new `OrganizationService` for organization/membership
management — the same layering split Phase 2.3 established for RBAC
itself: business rules live in the service layer, repositories stay
opinion-free.

## Why It Was Needed

Phase 3.1/3.2 built the schema and repository plumbing for organization
scoping; nothing yet decided *when* an org-scoped assignment should be
allowed. Two real business rules only belong at this layer: an org-scoped
role can only be assigned within its own organization (not a mismatched
one, not globally), and a user must actually belong to an organization
before being granted access scoped to it. Repositories deliberately don't
make either judgment — see Phase 3.2's docs — so this phase exists to make
them.

## Files Created

- `app/domain/services/organization_service.py` — `OrganizationService`:
  `create_organization`, `add_member`, `remove_member`, `list_members`,
  `list_organizations_for_user`. Deliberately separate from
  `AuthorizationService`, mirroring the `AuthService`/`AuthorizationService`
  split: this service owns "does this org exist, who belongs to it," not
  "what can a member do" — membership *enforcement* for RBAC purposes
  stays in `AuthorizationService.assign_role()`.
- `app/domain/schemas/organization.py` — `OrganizationResponse`,
  `OrganizationMemberResponse`.
- `tests/unit/test_organization_service.py` — 13 tests against mocked
  repositories.
- `docs/phases/phase-3.3.md` — this document.

## Files Modified

- `app/domain/services/authorization_service.py` — constructor gained
  `organization_repository` and `organization_membership_repository`.
  - `authorize(..., organization_id=None)` — passes straight through to
    `UserRoleRepository.get_permissions_for_user()`'s existing
    global-plus-scoped resolution (Phase 3.2); echoes `organization_id`
    back on the returned `AuthorizationDecision`.
  - `create_role(..., organization_id=None)` — validates the organization
    exists (`OrganizationNotFoundError`) before creating an org-scoped role.
  - `assign_role(..., organization_id=None)` — the phase's central piece
    of new logic; see Decisions below.
  - `revoke_role(..., organization_id=None)`,
    `get_user_permissions(..., organization_id=None)` — simple passthroughs
    to their already-org-aware repository counterparts.
- `app/domain/schemas/authorization.py` — `AuthorizationDecision` and
  `RoleResponse` both gained `organization_id: uuid.UUID | None = None`.
- `app/domain/exceptions.py` — added `OrganizationNotFoundError`,
  `OrganizationNameAlreadyExistsError`, `UserNotFoundError`,
  `RoleOrganizationMismatchError`, `UserNotOrganizationMemberError`,
  `OrganizationMembershipAlreadyExistsError`.
- `app/core/dependencies.py` — `get_authorization_service()` updated to
  construct and inject the two new repositories. This was a **required**
  fix, not new API-layer work: `AuthorizationService`'s constructor
  changed in this same phase, so its only real construction site had to
  change with it or the app would fail to boot.
- `tests/unit/test_authorization_service.py` — fixture updated for the new
  constructor shape; 11 new tests for organization-aware `authorize()`,
  `create_role()`, `assign_role()`, `revoke_role()`, and
  `get_user_permissions()`.

## Tests Added

- **13 tests** in `test_organization_service.py`: organization creation
  (success, duplicate name), `add_member` (success, unknown user, unknown
  organization, duplicate membership), `remove_member`
  (success, idempotent no-op), `list_members` (success, unknown
  organization raises, empty list for a real organization with no
  members), and `list_organizations_for_user` (populated and empty).
- **11 tests** added to `test_authorization_service.py`: `authorize()`
  passes `organization_id` through and echoes it back; `create_role()`
  scoped-creation success and unknown-organization rejection; `assign_role()`
  — a global role scoped to an organization (success, checks membership),
  unknown organization, non-member rejection, an org-scoped role assigned
  under the *wrong* organization (mismatch), an org-scoped role assigned
  with *no* organization at all (also a mismatch), and an org-scoped role
  assigned correctly under its own organization; `revoke_role()` and
  `get_user_permissions()` passing `organization_id` through.

Full suite after this phase: **270 tests collected, 269 passing** (246
from Phase 1–3.2 + 24 new). The one non-passing test is the same
pre-existing environment limitation carried since Phase 2.3, unchanged by
this phase.

## Important Architectural / Security Decisions

- **`assign_role()` is where every multi-tenant RBAC business rule lives,
  and it enforces them in a specific order:**
  1. The role must exist (`RoleNotFoundError`).
  2. If the role itself is org-scoped, the requested `organization_id`
     must exactly match the role's own — checked *before* even looking up
     whether that organization exists, since a role-organization mismatch
     is knowable from the role alone (`RoleOrganizationMismatchError`).
     This also covers "an org-scoped role assigned with no organization at
     all" as the same mismatch, not a separate case.
  3. If an `organization_id` was given, it must refer to a real
     organization (`OrganizationNotFoundError`).
  4. The user must already be a member of that organization
     (`UserNotOrganizationMemberError`) — checked once, at assignment
     time, not on every later `authorize()` call. Membership is a
     precondition for being *granted* scoped access, not something
     `authorize()` re-verifies on every request; `authorize()`'s existing
     no-caching permission resolution already keeps access current if a
     role is later revoked or a permission removed, which is the property
     that actually needs to hold on every request.
  5. Only then is the assignment attempted, and
     `DuplicateRoleAssignmentError` translated to `RoleAlreadyAssignedError`
     exactly as before.
- **A global role has no organization restriction at assignment time.**
  It can be assigned with no `organization_id` (a true global grant) or
  scoped to any one organization the user belongs to (e.g. "Manager, but
  only within Org A") — both are legitimate, and the membership check
  applies identically to both.
- **`OrganizationService` does not enforce RBAC membership rules, and
  `AuthorizationService` does not own organization CRUD.** Both services
  depend on `OrganizationRepository`/`OrganizationMembershipRepository`,
  which is ordinary shared-repository dependency injection, not a layering
  violation — the same repository is already reused this way elsewhere
  (e.g. `UserRepository` is depended on by both `AuthService` and
  `get_current_user`).
- **`get_authorization_service()`'s update in this phase is a mechanical
  necessity, not new capability.** It's called out explicitly in this
  phase's docs (rather than silently bundled in) because it touches
  `app/core/dependencies.py`, which conceptually belongs to the API layer
  (Phase 2.4's territory) — but leaving it unfixed here would have broken
  every existing authorization-related route the moment this phase's
  constructor change shipped.

## What This Phase Enables for Phase 3.4

`AuthorizationService` and `OrganizationService` are both complete,
independently tested business layers. Phase 3.4 can expose them as HTTP
routes (`POST /v1/organizations`, membership management, `organization_id`
support on the existing `/v1/authorize`, `/v1/roles`, and `/v1/users/*`
endpoints) with no further service-layer changes anticipated.
