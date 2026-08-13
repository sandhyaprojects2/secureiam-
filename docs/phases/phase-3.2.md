# Phase 3.2 — Multi-Tenancy Repository Layer

**Tag:** `phase-3.2-complete`
**Commit:** *(this phase's commit — see `git log docs/phases/phase-3.2.md`)*

## What This Phase Accomplished

Phase 3.2 adds the repository layer over Phase 3.1's schema:
`OrganizationRepository`, `OrganizationMembershipRepository`, and
organization-aware extensions to the existing `RoleRepository` and
`UserRoleRepository`. Still no service-layer business rules — this phase
answers "what does the database say," exactly matching the discipline
Phase 2.2 established for the original RBAC repositories.

## Why It Was Needed

Phase 3.3's `AuthorizationService` updates need an org-aware
`get_permissions_for_user()` to call, and a way to check organization
membership before granting an org-scoped role — both need to be built and
proven correct against real Postgres first, in isolation, the same way
Phase 2.2 delivered `get_permissions_for_user()` a full sub-phase ahead of
`AuthorizationService.authorize()` consuming it.

## Files Created

- `app/repositories/organization_repository.py` — `create_organization`,
  `get_by_id`, `get_by_name`, `list_all`. Same shape as `RoleRepository`.
- `app/repositories/organization_membership_repository.py` — `add_member`,
  `remove_member`, `is_member`, `get_organizations_for_user`,
  `get_members_for_organization`. The last returns lightweight joined rows
  (`user_id`, `email`, `joined_at`), not full `User` objects, since no
  caller needs more than that to identify and display a member.
- `tests/integration/test_organization_repositories.py` — 17 tests against
  real Postgres.
- `docs/phases/phase-3.2.md` — this document.

## Files Modified

- `app/repositories/exceptions.py` — added `DuplicateOrganizationNameError`
  and `DuplicateMembershipError`, same translation pattern as every other
  repository exception in this codebase.
- `app/repositories/role_repository.py` — `create_role()` gained an
  `organization_id: uuid.UUID | None = None` parameter, passed straight
  through to the `Role` constructor. Defaulting to `None` means every
  existing call site (Phase 2.2/2.3/2.4, all their tests) keeps creating
  global roles exactly as before.
- `app/repositories/user_role_repository.py` — `assign()`,
  `get_roles_for_user()`, and `get_permissions_for_user()` all gained the
  same optional `organization_id` parameter, with a shared
  `_organization_scope_filter()` helper implementing the "global rows
  always match; rows scoped to the given organization also match" read
  semantics documented in Phase 3.1. `revoke()` also gained the parameter,
  but deliberately does an **exact** match rather than the same
  global-plus-scoped union — revoking should only ever remove the one row
  actually asked for, never accidentally remove a global assignment when
  the caller meant to revoke an org-scoped one, or vice versa.
- `tests/integration/test_rbac_repositories.py` — added 6 tests for the
  new organization-scoping behavior on `RoleRepository`/`UserRoleRepository`.

## Tests Added

- **17 tests** in `test_organization_repositories.py`: `OrganizationRepository`
  (creation, duplicate-name rejection, lookups, listing) and
  `OrganizationMembershipRepository` (add/remove/idempotent-remove,
  `is_member` true/false, listing an individual user's organizations, and
  listing an organization's members with the expected joined fields).
- **6 tests** added to `test_rbac_repositories.py`: `create_role()`
  defaults to `organization_id=None`; a role can be created scoped to a
  real organization; a globally-assigned role is visible with no
  organization context; an org-scoped assignment is invisible with no
  context *and* under a different organization, but visible under its own;
  `get_permissions_for_user()` correctly unions global-plus-scoped
  permissions for a given organization (proven against real seeded roles —
  global `Intern` plus org-scoped `Developer` resolves to exactly
  `{document:view, document:edit}` under that org's context, but only
  `{document:view}` with no context); and `revoke()`'s exact-match
  semantics (revoking with the wrong organization context is a no-op,
  revoking with the right one succeeds).

Full suite after this phase: **246 tests collected, 245 passing** (223
from Phase 1–3.1 + 23 new). The one non-passing test is the same
pre-existing environment limitation carried since Phase 2.3, unchanged by
this phase.

## Important Architectural / Security Decisions

- **Read methods use global-plus-scoped union; `revoke()` uses exact
  match.** This asymmetry is deliberate, not an inconsistency: resolving
  "what can this user do in this org" must include their global grants
  (a global assignment applies everywhere, by definition), but removing a
  specific assignment must only ever touch the exact row requested — an
  admin revoking someone's org-scoped `Manager` role in Org A must never
  accidentally also strip a global role that happens to share the same
  `role_id`.
- **`get_members_for_organization()` returns a purpose-built row shape, not
  `User` objects.** Matches `UserRoleRepository.get_permissions_for_user()`'s
  established efficiency discipline from Phase 2.2 — select exactly the
  columns a caller needs in one query, not a heavier ORM object graph "just
  in case."
- **All new repository methods still validate nothing themselves.**
  `RoleRepository.create_role(organization_id=...)` doesn't check the
  organization exists; `UserRoleRepository.assign(organization_id=...)`
  doesn't check the role is actually scoped to that organization or that
  the user is even a member of it. This is intentional and consistent with
  every repository in this codebase: existence/business-rule validation is
  `AuthorizationService`'s job (Phase 3.3), not the repository's — a
  repository answers "what does the database say," never "should this be
  allowed."

## What This Phase Enables for Phase 3.3

A complete, tested repository surface for both organization management and
organization-scoped role resolution. Phase 3.3's `AuthorizationService`
updates (`authorize()`, `assign_role()`, `create_role()`, and a new
`OrganizationService`) can compose these directly — no further repository
methods are anticipated.
