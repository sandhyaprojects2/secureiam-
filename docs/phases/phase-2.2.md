# Phase 2.2 — RBAC Repository Layer

**Tag:** `phase-2.2-complete` → `45fc16a`
**Commit:** `45fc16a`

## What This Phase Accomplished

Phase 2.2 adds the repository layer over Phase 2.1's schema:
`RoleRepository`, `PermissionRepository`, and `UserRoleRepository`. Still no
business logic and no `AuthorizationService` — this phase answers "what does
the database say," matching the same repository contract Phase 1 established
for `UserRepository`/`RefreshTokenRepository`.

## Why It Was Needed

`AuthorizationService` (Phase 2.3) needs a permission-resolution query it
can call on every single authorization check — and that query needs to
already be efficient and correct, proven against real Postgres, before any
authorization logic is built on top of it. Phase 2.2 exists to deliver that
query (`get_permissions_for_user`) and the surrounding CRUD it depends on,
fully isolated and tested.

## Files / Features Introduced

- `app/repositories/exceptions.py` — added `DuplicateRoleNameError` and
  `DuplicateRoleAssignmentError`, same pattern as Phase 1's
  `DuplicateEmailError`: each translates a real DB constraint violation;
  neither decides what it means for the business.
- `app/repositories/role_repository.py` — `create_role`, `get_by_id`,
  `get_by_name`, `list_all`. Deliberately does **not** normalize name
  casing (unlike `UserRepository.get_by_email`) — role names are
  admin-controlled internal identifiers, not a user-facing field with an
  enumeration/confusion risk.
- `app/repositories/permission_repository.py` — `get_by_id`,
  `get_by_resource_action`, `list_all`. Deliberately read-only: permissions
  are seeded once via migration, not created dynamically through the API in
  this phase.
- `app/repositories/user_role_repository.py` — `assign`, `revoke`,
  `get_roles_for_user`, `get_permissions_for_user`. The last is the single
  most important query in Phase 2: one indexed join across
  `user_roles → role_permissions → permissions` with `DISTINCT`, not N+1
  lookups per role. No caching, by design, so role revocation takes effect
  immediately. `revoke()` returns `bool` (found-and-removed vs. not-found)
  rather than raising, leaving the "is this an error" decision to
  `AuthorizationService` in Phase 2.3 — matching
  `RefreshTokenRepository`'s established pattern from Phase 1.

## Tests Added

28 new integration tests in `tests/integration/test_rbac_repositories.py`
against real Postgres, covering `RoleRepository` (creation, duplicate
rejection, case-sensitive lookup, list including seeded roles),
`PermissionRepository` (read-only lookups against the seeded catalog, plus
an explicit test confirming no `create_permission`/`create` method exists),
and `UserRoleRepository` (assignment, duplicate rejection, idempotent
revoke, multi-role permission union with deduplication proven against real
seeded roles — Intern+Developer unions to exactly `{document:view,
document:edit}`, Manager+Developer's overlapping `document:view` doesn't
duplicate — immediate effect of revocation, and cascade delete on user
removal). Total after this phase: 146 tests (118 from Phase 1+2.1 + 28 new).

## Important Architectural / Security Decisions

- **A real finding, documented directly in the test file and here for
  visibility:** SQLAlchemy's `session.rollback()` (triggered by any
  duplicate-detection path in these repositories) expires *every* attribute
  of *every* object in that session's identity map, including primary
  keys — not just the object involved in the failed operation. Accessing an
  expired attribute outside an awaited context raises `MissingGreenlet`.
  This is not a repository bug; it's a caller-side pattern requirement:
  capture primitive values (e.g. `role_id = role.id`) into plain variables
  *before* any operation that might roll back, and use only those captured
  primitives afterward. Every test in `test_rbac_repositories.py` follows
  this deliberately, and it is directly relevant to how
  `AuthorizationService`'s assign/revoke methods are written in Phase 2.3.
- **No caching anywhere in the permission-resolution path.** This was a
  deliberate, tested design choice (`test_revoking_role_immediately_removes_
  its_permissions`) so that role revocation is never stale — a correctness
  property Phase 2.3's `authorize()` inherits for free by calling this
  layer on every check.

## What This Phase Enables for Phase 2.3

A complete, tested repository surface — role CRUD, read-only permission
lookups, and a single efficient permission-resolution query — that
`AuthorizationService` can compose directly. Phase 2.3 needed to add exactly
two new repository methods (`RoleRepository.add_permission` /
`remove_permission`) rather than build any new query infrastructure.
