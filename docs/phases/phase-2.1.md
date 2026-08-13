# Phase 2.1 — RBAC Schema

**Tag:** `phase-2.1-complete` → `09fcba5`
**Commit:** `09fcba5`

## What This Phase Accomplished

Phase 2.1 lays down the data model for role-based access control: four new
tables — `roles`, `permissions`, `role_permissions`, `user_roles` — plus a
seed migration populating the four default roles and a starter permission
catalog. No service or repository logic yet; this phase is schema only.

## Why It Was Needed

Phase 2's authorization engine (Phase 2.3) needs somewhere to store "who has
which role" and "which role grants which permission" before it can evaluate
either question. Building the schema as its own phase — reviewed and tested
independently of any service logic — meant the RBAC data model could be
validated (constraints, cascades, seed correctness) in isolation before any
business logic was layered on top of it.

## Files / Features Introduced

- `app/domain/models/role.py` — `Role`. Deliberately global, no
  `organization_id` (multi-tenancy is Phase 3 scope). `is_system_role`
  flags the four default roles as protected from deletion — enforced at the
  service layer in Phase 2.3, not by a DB constraint, since "can this be
  deleted" is a business rule.
- `app/domain/models/permission.py` — `Permission`, global
  `resource`/`action` catalog with `UNIQUE(resource, action)`.
- `app/domain/models/role_permission.py` — `role_permissions`, a pure
  many-to-many association implemented as a SQLAlchemy Core `Table` (not a
  mapped class), since it has no columns beyond the two FKs forming its
  composite primary key.
- `app/domain/models/user_role.py` — `UserRole`, a full mapped model (has
  its own `id`/`assigned_at`), references `users.id` directly rather than
  an organization-membership id, per the documented Phase 3 migration plan.
- Migration `16b0325bd7db` — schema migration for all four tables.
- Migration `ca306aad2376` — seed migration: 4 default roles (Admin,
  Manager, Developer, Intern), a 5-permission catalog
  (`document:view/edit/delete`, `role:manage`, `user:manage`), and the
  role→permission mapping matching the original project pitch (escalating
  document access). `downgrade()` is scoped to exactly what it inserted, not
  a blanket wipe, so it stays safe if custom roles are added later.

## Tests Added

16 new integration tests in `tests/integration/test_rbac_models.py` against
real Postgres: creation and unique-constraint enforcement for `Role` and
`Permission`, cascade-delete of `role_permissions` from both the role side
and the permission side, `UserRole` assignment/duplicate-rejection/cascade
in both directions, and 4 tests locking in the exact seed data shape (Admin
has all 5 permissions, Intern has only `document:view`). Total after this
phase: 118 tests (102 from Phase 1 + 16 new).

`tests/integration/test_fresh_database_migration.py` was also strengthened
to assert the four new tables exist and the seed migration produces exactly
4 roles, 5 permissions, and 12 mappings on a genuinely fresh database.

## Important Architectural / Security Decisions

- **No bootstrap-admin endpoint.** The seed migration creates roles and
  permissions, but assigning the first Admin to an actual user is a manual,
  documented SQL step performed outside the API — deliberately avoiding an
  API endpoint that could itself become a privilege-escalation target.
- **Permissions are global, not org-scoped**, even looking ahead to Phase 3:
  the concept `document:delete` is universal; which role grants it varies
  per organization, but the catalog itself doesn't fork per tenant. This
  also prevents permission-string drift across future organizations.
- **Every RBAC test uses a uuid-suffixed name for anything it creates.**
  Seeded roles/permissions are reference data that intentionally survive the
  shared `test_session` truncate fixture (see `tests/conftest.py`), so a
  fixed test-created name would collide with itself on a second run. This
  exact idempotency bug was caught and fixed before the phase was committed.

## What This Phase Enables for Phase 2.2

A fully migrated, seeded schema that Phase 2.2's repository layer
(`RoleRepository`, `PermissionRepository`, `UserRoleRepository`) can query
directly — no further schema changes were needed for either Phase 2.2 or
Phase 2.3.
