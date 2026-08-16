# Phase 4.2 — Audit Log Repository

**Tag:** `phase-4.2-complete`
**Commit:** *(this phase's commit — see `git log docs/phases/phase-4.2.md`)*

## What This Phase Accomplished

Phase 4.2 adds `AuditLogRepository`: `record()` for writing an event, and
`list_events()`/`count_events()` for reading them back with optional
filtering and pagination. Still no service-layer wiring — this phase
answers "what does the database say," exactly matching the discipline
every earlier repository phase (2.2, 3.2) established.

## Why It Was Needed

Phase 4.3 needs a write path the three existing services can call at the
moment of every auditable action, and Phase 4.4 needs a read path for the
query API — both need to exist and be proven correct against real Postgres
before any service or route depends on them.

## Files Created

- `app/repositories/audit_log_repository.py` — `record()`, `list_events()`,
  `count_events()`.
- `tests/integration/test_audit_log_repository.py` — 11 tests against real
  Postgres.
- `docs/phases/phase-4.2.md` — this document.

## Tests Added

11 integration tests: `record()` with minimal and full fields;
`list_events()` ordering (most recent first), each of its three filters
(`organization_id`, `actor_user_id`, `action`) in isolation, `limit`/`offset`
pagination producing disjoint pages, and an empty result for no matches;
`count_events()` matching `list_events()`'s filters and explicitly ignoring
pagination (it has no `limit`/`offset` parameters at all, by design); and a
hygiene test confirming no update/delete method exists on the repository,
mirroring `PermissionRepository`'s established "no `create_permission`
method exists here on purpose" convention in reverse.

Full suite after this phase: **313 tests collected, 312 passing** (302
from Phase 1–4.1 + 11 new). The one non-passing test is the same
pre-existing environment limitation carried since Phase 2.3, unchanged.

## Important Architectural / Security Decisions

- **No `DuplicateXError` translation, unlike every other repository's
  write method in this codebase.** `audit_logs` has no unique constraint —
  it's a pure append-only log, and every `record()` call is expected to
  succeed. This is the first repository write method in the whole
  codebase with no failure mode to translate at all.
- **`count_events()` exists as its own method rather than callers using
  `len(list_events(...))`.** A caller wanting a total-count-for-pagination
  (Phase 4.4's query API) would otherwise need to fetch every matching row
  just to count them, or reissue `list_events()` with an unbounded limit —
  `count_events()` runs a single `SELECT count(*)`, never materializing
  full rows, matching the efficiency discipline `UserRoleRepository.
  get_permissions_for_user()` established back in Phase 2.2 (one indexed
  query doing exactly the work needed, not more).
- **All three filters are additive (`AND`), never `OR`, and all three are
  optional.** Omitting every filter returns the most recent events
  system-wide — a deliberately permissive default for `list_events()`
  itself, since restricting *who* is allowed to call it with no filters is
  an authorization concern for Phase 4.4's API layer, not this repository.

## What This Phase Enables for Phase 4.3

A complete, tested read/write surface that `AuthService`,
`AuthorizationService`, and `OrganizationService` can each depend on
directly to record their own auditable events — no further repository
methods are anticipated for the remainder of Phase 4.
