# Phase 4.4 — Audit Log API

**Tag:** `phase-4.4-complete`
**Commit:** *(this phase's commit — see `git log docs/phases/phase-4.4.md`)*

## What This Phase Accomplished

Phase 4.4 exposes `AuditLogRepository.list_events()`/`count_events()`
(Phase 4.2) over HTTP via a new `AuditLogService` and `GET /v1/audit-logs`,
gated by a new `audit:view` permission. This completes Phase 4 end-to-end:
schema (4.1) → repository (4.2) → service integration/audit-writing (4.3)
→ query API (4.4) — the same four-layer shape Phase 2 and Phase 3 both
used.

## Why It Was Needed

Phase 4.3 made every auditable event in the system actually get recorded,
but nothing in the running application could read any of it back short of
a direct database query. This phase is the last piece needed to make the
audit trail usable end-to-end through the real API, by an Admin, over
HTTP.

## Files Created

- `app/db/migrations/versions/cbf5b83aa3f8_seed_audit_view_permission.py`
  — seeds one new permission, `audit:view`, granted to the existing seeded
  Admin role only. Same extensibility case as Phase 3.4's
  `organization:manage` migration: one new permission, one new mapping,
  nothing else touched.
- `app/domain/schemas/audit_log.py` — `AuditLogEntryResponse` /
  `AuditLogPageResponse`, the service-layer return types.
- `app/domain/services/audit_log_service.py` — `AuditLogService`, wrapping
  `AuditLogRepository.list_events()`/`count_events()` into a single
  `list_events()` call that returns one `AuditLogPageResponse`. Read-only:
  no method ever calls `audit_log_repository.record()`.
- `app/api/v1/schemas/audit_log.py` — HTTP-facing response types, kept
  separate from `app.domain.schemas.audit_log`, same convention as every
  other resource's API/domain schema split.
- `app/api/v1/audit.py` — `GET /v1/audit-logs` (requires `audit:view`) →
  200 with a page of events; accepts optional `organization_id`,
  `actor_user_id`, `action` filters and `limit`/`offset` pagination
  (`limit` bounded to `[1, 200]`, `offset` to `>= 0`, both enforced by
  FastAPI's own query-parameter validation).
- `tests/unit/test_audit_log_service.py` — 7 tests against mocked
  `AuditLogRepository`.
- `tests/integration/test_audit_log_api.py` — 9 tests against real
  Postgres, real FastAPI, real HTTP calls.
- `docs/phases/phase-4.4.md` — this document.

## Files Modified

- `app/core/dependencies.py` — added `get_audit_log_service()`, same DI
  shape as `get_auth_service()`/`get_authorization_service()`/
  `get_organization_service()`, just wired to a single repository.
- `app/main.py` — registered the new router; bumped version to `0.4.0` and
  description to mention Phase 4.
- `tests/integration/test_rbac_models.py` — the Admin all-permissions test
  now includes `audit:view`; added a dedicated test confirming that
  permission is granted to Admin only.
- `tests/integration/test_fresh_database_migration.py` — permission/mapping
  counts updated from 6/13 to 7/14 to reflect the new seed migration.
- `tests/unit/test_app_startup.py` — +2 tests for the new route's wiring
  and allowed methods.
- `tests/integration/test_dependency_wiring.py` — +2 tests for
  `get_audit_log_service()`.

## Tests Added

- **7 tests** in `test_audit_log_service.py`: wraps repository rows into
  `AuditLogEntryResponse`; empty page when nothing matches; `total`
  reflects the full `count_events()` result independent of page size;
  every filter (`organization_id`, `actor_user_id`, `action`, `limit`,
  `offset`) is passed through unchanged to the repository; defaults to no
  filters and `limit=50`; never calls `record()`; preserves the
  repository's most-recent-first ordering without re-sorting.
- **9 tests** in `test_audit_log_api.py`: requires `audit:view` (403
  without it, 401 unauthenticated); succeeds for Admin with the expected
  page shape; returns events written by both `AuthService` (login) and
  `OrganizationService` (organization creation) — proving the Phase 4.3
  write path and this read path share the same table; `action` filter
  excludes non-matching events; `limit` truncates the page while `total`
  still reflects the full matching count; `limit`/`offset` out-of-range
  values are rejected with `422`.
- **2 tests** modified + **1 test** added in `test_rbac_models.py` for the
  new seeded permission's exact grant shape.
- **2 tests** added to `test_app_startup.py`, **2 tests** added to
  `test_dependency_wiring.py` for route/DI wiring.

Full suite after this phase: **377 tests collected, 376 passing** (356
before this phase's work + 21 new/updated). The one non-passing test
(`test_migrations_apply_cleanly_to_a_fresh_empty_database`) is the same
pre-existing environment limitation carried since Phase 2.3, unchanged by
this phase — it hardcodes port `5432` (the dev `docker-compose.yml`
Postgres), which isn't running in this environment (only the
`docker-compose.test.yml` instance on `5433` is). Its updated assertions
(7 permissions, 14 mappings on a fresh install) were independently
verified against the available `5433` test database, the same way Phase
3.4 verified its own fresh-install assertions.

## Important Architectural / Security Decisions

- **`AuditLogService` performs no permission check of its own — enforcement
  is entirely `require_permission("audit", "view")` at the API layer**,
  identical to how `organization:manage` gates `OrganizationService`'s
  mutating routes and `role:manage`/`user:manage` gate
  `AuthorizationService`'s. Every service in this codebase already keeps
  HTTP concerns (and FastAPI/`HTTPException` imports) out of the service
  layer; this phase doesn't introduce an exception to that rule just
  because the resource being gated is itself the audit log.
- **Reading the audit log is never itself audited.** Matches
  `AuthorizationService.authorize()`/`get_user_permissions()` and
  `OrganizationService.list_members()`/`list_organizations_for_user()` —
  the codebase's other pure reads, none of which write an audit event.
  Recording "an admin viewed the audit log" would add volume with no
  forensic value beyond what `audit:view` already gates; the interesting
  security question (did an unauthorized caller *try* to view it) is
  already answered by the `403` itself, which — like every other rejected,
  already-authenticated request in this codebase — is not audited (see
  `AuthorizationService`'s Phase 4.3 docstring for the full "successes
  only, never failures" reasoning this follows).
- **`limit`/`offset` validation lives at the API layer (FastAPI
  `Query(ge=..., le=...)`), not in `AuditLogService` or
  `AuditLogRepository`.** Consistent with this codebase's existing
  division of responsibility: HTTP-shaped input validation (malformed
  UUIDs, missing required fields, now out-of-range pagination) is always
  handled by FastAPI/Pydantic at the boundary, never reimplemented deeper
  in the stack. `limit` is capped at 200 specifically to bound the cost of
  a single request against a table that, being append-only, only grows.
- **No single-event lookup route (`GET /v1/audit-logs/{id}`) was added.**
  Nothing in this codebase currently needs to fetch one audit event by id
  in isolation — every real use case is "show me recent events matching
  these filters" — so this phase doesn't speculatively add unused surface
  area, the same restraint Phase 2.4 documented for not exposing every
  conceivable `/v1/authorize`-adjacent query.
- **The new seed migration is deliberately minimal and additive**, exactly
  matching Phase 3.4's `organization:manage` migration: one permission,
  one role mapping, nothing else touched. The two pre-existing tests that
  assert an *exact* permission set for Admin needed their now-familiar
  update as a direct, expected consequence, not a regression.
- **`AuthService`/`AuthorizationService`/`OrganizationService` (the Phase
  4.3 audit-writing services) were not modified in this phase.** This
  phase is purely additive on the read side; no defect was found in the
  Phase 4.3 write path that would have required changing it.

## What This Phase Enables

Phase 4 is now fully wired end-to-end: schema (4.1) → repository (4.2) →
service integration (4.3) → API (4.4), the same shape Phase 2 and Phase 3
each completed for their own domains. Every auditable event recorded since
Phase 4.3 is queryable over real HTTP by an Admin, with the same
deny-by-default authorization guarantee every other privileged endpoint in
this codebase already has. A future phase needing forensic tooling (e.g.
exporting a date-range of events, or a UI dashboard) can build directly on
`GET /v1/audit-logs` without further changes to the authorization surface.
