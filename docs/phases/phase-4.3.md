# Phase 4.3 — Audit Log Service Integration

**Tag:** `phase-4.3-complete`
**Commit:** *(this phase's commit — see `git log docs/phases/phase-4.3.md`)*

## What This Phase Accomplished

Phase 4.3 wires all three existing services — `AuthService`,
`AuthorizationService`, `OrganizationService` — to actually write to the
audit log built in Phase 4.1/4.2. This is the first time `AuthService` has
been modified since Phase 1: every earlier phase's readiness docs
explicitly promised "zero modification required," and this phase is the
one place that promise was deliberately not kept, per the scoping decision
made before this phase began (full auth + RBAC/org coverage, over an
administrative-events-only alternative that would have left `AuthService`
untouched).

## Why It Was Needed

An audit log nobody writes to isn't an audit log. Phase 4.1/4.2 built a
complete, tested read/write surface with nothing calling it. This phase
makes the audit trail real: every register/login/refresh/logout outcome,
and every successful role/permission/organization mutation, now produces a
queryable row.

## Files Created

- `app/domain/audit_actions.py` — canonical action-name string constants
  (e.g. `USER_LOGIN_FAILED = "user.login_failed"`), shared by all three
  services so no service hand-types its own literal and risks a typo
  silently creating an orphaned, never-queried action name.
- `tests/integration/test_audit_logging_integration.py` — 10 end-to-end
  tests proving a real HTTP request produces a real, queryable
  `audit_logs` row through the entire stack (route → service →
  repository → Postgres) — not just that a mock was called correctly (the
  unit tests already prove that half).
- `docs/phases/phase-4.3.md` — this document.

## Files Modified

- **`app/domain/services/auth_service.py`** — every workflow now records
  its outcome:
  - `register()`: success (`user.registered`) and duplicate-email failure
    (`user.registration_failed`, with `attempted_email`/`reason` in
    `event_metadata`).
  - `login()`: success (`user.login_succeeded`) and all three failure
    reasons (`user.login_failed` with `reason` = `unknown_email` /
    `wrong_password` / `inactive_account`).
  - `refresh()`: success (`refresh_token.rotated`) and all four rejection
    reasons (`refresh_token.rejected` with `reason` = `unknown_token` /
    `revoked_token` / `expired_token` / `inactive_or_deleted_owner`).
  - `logout()`: only an actual revocation (`user.logout`) — a no-op call
    against an unknown/already-revoked token is not recorded.
  - Critically: the *external* exceptions these failures raise still
    collapse multiple causes into one indistinguishable message (see
    `app/domain/exceptions.py`) — the audit log is internal-only, never
    returned in an API response, so it's free to record the real reason.
- **`app/domain/services/authorization_service.py`** — `create_role`,
  `assign_role`, `revoke_role`, `assign_permission_to_role`, and
  `remove_permission_from_role` each gained a required, keyword-only
  `actor_user_id` and now record an event on success. `authorize()` and
  `get_user_permissions()` are unchanged and are never audited (see
  Decisions below).
- **`app/domain/services/organization_service.py`** — `create_organization`,
  `add_member`, and `remove_member` gained the same `actor_user_id`
  requirement and success-only recording. `list_members()` and
  `list_organizations_for_user()` are unchanged and never audited.
- **`app/core/dependencies.py`** — all three `get_*_service()` functions
  now construct and inject an `AuditLogRepository`.
- **`app/api/v1/authorize.py`, `app/api/v1/organizations.py`** — every
  mutating route's previously-discarded `_: User = Depends(require_permission(...))`
  became `admin: User = Depends(require_permission(...))`, and its
  service call now passes `actor_user_id=admin.id`. Every read-only route
  (`/v1/authorize`, `/v1/users/me/permissions`, `/v1/users/{id}/permissions`,
  `list_organization_members`, `/v1/users/me/organizations`) is
  unchanged.
- **`tests/unit/test_auth_service.py`, `test_authorization_service.py`,
  `test_organization_service.py`** — fixtures updated for the new
  constructor shapes (the injected `AsyncMock` audit repository is
  deliberately *not* part of each fixture's returned tuple, so no existing
  test's destructuring line needed to change — new tests reach it via
  `svc.audit_log_repository`); every call site of a now-`actor_user_id`-
  requiring method updated; and dozens of new tests asserting the exact
  audit event (action, actor, target, metadata) for each success path, the
  *absence* of any audit call for every failure/no-op path in
  `AuthorizationService`/`OrganizationService`, and the internal-vs-external
  reason-distinction guarantee for `AuthService`'s login/refresh failures.
- **`tests/integration/test_dependency_wiring.py`** — extended every
  existing wiring test to also assert on `audit_log_repository`.

## Tests Added

- **13 tests** in `test_auth_service.py`: one audit-event assertion per
  success/failure path across `register`/`login`/`refresh`/`logout`
  (11 distinct outcomes), plus a dedicated test confirming `logout()`'s
  no-op path records nothing.
- **12 tests** in `test_authorization_service.py`: one audit-event
  assertion per successful mutation (`create_role`, `assign_role`,
  `assign_permission_to_role`), one no-audit-on-failure assertion per
  fallible mutation, one no-audit-on-no-op assertion for `revoke_role`/
  `remove_permission_from_role`, and two tests confirming `authorize()`/
  `get_user_permissions()` are never audited at all.
- **8 tests** in `test_organization_service.py`: the equivalent coverage
  for `create_organization`/`add_member`/`remove_member`, plus
  never-audited confirmations for both list methods.
- **10 end-to-end tests** in `test_audit_logging_integration.py`: register
  (success and duplicate-email failure), login (success and wrong-password
  failure), logout, refresh, role creation, role assignment, organization
  creation, and organization membership — each verified by querying the
  real `audit_logs` table after a real HTTP call, not by inspecting a mock.

Full suite after this phase: **356 tests collected, 355 passing** (313
from Phase 1–4.2 + 43 new). The one non-passing test is the same
pre-existing environment limitation carried since Phase 2.3, unchanged by
this phase — no schema change occurred, so `alembic check` continues to
report zero drift.

## Important Architectural / Security Decisions

- **`AuthService` is modified for the first time since Phase 1** — the
  central, deliberate decision this phase's scoping question resolved.
  Every prior phase's readiness documentation promised this module would
  need zero changes; that promise was explicitly and knowingly broken
  here, in exchange for the single most valuable audit signal an IAM
  system can record: who attempted to authenticate, and whether it
  succeeded.
- **`AuthService`'s audit trail records more than its exceptions ever
  reveal, and that asymmetry is the whole point.** `InvalidCredentialsError`
  still can't be told apart for "unknown email" vs. "wrong password" by
  anything outside this codebase — but the audit log, which is never
  returned in an HTTP response, distinguishes them via `event_metadata`.
  This is a deliberately different, more permissive information-disclosure
  policy for an internal-only, `audit:view`-gated (Phase 4.4) surface than
  for the public API — not a weakening of the enumeration defense, since
  nothing about the public response changed.
- **`AuthorizationService`/`OrganizationService` audit successes only,
  never failures or no-ops.** Every caller of these methods has already
  passed `require_permission()` — a rejected `RoleNotFoundError` or a
  duplicate-name `409` here is an already-authorized admin's benign
  mistake, not a probing signal the way a failed login is. Auditing every
  validation failure here would add substantial log volume with no
  corresponding security value. This is the opposite policy from
  `AuthService`, and the difference is deliberate, not an oversight — both
  are explained in each service's own module docstring.
- **`authorize()` and every list/read method are never audited, in any
  service.** These are the highest-frequency calls in the whole system;
  auditing them would dwarf every other event combined for essentially no
  forensic value, since `authorize()`'s own no-caching design (Phase 2.3)
  already guarantees real-time correctness without needing a paper trail
  of every single permission check.
- **`actor_user_id` is required, not optional, on every RBAC/org mutation.**
  Every call site in this codebase already has a real authenticated admin
  by the time it reaches these methods (`require_permission()` guarantees
  it) — making the parameter optional would only invite a future caller to
  silently skip attribution, which defeats the purpose of an audit trail
  entirely.

## What This Phase Enables for Phase 4.4

Every auditable event in the system is now actually being recorded.
Phase 4.4 exposes `AuditLogRepository.list_events()`/`count_events()`
(Phase 4.2) over HTTP, gated by a new `audit:view` permission, completing
Phase 4 end-to-end: schema (4.1) → repository (4.2) → service integration
(4.3) → API (4.4) — the same four-layer shape Phase 2 and Phase 3 both
used.
