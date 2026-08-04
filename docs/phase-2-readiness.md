# SecureIAM — Phase 2 Readiness Review

Phase 1 proves **identity** — who is this? Phase 2 (RBAC + Authorization)
decides **permissions** — can they do this? This document confirms Phase 1
provides everything Phase 2 needs without requiring any changes to what's
already built.

---

## `get_current_user`: Verified Ready

**Location:** `app/core/dependencies.py`

**JWT extraction:** confirmed working — extracts the token from an
`Authorization: Bearer <token>` header, rejecting a missing header or a
non-`Bearer` scheme before ever attempting to decode.

**User resolution:** confirmed working — decodes the token via
`decode_access_token()`, parses the `sub` claim as a UUID, and resolves it
to a real `User` via `UserRepository.get_by_id()`.

**Generic authentication failures:** confirmed — every distinct rejection
reason (missing header, malformed scheme, tampered signature, expired
token, wrong issuer, unknown user id) raises the exact same
`HTTPException(401, "Could not validate credentials.")`. This was tested
directly: `test_all_rejection_reasons_produce_identical_response` collects
the `(status_code, detail)` tuple from four different failure modes and
asserts they're all byte-for-byte identical.

**Test coverage:** 7 integration tests
(`tests/integration/test_get_current_user.py`), run against a real
database and real issued tokens — not mocked.

**Not yet wired to any route.** This is intentional — there is nothing in
Phase 1 that needs protecting behind authentication beyond registration and
login themselves (which must remain open). Phase 2's `/authorize` endpoint,
and every subsequent protected route, will add
`user: User = Depends(get_current_user)` to its signature. No changes to
this dependency itself should be required.

---

## Future `POST /v1/authorize` — Confirmed Buildable Without Changes To:

**JWT format:** the access token's claim set (`sub`, `type`, `iat`, `exp`,
`jti`, `iss`) already contains everything an authorization check needs to
identify the calling user. No new claims (e.g. `org_id`, `roles`) are
required to build a first version of `/authorize` — role/permission lookups
can be a database query keyed on the user id already available via
`get_current_user`, exactly the pattern Phase 0's architecture spec
described.

**AuthService:** Phase 2's authorization logic belongs in a new
`AuthorizationService`, not inside `AuthService`. `AuthService` owns
authentication workflows (register/login/refresh/logout) only; it should
require zero modification to support Phase 2 — a new service, new
repositories (`RoleRepository`, `PermissionRepository`), and a new API
module (`app/api/v1/authorize.py`) can be added alongside it without
touching a single line of `auth_service.py`.

**Repositories:** `UserRepository` and `RefreshTokenRepository` need no
changes. Phase 2 introduces new repositories for roles, permissions, and
their associations — additive, not modifying, the existing repository
layer.

---

## What Phase 2 Will Need to Add (Not Change)

For completeness, since "no changes required" is only meaningful alongside
what *is* required:

- New tables: `roles`, `permissions`, `role_permissions`, `user_roles` (per
  the Phase 0 schema design)
- New repositories: `RoleRepository`, `PermissionRepository` (or a combined
  `RBACRepository`, depending on how Phase 2's own planning session
  resolves that)
- A new `AuthorizationService` implementing the RBAC evaluation algorithm
  from the Phase 0 spec (deny-by-default, permission-based rather than
  role-name-based checks)
- A new `POST /v1/authorize` route, protected by `get_current_user` for any
  endpoint that itself needs to know who's asking

None of this requires touching `app/domain/services/auth_service.py`,
`app/repositories/user_repository.py`,
`app/repositories/refresh_token_repository.py`, or the JWT claim structure
in `app/core/security.py`.

---

## Known Limitations Carried Into Phase 2 (Not Blocking, But Worth Tracking)

- **`InactiveUserError`** leaks account-existence information for
  deactivated accounts during login (see `docs/security-review.md` for
  detail). Not a Phase 2 blocker, but worth revisiting if the threat model
  tightens.
- **Refresh rotation lacks row-level locking or optimistic concurrency
  control.** A repeated sanity check suggests this doesn't cause observable
  double-rotation in this environment, but it isn't a proven guarantee
  under true multi-worker concurrency. Recommended as part of Phase 7
  hardening, alongside reuse detection (both touch `create_rotation_pair`).
- **`get_current_user` does not check `user.is_active`.** A deactivated
  user's still-valid (≤15 minute) access token continues to resolve
  successfully until natural expiry. Reasonable for Phase 1's scope, but
  worth an explicit decision in Phase 2 about whether authorization checks
  should also re-verify account status.

None of these limitations require rearchitecting anything already built —
each is a scoped, additive fix.
