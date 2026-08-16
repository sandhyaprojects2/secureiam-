# Phase 5 — Refresh Token Reuse Detection & Concurrency-Safe Rotation

**Tag:** `phase-5-complete`
**Commit:** *(this phase's commit — see `git log docs/phases/phase-5.md`)*

## What This Phase Accomplished

Phase 5 closes the single most-cited residual gap in this project's own
security review, present since Phase 1: refresh-token rotation had no
guard against a genuine concurrent lost-update race, and reused
(already-rotated-away) refresh tokens were rejected but never triggered
any defensive response. Both are fixed now, entirely inside
`RefreshTokenRepository`/`AuthService.refresh()` — no schema change, no new
infrastructure, no change to any other authentication behavior.

This work was originally referred to throughout the codebase as "Phase 7"
scope; it's implemented here as Phase 5, immediately following Phase 4
(Audit Logging), per an explicit design review and approval process (see
"Design Review" below) rather than being picked up automatically.

## Why It Was Needed

`docs/security-review.md` had, since Phase 1, explicitly flagged two open
items on the exact same code path (`RefreshTokenRepository.
create_rotation_pair`): no reuse detection, and no proof — only a
"sanity check" — that concurrent rotation of the same token couldn't
double-succeed. The second of these stopped being hypothetical during this
project's Phase 4.4 checkpoint closure: a real, reproducible flake
(`test_concurrent_refresh_with_same_token_only_one_succeeds` failing with
`assert 2 == 1`) was observed live in GitHub Actions CI, converting a
documented theoretical gap into demonstrated, current behavior that needed
closing before any further phase.

## Design Review

Before any code was written, a detailed design review traced the existing
refresh flow end-to-end, identified the exact mechanism of the race (not
just its symptom), evaluated atomic conditional `UPDATE` against
`SELECT ... FOR UPDATE` specifically against this codebase's async,
session-per-request architecture (not a generic preference), and designed
the reuse-detection/family-revocation algorithm and its audit events before
implementation began. That review was approved with four explicit
decisions, all honored as designed:

1. Atomic conditional `UPDATE ... WHERE revoked_at IS NULL`, not
   `SELECT ... FOR UPDATE`.
2. `create_rotation_pair()` returns `RefreshToken | None` (`None` = lost
   the race).
3. `replaced_by IS NOT NULL` vs. `IS NULL` distinguishes rotation-revoked
   (reuse) from logout-revoked (not reuse) tokens — no new column.
4. The pre-existing sequential-rotation test, which incidentally exercised
   what is now a real security response without ever asserting on it, was
   restructured rather than patched around.

A final pre-implementation consistency check (linearity of the
`replaced_by` chain, no possibility of revoking an unrelated token, a
bounded retry loop, no partially-committed rotation pairs, no orphaned
child token on a failed conditional update, and identical external
responses across every failure reason) found no issues before
implementation began.

## Files Modified

- **`app/repositories/refresh_token_repository.py`**:
  - `create_rotation_pair()` — the old token's revocation is now a single
    atomic `UPDATE refresh_tokens SET revoked_at = now() WHERE id = :id
    AND revoked_at IS NULL` (SQLAlchemy Core, not ORM attribute
    assignment), checked via `result.rowcount`. If it affected zero rows,
    the method returns `None` immediately — the new token's `INSERT` is
    only ever reached after that check succeeds, so a lost race can never
    produce an orphaned child token.
  - New `get_by_id()` — simple lookup, used by the chain walk below.
  - New `revoke_descendants(token)` — reuse-detection's family-revocation
    step. Walks forward through `replaced_by` to the family's current
    active leaf, using the identical atomic conditional update to revoke
    it, with a bounded (`_MAX_FAMILY_WALK_STEPS = 25`) retry loop for the
    case where a concurrent, legitimate rotation extends the chain out
    from under the walk.
- **`app/domain/services/auth_service.py`**:
  - `refresh()` — a revoked token's handling is now delegated to a new
    `_handle_revoked_token()` helper, which branches on `replaced_by`
    (reuse vs. logout-revoked); the rotation call site now handles
    `create_rotation_pair()` returning `None` as its own distinct,
    identically-generic rejection.
  - New `_handle_revoked_token()` helper implementing the branch above.
  - Module and `refresh()` docstrings updated to describe the new
    behavior.
- **`app/domain/audit_actions.py`** — two new constants:
  `REFRESH_TOKEN_REUSE_DETECTED`, `REFRESH_TOKEN_FAMILY_REVOKED`.
- **`app/domain/exceptions.py`** — `InvalidRefreshTokenError`'s docstring
  extended to list the two new internal reasons it now also covers
  (reuse, concurrent rotation loss) — its actual behavior (one exception
  type, one message, for every reason) is unchanged.
- **`app/domain/models/refresh_token.py`** — `replaced_by`'s comment
  updated: no longer "Phase 7", now points at the Phase 5 implementation
  that uses it, and notes the column needed no migration to support this,
  exactly as it was added for in Phase 1.
- **`docs/security-review.md`** — the "Not yet implemented: reuse
  detection" and "Known concurrency limitation" paragraphs rewritten to
  describe what's now implemented and why, rather than annotated as still
  open.
- **`docs/phase-2-readiness.md`**, **`README.md`** — "Phase 7" references
  to this specific work updated to point at this phase.
- **`docs/PROJECT_STATUS.md`** — Refresh tokens flips from "PLANNED
  (hardening)" to fully "IMPLEMENTED"; roadmap and completed-phases
  sections updated.
- **Tests** (see below).

## Tests Added

- **8 unit tests** in `tests/unit/test_auth_service.py` (mocked
  repositories): a revoked token with a successor calls
  `revoke_descendants()`, not just rejects; the resulting exception is
  identical in type/message to every other rejection; a revoked token
  *without* a successor does **not** call `revoke_descendants()` at all;
  `reuse_detected` is recorded on every reuse presentation;
  `family_revoked` is recorded only when a leaf was actually still live;
  `family_revoked` is **not** recorded on a repeat attempt against an
  already-dead family; `create_rotation_pair()` returning `None` raises
  the same generic exception and records the new `concurrent_rotation_lost`
  reason.
- **5 integration tests** in `tests/integration/test_repositories.py`
  (real Postgres): two *sequential* (non-concurrent, fully deterministic)
  calls to `create_rotation_pair()` against the same token prove the
  second returns `None` and creates no orphaned child — the same
  guarantee the HTTP-level concurrent test proves, but with zero timing
  dependency; an already-revoked token (via plain `revoke()`) is
  correctly rejected by the same guard; `revoke_descendants()` finds and
  revokes the current leaf across a multi-hop chain, is idempotent on a
  second call, and is a safe no-op on a token with no successor.
- **4 integration tests** in `tests/integration/test_refresh_edge_cases.py`:
  reusing an old token partway through a chain revokes the chain's
  *current* leaf (not just the token presented); the minimal
  rotate-then-replay case is rejected and revokes its one successor; a
  second reuse attempt against an already-fully-revoked family still
  rejects cleanly; a logged-out (never-rotated) token replayed again
  triggers **no** reuse-detection audit events, confirmed directly against
  the audit log, not just the HTTP response.
- **1 integration test strengthened** in `tests/integration/test_auth_api.py`
  (`test_old_refresh_token_rejected_after_rotation`) — now also asserts
  the rotation's successor token is revoked as a consequence of the reuse
  it incidentally exercises, instead of leaving that side effect untested.
- **1 existing test restructured, not just patched**
  (`test_refresh_token_can_be_rotated_multiple_times_in_sequence`) — its
  premise (an old token in a chain can be safely replayed for a 401 check
  while the newest token keeps working) is no longer true once reuse
  detection exists; split into a pure happy-path chaining test plus a new,
  dedicated test locking in the new behavior instead of accidentally
  colliding with it.
- **1 existing test's docstring corrected**
  (`test_concurrent_refresh_with_same_token_only_one_succeeds`) — no
  longer described as a "sanity check, not a proof"; the underlying
  guarantee is now deterministic, and the docstring explains why.

Every other existing test touching revoked tokens (`test_refresh_revoked_
token_rejected`, `test_refresh_revoked_token_records_audit_event_with_
actor`, `test_refresh_failure_reasons_are_indistinguishable`,
`test_revoked_refresh_token_cannot_be_used_after_logout`) passes
**unmodified** — each constructs a logout-revoked (no-`replaced_by`)
token, exercising exactly the branch this phase deliberately left
unchanged.

Full suite after this phase: **394 tests collected, 394 passing** (377
before this phase's work + 17 new). Zero pre-existing failures — the one
test fixed during the Phase 4.4 checkpoint closure remains fixed.

## Important Architectural / Security Decisions

- **Atomic conditional `UPDATE`, not `SELECT ... FOR UPDATE`.** Chosen
  because it requires no restructuring of `AuthService.refresh()`'s
  existing two-call shape (validate via one repository call, mutate via a
  separate one), holds no lock across `await` points spanning unrelated
  I/O (a real cost specific to this codebase's async, session-per-request
  design), and matches the "re-verify current state at the moment that
  matters" principle Phase 2.2/2.3 already established for RBAC — the
  same idiom, applied to a write instead of a read. Full tradeoff analysis
  in the design-review discussion preceding this phase.
- **The `replaced_by` chain is provably linear, and family revocation
  provably never touches an unrelated token.** `create_rotation_pair()`
  is the only writer of `replaced_by`, and the atomic guard means at most
  one caller can ever win the revoke that precedes setting it — so no row
  can ever acquire two children. `revoke_descendants()` only ever follows
  `replaced_by` values that were themselves only ever set by rotating the
  node pointing to them, and every such rotation inherits the same
  `user_id` — so the walk can never leave the single chain it started in,
  let alone cross into another user's tokens.
  "Revoke the whole family" therefore reduces to "revoke the one current
  leaf, if it's still live" — every earlier node in the chain is already
  revoked by construction, not by an extra check.
- **Reuse detection is fail-closed against a concurrently-racing
  legitimate rotation.** If a reuse-detection walk and a real, in-flight
  legitimate refresh race for the same leaf, whichever loses is rejected —
  including the legitimate one. This is a deliberate, accepted tradeoff
  (once reuse is detected on a family, the safer default is to kill
  whatever's live rather than trust it), not an oversight.
- **Every new/changed code path still raises the exact same
  `InvalidRefreshTokenError`, with the exact same message, as every
  pre-existing rejection reason.** Reuse detection, concurrent-rotation
  loss, expiry, unknown tokens, and logout-revocation are all
  distinguishable internally (via `event_metadata`/action name) but never
  externally — preserving the enumeration-prevention guarantee this
  method has had since Phase 1, now covering two new internal reasons
  without adding any new externally-observable behavior.
- **No schema change.** `replaced_by IS NOT NULL`/`IS NULL` already fully
  encoded "rotation-revoked vs. logout-revoked" — exactly what Phase 1's
  own docstring said this column was added for. A dedicated
  `revocation_reason` column was considered and explicitly rejected as
  redundant with information the schema already carries.
- **The retry loop in `revoke_descendants()` is bounded
  (`_MAX_FAMILY_WALK_STEPS = 25`), not unbounded**, as a defensive measure
  against a pathological sequence of concurrent legitimate rotations
  racing the same walk — not because such a sequence is expected, but
  because a security-critical loop should never be able to spin forever
  even in a scenario this unlikely.

## What This Phase Enables

The refresh-token rotation path is now hardened exactly as
`docs/security-review.md` had been recommending since Phase 1, with a
deterministic proof rather than a documented caveat. Combined with
Phase 4's audit log, a stolen-refresh-token replay is now both *detected*
and *recorded* in a queryable, `audit:view`-gated form
(`GET /v1/audit-logs?action=refresh_token.family_revoked`). No other
future phase's design depends on this one; it was undertaken specifically
because it was the highest-value, lowest-risk hardening available given
the project's actual current state, not because a later phase requires it.
