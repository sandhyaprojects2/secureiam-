"""
RefreshTokenRepository -- the only module that queries the `refresh_tokens`
table directly.

Contains no token generation or hashing logic (that's app.core.security) and
no decision-making about *when* a token should be rotated or rejected --
those are AuthService's business decisions. This module only persists and
retrieves rows, and provides transaction-safe helpers for the mechanical
parts of rotation and reuse-driven family revocation.

Phase 5: create_rotation_pair() and revoke_descendants() both use an atomic
conditional UPDATE (`WHERE id = :id AND revoked_at IS NULL`), never an
unconditional ORM attribute assignment, for any write that revokes a token.
This is the fix for a real, previously-unguarded lost-update race: two
concurrent callers both reading the same not-yet-revoked row and both then
issuing an unconditional UPDATE would previously both succeed, producing
two live children from one parent. Guarding every revocation with this
WHERE clause makes Postgres itself the single point of truth for "did I
win" -- exactly one concurrent caller's UPDATE can ever affect the row,
and every other caller's affects zero rows, which is how each method below
reports "I lost" without raising or requiring any explicit locking
(SELECT ... FOR UPDATE was considered and rejected -- see
docs/phases/phase-5.md for the full tradeoff analysis specific to this
codebase's async, session-per-request architecture).
"""

import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time import utc_now
from app.domain.models import RefreshToken

# Defensive bound on RefreshTokenRepository.revoke_descendants()'s
# walk-and-retry loop (see its docstring). Real chains never need
# anywhere close to this many hops to converge -- this exists purely so a
# pathological/adversarial sequence of concurrent legitimate rotations
# can never make the loop unbounded.
_MAX_FAMILY_WALK_STEPS = 25


class RefreshTokenRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self, user_id: uuid.UUID, token_hash: str, expires_at: datetime
    ) -> RefreshToken:
        """Persists a new refresh token row."""
        token = RefreshToken(user_id=user_id, token_hash=token_hash, expires_at=expires_at)
        self.session.add(token)
        await self.session.commit()
        await self.session.refresh(token)
        return token

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        """Lookup by SHA-256 hash. Returns None if no match. Does not check
        expiry or revocation status here -- that evaluation is AuthService's
        job; this method only reports what exists."""
        result = await self.session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, token_id: uuid.UUID) -> RefreshToken | None:
        """Lookup by primary key. Returns None if no match. Used by
        revoke_descendants() to walk the replaced_by chain one hop at a
        time."""
        result = await self.session.execute(
            select(RefreshToken).where(RefreshToken.id == token_id)
        )
        return result.scalar_one_or_none()

    async def revoke(self, token: RefreshToken) -> RefreshToken:
        """Sets revoked_at on a single token, unconditionally.

        Used only by AuthService.logout() -- a direct, single-user-initiated
        revocation of a token the caller has just proven possession of by
        presenting it, not a contested concurrent write, so no conditional
        guard is needed here the way create_rotation_pair()/
        revoke_descendants() need one. Deliberately does not set
        replaced_by -- that's what distinguishes a logout-revoked token from
        a rotation-revoked one (see AuthService.refresh()'s reuse-detection
        branch, which keys off exactly this distinction).

        Phase 5 scope note: still does not walk the replaced_by chain --
        logout only ever revokes the exact token presented, never a family.
        There is nothing to walk: a token reaching this method has, by
        definition, no replaced_by yet (see this method's docstring above),
        so it cannot be mid-chain.
        """
        token.revoked_at = utc_now()
        await self.session.commit()
        await self.session.refresh(token)
        return token

    async def create_rotation_pair(
        self, old_token: RefreshToken, new_token_hash: str, new_expires_at: datetime
    ) -> RefreshToken | None:
        """Performs a full rotation as a single transaction:
          1. Atomically revoke old_token -- ONLY if it is not already revoked.
          2. If (and only if) that succeeded: create the replacement token,
             link old_token.replaced_by -> new_token.id, commit.

        Returns the new token, or None if old_token was already revoked by
        the time this ran (a concurrent caller -- another rotation of the
        same token, or a concurrent reuse-detection family revocation --
        won the race). When None is returned, no new token is created and
        nothing is committed: the new-token INSERT is only ever reached
        after the conditional UPDATE has confirmed exactly one row was
        affected, so a failed conditional update can never accidentally
        produce an orphaned child token.

        Step 1 uses `UPDATE ... WHERE id = :id AND revoked_at IS NULL`
        (Core, not ORM attribute assignment) specifically so Postgres
        resolves "did I win" atomically, in one statement -- see this
        module's docstring for why this is used instead of
        SELECT ... FOR UPDATE. Because this guard makes at most one caller
        ever succeed in revoking a given row, and replaced_by is only ever
        set once, immediately after that same caller's own successful
        revoke, a token can never end up with two children: the
        replaced_by chain stays strictly linear by construction, not by
        convention.
        """
        result = await self.session.execute(
            update(RefreshToken)
            .where(RefreshToken.id == old_token.id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=utc_now())
        )
        if result.rowcount == 0:
            return None

        new_token = RefreshToken(
            user_id=old_token.user_id,
            token_hash=new_token_hash,
            expires_at=new_expires_at,
        )
        self.session.add(new_token)

        # flush (not commit) to obtain new_token.id within the same
        # transaction, so replaced_by can be set before anything is
        # persisted durably.
        await self.session.flush()

        await self.session.execute(
            update(RefreshToken)
            .where(RefreshToken.id == old_token.id)
            .values(replaced_by=new_token.id)
        )

        await self.session.commit()
        await self.session.refresh(new_token)
        await self.session.refresh(old_token)
        return new_token

    async def revoke_descendants(self, token: RefreshToken) -> RefreshToken | None:
        """Reuse-detection's family-revocation step (Phase 5).

        Called by AuthService.refresh() when `token` has just been found to
        be revoked *with a successor* (token.replaced_by is not None) --
        i.e. it was superseded by a legitimate rotation and is now being
        presented again. Walks forward through the replaced_by chain to
        find the family's current active leaf (the node whose replaced_by
        is still None) and atomically revokes it.

        Returns the token that was actually revoked, or None if there was
        nothing left to revoke -- either because a second (or later) reuse
        attempt is hitting an already-fully-revoked family, or because the
        leaf was independently revoked by an ordinary logout in the
        meantime. Both are legitimate, expected outcomes, not error cases.

        Every node strictly between `token` and the leaf is already revoked
        by construction (create_rotation_pair() only ever sets replaced_by
        immediately after that same row's own successful revocation) -- so
        this never needs to revoke anything except, at most, the one
        current leaf. It also never touches any row outside this exact
        chain: the walk only ever follows a replaced_by value that was
        itself only ever set by a rotation of the node pointing to it, so
        there is no path by which an unrelated token (a different user's,
        or a different family's) could ever be reached or revoked here.

        Races against a concurrent, legitimate rotation of the same leaf:
        the leaf-revocation attempt uses the identical atomic conditional
        UPDATE as create_rotation_pair(). If a legitimate rotation wins
        that race, this method re-reads the node, follows its
        newly-populated replaced_by, and retries against the new leaf --
        bounded by _MAX_FAMILY_WALK_STEPS so this can never loop
        unboundedly, no matter how many legitimate rotations race it.
        """
        next_id = token.replaced_by
        if next_id is None:
            return None

        for _ in range(_MAX_FAMILY_WALK_STEPS):
            candidate = await self.get_by_id(next_id)
            if candidate is None:
                # Nothing in this codebase deletes an individual
                # refresh_token row (only cascading user deletion removes
                # them, and that removes the whole family together) -- this
                # branch is unreachable in practice, handled defensively
                # rather than raising.
                return None

            if candidate.replaced_by is not None:
                # Not the leaf -- already revoked by construction (it was
                # superseded by whatever it points to). Keep walking
                # without attempting to revoke it again.
                next_id = candidate.replaced_by
                continue

            # candidate has no successor: it's the current leaf as far as
            # we've observed. Attempt to revoke it atomically.
            result = await self.session.execute(
                update(RefreshToken)
                .where(RefreshToken.id == candidate.id, RefreshToken.revoked_at.is_(None))
                .values(revoked_at=utc_now())
            )
            if result.rowcount == 0:
                # Lost the race on this specific node. Re-read it to see
                # why: either (a) a legitimate rotation just gave it a
                # successor -- follow that and retry against the new leaf
                # -- or (b) it was independently revoked without a
                # successor (e.g. an ordinary logout reached it first),
                # meaning the family is already fully dead and there is
                # nothing left for us to do.
                refreshed = await self.get_by_id(candidate.id)
                if refreshed is None or refreshed.replaced_by is None:
                    return None
                next_id = refreshed.replaced_by
                continue

            await self.session.commit()
            await self.session.refresh(candidate)
            return candidate

        # Defensive bound exceeded: give up cleanly. Reaching this would
        # require this many concurrent legitimate rotations racing this
        # one call in sequence, far beyond any real client behavior.
        return None
