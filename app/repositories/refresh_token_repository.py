"""
RefreshTokenRepository -- the only module that queries the `refresh_tokens`
table directly.

Contains no token generation or hashing logic (that's app.core.security) and
no decision-making about *when* a token should be rotated or rejected --
those are AuthService's business decisions. This module only persists and
retrieves rows, and provides one transaction-safe helper for the mechanical
part of rotation.
"""

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time import utc_now
from app.domain.models import RefreshToken


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

    async def revoke(self, token: RefreshToken) -> RefreshToken:
        """Sets revoked_at on a single token.

        Phase 1 scope only: this does not walk the replaced_by chain to
        revoke a whole token family. Reuse-detection (revoking descendants
        when an already-revoked token is presented again) is Phase 7 scope.
        """
        token.revoked_at = utc_now()
        await self.session.commit()
        await self.session.refresh(token)
        return token

    async def create_rotation_pair(
        self, old_token: RefreshToken, new_token_hash: str, new_expires_at: datetime
    ) -> RefreshToken:
        """Performs a full rotation as a single transaction:
          1. Revoke old_token
          2. Create the replacement token
          3. Link old_token.replaced_by -> new_token.id

        All of this happens before a single commit -- there is no
        intermediate state where the old token is revoked but the new one
        doesn't exist yet, or vice versa.
        """
        old_token.revoked_at = utc_now()

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
        old_token.replaced_by = new_token.id

        await self.session.commit()
        await self.session.refresh(new_token)
        await self.session.refresh(old_token)
        return new_token
