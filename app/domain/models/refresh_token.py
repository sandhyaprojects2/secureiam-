"""
RefreshToken model — persists the rotation chain for refresh tokens.

Only the SHA-256 hash of a refresh token is ever stored (see
app.core.security.hash_refresh_token) — the raw token is returned to the
client exactly once, at issuance, and never persisted.
"""

import uuid

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    issued_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[object | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Self-referential FK forming the rotation chain. Not used for
    # reuse-detection logic until Phase 5 (see RefreshTokenRepository.
    # revoke_descendants()) -- this column was added in Phase 1 specifically
    # so that logic could be built later with no migration needed, which is
    # exactly what happened: Phase 5 required zero schema changes.
    replaced_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("refresh_tokens.id"),
        nullable=True,
    )

    def __repr__(self) -> str:
        # Deliberately excludes token_hash from the repr as a defense-in-depth
        # habit, even though a hash is far less sensitive than a raw secret.
        return f"<RefreshToken id={self.id} user_id={self.user_id} revoked={self.revoked_at is not None}>"
