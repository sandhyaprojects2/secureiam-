"""
User model — the persistence representation of a registered account.

Multi-tenancy (organization membership) is deliberately not modeled here yet;
that's Phase 3 scope. A User in Phase 1 is tenant-agnostic identity only.
"""

import uuid

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_email_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[object] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    last_login_at: Mapped[object | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        # Deliberately excludes password_hash from the repr — a stray
        # print(user) or log statement must never surface it, even hashed.
        return f"<User id={self.id} email={self.email}>"
