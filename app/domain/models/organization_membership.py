"""
OrganizationMembership model -- records that a user belongs to an
organization.

Deliberately separate from role/permission assignment (UserRole, which as
of Phase 3 also carries its own optional organization_id). Membership
answers "is this user part of this org at all"; UserRole answers "what can
they do, and in which org context." A user can be a member of an
organization without holding any role scoped to it (e.g. immediately after
being added, before any role is granted). AuthorizationService.assign_role()
checks membership before allowing an org-scoped role assignment -- see its
docstring for the rationale.
"""

import uuid

from sqlalchemy import DateTime, ForeignKey, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class OrganizationMembership(Base):
    __tablename__ = "organization_memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "organization_id", name="uq_org_memberships_user_org"),
    )

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
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    joined_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    def __repr__(self) -> str:
        return (
            f"<OrganizationMembership user_id={self.user_id} "
            f"organization_id={self.organization_id}>"
        )
