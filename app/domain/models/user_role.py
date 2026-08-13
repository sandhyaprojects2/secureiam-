"""
UserRole model -- assigns a Role to a User, optionally scoped to an
Organization.

References users.id directly rather than an organization_membership_id --
a deliberate, documented deviation from the original Phase 0 spec, kept
even now that Phase 3 exists: OrganizationMembership answers "is this user
part of this org," which is a different (and independently useful)
question from "what role does this user hold, and where." Coupling
UserRole to a specific membership row would mean losing a role assignment
the moment membership lapsed, which isn't necessarily desired. See
docs/phases/phase-3.1.md for the fuller rationale of this choice over a
membership_id foreign key.

Phase 3 scoping model: organization_id is nullable, matching Role's own
convention. NULL means a global assignment -- this role applies to this
user everywhere, independent of organization, which is exactly the
pre-Phase-3 behavior and how every pre-Phase-3 UserRole row (and every
test written before this phase) continues to behave with zero migration
needed. A non-NULL value scopes the assignment to that one organization.

Uniqueness is enforced via two partial indexes rather than one plain
UNIQUE(user_id, role_id, organization_id) constraint, because PostgreSQL
treats every NULL as distinct from every other NULL in a plain unique
constraint -- which would silently stop rejecting duplicate *global*
assignments (organization_id IS NULL), regressing the guarantee Phase 2.2
already tested and shipped. The two indexes below restore that per-case:
  - uq_user_roles_user_role_global: at most one (user_id, role_id) row
    where organization_id IS NULL -- the original Phase 2.2 guarantee.
  - uq_user_roles_user_role_org: at most one (user_id, role_id,
    organization_id) row where organization_id IS NOT NULL -- lets the
    same user hold the same role in two different organizations as two
    separate rows, while still rejecting an exact duplicate within one.
"""

import uuid

from sqlalchemy import DateTime, ForeignKey, Index, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class UserRole(Base):
    __tablename__ = "user_roles"
    __table_args__ = (
        Index(
            "uq_user_roles_user_role_global",
            "user_id",
            "role_id",
            unique=True,
            postgresql_where=text("organization_id IS NULL"),
        ),
        Index(
            "uq_user_roles_user_role_org",
            "user_id",
            "role_id",
            "organization_id",
            unique=True,
            postgresql_where=text("organization_id IS NOT NULL"),
        ),
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
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Phase 3: NULL = global assignment (pre-Phase-3 behavior, unchanged).
    # Non-NULL = this assignment only grants the role's permissions within
    # that one organization. ON DELETE CASCADE -- deleting an organization
    # deletes org-scoped assignments into it, never touches global ones.
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    assigned_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    def __repr__(self) -> str:
        return (
            f"<UserRole user_id={self.user_id} role_id={self.role_id} "
            f"organization_id={self.organization_id}>"
        )
