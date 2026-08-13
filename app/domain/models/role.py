"""
Role model.

Deliberately global (no organization_id) through Phase 2 -- multi-tenancy
scoping was explicitly deferred to Phase 3, which is what
organization_id (below) is.

Phase 3 scoping model: organization_id is nullable. NULL means a global/
system role, usable by any organization (the four seeded roles --
Admin/Manager/Developer/Intern -- stay NULL and are never org-scoped). A
non-NULL value means a custom role that belongs to, and is only
assignable within, that one organization -- enforced at the service layer
(AuthorizationService.assign_role(), Phase 3.3), not by a DB constraint,
matching how is_system_role's deletion protection already works below.

Known, accepted limitation: role names remain globally unique (see
`ix_roles_name` in the migrations) even across organizations -- two
different organizations cannot both name a custom role "Support", nor can
an org-scoped role reuse one of the four system role names. This is a
simpler starting point than partial-unique-index-per-organization-name
scoping, deliberately deferred until it's an actual pain point rather than
a hypothetical one.
"""

import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Protects default roles (Admin/Manager/Developer/Intern) from being
    # deleted via the future role-management API -- enforced at the
    # service layer in Phase 2.3, not by a DB constraint, since "can this
    # be deleted" is a business rule.
    is_system_role: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Phase 3: NULL = global/system role; non-NULL = a custom role scoped
    # to one organization. ON DELETE CASCADE -- deleting an organization
    # deletes its own custom roles (and, transitively via role_permissions'
    # own CASCADE, their permission mappings), but never touches a global
    # role, since a global role's organization_id is NULL and therefore
    # can't reference the deleted row.
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )

    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    def __repr__(self) -> str:
        return f"<Role id={self.id} name={self.name}>"
