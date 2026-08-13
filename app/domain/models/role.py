"""
Role model.

Deliberately global (no organization_id) in Phase 2 -- multi-tenancy scoping
is Phase 3 scope. A migration will add organization scoping to this table
then; Phase 2 treats roles as shared across the whole system, matching the
single-org-per-session simplification carried over from the revised MVP
roadmap.
"""

import uuid

from sqlalchemy import Boolean, DateTime, String, Text, func
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

    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    def __repr__(self) -> str:
        return f"<Role id={self.id} name={self.name}>"
