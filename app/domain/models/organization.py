"""
Organization model -- the tenant boundary introduced in Phase 3.

Deliberately minimal: an organization is just a name and a creation
timestamp. Everything that needs to be organization-aware (role scoping via
Role.organization_id, role-assignment scoping via UserRole.organization_id,
membership via OrganizationMembership) references organizations.id rather
than this model growing to hold that logic itself.
"""

import uuid

from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    def __repr__(self) -> str:
        return f"<Organization id={self.id} name={self.name}>"
