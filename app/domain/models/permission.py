"""
Permission model.

Permissions are global, not org-scoped, even after Phase 3 -- the concept
"document:delete" is universal; which ROLE grants it varies per
organization, but the permission catalog itself does not. This also
prevents permission-string drift/typos across future organizations.
"""

import uuid

from sqlalchemy import String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class Permission(Base):
    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint("resource", "action", name="uq_permissions_resource_action"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    resource: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<Permission id={self.id} {self.resource}:{self.action}>"
