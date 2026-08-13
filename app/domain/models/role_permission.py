"""
role_permissions -- a pure many-to-many association table.

Implemented as a SQLAlchemy Core Table, not a mapped ORM class: it has no
columns beyond the two foreign keys forming its composite primary key, and
no independent identity worth representing as an entity. Compare to
UserRole (app.domain.models.user_role), which DOES have its own attributes
(id, assigned_at) and is therefore a full model.
"""

from sqlalchemy import Column, ForeignKey, Table
from sqlalchemy.dialects.postgresql import UUID

from app.db.session import Base

role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column(
        "role_id",
        UUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "permission_id",
        UUID(as_uuid=True),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)
