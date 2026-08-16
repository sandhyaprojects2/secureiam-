"""
AuditLog model -- Phase 4's append-only security/administrative event log.

Deliberately immutable: no repository method to update or delete a row
exists (Phase 4.2), matching PermissionRepository's "no create_permission
method exists here on purpose" convention from Phase 2.2 -- reversed here
into "no update/delete method exists here on purpose."

actor_user_id and organization_id are both nullable and ON DELETE SET NULL
(not CASCADE) -- deleting a user or organization must never silently erase
the historical record that they did something; the audit row survives
with its foreign key nulled out, not deleted along with it. (No code path
in this codebase currently deletes a user or organization, so this is
forward-looking hygiene, not behavior anything exercises today.)

target_id is deliberately NOT a foreign key -- what it points to depends on
target_type ("user", "role", "permission", "organization", ...), and a
single column can't hold a real FK to more than one table. This is the
standard, accepted trade-off for a polymorphic reference in an audit log:
referential integrity on target_id is not enforced at the database level,
only documented by convention (target_type says which table it means).

action/target_type are plain strings, not a fixed Postgres ENUM -- same
"plain data, no schema change needed to extend" philosophy as
Permission.resource/action (see the Phase 2.1 seed migration's docstring).

The metadata column is named `event_metadata`, not `metadata` -- SQLAlchemy's
declarative Base reserves `metadata` as the class attribute holding
Base.metadata (the MetaData registry); naming a mapped column `metadata`
would collide with it.
"""

import uuid

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    occurred_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    target_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    event_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action={self.action} actor_user_id={self.actor_user_id}>"
