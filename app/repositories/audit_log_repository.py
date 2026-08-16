"""
AuditLogRepository -- the only module that queries the `audit_logs` table
directly.

Unlike every other repository in this codebase, there is no
DuplicateXError translation here: audit_logs has no unique constraint to
violate, since it's a pure append-only log -- every record() call is
expected to succeed. There is also, deliberately, no update or delete
method -- matching PermissionRepository's "no create_permission method
exists here on purpose" convention, reversed: an audit log that can be
edited or removed after the fact isn't an audit log.
"""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models import AuditLog


class AuditLogRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def record(
        self,
        action: str,
        actor_user_id: uuid.UUID | None = None,
        target_type: str | None = None,
        target_id: uuid.UUID | None = None,
        organization_id: uuid.UUID | None = None,
        event_metadata: dict | None = None,
    ) -> AuditLog:
        """Persists one audit event. Callers (the three services that
        write audit events) are responsible for supplying a real
        actor_user_id/organization_id when they have one -- this method
        performs no existence validation of its own, the same as every
        other repository's write methods in this codebase."""
        log = AuditLog(
            action=action,
            actor_user_id=actor_user_id,
            target_type=target_type,
            target_id=target_id,
            organization_id=organization_id,
            event_metadata=event_metadata,
        )
        self.session.add(log)
        await self.session.commit()
        await self.session.refresh(log)
        return log

    async def list_events(
        self,
        organization_id: uuid.UUID | None = None,
        actor_user_id: uuid.UUID | None = None,
        action: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuditLog]:
        """Returns matching audit events, most recent first. Every filter
        is optional and additive (AND, not OR) -- omitting all of them
        returns the most recent events system-wide."""
        query = select(AuditLog).order_by(AuditLog.occurred_at.desc())

        if organization_id is not None:
            query = query.where(AuditLog.organization_id == organization_id)
        if actor_user_id is not None:
            query = query.where(AuditLog.actor_user_id == actor_user_id)
        if action is not None:
            query = query.where(AuditLog.action == action)

        query = query.limit(limit).offset(offset)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def count_events(
        self,
        organization_id: uuid.UUID | None = None,
        actor_user_id: uuid.UUID | None = None,
        action: str | None = None,
    ) -> int:
        """Returns the total count of events matching the same filters as
        list_events(), ignoring limit/offset -- used to compute pagination
        metadata (Phase 4.4) without a second round trip through the ORM
        for full rows."""
        query = select(func.count()).select_from(AuditLog)

        if organization_id is not None:
            query = query.where(AuditLog.organization_id == organization_id)
        if actor_user_id is not None:
            query = query.where(AuditLog.actor_user_id == actor_user_id)
        if action is not None:
            query = query.where(AuditLog.action == action)

        result = await self.session.execute(query)
        return result.scalar_one()
