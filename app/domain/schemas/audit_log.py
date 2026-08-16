"""
Data-return types for AuditLogService.

Same rationale as every other app/domain/schemas/*.py module: these are
what the service layer hands back to its callers, not HTTP request/
response models.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel


class AuditLogEntryResponse(BaseModel):
    id: uuid.UUID
    occurred_at: datetime
    actor_user_id: uuid.UUID | None = None
    action: str
    target_type: str | None = None
    target_id: uuid.UUID | None = None
    organization_id: uuid.UUID | None = None
    event_metadata: dict | None = None


class AuditLogPageResponse(BaseModel):
    """A page of audit log entries plus enough metadata to page through
    the rest -- total is the full count matching the given filters,
    independent of limit/offset (see AuditLogRepository.count_events())."""

    events: list[AuditLogEntryResponse]
    total: int
    limit: int
    offset: int
