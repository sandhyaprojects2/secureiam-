"""
HTTP-facing response schemas for the /v1/audit-logs endpoint.

Deliberately separate from app.domain.schemas.audit_log, for the same
reason app.api.v1.schemas.organization is kept separate from
app.domain.schemas.organization (see that module's docstring). There is no
request schema here -- unlike /v1/organizations' POST bodies, every input
to GET /v1/audit-logs is a query parameter, validated directly by FastAPI's
`Query(...)` at the route.
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
    events: list[AuditLogEntryResponse]
    total: int
    limit: int
    offset: int
