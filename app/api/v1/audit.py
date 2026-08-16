"""
/v1/audit-logs route.

Same thinness contract as app/api/v1/organizations.py: validate the
request, call AuditLogService, translate its (nonexistent, for this
read-only service) domain exceptions into HTTP responses. No repository
access and no business rules live here.

The whole route is a single GET gated by `require_permission("audit",
"view")` -- the permission seeded for Admin only by
cbf5b83aa3f8_seed_audit_view_permission.py (Phase 4.4). There is
deliberately no path-parameter form (e.g. GET /audit-logs/{id}) -- nothing
in this codebase currently needs to fetch a single audit event by id, and
adding one speculatively would be unused surface area.
"""

import uuid

from fastapi import APIRouter, Depends, Query

from app.api.v1.schemas.audit_log import AuditLogPageResponse
from app.core.dependencies import get_audit_log_service, require_permission
from app.domain.models import User
from app.domain.services.audit_log_service import AuditLogService

router = APIRouter(prefix="/v1", tags=["audit"])


@router.get("/audit-logs", response_model=AuditLogPageResponse)
async def list_audit_logs(
    organization_id: uuid.UUID | None = Query(default=None),
    actor_user_id: uuid.UUID | None = Query(default=None),
    action: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(require_permission("audit", "view")),
    service: AuditLogService = Depends(get_audit_log_service),
) -> AuditLogPageResponse:
    """Lists audit events, most recent first, optionally filtered by
    organization_id/actor_user_id/action -- every filter is optional and
    additive, matching AuditLogService.list_events()'s own contract.

    `limit` is bounded to [1, 200] here, at the HTTP boundary, not in the
    service or repository layer -- rejecting a pathological page size (or a
    negative one) is exactly the kind of HTTP-shaped input validation this
    codebase always keeps out of the service layer (see
    AuditLogService.list_events()'s docstring).
    """
    result = await service.list_events(
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action=action,
        limit=limit,
        offset=offset,
    )
    return AuditLogPageResponse(**result.model_dump())
