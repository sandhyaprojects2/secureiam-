"""
AuditLogService -- read-only access to the audit trail.

Coordinates a single repository, AuditLogRepository, and does nothing else:
unlike every mutating service in this codebase (AuthService,
AuthorizationService, OrganizationService), this one never writes an audit
event itself -- it exists to *query* the log those other three already
populate (Phase 4.3), not to add to it. There is deliberately no
`actor_user_id` parameter anywhere here, matching
AuthorizationService.authorize()/get_user_permissions() and
OrganizationService.list_members()/list_organizations_for_user(): those are
the codebase's other pure reads, and none of them are audited either --
recording "an admin viewed the audit log" would itself just be more log
volume with no forensic value beyond what access-control already gates.

Like every other service in this codebase, this module contains no SQL, no
SQLAlchemy model queries, no database session management, and no
HTTPException/FastAPI imports -- it is fully usable and testable with a
plain mocked repository.

Phase 4.4: authorization (the `audit:view` permission) is enforced entirely
at the API layer via `require_permission("audit", "view")` -- the same
place `organization:manage` and `role:manage` are enforced for
OrganizationService/AuthorizationService's mutating methods. This service
itself performs no permission check of its own, matching every other
service's convention: services answer domain questions, the API layer
answers "is this caller allowed to ask."
"""

import uuid

from app.domain.schemas.audit_log import AuditLogEntryResponse, AuditLogPageResponse


class AuditLogService:
    def __init__(self, audit_log_repository):
        self.audit_log_repository = audit_log_repository

    async def list_events(
        self,
        organization_id: uuid.UUID | None = None,
        actor_user_id: uuid.UUID | None = None,
        action: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> AuditLogPageResponse:
        """Returns one page of audit events matching the given filters,
        most recent first, plus enough metadata (`total`) to page through
        the rest.

        Every filter is optional and additive, exactly matching
        AuditLogRepository.list_events()'s own contract, which this simply
        delegates to and reshapes -- no filters at all returns the most
        recent events system-wide. `total` comes from a second,
        independent call to count_events() with the same filters, ignoring
        limit/offset, so callers can compute "page 3 of N" without a second
        round trip of their own.

        Bounding `limit` to a sane range (e.g. rejecting an unbounded or
        negative page size) is the API layer's job, via FastAPI's own
        query-parameter validation -- the same division of responsibility
        as every other paginated-in-spirit read in this codebase, where
        HTTP-shaped input validation never leaks into the service layer.
        """
        events = await self.audit_log_repository.list_events(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action=action,
            limit=limit,
            offset=offset,
        )
        total = await self.audit_log_repository.count_events(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action=action,
        )

        return AuditLogPageResponse(
            events=[
                AuditLogEntryResponse(
                    id=event.id,
                    occurred_at=event.occurred_at,
                    actor_user_id=event.actor_user_id,
                    action=event.action,
                    target_type=event.target_type,
                    target_id=event.target_id,
                    organization_id=event.organization_id,
                    event_metadata=event.event_metadata,
                )
                for event in events
            ],
            total=total,
            limit=limit,
            offset=offset,
        )
