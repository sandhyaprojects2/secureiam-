"""
Unit tests for AuditLogService.

AuditLogRepository is mocked (unittest.mock.AsyncMock) -- no database, no
network. Same shape as test_organization_service.py.
"""

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.domain.services.audit_log_service import AuditLogService


def make_fake_event(
    event_id=None,
    occurred_at=None,
    actor_user_id=None,
    action="user.login_succeeded",
    target_type=None,
    target_id=None,
    organization_id=None,
    event_metadata=None,
):
    return SimpleNamespace(
        id=event_id or uuid.uuid4(),
        occurred_at=occurred_at or datetime.now(timezone.utc),
        actor_user_id=actor_user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        organization_id=organization_id,
        event_metadata=event_metadata,
    )


@pytest.fixture
def service():
    audit_repo = AsyncMock()
    svc = AuditLogService(audit_repo)
    return svc, audit_repo


# --- list_events() ---------------------------------------------------

async def test_list_events_wraps_repository_rows_into_entry_schemas(service):
    svc, audit_repo = service
    event = make_fake_event(action="organization.created")
    audit_repo.list_events.return_value = [event]
    audit_repo.count_events.return_value = 1

    result = await svc.list_events()

    assert len(result.events) == 1
    entry = result.events[0]
    assert entry.id == event.id
    assert entry.action == "organization.created"
    assert entry.occurred_at == event.occurred_at


async def test_list_events_returns_empty_page_when_nothing_matches(service):
    svc, audit_repo = service
    audit_repo.list_events.return_value = []
    audit_repo.count_events.return_value = 0

    result = await svc.list_events()

    assert result.events == []
    assert result.total == 0


async def test_list_events_total_reflects_full_count_independent_of_page_size(service):
    """total comes from count_events(), which ignores limit/offset -- a
    page of 2 rows out of 50 matching total must still report total=50."""
    svc, audit_repo = service
    audit_repo.list_events.return_value = [make_fake_event(), make_fake_event()]
    audit_repo.count_events.return_value = 50

    result = await svc.list_events(limit=2, offset=10)

    assert len(result.events) == 2
    assert result.total == 50
    assert result.limit == 2
    assert result.offset == 10


async def test_list_events_passes_every_filter_through_to_the_repository(service):
    svc, audit_repo = service
    audit_repo.list_events.return_value = []
    audit_repo.count_events.return_value = 0
    org_id, actor_id = uuid.uuid4(), uuid.uuid4()

    await svc.list_events(
        organization_id=org_id, actor_user_id=actor_id, action="role.created", limit=25, offset=5
    )

    audit_repo.list_events.assert_called_once_with(
        organization_id=org_id, actor_user_id=actor_id, action="role.created", limit=25, offset=5
    )
    audit_repo.count_events.assert_called_once_with(
        organization_id=org_id, actor_user_id=actor_id, action="role.created"
    )


async def test_list_events_defaults_to_no_filters_and_standard_page_size(service):
    svc, audit_repo = service
    audit_repo.list_events.return_value = []
    audit_repo.count_events.return_value = 0

    await svc.list_events()

    audit_repo.list_events.assert_called_once_with(
        organization_id=None, actor_user_id=None, action=None, limit=50, offset=0
    )


async def test_list_events_never_writes_to_the_audit_log(service):
    """This service is read-only -- it must never call record(), matching
    every other pure-read method in the codebase (authorize(),
    list_members(), etc.)."""
    svc, audit_repo = service
    audit_repo.list_events.return_value = []
    audit_repo.count_events.return_value = 0

    await svc.list_events()

    audit_repo.record.assert_not_called()


async def test_list_events_preserves_most_recent_first_ordering_from_repository(service):
    """The service must not re-sort or otherwise reorder what the
    repository already returns in most-recent-first order."""
    svc, audit_repo = service
    newer = make_fake_event(action="user.login_succeeded")
    older = make_fake_event(action="user.logout")
    audit_repo.list_events.return_value = [newer, older]
    audit_repo.count_events.return_value = 2

    result = await svc.list_events()

    assert [e.id for e in result.events] == [newer.id, older.id]
