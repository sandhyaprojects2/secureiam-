"""
Integration tests for AuditLogRepository -- real Postgres throughout, no
mocked SQLAlchemy.

Audit log rows are per-test artifacts (see test_audit_log_model.py's
module docstring), not persistent reference data -- no uuid-suffixed
uniqueness workaround is needed, but tests that assert on exact counts
still scope their queries to a specific actor_user_id/organization_id/
action they created, rather than the whole table, since the table isn't
guaranteed empty at the start of any given test.
"""

import uuid

import pytest

from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.organization_repository import OrganizationRepository
from app.repositories.user_repository import UserRepository


async def _make_user(session, email=None):
    email = email or f"auditrepo-{uuid.uuid4().hex[:8]}@example.com"
    return await UserRepository(session).create_user(email=email, password_hash="fake-hash")


async def _make_org(session, name=None):
    name = name or f"AuditRepoOrg-{uuid.uuid4().hex[:8]}"
    return await OrganizationRepository(session).create_organization(name)


async def test_record_creates_event_with_minimal_fields(test_session):
    repo = AuditLogRepository(test_session)

    log = await repo.record(action="user.login_succeeded")

    assert log.id is not None
    assert log.occurred_at is not None
    assert log.actor_user_id is None


async def test_record_creates_event_with_all_fields(test_session):
    repo = AuditLogRepository(test_session)
    user = await _make_user(test_session)
    org = await _make_org(test_session)

    log = await repo.record(
        action="role.assigned",
        actor_user_id=user.id,
        target_type="user",
        target_id=user.id,
        organization_id=org.id,
        event_metadata={"role_name": "Manager"},
    )

    assert log.actor_user_id == user.id
    assert log.target_type == "user"
    assert log.target_id == user.id
    assert log.organization_id == org.id
    assert log.event_metadata == {"role_name": "Manager"}


async def test_list_events_returns_most_recent_first(test_session):
    repo = AuditLogRepository(test_session)
    user = await _make_user(test_session)
    action = f"test.ordering.{uuid.uuid4().hex[:8]}"
    first = await repo.record(action=action, actor_user_id=user.id)
    second = await repo.record(action=action, actor_user_id=user.id)
    third = await repo.record(action=action, actor_user_id=user.id)

    events = await repo.list_events(actor_user_id=user.id, action=action)

    ids_in_order = [e.id for e in events]
    assert ids_in_order.index(third.id) < ids_in_order.index(second.id) < ids_in_order.index(
        first.id
    )


async def test_list_events_filters_by_organization_id(test_session):
    repo = AuditLogRepository(test_session)
    org_a = await _make_org(test_session)
    org_b = await _make_org(test_session)
    action = f"test.orgfilter.{uuid.uuid4().hex[:8]}"
    await repo.record(action=action, organization_id=org_a.id)
    await repo.record(action=action, organization_id=org_b.id)

    events = await repo.list_events(organization_id=org_a.id, action=action)

    assert len(events) == 1
    assert events[0].organization_id == org_a.id


async def test_list_events_filters_by_actor_user_id(test_session):
    repo = AuditLogRepository(test_session)
    user_a = await _make_user(test_session)
    user_b = await _make_user(test_session)
    action = f"test.actorfilter.{uuid.uuid4().hex[:8]}"
    await repo.record(action=action, actor_user_id=user_a.id)
    await repo.record(action=action, actor_user_id=user_b.id)

    events = await repo.list_events(actor_user_id=user_a.id, action=action)

    assert len(events) == 1
    assert events[0].actor_user_id == user_a.id


async def test_list_events_filters_by_action(test_session):
    repo = AuditLogRepository(test_session)
    user = await _make_user(test_session)
    action_a = f"test.actionfilter.a.{uuid.uuid4().hex[:8]}"
    action_b = f"test.actionfilter.b.{uuid.uuid4().hex[:8]}"
    await repo.record(action=action_a, actor_user_id=user.id)
    await repo.record(action=action_b, actor_user_id=user.id)

    events = await repo.list_events(actor_user_id=user.id, action=action_a)

    assert len(events) == 1
    assert events[0].action == action_a


async def test_list_events_respects_limit_and_offset(test_session):
    repo = AuditLogRepository(test_session)
    user = await _make_user(test_session)
    action = f"test.paging.{uuid.uuid4().hex[:8]}"
    for _ in range(5):
        await repo.record(action=action, actor_user_id=user.id)

    first_page = await repo.list_events(actor_user_id=user.id, action=action, limit=2, offset=0)
    second_page = await repo.list_events(actor_user_id=user.id, action=action, limit=2, offset=2)

    assert len(first_page) == 2
    assert len(second_page) == 2
    assert {e.id for e in first_page}.isdisjoint({e.id for e in second_page})


async def test_list_events_with_no_matches_returns_empty_list(test_session):
    repo = AuditLogRepository(test_session)

    events = await repo.list_events(actor_user_id=uuid.uuid4())

    assert events == []


async def test_count_events_matches_list_events_filters(test_session):
    repo = AuditLogRepository(test_session)
    user = await _make_user(test_session)
    action = f"test.count.{uuid.uuid4().hex[:8]}"
    for _ in range(3):
        await repo.record(action=action, actor_user_id=user.id)

    count = await repo.count_events(actor_user_id=user.id, action=action)

    assert count == 3


async def test_count_events_ignores_limit_and_offset(test_session):
    """count_events() always reflects the total matching the filters, not
    a paginated subset -- it has no limit/offset parameters at all."""
    repo = AuditLogRepository(test_session)
    user = await _make_user(test_session)
    action = f"test.countignorespaging.{uuid.uuid4().hex[:8]}"
    for _ in range(4):
        await repo.record(action=action, actor_user_id=user.id)

    count = await repo.count_events(actor_user_id=user.id, action=action)
    paged_events = await repo.list_events(actor_user_id=user.id, action=action, limit=1)

    assert count == 4
    assert len(paged_events) == 1


async def test_audit_log_repository_has_no_update_or_delete_method(test_session):
    """Confirms the deliberate design decision: audit records are
    append-only, matching the model and migration docstrings."""
    repo = AuditLogRepository(test_session)
    assert not hasattr(repo, "update")
    assert not hasattr(repo, "delete")
    assert not hasattr(repo, "update_event")
    assert not hasattr(repo, "delete_event")
