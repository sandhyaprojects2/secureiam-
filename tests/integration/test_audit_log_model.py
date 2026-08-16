"""
Integration tests for the Phase 4.1 audit log schema -- AuditLog -- run
against real Postgres.

Unlike roles/permissions/organizations, audit log rows are NOT reference
data meant to persist across test runs -- they're per-test artifacts tied
to the users/organizations a test creates, and are cleared by the
test_session fixture's truncate along with those users (see conftest.py's
updated docstring). No uuid-suffixed uniqueness workaround is needed here.
"""

import uuid

import pytest
from sqlalchemy import select

from app.domain.models import AuditLog, Organization, Role, User


async def _make_user(session, email=None):
    email = email or f"auditlog-{uuid.uuid4().hex[:8]}@example.com"
    user = User(email=email, password_hash="fake-hash-for-testing")
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def _make_org(session, name=None):
    org = Organization(name=name or f"AuditLogOrg-{uuid.uuid4().hex[:8]}")
    session.add(org)
    await session.commit()
    await session.refresh(org)
    return org


async def test_audit_log_can_be_created_with_minimal_fields(test_session):
    log = AuditLog(action="user.login_succeeded")
    test_session.add(log)
    await test_session.commit()
    await test_session.refresh(log)

    assert log.id is not None
    assert log.occurred_at is not None
    assert log.actor_user_id is None
    assert log.target_type is None
    assert log.target_id is None
    assert log.organization_id is None
    assert log.event_metadata is None


async def test_audit_log_can_be_created_with_full_fields(test_session):
    user = await _make_user(test_session)
    org = await _make_org(test_session)
    role = Role(name=f"AuditLogRole-{uuid.uuid4().hex[:8]}")
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)

    log = AuditLog(
        actor_user_id=user.id,
        action="role.assigned",
        target_type="user",
        target_id=user.id,
        organization_id=org.id,
        event_metadata={"role_id": str(role.id), "role_name": role.name},
    )
    test_session.add(log)
    await test_session.commit()
    await test_session.refresh(log)

    assert log.actor_user_id == user.id
    assert log.target_type == "user"
    assert log.target_id == user.id
    assert log.organization_id == org.id
    assert log.event_metadata == {"role_id": str(role.id), "role_name": role.name}


async def test_event_metadata_round_trips_nested_json(test_session):
    log = AuditLog(
        action="user.login_failed",
        event_metadata={"reason": "wrong_password", "attempt_count": 3, "nested": {"a": [1, 2]}},
    )
    test_session.add(log)
    await test_session.commit()
    await test_session.refresh(log)

    found = await test_session.get(AuditLog, log.id)
    assert found.event_metadata == {
        "reason": "wrong_password",
        "attempt_count": 3,
        "nested": {"a": [1, 2]},
    }


async def test_deleting_actor_user_sets_actor_user_id_null_not_cascade(test_session):
    """The core guarantee this migration exists for: the audit row must
    survive the actor's deletion, unlike every CASCADE relationship
    elsewhere in this schema.

    Note: the surviving row is inspected via test_session.refresh(log), not
    a fresh select() -- test_session uses expire_on_commit=False, so a new
    select() for a primary key already in the session's identity map
    returns the same cached Python object without re-reading its columns,
    which would show the pre-delete in-memory value even though Postgres
    already applied SET NULL to the actual row. refresh() forces a real
    re-read.
    """
    user = await _make_user(test_session)
    log = AuditLog(actor_user_id=user.id, action="user.login_succeeded")
    test_session.add(log)
    await test_session.commit()

    await test_session.delete(user)
    await test_session.commit()
    await test_session.refresh(log)

    assert log.actor_user_id is None


async def test_deleting_organization_sets_organization_id_null_not_cascade(test_session):
    """See test_deleting_actor_user_sets_actor_user_id_null_not_cascade's
    docstring for why this uses refresh(log) rather than a fresh query."""
    org = await _make_org(test_session)
    log = AuditLog(action="organization.member_added", organization_id=org.id)
    test_session.add(log)
    await test_session.commit()

    await test_session.delete(org)
    await test_session.commit()
    await test_session.refresh(log)

    assert log.organization_id is None


async def test_multiple_audit_logs_for_same_actor_are_all_retained(test_session):
    user = await _make_user(test_session)
    test_session.add_all(
        [
            AuditLog(actor_user_id=user.id, action="user.login_succeeded"),
            AuditLog(actor_user_id=user.id, action="user.logout"),
            AuditLog(actor_user_id=user.id, action="user.login_succeeded"),
        ]
    )
    await test_session.commit()

    result = await test_session.execute(
        select(AuditLog).where(AuditLog.actor_user_id == user.id)
    )
    assert len(result.scalars().all()) == 3
