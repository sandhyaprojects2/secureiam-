"""
Unit tests for OrganizationService.

Repositories are mocked (unittest.mock.AsyncMock) -- no database, no
network. Same shape as test_authorization_service.py.
"""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.core.time import utc_now
from app.domain import audit_actions
from app.domain.exceptions import (
    OrganizationMembershipAlreadyExistsError,
    OrganizationNameAlreadyExistsError,
    OrganizationNotFoundError,
    UserNotFoundError,
)
from app.domain.services.organization_service import OrganizationService
from app.repositories.exceptions import DuplicateMembershipError, DuplicateOrganizationNameError


def make_fake_user(user_id=None):
    return SimpleNamespace(id=user_id or uuid.uuid4())


def make_fake_organization(organization_id=None, name="TestOrg"):
    return SimpleNamespace(id=organization_id or uuid.uuid4(), name=name, created_at=utc_now())


def make_fake_member_row(user_id=None, email="member@example.com"):
    return SimpleNamespace(user_id=user_id or uuid.uuid4(), email=email, joined_at=utc_now())


# A fixed placeholder for tests that need to pass *some* actor_user_id but
# don't care about its specific value -- tests that DO care construct
# their own explicit id instead of using this one.
ACTOR_ID = uuid.uuid4()


@pytest.fixture
def service():
    organization_repo = AsyncMock()
    membership_repo = AsyncMock()
    user_repo = AsyncMock()
    audit_repo = AsyncMock()
    # audit_repo is deliberately not part of the returned tuple -- existing
    # tests don't need to change their destructuring; tests that need to
    # assert on it reach it via svc.audit_log_repository.
    svc = OrganizationService(organization_repo, membership_repo, user_repo, audit_repo)
    return svc, organization_repo, membership_repo, user_repo


# --- create_organization() ---------------------------------------------------

async def test_create_organization_success(service):
    svc, organization_repo, _, _ = service
    organization_repo.create_organization.return_value = make_fake_organization(name="Acme")

    result = await svc.create_organization("Acme", actor_user_id=ACTOR_ID)

    assert result.name == "Acme"


async def test_create_organization_duplicate_name_raises_domain_exception(service):
    svc, organization_repo, _, _ = service
    organization_repo.create_organization.side_effect = DuplicateOrganizationNameError(
        "already exists"
    )

    with pytest.raises(OrganizationNameAlreadyExistsError):
        await svc.create_organization("Acme", actor_user_id=ACTOR_ID)


async def test_create_organization_records_audit_event(service):
    svc, organization_repo, _, _ = service
    org = make_fake_organization(name="Acme")
    organization_repo.create_organization.return_value = org
    actor_id = uuid.uuid4()

    await svc.create_organization("Acme", actor_user_id=actor_id)

    svc.audit_log_repository.record.assert_called_once_with(
        action=audit_actions.ORGANIZATION_CREATED,
        actor_user_id=actor_id,
        target_type="organization",
        target_id=org.id,
        organization_id=org.id,
        event_metadata={"name": "Acme"},
    )


async def test_create_organization_failure_does_not_record_audit_event(service):
    svc, organization_repo, _, _ = service
    organization_repo.create_organization.side_effect = DuplicateOrganizationNameError(
        "already exists"
    )

    with pytest.raises(OrganizationNameAlreadyExistsError):
        await svc.create_organization("Acme", actor_user_id=ACTOR_ID)

    svc.audit_log_repository.record.assert_not_called()


# --- add_member() ---------------------------------------------------

async def test_add_member_success(service):
    svc, organization_repo, membership_repo, user_repo = service
    user = make_fake_user()
    org = make_fake_organization()
    user_repo.get_by_id.return_value = user
    organization_repo.get_by_id.return_value = org

    await svc.add_member(user.id, org.id, actor_user_id=ACTOR_ID)

    membership_repo.add_member.assert_called_once_with(user.id, org.id)


async def test_add_member_unknown_user_raises_not_found(service):
    svc, organization_repo, membership_repo, user_repo = service
    user_repo.get_by_id.return_value = None

    with pytest.raises(UserNotFoundError):
        await svc.add_member(uuid.uuid4(), uuid.uuid4(), actor_user_id=ACTOR_ID)

    organization_repo.get_by_id.assert_not_called()
    membership_repo.add_member.assert_not_called()


async def test_add_member_unknown_organization_raises_not_found(service):
    svc, organization_repo, membership_repo, user_repo = service
    user_repo.get_by_id.return_value = make_fake_user()
    organization_repo.get_by_id.return_value = None

    with pytest.raises(OrganizationNotFoundError):
        await svc.add_member(uuid.uuid4(), uuid.uuid4(), actor_user_id=ACTOR_ID)

    membership_repo.add_member.assert_not_called()


async def test_add_member_duplicate_raises_domain_exception(service):
    svc, organization_repo, membership_repo, user_repo = service
    user_repo.get_by_id.return_value = make_fake_user()
    organization_repo.get_by_id.return_value = make_fake_organization()
    membership_repo.add_member.side_effect = DuplicateMembershipError("already a member")

    with pytest.raises(OrganizationMembershipAlreadyExistsError):
        await svc.add_member(uuid.uuid4(), uuid.uuid4(), actor_user_id=ACTOR_ID)


async def test_add_member_records_audit_event(service):
    svc, organization_repo, membership_repo, user_repo = service
    user = make_fake_user()
    org = make_fake_organization()
    user_repo.get_by_id.return_value = user
    organization_repo.get_by_id.return_value = org
    actor_id = uuid.uuid4()

    await svc.add_member(user.id, org.id, actor_user_id=actor_id)

    svc.audit_log_repository.record.assert_called_once_with(
        action=audit_actions.ORGANIZATION_MEMBER_ADDED,
        actor_user_id=actor_id,
        target_type="user",
        target_id=user.id,
        organization_id=org.id,
    )


async def test_add_member_failure_does_not_record_audit_event(service):
    svc, organization_repo, membership_repo, user_repo = service
    user_repo.get_by_id.return_value = None

    with pytest.raises(UserNotFoundError):
        await svc.add_member(uuid.uuid4(), uuid.uuid4(), actor_user_id=ACTOR_ID)

    svc.audit_log_repository.record.assert_not_called()


# --- remove_member() ---------------------------------------------------

async def test_remove_member_success_returns_true(service):
    svc, _, membership_repo, _ = service
    membership_repo.remove_member.return_value = True

    result = await svc.remove_member(uuid.uuid4(), uuid.uuid4(), actor_user_id=ACTOR_ID)

    assert result is True


async def test_remove_member_nonexistent_returns_false_without_raising(service):
    svc, _, membership_repo, _ = service
    membership_repo.remove_member.return_value = False

    result = await svc.remove_member(uuid.uuid4(), uuid.uuid4(), actor_user_id=ACTOR_ID)

    assert result is False


async def test_remove_member_success_records_audit_event(service):
    svc, _, membership_repo, _ = service
    membership_repo.remove_member.return_value = True
    user_id, org_id, actor_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()

    await svc.remove_member(user_id, org_id, actor_user_id=actor_id)

    svc.audit_log_repository.record.assert_called_once_with(
        action=audit_actions.ORGANIZATION_MEMBER_REMOVED,
        actor_user_id=actor_id,
        target_type="user",
        target_id=user_id,
        organization_id=org_id,
    )


async def test_remove_member_no_op_does_not_record_audit_event(service):
    svc, _, membership_repo, _ = service
    membership_repo.remove_member.return_value = False

    await svc.remove_member(uuid.uuid4(), uuid.uuid4(), actor_user_id=ACTOR_ID)

    svc.audit_log_repository.record.assert_not_called()


# --- list_members() ---------------------------------------------------

async def test_list_members_returns_schema_list(service):
    svc, organization_repo, membership_repo, _ = service
    org = make_fake_organization()
    organization_repo.get_by_id.return_value = org
    membership_repo.get_members_for_organization.return_value = [
        make_fake_member_row(email="a@example.com"),
        make_fake_member_row(email="b@example.com"),
    ]

    result = await svc.list_members(org.id)

    emails = {m.email for m in result}
    assert emails == {"a@example.com", "b@example.com"}


async def test_list_members_unknown_organization_raises_not_found(service):
    svc, organization_repo, membership_repo, _ = service
    organization_repo.get_by_id.return_value = None

    with pytest.raises(OrganizationNotFoundError):
        await svc.list_members(uuid.uuid4())

    membership_repo.get_members_for_organization.assert_not_called()


async def test_list_members_empty_for_organization_with_no_members(service):
    svc, organization_repo, membership_repo, _ = service
    organization_repo.get_by_id.return_value = make_fake_organization()
    membership_repo.get_members_for_organization.return_value = []

    result = await svc.list_members(uuid.uuid4())

    assert result == []


async def test_list_members_is_never_audited(service):
    svc, organization_repo, membership_repo, _ = service
    organization_repo.get_by_id.return_value = make_fake_organization()
    membership_repo.get_members_for_organization.return_value = []

    await svc.list_members(uuid.uuid4())

    svc.audit_log_repository.record.assert_not_called()


# --- list_organizations_for_user() ---------------------------------------------------

async def test_list_organizations_for_user_returns_schema_list(service):
    svc, _, membership_repo, _ = service
    membership_repo.get_organizations_for_user.return_value = [
        make_fake_organization(name="OrgA"),
        make_fake_organization(name="OrgB"),
    ]

    result = await svc.list_organizations_for_user(uuid.uuid4())

    names = {o.name for o in result}
    assert names == {"OrgA", "OrgB"}


async def test_list_organizations_for_user_empty_for_user_with_no_memberships(service):
    svc, _, membership_repo, _ = service
    membership_repo.get_organizations_for_user.return_value = []

    result = await svc.list_organizations_for_user(uuid.uuid4())

    assert result == []


async def test_list_organizations_for_user_is_never_audited(service):
    svc, _, membership_repo, _ = service
    membership_repo.get_organizations_for_user.return_value = []

    await svc.list_organizations_for_user(uuid.uuid4())

    svc.audit_log_repository.record.assert_not_called()
