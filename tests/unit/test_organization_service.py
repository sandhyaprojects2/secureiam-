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


@pytest.fixture
def service():
    organization_repo = AsyncMock()
    membership_repo = AsyncMock()
    user_repo = AsyncMock()
    svc = OrganizationService(organization_repo, membership_repo, user_repo)
    return svc, organization_repo, membership_repo, user_repo


# --- create_organization() ---------------------------------------------------

async def test_create_organization_success(service):
    svc, organization_repo, _, _ = service
    organization_repo.create_organization.return_value = make_fake_organization(name="Acme")

    result = await svc.create_organization("Acme")

    assert result.name == "Acme"


async def test_create_organization_duplicate_name_raises_domain_exception(service):
    svc, organization_repo, _, _ = service
    organization_repo.create_organization.side_effect = DuplicateOrganizationNameError(
        "already exists"
    )

    with pytest.raises(OrganizationNameAlreadyExistsError):
        await svc.create_organization("Acme")


# --- add_member() ---------------------------------------------------

async def test_add_member_success(service):
    svc, organization_repo, membership_repo, user_repo = service
    user = make_fake_user()
    org = make_fake_organization()
    user_repo.get_by_id.return_value = user
    organization_repo.get_by_id.return_value = org

    await svc.add_member(user.id, org.id)

    membership_repo.add_member.assert_called_once_with(user.id, org.id)


async def test_add_member_unknown_user_raises_not_found(service):
    svc, organization_repo, membership_repo, user_repo = service
    user_repo.get_by_id.return_value = None

    with pytest.raises(UserNotFoundError):
        await svc.add_member(uuid.uuid4(), uuid.uuid4())

    organization_repo.get_by_id.assert_not_called()
    membership_repo.add_member.assert_not_called()


async def test_add_member_unknown_organization_raises_not_found(service):
    svc, organization_repo, membership_repo, user_repo = service
    user_repo.get_by_id.return_value = make_fake_user()
    organization_repo.get_by_id.return_value = None

    with pytest.raises(OrganizationNotFoundError):
        await svc.add_member(uuid.uuid4(), uuid.uuid4())

    membership_repo.add_member.assert_not_called()


async def test_add_member_duplicate_raises_domain_exception(service):
    svc, organization_repo, membership_repo, user_repo = service
    user_repo.get_by_id.return_value = make_fake_user()
    organization_repo.get_by_id.return_value = make_fake_organization()
    membership_repo.add_member.side_effect = DuplicateMembershipError("already a member")

    with pytest.raises(OrganizationMembershipAlreadyExistsError):
        await svc.add_member(uuid.uuid4(), uuid.uuid4())


# --- remove_member() ---------------------------------------------------

async def test_remove_member_success_returns_true(service):
    svc, _, membership_repo, _ = service
    membership_repo.remove_member.return_value = True

    result = await svc.remove_member(uuid.uuid4(), uuid.uuid4())

    assert result is True


async def test_remove_member_nonexistent_returns_false_without_raising(service):
    svc, _, membership_repo, _ = service
    membership_repo.remove_member.return_value = False

    result = await svc.remove_member(uuid.uuid4(), uuid.uuid4())

    assert result is False


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
