"""
Integration tests for OrganizationRepository and
OrganizationMembershipRepository -- real Postgres throughout, no mocked
SQLAlchemy. Same caller-side pattern as test_rbac_repositories.py: capture
primitive values (e.g. `org_id = org.id`) before any operation that could
trigger a rollback, and use only those primitives afterward.
"""

import uuid

import pytest

from app.repositories.exceptions import DuplicateMembershipError, DuplicateOrganizationNameError
from app.repositories.organization_membership_repository import OrganizationMembershipRepository
from app.repositories.organization_repository import OrganizationRepository
from app.repositories.user_repository import UserRepository


def unique_org_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


async def _make_user(session, email=None):
    email = email or f"orgrepo-{uuid.uuid4().hex[:8]}@example.com"
    return await UserRepository(session).create_user(email=email, password_hash="fake-hash")


# --- OrganizationRepository ---------------------------------------------------

async def test_create_organization_succeeds(test_session):
    repo = OrganizationRepository(test_session)
    org = await repo.create_organization(unique_org_name("NewOrg"))

    assert org.id is not None
    assert org.created_at is not None


async def test_duplicate_organization_name_is_rejected(test_session):
    repo = OrganizationRepository(test_session)
    name = unique_org_name("DuplicateOrg")
    await repo.create_organization(name)

    with pytest.raises(DuplicateOrganizationNameError):
        await repo.create_organization(name)


async def test_get_by_id_returns_correct_organization(test_session):
    repo = OrganizationRepository(test_session)
    created = await repo.create_organization(unique_org_name("ById"))
    org_id = created.id

    found = await repo.get_by_id(org_id)

    assert found is not None
    assert found.id == org_id


async def test_get_by_id_unknown_returns_none(test_session):
    repo = OrganizationRepository(test_session)
    found = await repo.get_by_id(uuid.uuid4())
    assert found is None


async def test_get_by_name_returns_correct_organization(test_session):
    repo = OrganizationRepository(test_session)
    name = unique_org_name("ByName")
    await repo.create_organization(name)

    found = await repo.get_by_name(name)

    assert found is not None
    assert found.name == name


async def test_get_by_name_unknown_returns_none(test_session):
    repo = OrganizationRepository(test_session)
    found = await repo.get_by_name(unique_org_name("NeverCreated"))
    assert found is None


async def test_list_all_includes_newly_created_organization(test_session):
    repo = OrganizationRepository(test_session)
    name = unique_org_name("ListedOrg")
    await repo.create_organization(name)

    orgs = await repo.list_all()

    assert any(o.name == name for o in orgs)


# --- OrganizationMembershipRepository ---------------------------------------------------

async def test_add_member_succeeds(test_session):
    org_repo = OrganizationRepository(test_session)
    membership_repo = OrganizationMembershipRepository(test_session)
    user = await _make_user(test_session)
    org = await org_repo.create_organization(unique_org_name("AddMemberOrg"))

    membership = await membership_repo.add_member(user.id, org.id)

    assert membership.id is not None
    assert membership.joined_at is not None


async def test_duplicate_membership_is_rejected(test_session):
    org_repo = OrganizationRepository(test_session)
    membership_repo = OrganizationMembershipRepository(test_session)
    user = await _make_user(test_session)
    org = await org_repo.create_organization(unique_org_name("DupMemberOrg"))
    user_id, org_id = user.id, org.id

    await membership_repo.add_member(user_id, org_id)

    with pytest.raises(DuplicateMembershipError):
        await membership_repo.add_member(user_id, org_id)


async def test_remove_member_returns_true_and_removes(test_session):
    org_repo = OrganizationRepository(test_session)
    membership_repo = OrganizationMembershipRepository(test_session)
    user = await _make_user(test_session)
    org = await org_repo.create_organization(unique_org_name("RemoveMemberOrg"))
    user_id, org_id = user.id, org.id
    await membership_repo.add_member(user_id, org_id)

    result = await membership_repo.remove_member(user_id, org_id)

    assert result is True
    assert await membership_repo.is_member(user_id, org_id) is False


async def test_remove_member_nonexistent_returns_false(test_session):
    org_repo = OrganizationRepository(test_session)
    membership_repo = OrganizationMembershipRepository(test_session)
    user = await _make_user(test_session)
    org = await org_repo.create_organization(unique_org_name("NeverJoinedOrg"))

    result = await membership_repo.remove_member(user.id, org.id)

    assert result is False


async def test_is_member_true_after_add(test_session):
    org_repo = OrganizationRepository(test_session)
    membership_repo = OrganizationMembershipRepository(test_session)
    user = await _make_user(test_session)
    org = await org_repo.create_organization(unique_org_name("IsMemberOrg"))
    await membership_repo.add_member(user.id, org.id)

    assert await membership_repo.is_member(user.id, org.id) is True


async def test_is_member_false_for_non_member(test_session):
    org_repo = OrganizationRepository(test_session)
    membership_repo = OrganizationMembershipRepository(test_session)
    user = await _make_user(test_session)
    org = await org_repo.create_organization(unique_org_name("NotMemberOrg"))

    assert await membership_repo.is_member(user.id, org.id) is False


async def test_get_organizations_for_user_returns_all_memberships(test_session):
    org_repo = OrganizationRepository(test_session)
    membership_repo = OrganizationMembershipRepository(test_session)
    user = await _make_user(test_session)
    org_a = await org_repo.create_organization(unique_org_name("MultiOrgA"))
    org_b = await org_repo.create_organization(unique_org_name("MultiOrgB"))

    await membership_repo.add_member(user.id, org_a.id)
    await membership_repo.add_member(user.id, org_b.id)

    orgs = await membership_repo.get_organizations_for_user(user.id)
    org_names = {o.name for o in orgs}

    assert org_a.name in org_names
    assert org_b.name in org_names


async def test_get_organizations_for_user_with_no_memberships_returns_empty_list(test_session):
    membership_repo = OrganizationMembershipRepository(test_session)
    user = await _make_user(test_session)

    orgs = await membership_repo.get_organizations_for_user(user.id)

    assert orgs == []


async def test_get_members_for_organization_returns_expected_rows(test_session):
    org_repo = OrganizationRepository(test_session)
    membership_repo = OrganizationMembershipRepository(test_session)
    user = await _make_user(test_session)
    org = await org_repo.create_organization(unique_org_name("MembersListOrg"))
    await membership_repo.add_member(user.id, org.id)

    members = await membership_repo.get_members_for_organization(org.id)

    assert len(members) == 1
    assert members[0].user_id == user.id
    assert members[0].email == user.email
    assert members[0].joined_at is not None


async def test_get_members_for_organization_with_no_members_returns_empty_list(test_session):
    org_repo = OrganizationRepository(test_session)
    membership_repo = OrganizationMembershipRepository(test_session)
    org = await org_repo.create_organization(unique_org_name("EmptyOrg"))

    members = await membership_repo.get_members_for_organization(org.id)

    assert members == []
