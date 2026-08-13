"""
Integration tests for the Phase 3 multi-tenancy schema -- Organization,
OrganizationMembership, and the new organization_id scoping columns on
Role and UserRole -- run against real Postgres.

Same conventions as test_rbac_models.py: every organization/role/user this
file creates uses a uuid-suffixed unique name, since organizations (like
roles and permissions) are reference data that intentionally survives the
test_session fixture's truncate (see conftest.py) -- a fixed name would
collide with itself on a second run.
"""

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.domain.models import Organization, OrganizationMembership, Role, UserRole


def unique_org_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def unique_role_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


async def _make_user(session, email=None):
    from app.domain.models import User

    email = email or f"org-model-{uuid.uuid4().hex[:8]}@example.com"
    user = User(email=email, password_hash="fake-hash-for-testing")
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def _make_org(session, name=None):
    org = Organization(name=name or unique_org_name("TestOrg"))
    session.add(org)
    await session.commit()
    await session.refresh(org)
    return org


# --- Organization ---------------------------------------------------

async def test_organization_can_be_created(test_session):
    org = Organization(name=unique_org_name("Acme"))
    test_session.add(org)
    await test_session.commit()
    await test_session.refresh(org)

    assert org.id is not None
    assert org.created_at is not None


async def test_organization_name_unique_constraint_enforced(test_session):
    name = unique_org_name("DuplicateOrg")
    test_session.add(Organization(name=name))
    await test_session.commit()

    test_session.add(Organization(name=name))
    with pytest.raises(IntegrityError):
        await test_session.commit()
    await test_session.rollback()


# --- OrganizationMembership ---------------------------------------------------

async def test_membership_can_be_created(test_session):
    user = await _make_user(test_session)
    org = await _make_org(test_session)

    membership = OrganizationMembership(user_id=user.id, organization_id=org.id)
    test_session.add(membership)
    await test_session.commit()
    await test_session.refresh(membership)

    assert membership.id is not None
    assert membership.joined_at is not None


async def test_duplicate_membership_rejected(test_session):
    user = await _make_user(test_session)
    org = await _make_org(test_session)
    test_session.add(OrganizationMembership(user_id=user.id, organization_id=org.id))
    await test_session.commit()

    test_session.add(OrganizationMembership(user_id=user.id, organization_id=org.id))
    with pytest.raises(IntegrityError):
        await test_session.commit()
    await test_session.rollback()


async def test_deleting_user_cascades_memberships(test_session):
    user = await _make_user(test_session)
    org = await _make_org(test_session)
    membership = OrganizationMembership(user_id=user.id, organization_id=org.id)
    test_session.add(membership)
    await test_session.commit()
    membership_id = membership.id

    await test_session.delete(user)
    await test_session.commit()

    result = await test_session.execute(
        select(OrganizationMembership).where(OrganizationMembership.id == membership_id)
    )
    assert result.scalar_one_or_none() is None


async def test_deleting_organization_cascades_memberships(test_session):
    user = await _make_user(test_session)
    org = await _make_org(test_session)
    membership = OrganizationMembership(user_id=user.id, organization_id=org.id)
    test_session.add(membership)
    await test_session.commit()
    membership_id = membership.id

    await test_session.delete(org)
    await test_session.commit()

    result = await test_session.execute(
        select(OrganizationMembership).where(OrganizationMembership.id == membership_id)
    )
    assert result.scalar_one_or_none() is None


# --- Role.organization_id ---------------------------------------------------

async def test_role_organization_id_defaults_to_none(test_session):
    role = Role(name=unique_role_name("GlobalRole"))
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)

    assert role.organization_id is None


async def test_role_can_be_scoped_to_an_organization(test_session):
    org = await _make_org(test_session)
    role = Role(name=unique_role_name("OrgScopedRole"), organization_id=org.id)
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)

    assert role.organization_id == org.id


async def test_deleting_organization_cascades_its_scoped_roles(test_session):
    org = await _make_org(test_session)
    role = Role(name=unique_role_name("OrgRoleToDelete"), organization_id=org.id)
    test_session.add(role)
    await test_session.commit()
    role_id = role.id

    await test_session.delete(org)
    await test_session.commit()

    result = await test_session.execute(select(Role).where(Role.id == role_id))
    assert result.scalar_one_or_none() is None


async def test_deleting_organization_does_not_touch_global_roles(test_session):
    org = await _make_org(test_session)
    global_role = Role(name=unique_role_name("StillGlobalRole"))
    test_session.add(global_role)
    await test_session.commit()
    global_role_id = global_role.id

    await test_session.delete(org)
    await test_session.commit()

    result = await test_session.execute(select(Role).where(Role.id == global_role_id))
    assert result.scalar_one_or_none() is not None


# --- UserRole.organization_id ---------------------------------------------------

async def test_user_role_organization_id_defaults_to_none(test_session):
    user = await _make_user(test_session)
    role = Role(name=unique_role_name("GlobalAssignRole"))
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)

    user_role = UserRole(user_id=user.id, role_id=role.id)
    test_session.add(user_role)
    await test_session.commit()
    await test_session.refresh(user_role)

    assert user_role.organization_id is None


async def test_duplicate_global_assignment_still_rejected(test_session):
    """Locks in the exact regression this migration was written to avoid:
    two NULL-organization_id rows for the same (user_id, role_id) must
    still violate a unique constraint, via the partial index, even though
    a plain UNIQUE(user_id, role_id, organization_id) would have silently
    allowed it (NULL is never equal to NULL)."""
    user = await _make_user(test_session)
    role = Role(name=unique_role_name("DupGlobalAssignRole"))
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)

    test_session.add(UserRole(user_id=user.id, role_id=role.id))
    await test_session.commit()

    test_session.add(UserRole(user_id=user.id, role_id=role.id))
    with pytest.raises(IntegrityError):
        await test_session.commit()
    await test_session.rollback()


async def test_same_role_assignable_to_same_user_in_two_different_organizations(test_session):
    user = await _make_user(test_session)
    role = Role(name=unique_role_name("MultiOrgAssignRole"))
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)
    org_a = await _make_org(test_session)
    org_b = await _make_org(test_session)

    test_session.add(UserRole(user_id=user.id, role_id=role.id, organization_id=org_a.id))
    await test_session.commit()

    test_session.add(UserRole(user_id=user.id, role_id=role.id, organization_id=org_b.id))
    await test_session.commit()  # must not raise

    result = await test_session.execute(
        select(UserRole).where(UserRole.user_id == user.id, UserRole.role_id == role.id)
    )
    assert len(result.scalars().all()) == 2


async def test_duplicate_assignment_within_same_organization_rejected(test_session):
    user = await _make_user(test_session)
    role = Role(name=unique_role_name("DupOrgAssignRole"))
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)
    org = await _make_org(test_session)

    test_session.add(UserRole(user_id=user.id, role_id=role.id, organization_id=org.id))
    await test_session.commit()

    test_session.add(UserRole(user_id=user.id, role_id=role.id, organization_id=org.id))
    with pytest.raises(IntegrityError):
        await test_session.commit()
    await test_session.rollback()


async def test_global_and_org_scoped_assignment_of_same_role_can_coexist(test_session):
    """A user can hold the same role both globally AND scoped to one
    specific organization as two distinct rows -- the two partial indexes
    only conflict with rows that share their own NULL-ness, not with each
    other."""
    user = await _make_user(test_session)
    role = Role(name=unique_role_name("GlobalPlusOrgRole"))
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)
    org = await _make_org(test_session)

    test_session.add(UserRole(user_id=user.id, role_id=role.id))
    await test_session.commit()

    test_session.add(UserRole(user_id=user.id, role_id=role.id, organization_id=org.id))
    await test_session.commit()  # must not raise

    result = await test_session.execute(
        select(UserRole).where(UserRole.user_id == user.id, UserRole.role_id == role.id)
    )
    assert len(result.scalars().all()) == 2


async def test_deleting_organization_cascades_its_scoped_assignments_only(test_session):
    user = await _make_user(test_session)
    role = Role(name=unique_role_name("OrgAssignCascadeRole"))
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)
    org = await _make_org(test_session)

    global_assignment = UserRole(user_id=user.id, role_id=role.id)
    test_session.add(global_assignment)
    await test_session.commit()
    global_assignment_id = global_assignment.id

    org_assignment = UserRole(user_id=user.id, role_id=role.id, organization_id=org.id)
    test_session.add(org_assignment)
    await test_session.commit()
    org_assignment_id = org_assignment.id

    await test_session.delete(org)
    await test_session.commit()

    remaining = await test_session.execute(
        select(UserRole.id).where(
            UserRole.id.in_([global_assignment_id, org_assignment_id])
        )
    )
    remaining_ids = {row[0] for row in remaining.fetchall()}
    assert remaining_ids == {global_assignment_id}  # only the global one survives
