"""
Integration tests for the Phase 2.1 RBAC schema -- Role, Permission,
role_permissions, UserRole -- run against real Postgres.

These prove the actual SQL-level guarantees (unique constraints, cascade
deletes) hold, and that the seed migration produced exactly the expected
default roles/permissions/mappings. No AuthorizationService exists yet
(that's Phase 2.3) -- this file is schema-level only, matching the scope of
Phase 2.1.

IMPORTANT: every role/permission this file creates uses a uuid-suffixed
unique name (mirroring the unique_email() pattern from
test_repositories.py in Phase 1). roles/permissions are seed/reference data
that intentionally survives the test_session fixture's truncate (see
conftest.py) so that seed-data tests can rely on it -- which means any
test-created role/permission with a FIXED name would collide with itself
on a second test run. Unique names sidestep that without needing to touch
the shared truncate behavior.
"""

import uuid

import pytest
from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError

from app.domain.models import Permission, Role, UserRole
from app.domain.models.role_permission import role_permissions


def unique_role_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def unique_resource(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


async def _make_user(session, email=None):
    from app.domain.models import User
    email = email or f"rbacuser-{uuid.uuid4().hex[:8]}@example.com"
    user = User(email=email, password_hash="fake-hash-for-testing")
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


# --- Role ---------------------------------------------------

async def test_role_can_be_created_with_defaults(test_session):
    role = Role(name=unique_role_name("TestRole"), description="A role for testing")
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)

    assert role.id is not None
    assert role.is_system_role is False
    assert role.created_at is not None


async def test_role_name_unique_constraint_enforced(test_session):
    name = unique_role_name("DuplicateRole")
    test_session.add(Role(name=name))
    await test_session.commit()

    test_session.add(Role(name=name))
    with pytest.raises(IntegrityError):
        await test_session.commit()
    await test_session.rollback()


# --- Permission ---------------------------------------------------

async def test_permission_can_be_created(test_session):
    resource = unique_resource("widget")
    permission = Permission(resource=resource, action="create", description="Create widgets")
    test_session.add(permission)
    await test_session.commit()
    await test_session.refresh(permission)

    assert permission.id is not None


async def test_permission_resource_action_unique_constraint_enforced(test_session):
    resource = unique_resource("widget")
    test_session.add(Permission(resource=resource, action="delete"))
    await test_session.commit()

    test_session.add(Permission(resource=resource, action="delete"))
    with pytest.raises(IntegrityError):
        await test_session.commit()
    await test_session.rollback()


async def test_same_resource_different_action_is_allowed(test_session):
    """Sanity check that the unique constraint is on the (resource, action)
    PAIR, not on resource alone."""
    resource = unique_resource("widget")
    test_session.add(Permission(resource=resource, action="view"))
    test_session.add(Permission(resource=resource, action="edit"))
    await test_session.commit()  # must not raise


# --- role_permissions ---------------------------------------------------

async def test_permission_can_be_attached_to_role(test_session):
    role = Role(name=unique_role_name("AttachTestRole"))
    permission = Permission(resource=unique_resource("widget"), action="attach-test")
    test_session.add_all([role, permission])
    await test_session.commit()
    await test_session.refresh(role)
    await test_session.refresh(permission)

    await test_session.execute(
        insert(role_permissions).values(role_id=role.id, permission_id=permission.id)
    )
    await test_session.commit()

    result = await test_session.execute(
        select(role_permissions).where(role_permissions.c.role_id == role.id)
    )
    rows = result.fetchall()
    assert len(rows) == 1
    assert rows[0].permission_id == permission.id


async def test_deleting_role_cascades_role_permissions(test_session):
    role = Role(name=unique_role_name("CascadeDeleteRole"))
    permission = Permission(resource=unique_resource("widget"), action="cascade-test")
    test_session.add_all([role, permission])
    await test_session.commit()
    await test_session.refresh(role)
    await test_session.refresh(permission)

    await test_session.execute(
        insert(role_permissions).values(role_id=role.id, permission_id=permission.id)
    )
    await test_session.commit()

    await test_session.delete(role)
    await test_session.commit()

    result = await test_session.execute(
        select(role_permissions).where(role_permissions.c.permission_id == permission.id)
    )
    assert result.fetchall() == []


async def test_deleting_permission_cascades_role_permissions(test_session):
    role = Role(name=unique_role_name("PermCascadeRole"))
    permission = Permission(resource=unique_resource("widget"), action="perm-cascade-test")
    test_session.add_all([role, permission])
    await test_session.commit()
    await test_session.refresh(role)
    await test_session.refresh(permission)

    await test_session.execute(
        insert(role_permissions).values(role_id=role.id, permission_id=permission.id)
    )
    await test_session.commit()

    await test_session.delete(permission)
    await test_session.commit()

    result = await test_session.execute(
        select(role_permissions).where(role_permissions.c.role_id == role.id)
    )
    assert result.fetchall() == []


# --- UserRole ---------------------------------------------------

async def test_user_role_can_be_assigned(test_session):
    user = await _make_user(test_session)
    role = Role(name=unique_role_name("AssignTestRole"))
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)

    user_role = UserRole(user_id=user.id, role_id=role.id)
    test_session.add(user_role)
    await test_session.commit()
    await test_session.refresh(user_role)

    assert user_role.id is not None
    assert user_role.assigned_at is not None


async def test_duplicate_user_role_assignment_rejected(test_session):
    user = await _make_user(test_session)
    role = Role(name=unique_role_name("DupRoleTest"))
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)

    test_session.add(UserRole(user_id=user.id, role_id=role.id))
    await test_session.commit()

    test_session.add(UserRole(user_id=user.id, role_id=role.id))
    with pytest.raises(IntegrityError):
        await test_session.commit()
    await test_session.rollback()


async def test_deleting_user_cascades_user_roles(test_session):
    user = await _make_user(test_session)
    role = Role(name=unique_role_name("UserCascadeRole"))
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)

    user_role = UserRole(user_id=user.id, role_id=role.id)
    test_session.add(user_role)
    await test_session.commit()
    user_role_id = user_role.id

    await test_session.delete(user)
    await test_session.commit()

    result = await test_session.execute(select(UserRole).where(UserRole.id == user_role_id))
    assert result.scalar_one_or_none() is None


async def test_deleting_role_cascades_user_roles(test_session):
    user = await _make_user(test_session)
    role = Role(name=unique_role_name("RoleDeleteCascadeRole"))
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)

    user_role = UserRole(user_id=user.id, role_id=role.id)
    test_session.add(user_role)
    await test_session.commit()
    user_role_id = user_role.id

    await test_session.delete(role)
    await test_session.commit()

    result = await test_session.execute(select(UserRole).where(UserRole.id == user_role_id))
    assert result.scalar_one_or_none() is None


# --- Seed data ---------------------------------------------------

async def test_seed_migration_created_four_default_roles(test_session):
    result = await test_session.execute(select(Role.name).where(Role.is_system_role == True))  # noqa: E712
    names = {row[0] for row in result.fetchall()}
    assert {"Admin", "Manager", "Developer", "Intern"}.issubset(names)


async def test_seed_migration_created_expected_permission_catalog(test_session):
    result = await test_session.execute(select(Permission.resource, Permission.action))
    pairs = {(row[0], row[1]) for row in result.fetchall()}
    expected = {
        ("document", "view"),
        ("document", "edit"),
        ("document", "delete"),
        ("role", "manage"),
        ("user", "manage"),
    }
    assert expected.issubset(pairs)


async def test_seed_migration_admin_role_has_all_permissions(test_session):
    """"All permissions" as of the latest seed migration that grants any to
    Admin -- Phase 3.4 added organization:manage (see
    97122fa13dcc_seed_organization_manage_permission.py) on top of the
    original five from this migration."""
    result = await test_session.execute(
        select(Permission.resource, Permission.action)
        .join(role_permissions, role_permissions.c.permission_id == Permission.id)
        .join(Role, Role.id == role_permissions.c.role_id)
        .where(Role.name == "Admin")
    )
    admin_permissions = {(row[0], row[1]) for row in result.fetchall()}
    assert admin_permissions == {
        ("document", "view"),
        ("document", "edit"),
        ("document", "delete"),
        ("role", "manage"),
        ("user", "manage"),
        ("organization", "manage"),
    }


async def test_seed_migration_intern_role_has_only_document_view(test_session):
    result = await test_session.execute(
        select(Permission.resource, Permission.action)
        .join(role_permissions, role_permissions.c.permission_id == Permission.id)
        .join(Role, Role.id == role_permissions.c.role_id)
        .where(Role.name == "Intern")
    )
    intern_permissions = {(row[0], row[1]) for row in result.fetchall()}
    assert intern_permissions == {("document", "view")}


async def test_seed_migration_organization_manage_permission_granted_only_to_admin(test_session):
    """Phase 3.4 addition (97122fa13dcc): organization:manage exists and
    is granted to Admin only, not any of the other three default roles."""
    result = await test_session.execute(
        select(Role.name)
        .join(role_permissions, role_permissions.c.role_id == Role.id)
        .join(Permission, Permission.id == role_permissions.c.permission_id)
        .where(Permission.resource == "organization", Permission.action == "manage")
    )
    granted_to = {row[0] for row in result.fetchall()}
    assert granted_to == {"Admin"}
