"""
Integration tests for RoleRepository, PermissionRepository, and
UserRoleRepository -- real Postgres throughout, no mocked SQLAlchemy.

IMPORTANT pattern used throughout this file: after any call that could
trigger a rollback (duplicate-name / duplicate-assignment detection),
NEVER touch attributes on a previously-loaded ORM object from before that
call -- SQLAlchemy's rollback() expires every attribute of every object in
the session's identity map, including primary keys, and accessing an
expired attribute outside an awaited context raises MissingGreenlet. This
was discovered directly while manually verifying these repositories (see
Phase 2.2 commit message for detail) and is not a bug in the repositories
themselves -- it's a caller-side pattern: capture primitive values (e.g.
`role_id = role.id`) into plain variables *before* any operation that might
roll back, and use only those captured primitives afterward, re-fetching
fresh objects via new awaited queries rather than reusing old references.
"""

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.domain.models.role_permission import role_permissions
from app.repositories.exceptions import (
    DuplicateRoleAssignmentError,
    DuplicateRoleNameError,
    DuplicateRolePermissionError,
)
from app.repositories.organization_repository import OrganizationRepository
from app.repositories.permission_repository import PermissionRepository
from app.repositories.role_repository import RoleRepository
from app.repositories.user_repository import UserRepository
from app.repositories.user_role_repository import UserRoleRepository


def unique_role_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def unique_org_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


async def _make_user(session, email=None):
    email = email or f"rbacrepo-{uuid.uuid4().hex[:8]}@example.com"
    return await UserRepository(session).create_user(email=email, password_hash="fake-hash")


# --- RoleRepository ---------------------------------------------------

async def test_create_role_succeeds(test_session):
    repo = RoleRepository(test_session)
    role = await repo.create_role(unique_role_name("NewRole"), "a description")

    assert role.id is not None
    assert role.is_system_role is False
    assert role.description == "a description"


async def test_create_role_without_description(test_session):
    repo = RoleRepository(test_session)
    role = await repo.create_role(unique_role_name("NoDescRole"))
    assert role.description is None


async def test_duplicate_role_name_is_rejected(test_session):
    repo = RoleRepository(test_session)
    name = unique_role_name("DuplicateRole")
    await repo.create_role(name)

    with pytest.raises(DuplicateRoleNameError):
        await repo.create_role(name)


async def test_get_by_id_returns_correct_role(test_session):
    repo = RoleRepository(test_session)
    created = await repo.create_role(unique_role_name("ById"))
    role_id = created.id

    found = await repo.get_by_id(role_id)

    assert found is not None
    assert found.id == role_id


async def test_get_by_id_unknown_returns_none(test_session):
    repo = RoleRepository(test_session)
    found = await repo.get_by_id(uuid.uuid4())
    assert found is None


async def test_get_by_name_returns_correct_role(test_session):
    repo = RoleRepository(test_session)
    name = unique_role_name("ByName")
    await repo.create_role(name)

    found = await repo.get_by_name(name)

    assert found is not None
    assert found.name == name


async def test_get_by_name_is_case_sensitive(test_session):
    """Deliberately different from UserRepository.get_by_email(): role
    names are admin-controlled identifiers, not normalized."""
    repo = RoleRepository(test_session)
    name = unique_role_name("CaseSensitive")
    await repo.create_role(name)

    found = await repo.get_by_name(name.lower())

    assert found is None


async def test_get_by_name_unknown_returns_none(test_session):
    repo = RoleRepository(test_session)
    found = await repo.get_by_name(unique_role_name("NeverCreated"))
    assert found is None


async def test_list_all_includes_seeded_default_roles(test_session):
    repo = RoleRepository(test_session)
    roles = await repo.list_all()
    names = {r.name for r in roles}
    assert {"Admin", "Manager", "Developer", "Intern"}.issubset(names)


async def test_list_all_includes_newly_created_role(test_session):
    repo = RoleRepository(test_session)
    name = unique_role_name("ListedRole")
    await repo.create_role(name)

    roles = await repo.list_all()

    assert any(r.name == name for r in roles)


# --- RoleRepository permission management (Phase 2.3) -----------------

async def test_add_permission_to_role_succeeds(test_session):
    role_repo = RoleRepository(test_session)
    perm_repo = PermissionRepository(test_session)
    role = await role_repo.create_role(unique_role_name("PermAddRole"))
    permission = await perm_repo.get_by_resource_action("document", "view")
    role_id, permission_id = role.id, permission.id

    await role_repo.add_permission(role_id, permission_id)

    result = await test_session.execute(
        select(role_permissions).where(
            role_permissions.c.role_id == role_id,
            role_permissions.c.permission_id == permission_id,
        )
    )
    assert result.fetchone() is not None


async def test_add_permission_duplicate_is_rejected(test_session):
    role_repo = RoleRepository(test_session)
    perm_repo = PermissionRepository(test_session)
    role = await role_repo.create_role(unique_role_name("PermDupRole"))
    permission = await perm_repo.get_by_resource_action("document", "edit")
    role_id, permission_id = role.id, permission.id

    await role_repo.add_permission(role_id, permission_id)

    with pytest.raises(DuplicateRolePermissionError):
        await role_repo.add_permission(role_id, permission_id)


async def test_remove_permission_from_role_succeeds(test_session):
    role_repo = RoleRepository(test_session)
    perm_repo = PermissionRepository(test_session)
    role = await role_repo.create_role(unique_role_name("PermRemoveRole"))
    permission = await perm_repo.get_by_resource_action("document", "delete")
    role_id, permission_id = role.id, permission.id
    await role_repo.add_permission(role_id, permission_id)

    result = await role_repo.remove_permission(role_id, permission_id)

    assert result is True
    remaining = await test_session.execute(
        select(role_permissions).where(
            role_permissions.c.role_id == role_id,
            role_permissions.c.permission_id == permission_id,
        )
    )
    assert remaining.fetchone() is None


async def test_remove_permission_from_role_nonexistent_returns_false(test_session):
    role_repo = RoleRepository(test_session)
    perm_repo = PermissionRepository(test_session)
    role = await role_repo.create_role(unique_role_name("PermNeverAddedRole"))
    permission = await perm_repo.get_by_resource_action("role", "manage")

    result = await role_repo.remove_permission(role.id, permission.id)

    assert result is False


# --- PermissionRepository (read-only) ---------------------------------------------------

async def test_get_by_id_returns_seeded_permission(test_session):
    perm_repo = PermissionRepository(test_session)
    seeded = await perm_repo.get_by_resource_action("document", "view")
    seeded_id = seeded.id

    found = await perm_repo.get_by_id(seeded_id)

    assert found is not None
    assert found.resource == "document"
    assert found.action == "view"


async def test_get_by_id_unknown_returns_none(test_session):
    perm_repo = PermissionRepository(test_session)
    found = await perm_repo.get_by_id(uuid.uuid4())
    assert found is None


async def test_get_by_resource_action_finds_seeded_permission(test_session):
    perm_repo = PermissionRepository(test_session)
    found = await perm_repo.get_by_resource_action("role", "manage")
    assert found is not None


async def test_get_by_resource_action_unknown_returns_none(test_session):
    perm_repo = PermissionRepository(test_session)
    found = await perm_repo.get_by_resource_action("nonexistent", "action")
    assert found is None


async def test_list_all_returns_full_seeded_catalog(test_session):
    perm_repo = PermissionRepository(test_session)
    permissions = await perm_repo.list_all()
    pairs = {(p.resource, p.action) for p in permissions}
    expected = {
        ("document", "view"),
        ("document", "edit"),
        ("document", "delete"),
        ("role", "manage"),
        ("user", "manage"),
    }
    assert expected.issubset(pairs)


async def test_permission_repository_has_no_create_method(test_session):
    """Confirms the deliberate design decision: permissions are seeded via
    migration only, not created dynamically through this repository."""
    perm_repo = PermissionRepository(test_session)
    assert not hasattr(perm_repo, "create_permission")
    assert not hasattr(perm_repo, "create")


# --- UserRoleRepository ---------------------------------------------------

async def test_assign_role_to_user_succeeds(test_session):
    role_repo = RoleRepository(test_session)
    ur_repo = UserRoleRepository(test_session)
    user = await _make_user(test_session)
    role = await role_repo.create_role(unique_role_name("AssignRole"))

    user_role = await ur_repo.assign(user.id, role.id)

    assert user_role.id is not None
    assert user_role.assigned_at is not None


async def test_duplicate_assignment_is_rejected(test_session):
    role_repo = RoleRepository(test_session)
    ur_repo = UserRoleRepository(test_session)
    user = await _make_user(test_session)
    role = await role_repo.create_role(unique_role_name("DupAssignRole"))
    user_id, role_id = user.id, role.id

    await ur_repo.assign(user_id, role_id)

    with pytest.raises(DuplicateRoleAssignmentError):
        await ur_repo.assign(user_id, role_id)


async def test_revoke_removes_assignment_and_returns_true(test_session):
    role_repo = RoleRepository(test_session)
    ur_repo = UserRoleRepository(test_session)
    user = await _make_user(test_session)
    role = await role_repo.create_role(unique_role_name("RevokeRole"))
    user_id, role_id = user.id, role.id
    await ur_repo.assign(user_id, role_id)

    result = await ur_repo.revoke(user_id, role_id)

    assert result is True
    roles_after = await ur_repo.get_roles_for_user(user_id)
    assert role_id not in {r.id for r in roles_after}


async def test_revoke_nonexistent_assignment_returns_false(test_session):
    role_repo = RoleRepository(test_session)
    ur_repo = UserRoleRepository(test_session)
    user = await _make_user(test_session)
    role = await role_repo.create_role(unique_role_name("NeverAssignedRole"))

    result = await ur_repo.revoke(user.id, role.id)

    assert result is False


async def test_revoke_is_safe_to_call_twice(test_session):
    role_repo = RoleRepository(test_session)
    ur_repo = UserRoleRepository(test_session)
    user = await _make_user(test_session)
    role = await role_repo.create_role(unique_role_name("DoubleRevokeRole"))
    user_id, role_id = user.id, role.id
    await ur_repo.assign(user_id, role_id)

    first = await ur_repo.revoke(user_id, role_id)
    second = await ur_repo.revoke(user_id, role_id)

    assert first is True
    assert second is False


async def test_get_roles_for_user_returns_all_assigned_roles(test_session):
    role_repo = RoleRepository(test_session)
    ur_repo = UserRoleRepository(test_session)
    user = await _make_user(test_session)
    role_a = await role_repo.create_role(unique_role_name("MultiRoleA"))
    role_b = await role_repo.create_role(unique_role_name("MultiRoleB"))
    user_id = user.id

    await ur_repo.assign(user_id, role_a.id)
    await ur_repo.assign(user_id, role_b.id)

    roles = await ur_repo.get_roles_for_user(user_id)
    role_names = {r.name for r in roles}

    assert role_a.name in role_names
    assert role_b.name in role_names


async def test_get_roles_for_user_with_no_roles_returns_empty_list(test_session):
    ur_repo = UserRoleRepository(test_session)
    user = await _make_user(test_session)

    roles = await ur_repo.get_roles_for_user(user.id)

    assert roles == []


async def test_get_permissions_for_user_resolves_seeded_role_permissions(test_session):
    """A user assigned the seeded 'Intern' role should resolve to exactly
    that role's permission set (document:view only)."""
    role_repo = RoleRepository(test_session)
    ur_repo = UserRoleRepository(test_session)
    user = await _make_user(test_session)
    intern_role = await role_repo.get_by_name("Intern")

    await ur_repo.assign(user.id, intern_role.id)
    permissions = await ur_repo.get_permissions_for_user(user.id)
    pairs = {(p.resource, p.action) for p in permissions}

    assert pairs == {("document", "view")}


async def test_get_permissions_for_user_unions_permissions_across_multiple_roles(test_session):
    """Assigning both Intern and Developer should union their permission
    sets: {document:view} union {document:view, document:edit}."""
    role_repo = RoleRepository(test_session)
    ur_repo = UserRoleRepository(test_session)
    user = await _make_user(test_session)
    intern_role = await role_repo.get_by_name("Intern")
    developer_role = await role_repo.get_by_name("Developer")

    await ur_repo.assign(user.id, intern_role.id)
    await ur_repo.assign(user.id, developer_role.id)
    permissions = await ur_repo.get_permissions_for_user(user.id)
    pairs = {(p.resource, p.action) for p in permissions}

    assert pairs == {("document", "view"), ("document", "edit")}


async def test_get_permissions_for_user_deduplicates_overlapping_permissions(test_session):
    """Both Manager and Developer grant document:view -- the union must
    not contain a duplicate entry for it."""
    role_repo = RoleRepository(test_session)
    ur_repo = UserRoleRepository(test_session)
    user = await _make_user(test_session)
    manager_role = await role_repo.get_by_name("Manager")
    developer_role = await role_repo.get_by_name("Developer")

    await ur_repo.assign(user.id, manager_role.id)
    await ur_repo.assign(user.id, developer_role.id)
    permissions = await ur_repo.get_permissions_for_user(user.id)

    resource_action_pairs = [(p.resource, p.action) for p in permissions]
    assert len(resource_action_pairs) == len(set(resource_action_pairs))  # no duplicates
    assert ("document", "view") in resource_action_pairs  # confirm the overlap actually existed


async def test_get_permissions_for_user_with_no_roles_returns_empty_list(test_session):
    ur_repo = UserRoleRepository(test_session)
    user = await _make_user(test_session)

    permissions = await ur_repo.get_permissions_for_user(user.id)

    assert permissions == []


async def test_revoking_role_immediately_removes_its_permissions(test_session):
    """Locks in the 'no caching, revocation takes effect immediately'
    requirement at the repository layer -- AuthorizationService (Phase 2.3)
    will rely on this query always reflecting current state."""
    role_repo = RoleRepository(test_session)
    ur_repo = UserRoleRepository(test_session)
    user = await _make_user(test_session)
    intern_role = await role_repo.get_by_name("Intern")
    user_id, role_id = user.id, intern_role.id

    await ur_repo.assign(user_id, role_id)
    permissions_before = await ur_repo.get_permissions_for_user(user_id)
    assert len(permissions_before) == 1

    await ur_repo.revoke(user_id, role_id)
    permissions_after = await ur_repo.get_permissions_for_user(user_id)

    assert permissions_after == []


async def test_deleting_user_cascades_user_role_assignments(test_session):
    from sqlalchemy import select
    from app.domain.models import UserRole

    role_repo = RoleRepository(test_session)
    ur_repo = UserRoleRepository(test_session)
    user = await _make_user(test_session)
    role = await role_repo.create_role(unique_role_name("CascadeUserRole"))
    user_role = await ur_repo.assign(user.id, role.id)
    user_role_id = user_role.id

    await test_session.delete(user)
    await test_session.commit()

    result = await test_session.execute(select(UserRole).where(UserRole.id == user_role_id))
    assert result.scalar_one_or_none() is None


# --- Organization scoping (Phase 3.2) ---------------------------------------------------

async def test_create_role_organization_id_defaults_to_none(test_session):
    repo = RoleRepository(test_session)
    role = await repo.create_role(unique_role_name("DefaultGlobalRole"))
    assert role.organization_id is None


async def test_create_role_can_be_scoped_to_an_organization(test_session):
    role_repo = RoleRepository(test_session)
    org_repo = OrganizationRepository(test_session)
    org = await org_repo.create_organization(unique_org_name("RoleScopeOrg"))

    role = await role_repo.create_role(unique_role_name("OrgScopedRole"), organization_id=org.id)

    assert role.organization_id == org.id


async def test_assign_with_no_organization_id_is_global_and_visible_without_org_context(
    test_session,
):
    role_repo = RoleRepository(test_session)
    ur_repo = UserRoleRepository(test_session)
    user = await _make_user(test_session)
    role = await role_repo.create_role(unique_role_name("GlobalScopeAssignRole"))

    await ur_repo.assign(user.id, role.id)

    roles = await ur_repo.get_roles_for_user(user.id)
    assert any(r.id == role.id for r in roles)


async def test_org_scoped_assignment_is_not_visible_without_matching_organization_id(
    test_session,
):
    """A role assigned scoped to org A must not show up when resolving the
    user's roles/permissions with no organization context, and must not
    show up under a *different* organization's context either."""
    role_repo = RoleRepository(test_session)
    ur_repo = UserRoleRepository(test_session)
    org_repo = OrganizationRepository(test_session)
    user = await _make_user(test_session)
    role = await role_repo.create_role(unique_role_name("ScopedOnlyRole"))
    org_a = await org_repo.create_organization(unique_org_name("ScopeOrgA"))
    org_b = await org_repo.create_organization(unique_org_name("ScopeOrgB"))

    await ur_repo.assign(user.id, role.id, organization_id=org_a.id)

    no_context_roles = await ur_repo.get_roles_for_user(user.id)
    other_org_roles = await ur_repo.get_roles_for_user(user.id, organization_id=org_b.id)
    same_org_roles = await ur_repo.get_roles_for_user(user.id, organization_id=org_a.id)

    assert role.id not in {r.id for r in no_context_roles}
    assert role.id not in {r.id for r in other_org_roles}
    assert role.id in {r.id for r in same_org_roles}


async def test_get_permissions_for_user_includes_global_plus_org_scoped_for_given_org(
    test_session,
):
    role_repo = RoleRepository(test_session)
    ur_repo = UserRoleRepository(test_session)
    org_repo = OrganizationRepository(test_session)
    user = await _make_user(test_session)
    intern_role = await role_repo.get_by_name("Intern")  # seeded: document:view
    developer_role = await role_repo.get_by_name("Developer")  # seeded: document:view, edit
    org = await org_repo.create_organization(unique_org_name("PermScopeOrg"))

    await ur_repo.assign(user.id, intern_role.id)  # global
    await ur_repo.assign(user.id, developer_role.id, organization_id=org.id)  # org-scoped

    global_only = await ur_repo.get_permissions_for_user(user.id)
    with_org_context = await ur_repo.get_permissions_for_user(user.id, organization_id=org.id)

    assert {(p.resource, p.action) for p in global_only} == {("document", "view")}
    assert {(p.resource, p.action) for p in with_org_context} == {
        ("document", "view"),
        ("document", "edit"),
    }


async def test_revoke_requires_matching_organization_id(test_session):
    """Revoking with no organization_id must not remove an org-scoped
    assignment, and vice versa -- revoke() is an exact-row match, not the
    global-plus-scoped union reads use."""
    role_repo = RoleRepository(test_session)
    ur_repo = UserRoleRepository(test_session)
    org_repo = OrganizationRepository(test_session)
    user = await _make_user(test_session)
    role = await role_repo.create_role(unique_role_name("RevokeScopeRole"))
    org = await org_repo.create_organization(unique_org_name("RevokeScopeOrg"))
    user_id, role_id, org_id = user.id, role.id, org.id
    await ur_repo.assign(user_id, role_id, organization_id=org_id)

    wrong_scope_result = await ur_repo.revoke(user_id, role_id)  # no org_id -- wrong row
    correct_scope_result = await ur_repo.revoke(user_id, role_id, organization_id=org_id)

    assert wrong_scope_result is False
    assert correct_scope_result is True
