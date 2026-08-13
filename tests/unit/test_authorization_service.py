"""
Unit tests for AuthorizationService.

Repositories are mocked (unittest.mock.AsyncMock) -- no database, no
network. Same shape as tests/unit/test_auth_service.py: this is pure
business logic and should be exhaustively tested at this layer.
"""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.domain.exceptions import (
    PermissionAlreadyAssignedError,
    PermissionNotFoundError,
    RoleAlreadyAssignedError,
    RoleNameAlreadyExistsError,
    RoleNotFoundError,
)
from app.domain.schemas.authorization import AuthorizationDecision
from app.domain.services.authorization_service import AuthorizationService
from app.repositories.exceptions import (
    DuplicateRoleAssignmentError,
    DuplicateRoleNameError,
    DuplicateRolePermissionError,
)


def make_fake_user(is_active=True, user_id=None):
    return SimpleNamespace(id=user_id or uuid.uuid4(), is_active=is_active)


def make_fake_role(role_id=None, name="TestRole", description=None, is_system_role=False):
    return SimpleNamespace(
        id=role_id or uuid.uuid4(),
        name=name,
        description=description,
        is_system_role=is_system_role,
    )


def make_fake_permission(permission_id=None, resource="document", action="view", description=None):
    return SimpleNamespace(
        id=permission_id or uuid.uuid4(),
        resource=resource,
        action=action,
        description=description,
    )


@pytest.fixture
def service():
    user_repo = AsyncMock()
    role_repo = AsyncMock()
    permission_repo = AsyncMock()
    user_role_repo = AsyncMock()
    svc = AuthorizationService(user_repo, role_repo, permission_repo, user_role_repo)
    return svc, user_repo, role_repo, permission_repo, user_role_repo


# --- Module hygiene ---------------------------------------------------

def test_authorize_never_compares_against_a_hardcoded_role_name():
    """Locks in the 'permission-based, not role-name-based' design
    principle directly: the source of authorize() itself must never
    contain one of the seeded default role names as a string literal,
    which is the shape a hardcoded role check would take."""
    import inspect

    from app.domain.services import authorization_service as module

    source = inspect.getsource(module.AuthorizationService.authorize)
    for role_name in ("Admin", "Manager", "Developer", "Intern"):
        assert role_name not in source


# --- authorize() ---------------------------------------------------

async def test_authorize_allows_when_user_has_matching_permission(service):
    svc, user_repo, _, _, user_role_repo = service
    user = make_fake_user()
    user_repo.get_by_id.return_value = user
    user_role_repo.get_permissions_for_user.return_value = [
        make_fake_permission(resource="document", action="view")
    ]

    decision = await svc.authorize(user.id, "document", "view")

    assert decision == AuthorizationDecision(allowed=True, resource="document", action="view")


async def test_authorize_denies_by_default_when_permission_not_granted(service):
    svc, user_repo, _, _, user_role_repo = service
    user = make_fake_user()
    user_repo.get_by_id.return_value = user
    user_role_repo.get_permissions_for_user.return_value = [
        make_fake_permission(resource="document", action="view")
    ]

    decision = await svc.authorize(user.id, "document", "delete")

    assert decision.allowed is False


async def test_authorize_denies_user_with_no_roles(service):
    svc, user_repo, _, _, user_role_repo = service
    user = make_fake_user()
    user_repo.get_by_id.return_value = user
    user_role_repo.get_permissions_for_user.return_value = []

    decision = await svc.authorize(user.id, "document", "view")

    assert decision.allowed is False


async def test_authorize_denies_inactive_user_even_with_matching_permission(service):
    svc, user_repo, _, _, user_role_repo = service
    user = make_fake_user(is_active=False)
    user_repo.get_by_id.return_value = user
    user_role_repo.get_permissions_for_user.return_value = [
        make_fake_permission(resource="document", action="view")
    ]

    decision = await svc.authorize(user.id, "document", "view")

    assert decision.allowed is False


async def test_authorize_inactive_user_never_queries_permissions(service):
    """Deny-inactive-first ordering: no reason to resolve a permission set
    for a user who will be denied regardless of what it contains."""
    svc, user_repo, _, _, user_role_repo = service
    user = make_fake_user(is_active=False)
    user_repo.get_by_id.return_value = user

    await svc.authorize(user.id, "document", "view")

    user_role_repo.get_permissions_for_user.assert_not_called()


async def test_authorize_denies_unknown_user(service):
    svc, user_repo, _, _, user_role_repo = service
    user_repo.get_by_id.return_value = None

    decision = await svc.authorize(uuid.uuid4(), "document", "view")

    assert decision.allowed is False


async def test_authorize_denies_unrecognized_resource_action_pair_without_raising(service):
    """A (resource, action) pair that doesn't exist in the permission
    catalog at all must be denied silently, exactly like one that exists
    but isn't granted -- authorize() must never raise here."""
    svc, user_repo, _, _, user_role_repo = service
    user = make_fake_user()
    user_repo.get_by_id.return_value = user
    user_role_repo.get_permissions_for_user.return_value = [
        make_fake_permission(resource="document", action="view")
    ]

    decision = await svc.authorize(user.id, "spaceship", "launch")

    assert decision.allowed is False


async def test_authorize_reflects_permission_changes_immediately(service):
    """No caching: two consecutive calls must each re-query the
    repository, so a permission granted between calls is picked up on the
    very next check without any invalidation step."""
    svc, user_repo, _, _, user_role_repo = service
    user = make_fake_user()
    user_repo.get_by_id.return_value = user
    user_role_repo.get_permissions_for_user.return_value = []

    first = await svc.authorize(user.id, "document", "view")
    assert first.allowed is False

    user_role_repo.get_permissions_for_user.return_value = [
        make_fake_permission(resource="document", action="view")
    ]
    second = await svc.authorize(user.id, "document", "view")

    assert second.allowed is True
    assert user_role_repo.get_permissions_for_user.call_count == 2


# --- create_role() ---------------------------------------------------

async def test_create_role_success(service):
    svc, _, role_repo, _, _ = service
    role_repo.create_role.return_value = make_fake_role(name="Auditor", description="reads logs")

    result = await svc.create_role("Auditor", "reads logs")

    assert result.name == "Auditor"
    assert result.description == "reads logs"
    assert result.is_system_role is False


async def test_create_role_without_description(service):
    svc, _, role_repo, _, _ = service
    role_repo.create_role.return_value = make_fake_role(name="Auditor", description=None)

    result = await svc.create_role("Auditor")

    assert result.description is None


async def test_create_role_duplicate_name_raises_domain_exception(service):
    svc, _, role_repo, _, _ = service
    role_repo.create_role.side_effect = DuplicateRoleNameError("already exists")

    with pytest.raises(RoleNameAlreadyExistsError):
        await svc.create_role("Admin")


# --- assign_role() ---------------------------------------------------

async def test_assign_role_success(service):
    svc, _, role_repo, _, user_role_repo = service
    role = make_fake_role()
    role_repo.get_by_id.return_value = role
    user_id = uuid.uuid4()

    await svc.assign_role(user_id, role.id)

    user_role_repo.assign.assert_called_once_with(user_id, role.id)


async def test_assign_role_unknown_role_raises_not_found(service):
    svc, _, role_repo, _, user_role_repo = service
    role_repo.get_by_id.return_value = None

    with pytest.raises(RoleNotFoundError):
        await svc.assign_role(uuid.uuid4(), uuid.uuid4())

    user_role_repo.assign.assert_not_called()


async def test_assign_role_duplicate_raises_domain_exception(service):
    svc, _, role_repo, _, user_role_repo = service
    role_repo.get_by_id.return_value = make_fake_role()
    user_role_repo.assign.side_effect = DuplicateRoleAssignmentError("already assigned")

    with pytest.raises(RoleAlreadyAssignedError):
        await svc.assign_role(uuid.uuid4(), uuid.uuid4())


# --- revoke_role() ---------------------------------------------------

async def test_revoke_role_success_returns_true(service):
    svc, _, _, _, user_role_repo = service
    user_role_repo.revoke.return_value = True

    result = await svc.revoke_role(uuid.uuid4(), uuid.uuid4())

    assert result is True


async def test_revoke_role_nonexistent_returns_false_without_raising(service):
    svc, _, _, _, user_role_repo = service
    user_role_repo.revoke.return_value = False

    result = await svc.revoke_role(uuid.uuid4(), uuid.uuid4())

    assert result is False


# --- assign_permission_to_role() ---------------------------------------------------

async def test_assign_permission_to_role_success(service):
    svc, _, role_repo, permission_repo, _ = service
    role = make_fake_role()
    permission = make_fake_permission()
    role_repo.get_by_id.return_value = role
    permission_repo.get_by_id.return_value = permission

    await svc.assign_permission_to_role(role.id, permission.id)

    role_repo.add_permission.assert_called_once_with(role.id, permission.id)


async def test_assign_permission_to_role_unknown_role_raises_not_found(service):
    svc, _, role_repo, permission_repo, _ = service
    role_repo.get_by_id.return_value = None

    with pytest.raises(RoleNotFoundError):
        await svc.assign_permission_to_role(uuid.uuid4(), uuid.uuid4())

    permission_repo.get_by_id.assert_not_called()


async def test_assign_permission_to_role_unknown_permission_raises_not_found(service):
    svc, _, role_repo, permission_repo, _ = service
    role_repo.get_by_id.return_value = make_fake_role()
    permission_repo.get_by_id.return_value = None

    with pytest.raises(PermissionNotFoundError):
        await svc.assign_permission_to_role(uuid.uuid4(), uuid.uuid4())

    role_repo.add_permission.assert_not_called()


async def test_assign_permission_to_role_duplicate_raises_domain_exception(service):
    svc, _, role_repo, permission_repo, _ = service
    role_repo.get_by_id.return_value = make_fake_role()
    permission_repo.get_by_id.return_value = make_fake_permission()
    role_repo.add_permission.side_effect = DuplicateRolePermissionError("already has it")

    with pytest.raises(PermissionAlreadyAssignedError):
        await svc.assign_permission_to_role(uuid.uuid4(), uuid.uuid4())


# --- remove_permission_from_role() ---------------------------------------------------

async def test_remove_permission_from_role_success_returns_true(service):
    svc, _, role_repo, _, _ = service
    role_repo.get_by_id.return_value = make_fake_role()
    role_repo.remove_permission.return_value = True

    result = await svc.remove_permission_from_role(uuid.uuid4(), uuid.uuid4())

    assert result is True


async def test_remove_permission_from_role_unknown_role_raises_not_found(service):
    svc, _, role_repo, _, _ = service
    role_repo.get_by_id.return_value = None

    with pytest.raises(RoleNotFoundError):
        await svc.remove_permission_from_role(uuid.uuid4(), uuid.uuid4())

    role_repo.remove_permission.assert_not_called()


async def test_remove_permission_from_role_not_attached_returns_false(service):
    svc, _, role_repo, _, _ = service
    role_repo.get_by_id.return_value = make_fake_role()
    role_repo.remove_permission.return_value = False

    result = await svc.remove_permission_from_role(uuid.uuid4(), uuid.uuid4())

    assert result is False


# --- get_user_permissions() ---------------------------------------------------

async def test_get_user_permissions_returns_schema_list(service):
    svc, _, _, _, user_role_repo = service
    user_role_repo.get_permissions_for_user.return_value = [
        make_fake_permission(resource="document", action="view"),
        make_fake_permission(resource="document", action="edit"),
    ]

    result = await svc.get_user_permissions(uuid.uuid4())

    pairs = {(p.resource, p.action) for p in result}
    assert pairs == {("document", "view"), ("document", "edit")}


async def test_get_user_permissions_empty_for_user_with_no_roles(service):
    svc, _, _, _, user_role_repo = service
    user_role_repo.get_permissions_for_user.return_value = []

    result = await svc.get_user_permissions(uuid.uuid4())

    assert result == []


async def test_get_user_permissions_reflects_role_revocation_immediately(service):
    """No caching at this layer either: a second call after a role is
    revoked (simulated here by the mock returning a smaller set) must not
    return stale data from the first call."""
    svc, _, _, _, user_role_repo = service
    user_id = uuid.uuid4()
    user_role_repo.get_permissions_for_user.return_value = [
        make_fake_permission(resource="document", action="view")
    ]

    before = await svc.get_user_permissions(user_id)
    assert len(before) == 1

    user_role_repo.get_permissions_for_user.return_value = []
    after = await svc.get_user_permissions(user_id)

    assert after == []
