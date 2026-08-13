"""
Integration tests for /v1/authorize, /v1/roles, and /v1/users/*/roles|
permissions -- real Postgres, real FastAPI app, real HTTP calls via
httpx.AsyncClient, exactly like test_auth_api.py. AuthorizationService is
NOT mocked here.

Bootstrapping an admin user for these tests deliberately does NOT go
through the API -- it assigns the seeded "Admin" role directly via
UserRoleRepository, mirroring the documented Phase 2.1 decision that the
first Admin assignment is a manual step outside the API (see the seed
migration's docstring). There is no bootstrap-admin endpoint to test
against because there deliberately isn't one.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.domain.models import Permission, Role
from app.repositories.role_repository import RoleRepository
from app.repositories.user_role_repository import UserRoleRepository


def unique_email(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


async def _register_and_login(client, prefix):
    email = unique_email(prefix)
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})
    login_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )
    body = login_response.json()
    return body["access_token"], email


def _auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _get_user_id(test_engine, email: str) -> uuid.UUID:
    from app.domain.models import User

    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        result = await session.execute(select(User.id).where(User.email == email.lower()))
        return result.scalar_one()


async def _get_permission_id(test_engine, resource: str, action: str) -> uuid.UUID:
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        result = await session.execute(
            select(Permission.id).where(
                Permission.resource == resource, Permission.action == action
            )
        )
        return result.scalar_one()


async def _grant_admin_role(test_engine, user_id: uuid.UUID) -> None:
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        role_repo = RoleRepository(session)
        ur_repo = UserRoleRepository(session)
        admin_role = await role_repo.get_by_name("Admin")
        await ur_repo.assign(user_id, admin_role.id)


async def _make_admin(client, test_engine, prefix):
    token, email = await _register_and_login(client, prefix)
    user_id = await _get_user_id(test_engine, email)
    await _grant_admin_role(test_engine, user_id)
    return token, user_id


# --- POST /v1/authorize ---------------------------------------------------

async def test_authorize_allows_when_user_has_permission(client, test_engine):
    token, _ = await _make_admin(client, test_engine, "authz-allow")

    response = await client.post(
        "/v1/authorize",
        json={"resource": "document", "action": "view"},
        headers=_auth_header(token),
    )

    assert response.status_code == 200
    assert response.json() == {"allowed": True, "resource": "document", "action": "view"}


async def test_authorize_denies_when_user_has_no_roles(client):
    token, _ = await _register_and_login(client, "authz-deny")

    response = await client.post(
        "/v1/authorize",
        json={"resource": "document", "action": "view"},
        headers=_auth_header(token),
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is False


async def test_authorize_denies_unrecognized_permission_without_erroring(client, test_engine):
    """A (resource, action) pair that isn't in the seeded permission
    catalog at all must be denied silently -- not a 4xx/5xx -- even for an
    Admin."""
    token, _ = await _make_admin(client, test_engine, "authz-unknown")

    response = await client.post(
        "/v1/authorize",
        json={"resource": "spaceship", "action": "launch"},
        headers=_auth_header(token),
    )

    assert response.status_code == 200
    assert response.json()["allowed"] is False


async def test_authorize_requires_authentication(client):
    response = await client.post(
        "/v1/authorize", json={"resource": "document", "action": "view"}
    )
    assert response.status_code == 401


# --- POST /v1/roles ---------------------------------------------------

async def test_create_role_requires_role_manage_permission(client):
    token, _ = await _register_and_login(client, "createrole-noperm")

    response = await client.post(
        "/v1/roles",
        json={"name": f"Auditor-{uuid.uuid4().hex[:8]}"},
        headers=_auth_header(token),
    )

    assert response.status_code == 403


async def test_create_role_succeeds_for_admin(client, test_engine):
    token, _ = await _make_admin(client, test_engine, "createrole-admin")
    name = f"Auditor-{uuid.uuid4().hex[:8]}"

    response = await client.post(
        "/v1/roles", json={"name": name, "description": "reads logs"}, headers=_auth_header(token)
    )

    assert response.status_code == 201
    body = response.json()
    assert body["name"] == name
    assert body["description"] == "reads logs"
    assert body["is_system_role"] is False


async def test_create_role_duplicate_name_returns_409(client, test_engine):
    token, _ = await _make_admin(client, test_engine, "createrole-dup")
    name = f"Auditor-{uuid.uuid4().hex[:8]}"
    await client.post("/v1/roles", json={"name": name}, headers=_auth_header(token))

    response = await client.post("/v1/roles", json={"name": name}, headers=_auth_header(token))

    assert response.status_code == 409


# --- POST/DELETE /v1/roles/{role_id}/permissions ---------------------------------------------------

async def test_assign_permission_to_role_succeeds(client, test_engine):
    token, _ = await _make_admin(client, test_engine, "assignperm")
    role_name = f"PermTestRole-{uuid.uuid4().hex[:8]}"
    create_response = await client.post(
        "/v1/roles", json={"name": role_name}, headers=_auth_header(token)
    )
    role_id = create_response.json()["id"]
    permission_id = await _get_permission_id(test_engine, "document", "view")

    response = await client.post(
        f"/v1/roles/{role_id}/permissions",
        json={"permission_id": str(permission_id)},
        headers=_auth_header(token),
    )

    assert response.status_code == 204


async def test_assign_permission_to_role_unknown_role_returns_404(client, test_engine):
    token, _ = await _make_admin(client, test_engine, "assignperm-norole")
    permission_id = await _get_permission_id(test_engine, "document", "view")

    response = await client.post(
        f"/v1/roles/{uuid.uuid4()}/permissions",
        json={"permission_id": str(permission_id)},
        headers=_auth_header(token),
    )

    assert response.status_code == 404


async def test_assign_permission_to_role_unknown_permission_returns_404(client, test_engine):
    token, _ = await _make_admin(client, test_engine, "assignperm-noperm")
    role_name = f"PermTestRole2-{uuid.uuid4().hex[:8]}"
    create_response = await client.post(
        "/v1/roles", json={"name": role_name}, headers=_auth_header(token)
    )
    role_id = create_response.json()["id"]

    response = await client.post(
        f"/v1/roles/{role_id}/permissions",
        json={"permission_id": str(uuid.uuid4())},
        headers=_auth_header(token),
    )

    assert response.status_code == 404


async def test_assign_permission_to_role_duplicate_returns_409(client, test_engine):
    token, _ = await _make_admin(client, test_engine, "assignperm-dup")
    role_name = f"PermTestRole3-{uuid.uuid4().hex[:8]}"
    create_response = await client.post(
        "/v1/roles", json={"name": role_name}, headers=_auth_header(token)
    )
    role_id = create_response.json()["id"]
    permission_id = await _get_permission_id(test_engine, "document", "edit")
    await client.post(
        f"/v1/roles/{role_id}/permissions",
        json={"permission_id": str(permission_id)},
        headers=_auth_header(token),
    )

    response = await client.post(
        f"/v1/roles/{role_id}/permissions",
        json={"permission_id": str(permission_id)},
        headers=_auth_header(token),
    )

    assert response.status_code == 409


async def test_remove_permission_from_role_succeeds(client, test_engine):
    token, _ = await _make_admin(client, test_engine, "removeperm")
    role_name = f"PermTestRole4-{uuid.uuid4().hex[:8]}"
    create_response = await client.post(
        "/v1/roles", json={"name": role_name}, headers=_auth_header(token)
    )
    role_id = create_response.json()["id"]
    permission_id = await _get_permission_id(test_engine, "document", "delete")
    await client.post(
        f"/v1/roles/{role_id}/permissions",
        json={"permission_id": str(permission_id)},
        headers=_auth_header(token),
    )

    response = await client.delete(
        f"/v1/roles/{role_id}/permissions/{permission_id}", headers=_auth_header(token)
    )

    assert response.status_code == 204


async def test_remove_permission_from_role_unknown_role_returns_404(client, test_engine):
    token, _ = await _make_admin(client, test_engine, "removeperm-norole")

    response = await client.delete(
        f"/v1/roles/{uuid.uuid4()}/permissions/{uuid.uuid4()}", headers=_auth_header(token)
    )

    assert response.status_code == 404


async def test_remove_permission_from_role_not_attached_is_idempotent(client, test_engine):
    """Removing a permission the role never had is a 204, not a 404 or 409
    -- matches AuthorizationService.remove_permission_from_role()'s
    idempotent contract."""
    token, _ = await _make_admin(client, test_engine, "removeperm-neverattached")
    role_name = f"PermTestRole5-{uuid.uuid4().hex[:8]}"
    create_response = await client.post(
        "/v1/roles", json={"name": role_name}, headers=_auth_header(token)
    )
    role_id = create_response.json()["id"]
    permission_id = await _get_permission_id(test_engine, "role", "manage")

    response = await client.delete(
        f"/v1/roles/{role_id}/permissions/{permission_id}", headers=_auth_header(token)
    )

    assert response.status_code == 204


# --- GET /v1/users/me/permissions ---------------------------------------------------

async def test_get_my_permissions_returns_own_permissions(client, test_engine):
    token, _ = await _make_admin(client, test_engine, "mypermissions")

    response = await client.get("/v1/users/me/permissions", headers=_auth_header(token))

    assert response.status_code == 200
    pairs = {(p["resource"], p["action"]) for p in response.json()}
    assert ("document", "view") in pairs  # Admin role grants this


async def test_get_my_permissions_requires_authentication(client):
    response = await client.get("/v1/users/me/permissions")
    assert response.status_code == 401


# --- POST/DELETE /v1/users/{user_id}/roles ---------------------------------------------------

async def test_assign_role_to_user_succeeds(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "assignrole-admin")
    _, target_email = await _register_and_login(client, "assignrole-target")
    target_user_id = await _get_user_id(test_engine, target_email)
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        role = await RoleRepository(session).get_by_name("Intern")
        role_id = role.id

    response = await client.post(
        f"/v1/users/{target_user_id}/roles",
        json={"role_id": str(role_id)},
        headers=_auth_header(admin_token),
    )

    assert response.status_code == 204


async def test_assign_role_to_user_unknown_role_returns_404(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "assignrole-norole")
    _, target_email = await _register_and_login(client, "assignrole-target2")
    target_user_id = await _get_user_id(test_engine, target_email)

    response = await client.post(
        f"/v1/users/{target_user_id}/roles",
        json={"role_id": str(uuid.uuid4())},
        headers=_auth_header(admin_token),
    )

    assert response.status_code == 404


async def test_assign_role_to_user_duplicate_returns_409(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "assignrole-dup")
    _, target_email = await _register_and_login(client, "assignrole-target3")
    target_user_id = await _get_user_id(test_engine, target_email)
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        role = await RoleRepository(session).get_by_name("Developer")
        role_id = role.id
    await client.post(
        f"/v1/users/{target_user_id}/roles",
        json={"role_id": str(role_id)},
        headers=_auth_header(admin_token),
    )

    response = await client.post(
        f"/v1/users/{target_user_id}/roles",
        json={"role_id": str(role_id)},
        headers=_auth_header(admin_token),
    )

    assert response.status_code == 409


async def test_assign_role_to_user_requires_user_manage_permission(client, test_engine):
    _, target_email = await _register_and_login(client, "assignrole-noauth-target")
    target_user_id = await _get_user_id(test_engine, target_email)
    no_perm_token, _ = await _register_and_login(client, "assignrole-noauth-caller")
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        role = await RoleRepository(session).get_by_name("Intern")
        role_id = role.id

    response = await client.post(
        f"/v1/users/{target_user_id}/roles",
        json={"role_id": str(role_id)},
        headers=_auth_header(no_perm_token),
    )

    assert response.status_code == 403


async def test_revoke_role_from_user_succeeds_and_removes_permissions(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "revokerole-admin")
    target_token, target_email = await _register_and_login(client, "revokerole-target")
    target_user_id = await _get_user_id(test_engine, target_email)
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        role = await RoleRepository(session).get_by_name("Intern")
        role_id = role.id
    await client.post(
        f"/v1/users/{target_user_id}/roles",
        json={"role_id": str(role_id)},
        headers=_auth_header(admin_token),
    )
    before = await client.get("/v1/users/me/permissions", headers=_auth_header(target_token))
    assert len(before.json()) == 1

    response = await client.delete(
        f"/v1/users/{target_user_id}/roles/{role_id}", headers=_auth_header(admin_token)
    )

    assert response.status_code == 204
    after = await client.get("/v1/users/me/permissions", headers=_auth_header(target_token))
    assert after.json() == []


async def test_revoke_role_from_user_nonexistent_is_idempotent(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "revokerole-idempotent")
    _, target_email = await _register_and_login(client, "revokerole-idempotent-target")
    target_user_id = await _get_user_id(test_engine, target_email)

    response = await client.delete(
        f"/v1/users/{target_user_id}/roles/{uuid.uuid4()}", headers=_auth_header(admin_token)
    )

    assert response.status_code == 204


# --- GET /v1/users/{user_id}/permissions ---------------------------------------------------

async def test_get_user_permissions_requires_user_manage_permission(client, test_engine):
    _, target_email = await _register_and_login(client, "getuserperm-target")
    target_user_id = await _get_user_id(test_engine, target_email)
    no_perm_token, _ = await _register_and_login(client, "getuserperm-caller")

    response = await client.get(
        f"/v1/users/{target_user_id}/permissions", headers=_auth_header(no_perm_token)
    )

    assert response.status_code == 403


async def test_get_user_permissions_succeeds_for_admin(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "getuserperm-admin")
    _, target_email = await _register_and_login(client, "getuserperm-target2")
    target_user_id = await _get_user_id(test_engine, target_email)
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        role = await RoleRepository(session).get_by_name("Manager")
        role_id = role.id
    await client.post(
        f"/v1/users/{target_user_id}/roles",
        json={"role_id": str(role_id)},
        headers=_auth_header(admin_token),
    )

    response = await client.get(
        f"/v1/users/{target_user_id}/permissions", headers=_auth_header(admin_token)
    )

    assert response.status_code == 200
    pairs = {(p["resource"], p["action"]) for p in response.json()}
    assert ("user", "manage") in pairs  # Manager role grants this
