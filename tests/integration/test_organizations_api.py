"""
Integration tests for /v1/organizations and /v1/users/me/organizations --
real Postgres, real FastAPI, real HTTP calls via httpx.AsyncClient,
exactly like test_authorize_api.py. OrganizationService is NOT mocked
here.

Bootstrapping an admin user (organization:manage) for these tests uses the
same approach as test_authorize_api.py: assign the seeded Admin role
directly via UserRoleRepository, bypassing the API.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.domain.models import User
from app.repositories.role_repository import RoleRepository
from app.repositories.user_role_repository import UserRoleRepository


def unique_email(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


def unique_org_name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


async def _register_and_login(client, prefix):
    email = unique_email(prefix)
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})
    login_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )
    return login_response.json()["access_token"], email


def _auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _get_user_id(test_engine, email: str) -> uuid.UUID:
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        result = await session.execute(select(User.id).where(User.email == email.lower()))
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


# --- POST /v1/organizations ---------------------------------------------------

async def test_create_organization_requires_organization_manage_permission(client):
    token, _ = await _register_and_login(client, "createorg-noperm")

    response = await client.post(
        "/v1/organizations",
        json={"name": unique_org_name("Acme")},
        headers=_auth_header(token),
    )

    assert response.status_code == 403


async def test_create_organization_succeeds_for_admin(client, test_engine):
    token, _ = await _make_admin(client, test_engine, "createorg-admin")
    name = unique_org_name("Acme")

    response = await client.post(
        "/v1/organizations", json={"name": name}, headers=_auth_header(token)
    )

    assert response.status_code == 201
    body = response.json()
    assert body["name"] == name
    assert "id" in body
    assert "created_at" in body


async def test_create_organization_duplicate_name_returns_409(client, test_engine):
    token, _ = await _make_admin(client, test_engine, "createorg-dup")
    name = unique_org_name("Acme")
    await client.post("/v1/organizations", json={"name": name}, headers=_auth_header(token))

    response = await client.post(
        "/v1/organizations", json={"name": name}, headers=_auth_header(token)
    )

    assert response.status_code == 409


# --- POST/DELETE/GET /v1/organizations/{organization_id}/members ---------------------------------------------------

async def test_add_member_succeeds(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "addmember-admin")
    org_response = await client.post(
        "/v1/organizations", json={"name": unique_org_name("MemberOrg")}, headers=_auth_header(admin_token)
    )
    org_id = org_response.json()["id"]
    _, target_email = await _register_and_login(client, "addmember-target")
    target_user_id = await _get_user_id(test_engine, target_email)

    response = await client.post(
        f"/v1/organizations/{org_id}/members",
        json={"user_id": str(target_user_id)},
        headers=_auth_header(admin_token),
    )

    assert response.status_code == 204


async def test_add_member_unknown_organization_returns_404(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "addmember-noorg")
    _, target_email = await _register_and_login(client, "addmember-noorg-target")
    target_user_id = await _get_user_id(test_engine, target_email)

    response = await client.post(
        f"/v1/organizations/{uuid.uuid4()}/members",
        json={"user_id": str(target_user_id)},
        headers=_auth_header(admin_token),
    )

    assert response.status_code == 404


async def test_add_member_unknown_user_returns_404(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "addmember-nouser")
    org_response = await client.post(
        "/v1/organizations", json={"name": unique_org_name("NoUserOrg")}, headers=_auth_header(admin_token)
    )
    org_id = org_response.json()["id"]

    response = await client.post(
        f"/v1/organizations/{org_id}/members",
        json={"user_id": str(uuid.uuid4())},
        headers=_auth_header(admin_token),
    )

    assert response.status_code == 404


async def test_add_member_duplicate_returns_409(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "addmember-dup")
    org_response = await client.post(
        "/v1/organizations", json={"name": unique_org_name("DupMemberOrg")}, headers=_auth_header(admin_token)
    )
    org_id = org_response.json()["id"]
    _, target_email = await _register_and_login(client, "addmember-dup-target")
    target_user_id = await _get_user_id(test_engine, target_email)
    await client.post(
        f"/v1/organizations/{org_id}/members",
        json={"user_id": str(target_user_id)},
        headers=_auth_header(admin_token),
    )

    response = await client.post(
        f"/v1/organizations/{org_id}/members",
        json={"user_id": str(target_user_id)},
        headers=_auth_header(admin_token),
    )

    assert response.status_code == 409


async def test_remove_member_succeeds(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "removemember-admin")
    org_response = await client.post(
        "/v1/organizations", json={"name": unique_org_name("RemoveMemberOrg")}, headers=_auth_header(admin_token)
    )
    org_id = org_response.json()["id"]
    _, target_email = await _register_and_login(client, "removemember-target")
    target_user_id = await _get_user_id(test_engine, target_email)
    await client.post(
        f"/v1/organizations/{org_id}/members",
        json={"user_id": str(target_user_id)},
        headers=_auth_header(admin_token),
    )

    response = await client.delete(
        f"/v1/organizations/{org_id}/members/{target_user_id}", headers=_auth_header(admin_token)
    )

    assert response.status_code == 204


async def test_remove_member_nonexistent_is_idempotent(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "removemember-idempotent")
    org_response = await client.post(
        "/v1/organizations", json={"name": unique_org_name("IdempotentOrg")}, headers=_auth_header(admin_token)
    )
    org_id = org_response.json()["id"]

    response = await client.delete(
        f"/v1/organizations/{org_id}/members/{uuid.uuid4()}", headers=_auth_header(admin_token)
    )

    assert response.status_code == 204


async def test_list_members_returns_added_members(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "listmembers-admin")
    org_response = await client.post(
        "/v1/organizations", json={"name": unique_org_name("ListMembersOrg")}, headers=_auth_header(admin_token)
    )
    org_id = org_response.json()["id"]
    _, target_email = await _register_and_login(client, "listmembers-target")
    target_user_id = await _get_user_id(test_engine, target_email)
    await client.post(
        f"/v1/organizations/{org_id}/members",
        json={"user_id": str(target_user_id)},
        headers=_auth_header(admin_token),
    )

    response = await client.get(
        f"/v1/organizations/{org_id}/members", headers=_auth_header(admin_token)
    )

    assert response.status_code == 200
    emails = {m["email"] for m in response.json()}
    assert target_email in emails


async def test_list_members_unknown_organization_returns_404(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "listmembers-noorg")

    response = await client.get(
        f"/v1/organizations/{uuid.uuid4()}/members", headers=_auth_header(admin_token)
    )

    assert response.status_code == 404


async def test_list_members_requires_organization_manage_permission(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "listmembers-perm-admin")
    org_response = await client.post(
        "/v1/organizations", json={"name": unique_org_name("PermOrg")}, headers=_auth_header(admin_token)
    )
    org_id = org_response.json()["id"]
    no_perm_token, _ = await _register_and_login(client, "listmembers-perm-caller")

    response = await client.get(
        f"/v1/organizations/{org_id}/members", headers=_auth_header(no_perm_token)
    )

    assert response.status_code == 403


# --- GET /v1/users/me/organizations ---------------------------------------------------

async def test_get_my_organizations_returns_joined_organizations(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "myorgs-admin")
    org_response = await client.post(
        "/v1/organizations", json={"name": unique_org_name("MyOrgsOrg")}, headers=_auth_header(admin_token)
    )
    org_id = org_response.json()["id"]
    org_name = org_response.json()["name"]
    target_token, target_email = await _register_and_login(client, "myorgs-target")
    target_user_id = await _get_user_id(test_engine, target_email)
    await client.post(
        f"/v1/organizations/{org_id}/members",
        json={"user_id": str(target_user_id)},
        headers=_auth_header(admin_token),
    )

    response = await client.get("/v1/users/me/organizations", headers=_auth_header(target_token))

    assert response.status_code == 200
    names = {o["name"] for o in response.json()}
    assert org_name in names


async def test_get_my_organizations_empty_for_user_with_no_memberships(client):
    token, _ = await _register_and_login(client, "myorgs-empty")

    response = await client.get("/v1/users/me/organizations", headers=_auth_header(token))

    assert response.status_code == 200
    assert response.json() == []


async def test_get_my_organizations_requires_authentication(client):
    response = await client.get("/v1/users/me/organizations")
    assert response.status_code == 401
