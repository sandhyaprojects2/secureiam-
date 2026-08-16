"""
End-to-end integration tests proving Phase 4.3's audit wiring actually
writes real rows to audit_logs when hitting the real API -- real Postgres,
real FastAPI, real HTTP calls via httpx.AsyncClient, exactly like
test_auth_api.py and test_authorize_api.py.

The unit tests in test_auth_service.py/test_authorization_service.py/
test_organization_service.py already prove each service calls
audit_log_repository.record() with the right arguments, against a mocked
repository. This file proves the other half: that a real HTTP request
actually results in a real, queryable row in the database, through the
entire stack (route -> service -> repository -> Postgres).
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.domain.models import AuditLog, User
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
    return login_response.json().get("access_token"), email


def _auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _get_user_id(test_engine, email: str) -> uuid.UUID:
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        result = await session.execute(select(User.id).where(User.email == email.lower()))
        return result.scalar_one()


async def _get_audit_logs_for_actor(test_engine, actor_user_id):
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        result = await session.execute(
            select(AuditLog).where(AuditLog.actor_user_id == actor_user_id)
        )
        return list(result.scalars().all())


async def _get_audit_logs_by_action_and_metadata_email(test_engine, action, email):
    """Failed-login/failed-registration events have no actor_user_id (the
    account may not exist), so they're looked up by action + the
    attempted_email recorded in event_metadata instead."""
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        result = await session.execute(select(AuditLog).where(AuditLog.action == action))
        return [
            log
            for log in result.scalars().all()
            if log.event_metadata and log.event_metadata.get("attempted_email") == email
        ]


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


# --- AuthService events ---------------------------------------------------

async def test_register_writes_audit_row(client, test_engine):
    email = unique_email("auditregister")

    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})

    user_id = await _get_user_id(test_engine, email)
    logs = await _get_audit_logs_for_actor(test_engine, user_id)
    assert any(log.action == "user.registered" for log in logs)


async def test_register_duplicate_email_writes_audit_row_without_actor(client, test_engine):
    email = unique_email("auditdupregister")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})

    await client.post("/v1/auth/register", json={"email": email, "password": "anotherpassword1"})

    logs = await _get_audit_logs_by_action_and_metadata_email(
        test_engine, "user.registration_failed", email
    )
    assert len(logs) == 1
    assert logs[0].actor_user_id is None
    assert logs[0].event_metadata["reason"] == "duplicate_email"


async def test_login_success_writes_audit_row(client, test_engine):
    token, email = await _register_and_login(client, "auditloginsuccess")
    user_id = await _get_user_id(test_engine, email)

    logs = await _get_audit_logs_for_actor(test_engine, user_id)

    assert any(log.action == "user.login_succeeded" for log in logs)


async def test_login_wrong_password_writes_audit_row_with_reason(client, test_engine):
    email = unique_email("auditwrongpw")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})

    await client.post("/v1/auth/login", json={"email": email, "password": "wrongpassword"})

    user_id = await _get_user_id(test_engine, email)
    logs = await _get_audit_logs_for_actor(test_engine, user_id)
    failed = [log for log in logs if log.action == "user.login_failed"]
    assert len(failed) == 1
    assert failed[0].event_metadata["reason"] == "wrong_password"


async def test_logout_writes_audit_row(client, test_engine):
    token, email = await _register_and_login(client, "auditlogout")
    login_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )
    refresh_token = login_response.json()["refresh_token"]

    await client.post("/v1/auth/logout", json={"refresh_token": refresh_token})

    user_id = await _get_user_id(test_engine, email)
    logs = await _get_audit_logs_for_actor(test_engine, user_id)
    assert any(log.action == "user.logout" for log in logs)


async def test_refresh_writes_audit_row(client, test_engine):
    token, email = await _register_and_login(client, "auditrefresh")
    login_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )
    refresh_token = login_response.json()["refresh_token"]

    await client.post("/v1/auth/refresh", json={"refresh_token": refresh_token})

    user_id = await _get_user_id(test_engine, email)
    logs = await _get_audit_logs_for_actor(test_engine, user_id)
    assert any(log.action == "refresh_token.rotated" for log in logs)


# --- AuthorizationService events ---------------------------------------------------

async def test_create_role_writes_audit_row_with_correct_actor(client, test_engine):
    admin_token, admin_id = await _make_admin(client, test_engine, "auditcreaterole")
    role_name = unique_org_name("AuditRole")

    await client.post(
        "/v1/roles", json={"name": role_name}, headers=_auth_header(admin_token)
    )

    logs = await _get_audit_logs_for_actor(test_engine, admin_id)
    matching = [
        log
        for log in logs
        if log.action == "role.created" and log.event_metadata.get("name") == role_name
    ]
    assert len(matching) == 1
    assert matching[0].target_type == "role"


async def test_assign_role_writes_audit_row_with_correct_actor_and_target(client, test_engine):
    admin_token, admin_id = await _make_admin(client, test_engine, "auditassignrole")
    _, target_email = await _register_and_login(client, "auditassignrole-target")
    target_user_id = await _get_user_id(test_engine, target_email)
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        role_id = (await RoleRepository(session).get_by_name("Intern")).id

    await client.post(
        f"/v1/users/{target_user_id}/roles",
        json={"role_id": str(role_id)},
        headers=_auth_header(admin_token),
    )

    logs = await _get_audit_logs_for_actor(test_engine, admin_id)
    matching = [
        log
        for log in logs
        if log.action == "role.assigned" and log.target_id == target_user_id
    ]
    assert len(matching) == 1
    assert matching[0].event_metadata["role_id"] == str(role_id)


# --- OrganizationService events ---------------------------------------------------

async def test_create_organization_writes_audit_row(client, test_engine):
    admin_token, admin_id = await _make_admin(client, test_engine, "auditcreateorg")
    org_name = unique_org_name("AuditOrg")

    response = await client.post(
        "/v1/organizations", json={"name": org_name}, headers=_auth_header(admin_token)
    )
    org_id = response.json()["id"]

    logs = await _get_audit_logs_for_actor(test_engine, admin_id)
    matching = [
        log
        for log in logs
        if log.action == "organization.created" and str(log.target_id) == org_id
    ]
    assert len(matching) == 1


async def test_add_organization_member_writes_audit_row(client, test_engine):
    admin_token, admin_id = await _make_admin(client, test_engine, "auditaddmember")
    org_response = await client.post(
        "/v1/organizations",
        json={"name": unique_org_name("AuditMemberOrg")},
        headers=_auth_header(admin_token),
    )
    org_id = org_response.json()["id"]
    _, target_email = await _register_and_login(client, "auditaddmember-target")
    target_user_id = await _get_user_id(test_engine, target_email)

    await client.post(
        f"/v1/organizations/{org_id}/members",
        json={"user_id": str(target_user_id)},
        headers=_auth_header(admin_token),
    )

    logs = await _get_audit_logs_for_actor(test_engine, admin_id)
    matching = [
        log
        for log in logs
        if log.action == "organization.member_added" and log.target_id == target_user_id
    ]
    assert len(matching) == 1
    assert str(matching[0].organization_id) == org_id
