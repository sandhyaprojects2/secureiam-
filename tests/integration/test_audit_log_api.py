"""
Integration tests for GET /v1/audit-logs -- real Postgres, real FastAPI,
real HTTP calls via httpx.AsyncClient, exactly like
test_organizations_api.py. AuditLogService is NOT mocked here.

Bootstrapping an admin user (audit:view) uses the same approach as
test_organizations_api.py/test_authorize_api.py: assign the seeded Admin
role directly via UserRoleRepository, bypassing the API.

The audit_logs table is not truncated between tests (it's append-only
production data in spirit, and other test modules' register/login calls
write to it too), so every assertion here scopes its query to a specific
actor_user_id/action it just created, rather than asserting on the whole
table -- same convention as test_audit_log_repository.py.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.domain.models import User
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


# --- GET /v1/audit-logs ---------------------------------------------------

async def test_list_audit_logs_requires_audit_view_permission(client):
    token, _ = await _register_and_login(client, "auditlogs-noperm")

    response = await client.get("/v1/audit-logs", headers=_auth_header(token))

    assert response.status_code == 403


async def test_list_audit_logs_requires_authentication(client):
    response = await client.get("/v1/audit-logs")
    assert response.status_code == 401


async def test_list_audit_logs_succeeds_for_admin(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "auditlogs-admin")

    response = await client.get("/v1/audit-logs", headers=_auth_header(admin_token))

    assert response.status_code == 200
    body = response.json()
    assert "events" in body
    assert "total" in body
    assert body["limit"] == 50
    assert body["offset"] == 0


async def test_list_audit_logs_returns_events_recorded_by_auth_service(client, test_engine):
    """Login is one of AuthService's audited actions (Phase 4.3) -- filtering
    by the actor who just logged in must surface that event, proving the
    write path (4.3) and this read path (4.4) are wired to the same table."""
    admin_token, admin_user_id = await _make_admin(client, test_engine, "auditlogs-actorfilter")

    response = await client.get(
        "/v1/audit-logs",
        params={"actor_user_id": str(admin_user_id), "action": "user.login_succeeded"},
        headers=_auth_header(admin_token),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 1
    assert all(e["actor_user_id"] == str(admin_user_id) for e in body["events"])
    assert all(e["action"] == "user.login_succeeded" for e in body["events"])


async def test_list_audit_logs_returns_events_recorded_by_organization_service(client, test_engine):
    """organization.created is one of OrganizationService's audited actions
    (Phase 4.3) -- exercises a second service's writes through the same
    read path."""
    admin_token, admin_user_id = await _make_admin(client, test_engine, "auditlogs-orgfilter")
    org_name = f"AuditLogsOrg-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/v1/organizations", json={"name": org_name}, headers=_auth_header(admin_token)
    )

    response = await client.get(
        "/v1/audit-logs",
        params={"actor_user_id": str(admin_user_id), "action": "organization.created"},
        headers=_auth_header(admin_token),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total"] >= 1
    metadata = [e["event_metadata"] for e in body["events"] if e["event_metadata"]]
    assert any(m.get("name") == org_name for m in metadata)


async def test_list_audit_logs_action_filter_excludes_non_matching_actions(client, test_engine):
    admin_token, admin_user_id = await _make_admin(client, test_engine, "auditlogs-nomatch")

    response = await client.get(
        "/v1/audit-logs",
        params={"actor_user_id": str(admin_user_id), "action": "role.created"},
        headers=_auth_header(admin_token),
    )

    assert response.status_code == 200
    assert response.json()["events"] == []
    assert response.json()["total"] == 0


async def test_list_audit_logs_respects_limit(client, test_engine):
    admin_token, admin_user_id = await _make_admin(client, test_engine, "auditlogs-limit")
    for _ in range(3):
        await client.post(
            "/v1/organizations",
            json={"name": f"AuditLogsLimitOrg-{uuid.uuid4().hex[:8]}"},
            headers=_auth_header(admin_token),
        )

    response = await client.get(
        "/v1/audit-logs",
        params={
            "actor_user_id": str(admin_user_id),
            "action": "organization.created",
            "limit": 2,
        },
        headers=_auth_header(admin_token),
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body["events"]) == 2
    assert body["total"] >= 3
    assert body["limit"] == 2


async def test_list_audit_logs_rejects_limit_above_maximum(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "auditlogs-limitmax")

    response = await client.get(
        "/v1/audit-logs", params={"limit": 201}, headers=_auth_header(admin_token)
    )

    assert response.status_code == 422


async def test_list_audit_logs_rejects_negative_offset(client, test_engine):
    admin_token, _ = await _make_admin(client, test_engine, "auditlogs-negoffset")

    response = await client.get(
        "/v1/audit-logs", params={"offset": -1}, headers=_auth_header(admin_token)
    )

    assert response.status_code == 422
