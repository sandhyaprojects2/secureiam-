"""
Integration tests for /v1/auth/* -- real Postgres, real FastAPI app, real
HTTP calls via httpx.AsyncClient. AuthService is NOT mocked here; this is
the layer that proves the whole stack (routes -> service -> repositories ->
database) actually works together, not just each piece in isolation.
"""

import uuid

import httpx
import pytest
from sqlalchemy import text

from app.main import app


@pytest.fixture
async def client(test_engine):
    """An httpx AsyncClient wired to the real app, but pointed at the
    isolated test database via dependency override."""
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from app.db.session import get_db

    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    # Ensure a clean slate for each test, independent of test_session's own
    # truncate (this fixture builds its own sessions via the override).
    async with test_engine.begin() as conn:
        await conn.execute(text("TRUNCATE TABLE refresh_tokens, users CASCADE"))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


def unique_email(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


# --- Register ---------------------------------------------------

async def test_register_returns_201(client):
    email = unique_email("register")
    response = await client.post(
        "/v1/auth/register", json={"email": email, "password": "correcthorsebattery"}
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == email
    assert "id" in body
    assert "created_at" in body


async def test_register_duplicate_email_returns_409(client):
    email = unique_email("dup")
    await client.post(
        "/v1/auth/register", json={"email": email, "password": "correcthorsebattery"}
    )
    response = await client.post(
        "/v1/auth/register", json={"email": email, "password": "anotherpassword123"}
    )
    assert response.status_code == 409
    assert response.json() == {"detail": "Unable to register with the provided details."}


async def test_register_response_never_contains_password_fields(client):
    email = unique_email("nopass")
    response = await client.post(
        "/v1/auth/register", json={"email": email, "password": "correcthorsebattery"}
    )
    body_text = response.text
    assert "password" not in body_text.lower()
    assert "argon2" not in body_text.lower()


async def test_register_rejects_short_password(client):
    email = unique_email("shortpw")
    response = await client.post(
        "/v1/auth/register", json={"email": email, "password": "short"}
    )
    assert response.status_code == 422  # pydantic validation error


# --- Login ---------------------------------------------------

async def test_login_returns_tokens(client):
    email = unique_email("login")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})

    response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"access_token", "refresh_token", "token_type", "expires_in"}
    assert body["token_type"] == "bearer"


async def test_login_wrong_password_returns_401(client):
    email = unique_email("wrongpw")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})

    response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "wrongpassword"}
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password."}


async def test_login_unknown_email_returns_identical_response_to_wrong_password(client):
    email = unique_email("identical")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})

    wrong_password_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "wrongpassword"}
    )
    unknown_email_response = await client.post(
        "/v1/auth/login", json={"email": unique_email("doesnotexist"), "password": "whatever12"}
    )

    assert wrong_password_response.status_code == unknown_email_response.status_code == 401
    assert wrong_password_response.json() == unknown_email_response.json()


async def test_login_inactive_account_returns_403(client, test_engine):
    email = unique_email("inactive")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})

    async with test_engine.begin() as conn:
        await conn.execute(
            text("UPDATE users SET is_active = false WHERE email = :email"),
            {"email": email},
        )

    response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Account is inactive."}


# --- Refresh ---------------------------------------------------

async def test_refresh_rotates_tokens(client):
    email = unique_email("refresh")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})
    login_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )
    old_refresh_token = login_response.json()["refresh_token"]

    response = await client.post("/v1/auth/refresh", json={"refresh_token": old_refresh_token})

    assert response.status_code == 200
    body = response.json()
    assert body["refresh_token"] != old_refresh_token


async def test_old_refresh_token_rejected_after_rotation(client):
    email = unique_email("oldtoken")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})
    login_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )
    old_refresh_token = login_response.json()["refresh_token"]

    await client.post("/v1/auth/refresh", json={"refresh_token": old_refresh_token})
    reuse_response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": old_refresh_token}
    )

    assert reuse_response.status_code == 401
    assert reuse_response.json() == {"detail": "Invalid or expired refresh token."}


async def test_refresh_invalid_token_returns_401(client):
    response = await client.post(
        "/v1/auth/refresh", json={"refresh_token": "totally-made-up-token-value"}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or expired refresh token."}


# --- Logout ---------------------------------------------------

async def test_logout_returns_204(client):
    email = unique_email("logout")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})
    login_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )
    refresh_token = login_response.json()["refresh_token"]

    response = await client.post("/v1/auth/logout", json={"refresh_token": refresh_token})

    assert response.status_code == 204
    assert response.text == ""


async def test_repeated_logout_succeeds(client):
    email = unique_email("repeatlogout")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})
    login_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )
    refresh_token = login_response.json()["refresh_token"]

    first = await client.post("/v1/auth/logout", json={"refresh_token": refresh_token})
    second = await client.post("/v1/auth/logout", json={"refresh_token": refresh_token})

    assert first.status_code == 204
    assert second.status_code == 204


async def test_logout_unknown_token_succeeds(client):
    response = await client.post(
        "/v1/auth/logout", json={"refresh_token": "never-existed-token"}
    )
    assert response.status_code == 204


# --- Security cross-cutting checks ---------------------------------------------------

async def test_revoked_refresh_token_cannot_be_used_after_logout(client):
    email = unique_email("postlogout")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})
    login_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )
    refresh_token = login_response.json()["refresh_token"]

    await client.post("/v1/auth/logout", json={"refresh_token": refresh_token})
    response = await client.post("/v1/auth/refresh", json={"refresh_token": refresh_token})

    assert response.status_code == 401


async def test_no_response_ever_contains_argon2_hash_markers(client):
    """Cross-cutting check across the full flow: at no point should an
    Argon2id hash marker leak into any response body."""
    email = unique_email("noleak")
    responses = []
    responses.append(await client.post(
        "/v1/auth/register", json={"email": email, "password": "correcthorsebattery"}
    ))
    responses.append(await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    ))
    responses.append(await client.post(
        "/v1/auth/login", json={"email": email, "password": "wrongpassword"}
    ))

    for response in responses:
        assert "$argon2id$" not in response.text
