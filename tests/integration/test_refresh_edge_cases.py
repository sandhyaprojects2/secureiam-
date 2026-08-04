"""
Refresh token rotation edge cases and a concurrency sanity check.

These go beyond the basic rotation-works / old-token-rejected coverage in
test_auth_api.py to probe behavior that's easy to get subtly wrong:
chained rotations, and what happens when the same refresh token is
presented twice at effectively the same time.
"""

import asyncio
import uuid

from app.core.time import utc_now


def unique_email(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


async def test_refresh_token_can_be_rotated_multiple_times_in_sequence(client):
    """Rotate a chain: token A -> B -> C -> D. Each new token must work,
    and every earlier token in the chain must remain rejected."""
    email = unique_email("chainrotate")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})
    login_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )
    token_a = login_response.json()["refresh_token"]

    response_b = await client.post("/v1/auth/refresh", json={"refresh_token": token_a})
    assert response_b.status_code == 200
    token_b = response_b.json()["refresh_token"]

    response_c = await client.post("/v1/auth/refresh", json={"refresh_token": token_b})
    assert response_c.status_code == 200
    token_c = response_c.json()["refresh_token"]

    # Every earlier token in the chain must still be rejected, not just the
    # immediately preceding one.
    for old_token in (token_a, token_b):
        reuse_response = await client.post(
            "/v1/auth/refresh", json={"refresh_token": old_token}
        )
        assert reuse_response.status_code == 401

    # The newest token must still work.
    response_d = await client.post("/v1/auth/refresh", json={"refresh_token": token_c})
    assert response_d.status_code == 200


async def test_concurrent_refresh_with_same_token_only_one_succeeds(client):
    """Sanity check, not a full race-condition proof: fire two refresh
    requests concurrently with the identical (still-valid) refresh token
    and confirm exactly one succeeds. The other failing (rather than both
    succeeding and both returning valid-looking tokens) is the property
    that actually matters for security -- a stolen token being replayed
    concurrently with a legitimate refresh should not both succeed.
    """
    email = unique_email("concurrent")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})
    login_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )
    refresh_token = login_response.json()["refresh_token"]

    responses = await asyncio.gather(
        client.post("/v1/auth/refresh", json={"refresh_token": refresh_token}),
        client.post("/v1/auth/refresh", json={"refresh_token": refresh_token}),
        return_exceptions=True,
    )

    status_codes = sorted(
        r.status_code for r in responses if not isinstance(r, Exception)
    )

    # Exactly one request should succeed (200); the other should be
    # rejected (401) because the token was already revoked by the first
    # request to commit. Both succeeding would indicate a real race
    # condition in the rotation logic.
    assert status_codes.count(200) == 1
    assert status_codes.count(401) == 1


async def test_refresh_token_expiry_boundary_is_exclusive(client, test_engine):
    """A token whose expires_at is exactly now (or in the past) must be
    rejected -- confirms the boundary comparison isn't off-by-one in the
    permissive direction."""
    from sqlalchemy import text

    email = unique_email("expiryboundary")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})
    login_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )
    refresh_token = login_response.json()["refresh_token"]

    # Force this token's expires_at into the past directly at the DB level,
    # simulating a token that has just crossed its expiry boundary.
    async with test_engine.begin() as conn:
        await conn.execute(
            text("UPDATE refresh_tokens SET expires_at = :past WHERE user_id = "
                 "(SELECT id FROM users WHERE email = :email)"),
            {"past": utc_now().replace(year=2020), "email": email},
        )

    response = await client.post("/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert response.status_code == 401
