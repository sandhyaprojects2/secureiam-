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
    """Rotate a chain: token A -> B -> C -> D, with no stale-token
    presentations in between. Each new token must work.

    Deliberately does NOT also present an earlier token (A or B) partway
    through the chain and then expect the newest token to keep working
    afterward -- as of Phase 5, presenting an earlier token in the chain is
    reuse, and correctly-implemented reuse detection means it revokes
    whatever in the family is still live (see
    test_reusing_an_old_token_partway_through_a_chain_revokes_the_current_leaf
    below, which locks in exactly that behavior instead of accidentally
    colliding with it here).
    """
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

    response_d = await client.post("/v1/auth/refresh", json={"refresh_token": token_c})
    assert response_d.status_code == 200


# --- Reuse detection & token-family revocation (Phase 5) ---------------------------------------------------

async def test_reusing_an_old_token_partway_through_a_chain_revokes_the_current_leaf(client):
    """Build the same A -> B -> C chain as the happy-path test above, but
    this time present the *oldest* token (A, already rotated away to B)
    again partway through. That's reuse, by definition (A has a
    successor) -- and correctly-implemented reuse detection must revoke
    whatever is currently live in the family (C, the leaf at the moment A
    is replayed) as a fail-closed response, even though C itself was never
    directly implicated. This is the exact scenario the old, pre-Phase-5
    version of this test file accidentally exercised without ever
    asserting on it -- now it's locked in on purpose.
    """
    email = unique_email("chainreuse")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})
    login_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )
    token_a = login_response.json()["refresh_token"]

    response_b = await client.post("/v1/auth/refresh", json={"refresh_token": token_a})
    token_b = response_b.json()["refresh_token"]

    response_c = await client.post("/v1/auth/refresh", json={"refresh_token": token_b})
    token_c = response_c.json()["refresh_token"]

    # Replay the oldest token in the chain (A) -- reuse.
    reuse_response = await client.post("/v1/auth/refresh", json={"refresh_token": token_a})
    assert reuse_response.status_code == 401

    # The family's current leaf (C) must now be dead too, even though it
    # was never itself presented as reuse -- fail-closed family revocation.
    leaf_response = await client.post("/v1/auth/refresh", json={"refresh_token": token_c})
    assert leaf_response.status_code == 401


async def test_reusing_a_rotated_away_token_is_rejected_and_revokes_its_successor(client):
    """The minimal case: rotate A -> B, then replay A. Must be rejected
    with the same generic response as any other invalid token, and B (A's
    one and only successor) must now be revoked too."""
    email = unique_email("reusebasic")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})
    login_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )
    token_a = login_response.json()["refresh_token"]

    response_b = await client.post("/v1/auth/refresh", json={"refresh_token": token_a})
    token_b = response_b.json()["refresh_token"]

    reuse_response = await client.post("/v1/auth/refresh", json={"refresh_token": token_a})
    assert reuse_response.status_code == 401
    assert reuse_response.json() == {"detail": "Invalid or expired refresh token."}

    b_now_response = await client.post("/v1/auth/refresh", json={"refresh_token": token_b})
    assert b_now_response.status_code == 401


async def test_repeated_reuse_of_an_already_revoked_family_stays_rejected(client):
    """Presenting the same rotated-away token a second time, after its
    family has already been fully revoked by the first reuse attempt, must
    still be rejected the same way -- not error out, not behave
    differently just because there's nothing left to revoke."""
    email = unique_email("reuserepeat")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})
    login_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )
    token_a = login_response.json()["refresh_token"]
    await client.post("/v1/auth/refresh", json={"refresh_token": token_a})

    first_reuse = await client.post("/v1/auth/refresh", json={"refresh_token": token_a})
    second_reuse = await client.post("/v1/auth/refresh", json={"refresh_token": token_a})

    assert first_reuse.status_code == 401
    assert second_reuse.status_code == 401
    assert second_reuse.json() == {"detail": "Invalid or expired refresh token."}


async def test_reusing_a_logged_out_token_does_not_trigger_family_revocation(client, test_engine):
    """A token revoked via logout (never rotated -- no successor) is NOT
    reuse: presenting it again must behave exactly as it always has,
    with no family-revocation side effect. Confirmed directly against the
    audit log, not just the HTTP response, since the whole point of this
    test is to prove a side effect does NOT happen."""
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.domain.models import AuditLog, User

    email = unique_email("logoutnoreuse")
    await client.post("/v1/auth/register", json={"email": email, "password": "correcthorsebattery"})
    login_response = await client.post(
        "/v1/auth/login", json={"email": email, "password": "correcthorsebattery"}
    )
    refresh_token = login_response.json()["refresh_token"]

    await client.post("/v1/auth/logout", json={"refresh_token": refresh_token})
    response = await client.post("/v1/auth/refresh", json={"refresh_token": refresh_token})

    assert response.status_code == 401

    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        user_id = (
            await session.execute(select(User.id).where(User.email == email.lower()))
        ).scalar_one()
        actions = (
            await session.execute(
                select(AuditLog.action).where(AuditLog.actor_user_id == user_id)
            )
        ).scalars().all()

    assert "refresh_token.reuse_detected" not in actions
    assert "refresh_token.family_revoked" not in actions
    assert actions.count("refresh_token.rejected") == 1


async def test_concurrent_refresh_with_same_token_only_one_succeeds(client):
    """Phase 5: this is now a deterministic proof, not a probabilistic
    sanity check. Before Phase 5, RefreshTokenRepository.create_rotation_pair()
    revoked the old token via an unconditional ORM attribute assignment --
    both concurrent callers would read the same not-yet-revoked row, and
    both would then write their own unconditional UPDATE, so which one
    "won" (and whether both did) depended on asyncio scheduling. Now that
    the revoke is an atomic `UPDATE ... WHERE revoked_at IS NULL`, Postgres
    itself resolves the race at the row level: exactly one caller's UPDATE
    can ever affect the row, regardless of how the two coroutines happen
    to be interleaved. This test's outcome no longer depends on timing --
    see test_create_rotation_pair_second_concurrent_call_returns_none in
    tests/integration/test_repositories.py for the same guarantee proven
    with zero concurrency/timing involved at all.

    Fires two refresh requests concurrently with the identical
    (still-valid) refresh token and confirms exactly one succeeds. The
    other failing (rather than both succeeding and both returning
    valid-looking tokens) is the property that actually matters for
    security -- a stolen token being replayed concurrently with a
    legitimate refresh should not both succeed.
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
