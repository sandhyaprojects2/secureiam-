"""
Integration tests for the repository layer.

Real Postgres throughout -- no mocked SQLAlchemy. Repositories are thin
data-access wrappers; the point of these tests is proving the actual SQL
behavior (constraints, cascades, transactions) is correct, which a mock
would hide.
"""

from datetime import timedelta
import uuid

import pytest
from sqlalchemy import select

from app.core.time import utc_now
from app.domain.models import RefreshToken
from app.repositories.exceptions import DuplicateEmailError
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.user_repository import UserRepository


# --- UserRepository ---------------------------------------------------

async def test_create_user_succeeds(test_session):
    repo = UserRepository(test_session)
    user = await repo.create_user("newuser@example.com", "fake-hash")

    assert user.id is not None
    assert user.email == "newuser@example.com"
    assert user.password_hash == "fake-hash"
    assert user.is_active is True


async def test_duplicate_email_is_rejected(test_session):
    repo = UserRepository(test_session)
    await repo.create_user("duplicate@example.com", "hash-one")

    with pytest.raises(DuplicateEmailError):
        await repo.create_user("duplicate@example.com", "hash-two")


async def test_duplicate_email_rejected_case_insensitively(test_session):
    """Since emails are stored lowercase, 'User@x.com' and 'user@x.com'
    must collide at the DB constraint level, not just the app layer."""
    repo = UserRepository(test_session)
    await repo.create_user("MixedCase@Example.com", "hash-one")

    with pytest.raises(DuplicateEmailError):
        await repo.create_user("mixedcase@example.com", "hash-two")


async def test_get_by_email_returns_user(test_session):
    repo = UserRepository(test_session)
    created = await repo.create_user("findme@example.com", "hash")

    found = await repo.get_by_email("findme@example.com")

    assert found is not None
    assert found.id == created.id


async def test_get_by_email_is_case_insensitive(test_session):
    repo = UserRepository(test_session)
    created = await repo.create_user("CaseTest@Example.com", "hash")

    found = await repo.get_by_email("casetest@example.com")

    assert found is not None
    assert found.id == created.id
    assert found.email == "casetest@example.com"  # stored lowercase


async def test_get_by_email_unknown_returns_none(test_session):
    repo = UserRepository(test_session)
    found = await repo.get_by_email("doesnotexist@example.com")
    assert found is None


async def test_get_by_id_returns_correct_user(test_session):
    repo = UserRepository(test_session)
    created = await repo.create_user("byid@example.com", "hash")

    found = await repo.get_by_id(created.id)

    assert found is not None
    assert found.email == "byid@example.com"


async def test_get_by_id_unknown_returns_none(test_session):
    repo = UserRepository(test_session)
    found = await repo.get_by_id(uuid.uuid4())
    assert found is None


async def test_update_last_login_sets_timestamp(test_session):
    repo = UserRepository(test_session)
    user = await repo.create_user("loginupdate@example.com", "hash")
    assert user.last_login_at is None

    updated = await repo.update_last_login(user)

    assert updated.last_login_at is not None


# --- RefreshTokenRepository ---------------------------------------------------

async def test_refresh_token_create_succeeds(test_session):
    user_repo = UserRepository(test_session)
    token_repo = RefreshTokenRepository(test_session)
    user = await user_repo.create_user("tokenowner@example.com", "hash")

    token = await token_repo.create(user.id, "a" * 64, utc_now() + timedelta(days=14))

    assert token.id is not None
    assert token.user_id == user.id
    assert token.revoked_at is None


async def test_get_by_hash_finds_token(test_session):
    user_repo = UserRepository(test_session)
    token_repo = RefreshTokenRepository(test_session)
    user = await user_repo.create_user("hashlookup@example.com", "hash")
    created = await token_repo.create(user.id, "b" * 64, utc_now() + timedelta(days=14))

    found = await token_repo.get_by_hash("b" * 64)

    assert found is not None
    assert found.id == created.id


async def test_get_by_hash_unknown_returns_none(test_session):
    token_repo = RefreshTokenRepository(test_session)
    found = await token_repo.get_by_hash("z" * 64)
    assert found is None


async def test_revoke_sets_revoked_at(test_session):
    user_repo = UserRepository(test_session)
    token_repo = RefreshTokenRepository(test_session)
    user = await user_repo.create_user("revoke@example.com", "hash")
    token = await token_repo.create(user.id, "c" * 64, utc_now() + timedelta(days=14))
    assert token.revoked_at is None

    revoked = await token_repo.revoke(token)

    assert revoked.revoked_at is not None


async def test_create_rotation_pair_links_old_and_new_tokens(test_session):
    user_repo = UserRepository(test_session)
    token_repo = RefreshTokenRepository(test_session)
    user = await user_repo.create_user("rotation@example.com", "hash")
    old_token = await token_repo.create(user.id, "d" * 64, utc_now() + timedelta(days=14))

    new_token = await token_repo.create_rotation_pair(
        old_token, "e" * 64, utc_now() + timedelta(days=14)
    )

    assert old_token.revoked_at is not None
    assert old_token.replaced_by == new_token.id
    assert new_token.revoked_at is None
    assert new_token.user_id == user.id


async def test_create_rotation_pair_second_concurrent_call_returns_none(test_session):
    """Phase 5: deterministic proof of the atomic-conditional-update
    guarantee, with zero concurrency or timing involved at all. Two
    sequential calls to create_rotation_pair() against the SAME old_token
    prove the exact same thing test_concurrent_refresh_with_same_token_
    only_one_succeeds proves via real asyncio.gather concurrency --
    because the guarantee itself doesn't depend on timing: the first call's
    `UPDATE ... WHERE revoked_at IS NULL` unconditionally wins (the row was
    unrevoked), and the second call's identical statement is guaranteed to
    affect zero rows no matter when it runs, since the first call already
    committed the revoke."""
    user_repo = UserRepository(test_session)
    token_repo = RefreshTokenRepository(test_session)
    user = await user_repo.create_user("rotationrace@example.com", "hash")
    old_token = await token_repo.create(user.id, "1" * 64, utc_now() + timedelta(days=14))

    first = await token_repo.create_rotation_pair(
        old_token, "2" * 64, utc_now() + timedelta(days=14)
    )
    second = await token_repo.create_rotation_pair(
        old_token, "3" * 64, utc_now() + timedelta(days=14)
    )

    assert first is not None
    assert second is None

    # The loser must not have created an orphaned child token -- exactly
    # one descendant of old_token exists.
    result = await test_session.execute(
        select(RefreshToken).where(RefreshToken.user_id == user.id)
    )
    all_tokens = result.scalars().all()
    assert len(all_tokens) == 2  # old_token + first's new_token only
    assert {t.token_hash for t in all_tokens} == {"1" * 64, "2" * 64}


async def test_create_rotation_pair_already_revoked_token_returns_none(test_session):
    """A token revoked by any means (here, logout's plain revoke()) before
    create_rotation_pair() is attempted must be rejected the same way as a
    concurrent-loss case -- the WHERE clause doesn't care why revoked_at
    was already set."""
    user_repo = UserRepository(test_session)
    token_repo = RefreshTokenRepository(test_session)
    user = await user_repo.create_user("alreadyrevoked@example.com", "hash")
    token = await token_repo.create(user.id, "4" * 64, utc_now() + timedelta(days=14))
    await token_repo.revoke(token)

    result = await token_repo.create_rotation_pair(
        token, "5" * 64, utc_now() + timedelta(days=14)
    )

    assert result is None


# --- RefreshTokenRepository.revoke_descendants() (Phase 5) ---------------------------------------------------

async def test_revoke_descendants_revokes_the_current_leaf(test_session):
    user_repo = UserRepository(test_session)
    token_repo = RefreshTokenRepository(test_session)
    user = await user_repo.create_user("descendants@example.com", "hash")
    token_a = await token_repo.create(user.id, "6" * 64, utc_now() + timedelta(days=14))
    token_b = await token_repo.create_rotation_pair(
        token_a, "7" * 64, utc_now() + timedelta(days=14)
    )
    token_c = await token_repo.create_rotation_pair(
        token_b, "8" * 64, utc_now() + timedelta(days=14)
    )
    await test_session.refresh(token_a)

    revoked = await token_repo.revoke_descendants(token_a)

    assert revoked is not None
    assert revoked.id == token_c.id
    await test_session.refresh(token_c)
    assert token_c.revoked_at is not None


async def test_revoke_descendants_second_call_returns_none(test_session):
    """Idempotency: once a family has been fully revoked by one
    revoke_descendants() call, a second call against the same starting
    token must find nothing left to revoke."""
    user_repo = UserRepository(test_session)
    token_repo = RefreshTokenRepository(test_session)
    user = await user_repo.create_user("descendantstwice@example.com", "hash")
    token_a = await token_repo.create(user.id, "9" * 64, utc_now() + timedelta(days=14))
    await token_repo.create_rotation_pair(token_a, "a1" * 32, utc_now() + timedelta(days=14))
    await test_session.refresh(token_a)

    first = await token_repo.revoke_descendants(token_a)
    second = await token_repo.revoke_descendants(token_a)

    assert first is not None
    assert second is None


async def test_revoke_descendants_no_successor_returns_none(test_session):
    """A token with no replaced_by (never rotated -- e.g. logged out, or
    simply never used) has no family to walk. Defensive no-op, not an
    error."""
    user_repo = UserRepository(test_session)
    token_repo = RefreshTokenRepository(test_session)
    user = await user_repo.create_user("nosuccessor@example.com", "hash")
    token = await token_repo.create(user.id, "b2" * 32, utc_now() + timedelta(days=14))

    result = await token_repo.revoke_descendants(token)

    assert result is None


async def test_deleting_user_cascades_refresh_tokens(test_session):
    user_repo = UserRepository(test_session)
    token_repo = RefreshTokenRepository(test_session)
    user = await user_repo.create_user("cascadetest@example.com", "hash")
    token = await token_repo.create(user.id, "f" * 64, utc_now() + timedelta(days=14))
    token_id = token.id

    await test_session.delete(user)
    await test_session.commit()

    result = await test_session.execute(select(RefreshToken).where(RefreshToken.id == token_id))
    assert result.scalar_one_or_none() is None
