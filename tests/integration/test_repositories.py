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
