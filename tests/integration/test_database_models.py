"""
Integration tests proving the database-level guarantees behind the User and
RefreshToken models — run against the real, migrated test database.

These specifically test guarantees that must hold at the DB layer, not just
in application code (e.g. a unique constraint, not just an app-side check),
since a DB-level guarantee holds even if application logic has a bug.
"""

from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.time import utc_now
from app.domain.models import RefreshToken, User


async def _make_user(session, email="user@example.com") -> User:
    user = User(email=email, password_hash="fake-hash-for-testing")
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def test_user_can_be_created_with_defaults(test_session):
    user = await _make_user(test_session)

    assert user.id is not None
    assert user.is_active is True
    assert user.is_email_verified is False
    assert user.created_at is not None
    assert user.updated_at is not None
    assert user.last_login_at is None


async def test_user_email_unique_constraint_is_enforced_at_db_level(test_session):
    """Not just an app-level check -- the actual UNIQUE constraint must reject
    a duplicate insert, proving isolation holds even if application-level
    pre-check logic has a bug."""
    await _make_user(test_session, email="duplicate@example.com")

    duplicate = User(email="duplicate@example.com", password_hash="another-hash")
    test_session.add(duplicate)

    with pytest.raises(IntegrityError):
        await test_session.commit()

    await test_session.rollback()


async def test_refresh_token_can_be_created_for_a_user(test_session):
    user = await _make_user(test_session, email="tokenuser@example.com")

    token = RefreshToken(
        user_id=user.id,
        token_hash="a" * 64,
        expires_at=utc_now() + timedelta(days=14),
    )
    test_session.add(token)
    await test_session.commit()
    await test_session.refresh(token)

    assert token.id is not None
    assert token.revoked_at is None
    assert token.replaced_by is None


async def test_deleting_user_cascades_to_refresh_tokens(test_session):
    """RefreshToken.user_id uses ON DELETE CASCADE -- deleting a user must
    clean up their tokens automatically at the DB level."""
    user = await _make_user(test_session, email="cascade@example.com")
    token = RefreshToken(
        user_id=user.id,
        token_hash="b" * 64,
        expires_at=utc_now() + timedelta(days=14),
    )
    test_session.add(token)
    await test_session.commit()
    token_id = token.id

    await test_session.delete(user)
    await test_session.commit()

    result = await test_session.execute(
        select(RefreshToken).where(RefreshToken.id == token_id)
    )
    assert result.scalar_one_or_none() is None


async def test_refresh_token_replaced_by_chain(test_session):
    """The self-referential replaced_by FK should support linking a rotated
    token to its successor -- the foundation for Phase 7 reuse detection."""
    user = await _make_user(test_session, email="rotation@example.com")

    old_token = RefreshToken(
        user_id=user.id, token_hash="c" * 64, expires_at=utc_now() + timedelta(days=14)
    )
    test_session.add(old_token)
    await test_session.commit()
    await test_session.refresh(old_token)

    new_token = RefreshToken(
        user_id=user.id, token_hash="d" * 64, expires_at=utc_now() + timedelta(days=14)
    )
    test_session.add(new_token)
    await test_session.commit()
    await test_session.refresh(new_token)

    old_token.revoked_at = utc_now()
    old_token.replaced_by = new_token.id
    await test_session.commit()
    await test_session.refresh(old_token)

    assert old_token.revoked_at is not None
    assert old_token.replaced_by == new_token.id
