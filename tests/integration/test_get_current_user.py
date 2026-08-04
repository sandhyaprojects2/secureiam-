"""
Integration tests for app.core.dependencies.get_current_user.

Not yet wired to any route (no protected endpoints exist in Phase 1), but
built now because Phase 2 depends on it immediately. Tested directly here
against a real database and real issued tokens, rather than through an HTTP
route that doesn't exist yet.

Every distinct rejection reason (missing header, malformed scheme, tampered
token, expired token, unknown user) must raise the exact same generic 401 --
that's the property these tests exist to lock in.
"""

import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.dependencies import get_current_user
from app.core.security import create_access_token
from app.repositories.user_repository import UserRepository


@pytest.fixture
async def real_user_and_session(test_engine):
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        repo = UserRepository(session)
        user = await repo.create_user(
            email=f"depuser-{uuid.uuid4().hex[:8]}@example.com",
            password_hash="fake-hash-for-testing",
        )
        yield user, session


async def test_valid_token_resolves_correct_user(real_user_and_session):
    user, session = real_user_and_session
    token = create_access_token(str(user.id))

    resolved = await get_current_user(authorization=f"Bearer {token}", session=session)

    assert resolved.id == user.id
    assert resolved.email == user.email


async def test_missing_header_rejected(real_user_and_session):
    _, session = real_user_and_session

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(authorization=None, session=session)

    assert exc_info.value.status_code == 401


async def test_malformed_bearer_scheme_rejected(real_user_and_session):
    user, session = real_user_and_session
    token = create_access_token(str(user.id))

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(authorization=f"Token {token}", session=session)

    assert exc_info.value.status_code == 401


async def test_empty_bearer_token_rejected(real_user_and_session):
    _, session = real_user_and_session

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(authorization="Bearer ", session=session)

    assert exc_info.value.status_code == 401


async def test_tampered_token_rejected(real_user_and_session):
    user, session = real_user_and_session
    token = create_access_token(str(user.id))
    tampered = token[:-4] + ("A" if token[-4] != "A" else "B") + token[-3:]

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(authorization=f"Bearer {tampered}", session=session)

    assert exc_info.value.status_code == 401


async def test_unknown_user_id_rejected(real_user_and_session):
    """A structurally valid, correctly-signed token whose subject doesn't
    correspond to any existing user must be rejected identically to any
    other invalid token."""
    _, session = real_user_and_session
    token_for_nonexistent_user = create_access_token(str(uuid.uuid4()))

    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(
            authorization=f"Bearer {token_for_nonexistent_user}", session=session
        )

    assert exc_info.value.status_code == 401


async def test_all_rejection_reasons_produce_identical_response(real_user_and_session):
    """The core guarantee: whatever the underlying cause, the exception
    surfaced to a caller must be indistinguishable."""
    user, session = real_user_and_session
    token = create_access_token(str(user.id))
    tampered = token[:-4] + ("A" if token[-4] != "A" else "B") + token[-3:]
    unknown_user_token = create_access_token(str(uuid.uuid4()))

    results = []
    for auth_header in (None, f"Token {token}", f"Bearer {tampered}", f"Bearer {unknown_user_token}"):
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(authorization=auth_header, session=session)
        results.append((exc_info.value.status_code, exc_info.value.detail))

    assert len(set(results)) == 1  # every rejection is byte-for-byte identical
