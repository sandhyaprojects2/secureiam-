"""
FastAPI dependency-injection functions.

get_auth_service() wires AuthService to real repositories and a real
per-request database session -- this is the only place AuthService gets
constructed with concrete dependencies; nothing else in the codebase should
instantiate it directly.

get_current_user() extracts and validates the caller's identity from the
Authorization header. It is not yet used by any route in Phase 1 -- it's
built now because every later phase (starting with Phase 2's /authorize
endpoint and every protected route after it) depends on it immediately.
"""

import uuid

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TokenValidationError, decode_access_token
from app.db.session import get_db
from app.domain.models import User
from app.domain.services.auth_service import AuthService
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.user_repository import UserRepository

_AUTH_FAILURE_DETAIL = "Could not validate credentials."


async def get_auth_service(session: AsyncSession = Depends(get_db)) -> AuthService:
    """Constructs AuthService wired to real repositories sharing one
    per-request database session."""
    return AuthService(
        user_repository=UserRepository(session),
        refresh_token_repository=RefreshTokenRepository(session),
    )


async def get_current_user(
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(get_db),
) -> User:
    """Resolves the current authenticated user from a Bearer access token.

    Every distinct failure mode below -- missing header, malformed scheme,
    invalid/tampered/expired JWT, or a token whose subject no longer maps to
    an existing user -- raises the exact same 401 with the exact same
    message, on purpose. Distinguishing them would give a caller probing
    this endpoint information about which failure mode it hit.
    """
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=_AUTH_FAILURE_DETAIL
        )

    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=_AUTH_FAILURE_DETAIL
        )

    try:
        payload = decode_access_token(token)
    except TokenValidationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=_AUTH_FAILURE_DETAIL
        )

    try:
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=_AUTH_FAILURE_DETAIL
        )

    user_repository = UserRepository(session)
    user = await user_repository.get_by_id(user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=_AUTH_FAILURE_DETAIL
        )

    # Deliberately NOT checking user.is_active here -- an inactive-but-
    # authenticated-token edge case, and any role/permission logic, is
    # explicitly Phase 2+ scope. This dependency answers "who is this,"
    # not "should this request be allowed."

    return user
