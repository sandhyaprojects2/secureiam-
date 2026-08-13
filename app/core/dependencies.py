"""
FastAPI dependency-injection functions.

get_auth_service() wires AuthService to real repositories and a real
per-request database session -- this is the only place AuthService gets
constructed with concrete dependencies; nothing else in the codebase should
instantiate it directly. get_authorization_service() does the equivalent
for AuthorizationService (Phase 2.3/2.4).

get_current_user() extracts and validates the caller's identity from the
Authorization header -- it answers "who is this." require_permission()
answers "should this request be allowed": it's a dependency *factory* that
wraps get_current_user with an AuthorizationService.authorize() check,
raising 403 if the caller lacks the given permission. This is the only
place an AuthorizationDecision is translated into an HTTP status code --
mirrors how get_current_user is the only place a TokenValidationError is.
"""

import uuid

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TokenValidationError, decode_access_token
from app.db.session import get_db
from app.domain.models import User
from app.domain.services.auth_service import AuthService
from app.domain.services.authorization_service import AuthorizationService
from app.repositories.permission_repository import PermissionRepository
from app.repositories.refresh_token_repository import RefreshTokenRepository
from app.repositories.role_repository import RoleRepository
from app.repositories.user_repository import UserRepository
from app.repositories.user_role_repository import UserRoleRepository

_AUTH_FAILURE_DETAIL = "Could not validate credentials."
_PERMISSION_DENIED_DETAIL = "You do not have permission to perform this action."


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
    # not "should this request be allowed." (AuthorizationService.authorize()
    # -- used by require_permission() below -- does check is_active, which
    # is where that question belongs.)

    return user


async def get_authorization_service(
    session: AsyncSession = Depends(get_db),
) -> AuthorizationService:
    """Constructs AuthorizationService wired to real repositories sharing
    one per-request database session -- same shape as get_auth_service()."""
    return AuthorizationService(
        user_repository=UserRepository(session),
        role_repository=RoleRepository(session),
        permission_repository=PermissionRepository(session),
        user_role_repository=UserRoleRepository(session),
    )


def require_permission(resource: str, action: str):
    """Dependency factory: returns a dependency that resolves the current
    user, checks whether they hold the given (resource, action) permission,
    and raises 403 if not. On success, returns the resolved User, so a
    route can depend on this alone rather than also depending on
    get_current_user separately.

    Usage: `user: User = Depends(require_permission("role", "manage"))`.

    The 403 detail is deliberately generic and identical for every denial
    reason (inactive user, no matching role, role exists but permission
    doesn't) -- AuthorizationService.authorize() already collapses all of
    those into a single `allowed=False`, and this dependency preserves that
    by never inspecting anything beyond the boolean.
    """

    async def dependency(
        user: User = Depends(get_current_user),
        service: AuthorizationService = Depends(get_authorization_service),
    ) -> User:
        decision = await service.authorize(user.id, resource, action)
        if not decision.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail=_PERMISSION_DENIED_DETAIL
            )
        return user

    return dependency
