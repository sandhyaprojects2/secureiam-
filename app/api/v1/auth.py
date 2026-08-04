"""
/v1/auth/* routes.

This module is intentionally thin: validate the request, call AuthService,
translate its domain exceptions into HTTP responses. No password hashing,
no token generation, no database queries, and no business rules live here
-- all of that is AuthService's responsibility.

This is also the ONLY place (along with core/dependencies.py's
get_current_user) where HTTPException is permitted to appear anywhere in
this codebase's authentication path.
"""

from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.api.v1.schemas.auth import (
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    TokenResponse,
)
from app.core.dependencies import get_auth_service
from app.domain.exceptions import (
    EmailAlreadyExistsError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
)
from app.domain.services.auth_service import AuthService

router = APIRouter(prefix="/v1/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    request: RegisterRequest,
    service: AuthService = Depends(get_auth_service),
) -> RegisterResponse:
    try:
        result = await service.register(email=request.email, password=request.password)
    except EmailAlreadyExistsError:
        # Deliberately generic -- never confirms or denies that the email
        # is already registered beyond this single, non-specific message.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Unable to register with the provided details.",
        )

    return RegisterResponse(id=result.id, email=result.email, created_at=result.created_at)


@router.post("/login", response_model=TokenResponse)
async def login(
    request: LoginRequest,
    service: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    try:
        result = await service.login(email=request.email, password=request.password)
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )
    except InactiveUserError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive.",
        )

    return TokenResponse(**result.model_dump())


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: RefreshRequest,
    service: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    try:
        result = await service.refresh(refresh_token=request.refresh_token)
    except InvalidRefreshTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )

    return TokenResponse(**result.model_dump())


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: LogoutRequest,
    service: AuthService = Depends(get_auth_service),
) -> Response:
    # No try/except here on purpose: AuthService.logout() is idempotent and
    # never raises for an unknown/already-revoked token -- there is no
    # exception path to translate for this endpoint.
    await service.logout(refresh_token=request.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
