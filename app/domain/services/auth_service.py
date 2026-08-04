"""
AuthService -- authentication business workflows.

Coordinates repositories and security primitives to implement register,
login, refresh, and logout. Contains no SQL, no SQLAlchemy model queries, no
database session management, no HTTPException, and no FastAPI imports --
this module should be fully usable and testable with plain mocked
repositories and zero infrastructure.
"""

from app.core.security import (
    access_token_ttl_seconds,
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    refresh_token_expiry,
    verify_password,
)
from app.core.time import utc_now
from app.domain.exceptions import (
    EmailAlreadyExistsError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
)
from app.domain.schemas.auth import RegisterResponse, TokenResponse
from app.repositories.exceptions import DuplicateEmailError


class AuthService:
    def __init__(self, user_repository, refresh_token_repository):
        self.user_repository = user_repository
        self.refresh_token_repository = refresh_token_repository

    async def register(self, email: str, password: str) -> RegisterResponse:
        """Registers a new user. Issues no tokens -- Phase 1 registration is
        create-only; the caller must log in separately to obtain tokens."""
        password_hash = hash_password(password)

        try:
            user = await self.user_repository.create_user(
                email=email, password_hash=password_hash
            )
        except DuplicateEmailError as exc:
            # Repository-level fact ("a UNIQUE constraint was violated") is
            # translated here into a business-level fact ("registration
            # cannot proceed with this email").
            raise EmailAlreadyExistsError(
                "Unable to register with the provided details."
            ) from exc

        return RegisterResponse(id=user.id, email=user.email, created_at=user.created_at)

    async def login(self, email: str, password: str) -> TokenResponse:
        """Authenticates a user and issues a new access/refresh token pair.

        Security-critical ordering: "no such user" and "wrong password" both
        raise InvalidCredentialsError with an identical message, so a caller
        cannot distinguish them and enumerate valid emails by probing login.
        """
        user = await self.user_repository.get_by_email(email)

        if user is None:
            raise InvalidCredentialsError("Invalid email or password.")

        if not user.is_active:
            raise InactiveUserError("Account is inactive.")

        if not verify_password(password, user.password_hash):
            raise InvalidCredentialsError("Invalid email or password.")

        await self.user_repository.update_last_login(user)

        return await self._issue_token_pair(user)

    async def refresh(self, refresh_token: str) -> TokenResponse:
        """Validates an incoming refresh token and rotates it, issuing a new
        access/refresh token pair.

        Phase 1 scope only: rejects a reused (already-revoked) token exactly
        like any other invalid token. It does NOT walk the replaced_by chain
        to revoke a whole token family -- that reuse-detection behavior is
        Phase 7 scope.
        """
        token_hash = hash_refresh_token(refresh_token)
        token = await self.refresh_token_repository.get_by_hash(token_hash)

        if token is None:
            raise InvalidRefreshTokenError("Invalid or expired refresh token.")

        if token.revoked_at is not None:
            raise InvalidRefreshTokenError("Invalid or expired refresh token.")

        if token.expires_at <= utc_now():
            raise InvalidRefreshTokenError("Invalid or expired refresh token.")

        user = await self.user_repository.get_by_id(token.user_id)

        if user is None or not user.is_active:
            # Deliberately the same exception as the token-validity failures
            # above -- an inactive/deleted account's refresh token should
            # not be distinguishable from an ordinary invalid token.
            raise InvalidRefreshTokenError("Invalid or expired refresh token.")

        new_raw_refresh_token = generate_refresh_token()
        new_token_hash = hash_refresh_token(new_raw_refresh_token)
        new_expires_at = refresh_token_expiry()

        await self.refresh_token_repository.create_rotation_pair(
            old_token=token,
            new_token_hash=new_token_hash,
            new_expires_at=new_expires_at,
        )

        access_token = create_access_token(str(user.id))

        return TokenResponse(
            access_token=access_token,
            refresh_token=new_raw_refresh_token,
            token_type="bearer",
            expires_in=access_token_ttl_seconds(),
        )

    async def logout(self, refresh_token: str) -> None:
        """Revokes a refresh token. Idempotent and silent: an unknown or
        already-revoked token is treated identically to a successful logout
        -- no exception, no signal about whether the token ever existed."""
        token_hash = hash_refresh_token(refresh_token)
        token = await self.refresh_token_repository.get_by_hash(token_hash)

        if token is None or token.revoked_at is not None:
            return

        await self.refresh_token_repository.revoke(token)

    async def _issue_token_pair(self, user) -> TokenResponse:
        """Shared helper for issuing a fresh access/refresh token pair for
        an already-authenticated user. Used by login(); refresh() has its
        own issuance path since it rotates an existing token rather than
        creating a fresh one."""
        access_token = create_access_token(str(user.id))
        raw_refresh_token = generate_refresh_token()
        token_hash = hash_refresh_token(raw_refresh_token)
        expires_at = refresh_token_expiry()

        await self.refresh_token_repository.create(
            user_id=user.id, token_hash=token_hash, expires_at=expires_at
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=raw_refresh_token,
            token_type="bearer",
            expires_in=access_token_ttl_seconds(),
        )
