"""
AuthService -- authentication business workflows.

Coordinates repositories and security primitives to implement register,
login, refresh, and logout. Contains no SQL, no SQLAlchemy model queries, no
database session management, no HTTPException, and no FastAPI imports --
this module should be fully usable and testable with plain mocked
repositories and zero infrastructure.

Phase 4.3: every workflow now writes to the audit log via
audit_log_repository -- register, login, and refresh record BOTH their
success and every distinct failure reason (unlike the HTTP-facing
exceptions those failures raise, which deliberately collapse multiple
reasons into one indistinguishable message -- see app/domain/exceptions.py
-- the audit log is an internal-only surface, never returned in an API
response, so it's free to record the real reason for admin/security
investigation). logout() is the one exception: only an actual revocation
is recorded, not a no-op call against an unknown/already-revoked token --
that path carries no security signal worth the noise (see logout()'s own
docstring).

Phase 5: refresh() now detects refresh-token reuse (a rotated-away token
being presented again) and responds by revoking that token's entire
family, plus rotation itself is now concurrency-safe against the
lost-update race Phase 1's unconditional revoke was vulnerable to -- see
_handle_revoked_token()'s docstring and
RefreshTokenRepository.create_rotation_pair()/revoke_descendants() for the
full mechanism. None of this changes what refresh() ever returns to a
caller on failure: every rejection reason, old and new, still raises the
identical InvalidRefreshTokenError with the identical message.
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
from app.domain import audit_actions
from app.domain.exceptions import (
    EmailAlreadyExistsError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
)
from app.domain.schemas.auth import RegisterResponse, TokenResponse
from app.repositories.exceptions import DuplicateEmailError


class AuthService:
    def __init__(self, user_repository, refresh_token_repository, audit_log_repository):
        self.user_repository = user_repository
        self.refresh_token_repository = refresh_token_repository
        self.audit_log_repository = audit_log_repository

    async def register(self, email: str, password: str) -> RegisterResponse:
        """Registers a new user. Issues no tokens -- Phase 1 registration is
        create-only; the caller must log in separately to obtain tokens."""
        password_hash = hash_password(password)

        try:
            user = await self.user_repository.create_user(
                email=email, password_hash=password_hash
            )
        except DuplicateEmailError as exc:
            await self.audit_log_repository.record(
                action=audit_actions.USER_REGISTRATION_FAILED,
                target_type="user",
                event_metadata={"attempted_email": email, "reason": "duplicate_email"},
            )
            # Repository-level fact ("a UNIQUE constraint was violated") is
            # translated here into a business-level fact ("registration
            # cannot proceed with this email").
            raise EmailAlreadyExistsError(
                "Unable to register with the provided details."
            ) from exc

        await self.audit_log_repository.record(
            action=audit_actions.USER_REGISTERED,
            actor_user_id=user.id,
            target_type="user",
            target_id=user.id,
        )

        return RegisterResponse(id=user.id, email=user.email, created_at=user.created_at)

    async def login(self, email: str, password: str) -> TokenResponse:
        """Authenticates a user and issues a new access/refresh token pair.

        Security-critical ordering: "no such user" and "wrong password" both
        raise InvalidCredentialsError with an identical message, so a caller
        cannot distinguish them and enumerate valid emails by probing login.
        """
        user = await self.user_repository.get_by_email(email)

        if user is None:
            await self.audit_log_repository.record(
                action=audit_actions.USER_LOGIN_FAILED,
                target_type="user",
                event_metadata={"attempted_email": email, "reason": "unknown_email"},
            )
            raise InvalidCredentialsError("Invalid email or password.")

        if not user.is_active:
            await self.audit_log_repository.record(
                action=audit_actions.USER_LOGIN_FAILED,
                actor_user_id=user.id,
                target_type="user",
                target_id=user.id,
                event_metadata={"reason": "inactive_account"},
            )
            raise InactiveUserError("Account is inactive.")

        if not verify_password(password, user.password_hash):
            await self.audit_log_repository.record(
                action=audit_actions.USER_LOGIN_FAILED,
                actor_user_id=user.id,
                target_type="user",
                target_id=user.id,
                event_metadata={"reason": "wrong_password"},
            )
            raise InvalidCredentialsError("Invalid email or password.")

        await self.user_repository.update_last_login(user)

        await self.audit_log_repository.record(
            action=audit_actions.USER_LOGIN_SUCCEEDED,
            actor_user_id=user.id,
            target_type="user",
            target_id=user.id,
        )

        return await self._issue_token_pair(user)

    async def refresh(self, refresh_token: str) -> TokenResponse:
        """Validates an incoming refresh token and rotates it, issuing a new
        access/refresh token pair.

        Phase 5: a revoked token is now one of two distinct cases, told
        apart by whether it has a successor (replaced_by is not None) --
        see _handle_revoked_token()'s docstring for the full reuse-detection
        behavior. Either case still raises the identical
        InvalidRefreshTokenError with the identical message as every other
        rejection reason below -- reuse detection is an internal security
        response (audited, and it revokes the live session), never a signal
        exposed to the caller, preserving the same indistinguishability
        guarantee this method has always had.
        """
        token_hash = hash_refresh_token(refresh_token)
        token = await self.refresh_token_repository.get_by_hash(token_hash)

        if token is None:
            await self.audit_log_repository.record(
                action=audit_actions.REFRESH_TOKEN_REJECTED,
                event_metadata={"reason": "unknown_token"},
            )
            raise InvalidRefreshTokenError("Invalid or expired refresh token.")

        if token.revoked_at is not None:
            await self._handle_revoked_token(token)
            raise InvalidRefreshTokenError("Invalid or expired refresh token.")

        if token.expires_at <= utc_now():
            await self.audit_log_repository.record(
                action=audit_actions.REFRESH_TOKEN_REJECTED,
                actor_user_id=token.user_id,
                target_type="user",
                target_id=token.user_id,
                event_metadata={"reason": "expired_token"},
            )
            raise InvalidRefreshTokenError("Invalid or expired refresh token.")

        user = await self.user_repository.get_by_id(token.user_id)

        if user is None or not user.is_active:
            # Deliberately the same exception as the token-validity failures
            # above -- an inactive/deleted account's refresh token should
            # not be distinguishable from an ordinary invalid token.
            await self.audit_log_repository.record(
                action=audit_actions.REFRESH_TOKEN_REJECTED,
                actor_user_id=token.user_id,
                target_type="user",
                target_id=token.user_id,
                event_metadata={"reason": "inactive_or_deleted_owner"},
            )
            raise InvalidRefreshTokenError("Invalid or expired refresh token.")

        new_raw_refresh_token = generate_refresh_token()
        new_token_hash = hash_refresh_token(new_raw_refresh_token)
        new_expires_at = refresh_token_expiry()

        new_token = await self.refresh_token_repository.create_rotation_pair(
            old_token=token,
            new_token_hash=new_token_hash,
            new_expires_at=new_expires_at,
        )

        if new_token is None:
            # Phase 5: we passed every validity check above, but lost a
            # concurrent race to actually rotate this exact token -- another
            # request (an ordinary simultaneous refresh with the same token,
            # or a reuse-detection revocation triggered by a different,
            # stale token from the same family) revoked it first, between
            # our read above and this call. Distinguishable internally
            # (concurrent_rotation_lost) from every other rejection reason,
            # but externally identical: same exception, same message.
            await self.audit_log_repository.record(
                action=audit_actions.REFRESH_TOKEN_REJECTED,
                actor_user_id=token.user_id,
                target_type="user",
                target_id=token.user_id,
                event_metadata={"reason": "concurrent_rotation_lost"},
            )
            raise InvalidRefreshTokenError("Invalid or expired refresh token.")

        await self.audit_log_repository.record(
            action=audit_actions.REFRESH_TOKEN_ROTATED,
            actor_user_id=user.id,
            target_type="user",
            target_id=user.id,
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
        -- no exception, no signal about whether the token ever existed.

        Only an actual revocation is written to the audit log -- a no-op
        call against an unknown or already-revoked token carries no
        security signal worth recording (unlike a failed login, this isn't
        evidence of anything: it's the ordinary shape of a client that
        already logged out, or double-submitted a logout request).
        """
        token_hash = hash_refresh_token(refresh_token)
        token = await self.refresh_token_repository.get_by_hash(token_hash)

        if token is None or token.revoked_at is not None:
            return

        await self.refresh_token_repository.revoke(token)

        await self.audit_log_repository.record(
            action=audit_actions.USER_LOGOUT,
            actor_user_id=token.user_id,
            target_type="user",
            target_id=token.user_id,
        )

    async def _handle_revoked_token(self, token) -> None:
        """Phase 5: handles a refresh token found to already be revoked,
        distinguishing two cases by whether it has a successor
        (token.replaced_by):

        - replaced_by is None: revoked via logout (see
          RefreshTokenRepository.revoke(), which never sets replaced_by).
          Not reuse -- just an ordinary already-logged-out token being
          presented again. Unchanged since Phase 1: records
          REFRESH_TOKEN_REJECTED/reason=revoked_token, nothing else.

        - replaced_by is not None: revoked via rotation (see
          RefreshTokenRepository.create_rotation_pair(), which always sets
          replaced_by). Presenting this token again means a *rotated-away*
          token has resurfaced -- the classic signal of a stolen-refresh-
          token replay. Always records REFRESH_TOKEN_REUSE_DETECTED (every
          presentation is its own signal, even a second attempt against an
          already-dead family). Additionally walks forward to the family's
          current active leaf and revokes it
          (RefreshTokenRepository.revoke_descendants()) -- fail-closed: if
          anything in this family is still live, it's killed, regardless of
          who's actually holding it. Records REFRESH_TOKEN_FAMILY_REVOKED
          only when that walk actually revoked something (not on repeat
          attempts against an already-fully-revoked family).

        Callers must raise InvalidRefreshTokenError immediately after this
        returns, exactly as for every other rejection reason -- this method
        only records the appropriate audit trail; it never changes what
        response the caller receives.
        """
        if token.replaced_by is None:
            await self.audit_log_repository.record(
                action=audit_actions.REFRESH_TOKEN_REJECTED,
                actor_user_id=token.user_id,
                target_type="user",
                target_id=token.user_id,
                event_metadata={"reason": "revoked_token"},
            )
            return

        revoked_leaf = await self.refresh_token_repository.revoke_descendants(token)

        await self.audit_log_repository.record(
            action=audit_actions.REFRESH_TOKEN_REUSE_DETECTED,
            actor_user_id=token.user_id,
            target_type="user",
            target_id=token.user_id,
            event_metadata={
                "presented_token_id": str(token.id),
                "family_already_revoked": revoked_leaf is None,
            },
        )

        if revoked_leaf is not None:
            await self.audit_log_repository.record(
                action=audit_actions.REFRESH_TOKEN_FAMILY_REVOKED,
                actor_user_id=token.user_id,
                target_type="refresh_token",
                target_id=revoked_leaf.id,
                event_metadata={"presented_token_id": str(token.id)},
            )

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
