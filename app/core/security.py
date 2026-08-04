"""
Security primitives: password hashing, JWT issuance/validation, refresh
token generation and hashing.

This module is pure infrastructure — no database access, no FastAPI
dependencies, no domain/service imports. Every function here should be
callable and testable in isolation.
"""

import hashlib
import secrets
import uuid
from datetime import timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash

from app.core.config import get_settings
from app.core.time import utc_now

settings = get_settings()

_password_hasher = PasswordHasher(
    time_cost=settings.argon2_time_cost,
    memory_cost=settings.argon2_memory_cost_kib,
    parallelism=settings.argon2_parallelism,
)


class TokenValidationError(Exception):
    """Raised for any invalid access token: expired, tampered, wrong issuer,
    or otherwise malformed. Deliberately a single exception type — callers
    should not be able to distinguish *why* a token failed validation from
    the exception alone, to avoid leaking information to anything probing
    token validity."""
    pass


# --- Password hashing ---------------------------------------------------

def hash_password(password: str) -> str:
    """Hashes a plaintext password using Argon2id. Returns an encoded hash
    string safe to store directly in the database."""
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verifies a plaintext password against a stored Argon2id hash.

    Always returns a bool — never raises — so callers can treat "wrong
    password" and "malformed/corrupt hash" uniformly rather than needing
    to catch multiple exception types.
    """
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


# --- JWT access tokens ----------------------------------------------------

def create_access_token(user_id: str) -> str:
    """Creates a signed JWT access token for the given user id.

    Claims:
        sub  - subject (user id)
        type - "access" (self-describing, in case other token types are
               added via JWT later)
        iat  - issued-at
        exp  - expiry, per ACCESS_TOKEN_TTL_MINUTES
        jti  - unique token id (unused in Phase 1, but present so Phase 7's
               blacklist/rate-limiting work needs no token-format migration)
        iss  - issuer, validated on decode
    """
    now = utc_now()
    expires_at = now.timestamp() + (settings.access_token_ttl_minutes * 60)

    payload = {
        "sub": user_id,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expires_at),
        "jti": str(uuid.uuid4()),
        "iss": settings.jwt_issuer,
    }

    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    """Decodes and validates a JWT access token.

    Validates signature, expiration, and issuer. Raises TokenValidationError
    for any failure — expired, tampered signature, wrong issuer, or malformed
    token — without distinguishing which, by design.
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "iss", "jti", "type"]},
        )
    except jwt.PyJWTError as exc:
        raise TokenValidationError("Invalid or expired token") from exc

    return payload


# --- Refresh tokens ---------------------------------------------------

def generate_refresh_token() -> str:
    """Generates a cryptographically random, high-entropy opaque refresh
    token. Not a JWT — carries no claims, since the server always looks it
    up by hash rather than needing to inspect an embedded payload."""
    return secrets.token_urlsafe(64)


def hash_refresh_token(token: str) -> str:
    """Hashes a refresh token with SHA-256 before it touches storage.

    SHA-256, not Argon2: a refresh token is a 64-byte cryptographically
    random value, not a low-entropy human password — brute-forcing it is
    infeasible regardless of hash speed, so a fast, deterministic hash is
    the correct tool here. Argon2 would only add latency to every refresh
    lookup with no corresponding security benefit.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def access_token_ttl_seconds() -> int:
    """Returns the configured access token TTL in seconds.

    Exists so AuthService (and later the API layer) can report expires_in
    without reading Settings/environment variables directly — AuthService
    is only permitted to call security.py functions, not access
    configuration itself.
    """
    return settings.access_token_ttl_minutes * 60


def refresh_token_expiry():
    """Returns the expiry timestamp a newly-issued refresh token should use,
    based on the configured TTL. Same rationale as access_token_ttl_seconds():
    keeps configuration access inside the security/config layer, not the
    service layer.
    """
    return utc_now() + timedelta(days=settings.refresh_token_ttl_days)
