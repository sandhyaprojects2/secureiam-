"""
Unit tests for app.core.security.

Pure unit tests — no database, no network. These lock in the security
guarantees the rest of the system will depend on.
"""

import time

import jwt
import pytest

from app.core.config import get_settings
from app.core.security import (
    TokenValidationError,
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)

settings = get_settings()


# --- Password hashing ---------------------------------------------------

def test_hash_password_succeeds_and_produces_argon2id_hash():
    hashed = hash_password("correct-horse-battery-staple")
    assert hashed.startswith("$argon2id$")
    assert hashed != "correct-horse-battery-staple"


def test_hash_password_is_salted_and_not_deterministic():
    """Argon2 embeds a random salt — hashing the same password twice must
    produce two different hashes."""
    first = hash_password("same-password")
    second = hash_password("same-password")
    assert first != second


def test_verify_password_succeeds_with_correct_password():
    hashed = hash_password("correct-horse-battery-staple")
    assert verify_password("correct-horse-battery-staple", hashed) is True


def test_verify_password_fails_with_wrong_password():
    hashed = hash_password("correct-horse-battery-staple")
    assert verify_password("wrong-password", hashed) is False


def test_verify_password_fails_gracefully_on_malformed_hash():
    """A corrupted/invalid hash should return False, not raise."""
    assert verify_password("anything", "not-a-real-argon2-hash") is False


# --- JWT access tokens ----------------------------------------------------

def test_create_access_token_contains_expected_claims():
    token = create_access_token("user-123")
    payload = decode_access_token(token)

    assert payload["sub"] == "user-123"
    assert payload["type"] == "access"
    assert payload["iss"] == settings.jwt_issuer
    assert "iat" in payload
    assert "exp" in payload
    assert "jti" in payload


def test_access_token_expiry_matches_configured_ttl():
    token = create_access_token("user-123")
    payload = decode_access_token(token)

    expected_ttl_seconds = settings.access_token_ttl_minutes * 60
    actual_ttl_seconds = payload["exp"] - payload["iat"]
    assert actual_ttl_seconds == expected_ttl_seconds


def test_expired_token_is_rejected():
    """Manually craft a token with an expiry in the past to test the
    expiration check independent of waiting for a real token to expire."""
    now = int(time.time())
    expired_payload = {
        "sub": "user-123",
        "type": "access",
        "iat": now - 1000,
        "exp": now - 500,
        "jti": "test-jti",
        "iss": settings.jwt_issuer,
    }
    expired_token = jwt.encode(
        expired_payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
    )

    with pytest.raises(TokenValidationError):
        decode_access_token(expired_token)


def test_tampered_token_is_rejected():
    """Flipping characters in the signature portion must invalidate the token."""
    token = create_access_token("user-123")
    tampered = token[:-4] + ("A" if token[-4] != "A" else "B") + token[-3:]

    with pytest.raises(TokenValidationError):
        decode_access_token(tampered)


def test_token_with_wrong_issuer_is_rejected():
    now = int(time.time())
    payload = {
        "sub": "user-123",
        "type": "access",
        "iat": now,
        "exp": now + 900,
        "jti": "test-jti",
        "iss": "some-other-issuer",
    }
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

    with pytest.raises(TokenValidationError):
        decode_access_token(token)


def test_token_signed_with_wrong_secret_is_rejected():
    """A token signed with a different secret (e.g. forged) must be rejected."""
    now = int(time.time())
    payload = {
        "sub": "user-123",
        "type": "access",
        "iat": now,
        "exp": now + 900,
        "jti": "test-jti",
        "iss": settings.jwt_issuer,
    }
    forged_token = jwt.encode(payload, "wrong-secret-key", algorithm=settings.jwt_algorithm)

    with pytest.raises(TokenValidationError):
        decode_access_token(forged_token)


def test_token_missing_required_claim_is_rejected():
    """A token missing a required claim (e.g. jti) should be rejected, not
    silently accepted with a missing field."""
    now = int(time.time())
    incomplete_payload = {
        "sub": "user-123",
        "type": "access",
        "iat": now,
        "exp": now + 900,
        "iss": settings.jwt_issuer,
        # "jti" deliberately omitted
    }
    token = jwt.encode(
        incomplete_payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
    )

    with pytest.raises(TokenValidationError):
        decode_access_token(token)


# --- Refresh tokens ---------------------------------------------------

def test_generate_refresh_token_produces_random_values():
    tokens = {generate_refresh_token() for _ in range(20)}
    assert len(tokens) == 20  # all unique


def test_generate_refresh_token_has_sufficient_length():
    token = generate_refresh_token()
    # secrets.token_urlsafe(64) produces a string well over 64 characters
    assert len(token) > 64


def test_hash_refresh_token_is_deterministic():
    token = generate_refresh_token()
    assert hash_refresh_token(token) == hash_refresh_token(token)


def test_hash_refresh_token_differs_for_different_tokens():
    token_a = generate_refresh_token()
    token_b = generate_refresh_token()
    assert hash_refresh_token(token_a) != hash_refresh_token(token_b)


def test_hash_refresh_token_produces_sha256_hex_digest():
    token = generate_refresh_token()
    digest = hash_refresh_token(token)
    assert len(digest) == 64  # SHA-256 hex digest length
    assert all(c in "0123456789abcdef" for c in digest)
