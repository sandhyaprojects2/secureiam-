"""
Unit tests for app.core.config.

No database or network required — these test that settings load, validate,
and fail fast exactly as designed.
"""

import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings


def test_settings_load_from_environment(monkeypatch):
    """Settings should pick up required values from environment variables."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@localhost:5432/db")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret")

    settings = Settings(_env_file=None)

    assert settings.database_url == "postgresql+asyncpg://u:p@localhost:5432/db"
    assert settings.jwt_secret_key == "test-secret"


def test_settings_defaults_applied(monkeypatch):
    """Optional fields should fall back to documented defaults."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@localhost:5432/db")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret")

    settings = Settings(_env_file=None)

    assert settings.jwt_algorithm == "HS256"
    assert settings.access_token_ttl_minutes == 15
    assert settings.refresh_token_ttl_days == 14
    assert settings.argon2_time_cost == 3


def test_settings_fail_fast_on_missing_required_values(monkeypatch):
    """Missing DATABASE_URL or JWT_SECRET_KEY must raise at construction time,
    not surface later as a confusing runtime error."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_get_settings_is_cached(monkeypatch):
    """get_settings() should return the same instance on repeated calls."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@localhost:5432/db")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret")
    get_settings.cache_clear()

    first = get_settings()
    second = get_settings()

    assert first is second
    get_settings.cache_clear()  # avoid leaking cached state into other tests
