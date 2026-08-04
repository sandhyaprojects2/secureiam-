"""
Centralized application configuration.

Every environment-driven value used anywhere in the codebase must be read
through `get_settings()`. No other module should call `os.environ` directly —
this is the single source of truth for configuration, and it's what makes the
app fail fast (at startup) if something required is missing, instead of
failing confusingly mid-request.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application ---
    app_name: str = "SecureIAM"
    environment: str = "development"

    # --- Database ---
    database_url: str

    # --- JWT ---
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "secureiam"
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 14

    # --- Password hashing (Argon2id) ---
    argon2_time_cost: int = 3
    argon2_memory_cost_kib: int = 65536
    argon2_parallelism: int = 4


@lru_cache
def get_settings() -> Settings:
    """
    Returns a cached Settings instance.

    Cached (not a bare module-level singleton) so tests can call
    `get_settings.cache_clear()` and re-instantiate against different
    environment variables — e.g. a test database URL — without needing to
    monkeypatch `os.environ` throughout the test suite.
    """
    return Settings()
