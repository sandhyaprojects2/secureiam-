"""
Shared pytest fixtures.

Integration tests need a database engine pointed at the *test* database
(docker-compose.test.yml / secureiam_test), never the dev database — this
fixture guarantees that isolation.
"""

import os

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Defaults to the docker-compose.test.yml port (5433). Overridable via env var
# for environments (like CI runners or this sandbox) where the test db runs
# on a different host/port.
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://secureiam_test:secureiam_test@localhost:5433/secureiam_test",
)


@pytest_asyncio.fixture
async def test_engine():
    """A SQLAlchemy async engine pointed at the isolated test database."""
    engine = create_async_engine(TEST_DATABASE_URL, pool_pre_ping=True)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def test_session(test_engine) -> AsyncSession:
    """A single async session against the test database for a test to use directly.

    Truncates the domain tables (if present) before yielding, so tests that
    commit real rows (e.g. creating a User) are idempotent across repeated
    runs instead of failing on stale data from a previous run. TRUNCATE ...
    CASCADE handles the users -> refresh_tokens FK relationship in one
    statement. Wrapped in a try/except so this fixture still works for
    modules (like test_db_session.py) run before any migration has created
    these tables.
    """
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        try:
            await session.execute(text("TRUNCATE TABLE refresh_tokens, users CASCADE"))
            await session.commit()
        except Exception:
            await session.rollback()
        yield session
