"""
Shared pytest fixtures.

Integration tests need a database engine pointed at the *test* database
(docker-compose.test.yml / secureiam_test), never the dev database — this
fixture guarantees that isolation.
"""

import os

import pytest
import pytest_asyncio
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
    """A single async session against the test database for a test to use directly."""
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
