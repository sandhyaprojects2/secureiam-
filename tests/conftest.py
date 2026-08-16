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
    statement, and also implicitly cascades to every other table that
    references users.id: user_roles (Phase 2.1), organization_memberships
    (Phase 3.1), and audit_logs' actor_user_id (Phase 4.1) -- note that
    TRUNCATE's CASCADE ignores each FK's own ON DELETE action (audit_logs'
    is ON DELETE SET NULL, not CASCADE, but TRUNCATE CASCADE truncates the
    referencing table outright regardless, since it operates at the
    statement level to preserve referential integrity, not by simulating
    what a DELETE would do). It does NOT touch roles, permissions,
    role_permissions, or organizations, since none of those are downstream
    of users/refresh_tokens. This is intentional: seeded/admin-created
    reference data (roles, permissions, organizations) should persist
    across tests, while per-test associations to a truncated user
    (assignments, memberships, and that user's audit trail) are cleared
    along with the user itself. Wrapped in a try/except so this fixture
    still works for modules (like test_db_session.py) run before any
    migration has created these tables.
    """
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        try:
            await session.execute(text("TRUNCATE TABLE refresh_tokens, users CASCADE"))
            await session.commit()
        except Exception:
            await session.rollback()
        yield session


@pytest_asyncio.fixture
async def client(test_engine):
    """An httpx AsyncClient wired to the real FastAPI app, with the get_db
    dependency overridden to use the isolated test database. Shared across
    every integration test module that needs to make real HTTP calls
    against the app (test_auth_api.py, test_refresh_edge_cases.py, etc.)."""
    import httpx

    from app.db.session import get_db
    from app.main import app

    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    async with test_engine.begin() as conn:
        await conn.execute(text("TRUNCATE TABLE refresh_tokens, users CASCADE"))

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()
