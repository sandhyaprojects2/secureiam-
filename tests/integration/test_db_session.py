"""
Integration tests for app.db.session.

Requires a running test database (docker-compose.test.yml, or TEST_DATABASE_URL
pointed at any reachable Postgres instance).
"""

from sqlalchemy import text

from app.db.session import Base


async def test_can_execute_simple_query(test_session):
    """A session from the test engine should be able to run a real query."""
    result = await test_session.execute(text("SELECT 1"))
    assert result.scalar() == 1


async def test_declarative_base_is_usable_for_metadata(test_engine):
    """Base.metadata should be usable to create/drop tables against a real
    connection — this is what Alembic and test setup will rely on."""
    async with test_engine.begin() as conn:
        # No models registered yet (Phase 1 DB layer comes next) — this just
        # proves the Base + engine combination is wired correctly.
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(Base.metadata.drop_all)
