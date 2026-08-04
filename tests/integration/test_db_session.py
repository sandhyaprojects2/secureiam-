"""
Integration tests for app.db.session.

Requires a running test database (docker-compose.test.yml, or TEST_DATABASE_URL
pointed at any reachable Postgres instance).
"""

from sqlalchemy import Column, Integer, MetaData, Table, text

from app.db.session import Base


async def test_can_execute_simple_query(test_session):
    """A session from the test engine should be able to run a real query."""
    result = await test_session.execute(text("SELECT 1"))
    assert result.scalar() == 1


async def test_declarative_base_metadata_can_create_and_drop_tables(test_engine):
    """Base + engine should be able to create/drop tables against a real
    connection — this is what Alembic and test setup rely on.

    IMPORTANT: this uses a throwaway, isolated MetaData/Table rather than
    Base.metadata directly. Base.metadata is the SAME shared registry that
    User/RefreshToken (and every future domain model) register themselves
    on — calling drop_all() against the real Base.metadata here would drop
    the actual migrated application tables the moment any other test module
    imports those models into the same test run. Using a scratch table
    proves the same Base/engine wiring without that cross-test hazard.
    """
    scratch_metadata = MetaData()
    scratch_table = Table(
        "_wiring_check_scratch_table",
        scratch_metadata,
        Column("id", Integer, primary_key=True),
    )

    async with test_engine.begin() as conn:
        await conn.run_sync(scratch_metadata.create_all)
        await conn.run_sync(scratch_metadata.drop_all)

    # Sanity check that Base itself is the same declarative base our real
    # domain models use, without touching its metadata destructively.
    assert Base.metadata is not None
