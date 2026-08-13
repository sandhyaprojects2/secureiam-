"""
Verifies that Alembic migrations apply cleanly to a completely fresh,
empty database -- not the long-lived dev/test databases used by every
other test in this suite, which could theoretically mask a migration bug
if they've drifted from what `alembic upgrade head` alone would produce.

This creates a genuinely new, throwaway database, runs the real migration
against it via subprocess (exactly as a CI runner or a new contributor
would), inspects the resulting schema, then drops it.
"""

import os
import subprocess
import uuid

import asyncpg
import pytest

ADMIN_DSN = "postgresql://postgres:postgres@localhost:5432/postgres"


@pytest.mark.asyncio
async def test_migrations_apply_cleanly_to_a_fresh_empty_database():
    db_name = f"secureiam_migration_check_{uuid.uuid4().hex[:8]}"

    admin_conn = await asyncpg.connect(dsn=ADMIN_DSN)
    try:
        await admin_conn.execute(f'CREATE DATABASE "{db_name}"')
    finally:
        await admin_conn.close()

    fresh_db_url = (
        f"postgresql+asyncpg://postgres:postgres@localhost:5432/{db_name}"
    )

    try:
        result = subprocess.run(
            ["python3", "-m", "alembic", "upgrade", "head"],
            env={**os.environ, "DATABASE_URL": fresh_db_url},
            cwd=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Migration failed on a fresh database.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

        check_conn = await asyncpg.connect(
            dsn=f"postgresql://postgres:postgres@localhost:5432/{db_name}"
        )
        try:
            tables = await check_conn.fetch(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
            )
            table_names = {row["tablename"] for row in tables}
            assert "users" in table_names
            assert "refresh_tokens" in table_names
            assert "alembic_version" in table_names
            # Phase 2.1 tables -- a fresh install must produce these too.
            assert "roles" in table_names
            assert "permissions" in table_names
            assert "role_permissions" in table_names
            assert "user_roles" in table_names

            # pgcrypto must have been created by the migration itself, not
            # assumed to pre-exist on a fresh database.
            extensions = await check_conn.fetch(
                "SELECT extname FROM pg_extension WHERE extname = 'pgcrypto'"
            )
            assert len(extensions) == 1

            # The seed migration must have populated the default roles and
            # permission catalog on a completely fresh database, not just
            # on the long-lived dev/test databases used elsewhere.
            role_count = await check_conn.fetchval("SELECT count(*) FROM roles")
            permission_count = await check_conn.fetchval("SELECT count(*) FROM permissions")
            mapping_count = await check_conn.fetchval("SELECT count(*) FROM role_permissions")
            assert role_count == 4
            assert permission_count == 5
            assert mapping_count == 12
        finally:
            await check_conn.close()

    finally:
        admin_conn = await asyncpg.connect(dsn=ADMIN_DSN)
        try:
            await admin_conn.execute(
                f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)'
            )
        finally:
            await admin_conn.close()
