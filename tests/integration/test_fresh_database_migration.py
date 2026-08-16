"""
Verifies that Alembic migrations apply cleanly to a completely fresh,
empty database -- not the long-lived dev/test databases used by every
other test in this suite, which could theoretically mask a migration bug
if they've drifted from what `alembic upgrade head` alone would produce.

This creates a genuinely new, throwaway database, runs the real migration
against it via subprocess (exactly as a CI runner or a new contributor
would), inspects the resulting schema, then drops it.

Admin connection, corrected: this test used to hardcode a *separate*
superuser DSN (`postgres:postgres@localhost:5432`), on the assumption that
a second, standalone Postgres instance -- distinct from the one every
other integration test in this suite already uses via `TEST_DATABASE_URL`
-- would be available to `CREATE DATABASE` against. That assumption was
wrong in two different ways in the two environments that matter:
  - Locally, nothing listens on 5432 at all in this sandbox (only the
    `docker-compose.test.yml` instance on 5433 is running) -> connection
    refused.
  - In real GitHub Actions CI, a Postgres service container *is* running
    on 5432, but `.github/workflows/test.yml` provisions it with
    `secureiam`/`secureiam` credentials, not `postgres`/`postgres` ->
    `InvalidPasswordError`. This was a genuine, silent CI failure on every
    push since Phase 2.3, not merely a local-sandbox limitation.

The fix: derive the admin connection from the exact same
`TEST_DATABASE_URL` every other integration test already targets (see
`tests/conftest.py`), just pointed at the server's always-present
`postgres` maintenance database instead of the app's own database. The
bootstrap role docker-compose.yml/docker-compose.test.yml/CI's workflow
all create via `POSTGRES_USER` is a superuser (that's how Postgres's own
docker image initializes it), so it always has `CREATEDB` privilege and a
connection to `postgres` always exists -- there is no separate admin
identity to configure, deduplicate, or keep in sync. This means the test
now runs against whatever server the rest of the suite is already
pointed at, with zero new environment variables and zero duplicated
credentials.
"""

import os
import subprocess
import uuid

import asyncpg
import pytest
from sqlalchemy.engine import make_url

from tests.conftest import TEST_DATABASE_URL

_test_db_url = make_url(TEST_DATABASE_URL)


def _asyncpg_dsn(database: str) -> str:
    """A plain libpq-style DSN (no `+asyncpg` driver suffix -- asyncpg.connect()
    doesn't accept one) for `database`, on the same server/credentials as
    `TEST_DATABASE_URL`."""
    return _test_db_url.set(drivername="postgresql", database=database).render_as_string(
        hide_password=False
    )


# A connection to the same server's always-present `postgres` maintenance
# database, using the same credentials as every other integration test --
# not a separate, hardcoded superuser identity.
ADMIN_DSN = _asyncpg_dsn("postgres")


@pytest.mark.asyncio
async def test_migrations_apply_cleanly_to_a_fresh_empty_database():
    db_name = f"secureiam_migration_check_{uuid.uuid4().hex[:8]}"

    admin_conn = await asyncpg.connect(dsn=ADMIN_DSN)
    try:
        await admin_conn.execute(f'CREATE DATABASE "{db_name}"')
    finally:
        await admin_conn.close()

    fresh_db_url = _test_db_url.set(database=db_name).render_as_string(hide_password=False)

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

        check_conn = await asyncpg.connect(dsn=_asyncpg_dsn(db_name))
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

            # Phase 3 tables.
            assert "organizations" in table_names
            assert "organization_memberships" in table_names

            # Phase 4 table.
            assert "audit_logs" in table_names

            # pgcrypto must have been created by the migration itself, not
            # assumed to pre-exist on a fresh database.
            extensions = await check_conn.fetch(
                "SELECT extname FROM pg_extension WHERE extname = 'pgcrypto'"
            )
            assert len(extensions) == 1

            # The seed migrations must have populated the default roles and
            # permission catalog on a completely fresh database, not just
            # on the long-lived dev/test databases used elsewhere. Counts
            # reflect all three seed migrations: ca306aad2376 (4 roles, 5
            # permissions, 12 mappings), Phase 3.4's 97122fa13dcc (+1
            # permission, +1 mapping to Admin), and Phase 4.4's
            # cbf5b83aa3f8 (+1 permission, +1 mapping to Admin).
            role_count = await check_conn.fetchval("SELECT count(*) FROM roles")
            permission_count = await check_conn.fetchval("SELECT count(*) FROM permissions")
            mapping_count = await check_conn.fetchval("SELECT count(*) FROM role_permissions")
            assert role_count == 4
            assert permission_count == 7
            assert mapping_count == 14

            # Phase 3: no organizations are seeded -- they're created
            # through the API, not a migration -- and all four seeded
            # roles must be global (organization_id NULL), never org-scoped.
            organization_count = await check_conn.fetchval("SELECT count(*) FROM organizations")
            assert organization_count == 0
            global_role_count = await check_conn.fetchval(
                "SELECT count(*) FROM roles WHERE organization_id IS NULL"
            )
            assert global_role_count == 4

            # Phase 4: the audit log starts empty -- it's populated by
            # application activity, never by a migration.
            audit_log_count = await check_conn.fetchval("SELECT count(*) FROM audit_logs")
            assert audit_log_count == 0
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
