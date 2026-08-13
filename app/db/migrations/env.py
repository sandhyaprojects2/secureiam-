"""
Alembic migration environment, adapted to run against our async SQLAlchemy
engine.

DATABASE_URL comes from app.core.config.get_settings() — not duplicated in
alembic.ini — so there is exactly one place that defines which database
migrations run against.
"""

import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# Import Base and every model so Base.metadata is fully populated —
# this is what makes autogenerate see the complete schema.
from app.core.config import get_settings
from app.db.session import Base
from app.domain.models import (  # noqa: F401
    User,
    RefreshToken,
    Role,
    Permission,
    UserRole,
    Organization,
    OrganizationMembership,
)
from app.domain.models.role_permission import role_permissions  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# Single source of truth for the DB URL: our own Settings, not alembic.ini.
config.set_main_option("sqlalchemy.url", get_settings().database_url)


def run_migrations_offline() -> None:
    """Run migrations without a live DB connection (generates SQL only)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations against a live database using our async engine."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
