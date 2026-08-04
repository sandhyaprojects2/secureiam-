"""
Async database session infrastructure.

Provides:
- `Base`         — the declarative base every ORM model inherits from
- `engine`       — the async SQLAlchemy engine, built from Settings.database_url
- `get_db`       — a FastAPI dependency yielding a session, always closed after use
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

settings = get_settings()

engine = create_async_engine(
    settings.database_url,
    echo=False,          # set True locally if you need to see raw SQL while debugging
    pool_pre_ping=True,  # detects and replaces dead connections rather than erroring
)

async_session_factory = async_sessionmaker(
    engine,
    expire_on_commit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that yields a database session and guarantees it's
    closed after the request completes, even if an exception is raised
    mid-request.
    """
    async with async_session_factory() as session:
        yield session
