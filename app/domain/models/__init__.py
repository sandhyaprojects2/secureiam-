"""
Domain models package.

Importing every model here ensures Base.metadata is fully populated when
this package is imported -- which is what Alembic's env.py relies on for
autogenerate to see the complete schema.
"""

from app.domain.models.user import User
from app.domain.models.refresh_token import RefreshToken

__all__ = ["User", "RefreshToken"]
