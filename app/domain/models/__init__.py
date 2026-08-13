"""
Domain models package.

Importing every model here ensures Base.metadata is fully populated when
this package is imported -- which is what Alembic's env.py relies on for
autogenerate to see the complete schema.
"""

from app.domain.models.user import User
from app.domain.models.refresh_token import RefreshToken
from app.domain.models.role import Role
from app.domain.models.permission import Permission
from app.domain.models.role_permission import role_permissions
from app.domain.models.user_role import UserRole
from app.domain.models.organization import Organization
from app.domain.models.organization_membership import OrganizationMembership

__all__ = [
    "User",
    "RefreshToken",
    "Role",
    "Permission",
    "role_permissions",
    "UserRole",
    "Organization",
    "OrganizationMembership",
]
