"""
PermissionRepository -- the only module that queries the `permissions`
table directly.

Deliberately read-only in Phase 2: permissions are seeded once via the
Alembic seed migration (see app/db/migrations/versions/
ca306aad2376_seed_default_roles_and_permissions.py), not created
dynamically through the API. This matches the approved Phase 2 design --
no create_permission() method exists here on purpose.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models import Permission


class PermissionRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_id(self, permission_id: uuid.UUID) -> Permission | None:
        """Lookup by primary key. Returns None if no match."""
        result = await self.session.execute(
            select(Permission).where(Permission.id == permission_id)
        )
        return result.scalar_one_or_none()

    async def get_by_resource_action(self, resource: str, action: str) -> Permission | None:
        """Lookup by the (resource, action) pair -- the natural key callers
        actually think in terms of (e.g. "document", "delete"). Returns
        None if no match."""
        result = await self.session.execute(
            select(Permission).where(
                Permission.resource == resource, Permission.action == action
            )
        )
        return result.scalar_one_or_none()

    async def list_all(self) -> list[Permission]:
        """Returns the full permission catalog, ordered for stable output."""
        result = await self.session.execute(
            select(Permission).order_by(Permission.resource, Permission.action)
        )
        return list(result.scalars().all())
