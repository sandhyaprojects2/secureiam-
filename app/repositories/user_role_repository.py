"""
UserRoleRepository -- the only module that queries the `user_roles` table
directly, including the join across role_permissions and permissions
needed to resolve a user's full effective permission set.

get_permissions_for_user() is the single most performance-relevant query
in the whole system: it's what AuthorizationService.authorize() (Phase 2.3)
will call on every authorization check. It's implemented as one indexed
join, not N+1 queries.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models import Permission, Role, UserRole
from app.domain.models.role_permission import role_permissions
from app.repositories.exceptions import DuplicateRoleAssignmentError


class UserRoleRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def assign(self, user_id: uuid.UUID, role_id: uuid.UUID) -> UserRole:
        """Assigns a role to a user. Raises DuplicateRoleAssignmentError if
        the user already has this exact role -- callers decide what that
        means (error vs. idempotent no-op), this method only reports it."""
        user_role = UserRole(user_id=user_id, role_id=role_id)
        self.session.add(user_role)
        try:
            await self.session.commit()
        except IntegrityError as exc:
            await self.session.rollback()
            raise DuplicateRoleAssignmentError(
                f"User {user_id} already has role {role_id}"
            ) from exc

        await self.session.refresh(user_role)
        return user_role

    async def revoke(self, user_id: uuid.UUID, role_id: uuid.UUID) -> bool:
        """Removes a specific user-role assignment, if it exists.

        Returns True if an assignment was found and removed, False if the
        user didn't have that role to begin with. Deliberately does not
        raise on "not found" -- whether that should be treated as an error
        or a silent no-op is a business decision for AuthorizationService,
        not this repository.
        """
        result = await self.session.execute(
            select(UserRole).where(
                UserRole.user_id == user_id, UserRole.role_id == role_id
            )
        )
        user_role = result.scalar_one_or_none()

        if user_role is None:
            return False

        await self.session.delete(user_role)
        await self.session.commit()
        return True

    async def get_roles_for_user(self, user_id: uuid.UUID) -> list[Role]:
        """Returns every Role currently assigned to a user."""
        result = await self.session.execute(
            select(Role)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id)
            .order_by(Role.name)
        )
        return list(result.scalars().all())

    async def get_permissions_for_user(self, user_id: uuid.UUID) -> list[Permission]:
        """Returns the full, de-duplicated set of Permissions granted by
        ALL of a user's currently-assigned roles.

        This is a single joined query (user_roles -> role_permissions ->
        permissions), not N+1 lookups per role. DISTINCT handles the case
        where two of a user's roles both grant the same permission -- the
        caller should never see a duplicate.

        No caching here (or anywhere in Phase 2 by design) -- this query
        runs fresh on every call, which is what makes role revocation take
        effect immediately, as required.
        """
        result = await self.session.execute(
            select(Permission)
            .distinct()
            .join(role_permissions, role_permissions.c.permission_id == Permission.id)
            .join(UserRole, UserRole.role_id == role_permissions.c.role_id)
            .where(UserRole.user_id == user_id)
            .order_by(Permission.resource, Permission.action)
        )
        return list(result.scalars().all())
