"""
UserRoleRepository -- the only module that queries the `user_roles` table
directly, including the join across role_permissions and permissions
needed to resolve a user's full effective permission set.

get_permissions_for_user() is the single most performance-relevant query
in the whole system: it's what AuthorizationService.authorize() calls on
every authorization check. It's implemented as one indexed join, not N+1
queries.

Phase 3 organization scoping: every method below takes an optional
organization_id, defaulting to None. None means "no organization context"
-- exactly the only thing that existed pre-Phase-3 -- and resolves *only*
globally-scoped (organization_id IS NULL) rows, which is why every
pre-Phase-3 caller of these methods keeps working unmodified. Passing a
real organization_id additionally includes rows scoped to that specific
organization, on top of (never instead of) the global ones -- a global
role assignment always applies, everywhere.
"""

import uuid

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models import Permission, Role, UserRole
from app.domain.models.role_permission import role_permissions
from app.repositories.exceptions import DuplicateRoleAssignmentError


def _organization_scope_filter(organization_id: uuid.UUID | None):
    """Shared WHERE-clause fragment: global (NULL) rows always match; rows
    scoped to `organization_id` also match when one is given."""
    if organization_id is None:
        return UserRole.organization_id.is_(None)
    return or_(UserRole.organization_id.is_(None), UserRole.organization_id == organization_id)


class UserRoleRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def assign(
        self,
        user_id: uuid.UUID,
        role_id: uuid.UUID,
        organization_id: uuid.UUID | None = None,
    ) -> UserRole:
        """Assigns a role to a user, optionally scoped to an organization.
        Raises DuplicateRoleAssignmentError if the user already has this
        exact (role, organization) combination -- callers decide what that
        means (error vs. idempotent no-op), this method only reports it.

        organization_id defaults to None (a global assignment, applying
        everywhere) -- exactly the only behavior that existed before
        Phase 3. Existence of the organization (and of the role, and
        whether the user is even a member of that organization) is the
        caller's (AuthorizationService's) responsibility to check first;
        this method assumes any IntegrityError it sees is the duplicate-
        assignment case, not a foreign key violation.
        """
        user_role = UserRole(user_id=user_id, role_id=role_id, organization_id=organization_id)
        self.session.add(user_role)
        try:
            await self.session.commit()
        except IntegrityError as exc:
            await self.session.rollback()
            raise DuplicateRoleAssignmentError(
                f"User {user_id} already has role {role_id} "
                f"(organization_id={organization_id})"
            ) from exc

        await self.session.refresh(user_role)
        return user_role

    async def revoke(
        self,
        user_id: uuid.UUID,
        role_id: uuid.UUID,
        organization_id: uuid.UUID | None = None,
    ) -> bool:
        """Removes a specific user-role assignment, if it exists.

        organization_id must match exactly how the assignment was made
        (None for a global assignment, a specific org for a scoped one) --
        this is an exact-row lookup, not the same "global-plus-scoped"
        union that get_roles_for_user()/get_permissions_for_user() use for
        reads, since revoking should only ever remove the one row asked
        for.

        Returns True if an assignment was found and removed, False if the
        user didn't have that exact assignment to begin with. Deliberately
        does not raise on "not found" -- whether that should be treated as
        an error or a silent no-op is a business decision for
        AuthorizationService, not this repository.
        """
        result = await self.session.execute(
            select(UserRole).where(
                UserRole.user_id == user_id,
                UserRole.role_id == role_id,
                UserRole.organization_id == organization_id,
            )
        )
        user_role = result.scalar_one_or_none()

        if user_role is None:
            return False

        await self.session.delete(user_role)
        await self.session.commit()
        return True

    async def get_roles_for_user(
        self, user_id: uuid.UUID, organization_id: uuid.UUID | None = None
    ) -> list[Role]:
        """Returns every Role currently assigned to a user: global
        assignments always, plus assignments scoped to `organization_id`
        if one is given."""
        result = await self.session.execute(
            select(Role)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id, _organization_scope_filter(organization_id))
            .order_by(Role.name)
        )
        return list(result.scalars().all())

    async def get_permissions_for_user(
        self, user_id: uuid.UUID, organization_id: uuid.UUID | None = None
    ) -> list[Permission]:
        """Returns the full, de-duplicated set of Permissions granted by
        all of a user's currently-assigned roles: global assignments
        always, plus assignments scoped to `organization_id` if one is
        given.

        This is a single joined query (user_roles -> role_permissions ->
        permissions), not N+1 lookups per role. DISTINCT handles the case
        where two of a user's roles both grant the same permission -- the
        caller should never see a duplicate.

        No caching here (or anywhere in this codebase by design) -- this
        query runs fresh on every call, which is what makes role
        revocation take effect immediately, as required.
        """
        result = await self.session.execute(
            select(Permission)
            .distinct()
            .join(role_permissions, role_permissions.c.permission_id == Permission.id)
            .join(UserRole, UserRole.role_id == role_permissions.c.role_id)
            .where(UserRole.user_id == user_id, _organization_scope_filter(organization_id))
            .order_by(Permission.resource, Permission.action)
        )
        return list(result.scalars().all())
