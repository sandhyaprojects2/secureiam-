"""
OrganizationMembershipRepository -- the only module that queries the
`organization_memberships` table directly, including the join back to
`users` needed to list an organization's members with useful identifying
information (not just opaque user ids).

is_member() is what AuthorizationService.assign_role() (Phase 3.3) calls
before granting an organization-scoped role assignment -- see that
method's docstring for why membership is checked first.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models import Organization, OrganizationMembership, User
from app.repositories.exceptions import DuplicateMembershipError


class OrganizationMembershipRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def add_member(
        self, user_id: uuid.UUID, organization_id: uuid.UUID
    ) -> OrganizationMembership:
        """Adds a user to an organization. Raises DuplicateMembershipError
        if the user is already a member -- callers decide what that means,
        this method only reports it."""
        membership = OrganizationMembership(user_id=user_id, organization_id=organization_id)
        self.session.add(membership)
        try:
            await self.session.commit()
        except IntegrityError as exc:
            await self.session.rollback()
            raise DuplicateMembershipError(
                f"User {user_id} is already a member of organization {organization_id}"
            ) from exc

        await self.session.refresh(membership)
        return membership

    async def remove_member(self, user_id: uuid.UUID, organization_id: uuid.UUID) -> bool:
        """Removes a user from an organization, if they're a member.

        Returns True if a membership was found and removed, False
        otherwise -- deliberately idempotent, not an error, matching
        UserRoleRepository.revoke()'s established not-found pattern.
        """
        result = await self.session.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.user_id == user_id,
                OrganizationMembership.organization_id == organization_id,
            )
        )
        membership = result.scalar_one_or_none()

        if membership is None:
            return False

        await self.session.delete(membership)
        await self.session.commit()
        return True

    async def is_member(self, user_id: uuid.UUID, organization_id: uuid.UUID) -> bool:
        """Whether the given user currently belongs to the given
        organization. Used by AuthorizationService.assign_role() as a
        precondition for granting an organization-scoped role."""
        result = await self.session.execute(
            select(OrganizationMembership.id).where(
                OrganizationMembership.user_id == user_id,
                OrganizationMembership.organization_id == organization_id,
            )
        )
        return result.scalar_one_or_none() is not None

    async def get_organizations_for_user(self, user_id: uuid.UUID) -> list[Organization]:
        """Returns every organization the given user is a member of."""
        result = await self.session.execute(
            select(Organization)
            .join(OrganizationMembership, OrganizationMembership.organization_id == Organization.id)
            .where(OrganizationMembership.user_id == user_id)
            .order_by(Organization.name)
        )
        return list(result.scalars().all())

    async def get_members_for_organization(self, organization_id: uuid.UUID):
        """Returns every member of the given organization as lightweight
        rows (`.user_id`, `.email`, `.joined_at`) -- a single joined query,
        not a full User object per member, since callers only ever need
        enough to identify and display a member, not their full record."""
        result = await self.session.execute(
            select(
                User.id.label("user_id"), User.email, OrganizationMembership.joined_at
            )
            .join(OrganizationMembership, OrganizationMembership.user_id == User.id)
            .where(OrganizationMembership.organization_id == organization_id)
            .order_by(OrganizationMembership.joined_at)
        )
        return result.all()
