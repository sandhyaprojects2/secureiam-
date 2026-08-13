"""
OrganizationRepository -- the only module that queries the `organizations`
table directly.

Same shape as RoleRepository: constructor-injected AsyncSession, no
business logic, translates DB-level constraint violations into
repository-level exceptions and leaves interpretation to the service layer.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models import Organization
from app.repositories.exceptions import DuplicateOrganizationNameError


class OrganizationRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_organization(self, name: str) -> Organization:
        """Persists a new organization. Raises DuplicateOrganizationNameError
        if the name already exists -- callers decide what that means, this
        method only reports it."""
        organization = Organization(name=name)
        self.session.add(organization)
        try:
            await self.session.commit()
        except IntegrityError as exc:
            await self.session.rollback()
            raise DuplicateOrganizationNameError(
                f"Organization name already exists: {name}"
            ) from exc

        await self.session.refresh(organization)
        return organization

    async def get_by_id(self, organization_id: uuid.UUID) -> Organization | None:
        """Lookup by primary key. Returns None if no match."""
        result = await self.session.execute(
            select(Organization).where(Organization.id == organization_id)
        )
        return result.scalar_one_or_none()

    async def get_by_name(self, name: str) -> Organization | None:
        """Exact lookup by name. Returns None if no match."""
        result = await self.session.execute(
            select(Organization).where(Organization.name == name)
        )
        return result.scalar_one_or_none()

    async def list_all(self) -> list[Organization]:
        """Returns every organization, ordered by name for stable,
        predictable output."""
        result = await self.session.execute(select(Organization).order_by(Organization.name))
        return list(result.scalars().all())
