"""
RoleRepository -- the only module that queries the `roles` table directly.

Same shape as UserRepository from Phase 1: constructor-injected AsyncSession,
no business logic, translates DB-level constraint violations into
repository-level exceptions and leaves interpretation to the service layer.

Note on casing: unlike UserRepository.get_by_email(), role names are NOT
normalized to lowercase. Email normalization existed to prevent a
user-facing enumeration/confusion problem on a user-supplied field. Role
names are admin-controlled internal identifiers ("Admin", "Manager") --
there's no equivalent risk, and case-sensitivity is the more predictable
default for something an administrator sets deliberately.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models import Role
from app.repositories.exceptions import DuplicateRoleNameError


class RoleRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_role(self, name: str, description: str | None = None) -> Role:
        """Persists a new role. Raises DuplicateRoleNameError if the name
        already exists -- callers decide what that means, this method only
        reports it."""
        role = Role(name=name, description=description)
        self.session.add(role)
        try:
            await self.session.commit()
        except IntegrityError as exc:
            await self.session.rollback()
            raise DuplicateRoleNameError(f"Role name already exists: {name}") from exc

        await self.session.refresh(role)
        return role

    async def get_by_id(self, role_id: uuid.UUID) -> Role | None:
        """Lookup by primary key. Returns None if no match."""
        result = await self.session.execute(select(Role).where(Role.id == role_id))
        return result.scalar_one_or_none()

    async def get_by_name(self, name: str) -> Role | None:
        """Exact, case-sensitive lookup by name. Returns None if no match."""
        result = await self.session.execute(select(Role).where(Role.name == name))
        return result.scalar_one_or_none()

    async def list_all(self) -> list[Role]:
        """Returns every role, ordered by name for stable, predictable output."""
        result = await self.session.execute(select(Role).order_by(Role.name))
        return list(result.scalars().all())
