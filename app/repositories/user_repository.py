"""
UserRepository -- the only module that queries the `users` table directly.

Responsible strictly for persistence: executing queries, translating rows
into User instances, and translating DB-level failures (like a UNIQUE
constraint violation) into repository-level exceptions. Contains no
authentication logic, no password/token handling, and no business decisions
-- those belong to AuthService.

Email normalization policy (documented here since it must be applied
consistently everywhere emails are read or written):
  - Emails are stored lowercase in the database.
  - Lookups also lowercase the input before querying.
  Both, not just one: storing lowercase means the UNIQUE constraint itself
  catches case-only duplicates (e.g. "User@x.com" vs "user@x.com"); lowercasing
  on lookup means even a row that somehow ended up mixed-case still resolves
  correctly on read.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time import utc_now
from app.domain.models import User
from app.repositories.exceptions import DuplicateEmailError


class UserRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_user(self, email: str, password_hash: str) -> User:
        """Persists a new user. Raises DuplicateEmailError if the (normalized)
        email already exists -- callers decide what that means, this method
        only reports it."""
        user = User(email=email.lower(), password_hash=password_hash)
        self.session.add(user)
        try:
            await self.session.commit()
        except IntegrityError as exc:
            await self.session.rollback()
            raise DuplicateEmailError(f"Email already registered: {email.lower()}") from exc

        await self.session.refresh(user)
        return user

    async def get_by_email(self, email: str) -> User | None:
        """Case-insensitive lookup by email. Returns None if no match."""
        result = await self.session.execute(
            select(User).where(User.email == email.lower())
        )
        return result.scalar_one_or_none()

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        """Lookup by primary key. Returns None if no match. Used by
        get_current_user in later sections to resolve a JWT's `sub` claim
        into an actual User."""
        result = await self.session.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def update_last_login(self, user: User) -> User:
        """Stamps last_login_at with the current time. Audit-adjacent
        metadata only -- this is not the audit log itself (that's Phase 4),
        just a cheap signal that's useful immediately."""
        user.last_login_at = utc_now()
        await self.session.commit()
        await self.session.refresh(user)
        return user
