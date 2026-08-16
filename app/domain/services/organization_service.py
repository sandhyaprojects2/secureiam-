"""
OrganizationService -- manages organizations and their membership.

Coordinates OrganizationRepository, OrganizationMembershipRepository,
UserRepository, and AuditLogRepository. Deliberately separate from
AuthorizationService, the same way AuthService and AuthorizationService
are kept separate: this service owns "does this organization exist, and
who belongs to it," not "what can a member do" -- that remains
AuthorizationService's job, which is why AuthorizationService (not this
service) is what checks membership before granting an organization-scoped
role assignment.

Like every other service in this codebase, this module contains no SQL, no
SQLAlchemy model queries, no database session management, and no
HTTPException/FastAPI imports.

Phase 4.3: create_organization, add_member, and remove_member all take a
required, keyword-only actor_user_id and record an audit event -- but only
on success, never on a rejected attempt, for the same reasoning
AuthorizationService's mutating methods document: every caller has already
passed require_permission("organization", "manage") at the API layer, so a
rejected attempt here is an authorized admin's benign mistake, not a
security signal. list_members() and list_organizations_for_user() are pure
reads and are never audited.
"""

import uuid

from app.domain import audit_actions
from app.domain.exceptions import (
    OrganizationMembershipAlreadyExistsError,
    OrganizationNameAlreadyExistsError,
    OrganizationNotFoundError,
    UserNotFoundError,
)
from app.domain.schemas.organization import OrganizationMemberResponse, OrganizationResponse
from app.repositories.exceptions import DuplicateMembershipError, DuplicateOrganizationNameError


class OrganizationService:
    def __init__(
        self,
        organization_repository,
        organization_membership_repository,
        user_repository,
        audit_log_repository,
    ):
        self.organization_repository = organization_repository
        self.organization_membership_repository = organization_membership_repository
        self.user_repository = user_repository
        self.audit_log_repository = audit_log_repository

    async def create_organization(
        self, name: str, *, actor_user_id: uuid.UUID
    ) -> OrganizationResponse:
        """Creates a new organization. Raises
        OrganizationNameAlreadyExistsError if the name is already taken --
        translated from the repository layer's
        DuplicateOrganizationNameError.

        actor_user_id is required and identifies who performed this action
        for the audit log -- every caller is an already-authorized admin.
        """
        try:
            organization = await self.organization_repository.create_organization(name)
        except DuplicateOrganizationNameError as exc:
            raise OrganizationNameAlreadyExistsError(
                f"Organization name already exists: {name}"
            ) from exc

        await self.audit_log_repository.record(
            action=audit_actions.ORGANIZATION_CREATED,
            actor_user_id=actor_user_id,
            target_type="organization",
            target_id=organization.id,
            organization_id=organization.id,
            event_metadata={"name": organization.name},
        )

        return OrganizationResponse(
            id=organization.id, name=organization.name, created_at=organization.created_at
        )

    async def add_member(
        self, user_id: uuid.UUID, organization_id: uuid.UUID, *, actor_user_id: uuid.UUID
    ) -> None:
        """Adds a user to an organization.

        Raises UserNotFoundError or OrganizationNotFoundError if either id
        doesn't refer to a real row, or
        OrganizationMembershipAlreadyExistsError if the user is already a
        member. Both existence checks happen before the repository call,
        matching AuthorizationService.assign_permission_to_role()'s
        established pattern: validate first, so the repository can safely
        assume any IntegrityError it sees is the duplicate case, not a
        foreign key violation.
        """
        user = await self.user_repository.get_by_id(user_id)
        if user is None:
            raise UserNotFoundError(f"User not found: {user_id}")

        organization = await self.organization_repository.get_by_id(organization_id)
        if organization is None:
            raise OrganizationNotFoundError(f"Organization not found: {organization_id}")

        try:
            await self.organization_membership_repository.add_member(user_id, organization_id)
        except DuplicateMembershipError as exc:
            raise OrganizationMembershipAlreadyExistsError(
                f"User {user_id} is already a member of organization {organization_id}"
            ) from exc

        await self.audit_log_repository.record(
            action=audit_actions.ORGANIZATION_MEMBER_ADDED,
            actor_user_id=actor_user_id,
            target_type="user",
            target_id=user_id,
            organization_id=organization_id,
        )

    async def remove_member(
        self, user_id: uuid.UUID, organization_id: uuid.UUID, *, actor_user_id: uuid.UUID
    ) -> bool:
        """Removes a user from an organization, if they're a member.

        Returns True if a membership was found and removed, False
        otherwise -- deliberately idempotent, not an error, matching
        AuthorizationService.revoke_role()'s established shape. No
        existence validation here (unlike add_member): removing a
        membership that doesn't exist -- whether because the user, the
        organization, or just that specific membership doesn't exist -- is
        indistinguishable and equally a no-op.

        Only recorded to the audit log when a membership was actually
        removed, same reasoning as AuthorizationService.revoke_role().
        """
        removed = await self.organization_membership_repository.remove_member(
            user_id, organization_id
        )

        if removed:
            await self.audit_log_repository.record(
                action=audit_actions.ORGANIZATION_MEMBER_REMOVED,
                actor_user_id=actor_user_id,
                target_type="user",
                target_id=user_id,
                organization_id=organization_id,
            )

        return removed

    async def list_members(self, organization_id: uuid.UUID) -> list[OrganizationMemberResponse]:
        """Lists every member of an organization. Raises
        OrganizationNotFoundError if the organization doesn't exist --
        unlike remove_member(), a *listing* operation on a bad id is
        surfaced as a 404-shaped error rather than silently returning an
        empty list, since an empty list would otherwise be ambiguous
        between "this organization has no members" and "this organization
        doesn't exist."""
        organization = await self.organization_repository.get_by_id(organization_id)
        if organization is None:
            raise OrganizationNotFoundError(f"Organization not found: {organization_id}")

        members = await self.organization_membership_repository.get_members_for_organization(
            organization_id
        )
        return [
            OrganizationMemberResponse(
                user_id=member.user_id, email=member.email, joined_at=member.joined_at
            )
            for member in members
        ]

    async def list_organizations_for_user(
        self, user_id: uuid.UUID
    ) -> list[OrganizationResponse]:
        """Lists every organization the given user is a member of. A user
        with no memberships (or an unknown user_id) resolves to an empty
        list, not an error -- this is a self-service-friendly read, not an
        admin lookup by id, so there's no ambiguity worth a 404 for."""
        organizations = await self.organization_membership_repository.get_organizations_for_user(
            user_id
        )
        return [
            OrganizationResponse(id=org.id, name=org.name, created_at=org.created_at)
            for org in organizations
        ]
