"""
AuthorizationService -- the core RBAC authorization engine.

Coordinates RoleRepository, PermissionRepository, UserRoleRepository,
UserRepository, OrganizationRepository, and OrganizationMembershipRepository
to answer "can this user do this?" and to manage the role/permission graph
those answers depend on. Like AuthService, this module contains no SQL, no
SQLAlchemy model queries, no database session management, and no
HTTPException/FastAPI imports -- it is fully usable and testable with plain
mocked repositories.

Design principles this module is built around (see docs/phases/phase-2.3.md
and docs/phases/phase-3.3.md for the full rationale):

  - Deny by default. authorize() starts from "no" and only becomes "yes" if
    a matching permission is found; there is no implicit-allow path.

  - Permission-based, never role-name-based. authorize() never compares a
    role's *name* to a hardcoded string (e.g. `if role.name == "Admin"`).
    It only ever checks whether the user's resolved permission set contains
    the requested (resource, action) pair. This means granting Admin-level
    access to a new role is a data change (attach permissions to it), never
    a code change.

  - Inactive users are always denied, regardless of their role/permission
    assignments -- mirrors AuthService.login()'s InactiveUserError check.

  - No caching, anywhere. Every authorize() call and every
    get_user_permissions() call re-queries UserRoleRepository fresh, which
    is what UserRoleRepository.get_permissions_for_user() was already built
    for (see its docstring from Phase 2.2). This is what makes role
    revocation and permission removal take effect immediately.

  - Unknown permissions are handled gracefully, not exceptionally. Asking
    authorize() about a (resource, action) pair that doesn't exist in the
    permission catalog at all is treated exactly like asking about one that
    exists but isn't granted: both simply resolve to `allowed=False`. This
    keeps the hot authorization path exception-free.

  - Phase 3: organization_id is optional everywhere it appears, and
    defaults to None. Passing none of it reproduces exactly the pre-Phase-3
    (global-only) behavior these methods already had -- see each method's
    own docstring for its specific organization-scoping rule.
"""

import uuid

from app.domain.exceptions import (
    OrganizationNotFoundError,
    PermissionAlreadyAssignedError,
    PermissionNotFoundError,
    RoleAlreadyAssignedError,
    RoleNameAlreadyExistsError,
    RoleNotFoundError,
    RoleOrganizationMismatchError,
    UserNotOrganizationMemberError,
)
from app.domain.schemas.authorization import (
    AuthorizationDecision,
    PermissionResponse,
    RoleResponse,
)
from app.repositories.exceptions import (
    DuplicateRoleAssignmentError,
    DuplicateRoleNameError,
    DuplicateRolePermissionError,
)


class AuthorizationService:
    def __init__(
        self,
        user_repository,
        role_repository,
        permission_repository,
        user_role_repository,
        organization_repository,
        organization_membership_repository,
    ):
        self.user_repository = user_repository
        self.role_repository = role_repository
        self.permission_repository = permission_repository
        self.user_role_repository = user_role_repository
        self.organization_repository = organization_repository
        self.organization_membership_repository = organization_membership_repository

    async def authorize(
        self,
        user_id: uuid.UUID,
        resource: str,
        action: str,
        organization_id: uuid.UUID | None = None,
    ) -> AuthorizationDecision:
        """Deny-by-default permission check for a single (resource, action),
        optionally scoped to an organization.

        Denies (without raising) if the user doesn't exist, is inactive, or
        simply lacks a role granting the requested permission -- these are
        all indistinguishable to the caller, exactly like AuthService's
        login()/refresh() failure paths are indistinguishable to theirs.

        organization_id defaults to None, which resolves only the user's
        globally-scoped permissions -- identical to Phase 2's behavior.
        Passing a real organization_id additionally includes permissions
        granted by roles assigned scoped to that organization (see
        UserRoleRepository's module docstring for the exact resolution
        rule). This method does not itself verify the user is a member of
        that organization -- see assign_role()'s docstring for why that
        check belongs at assignment time, not at every check thereafter.
        """
        user = await self.user_repository.get_by_id(user_id)

        if user is None or not user.is_active:
            return AuthorizationDecision(
                allowed=False, resource=resource, action=action, organization_id=organization_id
            )

        permissions = await self.user_role_repository.get_permissions_for_user(
            user_id, organization_id=organization_id
        )
        allowed = any(p.resource == resource and p.action == action for p in permissions)

        return AuthorizationDecision(
            allowed=allowed, resource=resource, action=action, organization_id=organization_id
        )

    async def create_role(
        self,
        name: str,
        description: str | None = None,
        organization_id: uuid.UUID | None = None,
    ) -> RoleResponse:
        """Creates a new role, optionally scoped to an organization.

        Raises OrganizationNotFoundError if organization_id is given but
        doesn't exist, or RoleNameAlreadyExistsError if the name is already
        taken -- translated from the repository layer's
        DuplicateRoleNameError, matching AuthService.register()'s pattern
        for DuplicateEmailError.

        organization_id defaults to None, creating a global/system-style
        role usable everywhere -- identical to Phase 2's only behavior.
        """
        if organization_id is not None:
            organization = await self.organization_repository.get_by_id(organization_id)
            if organization is None:
                raise OrganizationNotFoundError(f"Organization not found: {organization_id}")

        try:
            role = await self.role_repository.create_role(name, description, organization_id)
        except DuplicateRoleNameError as exc:
            raise RoleNameAlreadyExistsError(f"Role name already exists: {name}") from exc

        return RoleResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            is_system_role=role.is_system_role,
            organization_id=role.organization_id,
        )

    async def assign_role(
        self,
        user_id: uuid.UUID,
        role_id: uuid.UUID,
        organization_id: uuid.UUID | None = None,
    ) -> None:
        """Assigns a role to a user, optionally scoped to an organization.

        Raises:
          - RoleNotFoundError if role_id doesn't exist.
          - OrganizationNotFoundError if organization_id is given but
            doesn't exist.
          - RoleOrganizationMismatchError if the role itself is scoped to
            one organization (role.organization_id is not None) and
            organization_id is missing or names a *different* organization
            -- an org-scoped role can only ever be assigned within its own
            organization. (A global role has no such restriction: it can
            be assigned with no organization_id, or scoped to any one.)
          - UserNotOrganizationMemberError if organization_id is given but
            the user isn't a member of that organization. Membership is
            checked once, here, at assignment time -- not on every
            subsequent authorize() call -- because membership answers "may
            this person be granted access scoped to this org," a
            one-time gate, not "is their access still valid right now,"
            which is what authorize()'s no-caching, always-fresh
            permission resolution already handles.
          - RoleAlreadyAssignedError if the user already has this exact
            (role, organization) combination.
        """
        role = await self.role_repository.get_by_id(role_id)
        if role is None:
            raise RoleNotFoundError(f"Role not found: {role_id}")

        if role.organization_id is not None and role.organization_id != organization_id:
            raise RoleOrganizationMismatchError(
                f"Role {role_id} is scoped to organization {role.organization_id}, "
                f"cannot be assigned under organization_id={organization_id}"
            )

        if organization_id is not None:
            organization = await self.organization_repository.get_by_id(organization_id)
            if organization is None:
                raise OrganizationNotFoundError(f"Organization not found: {organization_id}")

            is_member = await self.organization_membership_repository.is_member(
                user_id, organization_id
            )
            if not is_member:
                raise UserNotOrganizationMemberError(
                    f"User {user_id} is not a member of organization {organization_id}"
                )

        try:
            await self.user_role_repository.assign(user_id, role_id, organization_id)
        except DuplicateRoleAssignmentError as exc:
            raise RoleAlreadyAssignedError(
                f"User {user_id} already has role {role_id} "
                f"(organization_id={organization_id})"
            ) from exc

    async def revoke_role(
        self,
        user_id: uuid.UUID,
        role_id: uuid.UUID,
        organization_id: uuid.UUID | None = None,
    ) -> bool:
        """Revokes a role from a user, if assigned with an exactly matching
        organization scope (None for global, or a specific organization).

        Returns True if an assignment was found and removed, False
        otherwise -- deliberately idempotent, not an error, matching
        UserRoleRepository.revoke()'s own not-found semantics. Takes effect
        immediately: the very next authorize() or get_user_permissions()
        call for this user will no longer see permissions granted solely by
        this assignment, since neither method caches.
        """
        return await self.user_role_repository.revoke(user_id, role_id, organization_id)

    async def assign_permission_to_role(
        self, role_id: uuid.UUID, permission_id: uuid.UUID
    ) -> None:
        """Attaches a permission to a role.

        Raises RoleNotFoundError or PermissionNotFoundError if either id
        doesn't refer to a real row, or PermissionAlreadyAssignedError if
        the role already has that exact permission. Both existence checks
        happen before the repository call, which is what lets
        RoleRepository.add_permission() safely assume any IntegrityError it
        sees is the duplicate case, not a foreign key violation.

        Not organization-aware: a role's own organization_id already
        determines its scope (see create_role()); permissions attached to
        it apply within that scope automatically via authorize()'s
        resolution, with no separate scoping needed here.
        """
        role = await self.role_repository.get_by_id(role_id)
        if role is None:
            raise RoleNotFoundError(f"Role not found: {role_id}")

        permission = await self.permission_repository.get_by_id(permission_id)
        if permission is None:
            raise PermissionNotFoundError(f"Permission not found: {permission_id}")

        try:
            await self.role_repository.add_permission(role_id, permission_id)
        except DuplicateRolePermissionError as exc:
            raise PermissionAlreadyAssignedError(
                f"Role {role_id} already has permission {permission_id}"
            ) from exc

    async def remove_permission_from_role(
        self, role_id: uuid.UUID, permission_id: uuid.UUID
    ) -> bool:
        """Removes a permission from a role, if attached.

        Raises RoleNotFoundError if role_id doesn't exist. Returns True if
        the permission was attached and removed, False if it wasn't --
        removing a permission the role never had is a no-op, not an error,
        matching revoke_role()'s idempotent shape. Takes effect
        immediately, for the same no-caching reason as revoke_role().
        """
        role = await self.role_repository.get_by_id(role_id)
        if role is None:
            raise RoleNotFoundError(f"Role not found: {role_id}")

        return await self.role_repository.remove_permission(role_id, permission_id)

    async def get_user_permissions(
        self, user_id: uuid.UUID, organization_id: uuid.UUID | None = None
    ) -> list[PermissionResponse]:
        """Returns the full, de-duplicated set of permissions granted by
        all of a user's currently-assigned roles: global assignments
        always, plus assignments scoped to `organization_id` if one is
        given. A user with no roles (or an unknown user_id) resolves to an
        empty list, not an error -- mirrors UserRoleRepository.
        get_permissions_for_user()'s own contract, which this simply
        delegates to and reshapes."""
        permissions = await self.user_role_repository.get_permissions_for_user(
            user_id, organization_id=organization_id
        )
        return [
            PermissionResponse(
                id=p.id, resource=p.resource, action=p.action, description=p.description
            )
            for p in permissions
        ]
