"""
AuthorizationService -- the core RBAC authorization engine.

Coordinates RoleRepository, PermissionRepository, UserRoleRepository, and
UserRepository to answer "can this user do this?" and to manage the
role/permission graph those answers depend on. Like AuthService, this
module contains no SQL, no SQLAlchemy model queries, no database session
management, and no HTTPException/FastAPI imports -- it is fully usable and
testable with plain mocked repositories.

Design principles this module is built around (see docs/phases/phase-2.3.md
for the full rationale):

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
"""

import uuid

from app.domain.exceptions import (
    PermissionAlreadyAssignedError,
    PermissionNotFoundError,
    RoleAlreadyAssignedError,
    RoleNameAlreadyExistsError,
    RoleNotFoundError,
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
    ):
        self.user_repository = user_repository
        self.role_repository = role_repository
        self.permission_repository = permission_repository
        self.user_role_repository = user_role_repository

    async def authorize(
        self, user_id: uuid.UUID, resource: str, action: str
    ) -> AuthorizationDecision:
        """Deny-by-default permission check for a single (resource, action).

        Denies (without raising) if the user doesn't exist, is inactive, or
        simply lacks a role granting the requested permission -- these are
        all indistinguishable to the caller, exactly like AuthService's
        login()/refresh() failure paths are indistinguishable to theirs.
        """
        user = await self.user_repository.get_by_id(user_id)

        if user is None or not user.is_active:
            return AuthorizationDecision(allowed=False, resource=resource, action=action)

        permissions = await self.user_role_repository.get_permissions_for_user(user_id)
        allowed = any(p.resource == resource and p.action == action for p in permissions)

        return AuthorizationDecision(allowed=allowed, resource=resource, action=action)

    async def create_role(self, name: str, description: str | None = None) -> RoleResponse:
        """Creates a new role. Raises RoleNameAlreadyExistsError if the name
        is already taken -- translated from the repository layer's
        DuplicateRoleNameError, matching AuthService.register()'s pattern
        for DuplicateEmailError."""
        try:
            role = await self.role_repository.create_role(name, description)
        except DuplicateRoleNameError as exc:
            raise RoleNameAlreadyExistsError(f"Role name already exists: {name}") from exc

        return RoleResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            is_system_role=role.is_system_role,
        )

    async def assign_role(self, user_id: uuid.UUID, role_id: uuid.UUID) -> None:
        """Assigns a role to a user.

        Raises RoleNotFoundError if role_id doesn't exist, or
        RoleAlreadyAssignedError if the user already has that exact role.
        """
        role = await self.role_repository.get_by_id(role_id)
        if role is None:
            raise RoleNotFoundError(f"Role not found: {role_id}")

        try:
            await self.user_role_repository.assign(user_id, role_id)
        except DuplicateRoleAssignmentError as exc:
            raise RoleAlreadyAssignedError(
                f"User {user_id} already has role {role_id}"
            ) from exc

    async def revoke_role(self, user_id: uuid.UUID, role_id: uuid.UUID) -> bool:
        """Revokes a role from a user, if assigned.

        Returns True if an assignment was found and removed, False
        otherwise -- deliberately idempotent, not an error, matching
        UserRoleRepository.revoke()'s own not-found semantics. Takes effect
        immediately: the very next authorize() or get_user_permissions()
        call for this user will no longer see permissions granted solely by
        this role, since neither method caches.
        """
        return await self.user_role_repository.revoke(user_id, role_id)

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

    async def get_user_permissions(self, user_id: uuid.UUID) -> list[PermissionResponse]:
        """Returns the full, de-duplicated set of permissions granted by
        all of a user's currently-assigned roles. A user with no roles (or
        an unknown user_id) resolves to an empty list, not an error --
        mirrors UserRoleRepository.get_permissions_for_user()'s own
        contract, which this simply delegates to and reshapes."""
        permissions = await self.user_role_repository.get_permissions_for_user(user_id)
        return [
            PermissionResponse(
                id=p.id, resource=p.resource, action=p.action, description=p.description
            )
            for p in permissions
        ]
