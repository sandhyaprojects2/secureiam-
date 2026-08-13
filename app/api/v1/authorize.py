"""
/v1/authorize, /v1/roles, and /v1/users/*/roles|permissions routes.

Same thinness contract as app/api/v1/auth.py: validate the request, call
AuthorizationService, translate its domain exceptions into HTTP responses.
No permission-evaluation logic, no repository access, and no business
rules live here. This module (along with require_permission() and
get_current_user() in core/dependencies.py) is the only place HTTPException
is permitted to appear in the authorization path.

Route-ordering note: /users/me/permissions is registered before
/users/{user_id}/permissions on purpose -- {user_id} is typed as
uuid.UUID, and Starlette matches path patterns in registration order, not
by specificity, so the literal /me route must come first or it would never
be reached (a request to it would instead 422 on failing to parse "me" as
a UUID against the parameterized route).
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.api.v1.schemas.authorization import (
    AssignPermissionRequest,
    AssignRoleRequest,
    AuthorizeRequest,
    AuthorizeResponse,
    CreateRoleRequest,
    PermissionResponse,
    RoleResponse,
)
from app.core.dependencies import get_authorization_service, get_current_user, require_permission
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
from app.domain.models import User
from app.domain.services.authorization_service import AuthorizationService

router = APIRouter(prefix="/v1", tags=["authorization"])


@router.post("/authorize", response_model=AuthorizeResponse)
async def authorize(
    request: AuthorizeRequest,
    user: User = Depends(get_current_user),
    service: AuthorizationService = Depends(get_authorization_service),
) -> AuthorizeResponse:
    """Checks whether the caller may perform (resource, action).

    Deliberately always evaluates the calling user's own permissions --
    there is no user_id parameter. Letting a caller ask about someone
    else's permissions would itself be an authorization question this
    endpoint has no way to gate correctly, so it's simply not offered.
    """
    decision = await service.authorize(
        user.id, request.resource, request.action, organization_id=request.organization_id
    )
    return AuthorizeResponse(**decision.model_dump())


@router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    request: CreateRoleRequest,
    _: User = Depends(require_permission("role", "manage")),
    service: AuthorizationService = Depends(get_authorization_service),
) -> RoleResponse:
    try:
        result = await service.create_role(
            name=request.name,
            description=request.description,
            organization_id=request.organization_id,
        )
    except OrganizationNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found."
        )
    except RoleNameAlreadyExistsError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A role with this name already exists.",
        )

    return RoleResponse(**result.model_dump())


@router.post(
    "/roles/{role_id}/permissions",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def assign_permission_to_role(
    role_id: uuid.UUID,
    request: AssignPermissionRequest,
    _: User = Depends(require_permission("role", "manage")),
    service: AuthorizationService = Depends(get_authorization_service),
) -> Response:
    try:
        await service.assign_permission_to_role(role_id, request.permission_id)
    except RoleNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found.")
    except PermissionNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Permission not found."
        )
    except PermissionAlreadyAssignedError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Role already has this permission.",
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete(
    "/roles/{role_id}/permissions/{permission_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_permission_from_role(
    role_id: uuid.UUID,
    permission_id: uuid.UUID,
    _: User = Depends(require_permission("role", "manage")),
    service: AuthorizationService = Depends(get_authorization_service),
) -> Response:
    # No branch on the returned bool: removing a permission the role never
    # had is a no-op, not an error, matching
    # AuthorizationService.remove_permission_from_role()'s own idempotent
    # contract. Only an unknown role_id is a 404.
    try:
        await service.remove_permission_from_role(role_id, permission_id)
    except RoleNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found.")

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/users/me/permissions", response_model=list[PermissionResponse])
async def get_my_permissions(
    organization_id: uuid.UUID | None = Query(default=None),
    user: User = Depends(get_current_user),
    service: AuthorizationService = Depends(get_authorization_service),
) -> list[PermissionResponse]:
    """Self-service permission listing -- requires only authentication, no
    additional permission, since a user asking about their own grants is
    not a privileged operation. organization_id is optional: omitted,
    resolves only global grants; given, also includes grants scoped to
    that organization."""
    permissions = await service.get_user_permissions(user.id, organization_id=organization_id)
    return [PermissionResponse(**p.model_dump()) for p in permissions]


@router.post(
    "/users/{user_id}/roles",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def assign_role_to_user(
    user_id: uuid.UUID,
    request: AssignRoleRequest,
    _: User = Depends(require_permission("user", "manage")),
    service: AuthorizationService = Depends(get_authorization_service),
) -> Response:
    try:
        await service.assign_role(user_id, request.role_id, organization_id=request.organization_id)
    except RoleNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found.")
    except OrganizationNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found."
        )
    except RoleOrganizationMismatchError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This role's organization scope does not match the requested assignment.",
        )
    except UserNotOrganizationMemberError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is not a member of this organization.",
        )
    except RoleAlreadyAssignedError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already has this role.",
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete(
    "/users/{user_id}/roles/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_role_from_user(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    organization_id: uuid.UUID | None = Query(default=None),
    _: User = Depends(require_permission("user", "manage")),
    service: AuthorizationService = Depends(get_authorization_service),
) -> Response:
    # Same idempotent shape as remove_permission_from_role() above: revoking
    # a role the user never had (in the given organization scope) is a
    # no-op, not a 404.
    await service.revoke_role(user_id, role_id, organization_id=organization_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/users/{user_id}/permissions", response_model=list[PermissionResponse])
async def get_user_permissions(
    user_id: uuid.UUID,
    organization_id: uuid.UUID | None = Query(default=None),
    _: User = Depends(require_permission("user", "manage")),
    service: AuthorizationService = Depends(get_authorization_service),
) -> list[PermissionResponse]:
    permissions = await service.get_user_permissions(user_id, organization_id=organization_id)
    return [PermissionResponse(**p.model_dump()) for p in permissions]
