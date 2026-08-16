"""
/v1/organizations and /v1/users/me/organizations routes.

Same thinness contract as app/api/v1/auth.py and app/api/v1/authorize.py:
validate the request, call OrganizationService, translate its domain
exceptions into HTTP responses. No membership logic, no repository access,
and no business rules live here.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.api.v1.schemas.organization import (
    AddMemberRequest,
    CreateOrganizationRequest,
    OrganizationMemberResponse,
    OrganizationResponse,
)
from app.core.dependencies import get_current_user, get_organization_service, require_permission
from app.domain.exceptions import (
    OrganizationMembershipAlreadyExistsError,
    OrganizationNameAlreadyExistsError,
    OrganizationNotFoundError,
    UserNotFoundError,
)
from app.domain.models import User
from app.domain.services.organization_service import OrganizationService

router = APIRouter(prefix="/v1", tags=["organizations"])


@router.post(
    "/organizations", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED
)
async def create_organization(
    request: CreateOrganizationRequest,
    admin: User = Depends(require_permission("organization", "manage")),
    service: OrganizationService = Depends(get_organization_service),
) -> OrganizationResponse:
    try:
        result = await service.create_organization(request.name, actor_user_id=admin.id)
    except OrganizationNameAlreadyExistsError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An organization with this name already exists.",
        )

    return OrganizationResponse(**result.model_dump())


@router.post(
    "/organizations/{organization_id}/members",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def add_organization_member(
    organization_id: uuid.UUID,
    request: AddMemberRequest,
    admin: User = Depends(require_permission("organization", "manage")),
    service: OrganizationService = Depends(get_organization_service),
) -> Response:
    try:
        await service.add_member(request.user_id, organization_id, actor_user_id=admin.id)
    except UserNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    except OrganizationNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found."
        )
    except OrganizationMembershipAlreadyExistsError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is already a member of this organization.",
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete(
    "/organizations/{organization_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_organization_member(
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    admin: User = Depends(require_permission("organization", "manage")),
    service: OrganizationService = Depends(get_organization_service),
) -> Response:
    # No branch on the returned bool: removing a membership that doesn't
    # exist is a no-op, not an error -- matches
    # OrganizationService.remove_member()'s own idempotent contract.
    await service.remove_member(user_id, organization_id, actor_user_id=admin.id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/organizations/{organization_id}/members",
    response_model=list[OrganizationMemberResponse],
)
async def list_organization_members(
    organization_id: uuid.UUID,
    _: User = Depends(require_permission("organization", "manage")),
    service: OrganizationService = Depends(get_organization_service),
) -> list[OrganizationMemberResponse]:
    try:
        members = await service.list_members(organization_id)
    except OrganizationNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found."
        )

    return [OrganizationMemberResponse(**m.model_dump()) for m in members]


@router.get("/users/me/organizations", response_model=list[OrganizationResponse])
async def get_my_organizations(
    user: User = Depends(get_current_user),
    service: OrganizationService = Depends(get_organization_service),
) -> list[OrganizationResponse]:
    """Self-service organization listing -- requires only authentication,
    no additional permission, since a user asking which organizations they
    belong to is not a privileged operation."""
    organizations = await service.list_organizations_for_user(user.id)
    return [OrganizationResponse(**o.model_dump()) for o in organizations]
