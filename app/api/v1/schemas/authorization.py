"""
HTTP-facing request/response schemas for the /v1/authorize, /v1/roles, and
/v1/users/*/roles|permissions endpoints.

Deliberately separate from app.domain.schemas.authorization, for the same
reason app.api.v1.schemas.auth is kept separate from app.domain.schemas.auth
(see that module's docstring): the API contract and the internal service
return types can then evolve independently.
"""

import uuid

from pydantic import BaseModel


# --- Requests ---------------------------------------------------

class AuthorizeRequest(BaseModel):
    resource: str
    action: str
    organization_id: uuid.UUID | None = None


class CreateRoleRequest(BaseModel):
    name: str
    description: str | None = None
    organization_id: uuid.UUID | None = None


class AssignPermissionRequest(BaseModel):
    permission_id: uuid.UUID


class AssignRoleRequest(BaseModel):
    role_id: uuid.UUID
    organization_id: uuid.UUID | None = None


# --- Responses ---------------------------------------------------

class AuthorizeResponse(BaseModel):
    allowed: bool
    resource: str
    action: str
    organization_id: uuid.UUID | None = None


class RoleResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None = None
    is_system_role: bool
    organization_id: uuid.UUID | None = None


class PermissionResponse(BaseModel):
    id: uuid.UUID
    resource: str
    action: str
    description: str | None = None
