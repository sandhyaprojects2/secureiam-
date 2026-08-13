"""
HTTP-facing request/response schemas for the /v1/organizations and
/v1/users/me/organizations endpoints.

Deliberately separate from app.domain.schemas.organization, for the same
reason app.api.v1.schemas.auth is kept separate from
app.domain.schemas.auth (see that module's docstring).
"""

import uuid
from datetime import datetime

from pydantic import BaseModel


# --- Requests ---------------------------------------------------

class CreateOrganizationRequest(BaseModel):
    name: str


class AddMemberRequest(BaseModel):
    user_id: uuid.UUID


# --- Responses ---------------------------------------------------

class OrganizationResponse(BaseModel):
    id: uuid.UUID
    name: str
    created_at: datetime


class OrganizationMemberResponse(BaseModel):
    user_id: uuid.UUID
    email: str
    joined_at: datetime
