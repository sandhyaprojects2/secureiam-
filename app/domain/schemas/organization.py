"""
Data-return types for OrganizationService.

Same rationale as app/domain/schemas/auth.py and
app/domain/schemas/authorization.py: these are what the service layer
hands back to its callers, not HTTP request/response models.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel


class OrganizationResponse(BaseModel):
    id: uuid.UUID
    name: str
    created_at: datetime


class OrganizationMemberResponse(BaseModel):
    """A single member of an organization -- deliberately just enough to
    identify and display them (id, email, when they joined), not a full
    User record. Mirrors OrganizationMembershipRepository.
    get_members_for_organization()'s own lightweight row shape."""

    user_id: uuid.UUID
    email: str
    joined_at: datetime
