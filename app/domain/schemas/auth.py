"""
Data-return types for AuthService.

These are the objects the service layer returns to its callers (the API
layer, in Section 7). They are not HTTP request/response models -- the API
layer may reuse these directly or wrap them, but AuthService itself has no
concept of an HTTP request or response.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel


class RegisterResponse(BaseModel):
    id: uuid.UUID
    email: str
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
