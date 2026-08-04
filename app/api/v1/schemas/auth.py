"""
HTTP-facing request/response schemas for the /v1/auth/* endpoints.

Deliberately separate from app.domain.schemas.auth: these are the API
contract, not the internal domain data shape. They may look structurally
identical to their domain counterparts today, but keeping them as distinct
types means the API contract and internal service return types can evolve
independently later without one change forcing the other.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


# --- Requests ---------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


# --- Responses ---------------------------------------------------
# Deliberately expose only these fields -- never password_hash, never raw
# refresh_token database rows, never any other internal model field.

class RegisterResponse(BaseModel):
    id: uuid.UUID
    email: str
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
