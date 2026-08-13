"""
Data-return types for AuthorizationService.

Same rationale as app/domain/schemas/auth.py: these are what the service
layer hands back to its callers, not HTTP request/response models. A
future API layer (a POST /v1/authorize route, per docs/phase-2-readiness.md)
may reuse these directly or wrap them, but AuthorizationService itself has
no concept of an HTTP request or response.
"""

import uuid

from pydantic import BaseModel


class AuthorizationDecision(BaseModel):
    """The result of an authorize() check.

    Deliberately just `allowed` plus the (resource, action) that was
    checked -- no "reason" field. Distinguishing *why* a check was denied
    (inactive user vs. no matching permission vs. unrecognized permission)
    is exactly the kind of signal AuthorizationService must not leak, for
    the same reason InvalidCredentialsError never explains itself in
    app/domain/exceptions.py.
    """

    allowed: bool
    resource: str
    action: str


class RoleResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None = None
    is_system_role: bool


class PermissionResponse(BaseModel):
    id: uuid.UUID
    resource: str
    action: str
    description: str | None = None
