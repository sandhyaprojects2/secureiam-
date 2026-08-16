"""
Canonical audit action name constants.

Centralized here so every service writing an audit event uses the exact
same string, rather than each service hand-typing its own
`action="user.login_succeeded"`-style literal and risking a typo that
silently creates a new, never-queried, orphaned action name. See
app/domain/models/audit_log.py for why these are plain strings, not a
fixed Postgres ENUM: a future phase introducing a new auditable event type
never requires a migration, just a new constant added here.
"""

# --- AuthService ---------------------------------------------------
USER_REGISTERED = "user.registered"
USER_REGISTRATION_FAILED = "user.registration_failed"
USER_LOGIN_SUCCEEDED = "user.login_succeeded"
USER_LOGIN_FAILED = "user.login_failed"
USER_LOGOUT = "user.logout"
REFRESH_TOKEN_ROTATED = "refresh_token.rotated"
REFRESH_TOKEN_REJECTED = "refresh_token.rejected"

# --- AuthorizationService ---------------------------------------------------
ROLE_CREATED = "role.created"
ROLE_ASSIGNED = "role.assigned"
ROLE_REVOKED = "role.revoked"
PERMISSION_ASSIGNED_TO_ROLE = "permission.assigned_to_role"
PERMISSION_REMOVED_FROM_ROLE = "permission.removed_from_role"

# --- OrganizationService ---------------------------------------------------
ORGANIZATION_CREATED = "organization.created"
ORGANIZATION_MEMBER_ADDED = "organization.member_added"
ORGANIZATION_MEMBER_REMOVED = "organization.member_removed"
