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

# Phase 5: emitted when a token already revoked *via rotation* (i.e. one
# with replaced_by set) is presented again -- the signal of a possible
# stolen-token replay. Fired on every such presentation, even a second or
# third attempt against an already-fully-revoked family (each attempt is
# its own signal) -- see AuthService.refresh() and
# RefreshTokenRepository.revoke_descendants(). Deliberately distinct from
# REFRESH_TOKEN_REJECTED/reason=revoked_token, which (as of Phase 5) fires
# only for the logout-revoked (replaced_by is None) case.
REFRESH_TOKEN_REUSE_DETECTED = "refresh_token.reuse_detected"

# Phase 5: emitted only when reuse detection actually revoked a still-live
# leaf token as a consequence -- i.e. this presentation is the one that
# killed the family, not a later attempt against an already-dead one.
# Filterable independently of REFRESH_TOKEN_REUSE_DETECTED via
# GET /v1/audit-logs?action=refresh_token.family_revoked.
REFRESH_TOKEN_FAMILY_REVOKED = "refresh_token.family_revoked"

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
