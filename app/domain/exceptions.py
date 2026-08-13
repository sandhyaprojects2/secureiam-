"""
Domain exceptions -- business-level authentication failures.

These are what AuthService raises. The API layer (Section 7) is responsible
for translating each of these into an HTTP status code and response body;
AuthService itself knows nothing about HTTP.

Security note: InvalidCredentialsError and InvalidRefreshTokenError are each
used for multiple distinct underlying conditions on purpose (see each
docstring). Callers must not attempt to distinguish the underlying cause
from the exception alone -- that's what prevents user enumeration and
refresh-token oracle attacks.
"""


class EmailAlreadyExistsError(Exception):
    """Raised when registration is attempted with an email that's already
    registered. Translated from the repository layer's DuplicateEmailError."""
    pass


class InvalidCredentialsError(Exception):
    """Raised when login fails, for either of two distinct underlying
    reasons:
      - the email does not correspond to any account, OR
      - the password is incorrect for an account that does exist.

    These two cases MUST raise this same exception, with the same message,
    so that a caller (and ultimately an API response) cannot distinguish
    "no such user" from "wrong password" -- doing so would let an attacker
    enumerate registered email addresses by probing login attempts.
    """
    pass


class InactiveUserError(Exception):
    """Raised when login is attempted against an account that exists and
    has the correct password, but has been deactivated (is_active=False)."""
    pass


class InvalidRefreshTokenError(Exception):
    """Raised when a refresh token fails validation, for any of several
    distinct underlying reasons:
      - the token does not exist in storage
      - the token has expired
      - the token has already been revoked (including via rotation)

    All of these MUST raise this same exception with the same message --
    distinguishing them would give an attacker a signal about whether a
    guessed/stolen token value was ever valid.
    """
    pass


# --- Authorization (Phase 2.3) ---------------------------------------------
#
# These are raised by AuthorizationService. Unlike the authentication
# exceptions above, there is no enumeration concern here -- role and
# permission ids are internal, admin-supplied identifiers, not user-facing
# secrets, so each distinct failure is free to be its own exception type.
#
# Notably absent: there is no "PermissionDenied"-style exception.
# AuthorizationService.authorize() never raises to signal "not allowed" --
# it returns a decision. Deny-by-default is a return value, not a control-
# flow exception, so a caller can't accidentally treat "denied" as a bug to
# catch-and-ignore.


class RoleNotFoundError(Exception):
    """Raised when an operation references a role_id that does not exist
    (assign_role, revoke_role, assign_permission_to_role,
    remove_permission_from_role)."""
    pass


class PermissionNotFoundError(Exception):
    """Raised when an operation references a permission_id that does not
    exist (assign_permission_to_role).

    Deliberately distinct from authorize() being asked about an
    unrecognized (resource, action) pair -- that is NOT an error, it's
    simply denied, since authorize() must never distinguish "no such
    permission exists" from "this permission exists but you don't have
    it." This exception exists only for admin-facing role/permission
    *management* operations, where the id is expected to already exist.
    """
    pass


class RoleNameAlreadyExistsError(Exception):
    """Raised when create_role is attempted with a name that already
    exists. Translated from the repository layer's DuplicateRoleNameError."""
    pass


class RoleAlreadyAssignedError(Exception):
    """Raised when assign_role is attempted for a user who already has the
    given role. Translated from the repository layer's
    DuplicateRoleAssignmentError."""
    pass


class PermissionAlreadyAssignedError(Exception):
    """Raised when assign_permission_to_role is attempted for a role that
    already has the given permission. Translated from the repository
    layer's DuplicateRolePermissionError."""
    pass
