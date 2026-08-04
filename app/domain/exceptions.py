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
