"""
Repository-layer exceptions.

These represent persistence-level outcomes (a DB constraint was violated),
not business decisions. AuthService is responsible for translating these
into its own domain exceptions -- repositories should not know or care what
a duplicate email *means* for the login/registration flow.
"""


class DuplicateEmailError(Exception):
    """Raised when attempting to create a user with an email that already
    exists, as detected by the database's UNIQUE constraint."""
    pass


class DuplicateRoleNameError(Exception):
    """Raised when attempting to create a role with a name that already
    exists, as detected by the database's UNIQUE constraint on roles.name."""
    pass


class DuplicateRoleAssignmentError(Exception):
    """Raised when attempting to assign a role to a user who already has
    that exact role, as detected by the database's UNIQUE constraint on
    user_roles(user_id, role_id)."""
    pass
