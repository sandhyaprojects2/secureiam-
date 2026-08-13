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


class DuplicateRolePermissionError(Exception):
    """Raised when attempting to attach a permission to a role that
    already has it, as detected by the composite primary key on
    role_permissions(role_id, permission_id)."""
    pass


class DuplicateOrganizationNameError(Exception):
    """Raised when attempting to create an organization with a name that
    already exists, as detected by the database's UNIQUE constraint on
    organizations.name."""
    pass


class DuplicateMembershipError(Exception):
    """Raised when attempting to add a user to an organization they
    already belong to, as detected by the database's UNIQUE constraint on
    organization_memberships(user_id, organization_id)."""
    pass
