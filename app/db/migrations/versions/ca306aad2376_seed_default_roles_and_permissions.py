"""seed default roles and permissions

Revision ID: ca306aad2376
Revises: 16b0325bd7db
Create Date: 2026-08-13 00:27:34.739288

Seeds the four default system roles and an initial permission catalog, per
the approved Phase 2 bootstrap decision: a controlled Alembic data migration
seeds roles/permissions, and the first Admin role assignment is a manual,
documented SQL step performed outside the API -- deliberately avoiding a
bootstrap-admin endpoint that would itself be a standing security hole.

Permission catalog rationale: this is a starter set covering the
document-management demo application planned for a later phase, plus the
two permissions Phase 2's own role/permission-management endpoints will
require (role:manage, user:manage). It is intentionally small -- new
resource:action pairs can be added later as plain data, with no schema
change and no code change to AuthorizationService's evaluation logic.

Role -> permission mapping is a reasonable default reflecting the original
project pitch (Admin/Manager/Developer/Intern with escalating document
access); adjust freely, it's data, not architecture.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ca306aad2376'
down_revision: Union[str, None] = '16b0325bd7db'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


ROLES = [
    ("Admin", "Full administrative access to the system", True),
    ("Manager", "Manages documents and team members", True),
    ("Developer", "Can view and edit documents", True),
    ("Intern", "Read-only access to documents", True),
]

PERMISSIONS = [
    ("document", "view", "View documents"),
    ("document", "edit", "Edit documents"),
    ("document", "delete", "Delete documents"),
    ("role", "manage", "Create roles and manage role-permission assignments"),
    ("user", "manage", "Assign or revoke roles for users"),
]

ROLE_PERMISSION_MAP = [
    ("Admin", "document", "view"),
    ("Admin", "document", "edit"),
    ("Admin", "document", "delete"),
    ("Admin", "role", "manage"),
    ("Admin", "user", "manage"),
    ("Manager", "document", "view"),
    ("Manager", "document", "edit"),
    ("Manager", "document", "delete"),
    ("Manager", "user", "manage"),
    ("Developer", "document", "view"),
    ("Developer", "document", "edit"),
    ("Intern", "document", "view"),
]


def upgrade() -> None:
    role_rows = ", ".join(
        f"('{name}', '{description}', {str(is_system).lower()})"
        for name, description, is_system in ROLES
    )
    op.execute(f"""
        INSERT INTO roles (name, description, is_system_role)
        VALUES {role_rows}
    """)

    permission_rows = ", ".join(
        f"('{resource}', '{action}', '{description}')"
        for resource, action, description in PERMISSIONS
    )
    op.execute(f"""
        INSERT INTO permissions (resource, action, description)
        VALUES {permission_rows}
    """)

    mapping_tuples = ", ".join(
        f"('{role}', '{resource}', '{action}')"
        for role, resource, action in ROLE_PERMISSION_MAP
    )
    op.execute(f"""
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT r.id, p.id
        FROM roles r
        JOIN permissions p ON true
        WHERE (r.name, p.resource, p.action) IN ({mapping_tuples})
    """)


def downgrade() -> None:
    # Scoped deletes -- only remove exactly what this migration inserted,
    # not the entire table contents, in case other data has been added
    # since (e.g. custom roles created via the Phase 2 API).
    role_names = ", ".join(f"'{name}'" for name, _, _ in ROLES)
    permission_pairs = ", ".join(
        f"('{resource}', '{action}')" for resource, action, _ in PERMISSIONS
    )

    op.execute(f"""
        DELETE FROM role_permissions
        WHERE role_id IN (SELECT id FROM roles WHERE name IN ({role_names}))
          AND permission_id IN (
              SELECT id FROM permissions WHERE (resource, action) IN ({permission_pairs})
          )
    """)
    op.execute(f"DELETE FROM roles WHERE name IN ({role_names})")
    op.execute(f"DELETE FROM permissions WHERE (resource, action) IN ({permission_pairs})")
