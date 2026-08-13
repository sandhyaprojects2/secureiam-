"""seed organization manage permission

Revision ID: 97122fa13dcc
Revises: 714a446f6f38
Create Date: 2026-08-13 19:23:28.764210

Phase 3.4 needs a permission to gate its new organization-management
endpoints (create an organization, add/remove members) -- exactly the
extensibility case the original seed migration's docstring anticipated:
"new resource:action pairs can be added later as plain data, with no
schema change and no code change to AuthorizationService's evaluation
logic." This migration does exactly that: one new permission, granted to
the existing seeded Admin role, nothing else.

Scoped precisely, like the original seed migration's downgrade: only the
one permission and its one role mapping are touched, never a blanket wipe.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '97122fa13dcc'
down_revision: Union[str, None] = '714a446f6f38'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        INSERT INTO permissions (resource, action, description)
        VALUES ('organization', 'manage', 'Create organizations and manage their membership')
    """)

    op.execute("""
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT r.id, p.id
        FROM roles r
        JOIN permissions p ON p.resource = 'organization' AND p.action = 'manage'
        WHERE r.name = 'Admin'
    """)


def downgrade() -> None:
    op.execute("""
        DELETE FROM role_permissions
        WHERE permission_id IN (
            SELECT id FROM permissions WHERE resource = 'organization' AND action = 'manage'
        )
    """)
    op.execute("DELETE FROM permissions WHERE resource = 'organization' AND action = 'manage'")
