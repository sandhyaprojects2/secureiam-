"""seed audit view permission

Revision ID: cbf5b83aa3f8
Revises: 06072dc71cee
Create Date: 2026-08-15 23:52:04.101823

Phase 4.4 needs a permission to gate the new audit-log query endpoint --
same extensibility case as Phase 3.4's organization:manage migration: one
new permission, granted to the existing seeded Admin role, nothing else.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cbf5b83aa3f8'
down_revision: Union[str, None] = '06072dc71cee'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        INSERT INTO permissions (resource, action, description)
        VALUES ('audit', 'view', 'View the audit log')
    """)

    op.execute("""
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT r.id, p.id
        FROM roles r
        JOIN permissions p ON p.resource = 'audit' AND p.action = 'view'
        WHERE r.name = 'Admin'
    """)


def downgrade() -> None:
    op.execute("""
        DELETE FROM role_permissions
        WHERE permission_id IN (
            SELECT id FROM permissions WHERE resource = 'audit' AND action = 'view'
        )
    """)
    op.execute("DELETE FROM permissions WHERE resource = 'audit' AND action = 'view'")
