"""add central avatars

Revision ID: 4af8c912d6e0
Revises: 8c6f9a2e41b7
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "4af8c912d6e0"
down_revision = "8c6f9a2e41b7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("avatar_file", sa.String(length=160), nullable=True))
    op.add_column("users", sa.Column("avatar_updated_at", sa.DateTime(), nullable=True))
    op.add_column(
        "users",
        sa.Column(
            "avatar_color",
            sa.String(length=7),
            nullable=False,
            server_default="#6366f1",
        ),
    )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("avatar_color")
        batch_op.drop_column("avatar_updated_at")
        batch_op.drop_column("avatar_file")
