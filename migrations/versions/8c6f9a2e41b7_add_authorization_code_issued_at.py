"""add authorization code issuance time

Revision ID: 8c6f9a2e41b7
Revises: 0d558214a2cb
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "8c6f9a2e41b7"
down_revision = "0d558214a2cb"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Authorization codes are intentionally short-lived and can be discarded
    # during deployment instead of assigning them a misleading issuance time.
    op.execute("DELETE FROM oauth2_authorization_codes")
    op.add_column(
        "oauth2_authorization_codes",
        sa.Column("issued_at", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )


def downgrade() -> None:
    with op.batch_alter_table("oauth2_authorization_codes") as batch_op:
        batch_op.drop_column("issued_at")
