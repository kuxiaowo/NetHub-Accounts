"""Persist administrator overrides for community features."""

import sqlalchemy as sa
from alembic import op

revision = "f4bc7a81d203"
down_revision = "b147ae690c32"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "community_features",
        sa.Column("name", sa.String(32), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
    )


def downgrade():
    op.drop_table("community_features")
