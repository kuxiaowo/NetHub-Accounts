"""Invitation-only registration, verified email and restrictions."""

import sqlalchemy as sa
from alembic import op

revision = "b147ae690c32"
down_revision = "4af8c912d6e0"
branch_labels = None
depends_on = None


def upgrade():
    for column in [
        sa.Column("email", sa.String(254), nullable=True),
        sa.Column("email_verified_at", sa.DateTime(), nullable=True),
        sa.Column("first_email_verified_at", sa.DateTime(), nullable=True),
        sa.Column("invitation_suspended_until", sa.DateTime(), nullable=True),
        sa.Column("invitation_suspended", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("banned_until", sa.DateTime(), nullable=True),
        sa.Column("ban_reason", sa.Text(), server_default="", nullable=False),
    ]:
        op.add_column("users", column)
    op.create_index("uq_users_email", "users", ["email"], unique=True)
    op.create_table(
        "invitations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("inviter_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("detached_at", sa.DateTime()),
        sa.Column("token_hash", sa.String(64), unique=True, nullable=False),
        sa.Column("issued_day", sa.String(10), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime()),
        sa.Column("redeemed_at", sa.DateTime()),
        sa.Column("invitee_id", sa.Integer(), sa.ForeignKey("users.id"), unique=True),
        sa.UniqueConstraint("inviter_id", "issued_day"),
    )
    op.create_index("ix_invitations_inviter_id", "invitations", ["inviter_id"])
    op.create_table(
        "_private_email_verifications",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("token_hash", sa.String(64), unique=True, nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("consumed_at", sa.DateTime()),
    )
    op.create_index("ix_private_email_user", "_private_email_verifications", ["user_id"])
    op.create_table(
        "_private_email_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "verification_id",
            sa.Integer(),
            sa.ForeignKey("_private_email_verifications.id", ondelete="CASCADE"),
            unique=True,
            nullable=False,
        ),
        sa.Column("payload_encrypted", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("lease_until", sa.DateTime()),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("error_code", sa.String(64), nullable=False),
    )


def downgrade():
    raise RuntimeError("Restore the pre-migration backup; do not silently discard governance data")
