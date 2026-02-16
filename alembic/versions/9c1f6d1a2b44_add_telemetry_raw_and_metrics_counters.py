"""add telemetry_events_raw and metrics_counters

Revision ID: 9c1f6d1a2b44
Revises: 7e0e30d20d6a
Create Date: 2026-02-16

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "9c1f6d1a2b44"
down_revision: Union[str, Sequence[str], None] = "7e0e30d20d6a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""

    op.create_table(
        "telemetry_events_raw",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=20), nullable=False),
        sa.Column("installation_id", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_telemetry_events_raw_created_at"), "telemetry_events_raw", ["created_at"], unique=False)
    op.create_index(op.f("ix_telemetry_events_raw_event_type"), "telemetry_events_raw", ["event_type"], unique=False)
    op.create_index(op.f("ix_telemetry_events_raw_installation_id"), "telemetry_events_raw", ["installation_id"], unique=False)
    op.create_index(op.f("ix_telemetry_events_raw_source"), "telemetry_events_raw", ["source"], unique=False)

    op.create_table(
        "metrics_counters",
        sa.Column("metric_name", sa.String(length=100), nullable=False),
        sa.Column("metric_value", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("metric_name"),
    )


def downgrade() -> None:
    """Downgrade schema."""

    op.drop_table("metrics_counters")
    op.drop_index(op.f("ix_telemetry_events_raw_source"), table_name="telemetry_events_raw")
    op.drop_index(op.f("ix_telemetry_events_raw_installation_id"), table_name="telemetry_events_raw")
    op.drop_index(op.f("ix_telemetry_events_raw_event_type"), table_name="telemetry_events_raw")
    op.drop_index(op.f("ix_telemetry_events_raw_created_at"), table_name="telemetry_events_raw")
    op.drop_table("telemetry_events_raw")
