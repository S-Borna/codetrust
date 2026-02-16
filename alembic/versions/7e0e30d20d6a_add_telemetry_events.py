"""add telemetry_events

Revision ID: 7e0e30d20d6a
Revises: b74aff4dff57
Create Date: 2026-02-16

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "7e0e30d20d6a"
down_revision: Union[str, Sequence[str], None] = "b74aff4dff57"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""

    op.create_table(
        "telemetry_events",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("instance_id", sa.String(length=64), nullable=False),
        sa.Column("client", sa.String(length=20), nullable=False),
        sa.Column("client_version", sa.String(length=32), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("scan_type", sa.String(length=30), nullable=False),
        sa.Column("verdict", sa.String(length=10), nullable=False),
        sa.Column("language", sa.String(length=20), nullable=False),
        sa.Column("delta_scans", sa.Integer(), nullable=False),
        sa.Column("delta_findings_total", sa.Integer(), nullable=False),
        sa.Column(
            "delta_hallucinated_packages_prevented",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "delta_destructive_commands_blocked",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(op.f("ix_telemetry_events_client"), "telemetry_events", ["client"], unique=False)
    op.create_index(op.f("ix_telemetry_events_created_at"), "telemetry_events", ["created_at"], unique=False)
    op.create_index(op.f("ix_telemetry_events_event_type"), "telemetry_events", ["event_type"], unique=False)
    op.create_index(op.f("ix_telemetry_events_instance_id"), "telemetry_events", ["instance_id"], unique=False)
    op.create_index(op.f("ix_telemetry_events_language"), "telemetry_events", ["language"], unique=False)
    op.create_index(op.f("ix_telemetry_events_scan_type"), "telemetry_events", ["scan_type"], unique=False)
    op.create_index(op.f("ix_telemetry_events_verdict"), "telemetry_events", ["verdict"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""

    op.drop_index(op.f("ix_telemetry_events_verdict"), table_name="telemetry_events")
    op.drop_index(op.f("ix_telemetry_events_scan_type"), table_name="telemetry_events")
    op.drop_index(op.f("ix_telemetry_events_language"), table_name="telemetry_events")
    op.drop_index(op.f("ix_telemetry_events_instance_id"), table_name="telemetry_events")
    op.drop_index(op.f("ix_telemetry_events_event_type"), table_name="telemetry_events")
    op.drop_index(op.f("ix_telemetry_events_created_at"), table_name="telemetry_events")
    op.drop_index(op.f("ix_telemetry_events_client"), table_name="telemetry_events")
    op.drop_table("telemetry_events")
