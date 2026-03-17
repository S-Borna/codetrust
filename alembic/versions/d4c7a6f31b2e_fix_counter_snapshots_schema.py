"""fix counter_snapshots schema

Revision ID: d4c7a6f31b2e
Revises: 9c1f6d1a2b44
Create Date: 2026-03-17

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "d4c7a6f31b2e"
down_revision: Union[str, Sequence[str], None] = "9c1f6d1a2b44"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


TABLE_NAME: str = "counter_snapshots"
TMP_TABLE_NAME: str = "_counter_snapshots_new"


def _create_counter_snapshots_table(name: str) -> None:
    op.create_table(
        name,
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("value", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "snapshot_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = inspector.get_table_names()

    if TABLE_NAME not in table_names:
        _create_counter_snapshots_table(TABLE_NAME)
        op.create_index(op.f("ix_counter_snapshots_key"), TABLE_NAME, ["key"], unique=False)
        op.create_index(op.f("ix_counter_snapshots_snapshot_at"), TABLE_NAME, ["snapshot_at"], unique=False)
        return

    existing_columns = {column["name"] for column in inspector.get_columns(TABLE_NAME)}
    if "id" in existing_columns:
        return

    _create_counter_snapshots_table(TMP_TABLE_NAME)
    op.execute(
        sa.text(
            """
            INSERT INTO _counter_snapshots_new (key, value, snapshot_at)
            SELECT key, value, snapshot_at
            FROM counter_snapshots
            """,
        ),
    )
    op.drop_table(TABLE_NAME)
    op.rename_table(TMP_TABLE_NAME, TABLE_NAME)
    op.create_index(op.f("ix_counter_snapshots_key"), TABLE_NAME, ["key"], unique=False)
    op.create_index(op.f("ix_counter_snapshots_snapshot_at"), TABLE_NAME, ["snapshot_at"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_counter_snapshots_snapshot_at"), table_name=TABLE_NAME)
    op.drop_index(op.f("ix_counter_snapshots_key"), table_name=TABLE_NAME)
    op.drop_table(TABLE_NAME)
