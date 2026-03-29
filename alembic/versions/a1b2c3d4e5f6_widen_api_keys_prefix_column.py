"""widen api_keys prefix column from VARCHAR(12) to VARCHAR(20)

Revision ID: a1b2c3d4e5f6
Revises: d4c7a6f31b2e
Create Date: 2026-03-29

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, Sequence[str], None] = "d4c7a6f31b2e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Widen prefix column to accommodate 16-char key prefixes."""
    op.alter_column(
        "api_keys",
        "prefix",
        type_=sa.String(20),
        existing_type=sa.String(12),
        existing_nullable=False,
    )


def downgrade() -> None:
    """Revert prefix column to original width."""
    op.alter_column(
        "api_keys",
        "prefix",
        type_=sa.String(12),
        existing_type=sa.String(20),
        existing_nullable=False,
    )