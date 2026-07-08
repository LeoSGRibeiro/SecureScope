"""add_name_to_scans

Revision ID: b1d4e7f9c023
Revises: a3c5f8d2e901
Create Date: 2026-07-08 14:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = 'b1d4e7f9c023'
down_revision: Union[str, None] = 'a3c5f8d2e901'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('name', sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column('scans', 'name')
