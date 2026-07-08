"""add_scheduled_scans_table

Revision ID: a3c5f8d2e901
Revises: 9b114111057c
Create Date: 2026-07-08 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision: str = 'a3c5f8d2e901'
down_revision: Union[str, None] = '9b114111057c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'scheduled_scans',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('url', sa.String(2048), nullable=False),
        sa.Column('modules', sa.JSON, nullable=False),
        sa.Column('email_to', sa.String(255), nullable=False),
        sa.Column('interval_days', sa.Integer, nullable=False, server_default='7'),
        sa.Column('is_active', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('now()')),
        sa.Column('owner_id', UUID(as_uuid=True), nullable=False),
    )
    op.create_index('ix_scheduled_scans_owner_id', 'scheduled_scans', ['owner_id'])
    op.create_index('ix_scheduled_scans_next_run_at', 'scheduled_scans', ['next_run_at'])


def downgrade() -> None:
    op.drop_index('ix_scheduled_scans_next_run_at', 'scheduled_scans')
    op.drop_index('ix_scheduled_scans_owner_id', 'scheduled_scans')
    op.drop_table('scheduled_scans')
