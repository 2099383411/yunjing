"""Fix execution_steps.task_id length from 36 to 64

Revision ID: fix_task_id_length
Revises: 
Create Date: 2026-06-29

"""
from alembic import op
import sqlalchemy as sa

revision = "fix_task_id_length"
down_revision = None

def upgrade():
    op.alter_column("execution_steps", "task_id",
                    type_=sa.String(64),
                    existing_type=sa.String(36))

def downgrade():
    op.alter_column("execution_steps", "task_id",
                    type_=sa.String(36),
                    existing_type=sa.String(64))
