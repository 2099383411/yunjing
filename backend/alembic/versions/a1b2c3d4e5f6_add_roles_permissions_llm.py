"""add roles, permissions, llm_providers

Revision ID: a1b2c3d4e5f6
Revises: 73e0ebe5fa5a
Create Date: 2026-05-28 14:00:00.000000
"""
import sys
sys.path.insert(0, "/app")

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
import uuid

revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "73e0ebe5fa5a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # roles
    op.create_table(
        "roles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("description", sa.Text(), default=""),
        sa.Column("is_system", sa.Boolean(), default=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    # permissions
    op.create_table(
        "permissions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("resource", sa.String(64), nullable=False, index=True),
        sa.Column("action", sa.String(64), nullable=False, index=True),
        sa.Column("description", sa.Text(), default=""),
        sa.UniqueConstraint("resource", "action", name="uq_perm"),
    )
    # role_permissions
    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.String(36), sa.ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("permission_id", sa.String(36), sa.ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
    )
    # user_roles
    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("role_id", sa.String(36), sa.ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    )
    # llm_providers
    op.create_table(
        "llm_providers",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("provider_type", sa.String(64), nullable=False),
        sa.Column("api_key", sa.Text(), default=""),
        sa.Column("api_base", sa.String(512), default=""),
        sa.Column("model", sa.String(128), default=""),
        sa.Column("priority", sa.Integer(), default=0),
        sa.Column("is_active", sa.Boolean(), default=True),
        sa.Column("is_default", sa.Boolean(), default=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    # Seed permissions
    seed_perms = [
        ("scan", "execute", "执行扫描"),
        ("scan", "stop", "终止扫描"),
        ("report", "read", "查看报告"),
        ("report", "delete", "删除报告"),
        ("report", "download", "下载报告"),
        ("user_mgmt", "read", "查看用户"),
        ("user_mgmt", "write", "创建/编辑用户"),
        ("user_mgmt", "delete", "删除用户"),
        ("settings_llm", "read", "查看 LLM 配置"),
        ("settings_llm", "write", "编辑 LLM 配置"),
        ("settings_scan", "read", "查看扫描配置"),
        ("settings_scan", "write", "编辑扫描配置"),
        ("settings_system", "read", "查看系统信息"),
    ]
    for res, act, desc in seed_perms:
        op.execute(
            f"INSERT INTO permissions (id, resource, action, description) VALUES "
            f"('{str(uuid.uuid4())}', '{res}', '{act}', '{desc}')"
        )

    # Seed roles
    roles_data = [
        ("超级管理员", "完整系统权限，不可删除", True),
        ("安全管理员", "可执行扫描和查看报告，不可修改系统配置", True),
        ("普通用户", "仅可执行扫描和查看自己的报告", True),
    ]
    for rname, rdesc, rsystem in roles_data:
        rid = str(uuid.uuid4())
        op.execute(
            f"INSERT INTO roles (id, name, description, is_system, created_at) VALUES "
            f"('{rid}', '{rname}', '{rdesc}', {str(rsystem).upper()}, NOW())"
        )
        if rname == "超级管理员":
            op.execute(
                f"INSERT INTO role_permissions (role_id, permission_id) "
                f"SELECT '{rid}', id FROM permissions"
            )


def downgrade() -> None:
    op.drop_table("user_roles")
    op.drop_table("role_permissions")
    op.drop_table("llm_providers")
    op.drop_table("permissions")
    op.drop_table("roles")
