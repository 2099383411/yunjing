"""角色 + 权限模型（适配现有 UUID 主键规范）"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer, Table, ForeignKey, UniqueConstraint
from app.models.task import Base

# 关联表：User <-> Role
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", String(36), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)


class Role(Base):
    __tablename__ = "roles"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(64), unique=True, nullable=False, index=True)
    description = Column(Text, default="")
    is_system = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Permission(Base):
    __tablename__ = "permissions"
    __table_args__ = (UniqueConstraint("resource", "action", name="uq_perm"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    resource = Column(String(64), nullable=False, index=True)
    action = Column(String(64), nullable=False, index=True)
    description = Column(Text, default="")


class RolePermission(Base):
    __tablename__ = "role_permissions"
    role_id = Column(String(36), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id = Column(String(36), ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)


# 预置权限种子
SEED_PERMISSIONS = [
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

SEED_ROLES = [
    ("超级管理员", "完整系统权限，不可删除", True),
    ("安全管理员", "可执行扫描和查看报告，不可修改系统配置", True),
    ("普通用户", "仅可执行扫描和查看自己的报告", True),
]
