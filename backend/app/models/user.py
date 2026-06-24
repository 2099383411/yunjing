"""用户模型 + 授权日志（扩展 RBAC 关系）"""
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Boolean, Enum as SAEnum
from sqlalchemy.orm import relationship
from app.models.task import Base
import enum, uuid


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    READONLY = "readonly"


class User(Base):
    __tablename__ = "users"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    display_name = Column(String(128), default="")
    role = Column(SAEnum(UserRole), default=UserRole.ANALYST)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    roles = relationship("Role", secondary="user_roles", lazy="selectin")


class AuthorizationLog(Base):
    __tablename__ = "authorization_logs"
    id = Column(String(36), primary_key=True)
    target = Column(String(512), nullable=False)
    confirmed = Column(Boolean, default=False)
    confirmed_by = Column(String(36), nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
