"""API Key 模型"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text
from app.models.task import Base


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True)
    name = Column(String(128), nullable=False)
    key_hash = Column(String(256), nullable=False)
    key_prefix = Column(String(8), nullable=False)  # e.g. "yj_abc..."
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    created_by = Column(String(36), nullable=True)
