"""系统键值设置持久化"""
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime
from app.models.task import Base

class SystemSetting(Base):
    __tablename__ = "system_settings"
    key = Column(String(128), primary_key=True)
    value = Column(Text, default="")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
