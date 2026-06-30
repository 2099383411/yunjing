"""扫描任务模型"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, DateTime, JSON, Enum as SAEnum
from sqlalchemy.orm import DeclarativeBase
import enum

class Base(DeclarativeBase):
    pass

class TaskStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class ScanTask(Base):
    __tablename__ = "scan_tasks"
    id = Column(String(36), primary_key=True)
    target = Column(String(512), nullable=False, index=True)
    scan_type = Column(String(32), default="quick")
    status = Column(SAEnum(TaskStatus), default=TaskStatus.PENDING, index=True)
    progress = Column(Integer, default=0)
    result = Column(JSON, default=dict)
    error = Column(String(1024), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    conversation_id = Column(String(64), nullable=True)
    notified = Column(Boolean, default=False)
