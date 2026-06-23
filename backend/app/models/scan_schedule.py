"""扫描计划模型"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, JSON
from app.models.task import Base


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id = Column(String(36), primary_key=True)
    name = Column(String(128), nullable=False)
    target = Column(String(512), nullable=False)
    cron_expression = Column(String(64), nullable=False)  # e.g. "0 2 * * *"
    profile = Column(String(32), default="quick")  # quick / full / custom
    enabled = Column(Boolean, default=True)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(36), nullable=True)
