"""报告模型"""
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON
from app.models.task import Base

class Report(Base):
    __tablename__ = "reports"
    id = Column(String(36), primary_key=True)
    task_id = Column(String(36), nullable=False, index=True)
    format = Column(String(10), default="pdf")
    file_path = Column(String(512), nullable=True)
    summary = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
