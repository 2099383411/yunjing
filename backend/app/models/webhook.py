"""Webhook 通知模型"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, DateTime, JSON
from app.models.task import Base


class Webhook(Base):
    __tablename__ = "webhooks"

    id = Column(String(36), primary_key=True)
    name = Column(String(128), nullable=False)
    url = Column(String(512), nullable=False)
    events = Column(JSON, default=list)  # ["scan_complete", "vuln_critical", ...]
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(36), nullable=True)
