"""LLM 提供商模型"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer
from app.models.task import Base


class LLMProvider(Base):
    __tablename__ = "llm_providers"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(128), nullable=False)           # 显示名称，如 "DeepSeek V4"
    provider_type = Column(String(64), nullable=False)   # deepseek / openai / ollama
    api_key = Column(Text, default="")
    api_base = Column(String(512), default="")
    model = Column(String(128), default="")
    priority = Column(Integer, default=0)                # 数字越大优先级越高
    is_active = Column(Boolean, default=True)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
